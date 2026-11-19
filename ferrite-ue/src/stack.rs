//! The L2/L3 stack: MAC ↔ bearers (RLC + PDCP, [`crate::bearers`]) ↔ RRC ↔ NAS,
//! plus the user plane ([`crate::userplane`]). Implements the PHY's
//! [`MacHandler`], so the whole stack runs synchronously on the PHY timeline
//! thread, one event at a time — no shared mutable state between layers.
//!
//! The stack itself keeps no protocol state machine: RRC ([`RrcUe::state`]),
//! NAS (`MmState` / `SmState`) and MAC own theirs. What lives here is glue:
//! the AS-security hand-over between RRC and PDCP (`security`, the two pending
//! PDUs awaiting MAC-I verification), the connection retry policy, the uplink
//! queue of an idle UE and the paging identity handed to the PHY.

use crate::bearers::Bearers;
use crate::config::UeConfig;
use crate::machine::{ConnMachine, ConnPhase, ConnTrigger, SecMachine, SecState, SecTrigger};
use crate::pcap::{Dir, MacContext, Pcap, RntiType, RrcChannel};
use crate::userplane::{UserPlane, UserPlaneEvent};
use ferrite_common::fsm::Fsm;
use ferrite_common::{Numerology, SlotPoint};
use ferrite_fapi::*;
use ferrite_mac::{MacConfig, MacEntity, MacEvent, MacStats};
use ferrite_nas::{NasConfig, NasEvent, NasUe, UeIdentity};
use ferrite_rrc::{
    derive, AsSecurity, MacNotification, RbId, RrcConfig, RrcEvent, RrcState, RrcUe,
};
use std::collections::VecDeque;

/// Application-level events the stack reports.
#[derive(Clone, Debug)]
pub enum StackEvent {
    CellConfigured {
        plmn: String,
        tac: u32,
    },
    RrcConnected,
    Registered,
    PduSessionUp {
        ip: [u8; 4],
    },
    PingReply {
        seq: u16,
        rtt_ms: f64,
    },
    PingDone {
        sent: u32,
        received: u32,
    },
    Failed(String),
    /// RRC connection released by the network (idle, still registered).
    RrcReleased,
    /// The UE was paged (or had uplink data while idle) and asked for service.
    ServiceRequest {
        cause: &'static str,
    },
    /// Radio link failure: RRC re-establishment started / completed.
    Reestablishing,
    Reestablished,
    /// A NAS registration update (periodic / mobility / network-requested) completed.
    RegistrationUpdated,
    /// The UE is deregistered (network- or UE-initiated).
    Deregistered,
}

/// The UE stack.
pub struct Stack {
    cfg: UeConfig,
    mac: MacEntity,
    bearers: Bearers,
    rrc: RrcUe,
    nas: NasUe,
    user_plane: UserPlane,
    numerology: Numerology,
    mib: Option<derive::MibInfo>,
    radio: derive::RadioInfo,
    /// AS security in force (`None` before the SecurityModeCommand is verified
    /// and after release / re-establishment until the new keys are verified).
    /// AS security, changed only through [`SecMachine`]'s table.
    security: Fsm<SecMachine>,
    /// Raw PDCP PDU of the SecurityModeCommand, verified once the keys are known.
    pending_smc_pdu: Option<Vec<u8>>,
    /// Raw PDCP PDU of the RRCReestablishment, verified with the refreshed keys.
    pending_reest_pdu: Option<Vec<u8>>,
    /// The connection lifecycle, changed only through [`ConnMachine`]'s table.
    /// Retries after a failure are the NAS's (T3511 / T3502, TS 24.501
    /// §5.5.1.2.7), not the stack's: see `formal/ue.qnt`.
    conn: Fsm<ConnMachine>,
    /// Uplink IP packets waiting for the DRB to come back (idle → service request).
    idle_pending_ul: Vec<Vec<u8>>,
    /// Paging identity to hand to the PHY on the next message (`Some(None)` stops).
    pending_paging_cfg: Option<Option<u16>>,
    events: VecDeque<StackEvent>,
    start: std::time::Instant,
    last_slot: Option<SlotPoint>,
    /// Test aid: an RLF injected once at `--rlf-at-s`.
    rlf_injected: bool,
    /// NAS clock in microseconds, derived from the slot indications (the NAS
    /// timers run on the air-interface time, not the wall clock).
    nas_us: u64,
    /// NAS asked for an N1 connection (`NasEvent::ConnectionNeeded`).
    nas_connect_pending: bool,
    /// Wireshark capture (`--pcap`).
    pcap: Option<Pcap>,
    /// The last UL transport block captured per HARQ process: a HARQ
    /// retransmission (the same bytes again) is not captured twice.
    ul_captured: std::collections::BTreeMap<u8, Vec<u8>>,
}

/// A PHY sink that copies every PUSCH transport block for the capture.
struct CaptureUl<'a> {
    inner: &'a mut dyn MacToPhySink,
    ul: &'a mut Vec<(MacContext, Vec<u8>)>,
    tdd: bool,
}

impl MacToPhySink for CaptureUl<'_> {
    fn send(&mut self, msg: MacToPhy) {
        if let MacToPhy::UlTti(req) = &msg {
            for pdu in &req.pdus {
                if let UlTtiPdu::Pusch { grant, tb, .. } = pdu {
                    let c = mac_context(
                        self.tdd,
                        Dir::Uplink,
                        grant.rnti_kind,
                        grant.rnti.0,
                        grant.harq_id,
                        grant.pusch_slot,
                    );
                    self.ul.push((c, tb.clone()));
                }
            }
        }
        self.inner.send(msg);
    }
}

/// The MAC-NR capture context of a PDU.
fn mac_context(
    tdd: bool,
    dir: Dir,
    kind: ferrite_common::RntiKind,
    rnti: u16,
    harq_id: u8,
    slot: SlotPoint,
) -> MacContext {
    use ferrite_common::RntiKind as K;
    MacContext {
        tdd,
        dir,
        rnti_type: match kind {
            K::Si => RntiType::Si,
            K::P => RntiType::P,
            K::Ra => RntiType::Ra,
            K::Tc | K::C => RntiType::C,
        },
        rnti,
        harq_id,
        sfn: slot.sfn,
        subframe: (u32::from(slot.slot) / slot.numerology.slots_per_subframe().max(1)) as u8,
    }
}

impl Stack {
    pub fn new(cfg: UeConfig, mib: Option<derive::MibInfo>) -> Self {
        let numerology = Numerology::from_scs_khz(cfg.ssb_scs_khz).unwrap_or(Numerology::KHZ30);
        let id = UeIdentity::from_imsi(&cfg.imsi, cfg.ki, cfg.opc);
        let nas_cfg = NasConfig {
            dnn: cfg.dnn.clone(),
            t3512_override_ms: cfg.t3512_s.map(|s| s * 1000),
            ..NasConfig::default()
        };
        let radio = derive::RadioInfo {
            fs: cfg.fs,
            duplex: cfg.duplex,
            band: cfg.band,
        };
        let rrc = RrcUe::new(RrcConfig {
            bands: vec![cfg.band],
            tx_lead_slots: cfg.tx_lead,
            ..RrcConfig::default()
        });
        // A placeholder MAC config until SIB1 (reconfigured by RRC).
        let mac = MacEntity::new(placeholder_mac(numerology, cfg.duplex, cfg.tx_lead));
        let pcap = cfg.pcap.as_ref().and_then(|p| {
            match Pcap::create(std::path::Path::new(p), cfg.pcap_mac_udp) {
                Ok(w) => {
                    log::info!("capturing MAC-NR / RRC / NAS to {p}");
                    Some(w)
                }
                Err(e) => {
                    log::error!("pcap {p}: {e}; running without a capture");
                    None
                }
            }
        });
        let mut nas = NasUe::new(id, nas_cfg);
        nas.set_trace(pcap.is_some());
        Self {
            mac,
            bearers: Bearers::new(numerology),
            rrc,
            nas,
            user_plane: UserPlane::new(&cfg),
            numerology,
            mib,
            radio,
            security: Fsm::new(SecState::Inactive),
            pending_smc_pdu: None,
            pending_reest_pdu: None,
            conn: Fsm::new(ConnPhase::NotStarted),
            idle_pending_ul: Vec::new(),
            pending_paging_cfg: None,
            events: VecDeque::new(),
            start: std::time::Instant::now(),
            last_slot: None,
            rlf_injected: false,
            nas_us: 0,
            nas_connect_pending: false,
            pcap,
            ul_captured: std::collections::BTreeMap::new(),
            cfg,
        }
    }

    /// Shut down gracefully: a registered UE sends DEREGISTRATION REQUEST
    /// (switch off) first. Returns `true` when a message was sent or a
    /// connection for it was requested, so the caller should allow a moment
    /// before stopping the radio.
    pub fn begin_shutdown(&mut self, now: SlotPoint) -> bool {
        if !self.nas.is_registered() {
            return false;
        }
        match self.nas.deregister_with(true) {
            Some(pdu) => {
                self.rrc.send_nas(&pdu);
                true
            }
            None => {
                self.on_nas_events(now);
                self.nas_connect(now);
                true
            }
        }
    }

    /// The N1 connection the NAS asked for: an RRC connection with the NAS
    /// message in RRCSetupComplete (mo-Signalling), AS keys from that
    /// message's uplink NAS COUNT (TS 33.501 §6.9.2.1).
    fn nas_connect(&mut self, now: SlotPoint) {
        if !self.nas_connect_pending
            || self.rrc.state() != RrcState::Idle
            || self.rrc.cell().is_none()
        {
            return;
        }
        self.nas_connect_pending = false;
        if let Some(pdu) = self.nas.take_pending_initial_message() {
            if let Some(k) = self.nas.k_gnb_for_last_message() {
                self.rrc.set_k_gnb(k);
            }
            log::info!("NAS signalling connection requested (mo-Signalling)");
            self.connect(|rrc| rrc.connect_for(pdu, now, 3));
        }
    }

    pub fn set_mib(&mut self, mib: derive::MibInfo) {
        self.mib = Some(mib);
    }

    /// The transmitter calibration turns the RRC's power-control parameters
    /// into real powers: the PHY learns the dBm of full scale, the MAC's loops
    /// are enabled and `P_CMAX` is bounded by what the device can radiate with
    /// 12 dB of peak headroom (OFDM PAPR).
    fn apply_tx_calibration(&self, phy: &mut ferrite_fapi::config::PhyConfig, mac: &mut MacConfig) {
        phy.tx_full_scale_dbm = self.cfg.tx_full_scale_dbm;
        if let Some(fs) = self.cfg.tx_full_scale_dbm {
            mac.power.enabled = true;
            mac.power.pcmax_dbm = mac.power.pcmax_dbm.min(fs - 12.0);
        }
    }

    /// A serving-cell SSB measurement from the PHY for the RRC measurement
    /// procedure: dBFS at the applied receive gain → dBm with the configured
    /// receiver calibration (the dBm of a full-scale signal at 0 dB gain).
    pub fn on_measurement(
        &mut self,
        pci: u16,
        slot: SlotPoint,
        rsrp_dbfs: f32,
        rx_gain_db: f32,
        rsrq_db: f32,
        sinr_db: f32,
    ) {
        let rsrp_dbm = rsrp_dbfs - rx_gain_db + self.cfg.rx_power_offset_db;
        let m = ferrite_rrc::meas::CellMeasurement {
            pci,
            rsrp_dbm,
            rsrq_db,
            sinr_db,
        };
        self.rrc.on_measurement(slot, &m);
        self.mac.on_rsrp_dbm(rsrp_dbm);
    }

    /// Next application event, if any.
    pub fn take_event(&mut self) -> Option<StackEvent> {
        self.events.pop_front()
    }

    /// `(sent, received)` once the built-in ping probe has finished.
    pub fn ping_result(&self) -> Option<(u32, u32)> {
        self.user_plane.ping_result()
    }

    /// The verified AS keys, if security is active.
    fn as_keys(&self) -> Option<AsSecurity> {
        match self.security.state() {
            SecState::Active(k) => Some(*k),
            _ => None,
        }
    }

    /// Move the AS security context along [`SecMachine`] (a move to the
    /// current phase only updates the keys; a refusal is logged).
    fn sec_go(&mut self, t: SecTrigger, to: SecState) {
        match self.security.transition(t, to) {
            Ok(Some(t)) => log::info!("{t}"),
            Ok(None) => {}
            Err(v) => log::error!("{v}"),
        }
    }

    /// Transitions made and refused by the stack's machines (AS security,
    /// connection).
    pub fn fsm_stats(&self) -> ferrite_common::fsm::FsmStats {
        let (a, b) = (self.security.stats(), self.conn.stats());
        ferrite_common::fsm::FsmStats {
            transitions: a.transitions + b.transitions,
            violations: a.violations + b.violations,
        }
    }

    /// Ask RRC for a connection and, when it starts one, record it.
    fn connect(&mut self, request: impl FnOnce(&mut RrcUe)) {
        request(&mut self.rrc);
        if self.rrc.state() == RrcState::Connecting {
            self.conn_go(ConnTrigger::Connect, ConnPhase::Connecting);
        }
    }

    fn conn_go(&mut self, t: ConnTrigger, to: ConnPhase) {
        match self.conn.transition(t, to) {
            Ok(Some(t)) => log::info!("{t}"),
            Ok(None) => {}
            Err(v) => log::error!("{v}"),
        }
    }

    pub fn mac_stats(&self) -> MacStats {
        self.mac.stats()
    }

    /// Write out the capture's buffered packets (before the process exits).
    pub fn flush_capture(&mut self) {
        self.capture_nas();
        if let Some(p) = self.pcap.as_mut() {
            p.flush();
            log::info!("pcap: {} packets", p.packets());
        }
    }

    fn capture_rrc(&mut self, ch: RrcChannel, pdu: &[u8]) {
        if let Some(p) = self.pcap.as_mut() {
            p.rrc(ch, pdu);
        }
    }

    fn capture_nas(&mut self) {
        let trace = self.nas.take_trace();
        if let Some(p) = self.pcap.as_mut() {
            for t in trace {
                p.nas(&t.plain);
            }
        }
    }

    fn tdd(&self) -> bool {
        self.cfg.duplex == ferrite_common::DuplexMode::Tdd
    }

    pub fn rrc_state(&self) -> RrcState {
        self.rrc.state()
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    // ---------------------------------------------------------- RRC events

    fn apply_rrc_events(&mut self, phy: &mut dyn MacToPhySink, now: SlotPoint) {
        for ev in self.rrc.take_events() {
            self.on_rrc_event(ev, phy, now);
        }
    }

    fn on_rrc_event(&mut self, ev: RrcEvent, phy: &mut dyn MacToPhySink, now: SlotPoint) {
        match ev {
            RrcEvent::CellConfigured {
                phy: p,
                mac: m,
                plmn,
                tac,
                cell_id,
            } => {
                log::info!("SIB1: PLMN {plmn} TAC {tac} cell {cell_id:#x}");
                let (mut p, mut m) = (p, m);
                self.apply_tx_calibration(&mut p, &mut m);
                self.numerology = p.numerology;
                self.bearers.set_numerology(p.numerology);
                phy.send(MacToPhy::Config(p));
                self.mac.reconfigure(*m);
                self.events
                    .push_back(StackEvent::CellConfigured { plmn, tac });
                // Start registration: NAS → RRC connection request.
                if *self.conn.state() == ConnPhase::NotStarted {
                    self.start_connection(now);
                }
            }
            // SRB0 (CCCH) is transparent: MAC carries the SDU in Msg3.
            RrcEvent::StartRa { ccch } => {
                self.capture_rrc(RrcChannel::UlCcch, &ccch);
                self.mac.start_ra(ccch)
            }
            RrcEvent::Reestablishing => self.on_reestablishing(phy),
            RrcEvent::VerifyReestablishment(sec) => self.on_verify_reestablishment(sec),
            RrcEvent::Reestablished => {
                // §5.3.7.5: the refreshed keys apply to every bearer (COUNTs kept);
                // SRB1 already has them.
                if let Some(sec) = self.as_keys() {
                    self.bearers.install_security(&sec, |rb| rb != RbId::Srb(1));
                }
                self.events.push_back(StackEvent::Reestablished);
            }
            RrcEvent::Reconfigure { phy: p, mac: m } => {
                let (mut p, mut m) = (p, m);
                self.apply_tx_calibration(&mut p, &mut m);
                phy.send(MacToPhy::Config(p));
                self.mac.reconfigure(*m);
                if self.rrc.state() == RrcState::Connected {
                    self.bearers.end_reestablishment();
                }
            }
            RrcEvent::SetupBearer(b) => {
                let keys = self.as_keys();
                self.bearers.setup(b, keys.as_ref());
                // Data that queued up while idle goes out as soon as the DRB is back.
                if self.bearers.drb_lcid().is_some() && !self.idle_pending_ul.is_empty() {
                    let q = std::mem::take(&mut self.idle_pending_ul);
                    log::info!("DRB restored: sending {} queued packet(s)", q.len());
                    for pkt in q {
                        self.drb_tx(&pkt, now);
                    }
                }
            }
            RrcEvent::ReleaseBearer { lcid } => {
                self.bearers.remove(lcid);
            }
            RrcEvent::VerifySecurity(sec) => self.on_verify_security(sec, phy, now),
            RrcEvent::TxSrb { srb, pdu } => {
                self.capture_rrc(RrcChannel::UlDcch, &pdu);
                if !self.bearers.tx_srb(srb, &pdu, now) {
                    log::warn!("no SRB{srb} bearer for an RRC PDU");
                }
            }
            RrcEvent::DlNas(nas) => self.on_dl_nas(&nas, now),
            RrcEvent::Connected => {
                log::info!("RRC connected");
                self.conn_go(ConnTrigger::Established, ConnPhase::Connected);
                self.nas.on_connection_established();
                self.events.push_back(StackEvent::RrcConnected);
            }
            RrcEvent::Released => {
                // §5.3.8.3: to idle; the NAS stays registered, the PDU
                // session stays active, and the PHY keeps monitoring paging.
                log::info!("RRC released (idle)");
                self.conn_go(ConnTrigger::Released, ConnPhase::Idle);
                self.bearers.clear();
                self.sec_go(SecTrigger::ConnectionEnded, SecState::Inactive);
                self.mac.reset(phy);
                self.nas.on_connection_released();
                self.on_nas_events(now);
                self.events.push_back(StackEvent::RrcReleased);
            }
            RrcEvent::Paged => {
                log::info!("paged: requesting service (mt-Access)");
                self.service_request(now, 2, 2);
            }
            RrcEvent::Failed(why) => {
                log::warn!("RRC failure: {why}");
                self.conn_go(ConnTrigger::Failed, ConnPhase::Idle);
                // TS 24.501 §5.5.1.2.7: a lower-layer failure is an abnormal
                // case of the registration (attempt counter, T3511 / T3502);
                // the NAS asks for the next connection (ConnectionNeeded).
                // The stack used to retry by itself within a second and
                // restart the registration, so the counter never advanced and
                // T3502 never applied (formal/ue.qnt, `backoff`).
                self.nas.on_connection_released();
                self.nas.on_lower_layer_failure();
                self.on_nas_events(now);
                self.events.push_back(StackEvent::Failed(why.to_string()));
                self.bearers.clear();
                self.sec_go(SecTrigger::ConnectionEnded, SecState::Inactive);
                self.mac.reset(phy);
            }
        }
    }

    /// §5.3.7.4: MAC reset; RLC re-established for every bearer; SRB1 PDCP
    /// re-established (no security until the new keys are verified); SRB2 /
    /// DRB PDCP state kept, suspended until the network reconfigures them.
    fn on_reestablishing(&mut self, phy: &mut dyn MacToPhySink) {
        log::info!("RRC re-establishment: resetting MAC, suspending DRBs");
        self.mac.reset(phy);
        self.sec_go(SecTrigger::Reestablishing, SecState::Suspended);
        self.pending_reest_pdu = None;
        self.bearers.begin_reestablishment();
        self.events.push_back(StackEvent::Reestablishing);
    }

    /// §5.3.7.5: verify the RRCReestablishment MAC-I with the refreshed K_RRCint,
    /// then install the new keys on SRB1.
    fn on_verify_reestablishment(&mut self, sec: AsSecurity) {
        let ok = match (self.pending_reest_pdu.as_ref(), self.bearers.srb(1)) {
            (Some(pdu), Some(b)) => b
                .pdcp
                .verify_only(pdu, sec.integrity_alg, &sec.k_rrc_int)
                .is_some(),
            _ => false,
        };
        if ok {
            self.bearers.install_security(&sec, |rb| rb == RbId::Srb(1));
            self.sec_go(SecTrigger::ReestablishmentVerified, SecState::Active(sec));
            log::info!("RRCReestablishment verified; SRB1 keys refreshed");
        } else {
            log::warn!("RRCReestablishment MAC-I check failed");
        }
        self.pending_reest_pdu = None;
        self.rrc.reestablishment_verified(ok);
    }

    /// §5.3.4.3: check the SecurityModeCommand MAC-I with K_RRCint, then
    /// activate integrity and ciphering on the SRBs. The SecurityModeComplete
    /// itself is integrity protected but not ciphered.
    fn on_verify_security(&mut self, sec: AsSecurity, phy: &mut dyn MacToPhySink, now: SlotPoint) {
        let ok = match (self.pending_smc_pdu.as_ref(), self.bearers.srb(1)) {
            (Some(pdu), Some(b)) => b
                .pdcp
                .verify_only(pdu, sec.integrity_alg, &sec.k_rrc_int)
                .is_some(),
            _ => false,
        };
        if ok {
            self.sec_go(SecTrigger::SmcVerified, SecState::Active(sec));
            self.bearers
                .install_security(&sec, |rb| matches!(rb, RbId::Srb(_)));
            self.bearers.set_srb_tx_cipher(false);
            log::info!(
                "AS security activated ({} / {})",
                sec.integrity_alg.name(),
                sec.ciphering_alg.name()
            );
        } else {
            log::warn!("SecurityModeCommand MAC-I check failed");
        }
        self.rrc.security_verified(ok);
        // RRC queued the SecurityModeComplete: send it before ciphering is on.
        self.apply_rrc_events(phy, now);
        self.bearers.set_srb_tx_cipher(true);
        self.pending_smc_pdu = None;
    }

    // ------------------------------------------------------- connection / NAS

    /// NAS registration request → RRC connection establishment.
    fn start_connection(&mut self, now: SlotPoint) {
        match self.nas.start_registration() {
            Some(nas) => self.connect(|rrc| rrc.connect(nas, now)),
            None => log::warn!(
                "registration not allowed in NAS state {:?}",
                self.nas.state()
            ),
        }
    }

    /// Idle → connected for data: NAS SERVICE REQUEST (`service_type`: 1 =
    /// data, 2 = mobile terminated) inside an RRC connection with
    /// `establishmentCause` `cause` (mo-Data = 4, mt-Access = 2).
    fn service_request(&mut self, now: SlotPoint, service_type: u8, cause: u8) {
        if self.rrc.state() != RrcState::Idle {
            return;
        }
        match self.nas.service_request(service_type) {
            Some(pdu) => {
                // The AS keys of this connection derive from the Service
                // Request's uplink NAS COUNT (TS 33.501 §6.9.2.1).
                if let Some(k) = self.nas.k_gnb_for_last_message() {
                    self.rrc.set_k_gnb(k);
                }
                self.events.push_back(StackEvent::ServiceRequest {
                    cause: if cause == 2 { "mt-Access" } else { "mo-Data" },
                });
                self.connect(|rrc| rrc.connect_for(pdu, now, cause));
            }
            None => log::warn!("service request not possible (NAS not registered)"),
        }
    }

    fn on_dl_nas(&mut self, nas: &[u8], now: SlotPoint) {
        match self.nas.on_dl_nas(nas) {
            Ok(uls) => {
                for ul in uls {
                    self.rrc.send_nas(&ul);
                }
            }
            Err(e) => log::warn!("NAS: {e}"),
        }
        self.on_nas_events(now);
    }

    /// Drain the NAS events (after a DL NAS message and after every NAS tick).
    fn on_nas_events(&mut self, _now: SlotPoint) {
        for ev in self.nas.events() {
            match ev {
                NasEvent::SecurityActivated { ul_nas_count_at_activation, .. } => {
                    if let Some(k) = self.nas.k_gnb(ul_nas_count_at_activation) {
                        self.rrc.set_k_gnb(k);
                    }
                }
                NasEvent::RegistrationComplete { guti } => {
                    log::info!("registered");
                    // The 5G-S-TMSI is the RRC identity for paging and later
                    // connection requests; the PHY monitors paging for
                    // UE_ID = 5G-S-TMSI mod 1024.
                    let s_tmsi = guti.map(|g| g.s_tmsi_u64());
                    self.rrc.set_s_tmsi(s_tmsi);
                    self.pending_paging_cfg = Some(s_tmsi.map(|v| (v & 0x3ff) as u16));
                    self.events.push_back(StackEvent::Registered);
                }
                NasEvent::PduSessionUp { ipv4: Some(ip), psi, .. } => {
                    log::info!("PDU session {psi} up: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    self.user_plane.session_up(ip);
                    self.events.push_back(StackEvent::PduSessionUp { ip });
                }
                NasEvent::PduSessionUp { psi, .. } => log::warn!("PDU session {psi} without an IPv4 address: no user plane (IPv6 not supported yet)"),
                NasEvent::PduSessionDown { psi } => {
                    log::info!("PDU session {psi} released");
                    self.user_plane.session_down();
                    self.idle_pending_ul.clear();
                }
                NasEvent::PduSessionRejected { psi, cause } => self.events.push_back(StackEvent::Failed(format!("PDU session {psi} rejected: 5GSM cause {cause}"))),
                NasEvent::RegistrationRejected(c) => self.events.push_back(StackEvent::Failed(format!("registration rejected: cause {c}"))),
                NasEvent::RegistrationTimeout => self.events.push_back(StackEvent::Failed("registration abandoned (T3510)".into())),
                NasEvent::AuthenticationFailed => self.events.push_back(StackEvent::Failed("authentication failed".into())),
                NasEvent::Deregistered => {
                    log::info!("deregistered");
                    self.user_plane.session_down();
                    self.idle_pending_ul.clear();
                    self.rrc.set_s_tmsi(None);
                    self.pending_paging_cfg = Some(None);
                    self.events.push_back(StackEvent::Deregistered);
                }
                NasEvent::ConnectionNeeded { cause } => {
                    log::info!("NAS needs a connection ({cause:?})");
                    self.nas_connect_pending = true;
                }
                NasEvent::RegistrationUpdated { guti } | NasEvent::ConfigurationUpdated { guti } => {
                    // A reallocated 5G-GUTI changes the 5G-S-TMSI RRC puts in
                    // RRCSetupRequest and the paging UE_ID.
                    let s_tmsi = guti.map(|g| g.s_tmsi_u64());
                    self.rrc.set_s_tmsi(s_tmsi);
                    self.pending_paging_cfg = Some(s_tmsi.map(|v| (v & 0x3ff) as u16));
                    if matches!(ev, NasEvent::RegistrationUpdated { .. }) {
                        log::info!("registration update complete");
                        self.events.push_back(StackEvent::RegistrationUpdated);
                    } else {
                        log::info!("configuration updated");
                    }
                }
                NasEvent::ServiceAccepted => log::info!("service accepted"),
                NasEvent::ServiceRejected(c) => log::warn!("service rejected: 5GMM cause #{c}"),
                other => log::info!("NAS event: {other:?}"),
            }
        }
    }

    // ---------------------------------------------------------- user plane

    fn drb_tx(&mut self, ip_packet: &[u8], now: SlotPoint) {
        let Some(lcid) = self.bearers.drb_lcid() else {
            // No DRB: idle (or re-connecting). Queue the packet and ask for service.
            if self.user_plane.ip().is_some() && self.rrc.state() != RrcState::Connected {
                if self.idle_pending_ul.len() < 32 {
                    self.idle_pending_ul.push(ip_packet.to_vec());
                }
                if self.rrc.state() == RrcState::Idle {
                    log::info!("uplink data while idle: requesting service (mo-Data)");
                    self.service_request(now, 1, 4);
                }
            }
            return;
        };
        self.bearers.tx_drb(lcid, ip_packet, now);
    }

    fn user_plane_slot(&mut self, now: SlotPoint) {
        for p in self.user_plane.poll_uplink() {
            self.drb_tx(&p, now);
        }
        self.drain_user_plane_events();
    }

    fn drain_user_plane_events(&mut self) {
        for ev in self.user_plane.take_events() {
            self.events.push_back(match ev {
                UserPlaneEvent::PingReply { seq, rtt_ms } => StackEvent::PingReply { seq, rtt_ms },
                UserPlaneEvent::PingDone { sent, received } => {
                    StackEvent::PingDone { sent, received }
                }
            });
        }
    }

    /// Deliver reassembled RLC SDUs up: SRB → PDCP → RRC, DRB → PDCP → user plane.
    fn deliver_rx(&mut self, now: SlotPoint) {
        let d = self.bearers.deliver_rx(now);
        for lcid in d.rlc_max_retx {
            log::warn!("RLC max retransmissions on LCID {lcid}");
            self.rrc.on_mac(MacNotification::RlcMaxRetx { lcid });
        }
        for (srb, pdu, raw) in d.srb {
            // A SecurityModeCommand needs the raw PDCP PDU for verification;
            // so does the RRCReestablishment (with the refreshed keys).
            if self.as_keys().is_none() {
                if self.rrc.state() == RrcState::Reestablishing && srb == 1 {
                    self.pending_reest_pdu = Some(raw);
                } else {
                    self.pending_smc_pdu = Some(raw);
                }
            }
            self.capture_rrc(RrcChannel::DlDcch, &pdu);
            self.rrc.on_dl_dcch(srb, &pdu);
        }
        for pkt in d.ip {
            if let Some(reply) = self.user_plane.on_downlink(&pkt) {
                self.drb_tx(&reply, now);
            }
        }
        self.drain_user_plane_events();
    }

    fn on_mac_events(&mut self, phy: &mut dyn MacToPhySink, now: SlotPoint) {
        for ev in self.mac.take_events() {
            match ev {
                MacEvent::Bcch(tb) => {
                    self.capture_rrc(RrcChannel::BcchDlSch, &tb);
                    if let Some(mib) = self.mib.clone() {
                        self.rrc.on_bcch(&tb, &mib, &self.radio);
                    }
                }
                MacEvent::Ccch(pdu) => {
                    self.capture_rrc(RrcChannel::DlCcch, &pdu);
                    self.rrc.on_dl_ccch(&pdu)
                }
                MacEvent::Pcch(pdu) => {
                    self.capture_rrc(RrcChannel::Pcch, &pdu);
                    self.rrc.on_pcch(&pdu)
                }
                MacEvent::RaSucceeded { c_rnti } => {
                    log::info!("RA succeeded, C-RNTI {c_rnti}");
                    self.rrc
                        .on_mac(MacNotification::RaSucceeded { c_rnti: c_rnti.0 });
                }
                MacEvent::RaFailed => self.rrc.on_mac(MacNotification::RaFailed),
                MacEvent::SrFailure => self.rrc.on_mac(MacNotification::SrFailure),
                MacEvent::TimeAlignmentExpired => {
                    self.rrc.on_mac(MacNotification::TimeAlignmentExpired)
                }
                MacEvent::RadioLinkFailure => self.rrc.on_mac(MacNotification::RadioLinkFailure),
                MacEvent::Sync { in_sync } => {
                    self.rrc.on_mac(MacNotification::SyncIndication { in_sync })
                }
                MacEvent::BwpSwitch { dl_bwp, ul_bwp } => self
                    .rrc
                    .on_mac(MacNotification::BwpSwitch { dl_bwp, ul_bwp }),
            }
        }
        self.apply_rrc_events(phy, now);
    }
}

impl MacHandler for Stack {
    fn handle(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink) {
        // With a capture, DL transport blocks are copied here and UL ones on
        // their way to the PHY.
        if self.pcap.is_none() {
            return self.handle_inner(msg, phy);
        }
        let tdd = self.tdd();
        if let (PhyToMac::RxData(d), Some(p)) = (&msg, self.pcap.as_mut()) {
            if let Some(tb) = &d.tb {
                let c = mac_context(
                    tdd,
                    Dir::Downlink,
                    d.rnti_kind,
                    d.rnti.0,
                    d.harq_id,
                    d.pdsch_slot,
                );
                p.mac(&c, tb);
            }
        }
        let periodic =
            matches!(&msg, PhyToMac::Slot(s) if s.slot.slot == 0 && s.slot.sfn % 100 == 0);
        let mut ul = Vec::new();
        self.handle_inner(
            msg,
            &mut CaptureUl {
                inner: phy,
                ul: &mut ul,
                tdd,
            },
        );
        self.capture_nas();
        if let Some(p) = self.pcap.as_mut() {
            for (c, tb) in ul {
                if self.ul_captured.get(&c.harq_id) != Some(&tb) {
                    p.mac(&c, &tb);
                    self.ul_captured.insert(c.harq_id, tb);
                }
            }
            if periodic {
                // About once a second: a killed process loses at most that.
                p.flush();
            }
        }
    }
}

impl Stack {
    fn handle_inner(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink) {
        let now = match &msg {
            PhyToMac::Slot(s) => s.slot,
            PhyToMac::Dci(d) => d.slot,
            PhyToMac::RxData(d) => d.pdsch_slot,
            PhyToMac::Csi(c) => c.slot,
            PhyToMac::Rach(r) => r.slot,
            PhyToMac::Sync(s) => s.slot,
            PhyToMac::Error(_) => self
                .last_slot
                .unwrap_or(SlotPoint::new(self.numerology, 0, 0)),
        };
        self.last_slot = Some(now);
        let is_slot = matches!(msg, PhyToMac::Slot(_));
        if let Some(ue_id) = self.pending_paging_cfg.take() {
            phy.send(MacToPhy::Paging { ue_id });
        }
        if is_slot
            && self.cfg.rlf_at_s > 0
            && !self.rlf_injected
            && self.rrc.state() == RrcState::Connected
            && self.start.elapsed().as_secs() >= self.cfg.rlf_at_s
        {
            self.rlf_injected = true;
            log::warn!("test: injecting a radio link failure");
            self.rrc.on_mac(MacNotification::RadioLinkFailure);
        }
        self.mac.handle_with(msg, phy, &mut self.bearers);
        self.on_mac_events(phy, now);
        self.deliver_rx(now);
        self.apply_rrc_events(phy, now);
        if is_slot {
            self.bearers.tick(now);
            self.rrc.tick(now);
            // The NAS timers run on air-interface time: one slot (1 ms / 2^µ) per SLOT.indication.
            self.nas_us += 1_000 / u64::from(self.numerology.slots_per_subframe()).max(1);
            let nas_pdus = self.nas.tick(self.nas_us / 1000);
            for ul in nas_pdus {
                self.rrc.send_nas(&ul);
            }
            self.on_nas_events(now);
            self.nas_connect(now);
            self.user_plane_slot(now);
            self.apply_rrc_events(phy, now);
        }
    }
}

/// MAC configuration before SIB1 is known (nothing to do yet).
fn placeholder_mac(
    numerology: Numerology,
    duplex: ferrite_common::DuplexMode,
    tx_lead: u16,
) -> MacConfig {
    use ferrite_fapi::config::PrachConfig;
    MacConfig::initial(
        numerology,
        ferrite_mac::RachConfig {
            preamble_trans_max: 10,
            power_ramping_step_db: 4,
            target_power_dbm: -100,
            ra_response_window_slots: 10 << numerology.mu,
            contention_resolution_ms: 64,
            nof_cb_preambles: 64,
            cb_preambles_per_ssb: 64,
            prach: PrachConfig {
                phy: ferrite_ran::prach_config::PrachConfig {
                    index: 0,
                    duplex,
                    mu: numerology.mu,
                    msg1_scs_mu: numerology.mu,
                    msg1_fdm: 1,
                    msg1_frequency_start: 0,
                },
                tdd: None,
                ssb_symbols: Vec::new(),
                ssb_period_ms: 20,
                zero_correlation_zone: 0,
                root_sequence_index: 0,
                restricted_set: 0,
                total_preambles: 64,
                target_power_dbm: -100,
                power_ramping_step_db: 4,
            },
        },
        tx_lead,
    )
}
