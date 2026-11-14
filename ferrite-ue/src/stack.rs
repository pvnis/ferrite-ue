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
use crate::userplane::{UserPlane, UserPlaneEvent};
use ferrite_common::{Numerology, SlotPoint};
use ferrite_fapi::*;
use ferrite_mac::{MacConfig, MacEntity, MacEvent, MacStats};
use ferrite_nas::{NasConfig, NasEvent, NasUe, UeIdentity};
use ferrite_rrc::{derive, AsSecurity, MacNotification, RbId, RrcConfig, RrcEvent, RrcState, RrcUe};
use std::collections::VecDeque;

/// Application-level events the stack reports.
#[derive(Clone, Debug)]
pub enum StackEvent {
    CellConfigured { plmn: String, tac: u32 },
    RrcConnected,
    Registered,
    PduSessionUp { ip: [u8; 4] },
    PingReply { seq: u16, rtt_ms: f64 },
    PingDone { sent: u32, received: u32 },
    Failed(String),
    /// RRC connection released by the network (idle, still registered).
    RrcReleased,
    /// The UE was paged (or had uplink data while idle) and asked for service.
    ServiceRequest { cause: &'static str },
    /// Radio link failure: RRC re-establishment started / completed.
    Reestablishing,
    Reestablished,
}

/// Connection-establishment retry (an RRC failure is not final; TS 38.331
/// leaves the retry to the upper layers).
#[derive(Default)]
struct ConnectionRetry {
    started: bool,
    attempts: u32,
    retry_at: Option<SlotPoint>,
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
    security: Option<AsSecurity>,
    /// Raw PDCP PDU of the SecurityModeCommand, verified once the keys are known.
    pending_smc_pdu: Option<Vec<u8>>,
    /// Raw PDCP PDU of the RRCReestablishment, verified with the refreshed keys.
    pending_reest_pdu: Option<Vec<u8>>,
    conn: ConnectionRetry,
    /// Uplink IP packets waiting for the DRB to come back (idle → service request).
    idle_pending_ul: Vec<Vec<u8>>,
    /// Paging identity to hand to the PHY on the next message (`Some(None)` stops).
    pending_paging_cfg: Option<Option<u16>>,
    events: VecDeque<StackEvent>,
    start: std::time::Instant,
    last_slot: Option<SlotPoint>,
    /// Test aid: an RLF injected once at `--rlf-at-s`.
    rlf_injected: bool,
}

impl Stack {
    pub fn new(cfg: UeConfig, mib: Option<derive::MibInfo>) -> Self {
        let numerology = Numerology::from_scs_khz(cfg.ssb_scs_khz).unwrap_or(Numerology::KHZ30);
        let id = UeIdentity::from_imsi(&cfg.imsi, cfg.ki, cfg.opc);
        let nas_cfg = NasConfig { dnn: cfg.dnn.clone(), ..NasConfig::default() };
        let radio = derive::RadioInfo { fs: cfg.fs, duplex: cfg.duplex, band: cfg.band };
        let rrc = RrcUe::new(RrcConfig { bands: vec![cfg.band], tx_lead_slots: cfg.tx_lead, ..RrcConfig::default() });
        // A placeholder MAC config until SIB1 (reconfigured by RRC).
        let mac = MacEntity::new(placeholder_mac(numerology, cfg.duplex, cfg.tx_lead));
        Self {
            mac,
            bearers: Bearers::new(numerology),
            rrc,
            nas: NasUe::new(id, nas_cfg),
            user_plane: UserPlane::new(&cfg),
            numerology,
            mib,
            radio,
            security: None,
            pending_smc_pdu: None,
            pending_reest_pdu: None,
            conn: ConnectionRetry::default(),
            idle_pending_ul: Vec::new(),
            pending_paging_cfg: None,
            events: VecDeque::new(),
            start: std::time::Instant::now(),
            last_slot: None,
            rlf_injected: false,
            cfg,
        }
    }

    pub fn set_mib(&mut self, mib: derive::MibInfo) {
        self.mib = Some(mib);
    }

    /// A serving-cell SSB measurement from the PHY (dBFS → dBm with the
    /// configured receiver calibration) for the RRC measurement procedure.
    pub fn on_measurement(&mut self, pci: u16, slot: SlotPoint, rsrp_dbfs: f32, rsrq_db: f32, sinr_db: f32) {
        let m = ferrite_rrc::meas::CellMeasurement { pci, rsrp_dbm: rsrp_dbfs + self.cfg.rx_power_offset_db, rsrq_db, sinr_db };
        self.rrc.on_measurement(slot, &m);
    }

    /// Next application event, if any.
    pub fn take_event(&mut self) -> Option<StackEvent> {
        self.events.pop_front()
    }

    /// `(sent, received)` once the built-in ping probe has finished.
    pub fn ping_result(&self) -> Option<(u32, u32)> {
        self.user_plane.ping_result()
    }

    pub fn mac_stats(&self) -> MacStats {
        self.mac.stats()
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
            RrcEvent::CellConfigured { phy: p, mac: m, plmn, tac, cell_id } => {
                log::info!("SIB1: PLMN {plmn} TAC {tac} cell {cell_id:#x}");
                self.numerology = p.numerology;
                self.bearers.set_numerology(p.numerology);
                phy.send(MacToPhy::Config(p));
                self.mac.reconfigure(*m);
                self.events.push_back(StackEvent::CellConfigured { plmn, tac });
                // Start registration: NAS → RRC connection request.
                if !self.conn.started {
                    self.conn.started = true;
                    self.start_connection(now);
                }
            }
            // SRB0 (CCCH) is transparent: MAC carries the SDU in Msg3.
            RrcEvent::StartRa { ccch } => self.mac.start_ra(ccch),
            RrcEvent::Reestablishing => self.on_reestablishing(phy),
            RrcEvent::VerifyReestablishment(sec) => self.on_verify_reestablishment(sec),
            RrcEvent::Reestablished => {
                // §5.3.7.5: the refreshed keys apply to every bearer (COUNTs kept);
                // SRB1 already has them.
                if let Some(sec) = self.security {
                    self.bearers.install_security(&sec, |rb| rb != RbId::Srb(1));
                }
                self.events.push_back(StackEvent::Reestablished);
            }
            RrcEvent::Reconfigure { phy: p, mac: m } => {
                phy.send(MacToPhy::Config(p));
                self.mac.reconfigure(*m);
                if self.rrc.state() == RrcState::Connected {
                    self.bearers.end_reestablishment();
                }
            }
            RrcEvent::SetupBearer(b) => {
                self.bearers.setup(b, self.security.as_ref());
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
                if !self.bearers.tx_srb(srb, &pdu, now) {
                    log::warn!("no SRB{srb} bearer for an RRC PDU");
                }
            }
            RrcEvent::DlNas(nas) => self.on_dl_nas(&nas, now),
            RrcEvent::Connected => {
                log::info!("RRC connected");
                self.events.push_back(StackEvent::RrcConnected);
            }
            RrcEvent::Released => {
                // §5.3.8.3: to idle; the NAS stays registered, the PDU
                // session stays active, and the PHY keeps monitoring paging.
                log::info!("RRC released (idle)");
                self.bearers.clear();
                self.security = None;
                self.mac.reset(phy);
                self.events.push_back(StackEvent::RrcReleased);
            }
            RrcEvent::Paged => {
                log::info!("paged: requesting service (mt-Access)");
                self.service_request(now, 2, 2);
            }
            RrcEvent::Failed(why) => {
                log::warn!("RRC failure: {why}");
                self.events.push_back(StackEvent::Failed(why.to_string()));
                // Back off and try again (a failed RA / T300 is not final).
                self.bearers.clear();
                self.security = None;
                self.mac.reset(phy);
                let backoff_slots = 200 * self.numerology.slots_per_subframe() as u64 * (1 + self.conn.attempts.min(4) as u64);
                self.conn.retry_at = Some(now.add(backoff_slots));
            }
        }
    }

    /// §5.3.7.4: MAC reset; RLC re-established for every bearer; SRB1 PDCP
    /// re-established (no security until the new keys are verified); SRB2 /
    /// DRB PDCP state kept, suspended until the network reconfigures them.
    fn on_reestablishing(&mut self, phy: &mut dyn MacToPhySink) {
        log::info!("RRC re-establishment: resetting MAC, suspending DRBs");
        self.mac.reset(phy);
        self.security = None;
        self.pending_reest_pdu = None;
        self.bearers.begin_reestablishment();
        self.events.push_back(StackEvent::Reestablishing);
    }

    /// §5.3.7.5: verify the RRCReestablishment MAC-I with the refreshed K_RRCint,
    /// then install the new keys on SRB1.
    fn on_verify_reestablishment(&mut self, sec: AsSecurity) {
        let ok = match (self.pending_reest_pdu.as_ref(), self.bearers.srb(1)) {
            (Some(pdu), Some(b)) => b.pdcp.verify_only(pdu, sec.integrity_alg, &sec.k_rrc_int).is_some(),
            _ => false,
        };
        if ok {
            self.bearers.install_security(&sec, |rb| rb == RbId::Srb(1));
            self.security = Some(sec);
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
            (Some(pdu), Some(b)) => b.pdcp.verify_only(pdu, sec.integrity_alg, &sec.k_rrc_int).is_some(),
            _ => false,
        };
        if ok {
            self.security = Some(sec);
            self.bearers.install_security(&sec, |rb| matches!(rb, RbId::Srb(_)));
            self.bearers.set_srb_tx_cipher(false);
            log::info!("AS security activated ({} / {})", sec.integrity_alg.name(), sec.ciphering_alg.name());
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
        self.conn.attempts += 1;
        let nas = self.nas.start_registration();
        self.rrc.connect(nas, now);
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
                self.events.push_back(StackEvent::ServiceRequest { cause: if cause == 2 { "mt-Access" } else { "mo-Data" } });
                self.rrc.connect_for(pdu, now, cause);
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
                }
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
                UserPlaneEvent::PingDone { sent, received } => StackEvent::PingDone { sent, received },
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
            if self.security.is_none() {
                if self.rrc.state() == RrcState::Reestablishing && srb == 1 {
                    self.pending_reest_pdu = Some(raw);
                } else {
                    self.pending_smc_pdu = Some(raw);
                }
            }
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
                    if let Some(mib) = self.mib.clone() {
                        self.rrc.on_bcch(&tb, &mib, &self.radio);
                    }
                }
                MacEvent::Ccch(pdu) => self.rrc.on_dl_ccch(&pdu),
                MacEvent::Pcch(pdu) => self.rrc.on_pcch(&pdu),
                MacEvent::RaSucceeded { c_rnti } => {
                    log::info!("RA succeeded, C-RNTI {c_rnti}");
                    self.rrc.on_mac(MacNotification::RaSucceeded { c_rnti: c_rnti.0 });
                }
                MacEvent::RaFailed => self.rrc.on_mac(MacNotification::RaFailed),
                MacEvent::SrFailure => self.rrc.on_mac(MacNotification::SrFailure),
                MacEvent::TimeAlignmentExpired => self.rrc.on_mac(MacNotification::TimeAlignmentExpired),
                MacEvent::RadioLinkFailure => self.rrc.on_mac(MacNotification::RadioLinkFailure),
            }
        }
        self.apply_rrc_events(phy, now);
    }
}

impl MacHandler for Stack {
    fn handle(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink) {
        let now = match &msg {
            PhyToMac::Slot(s) => s.slot,
            PhyToMac::Dci(d) => d.slot,
            PhyToMac::RxData(d) => d.pdsch_slot,
            PhyToMac::Csi(c) => c.slot,
            PhyToMac::Rach(r) => r.slot,
            PhyToMac::Error(_) => self.last_slot.unwrap_or(SlotPoint::new(self.numerology, 0, 0)),
        };
        self.last_slot = Some(now);
        let is_slot = matches!(msg, PhyToMac::Slot(_));
        if let Some(ue_id) = self.pending_paging_cfg.take() {
            phy.send(MacToPhy::Paging { ue_id });
        }
        if is_slot && self.cfg.rlf_at_s > 0 && !self.rlf_injected && self.rrc.state() == RrcState::Connected && self.start.elapsed().as_secs() >= self.cfg.rlf_at_s {
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
            if let Some(t) = self.conn.retry_at {
                if now.diff(&t) >= 0 && self.rrc.state() == RrcState::Idle && self.rrc.cell().is_some() {
                    self.conn.retry_at = None;
                    log::info!("retrying the connection (attempt {})", self.conn.attempts + 1);
                    self.start_connection(now);
                }
            }
            let ms = self.start.elapsed().as_millis() as u64;
            for ul in self.nas.tick(ms) {
                self.rrc.send_nas(&ul);
            }
            self.on_nas_events(now);
            self.user_plane_slot(now);
            self.apply_rrc_events(phy, now);
        }
    }
}

/// MAC configuration before SIB1 is known (nothing to do yet).
fn placeholder_mac(numerology: Numerology, duplex: ferrite_common::DuplexMode, tx_lead: u16) -> MacConfig {
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
                phy: ferrite_ran::prach_config::PrachConfig { index: 0, duplex, mu: numerology.mu, msg1_scs_mu: numerology.mu, msg1_fdm: 1, msg1_frequency_start: 0 },
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
