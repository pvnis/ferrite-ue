//! The L2/L3 stack: MAC ↔ (RLC, PDCP) bearers ↔ RRC ↔ NAS, plus the user
//! plane (TUN / built-in ping). Implements the PHY's `MacHandler`, so the
//! whole stack runs synchronously on the PHY timeline thread, one event at a
//! time — no shared mutable state between layers.

use crate::config::UeConfig;
use crate::ip;
use ferrite_common::{Numerology, SlotPoint};
use ferrite_l1::fapi::*;
use ferrite_mac::{MacConfig, MacEntity, MacEvent, UpperLayers};
use ferrite_nas::{NasConfig, NasEvent, NasUe, UeIdentity};
use ferrite_pdcp::{CipherAlg, IntegrityAlg, PdcpConfig, PdcpEntity, SecurityConfig, SnLen};
use ferrite_rlc::{AmConfig, RlcEntity, RlcEvent, RlcMode, UmConfig};
use ferrite_rrc::{derive, AsSecurity, BearerSetup, MacNotification, RbId, RlcSetup, RrcConfig, RrcEvent, RrcUe};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};

/// One radio bearer: its RLC and PDCP entities.
pub struct Bearer {
    pub lcid: u8,
    pub rb: RbId,
    pub rlc: RlcEntity,
    pub pdcp: PdcpEntity,
    pub pdu_session: Option<u8>,
}

/// Bearer table + the MAC-facing SAP.
#[derive(Default)]
pub struct Bearers {
    pub by_lcid: BTreeMap<u8, Bearer>,
}

impl UpperLayers for Bearers {
    fn dl_sdu(&mut self, lcid: u8, sdu: &[u8], now: SlotPoint) {
        if let Some(b) = self.by_lcid.get_mut(&lcid) {
            b.rlc.rx_pdu(sdu, now);
        } else {
            log::debug!("DL SDU on unknown LCID {lcid} ({} B)", sdu.len());
        }
    }
    fn ul_pull(&mut self, lcid: u8, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        self.by_lcid.get_mut(&lcid).and_then(|b| b.rlc.pull_pdu(max_bytes, now))
    }
    fn ul_buffer_status(&mut self, lcid: u8) -> usize {
        self.by_lcid.get(&lcid).map_or(0, |b| b.rlc.buffer_status())
    }
}

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

/// The UE stack.
pub struct Stack {
    pub cfg: UeConfig,
    pub mac: MacEntity,
    pub bearers: Bearers,
    pub rrc: RrcUe,
    pub nas: NasUe,
    numerology: Numerology,
    mib: Option<derive::MibInfo>,
    radio: derive::RadioInfo,
    /// Pending SecurityModeCommand PDCP PDU (to verify once keys are known).
    pending_smc_pdu: Option<Vec<u8>>,
    security: Option<AsSecurity>,
    ue_ip: Option<[u8; 4]>,
    drb_lcid: Option<u8>,
    tun: Option<std::fs::File>,
    ping_seq: u16,
    ping_sent: Vec<std::time::Instant>,
    ping_recv: u32,
    next_ping: std::time::Instant,
    ping_id: u16,
    pub events: VecDeque<StackEvent>,
    start: std::time::Instant,
    registration_started: bool,
    last_slot: Option<SlotPoint>,
    /// `(sent, received)` once the built-in ping probe has finished.
    pub ping_result: Option<(u32, u32)>,
    /// Slot at which to retry the connection after an RRC failure.
    retry_at: Option<SlotPoint>,
    connect_attempts: u32,
    /// Uplink IP packets waiting for the DRB to come back (idle → service request).
    idle_pending_ul: Vec<Vec<u8>>,
    /// Paging identity to hand to the PHY on the next slot (`Some(None)` stops).
    pending_paging_cfg: Option<Option<u16>>,
    /// First SRB1 PDCP PDU received while re-establishing (the
    /// RRCReestablishment, verified once the new keys are known).
    pending_reest_pdu: Option<Vec<u8>>,
    /// Test aid: an RLF injected once at `--rlf-at-s`.
    rlf_injected: bool,
    /// Between a re-establishment and the reconfiguration that restores the
    /// bearers: every RLC entity is renewed, PDCP state is kept.
    reestablishing_bearers: bool,
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
            bearers: Bearers::default(),
            rrc,
            nas: NasUe::new(id, nas_cfg),
            numerology,
            mib,
            radio,
            pending_smc_pdu: None,
            security: None,
            ue_ip: None,
            drb_lcid: None,
            tun: None,
            ping_seq: 0,
            ping_sent: Vec::new(),
            ping_recv: 0,
            next_ping: std::time::Instant::now(),
            ping_id: 0xfe11,
            events: VecDeque::new(),
            start: std::time::Instant::now(),
            registration_started: false,
            last_slot: None,
            ping_result: None,
            retry_at: None,
            connect_attempts: 0,
            idle_pending_ul: Vec::new(),
            pending_paging_cfg: None,
            pending_reest_pdu: None,
            rlf_injected: false,
            reestablishing_bearers: false,
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

    // ------------------------------------------------------------- bearers

    fn setup_bearer(&mut self, b: BearerSetup) {
        let n = self.numerology;
        let rlc = match &b.rlc {
            RlcSetup::Tm => RlcEntity::new(RlcMode::Tm, n),
            RlcSetup::Um { sn_len, t_reassembly_ms } => RlcEntity::new(RlcMode::Um(UmConfig { sn_len: rlc_sn(*sn_len), t_reassembly_ms: *t_reassembly_ms }), n),
            RlcSetup::Am { sn_len, t_poll_retransmit_ms, poll_pdu, poll_byte, max_retx, t_reassembly_ms, t_status_prohibit_ms } => RlcEntity::new(
                RlcMode::Am(AmConfig {
                    sn_len: rlc_sn(*sn_len),
                    t_poll_retransmit_ms: *t_poll_retransmit_ms,
                    poll_pdu: *poll_pdu,
                    poll_byte: *poll_byte,
                    max_retx_threshold: *max_retx,
                    t_reassembly_ms: *t_reassembly_ms,
                    t_status_prohibit_ms: *t_status_prohibit_ms,
                }),
                n,
            ),
        };
        let mut pcfg = match b.rb {
            RbId::Srb(id) => PdcpConfig::srb(id),
            RbId::Drb(id) => PdcpConfig::drb(id, if b.pdcp_sn_len == 18 { SnLen::Len18 } else { SnLen::Len12 }),
        };
        pcfg.integrity_on_drb = b.pdcp_integrity;
        pcfg.sdap_header_ul = b.sdap_header_ul;
        pcfg.sdap_header_dl = b.sdap_header_dl;
        pcfg.qfi = b.qfi;
        pcfg.t_reordering_ms = b.t_reordering_ms.or(pcfg.t_reordering_ms);
        pcfg.discard_timer_ms = b.discard_timer_ms;
        // An existing bearer keeps its PDCP entity (COUNTs, reordering state)
        // unless the network asks for a PDCP re-establishment; its RLC entity
        // is kept unless reestablishRLC (a re-establishment already renewed
        // every RLC entity).
        let existing = self.bearers.by_lcid.iter().find(|(_, x)| x.rb == b.rb).map(|(l, _)| *l);
        let mut pdcp = match existing.and_then(|l| self.bearers.by_lcid.remove(&l)) {
            Some(old) => {
                let mut p = old.pdcp;
                if b.reestablish_pdcp {
                    p.reestablish();
                }
                if !b.reestablish_rlc && !self.reestablishing_bearers {
                    // Keep the RLC entity too: only the configuration is refreshed.
                    log::info!("bearer {:?} on LCID {} reconfigured ({:?})", b.rb, b.lcid, b.rlc);
                    if let RbId::Drb(_) = b.rb {
                        self.drb_lcid.get_or_insert(b.lcid);
                    }
                    self.bearers.by_lcid.insert(b.lcid, Bearer { lcid: b.lcid, rb: b.rb, rlc: old.rlc, pdcp: p, pdu_session: b.pdu_session.or(old.pdu_session) });
                    return;
                }
                p
            }
            None => PdcpEntity::new(pcfg, n),
        };
        if let (Some(sec), RbId::Drb(_)) = (self.security, b.rb) {
            let _ = pdcp.configure_security(SecurityConfig {
                integrity: b.pdcp_integrity.then_some((int_alg(sec.integrity_alg), sec.k_up_int)),
                cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_up_enc)),
            });
        }
        if let (Some(sec), RbId::Srb(_)) = (self.security, b.rb) {
            let _ = pdcp.configure_security(SecurityConfig { integrity: Some((int_alg(sec.integrity_alg), sec.k_rrc_int)), cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_rrc_enc)) });
        }
        if let RbId::Drb(_) = b.rb {
            self.drb_lcid.get_or_insert(b.lcid);
        }
        log::info!("bearer {:?} on LCID {} ({:?})", b.rb, b.lcid, b.rlc);
        self.bearers.by_lcid.insert(b.lcid, Bearer { lcid: b.lcid, rb: b.rb, rlc, pdcp, pdu_session: b.pdu_session });
    }

    fn tx_srb(&mut self, srb: u8, pdu: &[u8], now: SlotPoint) {
        let Some(b) = self.bearers.by_lcid.values_mut().find(|b| b.rb == RbId::Srb(srb)) else {
            log::warn!("no SRB{srb} bearer for an RRC PDU");
            return;
        };
        let pdcp_pdu = b.pdcp.tx_sdu(pdu, now);
        b.rlc.tx_sdu(pdcp_pdu);
    }

    fn apply_rrc_events(&mut self, phy: &mut dyn MacToPhySink, now: SlotPoint) {
        for ev in self.rrc.take_events() {
            match ev {
                RrcEvent::CellConfigured { phy: p, mac: m, plmn, tac, cell_id } => {
                    log::info!("SIB1: PLMN {plmn} TAC {tac} cell {cell_id:#x}");
                    self.numerology = p.numerology;
                    phy.send(MacToPhy::Config(p));
                    self.mac.reconfigure(*m);
                    self.events.push_back(StackEvent::CellConfigured { plmn, tac });
                    // Start registration: NAS → RRC connection request.
                    if !self.registration_started {
                        self.registration_started = true;
                        self.start_connection(now);
                    }
                }
                RrcEvent::StartRa { ccch } => {
                    // SRB0 (CCCH) is transparent: MAC carries the SDU in Msg3.
                    self.mac.start_ra(ccch);
                    if self.rrc.state == ferrite_rrc::RrcState::Reestablishing {
                        self.rrc.arm_t301(now);
                    }
                }
                RrcEvent::Reestablishing => {
                    // §5.3.7.2/3: MAC reset, SRB1 PDCP/RLC re-established (no
                    // security until the new keys are verified), other bearers
                    // suspended until the network reconfigures them.
                    // §5.3.7.4: MAC reset; RLC re-established for every bearer;
                    // SRB1 PDCP re-established (no security until the new keys
                    // are verified); SRB2/DRB PDCP state kept, suspended until
                    // the network reconfigures them.
                    log::info!("RRC re-establishment: resetting MAC, suspending DRBs");
                    self.mac.reset(phy);
                    self.drb_lcid = None;
                    self.security = None;
                    self.pending_reest_pdu = None;
                    self.reestablishing_bearers = true;
                    let n = self.numerology;
                    for b in self.bearers.by_lcid.values_mut() {
                        let mode = b.rlc.mode().clone();
                        b.rlc = RlcEntity::new(mode, n);
                        if b.rb == RbId::Srb(1) {
                            b.pdcp = PdcpEntity::new(PdcpConfig::srb(1), n);
                        }
                    }
                    self.events.push_back(StackEvent::Reestablishing);
                }
                RrcEvent::VerifyReestablishment(sec) => {
                    let ok = match (self.pending_reest_pdu.as_ref(), self.bearers.by_lcid.values_mut().find(|b| b.rb == RbId::Srb(1))) {
                        (Some(pdu), Some(b)) => {
                            let ok = b.pdcp.verify_only(pdu, &sec.k_rrc_int).is_some();
                            if ok {
                                let _ = b.pdcp.configure_security(SecurityConfig { integrity: Some((int_alg(sec.integrity_alg), sec.k_rrc_int)), cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_rrc_enc)) });
                            }
                            ok
                        }
                        _ => false,
                    };
                    if ok {
                        self.security = Some(sec);
                        log::info!("RRCReestablishment verified; SRB1 keys refreshed");
                    } else {
                        log::warn!("RRCReestablishment MAC-I check failed");
                    }
                    self.pending_reest_pdu = None;
                    self.rrc.reestablishment_verified(ok);
                }
                RrcEvent::Reestablished => {
                    // §5.3.7.5: the refreshed keys apply to every bearer (COUNTs kept).
                    if let Some(sec) = self.security {
                        for b in self.bearers.by_lcid.values_mut() {
                            match b.rb {
                                RbId::Srb(1) => {}
                                RbId::Srb(_) => {
                                    let _ = b.pdcp.configure_security(SecurityConfig { integrity: Some((int_alg(sec.integrity_alg), sec.k_rrc_int)), cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_rrc_enc)) });
                                }
                                RbId::Drb(_) => {
                                    let integ = b.pdcp.config().integrity_on_drb;
                                    let _ = b.pdcp.configure_security(SecurityConfig { integrity: integ.then_some((int_alg(sec.integrity_alg), sec.k_up_int)), cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_up_enc)) });
                                }
                            }
                        }
                    }
                    self.events.push_back(StackEvent::Reestablished);
                }
                RrcEvent::Reconfigure { phy: p, mac: m } => {
                    phy.send(MacToPhy::Config(p));
                    self.mac.reconfigure(*m);
                    if self.rrc.state == ferrite_rrc::RrcState::Connected {
                        self.reestablishing_bearers = false;
                    }
                }
                RrcEvent::SetupBearer(b) => {
                    self.setup_bearer(b);
                    // Data that queued up while idle goes out as soon as the DRB is back.
                    if self.drb_lcid.is_some() && !self.idle_pending_ul.is_empty() {
                        let q = std::mem::take(&mut self.idle_pending_ul);
                        log::info!("DRB restored: sending {} queued packet(s)", q.len());
                        for pkt in q {
                            self.drb_tx(&pkt, now);
                        }
                    }
                }
                RrcEvent::ReleaseBearer { lcid } => {
                    self.bearers.by_lcid.remove(&lcid);
                }
                RrcEvent::VerifySecurity(sec) => {
                    // §5.3.4.3: check the SMC MAC-I with K_RRCint, then activate.
                    let ok = match (self.pending_smc_pdu.as_ref(), self.bearers.by_lcid.values().find(|b| b.rb == RbId::Srb(1))) {
                        (Some(pdu), Some(b)) => b.pdcp.verify_only(pdu, &sec.k_rrc_int).is_some(),
                        _ => false,
                    };
                    if ok {
                        self.security = Some(sec);
                        for b in self.bearers.by_lcid.values_mut() {
                            if matches!(b.rb, RbId::Srb(_)) {
                                let _ = b.pdcp.configure_security(SecurityConfig {
                                    integrity: Some((int_alg(sec.integrity_alg), sec.k_rrc_int)),
                                    cipher: Some((cipher_alg(sec.ciphering_alg), sec.k_rrc_enc)),
                                });
                                // The SecurityModeComplete itself is integrity protected but not ciphered.
                                b.pdcp.set_tx_cipher_enabled(false);
                            }
                        }
                        log::info!("AS security activated (NIA{} / NEA{})", sec.integrity_alg, sec.ciphering_alg);
                    } else {
                        log::warn!("SecurityModeCommand MAC-I check failed");
                    }
                    self.rrc.security_verified(ok);
                    // The SecurityModeComplete is queued by RRC now; re-enable ciphering after it.
                    self.apply_rrc_events(phy, now);
                    for b in self.bearers.by_lcid.values_mut() {
                        if matches!(b.rb, RbId::Srb(_)) {
                            b.pdcp.set_tx_cipher_enabled(true);
                        }
                    }
                    self.pending_smc_pdu = None;
                }
                RrcEvent::TxSrb { srb, pdu } => self.tx_srb(srb, &pdu, now),
                RrcEvent::DlNas(nas) => self.on_dl_nas(&nas, now),
                RrcEvent::Connected => {
                    log::info!("RRC connected");
                    self.events.push_back(StackEvent::RrcConnected);
                }
                RrcEvent::Released => {
                    // §5.3.8.3: to idle; the NAS stays registered, the PDU
                    // session stays active, and the PHY keeps monitoring paging.
                    log::info!("RRC released (idle)");
                    self.bearers.by_lcid.clear();
                    self.drb_lcid = None;
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
                    self.bearers.by_lcid.clear();
                    self.security = None;
                    self.mac.reset(phy);
                    let backoff_slots = 200 * self.numerology.slots_per_subframe() as u64 * (1 + self.connect_attempts.min(4) as u64);
                    self.retry_at = Some(now.add(backoff_slots));
                }
            }
        }
    }

    /// NAS registration request → RRC connection establishment.
    fn start_connection(&mut self, now: SlotPoint) {
        self.connect_attempts += 1;
        let nas = self.nas.start_registration();
        self.rrc.connect(nas, now);
    }

    /// Idle → connected for data: NAS SERVICE REQUEST (`service_type`: 1 =
    /// data, 2 = mobile terminated) inside an RRC connection with
    /// `establishmentCause` `cause` (mo-Data = 4, mt-Access = 2).
    fn service_request(&mut self, now: SlotPoint, service_type: u8, cause: u8) {
        if self.rrc.state != ferrite_rrc::RrcState::Idle {
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
        for ev in self.nas.events() {
            match ev {
                NasEvent::SecurityActivated { ul_nas_count_at_activation, .. } => {
                    if let Some(k) = self.nas.k_gnb(ul_nas_count_at_activation) {
                        self.rrc.set_k_gnb(k);
                    }
                }
                NasEvent::RegistrationComplete { guti } => {
                    log::info!("registered");
                    // 5G-S-TMSI = AMF Set ID (10) | AMF Pointer (6) | 5G-TMSI (32):
                    // the RRC identity for paging and later connection requests;
                    // the PHY monitors paging for UE_ID = 5G-S-TMSI mod 1024.
                    let s_tmsi = guti.map(|g| (u64::from(g.amf_set_id & 0x3ff) << 38) | (u64::from(g.amf_pointer & 0x3f) << 32) | u64::from(g.tmsi));
                    self.rrc.set_s_tmsi(s_tmsi);
                    self.pending_paging_cfg = Some(s_tmsi.map(|v| (v & 0x3ff) as u16));
                    self.events.push_back(StackEvent::Registered);
                }
                NasEvent::PduSessionUp { ipv4, psi, .. } => {
                    if let Some(ip) = ipv4 {
                        log::info!("PDU session {psi} up: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                        self.next_ping = std::time::Instant::now() + std::time::Duration::from_millis(500);
                        self.ue_ip = Some(ip);
                        self.events.push_back(StackEvent::PduSessionUp { ip });
                        self.open_tun(ip);
                    }
                }
                NasEvent::RegistrationRejected(c) => self.events.push_back(StackEvent::Failed(format!("registration rejected: cause {c}"))),
                NasEvent::AuthenticationFailed => self.events.push_back(StackEvent::Failed("authentication failed".into())),
                other => log::info!("NAS event: {other:?}"),
            }
        }
        let _ = now;
    }

    fn open_tun(&mut self, ip: [u8; 4]) {
        let Some(name) = self.cfg.tun.clone() else { return };
        match crate::tun::open_tun(&name) {
            Ok(f) => {
                let _ = crate::tun::configure_tun(&name, ip, 1400, self.cfg.netns.as_deref());
                self.tun = Some(f);
                log::info!("TUN {name} up");
            }
            Err(e) => log::warn!("TUN {name}: {e}"),
        }
    }

    // ---------------------------------------------------------- user plane

    fn drb_tx(&mut self, ip_packet: &[u8], now: SlotPoint) {
        let Some(lcid) = self.drb_lcid else {
            // No DRB: idle (or re-connecting). Queue the packet and ask for service.
            if self.ue_ip.is_some() && self.rrc.state != ferrite_rrc::RrcState::Connected {
                if self.idle_pending_ul.len() < 32 {
                    self.idle_pending_ul.push(ip_packet.to_vec());
                }
                if self.rrc.state == ferrite_rrc::RrcState::Idle {
                    log::info!("uplink data while idle: requesting service (mo-Data)");
                    self.service_request(now, 1, 4);
                }
            }
            return;
        };
        if let Some(b) = self.bearers.by_lcid.get_mut(&lcid) {
            let pdu = b.pdcp.tx_sdu(ip_packet, now);
            b.rlc.tx_sdu(pdu);
        }
    }

    fn user_plane_slot(&mut self, now: SlotPoint) {
        // TUN → DRB.
        if let Some(t) = self.tun.as_mut() {
            let mut buf = [0u8; 2048];
            let mut pkts = Vec::new();
            for _ in 0..16 {
                match t.read(&mut buf) {
                    Ok(n) if n > 0 => pkts.push(buf[..n].to_vec()),
                    _ => break,
                }
            }
            for p in pkts {
                self.drb_tx(&p, now);
            }
        }
        // Built-in ping.
        if self.tun.is_none() && self.cfg.ping_count > 0 {
            if let Some(ip) = self.ue_ip {
                let total = self.cfg.ping_count * self.cfg.ping_rounds.max(1);
                if (self.ping_seq as u32) < total && std::time::Instant::now() >= self.next_ping {
                    let pkt = ip::ipv4_icmp_echo_request(ip, self.cfg.ping_target, self.ping_id, self.ping_seq, b"ferrite-ping");
                    self.ping_sent.push(std::time::Instant::now());
                    self.ping_seq += 1;
                    let round_done = self.ping_seq as u32 % self.cfg.ping_count == 0 && (self.ping_seq as u32) < total;
                    let wait = if round_done && self.cfg.ping_round_gap_s > 0 {
                        log::info!("ping round {} of {} done; next round in {} s", self.ping_seq as u32 / self.cfg.ping_count, self.cfg.ping_rounds, self.cfg.ping_round_gap_s);
                        std::time::Duration::from_secs(self.cfg.ping_round_gap_s)
                    } else {
                        std::time::Duration::from_millis(self.cfg.ping_interval_ms)
                    };
                    self.next_ping = std::time::Instant::now() + wait;
                    self.drb_tx(&pkt, now);
                }
                if self.ping_seq as u32 >= total && self.ping_sent.last().map_or(false, |t| t.elapsed() > std::time::Duration::from_secs(2)) {
                    if !self.ping_done_reported() {
                        self.ping_result = Some((self.ping_seq as u32, self.ping_recv));
                        self.events.push_back(StackEvent::PingDone { sent: self.ping_seq as u32, received: self.ping_recv });
                    }
                }
            }
        }
    }

    fn ping_done_reported(&mut self) -> bool {
        if self.ping_id == 0 {
            return true;
        }
        self.ping_id = 0;
        false
    }

    /// Deliver reassembled RLC SDUs up: SRB → PDCP → RRC, DRB → PDCP → TUN/ping.
    fn deliver_rx(&mut self, now: SlotPoint) {
        let lcids: Vec<u8> = self.bearers.by_lcid.keys().copied().collect();
        for lcid in lcids {
            let mut rrc_pdus = Vec::new();
            let mut ip_pkts = Vec::new();
            {
                let b = self.bearers.by_lcid.get_mut(&lcid).unwrap();
                while let Some(sdu) = b.rlc.pop_rx_sdu() {
                    // Keep the raw PDU of a would-be SecurityModeCommand for MAC-I verification.
                    let raw = sdu.clone();
                    match b.pdcp.rx_pdu(&sdu, now) {
                        Ok(()) => {}
                        Err(e) => {
                            log::warn!("PDCP rx on LCID {lcid}: {e}");
                            continue;
                        }
                    }
                    while let Some(s) = b.pdcp.pop_rx_sdu() {
                        match b.rb {
                            RbId::Srb(id) => rrc_pdus.push((id, s, raw.clone())),
                            RbId::Drb(_) => ip_pkts.push(s),
                        }
                    }
                }
                for ev in b.rlc.events() {
                    let RlcEvent::MaxRetxReached { .. } = ev;
                    log::warn!("RLC max retransmissions on LCID {lcid}");
                    self.rrc.on_mac(MacNotification::RadioLinkFailure);
                }
            }
            for (srb, pdu, raw) in rrc_pdus {
                // A SecurityModeCommand needs the raw PDCP PDU for verification;
                // so does the RRCReestablishment (with the refreshed keys).
                if !self.security.is_some() {
                    if self.rrc.state == ferrite_rrc::RrcState::Reestablishing && srb == 1 {
                        self.pending_reest_pdu = Some(raw);
                    } else {
                        self.pending_smc_pdu = Some(raw);
                    }
                }
                self.rrc.on_dl_dcch(srb, &pdu);
            }
            for pkt in ip_pkts {
                self.on_dl_ip(&pkt, now);
            }
        }
    }

    fn on_dl_ip(&mut self, pkt: &[u8], now: SlotPoint) {
        if let Some(t) = self.tun.as_mut() {
            let _ = t.write(pkt);
            return;
        }
        // Without a TUN the built-in stack still answers pings to the UE.
        if let Some(reply) = ip::ipv4_icmp_echo_reply_for(pkt) {
            log::info!("echo request from {}.{}.{}.{}: replying", pkt[12], pkt[13], pkt[14], pkt[15]);
            self.drb_tx(&reply, now);
            return;
        }
        if let Some(r) = ip::parse_ipv4_icmp_echo_reply(pkt) {
            if let Some(t0) = self.ping_sent.get(r.seq as usize) {
                let rtt = t0.elapsed().as_secs_f64() * 1e3;
                self.ping_recv += 1;
                log::info!("ping reply seq={} rtt={rtt:.1} ms", r.seq);
                self.events.push_back(StackEvent::PingReply { seq: r.seq, rtt_ms: rtt });
            }
        }
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
                MacEvent::RadioLinkFailure => self.rrc.on_mac(MacNotification::RadioLinkFailure),
            }
        }
        self.apply_rrc_events(phy, now);
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.start.elapsed()
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
        if is_slot && self.cfg.rlf_at_s > 0 && !self.rlf_injected && self.rrc.state == ferrite_rrc::RrcState::Connected && self.start.elapsed().as_secs() >= self.cfg.rlf_at_s {
            self.rlf_injected = true;
            log::warn!("test: injecting a radio link failure");
            self.rrc.on_mac(MacNotification::RadioLinkFailure);
        }
        self.mac.handle_with(msg, phy, &mut self.bearers);
        self.on_mac_events(phy, now);
        self.deliver_rx(now);
        self.apply_rrc_events(phy, now);
        if is_slot {
            for b in self.bearers.by_lcid.values_mut() {
                b.rlc.tick(now);
                b.pdcp.tick(now);
            }
            self.rrc.tick(now);
            if let Some(t) = self.retry_at {
                if now.diff(&t) >= 0 && self.rrc.state == ferrite_rrc::RrcState::Idle && self.rrc.cell().is_some() {
                    self.retry_at = None;
                    log::info!("retrying the connection (attempt {})", self.connect_attempts + 1);
                    self.start_connection(now);
                }
            }
            let ms = self.start.elapsed().as_millis() as u64;
            for ul in self.nas.tick(ms) {
                self.rrc.send_nas(&ul);
            }
            self.user_plane_slot(now);
            self.apply_rrc_events(phy, now);
        }
    }
}

fn rlc_sn(bits: u8) -> ferrite_rlc::SnLen {
    match bits {
        6 => ferrite_rlc::SnLen::Bits6,
        18 => ferrite_rlc::SnLen::Bits18,
        _ => ferrite_rlc::SnLen::Bits12,
    }
}

fn int_alg(a: u8) -> IntegrityAlg {
    match a {
        0 => IntegrityAlg::Nia0,
        1 => IntegrityAlg::Nia1,
        3 => IntegrityAlg::Nia3,
        _ => IntegrityAlg::Nia2,
    }
}

fn cipher_alg(a: u8) -> CipherAlg {
    match a {
        1 => CipherAlg::Nea1,
        2 => CipherAlg::Nea2,
        3 => CipherAlg::Nea3,
        _ => CipherAlg::Nea0,
    }
}

/// MAC configuration before SIB1 is known (nothing to do yet).
fn placeholder_mac(numerology: Numerology, duplex: ferrite_common::DuplexMode, tx_lead: u16) -> MacConfig {
    use ferrite_l1::config::{PrachConfig, TdraRow};
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
                phy: ferrite_phy::prach_config::PrachConfig { index: 0, duplex, mu: numerology.mu, msg1_scs_mu: numerology.mu, msg1_fdm: 1, msg1_frequency_start: 0 },
                zero_correlation_zone: 0,
                root_sequence_index: 0,
                restricted_set: 0,
                total_preambles: 64,
                target_power_dbm: -100,
                power_ramping_step_db: 4,
            },
            ul_bwp_rb: 24,
            msg3_delta: if numerology.mu == 0 { 2 } else { 3 },
            pusch_tdra_common: vec![TdraRow { k: 4, mapping_type_a: true, start_symbol: 0, n_symbols: 14 }],
        },
        tx_lead,
    )
}
