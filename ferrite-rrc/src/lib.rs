//! Ferrite RRC (TS 38.331) — the UE RRC entity.
//!
//! State machine:
//! ```text
//!  Idle ──connect(nas)──▶ Connecting{SetupRequest sent / RA running}
//!    ▲                        │ RRCSetup (Msg4)
//!    │ RRCRelease / RLF       ▼
//!    └──────────────────── Connected { security: Off → Activated, bearers }
//! ```
//! Procedures: system information (MIB/SIB1 → cell configuration), connection
//! establishment (§5.3.3), security mode (§5.3.4), UE capability (§5.6.1),
//! reconfiguration (§5.3.5: bearers, dedicated PHY/MAC), DL/UL information
//! transfer (§5.7.2), release (§5.3.8), measurements (§5.5, see [`meas`]).
//! RRC never touches ASN.1 bits itself
//! outside `ferrite_asn1`, and never touches the lower layers directly: it
//! emits [`RrcEvent`]s the stack applies.

#![forbid(unsafe_code)]

pub mod codec;
pub mod derive;
pub mod meas;

use ferrite_common::{Numerology, SlotPoint};
pub use ferrite_security::{CipherAlg, IntegrityAlg};
use ferrite_fapi::config::PhyConfig;
use ferrite_mac::MacConfig;

/// RRC states (§4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RrcState {
    Idle,
    Connecting,
    Connected,
    /// RRCReestablishmentRequest sent (T301 running), §5.3.7.
    Reestablishing,
}

/// AS security configuration requested by a SecurityModeCommand.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AsSecurity {
    pub integrity_alg: IntegrityAlg,
    pub ciphering_alg: CipherAlg,
    pub k_rrc_int: [u8; 16],
    pub k_rrc_enc: [u8; 16],
    pub k_up_int: [u8; 16],
    pub k_up_enc: [u8; 16],
}

impl AsSecurity {
    /// The RRC and UP keys for `k_gnb` with the given algorithms (TS 33.501 §A.8).
    pub fn derive(k_gnb: &[u8; 32], integrity_alg: IntegrityAlg, ciphering_alg: CipherAlg) -> Self {
        use ferrite_security::kdf::{algo_key, algo_type};
        Self {
            integrity_alg,
            ciphering_alg,
            k_rrc_int: algo_key(k_gnb, algo_type::RRC_INT, integrity_alg.id()),
            k_rrc_enc: algo_key(k_gnb, algo_type::RRC_ENC, ciphering_alg.id()),
            k_up_int: algo_key(k_gnb, algo_type::UP_INT, integrity_alg.id()),
            k_up_enc: algo_key(k_gnb, algo_type::UP_ENC, ciphering_alg.id()),
        }
    }
}

impl std::fmt::Debug for AsSecurity {
    /// Keys are never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AsSecurity({} / {})", self.integrity_alg.name(), self.ciphering_alg.name())
    }
}

/// A radio bearer the stack must create or reconfigure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerSetup {
    pub lcid: u8,
    /// SRB id (1..3) or DRB id (1..32).
    pub rb: RbId,
    pub rlc: RlcSetup,
    /// PDCP SN length (12/18), DRB only; SRBs use 12.
    pub pdcp_sn_len: u8,
    pub pdcp_integrity: bool,
    pub sdap_header_ul: bool,
    pub sdap_header_dl: bool,
    /// PDU session this DRB belongs to (DRB only).
    pub pdu_session: Option<u8>,
    pub qfi: u8,
    pub t_reordering_ms: Option<u32>,
    pub discard_timer_ms: Option<u32>,
    /// `reestablishPDCP` / `reestablishRLC`: reset the entity's state when
    /// the bearer already exists (otherwise an existing bearer keeps its
    /// PDCP COUNTs and RLC state across the reconfiguration).
    pub reestablish_pdcp: bool,
    pub reestablish_rlc: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RbId {
    Srb(u8),
    Drb(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RlcSetup {
    Tm,
    Um { sn_len: u8, t_reassembly_ms: u32 },
    Am { sn_len: u8, t_poll_retransmit_ms: u32, poll_pdu: Option<u32>, poll_byte: Option<u32>, max_retx: u32, t_reassembly_ms: u32, t_status_prohibit_ms: u32 },
}

/// What RRC asks the stack / lower layers to do.
#[derive(Clone, Debug)]
pub enum RrcEvent {
    /// SIB1 decoded and the cell is suitable: the PHY/MAC common configuration.
    CellConfigured { phy: Box<PhyConfig>, mac: Box<MacConfig>, plmn: String, tac: u32, cell_id: u64 },
    /// Start the random access with this CCCH SDU (RRCSetupRequest).
    StartRa { ccch: [u8; 6] },
    /// Dedicated configuration (after RRCSetup / RRCReconfiguration).
    Reconfigure { phy: Box<PhyConfig>, mac: Box<MacConfig> },
    SetupBearer(BearerSetup),
    ReleaseBearer { lcid: u8 },
    /// Verify the pending SecurityModeCommand with these keys/algorithms and, if
    /// the MAC-I checks, activate AS security (the stack answers with
    /// [`RrcUe::security_verified`]).
    VerifySecurity(AsSecurity),
    /// Send an RRC PDU on an SRB (the PDCP entity applies security).
    TxSrb { srb: u8, pdu: Vec<u8> },
    /// A NAS PDU for the NAS layer.
    DlNas(Vec<u8>),
    Connected,
    Released,
    /// Connection establishment failed (RA failure / T300) or RLF.
    Failed(&'static str),
    /// A Paging message carried this UE's 5G-S-TMSI (idle mode).
    Paged,
    /// Radio link failure with AS security active: the connection is being
    /// re-established (§5.3.7). The stack resets MAC, suspends the DRBs and
    /// re-establishes SRB1 PDCP without security; a `StartRa` follows.
    Reestablishing,
    /// `RRCReestablishment` received: verify its MAC-I with the new K_RRCint
    /// in these keys and, if it checks, apply them to SRB1 (the stack answers
    /// with [`RrcUe::reestablishment_verified`]).
    VerifyReestablishment(AsSecurity),
    /// Re-establishment complete (SRB1 up with the refreshed keys; the network
    /// restores the other bearers with an RRCReconfiguration).
    Reestablished,
}

/// What the stack tells RRC about.
#[derive(Clone, Debug)]
pub enum MacNotification {
    RaSucceeded { c_rnti: u16 },
    RaFailed,
    RadioLinkFailure,
}

/// The dedicated-bearer state RRC tracks.
#[derive(Clone, Debug, Default)]
struct Bearers {
    srb1: bool,
    srb2: bool,
    drbs: Vec<u8>,
}

/// RRC configuration knobs.
#[derive(Clone, Debug)]
pub struct RrcConfig {
    /// Supported NR bands advertised in the UE capability.
    pub bands: Vec<u16>,
    /// `establishmentCause` for the connection request (mo-Signalling = 3).
    pub establishment_cause: u8,
    /// 39-bit random UE identity (None → derived from the clock).
    pub ue_random_id: Option<u64>,
    /// T300 (ms).
    pub t300_ms: u32,
    /// Transmit lead for MAC/PHY (slots).
    pub tx_lead_slots: u16,
    pub numerology_hint: Option<Numerology>,
}

impl Default for RrcConfig {
    fn default() -> Self {
        Self { bands: vec![3, 78], establishment_cause: 3, ue_random_id: None, t300_ms: 1000, tx_lead_slots: 3, numerology_hint: None }
    }
}

/// The UE RRC entity.
pub struct RrcUe {
    pub cfg: RrcConfig,
    pub state: RrcState,
    events: Vec<RrcEvent>,
    cell: Option<derive::CellInfo>,
    /// The RRCSetupRequest CCCH SDU (for contention resolution / re-tries).
    setup_request: Option<[u8; 6]>,
    pending_nas: Option<Vec<u8>>,
    /// SecurityModeCommand awaiting verification: (transaction id, PDCP PDU).
    pending_smc: Option<(u8, u8, u8)>,
    k_gnb: Option<[u8; 32]>,
    security: Option<AsSecurity>,
    bearers: Bearers,
    t300_expiry: Option<SlotPoint>,
    /// The 5G-S-TMSI from the NAS registration (for paging and the
    /// RRCSetupRequest identity).
    s_tmsi: Option<u64>,
    /// `true` when the current connection request used `ng-5G-S-TMSI-Part1`.
    setup_used_s_tmsi: bool,
    /// C-RNTI of the current connection (from the random access).
    c_rnti: Option<u16>,
    t301_expiry: Option<SlotPoint>,
    /// Transaction id of the RRCReestablishment awaiting verification.
    pending_reest: Option<u8>,
    /// Measurement configuration and reporting (§5.5).
    pub meas: meas::MeasProcedure,
    /// Other system information acquired so far, by SIB type (§5.2.2.3).
    pub sibs: std::collections::BTreeMap<u8, ferrite_asn1::si::Sib>,
    pub stats: RrcStats,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RrcStats {
    pub dl_dcch: u64,
    pub ul_dcch: u64,
    pub reconfigurations: u64,
    pub meas_reports: u64,
    pub reestablishments: u64,
}

impl RrcUe {
    pub fn new(cfg: RrcConfig) -> Self {
        Self {
            cfg,
            state: RrcState::Idle,
            events: Vec::new(),
            cell: None,
            setup_request: None,
            pending_nas: None,
            pending_smc: None,
            k_gnb: None,
            security: None,
            bearers: Bearers::default(),
            t300_expiry: None,
            s_tmsi: None,
            setup_used_s_tmsi: false,
            c_rnti: None,
            t301_expiry: None,
            pending_reest: None,
            meas: meas::MeasProcedure::default(),
            sibs: std::collections::BTreeMap::new(),
            stats: RrcStats::default(),
        }
    }

    pub fn take_events(&mut self) -> Vec<RrcEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn cell(&self) -> Option<&derive::CellInfo> {
        self.cell.as_ref()
    }

    /// A BCCH transport block decoded by the PHY (SIB1 until the cell is
    /// known, then the other SI messages), with the MIB-derived facts.
    pub fn on_bcch(&mut self, tb: &[u8], mib: &derive::MibInfo, radio: &derive::RadioInfo) {
        if self.cell.is_some() {
            // BCCH-DL-SCH c1: bit 1 of the first octet set = SIB1 (repeats).
            if tb.first().is_some_and(|b| b & 0x40 != 0) {
                return;
            }
            match ferrite_asn1::si::SystemInformation::decode(tb) {
                Ok(si) => {
                    for sib in si.sibs {
                        let t = sib.sib_type();
                        let changed = self.sibs.get(&t) != Some(&sib);
                        if changed {
                            log::info!("acquired SIB{t}: {sib:?}");
                            self.sibs.insert(t, sib);
                        }
                    }
                }
                Err(e) => log::debug!("SI message not decoded: {e}"),
            }
            return;
        }
        match derive::cell_from_sib1(tb, mib, radio, self.cfg.tx_lead_slots) {
            Ok(info) => {
                if !info.si_scheduled.is_empty() {
                    log::info!("SI scheduling: SIB{:?} broadcast, SI window {} slots", info.si_scheduled, info.si_window_slots);
                }
                let (phy, mac) = (info.phy.clone(), info.mac.clone());
                self.events.push(RrcEvent::CellConfigured {
                    phy: Box::new(phy),
                    mac: Box::new(mac),
                    plmn: info.plmn.clone(),
                    tac: info.tac,
                    cell_id: info.cell_identity,
                });
                self.cell = Some(info);
            }
            Err(e) => log::warn!("SIB1 rejected: {e}"),
        }
    }

    /// The NAS-assigned 5G-S-TMSI (48 bits), or `None` once it is lost.
    pub fn set_s_tmsi(&mut self, s_tmsi: Option<u64>) {
        self.s_tmsi = s_tmsi;
    }

    /// NAS asks for a connection carrying `nas_pdu` in RRCSetupComplete (§5.3.3.2),
    /// with the configured establishment cause (initial registration).
    pub fn connect(&mut self, nas_pdu: Vec<u8>, now: SlotPoint) {
        self.connect_for(nas_pdu, now, self.cfg.establishment_cause);
    }

    /// Connection request with an explicit `establishmentCause` (service
    /// request: mo-Data = 4, mt-Access = 2). Uses the 5G-S-TMSI as the UE
    /// identity when it is known.
    pub fn connect_for(&mut self, nas_pdu: Vec<u8>, now: SlotPoint, cause: u8) {
        if self.state != RrcState::Idle || self.cell.is_none() {
            return;
        }
        let id = self.cfg.ue_random_id.unwrap_or_else(|| {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0x5eed);
            t.wrapping_mul(0x9E37_79B9_7F4A_7C15) & ((1 << 39) - 1)
        });
        self.setup_used_s_tmsi = self.s_tmsi.is_some();
        let ccch = derive::encode_setup_request(id, self.s_tmsi, cause);
        self.setup_request = Some(ccch);
        self.pending_nas = Some(nas_pdu);
        self.state = RrcState::Connecting;
        let t300 = self.cell.as_ref().map_or(self.cfg.t300_ms, |c| c.t300_ms);
        let slots = t300 * now.numerology.slots_per_subframe();
        self.t300_expiry = Some(now.add(slots as u64));
        self.events.push(RrcEvent::StartRa { ccch });
    }

    pub fn on_mac(&mut self, n: MacNotification) {
        match n {
            MacNotification::RaSucceeded { c_rnti } => self.c_rnti = Some(c_rnti),
            MacNotification::RaFailed => {
                if self.state == RrcState::Connecting {
                    self.state = RrcState::Idle;
                    self.events.push(RrcEvent::Failed("random access failed"));
                } else if self.state == RrcState::Reestablishing {
                    self.abort_reestablishment("random access failed during re-establishment");
                }
            }
            MacNotification::RadioLinkFailure => {
                if self.state == RrcState::Connected {
                    self.start_reestablishment();
                }
            }
        }
    }

    /// §5.3.7.2: on RLF with AS security active, request a re-establishment
    /// (RRCReestablishmentRequest on SRB0 with the shortMAC-I of the current
    /// context); without security the connection is simply lost.
    fn start_reestablishment(&mut self) {
        let (Some(sec), Some(c_rnti), Some(cell)) = (self.security, self.c_rnti, self.cell.as_ref()) else {
            self.meas.clear();
            self.events.push(RrcEvent::Failed("radio link failure"));
            return;
        };
        let pci = cell.phy.ssb.pci;
        let smac = derive::short_mac_i(&sec.k_rrc_int, sec.integrity_alg, pci, cell.cell_identity, c_rnti);
        let ccch = derive::encode_reestablishment_request(c_rnti, pci, smac, 2);
        let (common_phy, common_mac) = (cell.common_phy.clone(), cell.common_mac.clone());
        log::info!("radio link failure: RRC re-establishment (C-RNTI {c_rnti:#x}, PCI {pci}, shortMAC-I {smac:#06x})");
        self.stats.reestablishments += 1;
        self.state = RrcState::Reestablishing;
        self.pending_reest = None;
        self.t301_expiry = None;
        // §5.3.7.4: back to the default L1/MAC (common) configuration — the
        // dedicated resources belonged to the old context (no SR resources,
        // so the complete goes out through a C-RNTI random access; HARQ-ACK on
        // the common PUCCH). The later RRCReconfiguration applies the new
        // dedicated configuration on top of this baseline.
        if let Some(c) = self.cell.as_mut() {
            c.phy = common_phy.clone();
            c.mac = common_mac.clone();
        }
        self.events.push(RrcEvent::Reestablishing);
        self.events.push(RrcEvent::Reconfigure { phy: Box::new(common_phy), mac: Box::new(common_mac) });
        self.events.push(RrcEvent::StartRa { ccch });
    }

    /// T301 must be armed by the stack's slot clock: called when the request is
    /// sent (the stack does it on `StartRa` while re-establishing).
    pub fn arm_t301(&mut self, now: SlotPoint) {
        let t301 = self.cell.as_ref().map_or(1000, |c| c.t301_ms);
        self.t301_expiry = Some(now.add(u64::from(t301 * now.numerology.slots_per_subframe())));
    }

    fn abort_reestablishment(&mut self, why: &'static str) {
        self.state = RrcState::Idle;
        self.t301_expiry = None;
        self.pending_reest = None;
        self.security = None;
        self.bearers = Bearers::default();
        self.meas.clear();
        self.events.push(RrcEvent::Failed(why));
    }

    /// The stack verified (or not) the RRCReestablishment MAC-I with the new keys.
    pub fn reestablishment_verified(&mut self, ok: bool) {
        let Some(tid) = self.pending_reest.take() else { return };
        if !ok {
            self.abort_reestablishment("RRCReestablishment integrity check failed");
            return;
        }
        self.state = RrcState::Connected;
        self.t301_expiry = None;
        self.bearers = Bearers { srb1: true, ..Bearers::default() };
        self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_reestablishment_complete(tid) });
        self.events.push(RrcEvent::Reestablished);
        log::info!("RRC re-established");
    }

    pub fn tick(&mut self, now: SlotPoint) {
        if let Some(t) = self.t300_expiry {
            if self.state == RrcState::Connecting && now.diff(&t) >= 0 {
                self.t300_expiry = None;
                self.state = RrcState::Idle;
                self.events.push(RrcEvent::Failed("T300 expired"));
            }
        }
        if self.state == RrcState::Connected {
            self.meas.tick(now);
            self.send_measurement_reports();
        }
        if let Some(t) = self.t301_expiry {
            if self.state == RrcState::Reestablishing && now.diff(&t) >= 0 {
                self.abort_reestablishment("T301 expired");
            }
        }
    }

    /// A serving-cell SSB measurement from the PHY (§5.5.3).
    pub fn on_measurement(&mut self, now: SlotPoint, m: &meas::CellMeasurement) {
        if self.state != RrcState::Connected {
            return;
        }
        self.meas.on_serving_measurement(now, m);
        self.send_measurement_reports();
    }

    fn send_measurement_reports(&mut self) {
        for r in self.meas.take_reports() {
            log::info!("MeasurementReport: measId {} serving {:?}", r.meas_id, r.serving.first().map(|s| s.serving_cell.results_ssb_cell));
            self.stats.meas_reports += 1;
            self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_measurement_report(&r) });
        }
    }

    /// A DL-CCCH PDU (Msg4: RRCSetup / RRCReject), §5.3.3.4.
    pub fn on_dl_ccch(&mut self, pdu: &[u8]) {
        let Some(cell) = self.cell.as_ref() else { return };
        match derive::decode_dl_ccch(pdu, cell, self.cfg.tx_lead_slots) {
            Ok(derive::DlCcch::Setup { .. }) if self.state == RrcState::Reestablishing => {
                log::warn!("RRCSetup instead of RRCReestablishment: the network fell back; reconnecting");
                self.abort_reestablishment("re-establishment fallback to RRCSetup");
            }
            Ok(derive::DlCcch::Setup { tid, phy, mac, bearers }) => {
                self.t300_expiry = None;
                self.state = RrcState::Connected;
                // The dedicated configuration becomes the baseline later
                // reconfigurations are applied on top of.
                if let Some(c) = self.cell.as_mut() {
                    c.phy = phy.clone();
                    c.mac = mac.clone();
                }
                for b in bearers {
                    if let RbId::Srb(1) = b.rb {
                        self.bearers.srb1 = true;
                    }
                    if let Some(c) = self.cell.as_mut() {
                        c.rlc_bearers.insert(b.lcid, b.rlc.clone());
                    }
                    self.events.push(RrcEvent::SetupBearer(b));
                }
                self.events.push(RrcEvent::Reconfigure { phy: Box::new(phy), mac: Box::new(mac) });
                let nas = self.pending_nas.take().unwrap_or_default();
                let pdu = derive::encode_setup_complete(tid, 1, &nas, self.s_tmsi.filter(|_| self.setup_used_s_tmsi));
                self.events.push(RrcEvent::TxSrb { srb: 1, pdu });
                self.events.push(RrcEvent::Connected);
            }
            Ok(derive::DlCcch::Reject) => {
                self.state = RrcState::Idle;
                self.events.push(RrcEvent::Failed("RRCReject"));
            }
            Err(e) => log::warn!("DL-CCCH decode failed: {e}"),
        }
    }

    /// Remember the K_gNB NAS derived (TS 33.501 A.9) for the AS SMC.
    pub fn set_k_gnb(&mut self, k: [u8; 32]) {
        self.k_gnb = Some(k);
    }

    /// A DL-DCCH RRC PDU (PDCP SDU) on `srb`.
    pub fn on_dl_dcch(&mut self, srb: u8, pdu: &[u8]) {
        self.stats.dl_dcch += 1;
        let Some(cell) = self.cell.as_ref() else { return };
        let msg = match derive::decode_dl_dcch(pdu, cell, self.cfg.tx_lead_slots) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("DL-DCCH decode failed on SRB{srb}: {e}");
                return;
            }
        };
        match msg {
            derive::DlDcch::SecurityModeCommand { tid, integrity_alg, ciphering_alg } => {
                // §5.3.4.3: derive the keys from K_gNB; the stack verifies the MAC-I.
                let Some(k) = self.k_gnb else {
                    log::warn!("SecurityModeCommand before K_gNB is known");
                    self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_security_mode_failure(tid) });
                    return;
                };
                // §5.3.4.3: an algorithm the UE cannot run is a SecurityModeFailure.
                let algs = IntegrityAlg::try_from(integrity_alg).and_then(|i| i.check_supported()).and_then(|i| CipherAlg::try_from(ciphering_alg).and_then(|c| c.check_supported()).map(|c| (i, c)));
                let (ia, ea) = match algs {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!("SecurityModeCommand with NIA{integrity_alg} / NEA{ciphering_alg}: {e}");
                        self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_security_mode_failure(tid) });
                        return;
                    }
                };
                let sec = AsSecurity::derive(&k, ia, ea);
                self.pending_smc = Some((tid, integrity_alg, ciphering_alg));
                self.security = Some(sec);
                self.events.push(RrcEvent::VerifySecurity(sec));
            }
            derive::DlDcch::UeCapabilityEnquiry { tid } => {
                let pdu = derive::encode_ue_capability_information(tid, &self.cfg.bands);
                self.events.push(RrcEvent::TxSrb { srb: 1, pdu });
            }
            derive::DlDcch::Reconfiguration { tid, phy, mac, bearers, released, nas, meas } => {
                self.stats.reconfigurations += 1;
                if let Some(mc) = &meas {
                    self.meas.apply(mc);
                    log::info!("measConfig applied: {} objects, {} report configs, {} measIds", mc.meas_object_to_add_mod_list.len(), mc.report_config_to_add_mod_list.len(), mc.meas_id_to_add_mod_list.len());
                }
                for b in bearers {
                    match b.rb {
                        RbId::Srb(2) => self.bearers.srb2 = true,
                        RbId::Drb(id) => {
                            if !self.bearers.drbs.contains(&id) {
                                self.bearers.drbs.push(id);
                            }
                        }
                        _ => {}
                    }
                    if let Some(c) = self.cell.as_mut() {
                        c.rlc_bearers.insert(b.lcid, b.rlc.clone());
                    }
                    self.events.push(RrcEvent::SetupBearer(b));
                }
                for lcid in released {
                    self.events.push(RrcEvent::ReleaseBearer { lcid });
                }
                if let Some((phy, mac)) = phy.zip(mac) {
                    if let Some(c) = self.cell.as_mut() {
                        c.phy = phy.clone();
                        c.mac = mac.clone();
                    }
                    self.events.push(RrcEvent::Reconfigure { phy: Box::new(phy), mac: Box::new(mac) });
                }
                // Complete first, then hand the NAS PDUs up (§5.3.5.3).
                self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_reconfiguration_complete(tid) });
                for n in nas {
                    self.events.push(RrcEvent::DlNas(n));
                }
            }
            derive::DlDcch::DlInformationTransfer { nas } => {
                if let Some(n) = nas {
                    self.events.push(RrcEvent::DlNas(n));
                }
            }
            derive::DlDcch::Reestablishment { tid, ncc } => {
                if self.state != RrcState::Reestablishing {
                    log::warn!("RRCReestablishment while {:?}: ignored", self.state);
                    return;
                }
                let (Some(k), Some(old), Some(cell)) = (self.k_gnb, self.security, self.cell.as_ref()) else {
                    self.abort_reestablishment("RRCReestablishment without a security context");
                    return;
                };
                if ncc != 0 {
                    log::warn!("RRCReestablishment with nextHopChainingCount {ncc}: vertical key derivation not supported, using horizontal");
                }
                // §5.3.7.5 / TS 33.501 §6.11: K_NG-RAN* from the current K_gNB,
                // then fresh RRC/UP keys with the configured algorithms.
                let k_star = derive::k_ng_ran_star(&k, cell.phy.ssb.pci, cell.ssb_arfcn);
                let sec = AsSecurity::derive(&k_star, old.integrity_alg, old.ciphering_alg);
                self.k_gnb = Some(k_star);
                self.security = Some(sec);
                self.pending_reest = Some(tid);
                self.events.push(RrcEvent::VerifyReestablishment(sec));
            }
            derive::DlDcch::Release => {
                self.state = RrcState::Idle;
                self.security = None;
                self.bearers = Bearers::default();
                self.meas.clear();
                self.events.push(RrcEvent::Released);
            }
            derive::DlDcch::Other(name) => log::info!("DL-DCCH {name} ignored"),
        }
    }

    /// A PCCH PDU (Paging) decoded with the P-RNTI (§5.3.2.3).
    pub fn on_pcch(&mut self, pdu: &[u8]) {
        if self.state != RrcState::Idle {
            return;
        }
        match ferrite_asn1::rrc::PagingMessage::decode(pdu) {
            Ok(m) => {
                let mine = self.s_tmsi.is_some_and(|mine| m.records.iter().any(|r| matches!(r, ferrite_asn1::rrc::PagingUeIdentity::Ng5gSTmsi(v) if *v == mine)));
                log::info!("Paging: {} record(s){}", m.records.len(), if mine { ", this UE" } else { "" });
                if mine {
                    self.events.push(RrcEvent::Paged);
                }
            }
            Err(e) => log::warn!("PCCH decode failed: {e}"),
        }
    }

    /// The stack verified (or not) the pending SecurityModeCommand.
    pub fn security_verified(&mut self, ok: bool) {
        let Some((tid, _, _)) = self.pending_smc.take() else { return };
        let pdu = if ok { derive::encode_security_mode_complete(tid) } else { derive::encode_security_mode_failure(tid) };
        if !ok {
            self.security = None;
        }
        self.events.push(RrcEvent::TxSrb { srb: 1, pdu });
    }

    /// NAS wants to send a PDU (ULInformationTransfer, §5.7.2).
    pub fn send_nas(&mut self, nas: &[u8]) {
        if self.state != RrcState::Connected {
            log::warn!("NAS PDU dropped: not connected");
            return;
        }
        self.stats.ul_dcch += 1;
        self.events.push(RrcEvent::TxSrb { srb: 1, pdu: derive::encode_ul_information_transfer(nas) });
    }

    pub fn security(&self) -> Option<&AsSecurity> {
        self.security.as_ref()
    }
}
