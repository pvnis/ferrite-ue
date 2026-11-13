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
//! transfer (§5.7.2), release (§5.3.8). RRC never touches ASN.1 bits itself
//! outside `ferrite_asn1`, and never touches the lower layers directly: it
//! emits [`RrcEvent`]s the stack applies.

#![forbid(unsafe_code)]

pub mod codec;
pub mod derive;

use ferrite_common::{Numerology, SlotPoint};
use ferrite_l1::config::PhyConfig;
use ferrite_mac::MacConfig;

/// RRC states (§4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RrcState {
    Idle,
    Connecting,
    Connected,
}

/// AS security configuration requested by a SecurityModeCommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsSecurity {
    /// NIA / NEA algorithm identifiers (0..3).
    pub integrity_alg: u8,
    pub ciphering_alg: u8,
    pub k_rrc_int: [u8; 16],
    pub k_rrc_enc: [u8; 16],
    pub k_up_int: [u8; 16],
    pub k_up_enc: [u8; 16],
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
    pub stats: RrcStats,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RrcStats {
    pub dl_dcch: u64,
    pub ul_dcch: u64,
    pub reconfigurations: u64,
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
            stats: RrcStats::default(),
        }
    }

    pub fn take_events(&mut self) -> Vec<RrcEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn cell(&self) -> Option<&derive::CellInfo> {
        self.cell.as_ref()
    }

    /// A BCCH transport block (SIB1) decoded by the PHY, with the MIB-derived facts.
    pub fn on_bcch(&mut self, tb: &[u8], mib: &derive::MibInfo, radio: &derive::RadioInfo) {
        if self.cell.is_some() {
            return;
        }
        match derive::cell_from_sib1(tb, mib, radio, self.cfg.tx_lead_slots) {
            Ok(info) => {
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

    /// NAS asks for a connection carrying `nas_pdu` in RRCSetupComplete (§5.3.3.2).
    pub fn connect(&mut self, nas_pdu: Vec<u8>, now: SlotPoint) {
        if self.state != RrcState::Idle || self.cell.is_none() {
            return;
        }
        let id = self.cfg.ue_random_id.unwrap_or_else(|| {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0x5eed);
            t.wrapping_mul(0x9E37_79B9_7F4A_7C15) & ((1 << 39) - 1)
        });
        let ccch = derive::encode_setup_request(id, self.cfg.establishment_cause);
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
            MacNotification::RaSucceeded { .. } => {}
            MacNotification::RaFailed => {
                if self.state == RrcState::Connecting {
                    self.state = RrcState::Idle;
                    self.events.push(RrcEvent::Failed("random access failed"));
                }
            }
            MacNotification::RadioLinkFailure => {
                if self.state == RrcState::Connected {
                    self.events.push(RrcEvent::Failed("radio link failure"));
                }
            }
        }
    }

    pub fn tick(&mut self, now: SlotPoint) {
        if let Some(t) = self.t300_expiry {
            if self.state == RrcState::Connecting && now.diff(&t) >= 0 {
                self.t300_expiry = None;
                self.state = RrcState::Idle;
                self.events.push(RrcEvent::Failed("T300 expired"));
            }
        }
    }

    /// A DL-CCCH PDU (Msg4: RRCSetup / RRCReject), §5.3.3.4.
    pub fn on_dl_ccch(&mut self, pdu: &[u8]) {
        let Some(cell) = self.cell.as_ref() else { return };
        match derive::decode_dl_ccch(pdu, cell, self.cfg.tx_lead_slots) {
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
                    self.events.push(RrcEvent::SetupBearer(b));
                }
                self.events.push(RrcEvent::Reconfigure { phy: Box::new(phy), mac: Box::new(mac) });
                let nas = self.pending_nas.take().unwrap_or_default();
                let pdu = derive::encode_setup_complete(tid, 1, &nas);
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
                let sec = AsSecurity {
                    integrity_alg,
                    ciphering_alg,
                    k_rrc_int: derive::algo_key(&k, 4, integrity_alg),
                    k_rrc_enc: derive::algo_key(&k, 3, ciphering_alg),
                    k_up_int: derive::algo_key(&k, 2, integrity_alg),
                    k_up_enc: derive::algo_key(&k, 1, ciphering_alg),
                };
                self.pending_smc = Some((tid, integrity_alg, ciphering_alg));
                self.security = Some(sec);
                self.events.push(RrcEvent::VerifySecurity(sec));
            }
            derive::DlDcch::UeCapabilityEnquiry { tid } => {
                let pdu = derive::encode_ue_capability_information(tid, &self.cfg.bands);
                self.events.push(RrcEvent::TxSrb { srb: 1, pdu });
            }
            derive::DlDcch::Reconfiguration { tid, phy, mac, bearers, released, nas } => {
                self.stats.reconfigurations += 1;
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
            derive::DlDcch::Release => {
                self.state = RrcState::Idle;
                self.security = None;
                self.bearers = Bearers::default();
                self.events.push(RrcEvent::Released);
            }
            derive::DlDcch::Other(name) => log::info!("DL-DCCH {name} ignored"),
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
