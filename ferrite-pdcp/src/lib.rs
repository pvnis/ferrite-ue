//! PDCP (TS 38.323) for the Ferrite 5G NR UE, plus the AS security algorithms
//! of TS 33.501 Annex D in `ferrite_security`.
//!
//! [`PdcpEntity`] is one PDCP entity (one per radio bearer, TS 38.323 §4.2.2)
//! modelled as a pure state machine: no I/O, no threads, time arrives as a
//! [`SlotPoint`]. It implements
//!
//! * the transmit procedure (§5.2.1): COUNT allocation, SDAP header insertion
//!   (TS 37.324 §6.2.2), integrity protection (§5.9) and ciphering (§5.8), the
//!   discard timer (§5.3);
//! * the receive procedure (§5.2.2): HFN inference from RX_DELIV, deciphering,
//!   integrity verification, duplicate discard, reordering with `t-Reordering`
//!   (§5.2.2.1 / §5.2.2.2) and in-order delivery;
//! * the Data PDU formats of §6.2.2 (SRB: 12-bit SN + MAC-I; DRB: 12/18-bit SN,
//!   optional MAC-I) and recognition of Control PDUs (§6.2.3); status report
//!   construction (§5.4.1).
//!
//! RRC owns the keys: it calls [`PdcpEntity::configure_security`] once the
//! SecurityModeCommand has been verified (via [`PdcpEntity::verify_only`]) and
//! uses the ciphering switches to send the SecurityModeComplete integrity
//! protected but unciphered (TS 38.331 §5.3.4.3).

#![forbid(unsafe_code)]

use ferrite_common::{Numerology, SlotPoint};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

/// PDCP SN length (TS 38.323 §6.3.2): 12 bits for SRBs and optionally DRBs,
/// 18 bits for DRBs only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnLen {
    Len12,
    Len18,
}

impl SnLen {
    /// Number of SN bits.
    pub const fn bits(self) -> u32 {
        match self {
            SnLen::Len12 => 12,
            SnLen::Len18 => 18,
        }
    }

    /// `2^SN_len`.
    pub const fn modulus(self) -> u32 {
        1 << self.bits()
    }

    /// SN bit mask.
    pub const fn mask(self) -> u32 {
        self.modulus() - 1
    }

    /// `Window_Size = 2^(SN_len − 1)` (TS 38.323 §7.2).
    pub const fn window(self) -> u32 {
        1 << (self.bits() - 1)
    }

    /// Data PDU header length in octets (TS 38.323 §6.2.2).
    pub const fn header_len(self) -> usize {
        match self {
            SnLen::Len12 => 2,
            SnLen::Len18 => 3,
        }
    }
}

/// Radio bearer kind (TS 38.323 §4.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RbType {
    Srb,
    Drb,
}

pub use ferrite_security::{CipherAlg, IntegrityAlg};

/// Algorithms and keys for one bearer. For SRBs these are `K_RRCint` /
/// `K_RRCenc`, for DRBs `K_UPint` / `K_UPenc` (TS 33.501 §6.2.1). `None`
/// means the function is not configured (equivalent to the null algorithm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityConfig {
    pub integrity: Option<(IntegrityAlg, [u8; 16])>,
    pub cipher: Option<(CipherAlg, [u8; 16])>,
}

/// Static configuration of a PDCP entity (TS 38.331 `PDCP-Config` /
/// `SDAP-Config`, applied by RRC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdcpConfig {
    pub rb: RbType,
    /// 5-bit BEARER input to the security algorithms: the RB identity minus one
    /// (TS 38.323 §5.8/§5.9), i.e. `srb-Identity − 1` or `drb-Identity − 1`.
    pub bearer_id: u8,
    /// SN length; forced to 12 bits for SRBs (TS 38.323 §6.3.2).
    pub sn_len: SnLen,
    /// `t-Reordering` in ms; `None` = infinity (never deliver across a gap).
    pub t_reordering_ms: Option<u32>,
    /// `discardTimer` in ms; `None` = infinity.
    pub discard_timer_ms: Option<u32>,
    /// `integrityProtection` for DRBs: MAC-I present on DRB PDUs. Ignored for
    /// SRBs, which always carry a MAC-I.
    pub integrity_on_drb: bool,
    /// `sdap-HeaderUL = present` (TS 37.324 §5.2.1): add a 1-octet SDAP header
    /// to uplink SDUs. DRBs only.
    pub sdap_header_ul: bool,
    /// `sdap-HeaderDL = present`: downlink PDUs carry a 1-octet SDAP header to
    /// strip. DRBs only.
    pub sdap_header_dl: bool,
    /// QoS flow identifier written into the uplink SDAP header (6 bits).
    pub qfi: u8,
}

impl PdcpConfig {
    /// SRB defaults (TS 38.331 §9.2.1 / TS 38.323 §7.1): 12-bit SN, integrity
    /// always present, `t-Reordering` infinity, no discard timer, no SDAP.
    pub fn srb(srb_id: u8) -> Self {
        Self {
            rb: RbType::Srb,
            bearer_id: srb_id.saturating_sub(1),
            sn_len: SnLen::Len12,
            t_reordering_ms: None,
            discard_timer_ms: None,
            integrity_on_drb: false,
            sdap_header_ul: false,
            sdap_header_dl: false,
            qfi: 0,
        }
    }

    /// DRB with the given SN length, no integrity, `t-Reordering` 100 ms,
    /// no discard timer, no SDAP headers, QFI 1.
    pub fn drb(drb_id: u8, sn_len: SnLen) -> Self {
        Self {
            rb: RbType::Drb,
            bearer_id: drb_id.saturating_sub(1),
            sn_len,
            t_reordering_ms: Some(100),
            discard_timer_ms: None,
            integrity_on_drb: false,
            sdap_header_ul: false,
            sdap_header_dl: false,
            qfi: 1,
        }
    }
}

/// Which end of the radio link the entity sits on. Determines the `DIRECTION`
/// input to the security algorithms (0 = uplink, 1 = downlink, TS 33.501
/// D.2.1.1) and which SDAP-header setting applies to each direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Transmits uplink, receives downlink (the normal case).
    Ue,
    /// Transmits downlink, receives uplink. For peer entities in tests and
    /// simulations.
    Network,
}

/// Errors reported by a PDCP entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdcpError {
    /// Algorithm or feature not implemented.
    Unsupported(&'static str),
    /// A PDU shorter than its header/MAC-I layout requires.
    TooShort { needed: usize, got: usize },
    /// Integrity verification failed (TS 38.323 §5.2.2.1): the PDU is
    /// discarded and upper layers must be told (for SRBs RRC re-establishes).
    IntegrityFailure { count: u32 },
    /// A PDU whose COUNT is below `RX_DELIV` or already received; discarded
    /// (§5.2.2.1).
    Duplicate { count: u32 },
    /// A Control PDU with an unknown PDU type (§6.3.8); ignored.
    UnknownControlPdu(u8),
}

impl fmt::Display for PdcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdcpError::Unsupported(what) => write!(f, "unsupported: {what}"),
            PdcpError::TooShort { needed, got } => {
                write!(f, "PDU too short: need {needed} octets, got {got}")
            }
            PdcpError::IntegrityFailure { count } => {
                write!(f, "integrity verification failed (COUNT {count})")
            }
            PdcpError::Duplicate { count } => write!(f, "duplicate/stale PDU (COUNT {count})"),
            PdcpError::UnknownControlPdu(t) => write!(f, "unknown control PDU type {t}"),
        }
    }
}

impl std::error::Error for PdcpError {}

/// What a received Control PDU turned out to be (TS 38.323 §6.3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPdu {
    StatusReport,
    RohcFeedback,
    EhcFeedback,
}

/// Running counters for diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdcpStats {
    pub tx_pdus: u64,
    pub rx_pdus: u64,
    pub rx_delivered: u64,
    pub rx_duplicates: u64,
    pub rx_integrity_failures: u64,
    pub rx_malformed: u64,
    pub rx_control_pdus: u64,
    pub t_reordering_expiries: u64,
    pub discarded: u64,
}

/// One PDCP entity (TS 38.323 §4.2.2 / §7.1).
#[derive(Clone, Debug)]
pub struct PdcpEntity {
    cfg: PdcpConfig,
    numerology: Numerology,
    side: Side,

    integrity: Option<(IntegrityAlg, [u8; 16])>,
    cipher: Option<(CipherAlg, [u8; 16])>,
    tx_cipher_enabled: bool,
    rx_cipher_enabled: bool,

    /// COUNT of the next SDU to transmit (§7.1 TX_NEXT).
    tx_next: u32,
    /// COUNT following the highest received (§7.1 RX_NEXT).
    rx_next: u32,
    /// COUNT of the first SDU not yet delivered but still waited for (§7.1 RX_DELIV).
    rx_deliv: u32,
    /// COUNT following the one that triggered `t-Reordering` (§7.1 RX_REORD).
    rx_reord: u32,
    /// Start slot of a running `t-Reordering`, if any.
    t_reordering_start: Option<SlotPoint>,

    /// Received but not yet delivered SDUs, keyed by COUNT (§5.2.2.1 "reception buffer").
    reorder_buf: BTreeMap<u32, Vec<u8>>,
    /// Delivered SDUs awaiting [`PdcpEntity::pop_rx_sdu`].
    delivered: VecDeque<Vec<u8>>,
    /// Running discard timers `(COUNT, start)` in COUNT order (§5.3).
    discard_timers: VecDeque<(u32, SlotPoint)>,
    /// COUNTs whose discard timer expired and have not been collected yet.
    discarded: Vec<u32>,

    stats: PdcpStats,
}

impl PdcpEntity {
    /// A UE-side entity (uplink transmit, downlink receive). State variables
    /// start at zero (TS 38.323 §7.1).
    pub fn new(cfg: PdcpConfig, numerology: Numerology) -> Self {
        Self::with_side(cfg, numerology, Side::Ue)
    }

    /// An entity on the network side of the link: the peer of a UE entity with
    /// the same configuration. Intended for tests and simulations.
    pub fn new_network_side(cfg: PdcpConfig, numerology: Numerology) -> Self {
        Self::with_side(cfg, numerology, Side::Network)
    }

    fn with_side(mut cfg: PdcpConfig, numerology: Numerology, side: Side) -> Self {
        if cfg.rb == RbType::Srb {
            if cfg.sn_len != SnLen::Len12 {
                log::warn!(
                    "pdcp: SRB{} configured with 18-bit SN; forcing 12 (38.323 §6.3.2)",
                    cfg.bearer_id + 1
                );
                cfg.sn_len = SnLen::Len12;
            }
            cfg.sdap_header_ul = false;
            cfg.sdap_header_dl = false;
        }
        cfg.qfi &= 0x3f;
        Self {
            cfg,
            numerology,
            side,
            integrity: None,
            cipher: None,
            tx_cipher_enabled: true,
            rx_cipher_enabled: true,
            tx_next: 0,
            rx_next: 0,
            rx_deliv: 0,
            rx_reord: 0,
            t_reordering_start: None,
            reorder_buf: BTreeMap::new(),
            delivered: VecDeque::new(),
            discard_timers: VecDeque::new(),
            discarded: Vec::new(),
            stats: PdcpStats::default(),
        }
    }

    // ---------------------------------------------------------------- config

    pub fn config(&self) -> &PdcpConfig {
        &self.cfg
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn stats(&self) -> PdcpStats {
        self.stats
    }

    /// Activate integrity protection and ciphering for all subsequent PDUs in
    /// both directions (TS 38.323 §5.8 / §5.9). RRC calls this once the
    /// SecurityModeCommand has been verified (TS 38.331 §5.3.4.3). Both
    /// ciphering switches are turned on; use [`Self::set_tx_cipher_enabled`]
    /// to send the SecurityModeComplete unciphered.
    ///
    /// Fails with [`PdcpError::Unsupported`] for NIA1/NIA3/NEA1/NEA3, leaving
    /// the previous configuration in place.
    pub fn configure_security(&mut self, sec: SecurityConfig) -> Result<(), PdcpError> {
        if let Some((alg, _)) = sec.integrity {
            alg.check_supported()
                .map_err(|_| PdcpError::Unsupported(alg.name()))?;
        }
        if let Some((alg, _)) = sec.cipher {
            alg.check_supported()
                .map_err(|_| PdcpError::Unsupported(alg.name()))?;
        }
        self.integrity = sec.integrity;
        self.cipher = sec.cipher;
        self.tx_cipher_enabled = true;
        self.rx_cipher_enabled = true;
        log::info!(
            "pdcp: {} security: integrity {:?}, cipher {:?}",
            self.rb_name(),
            self.integrity.map(|(a, _)| a),
            self.cipher.map(|(a, _)| a)
        );
        Ok(())
    }

    /// Enable or disable ciphering in both directions while keeping the
    /// configured keys. Integrity protection is unaffected.
    pub fn set_cipher_enabled(&mut self, on: bool) {
        self.tx_cipher_enabled = on;
        self.rx_cipher_enabled = on;
    }

    /// Enable or disable ciphering of transmitted PDUs only. TS 38.331
    /// §5.3.4.3: the SecurityModeComplete is integrity protected but sent
    /// unciphered, ciphering applies from the following message. The intended
    /// sequence is `configure_security`, `set_tx_cipher_enabled(false)`,
    /// `tx_sdu(SecurityModeComplete)`, `set_tx_cipher_enabled(true)`.
    pub fn set_tx_cipher_enabled(&mut self, on: bool) {
        self.tx_cipher_enabled = on;
    }

    /// Enable or disable deciphering of received PDUs only.
    pub fn set_rx_cipher_enabled(&mut self, on: bool) {
        self.rx_cipher_enabled = on;
    }

    pub fn security_configured(&self) -> bool {
        self.integrity.is_some() || self.cipher.is_some()
    }

    // ------------------------------------------------------------- state vars

    /// `TX_NEXT`: the COUNT the next transmitted SDU will get.
    pub fn tx_count(&self) -> u32 {
        self.tx_next
    }

    /// `RX_NEXT`.
    pub fn rx_next(&self) -> u32 {
        self.rx_next
    }

    /// `RX_DELIV`.
    pub fn rx_deliv(&self) -> u32 {
        self.rx_deliv
    }

    /// Whether `t-Reordering` is running.
    pub fn t_reordering_running(&self) -> bool {
        self.t_reordering_start.is_some()
    }

    /// Number of received SDUs held back waiting for a gap to fill.
    pub fn reorder_buffer_len(&self) -> usize {
        self.reorder_buf.len()
    }

    /// PDCP re-establishment for an AM/SRB-style reset of the receive and
    /// transmit state (TS 38.323 §5.1.2, the SRB / "reset" branch): all
    /// state variables to 0, buffers and timers cleared, security kept.
    pub fn reestablish(&mut self) {
        self.tx_next = 0;
        self.rx_next = 0;
        self.rx_deliv = 0;
        self.rx_reord = 0;
        self.t_reordering_start = None;
        self.reorder_buf.clear();
        self.delivered.clear();
        self.discard_timers.clear();
        self.discarded.clear();
    }

    // -------------------------------------------------------------- transmit

    /// Build the PDCP Data PDU for one SDU (TS 38.323 §5.2.1): allocate
    /// `COUNT = TX_NEXT`, add the SDAP header if configured, integrity protect
    /// (header + data), cipher (data + MAC-I), advance `TX_NEXT`. The result is
    /// ready to hand to RLC as an RLC SDU. Starts the discard timer if one is
    /// configured.
    pub fn tx_sdu(&mut self, sdu: &[u8], now: SlotPoint) -> Vec<u8> {
        let count = self.tx_next;
        let sn = count & self.cfg.sn_len.mask();
        let hdr_len = self.header_len();
        let mac_present = self.mac_present();

        let mut pdu = Vec::with_capacity(hdr_len + 1 + sdu.len() + 4);
        self.write_header(&mut pdu, sn);
        if self.tx_sdap_header() {
            // TS 37.324 §6.2.2.3 UL SDAP Data PDU header: D/C(1)=1 | R(1) | QFI(6).
            pdu.push(0x80 | self.cfg.qfi);
        }
        pdu.extend_from_slice(sdu);

        if mac_present {
            let mac = self.compute_mac(count, self.tx_direction(), &pdu);
            pdu.extend_from_slice(&mac);
        }
        if self.tx_cipher_enabled {
            if let Some((alg, key)) = self.cipher {
                // Unsupported algorithms are rejected by `configure_security`.
                let _ = ferrite_security::cipher_in_place(
                    alg,
                    &key,
                    count,
                    self.cfg.bearer_id,
                    self.tx_direction(),
                    &mut pdu[hdr_len..],
                );
            }
        }

        if self.cfg.discard_timer_ms.is_some() {
            self.discard_timers.push_back((count, now));
        }
        self.tx_next = self.tx_next.wrapping_add(1);
        self.stats.tx_pdus += 1;
        log::trace!(
            "pdcp: {} tx COUNT {} ({} B sdu → {} B pdu)",
            self.rb_name(),
            count,
            sdu.len(),
            pdu.len()
        );
        pdu
    }

    /// COUNTs whose `discardTimer` expired since the last call (TS 38.323
    /// §5.3). The caller (RLC glue) may use them to discard the corresponding
    /// RLC SDUs if not yet transmitted (TS 38.322 §5.4).
    pub fn take_discarded(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.discarded)
    }

    // --------------------------------------------------------------- receive

    /// Process one PDCP PDU from RLC (TS 38.323 §5.2.2.1). Data PDUs are
    /// deciphered, integrity verified, duplicate-checked and placed in the
    /// reordering buffer; everything deliverable in order moves to the
    /// [`Self::pop_rx_sdu`] queue. Control PDUs are recognised and ignored.
    ///
    /// Errors mean the PDU was discarded; the entity state is unchanged except
    /// for the statistics.
    pub fn rx_pdu(&mut self, pdu: &[u8], now: SlotPoint) -> Result<(), PdcpError> {
        self.expire_timers(now);
        let first = match pdu.first() {
            Some(&b) => b,
            None => {
                self.stats.rx_malformed += 1;
                return Err(PdcpError::TooShort {
                    needed: self.header_len(),
                    got: 0,
                });
            }
        };
        if self.cfg.rb == RbType::Drb && first & 0x80 == 0 {
            self.stats.rx_control_pdus += 1;
            return Self::classify_control(first).map(|c| {
                log::debug!("pdcp: {} control PDU {:?} ignored", self.rb_name(), c);
            });
        }
        let (count, sdu) = match self.decode_data_pdu(pdu) {
            Ok(x) => x,
            Err(e) => {
                match e {
                    PdcpError::IntegrityFailure { .. } => self.stats.rx_integrity_failures += 1,
                    _ => self.stats.rx_malformed += 1,
                }
                return Err(e);
            }
        };
        self.stats.rx_pdus += 1;

        // §5.2.2.1: discard if COUNT < RX_DELIV or already received.
        if count < self.rx_deliv || self.reorder_buf.contains_key(&count) {
            self.stats.rx_duplicates += 1;
            return Err(PdcpError::Duplicate { count });
        }
        self.reorder_buf.insert(count, sdu);
        if count >= self.rx_next {
            self.rx_next = count.wrapping_add(1);
        }
        if count == self.rx_deliv {
            self.deliver_consecutive_from(self.rx_deliv);
        }
        if self.t_reordering_start.is_some() && self.rx_deliv >= self.rx_reord {
            self.t_reordering_start = None;
        }
        if self.t_reordering_start.is_none() && self.rx_deliv < self.rx_next {
            self.rx_reord = self.rx_next;
            if self.cfg.t_reordering_ms.is_some() {
                self.t_reordering_start = Some(now);
            }
        }
        Ok(())
    }

    /// Next in-order delivered SDU (SDAP header already removed), if any.
    pub fn pop_rx_sdu(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }

    /// Advance timers to `now`: `t-Reordering` expiry (TS 38.323 §5.2.2.2) and
    /// discard timers (§5.3).
    pub fn tick(&mut self, now: SlotPoint) {
        self.expire_timers(now);
    }

    /// Verify a received SRB/DRB Data PDU's MAC-I with a candidate integrity
    /// algorithm and key without touching the entity state. The COUNT is inferred
    /// from the current `RX_DELIV` exactly as [`Self::rx_pdu`] would; the
    /// configured deciphering (if enabled) is applied first. Returns the COUNT
    /// on success. RRC uses this to check a freshly derived `K_RRCint` against
    /// the SecurityModeCommand before activating it.
    pub fn verify_only(&self, pdu: &[u8], alg: IntegrityAlg, key: &[u8; 16]) -> Option<u32> {
        let hdr_len = self.header_len();
        if pdu.len() < hdr_len + 4 {
            return None;
        }
        if self.cfg.rb == RbType::Drb && pdu[0] & 0x80 == 0 {
            return None;
        }
        let sn = self.read_sn(pdu)?;
        let count = self.infer_count(sn);
        let mut body = pdu[hdr_len..].to_vec();
        if self.rx_cipher_enabled {
            if let Some((alg, k)) = self.cipher {
                let _ = ferrite_security::cipher_in_place(
                    alg,
                    &k,
                    count,
                    self.cfg.bearer_id,
                    self.rx_direction(),
                    &mut body,
                );
            }
        }
        let split = body.len() - 4;
        let mut msg = Vec::with_capacity(hdr_len + split);
        msg.extend_from_slice(&pdu[..hdr_len]);
        msg.extend_from_slice(&body[..split]);
        let mac = ferrite_security::integrity_mac(
            alg,
            key,
            count,
            self.cfg.bearer_id,
            self.rx_direction(),
            &msg,
        )
        .ok()?;
        (mac[..] == body[split..]).then_some(count)
    }

    /// Build a PDCP status report Control PDU (TS 38.323 §5.4.1 / §6.2.3.1):
    /// `FMC = RX_DELIV` followed by a bitmap of the COUNTs above it that have
    /// been received (1) or are missing (0), up to the highest received. DRBs
    /// only (`None` for SRBs).
    pub fn build_status_report(&self) -> Option<Vec<u8>> {
        if self.cfg.rb != RbType::Drb {
            return None;
        }
        let fmc = self.rx_deliv;
        let mut out = vec![0x00]; // D/C=0, PDU type 000 (status report), R.
        out.extend_from_slice(&fmc.to_be_bytes());
        if let Some((&highest, _)) = self.reorder_buf.iter().next_back() {
            if highest > fmc {
                let nbits = (highest - fmc) as usize; // bits for FMC+1 .. highest
                let mut bitmap = vec![0u8; nbits.div_ceil(8)];
                for &c in self.reorder_buf.keys() {
                    if c > fmc {
                        let i = (c - fmc - 1) as usize;
                        bitmap[i / 8] |= 0x80 >> (i % 8);
                    }
                }
                out.extend_from_slice(&bitmap);
            }
        }
        Some(out)
    }

    // ------------------------------------------------------------- internals

    fn rb_name(&self) -> String {
        match self.cfg.rb {
            RbType::Srb => format!("SRB{}", self.cfg.bearer_id + 1),
            RbType::Drb => format!("DRB{}", self.cfg.bearer_id + 1),
        }
    }

    fn header_len(&self) -> usize {
        self.cfg.sn_len.header_len()
    }

    /// MAC-I present on Data PDUs: always for SRBs (TS 38.323 §6.3.4), for
    /// DRBs when integrity protection is configured.
    fn mac_present(&self) -> bool {
        self.cfg.rb == RbType::Srb || self.cfg.integrity_on_drb
    }

    fn tx_direction(&self) -> u8 {
        match self.side {
            Side::Ue => 0,
            Side::Network => 1,
        }
    }

    fn rx_direction(&self) -> u8 {
        1 - self.tx_direction()
    }

    fn tx_sdap_header(&self) -> bool {
        self.cfg.rb == RbType::Drb
            && match self.side {
                Side::Ue => self.cfg.sdap_header_ul,
                Side::Network => self.cfg.sdap_header_dl,
            }
    }

    fn rx_sdap_header(&self) -> bool {
        self.cfg.rb == RbType::Drb
            && match self.side {
                Side::Ue => self.cfg.sdap_header_dl,
                Side::Network => self.cfg.sdap_header_ul,
            }
    }

    /// Data PDU header (TS 38.323 §6.2.2.1–§6.2.2.3).
    fn write_header(&self, pdu: &mut Vec<u8>, sn: u32) {
        let dc = if self.cfg.rb == RbType::Drb {
            0x80
        } else {
            0x00
        };
        match self.cfg.sn_len {
            SnLen::Len12 => {
                pdu.push(dc | ((sn >> 8) & 0x0f) as u8);
                pdu.push((sn & 0xff) as u8);
            }
            SnLen::Len18 => {
                pdu.push(dc | ((sn >> 16) & 0x03) as u8);
                pdu.push(((sn >> 8) & 0xff) as u8);
                pdu.push((sn & 0xff) as u8);
            }
        }
    }

    fn read_sn(&self, pdu: &[u8]) -> Option<u32> {
        match self.cfg.sn_len {
            SnLen::Len12 => Some(((*pdu.first()? as u32 & 0x0f) << 8) | *pdu.get(1)? as u32),
            SnLen::Len18 => Some(
                ((*pdu.first()? as u32 & 0x03) << 16)
                    | ((*pdu.get(1)? as u32) << 8)
                    | *pdu.get(2)? as u32,
            ),
        }
    }

    /// HFN inference (TS 38.323 §5.2.2.1):
    /// `RCVD_SN < SN(RX_DELIV) − Window_Size  ⇒ RCVD_HFN = HFN(RX_DELIV) + 1`,
    /// `RCVD_SN ≥ SN(RX_DELIV) + Window_Size  ⇒ RCVD_HFN = HFN(RX_DELIV) − 1`,
    /// otherwise `HFN(RX_DELIV)`.
    fn infer_count(&self, rcvd_sn: u32) -> u32 {
        let bits = self.cfg.sn_len.bits();
        let window = self.cfg.sn_len.window() as i64;
        let sn_deliv = (self.rx_deliv & self.cfg.sn_len.mask()) as i64;
        let hfn_deliv = self.rx_deliv >> bits;
        let hfn_mask = (1u32 << (32 - bits)) - 1;
        let rcvd = rcvd_sn as i64;
        let hfn = if rcvd < sn_deliv - window {
            hfn_deliv.wrapping_add(1)
        } else if rcvd >= sn_deliv + window {
            hfn_deliv.wrapping_sub(1)
        } else {
            hfn_deliv
        } & hfn_mask;
        (hfn << bits) | rcvd_sn
    }

    /// Integrity MAC-I over the (unciphered) header + data (TS 38.323 §5.9).
    /// NIA0 / not configured ⇒ all zeros (TS 33.501 D.3.1.1; §6.3.4 padding).
    fn compute_mac(&self, count: u32, direction: u8, msg: &[u8]) -> [u8; 4] {
        match self.integrity {
            Some((alg, key)) => ferrite_security::integrity_mac(
                alg,
                &key,
                count,
                self.cfg.bearer_id,
                direction,
                msg,
            )
            .unwrap_or([0u8; 4]),
            None => [0u8; 4],
        }
    }

    /// Parse, decipher and verify a Data PDU: returns `(COUNT, SDU)` with the
    /// SDAP header stripped. Pure (no state change).
    fn decode_data_pdu(&self, pdu: &[u8]) -> Result<(u32, Vec<u8>), PdcpError> {
        let hdr_len = self.header_len();
        let mac_len = if self.mac_present() { 4 } else { 0 };
        let min = hdr_len + mac_len + usize::from(self.rx_sdap_header());
        if pdu.len() < min {
            return Err(PdcpError::TooShort {
                needed: min,
                got: pdu.len(),
            });
        }
        let sn = self.read_sn(pdu).ok_or(PdcpError::TooShort {
            needed: hdr_len,
            got: pdu.len(),
        })?;
        let count = self.infer_count(sn);

        let mut body = pdu[hdr_len..].to_vec();
        if self.rx_cipher_enabled {
            if let Some((alg, key)) = self.cipher {
                let _ = ferrite_security::cipher_in_place(
                    alg,
                    &key,
                    count,
                    self.cfg.bearer_id,
                    self.rx_direction(),
                    &mut body,
                );
            }
        }
        if mac_len > 0 {
            let split = body.len() - 4;
            let rx_mac = body.split_off(split);
            if let Some((alg, key)) = self.integrity.filter(|(a, _)| *a != IntegrityAlg::Nia0) {
                let mut msg = Vec::with_capacity(hdr_len + body.len());
                msg.extend_from_slice(&pdu[..hdr_len]);
                msg.extend_from_slice(&body);
                let mac = ferrite_security::integrity_mac(
                    alg,
                    &key,
                    count,
                    self.cfg.bearer_id,
                    self.rx_direction(),
                    &msg,
                )
                .unwrap_or([0u8; 4]);
                if mac[..] != rx_mac[..] {
                    log::warn!(
                        "pdcp: {} integrity failure at COUNT {}",
                        self.rb_name(),
                        count
                    );
                    return Err(PdcpError::IntegrityFailure { count });
                }
            }
        }
        if self.rx_sdap_header() {
            // TS 37.324 §6.2.2.2 DL SDAP Data PDU header: RDI | RQI | QFI(6).
            let h = body.remove(0);
            if h & 0x40 != 0 {
                log::debug!("pdcp: {} SDAP RQI set (QFI {})", self.rb_name(), h & 0x3f);
            }
        }
        Ok((count, body))
    }

    /// Control PDU type field (TS 38.323 §6.3.8).
    fn classify_control(first: u8) -> Result<ControlPdu, PdcpError> {
        match (first >> 4) & 0x07 {
            0 => Ok(ControlPdu::StatusReport),
            1 => Ok(ControlPdu::RohcFeedback),
            2 => Ok(ControlPdu::EhcFeedback),
            t => Err(PdcpError::UnknownControlPdu(t)),
        }
    }

    /// Deliver all stored SDUs with consecutive COUNTs starting at `from`, and
    /// set `RX_DELIV` to the first COUNT not delivered (§5.2.2.1).
    fn deliver_consecutive_from(&mut self, from: u32) {
        let mut c = from;
        while let Some(sdu) = self.reorder_buf.remove(&c) {
            self.delivered.push_back(sdu);
            self.stats.rx_delivered += 1;
            c = c.wrapping_add(1);
        }
        self.rx_deliv = c;
    }

    fn ms_to_slots(&self, ms: u32) -> i64 {
        ms as i64 * self.numerology.slots_per_subframe() as i64
    }

    fn expire_timers(&mut self, now: SlotPoint) {
        // t-Reordering expiry (TS 38.323 §5.2.2.2).
        if let (Some(start), Some(ms)) = (self.t_reordering_start, self.cfg.t_reordering_ms) {
            if now.diff(&start) >= self.ms_to_slots(ms) {
                self.t_reordering_start = None;
                self.stats.t_reordering_expiries += 1;
                log::debug!(
                    "pdcp: {} t-Reordering expired: RX_DELIV {} → RX_REORD {}",
                    self.rb_name(),
                    self.rx_deliv,
                    self.rx_reord
                );
                // Deliver everything below RX_REORD (in COUNT order), then the
                // consecutive run from RX_REORD.
                let below: Vec<u32> = self
                    .reorder_buf
                    .range(..self.rx_reord)
                    .map(|(&c, _)| c)
                    .collect();
                for c in below {
                    if let Some(sdu) = self.reorder_buf.remove(&c) {
                        self.delivered.push_back(sdu);
                        self.stats.rx_delivered += 1;
                    }
                }
                self.deliver_consecutive_from(self.rx_reord);
                if self.rx_deliv < self.rx_next {
                    self.rx_reord = self.rx_next;
                    self.t_reordering_start = Some(now);
                }
            }
        }
        // discardTimer (TS 38.323 §5.3). Timers were started in COUNT order so
        // the queue front is always the oldest.
        if let Some(ms) = self.cfg.discard_timer_ms {
            let dur = self.ms_to_slots(ms);
            while let Some(&(count, start)) = self.discard_timers.front() {
                if now.diff(&start) >= dur {
                    self.discard_timers.pop_front();
                    self.discarded.push(count);
                    self.stats.discarded += 1;
                } else {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MU: Numerology = Numerology::KHZ30;
    const K_INT: [u8; 16] = [0x11; 16];
    const K_ENC: [u8; 16] = [0x22; 16];

    fn t(ms: u32) -> SlotPoint {
        SlotPoint::from_index(MU, ms as u64 * MU.slots_per_subframe() as u64)
    }

    fn full_security() -> SecurityConfig {
        SecurityConfig {
            integrity: Some((IntegrityAlg::Nia2, K_INT)),
            cipher: Some((CipherAlg::Nea2, K_ENC)),
        }
    }

    /// A UE entity and its network-side peer with identical configuration.
    fn pair(cfg: PdcpConfig, sec: Option<SecurityConfig>) -> (PdcpEntity, PdcpEntity) {
        let mut ue = PdcpEntity::new(cfg.clone(), MU);
        let mut nw = PdcpEntity::new_network_side(cfg, MU);
        if let Some(s) = sec {
            ue.configure_security(s.clone()).unwrap();
            nw.configure_security(s).unwrap();
        }
        (ue, nw)
    }

    // ------------------------------------------------------------ formats

    #[test]
    fn srb_pdu_format_without_security() {
        let mut ue = PdcpEntity::new(PdcpConfig::srb(1), MU);
        let pdu = ue.tx_sdu(&[0xaa, 0xbb], t(0));
        // R|R|R|R|SN(4) ; SN(8) ; data ; MAC-I = 0 (38.323 §6.2.2.1, §6.3.4).
        assert_eq!(pdu, vec![0x00, 0x00, 0xaa, 0xbb, 0, 0, 0, 0]);
        let pdu = ue.tx_sdu(&[0xcc], t(0));
        assert_eq!(pdu[..2], [0x00, 0x01]);
        assert_eq!(ue.tx_count(), 2);
    }

    #[test]
    fn drb_pdu_formats() {
        let mut d12 = PdcpEntity::new(PdcpConfig::drb(1, SnLen::Len12), MU);
        let pdu = d12.tx_sdu(&[0x01], t(0));
        assert_eq!(pdu, vec![0x80, 0x00, 0x01]); // D/C=1, no MAC-I
        let mut d18 = PdcpEntity::new(PdcpConfig::drb(2, SnLen::Len18), MU);
        d18.tx_next = 0x3_ABCD; // 18-bit SN 0x3ABCD
        let pdu = d18.tx_sdu(&[0x02], t(0));
        assert_eq!(pdu, vec![0x80 | 0x03, 0xab, 0xcd, 0x02]);
        let mut d18i = PdcpEntity::new(
            PdcpConfig {
                integrity_on_drb: true,
                ..PdcpConfig::drb(2, SnLen::Len18)
            },
            MU,
        );
        let pdu = d18i.tx_sdu(&[0x02], t(0));
        assert_eq!(pdu.len(), 3 + 1 + 4);
    }

    #[test]
    fn srb_forces_12_bit_sn() {
        let cfg = PdcpConfig {
            sn_len: SnLen::Len18,
            ..PdcpConfig::srb(2)
        };
        let e = PdcpEntity::new(cfg, MU);
        assert_eq!(e.config().sn_len, SnLen::Len12);
        assert_eq!(e.config().bearer_id, 1);
    }

    // ----------------------------------------------------------- security

    #[test]
    fn srb_integrity_and_cipher_round_trip() {
        let (mut ue, mut nw) = pair(PdcpConfig::srb(1), Some(full_security()));
        let msg = b"RRCSetupComplete".to_vec();
        let pdu = ue.tx_sdu(&msg, t(0));
        assert_eq!(pdu.len(), 2 + msg.len() + 4);
        // Ciphered: payload must not appear in clear.
        assert_ne!(&pdu[2..2 + msg.len()], &msg[..]);
        nw.rx_pdu(&pdu, t(0)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), msg);
        assert_eq!(nw.pop_rx_sdu(), None);
        assert_eq!(nw.rx_next(), 1);
        assert_eq!(nw.rx_deliv(), 1);

        // Downlink direction too (different DIRECTION input).
        let dl = nw.tx_sdu(b"RRCReconfiguration", t(1));
        ue.rx_pdu(&dl, t(1)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), b"RRCReconfiguration");
    }

    #[test]
    fn srb_integrity_failure_detected() {
        let (mut ue, mut nw) = pair(PdcpConfig::srb(1), Some(full_security()));
        let mut pdu = ue.tx_sdu(b"hello", t(0));
        pdu[3] ^= 0x01; // flip a ciphertext bit
        assert_eq!(
            nw.rx_pdu(&pdu, t(0)),
            Err(PdcpError::IntegrityFailure { count: 0 })
        );
        assert_eq!(nw.pop_rx_sdu(), None);
        assert_eq!(nw.rx_next(), 0);
        assert_eq!(nw.stats().rx_integrity_failures, 1);

        // Wrong integrity key at the receiver.
        let mut bad = PdcpEntity::new_network_side(PdcpConfig::srb(1), MU);
        bad.configure_security(SecurityConfig {
            integrity: Some((IntegrityAlg::Nia2, [0x99; 16])),
            cipher: Some((CipherAlg::Nea2, K_ENC)),
        })
        .unwrap();
        let pdu = ue.tx_sdu(b"hello", t(0));
        assert!(matches!(
            bad.rx_pdu(&pdu, t(0)),
            Err(PdcpError::IntegrityFailure { count: 1 })
        ));
    }

    #[test]
    fn security_mode_complete_ordering() {
        // UE receives the SMC on SRB1 before any key is active: integrity
        // protected (by the gNB) but unciphered.
        let mut gnb = PdcpEntity::new_network_side(PdcpConfig::srb(1), MU);
        gnb.configure_security(full_security()).unwrap();
        gnb.set_tx_cipher_enabled(false);
        let smc = gnb.tx_sdu(b"SecurityModeCommand", t(0));
        gnb.set_tx_cipher_enabled(true);
        assert_eq!(&smc[2..2 + 19], b"SecurityModeCommand");

        let mut ue = PdcpEntity::new(PdcpConfig::srb(1), MU);
        // RRC validates the derived key first…
        assert_eq!(ue.verify_only(&smc, IntegrityAlg::Nia2, &K_INT), Some(0));
        assert_eq!(ue.verify_only(&smc, IntegrityAlg::Nia2, &[0x00; 16]), None);
        assert_eq!(ue.verify_only(&smc[..3], IntegrityAlg::Nia2, &K_INT), None);
        // …then receives it with integrity not yet configured (MAC-I ignored).
        ue.rx_pdu(&smc, t(0)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), b"SecurityModeCommand");

        // Activate: SecurityModeComplete integrity protected, not ciphered
        // (38.331 §5.3.4.3); everything after is ciphered.
        ue.configure_security(full_security()).unwrap();
        ue.set_tx_cipher_enabled(false);
        let smcomp = ue.tx_sdu(b"SecurityModeComplete", t(1));
        ue.set_tx_cipher_enabled(true);
        assert_eq!(&smcomp[2..2 + 20], b"SecurityModeComplete");
        assert_ne!(&smcomp[22..26], &[0, 0, 0, 0]);

        // The gNB must receive the SMComplete unciphered too.
        gnb.set_rx_cipher_enabled(false);
        gnb.rx_pdu(&smcomp, t(1)).unwrap();
        gnb.set_rx_cipher_enabled(true);
        assert_eq!(gnb.pop_rx_sdu().unwrap(), b"SecurityModeComplete");

        let next = ue.tx_sdu(b"RRCReconfigurationComplete", t(2));
        assert_ne!(&next[2..2 + 26], b"RRCReconfigurationComplete");
        gnb.rx_pdu(&next, t(2)).unwrap();
        assert_eq!(gnb.pop_rx_sdu().unwrap(), b"RRCReconfigurationComplete");

        // Ciphered DL after activation.
        let rc = gnb.tx_sdu(b"RRCReconfiguration", t(3));
        ue.rx_pdu(&rc, t(3)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), b"RRCReconfiguration");
    }

    #[test]
    fn unsupported_algorithms_rejected() {
        let mut e = PdcpEntity::new(PdcpConfig::srb(1), MU);
        assert_eq!(
            e.configure_security(SecurityConfig {
                integrity: Some((IntegrityAlg::Nia1, K_INT)),
                cipher: None
            }),
            Err(PdcpError::Unsupported("NIA1 (SNOW 3G)"))
        );
        assert_eq!(
            e.configure_security(SecurityConfig {
                integrity: None,
                cipher: Some((CipherAlg::Nea3, K_ENC))
            }),
            Err(PdcpError::Unsupported("NEA3 (ZUC)"))
        );
        assert!(!e.security_configured());
        e.configure_security(SecurityConfig {
            integrity: Some((IntegrityAlg::Nia0, K_INT)),
            cipher: Some((CipherAlg::Nea0, K_ENC)),
        })
        .unwrap();
        // Null algorithms: zero MAC-I, plaintext.
        let pdu = e.tx_sdu(&[0xaa], t(0));
        assert_eq!(pdu, vec![0x00, 0x00, 0xaa, 0, 0, 0, 0]);
    }

    #[test]
    fn drb_with_integrity_round_trip() {
        let cfg = PdcpConfig {
            integrity_on_drb: true,
            ..PdcpConfig::drb(1, SnLen::Len18)
        };
        let (mut ue, mut nw) = pair(cfg, Some(full_security()));
        for i in 0..5u8 {
            let pdu = ue.tx_sdu(&[i; 7], t(i as u32));
            nw.rx_pdu(&pdu, t(i as u32)).unwrap();
            assert_eq!(nw.pop_rx_sdu().unwrap(), vec![i; 7]);
        }
        let mut pdu = ue.tx_sdu(&[9; 7], t(9));
        let last = pdu.len() - 1;
        pdu[last] ^= 0x80;
        assert_eq!(
            nw.rx_pdu(&pdu, t(9)),
            Err(PdcpError::IntegrityFailure { count: 5 })
        );
    }

    // --------------------------------------------------------------- SDAP

    #[test]
    fn drb_sdap_headers() {
        let cfg = PdcpConfig {
            sdap_header_ul: true,
            sdap_header_dl: true,
            qfi: 5,
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let (mut ue, mut nw) = pair(cfg, None);
        // UL: D/C=1 | R | QFI (37.324 §6.2.2.3).
        let pdu = ue.tx_sdu(&[0xde, 0xad], t(0));
        assert_eq!(pdu, vec![0x80, 0x00, 0x85, 0xde, 0xad]);
        nw.rx_pdu(&pdu, t(0)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![0xde, 0xad]);
        // DL: RDI | RQI | QFI; stripped by the UE (RQI only logged).
        let mut dl = nw.tx_sdu(&[0xbe, 0xef], t(0));
        dl[2] = 0x45; // RQI set, QFI 5
        ue.rx_pdu(&dl, t(0)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), vec![0xbe, 0xef]);
        // A DL PDU with header but no payload is malformed.
        assert!(matches!(
            ue.rx_pdu(&[0x80, 0x01], t(0)),
            Err(PdcpError::TooShort { .. })
        ));
        // Header-only DL PDU (empty SDU) is fine.
        ue.rx_pdu(&[0x80, 0x01, 0x05], t(0)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn drb_without_sdap_headers() {
        let (mut ue, mut nw) = pair(PdcpConfig::drb(1, SnLen::Len12), Some(full_security()));
        let pdu = ue.tx_sdu(&[1, 2, 3], t(0));
        assert_eq!(pdu.len(), 5);
        nw.rx_pdu(&pdu, t(0)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![1, 2, 3]);
        // Mixed: UL header only.
        let cfg = PdcpConfig {
            sdap_header_ul: true,
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let (mut ue, mut nw) = pair(cfg, None);
        let pdu = ue.tx_sdu(&[7], t(0));
        assert_eq!(pdu, vec![0x80, 0x00, 0x81, 0x07]);
        nw.rx_pdu(&pdu, t(0)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![7]);
        let dl = nw.tx_sdu(&[8], t(0));
        assert_eq!(dl, vec![0x80, 0x00, 0x08]);
        ue.rx_pdu(&dl, t(0)).unwrap();
        assert_eq!(ue.pop_rx_sdu().unwrap(), vec![8]);
    }

    // ------------------------------------------------- SN wrap / HFN inference

    #[test]
    fn sn_wrap_and_hfn_inference_12_bit() {
        let (mut ue, mut nw) = pair(PdcpConfig::drb(1, SnLen::Len12), Some(full_security()));
        let n = 4096 + 300;
        for i in 0..n {
            let pdu = ue.tx_sdu(&(i as u32).to_be_bytes(), t(0));
            nw.rx_pdu(&pdu, t(0)).unwrap();
            assert_eq!(nw.pop_rx_sdu().unwrap(), (i as u32).to_be_bytes());
        }
        assert_eq!(ue.tx_count(), n as u32);
        assert_eq!(nw.rx_next(), n as u32);
        assert_eq!(nw.rx_deliv(), n as u32);
        assert!(!nw.t_reordering_running());
    }

    #[test]
    fn hfn_inference_rules() {
        let mut e = PdcpEntity::new(PdcpConfig::drb(1, SnLen::Len12), MU);
        // RX_DELIV = HFN 1, SN 100.
        e.rx_deliv = (1 << 12) | 100;
        assert_eq!(e.infer_count(100), (1 << 12) | 100); // same HFN
        assert_eq!(e.infer_count(2147), (1 << 12) | 2147); // < SN+2048 → same HFN
        assert_eq!(e.infer_count(2148), 2148); // ≥ SN+2048 → HFN−1 (late PDU)
        assert_eq!(e.infer_count(4000), 4000);
        // RX_DELIV = HFN 0, SN 4000: small SNs belong to HFN 1.
        e.rx_deliv = 4000;
        assert_eq!(e.infer_count(10), (1 << 12) | 10);
        assert_eq!(e.infer_count(1951), (1 << 12) | 1951); // 1951 < 4000−2048
        assert_eq!(e.infer_count(1952), 1952);
        // 18-bit.
        let mut e = PdcpEntity::new(PdcpConfig::drb(1, SnLen::Len18), MU);
        e.rx_deliv = (3 << 18) | 5;
        assert_eq!(e.infer_count(4), (3 << 18) | 4);
        assert_eq!(e.infer_count(0x3_FFFF), (2 << 18) | 0x3_FFFF);
        e.rx_deliv = (3 << 18) | 0x3_FFF0;
        assert_eq!(e.infer_count(1), (4 << 18) | 1);
    }

    #[test]
    fn stale_pdu_from_previous_hfn_is_discarded() {
        let (mut ue, mut nw) = pair(PdcpConfig::drb(1, SnLen::Len12), None);
        let mut kept = Vec::new();
        for i in 0..4100u32 {
            let pdu = ue.tx_sdu(&[1], t(0));
            if i == 4090 {
                kept = pdu.clone(); // COUNT 4090 (HFN 0)
            }
            nw.rx_pdu(&pdu, t(0)).unwrap();
        }
        // Replayed: SN 4090 with RX_DELIV = 4100 (HFN 1, SN 4) → HFN 0 → stale.
        assert_eq!(
            nw.rx_pdu(&kept, t(0)),
            Err(PdcpError::Duplicate { count: 4090 })
        );
        assert_eq!(nw.stats().rx_duplicates, 1);
    }

    // ---------------------------------------------------------- reordering

    #[test]
    fn reordering_fills_gap_before_expiry() {
        let (mut ue, mut nw) = pair(PdcpConfig::drb(1, SnLen::Len12), Some(full_security()));
        let p: Vec<Vec<u8>> = (0..4u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        nw.rx_pdu(&p[0], t(0)).unwrap();
        nw.rx_pdu(&p[2], t(1)).unwrap();
        nw.rx_pdu(&p[3], t(1)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![0]);
        assert_eq!(nw.pop_rx_sdu(), None);
        assert!(nw.t_reordering_running());
        assert_eq!(nw.rx_deliv(), 1);
        assert_eq!(nw.rx_next(), 4);
        assert_eq!(nw.reorder_buffer_len(), 2);
        // Duplicate of a buffered PDU.
        assert_eq!(
            nw.rx_pdu(&p[2], t(2)),
            Err(PdcpError::Duplicate { count: 2 })
        );
        // Gap filled in time (t-Reordering 100 ms).
        nw.rx_pdu(&p[1], t(50)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![1]);
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![2]);
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![3]);
        assert!(!nw.t_reordering_running());
        assert_eq!(nw.rx_deliv(), 4);
        // Late duplicate of a delivered PDU.
        assert_eq!(
            nw.rx_pdu(&p[1], t(60)),
            Err(PdcpError::Duplicate { count: 1 })
        );
    }

    #[test]
    fn t_reordering_expiry_skips_gap() {
        let cfg = PdcpConfig {
            t_reordering_ms: Some(40),
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let (mut ue, mut nw) = pair(cfg, None);
        let p: Vec<Vec<u8>> = (0..6u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        nw.rx_pdu(&p[0], t(0)).unwrap();
        nw.rx_pdu(&p[2], t(10)).unwrap(); // starts t-Reordering at 10 ms, RX_REORD = 3
        nw.rx_pdu(&p[4], t(20)).unwrap(); // RX_NEXT = 5; timer keeps running
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![0]);
        assert_eq!(nw.pop_rx_sdu(), None);
        nw.tick(t(49));
        assert_eq!(nw.pop_rx_sdu(), None);
        assert!(nw.t_reordering_running());
        nw.tick(t(50)); // expiry: deliver < RX_REORD(3) → [2]; then from 3: nothing (3 missing)
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![2]);
        assert_eq!(nw.pop_rx_sdu(), None);
        assert_eq!(nw.rx_deliv(), 3);
        // RX_DELIV (3) < RX_NEXT (5): timer restarted with RX_REORD = 5.
        assert!(nw.t_reordering_running());
        assert_eq!(nw.stats().t_reordering_expiries, 1);
        // The late #1 is now stale.
        assert_eq!(
            nw.rx_pdu(&p[1], t(55)),
            Err(PdcpError::Duplicate { count: 1 })
        );
        // #3 arrives: deliver 3 and 4, timer stops (RX_DELIV 5 >= RX_REORD 5).
        nw.rx_pdu(&p[3], t(60)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![3]);
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![4]);
        assert!(!nw.t_reordering_running());
        nw.rx_pdu(&p[5], t(70)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![5]);
        assert_eq!(nw.rx_deliv(), 6);
        assert_eq!(nw.rx_next(), 6);
    }

    #[test]
    fn t_reordering_second_expiry_flushes_everything() {
        let cfg = PdcpConfig {
            t_reordering_ms: Some(10),
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let (mut ue, mut nw) = pair(cfg, None);
        let p: Vec<Vec<u8>> = (0..5u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        nw.rx_pdu(&p[1], t(0)).unwrap(); // RX_REORD = 2
        nw.rx_pdu(&p[4], t(5)).unwrap(); // RX_NEXT = 5
        nw.tick(t(10)); // deliver 1; RX_DELIV=2 <5 → restart with RX_REORD=5
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![1]);
        assert_eq!(nw.rx_deliv(), 2);
        nw.tick(t(20)); // deliver 4; RX_DELIV = 5 = RX_NEXT → timer stops
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![4]);
        assert_eq!(nw.rx_deliv(), 5);
        assert!(!nw.t_reordering_running());
    }

    #[test]
    fn infinite_t_reordering_holds_gap() {
        // SRBs: t-Reordering infinity; a gap is never skipped.
        let (mut ue, mut nw) = pair(PdcpConfig::srb(1), None);
        let p: Vec<Vec<u8>> = (0..3u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        nw.rx_pdu(&p[1], t(0)).unwrap();
        nw.tick(t(5000));
        assert_eq!(nw.pop_rx_sdu(), None);
        assert!(!nw.t_reordering_running());
        nw.rx_pdu(&p[0], t(5001)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![0]);
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![1]);
        nw.rx_pdu(&p[2], t(5002)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![2]);
    }

    #[test]
    fn timers_across_sfn_wrap() {
        let cfg = PdcpConfig {
            t_reordering_ms: Some(20),
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let (mut ue, mut nw) = pair(cfg, None);
        let p: Vec<Vec<u8>> = (0..2u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        let near_end = SlotPoint::new(MU, 1023, 15);
        nw.rx_pdu(&p[1], near_end).unwrap();
        nw.tick(near_end.add(39)); // 19.5 ms later, wrapped into SFN 0/1
        assert_eq!(nw.pop_rx_sdu(), None);
        nw.tick(near_end.add(40));
        assert_eq!(nw.pop_rx_sdu().unwrap(), vec![1]);
    }

    // ------------------------------------------------------ discard timer

    #[test]
    fn discard_timer_reports_expired_counts() {
        let cfg = PdcpConfig {
            discard_timer_ms: Some(100),
            ..PdcpConfig::drb(1, SnLen::Len12)
        };
        let mut ue = PdcpEntity::new(cfg, MU);
        ue.tx_sdu(&[0], t(0));
        ue.tx_sdu(&[1], t(30));
        ue.tick(t(99));
        assert!(ue.take_discarded().is_empty());
        ue.tick(t(100));
        assert_eq!(ue.take_discarded(), vec![0]);
        ue.tick(t(129));
        assert!(ue.take_discarded().is_empty());
        ue.tick(t(130));
        assert_eq!(ue.take_discarded(), vec![1]);
        assert_eq!(ue.stats().discarded, 2);
    }

    // ------------------------------------------------- control / malformed

    #[test]
    fn control_pdus_recognised_and_ignored() {
        let mut nw = PdcpEntity::new_network_side(PdcpConfig::drb(1, SnLen::Len12), MU);
        // Status report: D/C=0, type 000, FMC, bitmap.
        assert_eq!(nw.rx_pdu(&[0x00, 0, 0, 0, 5, 0b1010_0000], t(0)), Ok(()));
        assert_eq!(nw.rx_pdu(&[0x10, 0xaa], t(0)), Ok(())); // ROHC feedback
        assert_eq!(nw.rx_pdu(&[0x20], t(0)), Ok(())); // EHC feedback
        assert_eq!(
            nw.rx_pdu(&[0x70], t(0)),
            Err(PdcpError::UnknownControlPdu(7))
        );
        assert_eq!(nw.pop_rx_sdu(), None);
        assert_eq!(nw.rx_next(), 0);
        assert_eq!(nw.stats().rx_control_pdus, 4);
    }

    #[test]
    fn malformed_pdus_do_not_panic() {
        let mut srb = PdcpEntity::new(PdcpConfig::srb(1), MU);
        srb.configure_security(full_security()).unwrap();
        for bad in [&[][..], &[0x00], &[0x00, 0x00], &[0x00, 0x00, 1, 2, 3]] {
            assert!(
                matches!(srb.rx_pdu(bad, t(0)), Err(PdcpError::TooShort { .. })),
                "{bad:?}"
            );
        }
        // Minimal valid-length SRB PDU (header + MAC-I only) with a bad MAC.
        assert!(matches!(
            srb.rx_pdu(&[0, 0, 0, 0, 0, 0], t(0)),
            Err(PdcpError::IntegrityFailure { .. })
        ));
        let mut d18 = PdcpEntity::new(PdcpConfig::drb(1, SnLen::Len18), MU);
        assert!(matches!(
            d18.rx_pdu(&[0x80, 0x00], t(0)),
            Err(PdcpError::TooShort { .. })
        ));
        assert_eq!(d18.rx_pdu(&[0x80, 0x00, 0x00], t(0)), Ok(())); // empty SDU
        assert_eq!(d18.pop_rx_sdu(), Some(vec![]));
        assert_eq!(srb.stats().rx_malformed, 4);
        assert!(srb.verify_only(&[], IntegrityAlg::Nia2, &K_INT).is_none());
    }

    #[test]
    fn status_report_bitmap() {
        let (mut ue, mut nw) = pair(PdcpConfig::drb(1, SnLen::Len12), None);
        let p: Vec<Vec<u8>> = (0..12u8).map(|i| ue.tx_sdu(&[i], t(0))).collect();
        assert_eq!(nw.build_status_report().unwrap(), vec![0x00, 0, 0, 0, 0]);
        nw.rx_pdu(&p[0], t(0)).unwrap();
        nw.rx_pdu(&p[2], t(0)).unwrap();
        nw.rx_pdu(&p[3], t(0)).unwrap();
        nw.rx_pdu(&p[11], t(0)).unwrap();
        // FMC = 1; bits for COUNT 2..=11: 1,1,0,0,0,0,0,0,0,1 → 0b1100_0000 0b0100_0000
        assert_eq!(
            nw.build_status_report().unwrap(),
            vec![0x00, 0, 0, 0, 1, 0b1100_0000, 0b0100_0000]
        );
        assert!(PdcpEntity::new(PdcpConfig::srb(1), MU)
            .build_status_report()
            .is_none());
    }

    #[test]
    fn reestablish_resets_state() {
        let (mut ue, mut nw) = pair(PdcpConfig::srb(1), Some(full_security()));
        for _ in 0..3 {
            let pdu = ue.tx_sdu(b"x", t(0));
            nw.rx_pdu(&pdu, t(0)).unwrap();
        }
        ue.reestablish();
        nw.reestablish();
        assert_eq!(ue.tx_count(), 0);
        assert_eq!(nw.rx_next(), 0);
        assert!(nw.security_configured());
        let pdu = ue.tx_sdu(b"y", t(1));
        nw.rx_pdu(&pdu, t(1)).unwrap();
        assert_eq!(nw.pop_rx_sdu().unwrap(), b"y");
    }
}
