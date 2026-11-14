//! RLC (TS 38.322) for the Ferrite UE: TM, UM and AM entities as pure state
//! machines.
//!
//! No I/O, no threads, no clock: the caller drives an [`RlcEntity`] with
//! `tx_sdu` (from PDCP), `rx_pdu` (from MAC), `pull_pdu` (MAC transmission
//! opportunity) and `tick` (once per slot), always passing the current
//! [`SlotPoint`]. Timer values are configured in milliseconds (as signalled by
//! RRC) and converted to slots at the entity's [`Numerology`].
//!
//! * TM (§4.2.1.2): pass-through, no header (CCCH / SRB0).
//! * UM (§5.2.2, §6.2.2.3): 6/12-bit SN, segmentation with SO, reassembly
//!   window, t-Reassembly.
//! * AM (§5.2.3, §5.3, §6.2.2.4/5): 12/18-bit SN, transmitting/receiving
//!   windows, polling, STATUS reporting with NACK ranges and segment offsets,
//!   retransmission with re-segmentation, RETX_COUNT / maxRetxThreshold,
//!   t-PollRetransmit, t-Reassembly, t-StatusProhibit.
//!
//! The AM receiver delivers SDUs to PDCP in sequence (RX_Next order); this is
//! stricter than §5.2.3.2.3, which permits delivery as soon as an SDU is
//! reassembled, and is harmless to PDCP's own reordering.

#![forbid(unsafe_code)]

mod am;
mod header;
mod reasm;
mod timer;
mod um;

use std::collections::VecDeque;

use ferrite_common::{Numerology, SlotPoint};

pub use header::{is_status_pdu, AmdHeader, Nack, Si, StatusPdu, UmdHeader, SO_END_ALL};

/// Sequence-number field length (TS 38.322 §7.1: UM 6 or 12 bits, AM 12 or 18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnLen {
    Bits6,
    Bits12,
    Bits18,
}

impl SnLen {
    /// Field width in bits.
    pub const fn bits(self) -> u32 {
        match self {
            SnLen::Bits6 => 6,
            SnLen::Bits12 => 12,
            SnLen::Bits18 => 18,
        }
    }

    /// `2^bits`: the SN modulus.
    pub const fn modulus(self) -> u32 {
        1 << self.bits()
    }
}

/// `(sn − base) mod 2^bits`: an SN's position relative to a window base.
/// `modulus` must be a power of two.
pub(crate) const fn sn_mod(sn: u32, base: u32, modulus: u32) -> u32 {
    sn.wrapping_sub(base) & (modulus - 1)
}

/// UM entity configuration (TS 38.331 `UM-Uni-Directional`/`UM-Bi-Directional`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmConfig {
    /// 6 or 12 bits.
    pub sn_len: SnLen,
    pub t_reassembly_ms: u32,
}

impl Default for UmConfig {
    /// 12-bit SN, t-Reassembly 35 ms.
    fn default() -> Self {
        Self {
            sn_len: SnLen::Bits12,
            t_reassembly_ms: 35,
        }
    }
}

/// AM entity configuration (TS 38.331 `RLC-Config.am`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmConfig {
    /// 12 or 18 bits.
    pub sn_len: SnLen,
    pub t_poll_retransmit_ms: u32,
    /// `pollPDU`; `None` = infinity.
    pub poll_pdu: Option<u32>,
    /// `pollByte` in bytes; `None` = infinity.
    pub poll_byte: Option<u32>,
    pub max_retx_threshold: u32,
    pub t_reassembly_ms: u32,
    pub t_status_prohibit_ms: u32,
}

impl AmConfig {
    /// The SRB1/SRB2 default RLC configuration of TS 38.331 §9.2.1: 12-bit SN,
    /// t-PollRetransmit ms45, pollPDU/pollByte infinity, maxRetxThreshold t8,
    /// t-Reassembly ms35, t-StatusProhibit ms0.
    pub const fn srb_default() -> Self {
        Self {
            sn_len: SnLen::Bits12,
            t_poll_retransmit_ms: 45,
            poll_pdu: None,
            poll_byte: None,
            max_retx_threshold: 8,
            t_reassembly_ms: 35,
            t_status_prohibit_ms: 0,
        }
    }
}

impl Default for AmConfig {
    fn default() -> Self {
        Self::srb_default()
    }
}

/// The RLC mode of an entity (TS 38.322 §4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlcMode {
    Tm,
    Um(UmConfig),
    Am(AmConfig),
}

/// Indications from RLC to the upper layer (RRC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlcEvent {
    /// `RETX_COUNT` reached `maxRetxThreshold` for the SDU with this SN
    /// (§5.3.2) — RRC treats it as radio link failure (TS 38.331 §5.3.10.3).
    MaxRetxReached { sn: u32 },
}

/// A transparent-mode entity (§5.2.1): SDUs map one-to-one onto PDUs with no
/// header.
#[derive(Debug, Default)]
struct TmEntity {
    tx: VecDeque<Vec<u8>>,
    rx: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
enum Inner {
    Tm(TmEntity),
    Um(Box<um::UmEntity>),
    Am(Box<am::AmEntity>),
}

/// One bidirectional RLC entity (a TM, UM or AM entity with both a transmitting
/// and a receiving side) bound to one logical channel.
#[derive(Debug)]
pub struct RlcEntity {
    mode: RlcMode,
    inner: Inner,
}

impl RlcEntity {
    /// Create an entity. A UM `sn_len` other than 6/12 is clamped to 12 and an
    /// AM `sn_len` other than 12/18 to 12 (with a warning).
    pub fn new(mode: RlcMode, numerology: Numerology) -> Self {
        let inner = match mode {
            RlcMode::Tm => Inner::Tm(TmEntity::default()),
            RlcMode::Um(mut cfg) => {
                if cfg.sn_len == SnLen::Bits18 {
                    log::warn!("rlc: UM sn_len 18 is not valid; using 12");
                    cfg.sn_len = SnLen::Bits12;
                }
                Inner::Um(Box::new(um::UmEntity::new(cfg, numerology)))
            }
            RlcMode::Am(mut cfg) => {
                if cfg.sn_len == SnLen::Bits6 {
                    log::warn!("rlc: AM sn_len 6 is not valid; using 12");
                    cfg.sn_len = SnLen::Bits12;
                }
                Inner::Am(Box::new(am::AmEntity::new(cfg, numerology)))
            }
        };
        Self { mode, inner }
    }

    /// The configured mode.
    pub fn mode(&self) -> RlcMode {
        self.mode
    }

    /// Queue an RLC SDU from the upper layer (PDCP). Empty SDUs are ignored;
    /// SDUs longer than 65535 bytes (the SO field range) are discarded.
    pub fn tx_sdu(&mut self, sdu: Vec<u8>) {
        if sdu.is_empty() {
            return;
        }
        match &mut self.inner {
            Inner::Tm(t) => t.tx.push_back(sdu),
            Inner::Um(u) => u.tx_sdu(sdu),
            Inner::Am(a) => a.tx_sdu(sdu),
        }
    }

    /// Deliver one RLC PDU received from MAC. Malformed PDUs are logged and
    /// dropped.
    pub fn rx_pdu(&mut self, pdu: &[u8], now: SlotPoint) {
        match &mut self.inner {
            Inner::Tm(t) => {
                if !pdu.is_empty() {
                    t.rx.push_back(pdu.to_vec());
                }
            }
            Inner::Um(u) => u.rx_pdu(pdu, now),
            Inner::Am(a) => a.rx_pdu(pdu, now),
        }
    }

    /// Run the entity's timers; call once per slot.
    pub fn tick(&mut self, now: SlotPoint) {
        match &mut self.inner {
            Inner::Tm(_) => {}
            Inner::Um(u) => u.tick(now),
            Inner::Am(a) => a.tick(now),
        }
    }

    /// RLC data volume for buffer status reporting (TS 38.322 §5.5, TS 38.321
    /// §5.4.5): SDUs and SDU segments not yet included in a PDU, data pending
    /// retransmission and a triggered STATUS PDU (when t-StatusProhibit is not
    /// running), each including its header.
    pub fn buffer_status(&self) -> usize {
        match &self.inner {
            Inner::Tm(t) => t.tx.iter().map(Vec::len).sum(),
            Inner::Um(u) => u.buffer_status(),
            Inner::Am(a) => a.buffer_status(),
        }
    }

    /// Build at most one RLC PDU of at most `max_bytes` for a MAC transmission
    /// opportunity: a STATUS PDU first if one is due, then retransmissions,
    /// then new data (segmented to fit). `None` if nothing fits.
    pub fn pull_pdu(&mut self, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        match &mut self.inner {
            Inner::Tm(t) => {
                if t.tx.front().is_some_and(|s| s.len() <= max_bytes) {
                    t.tx.pop_front()
                } else {
                    None
                }
            }
            Inner::Um(u) => u.pull_pdu(max_bytes, now),
            Inner::Am(a) => a.pull_pdu(max_bytes, now),
        }
    }

    /// Next reassembled SDU for the upper layer (in sequence for AM; in order
    /// of reassembly for UM; in order of reception for TM).
    pub fn pop_rx_sdu(&mut self) -> Option<Vec<u8>> {
        match &mut self.inner {
            Inner::Tm(t) => t.rx.pop_front(),
            Inner::Um(u) => u.pop_rx_sdu(),
            Inner::Am(a) => a.pop_rx_sdu(),
        }
    }

    /// Drain pending indications for the upper layer.
    pub fn events(&mut self) -> Vec<RlcEvent> {
        match &mut self.inner {
            Inner::Am(a) => a.events(),
            _ => Vec::new(),
        }
    }

    /// RLC re-establishment (§5.1.2): discard all SDUs and PDUs, stop all
    /// timers and reset the state variables.
    pub fn reestablish(&mut self) {
        match &mut self.inner {
            Inner::Tm(t) => *t = TmEntity::default(),
            Inner::Um(u) => u.reestablish(),
            Inner::Am(a) => a.reestablish(),
        }
    }

    /// AM only: number of SDUs with an assigned SN not yet positively
    /// acknowledged (0 for TM/UM).
    pub fn unacked_sdus(&self) -> usize {
        match &self.inner {
            Inner::Am(a) => a.unacked_sdus(),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests;
