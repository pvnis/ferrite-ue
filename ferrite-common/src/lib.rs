//! Shared vocabulary for the Ferrite 5G NR UE: the sample type, the error type,
//! the slot clock every layer agrees on, RNTIs, duplex mode, and the frequency
//! helpers (ARFCN / GSCN / band table) that the configuration and the L1 share.
//!
//! Clean-room from the 3GPP specifications (TS 38.211 §4, TS 38.104 §5, TS
//! 38.101-1 §5, TS 38.133 §7.1.2). Nothing here depends on a particular cell.

use num_complex::Complex32;

pub mod band;
pub mod slot;

pub use band::{arfcn_to_hz, hz_to_arfcn, gscn_to_hz, hz_to_gscn, BandInfo, DuplexMode, NtaOffsetClass};
pub use slot::{Numerology, SlotPoint};

/// A baseband IQ sample (single-precision complex).
pub type Iq = Complex32;

/// Crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors surfaced across Ferrite layers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure (file/radio backends).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A radio backend failed.
    #[error("radio: {0}")]
    Radio(String),

    /// A physical-layer processing error.
    #[error("phy: {0}")]
    Phy(String),

    /// A protocol (L2/L3) error.
    #[error("protocol: {0}")]
    Protocol(String),

    /// A parameter was outside its 3GPP-defined range.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    /// A configuration is inconsistent or unsupported.
    #[error("config: {0}")]
    Config(String),
}

/// Radio network temporary identifier (TS 38.321 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rnti(pub u16);

impl Rnti {
    /// SI-RNTI (system information).
    pub const SI: Rnti = Rnti(0xFFFF);
    /// P-RNTI (paging).
    pub const P: Rnti = Rnti(0xFFFE);

    /// RA-RNTI for a PRACH occasion (TS 38.321 §5.1.3):
    /// `1 + s_id + 14·t_id + 14·80·f_id + 14·80·8·ul_carrier_id`.
    /// `s_id` = first OFDM symbol (0..14), `t_id` = first slot in the system
    /// frame (0..80), `f_id` = frequency-domain occasion index (0..8).
    pub fn ra(s_id: u32, t_id: u32, f_id: u32, ul_carrier_id: u32) -> Rnti {
        Rnti((1 + s_id + 14 * t_id + 14 * 80 * f_id + 14 * 80 * 8 * ul_carrier_id) as u16)
    }

    pub fn value(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for Rnti {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

/// Which identity a PDCCH/PDSCH is addressed to (the RNTI *type*).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RntiKind {
    Si,
    P,
    Ra,
    Tc,
    C,
}

/// Format a byte slice as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a hex string into bytes (whitespace ignored). `None` on a bad digit or
/// odd length.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    (0..clean.len() / 2).map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).ok()).collect()
}
