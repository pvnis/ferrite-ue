//! Configuration derivation and message codec adapters: ASN.1 structures
//! (`ferrite_asn1`) → the plain `PhyConfig` / `MacConfig` / bearer setups the
//! lower layers consume (TS 38.331 → TS 38.211/213/214/321 parameters).
//!
//! The plain-data types live here; the ASN.1-facing functions are in
//! [`crate::codec`] and re-exported below.

use crate::{BearerSetup, RlcSetup};
use ferrite_common::{DuplexMode, Numerology};
use ferrite_fapi::config::*;
use ferrite_mac::MacConfig;

/// What the PHY learned from the MIB / SSB.
#[derive(Clone, Debug)]
pub struct MibInfo {
    pub pci: u16,
    pub mu: u8,
    pub dmrs_typea_pos: u8,
    pub k_ssb: u8,
    pub coreset0_index: u8,
    pub ss0_index: u8,
    pub ssb_index: u8,
    pub ssb_scs_khz: u32,
    /// CORESET0 geometry from TS 38.213 Table 13-x (RBs, symbols, offset RBs).
    pub coreset0_n_rb: u16,
    pub coreset0_n_symb: u8,
    pub coreset0_offset_rb: i32,
    /// NR-ARFCN of the SSB the UE synchronised to (key derivation input).
    pub ssb_arfcn: u32,
}

/// Radio facts the UE was started with.
#[derive(Clone, Debug)]
pub struct RadioInfo {
    pub fs: f64,
    pub duplex: DuplexMode,
    pub band: u16,
}

/// Everything derived from SIB1 that the rest of RRC needs.
#[derive(Clone, Debug)]
pub struct CellInfo {
    pub plmn: String,
    pub tac: u32,
    pub cell_identity: u64,
    pub phy: PhyConfig,
    pub mac: MacConfig,
    pub t300_ms: u32,
    pub numerology: Numerology,
    /// SIB types SIB1 schedules for broadcast (`si-SchedulingInfo`), with the
    /// SI window length in slots.
    pub si_scheduled: Vec<u8>,
    pub si_window_slots: u16,
    pub ssb_arfcn: u32,
    /// T301 (ms) from SIB1 `ue-TimersAndConstants`.
    pub t301_ms: u32,
    /// Radio link monitoring constants from SIB1 `ue-TimersAndConstants`
    /// (TS 38.331 §7.1 / §7.3): T310 (ms, 0 = immediate failure), N310
    /// consecutive out-of-sync indications before T310 starts, N311
    /// consecutive in-sync indications that stop it, and T311 (ms) for the
    /// cell selection after the failure.
    pub t310_ms: u32,
    pub n310: u8,
    pub n311: u8,
    pub t311_ms: u32,
    /// The SIB1-only (common) configuration: the default the UE falls back to
    /// on re-establishment (§5.3.7.4) before the network reconfigures it.
    pub common_phy: PhyConfig,
    pub common_mac: MacConfig,
    /// RLC configuration of every bearer set up so far, by LCID (an
    /// `RLC-BearerConfig` without `rlc-Config` keeps it).
    pub rlc_bearers: std::collections::BTreeMap<u8, RlcSetup>,
    /// Dedicated configuration per DL BWP id (TS 38.331 §5.3.5.5.3; empty
    /// until the RRCSetup). `phy` / `mac` are the active BWP's.
    pub bwps: std::collections::BTreeMap<u8, (PhyConfig, MacConfig)>,
}

/// Decoded DL-CCCH messages the state machine acts on.
#[allow(clippy::large_enum_variant)] // one message at a time; boxing the configs buys nothing
pub enum DlCcch {
    Setup {
        tid: u8,
        phy: PhyConfig,
        mac: MacConfig,
        bearers: Vec<BearerSetup>,
        bwps: BwpConfigs,
    },
    Reject,
}

/// Decoded DL-DCCH messages the state machine acts on.
#[allow(clippy::large_enum_variant)]
pub enum DlDcch {
    SecurityModeCommand {
        tid: u8,
        integrity_alg: u8,
        ciphering_alg: u8,
    },
    UeCapabilityEnquiry {
        tid: u8,
    },
    Reconfiguration {
        tid: u8,
        phy: Option<PhyConfig>,
        mac: Option<MacConfig>,
        bearers: Vec<BearerSetup>,
        released: Vec<u8>,
        nas: Vec<Vec<u8>>,
        meas: Option<ferrite_asn1::meas::MeasConfig>,
        bwps: Option<BwpConfigs>,
    },
    DlInformationTransfer {
        nas: Option<Vec<u8>>,
    },
    Release,
    /// `RRCReestablishment` (§5.3.7.5) with its `nextHopChainingCount`.
    Reestablishment {
        tid: u8,
        ncc: u8,
    },
    Other(&'static str),
}

pub use crate::codec::*;
