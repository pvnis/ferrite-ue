//! Ferrite MAC (3GPP TS 38.321) — the UE MAC entity.
//!
//! Sits between the PHY (through the FAPI-style interface in
//! `ferrite_l1::fapi`) and the RLC bearers (through [`UpperLayers`]). Pure
//! state machines driven by PHY indications; no threads, no I/O.
//!
//! Sub-entities:
//! * [`ra`] — the random-access procedure (§5.1), one state machine;
//! * [`harq`] — DL/UL HARQ entities and the HARQ-ACK codebook (§5.3, §5.4.2, TS 38.213 §9.1);
//! * [`bsr`], [`sr`] — buffer status reporting (§5.4.5) and scheduling requests (§5.4.4);
//! * [`lcp`] — logical channel prioritisation (§5.4.3.1);
//! * [`pdu`], [`rar`] — MAC PDU multiplexing/demultiplexing (§6.1) and the RAR (§6.2.3);
//! * [`ta`] — timing advance maintenance (§5.2);
//! * [`entity`] — the [`MacEntity`] tying it together.

#![forbid(unsafe_code)]

pub mod bsr;
pub mod entity;
pub mod harq;
pub mod lcp;
pub mod pdu;
pub mod ra;
pub mod rar;
pub mod sr;
pub mod ta;

pub use entity::{MacEntity, MacEvent, UpperLayers};
pub use ferrite_l1::fapi;

use ferrite_common::Numerology;

// ---------------------------------------------------------------------------
// LCID values (TS 38.321 Table 6.2.1-1 DL-SCH, Table 6.2.1-2 UL-SCH).
// ---------------------------------------------------------------------------

/// DL-SCH: CCCH SDU (Msg4 RRCSetup), carried with a length field.
pub const LCID_DL_CCCH: u8 = 0;
/// UL-SCH: 64-bit CCCH SDU (8 octets), no length field.
pub const LCID_UL_CCCH64: u8 = 0;
/// Logical channels 1..=32 carry DCCH/DTCH SDUs (both directions).
pub const LCID_MIN_LCH: u8 = 1;
pub const LCID_MAX_LCH: u8 = 32;
/// UL-SCH: 48-bit CCCH SDU (6 octets), no length field.
pub const LCID_UL_CCCH48: u8 = 52;
/// UL-SCH: Configured Grant Confirmation / Multiple-entry PHR / Single-entry PHR.
pub const LCID_SINGLE_PHR: u8 = 57;
/// UL-SCH: C-RNTI MAC CE (2 octets).
pub const LCID_CRNTI: u8 = 58;
/// UL-SCH: Short Truncated BSR.
pub const LCID_SHORT_TRUNC_BSR: u8 = 59;
/// UL-SCH: Long Truncated BSR.
pub const LCID_LONG_TRUNC_BSR: u8 = 60;
/// UL-SCH: Short BSR (1 octet).
pub const LCID_SHORT_BSR: u8 = 61;
/// UL-SCH: Long BSR (variable, with length).
pub const LCID_LONG_BSR: u8 = 62;
/// DL-SCH: Timing Advance Command MAC CE (1 octet).
pub const LCID_TA_COMMAND: u8 = 61;
/// DL-SCH: UE Contention Resolution Identity (6 octets).
pub const LCID_DL_CON_RES: u8 = 62;
/// DL-SCH: DRX Command (0 octets).
pub const LCID_DRX: u8 = 60;
/// DL-SCH: Long DRX Command (0 octets).
pub const LCID_LONG_DRX: u8 = 59;
/// DL-SCH: SCell activation 1 octet / 4 octets.
pub const LCID_SCELL_ACT_1: u8 = 58;
pub const LCID_SCELL_ACT_4: u8 = 57;
/// DL-SCH: Duplication activation.
pub const LCID_DUP_ACT: u8 = 56;
/// Padding (both directions).
pub const LCID_PADDING: u8 = 63;

/// Logical channel configuration (`LogicalChannelConfig.ul-SpecificParameters`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalChannelConfig {
    pub lcid: u8,
    /// 1 = highest.
    pub priority: u8,
    /// Prioritised bit rate in bytes per ms (`None` = infinity).
    pub pbr_bytes_per_ms: Option<u32>,
    /// Bucket size duration in ms.
    pub bsd_ms: u32,
    /// Logical channel group (0..7) for BSR.
    pub lcg: u8,
    /// `schedulingRequestID` this channel triggers (None → any SR config).
    pub sr_id: Option<u8>,
    /// `logicalChannelSR-Mask`.
    pub sr_mask: bool,
}

/// `SchedulingRequestToAddMod` + its `SchedulingRequestResourceConfig`s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrConfig {
    pub sr_id: u8,
    /// `sr-ProhibitTimer` in ms (0 = none).
    pub prohibit_ms: u32,
    /// `sr-TransMax`.
    pub trans_max: u32,
    /// Resources: (period slots, offset slots, pucch resource id).
    pub resources: Vec<(u16, u16, u8)>,
}

/// RACH parameters MAC needs (`RACH-ConfigCommon` + the PRACH timing pattern).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RachConfig {
    pub preamble_trans_max: u32,
    pub power_ramping_step_db: u8,
    /// `preambleReceivedTargetPower` dBm.
    pub target_power_dbm: i16,
    /// `ra-ResponseWindow` in slots (at the data numerology).
    pub ra_response_window_slots: u16,
    /// `ra-ContentionResolutionTimer` in ms.
    pub contention_resolution_ms: u32,
    /// Total number of contention-based preambles available (group A).
    pub nof_cb_preambles: u8,
    /// `ssb-perRACH-OccasionAndCB-PreamblesPerSSB` (preambles per SSB per occasion).
    pub cb_preambles_per_ssb: u8,
    /// The PRACH configuration (occasion pattern lives in `ferrite_phy::prach_config`).
    pub prach: ferrite_l1::config::PrachConfig,
    /// Initial UL BWP size in RBs (for the RAR grant's frequency allocation).
    pub ul_bwp_rb: u16,
    /// Msg3 Δ (TS 38.214 Table 6.1.2.1.1-5): 2/3/4/6 for µ = 0..3.
    pub msg3_delta: u8,
    /// Common PUSCH TDRA list for the RAR grant's time-resource field.
    pub pusch_tdra_common: Vec<ferrite_l1::config::TdraRow>,
}

/// PUCCH facts MAC needs to pick a resource for UCI.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PucchMacConfig {
    /// Resource sets: (set id, resource ids, max payload bits).
    pub resource_sets: Vec<(u8, Vec<u8>, u16)>,
    /// Per resource: (id, format 0..4, max UCI bits the format carries here).
    pub resources: Vec<(u8, u8, u16)>,
    /// Whether F2 resources may carry HARQ-ACK and CSI together.
    pub simultaneous_harq_ack_csi: bool,
}

/// Periodic CSI report MAC schedules: (period slots, offset slots, pucch resource id).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiReportMacConfig {
    pub period_slots: u16,
    pub offset_slots: u16,
    pub pucch_resource: u8,
}

/// The MAC configuration (from RRC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacConfig {
    pub numerology: Numerology,
    pub rach: RachConfig,
    pub logical_channels: Vec<LogicalChannelConfig>,
    pub sr: Vec<SrConfig>,
    /// `periodicBSR-Timer` ms (0 = infinity) and `retxBSR-Timer` ms.
    pub periodic_bsr_ms: u32,
    pub retx_bsr_ms: u32,
    /// `timeAlignmentTimer` ms (0 = infinity).
    pub time_alignment_timer_ms: u32,
    pub pucch: PucchMacConfig,
    pub csi_reports: Vec<CsiReportMacConfig>,
    pub harq_codebook_dynamic: bool,
    pub nof_dl_harq: u8,
    pub nof_ul_harq: u8,
    /// How many slots ahead of a UL slot the PHY needs its UL_TTI.request.
    pub tx_lead_slots: u16,
    /// Whether the UE is allowed to send CSI reports yet (dedicated config applied).
    pub csi_enabled: bool,
}

impl MacConfig {
    /// A minimal configuration for the pre-connection phase (SIB1 only).
    pub fn initial(numerology: Numerology, rach: RachConfig, tx_lead_slots: u16) -> Self {
        Self {
            numerology,
            rach,
            logical_channels: vec![LogicalChannelConfig {
                lcid: 1,
                priority: 1,
                pbr_bytes_per_ms: None,
                bsd_ms: 1000,
                lcg: 0,
                sr_id: None,
                sr_mask: false,
            }],
            sr: Vec::new(),
            periodic_bsr_ms: 10,
            retx_bsr_ms: 80,
            time_alignment_timer_ms: 0,
            pucch: PucchMacConfig::default(),
            csi_reports: Vec::new(),
            harq_codebook_dynamic: true,
            nof_dl_harq: 16,
            nof_ul_harq: 16,
            tx_lead_slots,
            csi_enabled: false,
        }
    }

    /// Convert milliseconds to slots at the configured numerology (≥1 if ms > 0).
    pub fn ms_to_slots(&self, ms: u32) -> u32 {
        if ms == 0 {
            0
        } else {
            (ms * self.numerology.slots_per_subframe()).max(1)
        }
    }
}
