//! Ferrite MAC layer (3GPP TS 38.321).
//!
//! Clean-room MAC-layer processing for the Ferrite 5G NR UE: MAC PDU
//! multiplexing/demultiplexing (subheaders + SDUs + control elements) and the
//! MAC control elements the UE builds and consumes (Short BSR, Timing Advance
//! Command, UE Contention Resolution Identity, CCCH). Pure byte-level framing —
//! no radio, PHY, or higher-layer (RLC/PDCP/RRC) dependencies — so the RLC/PDCP
//! payloads are passed in as opaque octet strings by the caller.
//!
//! This is the transport-block-facing half of the MAC: the scheduling/HARQ
//! entity (which drives *when* these PDUs are built) is layered on top.

pub mod ce;
pub mod pdu;

pub use ce::{bsr_index, mac_short_bsr, parse_ta_command_ce, plausible_mac_pdu};
pub use pdu::{
    drb_mac_wrap, drb_mac_wrap_bsr, msg3_mac_pdu, parse_dl_mac_pdu, sdu_subpdu, DlSubPdu,
};

// ---------------------------------------------------------------------------
// LCID values (TS 38.321 Table 6.2.1-1 DL-SCH, Table 6.2.1-2 UL-SCH).
// LCIDs are direction-specific; the names encode which channel they apply to.
// ---------------------------------------------------------------------------

/// Logical channels 1..=32 carry DCCH/DTCH SDUs (both directions). SRB1 = 1.
pub const LCID_SRB1: u8 = 1;
/// DRB 1 logical channel identity (from the masterCellGroup RLC-BearerConfig).
pub const LCID_DRB1: u8 = 4;

/// UL-SCH: 48-bit CCCH SDU (Msg3 RRCSetupRequest), no length field.
pub const LCID_UL_CCCH48: u8 = 52;
/// UL-SCH: Short Buffer Status Report MAC CE (fixed 1-octet payload).
pub const LCID_SHORT_BSR: u8 = 61;

/// DL-SCH: CCCH SDU (Msg4 RRCSetup), carried with a length field.
pub const LCID_DL_CCCH: u8 = 0;
/// DL-SCH: Timing Advance Command MAC CE (fixed 1-octet payload).
pub const LCID_TA_COMMAND: u8 = 61;
/// DL-SCH: UE Contention Resolution Identity MAC CE (fixed 6-octet payload).
pub const LCID_DL_CON_RES: u8 = 62;

/// Padding (both directions): the remainder of the transport block.
pub const LCID_PADDING: u8 = 63;
