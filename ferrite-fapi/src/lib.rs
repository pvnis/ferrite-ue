//! FAPI — the PHY ↔ MAC interface (modelled on the SCF-222 5G FAPI PHY API,
//! adapted to the UE direction). This crate holds only plain data: the
//! messages exchanged between `ferrite-l1` (the PHY) and `ferrite-mac`, and
//! the PHY configuration ([`config::PhyConfig`], the CONFIG.request payload)
//! that RRC derives from the broadcast and dedicated signalling. It depends
//! on `ferrite-common` and the spec tables in `ferrite-ran` only, so the MAC
//! and RRC never link the signal-processing crate.
//!
//! Message families, mirroring FAPI naming:
//!
//! | direction | FAPI message | here |
//! |---|---|---|
//! | MAC → PHY | CONFIG.request / START.request / STOP.request | [`MacToPhy::Config`], [`MacToPhy::Start`], [`MacToPhy::Stop`] |
//! | MAC → PHY | UL_TTI.request (PRACH / PUSCH / PUCCH / SRS PDUs for one slot) | [`MacToPhy::UlTti`] |
//! | MAC → PHY | RAR UL grant → Msg3 grant resolution (UE-side; answered by a DCI indication) | [`MacToPhy::RarGrant`] |
//! | MAC → PHY | TX_Data.request (the PUSCH transport block payload) | carried inside [`UlTtiPdu::Pusch`] |
//! | PHY → MAC | SLOT.indication | [`PhyToMac::Slot`] |
//! | PHY → MAC | DCI (UE-side: the decoded PDCCH, not in gNB FAPI) | [`PhyToMac::Dci`] |
//! | PHY → MAC | RX_Data.indication + CRC.indication | [`PhyToMac::RxData`] |
//! | PHY → MAC | UCI/CSI measurement (UE-side CSI report input) | [`PhyToMac::Csi`] |
//! | PHY → MAC | RACH.indication (UE-side: preamble transmitted) | [`PhyToMac::Rach`] |
//! | PHY → MAC | ERROR.indication | [`PhyToMac::Error`] |
//!
//! Everything MAC receives is tagged with the `SlotPoint` it belongs to; every
//! transmission MAC wants goes down as a UL_TTI.request for a future slot. The
//! PHY owns the PHY configuration (CORESETs, search spaces, TDRA tables, k1
//! lists, PUCCH resources, …) and therefore *resolves* raw DCI fields into
//! grants (PRBs, symbols, TBS, HARQ info, timing) before handing them to MAC —
//! MAC never sees DCI bit fields. Sample indices never appear here.

#![forbid(unsafe_code)]

pub mod config;

use ferrite_common::{Rnti, RntiKind, SlotPoint};

/// Modulation order and target code rate of a transport block.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mcs {
    pub index: u8,
    /// Modulation order Qm (2/4/6/8).
    pub qm: u8,
    /// Target code rate R × 1024 (`None` for the reserved "retransmission" MCS
    /// indices, where the TB keeps its original size).
    pub r_x1024: Option<u16>,
}

/// Time-domain shape of a PDSCH/PUSCH (TS 38.214 §5.1.2.1 / §6.1.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAlloc {
    pub mapping_type_a: bool,
    pub start_symbol: u8,
    pub n_symbols: u8,
}

/// A DL assignment as MAC sees it (TS 38.212 §7.3.1.2 fields, resolved).
#[derive(Clone, Debug, PartialEq)]
pub struct DlGrant {
    pub rnti: Rnti,
    pub rnti_kind: RntiKind,
    /// Slot the PDSCH is in (n + k0).
    pub pdsch_slot: SlotPoint,
    pub prb_start: u16,
    pub n_prb: u16,
    pub time: TimeAlloc,
    pub mcs: Mcs,
    /// Transport block size in bits as derived from this DCI (for a
    /// retransmission MAC uses the stored size instead).
    pub tbs_bits: u32,
    pub harq_id: u8,
    pub ndi: u8,
    pub rv: u8,
    /// Slot the HARQ-ACK is due in (n_pdsch + k1); `None` for SI/RA/P-RNTI.
    pub ack_slot: Option<SlotPoint>,
    /// Counter DAI (0..3) from the DCI, for the dynamic HARQ-ACK codebook.
    pub dai: u8,
    /// PUCCH resource indicator (0..7).
    pub pri: u8,
    /// TPC command for PUCCH (0..3).
    pub tpc: u8,
    /// Number of DMRS CDM groups without data (1 or 2).
    pub cdm_groups_wo_data: u8,
    /// Spatial layers (1 or 2) and their DM-RS ports (`1000 + p`, type 1:
    /// ports 0/1 in CDM group 0, 2/3 in group 1).
    pub n_layers: u8,
    pub dmrs_ports: Vec<u8>,
    /// `dmrs-AdditionalPosition` to use (2 for fallback DCI, else configured).
    pub dmrs_add_pos: u8,
    /// VRB-to-PRB mapping bit of the DCI (true = interleaved).
    pub vrb_to_prb_interleaved: bool,
    /// `r_PUCCH` for the common PUCCH resource (TS 38.213 §9.2.1:
    /// ⌊2·n_CCE,0 / N_CCE⌋ + 2·Δ_PRI), used before a dedicated PUCCH config exists.
    pub r_pucch_common: u8,
}

/// A UL grant as MAC sees it (TS 38.212 §7.3.1.1 fields, resolved). Also used
/// for the RAR UL grant (Msg3) with `rnti_kind = Tc`.
#[derive(Clone, Debug, PartialEq)]
pub struct UlGrant {
    pub rnti: Rnti,
    pub rnti_kind: RntiKind,
    /// Slot the PUSCH is in (n + k2 [+ Δ for Msg3]).
    pub pusch_slot: SlotPoint,
    pub prb_start: u16,
    pub n_prb: u16,
    pub time: TimeAlloc,
    pub mcs: Mcs,
    pub tbs_bits: u32,
    pub harq_id: u8,
    pub ndi: u8,
    pub rv: u8,
    /// UL total-DAI for the UCI-on-PUSCH codebook (DCI 0_1 only).
    pub dai: Option<u8>,
    pub tpc: u8,
    /// CSI request bitmap (0 = none).
    pub csi_request: u8,
    /// True when the DCI carries UL-SCH (data); false for a CSI-only PUSCH.
    pub ul_sch: bool,
    /// Number of DMRS CDM groups without data (1 or 2).
    pub cdm_groups_wo_data: u8,
    /// `dmrs-AdditionalPosition` to use (2 for fallback DCI / RAR, else configured).
    pub dmrs_add_pos: u8,
    /// Frequency hopping requested (unsupported by the modulator: MAC refuses).
    pub freq_hopping: bool,
    /// Transform precoding (DFT-s-OFDM) with its DM-RS parameters; `None` =
    /// CP-OFDM.
    pub transform_precoding: Option<TransformPrecoding>,
}

/// Transform-precoded PUSCH parameters (FAPI PUSCH PDU `transformPrecoding`,
/// `nIdPusch`-style identities; TS 38.211 §6.3.1.4 / §6.4.1.1.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformPrecoding {
    /// `n_ID^RS` of the low-PAPR DM-RS (`nPUSCH-Identity` or the cell id).
    pub n_id_rs: u16,
    pub group_hopping: bool,
    pub sequence_hopping: bool,
    /// Table 6.1.4.1-1 `q = 1` rows modulate as π/2-BPSK (`tp-pi2BPSK`).
    pub pi2_bpsk: bool,
}

/// The UL grant fields of a Random Access Response (TS 38.213 Table 8.2-1),
/// as parsed by MAC from the RAR MAC PDU. The PHY resolves them into the Msg3
/// [`UlGrant`] ([`MacToPhy::RarGrant`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RarUlGrant {
    pub freq_hopping: bool,
    /// 14-bit frequency-domain resource allocation (RIV, possibly with hopping bits).
    pub fdra: u16,
    /// 4-bit PUSCH time resource allocation (row of the common PUSCH TDRA list).
    pub time_resource: u8,
    pub mcs: u8,
    /// 3-bit TPC command for Msg3 PUSCH.
    pub tpc: u8,
    pub csi_request: bool,
}

/// The payload of a decoded DCI, per format.
#[derive(Clone, Debug, PartialEq)]
pub enum Dci {
    Dl(DlGrant),
    Ul(UlGrant),
    /// A DCI the PHY recognised but MAC does not act on (paging short
    /// messages, SI scheduling for a SIB the UE has not requested, …).
    Other {
        format: &'static str,
    },
    /// A DCI 1_1 / 0_1 whose bandwidth-part indicator names a BWP other than
    /// the active one (TS 38.213 §12): MAC switches the active BWP; the
    /// grant itself, which would apply on the new BWP, is not resolved.
    BwpSwitch {
        dl_bwp: Option<u8>,
        ul_bwp: Option<u8>,
    },
}

/// SLOT.indication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotIndication {
    pub slot: SlotPoint,
}

/// DCI indication: a CRC-valid DCI found in `slot`.
#[derive(Clone, Debug, PartialEq)]
pub struct DciIndication {
    pub slot: SlotPoint,
    pub dci: Dci,
}

/// RX_Data.indication + CRC.indication: the decode result of a PDSCH.
#[derive(Clone, Debug, PartialEq)]
pub struct RxDataIndication {
    pub rnti: Rnti,
    pub rnti_kind: RntiKind,
    pub harq_id: u8,
    pub ndi: u8,
    /// Slot the PDSCH was received in.
    pub pdsch_slot: SlotPoint,
    /// `Some(bytes)` when the CRC passed (CRC.indication = OK).
    pub tb: Option<Vec<u8>>,
    /// Effective SINR estimate (dB) of the PDSCH, for link monitoring.
    pub sinr_db: f32,
}

/// A CSI measurement from the configured NZP-CSI-RS / TRS.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CsiIndication {
    pub slot: SlotPoint,
    pub sinr_db: f32,
    pub cqi: u8,
    /// Rank indicator (1-based) and the Type I single-panel PMI (`i2`) the
    /// PHY recommends; 1 / 0 for a single-layer receiver.
    pub ri: u8,
    pub pmi: u8,
    /// Wideband RSRP in dBFS (relative to full scale), for cell quality.
    pub rsrp_dbfs: f32,
}

/// RACH.indication (UE side): the requested preamble was transmitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RachIndication {
    pub slot: SlotPoint,
    pub ra_rnti: Rnti,
    pub preamble: u8,
}

/// ERROR.indication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorIndication {
    /// A UL_TTI PDU for `slot` could not be transmitted (too late / overlap).
    TxDropped { slot: SlotPoint, pdu: &'static str },
    /// PSS/SSB not found for several SSB periods: synchronisation lost.
    SyncLost,
    /// The radio stream ended or failed.
    Radio,
}

/// Radio link monitoring result for one evaluation period (TS 38.213 §5,
/// TS 38.133 §8.1): the PHY compares the serving-cell RLM-RS (SSB) quality
/// with Q_out / Q_in and reports `in_sync = false` when it is below Q_out (or
/// the SSB was not found) and `in_sync = true` when it is above Q_in. RRC
/// counts the indications (N310 / N311) and runs T310 (TS 38.331 §5.3.10).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SyncIndication {
    pub slot: SlotPoint,
    pub in_sync: bool,
}

/// PHY → MAC messages, delivered in slot order on the PHY's timeline thread.
#[derive(Clone, Debug, PartialEq)]
pub enum PhyToMac {
    Slot(SlotIndication),
    Dci(DciIndication),
    RxData(RxDataIndication),
    Csi(CsiIndication),
    Rach(RachIndication),
    /// Out-of-sync / in-sync indication from radio link monitoring; MAC passes
    /// it up unchanged (it is an L1 → RRC indication).
    Sync(SyncIndication),
    Error(ErrorIndication),
}

/// HARQ-ACK / SR / CSI bits for a PUCCH or for UCI on PUSCH.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UciPayload {
    /// HARQ-ACK bits in codebook order (1 = ACK), possibly empty.
    pub harq_ack: Vec<u8>,
    /// Scheduling request: `None` = no SR occasion here, `Some(true)` = positive.
    pub sr: Option<bool>,
    /// CSI part 1 bits (wideband CQI MSB first), possibly empty.
    pub csi1: Vec<u8>,
}

/// Which PUCCH resource to use. MAC picks by codebook size / PRI / SR
/// occasion from the PUCCH configuration; the PHY maps it to PRBs/symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PucchResourceRef {
    /// A dedicated resource by `pucch-ResourceId`.
    Dedicated(u8),
    /// The common PUCCH resource (before dedicated config), TS 38.213 §9.2.1:
    /// `r_PUCCH` (0..15) from the PRI and the CCE index of the scheduling DCI.
    Common { r_pucch: u8 },
}

/// A PRACH occasion selected by MAC (TS 38.211 §6.3.3.2 / 38.213 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachOccasion {
    /// Slot (at the PUSCH numerology) containing the occasion.
    pub slot: SlotPoint,
    pub start_symbol: u8,
    /// Frequency-domain occasion index (0..msg1-FDM).
    pub freq_index: u8,
    /// Time-domain occasion index within the PRACH slot.
    pub time_index: u8,
    /// RA-RNTI for this occasion (TS 38.321 §5.1.3).
    pub ra_rnti: Rnti,
    /// Start of the occasion within its subframe, in T_c units (TS 38.211 §5.3.2).
    pub start_tc: u64,
}

/// One PDU of a UL_TTI.request.
#[derive(Clone, Debug)]
pub enum UlTtiPdu {
    /// Transmit a preamble on an occasion (MAC chose preamble + occasion).
    Prach {
        occasion: PrachOccasion,
        preamble: u8,
        power_offset_db: f32,
    },
    /// Transmit a PUSCH for a grant with the given MAC PDU (TX_Data.request
    /// payload) and the UCI multiplexed onto it, if any.
    Pusch {
        grant: UlGrant,
        tb: Vec<u8>,
        uci: UciPayload,
    },
    /// Transmit a PUCCH on `resource` with `uci`.
    Pucch {
        resource: PucchResourceRef,
        uci: UciPayload,
    },
    /// Transmit the SRS resource `resource_id` (its periodic occasion).
    Srs { resource_id: u8 },
}

/// UL_TTI.request: everything MAC wants transmitted in `slot`.
#[derive(Clone, Debug)]
pub struct UlTtiRequest {
    pub slot: SlotPoint,
    pub pdus: Vec<UlTtiPdu>,
}

/// MAC → PHY messages.
#[derive(Clone, Debug)]
pub enum MacToPhy {
    /// CONFIG.request: apply a new PHY configuration (cell-common and/or dedicated).
    Config(Box<crate::config::PhyConfig>),
    /// START.request: begin (or resume) slot processing / transmissions.
    Start,
    /// STOP.request: stop transmitting entirely (RRC idle / RLF).
    Stop,
    /// UL_TTI.request (+ TX_Data) for one future slot.
    UlTti(UlTtiRequest),
    /// Set the RNTIs the PHY monitors (C-RNTI / TC-RNTI / RA-RNTI). `None` clears.
    SetRntis {
        c_rnti: Option<Rnti>,
        tc_rnti: Option<Rnti>,
        ra_rnti: Option<Rnti>,
    },
    /// Absolute N_TA in T_c units (MAC maintains it from the RAR + TA MAC CEs).
    TimingAdvance { n_ta_tc: i64 },
    /// Monitor paging for this UE_ID (5G-S-TMSI mod 1024); `None` stops.
    Paging { ue_id: Option<u16> },
    /// DRX (TS 38.321 §5.7): whether the PDCCH candidates addressed to the
    /// C-RNTI are monitored from this slot on (`false` outside Active Time).
    /// SI-, RA-, TC-, P-RNTI monitoring is unaffected.
    PdcchMonitoring { c_rnti: bool },
    /// Resolve a RAR UL grant (TS 38.213 §8.2 / §8.3) into the Msg3 PUSCH
    /// grant. The PHY answers with a [`PhyToMac::Dci`] carrying
    /// `Dci::Ul(UlGrant { rnti_kind: Tc, harq_id: 0, ndi: 0, .. })` for the
    /// slot `rar_slot + k2 + Δ`; MAC then builds Msg3 like any other PUSCH.
    RarGrant {
        rar_slot: SlotPoint,
        tc_rnti: Rnti,
        grant: RarUlGrant,
    },
}

/// What MAC implements: the PHY calls this on its timeline thread.
pub trait MacHandler {
    /// Handle one PHY → MAC message. MAC → PHY messages go through `phy`.
    fn handle(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink);
}

/// Where MAC puts its MAC → PHY messages.
pub trait MacToPhySink {
    fn send(&mut self, msg: MacToPhy);
}

impl MacToPhySink for Vec<MacToPhy> {
    fn send(&mut self, msg: MacToPhy) {
        self.push(msg);
    }
}
