//! PHY configuration as delivered by CONFIG.request (RRC → MAC → PHY).
//!
//! Plain data derived by RRC from the MIB, SIB1 and the dedicated
//! `CellGroupConfig`; no ASN.1 types. Every field has the TS 38.331 IE it comes
//! from in its doc comment. The PHY resolves DCIs and places transmissions from
//! this alone, so nothing here may be cell-specific by construction.

use ferrite_common::{DuplexMode, Numerology};

/// `TDD-UL-DL-Pattern` (TS 38.331) at the reference SCS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TddPattern {
    pub period_slots: u16,
    pub dl_slots: u16,
    pub dl_symbols: u8,
    pub ul_slots: u16,
    pub ul_symbols: u8,
}

/// `TDD-UL-DL-ConfigCommon`: pattern1 (+ pattern2) at `reference_scs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TddConfig {
    pub reference_scs: Numerology,
    pub pattern1: TddPattern,
    pub pattern2: Option<TddPattern>,
}

/// What a slot's symbols are, per the TDD configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotDirection {
    /// Number of leading DL symbols (14 = full DL slot).
    pub dl_symbols: u8,
    /// Number of trailing UL symbols (14 = full UL slot).
    pub ul_symbols: u8,
}

impl TddConfig {
    /// Direction of `slot` (absolute slot index at the data numerology `mu`).
    pub fn slot_direction(&self, slot_index: u64, mu: Numerology) -> SlotDirection {
        // Scale the pattern (given at the reference SCS) to the data numerology.
        let scale = mu.slots_per_subframe() as u64 / self.reference_scs.slots_per_subframe().max(1) as u64;
        let scale = scale.max(1);
        let p1 = self.pattern1.period_slots as u64 * scale;
        let total = p1 + self.pattern2.map_or(0, |p| p.period_slots as u64 * scale);
        let s = slot_index % total;
        let (pat, s) = if s < p1 { (self.pattern1, s) } else { (self.pattern2.unwrap(), s - p1) };
        let dl_full = pat.dl_slots as u64 * scale;
        let ul_full = pat.ul_slots as u64 * scale;
        let period = pat.period_slots as u64 * scale;
        if s < dl_full {
            SlotDirection { dl_symbols: 14, ul_symbols: 0 }
        } else if s >= period - ul_full {
            SlotDirection { dl_symbols: 0, ul_symbols: 14 }
        } else {
            // The flexible region, spread over (period − dl_full − ul_full) slots:
            // the first carries the leading DL symbols, the last the trailing UL
            // symbols (at the reference SCS these coincide in one special slot).
            let flex = period - dl_full - ul_full;
            let i = s - dl_full;
            let dl = if i == 0 { pat.dl_symbols } else { 0 };
            let ul = if i == flex - 1 { pat.ul_symbols } else { 0 };
            SlotDirection { dl_symbols: dl, ul_symbols: ul }
        }
    }
}

/// A time-domain resource allocation row (`PDSCH/PUSCH-TimeDomainResourceAllocation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdraRow {
    /// k0 (PDSCH) or k2 (PUSCH), in slots.
    pub k: u8,
    pub mapping_type_a: bool,
    pub start_symbol: u8,
    pub n_symbols: u8,
}

/// SSB properties (MIB + SIB1 + band).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SsbConfig {
    pub pci: u16,
    pub scs: Numerology,
    /// `ssb-PeriodicityServingCell` in ms (5/10/20/40/80/160).
    pub period_ms: u16,
    /// Candidate index of the SSB the UE synchronised to (0..L_max).
    pub ssb_index: u8,
    /// `k_SSB` (MIB ssb-SubcarrierOffset + msb), 15 kHz units in FR1.
    pub k_ssb: u8,
    /// `dmrs-TypeA-Position`: 2 or 3.
    pub dmrs_typea_pos: u8,
}

/// Bandwidth part (common or dedicated): `BWP` generic parameters resolved to CRBs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bwp {
    /// First common resource block (relative to point A) of the BWP.
    pub start_crb: u16,
    pub n_rb: u16,
    pub scs: Numerology,
}

/// CORESET geometry (`ControlResourceSet`). CORESET#0 is expressed the same way
/// with `id = 0`, its RBs derived from TS 38.213 Table 13-x.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoresetConfig {
    pub id: u8,
    /// Lowest CRB of the CORESET.
    pub start_crb: u16,
    /// RB occupation relative to `start_crb` (true = used), length = 6·groups.
    pub rb_mask: Vec<bool>,
    pub duration: u8,
    /// `cce-REG-MappingType`: `Some((L, R, n_shift))` for interleaved, `None` otherwise.
    pub interleaved: Option<(u8, u8, u16)>,
    /// `pdcch-DMRS-ScramblingID` (None → cell id).
    pub dmrs_scrambling_id: Option<u16>,
    /// True for CORESET#0 / controlResourceSetZero: DMRS and RB indexing are
    /// referenced to the CORESET's lowest RB instead of CRB 0.
    pub ref_lowest_rb: bool,
}

/// `SearchSpace` (TS 38.331) resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSpaceConfig {
    pub id: u8,
    pub coreset_id: u8,
    pub period_slots: u16,
    pub offset_slots: u16,
    pub duration_slots: u16,
    /// `monitoringSymbolsWithinSlot` (bit l = symbol l is a monitoring start).
    pub symbols: [bool; 14],
    /// `nrofCandidates` per aggregation level 1/2/4/8/16.
    pub candidates: [u8; 5],
    pub kind: SearchSpaceKind,
}

/// Where and when the UE monitors paging (TS 38.304 §7.1, TS 38.331 `PCCH-Config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingConfig {
    /// `defaultPagingCycle` T in radio frames.
    pub t_rf: u16,
    /// `nAndPagingFrameOffset`: N = T / n_div.
    pub n_div: u8,
    /// PF_offset.
    pub offset: u8,
    /// `ns`: paging occasions per paging frame.
    pub ns: u8,
    /// `pagingSearchSpace` (0 = the Type0 CSS).
    pub search_space_id: u8,
}

impl PagingConfig {
    /// Is `sfn` a paging frame of the UE with `ue_id` = 5G-S-TMSI mod 1024?
    /// `(SFN + PF_offset) mod T = (T div N) × (UE_ID mod N)`.
    pub fn is_paging_frame(&self, sfn: u16, ue_id: u16) -> bool {
        let t = u32::from(self.t_rf).max(1);
        let n = (t / u32::from(self.n_div.max(1))).max(1);
        (u32::from(sfn) + u32::from(self.offset)) % t == (t / n) * (u32::from(ue_id) % n)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchSpaceKind {
    /// Common: monitors DCI 0_0/1_0 with SI/RA/P/TC/C-RNTI as applicable.
    Common,
    /// UE-specific with DCI 0_0/1_0.
    UeSpecificFallback,
    /// UE-specific with DCI 0_1/1_1.
    UeSpecificNonFallback,
}

/// `RACH-ConfigCommon` + `RACH-ConfigGeneric` (the PHY-relevant subset).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrachConfig {
    /// Index/duplex/numerology/FDM/frequency start — the occasion pattern
    /// (TS 38.211 Table 6.3.3.2-2/-3) is enumerated by `ferrite_phy::prach_config`.
    pub phy: ferrite_phy::prach_config::PrachConfig,
    pub zero_correlation_zone: u8,
    pub root_sequence_index: u16,
    pub restricted_set: u8,
    pub total_preambles: u8,
    /// `preambleReceivedTargetPower` (dBm).
    pub target_power_dbm: i16,
    pub power_ramping_step_db: u8,
}

impl PrachConfig {
    /// All PRACH occasions whose transmission starts in data-numerology slot `slot`.
    pub fn occasions_in_slot(&self, slot: ferrite_common::SlotPoint) -> Vec<crate::fapi::PrachOccasion> {
        ferrite_phy::prach_config::prach_occasions_in_slot(&self.phy, slot)
            .map(|v| {
                v.into_iter()
                    .map(|o| crate::fapi::PrachOccasion {
                        slot,
                        start_symbol: o.start_symbol,
                        freq_index: o.freq_index,
                        time_index: o.time_index,
                        ra_rnti: ferrite_common::Rnti(o.ra_rnti(false)),
                        start_tc: o.start_tc,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// DMRS configuration for PDSCH or PUSCH mapping type A/B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmrsConfig {
    /// `dmrs-AdditionalPosition` 0..3 (default 2).
    pub additional_position: u8,
    /// `scramblingID0` (None → cell id).
    pub scrambling_id0: Option<u16>,
}

impl Default for DmrsConfig {
    fn default() -> Self {
        Self { additional_position: 2, scrambling_id0: None }
    }
}

/// MCS table selection (`mcs-Table`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum McsTableSel {
    #[default]
    Qam64,
    Qam256,
    Qam64LowSe,
}

/// `PDSCH-Config` (dedicated) subset.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PdschConfig {
    pub dmrs_type_a: DmrsConfig,
    pub dmrs_type_b: DmrsConfig,
    pub mcs_table: McsTableSel,
    /// Dedicated TDRA list (empty → common / default table applies).
    pub tdra: Vec<TdraRow>,
    /// `vrb-ToPRB-Interleaver` bundle size if configured.
    pub vrb_to_prb_interleaver: Option<u8>,
    /// `nrofHARQ-ProcessesForPDSCH` (default 8).
    pub nof_harq_processes: u8,
    /// ZP/NZP CSI-RS resources the PDSCH is rate-matched around.
    pub csi_rs_rate_match: Vec<CsiRsResource>,
}

/// `PUSCH-Config` (dedicated) subset.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PuschConfig {
    pub dmrs_type_a: DmrsConfig,
    pub dmrs_type_b: DmrsConfig,
    pub mcs_table: McsTableSel,
    pub tdra: Vec<TdraRow>,
    pub transform_precoder: bool,
    /// `uci-OnPUSCH` beta offsets (semi-static set): (ack idx, csi1 idx, csi2 idx).
    pub beta_offsets: Option<BetaOffsets>,
    /// `uci-OnPUSCH.scaling`: 0=0.5, 1=0.65, 2=0.8, 3=1.0.
    pub uci_scaling: u8,
    /// `frequencyHopping` configured (affects the DCI 0_1 size).
    pub frequency_hopping: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BetaOffsets {
    pub ack_index1: u8,
    pub ack_index2: u8,
    pub ack_index3: u8,
    pub csi1_index1: u8,
    pub csi1_index2: u8,
    pub csi2_index1: u8,
    pub csi2_index2: u8,
}

/// `PUCCH-Resource`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchResource {
    pub id: u8,
    pub starting_prb: u16,
    pub second_hop_prb: Option<u16>,
    pub format: PucchFormat,
    pub start_symbol: u8,
    pub n_symbols: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PucchFormat {
    F0 { initial_cyclic_shift: u8 },
    F1 { initial_cyclic_shift: u8, time_domain_occ: u8 },
    F2 { n_prb: u8 },
    F3 { n_prb: u8 },
    F4 { occ_length: u8, occ_index: u8 },
}

/// `PUCCH-ResourceSet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PucchResourceSet {
    pub id: u8,
    pub resources: Vec<u8>,
    pub max_payload: Option<u16>,
}

/// `SchedulingRequestResourceConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrResource {
    pub sr_resource_id: u8,
    pub sr_id: u8,
    pub period_slots: u16,
    pub offset_slots: u16,
    pub pucch_resource: u8,
}

/// `PUCCH-FormatConfig` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PucchFormatConfig {
    pub additional_dmrs: bool,
    pub max_code_rate_x100: Option<u8>,
    pub simultaneous_harq_ack_csi: bool,
    /// `pi2BPSK` (formats 3/4): π/2-BPSK instead of QPSK.
    pub pi2_bpsk: bool,
}

/// `PUCCH-Config` (dedicated) + `PUCCH-ConfigCommon`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PucchConfig {
    /// `pucch-ResourceCommon` row (TS 38.213 Table 9.2.1-1), if any.
    pub resource_common: Option<u8>,
    /// `hoppingId` (None → cell id); `pucch-GroupHopping` is neither/enable/disable (0/1/2).
    pub hopping_id: Option<u16>,
    pub group_hopping: u8,
    pub resource_sets: Vec<PucchResourceSet>,
    pub resources: Vec<PucchResource>,
    pub format1: PucchFormatConfig,
    pub format2: PucchFormatConfig,
    pub format3: PucchFormatConfig,
    pub sr_resources: Vec<SrResource>,
    /// `dl-DataToUL-ACK` (k1 list).
    pub k1_list: Vec<u8>,
}

/// One SRS resource: its PHY parameters and, for a periodic resource, the
/// occasions (`period_slots`/`offset_slots`); aperiodic/semi-persistent
/// resources have `period_slots = 0` (not transmitted today).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrsResourceConfig {
    pub id: u8,
    pub params: ferrite_phy::srs::SrsResourceParams,
    pub period_slots: u16,
    pub offset_slots: u16,
}

/// One CSI-RS resource (NZP or ZP) as a PHY RE pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiRsResource {
    pub zero_power: bool,
    /// `nzp-CSI-RS-ResourceId` / `zp-CSI-RS-ResourceId` (separate id spaces).
    pub id: u8,
    /// Row of TS 38.211 Table 7.4.1.5.3-1.
    pub row: u8,
    pub freq_bits: u16,
    pub first_symbol: u8,
    pub second_symbol: Option<u8>,
    /// Density ×2: 1 = dot5, 2 = one, 6 = three.
    pub density_x2: u8,
    pub start_rb: u16,
    pub n_rb: u16,
    pub period_slots: u16,
    pub offset_slots: u16,
    pub scrambling_id: u16,
    /// True for a TRS (nzp set with trs-Info) — used for timing/CQI measurement.
    pub trs: bool,
}

/// Periodic CSI report on PUCCH (`CSI-ReportConfig.periodic`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiReportConfig {
    pub report_id: u8,
    pub period_slots: u16,
    pub offset_slots: u16,
    pub pucch_resource: u8,
    /// `cqi-Table`: 0 = table1, 1 = table2, 2 = table3.
    pub cqi_table: u8,
}

/// A carrier (`SCS-SpecificCarrier`): where the sampled stream sits on the CRB grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carrier {
    /// `offsetToCarrier`: CRB (at the carrier SCS) of the carrier's first RB.
    pub offset_crb: u16,
    /// `carrierBandwidth` in RBs. The stream's DC is at subcarrier `6·n_rb`
    /// of the carrier (its centre).
    pub n_rb: u16,
}

/// Everything the PHY needs. `dedicated` fields are `None`/empty until RRC
/// connected; the common part is complete after SIB1.
#[derive(Clone, Debug, PartialEq)]
pub struct PhyConfig {
    pub duplex: DuplexMode,
    /// Paging (SIB1 `pcch-Config` + `pagingSearchSpace`), `None` = never monitor P-RNTI.
    pub paging: Option<PagingConfig>,
    /// Data numerology (`subcarrierSpacing` of the initial BWPs).
    pub numerology: Numerology,
    pub ssb: SsbConfig,
    /// The DL and UL carriers on their CRB grids.
    pub dl_carrier: Carrier,
    pub ul_carrier: Carrier,
    /// CRB (at the data SCS) of the SSB's first subcarrier RB, i.e. the common RB
    /// overlapping the SSB start (`offsetToPointA` converted) — with `ssb.k_ssb`
    /// the extra subcarrier offset.
    pub ssb_crb: u16,
    pub dl_bwp: Bwp,
    pub ul_bwp: Bwp,
    pub tdd: Option<TddConfig>,
    pub coresets: Vec<CoresetConfig>,
    pub search_spaces: Vec<SearchSpaceConfig>,
    /// `searchSpaceZero` index.
    pub ss0_index: u8,
    /// Common TDRA lists from SIB1 (empty → default tables).
    pub pdsch_tdra_common: Vec<TdraRow>,
    pub pusch_tdra_common: Vec<TdraRow>,
    pub prach: PrachConfig,
    /// `n-TimingAdvanceOffset` in T_c (25600 default).
    pub n_ta_offset_tc: u32,
    pub pdsch: PdschConfig,
    pub pusch: PuschConfig,
    pub pucch: PucchConfig,
    pub csi_reports: Vec<CsiReportConfig>,
    /// SRS resources (`SRS-Config`), one antenna port each.
    pub srs: Vec<SrsResourceConfig>,
    /// `pdsch-HARQ-ACK-Codebook` dynamic (true) / semi-static.
    pub harq_codebook_dynamic: bool,
    /// Transmit power (full-scale fraction) for UL waveforms; the radio backend
    /// applies the actual gain.
    pub ul_amplitude: f32,
}
