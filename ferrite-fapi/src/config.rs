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

/// Link direction of a transmission checked against the TDD pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    Dl,
    Ul,
}

impl TddConfig {
    /// Whether symbols `[start, start + n)` of `slot` conflict with the
    /// pattern for a transmission in `dir`: DL symbols block an uplink, UL
    /// symbols block a downlink; flexible symbols block neither (TS 38.213
    /// §11.1: a DCI may schedule in flexible symbols).
    pub fn conflicts(
        &self,
        slot_index: u64,
        mu: Numerology,
        start: u8,
        n: u8,
        dir: LinkDirection,
    ) -> bool {
        let d = self.slot_direction(slot_index, mu);
        let end = start.saturating_add(n).min(14);
        let (lo, hi) = match dir {
            // Symbols [0, dl_symbols) are DL.
            LinkDirection::Ul => (0u8, d.dl_symbols),
            // Symbols [14 − ul_symbols, 14) are UL.
            LinkDirection::Dl => (14u8.saturating_sub(d.ul_symbols), 14),
        };
        start < hi && end > lo && lo < hi
    }

    /// Direction of `slot` (absolute slot index at the data numerology `mu`).
    pub fn slot_direction(&self, slot_index: u64, mu: Numerology) -> SlotDirection {
        // Scale the pattern (given at the reference SCS) to the data numerology.
        let scale =
            mu.slots_per_subframe() as u64 / self.reference_scs.slots_per_subframe().max(1) as u64;
        let scale = scale.max(1);
        let p1 = self.pattern1.period_slots as u64 * scale;
        let total = p1 + self.pattern2.map_or(0, |p| p.period_slots as u64 * scale);
        let s = slot_index % total;
        let (pat, s) = if s < p1 {
            (self.pattern1, s)
        } else {
            (self.pattern2.unwrap(), s - p1)
        };
        let dl_full = pat.dl_slots as u64 * scale;
        let ul_full = pat.ul_slots as u64 * scale;
        let period = pat.period_slots as u64 * scale;
        if s < dl_full {
            SlotDirection {
                dl_symbols: 14,
                ul_symbols: 0,
            }
        } else if s >= period - ul_full {
            SlotDirection {
                dl_symbols: 0,
                ul_symbols: 14,
            }
        } else {
            // The flexible region, spread over (period − dl_full − ul_full) slots:
            // the first carries the leading DL symbols, the last the trailing UL
            // symbols (at the reference SCS these coincide in one special slot).
            let flex = period - dl_full - ul_full;
            let i = s - dl_full;
            let dl = if i == 0 { pat.dl_symbols } else { 0 };
            let ul = if i == flex - 1 { pat.ul_symbols } else { 0 };
            SlotDirection {
                dl_symbols: dl,
                ul_symbols: ul,
            }
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
    /// `BWP-Id` (0 = the initial BWP).
    pub id: u8,
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

/// Symbols of one transmitted SS/PBCH block, at the data numerology: used
/// for the PRACH occasion validity rule of TS 38.211 §6.3.3.2 (an occasion in
/// flexible symbols must not precede an SSB of its slot and must start
/// `N_gap` symbols after the SSB's last symbol).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsbSlotSymbols {
    /// Slot within the half frame carrying the burst.
    pub slot_in_half_frame: u8,
    pub first_symbol: u8,
    pub last_symbol: u8,
}

/// `RACH-ConfigCommon` + `RACH-ConfigGeneric` (the PHY-relevant subset).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrachConfig {
    /// Index/duplex/numerology/FDM/frequency start — the occasion pattern
    /// (TS 38.211 Table 6.3.3.2-2/-3) is enumerated by `ferrite_ran::prach_config`.
    pub phy: ferrite_ran::prach_config::PrachConfig,
    /// The cell's TDD pattern (`None` on FDD): PRACH occasions overlapping
    /// DL symbols are invalid (TS 38.211 §6.3.3.2).
    pub tdd: Option<TddConfig>,
    /// The transmitted SS/PBCH blocks of a burst and the burst period, for
    /// the occasion validity rule in flexible symbols.
    pub ssb_symbols: Vec<SsbSlotSymbols>,
    pub ssb_period_ms: u16,
    pub zero_correlation_zone: u8,
    pub root_sequence_index: u16,
    pub restricted_set: u8,
    pub total_preambles: u8,
    /// `preambleReceivedTargetPower` (dBm).
    pub target_power_dbm: i16,
    pub power_ramping_step_db: u8,
}

impl PrachConfig {
    /// Duration of an occasion of `format` in data-numerology symbols
    /// (rounded up; long formats longer than a slot count as the whole slot).
    fn occasion_symbols(&self, format: ferrite_ran::prach_config::PreambleFormat, mu: u8) -> u8 {
        let Ok(p) = ferrite_ran::prach_config::format_params(format, self.phy.msg1_scs_mu) else {
            return 14;
        };
        // Normal-CP symbol at mu: (2048 + 144) · 64 / 2^mu T_c.
        let symbol_tc = ((2048u64 + 144) * 64) >> mu;
        p.nominal_tc.div_ceil(symbol_tc).clamp(1, 14) as u8
    }

    /// TS 38.211 §6.3.3.2 (TDD): an occasion is valid when it lies within UL
    /// symbols, or when it is in flexible symbols, does not precede an SS/PBCH
    /// block of its slot and starts at least `N_gap` symbols after the last
    /// SSB symbol (`N_gap` = 0 for the long preamble formats, 2 otherwise).
    /// Always valid on FDD.
    pub fn occasion_valid(
        &self,
        slot: ferrite_common::SlotPoint,
        start_symbol: u8,
        n_symbols: u8,
        format: ferrite_ran::prach_config::PreambleFormat,
    ) -> bool {
        let Some(tdd) = &self.tdd else { return true };
        let d = tdd.slot_direction(slot.index(), slot.numerology);
        let end = start_symbol.saturating_add(n_symbols).min(14);
        if start_symbol >= 14u8.saturating_sub(d.ul_symbols) {
            return true; // within UL symbols
        }
        if start_symbol < d.dl_symbols {
            return false; // overlaps DL symbols
        }
        // Flexible symbols: the SSB rule, for the half frames that carry a burst.
        let spf = slot.numerology.slots_per_frame() as u16;
        let frames_per_burst = (self.ssb_period_ms / 10).max(1);
        let burst_frame = slot.sfn.is_multiple_of(frames_per_burst);
        if !burst_frame || slot.slot >= spf / 2 {
            return true;
        }
        use ferrite_ran::prach_config::PreambleFormat as F;
        let n_gap = if matches!(format, F::F0 | F::F1 | F::F2 | F::F3) {
            0
        } else {
            2
        };
        let _ = end;
        self.ssb_symbols
            .iter()
            .filter(|s| u16::from(s.slot_in_half_frame) == slot.slot)
            .all(|s| start_symbol >= s.last_symbol + 1 + n_gap)
    }

    /// All valid PRACH occasions whose transmission starts in data-numerology slot `slot`.
    pub fn occasions_in_slot(&self, slot: ferrite_common::SlotPoint) -> Vec<crate::PrachOccasion> {
        let mu = slot.numerology.mu;
        ferrite_ran::prach_config::prach_occasions_in_slot(&self.phy, slot)
            .map(|v| {
                v.into_iter()
                    .filter(|o| {
                        self.occasion_valid(
                            slot,
                            o.start_symbol,
                            self.occasion_symbols(o.format, mu),
                            o.format,
                        )
                    })
                    .map(|o| crate::PrachOccasion {
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
        Self {
            additional_position: 2,
            scrambling_id0: None,
        }
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
    /// Transform precoding for PUSCH scheduled by DCI 0_1: `transformPrecoder`
    /// of PUSCH-Config when present, else `msg3_transform_precoder`.
    pub transform_precoder: bool,
    /// `msg3-transformPrecoder` (SIB1 RACH-ConfigCommon): transform precoding
    /// for Msg3 and every PUSCH scheduled by a RAR grant or DCI 0_0.
    pub msg3_transform_precoder: bool,
    /// `groupHoppingEnabledTransformPrecoding` (SIB1 PUSCH-ConfigCommon).
    pub msg3_group_hopping: bool,
    /// `mcs-TableTransformPrecoder` (TS 38.214 §6.1.4.1: qam256 selects Table
    /// 5.1.3.1-2, otherwise Table 6.1.4.1-1 applies when transform precoding
    /// is enabled).
    pub mcs_table_tp: McsTableSel,
    /// `tp-pi2BPSK`: the `q = 1` rows of Table 6.1.4.1-1 use π/2-BPSK.
    pub tp_pi2_bpsk: bool,
    /// `DMRS-UplinkConfig.transformPrecodingEnabled` (mapping type A).
    pub tp_dmrs: TpDmrsConfig,
    /// `dataScramblingIdentityPUSCH` (not yet applied: OCUDU leaves it absent).
    pub data_scrambling_identity: Option<u16>,
    /// `uci-OnPUSCH` beta offsets (semi-static set): (ack idx, csi1 idx, csi2 idx).
    pub beta_offsets: Option<BetaOffsets>,
    /// `uci-OnPUSCH.scaling`: 0=0.5, 1=0.65, 2=0.8, 3=1.0.
    pub uci_scaling: u8,
    /// `frequencyHopping` configured (affects the DCI 0_1 size).
    pub frequency_hopping: bool,
}

/// `DMRS-UplinkConfig.transformPrecodingEnabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TpDmrsConfig {
    /// `nPUSCH-Identity` (None → cell id).
    pub n_pusch_identity: Option<u16>,
    /// `sequenceGroupHopping = disabled` present.
    pub group_hopping_disabled: bool,
    /// `sequenceHopping = enabled` present.
    pub sequence_hopping: bool,
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
    F0 {
        initial_cyclic_shift: u8,
    },
    F1 {
        initial_cyclic_shift: u8,
        time_domain_occ: u8,
    },
    F2 {
        n_prb: u8,
    },
    F3 {
        n_prb: u8,
    },
    F4 {
        occ_length: u8,
        occ_index: u8,
    },
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
    pub params: ferrite_ran::srs::SrsResourceParams,
    pub period_slots: u16,
    pub offset_slots: u16,
}

/// One CSI-RS resource (NZP or ZP) as a PHY RE pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiRsResource {
    pub zero_power: bool,
    /// `nzp-CSI-RS-ResourceId` / `zp-CSI-RS-ResourceId` (separate id spaces).
    pub id: u8,
    /// Row of TS 38.211 Table 7.4.1.5.3-1 as the `frequencyDomainAllocation`
    /// choice names it: 1, 2, 4, or 0 for `other` (rows 3 and 5+, told apart
    /// by `nof_ports`).
    pub row: u8,
    /// `nrofPorts`.
    pub nof_ports: u8,
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
    /// `reportQuantity`.
    pub quantity: CsiReportQuantity,
    /// CSI-RS antenna ports of the PMI codebook (1 without a `codebookConfig`).
    pub nof_ports: u8,
    /// `typeI-SinglePanel-ri-Restriction` (TS 38.214 §5.2.2.2.1: bit `i`,
    /// r0 = LSB, allows rank `i + 1`); `0x01` without a codebook.
    pub ri_restriction: u8,
}

/// `CSI-ReportConfig.reportQuantity`, the part the UE implements (TS 38.214
/// §5.2.1.4): CQI alone, with RI, or with RI and PMI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CsiReportQuantity {
    #[default]
    Cqi,
    RiCqi,
    RiPmiCqi,
}

impl CsiReportConfig {
    /// Ranks the `ri-Restriction` allows, ascending (rank 1 when nothing is set).
    pub fn allowed_ranks(&self) -> Vec<u8> {
        let v: Vec<u8> = (0..8u8)
            .filter(|i| self.ri_restriction & (1 << i) != 0)
            .map(|i| i + 1)
            .collect();
        if v.is_empty() {
            vec![1]
        } else {
            v
        }
    }
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

impl PhyConfig {
    /// Whether a downlink reception in symbols `[start, start + n)` of `slot`
    /// is compatible with the TDD pattern (always on FDD).
    pub fn dl_allowed(&self, slot: ferrite_common::SlotPoint, start: u8, n: u8) -> bool {
        self.tdd.as_ref().is_none_or(|t| {
            !t.conflicts(slot.index(), slot.numerology, start, n, LinkDirection::Dl)
        })
    }

    /// Whether an uplink transmission in symbols `[start, start + n)` of `slot`
    /// is compatible with the TDD pattern (always on FDD).
    pub fn ul_allowed(&self, slot: ferrite_common::SlotPoint, start: u8, n: u8) -> bool {
        self.tdd.as_ref().is_none_or(|t| {
            !t.conflicts(slot.index(), slot.numerology, start, n, LinkDirection::Ul)
        })
    }
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
    /// The active DL / UL bandwidth parts.
    pub dl_bwp: Bwp,
    pub ul_bwp: Bwp,
    /// Bandwidth parts configured by RRC besides the initial one (`n_BWP,RRC`
    /// of TS 38.212 §7.3.1: the DCI 1_1 / 0_1 BWP indicator width).
    pub nof_dl_bwp_rrc: u8,
    pub nof_ul_bwp_rrc: u8,
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
    /// Transmit level (full-scale peak fraction) for UL waveforms without a
    /// power in dBm; the radio backend applies the actual gain.
    pub ul_amplitude: f32,
    /// Transmitter calibration: the dBm a full-scale (0 dBFS) continuous
    /// signal produces at the configured transmit gain. With it, a PDU's
    /// `power_dbm` sets the waveform's RMS level; without it (`None`, the ZMQ
    /// case) every waveform is peak-normalised to `ul_amplitude`.
    pub tx_full_scale_dbm: Option<f32>,
}

impl PhyConfig {
    /// The configuration known right after the MIB, before SIB1: the initial
    /// DL/UL BWP equals CORESET#0, the Type0-PDCCH CSS is `ss0_index`, every
    /// dedicated part is at its default. The engine starts from this and RRC
    /// replaces it once SIB1 and the dedicated configuration are decoded.
    #[allow(clippy::too_many_arguments)]
    pub fn initial(
        duplex: DuplexMode,
        numerology: Numerology,
        ssb_scs: Numerology,
        pci: u16,
        coreset0_n_rb: usize,
        coreset0_n_symb: u8,
        dmrs_typea_pos: u8,
        k_ssb: u8,
        ss0_index: u8,
    ) -> Self {
        PhyConfig {
            duplex,
            paging: None,
            numerology,
            ssb: SsbConfig {
                pci,
                scs: ssb_scs,
                period_ms: 20,
                ssb_index: 0,
                k_ssb,
                dmrs_typea_pos,
            },
            dl_carrier: Carrier {
                offset_crb: 0,
                n_rb: 0,
            },
            ul_carrier: Carrier {
                offset_crb: 0,
                n_rb: 0,
            },
            ssb_crb: 0,
            dl_bwp: Bwp {
                id: 0,
                start_crb: 0,
                n_rb: coreset0_n_rb as u16,
                scs: numerology,
            },
            ul_bwp: Bwp {
                id: 0,
                start_crb: 0,
                n_rb: coreset0_n_rb as u16,
                scs: numerology,
            },
            nof_dl_bwp_rrc: 0,
            nof_ul_bwp_rrc: 0,
            tdd: None,
            coresets: vec![CoresetConfig {
                id: 0,
                start_crb: 0,
                rb_mask: vec![true; coreset0_n_rb],
                duration: coreset0_n_symb,
                interleaved: Some((6, 2, pci)),
                dmrs_scrambling_id: None,
                ref_lowest_rb: true,
            }],
            search_spaces: Vec::new(),
            ss0_index,
            pdsch_tdra_common: Vec::new(),
            pusch_tdra_common: Vec::new(),
            prach: PrachConfig {
                phy: ferrite_ran::prach_config::PrachConfig {
                    index: 0,
                    duplex,
                    mu: numerology.mu,
                    msg1_scs_mu: numerology.mu,
                    msg1_fdm: 1,
                    msg1_frequency_start: 0,
                },
                tdd: None,
                ssb_symbols: Vec::new(),
                ssb_period_ms: 20,
                zero_correlation_zone: 0,
                root_sequence_index: 0,
                restricted_set: 0,
                total_preambles: 64,
                target_power_dbm: -100,
                power_ramping_step_db: 0,
            },
            n_ta_offset_tc: 25600,
            pdsch: PdschConfig::default(),
            pusch: PuschConfig::default(),
            pucch: PucchConfig::default(),
            csi_reports: Vec::new(),
            srs: Vec::new(),
            harq_codebook_dynamic: true,
            ul_amplitude: 0.5,
            tx_full_scale_dbm: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::SlotPoint;

    const MU: Numerology = Numerology::KHZ30;

    fn tdd() -> TddConfig {
        // 6 DL + special (8 DL symbols, 2 UL symbols) + 3 UL in 10 slots.
        TddConfig {
            reference_scs: MU,
            pattern1: TddPattern {
                period_slots: 10,
                dl_slots: 6,
                dl_symbols: 8,
                ul_slots: 3,
                ul_symbols: 2,
            },
            pattern2: None,
        }
    }

    #[test]
    fn allowed_ranks_follow_ts_38_214_bit_order() {
        let c = |r: u8| CsiReportConfig {
            report_id: 0,
            period_slots: 20,
            offset_slots: 0,
            pucch_resource: 0,
            cqi_table: 0,
            quantity: CsiReportQuantity::RiPmiCqi,
            nof_ports: 2,
            ri_restriction: r,
        };
        assert_eq!(c(0b0000_0011).allowed_ranks(), vec![1, 2]);
        assert_eq!(c(0b0000_0001).allowed_ranks(), vec![1]);
        assert_eq!(c(0b0000_0010).allowed_ranks(), vec![2]);
        assert_eq!(c(0).allowed_ranks(), vec![1]);
    }

    #[test]
    fn tdd_conflicts_follow_the_pattern() {
        let t = tdd();
        // DL slot 2: uplink conflicts, downlink does not.
        assert!(t.conflicts(2, MU, 0, 14, LinkDirection::Ul));
        assert!(!t.conflicts(2, MU, 0, 14, LinkDirection::Dl));
        // UL slot 7.
        assert!(t.conflicts(7, MU, 0, 14, LinkDirection::Dl));
        assert!(!t.conflicts(7, MU, 0, 14, LinkDirection::Ul));
        // Special slot 6: symbols 0..8 DL, 8..12 flexible, 12..14 UL.
        assert!(t.conflicts(6, MU, 0, 10, LinkDirection::Ul));
        assert!(!t.conflicts(6, MU, 8, 4, LinkDirection::Ul));
        assert!(!t.conflicts(6, MU, 8, 4, LinkDirection::Dl));
        assert!(t.conflicts(6, MU, 10, 4, LinkDirection::Dl));
        assert!(!t.conflicts(6, MU, 12, 2, LinkDirection::Ul));
        // Second period.
        assert!(t.conflicts(17, MU, 0, 14, LinkDirection::Dl));
    }

    fn prach(tdd: Option<TddConfig>, ssb: Vec<SsbSlotSymbols>) -> PrachConfig {
        PrachConfig {
            phy: ferrite_ran::prach_config::PrachConfig {
                index: 159,
                duplex: DuplexMode::Tdd,
                mu: 1,
                msg1_scs_mu: 1,
                msg1_fdm: 1,
                msg1_frequency_start: 0,
            },
            tdd,
            ssb_symbols: ssb,
            ssb_period_ms: 20,
            zero_correlation_zone: 0,
            root_sequence_index: 1,
            restricted_set: 0,
            total_preambles: 64,
            target_power_dbm: -100,
            power_ramping_step_db: 4,
        }
    }

    #[test]
    fn prach_occasion_validity() {
        use ferrite_ran::prach_config::PreambleFormat as F;
        let slot = |n: u64| SlotPoint::from_index(MU, n);
        let ssb = vec![SsbSlotSymbols {
            slot_in_half_frame: 6,
            first_symbol: 2,
            last_symbol: 5,
        }];
        let p = prach(Some(tdd()), ssb.clone());
        // UL slot: valid; DL slot: invalid; FDD: always valid.
        assert!(p.occasion_valid(slot(7), 0, 12, F::B4));
        assert!(!p.occasion_valid(slot(2), 0, 12, F::B4));
        assert!(prach(None, Vec::new()).occasion_valid(slot(2), 0, 12, F::B4));
        // Special slot 6 (DL 0..8, flexible 8..12, UL 12..14) in an SSB frame
        // with an SSB in symbols 2..5: an occasion at 8 is ≥ 5 + 1 + 2 → valid;
        // one at symbol 4 overlaps DL → invalid.
        assert!(p.occasion_valid(slot(6), 8, 2, F::A1));
        assert!(!p.occasion_valid(slot(6), 4, 2, F::A1));
        // An SSB later in the slot than the occasion makes it invalid (gap rule).
        let late = vec![SsbSlotSymbols {
            slot_in_half_frame: 6,
            first_symbol: 8,
            last_symbol: 11,
        }];
        let p2 = prach(Some(tdd()), late);
        assert!(!p2.occasion_valid(slot(6), 8, 2, F::A1));
        // Not an SSB frame (period 20 ms = every other frame): the SSB rule is off.
        assert!(p2.occasion_valid(slot(20 + 6), 8, 2, F::A1));
        // T1's configuration (index 159, B4, slot 19 is UL) keeps its occasions.
        let p = prach(Some(tdd()), ssb);
        assert!(!p.occasions_in_slot(slot(19)).is_empty());
        assert!(
            p.occasions_in_slot(slot(18)).is_empty()
                || p.occasions_in_slot(slot(18))
                    .iter()
                    .all(|o| o.start_symbol >= 12)
        );
    }
}
