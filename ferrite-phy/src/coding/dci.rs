//! DCI coding and field layouts for the PDCCH (3GPP TS 38.212 §7.3).
//!
//! Two halves:
//!
//! 1. **Channel coding** (§7.3.2 – §7.3.4): [`dci_encode`], [`dci_decode`],
//!    [`pdcch_descramble_llr`].
//! 2. **Formats** (§7.3.1): payload sizes of DCI 0_0 / 1_0 / 0_1 / 1_1 derived
//!    from the RRC configuration ([`DciSizeConfig`] → [`dci_sizes`], including the
//!    §7.3.1.0 size-alignment steps), field-by-field parsers
//!    ([`parse_dci_1_0`], [`parse_dci_0_0`], [`parse_dci_1_1`], [`parse_dci_0_1`]),
//!    the type-1 RIV decoder ([`riv_decode`], [`riv_decode_css`]) and the default
//!    PDSCH / PUSCH time-domain allocation tables ([`default_pdsch_tdra`],
//!    [`default_pusch_tdra`]).
//!
//! Coding chain: payload `a` → CRC24C computed over `1×24 || a` (the 24 prepended
//! ones are not transmitted) → last 16 parity bits XOR-masked with the RNTI →
//! polar (`n_max = 9`, `I_IL = 1`, `n_PC = 0`) → sub-block interleave → bit
//! selection to `E = 108·L` bits (aggregation level `L` CCEs, 54 data REs and
//! thus 108 bits per CCE).
//!
//! Decoding is blind: the UE tries each candidate location/aggregation level
//! and accepts the one whose CRC (after RNTI unmasking) checks.

use crate::coding::crc::CRC24C;
use crate::coding::polar::{
    code_length, info_mask_rm, input_deinterleave, input_interleave, polar_encode, sc_decode,
};
use crate::coding::ratematch::{de_rate_match, rate_match, subblock_interleave};
use crate::dmrs::MappingType;

/// Coded bits per CCE: 6 REGs × 9 data REs × 2 bits (QPSK).
pub const BITS_PER_CCE: usize = 108;

/// `⌈log2(n)⌉` (0 for `n ≤ 1`).
pub fn log2_ceil(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

/// Width of the resource-allocation-type-1 frequency field for a BWP of `n_rb`
/// resource blocks: `⌈log2(N(N+1)/2)⌉` (38.214 §5.1.2.2.2 / §6.1.2.2.2).
pub fn fdra_type1_bits(n_rb: usize) -> usize {
    log2_ceil(n_rb * (n_rb + 1) / 2)
}

/// DCI format 1_0 payload size (bits) when CRC-scrambled by SI-RNTI, monitored
/// in a CSS with CORESET0 of `n_rb` resource blocks (38.212 §7.3.1.2.1):
/// frequency-domain RA `⌈log2(N(N+1)/2)⌉` + TDRA 4 + VRB-to-PRB 1 + MCS 5 +
/// RV 2 + SI indicator 1 + reserved 15. Every DCI 1_0 variant is `28 + FDRA`
/// bits before padding, so this is also the C-/TC-/RA-/P-RNTI size in the CSS.
pub fn dci_1_0_si_size(n_rb: usize) -> usize {
    fdra_type1_bits(n_rb) + 4 + 1 + 5 + 2 + 1 + 15
}

/// Compute the (RNTI-masked) CRC parity bits for payload `a` (§7.3.2).
fn dci_crc(a: &[u8], rnti: u16) -> Vec<u8> {
    let mut prefixed = vec![1u8; 24];
    prefixed.extend_from_slice(a);
    let mut p = CRC24C.compute(&prefixed);
    for i in 0..16 {
        p[8 + i] ^= ((rnti >> (15 - i)) & 1) as u8; // x_rnti,0 = RNTI MSB
    }
    p
}

/// Encode a DCI payload to `e` coded bits for the given RNTI.
pub fn dci_encode(a: &[u8], rnti: u16, e: usize) -> Vec<u8> {
    let k = a.len() + 24;
    let n = code_length(k, e, 9);
    let mut c = a.to_vec();
    c.extend(dci_crc(a, rnti));
    let c_prime = input_interleave(&c);
    let mask = info_mask_rm(n, k, e);
    let d = polar_encode(&c_prime, &mask);
    let y = subblock_interleave(&d);
    rate_match(&y, e, k)
}

/// Attempt to decode a DCI of payload length `a_len` from `llrs` (positive ⇒
/// bit 0), checking the CRC against `rnti`. Returns the payload bits on
/// success.
pub fn dci_decode(llrs: &[f32], rnti: u16, a_len: usize) -> Option<Vec<u8>> {
    let k = a_len + 24;
    let e = llrs.len();
    let n = code_length(k, e, 9);
    let d_llr = de_rate_match(llrs, n, k);
    let mask = info_mask_rm(n, k, e);
    let check = |info: &[u8]| -> bool {
        let c = input_deinterleave(info);
        c[a_len..] == dci_crc(&c[..a_len], rnti)[..]
    };
    // Blind decode is O(candidates·slots) and the coherence gate still passes several
    // overlapping candidates per PDCCH (only one decodes), so the decoder must reject the
    // wrong ones CHEAPLY. Use the single-path SC decoder (O(N log N)) — CRC-protected, it
    // decodes the real DCI on a clean channel and rejects wrong/noise candidates fast.
    // The old O(N²·L) CRC-aided list decoder (scl_decode, still available) ran per
    // candidate and was ~60% of the UE's CPU — it stretched the ZMQ lockstep to ~26x
    // slower than real time.
    let info = sc_decode(&d_llr, &mask);
    if check(&info) {
        let c = input_deinterleave(&info);
        return Some(c[..a_len].to_vec());
    }
    None
}

/// PDCCH coded-bit scrambling sequence applied to LLRs (38.211 §7.3.2.3):
/// flip LLR signs where the Gold bit is 1. For a CORESET configured by the
/// MIB (CORESET0), `c_init = N_cell_ID`.
pub fn pdcch_descramble_llr(llrs: &mut [f32], c_init: u32) {
    let c = crate::sequence::gold_sequence(c_init, llrs.len());
    for (l, &bit) in llrs.iter_mut().zip(&c) {
        if bit == 1 {
            *l = -*l;
        }
    }
}

// ---------------------------------------------------------------------------
// DCI format layouts (TS 38.212 §7.3.1)
// ---------------------------------------------------------------------------

/// Which RNTI scrambles the DCI CRC. The 1_0 / 0_0 field set depends on it
/// (§7.3.1.1.1, §7.3.1.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RntiKind {
    /// SI-RNTI: system information (SIB1 / other SI).
    Si,
    /// RA-RNTI: random-access response.
    Ra,
    /// P-RNTI: paging / short messages.
    P,
    /// TC-RNTI: Msg4 / Msg3 retransmission.
    Tc,
    /// C-RNTI (also MCS-C-RNTI / CS-RNTI layouts for 1_0 / 0_0).
    C,
}

/// `pdsch-HARQ-ACK-Codebook` (PhysicalCellGroupConfig).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarqAckCodebook {
    /// Type-1 codebook: no DAI in 1_1, 1-bit first DAI in 0_1.
    SemiStatic,
    /// Type-2 codebook: 2-bit DAI in 1_1 (4 with several serving cells), 2-bit
    /// first DAI in 0_1.
    Dynamic,
}

/// `resourceAllocation` in PDSCH-Config / PUSCH-Config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceAllocation {
    /// Type 0 (bitmap over `nof_rbg` RBGs).
    Type0 { nof_rbg: usize },
    /// Type 1 (RIV over the active BWP).
    Type1,
    /// Dynamic switch: `1 + max(type-0 width, type-1 width)` bits.
    DynamicSwitch { nof_rbg: usize },
}

/// DM-RS configuration type and `maxLength` for one mapping type
/// (`DMRS-DownlinkConfig` / `DMRS-UplinkConfig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmrsConfig {
    /// `dmrs-Type`: 1 (absent) or 2.
    pub config_type: u8,
    /// `maxLength`: 1 (absent) or 2.
    pub max_length: u8,
}

impl DmrsConfig {
    /// Type 1, single symbol — the configuration when both IEs are absent.
    pub const TYPE1_LEN1: DmrsConfig = DmrsConfig { config_type: 1, max_length: 1 };
}

/// `codebookSubset` (PUSCH-Config), for the precoding-information field width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodebookSubset {
    FullyAndPartialAndNonCoherent,
    PartialAndNonCoherent,
    NonCoherent,
}

/// PUSCH transmission scheme (`txConfig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PuschTxScheme {
    /// Codebook-based: `nof_srs_ports` from the SRS resource(s) of the
    /// `usage = codebook` set, `max_rank` = `maxRank`.
    Codebook { nof_srs_ports: u8, max_rank: u8, subset: CodebookSubset },
    /// Non-codebook-based: `l_max` = `maxMIMO-Layers` of PUSCH-ServingCellConfig.
    NonCodebook { l_max: u8 },
}

/// Everything in the RRC configuration that changes a DCI payload size.
/// Field documentation names the IE and the §7.3.1 rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DciSizeConfig {
    // -- Bandwidth parts ----------------------------------------------------
    /// `N_RB` of the initial DL BWP (SIB1 `initialDownlinkBWP`).
    pub dl_bwp_initial_rb: usize,
    /// `N_RB` of the active DL BWP (the one the USS is monitored in).
    pub dl_bwp_active_rb: usize,
    /// `N_RB` of the initial UL BWP.
    pub ul_bwp_initial_rb: usize,
    /// `N_RB` of the active UL BWP.
    pub ul_bwp_active_rb: usize,
    /// CORESET#0 size when configured for the cell: DCI 1_0 in a CSS uses it as
    /// `N_RB^DL,BWP` (§7.3.1.2.1), else the initial DL BWP.
    pub coreset0_rb: Option<usize>,
    /// Number of DL BWPs configured by RRC excluding the initial one
    /// (`n_BWP,RRC`); drives the 1_1 BWP-indicator width.
    pub nof_dl_bwp_rrc: usize,
    /// Same for UL (0_1).
    pub nof_ul_bwp_rrc: usize,

    // -- Which formats are monitored ----------------------------------------
    /// A UE-specific search space monitors 0_0 / 1_0 (`dci-Formats = formats0-0-And-1-0`).
    pub monitor_0_0_1_0_in_uss: bool,
    /// A UE-specific search space monitors 0_1 / 1_1.
    pub monitor_0_1_1_1: bool,

    // -- Cell-level ---------------------------------------------------------
    /// `supplementaryUplink` configured (UL/SUL indicator, 3-bit SRS request).
    pub sul_configured: bool,
    /// Cross-carrier scheduling configured (3-bit carrier indicator).
    pub cross_carrier: bool,
    /// More than one serving cell (4-bit DAI with the dynamic codebook).
    pub multiple_serving_cells: bool,
    /// `pdsch-HARQ-ACK-Codebook`.
    pub harq_ack_codebook: HarqAckCodebook,
    /// Two HARQ-ACK sub-codebooks (`pdsch-HARQ-ACK-CodebookList`, Rel-16): 2nd DAI.
    pub two_harq_ack_sub_codebooks: bool,

    // -- PDSCH (1_1) --------------------------------------------------------
    /// Rows of the applicable `pdsch-TimeDomainAllocationList` (dedicated if
    /// present, else common, else 16 for the default table). TDRA = `⌈log2 I⌉`.
    pub nof_pdsch_tdra_rows: usize,
    /// Entries of `dl-DataToUL-ACK` (PUCCH-Config): K1 field = `⌈log2 I⌉` (0–3 bits).
    pub nof_k1: usize,
    /// `harqProcessNumberSizeDCI-1-1` (Rel-17): 4 (absent) or 5.
    pub dl_harq_bits: u8,
    /// PDSCH `resourceAllocation`.
    pub pdsch_resource_allocation: ResourceAllocation,
    /// `vrb-ToPRB-Interleaver` present in PDSCH-Config → 1-bit VRB-to-PRB field.
    pub vrb_to_prb_interleaver: bool,
    /// `prb-BundlingType = dynamicBundling` → 1-bit PRB bundling size indicator.
    pub dynamic_prb_bundling: bool,
    /// Number of configured `rateMatchPatternGroup1/2` (0, 1 or 2 bits).
    pub rate_match_groups: u8,
    /// Number of aperiodic ZP-CSI-RS resource sets: trigger field `⌈log2(n+1)⌉`.
    pub nof_aperiodic_zp_csi_rs_sets: u8,
    /// `maxNrofCodeWordsScheduledByDCI = n2`: second MCS/NDI/RV block.
    pub two_codewords: bool,
    /// `dmrs-DownlinkForPDSCH-MappingTypeA`, if configured.
    pub pdsch_dmrs_type_a: Option<DmrsConfig>,
    /// `dmrs-DownlinkForPDSCH-MappingTypeB`, if configured.
    pub pdsch_dmrs_type_b: Option<DmrsConfig>,
    /// `tci-PresentInDCI` on the CORESET → 3-bit TCI field.
    pub tci_present: bool,
    /// `maxCodeBlockGroupsPerTransportBlock` (PDSCH-ServingCellConfig) → CBGTI bits.
    pub pdsch_cbg_bits: u8,
    /// `codeBlockGroupFlushIndicator = true` → 1-bit CBGFI.
    pub cbg_flush_indicator: bool,

    // -- PUSCH (0_1) --------------------------------------------------------
    /// Rows of the applicable `pusch-TimeDomainAllocationList` (dedicated, else
    /// common, else 16).
    pub nof_pusch_tdra_rows: usize,
    /// `harqProcessNumberSizeDCI-0-1`: 4 or 5.
    pub ul_harq_bits: u8,
    /// PUSCH `resourceAllocation`.
    pub pusch_resource_allocation: ResourceAllocation,
    /// `frequencyHopping` present in PUSCH-Config → 1-bit hopping flag (unless
    /// only RA type 0).
    pub frequency_hopping: bool,
    /// `txConfig` and SRS geometry; `None` when PUSCH-Config has no `txConfig`
    /// (single antenna port: no SRI / precoding fields).
    pub pusch_tx_scheme: Option<PuschTxScheme>,
    /// SRS resources in the resource set whose `usage` matches the tx scheme.
    pub nof_srs_resources: usize,
    /// `dmrs-UplinkForPUSCH-MappingTypeA`, if configured.
    pub pusch_dmrs_type_a: Option<DmrsConfig>,
    /// `dmrs-UplinkForPUSCH-MappingTypeB`, if configured.
    pub pusch_dmrs_type_b: Option<DmrsConfig>,
    /// Transform precoding in use for DCI 0_1 PUSCH (`transformPrecoder` /
    /// `msg3-transformPrecoder`).
    pub transform_precoding: bool,
    /// `reportTriggerSize` (CSI-MeasConfig): CSI-request bits (0 when absent).
    pub report_trigger_size: u8,
    /// `maxCodeBlockGroupsPerTransportBlock` (PUSCH-ServingCellConfig) → CBGTI bits.
    pub pusch_cbg_bits: u8,
    /// `PTRS-UplinkConfig` configured (with TP disabled and maxRank > 1 → 2-bit
    /// PTRS-DMRS association).
    pub ptrs_uplink: bool,
    /// `betaOffsets = dynamic` → 2-bit beta_offset indicator.
    pub dynamic_beta_offsets: bool,
}

impl DciSizeConfig {
    /// A single-cell, single-BWP baseline matching what OCUDU's DU hands a UE:
    /// `n_rb`-RB initial = active BWPs, CORESET#0 of `coreset0_rb`, dynamic
    /// HARQ-ACK codebook, RA type 1, non-interleaved VRB-to-PRB, DM-RS type 1
    /// single symbol (type A), codebook tx scheme with one SRS port / resource
    /// and `maxRank = 1`, no CSI request, no CBG, 16-row default TDRA tables
    /// and an 8-entry `dl-DataToUL-ACK`. Override fields as needed.
    pub fn single_bwp(n_rb: usize, coreset0_rb: usize) -> Self {
        Self {
            dl_bwp_initial_rb: n_rb,
            dl_bwp_active_rb: n_rb,
            ul_bwp_initial_rb: n_rb,
            ul_bwp_active_rb: n_rb,
            coreset0_rb: Some(coreset0_rb),
            nof_dl_bwp_rrc: 0,
            nof_ul_bwp_rrc: 0,
            monitor_0_0_1_0_in_uss: true,
            monitor_0_1_1_1: true,
            sul_configured: false,
            cross_carrier: false,
            multiple_serving_cells: false,
            harq_ack_codebook: HarqAckCodebook::Dynamic,
            two_harq_ack_sub_codebooks: false,
            nof_pdsch_tdra_rows: 16,
            nof_k1: 8,
            dl_harq_bits: 4,
            pdsch_resource_allocation: ResourceAllocation::Type1,
            vrb_to_prb_interleaver: false,
            dynamic_prb_bundling: false,
            rate_match_groups: 0,
            nof_aperiodic_zp_csi_rs_sets: 0,
            two_codewords: false,
            pdsch_dmrs_type_a: Some(DmrsConfig::TYPE1_LEN1),
            pdsch_dmrs_type_b: None,
            tci_present: false,
            pdsch_cbg_bits: 0,
            cbg_flush_indicator: false,
            nof_pusch_tdra_rows: 16,
            ul_harq_bits: 4,
            pusch_resource_allocation: ResourceAllocation::Type1,
            frequency_hopping: false,
            pusch_tx_scheme: Some(PuschTxScheme::Codebook {
                nof_srs_ports: 1,
                max_rank: 1,
                subset: CodebookSubset::NonCoherent,
            }),
            nof_srs_resources: 1,
            pusch_dmrs_type_a: Some(DmrsConfig::TYPE1_LEN1),
            pusch_dmrs_type_b: None,
            transform_precoding: false,
            report_trigger_size: 0,
            pusch_cbg_bits: 0,
            ptrs_uplink: false,
            dynamic_beta_offsets: false,
        }
    }
}

/// Field widths of a DCI format 0_0 payload (§7.3.1.1.1). Fixed fields:
/// identifier 1, TDRA 4, hopping flag 1, MCS 5, NDI 1, RV 2, HARQ 4, TPC 2 = 20.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dci0_0Size {
    /// Total payload bits after alignment.
    pub total: usize,
    /// Frequency-domain RA bits actually carried (after any §7.3.1.0 truncation
    /// of the MSBs). With hopping, `N_UL_hop` of these are the hopping offset.
    pub fdra: usize,
    /// Zero padding appended after TPC (the UL/SUL bit, if present, takes the
    /// last of these positions).
    pub padding: usize,
    /// A UL/SUL indicator occupies the last payload bit.
    pub ul_sul_present: bool,
}

/// Field widths of a DCI format 1_0 payload (§7.3.1.2.1): `28 + fdra + padding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dci1_0Size {
    /// Total payload bits.
    pub total: usize,
    /// Frequency-domain RA bits (after any truncation).
    pub fdra: usize,
    /// Zero padding appended at the end (USS alignment to 0_0 only).
    pub padding: usize,
}

/// Field widths of a DCI format 0_1 payload (§7.3.1.1.2), in payload order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dci0_1Size {
    pub total: usize,
    pub carrier_indicator: usize,
    pub ul_sul: usize,
    pub bwp_indicator: usize,
    pub fdra: usize,
    pub tdra: usize,
    pub frequency_hopping_flag: usize,
    pub harq_id: usize,
    pub first_dai: usize,
    pub second_dai: usize,
    pub srs_resource_indicator: usize,
    pub precoding_info: usize,
    pub antenna_ports: usize,
    pub srs_request: usize,
    pub csi_request: usize,
    pub cbgti: usize,
    pub ptrs_dmrs_association: usize,
    pub beta_offset: usize,
    pub dmrs_seq_init: usize,
    pub padding: usize,
}

/// Field widths of a DCI format 1_1 payload (§7.3.1.2.2), in payload order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dci1_1Size {
    pub total: usize,
    pub carrier_indicator: usize,
    pub bwp_indicator: usize,
    pub fdra: usize,
    pub tdra: usize,
    pub vrb_to_prb: usize,
    pub prb_bundling: usize,
    pub rate_matching: usize,
    pub zp_csi_rs_trigger: usize,
    pub tb2: usize,
    pub harq_id: usize,
    pub dai: usize,
    pub k1: usize,
    pub antenna_ports: usize,
    pub tci: usize,
    pub srs_request: usize,
    pub cbgti: usize,
    pub cbgfi: usize,
    pub padding: usize,
}

/// The aligned payload sizes of every monitored format (§7.3.1.0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DciSizes {
    /// 0_0 in a common search space (initial UL BWP, aligned to `f1_0_css`).
    pub f0_0_css: Dci0_0Size,
    /// 1_0 in a common search space (CORESET#0 size or initial DL BWP).
    pub f1_0_css: Dci1_0Size,
    /// 0_0 in a UE-specific search space (active UL BWP), when monitored.
    pub f0_0_uss: Option<Dci0_0Size>,
    /// 1_0 in a UE-specific search space (active DL BWP), when monitored.
    pub f1_0_uss: Option<Dci1_0Size>,
    /// 0_1, when monitored.
    pub f0_1: Option<Dci0_1Size>,
    /// 1_1, when monitored.
    pub f1_1: Option<Dci1_1Size>,
    /// Number of distinct payload sizes the UE must blind-decode (the "3 + 1"
    /// budget: at most 3 with C-RNTI, 4 in total).
    pub nof_distinct_sizes: usize,
    /// Step 4 of §7.3.1.0 fired: the USS fallback sizes were reset to the CSS ones.
    pub uss_fallback_aligned_to_css: bool,
}

fn fdra_bits(ra: ResourceAllocation, n_rb: usize) -> usize {
    match ra {
        ResourceAllocation::Type0 { nof_rbg } => nof_rbg,
        ResourceAllocation::Type1 => fdra_type1_bits(n_rb),
        ResourceAllocation::DynamicSwitch { nof_rbg } => 1 + nof_rbg.max(fdra_type1_bits(n_rb)),
    }
}

/// BWP-indicator width: `⌈log2(n_BWP)⌉` with `n_BWP = n_RRC + 1` if `n_RRC ≤ 3`,
/// else `n_RRC`.
fn bwp_indicator_bits(nof_bwp_rrc: usize) -> usize {
    if nof_bwp_rrc == 0 {
        return 0;
    }
    log2_ceil(if nof_bwp_rrc <= 3 { nof_bwp_rrc + 1 } else { nof_bwp_rrc })
}

/// DCI 1_1 antenna-port field width (Tables 7.3.1.2.2-1 … -4): 4 bits for type 1
/// single symbol, +1 for type 2, +1 for `maxLength = 2`; the maximum over the
/// configured mapping types.
fn dl_antenna_ports_bits(a: Option<DmrsConfig>, b: Option<DmrsConfig>) -> usize {
    let w = |d: DmrsConfig| 4 + usize::from(d.config_type == 2) + usize::from(d.max_length == 2);
    a.map(w).unwrap_or(0).max(b.map(w).unwrap_or(0))
}

/// DCI 0_1 antenna-port field width (Tables 7.3.1.1.2-6 … -23).
fn ul_antenna_ports_bits(a: Option<DmrsConfig>, b: Option<DmrsConfig>, transform_precoding: bool) -> usize {
    let w = |d: DmrsConfig| match (transform_precoding, d.config_type, d.max_length) {
        (true, 1, 1) => 2,
        (true, 1, 2) => 4,
        (false, 1, 1) => 3,
        (false, 1, 2) => 4,
        (false, 2, 1) => 4,
        (false, 2, 2) => 5,
        _ => 0,
    };
    a.map(w).unwrap_or(0).max(b.map(w).unwrap_or(0))
}

fn binomial(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    (0..k).fold(1usize, |acc, i| acc * (n - i) / (i + 1))
}

/// SRS resource indicator width: codebook `⌈log2 N_SRS⌉`; non-codebook
/// `⌈log2 Σ_{k=1}^{min(L_max, N_SRS)} C(N_SRS, k)⌉` (Tables 7.3.1.1.2-28 … -31).
fn sri_bits(scheme: Option<PuschTxScheme>, nof_srs: usize) -> usize {
    match scheme {
        None => 0,
        Some(PuschTxScheme::Codebook { .. }) => log2_ceil(nof_srs),
        Some(PuschTxScheme::NonCodebook { l_max }) => {
            let sum: usize = (1..=usize::from(l_max).min(nof_srs)).map(|k| binomial(nof_srs, k)).sum();
            log2_ceil(sum)
        }
    }
}

/// Precoding information and number of layers (Tables 7.3.1.1.2-2 … -5): 0 bits
/// for non-codebook or a single SRS port.
fn precoding_bits(scheme: Option<PuschTxScheme>, transform_precoding: bool) -> usize {
    let Some(PuschTxScheme::Codebook { nof_srs_ports, max_rank, subset }) = scheme else { return 0 };
    use CodebookSubset::*;
    match (nof_srs_ports, max_rank > 1 && !transform_precoding, subset) {
        (1, _, _) => 0,
        (4, true, FullyAndPartialAndNonCoherent) => 6,
        (4, true, PartialAndNonCoherent) => 5,
        (4, true, NonCoherent) => 4,
        (4, false, FullyAndPartialAndNonCoherent) => 5,
        (4, false, PartialAndNonCoherent) => 4,
        (4, false, NonCoherent) => 2,
        (2, true, FullyAndPartialAndNonCoherent) => 4,
        (2, true, _) => 2,
        (2, false, FullyAndPartialAndNonCoherent) => 3,
        (2, false, _) => 1,
        _ => 0,
    }
}

/// DCI 0_0 bits before padding: `20 + ⌈log2(N(N+1)/2)⌉`.
fn dci_0_0_raw(n_rb_ul: usize) -> Dci0_0Size {
    let fdra = fdra_type1_bits(n_rb_ul);
    Dci0_0Size { total: 20 + fdra, fdra, padding: 0, ul_sul_present: false }
}

/// DCI 1_0 bits before padding: `28 + ⌈log2(N(N+1)/2)⌉`.
fn dci_1_0_raw(n_rb_dl: usize) -> Dci1_0Size {
    let fdra = fdra_type1_bits(n_rb_dl);
    Dci1_0Size { total: 28 + fdra, fdra, padding: 0 }
}

/// DCI 0_1 size before the §7.3.1.0 padding (§7.3.1.1.2).
pub fn dci_0_1_size(cfg: &DciSizeConfig) -> Dci0_1Size {
    let carrier_indicator = if cfg.cross_carrier { 3 } else { 0 };
    let ul_sul = usize::from(cfg.sul_configured);
    let bwp_indicator = bwp_indicator_bits(cfg.nof_ul_bwp_rrc);
    let fdra = fdra_bits(cfg.pusch_resource_allocation, cfg.ul_bwp_active_rb);
    let tdra = log2_ceil(cfg.nof_pusch_tdra_rows);
    let frequency_hopping_flag = usize::from(
        cfg.frequency_hopping && !matches!(cfg.pusch_resource_allocation, ResourceAllocation::Type0 { .. }),
    );
    let harq_id = usize::from(cfg.ul_harq_bits);
    let first_dai = match cfg.harq_ack_codebook {
        HarqAckCodebook::Dynamic => 2,
        HarqAckCodebook::SemiStatic => 1,
    };
    let second_dai =
        if cfg.harq_ack_codebook == HarqAckCodebook::Dynamic && cfg.two_harq_ack_sub_codebooks { 2 } else { 0 };
    let srs_resource_indicator = sri_bits(cfg.pusch_tx_scheme, cfg.nof_srs_resources);
    let precoding_info = precoding_bits(cfg.pusch_tx_scheme, cfg.transform_precoding);
    let antenna_ports = ul_antenna_ports_bits(cfg.pusch_dmrs_type_a, cfg.pusch_dmrs_type_b, cfg.transform_precoding);
    let srs_request = if cfg.sul_configured { 3 } else { 2 };
    let csi_request = usize::from(cfg.report_trigger_size);
    let cbgti = usize::from(cfg.pusch_cbg_bits);
    let max_rank = match cfg.pusch_tx_scheme {
        Some(PuschTxScheme::Codebook { max_rank, .. }) => max_rank,
        Some(PuschTxScheme::NonCodebook { l_max }) => l_max,
        None => 1,
    };
    let ptrs_dmrs_association = if cfg.ptrs_uplink && !cfg.transform_precoding && max_rank > 1 { 2 } else { 0 };
    let beta_offset = if cfg.dynamic_beta_offsets { 2 } else { 0 };
    let dmrs_seq_init = usize::from(!cfg.transform_precoding);
    // identifier 1 + MCS 5 + NDI 1 + RV 2 + TPC 2 + UL-SCH indicator 1 = 12 fixed.
    let total = 12
        + carrier_indicator
        + ul_sul
        + bwp_indicator
        + fdra
        + tdra
        + frequency_hopping_flag
        + harq_id
        + first_dai
        + second_dai
        + srs_resource_indicator
        + precoding_info
        + antenna_ports
        + srs_request
        + csi_request
        + cbgti
        + ptrs_dmrs_association
        + beta_offset
        + dmrs_seq_init;
    Dci0_1Size {
        total,
        carrier_indicator,
        ul_sul,
        bwp_indicator,
        fdra,
        tdra,
        frequency_hopping_flag,
        harq_id,
        first_dai,
        second_dai,
        srs_resource_indicator,
        precoding_info,
        antenna_ports,
        srs_request,
        csi_request,
        cbgti,
        ptrs_dmrs_association,
        beta_offset,
        dmrs_seq_init,
        padding: 0,
    }
}

/// DCI 1_1 size before the §7.3.1.0 padding (§7.3.1.2.2).
pub fn dci_1_1_size(cfg: &DciSizeConfig) -> Dci1_1Size {
    let carrier_indicator = if cfg.cross_carrier { 3 } else { 0 };
    let bwp_indicator = bwp_indicator_bits(cfg.nof_dl_bwp_rrc);
    let fdra = fdra_bits(cfg.pdsch_resource_allocation, cfg.dl_bwp_active_rb);
    let tdra = log2_ceil(cfg.nof_pdsch_tdra_rows);
    let vrb_to_prb = usize::from(
        cfg.vrb_to_prb_interleaver && !matches!(cfg.pdsch_resource_allocation, ResourceAllocation::Type0 { .. }),
    );
    let prb_bundling = usize::from(cfg.dynamic_prb_bundling);
    let rate_matching = usize::from(cfg.rate_match_groups.min(2));
    let zp_csi_rs_trigger = log2_ceil(usize::from(cfg.nof_aperiodic_zp_csi_rs_sets) + 1);
    let tb2 = if cfg.two_codewords { 8 } else { 0 };
    let harq_id = usize::from(cfg.dl_harq_bits);
    let dai = match cfg.harq_ack_codebook {
        HarqAckCodebook::Dynamic if cfg.multiple_serving_cells => 4,
        HarqAckCodebook::Dynamic => 2,
        HarqAckCodebook::SemiStatic => 0,
    };
    let k1 = log2_ceil(cfg.nof_k1);
    let antenna_ports = dl_antenna_ports_bits(cfg.pdsch_dmrs_type_a, cfg.pdsch_dmrs_type_b);
    let tci = if cfg.tci_present { 3 } else { 0 };
    let srs_request = if cfg.sul_configured { 3 } else { 2 };
    let cbgti = usize::from(cfg.pdsch_cbg_bits);
    let cbgfi = usize::from(cfg.cbg_flush_indicator);
    // identifier 1 + MCS 5 + NDI 1 + RV 2 + TPC 2 + PRI 3 + DM-RS seq init 1 = 15 fixed.
    let total = 15
        + carrier_indicator
        + bwp_indicator
        + fdra
        + tdra
        + vrb_to_prb
        + prb_bundling
        + rate_matching
        + zp_csi_rs_trigger
        + tb2
        + harq_id
        + dai
        + k1
        + antenna_ports
        + tci
        + srs_request
        + cbgti
        + cbgfi;
    Dci1_1Size {
        total,
        carrier_indicator,
        bwp_indicator,
        fdra,
        tdra,
        vrb_to_prb,
        prb_bundling,
        rate_matching,
        zp_csi_rs_trigger,
        tb2,
        harq_id,
        dai,
        k1,
        antenna_ports,
        tci,
        srs_request,
        cbgti,
        cbgfi,
        padding: 0,
    }
}

/// Align a 0_0 / 1_0 pair: pad the smaller 0_0 (padding precedes the UL/SUL bit,
/// which only exists when 1_0 was larger before padding); truncate the 0_0 FDRA
/// MSBs when 0_0 is larger (CSS, step 0) or pad 1_0 (USS, step 1).
fn align_fallback(mut f0: Dci0_0Size, mut f1: Dci1_0Size, sul: bool, truncate_0_0: bool) -> (Dci0_0Size, Dci1_0Size) {
    if f0.total < f1.total {
        f0.padding = f1.total - f0.total;
        f0.ul_sul_present = sul;
        f0.total = f1.total;
    } else if f0.total > f1.total {
        if truncate_0_0 {
            let cut = f0.total - f1.total;
            f0.fdra -= cut;
            f0.total = f1.total;
        } else {
            f1.padding = f0.total - f1.total;
            f1.total = f0.total;
        }
    }
    (f0, f1)
}

/// Force a USS fallback pair to the CSS size (§7.3.1.0 step 4): truncate the
/// FDRA MSBs or pad, whichever closes the gap.
fn force_size_0_0(mut f: Dci0_0Size, target: usize, sul: bool) -> Dci0_0Size {
    let raw = f.total - f.padding;
    f.padding = 0;
    f.ul_sul_present = false;
    if raw <= target {
        f.padding = target - raw;
        f.ul_sul_present = sul && f.padding > 0;
    } else {
        f.fdra -= raw - target;
    }
    f.total = target;
    f
}

fn force_size_1_0(mut f: Dci1_0Size, target: usize) -> Dci1_0Size {
    let raw = f.total - f.padding;
    f.padding = 0;
    if raw <= target {
        f.padding = target - raw;
    } else {
        f.fdra -= raw - target;
    }
    f.total = target;
    f
}

/// The §7.3.1.0 DCI size alignment procedure.
///
/// * Step 0: 0_0 / 1_0 in the CSS, with the initial UL BWP and CORESET#0 (or the
///   initial DL BWP); 0_0 is padded or its FDRA truncated to the 1_0 size.
/// * Step 1: 0_0 / 1_0 in a USS with the active BWPs; the smaller one is padded.
/// * Step 2: 0_1 / 1_1; one zero bit is appended when a size collides with the
///   USS 0_0 / 1_0 size.
/// * Steps 3–4: if more than 3 distinct C-RNTI sizes result, the USS fallback
///   formats are resized to the CSS fallback size.
pub fn dci_sizes(cfg: &DciSizeConfig) -> DciSizes {
    // Step 0.
    let f0_css = dci_0_0_raw(cfg.ul_bwp_initial_rb);
    let f1_css = dci_1_0_raw(cfg.coreset0_rb.unwrap_or(cfg.dl_bwp_initial_rb));
    let (f0_0_css, f1_0_css) = align_fallback(f0_css, f1_css, cfg.sul_configured, true);

    // Step 1.
    let (mut f0_0_uss, mut f1_0_uss) = if cfg.monitor_0_0_1_0_in_uss {
        let (a, b) = align_fallback(
            dci_0_0_raw(cfg.ul_bwp_active_rb),
            dci_1_0_raw(cfg.dl_bwp_active_rb),
            cfg.sul_configured,
            false,
        );
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    // Step 2.
    let (f0_1, f1_1) = if cfg.monitor_0_1_1_1 {
        let mut a = dci_0_1_size(cfg);
        let mut b = dci_1_1_size(cfg);
        if let Some(u) = f0_0_uss {
            if a.total == u.total {
                a.padding = 1;
                a.total += 1;
            }
            if b.total == u.total {
                b.padding = 1;
                b.total += 1;
            }
        }
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    // Steps 3-4.
    let count = |uss: Option<Dci0_0Size>| {
        let mut sizes = vec![f0_0_css.total];
        if let Some(u) = uss {
            sizes.push(u.total);
        }
        if let Some(a) = f0_1 {
            sizes.push(a.total);
        }
        if let Some(b) = f1_1 {
            sizes.push(b.total);
        }
        sizes.sort_unstable();
        sizes.dedup();
        sizes.len()
    };
    let mut nof_distinct_sizes = count(f0_0_uss);
    let mut uss_fallback_aligned_to_css = false;
    if nof_distinct_sizes > 3 {
        if let (Some(a), Some(b)) = (f0_0_uss, f1_0_uss) {
            f0_0_uss = Some(force_size_0_0(a, f0_0_css.total, cfg.sul_configured));
            f1_0_uss = Some(force_size_1_0(b, f1_0_css.total));
            uss_fallback_aligned_to_css = true;
            nof_distinct_sizes = count(f0_0_uss);
        }
    }

    DciSizes { f0_0_css, f1_0_css, f0_0_uss, f1_0_uss, f0_1, f1_1, nof_distinct_sizes, uss_fallback_aligned_to_css }
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Why a payload could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DciParseError {
    /// Payload length differs from the configured size.
    WrongLength { expected: usize, got: usize },
    /// The identifier bit does not match the format (0 = UL, 1 = DL).
    WrongIdentifier,
    /// A bit was not 0 or 1.
    NotABit,
}

impl std::fmt::Display for DciParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { expected, got } => write!(f, "DCI payload is {got} bits, expected {expected}"),
            Self::WrongIdentifier => write!(f, "DCI format identifier bit mismatch"),
            Self::NotABit => write!(f, "DCI payload contains a non-binary value"),
        }
    }
}

impl std::error::Error for DciParseError {}

/// MSB-first field reader over a bit slice.
struct BitReader<'a> {
    bits: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bits: &'a [u8], expected: usize) -> Result<Self, DciParseError> {
        if bits.len() != expected {
            return Err(DciParseError::WrongLength { expected, got: bits.len() });
        }
        if bits.iter().any(|&b| b > 1) {
            return Err(DciParseError::NotABit);
        }
        Ok(Self { bits, pos: 0 })
    }

    /// Read `n ≤ 32` bits as an integer (0 when `n == 0`).
    fn read(&mut self, n: usize) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | u32::from(self.bits[self.pos]);
            self.pos += 1;
        }
        v
    }

    fn read_u8(&mut self, n: usize) -> u8 {
        self.read(n) as u8
    }

    fn flag(&mut self) -> bool {
        self.read(1) == 1
    }

    fn opt(&mut self, n: usize) -> Option<u8> {
        (n > 0).then(|| self.read_u8(n))
    }

    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
}

/// Random-access procedure triggered by a PDCCH order (DCI 1_0, C-RNTI, FDRA
/// all ones).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdcchOrder {
    /// `ra-PreambleIndex` (6 bits).
    pub preamble_index: u8,
    /// UL/SUL indicator.
    pub ul_sul: bool,
    /// SS/PBCH block index (6 bits).
    pub ssb_index: u8,
    /// PRACH mask index (4 bits).
    pub prach_mask_index: u8,
}

/// Parsed DCI format 1_0 (§7.3.1.2.1). Fields absent for the RNTI are `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dci1_0 {
    pub rnti: RntiKind,
    /// Frequency-domain resource assignment (RIV over CORESET#0 / the BWP).
    pub fdra: u32,
    /// Time-domain resource assignment (row index `m`, table row `m + 1`).
    pub tdra: u8,
    /// VRB-to-PRB mapping: `true` = interleaved.
    pub vrb_to_prb_interleaved: bool,
    /// `I_MCS` (MCS table 1).
    pub mcs: u8,
    /// New data indicator (C / TC).
    pub ndi: Option<bool>,
    /// Redundancy version (SI / C / TC).
    pub rv: Option<u8>,
    /// HARQ process number (C / TC).
    pub harq_id: Option<u8>,
    /// Downlink assignment index (C; the 2 bits are reserved for TC).
    pub dai: Option<u8>,
    /// TPC command for the scheduled PUCCH (C / TC).
    pub tpc: Option<u8>,
    /// PUCCH resource indicator (C / TC).
    pub pri: Option<u8>,
    /// PDSCH-to-HARQ_feedback timing indicator (C / TC): index into
    /// `dl-DataToUL-ACK`, or `k1 = value + 1` for the common fallback set.
    pub k1_idx: Option<u8>,
    /// System information indicator (SI): 0 = SIB1, 1 = other SI.
    pub si_indicator: Option<u8>,
    /// TB scaling (RA / P), Table 5.1.3.2-2.
    pub tb_scaling: Option<u8>,
    /// Short-messages indicator (P): 1 = scheduling info only, 2 = short
    /// messages only, 3 = both.
    pub short_messages_indicator: Option<u8>,
    /// Short messages (P).
    pub short_messages: Option<u8>,
    /// PDCCH order (C-RNTI with all-ones FDRA); the scheduling fields are
    /// meaningless when this is `Some`.
    pub pdcch_order: Option<PdcchOrder>,
}

/// Parse a DCI 1_0 payload of `size` bits (from [`DciSizes::f1_0_css`] or
/// `f1_0_uss`) for the given RNTI.
pub fn parse_dci_1_0(bits: &[u8], rnti: RntiKind, size: &Dci1_0Size) -> Result<Dci1_0, DciParseError> {
    let mut r = BitReader::new(bits, size.total)?;
    let f = size.fdra;
    let mut d = Dci1_0 {
        rnti,
        fdra: 0,
        tdra: 0,
        vrb_to_prb_interleaved: false,
        mcs: 0,
        ndi: None,
        rv: None,
        harq_id: None,
        dai: None,
        tpc: None,
        pri: None,
        k1_idx: None,
        si_indicator: None,
        tb_scaling: None,
        short_messages_indicator: None,
        short_messages: None,
        pdcch_order: None,
    };
    match rnti {
        RntiKind::Si => {
            d.fdra = r.read(f);
            d.tdra = r.read_u8(4);
            d.vrb_to_prb_interleaved = r.flag();
            d.mcs = r.read_u8(5);
            d.rv = Some(r.read_u8(2));
            d.si_indicator = Some(r.read_u8(1));
            r.skip(15);
        }
        RntiKind::Ra => {
            d.fdra = r.read(f);
            d.tdra = r.read_u8(4);
            d.vrb_to_prb_interleaved = r.flag();
            d.mcs = r.read_u8(5);
            d.tb_scaling = Some(r.read_u8(2));
            r.skip(16); // 2 LSBs of SFN (shared spectrum only) + 14 reserved
        }
        RntiKind::P => {
            d.short_messages_indicator = Some(r.read_u8(2));
            d.short_messages = Some(r.read_u8(8));
            d.fdra = r.read(f);
            d.tdra = r.read_u8(4);
            d.vrb_to_prb_interleaved = r.flag();
            d.mcs = r.read_u8(5);
            d.tb_scaling = Some(r.read_u8(2));
            r.skip(6);
        }
        RntiKind::Tc | RntiKind::C => {
            if !r.flag() {
                return Err(DciParseError::WrongIdentifier);
            }
            d.fdra = r.read(f);
            let all_ones = f > 0 && d.fdra == (1u32 << f) - 1;
            if rnti == RntiKind::C && all_ones {
                let preamble_index = r.read_u8(6);
                let ul_sul = r.flag();
                let ssb_index = r.read_u8(6);
                let prach_mask_index = r.read_u8(4);
                r.skip(10);
                d.pdcch_order = Some(PdcchOrder { preamble_index, ul_sul, ssb_index, prach_mask_index });
            } else {
                d.tdra = r.read_u8(4);
                d.vrb_to_prb_interleaved = r.flag();
                d.mcs = r.read_u8(5);
                d.ndi = Some(r.flag());
                d.rv = Some(r.read_u8(2));
                d.harq_id = Some(r.read_u8(4));
                let dai = r.read_u8(2);
                d.dai = (rnti == RntiKind::C).then_some(dai);
                d.tpc = Some(r.read_u8(2));
                d.pri = Some(r.read_u8(3));
                d.k1_idx = Some(r.read_u8(3));
            }
        }
    }
    Ok(d)
}

/// Parsed DCI format 0_0 (§7.3.1.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dci0_0 {
    pub rnti: RntiKind,
    /// RIV over the UL BWP (the `fdra − N_UL_hop` LSBs of the field when
    /// hopping is enabled, 38.214 §6.3).
    pub fdra: u32,
    /// Hopping offset index (`N_UL_hop` = 1 bit for `N_BWP < 50`, else 2) when
    /// the frequency-hopping flag is set.
    pub hopping_offset: Option<u8>,
    pub tdra: u8,
    pub frequency_hopping: bool,
    pub mcs: u8,
    /// New data indicator (reserved for TC-RNTI → `None`).
    pub ndi: Option<bool>,
    pub rv: u8,
    /// HARQ process number (reserved for TC-RNTI → `None`).
    pub harq_id: Option<u8>,
    /// TPC command for the scheduled PUSCH.
    pub tpc: u8,
    /// UL/SUL indicator when present (last payload bit).
    pub ul_sul: Option<bool>,
}

/// Parse a DCI 0_0 payload. `n_bwp_ul` is the UL BWP size the RIV refers to
/// (initial UL BWP in the CSS, active UL BWP in a USS) — it fixes `N_UL_hop`.
pub fn parse_dci_0_0(bits: &[u8], rnti: RntiKind, size: &Dci0_0Size, n_bwp_ul: usize) -> Result<Dci0_0, DciParseError> {
    let mut r = BitReader::new(bits, size.total)?;
    if r.flag() {
        return Err(DciParseError::WrongIdentifier);
    }
    // The hopping flag follows the FDRA field, so read the raw field first.
    let raw = r.read(size.fdra);
    let tdra = r.read_u8(4);
    let frequency_hopping = r.flag();
    let n_ul_hop = if n_bwp_ul < 50 { 1 } else { 2 };
    let (fdra, hopping_offset) = if frequency_hopping && size.fdra > n_ul_hop {
        let riv_bits = size.fdra - n_ul_hop;
        (raw & ((1u32 << riv_bits) - 1), Some((raw >> riv_bits) as u8))
    } else {
        (raw, None)
    };
    let mcs = r.read_u8(5);
    let ndi = r.flag();
    let rv = r.read_u8(2);
    let harq = r.read_u8(4);
    let tpc = r.read_u8(2);
    let ul_sul = if size.ul_sul_present {
        r.skip(size.padding - 1);
        Some(r.flag())
    } else {
        r.skip(size.padding);
        None
    };
    let is_tc = rnti == RntiKind::Tc;
    Ok(Dci0_0 {
        rnti,
        fdra,
        hopping_offset,
        tdra,
        frequency_hopping,
        mcs,
        ndi: (!is_tc).then_some(ndi),
        rv,
        harq_id: (!is_tc).then_some(harq),
        tpc,
        ul_sul,
    })
}

/// Parsed DCI format 1_1 (§7.3.1.2.2). Optional fields are `None` when their
/// configured width is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dci1_1 {
    pub carrier_indicator: Option<u8>,
    pub bwp_indicator: Option<u8>,
    /// Raw frequency-domain RA field (RIV for type 1; with dynamic switching
    /// the MSB selects the type and the rest is the type-0 bitmap / RIV).
    pub fdra: u32,
    pub tdra: u8,
    pub vrb_to_prb_interleaved: Option<bool>,
    pub prb_bundling_size: Option<u8>,
    pub rate_matching_indicator: Option<u8>,
    pub zp_csi_rs_trigger: Option<u8>,
    pub mcs: u8,
    pub ndi: bool,
    pub rv: u8,
    /// Second codeword (MCS, NDI, RV) when `maxNrofCodeWordsScheduledByDCI = n2`.
    pub tb2: Option<(u8, bool, u8)>,
    pub harq_id: u8,
    pub dai: Option<u8>,
    /// TPC command for the scheduled PUCCH.
    pub tpc: u8,
    pub pri: u8,
    /// Index into `dl-DataToUL-ACK`.
    pub k1_idx: Option<u8>,
    /// Antenna-port field (decode with [`crate::dmrs::dci_1_1_antenna_ports_type1_len1`]).
    pub antenna_ports: u8,
    pub tci: Option<u8>,
    pub srs_request: u8,
    pub cbgti: Option<u8>,
    pub cbgfi: Option<bool>,
    /// DM-RS sequence initialization (`n_SCID`).
    pub dmrs_seq_init: u8,
}

/// Parse a DCI 1_1 payload with the widths from [`dci_1_1_size`] / [`DciSizes::f1_1`].
pub fn parse_dci_1_1(bits: &[u8], size: &Dci1_1Size) -> Result<Dci1_1, DciParseError> {
    let mut r = BitReader::new(bits, size.total)?;
    if !r.flag() {
        return Err(DciParseError::WrongIdentifier);
    }
    let carrier_indicator = r.opt(size.carrier_indicator);
    let bwp_indicator = r.opt(size.bwp_indicator);
    let fdra = r.read(size.fdra);
    let tdra = r.read_u8(size.tdra);
    let vrb_to_prb_interleaved = r.opt(size.vrb_to_prb).map(|v| v == 1);
    let prb_bundling_size = r.opt(size.prb_bundling);
    let rate_matching_indicator = r.opt(size.rate_matching);
    let zp_csi_rs_trigger = r.opt(size.zp_csi_rs_trigger);
    let mcs = r.read_u8(5);
    let ndi = r.flag();
    let rv = r.read_u8(2);
    let tb2 = (size.tb2 > 0).then(|| {
        let m = r.read_u8(5);
        let n = r.flag();
        let v = r.read_u8(2);
        (m, n, v)
    });
    let harq_id = r.read_u8(size.harq_id);
    let dai = r.opt(size.dai);
    let tpc = r.read_u8(2);
    let pri = r.read_u8(3);
    let k1_idx = r.opt(size.k1);
    let antenna_ports = r.read_u8(size.antenna_ports);
    let tci = r.opt(size.tci);
    let srs_request = r.read_u8(size.srs_request);
    let cbgti = r.opt(size.cbgti);
    let cbgfi = r.opt(size.cbgfi).map(|v| v == 1);
    let dmrs_seq_init = r.read_u8(1);
    r.skip(size.padding);
    Ok(Dci1_1 {
        carrier_indicator,
        bwp_indicator,
        fdra,
        tdra,
        vrb_to_prb_interleaved,
        prb_bundling_size,
        rate_matching_indicator,
        zp_csi_rs_trigger,
        mcs,
        ndi,
        rv,
        tb2,
        harq_id,
        dai,
        tpc,
        pri,
        k1_idx,
        antenna_ports,
        tci,
        srs_request,
        cbgti,
        cbgfi,
        dmrs_seq_init,
    })
}

/// Parsed DCI format 0_1 (§7.3.1.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dci0_1 {
    pub carrier_indicator: Option<u8>,
    pub ul_sul: Option<bool>,
    pub bwp_indicator: Option<u8>,
    /// Raw frequency-domain RA field (with hopping, the `N_UL_hop` MSBs are the
    /// hopping offset — see [`Dci0_0`]).
    pub fdra: u32,
    pub tdra: u8,
    pub frequency_hopping: Option<bool>,
    pub mcs: u8,
    pub ndi: bool,
    pub rv: u8,
    pub harq_id: u8,
    pub first_dai: u8,
    pub second_dai: Option<u8>,
    /// TPC command for the scheduled PUSCH.
    pub tpc: u8,
    pub srs_resource_indicator: Option<u8>,
    pub precoding_info: Option<u8>,
    /// Antenna-port field (decode with [`crate::dmrs::dci_0_1_antenna_ports_type1_len1_rank1`]).
    pub antenna_ports: u8,
    pub srs_request: u8,
    pub csi_request: Option<u8>,
    pub cbgti: Option<u8>,
    pub ptrs_dmrs_association: Option<u8>,
    pub beta_offset_indicator: Option<u8>,
    pub dmrs_seq_init: Option<u8>,
    /// UL-SCH indicator: 0 = no UL-SCH (CSI-only PUSCH), 1 = UL-SCH present.
    pub ul_sch: bool,
}

/// Parse a DCI 0_1 payload with the widths from [`dci_0_1_size`] / [`DciSizes::f0_1`].
pub fn parse_dci_0_1(bits: &[u8], size: &Dci0_1Size) -> Result<Dci0_1, DciParseError> {
    let mut r = BitReader::new(bits, size.total)?;
    if r.flag() {
        return Err(DciParseError::WrongIdentifier);
    }
    let carrier_indicator = r.opt(size.carrier_indicator);
    let ul_sul = r.opt(size.ul_sul).map(|v| v == 1);
    let bwp_indicator = r.opt(size.bwp_indicator);
    let fdra = r.read(size.fdra);
    let tdra = r.read_u8(size.tdra);
    let frequency_hopping = r.opt(size.frequency_hopping_flag).map(|v| v == 1);
    let mcs = r.read_u8(5);
    let ndi = r.flag();
    let rv = r.read_u8(2);
    let harq_id = r.read_u8(size.harq_id);
    let first_dai = r.read_u8(size.first_dai);
    let second_dai = r.opt(size.second_dai);
    let tpc = r.read_u8(2);
    let srs_resource_indicator = r.opt(size.srs_resource_indicator);
    let precoding_info = r.opt(size.precoding_info);
    let antenna_ports = r.read_u8(size.antenna_ports);
    let srs_request = r.read_u8(size.srs_request);
    let csi_request = r.opt(size.csi_request);
    let cbgti = r.opt(size.cbgti);
    let ptrs_dmrs_association = r.opt(size.ptrs_dmrs_association);
    let beta_offset_indicator = r.opt(size.beta_offset);
    let dmrs_seq_init = r.opt(size.dmrs_seq_init);
    let ul_sch = r.flag();
    r.skip(size.padding);
    Ok(Dci0_1 {
        carrier_indicator,
        ul_sul,
        bwp_indicator,
        fdra,
        tdra,
        frequency_hopping,
        mcs,
        ndi,
        rv,
        harq_id,
        first_dai,
        second_dai,
        tpc,
        srs_resource_indicator,
        precoding_info,
        antenna_ports,
        srs_request,
        csi_request,
        cbgti,
        ptrs_dmrs_association,
        beta_offset_indicator,
        dmrs_seq_init,
        ul_sch,
    })
}

// ---------------------------------------------------------------------------
// Resource allocation helpers
// ---------------------------------------------------------------------------

/// Decode a resource-allocation-type-1 RIV over a BWP of `n_bwp` RBs
/// (38.214 §5.1.2.2.2 / §6.1.2.2.2) into `(rb_start, n_rb)`:
/// `RIV = N(L−1) + S` if `L−1 ≤ ⌊N/2⌋`, else `N(N−L+1) + (N−1−S)`.
/// `None` when the RIV does not describe a valid allocation.
pub fn riv_decode(riv: u32, n_bwp: usize) -> Option<(usize, usize)> {
    if n_bwp == 0 || riv as usize >= n_bwp * (n_bwp + 1) / 2 {
        return None;
    }
    let riv = riv as usize;
    let mut l = riv / n_bwp + 1;
    let mut s = riv % n_bwp;
    if l + s > n_bwp {
        l = n_bwp - l + 2;
        s = n_bwp - 1 - s;
    }
    (l >= 1 && s + l <= n_bwp).then_some((s, l))
}

/// Encode `(rb_start, n_rb)` to a type-1 RIV over `n_bwp` RBs.
pub fn riv_encode(rb_start: usize, n_rb: usize, n_bwp: usize) -> u32 {
    let (s, l, n) = (rb_start, n_rb, n_bwp);
    (if l - 1 <= n / 2 { n * (l - 1) + s } else { n * (n - l + 1) + (n - 1 - s) }) as u32
}

/// RIV of a DCI 1_0 received in a **common search space** (38.214 §5.1.2.2.2):
/// `N_BWP` is the CORESET#0 size and RB numbering starts at the lowest RB of
/// CORESET#0, which may sit above the BWP's lowest RB. Returns the allocation
/// as `(crb_start, n_rb)` in the numbering of `coreset0_first_crb`.
pub fn riv_decode_css(riv: u32, coreset0_rb: usize, coreset0_first_crb: usize) -> Option<(usize, usize)> {
    riv_decode(riv, coreset0_rb).map(|(s, l)| (coreset0_first_crb + s, l))
}

/// Decode a SLIV (`startSymbolAndLength`, 38.214 §5.1.2.1) into `(S, L)`.
pub fn sliv_decode(sliv: u8) -> Option<(usize, usize)> {
    let sliv = usize::from(sliv);
    if sliv >= 14 * 15 / 2 {
        return None;
    }
    let (mut l, mut s) = (sliv / 14 + 1, sliv % 14);
    if l + s > 14 {
        l = 14 - l + 2;
        s = 13 - s;
    }
    (l >= 1 && s + l <= 14).then_some((s, l))
}

// ---------------------------------------------------------------------------
// Default time-domain allocation tables (TS 38.214 §5.1.2.1.1, §6.1.2.1.1)
// ---------------------------------------------------------------------------

/// One row of a default time-domain allocation table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdraRow {
    /// Slot offset `K0` (PDSCH) or `K2` (PUSCH).
    pub k: u8,
    pub mapping: MappingType,
    /// First symbol `S`.
    pub s: usize,
    /// Length `L` in symbols.
    pub l: usize,
}

const fn tr(k: u8, mapping: MappingType, s: usize, l: usize) -> TdraRow {
    TdraRow { k, mapping, s, l }
}

/// Table 5.1.2.1.1-2, default PDSCH time-domain allocation A, normal CP,
/// `dmrs-TypeA-Position = pos2`; rows 1..=16 at indices 0..=15.
const PDSCH_DEFAULT_A_POS2: [TdraRow; 16] = [
    tr(0, MappingType::TypeA, 2, 12),
    tr(0, MappingType::TypeA, 2, 10),
    tr(0, MappingType::TypeA, 2, 9),
    tr(0, MappingType::TypeA, 2, 7),
    tr(0, MappingType::TypeA, 2, 5),
    tr(0, MappingType::TypeB, 9, 4),
    tr(0, MappingType::TypeB, 4, 4),
    tr(0, MappingType::TypeB, 5, 7),
    tr(0, MappingType::TypeB, 5, 2),
    tr(0, MappingType::TypeB, 9, 2),
    tr(0, MappingType::TypeB, 12, 2),
    tr(0, MappingType::TypeA, 1, 13),
    tr(0, MappingType::TypeA, 1, 6),
    tr(0, MappingType::TypeA, 2, 4),
    tr(0, MappingType::TypeB, 4, 7),
    tr(0, MappingType::TypeB, 8, 4),
];

/// Row `row` (0-based, i.e. the TDRA field value) of the default PDSCH table A
/// (Table 5.1.2.1.1-2, normal CP) for `dmrs-TypeA-Position` 2 or 3. With pos3
/// the type-A rows 1–5 start one symbol later (same end) and rows 6–7 shift by
/// 1 and 2 symbols. `None` for `row ≥ 16` or an invalid position.
pub fn default_pdsch_tdra(row: u8, typea_pos: u8) -> Option<TdraRow> {
    let mut r = *PDSCH_DEFAULT_A_POS2.get(usize::from(row))?;
    match typea_pos {
        2 => {}
        3 => match row {
            0..=4 => {
                r.s += 1;
                r.l -= 1;
            }
            5 => r.s += 1,
            6 => r.s += 2,
            _ => {}
        },
        _ => return None,
    }
    Some(r)
}

/// Table 6.1.2.1.1-2, default PUSCH time-domain allocation A, normal CP, with
/// `K2` expressed as an offset to `j` (Table 6.1.2.1.1-4: `j = 1, 1, 2, 3` for
/// µ = 0..3).
const PUSCH_DEFAULT_A: [TdraRow; 16] = [
    tr(0, MappingType::TypeA, 0, 14),
    tr(0, MappingType::TypeA, 0, 12),
    tr(0, MappingType::TypeA, 0, 10),
    tr(0, MappingType::TypeB, 2, 10),
    tr(0, MappingType::TypeB, 4, 10),
    tr(0, MappingType::TypeB, 4, 8),
    tr(0, MappingType::TypeB, 4, 6),
    tr(1, MappingType::TypeA, 0, 14),
    tr(1, MappingType::TypeA, 0, 12),
    tr(1, MappingType::TypeA, 0, 10),
    tr(2, MappingType::TypeA, 0, 14),
    tr(2, MappingType::TypeA, 0, 12),
    tr(2, MappingType::TypeA, 0, 10),
    tr(0, MappingType::TypeB, 8, 6),
    tr(3, MappingType::TypeA, 0, 14),
    tr(3, MappingType::TypeA, 0, 10),
];

/// Row `row` (0-based) of the default PUSCH table A (Table 6.1.2.1.1-2, normal
/// CP) at numerology `mu`; `k` is `K2 = j + offset`.
pub fn default_pusch_tdra(row: u8, mu: u8) -> Option<TdraRow> {
    let j = [1u8, 1, 2, 3].get(usize::from(mu)).copied()?;
    let mut r = *PUSCH_DEFAULT_A.get(usize::from(row))?;
    r.k += j;
    Some(r)
}

#[cfg(test)]
mod tests {

    /// A clean AL4 DCI must decode only as itself: trying the same candidate
    /// LLRs at other payload sizes, and the AL2 / AL8 candidates that overlap
    /// it, must not yield a CRC-passing phantom (the SC decoder is
    /// deterministic, so one such phantom would recur every time the gNB sends
    /// that DCI).
    #[test]
    fn no_phantom_decodes_from_overlapping_candidates() {
        let rnti = 0x4601u16;
        let mut seed = 0x9e37_79b9u32;
        let mut bit = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            (seed & 1) as u8
        };
        for trial in 0..40 {
            let a: Vec<u8> = (0..41).map(|_| bit()).collect();
            let coded = dci_encode(&a, rnti, 576);
            let llr_al4: Vec<f32> = coded.iter().map(|&b| if b == 1 { -8.0 } else { 8.0 }).collect();
            // AL8 candidate containing the AL4 one at its start (other CCEs empty).
            let mut llr_al8 = llr_al4.clone();
            llr_al8.resize(1152, 0.0);
            // AL8 candidate containing it in its second half.
            let mut llr_al8b = vec![0.0f32; 576];
            llr_al8b.extend_from_slice(&llr_al4);
            // AL2 candidates = halves of the AL4 one.
            let llr_al2a = llr_al4[..288].to_vec();
            let llr_al2b = llr_al4[288..].to_vec();
            for (name, llr) in [("al4", &llr_al4), ("al8", &llr_al8), ("al8b", &llr_al8b), ("al2a", &llr_al2a), ("al2b", &llr_al2b)] {
                for size in [37usize, 41, 47] {
                    let got = dci_decode(llr, rnti, size);
                    let legit = size == 41 && (name == "al4" || name == "al8");
                    if legit {
                        assert_eq!(got.as_deref(), Some(&a[..]), "trial {trial} {name} size {size}");
                    } else {
                        assert!(got.is_none(), "trial {trial}: phantom decode at {name} size {size}: {got:?}");
                    }
                }
            }
        }
    }
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn bit(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            (x >> 40) as u8 & 1
        }
        fn uniform(&mut self) -> f32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            ((x >> 11) as f32) / ((1u64 << 53) as f32)
        }
        fn normal(&mut self) -> f32 {
            let u1 = self.uniform().max(1e-9);
            let u2 = self.uniform();
            (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
        }
    }

    #[test]
    fn si_dci_size_for_coreset0_widths() {
        // N_RB = 24: RIV over 300 values → 9 bits → total 37.
        assert_eq!(dci_1_0_si_size(24), 37);
        // N_RB = 48: RIV over 1176 → 11 bits → total 39.
        assert_eq!(dci_1_0_si_size(48), 39);
    }

    #[test]
    fn code_length_matches_spec_cases() {
        // DCI AL4: E=432, K=61 → N=512 (no n1 reduction: 432 > 9/8·256).
        assert_eq!(code_length(61, 432, 9), 512);
        // DCI AL8: E=864, K=61 → N=512 (n_max caps at 9).
        assert_eq!(code_length(61, 864, 9), 512);
        // DCI AL2: E=216, K=61 → N=256.
        assert_eq!(code_length(61, 216, 9), 256);
        // BCH: E=864, K=56 → N=512.
        assert_eq!(code_length(56, 864, 9), 512);
        // n1 reduction case: E=288 = 9/8·256, K small → n1 = 8.
        assert_eq!(code_length(40, 288, 9), 256);
    }

    /// Round trip at every Type0-CSS aggregation level, noiseless. AL4/AL2
    /// exercise puncturing; AL8/AL16 exercise repetition.
    #[test]
    fn dci_roundtrip_all_aggregation_levels() {
        let a_len = dci_1_0_si_size(24);
        let rnti = 0xFFFF; // SI-RNTI
        let mut rng = Rng(0xD0C1_0001);
        for al in [2usize, 4, 8, 16] {
            let e = al * BITS_PER_CCE;
            let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
            let coded = dci_encode(&a, rnti, e);
            assert_eq!(coded.len(), e);
            let llrs: Vec<f32> = coded.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
            let dec = dci_decode(&llrs, rnti, a_len).unwrap_or_else(|| panic!("AL{al} failed"));
            assert_eq!(dec, a, "AL{al}");
        }
    }

    /// Blind-decode discipline: a wrong RNTI or wrong payload size must not
    /// produce a CRC pass.
    #[test]
    fn wrong_rnti_or_size_rejected() {
        let a_len = dci_1_0_si_size(24);
        let mut rng = Rng(0xD0C1_0002);
        let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
        let coded = dci_encode(&a, 0xFFFF, 4 * BITS_PER_CCE);
        let llrs: Vec<f32> = coded.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
        assert!(dci_decode(&llrs, 0xFFFE, a_len).is_none(), "wrong RNTI");
        assert!(dci_decode(&llrs, 0xFFFF, a_len + 2).is_none(), "wrong size");
    }

    /// AL4 (punctured) under noise: the DCI working point.
    #[test]
    fn dci_al4_decodes_under_noise() {
        let a_len = dci_1_0_si_size(24);
        let rnti = 0xFFFF;
        let mut rng = Rng(0xD0C1_0003);
        let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
        let coded = dci_encode(&a, rnti, 4 * BITS_PER_CCE);

        let sigma = 0.7f32; // ~3 dB per coded bit
        let llrs: Vec<f32> = coded
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let r = s + rng.normal() * sigma;
                2.0 * r / (sigma * sigma)
            })
            .collect();
        assert_eq!(dci_decode(&llrs, rnti, a_len).expect("decode failed"), a);
    }

    // -----------------------------------------------------------------------
    // Format sizes (cross-checked against OCUDU `get_dci_sizes`) and parsers
    // -----------------------------------------------------------------------

    /// The live 10 MHz TDD cell as configured by OCUDU: 24-RB BWPs, CORESET#0
    /// 24 RB, dynamic HARQ-ACK codebook, 2-row SIB1 PDSCH TDRA list, 7-row
    /// PUSCH TDRA list (one k2 per DL slot of DDDDDDDSUU), 8-entry
    /// dl-DataToUL-ACK, one SRS resource/port, DM-RS type 1 len 1.
    fn live_tdd_10mhz() -> DciSizeConfig {
        let mut c = DciSizeConfig::single_bwp(24, 24);
        c.nof_pdsch_tdra_rows = 2;
        c.nof_pusch_tdra_rows = 7;
        c.nof_k1 = 8;
        c
    }

    #[test]
    fn sizes_live_tdd_10mhz() {
        let s = dci_sizes(&live_tdd_10mhz());
        // 1_0 = 28 + 9; 0_0 = 20 + 9 padded by 8.
        assert_eq!(s.f1_0_css, Dci1_0Size { total: 37, fdra: 9, padding: 0 });
        assert_eq!(s.f0_0_css, Dci0_0Size { total: 37, fdra: 9, padding: 8, ul_sul_present: false });
        assert_eq!(s.f1_0_uss.unwrap().total, 37);
        assert_eq!(s.f0_0_uss.unwrap().total, 37);
        // 0_1: id 1 + FDRA 9 + TDRA 3 + MCS 5 + NDI 1 + RV 2 + HARQ 4 + DAI 2 +
        // TPC 2 + antenna ports 3 + SRS request 2 + DM-RS init 1 + UL-SCH 1 = 36.
        let f0_1 = s.f0_1.unwrap();
        assert_eq!(f0_1.total, 36);
        assert_eq!((f0_1.fdra, f0_1.tdra, f0_1.frequency_hopping_flag), (9, 3, 0));
        assert_eq!((f0_1.first_dai, f0_1.srs_resource_indicator, f0_1.precoding_info), (2, 0, 0));
        assert_eq!((f0_1.antenna_ports, f0_1.srs_request, f0_1.csi_request, f0_1.dmrs_seq_init), (3, 2, 0, 1));
        // 1_1: id 1 + FDRA 9 + TDRA 1 + MCS 5 + NDI 1 + RV 2 + HARQ 4 + DAI 2 +
        // TPC 2 + PRI 3 + K1 3 + antenna ports 4 + SRS request 2 + DM-RS init 1 = 40.
        let f1_1 = s.f1_1.unwrap();
        assert_eq!(f1_1.total, 40);
        assert_eq!((f1_1.fdra, f1_1.tdra, f1_1.vrb_to_prb, f1_1.dai, f1_1.k1, f1_1.antenna_ports), (9, 1, 0, 2, 3, 4));
        assert_eq!(s.nof_distinct_sizes, 3);
        assert!(!s.uss_fallback_aligned_to_css);
    }

    /// 20 MHz TDD: 51-RB BWPs (11 FDRA bits), CORESET#0 48 RB.
    #[test]
    fn sizes_live_tdd_20mhz() {
        let mut c = live_tdd_10mhz();
        c.dl_bwp_initial_rb = 51;
        c.dl_bwp_active_rb = 51;
        c.ul_bwp_initial_rb = 51;
        c.ul_bwp_active_rb = 51;
        c.coreset0_rb = Some(48);
        let s = dci_sizes(&c);
        assert_eq!(s.f1_0_css.total, 39);
        assert_eq!(s.f0_0_css.total, 39);
        assert_eq!(s.f0_0_css.padding, 8);
        assert_eq!(s.f1_0_uss.unwrap().total, 39);
        assert_eq!(s.f0_1.unwrap().total, 38);
        assert_eq!(s.f1_1.unwrap().total, 42);
        assert_eq!(s.nof_distinct_sizes, 3);
    }

    /// FDD n3, 15 kHz, 20 MHz: 106-RB BWPs (13 FDRA bits), CORESET#0 96 RB
    /// (index 12 of Table 13-1).
    #[test]
    fn sizes_fdd_20mhz_15khz() {
        let mut c = DciSizeConfig::single_bwp(106, 96);
        c.nof_pusch_tdra_rows = 1; // FDD: one k2
        c.nof_pdsch_tdra_rows = 16;
        let s = dci_sizes(&c);
        assert_eq!(s.f1_0_css.total, 28 + 13);
        assert_eq!(s.f0_0_css, Dci0_0Size { total: 41, fdra: 13, padding: 8, ul_sul_present: false });
        assert_eq!(s.f1_0_uss.unwrap().total, 41);
        // 0_1: 33 + 0 TDRA (one row) + 13 − 9 = 37; 1_1: 36 + 4 TDRA + 3 K1 + 4 = 47.
        assert_eq!(s.f0_1.unwrap().tdra, 0);
        assert_eq!(s.f0_1.unwrap().total, 37);
        assert_eq!(s.f1_1.unwrap().total, 47);
    }

    /// Step 0 truncation: no CORESET#0, a tiny initial DL BWP (11 RB → 7 bits →
    /// 1_0 = 35) and a wide initial UL BWP (275 RB → 16 bits → 0_0 = 36): the
    /// 0_0 FDRA loses one MSB.
    #[test]
    fn css_truncates_0_0_fdra() {
        let mut c = DciSizeConfig::single_bwp(11, 24);
        c.coreset0_rb = None;
        c.ul_bwp_initial_rb = 275;
        c.monitor_0_0_1_0_in_uss = false;
        c.monitor_0_1_1_1 = false;
        let s = dci_sizes(&c);
        assert_eq!(s.f1_0_css.total, 35);
        assert_eq!(s.f0_0_css, Dci0_0Size { total: 35, fdra: 15, padding: 0, ul_sul_present: false });
        assert_eq!(s.nof_distinct_sizes, 1);
    }

    /// Step 1: in a USS the *1_0* gets padded when 0_0 is larger (active UL BWP
    /// wider than the active DL BWP); SUL adds the UL/SUL bit inside the padding.
    #[test]
    fn uss_pads_1_0_and_ul_sul() {
        let mut c = DciSizeConfig::single_bwp(24, 24);
        c.ul_bwp_active_rb = 273; // 16 bits → 0_0 = 36 < 37 … make DL smaller instead
        c.dl_bwp_active_rb = 11; // 7 bits → 1_0 = 35
        c.monitor_0_1_1_1 = false;
        c.sul_configured = true;
        let s = dci_sizes(&c);
        let u0 = s.f0_0_uss.unwrap();
        let u1 = s.f1_0_uss.unwrap();
        assert_eq!(u0.total, 36);
        assert_eq!(u1, Dci1_0Size { total: 36, fdra: 7, padding: 1 });
        // CSS: 0_0 (20 + 9 = 29) padded to 37 with the UL/SUL bit last.
        assert_eq!(s.f0_0_css, Dci0_0Size { total: 37, fdra: 9, padding: 8, ul_sul_present: true });
    }

    /// Step 2: a 0_1 that lands on the USS fallback size gets one padding bit.
    #[test]
    fn non_fallback_collision_pads_one_bit() {
        let mut c = DciSizeConfig::single_bwp(24, 24);
        c.nof_pusch_tdra_rows = 16; // TDRA 4 → 0_1 = 37 = 0_0 USS
        c.nof_pdsch_tdra_rows = 2;
        c.nof_k1 = 1; // K1 0 bits → 1_1 = 37 too
        let s = dci_sizes(&c);
        assert_eq!(s.f0_0_uss.unwrap().total, 37);
        let a = s.f0_1.unwrap();
        assert_eq!((a.total, a.padding), (38, 1));
        let b = s.f1_1.unwrap();
        assert_eq!((b.total, b.padding), (38, 1));
        assert_eq!(s.nof_distinct_sizes, 2);
    }

    /// Steps 3–4: four distinct C-RNTI sizes (CSS 37, USS 39, 0_1 38, 1_1 42)
    /// exceed the budget, so the USS fallback formats are resized to the CSS.
    #[test]
    fn budget_resets_uss_fallback_to_css() {
        let mut c = live_tdd_10mhz();
        c.dl_bwp_active_rb = 51;
        c.ul_bwp_active_rb = 51;
        let s = dci_sizes(&c);
        assert!(s.uss_fallback_aligned_to_css);
        assert_eq!(s.f1_0_uss.unwrap(), Dci1_0Size { total: 37, fdra: 9, padding: 0 });
        let u0 = s.f0_0_uss.unwrap();
        // 0_0 USS: 20 + 11 = 31 bits before padding → padded (not truncated) to 37.
        assert_eq!((u0.total, u0.fdra, u0.padding), (37, 11, 6));
        assert_eq!(s.f0_1.unwrap().total, 38);
        assert_eq!(s.f1_1.unwrap().total, 42);
        assert_eq!(s.nof_distinct_sizes, 3);
    }

    /// Field-width rules that the live cell does not exercise.
    #[test]
    fn optional_field_widths() {
        let mut c = DciSizeConfig::single_bwp(24, 24);
        c.frequency_hopping = true;
        c.vrb_to_prb_interleaver = true;
        c.harq_ack_codebook = HarqAckCodebook::SemiStatic;
        c.report_trigger_size = 2;
        c.nof_aperiodic_zp_csi_rs_sets = 1;
        c.rate_match_groups = 2;
        c.tci_present = true;
        c.two_codewords = true;
        c.pdsch_dmrs_type_a = Some(DmrsConfig { config_type: 2, max_length: 2 });
        c.nof_dl_bwp_rrc = 1;
        c.nof_ul_bwp_rrc = 4;
        c.pusch_tx_scheme = Some(PuschTxScheme::Codebook {
            nof_srs_ports: 2,
            max_rank: 2,
            subset: CodebookSubset::FullyAndPartialAndNonCoherent,
        });
        c.nof_srs_resources = 2;
        c.ptrs_uplink = true;
        c.dynamic_beta_offsets = true;
        c.transform_precoding = false;
        let a = dci_0_1_size(&c);
        assert_eq!((a.bwp_indicator, a.frequency_hopping_flag, a.first_dai), (2, 1, 1));
        assert_eq!((a.srs_resource_indicator, a.precoding_info, a.antenna_ports), (1, 4, 3));
        assert_eq!((a.csi_request, a.ptrs_dmrs_association, a.beta_offset, a.dmrs_seq_init), (2, 2, 2, 1));
        let b = dci_1_1_size(&c);
        assert_eq!((b.bwp_indicator, b.vrb_to_prb, b.rate_matching, b.zp_csi_rs_trigger), (1, 1, 2, 1));
        assert_eq!((b.tb2, b.dai, b.antenna_ports, b.tci), (8, 0, 6, 3));
        // Non-codebook SRI: N_SRS = 4, L_max = 2 → C(4,1) + C(4,2) = 10 → 4 bits.
        c.pusch_tx_scheme = Some(PuschTxScheme::NonCodebook { l_max: 2 });
        c.nof_srs_resources = 4;
        let a = dci_0_1_size(&c);
        assert_eq!((a.srs_resource_indicator, a.precoding_info), (4, 0));
        // Transform precoding: 2-bit antenna ports, no DM-RS init bit.
        c.transform_precoding = true;
        let a = dci_0_1_size(&c);
        assert_eq!((a.antenna_ports, a.dmrs_seq_init), (2, 0));
    }

    fn bits_of(fields: &[(u32, usize)]) -> Vec<u8> {
        let mut v = Vec::new();
        for &(val, w) in fields {
            for i in (0..w).rev() {
                v.push(((val >> i) & 1) as u8);
            }
        }
        v
    }

    #[test]
    fn parse_1_0_variants() {
        let s = dci_sizes(&live_tdd_10mhz());
        let f = s.f1_0_css;
        // SI-RNTI: RIV 275 (= 24·11 + 11 → start 11, 12 RB), row 0, MCS 5, RV 0, SIB1.
        let si = bits_of(&[(275, 9), (0, 4), (1, 1), (5, 5), (0, 2), (0, 1), (0, 15)]);
        let d = parse_dci_1_0(&si, RntiKind::Si, &f).unwrap();
        assert_eq!((d.fdra, d.tdra, d.vrb_to_prb_interleaved, d.mcs, d.rv, d.si_indicator), (275, 0, true, 5, Some(0), Some(0)));
        assert_eq!(riv_decode(d.fdra, 24), Some((11, 12)));
        assert_eq!(riv_decode_css(d.fdra, 24, 0), Some((11, 12)));
        // RA-RNTI: TB scaling 1.
        let ra = bits_of(&[(3, 9), (2, 4), (0, 1), (9, 5), (1, 2), (0, 16)]);
        let d = parse_dci_1_0(&ra, RntiKind::Ra, &f).unwrap();
        assert_eq!((d.fdra, d.tdra, d.mcs, d.tb_scaling, d.rv), (3, 2, 9, Some(1), None));
        // C-RNTI: id 1, RIV 100, row 1, MCS 7, NDI 1, RV 2, HARQ 5, DAI 3, TPC 1, PRI 6, K1 idx 4.
        let c = bits_of(&[(1, 1), (100, 9), (1, 4), (0, 1), (7, 5), (1, 1), (2, 2), (5, 4), (3, 2), (1, 2), (6, 3), (4, 3)]);
        let d = parse_dci_1_0(&c, RntiKind::C, &f).unwrap();
        assert_eq!((d.fdra, d.tdra, d.mcs, d.ndi, d.rv, d.harq_id), (100, 1, 7, Some(true), Some(2), Some(5)));
        assert_eq!((d.dai, d.tpc, d.pri, d.k1_idx), (Some(3), Some(1), Some(6), Some(4)));
        assert!(d.pdcch_order.is_none());
        // TC-RNTI: the DAI bits are reserved.
        let d = parse_dci_1_0(&c, RntiKind::Tc, &f).unwrap();
        assert_eq!(d.dai, None);
        assert_eq!(d.pri, Some(6));
        // PDCCH order: FDRA all ones.
        let po = bits_of(&[(1, 1), (511, 9), (17, 6), (0, 1), (3, 6), (2, 4), (0, 10)]);
        let d = parse_dci_1_0(&po, RntiKind::C, &f).unwrap();
        assert_eq!(d.pdcch_order, Some(PdcchOrder { preamble_index: 17, ul_sul: false, ssb_index: 3, prach_mask_index: 2 }));
        // P-RNTI.
        let p = bits_of(&[(2, 2), (0b1000_0000, 8), (5, 9), (0, 4), (0, 1), (2, 5), (0, 2), (0, 6)]);
        let d = parse_dci_1_0(&p, RntiKind::P, &f).unwrap();
        assert_eq!((d.short_messages_indicator, d.short_messages, d.fdra, d.mcs), (Some(2), Some(128), 5, 2));
        // Wrong identifier / length.
        let mut bad = c.clone();
        bad[0] = 0;
        assert_eq!(parse_dci_1_0(&bad, RntiKind::C, &f), Err(DciParseError::WrongIdentifier));
        assert!(matches!(parse_dci_1_0(&c[..36], RntiKind::C, &f), Err(DciParseError::WrongLength { .. })));
    }

    #[test]
    fn parse_0_0_with_padding_and_hopping() {
        let s = dci_sizes(&live_tdd_10mhz());
        let f = s.f0_0_css; // 37 bits: 9 FDRA + 8 padding
        // Hopping on: 1 MSB of the FDRA field is the offset (N_BWP = 24 < 50).
        let raw = (1 << 8) | 37; // offset 1, RIV 37
        let b = bits_of(&[(0, 1), (raw, 9), (3, 4), (1, 1), (4, 5), (1, 1), (0, 2), (2, 4), (3, 2), (0, 8)]);
        let d = parse_dci_0_0(&b, RntiKind::C, &f, 24).unwrap();
        assert_eq!((d.fdra, d.hopping_offset, d.tdra, d.frequency_hopping), (37, Some(1), 3, true));
        assert_eq!((d.mcs, d.ndi, d.rv, d.harq_id, d.tpc, d.ul_sul), (4, Some(true), 0, Some(2), 3, None));
        // Same payload for TC-RNTI: NDI / HARQ reserved.
        let d = parse_dci_0_0(&b, RntiKind::Tc, &f, 24).unwrap();
        assert_eq!((d.ndi, d.harq_id), (None, None));
        // Hopping off: the whole field is the RIV.
        let b = bits_of(&[(0, 1), (raw, 9), (3, 4), (0, 1), (4, 5), (1, 1), (0, 2), (2, 4), (3, 2), (0, 8)]);
        let d = parse_dci_0_0(&b, RntiKind::C, &f, 24).unwrap();
        assert_eq!((d.fdra, d.hopping_offset), (raw, None));
        // UL/SUL bit in the last padding position.
        let mut c = live_tdd_10mhz();
        c.sul_configured = true;
        let f = dci_sizes(&c).f0_0_css;
        assert!(f.ul_sul_present);
        let b = bits_of(&[(0, 1), (raw, 9), (3, 4), (0, 1), (4, 5), (1, 1), (0, 2), (2, 4), (3, 2), (0, 7), (1, 1)]);
        assert_eq!(parse_dci_0_0(&b, RntiKind::C, &f, 24).unwrap().ul_sul, Some(true));
    }

    #[test]
    fn parse_1_1_and_0_1_live_layout() {
        let s = dci_sizes(&live_tdd_10mhz());
        let f1 = s.f1_1.unwrap();
        // id 1, RIV 200, TDRA 1, MCS 20, NDI 0, RV 1, HARQ 9, DAI 2, TPC 1, PRI 5, K1 idx 3,
        // antenna ports 2, SRS request 0, DM-RS init 1.
        let b = bits_of(&[(1, 1), (200, 9), (1, 1), (20, 5), (0, 1), (1, 2), (9, 4), (2, 2), (1, 2), (5, 3), (3, 3), (2, 4), (0, 2), (1, 1)]);
        assert_eq!(b.len(), 40);
        let d = parse_dci_1_1(&b, &f1).unwrap();
        assert_eq!((d.fdra, d.tdra, d.mcs, d.ndi, d.rv, d.harq_id), (200, 1, 20, false, 1, 9));
        assert_eq!((d.dai, d.tpc, d.pri, d.k1_idx, d.antenna_ports, d.dmrs_seq_init), (Some(2), 1, 5, Some(3), 2, 1));
        assert_eq!((d.vrb_to_prb_interleaved, d.tci, d.cbgti, d.tb2), (None, None, None, None));
        assert_eq!(crate::dmrs::dci_1_1_antenna_ports_type1_len1(d.antenna_ports).unwrap().nof_cdm_groups_without_data, 1);
        let f0 = s.f0_1.unwrap();
        // id 0, RIV 300, TDRA 5, MCS 10, NDI 1, RV 0, HARQ 3, DAI 1, TPC 2, antenna 2, SRS req 0,
        // DM-RS init 0, UL-SCH 1.
        let b = bits_of(&[(0, 1), (300, 9), (5, 3), (10, 5), (1, 1), (0, 2), (3, 4), (1, 2), (2, 2), (2, 3), (0, 2), (0, 1), (1, 1)]);
        assert_eq!(b.len(), 36);
        let d = parse_dci_0_1(&b, &f0).unwrap();
        assert_eq!((d.fdra, d.tdra, d.mcs, d.ndi, d.rv, d.harq_id), (300, 5, 10, true, 0, 3));
        assert_eq!((d.first_dai, d.tpc, d.antenna_ports, d.srs_request, d.dmrs_seq_init, d.ul_sch), (1, 2, 2, 0, Some(0), true));
        assert_eq!((d.frequency_hopping, d.srs_resource_indicator, d.csi_request), (None, None, None));
        assert_eq!(parse_dci_0_1(&b[..35], &f0), Err(DciParseError::WrongLength { expected: 36, got: 35 }));
    }

    #[test]
    fn riv_roundtrip_and_sliv() {
        for n in [11usize, 24, 51, 106, 273] {
            for s in 0..n {
                for l in 1..=(n - s) {
                    let riv = riv_encode(s, l, n);
                    assert!(riv < (n * (n + 1) / 2) as u32);
                    assert_eq!(riv_decode(riv, n), Some((s, l)), "n={n} s={s} l={l}");
                }
            }
        }
        assert_eq!(riv_decode(300, 24), None); // ≥ N(N+1)/2
        assert_eq!(riv_decode_css(0, 24, 10), Some((10, 1)));
        assert_eq!(sliv_decode(2 * 14 + 2), Some((2, 3)));
        assert_eq!(sliv_decode(53), Some((2, 12))); // L−1 = 11 > 7: 14·(14−12+1) + (13−2)
        assert_eq!(sliv_decode(27), Some((0, 14)));
        assert_eq!(sliv_decode(13 * 14 + 13), None);
    }

    #[test]
    fn default_tdra_tables() {
        let r = default_pdsch_tdra(0, 2).unwrap();
        assert_eq!((r.k, r.mapping, r.s, r.l), (0, MappingType::TypeA, 2, 12));
        let r = default_pdsch_tdra(0, 3).unwrap();
        assert_eq!((r.s, r.l), (3, 11));
        assert_eq!(default_pdsch_tdra(5, 3).unwrap().s, 10);
        assert_eq!(default_pdsch_tdra(6, 3).unwrap().s, 6);
        assert_eq!(default_pdsch_tdra(11, 2).unwrap().l, 13);
        assert_eq!(default_pdsch_tdra(15, 2).unwrap(), TdraRow { k: 0, mapping: MappingType::TypeB, s: 8, l: 4 });
        assert!(default_pdsch_tdra(16, 2).is_none());
        assert!(default_pdsch_tdra(0, 1).is_none());
        let r = default_pusch_tdra(0, 1).unwrap();
        assert_eq!((r.k, r.mapping, r.s, r.l), (1, MappingType::TypeA, 0, 14));
        assert_eq!(default_pusch_tdra(0, 2).unwrap().k, 2);
        assert_eq!(default_pusch_tdra(7, 0).unwrap().k, 2);
        assert_eq!(default_pusch_tdra(14, 3).unwrap().k, 6);
        assert_eq!(default_pusch_tdra(13, 1).unwrap(), TdraRow { k: 1, mapping: MappingType::TypeB, s: 8, l: 6 });
        assert!(default_pusch_tdra(0, 4).is_none());
    }
}
