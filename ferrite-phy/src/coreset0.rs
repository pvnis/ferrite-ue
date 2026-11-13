//! CORESET#0 and Type0-PDCCH monitoring occasions from the MIB
//! (3GPP TS 38.213 §13).
//!
//! `pdcch-ConfigSIB1` in the MIB carries two 4-bit indices: `controlResourceSetZero`
//! (row of Tables 13-1 … 13-10, selected by the {SSB, PDCCH} subcarrier spacing
//! and the band's minimum channel bandwidth) and `searchSpaceZero` (row of
//! Table 13-11 / 13-12). This module holds those tables for FR1 (13-1 … 13-6,
//! 13-11) and the FR2 monitoring table (13-12), plus the frequency-offset
//! arithmetic that places CORESET#0 relative to the detected SS/PBCH block.

use ferrite_common::Numerology;

/// SS/PBCH block and CORESET#0 multiplexing pattern (38.213 §13). FR1 always
/// uses pattern 1 (SSB and CORESET#0 in different symbols / slots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiplexingPattern {
    /// SSB and Type0-PDCCH in different time instances, overlapping bandwidth.
    Pattern1,
    /// FR2 only: same slot, different frequencies (SSB SCS twice the PDCCH SCS).
    Pattern2,
    /// FR2 only: same slot, same SCS, different frequencies.
    Pattern3,
}

/// One row of 38.213 Tables 13-1 … 13-10.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coreset0Config {
    /// Number of resource blocks `N_RB^CORESET` (24, 48 or 96), in PDCCH-SCS RBs.
    pub n_rb: usize,
    /// Number of OFDM symbols `N_symb^CORESET` (1, 2 or 3).
    pub n_symb: usize,
    /// RB offset from the lowest RB of CORESET#0 to the lowest common RB that
    /// overlaps the first RB of the SS/PBCH block, in PDCCH-SCS RBs. Positive
    /// values put CORESET#0 *below* the SSB; negative values (FR2 patterns 2/3
    /// only) put it above.
    pub offset_rb: i32,
    /// Multiplexing pattern (always [`MultiplexingPattern::Pattern1`] for FR1).
    pub multiplexing_pattern: MultiplexingPattern,
}

const fn row(n_rb: usize, n_symb: usize, offset_rb: i32) -> Coreset0Config {
    Coreset0Config { n_rb, n_symb, offset_rb, multiplexing_pattern: MultiplexingPattern::Pattern1 }
}

/// Table 13-1: {SSB 15 kHz, PDCCH 15 kHz}, minimum channel bandwidth 5 or 10 MHz.
pub const TABLE_13_1: [Coreset0Config; 15] = [
    row(24, 2, 0), row(24, 2, 2), row(24, 2, 4),
    row(24, 3, 0), row(24, 3, 2), row(24, 3, 4),
    row(48, 1, 12), row(48, 1, 16),
    row(48, 2, 12), row(48, 2, 16),
    row(48, 3, 12), row(48, 3, 16),
    row(96, 1, 38), row(96, 2, 38), row(96, 3, 38),
];

/// Table 13-2: {SSB 15 kHz, PDCCH 30 kHz}, minimum channel bandwidth 5 or 10 MHz.
pub const TABLE_13_2: [Coreset0Config; 14] = [
    row(24, 2, 5), row(24, 2, 6), row(24, 2, 7), row(24, 2, 8),
    row(24, 3, 5), row(24, 3, 6), row(24, 3, 7), row(24, 3, 8),
    row(48, 1, 18), row(48, 1, 20),
    row(48, 2, 18), row(48, 2, 20),
    row(48, 3, 18), row(48, 3, 20),
];

/// Table 13-3: {SSB 30 kHz, PDCCH 15 kHz}, minimum channel bandwidth 5 or 10 MHz.
pub const TABLE_13_3: [Coreset0Config; 9] = [
    row(48, 1, 2), row(48, 1, 6),
    row(48, 2, 2), row(48, 2, 6),
    row(48, 3, 2), row(48, 3, 6),
    row(96, 1, 28), row(96, 2, 28), row(96, 3, 28),
];

/// Table 13-4: {SSB 30 kHz, PDCCH 30 kHz}, minimum channel bandwidth 5 or 10 MHz.
pub const TABLE_13_4: [Coreset0Config; 16] = [
    row(24, 2, 0), row(24, 2, 1), row(24, 2, 2), row(24, 2, 3), row(24, 2, 4),
    row(24, 3, 0), row(24, 3, 1), row(24, 3, 2), row(24, 3, 3), row(24, 3, 4),
    row(48, 1, 12), row(48, 1, 14), row(48, 1, 16),
    row(48, 2, 12), row(48, 2, 14), row(48, 2, 16),
];

/// Table 13-5: {SSB 30 kHz, PDCCH 15 kHz}, minimum channel bandwidth 40 MHz.
pub const TABLE_13_5: [Coreset0Config; 9] = [
    row(48, 1, 4), row(48, 2, 4), row(48, 3, 4),
    row(96, 1, 0), row(96, 1, 56),
    row(96, 2, 0), row(96, 2, 56),
    row(96, 3, 0), row(96, 3, 56),
];

/// Table 13-6: {SSB 30 kHz, PDCCH 30 kHz}, minimum channel bandwidth 40 MHz.
pub const TABLE_13_6: [Coreset0Config; 10] = [
    row(24, 2, 0), row(24, 2, 4),
    row(24, 3, 0), row(24, 3, 4),
    row(48, 1, 0), row(48, 1, 28),
    row(48, 2, 0), row(48, 2, 28),
    row(48, 3, 0), row(48, 3, 28),
];

/// Select the FR1 CORESET#0 table (13-1 … 13-6) for the {SSB, PDCCH} SCS pair and
/// the band's minimum channel bandwidth (`5`, `10` or `40` MHz; 5 and 10 share
/// tables), then return row `index` (`controlResourceSetZero`). `None` for a
/// reserved row or an unsupported combination (e.g. 40 MHz with 15 kHz SSB,
/// which no FR1 band uses).
pub fn coreset0_config(ssb_scs_khz: u32, pdcch_scs_khz: u32, min_bw_mhz: u32, index: u8) -> Option<Coreset0Config> {
    let table: &[Coreset0Config] = match (ssb_scs_khz, pdcch_scs_khz, min_bw_mhz) {
        (15, 15, 5 | 10) => &TABLE_13_1,
        (15, 30, 5 | 10) => &TABLE_13_2,
        (30, 15, 5 | 10) => &TABLE_13_3,
        (30, 30, 5 | 10) => &TABLE_13_4,
        (30, 15, 40) => &TABLE_13_5,
        (30, 30, 40) => &TABLE_13_6,
        _ => return None,
    };
    table.get(usize::from(index)).copied()
}

/// Why the CORESET#0 frequency position cannot be expressed on the requested grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coreset0Error {
    /// `k_SSB` is odd while the PDCCH SCS is 30 kHz: the common RB grid sits one
    /// 15 kHz subcarrier (half a 30 kHz subcarrier) off the SSB grid. The UE must
    /// re-demodulate with the whole FFT grid shifted by 15 kHz (a frequency shift
    /// of the time-domain samples), which a plain bin offset cannot represent.
    HalfSubcarrierOffset { k_ssb: u8 },
    /// Unsupported SCS combination.
    UnsupportedScs,
}

impl std::fmt::Display for Coreset0Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HalfSubcarrierOffset { k_ssb } => write!(
                f,
                "odd k_SSB={k_ssb} with 30 kHz PDCCH SCS: CORESET#0 is half a subcarrier off the SSB grid"
            ),
            Self::UnsupportedScs => write!(f, "unsupported SSB/PDCCH SCS combination"),
        }
    }
}

impl std::error::Error for Coreset0Error {}

/// Lowest subcarrier of CORESET#0 relative to the lowest subcarrier of the
/// SS/PBCH block, in **15 kHz subcarriers** (FR1), from the MIB alone.
///
/// 38.211 §7.4.3.1: `k_SSB` (15 kHz units in FR1) is the offset from subcarrier 0
/// of common RB `N_SSB^CRB` to subcarrier 0 of the SSB, and 38.211 §4.4.4.2 fixes
/// `N_SSB^CRB` (via `offsetToPointA`) to the lowest RB *of the common SCS* that
/// overlaps the SSB. So the common RB overlapping the first SSB RB starts
/// `k_SSB` 15 kHz subcarriers below the SSB, and CORESET#0 starts
/// `offset_rb` PDCCH-SCS RBs below that:
///
/// `Δ = −k_SSB − 12 · (pdcch_scs / 15) · offset_rb`.
pub fn coreset0_offset_15khz(k_ssb: u8, pdcch_scs_khz: u32, cfg: &Coreset0Config) -> i32 {
    let f = (pdcch_scs_khz / 15) as i32;
    -i32::from(k_ssb) - 12 * f * cfg.offset_rb
}

/// Lowest subcarrier of CORESET#0 relative to the lowest subcarrier of the SSB,
/// in **PDCCH-SCS subcarriers**. For 15 kHz PDCCH this is
/// `−k_SSB − 12·offset_rb`; for 30 kHz PDCCH it is `−k_SSB/2 − 12·offset_rb`,
/// which only exists for even `k_SSB` (see [`Coreset0Error::HalfSubcarrierOffset`]).
/// The SSB's own SCS does not enter: the SSB lowest subcarrier is the reference
/// point regardless of its spacing (an SSB at 15 kHz under a 30 kHz CORESET is
/// 10 PDCCH RBs wide, at 30 kHz under 15 kHz PDCCH it is 40 PDCCH RBs wide).
pub fn coreset0_first_subcarrier_rel_ssb(
    k_ssb: u8,
    pdcch_scs_khz: u32,
    cfg: &Coreset0Config,
) -> Result<i32, Coreset0Error> {
    let f = match pdcch_scs_khz {
        15 => 1,
        30 => 2,
        _ => return Err(Coreset0Error::UnsupportedScs),
    };
    let d = coreset0_offset_15khz(k_ssb, pdcch_scs_khz, cfg);
    if d.rem_euclid(f) != 0 {
        return Err(Coreset0Error::HalfSubcarrierOffset { k_ssb });
    }
    Ok(d / f)
}

/// Same as [`coreset0_first_subcarrier_rel_ssb`] but relative to the SSB
/// **centre** (the point the synchronisation grid is centred on), in PDCCH-SCS
/// subcarriers. The SSB spans 240 subcarriers of its own SCS, so its lowest
/// subcarrier is `120 · ssb_scs / pdcch_scs` PDCCH subcarriers below the centre.
pub fn coreset0_first_subcarrier_rel_ssb_centre(
    k_ssb: u8,
    ssb_scs_khz: u32,
    pdcch_scs_khz: u32,
    cfg: &Coreset0Config,
) -> Result<i32, Coreset0Error> {
    let rel_low = coreset0_first_subcarrier_rel_ssb(k_ssb, pdcch_scs_khz, cfg)?;
    let half_ssb_15k = 120 * (ssb_scs_khz / 15) as i32; // half the SSB in 15 kHz units
    let f = (pdcch_scs_khz / 15) as i32;
    if half_ssb_15k % f != 0 {
        // 15 kHz SSB under 30 kHz PDCCH: 120 × 15 kHz = 60 × 30 kHz, always integral.
        return Err(Coreset0Error::UnsupportedScs);
    }
    Ok(rel_low - half_ssb_15k / f)
}

/// First-symbol rule of the Type0-PDCCH occasion tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstSymbolRule {
    /// A fixed first symbol index.
    Fixed(u8),
    /// `M = 1/2` rows: symbol 0 for even SSB index `i`, `N_symb^CORESET` for odd `i`.
    ZeroOrCoresetLen,
    /// FR2 `M = 1/2` rows with two occasions at symbols 0 and 7.
    ZeroOrSeven,
}

/// One row of Table 13-11 / 13-12: `O` (in slots, ×2 to keep halves exact),
/// `M` (×2), first-symbol rule.
#[derive(Clone, Copy, Debug)]
struct OccasionRow {
    o_x2: u8,
    m_x2: u8,
    first_symbol: FirstSymbolRule,
}

const fn r(o_x2: u8, m_x2: u8, first_symbol: FirstSymbolRule) -> OccasionRow {
    OccasionRow { o_x2, m_x2, first_symbol }
}

/// Table 13-11 (FR1, multiplexing pattern 1), indexed by `searchSpaceZero`.
/// Columns: `O`, number of search-space sets per slot (implied by `M`), `M`,
/// first symbol index.
const TABLE_13_11: [OccasionRow; 16] = [
    r(0, 2, FirstSymbolRule::Fixed(0)),
    r(0, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(4, 2, FirstSymbolRule::Fixed(0)),
    r(4, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(10, 2, FirstSymbolRule::Fixed(0)),
    r(10, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(14, 2, FirstSymbolRule::Fixed(0)),
    r(14, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(0, 4, FirstSymbolRule::Fixed(0)),
    r(10, 4, FirstSymbolRule::Fixed(0)),
    r(0, 2, FirstSymbolRule::Fixed(1)),
    r(0, 2, FirstSymbolRule::Fixed(2)),
    r(4, 2, FirstSymbolRule::Fixed(1)),
    r(4, 2, FirstSymbolRule::Fixed(2)),
    r(10, 2, FirstSymbolRule::Fixed(1)),
    r(10, 2, FirstSymbolRule::Fixed(2)),
];

/// Table 13-12 (FR2, multiplexing pattern 1), indexed by `searchSpaceZero`
/// (rows 14 and 15 are reserved).
const TABLE_13_12: [OccasionRow; 14] = [
    r(0, 2, FirstSymbolRule::Fixed(0)),
    r(0, 1, FirstSymbolRule::ZeroOrSeven),
    r(5, 2, FirstSymbolRule::Fixed(0)),
    r(5, 1, FirstSymbolRule::ZeroOrSeven),
    r(10, 2, FirstSymbolRule::Fixed(0)),
    r(10, 1, FirstSymbolRule::ZeroOrSeven),
    r(0, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(5, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(10, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(15, 2, FirstSymbolRule::Fixed(0)),
    r(15, 1, FirstSymbolRule::ZeroOrSeven),
    r(15, 1, FirstSymbolRule::ZeroOrCoresetLen),
    r(0, 4, FirstSymbolRule::Fixed(0)),
    r(10, 4, FirstSymbolRule::Fixed(0)),
];

/// Which system-frame parity the Type0-PDCCH monitoring slots fall in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SfnParity {
    /// `SFN_C mod 2 = 0`.
    Even,
    /// `SFN_C mod 2 = 1`.
    Odd,
}

/// Type0-PDCCH CSS monitoring occasion for one SS/PBCH block index (38.213 §13,
/// multiplexing pattern 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Type0Monitoring {
    /// `O` from the table (in ms, i.e. slots at 15 kHz), doubled to keep the FR2
    /// halves exact: `O = o_x2 / 2` ∈ {0, 2, 5, 7} (FR1) or {0, 2.5, 5, 7.5} (FR2).
    pub o_x2: u8,
    /// `M` from the table, doubled: {1, 2, 4} ↔ M ∈ {1/2, 1, 2}.
    pub m_x2: u8,
    /// First monitoring slot `n0 = (O·2^µ + ⌊i·M⌋) mod N_slot^frame,µ`; the UE
    /// monitors slots `n0` and `n0 + 1`.
    pub n0: u32,
    /// Parity of the frame `SFN_C` containing slot `n0`:
    /// even if `⌊(O·2^µ + ⌊i·M⌋) / N_slot^frame,µ⌋ mod 2 = 0`, else odd.
    pub sfn_parity: SfnParity,
    /// First OFDM symbol of the CORESET in each monitored slot.
    pub first_symbol: u8,
}

/// Table 13-11 (FR1) occasion for `searchSpaceZero = ss0_index`, SSB index
/// `ssb_index` (`i`), PDCCH numerology `mu` and the CORESET#0 row (for its
/// symbol count). `None` for a reserved row.
pub fn type0_pdcch_monitoring(ss0_index: u8, ssb_index: u8, mu: u8, coreset0: &Coreset0Config) -> Option<Type0Monitoring> {
    let row = *TABLE_13_11.get(usize::from(ss0_index))?;
    Some(type0_occasion(row, ssb_index, mu, coreset0))
}

/// Table 13-12 (FR2) occasion; same contract as [`type0_pdcch_monitoring`].
pub fn type0_pdcch_monitoring_fr2(ss0_index: u8, ssb_index: u8, mu: u8, coreset0: &Coreset0Config) -> Option<Type0Monitoring> {
    let row = *TABLE_13_12.get(usize::from(ss0_index))?;
    Some(type0_occasion(row, ssb_index, mu, coreset0))
}

fn type0_occasion(row: OccasionRow, ssb_index: u8, mu: u8, coreset0: &Coreset0Config) -> Type0Monitoring {
    let slots_per_frame = Numerology::new(mu).slots_per_frame();
    // O·2^µ + ⌊i·M⌋, all in units of slots. O·2^µ = o_x2·2^µ/2 is integral for
    // µ ≥ 1 and for the FR1 (integer O) rows at µ = 0.
    let o_slots = (u32::from(row.o_x2) << mu) / 2;
    let im = (u32::from(ssb_index) * u32::from(row.m_x2)) / 2;
    let total = o_slots + im;
    let n0 = total % slots_per_frame;
    let sfn_parity = if (total / slots_per_frame).is_multiple_of(2) { SfnParity::Even } else { SfnParity::Odd };
    let first_symbol = match row.first_symbol {
        FirstSymbolRule::Fixed(s) => s,
        FirstSymbolRule::ZeroOrCoresetLen => {
            if ssb_index.is_multiple_of(2) {
                0
            } else {
                coreset0.n_symb as u8
            }
        }
        FirstSymbolRule::ZeroOrSeven => {
            if ssb_index.is_multiple_of(2) {
                0
            } else {
                7
            }
        }
    };
    Type0Monitoring { o_x2: row.o_x2, m_x2: row.m_x2, n0, sfn_parity, first_symbol }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live TDD cell: pdcch-ConfigSIB1 = 0x20 → controlResourceSetZero = 2,
    /// searchSpaceZero = 0, SSB/PDCCH 30/30 kHz, band n78 (min bw 10 MHz).
    #[test]
    fn live_tdd_cell_coreset0_index_2() {
        let pdcch_config_sib1: u8 = 0x20;
        let cset0_idx = pdcch_config_sib1 >> 4;
        let ss0_idx = pdcch_config_sib1 & 0xF;
        let c = coreset0_config(30, 30, 10, cset0_idx).unwrap();
        assert_eq!(c, row(24, 2, 2));
        let m = type0_pdcch_monitoring(ss0_idx, 0, 1, &c).unwrap();
        assert_eq!(m.o_x2, 0);
        assert_eq!(m.m_x2, 2);
        assert_eq!(m.n0, 0);
        assert_eq!(m.sfn_parity, SfnParity::Even);
        assert_eq!(m.first_symbol, 0);
        // SSB index 3 with M = 1 → n0 = 3, still even frame.
        let m3 = type0_pdcch_monitoring(ss0_idx, 3, 1, &c).unwrap();
        assert_eq!(m3.n0, 3);
        assert_eq!(m3.sfn_parity, SfnParity::Even);
    }

    /// FDD n3 at 15 kHz, 20 MHz: controlResourceSetZero = 12 of Table 13-1
    /// (96 RB, 1 symbol, offset 38); 10 MHz (52 RB carrier) index 6 (48 RB, 1
    /// symbol, offset 12).
    #[test]
    fn fdd_n3_15khz_rows() {
        assert_eq!(coreset0_config(15, 15, 5, 12).unwrap(), row(96, 1, 38));
        assert_eq!(coreset0_config(15, 15, 10, 6).unwrap(), row(48, 1, 12));
        assert_eq!(coreset0_config(15, 15, 5, 15), None);
        assert_eq!(coreset0_config(15, 15, 40, 0), None);
    }

    #[test]
    fn table_sizes_and_fr1_pattern() {
        for t in [&TABLE_13_1[..], &TABLE_13_2, &TABLE_13_3, &TABLE_13_4, &TABLE_13_5, &TABLE_13_6] {
            for c in t {
                assert_eq!(c.multiplexing_pattern, MultiplexingPattern::Pattern1);
                assert!(matches!(c.n_rb, 24 | 48 | 96));
                assert!((1..=3).contains(&c.n_symb));
                assert!(c.offset_rb >= 0);
            }
        }
        assert_eq!(coreset0_config(30, 30, 40, 9).unwrap(), row(48, 3, 28));
        assert_eq!(coreset0_config(30, 15, 40, 4).unwrap(), row(96, 1, 56));
        assert_eq!(coreset0_config(15, 30, 10, 13).unwrap(), row(48, 3, 20));
        assert_eq!(coreset0_config(30, 15, 10, 8).unwrap(), row(96, 3, 28));
    }

    /// Frequency placement: matches the legacy 30/30 formula
    /// (`-120 - k_SSB/2 - 12·offset_rb` from the SSB centre) and rejects odd k_SSB
    /// at 30 kHz.
    #[test]
    fn first_subcarrier_offsets() {
        let c = row(24, 2, 2);
        assert_eq!(coreset0_first_subcarrier_rel_ssb(16, 30, &c), Ok(-8 - 24));
        assert_eq!(coreset0_first_subcarrier_rel_ssb_centre(16, 30, 30, &c), Ok(-152));
        assert_eq!(
            coreset0_first_subcarrier_rel_ssb(7, 30, &c),
            Err(Coreset0Error::HalfSubcarrierOffset { k_ssb: 7 })
        );
        // 15/15: one subcarrier per k_SSB unit.
        let c15 = row(96, 1, 38);
        assert_eq!(coreset0_first_subcarrier_rel_ssb(7, 15, &c15), Ok(-7 - 12 * 38));
        assert_eq!(coreset0_first_subcarrier_rel_ssb_centre(0, 15, 15, &c15), Ok(-120 - 456));
        // 15 kHz SSB under 30 kHz PDCCH: the SSB is 120 subcarriers (10 RB) wide
        // on the PDCCH grid, so its centre is 60 PDCCH subcarriers above its edge.
        let c2 = row(24, 2, 5);
        assert_eq!(coreset0_first_subcarrier_rel_ssb(2, 30, &c2), Ok(-1 - 60));
        assert_eq!(coreset0_first_subcarrier_rel_ssb_centre(2, 15, 30, &c2), Ok(-61 - 60));
        // 30 kHz SSB under 15 kHz PDCCH: SSB 480 subcarriers wide on the 15 kHz grid.
        let c3 = row(48, 1, 2);
        assert_eq!(coreset0_first_subcarrier_rel_ssb_centre(4, 30, 15, &c3), Ok(-4 - 24 - 240));
    }

    /// Table 13-11 semantics: M = 1/2 rows alternate first symbol with the SSB
    /// index; O = 5 ms rows land in the second half-frame; the frame parity flips
    /// when the slot count wraps.
    #[test]
    fn type0_occasions_table_13_11() {
        let c = row(24, 2, 0);
        // Row 1: O = 0, M = 1/2, first symbol 0 / N_symb.
        let m = type0_pdcch_monitoring(1, 0, 1, &c).unwrap();
        assert_eq!((m.n0, m.first_symbol), (0, 0));
        let m = type0_pdcch_monitoring(1, 1, 1, &c).unwrap();
        assert_eq!((m.n0, m.first_symbol), (0, 2));
        let m = type0_pdcch_monitoring(1, 3, 1, &c).unwrap();
        assert_eq!((m.n0, m.first_symbol), (1, 2));
        // Row 4: O = 5, M = 1 at µ = 1 → slot 10 + i.
        let m = type0_pdcch_monitoring(4, 2, 1, &c).unwrap();
        assert_eq!(m.n0, 12);
        assert_eq!(m.sfn_parity, SfnParity::Even);
        // Row 6: O = 7, M = 1 at µ = 0, SSB 3 → total 10 → wraps into odd frame, slot 0.
        let m = type0_pdcch_monitoring(6, 3, 0, &c).unwrap();
        assert_eq!(m.n0, 0);
        assert_eq!(m.sfn_parity, SfnParity::Odd);
        // Row 8: M = 2 → n0 = 2i.
        let m = type0_pdcch_monitoring(8, 5, 1, &c).unwrap();
        assert_eq!(m.n0, 10);
        // Row 11: first symbol 2.
        assert_eq!(type0_pdcch_monitoring(11, 0, 1, &c).unwrap().first_symbol, 2);
        assert!(type0_pdcch_monitoring(16, 0, 1, &c).is_none());
    }

    #[test]
    fn type0_occasions_table_13_12() {
        let c = row(48, 1, 0);
        // Row 2: O = 2.5 at µ = 3 → 20 slots.
        let m = type0_pdcch_monitoring_fr2(2, 0, 3, &c).unwrap();
        assert_eq!(m.n0, 20);
        // Row 1: M = 1/2, first symbol 0 / 7.
        assert_eq!(type0_pdcch_monitoring_fr2(1, 1, 3, &c).unwrap().first_symbol, 7);
        assert!(type0_pdcch_monitoring_fr2(14, 0, 3, &c).is_none());
    }
}
