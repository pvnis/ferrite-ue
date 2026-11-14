//! Default PDSCH / PUSCH time-domain resource allocation tables
//! (TS 38.214 §5.1.2.1.1 Table 5.1.2.1.1-2 and §6.1.2.1.1 Table 6.1.2.1.1-2).

use crate::dmrs::MappingType;


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

