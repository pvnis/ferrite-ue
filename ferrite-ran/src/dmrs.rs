//! DM-RS time positions and CDM-group bookkeeping for PDSCH and PUSCH
//! (3GPP TS 38.211 §7.4.1.1.2 and §6.4.1.1.3; TS 38.212 Table 7.3.1.2.2-1).
//!
//! The front-loaded DM-RS symbol `l0` is `dmrs-TypeA-Position` (2 or 3) for
//! mapping type A and the first symbol of the allocation for mapping type B.
//! Additional DM-RS symbols follow Table 7.4.1.1.2-3 (PDSCH) / 6.4.1.1.3-3
//! (PUSCH) as a function of `l_d`, which is the duration from slot symbol 0 to
//! the end of the allocation for type A (`S + L`) and the allocation length `L`
//! for type B. Positions are returned as absolute symbol indices in the slot.

/// PDSCH/PUSCH mapping type (38.214 §5.1.2.1 / §6.1.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingType {
    /// DM-RS at `dmrs-TypeA-Position`; allocation starts at symbol 0..3.
    TypeA,
    /// DM-RS at the first allocated symbol.
    TypeB,
}

/// Reasons a DM-RS pattern cannot be derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmrsError {
    /// `dmrs-TypeA-Position` must be 2 or 3.
    InvalidTypeAPosition(u8),
    /// `dmrs-AdditionalPosition` must be 0..=3.
    InvalidAdditionalPosition(u8),
    /// The allocation (`start_symbol`, `n_symbols`) is not a valid row of the
    /// relevant table (e.g. type A ending before `l0`, type B of 14 symbols).
    InvalidAllocation {
        start_symbol: usize,
        n_symbols: usize,
    },
    /// Double-symbol DM-RS (`maxLength = 2`) is not supported.
    DoubleSymbolUnsupported,
}

impl std::fmt::Display for DmrsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTypeAPosition(p) => write!(f, "dmrs-TypeA-Position {p} not in {{2,3}}"),
            Self::InvalidAdditionalPosition(p) => {
                write!(f, "dmrs-AdditionalPosition {p} not in 0..=3")
            }
            Self::InvalidAllocation {
                start_symbol,
                n_symbols,
            } => {
                write!(f, "no DM-RS row for S={start_symbol}, L={n_symbols}")
            }
            Self::DoubleSymbolUnsupported => write!(f, "double-symbol DM-RS not supported"),
        }
    }
}

impl std::error::Error for DmrsError {}

/// Additional DM-RS symbol positions for PDSCH mapping type A, single-symbol
/// DM-RS (Table 7.4.1.1.2-3, type A columns), excluding `l0`. Indexed by
/// `l_d` and `dmrs-AdditionalPosition`. Identical for PUSCH (Table 6.4.1.1.3-3).
fn type_a_additional(l_d: usize, add_pos: u8) -> &'static [usize] {
    match (l_d, add_pos) {
        (_, 0) => &[],
        (..=7, _) => &[],
        (8 | 9, _) => &[7],
        (10 | 11, 1) => &[9],
        (10 | 11, _) => &[6, 9],
        (12, 1) => &[9],
        (12, 2) => &[6, 9],
        (12, _) => &[5, 8, 11],
        (13 | 14, 1) => &[11],
        (13 | 14, 2) => &[7, 11],
        (13 | 14, _) => &[5, 8, 11],
        _ => &[],
    }
}

/// DM-RS symbol positions (relative to the allocation start, including `l' = 0`)
/// for PDSCH mapping type B, single-symbol DM-RS (Table 7.4.1.1.2-3, type B
/// columns). `None` for durations outside the table (`l_d = 14`).
fn pdsch_type_b_positions(l_d: usize, add_pos: u8) -> Option<&'static [usize]> {
    Some(match (l_d, add_pos) {
        (2..=4, _) | (_, 0) if l_d <= 13 => &[0],
        (5..=7, _) => &[0, 4],
        (8, 1) => &[0, 6],
        (8, _) => &[0, 3, 6],
        (9 | 10, 1) => &[0, 7],
        (9 | 10, _) => &[0, 4, 7],
        (11, 1) => &[0, 8],
        (11, 2) => &[0, 4, 8],
        (11, _) => &[0, 3, 6, 9],
        (12 | 13, 1) => &[0, 9],
        (12 | 13, 2) => &[0, 5, 9],
        (12 | 13, _) => &[0, 3, 6, 9],
        _ => return None,
    })
}

/// DM-RS symbol positions (relative to the allocation start, including `l' = 0`)
/// for PUSCH mapping type B, single-symbol DM-RS, intra-slot frequency hopping
/// disabled (Table 6.4.1.1.3-3, type B columns).
fn pusch_type_b_positions(l_d: usize, add_pos: u8) -> Option<&'static [usize]> {
    Some(match (l_d, add_pos) {
        (1..=4, _) | (_, 0) if l_d <= 14 => &[0],
        (5..=7, _) => &[0, 4],
        (8 | 9, 1) => &[0, 6],
        (8 | 9, _) => &[0, 3, 6],
        (10 | 11, 1) => &[0, 8],
        (10 | 11, 2) => &[0, 4, 8],
        (10 | 11, _) => &[0, 3, 6, 9],
        (12..=14, 1) => &[0, 10],
        (12..=14, 2) => &[0, 5, 10],
        (12..=14, _) => &[0, 3, 6, 9],
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Channel {
    Pdsch,
    Pusch,
}

fn dmrs_symbols(
    ch: Channel,
    mapping: MappingType,
    typea_pos: u8,
    add_pos: u8,
    start_symbol: usize,
    n_symbols: usize,
) -> Result<Vec<usize>, DmrsError> {
    if !matches!(typea_pos, 2 | 3) {
        return Err(DmrsError::InvalidTypeAPosition(typea_pos));
    }
    if add_pos > 3 {
        return Err(DmrsError::InvalidAdditionalPosition(add_pos));
    }
    let invalid = DmrsError::InvalidAllocation {
        start_symbol,
        n_symbols,
    };
    if n_symbols == 0 || start_symbol + n_symbols > 14 {
        return Err(invalid);
    }
    match mapping {
        MappingType::TypeA => {
            let l0 = usize::from(typea_pos);
            let l_d = start_symbol + n_symbols;
            // Type A: S ∈ {0..3} with S ≤ l0, and the allocation must contain l0.
            // The spec's table starts at l_d = 3 (38.214 Table 5.1.2.1-1 allows
            // S + L ≥ 3 for type A); l_d = 3 or 4 is only valid with pos2.
            let min_ld = match ch {
                Channel::Pdsch => 3,
                Channel::Pusch => 4,
            };
            if start_symbol > l0 || l_d <= l0 || l_d < min_ld || (typea_pos == 3 && l_d < 5) {
                return Err(invalid);
            }
            if typea_pos == 3 && add_pos == 3 {
                // 38.211 §7.4.1.1.2: pos3 additional positions require l0 = 2.
                return Err(invalid);
            }
            let mut v = vec![l0];
            v.extend_from_slice(type_a_additional(l_d, add_pos));
            Ok(v)
        }
        MappingType::TypeB => {
            let rel = match ch {
                Channel::Pdsch => pdsch_type_b_positions(n_symbols, add_pos),
                Channel::Pusch => pusch_type_b_positions(n_symbols, add_pos),
            }
            .ok_or(invalid)?;
            Ok(rel.iter().map(|l| start_symbol + l).collect())
        }
    }
}

/// PDSCH DM-RS symbol positions (absolute symbol indices in the slot) for
/// single-symbol DM-RS, Table 7.4.1.1.2-3. `typea_pos` is `dmrs-TypeA-Position`
/// (2 or 3), `add_pos` is `dmrs-AdditionalPosition` (0..=3), the allocation is
/// `[start_symbol, start_symbol + n_symbols)`.
pub fn pdsch_dmrs_symbols(
    mapping: MappingType,
    typea_pos: u8,
    add_pos: u8,
    start_symbol: usize,
    n_symbols: usize,
) -> Result<Vec<usize>, DmrsError> {
    dmrs_symbols(
        Channel::Pdsch,
        mapping,
        typea_pos,
        add_pos,
        start_symbol,
        n_symbols,
    )
}

/// PDSCH DM-RS positions for double-symbol DM-RS (Table 7.4.1.1.2-4).
/// `maxLength = 2` is not supported: always `Err(DoubleSymbolUnsupported)`.
pub fn pdsch_dmrs_symbols_len2(
    _mapping: MappingType,
    _typea_pos: u8,
    _add_pos: u8,
    _start_symbol: usize,
    _n_symbols: usize,
) -> Result<Vec<usize>, DmrsError> {
    Err(DmrsError::DoubleSymbolUnsupported)
}

/// PUSCH DM-RS symbol positions (absolute), single-symbol DM-RS, intra-slot
/// frequency hopping disabled, Table 6.4.1.1.3-3. Type A rows exist for
/// `l_d ≥ 4` only.
pub fn pusch_dmrs_symbols(
    mapping: MappingType,
    typea_pos: u8,
    add_pos: u8,
    start_symbol: usize,
    n_symbols: usize,
) -> Result<Vec<usize>, DmrsError> {
    dmrs_symbols(
        Channel::Pusch,
        mapping,
        typea_pos,
        add_pos,
        start_symbol,
        n_symbols,
    )
}

/// DM-RS configuration type 1 (38.211 §7.4.1.1.2): CDM group λ occupies
/// subcarriers `2n + λ` (λ ∈ {0, 1}) of every RB in a DM-RS symbol. With
/// `nof_cdm_groups_without_data = 1` only group 0 is reserved, so the odd
/// subcarriers of a DM-RS symbol still carry data; with 2 the whole symbol is
/// DM-RS. Returns, per subcarrier of an RB, whether it carries **data**.
pub fn dmrs_type1_data_sc_mask(nof_cdm_groups_without_data: u8) -> [bool; 12] {
    let mut m = [false; 12];
    if nof_cdm_groups_without_data <= 1 {
        for (k, slot) in m.iter_mut().enumerate() {
            *slot = k % 2 == 1;
        }
    }
    m
}

/// DM-RS REs per RB in one DM-RS symbol for configuration type 1: 6 per CDM
/// group without data (used for the TBS `N_DMRS^PRB` term, 38.214 §5.1.3.2).
pub const fn dmrs_type1_re_per_rb_symbol(nof_cdm_groups_without_data: u8) -> usize {
    6 * nof_cdm_groups_without_data as usize
}

/// One row of 38.212 Table 7.3.1.2.2-1 (DCI 1_1 antenna-port field, DM-RS type
/// 1, `maxLength = 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AntennaPorts {
    /// Number of DM-RS CDM group(s) without data (1 or 2).
    pub nof_cdm_groups_without_data: u8,
    /// DM-RS port(s) `1000 + p`, as `p`.
    pub ports: &'static [u8],
}

/// 38.212 Table 7.3.1.2.2-1: antenna-port field value (4 bits) → CDM groups
/// without data and DM-RS ports, for DM-RS type 1 and `maxLength = 1`.
/// Values 12..15 are reserved.
pub fn dci_1_1_antenna_ports_type1_len1(value: u8) -> Option<AntennaPorts> {
    const T: [AntennaPorts; 12] = [
        AntennaPorts {
            nof_cdm_groups_without_data: 1,
            ports: &[0],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 1,
            ports: &[1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 1,
            ports: &[0, 1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[2],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[3],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0, 1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[2, 3],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0, 1, 2],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0, 1, 2, 3],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0, 2],
        },
    ];
    T.get(usize::from(value)).copied()
}

/// 38.212 Table 7.3.1.1.2-8: DCI 0_1 antenna-port field (3 bits) for PUSCH
/// with transform precoding disabled, DM-RS type 1, `maxLength = 1`, rank 1.
/// Values 6, 7 are reserved.
pub fn dci_0_1_antenna_ports_type1_len1_rank1(value: u8) -> Option<AntennaPorts> {
    const T: [AntennaPorts; 6] = [
        AntennaPorts {
            nof_cdm_groups_without_data: 1,
            ports: &[0],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 1,
            ports: &[1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[0],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[1],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[2],
        },
        AntennaPorts {
            nof_cdm_groups_without_data: 2,
            ports: &[3],
        },
    ];
    T.get(usize::from(value)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use MappingType::*;

    fn pdsch(m: MappingType, pos: u8, add: u8, s: usize, l: usize) -> Vec<usize> {
        pdsch_dmrs_symbols(m, pos, add, s, l).unwrap()
    }

    #[test]
    fn pdsch_type_a_rows() {
        assert_eq!(pdsch(TypeA, 2, 2, 0, 14), vec![2, 7, 11]);
        assert_eq!(pdsch(TypeA, 2, 2, 2, 12), vec![2, 7, 11]); // l_d = 14
        assert_eq!(pdsch(TypeA, 2, 2, 2, 6), vec![2, 7]); // l_d = 8
        assert_eq!(pdsch(TypeA, 2, 2, 0, 10), vec![2, 6, 9]); // l_d = 10
        assert_eq!(pdsch(TypeA, 2, 2, 0, 11), vec![2, 6, 9]); // l_d = 11 (Table 7.4.1.1.2-3)
        assert_eq!(pdsch(TypeA, 2, 2, 0, 12), vec![2, 6, 9]); // l_d = 12, pos2
        assert_eq!(pdsch(TypeA, 2, 3, 0, 12), vec![2, 5, 8, 11]); // l_d = 12, pos3
        assert_eq!(pdsch(TypeA, 2, 2, 0, 13), vec![2, 7, 11]);
        assert_eq!(pdsch(TypeA, 2, 1, 0, 14), vec![2, 11]);
        assert_eq!(pdsch(TypeA, 2, 1, 0, 12), vec![2, 9]);
        assert_eq!(pdsch(TypeA, 2, 3, 0, 14), vec![2, 5, 8, 11]);
        assert_eq!(pdsch(TypeA, 2, 0, 0, 14), vec![2]);
        assert_eq!(pdsch(TypeA, 2, 2, 2, 5), vec![2]); // l_d = 7
        assert_eq!(pdsch(TypeA, 3, 2, 0, 14), vec![3, 7, 11]);
        assert_eq!(pdsch(TypeA, 3, 1, 1, 13), vec![3, 11]);
        // Invalid: allocation ends before l0, or pos3 with l_d < 5.
        assert!(pdsch_dmrs_symbols(TypeA, 2, 2, 0, 2).is_err());
        assert!(pdsch_dmrs_symbols(TypeA, 3, 2, 0, 4).is_err());
        assert!(pdsch_dmrs_symbols(TypeA, 3, 3, 0, 14).is_err());
        assert!(pdsch_dmrs_symbols(TypeA, 4, 2, 0, 14).is_err());
        assert!(pdsch_dmrs_symbols(TypeA, 2, 4, 0, 14).is_err());
    }

    #[test]
    fn pdsch_type_b_rows() {
        assert_eq!(pdsch(TypeB, 2, 2, 9, 4), vec![9]);
        assert_eq!(pdsch(TypeB, 2, 2, 5, 2), vec![5]);
        assert_eq!(pdsch(TypeB, 2, 1, 5, 7), vec![5, 9]);
        assert_eq!(pdsch(TypeB, 2, 0, 5, 7), vec![5]);
        assert_eq!(pdsch(TypeB, 2, 2, 2, 8), vec![2, 5, 8]);
        assert_eq!(pdsch(TypeB, 2, 1, 0, 11), vec![0, 8]);
        assert_eq!(pdsch(TypeB, 2, 3, 0, 12), vec![0, 3, 6, 9]);
        assert_eq!(pdsch(TypeB, 2, 2, 0, 13), vec![0, 5, 9]);
        assert!(pdsch_dmrs_symbols(TypeB, 2, 2, 0, 14).is_err());
        assert!(pdsch_dmrs_symbols_len2(TypeB, 2, 2, 0, 4).is_err());
    }

    #[test]
    fn pusch_rows() {
        let p = |m, add, s, l| pusch_dmrs_symbols(m, 2, add, s, l).unwrap();
        assert_eq!(p(TypeA, 2, 0, 14), vec![2, 7, 11]);
        assert_eq!(p(TypeA, 1, 0, 14), vec![2, 11]);
        assert_eq!(p(TypeA, 3, 0, 12), vec![2, 5, 8, 11]);
        assert_eq!(p(TypeA, 2, 0, 10), vec![2, 6, 9]);
        assert_eq!(p(TypeB, 2, 0, 14), vec![0, 5, 10]);
        assert_eq!(p(TypeB, 1, 2, 10), vec![2, 10]);
        assert_eq!(p(TypeB, 3, 0, 11), vec![0, 3, 6, 9]);
        assert_eq!(p(TypeB, 2, 4, 8), vec![4, 7, 10]);
        assert_eq!(p(TypeB, 2, 4, 1), vec![4]);
        assert!(pusch_dmrs_symbols(TypeA, 2, 2, 0, 3).is_err());
    }

    #[test]
    fn cdm_groups_and_antenna_ports() {
        let m1 = dmrs_type1_data_sc_mask(1);
        assert_eq!(m1.iter().filter(|&&d| d).count(), 6);
        assert!(!m1[0] && m1[1]);
        assert!(dmrs_type1_data_sc_mask(2).iter().all(|&d| !d));
        assert_eq!(dmrs_type1_re_per_rb_symbol(2), 12);
        assert_eq!(dmrs_type1_re_per_rb_symbol(1), 6);
        let v2 = dci_1_1_antenna_ports_type1_len1(2).unwrap();
        assert_eq!(
            (v2.nof_cdm_groups_without_data, v2.ports),
            (1, &[0u8, 1][..])
        );
        let v3 = dci_1_1_antenna_ports_type1_len1(3).unwrap();
        assert_eq!((v3.nof_cdm_groups_without_data, v3.ports), (2, &[0u8][..]));
        assert_eq!(dci_1_1_antenna_ports_type1_len1(11).unwrap().ports, &[0, 2]);
        assert!(dci_1_1_antenna_ports_type1_len1(12).is_none());
        assert_eq!(
            dci_0_1_antenna_ports_type1_len1_rank1(2)
                .unwrap()
                .nof_cdm_groups_without_data,
            2
        );
        assert!(dci_0_1_antenna_ports_type1_len1_rank1(6).is_none());
    }
}
