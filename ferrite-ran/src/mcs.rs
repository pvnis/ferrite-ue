//! MCS index tables (3GPP TS 38.214 §5.1.3.1 for PDSCH, §6.1.4.1 for PUSCH).
//!
//! Each entry is `(Q_m, R × 1024)`. The last rows of every table (29–31 for the
//! 64QAM tables, 28–31 for 256QAM) carry no code rate: they signal a
//! retransmission that keeps the modulation order of the initial transmission
//! and are reported as `None` here. The target code rate is stored ×1024 so the
//! 256QAM half-steps (682.5, 916.5) become ×2048 internally; use
//! [`mcs_code_rate`] for the float.

/// Which MCS table the RRC configuration selects (`mcs-Table` in PDSCH-Config /
/// PUSCH-Config; absent → [`McsTable::Qam64`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McsTable {
    /// Table 5.1.3.1-1 (MCS index table 1, up to 64QAM).
    Qam64,
    /// Table 5.1.3.1-2 (MCS index table 2, up to 256QAM).
    Qam256,
    /// Table 5.1.3.1-3 (MCS index table 3, low spectral efficiency).
    Qam64LowSe,
    /// Table 6.1.4.1-1: PUSCH with transform precoding **enabled** and
    /// `mcs-Table` absent/64QAM; `q = 1` (π/2-BPSK) rows have `Q_m = 1`.
    Qam64TransformPrecoding,
}

/// Table 5.1.3.1-1: `(Q_m, R×2048)` for `I_MCS` 0..=28.
const TABLE_1: [(u8, u16); 29] = [
    (2, 240),
    (2, 314),
    (2, 386),
    (2, 502),
    (2, 616),
    (2, 758),
    (2, 898),
    (2, 1052),
    (2, 1204),
    (2, 1358),
    (4, 680),
    (4, 756),
    (4, 868),
    (4, 980),
    (4, 1106),
    (4, 1232),
    (4, 1316),
    (6, 876),
    (6, 932),
    (6, 1034),
    (6, 1134),
    (6, 1232),
    (6, 1332),
    (6, 1438),
    (6, 1544),
    (6, 1644),
    (6, 1746),
    (6, 1820),
    (6, 1896),
];

/// Table 5.1.3.1-2: `(Q_m, R×2048)` for `I_MCS` 0..=27.
const TABLE_2: [(u8, u16); 28] = [
    (2, 240),
    (2, 386),
    (2, 616),
    (2, 898),
    (2, 1204),
    (4, 756),
    (4, 868),
    (4, 980),
    (4, 1106),
    (4, 1232),
    (4, 1316),
    (6, 932),
    (6, 1034),
    (6, 1134),
    (6, 1232),
    (6, 1332),
    (6, 1438),
    (6, 1544),
    (6, 1644),
    (6, 1746),
    (8, 1365),
    (8, 1422),
    (8, 1508),
    (8, 1594),
    (8, 1682),
    (8, 1770),
    (8, 1833),
    (8, 1896),
];

/// Table 5.1.3.1-3: `(Q_m, R×2048)` for `I_MCS` 0..=28.
const TABLE_3: [(u8, u16); 29] = [
    (2, 60),
    (2, 80),
    (2, 100),
    (2, 128),
    (2, 156),
    (2, 198),
    (2, 240),
    (2, 314),
    (2, 386),
    (2, 502),
    (2, 616),
    (2, 758),
    (2, 898),
    (2, 1052),
    (2, 1204),
    (4, 680),
    (4, 756),
    (4, 868),
    (4, 980),
    (4, 1106),
    (4, 1232),
    (6, 876),
    (6, 932),
    (6, 1034),
    (6, 1134),
    (6, 1232),
    (6, 1332),
    (6, 1438),
    (6, 1544),
];

/// Table 6.1.4.1-1 (transform precoding, `q = 1`): `(Q_m, R×2048)` for `I_MCS` 0..=27.
const TABLE_TP_1: [(u8, u16); 28] = [
    (1, 480),
    (1, 628),
    (2, 386),
    (2, 502),
    (2, 616),
    (2, 758),
    (2, 898),
    (2, 1052),
    (2, 1204),
    (2, 1358),
    (4, 680),
    (4, 756),
    (4, 868),
    (4, 980),
    (4, 1106),
    (4, 1232),
    (4, 1316),
    (6, 932),
    (6, 1034),
    (6, 1134),
    (6, 1232),
    (6, 1332),
    (6, 1438),
    (6, 1544),
    (6, 1644),
    (6, 1746),
    (6, 1820),
    (6, 1896),
];

/// Modulation order and target code rate ×1024 for `i_mcs` from `table`.
/// Half-steps of the 256QAM table are rounded **down** (682.5 → 682); use
/// [`mcs_params_x2048`] or [`mcs_code_rate`] for the exact value. `None` for
/// the reserved (retransmission-only) rows and out-of-range indices.
pub fn mcs_params(table: McsTable, i_mcs: u8) -> Option<(u8, u16)> {
    mcs_params_x2048(table, i_mcs).map(|(qm, r2048)| (qm, r2048 / 2))
}

/// Modulation order and target code rate ×2048 (exact for every table).
pub fn mcs_params_x2048(table: McsTable, i_mcs: u8) -> Option<(u8, u16)> {
    let t: &[(u8, u16)] = match table {
        McsTable::Qam64 => &TABLE_1,
        McsTable::Qam256 => &TABLE_2,
        McsTable::Qam64LowSe => &TABLE_3,
        McsTable::Qam64TransformPrecoding => &TABLE_TP_1,
    };
    t.get(usize::from(i_mcs)).copied()
}

/// Modulation order `Q_m` of the row, including the reserved rows (which only
/// carry the modulation): `None` for `i_mcs > 31`.
pub fn mcs_modulation_order(table: McsTable, i_mcs: u8) -> Option<u8> {
    if let Some((qm, _)) = mcs_params_x2048(table, i_mcs) {
        return Some(qm);
    }
    match (table, i_mcs) {
        (McsTable::Qam64 | McsTable::Qam64LowSe, 29) => Some(2),
        (McsTable::Qam64 | McsTable::Qam64LowSe, 30) => Some(4),
        (McsTable::Qam64 | McsTable::Qam64LowSe, 31) => Some(6),
        (McsTable::Qam256, 28) => Some(2),
        (McsTable::Qam256, 29) => Some(4),
        (McsTable::Qam256, 30) => Some(6),
        (McsTable::Qam256, 31) => Some(8),
        (McsTable::Qam64TransformPrecoding, 28) => Some(1),
        (McsTable::Qam64TransformPrecoding, 29) => Some(2),
        (McsTable::Qam64TransformPrecoding, 30) => Some(4),
        (McsTable::Qam64TransformPrecoding, 31) => Some(6),
        _ => None,
    }
}

/// Target code rate `R` as a float.
pub fn mcs_code_rate(table: McsTable, i_mcs: u8) -> Option<f64> {
    mcs_params_x2048(table, i_mcs).map(|(_, r)| f64::from(r) / 2048.0)
}

/// Whether the row is a reserved "same modulation, retransmission" entry.
pub fn mcs_is_reserved(table: McsTable, i_mcs: u8) -> bool {
    i_mcs <= 31 && mcs_params_x2048(table, i_mcs).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table1_spot_checks() {
        assert_eq!(mcs_params(McsTable::Qam64, 0), Some((2, 120)));
        assert_eq!(mcs_params(McsTable::Qam64, 7), Some((2, 526)));
        assert_eq!(mcs_params(McsTable::Qam64, 10), Some((4, 340)));
        assert_eq!(mcs_params(McsTable::Qam64, 17), Some((6, 438)));
        assert_eq!(mcs_params(McsTable::Qam64, 28), Some((6, 948)));
        assert_eq!(mcs_params(McsTable::Qam64, 29), None);
        assert!(mcs_is_reserved(McsTable::Qam64, 31));
        assert_eq!(mcs_modulation_order(McsTable::Qam64, 30), Some(4));
        assert_eq!(mcs_params(McsTable::Qam64, 32), None);
    }

    #[test]
    fn table2_spot_checks() {
        assert_eq!(mcs_params(McsTable::Qam256, 5), Some((4, 378)));
        assert_eq!(mcs_params(McsTable::Qam256, 11), Some((6, 466)));
        assert_eq!(mcs_params_x2048(McsTable::Qam256, 20), Some((8, 1365)));
        assert!((mcs_code_rate(McsTable::Qam256, 20).unwrap() - 682.5 / 1024.0).abs() < 1e-12);
        assert_eq!(mcs_params_x2048(McsTable::Qam256, 26), Some((8, 1833)));
        assert_eq!(mcs_params(McsTable::Qam256, 27), Some((8, 948)));
        assert_eq!(mcs_params(McsTable::Qam256, 28), None);
        assert_eq!(mcs_modulation_order(McsTable::Qam256, 31), Some(8));
    }

    #[test]
    fn table3_and_tp_spot_checks() {
        assert_eq!(mcs_params(McsTable::Qam64LowSe, 0), Some((2, 30)));
        assert_eq!(mcs_params(McsTable::Qam64LowSe, 14), Some((2, 602)));
        assert_eq!(mcs_params(McsTable::Qam64LowSe, 15), Some((4, 340)));
        assert_eq!(mcs_params(McsTable::Qam64LowSe, 28), Some((6, 772)));
        assert_eq!(mcs_params(McsTable::Qam64LowSe, 29), None);
        assert_eq!(
            mcs_params(McsTable::Qam64TransformPrecoding, 0),
            Some((1, 240))
        );
        assert_eq!(
            mcs_params(McsTable::Qam64TransformPrecoding, 2),
            Some((2, 193))
        );
        assert_eq!(
            mcs_params(McsTable::Qam64TransformPrecoding, 17),
            Some((6, 466))
        );
        assert_eq!(
            mcs_params(McsTable::Qam64TransformPrecoding, 27),
            Some((6, 948))
        );
        assert_eq!(mcs_params(McsTable::Qam64TransformPrecoding, 28), None);
    }

    /// Every table is monotone in spectral efficiency within each modulation.
    #[test]
    fn code_rates_monotone_per_modulation() {
        for t in [
            McsTable::Qam64,
            McsTable::Qam256,
            McsTable::Qam64LowSe,
            McsTable::Qam64TransformPrecoding,
        ] {
            let mut prev: Option<(u8, u16)> = None;
            for i in 0..32 {
                if let Some(cur) = mcs_params_x2048(t, i) {
                    if let Some(p) = prev {
                        assert!(cur.0 >= p.0);
                        if cur.0 == p.0 {
                            assert!(cur.1 > p.1, "{t:?} row {i}");
                        }
                    }
                    prev = Some(cur);
                }
            }
        }
    }
}
