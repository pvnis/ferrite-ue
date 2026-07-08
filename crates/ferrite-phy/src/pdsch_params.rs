//! PDSCH transport-block-size and modulation/coding parameters
//! (3GPP TS 38.214 §5.1.3). MCS index table 1 (Table 5.1.3.1-1) and the
//! `N_info ≤ 3824` TBS table (Table 5.1.3.2-1).

/// MCS index table 1: `(Qm, R×1024)` for `I_MCS` in `0..=28`.
pub const MCS_TABLE_1: [(u8, u16); 29] = [
    (2, 120),
    (2, 157),
    (2, 193),
    (2, 251),
    (2, 308),
    (2, 379),
    (2, 449),
    (2, 526),
    (2, 602),
    (2, 679),
    (4, 340),
    (4, 378),
    (4, 434),
    (4, 490),
    (4, 553),
    (4, 616),
    (4, 658),
    (6, 438),
    (6, 466),
    (6, 517),
    (6, 567),
    (6, 616),
    (6, 666),
    (6, 719),
    (6, 772),
    (6, 822),
    (6, 873),
    (6, 910),
    (6, 948),
];

/// Quantized TBS values (Table 5.1.3.2-1) for `N_info ≤ 3824`, ascending.
pub const TBS_TABLE: [u32; 93] = [
    24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,208,224,240,256,272,288,304,320,336,352,368,384,408,432,456,480,504,528,552,576,608,640,672,704,736,768,808,848,888,928,984,1032,1064,1128,1160,1192,1224,1256,1288,1320,1352,1416,1480,1544,1608,1672,1736,1800,1864,1928,2024,2088,2152,2216,2280,2408,2472,2536,2600,2664,2728,2792,2856,2976,3104,3240,3368,3496,3624,3752,3824,
];

/// Modulation order and code rate for `I_MCS` from table 1.
pub fn mcs_params(i_mcs: u8) -> (u8, f64) {
    let (qm, r1024) = MCS_TABLE_1[i_mcs as usize];
    (qm, r1024 as f64 / 1024.0)
}

/// DM-RS overhead REs per PRB for the SIB1 PDSCH (TBS purposes). DCI format 1_0
/// assumes 2 DM-RS CDM groups without data, so the whole DM-RS symbol (12
/// subcarriers) counts as overhead on each of `n_dmrs_symbols` symbols.
pub fn ndmrs_per_prb(n_dmrs_symbols: usize) -> usize {
    12 * n_dmrs_symbols
}

/// Transport block size (§5.1.3.2) for a PDSCH allocation. `n_re_per_prb` is the
/// data REs per PRB (after DM-RS/overhead), `n_prb` the allocated PRBs, `qm` the
/// modulation order, `r` the target code rate, `layers` the number of layers.
pub fn transport_block_size(n_re_per_prb: usize, n_prb: usize, qm: u8, r: f64, layers: usize) -> usize {
    let n_re = n_re_per_prb.min(156) * n_prb;
    let n_info = n_re as f64 * r * qm as f64 * layers as f64;
    if n_info <= 3824.0 {
        let n = ((n_info.log2().floor() as i32) - 6).max(3);
        let step = 1u32 << n;
        let n_info_q = (((n_info as u32) / step) * step).max(24);
        // smallest TBS >= n_info_q
        *TBS_TABLE.iter().find(|&&t| t >= n_info_q).unwrap_or(TBS_TABLE.last().unwrap()) as usize
    } else {
        // Large-block branch (not needed for SIB1); quantize to byte multiple.
        let n = (((n_info - 24.0).log2()).floor() as i32 - 5).max(0);
        let step = 1u32 << n;
        let n_info_q = ((((n_info / step as f64).round() as u32) * step).max(3840)) as f64;
        let c = if r <= 0.25 { (n_info_q + 24.0) / 3816.0 } else if n_info_q > 8424.0 { (n_info_q + 24.0) / 8424.0 } else { 1.0 };
        let c = c.ceil();
        (8.0 * c * ((n_info_q + 24.0) / (8.0 * c)).ceil() - 24.0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcs5_is_qpsk() {
        let (qm, r) = mcs_params(5);
        assert_eq!(qm, 2);
        assert!((r - 379.0 / 1024.0).abs() < 1e-9);
    }

    #[test]
    fn tbs_table_bounds() {
        assert_eq!(TBS_TABLE[0], 24);
        assert_eq!(TBS_TABLE[92], 3824);
        assert!(TBS_TABLE.windows(2).all(|w| w[0] < w[1]));
    }

    /// A representative SIB1 allocation: 10 PRBs, 12 symbols, 3 DM-RS symbols,
    /// QPSK MCS 5. TBS must land on a table value.
    #[test]
    fn sib1_like_tbs_is_tabulated() {
        let n_re_prb = 12 * 12 - ndmrs_per_prb(3); // 12 symbols, 3 DM-RS
        let (qm, r) = mcs_params(5);
        let tbs = transport_block_size(n_re_prb, 10, qm, r, 1);
        assert!(TBS_TABLE.contains(&(tbs as u32)), "TBS {tbs} not in table");
        assert!(tbs >= 24 && tbs <= 3824);
    }
}
