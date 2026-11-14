//! Transport block size determination (3GPP TS 38.214 §5.1.3.2, shared with
//! PUSCH §6.1.4.2) and the PDSCH-side helpers around it: the quantised TBS
//! table (Table 5.1.3.2-1), the RE-per-PRB count and the DM-RS overhead term.
//!
//! The MCS tables live in [`crate::mcs`].

/// Quantized TBS values (Table 5.1.3.2-1) for `N_info ≤ 3824`, ascending.
#[rustfmt::skip]
pub const TBS_TABLE: [u32; 93] = [
    24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,208,224,240,256,272,288,304,320,336,352,368,384,408,432,456,480,504,528,552,576,608,640,672,704,736,768,808,848,888,928,984,1032,1064,1128,1160,1192,1224,1256,1288,1320,1352,1416,1480,1544,1608,1672,1736,1800,1864,1928,2024,2088,2152,2216,2280,2408,2472,2536,2600,2664,2728,2792,2856,2976,3104,3240,3368,3496,3624,3752,3824,
];

/// DM-RS overhead REs per PRB when **all 12 subcarriers** of each of
/// `n_dmrs_symbols` DM-RS symbols are reserved: DCI format 1_0 scheduling
/// assumes 2 CDM groups without data (38.214 §5.1.6.2), i.e. the whole DM-RS
/// symbol. Equivalent to [`dmrs_re_per_prb`]`(n_dmrs_symbols, 2)`.
pub fn ndmrs_per_prb(n_dmrs_symbols: usize) -> usize {
    12 * n_dmrs_symbols
}

/// `N_DMRS^PRB`: DM-RS REs per PRB over the allocation for DM-RS configuration
/// type 1 — 6 REs per DM-RS symbol per CDM group without data
/// (38.211 §7.4.1.1.2: type 1 has two CDM groups of 6 subcarriers each).
pub fn dmrs_re_per_prb(n_dmrs_symbols: usize, nof_cdm_groups_without_data: u8) -> usize {
    6 * usize::from(nof_cdm_groups_without_data) * n_dmrs_symbols
}

/// `N'_RE = N_sc^RB · N_symb^sh − N_DMRS^PRB − N_oh^PRB` (38.214 §5.1.3.2 step
/// 1). `x_overhead` is `xOverhead` from PDSCH-ServingCellConfig (0 when absent;
/// 6, 12 or 18).
pub fn n_re_per_prb(n_symb: usize, n_dmrs_re_per_prb: usize, x_overhead: usize) -> usize {
    debug_assert!(
        matches!(x_overhead, 0 | 6 | 12 | 18),
        "xOverhead must be 0/6/12/18"
    );
    (12 * n_symb).saturating_sub(n_dmrs_re_per_prb + x_overhead)
}

/// Transport block size in bits, TS 38.214 §5.1.3.2 (PDSCH) / §6.1.4.2 (PUSCH).
///
/// * `n_re_per_prb_total` is `N'_RE` from [`n_re_per_prb`]; the caller has
///   already subtracted DM-RS and overhead.
/// * `r_x2048` is the target code rate ×2048 (exact for the 256QAM half-steps;
///   see [`tbs`] for the ×1024 convenience).
///
/// Step 1: `N_RE = min(156, N'_RE) · n_PRB`. Step 2: `N_info = N_RE·R·Q_m·ν`.
/// Step 3 (`N_info ≤ 3824`): `n = max(3, ⌊log2 N_info⌋ − 6)`,
/// `N'_info = max(24, 2^n·⌊N_info/2^n⌋)`, TBS = smallest table entry ≥ `N'_info`.
/// Step 4 (`N_info > 3824`): `n = ⌊log2(N_info − 24)⌋ − 5`,
/// `N'_info = max(3840, 2^n·round((N_info − 24)/2^n))`; `C = ⌈(N'_info+24)/3816⌉`
/// if `R ≤ 1/4`, else `⌈(N'_info+24)/8424⌉` if `N'_info > 8424`, else 1;
/// `TBS = 8·C·⌈(N'_info+24)/(8·C)⌉ − 24`.
pub fn tbs_x2048(
    n_re_per_prb_total: usize,
    n_prb: usize,
    qm: u8,
    r_x2048: u32,
    n_layers: usize,
) -> usize {
    let n_re = n_re_per_prb_total.min(156) * n_prb;
    let r = f64::from(r_x2048) / 2048.0;
    let n_info = n_re as f64 * r * f64::from(qm) * n_layers as f64;
    if n_info <= 3824.0 {
        let n = ((n_info.log2().floor() as i64) - 6).max(3) as u32;
        let step = 1u64 << n;
        let n_info_q = (step * (n_info as u64 / step)).max(24);
        TBS_TABLE
            .iter()
            .copied()
            .find(|&t| u64::from(t) >= n_info_q)
            .unwrap_or(3824) as usize
    } else {
        let n = ((n_info - 24.0).log2().floor() as i64 - 5).max(0) as u32;
        let step = (1u64 << n) as f64;
        let n_info_q = ((step * ((n_info - 24.0) / step).round()) as u64).max(3840);
        let c = if r_x2048 <= 512 {
            (n_info_q + 24).div_ceil(3816)
        } else if n_info_q > 8424 {
            (n_info_q + 24).div_ceil(8424)
        } else {
            1
        };
        (8 * c * (n_info_q + 24).div_ceil(8 * c) - 24) as usize
    }
}

/// [`tbs_x2048`] with the code rate given ×1024 (the MCS table convention).
pub fn tbs(
    n_re_per_prb_total: usize,
    n_prb: usize,
    qm: u8,
    r_x1024: u16,
    n_layers: usize,
) -> usize {
    tbs_x2048(
        n_re_per_prb_total,
        n_prb,
        qm,
        2 * u32::from(r_x1024),
        n_layers,
    )
}

/// Transport block size for a float code rate `r` (legacy signature; rounds `r`
/// to the nearest ×2048 step, which is exact for every MCS table entry).
pub fn transport_block_size(
    n_re_per_prb: usize,
    n_prb: usize,
    qm: u8,
    r: f64,
    layers: usize,
) -> usize {
    tbs_x2048(n_re_per_prb, n_prb, qm, (r * 2048.0).round() as u32, layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcs::{self, McsTable};

    #[test]
    fn mcs5_is_qpsk() {
        let (qm, r1024) = mcs::mcs_params(McsTable::Qam64, 5).unwrap();
        let r = f64::from(r1024) / 1024.0;
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
        let n_re_prb = n_re_per_prb(12, ndmrs_per_prb(3), 0);
        assert_eq!(n_re_prb, 108);
        let (qm, r1024) = mcs::mcs_params(McsTable::Qam64, 5).unwrap();
        let r = f64::from(r1024) / 1024.0;
        let t = transport_block_size(n_re_prb, 10, qm, r, 1);
        assert!(TBS_TABLE.contains(&(t as u32)), "TBS {t} not in table");
        assert!((24..=3824).contains(&t));
        // N_info = 1080 · 0.370 · 2 = 799.4 → n = 3, N'_info = 792 → 808.
        assert_eq!(t, 808);
    }

    /// The live cell's 24-RB BWP, 12 symbols type A, DM-RS {2,7,11} with 2 CDM
    /// groups (36 DM-RS RE/PRB), QPSK MCS 7 (R = 526/1024):
    /// N_RE = 108·24 = 2592, N_info = 2592·2·0.5137 = 2663 → n = 5,
    /// N'_info = 2656 → 2664.
    #[test]
    fn live_cell_24rb_qpsk_mcs7() {
        let n_re = n_re_per_prb(12, dmrs_re_per_prb(3, 2), 0);
        assert_eq!(n_re, 108);
        assert_eq!(tbs(n_re, 24, 2, 526, 1), 2664);
    }

    /// Vectors from the OCUDU scheduler's `mcs_tbs_calculator_test` (default
    /// cell: 12-symbol type A PDSCH, DM-RS {2,7,11}, 2 CDM groups → N'_RE = 108,
    /// MCS table 1, one layer), in bytes.
    #[test]
    fn ocudu_dl_vectors() {
        let n_re = 108;
        let cases: &[(u8, usize, usize)] = &[
            // (I_MCS, n_PRB, TBS bytes)
            (28, 5, 372),
            (28, 20, 1505),
            (26, 106, 7298),
            (23, 3, 177),
            (19, 275, 11272),
            (13, 32, 816),
            (11, 41, 816),
            (8, 179, 2817),
            (3, 84, 561),
            (0, 55, 177),
            (0, 5, 15),
        ];
        for &(i_mcs, n_prb, bytes) in cases {
            let (qm, r) = mcs::mcs_params(McsTable::Qam64, i_mcs).unwrap();
            let t = tbs(n_re, n_prb, qm, r, 1);
            assert_eq!(
                t % 8,
                0,
                "MCS {i_mcs} × {n_prb} PRB: {t} bits not byte aligned"
            );
            assert_eq!(t / 8, bytes, "MCS {i_mcs} × {n_prb} PRB");
        }
    }

    /// Large-block branch details: R ≤ 1/4 uses the 3816-bit segment, the
    /// 8424 threshold decides C otherwise, and the result is always byte aligned.
    #[test]
    fn large_block_branch() {
        // MCS 0 (R = 120/1024 ≤ 1/4), 273 PRB: N_info = 29484·2·0.117 = 6910 →
        // n = 7, N'_info = 6912, C = ⌈6936/3816⌉ = 2, TBS = 16·⌈6936/16⌉ − 24 = 6920.
        assert_eq!(tbs(108, 273, 2, 120, 1), 6920);
        // Between 3824 and 8424 with R > 1/4: single segment, TBS = 8·⌈(N'+24)/8⌉ − 24.
        let t = tbs(108, 20, 4, 490, 1); // N_info = 2160·4·0.478 = 4134
        assert!(t > 3824 && t < 8424 && t.is_multiple_of(8));
        // n = 7 → N'_info = 128·round(4110.4/128) = 4096, C = 1 → 8·⌈4120/8⌉ − 24 = 4096.
        assert_eq!(t, 4096);
    }
}
