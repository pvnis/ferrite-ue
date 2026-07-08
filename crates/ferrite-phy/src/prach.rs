//! Physical random-access channel (PRACH) preamble generation — the
//! Zadoff-Chu root sequences and cyclic shifts of 3GPP TS 38.211 §6.3.3.1.
//!
//! The random-access preamble sequence is
//! ```text
//!   x_{u,v}(n) = x_u((n + C_v) mod L_RA),   x_u(i) = exp(-jπ·u·i·(i+1)/L_RA)
//! ```
//! with `u` the physical root sequence number (from the logical root index via
//! Tables 6.3.3.1-3/-4) and `C_v = v·N_CS` the cyclic shift (unrestricted set).
//! The 64 preambles of an occasion are enumerated by increasing cyclic shift
//! `v`, then increasing logical root index (§6.3.3.1).
//!
//! Frequency-domain mapping / OFDM modulation (§6.3.3.2) is done by the caller.

use crate::prach_tables::{ROOT_L139, ROOT_L839};
use num_complex::Complex32;
use std::f32::consts::PI;

/// PRACH preamble sequence length `L_RA` (§6.3.3.1): 839 for the long formats
/// (0/1/2/3), 139 for the short formats (A1-A3, B1-B4, C0, C2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrachSeqLen {
    Long,  // L_RA = 839
    Short, // L_RA = 139
}

impl PrachSeqLen {
    pub fn l_ra(self) -> usize {
        match self {
            PrachSeqLen::Long => 839,
            PrachSeqLen::Short => 139,
        }
    }
}

/// PRACH subcarrier spacing, selecting the `N_CS` table (§6.3.3.1
/// Tables 6.3.3.1-5/-6/-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrachScs {
    /// 1.25 kHz — long formats 0/1/2 (Table 6.3.3.1-5).
    Khz1_25,
    /// 5 kHz — long format 3 (Table 6.3.3.1-6).
    Khz5,
    /// 15/30/60/120 kHz — short formats (Table 6.3.3.1-7).
    Short,
}

/// `N_CS` for **unrestricted** sets (first column of Tables 6.3.3.1-5/-6/-7),
/// indexed by `zeroCorrelationZoneConfig` (0..15). `None` for reserved entries.
pub fn prach_ncs_unrestricted(scs: PrachScs, zero_correlation_zone: usize) -> Option<usize> {
    // Table 6.3.3.1-5/-6/-7, first (unrestricted) columns.
    const NCS_1_25: [u16; 16] = [0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419];
    const NCS_5: [u16; 16] = [0, 13, 26, 33, 38, 41, 49, 55, 64, 76, 93, 119, 139, 209, 279, 419];
    const NCS_SHORT: [u16; 16] = [0, 2, 4, 6, 8, 10, 12, 13, 15, 17, 19, 23, 27, 34, 46, 69];
    let table = match scs {
        PrachScs::Khz1_25 => &NCS_1_25,
        PrachScs::Khz5 => &NCS_5,
        PrachScs::Short => &NCS_SHORT,
    };
    table.get(zero_correlation_zone).map(|&n| n as usize)
}

/// Physical root sequence number `u` for a logical root sequence index
/// (Tables 6.3.3.1-3/-4). The logical order is cyclic (index 0 follows L_RA-2).
pub fn prach_root(logical_root_index: usize, seq_len: PrachSeqLen) -> u16 {
    match seq_len {
        PrachSeqLen::Long => ROOT_L839[logical_root_index % ROOT_L839.len()],
        PrachSeqLen::Short => ROOT_L139[logical_root_index % ROOT_L139.len()],
    }
}

/// The `u`-th root Zadoff-Chu sequence `x_u(i) = exp(-jπ·u·i·(i+1)/L_RA)`,
/// `i = 0..L_RA` (§6.3.3.1). `L_RA` (839/139) is prime, so this has unit
/// amplitude and ideal periodic autocorrelation.
pub fn zadoff_chu(u: u16, l_ra: usize) -> Vec<Complex32> {
    let two_l = 2 * l_ra as u64;
    (0..l_ra)
        .map(|i| {
            // phase = -π·(u·i·(i+1) mod 2L_RA)/L_RA, reduced to preserve precision.
            let x = (u as u64 * i as u64 * (i as u64 + 1)) % two_l;
            Complex32::from_polar(1.0, -PI * x as f32 / l_ra as f32)
        })
        .collect()
}

/// Number of preambles obtainable per root for a given `N_CS` (unrestricted):
/// `⌊L_RA/N_CS⌋`, or 1 when `N_CS = 0` (one preamble per root, no shift).
pub fn prach_preambles_per_root(n_cs: usize, seq_len: PrachSeqLen) -> usize {
    if n_cs == 0 {
        1
    } else {
        seq_len.l_ra() / n_cs
    }
}

/// Time-domain root-sequence-domain preamble `x_{u,v}(n)` for `preamble_index`
/// (0..63) given the cell's `root_sequence_index` (`prach-RootSequenceIndex`)
/// and `N_CS` (unrestricted set, §6.3.3.1). Length `L_RA`.
///
/// Preambles are enumerated by increasing cyclic shift `v` then increasing
/// logical root index; consecutive indices consume shifts of one root before
/// advancing to the next root.
pub fn prach_preamble_seq(
    root_sequence_index: usize,
    preamble_index: usize,
    n_cs: usize,
    seq_len: PrachSeqLen,
) -> Vec<Complex32> {
    let l_ra = seq_len.l_ra();
    let (logical_root, c_v) = if n_cs == 0 {
        (root_sequence_index + preamble_index, 0)
    } else {
        let per_root = l_ra / n_cs;
        (
            root_sequence_index + preamble_index / per_root,
            (preamble_index % per_root) * n_cs,
        )
    };
    let u = prach_root(logical_root, seq_len);
    let x_u = zadoff_chu(u, l_ra);
    (0..l_ra).map(|n| x_u[(n + c_v) % l_ra]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_tables_sized_and_bounded() {
        assert_eq!(ROOT_L839.len(), 838);
        assert_eq!(ROOT_L139.len(), 138);
        assert_eq!(prach_root(0, PrachSeqLen::Long), 129);
        assert_eq!(prach_root(1, PrachSeqLen::Long), 710);
        assert_eq!(prach_root(0, PrachSeqLen::Short), 1);
        assert!(ROOT_L839.iter().all(|&u| (1..=838).contains(&u)));
        assert!(ROOT_L139.iter().all(|&u| (1..=138).contains(&u)));
        // logical order is cyclic.
        assert_eq!(prach_root(838, PrachSeqLen::Long), prach_root(0, PrachSeqLen::Long));
    }

    #[test]
    fn zc_constant_amplitude() {
        let x = zadoff_chu(prach_root(0, PrachSeqLen::Long), 839);
        assert_eq!(x.len(), 839);
        for s in &x {
            assert!((s.norm() - 1.0).abs() < 1e-4);
        }
    }

    /// Zadoff-Chu has ideal periodic autocorrelation: for a prime L_RA and
    /// root coprime to it, the cyclic autocorrelation is 0 for all non-zero lags.
    #[test]
    fn zc_ideal_periodic_autocorrelation() {
        let l = 839usize;
        let x = zadoff_chu(prach_root(3, PrachSeqLen::Long), l);
        for tau in 1..l {
            let mut acc = Complex32::new(0.0, 0.0);
            for n in 0..l {
                acc += x[n] * x[(n + tau) % l].conj();
            }
            assert!(acc.norm() < 1e-2, "lag {tau}: |R|={}", acc.norm());
        }
    }

    /// Two cyclic shifts of the same root are orthogonal at zero lag and their
    /// cross-correlation peaks at the shift separation — the property the gNB
    /// detector exploits to separate preambles.
    #[test]
    fn cyclic_shifts_separate() {
        let n_cs = prach_ncs_unrestricted(PrachScs::Khz1_25, 8).unwrap(); // 46
        let seq_len = PrachSeqLen::Long;
        let p0 = prach_preamble_seq(0, 0, n_cs, seq_len);
        let p1 = prach_preamble_seq(0, 1, n_cs, seq_len);
        // both derive from the same root (per_root = 839/46 = 18 > 1).
        assert_eq!(prach_preambles_per_root(n_cs, seq_len), 18);
        let zero_lag: Complex32 = p0.iter().zip(&p1).map(|(a, b)| a * b.conj()).sum();
        assert!(zero_lag.norm() < 1.0, "shifted preambles not orthogonal: {}", zero_lag.norm());
    }

    #[test]
    fn ncs_reserved_and_values() {
        assert_eq!(prach_ncs_unrestricted(PrachScs::Khz1_25, 0), Some(0));
        assert_eq!(prach_ncs_unrestricted(PrachScs::Khz1_25, 8), Some(46));
        assert_eq!(prach_ncs_unrestricted(PrachScs::Short, 15), Some(69));
    }
}
