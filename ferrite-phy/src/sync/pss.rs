//! Primary Synchronization Signal — 3GPP TS 38.211 §7.4.2.2.1.
//!
//! The PSS is a length-127 BPSK sequence derived from a maximal-length sequence
//! (m-sequence) with generator polynomial `x^7 + x^4 + 1`. Each of the three
//! `N_ID^(2)` values selects a distinct cyclic shift (by `43 * N_ID^(2)`).

/// Length of the PSS sequence (§7.4.2.2.1).
pub const PSS_LEN: usize = 127;

/// The base m-sequence `x(n)`, `n = 0..127`, valued in `{0, 1}`.
///
/// Recurrence `x(i+7) = (x(i+4) + x(i)) mod 2`, with initial state
/// `[x(6) x(5) x(4) x(3) x(2) x(1) x(0)] = [1 1 1 0 1 1 0]`.
fn base_m_sequence() -> [i32; PSS_LEN] {
    let mut x = [0i32; PSS_LEN];
    // Initial state, indexed x(0)..x(6).
    x[..7].copy_from_slice(&[0, 1, 1, 0, 1, 1, 1]);
    for i in 0..(PSS_LEN - 7) {
        x[i + 7] = (x[i + 4] + x[i]) % 2;
    }
    x
}

/// The PSS sequence `d_PSS(n) ∈ {+1, -1}` for `N_ID^(2) ∈ {0, 1, 2}`.
///
/// `d_PSS(n) = 1 - 2 * x(m)`, where `m = (n + 43 * N_ID^(2)) mod 127`.
///
/// # Panics
/// Panics if `n_id_2 >= 3`.
pub fn pss(n_id_2: u8) -> [i32; PSS_LEN] {
    assert!(n_id_2 < 3, "N_ID^(2) must be in 0..=2, got {n_id_2}");
    let x = base_m_sequence();
    let shift = 43 * n_id_2 as usize;
    let mut d = [0i32; PSS_LEN];
    for (n, dn) in d.iter_mut().enumerate() {
        let m = (n + shift) % PSS_LEN;
        *dn = 1 - 2 * x[m];
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Periodic (cyclic) autocorrelation of a `±1` sequence at lag `tau`.
    fn periodic_autocorr(seq: &[i32], tau: usize) -> i32 {
        let n = seq.len();
        (0..n).map(|i| seq[i] * seq[(i + tau) % n]).sum()
    }

    #[test]
    fn is_bipolar_and_length_127() {
        for n_id_2 in 0..3 {
            let d = pss(n_id_2);
            assert_eq!(d.len(), 127);
            assert!(d.iter().all(|&v| v == 1 || v == -1));
        }
    }

    /// A maximal-length sequence has ideal periodic autocorrelation:
    /// `N` at lag 0 and `-1` at every other lag. A wrong recurrence or initial
    /// state breaks this, so it is a strong correctness anchor.
    #[test]
    fn ideal_periodic_autocorrelation() {
        let d = pss(0);
        assert_eq!(periodic_autocorr(&d, 0), 127);
        for tau in 1..127 {
            assert_eq!(
                periodic_autocorr(&d, tau),
                -1,
                "autocorr at lag {tau} should be -1"
            );
        }
    }

    /// PSS for `N_ID^(2)` is the base sequence cyclically shifted by `43*N_ID^(2)`.
    #[test]
    fn n_id_2_are_cyclic_shifts() {
        let base = pss(0);
        for n_id_2 in 1..3u8 {
            let d = pss(n_id_2);
            let shift = 43 * n_id_2 as usize;
            for n in 0..PSS_LEN {
                assert_eq!(d[n], base[(n + shift) % PSS_LEN]);
            }
        }
    }
}
