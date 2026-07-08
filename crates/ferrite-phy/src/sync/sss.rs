//! Secondary Synchronization Signal — 3GPP TS 38.211 §7.4.2.2.2.
//!
//! The SSS is a length-127 sequence formed as the product of two cyclically
//! shifted m-sequences `x0` and `x1` (generator polynomials `x^7 + x^4 + 1` and
//! `x^7 + x + 1`). The shifts encode `N_ID^(1)` and `N_ID^(2)`.

/// Length of the SSS sequence (§7.4.2.2.2).
pub const SSS_LEN: usize = 127;

/// m-sequence `x0`: `x0(i+7) = (x0(i+4) + x0(i)) mod 2`, initial state
/// `[x0(6)..x0(0)] = [0 0 0 0 0 0 1]`.
fn m_seq_x0() -> [i32; SSS_LEN] {
    let mut x = [0i32; SSS_LEN];
    x[0] = 1;
    for i in 0..(SSS_LEN - 7) {
        x[i + 7] = (x[i + 4] + x[i]) % 2;
    }
    x
}

/// m-sequence `x1`: `x1(i+7) = (x1(i+1) + x1(i)) mod 2`, initial state
/// `[x1(6)..x1(0)] = [0 0 0 0 0 0 1]`.
fn m_seq_x1() -> [i32; SSS_LEN] {
    let mut x = [0i32; SSS_LEN];
    x[0] = 1;
    for i in 0..(SSS_LEN - 7) {
        x[i + 7] = (x[i + 1] + x[i]) % 2;
    }
    x
}

/// The SSS sequence `d_SSS(n) ∈ {+1, -1}` for the given cell-ID components.
///
/// ```text
/// m0 = 15 * floor(N_ID^(1) / 112) + 5 * N_ID^(2)
/// m1 = N_ID^(1) mod 112
/// d_SSS(n) = [1 - 2 x0((n+m0) mod 127)] * [1 - 2 x1((n+m1) mod 127)]
/// ```
///
/// # Panics
/// Panics if `n_id_1 >= 336` or `n_id_2 >= 3`.
pub fn sss(n_id_1: u16, n_id_2: u8) -> [i32; SSS_LEN] {
    assert!(n_id_1 < 336, "N_ID^(1) must be in 0..=335, got {n_id_1}");
    assert!(n_id_2 < 3, "N_ID^(2) must be in 0..=2, got {n_id_2}");

    let x0 = m_seq_x0();
    let x1 = m_seq_x1();

    let m0 = 15 * (n_id_1 as usize / 112) + 5 * n_id_2 as usize;
    let m1 = n_id_1 as usize % 112;

    let mut d = [0i32; SSS_LEN];
    for (n, dn) in d.iter_mut().enumerate() {
        let a = 1 - 2 * x0[(n + m0) % SSS_LEN];
        let b = 1 - 2 * x1[(n + m1) % SSS_LEN];
        *dn = a * b;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn periodic_autocorr(seq: &[i32], tau: usize) -> i32 {
        let n = seq.len();
        (0..n).map(|i| seq[i] * seq[(i + tau) % n]).sum()
    }

    /// Map an m-sequence `{0,1}` to `±1` and check ideal autocorrelation. This
    /// validates both generator polynomials and both initial states.
    #[test]
    fn constituent_m_sequences_are_maximal_length() {
        for x in [m_seq_x0(), m_seq_x1()] {
            let bipolar: Vec<i32> = x.iter().map(|&b| 1 - 2 * b).collect();
            assert_eq!(periodic_autocorr(&bipolar, 0), 127);
            for tau in 1..127 {
                assert_eq!(periodic_autocorr(&bipolar, tau), -1, "lag {tau}");
            }
        }
    }

    #[test]
    fn is_bipolar_and_length_127() {
        for &(n1, n2) in &[(0u16, 0u8), (335, 2), (111, 1), (112, 0), (200, 2)] {
            let d = sss(n1, n2);
            assert_eq!(d.len(), 127);
            assert!(d.iter().all(|&v| v == 1 || v == -1));
        }
    }

    /// Distinct cell IDs must yield distinct SSS sequences (identifiability).
    #[test]
    fn distinct_ids_distinct_sequences() {
        let a = sss(0, 0);
        let b = sss(0, 1);
        let c = sss(1, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
