//! Pseudo-random sequence generation — 3GPP TS 38.211 §5.2.1.
//!
//! NR uses a length-31 Gold sequence `c(n) = (x1(n+Nc) + x2(n+Nc)) mod 2` with
//! `Nc = 1600`. `x1` has a fixed initial state; `x2` is seeded from `c_init`.
//! It underlies DMRS generation and every physical-channel scrambler.

/// Offset `Nc` applied before reading the Gold sequence (§5.2.1).
pub const NC: usize = 1600;

/// Generate the first `len` bits of the length-31 Gold sequence for `c_init`.
///
/// ```text
/// x1(n+31) = (x1(n+3) + x1(n)) mod 2,                       x1 = [1,0,0,…]
/// x2(n+31) = (x2(n+3)+x2(n+2)+x2(n+1)+x2(n)) mod 2,          x2 = bits of c_init
/// c(n)     = (x1(n+Nc) + x2(n+Nc)) mod 2
/// ```
pub fn gold_sequence(c_init: u32, len: usize) -> Vec<u8> {
    let total = len + NC;
    let mut x1 = vec![0u8; total + 31];
    let mut x2 = vec![0u8; total + 31];

    x1[0] = 1;
    for (i, x) in x2.iter_mut().take(31).enumerate() {
        *x = ((c_init >> i) & 1) as u8;
    }
    for n in 0..total {
        x1[n + 31] = (x1[n + 3] + x1[n]) & 1;
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) & 1;
    }

    (0..len).map(|n| (x1[n + NC] + x2[n + NC]) & 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_binary_and_correct_length() {
        let c = gold_sequence(0x1234, 500);
        assert_eq!(c.len(), 500);
        assert!(c.iter().all(|&b| b <= 1));
    }

    #[test]
    fn deterministic_and_seed_dependent() {
        assert_eq!(gold_sequence(42, 200), gold_sequence(42, 200));
        assert_ne!(gold_sequence(1, 200), gold_sequence(2, 200));
    }

    /// A length-31 Gold sequence is balanced: over a long span the count of 0s
    /// and 1s is close to equal. A broken recurrence skews this badly.
    #[test]
    fn approximately_balanced() {
        let c = gold_sequence(0xDEAD, 20_000);
        let ones = c.iter().filter(|&&b| b == 1).count();
        let frac = ones as f64 / c.len() as f64;
        assert!((frac - 0.5).abs() < 0.03, "ones fraction {frac}");
    }

    /// Two different seeds produce nearly uncorrelated sequences (low agreement
    /// away from 0.5 would indicate a generator bug).
    #[test]
    fn cross_seed_low_correlation() {
        let a = gold_sequence(0x1111_2222, 10_000);
        let b = gold_sequence(0x3333_4444, 10_000);
        let agree = a.iter().zip(&b).filter(|(x, y)| x == y).count();
        let frac = agree as f64 / a.len() as f64;
        assert!((frac - 0.5).abs() < 0.03, "agreement {frac}");
    }
}
