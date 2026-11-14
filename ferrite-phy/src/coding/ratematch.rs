//! Polar rate matching (3GPP TS 38.212 §5.4.1).
//!
//! The `N` coded bits pass through a 32-way sub-block interleaver, then bit
//! selection produces `E` output bits (§5.4.1.2):
//!
//! * `E ≥ N` — **repetition**: `e(k) = y(k mod N)`;
//! * `E < N`, `K/E ≤ 7/16` — **puncturing**: `e(k) = y(k + N − E)` (the first
//!   `N−E` interleaved bits are never sent; the receiver sets their LLRs to 0);
//! * `E < N` otherwise — **shortening**: `e(k) = y(k)` (the last `N−E` bits are
//!   forced to 0 by the frozen-set choice; the receiver knows them exactly).
//!
//! When `E < N` the information set must additionally avoid the pre-frozen
//! indices of §5.4.1.1 — see [`rm_pre_frozen`].

use super::tables::SUBBLOCK_INTERLEAVER_P;

/// LLR magnitude standing in for "known-zero bit" at shortened positions.
const SHORTENED_LLR: f32 = 1e6;

/// Sub-block interleaved index: output position `n` takes input bit `J(n)`
/// where `J(n) = P(⌊32n/N⌋)·(N/32) + (n mod N/32)` (§5.4.1.1).
fn j_index(n: usize, big_n: usize) -> usize {
    let chunk = big_n / 32;
    usize::from(SUBBLOCK_INTERLEAVER_P[n / chunk]) * chunk + (n % chunk)
}

/// True if the `(K, E)` combination puncture-rate-matches (`K/E ≤ 7/16`).
fn is_puncturing(k: usize, e: usize) -> bool {
    16 * k <= 7 * e
}

/// Sub-block interleave `d` (length `N`, a multiple of 32): `y(n) = d(J(n))`.
pub fn subblock_interleave(d: &[u8]) -> Vec<u8> {
    let n = d.len();
    assert!(n.is_multiple_of(32));
    (0..n).map(|i| d[j_index(i, n)]).collect()
}

/// Pre-frozen bit indices from §5.4.1.1 (`Q̄F,tmp`): positions the information
/// set must avoid when `E < N`. Empty for repetition.
pub fn rm_pre_frozen(big_n: usize, k: usize, e: usize) -> Vec<usize> {
    if e >= big_n {
        return Vec::new();
    }
    let mut frozen: Vec<usize> = Vec::new();
    if is_puncturing(k, e) {
        for n in 0..(big_n - e) {
            frozen.push(j_index(n, big_n));
        }
        let head = if 4 * e >= 3 * big_n {
            (3 * big_n).div_ceil(4).saturating_sub(e / 2)
        } else {
            (9 * big_n).div_ceil(16).saturating_sub(e / 4)
        };
        frozen.extend(0..head);
    } else {
        for n in e..big_n {
            frozen.push(j_index(n, big_n));
        }
    }
    frozen.sort_unstable();
    frozen.dedup();
    frozen
}

/// Rate-match the interleaved coded bits `y` (length `N`) to `e_len` bits.
/// `k` selects puncturing vs. shortening when `e_len < N`.
pub fn rate_match(y: &[u8], e_len: usize, k: usize) -> Vec<u8> {
    let n = y.len();
    if e_len >= n {
        (0..e_len).map(|i| y[i % n]).collect()
    } else if is_puncturing(k, e_len) {
        y[n - e_len..].to_vec()
    } else {
        y[..e_len].to_vec()
    }
}

/// Invert rate matching on soft bits, returning `N` coded-bit LLRs in `d`
/// (pre-sub-block-interleaver) order. Repeated LLRs combine by addition;
/// punctured positions get LLR 0; shortened positions get a huge positive LLR
/// (the bit is known to be 0).
pub fn de_rate_match(llr_e: &[f32], big_n: usize, k: usize) -> Vec<f32> {
    assert!(big_n.is_multiple_of(32));
    let e = llr_e.len();
    let mut y = vec![0f32; big_n];
    if e >= big_n {
        for (i, &l) in llr_e.iter().enumerate() {
            y[i % big_n] += l;
        }
    } else if is_puncturing(k, e) {
        y[big_n - e..].copy_from_slice(llr_e);
        // punctured head stays 0 (unknown)
    } else {
        y[..e].copy_from_slice(llr_e);
        for v in &mut y[e..] {
            *v = SHORTENED_LLR;
        }
    }
    let mut d = vec![0f32; big_n];
    for (n, &v) in y.iter().enumerate() {
        d[j_index(n, big_n)] = v;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleave_is_permutation() {
        let n = 512;
        let d: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let y = subblock_interleave(&d);
        let mut back = vec![0u8; n];
        for i in 0..n {
            back[j_index(i, n)] = y[i];
        }
        assert_eq!(back, d);
    }

    /// Repetition round trip at the BCH size (E=864 > N=512).
    #[test]
    fn repetition_roundtrip() {
        let (n, e, k) = (512usize, 864usize, 56usize);
        let d: Vec<u8> = (0..n).map(|i| ((i * 37 + 11) % 2) as u8).collect();
        let y = subblock_interleave(&d);
        let f = rate_match(&y, e, k);
        assert_eq!(f.len(), e);
        for kk in n..e {
            assert_eq!(f[kk], y[kk % n]);
        }
        let llr_e: Vec<f32> = f.iter().map(|&b| if b == 0 { 1.0 } else { -1.0 }).collect();
        let llr_d = de_rate_match(&llr_e, n, k);
        let mut pos_of = vec![0usize; n];
        for p in 0..n {
            pos_of[j_index(p, n)] = p;
        }
        for (i, &l) in llr_d.iter().enumerate() {
            assert_eq!((l < 0.0) as u8, d[i], "bit {i}");
            let expected_mag = if pos_of[i] < e - n { 2.0 } else { 1.0 };
            assert!((l.abs() - expected_mag).abs() < 1e-6, "bit {i} mag {l}");
        }
    }

    /// Puncturing (DCI AL4-like: K=61, E=432, N=512): transmitted bits round
    /// trip; punctured positions come back with LLR exactly 0.
    #[test]
    fn puncturing_roundtrip() {
        let (n, e, k) = (512usize, 432usize, 61usize);
        assert!(is_puncturing(k, e));
        let d: Vec<u8> = (0..n).map(|i| ((i * 13 + 5) % 2) as u8).collect();
        let y = subblock_interleave(&d);
        let f = rate_match(&y, e, k);
        assert_eq!(f, y[n - e..].to_vec());

        let llr_e: Vec<f32> = f.iter().map(|&b| if b == 0 { 1.0 } else { -1.0 }).collect();
        let llr_d = de_rate_match(&llr_e, n, k);
        let mut zero_count = 0;
        for i in 0..n {
            // invert: d-position i sits at interleaved position pos.
            let pos = (0..n).find(|&p| j_index(p, n) == i).unwrap();
            if pos < n - e {
                assert_eq!(llr_d[i], 0.0, "punctured bit {i} must be erased");
                zero_count += 1;
            } else {
                assert_eq!((llr_d[i] < 0.0) as u8, d[i], "bit {i}");
            }
        }
        assert_eq!(zero_count, n - e);
    }

    /// Shortening (high-rate UCI-like: K=120, E=200, N=256): last N−E
    /// positions come back as strong known-zeros.
    #[test]
    fn shortening_roundtrip() {
        let (n, e, k) = (256usize, 200usize, 120usize);
        assert!(!is_puncturing(k, e));
        let d: Vec<u8> = (0..n).map(|i| ((i * 7 + 1) % 2) as u8).collect();
        let y = subblock_interleave(&d);
        let f = rate_match(&y, e, k);
        assert_eq!(f, y[..e].to_vec());

        let llr_e: Vec<f32> = f.iter().map(|&b| if b == 0 { 1.0 } else { -1.0 }).collect();
        let llr_d = de_rate_match(&llr_e, n, k);
        for i in 0..n {
            let pos = (0..n).find(|&p| j_index(p, n) == i).unwrap();
            if pos >= e {
                assert!(llr_d[i] > 1e5, "shortened bit {i} must be known-zero");
            } else {
                assert_eq!((llr_d[i] < 0.0) as u8, d[i], "bit {i}");
            }
        }
    }

    /// §5.4.1.1 pre-frozen sets: puncturing freezes J(0..N−E) plus a head
    /// range; shortening freezes J(E..N). Spot-check counts and ranges.
    #[test]
    fn pre_frozen_sets() {
        // Repetition: nothing pre-frozen.
        assert!(rm_pre_frozen(512, 56, 864).is_empty());

        // Puncturing with E ≥ 3N/4 (432 ≥ 384): head = ⌈3N/4 − E/2⌉ = 168.
        let (n, k, e) = (512, 61, 432);
        let f = rm_pre_frozen(n, k, e);
        for i in 0..168 {
            assert!(f.binary_search(&i).is_ok(), "head index {i} must be frozen");
        }
        assert!(f.binary_search(&168).is_err() || (0..n - e).any(|j| j_index(j, n) == 168));
        for j in 0..(n - e) {
            assert!(f.binary_search(&j_index(j, n)).is_ok());
        }

        // Shortening: exactly the J-images of E..N (all distinct).
        let f = rm_pre_frozen(256, 120, 200);
        assert_eq!(f.len(), 56);
    }
}
