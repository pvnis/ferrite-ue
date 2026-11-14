//! Polar coding (3GPP TS 38.212 §5.3.1).
//!
//! The information set comes from the NR Polar sequence (Table 5.3.1.2-1,
//! transcribed in [`super::tables`]); for `N < 1024` the sequence is the
//! in-order subset of entries `< N` (§5.3.1.2). The polar transform is
//! `G_N = F^{⊗n}` with `F = [[1,0],[1,1]]`, no bit reversal. Decoders: plain
//! successive cancellation ([`sc_decode`]) and CRC-aided successive-cancellation
//! list ([`scl_decode`]).

use super::tables::{NR_POLAR_SEQUENCE_1024, PI_IL_MAX};

/// Reliability order for a length-`n` code: bit indices least→most reliable.
/// `n` must be a power of two, at most 1024.
pub fn reliability_order(n: usize) -> Vec<usize> {
    assert!(
        n.is_power_of_two() && (2..=1024).contains(&n),
        "n must be a power of two in 2..=1024"
    );
    NR_POLAR_SEQUENCE_1024
        .iter()
        .copied()
        .map(usize::from)
        .filter(|&q| q < n)
        .collect()
}

/// Information-bit mask: `true` at the `k` most reliable positions.
pub fn info_mask(n: usize, k: usize) -> Vec<bool> {
    assert!(k <= n);
    let order = reliability_order(n);
    let mut mask = vec![false; n];
    for &i in order.iter().rev().take(k) {
        mask[i] = true;
    }
    mask
}

/// Information-bit mask honoring the rate-matching pre-frozen set (§5.4.1.1):
/// the `k` most reliable positions *excluding* `Q̄F,tmp` for output length `e`.
/// Identical to [`info_mask`] when `e ≥ n` (repetition).
pub fn info_mask_rm(n: usize, k: usize, e: usize) -> Vec<bool> {
    let pre = super::ratematch::rm_pre_frozen(n, k, e);
    let order = reliability_order(n);
    let mut mask = vec![false; n];
    let mut placed = 0;
    for &i in order.iter().rev() {
        if placed == k {
            break;
        }
        if pre.binary_search(&i).is_err() {
            mask[i] = true;
            placed += 1;
        }
    }
    assert_eq!(
        placed, k,
        "not enough usable positions for K={k}, N={n}, E={e}"
    );
    mask
}

/// Polar code length `N = 2^n` for payload `k` and rate-matched length `e`
/// (§5.3.1): `n = max(min(n1, n2, n_max), 5)` with
/// `n1 = ⌈log2 E⌉ − 1` if `E ≤ (9/8)·2^(⌈log2 E⌉−1)` and `K/E < 9/16`, else
/// `⌈log2 E⌉`, and `n2 = ⌈log2(8K)⌉` (from `R_min = 1/8`).
pub fn code_length(k: usize, e: usize, n_max: u32) -> usize {
    let ceil_log2 = |v: usize| usize::BITS - (v - 1).leading_zeros();
    let l = ceil_log2(e);
    let n1 = if 8 * e <= 9 * (1usize << (l - 1)) && 16 * k < 9 * e {
        l - 1
    } else {
        l
    };
    let n2 = ceil_log2(8 * k);
    1usize << n1.min(n2).min(n_max).max(5)
}

/// Input-bit interleaving pattern `π(k)` for `K` bits (§5.3.1.1, `I_IL = 1`):
/// entries of `Π_IL_max` that are `≥ K_IL_max − K`, each reduced by that offset.
/// The interleaved sequence is `c'(k) = c(π(k))`.
pub fn input_interleave_pattern(k: usize) -> Vec<usize> {
    let k_il_max = PI_IL_MAX.len();
    assert!(k <= k_il_max, "K must be ≤ {k_il_max}");
    let offset = k_il_max - k;
    PI_IL_MAX
        .iter()
        .copied()
        .map(usize::from)
        .filter(|&p| p >= offset)
        .map(|p| p - offset)
        .collect()
}

/// Apply the input interleaver: `out[k] = bits[π(k)]`.
pub fn input_interleave(bits: &[u8]) -> Vec<u8> {
    input_interleave_pattern(bits.len())
        .into_iter()
        .map(|p| bits[p])
        .collect()
}

/// Invert the input interleaver: recover `bits` from `c'` where `c'[k] = bits[π(k)]`.
pub fn input_deinterleave(interleaved: &[u8]) -> Vec<u8> {
    let pat = input_interleave_pattern(interleaved.len());
    let mut out = vec![0u8; interleaved.len()];
    for (k, &p) in pat.iter().enumerate() {
        out[p] = interleaved[k];
    }
    out
}

/// In-place polar transform `x = u · F^{⊗n}` (no bit reversal). Applying it
/// twice is the identity over GF(2).
pub fn polar_transform(u: &mut [u8]) {
    let n = u.len();
    debug_assert!(n.is_power_of_two());
    let mut step = 1;
    while step < n {
        let mut base = 0;
        while base < n {
            for j in base..base + step {
                u[j] ^= u[j + step];
            }
            base += 2 * step;
        }
        step <<= 1;
    }
}

/// Encode `info` bits (length = number of set bits in `mask`) into `n` coded bits.
pub fn polar_encode(info: &[u8], mask: &[bool]) -> Vec<u8> {
    let n = mask.len();
    let mut u = vec![0u8; n];
    let mut it = info.iter();
    for (i, &is_info) in mask.iter().enumerate() {
        if is_info {
            u[i] = *it.next().expect("info length must match mask");
        }
    }
    assert!(it.next().is_none(), "info length must match mask");
    polar_transform(&mut u);
    u
}

fn f_op(a: f32, b: f32) -> f32 {
    a.signum() * b.signum() * a.abs().min(b.abs())
}

fn g_op(a: f32, b: f32, u_sum: u8) -> f32 {
    if u_sum == 0 {
        b + a
    } else {
        b - a
    }
}

/// Successive-cancellation decode. `llr[i]` is the channel LLR for coded bit `i`
/// (positive ⇒ 0). Returns the decoded information bits (in `mask` order).
pub fn sc_decode(llr: &[f32], mask: &[bool]) -> Vec<u8> {
    let n = llr.len();
    assert_eq!(mask.len(), n);
    let mut u = vec![0u8; n];
    sc(llr, mask, &mut u);
    mask.iter()
        .zip(&u)
        .filter_map(|(&m, &b)| m.then_some(b))
        .collect()
}

/// Recursive SC: fills `out` (u-domain bits) for the sub-code described by
/// `llr`/`mask` of equal length.
fn sc(llr: &[f32], mask: &[bool], out: &mut [u8]) {
    let n = llr.len();
    if n == 1 {
        out[0] = if mask[0] && llr[0] < 0.0 { 1 } else { 0 };
        return;
    }
    let h = n / 2;

    let mut left = vec![0f32; h];
    for i in 0..h {
        left[i] = f_op(llr[i], llr[i + h]);
    }
    let (mask_l, mask_r) = mask.split_at(h);
    let (out_l, out_r) = out.split_at_mut(h);
    sc(&left, mask_l, out_l);

    let mut left_enc = out_l.to_vec();
    polar_transform(&mut left_enc);
    let mut right = vec![0f32; h];
    for i in 0..h {
        right[i] = g_op(llr[i], llr[i + h], left_enc[i]);
    }
    sc(&right, mask_r, out_r);
}

/// One decoding path in the SCL decoder: its u-domain decisions so far and the
/// accumulated path metric (smaller = more likely).
#[derive(Clone)]
struct Path {
    u: Vec<u8>,
    metric: f32,
}

/// Compute the decision LLR for u-bit `u.len()` given channel LLRs and the
/// path's previous decisions, by descending the SC recursion.
fn path_bit_llr(llr: &[f32], u_prefix: &[u8]) -> f32 {
    let n = llr.len();
    if n == 1 {
        return llr[0];
    }
    let h = n / 2;
    if u_prefix.len() < h {
        let left: Vec<f32> = (0..h).map(|i| f_op(llr[i], llr[i + h])).collect();
        path_bit_llr(&left, u_prefix)
    } else {
        let (u_l, u_r) = u_prefix.split_at(h);
        let mut left_enc = u_l.to_vec();
        polar_transform(&mut left_enc);
        let right: Vec<f32> = (0..h)
            .map(|i| g_op(llr[i], llr[i + h], left_enc[i]))
            .collect();
        path_bit_llr(&right, u_r)
    }
}

/// CRC-aided successive-cancellation list decode.
///
/// Maintains up to `list_size` paths; at the end returns the information bits of
/// the lowest-metric path whose `crc_check` passes, or (if none passes) of the
/// overall lowest-metric path, along with whether the CRC passed.
pub fn scl_decode(
    llr: &[f32],
    mask: &[bool],
    list_size: usize,
    crc_check: impl Fn(&[u8]) -> bool,
) -> (Vec<u8>, bool) {
    let n = llr.len();
    assert_eq!(mask.len(), n);
    assert!(list_size >= 1);

    let mut paths = vec![Path {
        u: Vec::with_capacity(n),
        metric: 0.0,
    }];

    for i in 0..n {
        let mut next: Vec<Path> = Vec::with_capacity(paths.len() * 2);
        for p in &paths {
            let l = path_bit_llr(llr, &p.u);
            if mask[i] {
                // Fork: follow both hypotheses, penalizing the one that
                // contradicts the LLR by |l|.
                for bit in [0u8, 1u8] {
                    let mismatch = (l < 0.0) != (bit == 1);
                    let mut q = p.clone();
                    q.u.push(bit);
                    if mismatch {
                        q.metric += l.abs();
                    }
                    next.push(q);
                }
            } else {
                // Frozen bit: forced to 0; penalize if the LLR disagrees.
                let mut q = p.clone();
                q.u.push(0);
                if l < 0.0 {
                    q.metric += l.abs();
                }
                next.push(q);
            }
        }
        if next.len() > list_size {
            next.sort_by(|a, b| a.metric.partial_cmp(&b.metric).unwrap());
            next.truncate(list_size);
        }
        paths = next;
    }

    paths.sort_by(|a, b| a.metric.partial_cmp(&b.metric).unwrap());
    let extract = |p: &Path| -> Vec<u8> {
        mask.iter()
            .zip(&p.u)
            .filter_map(|(&m, &b)| m.then_some(b))
            .collect()
    };
    for p in &paths {
        let info = extract(p);
        if crc_check(&info) {
            return (info, true);
        }
    }
    (extract(&paths[0]), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::crc::CRC24C;

    struct Rng(u64);
    impl Rng {
        fn bit(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            (x >> 40) as u8 & 1
        }
        fn uniform(&mut self) -> f32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            ((x >> 11) as f32) / ((1u64 << 53) as f32)
        }
        fn normal(&mut self) -> f32 {
            let u1 = self.uniform().max(1e-9);
            let u2 = self.uniform();
            (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
        }
    }

    #[test]
    fn reliability_order_matches_spec_prefix() {
        // The most reliable indices of the N=1024 sequence, per Table 5.3.1.2-1.
        let order = reliability_order(1024);
        assert_eq!(order[..8], [0, 1, 2, 4, 8, 16, 32, 3]);
        assert_eq!(*order.last().unwrap(), 1023);
        // Subset property: N=512's least reliable is 0, most reliable is 511.
        let o512 = reliability_order(512);
        assert_eq!(o512.len(), 512);
        assert_eq!(o512[0], 0);
        assert_eq!(*o512.last().unwrap(), 511);
    }

    #[test]
    fn input_interleaver_roundtrip_and_k56() {
        // K = 56 is the BCH case.
        let pat = input_interleave_pattern(56);
        assert_eq!(pat.len(), 56);
        let mut sorted = pat.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..56).collect::<Vec<_>>(), "must be a permutation");

        let mut rng = Rng(0x77);
        let bits: Vec<u8> = (0..56).map(|_| rng.bit()).collect();
        assert_eq!(input_deinterleave(&input_interleave(&bits)), bits);
    }

    #[test]
    fn transform_is_involution() {
        let mut a = [1u8, 0, 1, 1, 0, 0, 1, 0];
        let orig = a;
        polar_transform(&mut a);
        polar_transform(&mut a);
        assert_eq!(a, orig);
    }

    #[test]
    fn info_mask_counts() {
        let mask = info_mask(128, 64);
        assert_eq!(mask.iter().filter(|&&b| b).count(), 64);
    }

    /// Noiseless SC decode is the exact inverse of the encoder.
    #[test]
    fn encode_sc_decode_noiseless() {
        let (n, k) = (128usize, 64usize);
        let mask = info_mask(n, k);
        let mut rng = Rng(0x1234_5678);
        let msg: Vec<u8> = (0..k).map(|_| rng.bit()).collect();
        let coded = polar_encode(&msg, &mask);
        let llr: Vec<f32> = coded
            .iter()
            .map(|&b| if b == 0 { 10.0 } else { -10.0 })
            .collect();
        assert_eq!(sc_decode(&llr, &mask), msg);
    }

    /// SC decode recovers the message through a mildly noisy BPSK channel.
    #[test]
    fn encode_sc_decode_with_noise() {
        let (n, k) = (256usize, 128usize);
        let mask = info_mask(n, k);
        let mut rng = Rng(0xABCD_0001);
        let msg: Vec<u8> = (0..k).map(|_| rng.bit()).collect();
        let coded = polar_encode(&msg, &mask);

        let sigma = 0.30f32;
        let llr: Vec<f32> = coded
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let r = s + rng.normal() * sigma;
                2.0 * r / (sigma * sigma)
            })
            .collect();
        assert_eq!(sc_decode(&llr, &mask), msg);
    }

    /// SCL with CRC recovers messages at noise levels where plain SC fails.
    /// This is the BCH-like configuration: N=512, K=56 (32 payload + CRC24C).
    #[test]
    fn scl_beats_sc_at_low_snr() {
        let (n, a) = (512usize, 32usize);
        let k = a + 24;
        let mask = info_mask(n, k);
        let mut rng = Rng(0xFEED_5EED);

        // ~ -6 dB per coded bit. Deterministic seed; at this point plain SC
        // fails 8/20 while CRC-aided SCL(8) recovers every trial.
        let sigma = 2.0f32;
        let mut sc_fail = 0;
        let mut scl_fail = 0;
        let trials = 20;
        for _ in 0..trials {
            let payload: Vec<u8> = (0..a).map(|_| rng.bit()).collect();
            let msg = CRC24C.attach(&payload);
            let coded = polar_encode(&msg, &mask);
            let llr: Vec<f32> = coded
                .iter()
                .map(|&b| {
                    let s = 1.0 - 2.0 * b as f32;
                    let r = s + rng.normal() * sigma;
                    2.0 * r / (sigma * sigma)
                })
                .collect();

            if sc_decode(&llr, &mask) != msg {
                sc_fail += 1;
            }
            let (dec, crc_ok) = scl_decode(&llr, &mask, 8, |bits| CRC24C.check(bits));
            if !(crc_ok && dec == msg) {
                scl_fail += 1;
            }
        }
        assert_eq!(scl_fail, 0, "SCL failed {scl_fail}/{trials}");
        assert!(
            sc_fail > scl_fail,
            "expected SC ({sc_fail} fails) to be worse than SCL ({scl_fail})"
        );
    }
}
