//! DL-SCH transport-channel processing (3GPP TS 38.212 §7.2, §5.2.2, §5.4.2).
//!
//! Receive chain for one transport block:
//! ```text
//! E soft bits ──5.4.2.2 deinterleave──▶ ──5.4.2.1 de-select (circular buffer,
//!   k0 by RV, skip filler)──▶ codeword LLRs (punctured 2·Zc systematic = 0,
//!   filler = known-0) ──▶ LDPC BP decode ──▶ code block ──▶ (de-seg) ──▶
//!   ──5.2.2 CB-CRC / 7.2.1 TB-CRC24A──▶ transport block
//! ```
//! SIB1 is a single code block (`B ≤ 3840`), BG2, RV0.

use crate::coding::crc::{CRC24A, CRC24B};
use crate::coding::ldpc::{BaseGraph, LdpcGraph};
use crate::coding::ldpc_tables::LIFTING_SETS;

/// Base-graph selection (§7.2.2) from payload size `a` (bits) and code rate `r`.
pub fn select_base_graph(a: usize, r: f64) -> BaseGraph {
    if a <= 292 || (a <= 3824 && r <= 0.67) || r <= 0.25 {
        BaseGraph::Bg2
    } else {
        BaseGraph::Bg1
    }
}

/// Segmentation parameters for a transport block of `a` payload bits at rate
/// `r` (§5.2.2). Single- or multi-CB.
#[derive(Clone, Copy, Debug)]
pub struct SegParams {
    pub bg: BaseGraph,
    /// Number of code blocks `C`.
    pub c: usize,
    /// Lifting size `Zc`.
    pub zc: usize,
    /// Bits per code block including CB-CRC, `K = Kb_max·Zc` (`22` or `10`).
    pub k: usize,
    /// Information bits per CB *before* any CB-CRC, `K' - L`.
    pub k_info: usize,
    /// CB-CRC length `L` (0 for single CB, else 24).
    pub l: usize,
    /// Filler bits per CB, `K - K'`.
    pub filler: usize,
}

/// Compute segmentation parameters (§5.2.2) for `a` payload bits at rate `r`.
pub fn seg_params(a: usize, r: f64) -> SegParams {
    let bg = select_base_graph(a, r);
    let b = a + 24; // TB CRC24A
    let k_cb = match bg {
        BaseGraph::Bg1 => 8448,
        BaseGraph::Bg2 => 3840,
    };
    let (c, l, b_prime) = if b <= k_cb {
        (1, 0, b)
    } else {
        let c = b.div_ceil(k_cb - 24);
        (c, 24, b + c * 24)
    };
    let k_prime = b_prime / c;
    let kb = match bg {
        BaseGraph::Bg1 => 22,
        BaseGraph::Bg2 => {
            if b > 640 {
                10
            } else if b > 560 {
                9
            } else if b > 192 {
                8
            } else {
                6
            }
        }
    };
    // Smallest lifting size Zc with kb·Zc ≥ K'.
    let zc = LIFTING_SETS
        .iter()
        .flat_map(|s| s.iter().copied())
        .filter(|&z| kb as usize * z as usize >= k_prime)
        .min()
        .expect("no lifting size fits") as usize;
    let k_full = match bg {
        BaseGraph::Bg1 => 22,
        BaseGraph::Bg2 => 10,
    } * zc;
    SegParams {
        bg,
        c,
        zc,
        k: k_full,
        k_info: k_prime - l,
        l,
        filler: k_full - k_prime,
    }
}

/// Deinterleave `E` soft bits by modulation order `Qm` (inverse of §5.4.2.2).
fn deinterleave(f: &[f32], qm: usize) -> Vec<f32> {
    let e = f.len();
    let rows = e / qm;
    let mut out = vec![0f32; e];
    for j in 0..rows {
        for i in 0..qm {
            out[i * rows + j] = f[i + j * qm];
        }
    }
    out
}

/// Interleave `E` bits by `Qm` (forward §5.4.2.2), for the encoder/tests.
fn interleave(e: &[u8], qm: usize) -> Vec<u8> {
    let n = e.len();
    let rows = n / qm;
    let mut out = vec![0u8; n];
    for j in 0..rows {
        for i in 0..qm {
            out[i + j * qm] = e[i * rows + j];
        }
    }
    out
}

/// `k0` for one code block (Table 5.4.2.1-2), given RV, base graph, and `Ncb`.
fn k0_of(rv: u8, bg: BaseGraph, ncb: usize, zc: usize) -> usize {
    let nrows = ncb / zc; // = N_base - 2 columns worth
    let f = |num: usize| (num * nrows).div_euclid(match bg {
        BaseGraph::Bg1 => 66,
        BaseGraph::Bg2 => 50,
    }) * zc;
    match (bg, rv) {
        (_, 0) => 0,
        (BaseGraph::Bg1, 1) => f(17),
        (BaseGraph::Bg1, 2) => f(33),
        (BaseGraph::Bg1, 3) => f(56),
        (BaseGraph::Bg2, 1) => f(13),
        (BaseGraph::Bg2, 2) => f(25),
        (BaseGraph::Bg2, 3) => f(43),
        _ => 0,
    }
}

/// Rate-match one code block's codeword `d` (length `N = Ncb`, filler positions
/// marked) to `E` bits (forward, for the encoder/tests). `filler` marks
/// circular-buffer positions that are NULL and skipped.
fn rate_match_cb(d: &[u8], filler: &[bool], e_len: usize, k0: usize, qm: usize) -> Vec<u8> {
    let ncb = d.len();
    let mut e = Vec::with_capacity(e_len);
    let mut j = 0;
    while e.len() < e_len {
        let pos = (k0 + j) % ncb;
        if !filler[pos] {
            e.push(d[pos]);
        }
        j += 1;
    }
    interleave(&e, qm)
}

/// Inverse rate matching: scatter `E` soft bits back into the length-`Ncb`
/// circular buffer (combining repeats), skipping filler. Returns the buffer LLRs
/// with filler set to a large positive value (known 0).
fn de_rate_match_cb(f: &[f32], filler: &[bool], ncb: usize, k0: usize, qm: usize) -> Vec<f32> {
    let e = deinterleave(f, qm);
    let mut cb = vec![0f32; ncb];
    let mut j = 0;
    let mut k = 0;
    while k < e.len() {
        let pos = (k0 + j) % ncb;
        if !filler[pos] {
            cb[pos] += e[k];
            k += 1;
        }
        j += 1;
    }
    for (p, &fill) in filler.iter().enumerate() {
        if fill {
            cb[p] = 1e6; // known 0
        }
    }
    cb
}

/// Encode one transport block to `E` DL-SCH bits (single code block; for tests
/// and loopback). `qm` modulation order, `rv` redundancy version.
pub fn dlsch_encode_single(tb: &[u8], e_len: usize, r: f64, qm: usize, rv: u8) -> Vec<u8> {
    let p = seg_params(tb.len(), r);
    assert_eq!(p.c, 1, "single-CB helper");
    // b = tb || CRC24A
    let b = CRC24A.attach(tb);
    // code block c: b then filler (NULL modeled as 0 here; excluded via mask)
    let mut cb = vec![0u8; p.k];
    cb[..b.len()].copy_from_slice(&b);
    let g = LdpcGraph::new(p.bg, p.zc as u16).unwrap();
    let code = g.encode(&cb); // full 52·Zc (or 68·Zc) codeword
    // d = codeword minus first 2·Zc punctured systematic bits.
    let d = &code[2 * p.zc..];
    let ncb = d.len();
    // filler mask over the circular buffer (d-index): systematic filler bits at
    // codeword positions [b.len(), K) → d-index [b.len()-2Zc, K-2Zc).
    let mut filler = vec![false; ncb];
    let fstart = b.len().saturating_sub(2 * p.zc);
    for f in fstart..(p.k - 2 * p.zc) {
        filler[f] = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    rate_match_cb(d, &filler, e_len, k0, qm)
}

/// Decode `E` DL-SCH soft bits (positive ⇒ 0) into the transport block of
/// `tbs` bits, or `None` if the CRC fails. Single code block (SIB1). `qm`
/// modulation order, `rv` redundancy version, `r` the code rate used for BG
/// selection.
pub fn dlsch_decode_single(
    f: &[f32],
    tbs: usize,
    r: f64,
    qm: usize,
    rv: u8,
    max_iter: usize,
) -> Option<Vec<u8>> {
    let p = seg_params(tbs, r);
    if p.c != 1 {
        return None; // multi-CB not needed for SIB1
    }
    let b_len = tbs + 24;
    let g = LdpcGraph::new(p.bg, p.zc as u16)?;
    let ncb = g.n() - 2 * p.zc; // N = 50·Zc / 66·Zc

    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for fi in fstart..(p.k - 2 * p.zc) {
        filler[fi] = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);

    let cb_llr = de_rate_match_cb(f, &filler, ncb, k0, qm);
    // Full codeword LLR: 2·Zc punctured systematic (0) then the circular buffer.
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb_llr);

    let (info, _) = g.decode(&full, max_iter, 0.75);
    // info is K = Kb·Zc systematic bits; the block is b (tbs+24) then filler.
    let b = &info[..b_len];
    if !CRC24A.check(b) {
        return None;
    }
    Some(b[..tbs].to_vec())
}

/// Like [`dlsch_decode_single`] but also reports whether the LDPC decoder
/// converged to a valid codeword (independent of the CRC) — for diagnostics.
pub fn dlsch_decode_single_dbg(
    f: &[f32],
    tbs: usize,
    r: f64,
    qm: usize,
    rv: u8,
    max_iter: usize,
) -> (Option<Vec<u8>>, bool) {
    let p = seg_params(tbs, r);
    if p.c != 1 {
        return (None, false);
    }
    let b_len = tbs + 24;
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (None, false);
    };
    let ncb = g.n() - 2 * p.zc;
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for fi in fstart..(p.k - 2 * p.zc) {
        filler[fi] = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    let cb_llr = de_rate_match_cb(f, &filler, ncb, k0, qm);
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb_llr);
    let (info, converged) = g.decode(&full, max_iter, 0.75);
    let b = &info[..b_len];
    let tb = if CRC24A.check(b) { Some(b[..tbs].to_vec()) } else { None };
    (tb, converged)
}

/// Verify a multi-CB block's per-CB CRC24B (helper for future multi-CB support).
pub fn check_cb_crc(cb: &[u8]) -> bool {
    CRC24B.check(cb)
}

/// De-rate-match `E` soft bits to the full LDPC codeword LLRs (length
/// `N_base·Zc`, first `2·Zc` punctured = 0), *without* LDPC decoding. The
/// systematic bits are then the info bits directly: `codeword[0..K]` = the
/// transport block + CRC + filler. For interface debugging.
pub fn de_rate_match_full(f: &[f32], tbs: usize, r: f64, qm: usize, rv: u8) -> (Vec<f32>, usize) {
    let p = seg_params(tbs, r);
    let g = LdpcGraph::new(p.bg, p.zc as u16).unwrap();
    let ncb = g.n() - 2 * p.zc;
    let b_len = tbs + 24;
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for fi in fstart..(p.k - 2 * p.zc) {
        filler[fi] = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    let cb = de_rate_match_cb(f, &filler, ncb, k0, qm);
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb);
    (full, p.zc)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn segmentation_for_sib1_sized_block() {
        // ~776-bit SIB1 payload → single CB, BG2.
        let p = seg_params(776, 0.19);
        assert_eq!(p.bg, BaseGraph::Bg2);
        assert_eq!(p.c, 1);
        assert_eq!(p.l, 0);
        assert_eq!(p.k, 10 * p.zc);
        assert_eq!(p.filler, p.k - (776 + 24));
    }

    #[test]
    fn interleave_roundtrip() {
        let e: Vec<u8> = (0..24).map(|i| (i % 2) as u8).collect();
        let de: Vec<f32> = deinterleave(
            &interleave(&e, 2).iter().map(|&b| b as f32).collect::<Vec<_>>(),
            2,
        );
        assert_eq!(de.iter().map(|&x| x as u8).collect::<Vec<_>>(), e);
    }

    /// Full DL-SCH loopback: encode a TB, transmit over a QPSK AWGN channel,
    /// decode, and recover the exact transport block with a valid CRC.
    #[test]
    fn dlsch_roundtrip_qpsk() {
        let mut rng = Rng(0xD15C_0001);
        let tbs = 776usize;
        let qm = 2usize; // QPSK
        // E must be a multiple of Qm; pick a rate ~0.2.
        let e_len = ((tbs + 24) as f64 / 0.2) as usize / qm * qm;
        let r = 0.2;
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();

        let f_bits = dlsch_encode_single(&tb, e_len, r, qm, 0);
        assert_eq!(f_bits.len(), e_len);

        let sigma = 0.7f32;
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let x = s + rng.normal() * sigma;
                2.0 * x / (sigma * sigma)
            })
            .collect();

        let dec = dlsch_decode_single(&llr, tbs, r, qm, 0, 40).expect("CRC failed");
        assert_eq!(dec, tb);
    }

    /// SIB1 regime: E < Ncb (the transmitted bits are a *prefix* of the
    /// circular buffer, so most of the mother code is untransmitted). tbs=808 →
    /// Zc=88, N=50·Zc=4400, E=2160.
    #[test]
    fn dlsch_roundtrip_e_less_than_ncb() {
        let mut rng = Rng(0xD15C_0808);
        let (tbs, qm, e_len, r) = (808usize, 2usize, 2160usize, 0.370);
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        let f_bits = dlsch_encode_single(&tb, e_len, r, qm, 0);
        assert_eq!(f_bits.len(), e_len);
        let sigma = 0.6f32;
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let x = s + rng.normal() * sigma;
                2.0 * x / (sigma * sigma)
            })
            .collect();
        let dec = dlsch_decode_single(&llr, tbs, r, qm, 0, 60).expect("CRC failed (E<Ncb)");
        assert_eq!(dec, tb);
    }

    /// Same E<Ncb regime but noiseless with *uniform* LLR magnitudes (what a
    /// clean ZMQ channel produces: EVM ≈ 0). Exercises the decoder where every
    /// transmitted bit has identical reliability and ~half the mother code is
    /// erased.
    #[test]
    fn dlsch_roundtrip_uniform_llr_e_less_than_ncb() {
        let mut rng = Rng(0xD15C_1808);
        let (tbs, qm, e_len, r) = (808usize, 2usize, 2160usize, 0.370);
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        let f_bits = dlsch_encode_single(&tb, e_len, r, qm, 0);
        let llr: Vec<f32> = f_bits.iter().map(|&b| if b == 0 { 10.0 } else { -10.0 }).collect();
        let dec = dlsch_decode_single(&llr, tbs, r, qm, 0, 80).expect("CRC failed (uniform)");
        assert_eq!(dec, tb);
    }

    #[test]
    fn wrong_tbs_fails_crc() {
        let mut rng = Rng(0xD15C_0002);
        let tb: Vec<u8> = (0..776).map(|_| rng.bit()).collect();
        let f_bits = dlsch_encode_single(&tb, 4000, 0.2, 2, 0);
        let llr: Vec<f32> = f_bits.iter().map(|&b| if b == 0 { 6.0 } else { -6.0 }).collect();
        // Decoding as a different size must not spuriously pass.
        assert!(dlsch_decode_single(&llr, 700, 0.2, 2, 0, 20).is_none());
    }
}
