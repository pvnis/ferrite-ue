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

use crate::coding::crc::{Crc, CRC16, CRC24A, CRC24B};
use crate::coding::ldpc::{BaseGraph, LdpcGraph};
use crate::coding::ldpc_tables::LIFTING_SETS;

/// Transport-block CRC for DL-SCH (§7.2.1): CRC24A if `A > 3824`, else CRC16.
pub fn tb_crc(a: usize) -> Crc {
    if a > 3824 {
        CRC24A
    } else {
        CRC16
    }
}

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
    let b = a + tb_crc(a).width(); // TB CRC (§7.2.1): 24A if A>3824 else 16
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
        // Segmentation bounds K' by K_cb = kb · 384, so the largest lifting
        // size always fits.
        .unwrap_or(384) as usize;
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
    let f = |num: usize| {
        (num * nrows).div_euclid(match bg {
            BaseGraph::Bg1 => 66,
            BaseGraph::Bg2 => 50,
        }) * zc
    };
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

/// Encode ONE code block: `cb_bits` are the `K'` populated bits (info + any
/// CB-CRC), padded with filler to `K`, LDPC-encoded, punctured (drop the first
/// `2·Zc` systematic), and rate-matched to `e_r` bits at this RV.
fn encode_cb(cb_bits: &[u8], p: &SegParams, e_r: usize, rv: u8, qm: usize) -> Vec<u8> {
    // code block: cb_bits then filler (NULL modeled as 0 here; excluded via mask)
    let mut cb = vec![0u8; p.k];
    cb[..cb_bits.len()].copy_from_slice(cb_bits);
    // seg_params only picks lifting sizes of the 38.212 table.
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return vec![0u8; e_r];
    };
    let code = g.encode(&cb); // full 52·Zc (or 68·Zc) codeword
                              // d = codeword minus first 2·Zc punctured systematic bits.
    let d = &code[2 * p.zc..];
    let ncb = d.len();
    // filler mask over the circular buffer (d-index): systematic filler bits at
    // codeword positions [K', K) → d-index [K'-2Zc, K-2Zc).
    let mut filler = vec![false; ncb];
    let fstart = cb_bits.len().saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    rate_match_cb(d, &filler, e_r, k0, qm)
}

/// Encode one transport block to `E` DL-SCH bits (single code block; for tests
/// and loopback). `qm` modulation order, `rv` redundancy version. Panics if the
/// TB would segment into multiple code blocks — use [`dlsch_encode`] for those.
pub fn dlsch_encode_single(tb: &[u8], e_len: usize, r: f64, qm: usize, rv: u8) -> Vec<u8> {
    let p = seg_params(tb.len(), r);
    assert_eq!(p.c, 1, "single-CB helper");
    // b = tb || TB-CRC (CRC16 for A<=3824, else CRC24A)
    let b = tb_crc(tb.len()).attach(tb);
    encode_cb(&b, &p, e_len, rv, qm)
}

/// Encode one transport block to `E` (UL/DL)-SCH bits, segmenting into multiple
/// LDPC code blocks when `B = A + TB-CRC` exceeds the base graph's max block size
/// (§5.2.2, §5.4.2.1). Single-CB TBs give byte-identical output to
/// [`dlsch_encode_single`]. `qm` modulation order, `rv` redundancy version.
pub fn dlsch_encode(tb: &[u8], e_len: usize, r: f64, qm: usize, rv: u8) -> Vec<u8> {
    let p = seg_params(tb.len(), r);
    // b = tb || TB-CRC (CRC24A for A>3824 — always the case once C>1).
    let b = tb_crc(tb.len()).attach(tb);
    if p.c == 1 {
        return encode_cb(&b, &p, e_len, rv, qm);
    }
    // Multi-CB: split `b` into C blocks of `k_info` info bits, each closed with a
    // CRC24B (§5.2.2), then distribute the grant's E bits across the blocks
    // (§5.4.2.1, Nl = 1 layer): the first `C - (G/Qm mod C)` blocks get the floor
    // length, the rest get one more Qm-group. Concatenate the rate-matched blocks.
    let g_by = e_len / qm; // G / (Nl·Qm), Nl = 1
    let base = g_by / p.c;
    let rem = g_by % p.c;
    let mut out = Vec::with_capacity(e_len);
    for j in 0..p.c {
        let e_r = if j < p.c - rem {
            base * qm
        } else {
            (base + 1) * qm
        };
        let info = &b[j * p.k_info..(j + 1) * p.k_info];
        let cb_bits = CRC24B.attach(info); // k_info info + 24 CB-CRC = K'
        out.extend(encode_cb(&cb_bits, &p, e_r, rv, qm));
    }
    out
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
    let b_len = tbs + tb_crc(tbs).width();
    let g = LdpcGraph::new(p.bg, p.zc as u16)?;
    let ncb = g.n() - 2 * p.zc; // N = 50·Zc / 66·Zc

    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);

    let cb_llr = de_rate_match_cb(f, &filler, ncb, k0, qm);
    // Full codeword LLR: 2·Zc punctured systematic (0) then the circular buffer.
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb_llr);

    let (info, _) = g.decode(&full, max_iter, 0.75);
    // info is K = Kb·Zc systematic bits; the block is b (tbs+24) then filler.
    let b = &info[..b_len];
    if !tb_crc(tbs).check(b) {
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
    let b_len = tbs + tb_crc(tbs).width();
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (None, false);
    };
    let ncb = g.n() - 2 * p.zc;
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    let cb_llr = de_rate_match_cb(f, &filler, ncb, k0, qm);
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb_llr);
    let (info, converged) = g.decode(&full, max_iter, 0.75);
    let b = &info[..b_len];
    let tb = if tb_crc(tbs).check(b) {
        Some(b[..tbs].to_vec())
    } else {
        None
    };
    (tb, converged)
}

/// Like [`dlsch_decode_single_dbg`] but also returns the raw decoded transport
/// block bits (systematic, ignoring CRC) for interface debugging.
pub fn dlsch_decode_single_bits(
    f: &[f32],
    tbs: usize,
    r: f64,
    qm: usize,
    rv: u8,
    max_iter: usize,
) -> (Vec<u8>, bool, bool) {
    let p = seg_params(tbs, r);
    if p.c > 1 {
        return dlsch_decode_multi(f, tbs, qm, rv, max_iter, &p);
    }
    let b_len = tbs + tb_crc(tbs).width();
    // seg_params only picks lifting sizes of the 38.212 table.
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (vec![0u8; tbs], false, false);
    };
    let ncb = g.n() - 2 * p.zc;
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    let cb_llr = de_rate_match_cb(f, &filler, ncb, k0, qm);
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cb_llr);
    let (info, converged) = g.decode(&full, max_iter, 0.75);
    let b = &info[..b_len];
    (b[..tbs].to_vec(), converged, tb_crc(tbs).check(b))
}

/// Decode a multi-code-block TB (§5.2.2, §5.4.2.1): split the `E` soft bits back
/// across the `C` code blocks (same allocation as [`dlsch_encode`]), LDPC-decode
/// each, strip its CB-CRC24B, concatenate the info bits into `b = tb || TB-CRC`,
/// and verify the TB-CRC. Returns `(tb_bits, all_converged, crc_ok)`. Symmetric
/// to the encoder so a wide grant that segments into >1 block still decodes
/// instead of panicking / silently failing on the single-CB assumption.
fn dlsch_decode_multi(
    f: &[f32],
    tbs: usize,
    qm: usize,
    rv: u8,
    max_iter: usize,
    p: &SegParams,
) -> (Vec<u8>, bool, bool) {
    let g_by = f.len() / qm;
    let base = g_by / p.c;
    let rem = g_by % p.c;
    // seg_params only picks lifting sizes of the 38.212 table.
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (vec![0u8; tbs], false, false);
    };
    let ncb = g.n() - 2 * p.zc;
    let k_prime = p.k_info + p.l; // K' = info + CB-CRC (24)
    let mut filler = vec![false; ncb];
    let fstart = k_prime.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    let mut b = Vec::with_capacity(p.c * p.k_info);
    let mut all_conv = true;
    let mut off = 0;
    for j in 0..p.c {
        let e_r = if j < p.c - rem {
            base * qm
        } else {
            (base + 1) * qm
        };
        if off + e_r > f.len() {
            return (vec![0u8; tbs], false, false); // malformed E length → NACK, don't panic
        }
        let cb_llr = de_rate_match_cb(&f[off..off + e_r], &filler, ncb, k0, qm);
        off += e_r;
        let mut full = vec![0f32; g.n()];
        full[2 * p.zc..].copy_from_slice(&cb_llr);
        let (info, conv) = g.decode(&full, max_iter, 0.75);
        all_conv &= conv;
        b.extend_from_slice(&info[..p.k_info]); // drop the per-CB CRC24B
    }
    // b = tb || TB-CRC. The TB-CRC over the concatenated info catches any CB error.
    let crc_ok = tb_crc(tbs).check(&b);
    (b[..tbs].to_vec(), all_conv, crc_ok)
}

/// Verify a multi-CB block's per-CB CRC24B (helper for future multi-CB support).
pub fn check_cb_crc(cb: &[u8]) -> bool {
    CRC24B.check(cb)
}

/// De-rate-match ONE HARQ (re)transmission's `E` soft bits into the length-`Ncb`
/// circular buffer at this RV's offset, WITHOUT the filler override. Filler bits are
/// not transmitted so they stay 0 here; the caller sums these buffers across the RVs
/// of one transport block (HARQ soft-combining / incremental redundancy) and decodes
/// the sum with [`dlsch_decode_cb`]. Returns an empty vec if the block isn't single-CB.
pub fn dlsch_cb_llr(f: &[f32], tbs: usize, r: f64, qm: usize, rv: u8) -> Vec<f32> {
    let p = seg_params(tbs, r);
    if p.c != 1 {
        return Vec::new();
    }
    let b_len = tbs + tb_crc(tbs).width();
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return Vec::new();
    };
    let ncb = g.n() - 2 * p.zc;
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
    }
    let k0 = k0_of(rv, p.bg, ncb, p.zc);
    // Scatter E soft bits into the buffer, skipping (untransmitted) filler positions;
    // do NOT pin filler to 1e6 (that happens once, at decode, after summing).
    let e = deinterleave(f, qm);
    let mut cb = vec![0f32; ncb];
    let (mut j, mut k) = (0usize, 0usize);
    while k < e.len() {
        let pos = (k0 + j) % ncb;
        if !filler[pos] {
            cb[pos] += e[k];
            k += 1;
        }
        j += 1;
    }
    cb
}

/// Decode an accumulated circular buffer (the sum of one or more RVs' [`dlsch_cb_llr`]
/// outputs for one TB) into `(tb_bits, converged, crc_ok)`. Pins the filler bits to
/// known-0, prepends the 2·Zc punctured systematic bits, and LDPC-decodes. Combining
/// several RVs before this call is what lets a TB that no single (re)transmission could
/// decode succeed once enough redundancy has accumulated.
pub fn dlsch_decode_cb(cb: &[f32], tbs: usize, r: f64, max_iter: usize) -> (Vec<u8>, bool, bool) {
    let p = seg_params(tbs, r);
    if p.c > 1 {
        // Multi-CB soft-combining isn't accumulated here (dlsch_cb_llr returns empty
        // for c>1); guard so a stray call can't index past the single-CB info length.
        return (vec![0u8; tbs], false, false);
    }
    let b_len = tbs + tb_crc(tbs).width();
    // seg_params only picks lifting sizes of the 38.212 table.
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (vec![0u8; tbs], false, false);
    };
    let ncb = g.n() - 2 * p.zc;
    let mut cbf = cb.to_vec();
    cbf.resize(ncb, 0.0);
    let fstart = b_len.saturating_sub(2 * p.zc);
    for v in cbf.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *v = 1e6; // filler = known 0
    }
    let mut full = vec![0f32; g.n()];
    full[2 * p.zc..].copy_from_slice(&cbf);
    let (info, converged) = g.decode(&full, max_iter, 0.75);
    let b = &info[..b_len];
    (
        b[..tbs.min(b.len())].to_vec(),
        converged,
        tb_crc(tbs).check(b),
    )
}

/// De-rate-match `E` soft bits to the full LDPC codeword LLRs (length
/// `N_base·Zc`, first `2·Zc` punctured = 0), *without* LDPC decoding. The
/// systematic bits are then the info bits directly: `codeword[0..K]` = the
/// transport block + CRC + filler. For interface debugging.
pub fn de_rate_match_full(f: &[f32], tbs: usize, r: f64, qm: usize, rv: u8) -> (Vec<f32>, usize) {
    let p = seg_params(tbs, r);
    // seg_params only picks lifting sizes of the 38.212 table.
    let Some(g) = LdpcGraph::new(p.bg, p.zc as u16) else {
        return (Vec::new(), 0);
    };
    let ncb = g.n() - 2 * p.zc;
    let b_len = tbs + tb_crc(tbs).width();
    let mut filler = vec![false; ncb];
    let fstart = b_len.saturating_sub(2 * p.zc);
    for f in filler.iter_mut().take(p.k - 2 * p.zc).skip(fstart) {
        *f = true;
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
        // ~776-bit SIB1 payload → single CB, BG2. A ≤ 3824 ⇒ TB CRC16.
        let p = seg_params(776, 0.19);
        assert_eq!(p.bg, BaseGraph::Bg2);
        assert_eq!(p.c, 1);
        assert_eq!(p.l, 0);
        assert_eq!(p.k, 10 * p.zc);
        assert_eq!(p.filler, p.k - (776 + 16));
    }

    #[test]
    fn interleave_roundtrip() {
        let e: Vec<u8> = (0..24).map(|i| (i % 2) as u8).collect();
        let de: Vec<f32> = deinterleave(
            &interleave(&e, 2)
                .iter()
                .map(|&b| b as f32)
                .collect::<Vec<_>>(),
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

    /// A single RV of a high-rate TB fails to decode, but soft-combining two RVs
    /// (0 and 2) of the SAME TB recovers it — the essence of HARQ IR combining.
    /// Scans SNR to land in the regime where combining *strictly* helps.
    #[test]
    fn harq_soft_combining_recovers() {
        let (tbs, qm, r) = (400usize, 2usize, 0.88); // near-capacity rate → one RV is weak
        let e_len = ((tbs + 16) as f64 / r) as usize / qm * qm;
        for sigma_x100 in (70..=180).rev().step_by(3) {
            let sigma = sigma_x100 as f32 / 100.0;
            let mut rng = Rng(0xC0FF_EE01);
            let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
            let mut tx = |rv: u8| -> Vec<f32> {
                dlsch_encode_single(&tb, e_len, r, qm, rv)
                    .iter()
                    .map(|&b| {
                        let x = (1.0 - 2.0 * b as f32) + rng.normal() * sigma;
                        2.0 * x / (sigma * sigma)
                    })
                    .collect()
            };
            let (f0, f2) = (tx(0), tx(2));
            let (_, _, c0) = dlsch_decode_single_bits(&f0, tbs, r, qm, 0, 40);
            // Sum the two RVs' circular buffers and decode the combination.
            let cb0 = dlsch_cb_llr(&f0, tbs, r, qm, 0);
            let cb2 = dlsch_cb_llr(&f2, tbs, r, qm, 2);
            let acc: Vec<f32> = cb0.iter().zip(&cb2).map(|(a, b)| a + b).collect();
            let (bits, _conv, cc) = dlsch_decode_cb(&acc, tbs, r, 40);
            if !c0 && cc {
                // Found an SNR where RV 0 alone fails but adding RV 2's redundancy
                // (incremental-redundancy soft-combining) recovers the transport block.
                assert_eq!(&bits[..tbs], &tb[..]);
                return;
            }
        }
        panic!("no SNR regime found where combining strictly recovers the TB");
    }

    /// A single-RV round trip through the combining API matches the direct decoder.
    #[test]
    fn cb_api_matches_single() {
        let mut rng = Rng(0xC0FF_EE02);
        let (tbs, qm, r) = (776usize, 2usize, 0.2);
        let e_len = ((tbs + 24) as f64 / r) as usize / qm * qm;
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        let llr: Vec<f32> = dlsch_encode_single(&tb, e_len, r, qm, 0)
            .iter()
            .map(|&b| (1.0 - 2.0 * b as f32) + rng.normal() * 0.5)
            .collect();
        let cb = dlsch_cb_llr(&llr, tbs, r, qm, 0);
        let (bits, _, crc) = dlsch_decode_cb(&cb, tbs, r, 40);
        assert!(crc);
        assert_eq!(&bits[..tbs], &tb[..]);
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

    /// `dlsch_encode` is byte-identical to the single-CB helper when the TB fits
    /// one code block (the common case — no behaviour change there).
    #[test]
    fn dlsch_encode_single_cb_equiv() {
        let mut rng = Rng(0xD15C_5011);
        for &(tbs, r) in &[(776usize, 0.2f64), (808, 0.37), (1800, 0.5), (300, 0.88)] {
            let qm = 2usize;
            let e_len = ((tbs + 24) as f64 / r) as usize / qm * qm;
            let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
            assert_eq!(seg_params(tbs, r).c, 1, "expected single CB for tbs={tbs}");
            for rv in 0..4u8 {
                assert_eq!(
                    dlsch_encode(&tb, e_len, r, qm, rv),
                    dlsch_encode_single(&tb, e_len, r, qm, rv),
                    "tbs={tbs} r={r} rv={rv}"
                );
            }
        }
    }

    /// A TB large enough to segment into >1 LDPC code block encodes without
    /// panicking (the crash the single-CB helper hit under load) and produces
    /// exactly `E` bits, split across the code blocks per §5.4.2.1.
    #[test]
    fn dlsch_encode_multi_cb() {
        let mut rng = Rng(0xD15C_C0DE);
        let (tbs, qm, r) = (9000usize, 2usize, 0.5f64); // B = 9024 > 8448 (BG1) → C = 2
        let e_len = ((tbs + 24) as f64 / r) as usize / qm * qm;
        let p = seg_params(tbs, r);
        assert!(p.c > 1, "expected multi-CB, got c={}", p.c);
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        for rv in 0..4u8 {
            let e = dlsch_encode(&tb, e_len, r, qm, rv);
            assert_eq!(e.len(), e_len, "multi-CB E length rv={rv}");
        }
    }

    /// Full multi-CB round trip: encode a >1-code-block TB, then decode it back
    /// through the (now multi-CB-aware) receive path on a clean channel.
    #[test]
    fn dlsch_multi_cb_roundtrip() {
        let mut rng = Rng(0xD15C_2CB0);
        let (tbs, qm, r) = (9000usize, 2usize, 0.5f64);
        let e_len = ((tbs + 24) as f64 / r) as usize / qm * qm;
        assert!(seg_params(tbs, r).c > 1);
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        // rv0 self-decodes on a clean channel (LLR sign: positive ⇒ 0).
        let f_bits = dlsch_encode(&tb, e_len, r, qm, 0);
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| if b == 0 { 12.0 } else { -12.0 })
            .collect();
        let (bits, _conv, crc) = dlsch_decode_single_bits(&llr, tbs, r, qm, 0, 40);
        assert!(crc, "multi-CB CRC failed");
        assert_eq!(bits, tb, "multi-CB bits mismatch");
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
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| if b == 0 { 10.0 } else { -10.0 })
            .collect();
        let dec = dlsch_decode_single(&llr, tbs, r, qm, 0, 80).expect("CRC failed (uniform)");
        assert_eq!(dec, tb);
    }

    /// Reproduce the live-failing DRB grant: 2-RB MCS-9 (R=616/1024, QPSK), the tiny
    /// high-rate TB the UE decodes ~1% of on a LOSSLESS channel. rv0 carries the
    /// systematic bits, so with perfect LLRs it MUST round-trip standalone; if it does,
    /// the dlsch chain is fine and the live failure is in the grid→LLR path (extract/
    /// descramble), not the decoder. (rv1/2/3 alone are mostly parity and not
    /// self-decodable at this rate — HARQ combining is covered by harq_soft_combining_recovers.)
    #[test]
    fn dlsch_roundtrip_mcs9_2rb_perfect_llr() {
        let mut rng = Rng(0xD15C_9209);
        let tbs = 336usize; // 42 bytes, matches gNB tbs=42
        let qm = 2usize;
        let r = 616.0 / 1024.0;
        let e_len = 504usize; // cdm=1: 252 data REs × 2 bits
        let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
        let f_bits = dlsch_encode_single(&tb, e_len, r, qm, 0);
        assert_eq!(f_bits.len(), e_len);
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| if b == 0 { 20.0 } else { -20.0 })
            .collect();
        assert_eq!(
            dlsch_decode_single(&llr, tbs, r, qm, 0, 40).as_deref(),
            Some(&tb[..])
        );
    }

    /// The LDPC decoder is scale-invariant: clean LLRs decode regardless of magnitude. The
    /// live UE feeds raw equalized QPSK components (≈±0.7), not ±20; this pins that small
    /// magnitude never causes a false failure on a clean channel (ruling that out as a decode
    /// cause), across many random TBs at the 2-RB MCS-9 working point.
    #[test]
    fn dlsch_mcs9_magnitude_scale_invariant() {
        let (tbs, qm, r, e_len) = (336usize, 2usize, 616.0 / 1024.0, 504usize);
        for &mag in &[20.0f32, 1.0, 0.707, 0.1] {
            let mut rng = Rng(0xA53F_0001);
            for _ in 0..200 {
                let tb: Vec<u8> = (0..tbs).map(|_| rng.bit()).collect();
                let f_bits = dlsch_encode_single(&tb, e_len, r, qm, 0);
                let llr: Vec<f32> = f_bits
                    .iter()
                    .map(|&b| if b == 0 { mag } else { -mag })
                    .collect();
                assert_eq!(
                    dlsch_decode_single(&llr, tbs, r, qm, 0, 40).as_deref(),
                    Some(&tb[..]),
                    "mag ±{mag}"
                );
            }
        }
    }

    #[test]
    fn wrong_tbs_fails_crc() {
        let mut rng = Rng(0xD15C_0002);
        let tb: Vec<u8> = (0..776).map(|_| rng.bit()).collect();
        let f_bits = dlsch_encode_single(&tb, 4000, 0.2, 2, 0);
        let llr: Vec<f32> = f_bits
            .iter()
            .map(|&b| if b == 0 { 6.0 } else { -6.0 })
            .collect();
        // Decoding as a different size must not spuriously pass.
        assert!(dlsch_decode_single(&llr, 700, 0.2, 2, 0, 20).is_none());
    }
}
