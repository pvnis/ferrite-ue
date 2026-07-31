//! LDPC coding for NR (3GPP TS 38.212 §5.3.2).
//!
//! A base graph `H_BG` (BG1 or BG2) is lifted by a size `Zc`: each edge with
//! shift value `V` becomes a `Zc × Zc` cyclic-permutation block shifted by
//! `V mod Zc`, and each non-edge a zero block. This module expands the parity
//! structure, encodes systematically, and decodes with normalized min-sum
//! belief propagation on the lifted graph.

use crate::coding::ldpc_tables::{BG1_EDGES, BG1_M, BG1_N, BG2_EDGES, BG2_M, BG2_N, LIFTING_SETS};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

/// Which NR LDPC base graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BaseGraph {
    Bg1,
    Bg2,
}

/// Cache of the packed parity-solver matrix S per (base graph, Zc): the parity part
/// H_p of the check matrix depends only on (bg, Zc), so its inversion (the expensive
/// Gaussian elimination) is done ONCE per size and reused. Encoding is then
/// `p[col] = parity(S[col] & (H_s · info))` — a cheap packed matrix-vector product,
/// turning a per-PUSCH ~300 ms elimination into ~0.3 ms.
static PARITY_SOLVER: LazyLock<Mutex<HashMap<(BaseGraph, usize), Arc<Vec<u64>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl BaseGraph {
    /// Number of systematic (information) base columns: 22 for BG1, 10 for BG2.
    pub fn info_cols(self) -> usize {
        match self {
            BaseGraph::Bg1 => 22,
            BaseGraph::Bg2 => 10,
        }
    }

    fn edges(self) -> &'static [(u8, u8, [u16; 8])] {
        match self {
            BaseGraph::Bg1 => BG1_EDGES,
            BaseGraph::Bg2 => BG2_EDGES,
        }
    }

    fn dims(self) -> (usize, usize) {
        match self {
            BaseGraph::Bg1 => (BG1_M, BG1_N),
            BaseGraph::Bg2 => (BG2_M, BG2_N),
        }
    }
}

/// The set index `iLS` and lifting size `Zc` for a base column size `Kb·Zc`.
/// `Zc` is the smallest lifting size (over all sets) with `Zc ≥ ceil(k / Kb)`.
pub fn select_lifting(base_info_cols: usize, k: usize) -> Option<(usize, u16)> {
    let need = k.div_ceil(base_info_cols) as u16;
    let mut best: Option<(usize, u16)> = None;
    for (ils, set) in LIFTING_SETS.iter().enumerate() {
        for &z in *set {
            if z >= need && best.map_or(true, |(_, b)| z < b) {
                best = Some((ils, z));
            }
        }
    }
    best
}

/// A lifted LDPC parity-check graph for a specific base graph and `Zc`.
pub struct LdpcGraph {
    bg: BaseGraph,
    zc: usize,
    ils: usize,
    m_base: usize,
    n_base: usize,
    /// Per base check node `m`: list of `(base var node n, shift)`.
    rows: Vec<Vec<(usize, usize)>>,
}

impl LdpcGraph {
    /// Build the lifted graph for `k` information bits (`k` a multiple of `Zc`).
    pub fn new(bg: BaseGraph, zc: u16) -> Option<Self> {
        // Find the set index containing zc.
        let ils = LIFTING_SETS.iter().position(|s| s.contains(&zc))?;
        let (m_base, n_base) = bg.dims();
        let mut rows = vec![Vec::new(); m_base];
        for &(m, n, ref v) in bg.edges() {
            rows[m as usize].push((n as usize, (v[ils] as usize) % zc as usize));
        }
        Some(Self {
            bg,
            zc: zc as usize,
            ils,
            m_base,
            n_base,
            rows,
        })
    }

    /// Lifting size.
    pub fn zc(&self) -> usize {
        self.zc
    }
    /// Set index.
    pub fn ils(&self) -> usize {
        self.ils
    }
    /// Number of information bits carried (`Kb · Zc`).
    pub fn k(&self) -> usize {
        self.bg.info_cols() * self.zc
    }
    /// Full codeword length before rate matching (`N_base · Zc`).
    pub fn n(&self) -> usize {
        self.n_base * self.zc
    }
    /// Number of parity check equations (`M_base · Zc`).
    pub fn m(&self) -> usize {
        self.m_base * self.zc
    }

    /// Lifted bit index for base column `n`, offset `z`.
    fn bit(&self, n: usize, z: usize) -> usize {
        n * self.zc + z
    }

    /// Check `H · c == 0` for a full lifted codeword `c` (length `n()`).
    pub fn is_codeword(&self, c: &[u8]) -> bool {
        for row in &self.rows {
            for zshift in 0..self.zc {
                let mut acc = 0u8;
                for &(n, s) in row {
                    // cyclic block: check node offset i connects to var offset
                    // (i + shift) mod Zc.
                    acc ^= c[self.bit(n, (zshift + s) % self.zc)];
                }
                if acc != 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Build the packed parity-solver matrix S (rows = parity unknowns, `words` u64
    /// each): `p = S · rhs` where `rhs = H_s · info`. Derived once by Gauss-Jordan on
    /// `[H_p | I]` — the right half at the pivot row of each column is that column's
    /// solver row (the accumulated GF(2) row operations = H_p⁻¹ up to the pivot order).
    /// info-independent, so cached per (bg, Zc). O(np³) but paid once per size.
    fn build_parity_solver(&self) -> Vec<u64> {
        let (kb, zc, np) = (self.bg.info_cols(), self.zc, self.m());
        let words = np.div_ceil(64);
        let stride = 2 * words; // each row: [ H_p (words) | I→inverse (words) ]
        let mut aug = vec![0u64; np * stride];
        let mut eqn = 0usize;
        for row in &self.rows {
            for zoff in 0..zc {
                for &(n, s) in row {
                    if n >= kb {
                        let u = (n - kb) * zc + (zoff + s) % zc;
                        aug[eqn * stride + u / 64] ^= 1u64 << (u % 64);
                    }
                }
                aug[eqn * stride + words + eqn / 64] ^= 1u64 << (eqn % 64); // identity
                eqn += 1;
            }
        }
        let mut pivot_of = vec![usize::MAX; np];
        let mut r = 0usize;
        for col in 0..np {
            let (w, bit) = (col / 64, col % 64);
            let Some(piv) = (r..np).find(|&rr| (aug[rr * stride + w] >> bit) & 1 == 1) else {
                continue;
            };
            if piv != r {
                for k in 0..stride {
                    aug.swap(r * stride + k, piv * stride + k);
                }
            }
            // Eliminate this column from every other row (Gauss-Jordan). Split the
            // buffer at the pivot row so the read (pivot) and write (target) don't alias.
            for rr in 0..np {
                if rr == r || (aug[rr * stride + w] >> bit) & 1 == 0 {
                    continue;
                }
                let (pivot, target) = if rr < r {
                    let (left, right) = aug.split_at_mut(r * stride);
                    (&right[..stride], &mut left[rr * stride..rr * stride + stride])
                } else {
                    let (left, right) = aug.split_at_mut(rr * stride);
                    (&left[r * stride..r * stride + stride], &mut right[..stride])
                };
                for k in 0..stride {
                    target[k] ^= pivot[k];
                }
            }
            pivot_of[col] = r;
            r += 1;
        }
        let mut solver = vec![0u64; np * words];
        for col in 0..np {
            let row = pivot_of[col];
            if row != usize::MAX {
                solver[col * words..col * words + words]
                    .copy_from_slice(&aug[row * stride + words..row * stride + stride]);
            }
        }
        solver
    }

    /// The cached parity solver for this (bg, Zc); builds it on first use.
    fn parity_solver(&self) -> Arc<Vec<u64>> {
        let mut cache = PARITY_SOLVER.lock().unwrap();
        cache
            .entry((self.bg, self.zc))
            .or_insert_with(|| Arc::new(self.build_parity_solver()))
            .clone()
    }

    /// Systematically encode `info` (length `k()`) into a full codeword (length
    /// `n()`). Computes the systematic syndrome `rhs = H_s · info`, then the `M·Zc`
    /// parity bits `p = S · rhs` via the cached solver (a packed GF(2) matrix-vector
    /// product) — consistent with [`Self::is_codeword`] by construction.
    pub fn encode(&self, info: &[u8]) -> Vec<u8> {
        assert_eq!(info.len(), self.k());
        let (kb, zc, np) = (self.bg.info_cols(), self.zc, self.m());
        let words = np.div_ceil(64);
        // rhs = H_s · info, packed one bit per equation.
        let mut rhs = vec![0u64; words];
        let mut eqn = 0usize;
        for row in &self.rows {
            for zoff in 0..zc {
                let mut b = 0u8;
                for &(n, s) in row {
                    if n < kb {
                        b ^= info[n * zc + (zoff + s) % zc];
                    }
                }
                if b != 0 {
                    rhs[eqn / 64] ^= 1u64 << (eqn % 64);
                }
                eqn += 1;
            }
        }
        let solver = self.parity_solver();
        let mut c = vec![0u8; self.n()];
        c[..self.k()].copy_from_slice(info);
        for col in 0..np {
            let s = &solver[col * words..col * words + words];
            let acc = s.iter().zip(&rhs).fold(0u64, |a, (&x, &y)| a ^ (x & y));
            if acc.count_ones() & 1 == 1 {
                c[(kb + col / zc) * zc + col % zc] = 1;
            }
        }
        c
    }

    /// Decode `llr` (length `n()`, positive ⇒ bit 0; punctured positions 0),
    /// returning the information bits and whether all checks are satisfied.
    /// Normalized min-sum, `max_iter` iterations, scaling `alpha`.
    /// Normalised min-sum belief-propagation decode. Dispatches to a hand-written AVX2
    /// path at runtime when the CPU supports it, otherwise runs the portable scalar
    /// decoder — which is also the clean-room reference the AVX2 path is checked against
    /// (see the `avx2_matches_scalar` test).
    pub fn decode(&self, llr: &[f32], max_iter: usize, alpha: f32) -> (Vec<u8>, bool) {
        #[cfg(target_arch = "x86_64")]
        {
            use std::sync::OnceLock;
            // Cached once: AVX2 present AND not disabled. `FERRITE_NO_AVX2=1` forces the
            // scalar path — for A/B against the reference and non-AVX2 debugging.
            static AVX2: OnceLock<bool> = OnceLock::new();
            let use_avx2 = *AVX2.get_or_init(|| {
                std::is_x86_feature_detected!("avx2")
                    && std::env::var_os("FERRITE_NO_AVX2").is_none()
            });
            if use_avx2 {
                // SAFETY: taken only when the CPU reports AVX2 support.
                return unsafe { self.decode_avx2(llr, max_iter, alpha) };
            }
        }
        self.decode_scalar(llr, max_iter, alpha)
    }

    /// Portable scalar reference decoder (see [`LdpcGraph::decode`]).
    pub fn decode_scalar(&self, llr: &[f32], max_iter: usize, alpha: f32) -> (Vec<u8>, bool) {
        assert_eq!(llr.len(), self.n());
        let zc = self.zc;
        // Flat check->var message store, indexed [(edge_off[m] + e)·Zc + z]: one
        // allocation instead of the old jagged Vec<Vec<Vec<f32>>>. `vals`/`hard` are
        // reused scratch (the old code allocated a Vec per check-node per Z per
        // iteration). The Z rotation is a branch, not a `% Zc` modulo, in the hot loop.
        let mut edge_off = Vec::with_capacity(self.rows.len());
        let mut n_edges = 0usize;
        for row in &self.rows {
            edge_off.push(n_edges);
            n_edges += row.len();
        }
        let mut msg = vec![0f32; n_edges * zc];
        let mut total = llr.to_vec();
        let max_deg = self.rows.iter().map(|r| r.len()).max().unwrap_or(0);
        let mut vals = vec![0f32; max_deg];
        let mut hard = vec![0u8; self.n()];

        for _ in 0..max_iter {
            // Check-node update (normalized min-sum) per lifted equation z.
            for (m, row) in self.rows.iter().enumerate() {
                let base = edge_off[m] * zc;
                for zc_off in 0..zc {
                    let mut sign = 1.0f32;
                    let mut min1 = f32::INFINITY;
                    let mut min2 = f32::INFINITY;
                    let mut argmin = 0usize;
                    for (e, &(n, s)) in row.iter().enumerate() {
                        let z = zc_off + s;
                        let z = if z < zc { z } else { z - zc };
                        let v = total[n * zc + z] - msg[base + e * zc + zc_off];
                        vals[e] = v;
                        if v < 0.0 {
                            sign = -sign;
                        }
                        let a = v.abs();
                        if a < min1 {
                            min2 = min1;
                            min1 = a;
                            argmin = e;
                        } else if a < min2 {
                            min2 = a;
                        }
                    }
                    for (e, &v) in vals[..row.len()].iter().enumerate() {
                        let mag = if e == argmin { min2 } else { min1 };
                        let s = if v < 0.0 { -sign } else { sign };
                        msg[base + e * zc + zc_off] = alpha * s * mag;
                    }
                }
            }
            // Variable-node update: total = channel + Σ incoming check messages.
            total.copy_from_slice(llr);
            for (m, row) in self.rows.iter().enumerate() {
                let base = edge_off[m] * zc;
                for (e, &(n, s)) in row.iter().enumerate() {
                    let eb = base + e * zc;
                    for zc_off in 0..zc {
                        let z = zc_off + s;
                        let z = if z < zc { z } else { z - zc };
                        total[n * zc + z] += msg[eb + zc_off];
                    }
                }
            }
            // Hard decision + early exit on a valid codeword.
            for (h, &l) in hard.iter_mut().zip(&total) {
                *h = (l < 0.0) as u8;
            }
            if self.is_codeword(&hard) {
                return (hard[..self.k()].to_vec(), true);
            }
        }
        for (h, &l) in hard.iter_mut().zip(&total) {
            *h = (l < 0.0) as u8;
        }
        (hard[..self.k()].to_vec(), self.is_codeword(&hard))
    }

    /// AVX2 normalised min-sum decode: vectorises the check-/variable-node updates 8
    /// lifted-equation offsets (`zc_off`) at a time. Algorithmically equivalent to
    /// [`LdpcGraph::decode_scalar`] (same normalised min-sum, same per-iteration syndrome
    /// early-exit); the only intentional difference is check-node tie handling (the vector
    /// path picks the second-minimum by `|v|==min1` rather than a strict first argmin),
    /// which does not affect which codeword it converges to.
    ///
    /// The cyclic shift `z = (zc_off + s) mod Zc` is materialised by rotating each node
    /// block into a contiguous scratch (two `copy_from_slice`s) so the hot loops are plain
    /// contiguous vector loads/stores rather than gathers.
    ///
    /// # Safety
    /// Requires the `avx2` target feature; call only behind `is_x86_feature_detected!`.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn decode_avx2(&self, llr: &[f32], max_iter: usize, alpha: f32) -> (Vec<u8>, bool) {
        use std::arch::x86_64::*;
        assert_eq!(llr.len(), self.n());
        let zc = self.zc;
        let mut edge_off = Vec::with_capacity(self.rows.len());
        let mut n_edges = 0usize;
        for row in &self.rows {
            edge_off.push(n_edges);
            n_edges += row.len();
        }
        let mut msg = vec![0f32; n_edges * zc];
        let mut total = llr.to_vec();
        let max_deg = self.rows.iter().map(|r| r.len()).max().unwrap_or(0);
        let mut hard = vec![0u8; self.n()];
        // Scratch: rotated total blocks for the current row, per-chunk saved `v`,
        // and a scalar-remainder value buffer.
        let mut rot = vec![0f32; max_deg * zc];
        let mut vbuf = vec![0f32; max_deg * 8];
        let mut svals = vec![0f32; max_deg];

        let signmask = _mm256_set1_ps(f32::from_bits(0x8000_0000));
        let absmask = _mm256_set1_ps(f32::from_bits(0x7fff_ffff));
        let alpha8 = _mm256_set1_ps(alpha);
        let inf8 = _mm256_set1_ps(f32::INFINITY);
        let nvec = zc / 8; // number of full 8-lane chunks
        let tail = nvec * 8; // start of the scalar remainder

        for _ in 0..max_iter {
            // ---- Check-node update (normalised min-sum) ----
            for (m, row) in self.rows.iter().enumerate() {
                let base = edge_off[m] * zc;
                let deg = row.len();
                // Rotate each edge's `total` node block into `rot` (zc_off frame):
                // rot[e][zc_off] = total[n·Zc + (zc_off + s) mod Zc].
                for (e, &(n, s)) in row.iter().enumerate() {
                    let off = n * zc;
                    let d = e * zc;
                    rot[d..d + (zc - s)].copy_from_slice(&total[off + s..off + zc]);
                    rot[d + (zc - s)..d + zc].copy_from_slice(&total[off..off + s]);
                }
                // Vectorised over zc_off, 8 lanes at a time.
                for c in (0..tail).step_by(8) {
                    let mut min1 = inf8;
                    let mut min2 = inf8;
                    let mut signacc = _mm256_setzero_ps();
                    for e in 0..deg {
                        let tv = _mm256_loadu_ps(rot.as_ptr().add(e * zc + c));
                        let mv = _mm256_loadu_ps(msg.as_ptr().add(base + e * zc + c));
                        let v = _mm256_sub_ps(tv, mv);
                        _mm256_storeu_ps(vbuf.as_mut_ptr().add(e * 8), v);
                        let a = _mm256_and_ps(v, absmask);
                        signacc = _mm256_xor_ps(signacc, _mm256_and_ps(v, signmask));
                        let lt = _mm256_cmp_ps::<_CMP_LT_OS>(a, min1);
                        let mina2 = _mm256_min_ps(min2, a);
                        min2 = _mm256_blendv_ps(mina2, min1, lt);
                        min1 = _mm256_min_ps(min1, a);
                    }
                    for e in 0..deg {
                        let v = _mm256_loadu_ps(vbuf.as_ptr().add(e * 8));
                        let a = _mm256_and_ps(v, absmask);
                        let is_min = _mm256_cmp_ps::<_CMP_EQ_OQ>(a, min1);
                        let mag = _mm256_blendv_ps(min1, min2, is_min);
                        let sbit = _mm256_xor_ps(signacc, _mm256_and_ps(v, signmask));
                        let out = _mm256_or_ps(_mm256_mul_ps(alpha8, mag), sbit);
                        _mm256_storeu_ps(msg.as_mut_ptr().add(base + e * zc + c), out);
                    }
                }
                // Scalar remainder for zc_off in tail..zc (bit-faithful to decode_scalar).
                for zc_off in tail..zc {
                    let mut sign = 1.0f32;
                    let mut min1 = f32::INFINITY;
                    let mut min2 = f32::INFINITY;
                    let mut argmin = 0usize;
                    for (e, _) in row.iter().enumerate() {
                        let v = rot[e * zc + zc_off] - msg[base + e * zc + zc_off];
                        svals[e] = v;
                        if v < 0.0 {
                            sign = -sign;
                        }
                        let a = v.abs();
                        if a < min1 {
                            min2 = min1;
                            min1 = a;
                            argmin = e;
                        } else if a < min2 {
                            min2 = a;
                        }
                    }
                    for e in 0..deg {
                        let v = svals[e];
                        let mag = if e == argmin { min2 } else { min1 };
                        let s = if v < 0.0 { -sign } else { sign };
                        msg[base + e * zc + zc_off] = alpha * s * mag;
                    }
                }
            }
            // ---- Variable-node update: total = channel + Σ incoming check messages ----
            total.copy_from_slice(llr);
            for (m, row) in self.rows.iter().enumerate() {
                let base = edge_off[m] * zc;
                for (e, &(n, s)) in row.iter().enumerate() {
                    let off = n * zc;
                    let src = base + e * zc;
                    // total[off+s .. off+Zc] += msg[src .. src+(Zc-s)]
                    Self::avx2_add_acc(
                        total.as_mut_ptr().add(off + s),
                        msg.as_ptr().add(src),
                        zc - s,
                    );
                    // total[off .. off+s] += msg[src+(Zc-s) .. src+Zc]
                    Self::avx2_add_acc(
                        total.as_mut_ptr().add(off),
                        msg.as_ptr().add(src + (zc - s)),
                        s,
                    );
                }
            }
            // Hard decision + early exit on a valid codeword.
            for (h, &l) in hard.iter_mut().zip(&total) {
                *h = (l < 0.0) as u8;
            }
            if self.is_codeword(&hard) {
                return (hard[..self.k()].to_vec(), true);
            }
        }
        for (h, &l) in hard.iter_mut().zip(&total) {
            *h = (l < 0.0) as u8;
        }
        (hard[..self.k()].to_vec(), self.is_codeword(&hard))
    }

    /// `dst[0..len] += src[0..len]`, AVX2, unaligned. Disjoint buffers (total vs msg).
    ///
    /// # Safety
    /// Requires `avx2`; `dst`/`src` must be valid for `len` f32 reads/writes.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn avx2_add_acc(dst: *mut f32, src: *const f32, len: usize) {
        use std::arch::x86_64::*;
        let mut i = 0usize;
        while i + 8 <= len {
            let d = _mm256_loadu_ps(dst.add(i));
            let s = _mm256_loadu_ps(src.add(i));
            _mm256_storeu_ps(dst.add(i), _mm256_add_ps(d, s));
            i += 8;
        }
        while i < len {
            *dst.add(i) += *src.add(i);
            i += 1;
        }
    }
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
    #[ignore = "quick inline timing; the real benchmark is benches/ldpc_decode.rs (cargo bench)"]
    fn bench_encode_decode() {
        for (bg, zc) in [(BaseGraph::Bg2, 192u16), (BaseGraph::Bg2, 80), (BaseGraph::Bg1, 96)] {
            let g = LdpcGraph::new(bg, zc).unwrap();
            let info: Vec<u8> = (0..g.k()).map(|i| (i % 3 == 0) as u8).collect();
            let t0 = std::time::Instant::now();
            let mut c = g.encode(&info); // first call builds + caches the solver
            let first = t0.elapsed().as_micros();
            let t = std::time::Instant::now();
            for _ in 0..100 {
                c = g.encode(&info);
            }
            let enc = t.elapsed().as_micros() as f64 / 100.0;
            println!("  (first encode incl. solver build: {first}us)");
            let llr: Vec<f32> = c.iter().map(|&b| if b == 0 { 3.0 } else { -3.0 }).collect();
            let t = std::time::Instant::now();
            for _ in 0..100 {
                let _ = g.decode(&llr, 20, 0.75);
            }
            let dec = t.elapsed().as_micros() as f64 / 100.0;
            println!("{bg:?} Zc={zc} (k={}, np={}): encode {enc:.0}us  decode {dec:.0}us  [slot=500us]", g.k(), g.m());
        }
    }

    #[test]
    fn tables_have_expected_edge_counts() {
        assert_eq!(BG2_EDGES.len(), 197);
        assert_eq!(BG1_EDGES.len(), 316);
        // Extension diagonals present (shift 0) for both graphs.
        for &(m, n, ref v) in BG2_EDGES {
            if m >= 4 && n as usize == 10 + m as usize {
                assert!(v.iter().all(|&x| x == 0), "BG2 diag ({m},{n}) not 0");
            }
        }
    }

    #[test]
    fn lifting_selection() {
        // BG2, K=101 bits -> ceil(101/10)=11 -> smallest Zc>=11 is 11 (iLS 5).
        assert_eq!(select_lifting(10, 101), Some((5, 11)));
        // K=220 -> ceil/10=22 -> Zc>=22 -> 22 (iLS5).
        assert_eq!(select_lifting(10, 220), Some((5, 22)));
    }

    /// Encoder produces valid codewords (H·c = 0) for both base graphs.
    #[test]
    fn encode_produces_valid_codewords() {
        let mut rng = Rng(0x1CDC_0001);
        for (bg, zc) in [(BaseGraph::Bg2, 16u16), (BaseGraph::Bg2, 20), (BaseGraph::Bg1, 16)] {
            let g = LdpcGraph::new(bg, zc).unwrap();
            let info: Vec<u8> = (0..g.k()).map(|_| rng.bit()).collect();
            let c = g.encode(&info);
            assert_eq!(&c[..g.k()], &info[..], "systematic prefix");
            assert!(g.is_codeword(&c), "H·c != 0 for {bg:?} Zc={zc}");
        }
    }

    /// BP decode recovers the message through a noisy channel.
    #[test]
    fn decode_recovers_through_noise() {
        let mut rng = Rng(0x1CDC_0002);
        let g = LdpcGraph::new(BaseGraph::Bg2, 20).unwrap();
        let info: Vec<u8> = (0..g.k()).map(|_| rng.bit()).collect();
        let c = g.encode(&info);

        // First 2·Zc systematic bits are punctured in NR; emulate by 0 LLR.
        let sigma = 0.5f32;
        let mut llr = vec![0f32; g.n()];
        for i in (2 * g.zc())..g.n() {
            let s = 1.0 - 2.0 * c[i] as f32;
            let r = s + rng.normal() * sigma;
            llr[i] = 2.0 * r / (sigma * sigma);
        }
        let (dec, ok) = g.decode(&llr, 40, 0.75);
        assert!(ok, "decoder did not converge");
        assert_eq!(dec, info);
    }

    /// Lifted-graph construction invariants over EVERY NR lifting size for both base
    /// graphs (k = info·Zc, n = k + parity, m = checks·Zc), then a full encode→(clean
    /// channel)→decode round-trip on the smallest Zc of each of the eight lifting sets —
    /// which covers every distinct iLS shift-folding path. Large-Zc encode (parity-solver
    /// Gaussian elimination) is a *performance* concern covered by benches/ldpc_decode.rs,
    /// so it is kept out of this correctness test to keep debug `cargo test` fast.
    #[test]
    fn roundtrip_every_lifting_size() {
        let mut rng = Rng(0x1CDC_0003);
        let mut sizes: Vec<u16> = LIFTING_SETS.iter().flat_map(|s| s.iter().copied()).collect();
        sizes.sort_unstable();
        sizes.dedup();
        // Smallest Zc of each lifting set — one representative per iLS folding path.
        let decode_set: Vec<u16> = LIFTING_SETS.iter().map(|s| s[0]).collect();

        for bg in [BaseGraph::Bg1, BaseGraph::Bg2] {
            for &zc in &sizes {
                let g = LdpcGraph::new(bg, zc).unwrap();
                assert_eq!(g.k(), bg.info_cols() * zc as usize, "k() for {bg:?} Zc={zc}");
                assert_eq!(g.n(), g.k() + g.m(), "n = k + parity for {bg:?} Zc={zc}");
                assert_eq!(g.zc(), zc as usize, "Zc round-trip for {bg:?} Zc={zc}");

                if !decode_set.contains(&zc) {
                    continue;
                }
                let info: Vec<u8> = (0..g.k()).map(|_| rng.bit()).collect();
                let c = g.encode(&info);
                assert_eq!(&c[..g.k()], &info[..], "systematic prefix {bg:?} Zc={zc}");
                assert!(g.is_codeword(&c), "invalid codeword {bg:?} Zc={zc}");
                // Clean channel: bit 0 -> +L, bit 1 -> -L, first 2·Zc punctured (0 LLR).
                let mut llr = vec![0f32; g.n()];
                for i in (2 * g.zc())..g.n() {
                    llr[i] = if c[i] == 0 { 4.0 } else { -4.0 };
                }
                let (dec, ok) = g.decode(&llr, 20, 0.75);
                assert!(ok, "no convergence {bg:?} Zc={zc}");
                assert_eq!(dec, info, "wrong message {bg:?} Zc={zc}");
            }
        }
    }

    /// The decoder corrects hard bit-flips (sign errors) up to a moderate count,
    /// exercising the iterative correction rather than a single clean pass.
    #[test]
    fn decode_corrects_bit_flips() {
        let mut rng = Rng(0x1CDC_0004);
        let g = LdpcGraph::new(BaseGraph::Bg1, 32).unwrap();
        let info: Vec<u8> = (0..g.k()).map(|_| rng.bit()).collect();
        let c = g.encode(&info);
        let mut llr = vec![0f32; g.n()];
        for i in (2 * g.zc())..g.n() {
            llr[i] = if c[i] == 0 { 3.0 } else { -3.0 };
        }
        // Flip the sign (and shrink the magnitude) of 20 received soft bits.
        let span = g.n() - 2 * g.zc();
        for _ in 0..20 {
            let i = 2 * g.zc() + ((rng.uniform() * span as f32) as usize).min(span - 1);
            llr[i] = -0.5 * llr[i];
        }
        let (dec, ok) = g.decode(&llr, 40, 0.75);
        assert!(ok, "decoder failed to correct bit flips");
        assert_eq!(dec, info);
    }

    /// The AVX2 decode path must agree with the scalar reference — same recovered message
    /// and same converged/failed verdict — across base graphs, lifting sizes that are and
    /// are not multiples of 8 (exercising both the vector body and the scalar remainder),
    /// and several noise realisations. On a non-AVX2 host this compares scalar to scalar.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_matches_scalar() {
        let mut rng = Rng(0x1CDC_0005);
        for (bg, zc) in [
            (BaseGraph::Bg2, 10u16),
            (BaseGraph::Bg2, 13),
            (BaseGraph::Bg2, 96),
            (BaseGraph::Bg1, 8),
            (BaseGraph::Bg1, 13),
            (BaseGraph::Bg1, 64),
            (BaseGraph::Bg1, 128),
        ] {
            let g = LdpcGraph::new(bg, zc).unwrap();
            for _ in 0..3 {
                let info: Vec<u8> = (0..g.k()).map(|_| rng.bit()).collect();
                let c = g.encode(&info);
                let sigma = 0.7f32;
                let mut llr = vec![0f32; g.n()];
                for i in (2 * g.zc())..g.n() {
                    let s = 1.0 - 2.0 * c[i] as f32;
                    let r = s + rng.normal() * sigma;
                    llr[i] = 2.0 * r / (sigma * sigma);
                }
                let (scalar, ok_s) = g.decode_scalar(&llr, 25, 0.75);
                let (avx, ok_a) = if std::is_x86_feature_detected!("avx2") {
                    unsafe { g.decode_avx2(&llr, 25, 0.75) }
                } else {
                    g.decode_scalar(&llr, 25, 0.75)
                };
                assert_eq!(ok_s, ok_a, "verdict mismatch {bg:?} Zc={zc}");
                assert_eq!(scalar, avx, "message mismatch {bg:?} Zc={zc}");
                if ok_s {
                    assert_eq!(avx, info, "wrong message {bg:?} Zc={zc}");
                }
            }
        }
    }
}
