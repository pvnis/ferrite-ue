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
    pub fn decode(&self, llr: &[f32], max_iter: usize, alpha: f32) -> (Vec<u8>, bool) {
        assert_eq!(llr.len(), self.n());
        let zc = self.zc;
        // Messages per edge (check->var), indexed by (row, edge-in-row, z).
        let mut msg: Vec<Vec<Vec<f32>>> = self
            .rows
            .iter()
            .map(|r| vec![vec![0f32; zc]; r.len()])
            .collect();
        let mut total = llr.to_vec();

        for _ in 0..max_iter {
            // Check node update (min-sum).
            for (m, row) in self.rows.iter().enumerate() {
                for zc_off in 0..zc {
                    // Gather incoming var->check = total - msg for each edge.
                    let mut sign = 1.0f32;
                    let mut min1 = f32::INFINITY;
                    let mut min2 = f32::INFINITY;
                    let mut argmin = 0usize;
                    let vals: Vec<f32> = row
                        .iter()
                        .enumerate()
                        .map(|(e, &(n, s))| {
                            let idx = self.bit(n, (zc_off + s) % zc);
                            total[idx] - msg[m][e][zc_off]
                        })
                        .collect();
                    for (e, &v) in vals.iter().enumerate() {
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
                    for (e, &v) in vals.iter().enumerate() {
                        let mag = if e == argmin { min2 } else { min1 };
                        let s = if v < 0.0 { -sign } else { sign };
                        msg[m][e][zc_off] = alpha * s * mag;
                    }
                }
            }
            // Variable node update: total = channel + sum of incoming checks.
            total.copy_from_slice(llr);
            for (m, row) in self.rows.iter().enumerate() {
                for (e, &(n, s)) in row.iter().enumerate() {
                    for zc_off in 0..zc {
                        let idx = self.bit(n, (zc_off + s) % zc);
                        total[idx] += msg[m][e][zc_off];
                    }
                }
            }
            // Hard decision + early exit if valid codeword.
            let hard: Vec<u8> = total.iter().map(|&l| (l < 0.0) as u8).collect();
            if self.is_codeword(&hard) {
                return (hard[..self.k()].to_vec(), true);
            }
        }
        let hard: Vec<u8> = total.iter().map(|&l| (l < 0.0) as u8).collect();
        let ok = self.is_codeword(&hard);
        (hard[..self.k()].to_vec(), ok)
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
    #[test]
    #[ignore = "timing benchmark; run with --ignored --nocapture"]
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
}
