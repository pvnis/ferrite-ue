//! LDPC coding for NR (3GPP TS 38.212 §5.3.2).
//!
//! A base graph `H_BG` (BG1 or BG2) is lifted by a size `Zc`: each edge with
//! shift value `V` becomes a `Zc × Zc` cyclic-permutation block shifted by
//! `V mod Zc`, and each non-edge a zero block. This module expands the parity
//! structure, encodes systematically, and decodes with normalized min-sum
//! belief propagation on the lifted graph.

use crate::coding::ldpc_tables::{BG1_EDGES, BG1_M, BG1_N, BG2_EDGES, BG2_M, BG2_N, LIFTING_SETS};

/// Which NR LDPC base graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseGraph {
    Bg1,
    Bg2,
}

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

    /// Systematically encode `info` (length `k()`) into a full codeword
    /// (length `n()`). The `M·Zc` parity bits are solved from `H·c = 0` by
    /// Gaussian elimination over GF(2) — correct for any base graph and
    /// consistent with [`Self::is_codeword`] by construction. (Encoding is only
    /// needed by tests/tools; a real UE only decodes.)
    pub fn encode(&self, info: &[u8]) -> Vec<u8> {
        assert_eq!(info.len(), self.k());
        let kb = self.bg.info_cols();
        let zc = self.zc;
        let np = self.m(); // number of parity bits = M·Zc (= unknowns = equations)
        let words = np.div_ceil(64);

        // Each equation: augmented row over `np` parity unknowns + RHS bit.
        // Parity unknown index for base col n (>=kb), offset z: (n-kb)*zc + z.
        let mut a: Vec<Vec<u64>> = Vec::with_capacity(np);
        let mut rhs: Vec<u8> = Vec::with_capacity(np);
        for row in &self.rows {
            for zoff in 0..zc {
                let mut eq = vec![0u64; words];
                let mut b = 0u8;
                for &(n, s) in row {
                    let z = (zoff + s) % zc;
                    if n < kb {
                        b ^= info[n * zc + z];
                    } else {
                        let u = (n - kb) * zc + z;
                        eq[u / 64] ^= 1u64 << (u % 64);
                    }
                }
                a.push(eq);
                rhs.push(b);
            }
        }

        // Forward elimination to reduced form, tracking pivots.
        let mut pivot_of = vec![usize::MAX; np]; // column -> equation row
        let mut r = 0;
        for col in 0..np {
            let (w, bit) = (col / 64, col % 64);
            let mut piv = None;
            for rr in r..np {
                if a[rr][w] >> bit & 1 == 1 {
                    piv = Some(rr);
                    break;
                }
            }
            let Some(piv) = piv else { continue };
            a.swap(r, piv);
            rhs.swap(r, piv);
            for rr in 0..np {
                if rr != r && a[rr][w] >> bit & 1 == 1 {
                    for k in 0..words {
                        a[rr][k] ^= a[r][k];
                    }
                    rhs[rr] ^= rhs[r];
                }
            }
            pivot_of[col] = r;
            r += 1;
        }

        // Back out the parity bits (unique solution: H_parity is full rank).
        let mut c = vec![0u8; self.n()];
        c[..self.k()].copy_from_slice(info);
        for col in 0..np {
            let row = pivot_of[col];
            let val = if row == usize::MAX { 0 } else { rhs[row] };
            let n = kb + col / zc;
            let z = col % zc;
            c[n * zc + z] = val;
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
