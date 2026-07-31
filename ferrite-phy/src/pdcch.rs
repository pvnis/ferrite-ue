//! PDCCH reception for CORESET#0 / Type0-PDCCH CSS (SIB1 scheduling).
//!
//! * CORESET#0 geometry: 38.213 §13, Table 13-4 ({SSB 30 kHz, PDCCH 30 kHz},
//!   minimum channel bandwidth 5/10 MHz).
//! * CCE→REG mapping: 38.211 §7.3.2.2 — interleaved, `L = 6`, `R = 2`,
//!   `n_shift = N_cell_ID`; REGs numbered time-first.
//! * PDCCH DMRS: 38.211 §7.4.1.3 — Gold-seeded QPSK on subcarriers `4k+1`,
//!   reference point = lowest RB of the CORESET.
//! * Candidates: 38.213 §10.1 Type0 CSS (`Y = 0`), CCE index
//!   `L·((⌊m·N_CCE/(L·M)⌋) mod ⌊N_CCE/L⌋) + i`.
//! * Mapping order: data symbols fill the candidate's non-DMRS REs in
//!   increasing symbol `l`, then subcarrier `k` (empirically validated against
//!   a live gNB — the decoded RIV matched the gNB's own SIB1 RB allocation).

use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

use crate::sequence::gold_sequence;

/// CORESET#0 layout from Table 13-4 (multiplexing pattern 1 only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coreset0 {
    /// CORESET bandwidth in RBs (24 or 48).
    pub n_rb: usize,
    /// CORESET duration in OFDM symbols (1..3).
    pub n_symb: usize,
    /// Offset (RBs) from the CORESET's lowest RB up to the common RB
    /// overlapping the SSB's first RB.
    pub offset_rb: usize,
}

impl Coreset0 {
    /// Look up `controlResourceSetZero` for {SSB 30, PDCCH 30} kHz, minimum
    /// channel bandwidth 5/10 MHz (Table 13-4). Indices 0..=15.
    pub fn from_index_30_30_minbw5_10(index: u8) -> Option<Coreset0> {
        let (n_rb, n_symb, offset_rb) = match index {
            0 => (24, 2, 0),
            1 => (24, 2, 1),
            2 => (24, 2, 2),
            3 => (24, 2, 3),
            4 => (24, 2, 4),
            5 => (24, 3, 0),
            6 => (24, 3, 1),
            7 => (24, 3, 2),
            8 => (24, 3, 3),
            9 => (24, 3, 4),
            10 => (48, 1, 12),
            11 => (48, 1, 14),
            12 => (48, 1, 16),
            13 => (48, 2, 12),
            14 => (48, 2, 14),
            15 => (48, 2, 16),
            _ => return None,
        };
        Some(Coreset0 {
            n_rb,
            n_symb,
            offset_rb,
        })
    }

    /// Number of REGs (`N_RB · N_symb`).
    pub fn n_reg(&self) -> usize {
        self.n_rb * self.n_symb
    }

    /// Number of CCEs (6 REGs each).
    pub fn n_cce(&self) -> usize {
        self.n_reg() / 6
    }

    /// The CORESET's lowest subcarrier, in 30 kHz subcarriers relative to the
    /// **SSB centre**. `k_ssb` is in 15 kHz subcarriers (FR1) and must be even
    /// (odd values put the CORESET grid 7.5 kHz off the SSB grid; unsupported
    /// here). SSB first subcarrier is at −120; the common RB overlapping it
    /// starts `k_ssb/2` below that; the CORESET starts `offset_rb` RBs lower.
    pub fn first_subcarrier_rel_ssb_centre(&self, k_ssb: u8) -> i32 {
        assert!(k_ssb % 2 == 0, "odd k_SSB (15 kHz offset) not supported yet");
        -120 - i32::from(k_ssb / 2) - 12 * self.offset_rb as i32
    }
}

/// REG index → (symbol `l`, resource block `rb`): time-first numbering.
fn reg_to_symbol_rb(reg: usize, n_symb: usize) -> (usize, usize) {
    (reg % n_symb, reg / n_symb)
}

/// The CCE→REG-bundle interleaver `f(x)` for CORESET#0 (`L = 6`, `R = 2`,
/// `n_shift = N_cell_ID`): `f(cR + r) = (rC + c + n_shift) mod (N_REG/L)`.
fn bundle_interleaver(n_bundles: usize, cell_id: u16) -> Vec<usize> {
    const R: usize = 2;
    let c_cols = n_bundles / R;
    let mut f = vec![0usize; n_bundles];
    for (x, fx) in f.iter_mut().enumerate() {
        let (c, r) = (x / R, x % R);
        *fx = (r * c_cols + c + usize::from(cell_id)) % n_bundles;
    }
    f
}

/// A Type0-CSS PDCCH candidate: its aggregation level and CCE indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub agg_level: usize,
    pub cces: Vec<usize>,
}

/// Enumerate the distinct Type0-PDCCH CSS candidates (38.213 Table 10.1-1:
/// 4 candidates at AL4, 2 at AL8, 1 at AL16), deduplicated.
pub fn type0_candidates(n_cce: usize) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for (l, m_max) in [(4usize, 4usize), (8, 2), (16, 1)] {
        if n_cce / l == 0 {
            continue;
        }
        for m in 0..m_max {
            let base = l * ((m * n_cce / (l * m_max)) % (n_cce / l));
            let cand = Candidate {
                agg_level: l,
                cces: (base..base + l).collect(),
            };
            if !out.contains(&cand) {
                out.push(cand);
            }
        }
    }
    out
}

/// PDCCH DMRS for one OFDM symbol across the whole CORESET: `3·N_RB` QPSK
/// symbols, `r_l(m)` with the sequence reference at the CORESET's lowest RB.
/// `c_init = (2^17·(14·slot + l + 1)·(2·N_ID + 1) + 2·N_ID) mod 2^31`.
pub fn pdcch_dmrs(cell_id: u16, slot: u32, symbol: u32, n_rb: usize) -> Vec<Complex32> {
    let n_id = u64::from(cell_id);
    let c_init = (((1u64 << 17) * (14 * u64::from(slot) + u64::from(symbol) + 1)
        * (2 * n_id + 1)
        + 2 * n_id)
        % (1 << 31)) as u32;
    let c = gold_sequence(c_init, 6 * n_rb);
    (0..3 * n_rb)
        .map(|m| {
            Complex32::new(
                (1 - 2 * i32::from(c[2 * m])) as f32 * FRAC_1_SQRT_2,
                (1 - 2 * i32::from(c[2 * m + 1])) as f32 * FRAC_1_SQRT_2,
            )
        })
        .collect()
}

/// Resource-element layout of one candidate: for each of its REGs, the DMRS
/// and data REs as `(symbol, subcarrier-within-CORESET)` plus the DMRS
/// sequence index. Data REs are globally sorted by (k, l) per §7.3.2.5.
pub struct CandidateLayout {
    /// `(l, k, dmrs_seq_index)` for the 18·L DMRS REs.
    pub dmrs: Vec<(usize, usize, usize)>,
    /// `(l, k)` for the 54·L data REs, in mapping order (k first, then l).
    pub data: Vec<(usize, usize)>,
}

/// Compute the layout of `cand` within `coreset` for a cell.
pub fn candidate_layout(coreset: &Coreset0, cell_id: u16, cand: &Candidate) -> CandidateLayout {
    let n_bundles = coreset.n_reg() / 6;
    let f = bundle_interleaver(n_bundles, cell_id);
    layout_from_bundles(coreset.n_symb, cand, |cce| f[cce])
}

/// Build a candidate's RE layout given a `bundle_of(cce)` map (interleaved for
/// CORESET#0, identity for a non-interleaved RRC-configured CORESET). L = 6, so
/// there is exactly one REG bundle per CCE.
fn layout_from_bundles(n_symb: usize, cand: &Candidate, bundle_of: impl Fn(usize) -> usize) -> CandidateLayout {
    let mut dmrs = Vec::new();
    let mut data = Vec::new();
    for &cce in &cand.cces {
        let bundle = bundle_of(cce);
        for reg in 6 * bundle..6 * bundle + 6 {
            let (l, rb) = reg_to_symbol_rb(reg, n_symb);
            for sc in 0..12 {
                let k = 12 * rb + sc;
                if sc % 4 == 1 {
                    dmrs.push((l, k, 3 * rb + sc / 4));
                } else {
                    data.push((l, k));
                }
            }
        }
    }
    // Data symbols map to REs in increasing symbol `l`, then subcarrier `k`
    // (verified against a live srsRAN-derived gNB: any other order fails CRC).
    data.sort_by_key(|&(l, k)| (l, k));
    dmrs.sort_by_key(|&(l, k, _)| (l, k));
    CandidateLayout { dmrs, data }
}

/// UE-specific search-space candidate CCE hashing (TS 38.213 §10.1). For a USS
/// on CORESET `coreset_id`, C-RNTI `rnti`, and slot-in-frame `slot`:
/// `Y_{p,n} = (A_p·Y_{p,n-1}) mod 65537`, `Y_{p,-1}=n_RNTI`, `A_p` per `p mod 3`;
/// CCE = `L·((Y + ⌊m·N_CCE/(L·M)⌋) mod ⌊N_CCE/L⌋) + i`. `al_counts` is
/// `(aggregation_level, nrofCandidates)` from the SearchSpace config.
pub fn uss_candidates(n_cce: usize, coreset_id: u16, rnti: u16, slot: u32, al_counts: &[(usize, usize)]) -> Vec<Candidate> {
    const D: u64 = 65537;
    let a = match coreset_id % 3 {
        0 => 39827u64,
        1 => 39829,
        _ => 39839,
    };
    let mut y = u64::from(rnti); // Y_{p,-1}
    for _ in 0..=slot {
        y = (a * y) % D; // iterate (slot+1) times → Y_{p,slot}
    }
    let mut out = Vec::new();
    for &(l, m_max) in al_counts {
        if m_max == 0 || n_cce / l == 0 {
            continue;
        }
        for m in 0..m_max {
            let base = l * (((y + (m * n_cce) as u64 / (l * m_max) as u64) % (n_cce / l) as u64) as usize);
            let cand = Candidate { agg_level: l, cces: (base..base + l).collect() };
            if !out.contains(&cand) {
                out.push(cand);
            }
        }
    }
    out
}

/// Every CCE-aligned candidate on a small CORESET, for each aggregation level in
/// `als`: candidate m of level L occupies CCEs `[m·L, m·L+L)`. This is an exhaustive
/// SUPERSET of whatever hashed candidates the actual SearchSpace defines (any Y, any
/// nrofCandidates), so it blind-decodes the DCI without tracking the exact SearchSpace
/// config. Sound because the 24-bit RNTI-masked CRC rejects the (few) empty positions,
/// and cheap on an 8-CCE CORESET. Needed because with CQI feedback the gNB drops the
/// PDCCH to AL1 with Y=0-style CCEs {0,2,4,6}, which the rnti-hashed USS misses.
pub fn all_candidates(n_cce: usize, als: &[usize]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for &l in als {
        if l == 0 || l > n_cce {
            continue;
        }
        let mut base = 0;
        while base + l <= n_cce {
            out.push(Candidate { agg_level: l, cces: (base..base + l).collect() });
            base += l;
        }
    }
    out
}

/// Equalize one candidate from per-symbol frequency grids and produce its
/// `108·L` LLRs (positive ⇒ bit 0), before descrambling.
///
/// `grids[l]` is the demodulated grid of CORESET symbol `l` (natural FFT
/// order); `sc_to_bin` maps a CORESET subcarrier index to an FFT bin. The
/// channel is estimated per REG from its 3 DMRS REs (sameAsREG-bundle
/// precoding ⇒ constant within a REG bundle; we estimate per RB-symbol).
pub fn equalize_candidate(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    coreset: &Coreset0,
    cell_id: u16,
    slot: u32,
    cand: &Candidate,
) -> Vec<f32> {
    let layout = candidate_layout(coreset, cell_id, cand);
    equalize_layout(grids, sc_to_bin, &layout, cell_id, slot, coreset.n_symb, coreset.n_rb)
}

/// Equalize a candidate in an RRC-configured CORESET with NON-interleaved
/// CCE→REG mapping (identity bundle map), spanning `n_rb` RBs over `n_symb`
/// symbols, DMRS referenced at the CORESET's lowest RB (`sc_to_bin(0)` = its
/// first subcarrier). Used for CORESET#1 / the UE-specific search space.
pub fn equalize_candidate_c1(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    n_rb: usize,
    n_symb: usize,
    cell_id: u16,
    slot: u32,
    cand: &Candidate,
) -> Vec<f32> {
    let layout = layout_from_bundles(n_symb, cand, |cce| cce);
    equalize_layout(grids, sc_to_bin, &layout, cell_id, slot, n_symb, n_rb)
}

/// Estimate the per-(symbol, RB) channel across a whole non-interleaved CORESET from
/// its PDCCH DM-RS, ONCE, so the many overlapping blind-decode candidates can reuse it
/// (the DM-RS correlation is the expensive part; the same REG's estimate is identical
/// for every candidate that touches it). Keyed by (symbol, rb).
pub fn estimate_coreset_c1(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    n_rb: usize,
    n_symb: usize,
    cell_id: u16,
    slot: u32,
) -> std::collections::HashMap<(usize, usize), Complex32> {
    let dmrs_ref: Vec<Vec<Complex32>> =
        (0..n_symb).map(|l| pdcch_dmrs(cell_id, slot, l as u32, n_rb)).collect();
    let mut h = std::collections::HashMap::new();
    for l in 0..n_symb {
        for rb in 0..n_rb {
            let mut sum = Complex32::new(0.0, 0.0);
            for (i, sc) in (1..12).step_by(4).enumerate() {
                let rx = grids[l][sc_to_bin(12 * rb + sc)];
                sum += rx * dmrs_ref[l][3 * rb + i].conj();
            }
            h.insert((l, rb), sum / 3.0);
        }
    }
    h
}

/// Produce one candidate's LLRs from a precomputed CORESET channel estimate (see
/// [`estimate_coreset_c1`]) — match-filter the data REs only, no re-estimation. Same
/// result as [`equalize_candidate_c1`] but cheap enough to blind-decode every AL/CCE.
pub fn equalize_candidate_c1_cached(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    n_symb: usize,
    cand: &Candidate,
    h_reg: &std::collections::HashMap<(usize, usize), Complex32>,
) -> Vec<f32> {
    let layout = layout_from_bundles(n_symb, cand, |cce| cce);
    let mut llrs = Vec::with_capacity(layout.data.len() * 2);
    for &(l, k) in &layout.data {
        let z = grids[l][sc_to_bin(k)] * h_reg[&(l, k / 12)].conj();
        llrs.push(z.re);
        llrs.push(z.im);
    }
    llrs
}

/// Cheap per-candidate PDCCH presence metric (srsUE's get_measure → discard): the
/// COHERENCE of the cached per-REG channel estimate across the candidate's REGs,
/// `|mean(h)|² / mean(|h|²)`. When a PDCCH really occupies the candidate every REG sees
/// the same channel ⇒ ≈1; over empty (noise-only DM-RS) REGs the estimates are random
/// ⇒ ≈1/N. Gating the blind decode on this (skip if below ~0.5) avoids the equalize +
/// polar decode for the ~13 of 15 candidates that carry nothing — using only the
/// estimate from [`estimate_coreset_c1`], no extra reads.
pub fn coreset_candidate_coherence(
    h_reg: &std::collections::HashMap<(usize, usize), Complex32>,
    cand: &Candidate,
    n_symb: usize,
) -> f32 {
    let mut sum = Complex32::new(0.0, 0.0);
    let mut power = 0.0f32;
    let mut n = 0u32;
    for &cce in &cand.cces {
        for reg in 6 * cce..6 * cce + 6 {
            let (l, rb) = reg_to_symbol_rb(reg, n_symb);
            if let Some(&h) = h_reg.get(&(l, rb)) {
                sum += h;
                power += h.norm_sqr();
                n += 1;
            }
        }
    }
    if n == 0 || power <= 1e-12 {
        return 0.0;
    }
    (sum / n as f32).norm_sqr() / (power / n as f32)
}

/// Shared equalization: per-(symbol, rb) LS channel estimate from each REG's
/// 3 DMRS REs, then match-filter the data REs into LLRs (positive ⇒ bit 0).
fn equalize_layout(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    layout: &CandidateLayout,
    cell_id: u16,
    slot: u32,
    n_symb: usize,
    n_rb: usize,
) -> Vec<f32> {
    let dmrs_ref: Vec<Vec<Complex32>> = (0..n_symb)
        .map(|l| pdcch_dmrs(cell_id, slot, l as u32, n_rb))
        .collect();

    use std::collections::HashMap;
    let mut h_reg: HashMap<(usize, usize), Complex32> = HashMap::new();
    let mut acc: HashMap<(usize, usize), (Complex32, u32)> = HashMap::new();
    for &(l, k, m) in &layout.dmrs {
        let rx = grids[l][sc_to_bin(k)];
        let est = rx * dmrs_ref[l][m].conj();
        let e = acc.entry((l, k / 12)).or_insert((Complex32::new(0.0, 0.0), 0));
        e.0 += est;
        e.1 += 1;
    }
    for ((l, rb), (sum, n)) in acc {
        h_reg.insert((l, rb), sum / n as f32);
    }

    let mut llrs = Vec::with_capacity(layout.data.len() * 2);
    for &(l, k) in &layout.data {
        let h = h_reg[&(l, k / 12)];
        let z = grids[l][sc_to_bin(k)] * h.conj();
        llrs.push(z.re);
        llrs.push(z.im);
    }
    llrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::dci::{
        dci_1_0_si_size, dci_decode, dci_encode, pdcch_descramble_llr, BITS_PER_CCE,
    };
    use crate::sequence::gold_sequence as gold;

    /// The cached-channel candidate equalization matches the per-candidate one bit for
    /// bit (so blind-decoding every candidate off one channel estimate is exact).
    #[test]
    fn cached_equalization_matches_direct() {
        let (n_rb, n_symb, cell_id, slot) = (24usize, 2usize, 1u16, 3u32);
        // Synthetic CORESET grids: DM-RS + arbitrary data, a flat channel h.
        let h = Complex32::new(0.7, 0.4);
        let dmrs: Vec<Vec<Complex32>> = (0..n_symb).map(|l| pdcch_dmrs(cell_id, slot, l as u32, n_rb)).collect();
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); 12 * n_rb]; n_symb];
        for l in 0..n_symb {
            for rb in 0..n_rb {
                for (i, sc) in (1..12).step_by(4).enumerate() {
                    grids[l][12 * rb + sc] = h * dmrs[l][3 * rb + i];
                }
                for sc in (0..12).filter(|s| s % 4 != 1) {
                    grids[l][12 * rb + sc] = h * Complex32::new((rb as f32).cos(), (sc as f32).sin());
                }
            }
        }
        let hmap = estimate_coreset_c1(&grids, |sc| sc, n_rb, n_symb, cell_id, slot);
        for &(al, base) in &[(1usize, 3usize), (2, 4), (4, 0)] {
            let cand = Candidate { agg_level: al, cces: (base..base + al).collect() };
            let direct = equalize_candidate_c1(&grids, |sc| sc, n_rb, n_symb, cell_id, slot, &cand);
            let cached = equalize_candidate_c1_cached(&grids, |sc| sc, n_symb, &cand, &hmap);
            assert_eq!(direct.len(), cached.len());
            for (a, b) in direct.iter().zip(&cached) {
                assert!((a - b).abs() < 1e-4, "AL{al} cce{base}: {a} vs {b}");
            }
        }
    }

    /// The coherence gate: a candidate whose REGs all see the same channel scores ≈1;
    /// one over random (noise-only) estimates scores ≪ the 0.5 gate.
    #[test]
    fn candidate_coherence_gates_noise() {
        let n_symb = 2usize;
        let h = Complex32::new(0.7, -0.4);
        let mut coherent = std::collections::HashMap::new();
        let mut noise = std::collections::HashMap::new();
        let mut seed = 0x1234_5678u64;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 40) as f32) / (1u64 << 24) as f32 - 0.5
        };
        for l in 0..n_symb {
            for rb in 0..24 {
                coherent.insert((l, rb), h);
                noise.insert((l, rb), Complex32::new(rng(), rng()));
            }
        }
        let cand = Candidate { agg_level: 4, cces: (0..4).collect() };
        assert!(coreset_candidate_coherence(&coherent, &cand, n_symb) > 0.95, "coherent ≈ 1");
        assert!(coreset_candidate_coherence(&noise, &cand, n_symb) < 0.5, "noise low");
    }

    /// Exhaustive candidates cover every CCE-aligned position, in particular the
    /// gNB's AL1 CCEs {0,2,4,6} (which the rnti-hashed USS could place at odd CCEs).
    #[test]
    fn all_candidates_cover_al1() {
        let c = all_candidates(8, &[1, 2, 4, 8]);
        let al1: Vec<usize> = c.iter().filter(|x| x.agg_level == 1).map(|x| x.cces[0]).collect();
        assert_eq!(al1, vec![0, 1, 2, 3, 4, 5, 6, 7]); // covers {0,2,4,6}
        assert_eq!(c.iter().filter(|x| x.agg_level == 2).map(|x| x.cces[0]).collect::<Vec<_>>(), vec![0, 2, 4, 6]);
        assert_eq!(c.iter().filter(|x| x.agg_level == 4).map(|x| x.cces[0]).collect::<Vec<_>>(), vec![0, 4]);
        assert_eq!(c.iter().filter(|x| x.agg_level == 8).map(|x| x.cces[0]).collect::<Vec<_>>(), vec![0]);
        // Every candidate is contiguous and aligned.
        for cand in &c {
            assert_eq!(cand.cces.len(), cand.agg_level);
            assert_eq!(cand.cces[0] % cand.agg_level, 0);
            assert!(cand.cces.windows(2).all(|w| w[1] == w[0] + 1));
        }
    }

    #[test]
    fn uss_hashing_matches_live_gnb() {
        // Live OCUDU cell: CORESET#1 (id 1, 8 CCEs), USS ss-id 2, C-RNTI 0x4626,
        // nrofCandidates AL2=4, AL4=2. The gNB was observed scheduling this UE at
        // AL4 with cce_index ∈ {0, 4} across slots. Every AL4 candidate we produce
        // must therefore be one of those two, and AL2 must be 2-CCE aligned.
        for slot in 0..20u32 {
            let cands = uss_candidates(8, 1, 0x4626, slot, &[(2, 4), (4, 2)]);
            for c in &cands {
                assert!(c.cces.iter().all(|&x| x < 8), "CCE out of range");
                assert_eq!(c.cces.len(), c.agg_level);
                // contiguous, aligned to the aggregation level
                assert_eq!(c.cces[0] % c.agg_level, 0);
                assert!(c.cces.windows(2).all(|w| w[1] == w[0] + 1));
                if c.agg_level == 4 {
                    assert!(c.cces[0] == 0 || c.cces[0] == 4, "AL4 base {} not in {{0,4}}", c.cces[0]);
                }
            }
        }
        // A_p for p=1 is 39829; Y_{1,0} = 39829·0x4626 mod 65537.
        let y0 = (39829u64 * 0x4626) % 65537;
        // AL4 (L=4, M=2): base = 4·(Y mod 2) → {0 or 4}; both m give both parities.
        let c0 = uss_candidates(8, 1, 0x4626, 0, &[(4, 2)]);
        assert!(c0.iter().any(|c| c.cces[0] == 4 * ((y0 % 2) as usize)));
    }

    #[test]
    fn coreset0_table_13_4() {
        let c = Coreset0::from_index_30_30_minbw5_10(2).unwrap();
        assert_eq!(
            c,
            Coreset0 {
                n_rb: 24,
                n_symb: 2,
                offset_rb: 2
            }
        );
        assert_eq!(c.n_cce(), 8);
        assert!(Coreset0::from_index_30_30_minbw5_10(16).is_none());
        // Live OCUDU cell: k_SSB = 16 → CORESET starts 152 subcarriers below
        // the SSB centre (−120 − 8 − 24).
        assert_eq!(c.first_subcarrier_rel_ssb_centre(16), -152);
    }

    #[test]
    fn type0_candidates_for_8_cces() {
        let cands = type0_candidates(8);
        // AL4: {0..4}, {4..8}; AL8: {0..8}; AL16 impossible → 3 distinct.
        assert_eq!(cands.len(), 3);
        assert_eq!(cands[0], Candidate { agg_level: 4, cces: vec![0, 1, 2, 3] });
        assert_eq!(cands[1], Candidate { agg_level: 4, cces: vec![4, 5, 6, 7] });
        assert_eq!(cands[2], Candidate { agg_level: 8, cces: (0..8).collect() });
    }

    #[test]
    fn interleaver_is_permutation_and_shifts_with_pci() {
        for pci in [0u16, 1, 7, 623] {
            let f = bundle_interleaver(8, pci);
            let mut seen = vec![false; 8];
            for &v in &f {
                assert!(!seen[v]);
                seen[v] = true;
            }
        }
        assert_ne!(bundle_interleaver(8, 1), bundle_interleaver(8, 2));
    }

    #[test]
    fn candidate_layout_counts() {
        let coreset = Coreset0::from_index_30_30_minbw5_10(2).unwrap();
        let cand = Candidate { agg_level: 4, cces: vec![0, 1, 2, 3] };
        let lay = candidate_layout(&coreset, 1, &cand);
        assert_eq!(lay.dmrs.len(), 4 * 18);
        assert_eq!(lay.data.len(), 4 * 54);
        // Mapping order: strictly increasing (l, k) — symbol first.
        for w in lay.data.windows(2) {
            let (l0, k0) = w[0];
            let (l1, k1) = w[1];
            assert!((l1, k1) > (l0, k0));
        }
    }

    /// Full synthetic PDCCH: encode a SI-RNTI DCI, scramble, QPSK, map onto
    /// CORESET grids with DMRS, pass a flat channel + noise, then blind-decode
    /// via the candidate list.
    #[test]
    fn pdcch_end_to_end_blind_decode() {
        use std::f32::consts::TAU;
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
                (-2.0 * u1.ln()).sqrt() * (TAU * u2).cos()
            }
        }

        let coreset = Coreset0::from_index_30_30_minbw5_10(2).unwrap();
        let (cell_id, slot, rnti) = (1u16, 0u32, 0xFFFFu16);
        let fft = 512usize;
        let first_sc: i32 = -144; // arbitrary placement within the grid
        let sc_to_bin =
            move |sc: usize| (first_sc + sc as i32).rem_euclid(fft as i32) as usize;

        let mut rng = Rng(0x9DCC_0001);
        let a_len = dci_1_0_si_size(coreset.n_rb);
        let payload: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();

        // Transmit on the second AL4 candidate (CCEs 4..8).
        let tx_cand = Candidate { agg_level: 4, cces: vec![4, 5, 6, 7] };
        let e = tx_cand.agg_level * BITS_PER_CCE;
        let mut bits = dci_encode(&payload, rnti, e);
        // 38.211 §7.3.2.3 scrambling with c_init = N_cell_ID.
        let c = gold(u32::from(cell_id), bits.len());
        for (b, &cb) in bits.iter_mut().zip(&c) {
            *b ^= cb;
        }

        // Build the CORESET grids: DMRS everywhere in the candidate's REGs,
        // QPSK data in (k, l) order.
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); fft]; coreset.n_symb];
        let lay = candidate_layout(&coreset, cell_id, &tx_cand);
        for &(l, k, m) in &lay.dmrs {
            grids[l][sc_to_bin(k)] = pdcch_dmrs(cell_id, slot, l as u32, coreset.n_rb)[m];
        }
        for (i, &(l, k)) in lay.data.iter().enumerate() {
            grids[l][sc_to_bin(k)] = Complex32::new(
                (1 - 2 * i32::from(bits[2 * i])) as f32 * FRAC_1_SQRT_2,
                (1 - 2 * i32::from(bits[2 * i + 1])) as f32 * FRAC_1_SQRT_2,
            );
        }

        // Flat channel + noise at 15 dB.
        let h = Complex32::from_polar(0.9, 0.6);
        let sigma = 10f32.powf(-15.0 / 20.0);
        for g in &mut grids {
            for s in g.iter_mut() {
                *s = *s * h
                    + Complex32::new(rng.normal(), rng.normal())
                        * (sigma / std::f32::consts::SQRT_2);
            }
        }

        // Receiver: try every candidate blindly; exactly one must decode.
        let mut hits = Vec::new();
        for cand in type0_candidates(coreset.n_cce()) {
            let mut llrs =
                equalize_candidate(&grids, sc_to_bin, &coreset, cell_id, slot, &cand);
            pdcch_descramble_llr(&mut llrs, u32::from(cell_id));
            if let Some(dec) = dci_decode(&llrs, rnti, a_len) {
                hits.push((cand.clone(), dec));
            }
        }
        assert_eq!(hits.len(), 1, "exactly one candidate should decode");
        assert_eq!(hits[0].0, tx_cand);
        assert_eq!(hits[0].1, payload);
    }
}
