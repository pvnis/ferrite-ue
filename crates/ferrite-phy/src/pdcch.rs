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

    let mut dmrs = Vec::new();
    let mut data = Vec::new();
    for &cce in &cand.cces {
        let bundle = f[cce]; // L = 6: one bundle per CCE
        for reg in 6 * bundle..6 * bundle + 6 {
            let (l, rb) = reg_to_symbol_rb(reg, coreset.n_symb);
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
    let dmrs_ref: Vec<Vec<Complex32>> = (0..coreset.n_symb)
        .map(|l| pdcch_dmrs(cell_id, slot, l as u32, coreset.n_rb))
        .collect();

    // Per-(symbol, rb) LS channel estimate from the REG's 3 DMRS REs.
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
