//! PDSCH receive front-end for SIB1 (3GPP TS 38.211 §7.3.1, §7.4.1.1).
//!
//! Extracts the PDSCH from a demodulated slot: DM-RS (config type 1, 1 CDM
//! group without data → even subcarriers on DM-RS symbols) drives per-RB channel
//! estimation; data REs are equalized, QPSK-demapped to LLRs in the §7.3.1.5
//! mapping order (increasing subcarrier `k'`, then symbol `l`), and descrambled
//! (§7.3.1.1). The LLRs feed [`crate::coding::dlsch`].

use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

use crate::ofdm::Ofdm;
use crate::sequence::gold_sequence;

/// A SIB1 PDSCH allocation.
#[derive(Clone, Debug)]
pub struct PdschAlloc {
    /// First RB, relative to CORESET#0 (from the DCI RIV; SIB1 uses
    /// non-interleaved VRB→PRB so PRB = CORESET0 RB + this).
    pub rb_start: usize,
    /// Number of RBs.
    pub n_rb: usize,
    /// First OFDM symbol in the slot.
    pub sym_start: usize,
    /// Number of OFDM symbols.
    pub n_sym: usize,
    /// Slot symbols carrying DM-RS (config type 1, single-symbol).
    pub dmrs_symbols: Vec<usize>,
    /// Modulation order (2 = QPSK).
    pub qm: usize,
    /// CORESET#0 size in RBs for interleaved VRB→PRB mapping (§7.3.1.6). `0`
    /// means non-interleaved (PRB = VRB). SIB1 in CORESET0 is interleaved (L=2).
    pub n_bwp: usize,
}

impl PdschAlloc {
    /// Physical (CORESET0-relative) PRB carrying local VRB `v` (`0..n_rb`).
    /// Applies the interleaved VRB→PRB bundle mapping (§7.3.1.6) when
    /// `n_bwp != 0`, otherwise identity.
    pub fn prb_of(&self, v: usize) -> usize {
        if self.n_bwp == 0 {
            self.rb_start + v
        } else {
            coreset0_vrb_to_prb(self.n_bwp)[self.rb_start + v]
        }
    }
}

/// Interleaved VRB→PRB mapping for CORESET0 (§7.3.1.6, bundle size `L = 2`),
/// coreset_start-relative. Returns `prb[vrb]` for `vrb ∈ 0..n_bwp`. Mirrors
/// OCUDU's `vrb_to_prb_mapper_get_interleaved_prb`.
pub fn coreset0_vrb_to_prb(n_bwp: usize) -> Vec<usize> {
    let l = 2usize;
    let nof_bundles = n_bwp.div_ceil(l);
    let (first, other) = (l, l);
    let last = if n_bwp % l > 0 { n_bwp % l } else { l };
    let r = 2usize;
    let c = nof_bundles / r;
    let mut prb = vec![0usize; n_bwp];
    for (i, p) in prb.iter_mut().take(first).enumerate() {
        *p = i; // first bundle
    }
    let last_prb_start = (nof_bundles - 2) * other + first;
    for i in 0..last {
        prb[n_bwp - last + i] = last_prb_start + i; // last bundle
    }
    for cc in 0..c {
        for rr in 0..r {
            let j = cc * r + rr;
            if j == 0 || j > nof_bundles - 2 {
                continue;
            }
            let f_j = rr * c + cc;
            let vrb_start = (j - 1) * other + first;
            let prb_start = (f_j - 1) * other + first;
            for i in 0..other {
                prb[vrb_start + i] = prb_start + i;
            }
        }
    }
    prb
}

/// PDSCH DM-RS sequence values `r(0..len)` for one OFDM symbol (§7.4.1.1.1),
/// `c_init = (2^17·(14·slot + l + 1)·(2·N_ID+1) + 2·N_ID + n_SCID) mod 2^31`,
/// with `N_ID = N_cell_ID`, `n_SCID = 0`.
pub fn pdsch_dmrs(cell_id: u16, slot: u32, symbol: u32, len: usize) -> Vec<Complex32> {
    let n_id = u64::from(cell_id);
    let c_init = (((1u64 << 17) * (14 * u64::from(slot) + u64::from(symbol) + 1) * (2 * n_id + 1)
        + 2 * n_id)
        % (1u64 << 31)) as u32;
    let c = gold_sequence(c_init, 2 * len);
    (0..len)
        .map(|m| {
            Complex32::new(
                (1 - 2 * i32::from(c[2 * m])) as f32 * FRAC_1_SQRT_2,
                (1 - 2 * i32::from(c[2 * m + 1])) as f32 * FRAC_1_SQRT_2,
            )
        })
        .collect()
}

/// Demodulate all 14 OFDM symbols of a slot starting at `slot_start` (samples),
/// numerology `mu`, where the slot is the `slot_in_subframe`-th of its subframe
/// (0 or 1 at mu=1) so the first-symbol long CP is applied correctly.
pub fn demod_slot(
    ofdm: &Ofdm,
    samples: &[Complex32],
    slot_start: usize,
    slot_in_subframe: usize,
    mu: u8,
) -> Option<Vec<Vec<Complex32>>> {
    let n = ofdm.fft_size();
    let mut grids = Vec::with_capacity(14);
    let mut off = slot_start;
    for l in 0..14 {
        let sym_in_subframe = slot_in_subframe * 14 + l;
        let cp = ofdm.cp_len(sym_in_subframe, mu);
        if off + cp + n > samples.len() {
            return None;
        }
        grids.push(ofdm.demodulate_symbol(&samples[off..], cp));
        off += cp + n;
    }
    Some(grids)
}

/// Result of PDSCH extraction.
pub struct PdschLlrs {
    /// Descrambled soft bits (positive ⇒ 0), length `n_data_re · Qm`.
    pub llrs: Vec<f32>,
    /// Mean normalized DM-RS correlation (≈1 when the DM-RS model is right).
    pub dmrs_metric: f32,
    /// RMS error-vector magnitude of the equalized data symbols vs the nearest
    /// QPSK point (0 = perfect constellation).
    pub evm: f32,
    /// Number of data resource elements.
    pub n_data_re: usize,
}

/// Extract, equalize, and descramble the PDSCH into LLRs.
///
/// `grids[l]` is the demodulated grid of slot symbol `l`; `sc_to_bin` maps a
/// subcarrier index relative to **CORESET#0 RB 0** to an FFT bin. `dmrs_base` is
/// the DM-RS sequence index of the first subcarrier of CORESET#0 RB 0 (i.e.
/// `6·N_start_CORESET0`); it is scanned against `dmrs_metric` when unknown.
/// `rnti` and `n_id` seed the data scrambler.
#[allow(clippy::too_many_arguments)]
pub fn extract_pdsch(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize,
    alloc: &PdschAlloc,
    cell_id: u16,
    slot: u32,
    dmrs_base: usize,
    rnti: u16,
    n_id: u16,
    time_first: bool,
) -> PdschLlrs {
    let n_rb = alloc.n_rb;
    // Physical (CORESET0-relative) PRB for each local VRB (interleaved for SIB1).
    let prb: Vec<usize> = (0..n_rb).map(|v| alloc.prb_of(v)).collect();
    let ref_len = dmrs_base + 6 * (alloc.n_bwp.max(alloc.rb_start + n_rb) + 1);

    // Per-(DM-RS symbol, RB) channel estimate (a per-symbol phase rotation, e.g.
    // from residual CFO, means we must NOT average across symbols). DM-RS is
    // PRB-domain: sequence indexed by the physical PRB.
    let dmrs_syms = &alloc.dmrs_symbols;
    let mut h = vec![vec![Complex32::new(0.0, 0.0); n_rb]; dmrs_syms.len()];
    let mut per_sym_corr = vec![Complex32::new(0.0, 0.0); dmrs_syms.len()];
    let mut corr_pow = 0f32;
    for (si, &l) in dmrs_syms.iter().enumerate() {
        let full_ref = pdsch_dmrs(cell_id, slot, l as u32, ref_len);
        for rb in 0..n_rb {
            let mut acc = Complex32::new(0.0, 0.0);
            for j in 0..6 {
                let k = (12 * prb[rb] + 2 * j) as i32;
                let rx = grids[l][sc_to_bin(k)];
                let est = rx * full_ref[dmrs_base + 6 * prb[rb] + j].conj();
                acc += est;
                corr_pow += rx.norm_sqr();
            }
            h[si][rb] = acc / 6.0;
            per_sym_corr[si] += acc;
        }
    }
    // Diagnostic: coherence within each symbol (phase-aligned per symbol).
    let n_dmrs_re = dmrs_syms.len() * n_rb * 6;
    let dmrs_metric = if corr_pow > 0.0 {
        per_sym_corr.iter().map(|c| c.norm()).sum::<f32>()
            / (corr_pow.sqrt() * (n_dmrs_re as f32).sqrt())
    } else {
        0.0
    };

    // A residual CFO shows up as a per-symbol phase ramp shared by all
    // subcarriers. Estimate its slope from the DM-RS symbols' average phase
    // (resolving the 2π ambiguity by collinearity when ≥3 DM-RS symbols), then
    // model the channel as `h_avg · e^{j·slope·l}` — de-rotating the CFO instead
    // of linearly interpolating across large phase jumps.
    use std::f32::consts::{PI, TAU};
    let sym_phase: Vec<f32> = h
        .iter()
        .map(|hr| hr.iter().copied().sum::<Complex32>().arg())
        .collect();
    let slope = if dmrs_syms.len() >= 3 {
        let (l0, l1, l2) = (dmrs_syms[0] as f32, dmrs_syms[1] as f32, dmrs_syms[2] as f32);
        let mut best = (0f32, f32::MAX);
        for k in -3..=3 {
            let s = (sym_phase[1] - sym_phase[0] + k as f32 * TAU) / (l1 - l0);
            let pred = sym_phase[0] + s * (l2 - l0);
            let err = ((pred - sym_phase[2] + PI).rem_euclid(TAU) - PI).abs();
            if err < best.1 {
                best = (s, err);
            }
        }
        best.0
    } else if dmrs_syms.len() == 2 {
        (sym_phase[1] - sym_phase[0]) / (dmrs_syms[1] as f32 - dmrs_syms[0] as f32)
    } else {
        0.0
    };
    // De-rotate each DM-RS symbol's channel and average (magnitude + de-CFO'd
    // phase); per-RB to keep any frequency selectivity.
    let mut h_avg = vec![Complex32::new(0.0, 0.0); n_rb];
    for (si, &ls) in dmrs_syms.iter().enumerate() {
        let derot = Complex32::from_polar(1.0, -slope * ls as f32);
        for rb in 0..n_rb {
            h_avg[rb] += h[si][rb] * derot;
        }
    }
    for hr in &mut h_avg {
        *hr /= dmrs_syms.len() as f32;
    }
    let chan = |l: usize, rb: usize| h_avg[rb] * Complex32::from_polar(1.0, slope * l as f32);

    // Data REs in §7.3.1.5 order: increasing k' (subcarrier over all RBs), then l.
    let syms: Vec<usize> = (alloc.sym_start..alloc.sym_start + alloc.n_sym).collect();
    let dmrs_set: std::collections::HashSet<usize> = dmrs_syms.iter().copied().collect();
    // DCI 1_0 uses 2 DM-RS CDM groups without data, so DM-RS symbols carry no
    // PDSCH data on any subcarrier — data lives only on the non-DM-RS symbols.
    let data_syms: Vec<usize> = syms.iter().copied().filter(|l| !dmrs_set.contains(l)).collect();
    let mut data: Vec<f32> = Vec::new();
    let mut evm_acc = 0f32;
    let mut evm_n = 0usize;
    let mut push_re = |z: Complex32, data: &mut Vec<f32>| {
        let mag = z.norm().max(1e-12);
        let n = Complex32::new(z.re.signum(), z.im.signum()) * FRAC_1_SQRT_2;
        evm_acc += (z / mag - n).norm_sqr();
        evm_n += 1;
        data.push(z.re);
        data.push(z.im);
    };
    if time_first {
        // (l, k') — symbol-outer, subcarrier-inner.
        for &l in &data_syms {
            for kp in 0..(12 * n_rb) {
                let rb = kp / 12;
                let k = (12 * prb[rb] + kp % 12) as i32;
                let z = grids[l][sc_to_bin(k)] * chan(l, rb).conj();
                push_re(z, &mut data);
            }
        }
    } else {
        // (k', l) — subcarrier-outer, symbol-inner (§7.3.1.5).
        for kp in 0..(12 * n_rb) {
            let rb = kp / 12;
            let k = (12 * prb[rb] + kp % 12) as i32;
            for &l in &data_syms {
                let z = grids[l][sc_to_bin(k)] * chan(l, rb).conj();
                push_re(z, &mut data);
            }
        }
    }
    let evm = (evm_acc / evm_n.max(1) as f32).sqrt();
    let _ = (rnti, n_id); // descrambling is applied by the caller

    let n_data_re = data.len() / 2;
    PdschLlrs {
        llrs: data,
        dmrs_metric,
        evm,
        n_data_re,
    }
}

/// Capture the equalized data symbols with `(rb, sc, l)` coordinates (for
/// offline decode debugging). Same DM-RS/channel handling as [`extract_pdsch`].
#[allow(clippy::too_many_arguments)]
pub fn capture_data_res(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize,
    alloc: &PdschAlloc,
    cell_id: u16,
    slot: u32,
    dmrs_base: usize,
) -> Vec<(usize, usize, usize, f32, f32)> {
    let n_rb = alloc.n_rb;
    let dmrs_syms = &alloc.dmrs_symbols;
    // Physical (CORESET0-relative) PRB for each local VRB (interleaved for SIB1).
    let prb: Vec<usize> = (0..n_rb).map(|v| alloc.prb_of(v)).collect();
    let ref_len = dmrs_base + 6 * (alloc.n_bwp.max(alloc.rb_start + n_rb) + 1);
    let mut h = vec![vec![Complex32::new(0.0, 0.0); n_rb]; dmrs_syms.len()];
    for (si, &l) in dmrs_syms.iter().enumerate() {
        let full_ref = pdsch_dmrs(cell_id, slot, l as u32, ref_len);
        for rb in 0..n_rb {
            let mut acc = Complex32::new(0.0, 0.0);
            for j in 0..6 {
                // DM-RS is PRB-domain: sequence indexed by the physical PRB.
                let k = (12 * prb[rb] + 2 * j) as i32;
                acc += grids[l][sc_to_bin(k)] * full_ref[dmrs_base + 6 * prb[rb] + j].conj();
            }
            h[si][rb] = acc / 6.0;
        }
    }
    use std::f32::consts::{PI, TAU};
    let sym_phase: Vec<f32> = h.iter().map(|hr| hr.iter().copied().sum::<Complex32>().arg()).collect();
    let slope = if dmrs_syms.len() >= 3 {
        let (l0, l1, l2) = (dmrs_syms[0] as f32, dmrs_syms[1] as f32, dmrs_syms[2] as f32);
        let mut best = (0f32, f32::MAX);
        for k in -3..=3 {
            let s = (sym_phase[1] - sym_phase[0] + k as f32 * TAU) / (l1 - l0);
            let err = ((sym_phase[0] + s * (l2 - l0) - sym_phase[2] + PI).rem_euclid(TAU) - PI).abs();
            if err < best.1 {
                best = (s, err);
            }
        }
        best.0
    } else {
        0.0
    };
    let mut h_avg = vec![Complex32::new(0.0, 0.0); n_rb];
    for (si, &ls) in dmrs_syms.iter().enumerate() {
        let derot = Complex32::from_polar(1.0, -slope * ls as f32);
        for rb in 0..n_rb {
            h_avg[rb] += h[si][rb] * derot;
        }
    }
    for hr in &mut h_avg {
        *hr /= dmrs_syms.len() as f32;
    }
    let dmrs_set: std::collections::HashSet<usize> = dmrs_syms.iter().copied().collect();
    let mut out = Vec::new();
    for l in alloc.sym_start..alloc.sym_start + alloc.n_sym {
        if dmrs_set.contains(&l) {
            continue;
        }
        for kp in 0..(12 * n_rb) {
            let rb = kp / 12;
            let sc = kp % 12;
            let k = (12 * prb[rb] + sc) as i32; // (interleaved) physical PRB
            let chan = h_avg[rb] * Complex32::from_polar(1.0, slope * l as f32);
            let z = grids[l][sc_to_bin(k)] * chan.conj();
            out.push((rb, sc, l, z.re, z.im));
        }
    }
    out
}

/// PDSCH data-scrambling `c_init` (§7.3.1.1): `n_RNTI·2^15 + q·2^14 + n_ID`
/// (codeword `q = 0`). For SIB1, `n_RNTI = SI-RNTI`, `n_ID = N_cell_ID`.
pub fn pdsch_scramble_c_init(rnti: u16, n_id: u16) -> u32 {
    (u32::from(rnti) << 15) | u32::from(n_id)
}

/// Descramble PDSCH LLRs in place (§7.3.1.1): flip the sign where the gold
/// sequence bit is 1.
pub fn descramble_llrs(llrs: &mut [f32], c_init: u32) {
    let c = gold_sequence(c_init, llrs.len());
    for (llr, &b) in llrs.iter_mut().zip(&c) {
        if b == 1 {
            *llr = -*llr;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmrs_are_unit_qpsk() {
        let d = pdsch_dmrs(1, 1, 2, 60);
        assert_eq!(d.len(), 60);
        for s in &d {
            assert!((s.norm() - 1.0).abs() < 1e-5);
        }
    }

    #[test]
    fn dmrs_depends_on_symbol_and_slot() {
        assert_ne!(pdsch_dmrs(1, 1, 2, 20), pdsch_dmrs(1, 1, 7, 20));
        assert_ne!(pdsch_dmrs(1, 1, 2, 20), pdsch_dmrs(1, 2, 2, 20));
    }
}
