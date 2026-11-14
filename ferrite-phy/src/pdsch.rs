//! PDSCH receive front-end (3GPP TS 38.211 §7.3.1, §7.4.1.1).
//!
//! Extracts a PDSCH from a demodulated slot: DM-RS (configuration type 1,
//! single-symbol, 1 or 2 CDM groups without data) drives a per-RB channel
//! estimate with a residual-CFO phase-slope model; the data REs are equalized,
//! soft-demapped (QPSK … 256QAM, §5.1.3) in the §7.3.1.5 mapping order and
//! returned as LLRs for [`crate::coding::dlsch`] after descrambling
//! ([`descramble_llrs`], §7.3.1.1).
//!
//! Mapping order: §7.3.1.5 maps the modulation symbols "in increasing order of
//! first the index `k` over the assigned VRBs ... and then the index `l`" —
//! which, together with the VRB→PRB step, is realised (as in the OCUDU
//! reference and verified against a live gNB) as an outer loop over the OFDM
//! symbols of the allocation and an inner loop over the subcarriers in
//! increasing `k`. That is the order implemented here.

use num_complex::Complex32;
use std::f32::consts::{PI, TAU};

use crate::ofdm::{Ofdm, PhaseCompensation};
use crate::sequence::gold_sequence;

/// VRB-to-PRB mapping of a PDSCH allocation (TS 38.211 §7.3.1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VrbToPrb {
    /// `PRB = VRB` (`vrb-ToPRB-Interleaver` absent / DCI bit 0).
    NonInterleaved,
    /// Interleaved in RB bundles of `bundle_size` (`L_i` = 2 or 4) over the
    /// BWP `[n_bwp_start, n_bwp_start + n_bwp_size)` (CRBs). For a PDSCH
    /// scheduled by DCI 1_0 in a CSS with CORESET 0 configured, the "BWP" is
    /// CORESET 0 itself: `n_bwp_start = 0` (relative to the CORESET's lowest
    /// RB), `n_bwp_size` = CORESET 0 size, `bundle_size = 2`
    /// ([`VrbToPrb::coreset0`]).
    Interleaved {
        bundle_size: usize,
        n_bwp_start: usize,
        n_bwp_size: usize,
    },
}

impl VrbToPrb {
    /// The CORESET 0 case of §7.3.1.6 (DCI 1_0 in a common search space).
    pub fn coreset0(n_coreset0_rb: usize) -> Self {
        VrbToPrb::Interleaved {
            bundle_size: 2,
            n_bwp_start: 0,
            n_bwp_size: n_coreset0_rb,
        }
    }

    /// `prb[vrb]` over the whole BWP (BWP-relative PRBs), or `None` when
    /// non-interleaved.
    pub fn table(&self) -> Option<Vec<usize>> {
        match *self {
            VrbToPrb::NonInterleaved => None,
            VrbToPrb::Interleaved {
                bundle_size,
                n_bwp_start,
                n_bwp_size,
            } => Some(interleaved_vrb_to_prb(n_bwp_size, n_bwp_start, bundle_size)),
        }
    }
}

/// Interleaved VRB→PRB mapping (TS 38.211 §7.3.1.6) for a BWP of `n_bwp_size`
/// RBs starting at CRB `n_bwp_start`, bundle size `l` (2 or 4). Returns
/// `prb[vrb]` for `vrb ∈ 0..n_bwp_size`, BWP-relative.
///
/// `N_bundle = ⌈(N_size + (N_start mod L)) / L⌉`; bundle 0 has
/// `L − (N_start mod L)` RBs, the last `(N_start + N_size) mod L` (or `L`),
/// the rest `L`. VRB bundle `j = cR + r` (`R = 2`, `C = ⌊N_bundle/R⌋`) maps to
/// PRB bundle `f(j) = rC + c`; the last bundle maps to itself.
pub fn interleaved_vrb_to_prb(n_bwp_size: usize, n_bwp_start: usize, l: usize) -> Vec<usize> {
    assert!(l == 2 || l == 4, "RB bundle size is 2 or 4");
    let head = n_bwp_start % l;
    let n_bundle = (n_bwp_size + head).div_ceil(l);
    let first = l - head;
    let last = {
        let r = (n_bwp_start + n_bwp_size) % l;
        if r > 0 {
            r
        } else {
            l
        }
    };
    let bundle_start = |b: usize| if b == 0 { 0 } else { first + (b - 1) * l };
    let bundle_size = |b: usize| {
        if b == 0 {
            first.min(n_bwp_size)
        } else if b == n_bundle - 1 {
            last
        } else {
            l
        }
    };
    const R: usize = 2;
    let c_cols = n_bundle / R;
    let mut prb = vec![0usize; n_bwp_size];
    for j in 0..n_bundle {
        let f_j = if j == n_bundle - 1 {
            j
        } else {
            let (c, r) = (j / R, j % R);
            r * c_cols + c
        };
        let (vs, ps) = (bundle_start(j), bundle_start(f_j));
        for i in 0..bundle_size(j) {
            prb[vs + i] = ps + i;
        }
    }
    prb
}

/// Interleaved VRB→PRB mapping for CORESET 0 (§7.3.1.6, `L = 2`, bundles
/// relative to the CORESET's lowest RB). Verified against a live gNB.
pub fn coreset0_vrb_to_prb(n_coreset0_rb: usize) -> Vec<usize> {
    interleaved_vrb_to_prb(n_coreset0_rb, 0, 2)
}

/// A PDSCH allocation (single layer, DM-RS configuration type 1,
/// single-symbol DM-RS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdschAlloc {
    /// First VRB of the allocation, relative to the BWP (from the DCI RIV).
    pub rb_start: usize,
    /// Number of RBs.
    pub n_rb: usize,
    /// CRB of the BWP's first RB (for CORESET 0 scheduling, the CORESET's
    /// lowest RB counts as "CRB 0" and this is 0).
    pub bwp_start_crb: usize,
    /// Reference CRB of the DM-RS sequence (§7.4.1.1.2): the lowest CRB of
    /// CORESET 0 for the SIB1 PDSCH (SI-RNTI in the Type0-PDCCH CSS with
    /// CORESET 0), otherwise CRB 0. DM-RS RE `j` of PRB `p` (BWP-relative)
    /// takes `r(6·(bwp_start_crb + p − dmrs_ref_crb) + j)`.
    pub dmrs_ref_crb: usize,
    /// First OFDM symbol in the slot.
    pub sym_start: usize,
    /// Number of OFDM symbols.
    pub n_sym: usize,
    /// Slot symbols carrying DM-RS (see [`crate::dmrs`]).
    pub dmrs_symbols: Vec<usize>,
    /// Number of DM-RS CDM groups without data (1 or 2): with 2, DM-RS
    /// symbols carry no data; with 1, the odd subcarriers of DM-RS symbols
    /// carry data (type 1 → CDM group 0 on the even subcarriers).
    pub nof_cdm_groups_without_data: usize,
    /// Modulation order `Q_m` (2, 4, 6 or 8).
    pub qm: usize,
    /// VRB→PRB mapping.
    pub vrb_to_prb: VrbToPrb,
    /// DM-RS scrambling selector `n_SCID` (0 or 1, from DCI 1_1; 0 for 1_0).
    pub n_scid: u8,
    /// DM-RS scrambling identity `N_ID^{n_SCID}`: `dmrs-ScramblingID0/1` when
    /// configured, else the cell ID (§7.4.1.1.1).
    pub scrambling_id: u16,
}

impl PdschAlloc {
    /// BWP-relative PRB carrying local VRB `v` (`0..n_rb`) of this allocation.
    pub fn prb_of(&self, v: usize) -> usize {
        match self.vrb_to_prb.table() {
            None => self.rb_start + v,
            Some(t) => t[self.rb_start + v],
        }
    }

    /// BWP-relative PRBs of the allocation, indexed by local VRB.
    pub fn prbs(&self) -> Vec<usize> {
        match self.vrb_to_prb.table() {
            None => (self.rb_start..self.rb_start + self.n_rb).collect(),
            Some(t) => t[self.rb_start..self.rb_start + self.n_rb].to_vec(),
        }
    }

    /// Whether `(symbol, subcarrier-in-RB)` is a data RE of the allocation
    /// before CSI-RS rate matching (type 1 DM-RS: even subcarriers on DM-RS
    /// symbols; odd ones reserved when 2 CDM groups are without data).
    pub fn is_data_re(&self, l: usize, k_in_rb: usize) -> bool {
        if !self.dmrs_symbols.contains(&l) {
            return true;
        }
        self.nof_cdm_groups_without_data == 1 && k_in_rb % 2 == 1
    }

    /// Data REs per PRB over the allocation (before rate matching): the
    /// `N'_RE` of TS 38.214 §5.1.3.2 *before* the min(…, 156) cap.
    pub fn data_re_per_prb(&self) -> usize {
        (self.sym_start..self.sym_start + self.n_sym)
            .map(|l| (0..12).filter(|&k| self.is_data_re(l, k)).count())
            .sum()
    }

    /// DM-RS sequence index of the first DM-RS RE of the BWP's first RB.
    pub fn dmrs_seq_base(&self) -> usize {
        assert!(
            self.bwp_start_crb >= self.dmrs_ref_crb,
            "DM-RS reference CRB must not exceed the BWP start"
        );
        6 * (self.bwp_start_crb - self.dmrs_ref_crb)
    }
}

/// PDSCH DM-RS sequence `r(0..len)` for one OFDM symbol (§7.4.1.1.1):
/// `c_init = (2^17·(14·n_slot + l + 1)·(2·N_ID + 1) + 2·N_ID + n_SCID) mod 2^31`
/// with `N_ID = N_ID^{n_SCID}` (`scrambling_id`).
pub fn pdsch_dmrs_sequence(
    scrambling_id: u16,
    n_scid: u8,
    slot: u32,
    symbol: u32,
    len: usize,
) -> Vec<Complex32> {
    use std::f32::consts::FRAC_1_SQRT_2;
    let n_id = u64::from(scrambling_id);
    let c_init = (((1u64 << 17) * (14 * u64::from(slot) + u64::from(symbol) + 1) * (2 * n_id + 1)
        + 2 * n_id
        + u64::from(n_scid & 1))
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

/// PDSCH DM-RS with `N_ID = N_cell_ID`, `n_SCID = 0` (DCI 1_0 / SIB1 / Msg2 /
/// Msg4; also the PUSCH DM-RS seed, see [`crate::pusch`]).
pub fn pdsch_dmrs(cell_id: u16, slot: u32, symbol: u32, len: usize) -> Vec<Complex32> {
    pdsch_dmrs_sequence(cell_id, 0, slot, symbol, len)
}

/// Demodulate all 14 OFDM symbols of a slot starting at `slot_start` (samples),
/// numerology `mu`, where the slot is the `slot_in_subframe`-th (`0..2^mu`) of
/// its subframe so the long CP of symbols 0 and `7·2^mu` is applied correctly.
pub fn demod_slot(
    ofdm: &Ofdm,
    samples: &[Complex32],
    slot_start: usize,
    slot_in_subframe: usize,
    mu: u8,
    comp: Option<&PhaseCompensation>,
) -> Option<Vec<Vec<Complex32>>> {
    assert!(
        slot_in_subframe < (1usize << mu),
        "slot_in_subframe out of range for mu={mu}"
    );
    let n = ofdm.fft_size();
    let mut grids = Vec::with_capacity(14);
    let mut off = slot_start;
    for l in 0..14 {
        let sym = slot_in_subframe * 14 + l;
        let cp = ofdm.cp_len(sym, mu);
        if off + cp + n > samples.len() {
            return None;
        }
        let mut g = ofdm.demodulate_symbol(&samples[off..], cp);
        if let Some(c) = comp {
            c.apply(&mut g, sym);
        }
        grids.push(g);
        off += cp + n;
    }
    Some(grids)
}

/// Max-log soft demapper for the square QAM constellations of TS 38.211
/// §5.1.3 (`Q_m` = 2/4/6/8). Per axis, the `m = Q_m/2` bits label a PAM level
/// `(1−2b_0)·(2^{m−1} − (1−2b_1)·(2^{m−2} − …))` scaled by `1/√norm`; the I
/// axis carries the even bits, the Q axis the odd bits.
pub(crate) struct Demapper {
    /// Bits per axis.
    m: usize,
    /// `√norm`: 2, 10, 42, 170.
    scale: f32,
    /// PAM level value per `m`-bit label.
    levels: [f32; 16],
}

impl Demapper {
    pub(crate) fn new(qm: usize) -> Self {
        assert!(
            matches!(qm, 2 | 4 | 6 | 8),
            "unsupported modulation order {qm}"
        );
        let m = qm / 2;
        let scale = [2.0f32, 10.0, 42.0, 170.0][m - 1].sqrt();
        let mut levels = [0f32; 16];
        for (label, lv) in levels.iter_mut().enumerate().take(1 << m) {
            let bit = |i: usize| 1.0 - 2.0 * ((label >> (m - 1 - i)) & 1) as f32;
            // Innermost first: v = 2 − s_{m−1}; v = 2^k − s·v ...
            let mut v = 1.0f32;
            for i in (1..m).rev() {
                v = (1 << (m - i)) as f32 - bit(i) * v;
            }
            *lv = bit(0) * v;
        }
        Self { m, scale, levels }
    }

    /// Append the `Q_m` LLRs (positive ⇒ bit 0) for the zero-forced symbol
    /// `y`, weighted by the channel reliability `w = |h|²`. Returns the squared
    /// error to the nearest constellation point (normalized units) for EVM.
    pub(crate) fn demap(&self, y: Complex32, w: f32, out: &mut Vec<f32>) -> f32 {
        let n = 1usize << self.m;
        let mut err = 0f32;
        // Interleave the axes' LLRs: bit 2i from I, bit 2i+1 from Q.
        let mut axis_llr = [[0f32; 4]; 2];
        for (axis, x) in [y.re, y.im].into_iter().enumerate() {
            let x = x * self.scale;
            let mut nearest = f32::MAX;
            for (i, llr) in axis_llr[axis].iter_mut().enumerate().take(self.m) {
                let (mut d0, mut d1) = (f32::MAX, f32::MAX);
                for (label, &lv) in self.levels.iter().enumerate().take(n) {
                    let d = (x - lv) * (x - lv);
                    if (label >> (self.m - 1 - i)) & 1 == 0 {
                        d0 = d0.min(d);
                    } else {
                        d1 = d1.min(d);
                    }
                    nearest = nearest.min(d);
                }
                *llr = 0.25 * (d1 - d0) * w;
            }
            err += nearest / (self.scale * self.scale);
        }
        for (&i_llr, &q_llr) in axis_llr[0].iter().zip(&axis_llr[1]).take(self.m) {
            out.push(i_llr);
            out.push(q_llr);
        }
        err
    }
}

/// Result of PDSCH extraction.
#[derive(Clone, Debug)]
pub struct PdschLlrs {
    /// Soft bits (positive ⇒ 0) in mapping order, length `n_data_re · Q_m`,
    /// *before* descrambling.
    pub llrs: Vec<f32>,
    /// Mean normalized DM-RS correlation (≈1 when the DM-RS model is right).
    pub dmrs_metric: f32,
    /// RMS error-vector magnitude of the equalized data symbols vs the nearest
    /// constellation point (0 = perfect constellation).
    pub evm: f32,
    /// Number of data resource elements.
    pub n_data_re: usize,
    /// Estimated residual-CFO phase slope (rad per OFDM symbol) from the DM-RS
    /// symbols (receive-side diagnostic).
    pub cfo_slope: f32,
}

/// Extract, equalize and soft-demap the PDSCH into LLRs.
///
/// `grids[l]` is the demodulated grid of slot symbol `l`; `sc_to_bin` maps a
/// BWP-relative subcarrier index (`12·prb + k`) to an FFT bin; `slot` is the
/// slot in the frame (DM-RS seed). `rm_skip(l, prb, k_in_rb)` marks REs the
/// PDSCH is rate-matched around (ZP/NZP CSI-RS, TS 38.214 §5.1.4; see
/// [`crate::csi::CsiRsPattern`]): skipping them keeps the LLR sequence aligned
/// with the transmitted codeword (the TBS is unaffected — only the
/// rate-matched length `E` shrinks).
pub fn extract_pdsch(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    alloc: &PdschAlloc,
    slot: u32,
    rm_skip: Option<&dyn Fn(usize, usize, usize) -> bool>,
) -> PdschLlrs {
    let n_rb = alloc.n_rb;
    let prb = alloc.prbs();
    let dmrs_syms = &alloc.dmrs_symbols;
    let seq_base = alloc.dmrs_seq_base();
    let ref_len = seq_base + 6 * (prb.iter().copied().max().map_or(0, |p| p + 1));

    // Per-(DM-RS symbol, RB) channel estimate. A per-symbol phase rotation
    // (residual CFO) means we must not average across symbols yet. The DM-RS
    // sequence is indexed by the physical PRB.
    let mut h = vec![Complex32::new(0.0, 0.0); dmrs_syms.len() * n_rb];
    let mut per_sym_corr = vec![Complex32::new(0.0, 0.0); dmrs_syms.len()];
    let mut corr_pow = 0f32;
    for (si, &l) in dmrs_syms.iter().enumerate() {
        let full_ref =
            pdsch_dmrs_sequence(alloc.scrambling_id, alloc.n_scid, slot, l as u32, ref_len);
        for (rb, &p) in prb.iter().enumerate() {
            let mut acc = Complex32::new(0.0, 0.0);
            for j in 0..6 {
                let rx = grids[l][sc_to_bin(12 * p + 2 * j)];
                acc += rx * full_ref[seq_base + 6 * p + j].conj();
                corr_pow += rx.norm_sqr();
            }
            h[si * n_rb + rb] = acc / 6.0;
            per_sym_corr[si] += acc;
        }
    }
    // Coherence within each symbol (phase-aligned per symbol).
    let n_dmrs_re = dmrs_syms.len() * n_rb * 6;
    let dmrs_metric = if corr_pow > 0.0 {
        per_sym_corr.iter().map(|c| c.norm()).sum::<f32>()
            / (corr_pow.sqrt() * (n_dmrs_re as f32).sqrt())
    } else {
        0.0
    };

    let demapper = Demapper::new(alloc.qm);
    let is_data = |l: usize, rb: usize, k: usize| {
        alloc.is_data_re(l, k) && !rm_skip.is_some_and(|f| f(l, prb[rb], k))
    };

    // Average the de-rotated per-symbol estimates (per RB, keeping frequency
    // selectivity) for a candidate CFO slope.
    let h_avg_for = |slope: f32, h_avg: &mut Vec<Complex32>| {
        h_avg.clear();
        h_avg.resize(n_rb, Complex32::new(0.0, 0.0));
        for (si, &ls) in dmrs_syms.iter().enumerate() {
            let derot = Complex32::from_polar(1.0, -slope * ls as f32);
            for rb in 0..n_rb {
                h_avg[rb] += h[si * n_rb + rb] * derot;
            }
        }
        // TS 38.214 Table 4.1-1: PDSCH EPRE relative to the DM-RS EPRE is
        // 0 dB with one CDM group without data, −3 dB with two (DM-RS boosted
        // by √2), −4.77 dB with three. Scale the estimate to the data level.
        let boost = match alloc.nof_cdm_groups_without_data {
            0 | 1 => 1.0,
            2 => std::f32::consts::FRAC_1_SQRT_2,
            _ => 1.0 / 3f32.sqrt(),
        };
        for hr in h_avg.iter_mut() {
            *hr *= boost / dmrs_syms.len().max(1) as f32;
        }
    };
    // Equalize every data RE with the slope model `h_avg · e^{j·slope·l}` and
    // demap into `out` (cleared); returns the RMS EVM.
    let mut h_avg: Vec<Complex32> = Vec::with_capacity(n_rb);
    let equalize = |slope: f32, out: &mut Vec<f32>, h_avg: &mut Vec<Complex32>| -> f32 {
        h_avg_for(slope, h_avg);
        out.clear();
        let (mut err, mut n) = (0f32, 0usize);
        for (l, grid) in grids
            .iter()
            .enumerate()
            .take(alloc.sym_start + alloc.n_sym)
            .skip(alloc.sym_start)
        {
            let rot = Complex32::from_polar(1.0, slope * l as f32);
            for rb in 0..n_rb {
                let chan = h_avg[rb] * rot;
                let w = chan.norm_sqr().max(1e-12);
                for k in 0..12 {
                    if !is_data(l, rb, k) {
                        continue;
                    }
                    let y = grid[sc_to_bin(12 * prb[rb] + k)] * chan.conj() / w;
                    err += demapper.demap(y, w, out);
                    n += 1;
                }
            }
        }
        (err / n.max(1) as f32).sqrt()
    };

    // A residual CFO shows up as a per-symbol phase ramp shared by all
    // subcarriers. Estimate its slope from the DM-RS symbols' average phase.
    let sym_phase: Vec<f32> = (0..dmrs_syms.len())
        .map(|si| {
            h[si * n_rb..(si + 1) * n_rb]
                .iter()
                .copied()
                .sum::<Complex32>()
                .arg()
        })
        .collect();
    let mut data: Vec<f32> = Vec::new();
    let slope = if dmrs_syms.len() >= 3 {
        // Resolve the 2π ambiguity of the first pair by collinearity with the
        // third DM-RS symbol.
        let (l0, l1, l2) = (
            dmrs_syms[0] as f32,
            dmrs_syms[1] as f32,
            dmrs_syms[2] as f32,
        );
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
        // Two DM-RS symbols pin the slope only modulo `2π/gap`: a wideband
        // residual CFO can exceed ±π over the gap and wrap, so pick the alias
        // whose de-rotation minimises the data EVM (the true slope gives a
        // clean constellation, the aliases a rotated one).
        let gap = dmrs_syms[1] as f32 - dmrs_syms[0] as f32;
        let base = (sym_phase[1] - sym_phase[0]) / gap;
        let mut best = (base, f32::MAX);
        for k in -3..=3 {
            let s = base + k as f32 * TAU / gap;
            let e = equalize(s, &mut data, &mut h_avg);
            if e < best.1 {
                best = (s, e);
            }
        }
        best.0
    } else {
        0.0
    };
    let evm = equalize(slope, &mut data, &mut h_avg);

    let n_data_re = data.len() / alloc.qm;
    PdschLlrs {
        llrs: data,
        dmrs_metric,
        evm,
        n_data_re,
        cfo_slope: slope,
    }
}

/// Invert a 2×2 complex matrix given as `[[a, b], [c, d]]` (row major).
fn inv2(m: [[Complex32; 2]; 2]) -> Option<[[Complex32; 2]; 2]> {
    let det = m[0][0] * m[1][1] - m[0][1] * m[1][0];
    if det.norm_sqr() < 1e-20 {
        return None;
    }
    let inv = Complex32::new(1.0, 0.0) / det;
    Some([
        [m[1][1] * inv, -m[0][1] * inv],
        [-m[1][0] * inv, m[0][0] * inv],
    ])
}

/// Multi-antenna, multi-layer PDSCH extraction: `grids[a][l]` is the
/// resource grid of symbol `l` on receive antenna `a`; `ports` the DM-RS
/// ports of the layers (type 1, `maxLength = 1`: ports 0/1 share CDM group 0
/// with the frequency OCC `[+1, +1]` / `[+1, −1]` over each RE pair, ports
/// 2/3 the same in group 1, TS 38.211 §7.4.1.1.2). Per RB and layer the
/// channel of every antenna is estimated from the DM-RS (de-rotated by the
/// residual-CFO slope of antenna 0 / the first port, as [`extract_pdsch`]),
/// the noise variance from the spread of the pair estimates, and every data
/// RE is equalised with a regularised zero-forcing (MMSE) combiner; the
/// LLRs come out in codeword order (layer 0 then layer 1 of each RE,
/// TS 38.211 §7.3.1.3).
pub fn extract_pdsch_mimo(
    grids: &[Vec<Vec<Complex32>>],
    sc_to_bin: impl Fn(usize) -> usize,
    alloc: &PdschAlloc,
    slot: u32,
    rm_skip: Option<&dyn Fn(usize, usize, usize) -> bool>,
    ports: &[u8],
) -> PdschLlrs {
    let n_ant = grids.len();
    let n_lay = ports.len().clamp(1, 2);
    let ports: Vec<u8> = ports.iter().take(n_lay).copied().collect();
    let n_rb = alloc.n_rb;
    let prb = alloc.prbs();
    let dmrs_syms = &alloc.dmrs_symbols;
    let seq_base = alloc.dmrs_seq_base();
    let ref_len = seq_base + 6 * (prb.iter().copied().max().map_or(0, |p| p + 1));
    let n_sym = dmrs_syms.len();
    let empty = PdschLlrs {
        llrs: Vec::new(),
        dmrs_metric: 0.0,
        evm: 1.0,
        n_data_re: 0,
        cfo_slope: 0.0,
    };
    if n_ant == 0 || n_sym == 0 || n_rb == 0 {
        return empty;
    }
    // h[((si · n_ant + a) · n_lay + p) · n_rb + rb]: per DM-RS symbol, antenna, layer, RB.
    let idx = |si: usize, a: usize, p: usize, rb: usize| ((si * n_ant + a) * n_lay + p) * n_rb + rb;
    let mut h = vec![Complex32::new(0.0, 0.0); n_sym * n_ant * n_lay * n_rb];
    let mut noise_acc = 0f32;
    let mut noise_n = 0usize;
    let mut corr_pow = 0f32;
    let mut per_sym_corr = vec![Complex32::new(0.0, 0.0); n_sym];
    for (si, &l) in dmrs_syms.iter().enumerate() {
        let full_ref =
            pdsch_dmrs_sequence(alloc.scrambling_id, alloc.n_scid, slot, l as u32, ref_len);
        for a in 0..n_ant {
            let grid = &grids[a][l];
            for (rb, &p_rb) in prb.iter().enumerate() {
                for (p, &port) in ports.iter().enumerate() {
                    let delta = usize::from(port / 2);
                    let occ = if port % 2 == 1 { -1.0f32 } else { 1.0 };
                    let mut pairs = [Complex32::new(0.0, 0.0); 3];
                    for (n, pair) in pairs.iter_mut().enumerate() {
                        let y0 = grid[sc_to_bin(12 * p_rb + 4 * n + delta)];
                        let y1 = grid[sc_to_bin(12 * p_rb + 4 * n + 2 + delta)];
                        let r0 = full_ref[seq_base + 6 * p_rb + 2 * n];
                        let r1 = full_ref[seq_base + 6 * p_rb + 2 * n + 1];
                        *pair = (y0 * r0.conj() + occ * y1 * r1.conj()) / 2.0;
                        if a == 0 && p == 0 {
                            corr_pow += y0.norm_sqr() + y1.norm_sqr();
                        }
                    }
                    let mean = (pairs[0] + pairs[1] + pairs[2]) / 3.0;
                    h[idx(si, a, p, rb)] = mean;
                    for pr in &pairs {
                        // A pair estimate averages two REs: its variance is half the RE noise.
                        noise_acc += 2.0 * (pr - mean).norm_sqr();
                        noise_n += 1;
                    }
                    if a == 0 && p == 0 {
                        per_sym_corr[si] += mean * 6.0;
                    }
                }
            }
        }
    }
    let n_dmrs_re = n_sym * n_rb * 6;
    let dmrs_metric = if corr_pow > 0.0 {
        per_sym_corr.iter().map(|c| c.norm()).sum::<f32>()
            / (corr_pow.sqrt() * (n_dmrs_re as f32).sqrt())
    } else {
        0.0
    };
    // The spread of the three pair estimates of a port also contains the
    // frequency selectivity within the RB and the other port's leakage: a
    // floor keeps the regularisation sane on a clean channel.
    let noise = (noise_acc / noise_n.max(1) as f32).max(1e-6);

    let boost = match alloc.nof_cdm_groups_without_data {
        0 | 1 => 1.0f32,
        2 => std::f32::consts::FRAC_1_SQRT_2,
        _ => 1.0 / 3f32.sqrt(),
    };
    let demapper = Demapper::new(alloc.qm);
    let is_data = |l: usize, rb: usize, k: usize| {
        alloc.is_data_re(l, k) && !rm_skip.is_some_and(|f| f(l, prb[rb], k))
    };

    // Average the de-rotated per-symbol estimates for a candidate CFO slope:
    // havg[(a · n_lay + p) · n_rb + rb].
    let havg_for = |slope: f32, havg: &mut Vec<Complex32>| {
        havg.clear();
        havg.resize(n_ant * n_lay * n_rb, Complex32::new(0.0, 0.0));
        for (si, &ls) in dmrs_syms.iter().enumerate() {
            let derot = Complex32::from_polar(1.0, -slope * ls as f32);
            for a in 0..n_ant {
                for p in 0..n_lay {
                    for rb in 0..n_rb {
                        havg[(a * n_lay + p) * n_rb + rb] += h[idx(si, a, p, rb)] * derot;
                    }
                }
            }
        }
        for v in havg.iter_mut() {
            *v *= boost / n_sym as f32;
        }
    };
    let mut havg: Vec<Complex32> = Vec::new();
    let equalize = |slope: f32, out: &mut Vec<f32>, havg: &mut Vec<Complex32>| -> f32 {
        havg_for(slope, havg);
        out.clear();
        let (mut err, mut n) = (0f32, 0usize);
        for (l, _) in grids[0]
            .iter()
            .enumerate()
            .take(alloc.sym_start + alloc.n_sym)
            .skip(alloc.sym_start)
        {
            let rot = Complex32::from_polar(1.0, slope * l as f32);
            for rb in 0..n_rb {
                // H (n_ant × n_lay) of this RB and symbol.
                let hh = |a: usize, p: usize| havg[(a * n_lay + p) * n_rb + rb] * rot;
                // G = Hᴴ H + σ² I and its inverse (n_lay ≤ 2).
                let mut g = [[Complex32::new(0.0, 0.0); 2]; 2];
                for p in 0..n_lay {
                    for q in 0..n_lay {
                        let mut s = Complex32::new(0.0, 0.0);
                        for a in 0..n_ant {
                            s += hh(a, p).conj() * hh(a, q);
                        }
                        g[p][q] = s;
                    }
                    g[p][p] += noise;
                }
                let ginv = if n_lay == 1 {
                    [
                        [Complex32::new(1.0, 0.0) / g[0][0], Complex32::new(0.0, 0.0)],
                        [Complex32::new(0.0, 0.0), Complex32::new(0.0, 0.0)],
                    ]
                } else {
                    match inv2(g) {
                        Some(m) => m,
                        None => continue,
                    }
                };
                // Per-layer gain: 1 / [G⁻¹]ₚₚ (= |h|² for one layer, one antenna).
                let gains: Vec<f32> = (0..n_lay)
                    .map(|p| (1.0 / ginv[p][p].re.max(1e-12)) - noise)
                    .map(|v| v.max(1e-9))
                    .collect();
                for k in 0..12 {
                    if !is_data(l, rb, k) {
                        continue;
                    }
                    let bin = sc_to_bin(12 * prb[rb] + k);
                    // z = Hᴴ y, x̂ = G⁻¹ z, unbiased by the diagonal of G⁻¹ Hᴴ H.
                    let mut z = [Complex32::new(0.0, 0.0); 2];
                    for p in 0..n_lay {
                        for a in 0..n_ant {
                            z[p] += hh(a, p).conj() * grids[a][l][bin];
                        }
                    }
                    for p in 0..n_lay {
                        let mut x = Complex32::new(0.0, 0.0);
                        let mut bias = Complex32::new(0.0, 0.0);
                        for q in 0..n_lay {
                            x += ginv[p][q] * z[q];
                            bias += ginv[p][q]
                                * (g[q][p]
                                    - if q == p {
                                        Complex32::new(noise, 0.0)
                                    } else {
                                        Complex32::new(0.0, 0.0)
                                    });
                        }
                        let x = if bias.norm_sqr() > 1e-12 { x / bias } else { x };
                        err += demapper.demap(x, gains[p], out);
                        n += 1;
                    }
                }
            }
        }
        (err / n.max(1) as f32).sqrt()
    };

    // Residual-CFO slope from antenna 0 / first port (see `extract_pdsch`).
    let sym_phase: Vec<f32> = (0..n_sym)
        .map(|si| {
            (0..n_rb)
                .map(|rb| h[idx(si, 0, 0, rb)])
                .sum::<Complex32>()
                .arg()
        })
        .collect();
    let mut data: Vec<f32> = Vec::new();
    let slope = if n_sym >= 3 {
        let (l0, l1, l2) = (
            dmrs_syms[0] as f32,
            dmrs_syms[1] as f32,
            dmrs_syms[2] as f32,
        );
        let mut best = (0f32, f32::MAX);
        for k in -3..=3 {
            let s = (sym_phase[1] - sym_phase[0] + k as f32 * TAU) / (l1 - l0);
            let pred = sym_phase[0] + s * (l2 - l0);
            let e = ((pred - sym_phase[2] + PI).rem_euclid(TAU) - PI).abs();
            if e < best.1 {
                best = (s, e);
            }
        }
        best.0
    } else if n_sym == 2 {
        let gap = dmrs_syms[1] as f32 - dmrs_syms[0] as f32;
        let base = (sym_phase[1] - sym_phase[0]) / gap;
        let mut best = (base, f32::MAX);
        for k in -3..=3 {
            let s = base + k as f32 * TAU / gap;
            let e = equalize(s, &mut data, &mut havg);
            if e < best.1 {
                best = (s, e);
            }
        }
        best.0
    } else {
        0.0
    };
    let evm = equalize(slope, &mut data, &mut havg);
    let n_data_re = data.len() / (alloc.qm * n_lay).max(1);
    PdschLlrs {
        llrs: data,
        dmrs_metric,
        evm,
        n_data_re,
        cfo_slope: slope,
    }
}

/// PDSCH data-scrambling `c_init` (§7.3.1.1): `n_RNTI·2^15 + q·2^14 + n_ID`
/// (codeword `q = 0`). `n_ID` is `dataScramblingIdentityPDSCH` when configured
/// and the RNTI is a C-RNTI/MCS-C-RNTI/CS-RNTI in a USS, else `N_cell_ID`.
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
    fn dmrs_depends_on_symbol_slot_and_scid() {
        assert_ne!(pdsch_dmrs(1, 1, 2, 20), pdsch_dmrs(1, 1, 7, 20));
        assert_ne!(pdsch_dmrs(1, 1, 2, 20), pdsch_dmrs(1, 2, 2, 20));
        assert_ne!(
            pdsch_dmrs_sequence(1, 0, 1, 2, 20),
            pdsch_dmrs_sequence(1, 1, 1, 2, 20)
        );
        assert_eq!(pdsch_dmrs_sequence(7, 0, 3, 2, 20), pdsch_dmrs(7, 3, 2, 20));
    }

    #[test]
    fn coreset0_interleaver_matches_reference() {
        // 24 RB, L = 2: 12 bundles, R = 2, C = 6; f(j = 2c + r) = 6r + c.
        let t = coreset0_vrb_to_prb(24);
        assert_eq!(&t[0..2], &[0, 1]); // bundle 0 → 0
        assert_eq!(&t[2..4], &[12, 13]); // bundle 1 (c=0,r=1) → 6
        assert_eq!(&t[4..6], &[2, 3]); // bundle 2 (c=1,r=0) → 1
        assert_eq!(&t[22..24], &[22, 23]); // last bundle → itself
        let mut sorted = t.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..24).collect::<Vec<_>>(), "permutation");
        // Odd CORESET size: last bundle is a single RB.
        let t = coreset0_vrb_to_prb(45);
        assert_eq!(t[44], 44);
        let mut sorted = t.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..45).collect::<Vec<_>>());
    }

    #[test]
    fn general_interleaver_handles_bwp_start_offset() {
        // BWP start 3, size 20, L = 4: first bundle holds 1 RB (4 − 3 mod 4),
        // N_bundle = ⌈(20 + 3)/4⌉ = 6, last = (3 + 20) mod 4 = 3 RBs.
        let t = interleaved_vrb_to_prb(20, 3, 4);
        let mut sorted = t.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..20).collect::<Vec<_>>(), "permutation");
        assert_eq!(t[0], 0, "first bundle maps to itself (j = 0 → f = 0)");
        // Bundle 1 (c=0, r=1) → f = 1·3 + 0 = 3: VRB 1..5 → PRB 1 + 2·4 = 9..13.
        assert_eq!(&t[1..5], &[9, 10, 11, 12]);
        // Last bundle (3 RBs) maps to itself.
        assert_eq!(&t[17..20], &[17, 18, 19]);
    }

    #[test]
    fn data_re_bookkeeping() {
        let alloc = PdschAlloc {
            rb_start: 0,
            n_rb: 1,
            bwp_start_crb: 0,
            dmrs_ref_crb: 0,
            sym_start: 2,
            n_sym: 12,
            dmrs_symbols: vec![2, 7, 11],
            nof_cdm_groups_without_data: 2,
            qm: 2,
            vrb_to_prb: VrbToPrb::NonInterleaved,
            n_scid: 0,
            scrambling_id: 1,
        };
        assert_eq!(alloc.data_re_per_prb(), 9 * 12);
        let one = PdschAlloc {
            nof_cdm_groups_without_data: 1,
            ..alloc.clone()
        };
        assert_eq!(one.data_re_per_prb(), 9 * 12 + 3 * 6);
        assert!(one.is_data_re(2, 1) && !one.is_data_re(2, 0));
    }

    /// Two layers on two antennas through a full-rank channel: the per-port
    /// DM-RS (OCC over RE pairs) separates the layers and the MMSE combiner
    /// recovers both bit streams; a single layer over two antennas (MRC) and
    /// the 1x1 case go through the same path.
    #[test]
    fn mimo_extraction_recovers_two_layers() {
        let cell_id = 1u16;
        let slot = 3u32;
        let n_rb = 8usize;
        let alloc = PdschAlloc {
            rb_start: 2,
            n_rb,
            bwp_start_crb: 0,
            dmrs_ref_crb: 0,
            sym_start: 2,
            n_sym: 12,
            dmrs_symbols: vec![2, 7, 11],
            nof_cdm_groups_without_data: 1,
            qm: 4,
            vrb_to_prb: VrbToPrb::NonInterleaved,
            n_scid: 0,
            scrambling_id: cell_id,
        };
        let prbs = alloc.prbs();
        let dm = Demapper::new(4);
        let mut seed = 0xBEEFu64;
        let mut bit = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 33) & 1) as u8
        };
        let sym = |b: &[u8]| {
            let label = |axis: usize| (usize::from(b[axis]) << 1) | usize::from(b[2 + axis]);
            Complex32::new(dm.levels[label(0)], dm.levels[label(1)]) / dm.scale
        };
        let run = |hm: Vec<Vec<Complex32>>, bit: &mut dyn FnMut() -> u8| -> (PdschLlrs, Vec<u8>) {
            let (n_ant, n_lay) = (hm.len(), hm[0].len());
            let slope = 0.3f32;
            let mut grids = vec![vec![vec![Complex32::new(0.0, 0.0); 12 * 24]; 14]; n_ant];
            let mut tx_bits = Vec::new();
            for l in alloc.sym_start..alloc.sym_start + alloc.n_sym {
                let rot = Complex32::from_polar(1.0, slope * l as f32);
                let dmrs = alloc
                    .dmrs_symbols
                    .contains(&l)
                    .then(|| pdsch_dmrs_sequence(cell_id, 0, slot, l as u32, 6 * 24));
                for &p in &prbs {
                    for k in 0..12 {
                        // Layer symbols at this RE: DM-RS (ports 0/1, OCC on k' = 1) or data.
                        let x: Vec<Complex32> = if let (Some(d), true) = (&dmrs, k % 2 == 0) {
                            let (n, kp) = (k / 4, (k / 2) % 2);
                            let r = d[6 * p + 2 * n + kp];
                            (0..n_lay)
                                .map(|q| if q == 1 && kp == 1 { -r } else { r })
                                .collect()
                        } else if alloc.is_data_re(l, k) {
                            (0..n_lay)
                                .map(|_| {
                                    let b: Vec<u8> = (0..4).map(|_| bit()).collect();
                                    tx_bits.extend_from_slice(&b);
                                    sym(&b)
                                })
                                .collect()
                        } else {
                            continue;
                        };
                        for (a, g) in grids.iter_mut().enumerate() {
                            let y: Complex32 = (0..n_lay).map(|q| hm[a][q] * x[q]).sum();
                            g[l][12 * p + k] = y * rot;
                        }
                    }
                }
            }
            let ports: Vec<u8> = (0..n_lay as u8).collect();
            (
                extract_pdsch_mimo(&grids, |sc| sc, &alloc, slot, None, &ports),
                tx_bits,
            )
        };
        let errors = |out: &PdschLlrs, tx: &[u8]| {
            out.llrs
                .iter()
                .zip(tx)
                .filter(|(&l, &b)| (l < 0.0) as u8 != b)
                .count()
        };
        // 2x2 full rank.
        let h22 = vec![
            vec![Complex32::new(0.9, 0.1), Complex32::new(0.2, -0.3)],
            vec![Complex32::new(-0.25, 0.4), Complex32::new(0.8, 0.2)],
        ];
        let (out, tx) = run(h22, &mut bit);
        assert_eq!(out.llrs.len(), tx.len());
        assert!(out.dmrs_metric > 0.5, "dmrs metric {}", out.dmrs_metric);
        assert!(
            (out.cfo_slope - 0.3).abs() < 0.03,
            "slope {}",
            out.cfo_slope
        );
        assert_eq!(errors(&out, &tx), 0, "2x2: evm {}", out.evm);
        assert_eq!(out.n_data_re, n_rb * alloc.data_re_per_prb());
        // 2x2 identity (the ZMQ wiring).
        let (out, tx) = run(
            vec![
                vec![Complex32::new(1.0, 0.0), Complex32::new(0.0, 0.0)],
                vec![Complex32::new(0.0, 0.0), Complex32::new(1.0, 0.0)],
            ],
            &mut bit,
        );
        assert_eq!(errors(&out, &tx), 0, "identity: evm {}", out.evm);
        // One layer, two antennas (MRC) and the plain 1x1 case.
        let (out, tx) = run(
            vec![
                vec![Complex32::new(0.7, 0.2)],
                vec![Complex32::new(-0.3, 0.6)],
            ],
            &mut bit,
        );
        assert_eq!(errors(&out, &tx), 0, "mrc: evm {}", out.evm);
        let (out, tx) = run(vec![vec![Complex32::from_polar(0.8, 0.4)]], &mut bit);
        assert_eq!(errors(&out, &tx), 0, "1x1: evm {}", out.evm);
        assert!(out.evm < 0.05, "1x1 evm {}", out.evm);
    }

    #[test]
    fn demapper_constellations_match_38_211() {
        // 16QAM: bits (b0 b1 b2 b3) = (0 0 1 1) → I = (2+1)/√10, Q = (2+1)/√10.
        let d = Demapper::new(4);
        assert_eq!(d.levels[0b01], 3.0); // b0=0, b2=1 → +3
        assert_eq!(d.levels[0b00], 1.0);
        assert_eq!(d.levels[0b10], -1.0);
        assert_eq!(d.levels[0b11], -3.0);
        // 64QAM label (b0 b2 b4) = (0 1 0) → 4 + (2 − 1) = 5.
        let d = Demapper::new(6);
        assert_eq!(d.levels[0b010], 5.0);
        assert_eq!(d.levels[0b011], 7.0);
        assert_eq!(d.levels[0b001], 1.0); // 4 − (2 + 1)
        assert_eq!(d.levels[0b000], 3.0); // 4 − (2 − 1)
                                          // 256QAM label (0 1 1 1) → 8 + (4 + (2 + 1)) = 15.
        let d = Demapper::new(8);
        assert_eq!(d.levels[0b0111], 15.0);
        assert_eq!(d.levels[0b0100], 11.0); // 8 + (4 − (2 − 1))
    }

    /// Modulate random bits at every Q_m, demap the clean symbols and check the
    /// LLR signs recover the bits in §5.1.3 bit order.
    /// A rate-0.93 256-QAM single-codeblock TB (the MCS 27 / 2-PRB case OCUDU
    /// schedules at CQI 15) must decode from a clean and from a 34 dB SNR
    /// (EVM 2 %) constellation within the worker's iteration budget.
    #[test]
    fn high_rate_256qam_decodes() {
        use crate::coding::dlsch::{dlsch_decode_single_bits, dlsch_encode_single};
        use crate::pusch::qam_modulate;
        let tbs = 1416usize;
        let r = 948.0 / 1024.0;
        let qm = 8usize;
        let n_re = 192usize;
        let e = n_re * qm;
        let mut seed = 0x1234_5678u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 11) as f32 / (1u64 << 53) as f32
        };
        let tb: Vec<u8> = (0..tbs).map(|_| (rnd() < 0.5) as u8).collect();
        let coded = dlsch_encode_single(&tb, e, r, qm, 0);
        assert_eq!(coded.len(), e);
        for (evm, iters) in [(0.0f32, 12usize), (0.02, 12), (0.02, 30)] {
            let d = Demapper::new(qm);
            let mut llr = Vec::with_capacity(e);
            for sym in coded.chunks(qm) {
                let mut y = qam_modulate(sym);
                if evm > 0.0 {
                    let g = |r1: f32, r2: f32| {
                        (-2.0 * r1.max(1e-9).ln()).sqrt() * (std::f32::consts::TAU * r2).cos()
                    };
                    y += Complex32::new(g(rnd(), rnd()), g(rnd(), rnd())) * (evm / 2f32.sqrt());
                }
                d.demap(y, 1.0, &mut llr);
            }
            let (bits, _conv, crc) = dlsch_decode_single_bits(&llr, tbs, r, qm, 0, iters);
            assert!(
                crc && bits == tb,
                "rate 0.93 256-QAM failed at evm {evm} with {iters} iterations"
            );
        }
    }

    #[test]
    fn demapper_roundtrip_all_orders() {
        let mut seed = 0x1234_5678_9ABCu64;
        let mut bit = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 33) & 1) as u8
        };
        for qm in [2usize, 4, 6, 8] {
            let d = Demapper::new(qm);
            let m = qm / 2;
            for _ in 0..200 {
                let bits: Vec<u8> = (0..qm).map(|_| bit()).collect();
                let label = |axis: usize| {
                    (0..m).fold(0usize, |a, i| (a << 1) | usize::from(bits[2 * i + axis]))
                };
                let y = Complex32::new(d.levels[label(0)], d.levels[label(1)]) / d.scale;
                let mut out = Vec::new();
                let err = d.demap(y, 1.0, &mut out);
                assert!(err < 1e-6);
                assert_eq!(out.len(), qm);
                for (i, (&l, &b)) in out.iter().zip(&bits).enumerate() {
                    assert!((l < 0.0) as u8 == b, "qm={qm} bit {i}: llr {l} for bit {b}");
                }
            }
        }
    }

    /// Full RE-level loop: map DM-RS + 16QAM data onto a slot with a residual
    /// CFO phase ramp and 2 CDM groups without data, then extract; the LLR signs
    /// must reproduce the bits in mapping order (symbol-outer, k-inner).
    #[test]
    fn extract_recovers_bits_under_cfo_ramp() {
        let (n_rb, slot, cell_id) = (6usize, 3u32, 17u16);
        let alloc = PdschAlloc {
            rb_start: 2,
            n_rb,
            bwp_start_crb: 0,
            dmrs_ref_crb: 0,
            sym_start: 2,
            n_sym: 12,
            dmrs_symbols: vec![2, 7, 11],
            nof_cdm_groups_without_data: 1,
            qm: 4,
            vrb_to_prb: VrbToPrb::coreset0(24),
            n_scid: 0,
            scrambling_id: cell_id,
        };
        let prbs = alloc.prbs();
        let dm = Demapper::new(4);
        let mut seed = 0xACE1u64;
        let mut bit = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 33) & 1) as u8
        };
        let h = Complex32::from_polar(0.8, 0.4);
        let slope = 0.9f32; // rad/symbol residual CFO
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); 12 * 24]; 14];
        let mut tx_bits = Vec::new();
        for (l, grid) in grids
            .iter_mut()
            .enumerate()
            .take(alloc.sym_start + alloc.n_sym)
            .skip(alloc.sym_start)
        {
            let rot = h * Complex32::from_polar(1.0, slope * l as f32);
            let dmrs = alloc
                .dmrs_symbols
                .contains(&l)
                .then(|| pdsch_dmrs(cell_id, slot, l as u32, 6 * 24));
            for &p in &prbs {
                for k in 0..12 {
                    let s = if let (Some(d), true) = (&dmrs, k % 2 == 0) {
                        d[6 * p + k / 2]
                    } else if alloc.is_data_re(l, k) {
                        let b: Vec<u8> = (0..4).map(|_| bit()).collect();
                        tx_bits.extend_from_slice(&b);
                        let label =
                            |axis: usize| (usize::from(b[axis]) << 1) | usize::from(b[2 + axis]);
                        Complex32::new(dm.levels[label(0)], dm.levels[label(1)]) / dm.scale
                    } else {
                        continue;
                    };
                    grid[12 * p + k] = s * rot;
                }
            }
        }
        let out = extract_pdsch(&grids, |sc| sc, &alloc, slot, None);
        assert!(out.dmrs_metric > 0.99, "dmrs metric {}", out.dmrs_metric);
        assert!(out.evm < 0.05, "evm {}", out.evm);
        assert!(
            (out.cfo_slope - slope).abs() < 0.02,
            "slope {}",
            out.cfo_slope
        );
        assert_eq!(out.llrs.len(), tx_bits.len());
        assert_eq!(out.n_data_re, n_rb * alloc.data_re_per_prb());
        let errors = out
            .llrs
            .iter()
            .zip(&tx_bits)
            .filter(|(&l, &b)| (l < 0.0) as u8 != b)
            .count();
        assert_eq!(errors, 0);

        // Rate matching around a CSI-RS RE drops exactly those LLRs.
        let skip = |l: usize, _prb: usize, k: usize| l == 4 && k == 1;
        let rm = extract_pdsch(&grids, |sc| sc, &alloc, slot, Some(&skip));
        assert_eq!(rm.n_data_re, out.n_data_re - n_rb);
    }
}
