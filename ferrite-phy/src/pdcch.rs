//! PDCCH reception: CORESET geometry, search-space candidates, DMRS channel
//! estimation and candidate equalization.
//!
//! * CORESET model (TS 38.331 `ControlResourceSet`): any set of 6-RB groups
//!   (or a contiguous range), 1–3 symbols, interleaved or non-interleaved
//!   CCE→REG mapping with the general `(L, R, n_shift)` interleaver of
//!   TS 38.211 §7.3.2.2, REGs numbered time-first (symbol fastest, then RB)
//!   starting at the lowest RB.
//! * PDCCH DMRS (§7.4.1.3): Gold-seeded QPSK on subcarriers `4k' + 1`; the
//!   sequence reference is the CORESET's lowest RB for CORESET 0 (configured
//!   by the PBCH / `controlResourceSetZero`), CRB 0 otherwise
//!   ([`Coreset::dmrs_ref_crb`]).
//! * Search spaces (TS 38.213 §10.1): monitoring occasions and the CCE hashing
//!   for common (`Y = 0`) and UE-specific (`Y_{p,n}` recursion) search spaces.
//! * Mapping order: a candidate's modulation symbols fill its non-DMRS REs in
//!   increasing symbol `l`, then subcarrier `k` (validated against a live gNB:
//!   the decoded RIV matched the gNB's own SIB1 allocation).

use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

use crate::coreset0::Coreset0Config;
use crate::sequence::gold_sequence;
use ferrite_common::SlotPoint;

/// Maximum number of 6-RB groups in `frequencyDomainResources` (TS 38.331).
pub const CORESET_RB_GROUPS: usize = 45;
/// REGs per CCE (§7.3.2.2).
pub const REGS_PER_CCE: usize = 6;
/// DMRS REs per REG (subcarriers 1, 5, 9).
const DMRS_PER_REG: usize = 3;

/// CCE-to-REG mapping of a CORESET (§7.3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CceToRegMapping {
    /// `L = 6`, `f(x) = x`.
    NonInterleaved,
    /// Bundles of `reg_bundle_size` REGs (`L`: 2 or 6 for 1 symbol, `N_symb`
    /// or 6 otherwise), interleaver rows `interleaver_size` (`R`: 2, 3, 6),
    /// `shift_index` (`n_shift`: `shiftIndex` if configured, else the cell ID;
    /// the cell ID for CORESET 0).
    Interleaved {
        reg_bundle_size: usize,
        interleaver_size: usize,
        shift_index: u16,
    },
}

/// `precoderGranularity` (TS 38.331): whether the DMRS of a REG bundle may be
/// assumed precoded identically only within the bundle or across all the
/// CORESET's contiguous RBs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecoderGranularity {
    SameAsRegBundle,
    AllContiguousRbs,
}

/// A control resource set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coreset {
    /// `controlResourceSetId` (0 for CORESET 0).
    pub id: u8,
    /// Common resource blocks of the CORESET, ascending. For CORESET 0 before
    /// SIB1 is known the caller may number CRBs relative to the CORESET's
    /// lowest RB (`first_crb = 0`).
    pub rbs: Vec<usize>,
    /// Duration in OFDM symbols (1..=3).
    pub n_symb: usize,
    pub mapping: CceToRegMapping,
    pub precoder_granularity: PrecoderGranularity,
    /// `N_ID` of the DMRS: `pdcch-DMRS-ScramblingID` if configured, else the
    /// cell ID.
    pub dmrs_scrambling_id: u16,
    /// Reference CRB of the DMRS sequence (§7.4.1.3.2): the CORESET's lowest
    /// RB for CORESET 0, CRB 0 otherwise. DMRS RE `k'` of CRB `n` takes
    /// `r(3·(n − dmrs_ref_crb) + k')`.
    pub dmrs_ref_crb: usize,
}

impl Coreset {
    /// A contiguous CORESET of `n_rb` RBs from CRB `first_crb`, DMRS referenced
    /// at CRB 0 and `sameAsREG-bundle` precoding.
    pub fn contiguous(
        id: u8,
        first_crb: usize,
        n_rb: usize,
        n_symb: usize,
        mapping: CceToRegMapping,
        dmrs_scrambling_id: u16,
    ) -> Self {
        Self {
            id,
            rbs: (first_crb..first_crb + n_rb).collect(),
            n_symb,
            mapping,
            precoder_granularity: PrecoderGranularity::SameAsRegBundle,
            dmrs_scrambling_id,
            dmrs_ref_crb: 0,
        }
    }

    /// A CORESET from `frequencyDomainResources`: `groups[i]` is bit `i`
    /// (group 0 = the first / most significant bit), each group covering 6
    /// CRBs; the first group starts at CRB `6·⌈N_BWP_start/6⌉` (§7.3.2.2).
    #[allow(clippy::too_many_arguments)]
    pub fn from_bitmap(
        id: u8,
        bwp_start_crb: usize,
        groups: &[bool],
        n_symb: usize,
        mapping: CceToRegMapping,
        precoder_granularity: PrecoderGranularity,
        dmrs_scrambling_id: u16,
    ) -> Self {
        let base = 6 * bwp_start_crb.div_ceil(6);
        let rbs = groups
            .iter()
            .take(CORESET_RB_GROUPS)
            .enumerate()
            .filter(|(_, &set)| set)
            .flat_map(|(g, _)| base + 6 * g..base + 6 * g + 6)
            .collect();
        Self {
            id,
            rbs,
            n_symb,
            mapping,
            precoder_granularity,
            dmrs_scrambling_id,
            dmrs_ref_crb: 0,
        }
    }

    /// CORESET 0 from its Table 13-x row (TS 38.213 §13): interleaved with
    /// `L = 6`, `R = 2`, `n_shift = N_cell_ID`, DMRS seeded by the cell ID and
    /// referenced at the CORESET's lowest RB, which is CRB `first_crb`.
    pub fn coreset0(cfg: &Coreset0Config, cell_id: u16, first_crb: usize) -> Self {
        Self {
            id: 0,
            rbs: (first_crb..first_crb + cfg.n_rb).collect(),
            n_symb: cfg.n_symb,
            mapping: CceToRegMapping::Interleaved {
                reg_bundle_size: 6,
                interleaver_size: 2,
                shift_index: cell_id,
            },
            precoder_granularity: PrecoderGranularity::SameAsRegBundle,
            dmrs_scrambling_id: cell_id,
            dmrs_ref_crb: first_crb,
        }
    }

    /// Number of RBs.
    pub fn n_rb(&self) -> usize {
        self.rbs.len()
    }

    /// Number of REGs (`N_RB · N_symb`).
    pub fn n_reg(&self) -> usize {
        self.rbs.len() * self.n_symb
    }

    /// Number of CCEs.
    pub fn n_cce(&self) -> usize {
        self.n_reg() / REGS_PER_CCE
    }

    /// REG bundle size `L`.
    pub fn reg_bundle_size(&self) -> usize {
        match self.mapping {
            CceToRegMapping::NonInterleaved => 6,
            CceToRegMapping::Interleaved { reg_bundle_size, .. } => reg_bundle_size,
        }
    }

    /// REG index → `(symbol, rb_index)`: time-first numbering, `rb_index`
    /// indexing [`Coreset::rbs`].
    pub fn reg_to_symbol_rb(&self, reg: usize) -> (usize, usize) {
        (reg % self.n_symb, reg / self.n_symb)
    }

    /// The REG-bundle interleaver `f(x)` (§7.3.2.2): identity when
    /// non-interleaved, else `f(cR + r) = (rC + c + n_shift) mod (N_REG/L)`
    /// with `C = N_REG/(L·R)`.
    pub fn bundle_interleaver(&self, x: usize) -> usize {
        match self.mapping {
            CceToRegMapping::NonInterleaved => x,
            CceToRegMapping::Interleaved {
                reg_bundle_size: l,
                interleaver_size: r,
                shift_index,
            } => {
                let n_bundles = self.n_reg() / l;
                debug_assert!(n_bundles.is_multiple_of(r), "N_REG must be a multiple of L·R");
                let c_cols = n_bundles / r;
                let (c, rr) = (x / r, x % r);
                (rr * c_cols + c + usize::from(shift_index)) % n_bundles
            }
        }
    }

    /// The REGs `(symbol, rb_index)` of CCE `cce`: bundles `f(6j/L + i)`,
    /// `i ∈ 0..6/L`, each of `L` consecutive REGs.
    pub fn cce_regs(&self, cce: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        let l = self.reg_bundle_size();
        (0..REGS_PER_CCE / l).flat_map(move |i| {
            let bundle = self.bundle_interleaver(REGS_PER_CCE * cce / l + i);
            (bundle * l..bundle * l + l).map(move |reg| self.reg_to_symbol_rb(reg))
        })
    }

    /// All REGs of a candidate, sorted by `(symbol, rb_index)` — the RE mapping
    /// order of its data (symbol-outer, subcarrier-inner).
    pub fn candidate_regs(&self, cand: &Candidate) -> Vec<(usize, usize)> {
        let mut regs: Vec<(usize, usize)> = cand.cces.iter().flat_map(|&c| self.cce_regs(c)).collect();
        regs.sort_unstable();
        regs
    }

    /// DMRS sequence index of DMRS RE `k'` (0..3) of the RB at `rb_index`.
    fn dmrs_seq_index(&self, rb_index: usize, k_prime: usize) -> usize {
        DMRS_PER_REG * (self.rbs[rb_index] - self.dmrs_ref_crb) + k_prime
    }

    /// DMRS sequence length needed to cover the CORESET.
    fn dmrs_seq_len(&self) -> usize {
        self.rbs.last().map_or(0, |&last| DMRS_PER_REG * (last - self.dmrs_ref_crb + 1))
    }
}

/// A PDCCH candidate: its aggregation level and CCE indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub agg_level: usize,
    pub cces: Vec<usize>,
}

/// The §10.1 CCE hashing for one aggregation level: candidate `m` of `L` CCEs
/// starts at `L·((Y + ⌊m·N_CCE/(L·M)⌋ + n_CI) mod ⌊N_CCE/L⌋)`, `n_CI = 0`.
fn hashed_candidates(n_cce: usize, y: u64, l: usize, m_max: usize, out: &mut Vec<Candidate>) {
    if m_max == 0 || n_cce / l == 0 {
        return;
    }
    for m in 0..m_max {
        let base = l * (((y + (m * n_cce / (l * m_max)) as u64) % (n_cce / l) as u64) as usize);
        let cand = Candidate {
            agg_level: l,
            cces: (base..base + l).collect(),
        };
        if !out.contains(&cand) {
            out.push(cand);
        }
    }
}

/// Common-search-space candidates (`Y = 0`) for `(aggregation level,
/// nrofCandidates)` pairs, deduplicated.
pub fn css_candidates(n_cce: usize, al_counts: &[(usize, usize)]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for &(l, m_max) in al_counts {
        hashed_candidates(n_cce, 0, l, m_max, &mut out);
    }
    out
}

/// The distinct Type0-PDCCH CSS candidates (TS 38.213 Table 10.1-1: 4 at AL4,
/// 2 at AL8, 1 at AL16).
pub fn type0_candidates(n_cce: usize) -> Vec<Candidate> {
    css_candidates(n_cce, &[(4, 4), (8, 2), (16, 1)])
}

/// `Y_{p,n_s}` of the UE-specific search space hashing (§10.1):
/// `Y_{p,n} = (A_p·Y_{p,n-1}) mod 65537`, `Y_{p,-1} = n_RNTI`, `A_p` by
/// `p mod 3` (39827, 39829, 39839), iterated to the slot in the frame.
pub fn uss_y(coreset_id: u8, rnti: u16, slot_in_frame: u32) -> u64 {
    const D: u64 = 65537;
    let a = match coreset_id % 3 {
        0 => 39827u64,
        1 => 39829,
        _ => 39839,
    };
    let mut y = u64::from(rnti);
    for _ in 0..=slot_in_frame {
        y = (a * y) % D;
    }
    y
}

/// UE-specific search-space candidates for CORESET `coreset_id`, C-RNTI
/// `rnti`, slot-in-frame `slot`, and `(aggregation level, nrofCandidates)`
/// pairs from the SearchSpace configuration.
pub fn uss_candidates(
    n_cce: usize,
    coreset_id: u8,
    rnti: u16,
    slot: u32,
    al_counts: &[(usize, usize)],
) -> Vec<Candidate> {
    let y = uss_y(coreset_id, rnti, slot);
    let mut out = Vec::new();
    for &(l, m_max) in al_counts {
        hashed_candidates(n_cce, y, l, m_max, &mut out);
    }
    out
}

/// Every CCE-aligned candidate on a CORESET for each aggregation level in
/// `als`: candidate `m` of level `L` occupies CCEs `[m·L, m·L+L)`. An
/// exhaustive superset of any hashed search space, for blind decoding when the
/// SearchSpace configuration is not (yet) parsed; sound because the 24-bit
/// RNTI-masked CRC rejects empty positions, and cheap on small CORESETs. Note
/// that OCUDU's auto-configured UE-specific search space declares
/// `nrofCandidates` = `N_CCE/L` (capped at 8) for AL1/AL2/AL4 and 0 for
/// AL8/AL16, and the gNB only ever places a PDCCH on a declared candidate, so
/// [`SearchSpace::candidates`] with the RRC-signalled counts covers the same
/// positions once the configuration is known.
pub fn all_candidates(n_cce: usize, als: &[usize]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for &l in als {
        if l == 0 || l > n_cce {
            continue;
        }
        let mut base = 0;
        while base + l <= n_cce {
            out.push(Candidate {
                agg_level: l,
                cces: (base..base + l).collect(),
            });
            base += l;
        }
    }
    out
}

/// Search-space type (TS 38.331 `SearchSpace.searchSpaceType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchSpaceKind {
    /// Common: DCI formats 0_0/1_0 (and 2_x); `Y = 0`.
    Common,
    /// UE-specific: `fallback` selects formats 0_0/1_0 instead of 0_1/1_1.
    UeSpecific { fallback: bool },
}

/// A search space (TS 38.331 `SearchSpace`, TS 38.213 §10.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSpace {
    pub id: u8,
    pub coreset_id: u8,
    /// `monitoringSlotPeriodicityAndOffset`: period and offset in slots.
    pub period_slots: u32,
    pub offset_slots: u32,
    /// `duration`: consecutive monitored slots per occasion (1 if absent).
    pub duration_slots: u32,
    /// `monitoringSymbolsWithinSlot`: first symbols of the PDCCH monitoring
    /// occasions within a monitored slot.
    pub first_symbols: [bool; 14],
    /// `nrofCandidates` for aggregation levels 1, 2, 4, 8, 16.
    pub n_candidates: [u8; 5],
    pub kind: SearchSpaceKind,
}

impl SearchSpace {
    /// The Type0-PDCCH CSS (`searchSpaceZero`) candidate counts of Table
    /// 10.1-1 on CORESET 0, monitored every slot of its occasions (the slot
    /// pattern itself comes from [`crate::coreset0::type0_pdcch_monitoring`]).
    pub fn type0(first_symbol: usize) -> Self {
        let mut first_symbols = [false; 14];
        first_symbols[first_symbol] = true;
        Self {
            id: 0,
            coreset_id: 0,
            period_slots: 1,
            offset_slots: 0,
            duration_slots: 1,
            first_symbols,
            n_candidates: [0, 0, 4, 2, 1],
            kind: SearchSpaceKind::Common,
        }
    }

    /// Whether `slot` is a monitored slot (§10.1): `(SFN·N_slot_frame + n_s −
    /// o_s) mod k_s = 0` for one of the `duration` consecutive slots.
    pub fn is_monitored(&self, slot: SlotPoint) -> bool {
        if self.period_slots == 0 {
            return false;
        }
        let idx = slot.index();
        (0..self.duration_slots.max(1)).any(|d| {
            (idx + u64::from(self.period_slots) * 1024 - u64::from(self.offset_slots) - u64::from(d))
                .is_multiple_of(u64::from(self.period_slots))
        })
    }

    /// `(aggregation level, nrofCandidates)` pairs with non-zero counts.
    pub fn al_counts(&self) -> Vec<(usize, usize)> {
        self.n_candidates
            .iter()
            .enumerate()
            .filter(|(_, &m)| m > 0)
            .map(|(i, &m)| (1usize << i, usize::from(m)))
            .collect()
    }

    /// The PDCCH candidates to monitor in `coreset` for `rnti` in slot
    /// `slot_in_frame` (`Y = 0` for a CSS; the `Y_{p,n}` recursion for a USS).
    pub fn candidates(&self, coreset: &Coreset, rnti: u16, slot_in_frame: u32) -> Vec<Candidate> {
        let counts = self.al_counts();
        match self.kind {
            SearchSpaceKind::Common => css_candidates(coreset.n_cce(), &counts),
            SearchSpaceKind::UeSpecific { .. } => {
                uss_candidates(coreset.n_cce(), coreset.id, rnti, slot_in_frame, &counts)
            }
        }
    }
}

/// PDCCH DMRS sequence `r_l(0..len)` for one OFDM symbol (§7.4.1.3.1):
/// `c_init = (2^17·(14·n_slot + l + 1)·(2·N_ID + 1) + 2·N_ID) mod 2^31`.
pub fn pdcch_dmrs_sequence(n_id: u16, slot: u32, symbol: u32, len: usize) -> Vec<Complex32> {
    let n_id = u64::from(n_id);
    let c_init = (((1u64 << 17) * (14 * u64::from(slot) + u64::from(symbol) + 1) * (2 * n_id + 1) + 2 * n_id)
        % (1 << 31)) as u32;
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

/// Per-REG channel estimate over a whole CORESET, estimated once per slot so
/// every blind-decode candidate reuses it (the DMRS correlation is the
/// expensive part; a REG's estimate is identical for every candidate touching
/// it). Indexed by `(symbol, rb_index)`.
#[derive(Clone, Debug)]
pub struct CoresetEstimate {
    n_rb: usize,
    h: Vec<Complex32>,
}

impl CoresetEstimate {
    /// Channel of REG `(symbol, rb_index)`.
    pub fn get(&self, symbol: usize, rb_index: usize) -> Complex32 {
        self.h[symbol * self.n_rb + rb_index]
    }
}

/// Subcarrier (CRB domain) of DMRS RE `k'` of `crb`.
fn dmrs_sc(crb: usize, k_prime: usize) -> usize {
    12 * crb + 4 * k_prime + 1
}

/// LS channel estimate of one REG from its 3 DMRS REs.
fn estimate_reg(
    grids: &[Vec<Complex32>],
    sc_to_bin: &impl Fn(usize) -> usize,
    coreset: &Coreset,
    dmrs_ref: &[Vec<Complex32>],
    l: usize,
    rb: usize,
) -> Complex32 {
    let mut sum = Complex32::new(0.0, 0.0);
    for k_prime in 0..DMRS_PER_REG {
        let rx = grids[l][sc_to_bin(dmrs_sc(coreset.rbs[rb], k_prime))];
        sum += rx * dmrs_ref[l][coreset.dmrs_seq_index(rb, k_prime)].conj();
    }
    sum / DMRS_PER_REG as f32
}

/// Estimate the per-REG channel across a whole CORESET from its PDCCH DMRS.
/// `grids[l]` is the demodulated grid of CORESET symbol `l` (natural FFT
/// order); `sc_to_bin` maps a CRB-domain subcarrier index (`12·crb + k`) to an
/// FFT bin; `slot` is the slot in the frame.
pub fn estimate_coreset(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    coreset: &Coreset,
    slot: u32,
) -> CoresetEstimate {
    let len = coreset.dmrs_seq_len();
    let dmrs_ref: Vec<Vec<Complex32>> = (0..coreset.n_symb)
        .map(|l| pdcch_dmrs_sequence(coreset.dmrs_scrambling_id, slot, l as u32, len))
        .collect();
    let n_rb = coreset.n_rb();
    let mut h = Vec::with_capacity(coreset.n_reg());
    for l in 0..coreset.n_symb {
        for rb in 0..n_rb {
            h.push(estimate_reg(grids, &sc_to_bin, coreset, &dmrs_ref, l, rb));
        }
    }
    CoresetEstimate { n_rb, h }
}

/// Match-filter a candidate's data REs against a channel estimate into `out`
/// (cleared; `108·L` LLRs, positive ⇒ bit 0, before descrambling), in the RE
/// mapping order (symbol-outer, subcarrier-inner).
pub fn equalize_candidate_cached(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    coreset: &Coreset,
    cand: &Candidate,
    est: &CoresetEstimate,
    out: &mut Vec<f32>,
) {
    out.clear();
    out.reserve(cand.cces.len() * REGS_PER_CCE * 9 * 2);
    for (l, rb) in coreset.candidate_regs(cand) {
        let h = est.get(l, rb).conj();
        let crb = coreset.rbs[rb];
        for k in (0..12).filter(|k| k % 4 != 1) {
            let z = grids[l][sc_to_bin(12 * crb + k)] * h;
            out.push(z.re);
            out.push(z.im);
        }
    }
}

/// Equalize one candidate on its own: per-REG LS channel estimate from the
/// candidate's DMRS REs, then match-filter its data REs. Identical to
/// [`estimate_coreset`] + [`equalize_candidate_cached`] for a single candidate.
pub fn equalize_candidate(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(usize) -> usize,
    coreset: &Coreset,
    cand: &Candidate,
    slot: u32,
) -> Vec<f32> {
    let len = coreset.dmrs_seq_len();
    let dmrs_ref: Vec<Vec<Complex32>> = (0..coreset.n_symb)
        .map(|l| pdcch_dmrs_sequence(coreset.dmrs_scrambling_id, slot, l as u32, len))
        .collect();
    let regs = coreset.candidate_regs(cand);
    let mut out = Vec::with_capacity(regs.len() * 9 * 2);
    for (l, rb) in regs {
        let h = estimate_reg(grids, &sc_to_bin, coreset, &dmrs_ref, l, rb).conj();
        let crb = coreset.rbs[rb];
        for k in (0..12).filter(|k| k % 4 != 1) {
            let z = grids[l][sc_to_bin(12 * crb + k)] * h;
            out.push(z.re);
            out.push(z.im);
        }
    }
    out
}

/// Cheap PDCCH presence metric for a candidate: the coherence of the per-REG
/// channel estimate across its REGs, `|mean(h)|² / mean(|h|²)`. A real PDCCH
/// (same precoder across its REG bundles) scores ≈1; noise-only REGs give
/// random estimates, ≈1/N. Gating the blind decode on it (≈0.3–0.5) skips the
/// equalize + polar decode for the many empty candidates, at no extra reads.
pub fn candidate_coherence(est: &CoresetEstimate, coreset: &Coreset, cand: &Candidate) -> f32 {
    let mut sum = Complex32::new(0.0, 0.0);
    let mut power = 0.0f32;
    let mut n = 0u32;
    for &cce in &cand.cces {
        for (l, rb) in coreset.cce_regs(cce) {
            let h = est.get(l, rb);
            sum += h;
            power += h.norm_sqr();
            n += 1;
        }
    }
    if n == 0 || power <= 1e-12 {
        return 0.0;
    }
    (sum / n as f32).norm_sqr() / (power / n as f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::dci::{dci_1_0_si_size, dci_decode, dci_encode, pdcch_descramble_llr, BITS_PER_CCE};
    use crate::coreset0::coreset0_config;
    use crate::sequence::gold_sequence as gold;
    use ferrite_common::Numerology;

    fn coreset0_live() -> Coreset {
        // Live OCUDU cell: controlResourceSetZero = 2 (Table 13-4: 24 RB, 2 symbols).
        Coreset::coreset0(&coreset0_config(30, 30, 10, 2).unwrap(), 1, 0)
    }

    fn coreset1(n_rb: usize, n_symb: usize, cell_id: u16) -> Coreset {
        Coreset::contiguous(1, 0, n_rb, n_symb, CceToRegMapping::NonInterleaved, cell_id)
    }

    /// Fill CORESET grids with DMRS + arbitrary data through a flat channel.
    fn synthetic_grids(coreset: &Coreset, slot: u32, h: Complex32) -> Vec<Vec<Complex32>> {
        let len = 3 * (coreset.rbs.last().unwrap() + 1);
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); 12 * (coreset.rbs.last().unwrap() + 1)]; coreset.n_symb];
        for (l, grid) in grids.iter_mut().enumerate() {
            let dmrs = pdcch_dmrs_sequence(coreset.dmrs_scrambling_id, slot, l as u32, len);
            for &crb in &coreset.rbs {
                for kp in 0..3 {
                    grid[12 * crb + 4 * kp + 1] = h * dmrs[3 * (crb - coreset.dmrs_ref_crb) + kp];
                }
                for sc in (0..12).filter(|s| s % 4 != 1) {
                    grid[12 * crb + sc] = h * Complex32::new((crb as f32).cos(), (sc as f32).sin());
                }
            }
        }
        grids
    }

    /// The cached-channel candidate equalization matches the per-candidate one
    /// bit for bit (so blind-decoding every candidate off one estimate is exact),
    /// on both an interleaved and a non-interleaved CORESET.
    #[test]
    fn cached_equalization_matches_direct() {
        let slot = 3u32;
        let h = Complex32::new(0.7, 0.4);
        for coreset in [coreset1(24, 2, 1), coreset0_live(), coreset1(48, 1, 5)] {
            let grids = synthetic_grids(&coreset, slot, h);
            let est = estimate_coreset(&grids, |sc| sc, &coreset, slot);
            let mut cached = Vec::new();
            for &(al, base) in &[(1usize, 3usize), (2, 4), (4, 0)] {
                let cand = Candidate {
                    agg_level: al,
                    cces: (base..base + al).collect(),
                };
                let direct = equalize_candidate(&grids, |sc| sc, &coreset, &cand, slot);
                equalize_candidate_cached(&grids, |sc| sc, &coreset, &cand, &est, &mut cached);
                assert_eq!(direct.len(), cached.len());
                assert_eq!(direct.len(), al * BITS_PER_CCE);
                for (a, b) in direct.iter().zip(&cached) {
                    assert!((a - b).abs() < 1e-4, "AL{al} cce{base}: {a} vs {b}");
                }
                assert!(candidate_coherence(&est, &coreset, &cand) > 0.99);
            }
        }
    }

    /// The coherence gate: a candidate whose REGs all see the same channel scores
    /// ≈1; one over random (noise-only) estimates scores ≪ the 0.5 gate.
    #[test]
    fn candidate_coherence_gates_noise() {
        let coreset = coreset1(24, 2, 1);
        let h = Complex32::new(0.7, -0.4);
        let mut seed = 0x1234_5678u64;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 40) as f32) / (1u64 << 24) as f32 - 0.5
        };
        let n_rb = coreset.n_rb();
        let coherent = CoresetEstimate { n_rb, h: vec![h; coreset.n_reg()] };
        let noise = CoresetEstimate {
            n_rb,
            h: (0..coreset.n_reg()).map(|_| Complex32::new(rng(), rng())).collect(),
        };
        let cand = Candidate { agg_level: 4, cces: (0..4).collect() };
        assert!(candidate_coherence(&coherent, &coreset, &cand) > 0.95, "coherent ≈ 1");
        assert!(candidate_coherence(&noise, &coreset, &cand) < 0.5, "noise low");
    }

    /// Exhaustive candidates cover every CCE-aligned position, in particular AL1
    /// CCEs {0,2,4,6} (which an rnti-hashed USS could place at odd CCEs).
    #[test]
    fn all_candidates_cover_al1() {
        let c = all_candidates(8, &[1, 2, 4, 8]);
        let al1: Vec<usize> = c.iter().filter(|x| x.agg_level == 1).map(|x| x.cces[0]).collect();
        assert_eq!(al1, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            c.iter().filter(|x| x.agg_level == 2).map(|x| x.cces[0]).collect::<Vec<_>>(),
            vec![0, 2, 4, 6]
        );
        assert_eq!(c.iter().filter(|x| x.agg_level == 4).map(|x| x.cces[0]).collect::<Vec<_>>(), vec![0, 4]);
        assert_eq!(c.iter().filter(|x| x.agg_level == 8).map(|x| x.cces[0]).collect::<Vec<_>>(), vec![0]);
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
        let coreset = coreset1(24, 2, 1);
        let ss = SearchSpace {
            id: 2,
            coreset_id: 1,
            period_slots: 1,
            offset_slots: 0,
            duration_slots: 1,
            first_symbols: [false; 14],
            n_candidates: [0, 4, 2, 0, 0],
            kind: SearchSpaceKind::UeSpecific { fallback: false },
        };
        for slot in 0..20u32 {
            let cands = ss.candidates(&coreset, 0x4626, slot);
            assert_eq!(cands, uss_candidates(8, 1, 0x4626, slot, &[(2, 4), (4, 2)]));
            for c in &cands {
                assert!(c.cces.iter().all(|&x| x < 8), "CCE out of range");
                assert_eq!(c.cces.len(), c.agg_level);
                assert_eq!(c.cces[0] % c.agg_level, 0);
                assert!(c.cces.windows(2).all(|w| w[1] == w[0] + 1));
                if c.agg_level == 4 {
                    assert!(c.cces[0] == 0 || c.cces[0] == 4, "AL4 base {} not in {{0,4}}", c.cces[0]);
                }
            }
        }
        // A_p for p=1 is 39829; Y_{1,0} = 39829·0x4626 mod 65537.
        let y0 = (39829u64 * 0x4626) % 65537;
        assert_eq!(uss_y(1, 0x4626, 0), y0);
        let c0 = uss_candidates(8, 1, 0x4626, 0, &[(4, 2)]);
        assert!(c0.iter().any(|c| c.cces[0] == 4 * ((y0 % 2) as usize)));
    }

    #[test]
    fn search_space_monitoring_occasions() {
        let n = Numerology::KHZ30;
        let ss = SearchSpace {
            id: 1,
            coreset_id: 0,
            period_slots: 20,
            offset_slots: 3,
            duration_slots: 2,
            first_symbols: [false; 14],
            n_candidates: [0, 0, 4, 2, 1],
            kind: SearchSpaceKind::Common,
        };
        assert!(ss.is_monitored(SlotPoint::new(n, 0, 3)));
        assert!(ss.is_monitored(SlotPoint::new(n, 0, 4)));
        assert!(!ss.is_monitored(SlotPoint::new(n, 0, 5)));
        assert!(ss.is_monitored(SlotPoint::new(n, 7, 3)));
        assert!(!ss.is_monitored(SlotPoint::new(n, 0, 2)));
        // Common search space uses Y = 0: identical to the Type0 candidate set.
        let coreset = coreset0_live();
        assert_eq!(ss.candidates(&coreset, 0xFFFF, 5), type0_candidates(coreset.n_cce()));
        assert_eq!(SearchSpace::type0(0).candidates(&coreset, 0xFFFF, 0), type0_candidates(8));
    }

    #[test]
    fn coreset0_from_table_13_4() {
        let c = coreset0_live();
        assert_eq!(c.n_rb(), 24);
        assert_eq!(c.n_symb, 2);
        assert_eq!(c.n_cce(), 8);
        assert_eq!(c.dmrs_ref_crb, 0);
        assert_eq!(
            c.mapping,
            CceToRegMapping::Interleaved { reg_bundle_size: 6, interleaver_size: 2, shift_index: 1 }
        );
    }

    #[test]
    fn coreset_from_bitmap_groups_and_regs() {
        let mut groups = [false; CORESET_RB_GROUPS];
        groups[0] = true;
        groups[2] = true;
        // BWP starting at CRB 4: the first group starts at CRB 6.
        let c = Coreset::from_bitmap(
            1,
            4,
            &groups,
            2,
            CceToRegMapping::NonInterleaved,
            PrecoderGranularity::AllContiguousRbs,
            7,
        );
        let expect: Vec<usize> = (6..12).chain(18..24).collect();
        assert_eq!(c.rbs, expect);
        assert_eq!(c.n_cce(), 4);
        // Time-first REG numbering: REG 1 is symbol 1 of the lowest RB.
        assert_eq!(c.reg_to_symbol_rb(1), (1, 0));
        assert_eq!(c.reg_to_symbol_rb(2), (0, 1));
        // Non-interleaved CCE 1 = REGs 6..12 = RBs 3..6 over both symbols.
        let regs: Vec<_> = c.cce_regs(1).collect();
        assert_eq!(regs, vec![(0, 3), (1, 3), (0, 4), (1, 4), (0, 5), (1, 5)]);
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
        let f_for = |pci: u16| -> Vec<usize> {
            let c = Coreset::coreset0(&coreset0_config(30, 30, 10, 2).unwrap(), pci, 0);
            (0..8).map(|x| c.bundle_interleaver(x)).collect()
        };
        for pci in [0u16, 1, 7, 623] {
            let f = f_for(pci);
            let mut seen = [false; 8];
            for &v in &f {
                assert!(!seen[v]);
                seen[v] = true;
            }
        }
        assert_ne!(f_for(1), f_for(2));
        // General (L, R): 48 RB × 1 symbol, L = 2, R = 6 → 24 bundles, C = 4,
        // f(cR + r) = 4r + c + n_shift.
        let c = Coreset::contiguous(
            1,
            0,
            48,
            1,
            CceToRegMapping::Interleaved { reg_bundle_size: 2, interleaver_size: 6, shift_index: 3 },
            1,
        );
        assert_eq!(c.bundle_interleaver(0), 3);
        assert_eq!(c.bundle_interleaver(1), 7); // c=0, r=1
        assert_eq!(c.bundle_interleaver(6), 4); // c=1, r=0
        let mut all: Vec<usize> = (0..24).map(|x| c.bundle_interleaver(x)).collect();
        all.sort_unstable();
        assert_eq!(all, (0..24).collect::<Vec<_>>());
        // CCE 0 = bundles f(0), f(1), f(2) of 2 REGs each.
        let regs: Vec<_> = c.cce_regs(0).collect();
        assert_eq!(regs.len(), 6);
        assert_eq!(regs[0], (0, 6)); // bundle 3 → REGs 6, 7 → RBs 6, 7
        assert_eq!(regs[2], (0, 14)); // bundle 7 → REG 14
    }

    #[test]
    fn candidate_layout_counts_and_order() {
        let coreset = coreset0_live();
        let cand = Candidate { agg_level: 4, cces: vec![0, 1, 2, 3] };
        let regs = coreset.candidate_regs(&cand);
        assert_eq!(regs.len(), 4 * 6);
        // Mapping order: strictly increasing (l, rb) — symbol first.
        assert!(regs.windows(2).all(|w| w[1] > w[0]));
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

        let coreset = coreset0_live();
        let (cell_id, slot, rnti) = (1u16, 0u32, 0xFFFFu16);
        let fft = 512usize;
        let first_sc: i32 = -144; // arbitrary placement within the grid
        let sc_to_bin = move |sc: usize| (first_sc + sc as i32).rem_euclid(fft as i32) as usize;

        let mut rng = Rng(0x9DCC_0001);
        let a_len = dci_1_0_si_size(coreset.n_rb());
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

        // Build the CORESET grids: DMRS in the candidate's REGs, QPSK data in
        // (l, k) order.
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); fft]; coreset.n_symb];
        let len = 3 * coreset.n_rb();
        let dmrs: Vec<Vec<Complex32>> =
            (0..coreset.n_symb).map(|l| pdcch_dmrs_sequence(cell_id, slot, l as u32, len)).collect();
        let mut i = 0;
        for (l, rb) in coreset.candidate_regs(&tx_cand) {
            let crb = coreset.rbs[rb];
            for k in 0..12 {
                grids[l][sc_to_bin(12 * crb + k)] = if k % 4 == 1 {
                    dmrs[l][3 * crb + k / 4]
                } else {
                    let s = Complex32::new(
                        (1 - 2 * i32::from(bits[2 * i])) as f32 * FRAC_1_SQRT_2,
                        (1 - 2 * i32::from(bits[2 * i + 1])) as f32 * FRAC_1_SQRT_2,
                    );
                    i += 1;
                    s
                };
            }
        }
        assert_eq!(2 * i, e);

        // Flat channel + noise at 15 dB.
        let h = Complex32::from_polar(0.9, 0.6);
        let sigma = 10f32.powf(-15.0 / 20.0);
        for g in &mut grids {
            for s in g.iter_mut() {
                *s = *s * h + Complex32::new(rng.normal(), rng.normal()) * (sigma / std::f32::consts::SQRT_2);
            }
        }

        // Receiver: try every candidate blindly, gated on coherence; exactly one
        // must decode — through both the direct and the cached path.
        let est = estimate_coreset(&grids, sc_to_bin, &coreset, slot);
        let mut hits = Vec::new();
        let mut cached = Vec::new();
        for cand in type0_candidates(coreset.n_cce()) {
            let mut llrs = equalize_candidate(&grids, sc_to_bin, &coreset, &cand, slot);
            pdcch_descramble_llr(&mut llrs, u32::from(cell_id));
            let direct = dci_decode(&llrs, rnti, a_len);
            equalize_candidate_cached(&grids, sc_to_bin, &coreset, &cand, &est, &mut cached);
            pdcch_descramble_llr(&mut cached, u32::from(cell_id));
            let via_cache = dci_decode(&cached, rnti, a_len);
            assert_eq!(direct, via_cache);
            if cand == tx_cand {
                assert!(candidate_coherence(&est, &coreset, &cand) > 0.5);
            }
            if let Some(dec) = direct {
                hits.push((cand.clone(), dec));
            }
        }
        assert_eq!(hits.len(), 1, "exactly one candidate should decode");
        assert_eq!(hits[0].0, tx_cand);
        assert_eq!(hits[0].1, payload);
    }
}
