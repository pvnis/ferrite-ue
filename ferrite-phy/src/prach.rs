//! Physical random-access channel (PRACH) preamble generation — the
//! Zadoff-Chu root sequences and cyclic shifts of 3GPP TS 38.211 §6.3.3.1 and
//! the baseband waveform of §5.3.2 for every preamble format.
//!
//! The random-access preamble sequence is
//! ```text
//!   x_{u,v}(n) = x_u((n + C_v) mod L_RA),   x_u(i) = exp(-jπ·u·i·(i+1)/L_RA)
//! ```
//! with `u` the physical root sequence number (from the logical root index via
//! Tables 6.3.3.1-3/-4) and `C_v = v·N_CS` the cyclic shift (unrestricted set).
//! The 64 preambles of an occasion are enumerated by increasing cyclic shift
//! `v`, then increasing logical root index (§6.3.3.1).
//!
//! The time-continuous signal (§5.3.2) is
//! ```text
//!   s(t) = Σ_k y_{u,v}(k) · exp(j2π (k + K·k_1 + k̄) Δf_RA (t − N_CP^RA T_c − t_start^RA))
//! ```
//! for `t_start^RA ≤ t < t_start^RA + (N_u + N_CP^RA) T_c`, with
//! `y_{u,v} = DFT(x_{u,v})`. At sample rate `fs` this is one IFFT of size
//! `fs/Δf_RA` whose output is repeated `N_u·Δf_RA` (= [`PreambleFormatParams::n_repeat`])
//! times after a cyclic prefix of `N_CP^RA` — for the long formats one
//! 0.8 ms (1.25 kHz) or 0.2 ms (5 kHz) symbol, for the short ones one
//! `1/(15·2^µ kHz)` symbol. The occasion's position in the slot, `t_start^RA`,
//! is the start of OFDM symbol `l_0 (+ n_t·N_dur^RA + 14·n_slot^RA)` at the
//! PRACH-slot numerology, including the longer CP of symbols `0` and `7·2^µ`:
//! see [`crate::prach_config::symbol_start_tc`] and
//! [`crate::prach_config::PrachOccasionRef::start_tc`].
#![forbid(unsafe_code)]

pub use crate::prach_config::PrachScs;
use crate::prach_config::{format_params, PrachError, PreambleFormat, PreambleFormatParams};
use crate::prach_tables::{ROOT_L139, ROOT_L839};
use num_complex::Complex32;
use rustfft::FftPlanner;
use std::f32::consts::PI;

/// PRACH preamble sequence length `L_RA` (§6.3.3.1): 839 for the long formats
/// (0/1/2/3), 139 for the short formats (A1-A3, B1-B4, C0, C2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrachSeqLen {
    Long,  // L_RA = 839
    Short, // L_RA = 139
}

impl PrachSeqLen {
    pub fn l_ra(self) -> usize {
        match self {
            PrachSeqLen::Long => 839,
            PrachSeqLen::Short => 139,
        }
    }

    /// Sequence length of a preamble format.
    pub fn of(format: PreambleFormat) -> Self {
        if format.is_long() {
            PrachSeqLen::Long
        } else {
            PrachSeqLen::Short
        }
    }
}

/// `restrictedSetConfig` (TS 38.331 `RACH-ConfigCommon`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestrictedSet {
    Unrestricted,
    TypeA,
    TypeB,
}

/// `N_CS` for **unrestricted** sets (first column of Tables 6.3.3.1-5/-6/-7),
/// indexed by `zeroCorrelationZoneConfig` (0..15). `None` for reserved entries.
pub fn prach_ncs_unrestricted(scs: PrachScs, zero_correlation_zone: usize) -> Option<usize> {
    // Table 6.3.3.1-5/-6/-7, first (unrestricted) columns.
    const NCS_1_25: [u16; 16] = [
        0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419,
    ];
    const NCS_5: [u16; 16] = [
        0, 13, 26, 33, 38, 41, 49, 55, 64, 76, 93, 119, 139, 209, 279, 419,
    ];
    const NCS_SHORT: [u16; 16] = [0, 2, 4, 6, 8, 10, 12, 13, 15, 17, 19, 23, 27, 34, 46, 69];
    let table = match scs {
        PrachScs::Khz1_25 => &NCS_1_25,
        PrachScs::Khz5 => &NCS_5,
        PrachScs::Short => &NCS_SHORT,
    };
    table.get(zero_correlation_zone).map(|&n| n as usize)
}

/// `N_CS` for `format` / `zeroCorrelationZoneConfig` (Tables 6.3.3.1-5/-6/-7,
/// selected by the format's Δf_RA). Restricted sets are rejected.
pub fn prach_ncs(
    format: PreambleFormat,
    zero_correlation_zone: u8,
    restricted: RestrictedSet,
) -> Result<usize, PrachError> {
    if restricted != RestrictedSet::Unrestricted {
        return Err(PrachError::RestrictedSetUnsupported);
    }
    let scs = match format {
        PreambleFormat::F0 | PreambleFormat::F1 | PreambleFormat::F2 => PrachScs::Khz1_25,
        PreambleFormat::F3 => PrachScs::Khz5,
        _ => PrachScs::Short,
    };
    prach_ncs_unrestricted(scs, usize::from(zero_correlation_zone)).ok_or(
        PrachError::InvalidZeroCorrelationZone(zero_correlation_zone),
    )
}

/// Physical root sequence number `u` for a logical root sequence index
/// (Tables 6.3.3.1-3/-4). The logical order is cyclic (index 0 follows L_RA-2).
pub fn prach_root(logical_root_index: usize, seq_len: PrachSeqLen) -> u16 {
    match seq_len {
        PrachSeqLen::Long => ROOT_L839[logical_root_index % ROOT_L839.len()],
        PrachSeqLen::Short => ROOT_L139[logical_root_index % ROOT_L139.len()],
    }
}

/// The `u`-th root Zadoff-Chu sequence `x_u(i) = exp(-jπ·u·i·(i+1)/L_RA)`,
/// `i = 0..L_RA` (§6.3.3.1). `L_RA` (839/139) is prime, so this has unit
/// amplitude and ideal periodic autocorrelation.
pub fn zadoff_chu(u: u16, l_ra: usize) -> Vec<Complex32> {
    let two_l = 2 * l_ra as u64;
    (0..l_ra)
        .map(|i| {
            // phase = -π·(u·i·(i+1) mod 2L_RA)/L_RA, reduced to preserve precision.
            let x = (u as u64 * i as u64 * (i as u64 + 1)) % two_l;
            Complex32::from_polar(1.0, -PI * x as f32 / l_ra as f32)
        })
        .collect()
}

/// Number of preambles obtainable per root for a given `N_CS` (unrestricted):
/// `⌊L_RA/N_CS⌋`, or 1 when `N_CS = 0` (one preamble per root, no shift).
pub fn prach_preambles_per_root(n_cs: usize, seq_len: PrachSeqLen) -> usize {
    seq_len.l_ra().checked_div(n_cs).unwrap_or(1)
}

/// Logical root index and cyclic shift `C_v` of `preamble_index` given the
/// cell's `prach-RootSequenceIndex` and `N_CS` (unrestricted set, §6.3.3.1):
/// preambles are enumerated by increasing cyclic shift `v` then increasing
/// logical root index.
pub fn prach_root_and_shift(
    root_sequence_index: usize,
    preamble_index: usize,
    n_cs: usize,
    seq_len: PrachSeqLen,
) -> (usize, usize) {
    let per_root = prach_preambles_per_root(n_cs, seq_len);
    (
        root_sequence_index + preamble_index / per_root,
        (preamble_index % per_root) * n_cs,
    )
}

/// Time-domain root-sequence-domain preamble `x_{u,v}(n)` for `preamble_index`
/// (0..63) given the cell's `root_sequence_index` (`prach-RootSequenceIndex`)
/// and `N_CS` (unrestricted set, §6.3.3.1). Length `L_RA`.
pub fn prach_preamble_seq(
    root_sequence_index: usize,
    preamble_index: usize,
    n_cs: usize,
    seq_len: PrachSeqLen,
) -> Vec<Complex32> {
    let l_ra = seq_len.l_ra();
    let (logical_root, c_v) =
        prach_root_and_shift(root_sequence_index, preamble_index, n_cs, seq_len);
    let u = prach_root(logical_root, seq_len);
    let x_u = zadoff_chu(u, l_ra);
    (0..l_ra).map(|n| x_u[(n + c_v) % l_ra]).collect()
}

/// Preamble `x_{u,v}` for a cell: `prach-RootSequenceIndex`, the preamble
/// index chosen by MAC (0..63), `zeroCorrelationZoneConfig`, the preamble
/// format (selects `L_RA` and the `N_CS` table) and `restrictedSetConfig`
/// (unrestricted only; TS 38.321 §5.1.2 / TS 38.211 §6.3.3.1).
pub fn preamble_sequence(
    root_sequence_index: u16,
    preamble_index: u8,
    zero_correlation_zone: u8,
    format: PreambleFormat,
    restricted: RestrictedSet,
) -> Result<Vec<Complex32>, PrachError> {
    if preamble_index > 63 {
        return Err(PrachError::InvalidPreambleIndex(preamble_index));
    }
    let n_cs = prach_ncs(format, zero_correlation_zone, restricted)?;
    Ok(prach_preamble_seq(
        usize::from(root_sequence_index),
        usize::from(preamble_index),
        n_cs,
        PrachSeqLen::of(format),
    ))
}

/// Unnormalized DFT: `X[k] = Σ_n x[n]·exp(-j2π·k·n/N)`.
pub(crate) fn dft(x: &[Complex32]) -> Vec<Complex32> {
    let mut buf = x.to_vec();
    FftPlanner::new()
        .plan_fft_forward(buf.len())
        .process(&mut buf);
    buf
}

/// Inverse DFT (1/N normalized): `x[n] = (1/N)·Σ_k X[k]·exp(+j2π·k·n/N)`.
pub(crate) fn idft(x: &[Complex32]) -> Vec<Complex32> {
    let mut buf = x.to_vec();
    FftPlanner::new()
        .plan_fft_inverse(buf.len())
        .process(&mut buf);
    let scale = 1.0 / buf.len() as f32;
    buf.iter_mut().for_each(|v| *v *= scale);
    buf
}

/// Time/frequency parameters of one PRACH occasion for the base sample rate
/// (§6.3.3.2, §5.3.2). All lengths in samples of that rate.
#[derive(Clone, Copy, Debug)]
pub struct PrachOccasion {
    /// IFFT size = base_rate / PRACH_SCS (e.g. 512 for 30 kHz at 15.36 Msps,
    /// 12288 for 1.25 kHz).
    pub fft_size: usize,
    /// PRACH grid size = N_RB_ul_grid · K · 12 (subcarriers at Δf_RA, DC-centred).
    pub grid_size: usize,
    /// First occupied subcarrier in the grid: `K·12·(rb_offset + nof_rb_ra·i) + k_bar`
    /// (see [`crate::prach_config::prach_subcarrier_offset`] with
    /// `bwp_start_rb` relative to the grid start).
    pub k_start: usize,
    /// Cyclic-prefix length in samples.
    pub cp_samples: usize,
    /// PRACH OFDM symbols per occasion (1 for C0 / format 0, 12 for B4, …).
    pub nof_symbols: usize,
}

impl PrachOccasion {
    /// Occasion of preamble format `params` at sample rate `fs` in a UL grid of
    /// `grid_rb` RBs (at the PUSCH numerology, `K = Δf/Δf_RA`), the sequence
    /// starting at subcarrier `k_start` (Δf_RA units) from the grid start.
    pub fn for_format(
        params: &PreambleFormatParams,
        fs: f64,
        grid_rb: usize,
        k: usize,
        k_start: usize,
    ) -> Result<Self, PrachError> {
        let layout = params.sample_layout(fs)?;
        Ok(Self {
            fft_size: layout.symbol_samples,
            grid_size: grid_rb * 12 * k,
            k_start,
            cp_samples: layout.cp_samples,
            nof_symbols: layout.n_repeat,
        })
    }
}

/// Frequency-domain mapping: subcarrier `k_start + k` (0-centred grid of
/// `grid_size`) → IFFT bin, `(k_start + k − grid_size/2) mod fft_size`.
pub fn prach_bin(occ: &PrachOccasion, k: usize) -> usize {
    (occ.k_start + k + occ.fft_size - occ.grid_size / 2) % occ.fft_size
}

/// Core synthesis: `y = DFT(x_uv)` on bins `(bin0 + k) mod fft_size`, IFFT,
/// cyclic prefix, `n_repeat` copies of the symbol.
fn synthesize(
    x_uv: &[Complex32],
    fft_size: usize,
    bin0: usize,
    cp_samples: usize,
    n_repeat: usize,
) -> Vec<Complex32> {
    let y = dft(x_uv);
    let mut grid = vec![Complex32::new(0.0, 0.0); fft_size];
    for (k, &yk) in y.iter().enumerate() {
        grid[(bin0 + k) % fft_size] = yk;
    }
    let sym = idft(&grid);
    let mut out = Vec::with_capacity(cp_samples + n_repeat * fft_size);
    out.extend_from_slice(&sym[fft_size - cp_samples..]); // cyclic prefix
    for _ in 0..n_repeat {
        out.extend_from_slice(&sym);
    }
    out
}

/// Generate the time-domain PRACH occasion for a sequence-domain preamble
/// `x_{u,v}` (§5.3.2): place `y_{u,v} = DFT(x_{u,v})` on the mapped subcarriers,
/// IFFT to time, prepend the cyclic prefix, and repeat the symbol `nof_symbols`
/// times. Returns `cp_samples + nof_symbols·fft_size` samples.
pub fn prach_occasion_waveform(x_uv: &[Complex32], occ: &PrachOccasion) -> Vec<Complex32> {
    synthesize(
        x_uv,
        occ.fft_size,
        prach_bin(occ, 0),
        occ.cp_samples,
        occ.nof_symbols,
    )
}

/// Baseband waveform of one preamble of any format at sample rate `fs`
/// (§5.3.2): `first_sc_from_dc` is the index of PRACH subcarrier `k = 0`
/// relative to the carrier centre in units of Δf_RA, i.e. `K·k_1 + k̄`
/// ([`crate::prach_config::prach_subcarrier_offset`] with `bwp_start_rb` the
/// BWP start relative to the carrier centre). Returns
/// `cp_samples + n_repeat · fs/Δf_RA` samples starting at `t_start^RA`
/// (the caller places them at the symbol boundary, see the module docs).
pub fn prach_waveform(
    x_uv: &[Complex32],
    params: &PreambleFormatParams,
    fs: f64,
    first_sc_from_dc: i64,
) -> Result<Vec<Complex32>, PrachError> {
    let layout = params.sample_layout(fs)?;
    let n = layout.symbol_samples as i64;
    let bin0 = first_sc_from_dc.rem_euclid(n) as usize;
    Ok(synthesize(
        x_uv,
        layout.symbol_samples,
        bin0,
        layout.cp_samples,
        layout.n_repeat,
    ))
}

/// Waveform of preamble `preamble_index` for a cell (convenience wrapper
/// around [`preamble_sequence`] and [`prach_waveform`]).
#[allow(clippy::too_many_arguments)]
pub fn prach_preamble_waveform(
    format: PreambleFormat,
    mu: u8,
    root_sequence_index: u16,
    preamble_index: u8,
    zero_correlation_zone: u8,
    restricted: RestrictedSet,
    fs: f64,
    first_sc_from_dc: i64,
) -> Result<Vec<Complex32>, PrachError> {
    let params = format_params(format, mu)?;
    let x = preamble_sequence(
        root_sequence_index,
        preamble_index,
        zero_correlation_zone,
        format,
        restricted,
    )?;
    prach_waveform(&x, &params, fs, first_sc_from_dc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prach_config::{prach_frequency_mapping, prach_subcarrier_offset};

    #[test]
    fn root_tables_sized_and_bounded() {
        assert_eq!(ROOT_L839.len(), 838);
        assert_eq!(ROOT_L139.len(), 138);
        assert_eq!(prach_root(0, PrachSeqLen::Long), 129);
        assert_eq!(prach_root(1, PrachSeqLen::Long), 710);
        assert_eq!(prach_root(0, PrachSeqLen::Short), 1);
        assert!(ROOT_L839.iter().all(|&u| (1..=838).contains(&u)));
        assert!(ROOT_L139.iter().all(|&u| (1..=138).contains(&u)));
        // logical order is cyclic.
        assert_eq!(
            prach_root(838, PrachSeqLen::Long),
            prach_root(0, PrachSeqLen::Long)
        );
    }

    #[test]
    fn zc_constant_amplitude() {
        let x = zadoff_chu(prach_root(0, PrachSeqLen::Long), 839);
        assert_eq!(x.len(), 839);
        for s in &x {
            assert!((s.norm() - 1.0).abs() < 1e-4);
        }
    }

    /// Zadoff-Chu has ideal periodic autocorrelation: for a prime L_RA and
    /// root coprime to it, the cyclic autocorrelation is 0 for all non-zero lags.
    #[test]
    fn zc_ideal_periodic_autocorrelation() {
        let l = 839usize;
        let x = zadoff_chu(prach_root(3, PrachSeqLen::Long), l);
        for tau in 1..l {
            let mut acc = Complex32::new(0.0, 0.0);
            for n in 0..l {
                acc += x[n] * x[(n + tau) % l].conj();
            }
            assert!(acc.norm() < 1e-2, "lag {tau}: |R|={}", acc.norm());
        }
    }

    /// Two cyclic shifts of the same root are orthogonal at zero lag and their
    /// cross-correlation peaks at the shift separation — the property the gNB
    /// detector exploits to separate preambles.
    #[test]
    fn cyclic_shifts_separate() {
        let n_cs = prach_ncs_unrestricted(PrachScs::Khz1_25, 8).unwrap(); // 46
        let seq_len = PrachSeqLen::Long;
        let p0 = prach_preamble_seq(0, 0, n_cs, seq_len);
        let p1 = prach_preamble_seq(0, 1, n_cs, seq_len);
        // both derive from the same root (per_root = 839/46 = 18 > 1).
        assert_eq!(prach_preambles_per_root(n_cs, seq_len), 18);
        let zero_lag: Complex32 = p0.iter().zip(&p1).map(|(a, b)| a * b.conj()).sum();
        assert!(
            zero_lag.norm() < 1.0,
            "shifted preambles not orthogonal: {}",
            zero_lag.norm()
        );
    }

    #[test]
    fn ncs_reserved_and_values() {
        assert_eq!(prach_ncs_unrestricted(PrachScs::Khz1_25, 0), Some(0));
        assert_eq!(prach_ncs_unrestricted(PrachScs::Khz1_25, 8), Some(46));
        assert_eq!(prach_ncs_unrestricted(PrachScs::Short, 15), Some(69));
        assert_eq!(
            prach_ncs(PreambleFormat::F0, 8, RestrictedSet::Unrestricted),
            Ok(46)
        );
        assert_eq!(
            prach_ncs(PreambleFormat::F3, 8, RestrictedSet::Unrestricted),
            Ok(64)
        );
        assert_eq!(
            prach_ncs(PreambleFormat::B4, 8, RestrictedSet::Unrestricted),
            Ok(15)
        );
        assert_eq!(
            prach_ncs(PreambleFormat::F0, 16, RestrictedSet::Unrestricted),
            Err(PrachError::InvalidZeroCorrelationZone(16))
        );
        assert_eq!(
            prach_ncs(PreambleFormat::F0, 1, RestrictedSet::TypeA),
            Err(PrachError::RestrictedSetUnsupported)
        );
    }

    /// Preamble enumeration (§6.3.3.1): with N_CS = 13 at L = 839 there are 64
    /// shifts per root, so all 64 preambles come from one root; with N_CS = 0
    /// each preamble is its own root.
    #[test]
    fn preamble_selection() {
        assert_eq!(
            prach_root_and_shift(5, 63, 13, PrachSeqLen::Long),
            (5, 63 * 13)
        );
        assert_eq!(prach_root_and_shift(5, 63, 0, PrachSeqLen::Long), (68, 0));
        // N_CS = 46 → 18 per root: preamble 19 is root+1, shift 46.
        assert_eq!(prach_root_and_shift(0, 19, 46, PrachSeqLen::Long), (1, 46));
        // Short: N_CS = 69 → 2 per root.
        assert_eq!(prach_root_and_shift(1, 3, 69, PrachSeqLen::Short), (2, 69));
        let s =
            preamble_sequence(1, 3, 15, PreambleFormat::C0, RestrictedSet::Unrestricted).unwrap();
        assert_eq!(s, prach_preamble_seq(1, 3, 69, PrachSeqLen::Short));
        assert_eq!(
            preamble_sequence(1, 64, 0, PreambleFormat::C0, RestrictedSet::Unrestricted),
            Err(PrachError::InvalidPreambleIndex(64))
        );
    }

    /// Demodulate a waveform: skip the CP, DFT the `symbol`-th sequence symbol,
    /// take the `l_ra` bins from `bin0`, IDFT back to the sequence domain and
    /// correlate against the root ZC over all cyclic shifts. Returns
    /// (peak shift, peak, second-largest).
    fn demod_peak(
        wf: &[Complex32],
        cp: usize,
        fft: usize,
        symbol: usize,
        bin0: usize,
        root: &[Complex32],
    ) -> (usize, f32, f32) {
        let l = root.len();
        let sym = &wf[cp + symbol * fft..cp + (symbol + 1) * fft];
        let g = dft(sym);
        let y_rx: Vec<Complex32> = (0..l).map(|k| g[(bin0 + k) % fft]).collect();
        let x_rx = idft(&y_rx);
        let (mut peak, mut peak_tau, mut second) = (0f32, 0usize, 0f32);
        for tau in 0..l {
            let c: Complex32 = (0..l).map(|n| x_rx[n] * root[(n + tau) % l].conj()).sum();
            let m = c.norm();
            if m > peak {
                second = peak;
                peak = m;
                peak_tau = tau;
            } else if m > second {
                second = m;
            }
        }
        (peak_tau, peak, second)
    }

    /// Generate the cell's format-C0 occasion (30 kHz, 15.36 Msps), demodulate,
    /// and recover the preamble: the sequence-domain correlation against the
    /// root ZC must peak sharply at the transmitted cyclic shift.
    #[test]
    fn c0_waveform_round_trip() {
        let occ = PrachOccasion {
            fft_size: 512,
            grid_size: 24 * 12,
            k_start: 62,
            cp_samples: 310,
            nof_symbols: 1,
        };
        // cell config: root sequence index 1, N_CS = 0, preamble 0 → u = ROOT[1].
        let seq_len = PrachSeqLen::Short;
        let x = prach_preamble_seq(1, 0, 0, seq_len); // N_CS=0
        let wf = prach_occasion_waveform(&x, &occ);
        assert_eq!(wf.len(), occ.cp_samples + occ.fft_size);

        // Correlate with the root ZC (u = ROOT_L139[1] = 138) over cyclic shifts.
        let root = zadoff_chu(prach_root(1, seq_len), seq_len.l_ra());
        let (peak_tau, peak, second) = demod_peak(
            &wf,
            occ.cp_samples,
            occ.fft_size,
            0,
            prach_bin(&occ, 0),
            &root,
        );
        assert_eq!(peak_tau, 0, "correlation peak at wrong shift");
        assert!(
            peak > 20.0 * second,
            "correlation not a sharp delta: peak {peak}, 2nd {second}"
        );

        // The same occasion through the generic path (C0 at µ=1, 24-RB grid,
        // msg1-FrequencyStart 5 → k_start = 12·5 + 2 = 62).
        let params = format_params(PreambleFormat::C0, 1).unwrap();
        let fm = prach_frequency_mapping(params.delta_f_ra_hz, 1).unwrap();
        let k_start = prach_subcarrier_offset(&fm, 5, 0, 0);
        assert_eq!(k_start, 62);
        let occ2 =
            PrachOccasion::for_format(&params, 15.36e6, 24, usize::from(fm.k), k_start as usize)
                .unwrap();
        assert_eq!(
            (
                occ2.fft_size,
                occ2.grid_size,
                occ2.cp_samples,
                occ2.nof_symbols
            ),
            (512, 288, 310, 1)
        );
        let wf2 = prach_waveform(
            &x,
            &params,
            15.36e6,
            prach_subcarrier_offset(&fm, 5, 0, -12),
        )
        .unwrap();
        assert_eq!(wf2.len(), wf.len());
        for (a, b) in wf.iter().zip(&wf2) {
            assert!((a - b).norm() < 1e-4);
        }
    }

    /// Format 0 (L = 839, Δf_RA = 1.25 kHz) at 11.52 and 23.04 Msps: 9216- /
    /// 18432-point IFFT, CP 1188 / 2376 samples. Demodulate with the same-size
    /// DFT and recover the cyclic shift C_v = 3·13 = 39 (zczc 1, preamble 3).
    #[test]
    fn format0_round_trip() {
        let params = format_params(PreambleFormat::F0, 0).unwrap();
        let fm = prach_frequency_mapping(params.delta_f_ra_hz, 0).unwrap(); // 15 kHz PUSCH: K=12, k̄=7
                                                                            // 52-RB grid, BWP = carrier, msg1-FrequencyStart 2, occasion n_RA = 1.
        let first_sc = prach_subcarrier_offset(&fm, 2, 1, -26);
        assert_eq!(first_sc, 12 * 12 * (-26 + 2 + 6) + 7);
        let x =
            preamble_sequence(0, 3, 1, PreambleFormat::F0, RestrictedSet::Unrestricted).unwrap();
        let root = zadoff_chu(prach_root(0, PrachSeqLen::Long), 839);
        for (fs, fft, cp) in [(11.52e6, 9216usize, 1188usize), (23.04e6, 18432, 2376)] {
            let wf = prach_waveform(&x, &params, fs, first_sc).unwrap();
            assert_eq!(wf.len(), cp + fft, "fs {fs}");
            let bin0 = first_sc.rem_euclid(fft as i64) as usize;
            let (tau, peak, second) = demod_peak(&wf, cp, fft, 0, bin0, &root);
            assert_eq!(tau, 39, "fs {fs}: wrong cyclic shift");
            assert!(peak > 20.0 * second, "fs {fs}: peak {peak}, 2nd {second}");
            // The CP is a true cyclic prefix of the symbol.
            for i in 0..cp {
                assert!((wf[i] - wf[i + fft]).norm() < 1e-3);
            }
        }
    }

    /// Formats 1 (two 0.8 ms repetitions) and 3 (5 kHz, four repetitions):
    /// every repetition demodulates to the same preamble.
    #[test]
    fn long_formats_repeat() {
        let fs = 15.36e6;
        for (format, mu_pusch, fft, cp, n_rep) in [
            (PreambleFormat::F1, 1, 12288usize, 10512, 2usize),
            (PreambleFormat::F3, 0, 3072, 1584, 4),
        ] {
            let params = format_params(format, 0).unwrap();
            let fm = prach_frequency_mapping(params.delta_f_ra_hz, mu_pusch).unwrap();
            let first_sc = prach_subcarrier_offset(&fm, 0, 0, -10);
            let x = preamble_sequence(10, 7, 2, format, RestrictedSet::Unrestricted).unwrap();
            let (logical, c_v) = prach_root_and_shift(
                10,
                7,
                prach_ncs(format, 2, RestrictedSet::Unrestricted).unwrap(),
                PrachSeqLen::Long,
            );
            let root = zadoff_chu(prach_root(logical, PrachSeqLen::Long), 839);
            let wf = prach_waveform(&x, &params, fs, first_sc).unwrap();
            assert_eq!(wf.len(), cp + n_rep * fft, "{format:?}");
            let bin0 = first_sc.rem_euclid(fft as i64) as usize;
            for r in 0..n_rep {
                let (tau, peak, second) = demod_peak(&wf, cp, fft, r, bin0, &root);
                assert_eq!(tau, c_v, "{format:?} rep {r}");
                assert!(peak > 20.0 * second);
            }
        }
    }

    /// B4 at 30 kHz: 12 repetitions of the 512-sample symbol after a 234-sample CP.
    #[test]
    fn b4_waveform_shape() {
        let params = format_params(PreambleFormat::B4, 1).unwrap();
        let wf = prach_preamble_waveform(
            PreambleFormat::B4,
            1,
            1,
            0,
            0,
            RestrictedSet::Unrestricted,
            15.36e6,
            -144 + 2,
        )
        .unwrap();
        assert_eq!(wf.len(), 234 + 12 * 512);
        assert_eq!(params.n_repeat, 12);
        for i in 0..512 {
            assert!((wf[234 + i] - wf[234 + 11 * 512 + i]).norm() < 1e-4);
        }
        assert!(prach_preamble_waveform(
            PreambleFormat::A1B1,
            1,
            1,
            0,
            0,
            RestrictedSet::Unrestricted,
            15.36e6,
            0
        )
        .is_err());
    }
}
