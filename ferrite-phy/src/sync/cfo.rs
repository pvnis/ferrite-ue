//! Carrier frequency offset (CFO) estimation and correction.
//!
//! A frequency offset `Δf` rotates the time samples by `exp(j2π·Δf·n/fs)`. Since
//! the cyclic prefix is a copy of the OFDM symbol's tail `N` samples earlier, the
//! product `y[i]·conj(y[i+N])` over the CP has phase `-2π·Δf·N/fs`. Averaging
//! gives an estimate that is unambiguous for `|Δf| < SCS/2` (half a subcarrier).

use num_complex::{Complex32, Complex64};
use std::f64::consts::TAU;

/// Estimate the CFO as a fraction of the subcarrier spacing from one OFDM symbol.
///
/// `symbol[0..cp]` is the cyclic prefix and `symbol[cp..cp+fft_size]` the useful
/// part. The result lies in `(-0.5, 0.5]`.
pub fn estimate_cfo_fraction(symbol: &[Complex32], cp: usize, fft_size: usize) -> f64 {
    assert!(symbol.len() >= cp + fft_size);
    let mut acc = Complex64::new(0.0, 0.0);
    for i in 0..cp {
        let p = symbol[i] * symbol[i + fft_size].conj();
        acc += Complex64::new(p.re as f64, p.im as f64);
    }
    -acc.arg() / TAU
}

/// Estimate the CFO in Hz, given the subcarrier spacing in Hz.
pub fn estimate_cfo_hz(symbol: &[Complex32], cp: usize, fft_size: usize, scs_hz: f64) -> f64 {
    estimate_cfo_fraction(symbol, cp, fft_size) * scs_hz
}

/// Estimate CFO (Hz) by accumulating the CP autocorrelation across up to
/// `max_symbols` contiguous OFDM symbols (each `cp + fft_size` samples) starting
/// at `data[0]`. Symbols that run past the end of `data` are skipped, so it is
/// safe to over-request. Averaging over more symbols reduces the estimate
/// variance; all symbols must share the same CFO (true within one SSB).
pub fn estimate_cfo_hz_multi(
    data: &[Complex32],
    cp: usize,
    fft_size: usize,
    max_symbols: usize,
    scs_hz: f64,
) -> f64 {
    let stride = cp + fft_size;
    let mut acc = Complex64::new(0.0, 0.0);
    for s in 0..max_symbols {
        let base = s * stride;
        if base + stride > data.len() {
            break;
        }
        for i in 0..cp {
            let p = data[base + i] * data[base + i + fft_size].conj();
            acc += Complex64::new(p.re as f64, p.im as f64);
        }
    }
    (-acc.arg() / TAU) * scs_hz
}

/// De-rotate `samples` in place to remove a CFO of `cfo_hz`, given `sample_rate`.
pub fn correct_cfo(samples: &mut [Complex32], cfo_hz: f64, sample_rate: f64) {
    let w = -TAU * cfo_hz / sample_rate;
    for (n, s) in samples.iter_mut().enumerate() {
        let ph = w * n as f64;
        *s *= Complex32::new(ph.cos() as f32, ph.sin() as f32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ofdm::Ofdm;
    use crate::sync::ssb::pss_grid;

    fn apply_cfo(samples: &mut [Complex32], cfo_hz: f64, fs: f64) {
        for (n, s) in samples.iter_mut().enumerate() {
            let ph = TAU * cfo_hz * n as f64 / fs;
            *s *= Complex32::new(ph.cos() as f32, ph.sin() as f32);
        }
    }

    #[test]
    fn estimates_known_offsets() {
        let ofdm = Ofdm::new(256);
        let cp = ofdm.cp_len(0, 1);
        let scs = 30_000.0;
        let fs = 256.0 * scs;
        let clean = ofdm.modulate_symbol(&pss_grid(0, 256), cp);

        for &cfo in &[-12_000.0, -4_000.0, 0.0, 3_500.0, 11_000.0] {
            let mut sym = clean.clone();
            apply_cfo(&mut sym, cfo, fs);
            let est = estimate_cfo_hz(&sym, cp, 256, scs);
            assert!((est - cfo).abs() < 50.0, "cfo {cfo} -> est {est}");
        }
    }

    #[test]
    fn multi_symbol_estimate_and_early_break() {
        let ofdm = Ofdm::new(256);
        let cp = ofdm.cp_len(3, 1);
        let scs = 30_000.0;
        let fs = 256.0 * scs;
        let mut wave = Vec::new();
        for n_id_2 in 0..3u8 {
            wave.extend(ofdm.modulate_symbol(&pss_grid(n_id_2, 256), cp));
        }
        apply_cfo(&mut wave, 5_000.0, fs);
        // Only 3 symbols present, but request 4 — the last must be skipped safely.
        let est = estimate_cfo_hz_multi(&wave, cp, 256, 4, scs);
        assert!((est - 5_000.0).abs() < 50.0, "est {est}");
    }

    #[test]
    fn correct_cancels_offset() {
        let ofdm = Ofdm::new(256);
        let cp = ofdm.cp_len(0, 1);
        let fs = 256.0 * 30_000.0;
        let clean = ofdm.modulate_symbol(&pss_grid(1, 256), cp);

        let mut sym = clean.clone();
        apply_cfo(&mut sym, 7_000.0, fs);
        correct_cfo(&mut sym, 7_000.0, fs);
        for (a, b) in clean.iter().zip(&sym) {
            assert!((a - b).norm() < 1e-3);
        }
    }
}
