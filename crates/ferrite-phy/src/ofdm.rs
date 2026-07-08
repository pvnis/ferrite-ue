//! OFDM modulation / demodulation with the NR cyclic prefix (3GPP TS 38.211 §5.3).
//!
//! An OFDM symbol at FFT size `N` and subcarrier spacing `Δf` occupies `N` time
//! samples at sample rate `fs = N·Δf`, preceded by a cyclic prefix. With the
//! normal CP, the per-symbol CP length (in samples) scales from the 15 kHz /
//! 2048-point reference: `144·N/2048`, except the first symbol of each 0.5 ms
//! half-subframe, which uses `160·N/2048`.

use num_complex::Complex32;
use rustfft::{Fft, FftPlanner};
use std::sync::Arc;

/// Planned OFDM (de)modulator for a fixed FFT size.
pub struct Ofdm {
    fft_size: usize,
    fft: Arc<dyn Fft<f32>>,
    ifft: Arc<dyn Fft<f32>>,
    scale: f32,
}

impl Ofdm {
    /// Plan forward/inverse transforms for `fft_size` (must be a multiple of 128
    /// so the CP lengths are integral).
    pub fn new(fft_size: usize) -> Self {
        assert!(
            fft_size % 128 == 0,
            "fft_size must be a multiple of 128 for integral NR CP lengths"
        );
        let mut planner = FftPlanner::<f32>::new();
        Self {
            fft: planner.plan_fft_forward(fft_size),
            ifft: planner.plan_fft_inverse(fft_size),
            scale: 1.0 / (fft_size as f32).sqrt(),
            fft_size,
        }
    }

    /// FFT size `N`.
    pub fn fft_size(&self) -> usize {
        self.fft_size
    }

    /// Cyclic-prefix length (samples) for `symbol_in_subframe`, given numerology
    /// `mu` (38.211 §5.3.1). The normal CP is `144·N/2048`; the first symbol of
    /// each 0.5 ms half-subframe (`l = 0` and `l = 7·2^mu`) is extended by
    /// `16·κ` reference samples, which is `16·N·2^mu/2048` at this FFT size —
    /// the extension absorbs the half-subframe rounding and scales with `mu`.
    pub fn cp_len(&self, symbol_in_subframe: usize, mu: u8) -> usize {
        let is_half_subframe_start =
            symbol_in_subframe == 0 || symbol_in_subframe == 7 * (1usize << mu);
        let normal = 144 * self.fft_size / 2048;
        if is_half_subframe_start {
            normal + (16 << mu) * self.fft_size / 2048
        } else {
            normal
        }
    }

    /// Modulate one symbol: IFFT the frequency-domain `grid` (natural FFT bin
    /// order, DC at index 0), then prepend `cp` cyclic-prefix samples. Output
    /// length is `cp + fft_size`. Uses the unitary `1/√N` scaling.
    pub fn modulate_symbol(&self, grid: &[Complex32], cp: usize) -> Vec<Complex32> {
        assert_eq!(grid.len(), self.fft_size);
        assert!(cp <= self.fft_size);
        let mut buf = grid.to_vec();
        self.ifft.process(&mut buf);
        for s in &mut buf {
            *s *= self.scale;
        }
        let mut out = Vec::with_capacity(cp + self.fft_size);
        out.extend_from_slice(&buf[self.fft_size - cp..]);
        out.extend_from_slice(&buf);
        out
    }

    /// Demodulate one symbol: drop `cp` prefix samples, FFT the next `fft_size`,
    /// returning the frequency-domain grid (natural FFT bin order).
    pub fn demodulate_symbol(&self, time: &[Complex32], cp: usize) -> Vec<Complex32> {
        assert!(time.len() >= cp + self.fft_size);
        let mut buf = time[cp..cp + self.fft_size].to_vec();
        self.fft.process(&mut buf);
        for s in &mut buf {
            *s *= self.scale;
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp_lengths_match_reference() {
        // mu = 0 at the 2048-point reference: the classic 160/144 samples.
        let ofdm = Ofdm::new(2048);
        assert_eq!(ofdm.cp_len(0, 0), 160);
        assert_eq!(ofdm.cp_len(7, 0), 160); // 7·2^0, second half-subframe
        assert_eq!(ofdm.cp_len(1, 0), 144);

        // mu = 1: extension doubles → 176·N/2048.
        assert_eq!(ofdm.cp_len(0, 1), 176);
        assert_eq!(ofdm.cp_len(14, 1), 176); // 7·2^1
        assert_eq!(ofdm.cp_len(1, 1), 144);

        // Slot arithmetic must close exactly: at N=512, mu=1 (fs = 15.36 MHz)
        // a 0.5 ms half-subframe of 14 symbols is 7680 samples.
        let n512 = Ofdm::new(512);
        let half_subframe: usize =
            (0..14).map(|l| n512.cp_len(l, 1) + 512).sum();
        assert_eq!(half_subframe, 7680);
        assert_eq!(n512.cp_len(0, 1), 44);
        assert_eq!(n512.cp_len(1, 1), 36);
    }

    #[test]
    fn modulate_demodulate_roundtrip() {
        let ofdm = Ofdm::new(256);
        let grid: Vec<Complex32> = (0..256)
            .map(|k| Complex32::new((k % 5) as f32 - 2.0, (k % 7) as f32 - 3.0))
            .collect();
        let cp = ofdm.cp_len(3, 1);
        let time = ofdm.modulate_symbol(&grid, cp);
        assert_eq!(time.len(), cp + 256);
        let recovered = ofdm.demodulate_symbol(&time, cp);
        for (a, b) in grid.iter().zip(&recovered) {
            assert!((a - b).norm() < 1e-3, "{a} vs {b}");
        }
    }
}
