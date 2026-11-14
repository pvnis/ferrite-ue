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
            fft_size.is_multiple_of(128),
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

    /// Samples in one 1 ms subframe at this FFT size and numerology `mu`:
    /// `fs · 1 ms = N · 15 · 2^mu` (exact for every NR sample rate, since
    /// `fs = N · 15 kHz · 2^mu`).
    pub fn samples_per_subframe(&self, mu: u8) -> usize {
        self.fft_size * (15usize << mu)
    }

    /// Samples in one slot (`2^mu` slots per subframe, §4.3.2).
    pub fn samples_per_slot(&self, mu: u8) -> usize {
        self.samples_per_subframe(mu) >> mu
    }

    /// Sample offset, from the start of the subframe, of the *cyclic prefix* of
    /// symbol `symbol_in_subframe` (`0..14·2^mu`): the sum of `CP + N` over all
    /// preceding symbols of the subframe (§5.3.1).
    pub fn symbol_offset_in_subframe(&self, symbol_in_subframe: usize, mu: u8) -> usize {
        (0..symbol_in_subframe)
            .map(|l| self.cp_len(l, mu) + self.fft_size)
            .sum()
    }

    /// Sample offset, from the start of the slot, of each of the 14 symbols'
    /// cyclic prefixes, for the `slot_in_subframe`-th slot (`0..2^mu`) of its
    /// subframe (the first slot of a subframe and the slot at the half-subframe
    /// boundary start with the long CP).
    pub fn slot_symbol_offsets(&self, mu: u8, slot_in_subframe: usize) -> [usize; 14] {
        assert!(
            slot_in_subframe < (1usize << mu),
            "slot_in_subframe out of range for mu={mu}"
        );
        let mut out = [0usize; 14];
        let mut off = 0usize;
        for (l, o) in out.iter_mut().enumerate() {
            *o = off;
            off += self.cp_len(slot_in_subframe * 14 + l, mu) + self.fft_size;
        }
        out
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

/// TS 38.211 §5.4 up/down-conversion phase compensation: the transmitter
/// multiplies OFDM symbol `l` by `e^{-j2π f₀ t_start,l}` (`t_start,l` = start
/// of the symbol's useful part within the subframe, `f₀` the carrier centre),
/// so the carrier phase restarts at every symbol; a receiver must undo it
/// with `e^{+j2π f₀ t_start,l}` before combining channel estimates across
/// symbols. One coefficient per symbol of a subframe (`14·2^µ`).
#[derive(Clone, Debug)]
pub struct PhaseCompensation {
    coeffs: Vec<Complex32>,
}

impl PhaseCompensation {
    /// Table for `center_hz` at this FFT size / numerology. `rx` selects the
    /// receive direction (`+2π`); `false` gives the transmit coefficients.
    pub fn new(ofdm: &Ofdm, mu: u8, center_hz: f64, rx: bool) -> Self {
        let n = ofdm.fft_size();
        let fs = n as f64 * 15e3 * (1u32 << mu) as f64;
        let n_sym = 14 << mu;
        let mut coeffs = Vec::with_capacity(n_sym);
        let mut off = 0usize;
        for l in 0..n_sym {
            off += ofdm.cp_len(l, mu);
            // Reduce the cycle count in f64 before the trig (f₀·t is ~1e5 cycles).
            let cycles = (center_hz * off as f64 / fs).rem_euclid(1.0);
            let phase = if rx { 1.0 } else { -1.0 } * std::f64::consts::TAU * cycles;
            coeffs.push(Complex32::new(phase.cos() as f32, phase.sin() as f32));
            off += n;
        }
        Self { coeffs }
    }

    /// Identity table (no compensation, `f₀ = 0`).
    pub fn none(mu: u8) -> Self {
        Self {
            coeffs: vec![Complex32::new(1.0, 0.0); 14 << mu],
        }
    }

    #[inline]
    pub fn coefficient(&self, symbol_in_subframe: usize) -> Complex32 {
        self.coeffs[symbol_in_subframe]
    }

    /// Apply to a demodulated (or to-be-modulated) symbol grid in place.
    pub fn apply(&self, grid: &mut [Complex32], symbol_in_subframe: usize) {
        let c = self.coeffs[symbol_in_subframe];
        if c.re != 1.0 || c.im != 0.0 {
            for g in grid.iter_mut() {
                *g *= c;
            }
        }
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
        let half_subframe: usize = (0..14).map(|l| n512.cp_len(l, 1) + 512).sum();
        assert_eq!(half_subframe, 7680);
        assert_eq!(n512.cp_len(0, 1), 44);
        assert_eq!(n512.cp_len(1, 1), 36);
    }

    #[test]
    fn slot_and_subframe_sample_counts() {
        let n = Ofdm::new(512);
        assert_eq!(n.samples_per_subframe(1), 15_360); // 15.36 MHz · 1 ms
        assert_eq!(n.samples_per_slot(1), 7_680);
        // Same FFT size at mu=0 is fs = 7.68 MHz: one 1 ms slot of 7680 samples.
        assert_eq!(n.samples_per_slot(0), 7_680);
        assert_eq!(n.samples_per_subframe(0), 7_680);
        // Offsets close exactly on the slot length for both slots of a mu=1 subframe.
        for s in 0..2 {
            let offs = n.slot_symbol_offsets(1, s);
            assert_eq!(offs[0], 0);
            assert_eq!(offs[1], n.cp_len(14 * s, 1) + 512);
            let total = offs[13] + n.cp_len(14 * s + 13, 1) + 512;
            assert_eq!(total, n.samples_per_slot(1));
        }
        // Symbol 14 at mu=1 is the second slot's first symbol (long CP).
        assert_eq!(n.symbol_offset_in_subframe(14, 1), n.samples_per_slot(1));
        assert_eq!(
            n.symbol_offset_in_subframe(28, 1),
            n.samples_per_subframe(1)
        );
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

    #[test]
    fn phase_compensation_restarts_each_symbol_and_cancels() {
        // 11.52 MHz, 15 kHz, 1842.5 MHz: symbol 7 (long CP) carries an extra
        // 6-sample step; rx × tx must be the identity.
        let ofdm = Ofdm::new(768);
        let rx = PhaseCompensation::new(&ofdm, 0, 1842.5e6, true);
        let tx = PhaseCompensation::new(&ofdm, 0, 1842.5e6, false);
        for l in 0..14 {
            let p = rx.coefficient(l) * tx.coefficient(l);
            assert!((p.re - 1.0).abs() < 1e-5 && p.im.abs() < 1e-5);
        }
        // Reference: coefficient = exp(j2π f0 · t_start,l), t_start,l from the CP sums.
        let fs = 11.52e6;
        let t7 = (60 + 768 + 6 * (54 + 768) + 60) as f64 / fs;
        let want = (std::f64::consts::TAU * (1842.5e6 * t7).rem_euclid(1.0)) as f32;
        let got = rx.coefficient(7).arg();
        assert!(
            ((got - want + std::f32::consts::PI).rem_euclid(std::f32::consts::TAU)
                - std::f32::consts::PI)
                .abs()
                < 1e-3
        );
        assert_eq!(
            PhaseCompensation::none(1).coefficient(27),
            Complex32::new(1.0, 0.0)
        );
    }
}
