//! Time-domain PSS search: coarse symbol timing + `N_ID^(2)`.
//!
//! The three PSS time-domain waveforms are used as matched filters. For every
//! candidate start offset we compute the normalized correlation
//! `|⟨window, ref⟩| / ‖window‖` (the reference is unit energy), which is
//! amplitude-invariant and bounded in `[0, 1]`. The largest response over all
//! offsets and all `N_ID^(2)` gives coarse timing and the PSS identity.

use num_complex::Complex32;

use crate::ofdm::Ofdm;
use crate::sync::ssb::pss_time_reference;
use crate::sync::N_ID_2_COUNT;

/// Result of a PSS search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PssDetection {
    /// Sample index (into the searched buffer) of the PSS symbol's useful part.
    pub sample_index: usize,
    /// Detected `N_ID^(2)` in `{0, 1, 2}`.
    pub n_id_2: u8,
    /// Peak normalized correlation in `[0, 1]`.
    pub metric: f32,
}

/// Matched-filter bank for the three PSS sequences.
pub struct PssDetector {
    refs: Vec<Vec<Complex32>>,
    len: usize,
}

impl PssDetector {
    /// Build the detector for the given OFDM configuration.
    pub fn new(ofdm: &Ofdm) -> Self {
        let refs = (0..N_ID_2_COUNT)
            .map(|n| pss_time_reference(n, ofdm))
            .collect();
        Self {
            refs,
            len: ofdm.fft_size(),
        }
    }

    /// The correlation window length (one OFDM symbol, `N` samples).
    pub fn window_len(&self) -> usize {
        self.len
    }

    /// Re-correlate a *known* PSS (`n_id_2`) over a restricted window of start
    /// offsets — the tracking fast path once a cell is acquired. `start_range`
    /// is clamped to the buffer. Returns `None` if the window is empty.
    pub fn track(
        &self,
        samples: &[Complex32],
        n_id_2: u8,
        start_range: std::ops::Range<usize>,
    ) -> Option<PssDetection> {
        let reference = &self.refs[usize::from(n_id_2)];
        let last_start = samples.len().checked_sub(self.len)?;
        let lo = start_range.start.min(last_start);
        let hi = start_range.end.min(last_start + 1);
        let mut best: Option<PssDetection> = None;
        for start in lo..hi {
            let window = &samples[start..start + self.len];
            let energy: f32 = window.iter().map(|s| s.norm_sqr()).sum();
            if energy <= 0.0 {
                continue;
            }
            let mut acc = Complex32::new(0.0, 0.0);
            for (w, r) in window.iter().zip(reference) {
                acc += w * r.conj();
            }
            let metric = acc.norm() / energy.sqrt();
            if best.as_ref().is_none_or(|b| metric > b.metric) {
                best = Some(PssDetection {
                    sample_index: start,
                    n_id_2,
                    metric,
                });
            }
        }
        best
    }

    /// Search `samples` for the strongest PSS response. Returns `None` if the
    /// input is shorter than one symbol.
    pub fn search(&self, samples: &[Complex32]) -> Option<PssDetection> {
        if samples.len() < self.len {
            return None;
        }
        let last_start = samples.len() - self.len;
        let mut best = PssDetection {
            sample_index: 0,
            n_id_2: 0,
            metric: -1.0,
        };

        for start in 0..=last_start {
            let window = &samples[start..start + self.len];
            let energy: f32 = window.iter().map(|s| s.norm_sqr()).sum();
            if energy <= 0.0 {
                continue;
            }
            let inv_norm = 1.0 / energy.sqrt();

            for (n_id_2, reference) in self.refs.iter().enumerate() {
                let mut acc = Complex32::new(0.0, 0.0);
                for (w, r) in window.iter().zip(reference) {
                    acc += w * r.conj();
                }
                let metric = acc.norm() * inv_norm;
                if metric > best.metric {
                    best = PssDetection {
                        sample_index: start,
                        n_id_2: n_id_2 as u8,
                        metric,
                    };
                }
            }
        }
        Some(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::ssb::pss_grid;
    use std::f32::consts::{SQRT_2, TAU};

    /// Deterministic xorshift64* PRNG → standard-normal samples (Box–Muller).
    struct Rng(u64);
    impl Rng {
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

    /// Build a transmitted PSS OFDM symbol (with its cyclic prefix).
    fn pss_symbol_with_cp(n_id_2: u8, ofdm: &Ofdm) -> (Vec<Complex32>, usize) {
        let cp = ofdm.cp_len(0, 1);
        let grid = pss_grid(n_id_2, ofdm.fft_size());
        (ofdm.modulate_symbol(&grid, cp), cp)
    }

    #[test]
    fn detects_timing_and_nid2_noiseless() {
        let ofdm = Ofdm::new(256);
        let detector = PssDetector::new(&ofdm);
        let true_nid2 = 2u8;
        let (symbol, cp) = pss_symbol_with_cp(true_nid2, &ofdm);

        let prepad = 137usize;
        let mut sig = vec![Complex32::new(0.0, 0.0); prepad];
        sig.extend_from_slice(&symbol);
        sig.extend(std::iter::repeat_n(Complex32::new(0.0, 0.0), 200));

        let d = detector.search(&sig).unwrap();
        assert_eq!(d.n_id_2, true_nid2);
        assert_eq!(d.sample_index, prepad + cp); // start of the useful part
        assert!(d.metric > 0.99, "metric {}", d.metric);
    }

    #[test]
    fn detects_under_cfo_and_noise() {
        let ofdm = Ofdm::new(256);
        let fs = 256.0 * 30_000.0; // 7.68 MHz
        let detector = PssDetector::new(&ofdm);
        let true_nid2 = 1u8;
        let (symbol, cp) = pss_symbol_with_cp(true_nid2, &ofdm);

        let prepad = 300usize;
        let mut sig = vec![Complex32::new(0.0, 0.0); prepad];
        sig.extend_from_slice(&symbol);
        sig.extend(std::iter::repeat_n(Complex32::new(0.0, 0.0), 300));

        // Per-sample signal RMS over the symbol (for SNR scaling).
        let sig_rms =
            (symbol.iter().map(|s| s.norm_sqr()).sum::<f32>() / symbol.len() as f32).sqrt();

        // Apply a 2 kHz carrier frequency offset.
        let cfo = 2_000.0f32;
        for (n, s) in sig.iter_mut().enumerate() {
            *s *= Complex32::from_polar(1.0, TAU * cfo * n as f32 / fs as f32);
        }

        // Add complex AWGN at ~6 dB SNR over the symbol region.
        let sigma = sig_rms * 0.5;
        let mut rng = Rng(0x00C0_FFEE_1234_5678);
        for s in sig.iter_mut() {
            *s += Complex32::new(rng.normal() * sigma / SQRT_2, rng.normal() * sigma / SQRT_2);
        }

        let d = detector.search(&sig).unwrap();
        assert_eq!(d.n_id_2, true_nid2, "wrong N_ID(2)");
        let expected = (prepad + cp) as i64;
        assert!(
            (d.sample_index as i64 - expected).abs() <= 2,
            "timing {} vs expected {}",
            d.sample_index,
            expected
        );
        assert!(d.metric > 0.3, "metric {}", d.metric);
    }

    /// A buffer of pure noise must not report a confident detection.
    #[test]
    fn noise_only_stays_below_threshold() {
        let ofdm = Ofdm::new(256);
        let detector = PssDetector::new(&ofdm);
        let mut rng = Rng(0xDEAD_BEEF_0042);
        let sig: Vec<Complex32> = (0..2000)
            .map(|_| Complex32::new(rng.normal(), rng.normal()))
            .collect();
        let d = detector.search(&sig).unwrap();
        assert!(
            d.metric < 0.3,
            "noise metric unexpectedly high: {}",
            d.metric
        );
    }
}
