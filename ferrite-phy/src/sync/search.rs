//! Full downlink cell search: PSS (timing + `N_ID^(2)`) then SSS (`N_ID^(1)`),
//! yielding the physical cell identity `N_cell_ID = 3·N_ID^(1) + N_ID^(2)`.
//!
//! Within an SSB the SSS sits two OFDM symbols after the PSS (symbols 0 and 2).
//! We demodulate that symbol at the PSS-derived timing and correlate its 127
//! subcarriers against every `N_ID^(1)` candidate. Because the SSS is BPSK, a
//! magnitude correlation is invariant to the unknown flat channel gain/phase.

use num_complex::Complex32;

use crate::coding::bch::{bch_decode, Mib};
use crate::ofdm::Ofdm;
use crate::sync::cfo::estimate_cfo_hz_multi;
use crate::sync::detect::PssDetector;
use crate::sync::pbch::{detect_ssb_index, equalize_pbch, extract_pbch, L_MAX_FR1_ABOVE_3GHZ};
use crate::sync::ssb::extract_sync_subcarriers;
use crate::sync::sss::sss;
use crate::sync::{physical_cell_id, N_ID_1_COUNT};

/// Outcome of correlating received SSS subcarriers over all `N_ID^(1)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SssDetection {
    /// Detected `N_ID^(1)` in `0..336`.
    pub n_id_1: u16,
    /// Peak normalized correlation in `[0, 1]`.
    pub metric: f32,
}

/// Detect `N_ID^(1)` from received SSS subcarriers, given the known `N_ID^(2)`.
///
/// `rx` holds the 127 demodulated SSS subcarriers (in SSB order). The metric is
/// `|⟨rx, ref⟩| / (‖rx‖·√127)`, which is 1 for a noiseless, flat-channel match.
pub fn detect_sss(rx: &[Complex32], n_id_2: u8) -> SssDetection {
    let rx_norm: f32 = rx.iter().map(|s| s.norm_sqr()).sum::<f32>().sqrt();
    let inv = if rx_norm > 0.0 { 1.0 / rx_norm } else { 0.0 };
    let ref_norm = (rx.len() as f32).sqrt();

    let mut best = SssDetection {
        n_id_1: 0,
        metric: -1.0,
    };
    for n_id_1 in 0..N_ID_1_COUNT {
        let seq = sss(n_id_1, n_id_2);
        let mut acc = Complex32::new(0.0, 0.0);
        for (r, &s) in rx.iter().zip(seq.iter()) {
            acc += r * s as f32;
        }
        let metric = acc.norm() * inv / ref_norm;
        if metric > best.metric {
            best = SssDetection { n_id_1, metric };
        }
    }
    best
}

/// A completed cell-search result.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CellSearchResult {
    /// Physical cell identity `N_cell_ID` in `0..1008`.
    pub cell_id: u16,
    /// `N_ID^(1)` (from SSS).
    pub n_id_1: u16,
    /// `N_ID^(2)` (from PSS).
    pub n_id_2: u8,
    /// Sample index of the PSS symbol's useful part (coarse timing).
    pub timing_index: usize,
    /// Estimated carrier frequency offset in Hz (from the PSS cyclic prefix,
    /// unambiguous within ±½ SCS).
    pub cfo_hz: f64,
    /// PSS peak metric.
    pub pss_metric: f32,
    /// SSS peak metric.
    pub sss_metric: f32,
}

/// Downlink cell searcher combining PSS and SSS detection.
pub struct CellSearcher {
    ofdm: Ofdm,
    pss: PssDetector,
    mu: u8,
}

impl CellSearcher {
    /// Build a searcher for the given SSB FFT size and numerology `mu`.
    pub fn new(fft_size: usize, mu: u8) -> Self {
        let ofdm = Ofdm::new(fft_size);
        let pss = PssDetector::new(&ofdm);
        Self { ofdm, pss, mu }
    }

    /// Run PSS then SSS detection over `samples`. Returns `None` if no PSS is
    /// found or the buffer is too short to contain the SSS symbol.
    pub fn search(&self, samples: &[Complex32]) -> Option<CellSearchResult> {
        let pss = self.pss.search(samples)?;
        let n = self.ofdm.fft_size();
        // For SSB Case C (n78, 30 kHz) all four SSB symbols use the normal CP.
        let cp = self.ofdm.cp_len(3, self.mu);
        // SSS useful part = two full OFDM symbols after the PSS useful part.
        let sss_start = pss.sample_index + 2 * (n + cp);
        if sss_start + n > samples.len() {
            return None;
        }

        let grid = self.ofdm.demodulate_symbol(&samples[sss_start..], 0);
        let rx_sss = extract_sync_subcarriers(&grid);
        let sss = detect_sss(&rx_sss, pss.n_id_2);
        let cell_id = physical_cell_id(sss.n_id_1, pss.n_id_2)?;

        // Fine CFO: accumulate the CP autocorrelation over the SSB's symbols
        // (all share one offset), starting at the PSS symbol's cyclic prefix.
        let scs_hz = f64::from(15_000u32 << self.mu);
        let cfo_hz = if pss.sample_index >= cp {
            estimate_cfo_hz_multi(&samples[pss.sample_index - cp..], cp, n, 4, scs_hz)
        } else {
            0.0
        };

        Some(CellSearchResult {
            cell_id,
            n_id_1: sss.n_id_1,
            n_id_2: pss.n_id_2,
            timing_index: pss.sample_index,
            cfo_hz,
            pss_metric: pss.metric,
            sss_metric: sss.metric,
        })
    }

    /// Complete the cell search by decoding the PBCH at a found cell: detect the
    /// SSB index blindly from the DMRS, equalize, and polar-decode the MIB.
    ///
    /// `samples` should already be CFO-corrected (use [`CellSearchResult::cfo_hz`]
    /// with [`crate::sync::cfo::correct_cfo`]). Returns the MIB and the detected
    /// `i_SSB`, or `None` if extraction fails or no SCL path passes the CRC.
    pub fn decode_mib(
        &self,
        samples: &[Complex32],
        found: &CellSearchResult,
    ) -> Option<(Mib, u8)> {
        let (rx_dmrs, rx_data, layout) = extract_pbch(
            &self.ofdm,
            samples,
            found.timing_index,
            self.mu,
            found.cell_id,
        )?;
        let det = detect_ssb_index(&rx_dmrs, found.cell_id, L_MAX_FR1_ABOVE_3GHZ);
        let llrs = equalize_pbch(&rx_dmrs, &rx_data, &layout, found.cell_id, det.i_ssb);
        let mib = bch_decode(&llrs, found.cell_id, det.i_ssb)?;
        Some((mib, det.i_ssb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::ssb::{pss_grid, sss_grid};
    use std::f32::consts::{SQRT_2, TAU};

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

    fn random_grid(n: usize, rng: &mut Rng) -> Vec<Complex32> {
        (0..n)
            .map(|_| Complex32::new(rng.normal(), rng.normal()))
            .collect()
    }

    /// Build a full 4-symbol SSB (PSS, PBCH, SSS, PBCH) as a time-domain wave.
    fn build_ssb(n_id_1: u16, n_id_2: u8, ofdm: &Ofdm, mu: u8, rng: &mut Rng) -> Vec<Complex32> {
        let n = ofdm.fft_size();
        let cp = ofdm.cp_len(3, mu);
        let mut wave = Vec::new();
        wave.extend(ofdm.modulate_symbol(&pss_grid(n_id_2, n), cp)); // symbol 0
        wave.extend(ofdm.modulate_symbol(&random_grid(n, rng), cp)); // symbol 1 (PBCH)
        wave.extend(ofdm.modulate_symbol(&sss_grid(n_id_1, n_id_2, n), cp)); // symbol 2
        wave.extend(ofdm.modulate_symbol(&random_grid(n, rng), cp)); // symbol 3 (PBCH)
        wave
    }

    #[test]
    fn recovers_full_physical_cell_id() {
        let mu = 1u8;
        let searcher = CellSearcher::new(256, mu);
        let ofdm = Ofdm::new(256);
        let fs = 256.0 * 30_000.0;
        let mut rng = Rng(0x0BAD_C0DE_1111);

        for &(n_id_1, n_id_2) in &[(0u16, 0u8), (100, 1), (335, 2), (207, 0)] {
            let ssb = build_ssb(n_id_1, n_id_2, &ofdm, mu, &mut rng);
            let mut sig = vec![Complex32::new(0.0, 0.0); 250];
            sig.extend_from_slice(&ssb);
            sig.extend(std::iter::repeat(Complex32::new(0.0, 0.0)).take(250));

            // Flat channel, 800 Hz CFO, ~20 dB SNR.
            let h = Complex32::from_polar(0.7, 1.2);
            let cfo = 800.0f32;
            let sig_rms =
                (ssb.iter().map(|s| s.norm_sqr()).sum::<f32>() / ssb.len() as f32).sqrt();
            let sigma = sig_rms / 10f32.powf(20.0 / 20.0);
            for (m, s) in sig.iter_mut().enumerate() {
                *s = *s * h * Complex32::from_polar(1.0, TAU * cfo * m as f32 / fs);
                *s += Complex32::new(rng.normal(), rng.normal()) * (sigma / SQRT_2);
            }

            let r = searcher.search(&sig).unwrap();
            let expected = 3 * n_id_1 + u16::from(n_id_2);
            assert_eq!(r.n_id_2, n_id_2, "N_ID(2) for cell {expected}");
            assert_eq!(r.n_id_1, n_id_1, "N_ID(1) for cell {expected}");
            assert_eq!(r.cell_id, expected, "cell id");
            assert!(r.sss_metric > 0.5, "sss metric {}", r.sss_metric);
            assert!((r.cfo_hz - cfo as f64).abs() < 300.0, "cfo est {}", r.cfo_hz);
        }
    }
}
