//! Full downlink cell search: PSS (timing + `N_ID^(2)`) then SSS (`N_ID^(1)`),
//! yielding the physical cell identity `N_cell_ID = 3·N_ID^(1) + N_ID^(2)`, and
//! the PBCH decode that completes it (SSB index, half frame, MIB).
//!
//! Within an SSB the SSS sits two OFDM symbols after the PSS (symbols 0 and 2).
//! We demodulate that symbol at the PSS-derived timing and correlate its 127
//! subcarriers against every `N_ID^(1)` candidate. Because the SSS is BPSK, a
//! magnitude correlation is invariant to the unknown flat channel gain/phase.
//!
//! Generic over the SSB numerology `mu ∈ {0, 1}` (Cases A/B/C, TS 38.213
//! §4.1) and `L_max ∈ {4, 8}`.

use num_complex::Complex32;

use crate::coding::bch::{bch_decode, Mib};
use crate::ofdm::Ofdm;
use crate::sync::cfo::estimate_cfo_hz_multi;
use crate::sync::detect::PssDetector;
use crate::sync::pbch::{rank_ssb_index, equalize_pbch, extract_pbch};
use crate::sync::ssb::{extract_sync_subcarriers, SSB_SYMBOLS};
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
    /// Estimated carrier frequency offset in Hz (from the SSB cyclic prefixes,
    /// unambiguous within ±½ SCS).
    pub cfo_hz: f64,
    /// PSS peak metric.
    pub pss_metric: f32,
    /// SSS peak metric.
    pub sss_metric: f32,
}

/// A decoded PBCH: the MIB plus the SSB timing it pins down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PbchDecode {
    /// The decoded MIB (CRC-verified).
    pub mib: Mib,
    /// Candidate SSB index within the half frame (`0..L_max`): the index into
    /// [`crate::sync::ssb::SsbCase::candidate_symbols`].
    pub i_ssb: u8,
    /// Half frame (0/1) carrying the SSB, from the CRC-protected PBCH payload.
    pub half_frame: u8,
}

/// Downlink cell searcher combining PSS and SSS detection with the PBCH decode.
/// Minimum normalised PSS correlation accepted as a detection.
pub const PSS_DETECTION_THRESHOLD: f32 = 0.3;
/// Minimum normalised SSS correlation accepted as a detection.
pub const SSS_DETECTION_THRESHOLD: f32 = 0.3;

pub struct CellSearcher {
    ofdm: Ofdm,
    pss: PssDetector,
    mu: u8,
    l_max: u8,
}

impl CellSearcher {
    /// Build a searcher for the given SSB FFT size, SSB numerology `mu` and
    /// `L_max` (4 or 8; see [`crate::sync::ssb::SsbCase::l_max`]).
    pub fn new(fft_size: usize, mu: u8, l_max: u8) -> Self {
        assert!(l_max == 4 || l_max == 8, "FR1 L_max is 4 or 8");
        let ofdm = Ofdm::new(fft_size);
        let pss = PssDetector::new(&ofdm);
        Self { ofdm, pss, mu, l_max }
    }

    /// The OFDM (de)modulator (SSB FFT size).
    pub fn ofdm(&self) -> &Ofdm {
        &self.ofdm
    }

    /// The PSS matched-filter bank (for narrow-window tracking).
    pub fn pss_detector(&self) -> &PssDetector {
        &self.pss
    }

    /// SSB numerology.
    pub fn mu(&self) -> u8 {
        self.mu
    }

    /// `L_max` this searcher decodes for.
    pub fn l_max(&self) -> u8 {
        self.l_max
    }

    /// Normal CP length of the SSB symbols (no FR1 SSB candidate spans a
    /// long-CP symbol).
    fn ssb_cp(&self) -> usize {
        self.ofdm.cp_len(1, self.mu)
    }

    /// Run PSS then SSS detection over `samples`. Returns `None` if no PSS is
    /// found or the buffer is too short to contain the SSS symbol.
    pub fn search(&self, samples: &[Complex32]) -> Option<CellSearchResult> {
        let pss = self.pss.search(samples)?;
        // A normalised PSS correlation below the noise floor is no detection
        // (pure noise reads ~0.1-0.2 at these window sizes; a real SSB ≫ 0.3).
        if pss.metric < PSS_DETECTION_THRESHOLD {
            return None;
        }
        self.complete(samples, pss)
    }

    /// Re-run the SSS detection (and CFO estimate) for a *known* `N_ID^(2)`
    /// around a known position: PSS re-correlation restricted to
    /// `start_range`, the tracking fast path.
    pub fn search_near(
        &self,
        samples: &[Complex32],
        n_id_2: u8,
        start_range: std::ops::Range<usize>,
    ) -> Option<CellSearchResult> {
        let pss = self.pss.track(samples, n_id_2, start_range)?;
        self.complete(samples, pss)
    }

    fn complete(&self, samples: &[Complex32], pss: crate::sync::PssDetection) -> Option<CellSearchResult> {
        let n = self.ofdm.fft_size();
        let cp = self.ssb_cp();
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
            estimate_cfo_hz_multi(&samples[pss.sample_index - cp..], cp, n, SSB_SYMBOLS, scs_hz)
        } else {
            0.0
        };

        if sss.metric < SSS_DETECTION_THRESHOLD {
            return None;
        }
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
    /// DMRS index `ī_SSB` blindly, equalize, and polar-decode the MIB.
    ///
    /// `samples` should already be CFO-corrected (use [`CellSearchResult::cfo_hz`]
    /// with [`crate::sync::cfo::correct_cfo`]). Returns `None` if extraction
    /// fails or no SCL path passes the CRC. For `L_max = 4` the half frame is
    /// taken from the CRC-protected payload (the DMRS carries it too, but the
    /// scrambling does not distinguish the two half-frame hypotheses, so the
    /// payload bit is the reliable one).
    pub fn decode_mib(&self, samples: &[Complex32], found: &CellSearchResult) -> Option<PbchDecode> {
        let (rx_dmrs, rx_data, layout) =
            extract_pbch(&self.ofdm, samples, found.timing_index, self.mu, found.cell_id)?;
        // The DMRS metric separates the hypotheses only at good SNR; the BCH
        // CRC (24 bits, no false passes measured on noise) is the final
        // arbiter, so walk the hypotheses best-first until one decodes.
        for det in rank_ssb_index(&rx_dmrs, found.cell_id, self.l_max) {
            let llrs = equalize_pbch(&rx_dmrs, &rx_data, &layout, found.cell_id, det.i_ssb_bar);
            if let Some(mib) = bch_decode(&llrs, found.cell_id, det.scrambling_index()) {
                return Some(PbchDecode {
                    mib,
                    i_ssb: det.candidate_index(),
                    half_frame: mib.half_frame,
                });
            }
        }
        None
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
        let cp = ofdm.cp_len(1, mu);
        let mut wave = Vec::new();
        wave.extend(ofdm.modulate_symbol(&pss_grid(n_id_2, n), cp)); // symbol 0
        wave.extend(ofdm.modulate_symbol(&random_grid(n, rng), cp)); // symbol 1 (PBCH)
        wave.extend(ofdm.modulate_symbol(&sss_grid(n_id_1, n_id_2, n), cp)); // symbol 2
        wave.extend(ofdm.modulate_symbol(&random_grid(n, rng), cp)); // symbol 3 (PBCH)
        wave
    }

    fn check_cell_ids(mu: u8, fft: usize, seed: u64) {
        let searcher = CellSearcher::new(fft, mu, if mu == 0 { 4 } else { 8 });
        let ofdm = Ofdm::new(fft);
        let fs = fft as f64 * f64::from(15_000u32 << mu);
        let mut rng = Rng(seed);

        for &(n_id_1, n_id_2) in &[(0u16, 0u8), (100, 1), (335, 2), (207, 0)] {
            let ssb = build_ssb(n_id_1, n_id_2, &ofdm, mu, &mut rng);
            let mut sig = vec![Complex32::new(0.0, 0.0); 250];
            sig.extend_from_slice(&ssb);
            sig.extend(std::iter::repeat_n(Complex32::new(0.0, 0.0), 250));

            // Flat channel, a CFO of ~2.7% SCS, 20 dB SNR.
            let h = Complex32::from_polar(0.7, 1.2);
            let cfo = 0.027 * (15_000u32 << mu) as f32;
            let snr_db = 20.0f32;
            let sig_rms =
                (ssb.iter().map(|s| s.norm_sqr()).sum::<f32>() / ssb.len() as f32).sqrt();
            let sigma = sig_rms / 10f32.powf(snr_db / 20.0);
            for (m, s) in sig.iter_mut().enumerate() {
                *s = *s * h * Complex32::from_polar(1.0, TAU * cfo * m as f32 / fs as f32);
                *s += Complex32::new(rng.normal(), rng.normal()) * (sigma / SQRT_2);
            }

            let r = searcher.search(&sig).unwrap();
            let expected = 3 * n_id_1 + u16::from(n_id_2);
            assert_eq!(r.n_id_2, n_id_2, "N_ID(2) for cell {expected}");
            assert_eq!(r.n_id_1, n_id_1, "N_ID(1) for cell {expected}");
            assert_eq!(r.cell_id, expected, "cell id");
            assert!(r.sss_metric > 0.5, "sss metric {}", r.sss_metric);
            assert!(
                (r.cfo_hz - f64::from(cfo)).abs() < 0.01 * f64::from(15_000u32 << mu),
                "cfo est {} vs {cfo}",
                r.cfo_hz
            );
        }
    }

    #[test]
    fn recovers_full_physical_cell_id_mu1() {
        check_cell_ids(1, 256, 0x0BAD_C0DE_1111);
    }

    #[test]
    fn recovers_full_physical_cell_id_mu0() {
        check_cell_ids(0, 256, 0x0BAD_C0DE_2222);
    }
}
