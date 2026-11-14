//! SS/PBCH-block based cell quality measurements (TS 38.215 §5.1.1–5.1.3,
//! §5.1.5): SS-RSRP, SS-RSSI, SS-RSRQ and SS-SINR of one SSB, from the SSS
//! symbol.
//!
//! * SS-RSRP: linear average of the power of the REs carrying the SSS,
//!   estimated coherently (the SSS is a known ±1 sequence, so the channel on
//!   each RE is `y_k·s_k`; averaging those before taking the power removes the
//!   noise contribution a per-RE power average would include).
//! * SS-RSSI: total received power over the SSB bandwidth (`N` = 20 RBs) of
//!   the SSS symbol.
//! * SS-RSRQ: `N·RSRP / RSSI`.
//! * SS-SINR: coherent signal power over the residual after removing it.
//!
//! Values are linear in the receiver's own scale (dBFS once converted); the
//! absolute calibration to dBm is the radio backend's business.

use super::ssb::{ssb_subcarrier_bin, SYNC_SC_START};
use super::sss::{sss, SSS_LEN};
use crate::Ofdm;
use num_complex::Complex32;

/// Number of RBs the SSB spans.
pub const SSB_N_RB: usize = 20;

/// One SSB measurement in linear units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SsbMeasurement {
    /// SS-RSRP per RE (linear power).
    pub rsrp: f32,
    /// SS-RSSI over the 20 SSB RBs (linear power).
    pub rssi: f32,
    /// SS-SINR (linear).
    pub sinr: f32,
}

impl SsbMeasurement {
    pub fn rsrp_db(&self) -> f32 {
        10.0 * self.rsrp.max(1e-30).log10()
    }
    pub fn rsrq_db(&self) -> f32 {
        10.0 * (SSB_N_RB as f32 * self.rsrp / self.rssi.max(1e-30))
            .max(1e-30)
            .log10()
    }
    pub fn sinr_db(&self) -> f32 {
        10.0 * self.sinr.max(1e-30).log10()
    }
}

/// Measure the SSB whose PSS useful part starts at `pss_useful_start` in
/// `samples` (the SSS is two symbols later), for cell `n_id_1`/`n_id_2`.
/// `None` when the samples do not cover the SSS symbol.
pub fn ssb_measure(
    ofdm: &Ofdm,
    samples: &[Complex32],
    pss_useful_start: usize,
    mu: u8,
    n_id_1: u16,
    n_id_2: u8,
) -> Option<SsbMeasurement> {
    let n = ofdm.fft_size();
    let cp = ofdm.cp_len(1, mu);
    let start = pss_useful_start + 2 * (n + cp);
    if start + n > samples.len() {
        return None;
    }
    let grid = ofdm.demodulate_symbol(&samples[start..], 0);
    let seq = sss(n_id_1, n_id_2);
    // Coherent channel average over the SSS REs.
    let mut h_sum = Complex32::new(0.0, 0.0);
    let mut ys = [Complex32::new(0.0, 0.0); SSS_LEN];
    for (i, y) in ys.iter_mut().enumerate() {
        *y = grid[ssb_subcarrier_bin(SYNC_SC_START + i, n)] * seq[i] as f32;
        h_sum += *y;
    }
    let h = h_sum / SSS_LEN as f32;
    let rsrp = h.norm_sqr();
    let noise: f32 = ys.iter().map(|y| (y - h).norm_sqr()).sum::<f32>() / SSS_LEN as f32;
    let sinr = rsrp / noise.max(1e-30);
    // RSSI over the whole SSB bandwidth of the SSS symbol.
    let rssi: f32 = (0..12 * SSB_N_RB)
        .map(|k| grid[ssb_subcarrier_bin(k, n)].norm_sqr())
        .sum();
    Some(SsbMeasurement { rsrp, rssi, sinr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::ssb::sss_grid;

    /// An SSS symbol at known amplitude, with and without white noise.
    #[test]
    fn measures_a_synthetic_sss() {
        let ofdm = Ofdm::new(256);
        let n = 256;
        let cp = ofdm.cp_len(1, 1);
        let (n_id_1, n_id_2) = (123u16, 1u8);
        let amp = 0.5f32;
        let grid: Vec<Complex32> = sss_grid(n_id_1, n_id_2, n)
            .iter()
            .map(|v| v * amp)
            .collect();
        let sym = ofdm.modulate_symbol(&grid, cp);
        // Lay out PSS(0) PBCH(1) SSS(2) with zeros around the SSS.
        let mut samples = vec![Complex32::new(0.0, 0.0); 4 * (n + cp)];
        samples[2 * (n + cp) + cp..3 * (n + cp)].copy_from_slice(&sym[cp..]);
        let m = ssb_measure(&ofdm, &samples, cp, 1, n_id_1, n_id_2).unwrap();
        // The demodulator scales so that a unit-amplitude RE comes back as itself.
        let expect = amp * amp;
        assert!(
            (m.rsrp / expect - 1.0).abs() < 1e-3,
            "rsrp {} expect {expect}",
            m.rsrp
        );
        assert!(m.sinr_db() > 60.0, "clean sinr {}", m.sinr_db());
        // Only the SSS carries power: RSSI = 127·RSRP.
        assert!((m.rssi / (expect * 127.0) - 1.0).abs() < 1e-3);
        assert!((m.rsrq_db() - 10.0 * (20.0f32 / 127.0).log10()).abs() < 0.05);

        // Add noise at 10 dB below the per-RE signal power over the whole symbol.
        let mut seed = 1u64;
        let mut gauss = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let u = (seed >> 11) as f32 / (1u64 << 53) as f32;
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let v = (seed >> 11) as f32 / (1u64 << 53) as f32;
            (-2.0 * u.max(1e-12).ln()).sqrt() * (std::f32::consts::TAU * v).cos()
        };
        let sigma = (expect / 10.0 / 2.0).sqrt() / (n as f32).sqrt() * (n as f32).sqrt();
        let mut noisy = samples.clone();
        for s in noisy.iter_mut() {
            *s += Complex32::new(gauss() * sigma, gauss() * sigma);
        }
        let m = ssb_measure(&ofdm, &noisy, cp, 1, n_id_1, n_id_2).unwrap();
        assert!(
            (m.rsrp / expect - 1.0).abs() < 0.2,
            "noisy rsrp {} expect {expect}",
            m.rsrp
        );
        assert!(
            (m.sinr_db() - 10.0).abs() < 2.0,
            "noisy sinr {} dB",
            m.sinr_db()
        );
    }
}
