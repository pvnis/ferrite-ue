//! PBCH demodulation-reference-signal (DMRS) — 3GPP TS 38.211 §7.4.1.4.
//!
//! The PBCH carries 144 DMRS resource elements per SSB, generated from the Gold
//! sequence with a seed that depends on the cell ID and the SSB index `i_SSB`.
//! Because `i_SSB` (3 LSBs of the SSB index for FR1 above 3 GHz, `L_max = 8`)
//! selects the seed, correlating the received DMRS against the eight candidates
//! recovers the SSB index blindly.

use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

use crate::ofdm::Ofdm;
use crate::sequence::gold_sequence;
use crate::sync::ssb::ssb_subcarrier_bin;

/// Number of PBCH DMRS resource elements per SSB.
pub const PBCH_DMRS_LEN: usize = 144;

/// Maximum number of SSBs (`L_max`) for FR1 carriers above 3 GHz (e.g. n78);
/// `i_SSB` therefore ranges over `0..8`.
pub const L_MAX_FR1_ABOVE_3GHZ: u8 = 8;

/// DMRS scrambling seed `c_init` (§7.4.1.4.1) for a cell and SSB index.
///
/// `c_init = 2^11·(i_SSB+1)·(⌊N_cell_ID/4⌋+1) + 2^6·(i_SSB+1) + (N_cell_ID mod 4)`.
pub fn dmrs_c_init(cell_id: u16, i_ssb: u8) -> u32 {
    let n = u32::from(cell_id);
    let i = u32::from(i_ssb) + 1;
    (1 << 11) * i * ((n / 4) + 1) + (1 << 6) * i + (n % 4)
}

/// Generate the 144 QPSK PBCH DMRS symbols for `cell_id` and `i_ssb`.
///
/// `r(m) = (1-2c(2m))/√2 + j(1-2c(2m+1))/√2`.
pub fn pbch_dmrs(cell_id: u16, i_ssb: u8) -> Vec<Complex32> {
    let c = gold_sequence(dmrs_c_init(cell_id, i_ssb), 2 * PBCH_DMRS_LEN);
    (0..PBCH_DMRS_LEN)
        .map(|m| {
            let re = (1 - 2 * i32::from(c[2 * m])) as f32 * FRAC_1_SQRT_2;
            let im = (1 - 2 * i32::from(c[2 * m + 1])) as f32 * FRAC_1_SQRT_2;
            Complex32::new(re, im)
        })
        .collect()
}

/// Result of blind SSB-index detection from the PBCH DMRS.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SsbIndexDetection {
    /// Detected `i_SSB` (3 LSBs of the SSB index for `L_max = 8`).
    pub i_ssb: u8,
    /// Peak normalized correlation in `[0, 1]`.
    pub metric: f32,
}

/// Detect `i_SSB` by correlating received DMRS symbols against the `L_max`
/// candidate sequences for `cell_id`. Robust to an unknown flat channel.
pub fn detect_ssb_index(rx_dmrs: &[Complex32], cell_id: u16, l_max: u8) -> SsbIndexDetection {
    let rx_norm: f32 = rx_dmrs.iter().map(|s| s.norm_sqr()).sum::<f32>().sqrt();
    let inv = if rx_norm > 0.0 { 1.0 / rx_norm } else { 0.0 };
    let ref_norm = (rx_dmrs.len() as f32).sqrt();

    let mut best = SsbIndexDetection {
        i_ssb: 0,
        metric: -1.0,
    };
    for i_ssb in 0..l_max {
        let reference = pbch_dmrs(cell_id, i_ssb);
        let mut acc = Complex32::new(0.0, 0.0);
        for (r, d) in rx_dmrs.iter().zip(&reference) {
            acc += r * d.conj();
        }
        let metric = acc.norm() * inv / ref_norm;
        if metric > best.metric {
            best = SsbIndexDetection { i_ssb, metric };
        }
    }
    best
}

/// Number of PBCH data (non-DMRS) REs per SSB → 432 QPSK symbols, i.e. the
/// rate-matched codeword length `E = 864` bits.
pub const PBCH_DATA_LEN: usize = 432;

/// PBCH regions within the SSB (Table 7.4.3.1-1): SSB symbol (relative to the
/// PSS symbol) and the subcarrier ranges `[start, end)` it occupies.
const PBCH_REGIONS: &[(u8, &[(u16, u16)])] = &[
    (1, &[(0, 240)]),
    (2, &[(0, 48), (192, 240)]),
    (3, &[(0, 240)]),
];

/// Resource-element layout of the PBCH within an SSB, split into DMRS and data
/// positions in 3GPP mapping order (increasing subcarrier, then symbol).
pub struct PbchLayout {
    /// `(ssb_symbol, subcarrier)` of each of the 144 DMRS REs.
    pub dmrs_re: Vec<(u8, u16)>,
    /// `(ssb_symbol, subcarrier)` of each of the 432 data REs.
    pub data_re: Vec<(u8, u16)>,
}

impl PbchLayout {
    /// Build the layout for a cell; the DMRS subcarrier shift is `v = cell_id % 4`.
    pub fn new(cell_id: u16) -> Self {
        let v = cell_id % 4;
        let mut dmrs_re = Vec::with_capacity(PBCH_DMRS_LEN);
        let mut data_re = Vec::with_capacity(PBCH_DATA_LEN);
        for &(l, ranges) in PBCH_REGIONS {
            for &(start, end) in ranges {
                for k in start..end {
                    if k % 4 == v {
                        dmrs_re.push((l, k));
                    } else {
                        data_re.push((l, k));
                    }
                }
            }
        }
        debug_assert_eq!(dmrs_re.len(), PBCH_DMRS_LEN);
        debug_assert_eq!(data_re.len(), PBCH_DATA_LEN);
        Self { dmrs_re, data_re }
    }
}

/// Demodulate SSB symbols 1–3 and extract the received PBCH DMRS (144) and data
/// (432) resource elements in mapping order. `pss_useful_start` is the sample
/// index of the PSS symbol's useful part (from cell search).
pub fn extract_pbch(
    ofdm: &Ofdm,
    samples: &[Complex32],
    pss_useful_start: usize,
    mu: u8,
    cell_id: u16,
) -> Option<(Vec<Complex32>, Vec<Complex32>, PbchLayout)> {
    let n = ofdm.fft_size();
    let cp = ofdm.cp_len(3, mu); // Case C SSB: all symbols use the normal CP.
    let mut grids: Vec<Option<Vec<Complex32>>> = vec![None; 4];
    for l in 1..=3usize {
        let start = pss_useful_start + l * (n + cp);
        if start + n > samples.len() {
            return None;
        }
        grids[l] = Some(ofdm.demodulate_symbol(&samples[start..], 0));
    }

    let layout = PbchLayout::new(cell_id);
    let dmrs = layout
        .dmrs_re
        .iter()
        .map(|&(l, k)| grids[l as usize].as_ref().unwrap()[ssb_subcarrier_bin(k as usize, n)])
        .collect();
    let data = layout
        .data_re
        .iter()
        .map(|&(l, k)| grids[l as usize].as_ref().unwrap()[ssb_subcarrier_bin(k as usize, n)])
        .collect();
    Some((dmrs, data, layout))
}

/// Linearly interpolate the channel (estimated at DMRS REs) onto the data REs,
/// per SSB symbol across subcarriers.
fn interpolate_channel(
    dmrs_re: &[(u8, u16)],
    h_dmrs: &[Complex32],
    data_re: &[(u8, u16)],
) -> Vec<Complex32> {
    use std::collections::BTreeMap;
    let mut by_symbol: BTreeMap<u8, Vec<(u16, Complex32)>> = BTreeMap::new();
    for (&(l, k), &h) in dmrs_re.iter().zip(h_dmrs) {
        by_symbol.entry(l).or_default().push((k, h));
    }
    for pts in by_symbol.values_mut() {
        pts.sort_by_key(|p| p.0);
    }

    data_re
        .iter()
        .map(|&(l, k)| {
            let pts = &by_symbol[&l];
            match pts.binary_search_by_key(&k, |p| p.0) {
                Ok(i) => pts[i].1,
                Err(0) => pts[0].1,
                Err(i) if i >= pts.len() => pts[pts.len() - 1].1,
                Err(i) => {
                    let (k0, h0) = pts[i - 1];
                    let (k1, h1) = pts[i];
                    let t = (k - k0) as f32 / (k1 - k0) as f32;
                    h0 + (h1 - h0) * t
                }
            }
        })
        .collect()
}

/// Estimate the channel from the PBCH DMRS, equalize the data REs (maximum-ratio
/// combining), and produce the 864 soft bits (LLRs; positive ⇒ bit 0) in QPSK
/// order (real, imag per symbol). These are the pre-descrambling PBCH LLRs.
pub fn equalize_pbch(
    rx_dmrs: &[Complex32],
    rx_data: &[Complex32],
    layout: &PbchLayout,
    cell_id: u16,
    i_ssb: u8,
) -> Vec<f32> {
    let dmrs_ref = pbch_dmrs(cell_id, i_ssb);
    let h_dmrs: Vec<Complex32> = rx_dmrs
        .iter()
        .zip(&dmrs_ref)
        .map(|(rx, d)| rx * d.conj())
        .collect();
    let h_data = interpolate_channel(&layout.dmrs_re, &h_dmrs, &layout.data_re);

    let mut llrs = Vec::with_capacity(rx_data.len() * 2);
    for (rx, h) in rx_data.iter().zip(&h_data) {
        let z = rx * h.conj(); // MRC: |h|^2·s + conj(h)·n
        llrs.push(z.re);
        llrs.push(z.im);
    }
    llrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::TAU;

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

    #[test]
    fn dmrs_are_unit_magnitude_qpsk() {
        let d = pbch_dmrs(623, 3);
        assert_eq!(d.len(), PBCH_DMRS_LEN);
        for s in &d {
            assert!((s.norm() - 1.0).abs() < 1e-5);
            assert!((s.re.abs() - FRAC_1_SQRT_2).abs() < 1e-5);
            assert!((s.im.abs() - FRAC_1_SQRT_2).abs() < 1e-5);
        }
    }

    #[test]
    fn distinct_index_or_cell_distinct_dmrs() {
        assert_ne!(pbch_dmrs(623, 0), pbch_dmrs(623, 1));
        assert_ne!(pbch_dmrs(100, 2), pbch_dmrs(101, 2));
    }

    /// Blindly recover the SSB index from received DMRS over a flat channel with
    /// noise — this functionally validates the Gold generator and c_init.
    #[test]
    fn recovers_ssb_index_under_channel_and_noise() {
        let cell_id = 623;
        let mut rng = Rng(0x515B_1DE1);
        for true_i in 0..L_MAX_FR1_ABOVE_3GHZ {
            let dmrs = pbch_dmrs(cell_id, true_i);
            let h = Complex32::from_polar(0.6, -2.0);
            let sig_pow = 1.0f32; // |r(m)| = 1
            let sigma = (sig_pow / 10f32.powf(10.0 / 10.0)).sqrt(); // 10 dB SNR

            let rx: Vec<Complex32> = dmrs
                .iter()
                .map(|d| {
                    d * h
                        + Complex32::new(rng.normal(), rng.normal())
                            * (sigma / std::f32::consts::SQRT_2)
                })
                .collect();

            let det = detect_ssb_index(&rx, cell_id, L_MAX_FR1_ABOVE_3GHZ);
            assert_eq!(det.i_ssb, true_i, "expected i_SSB {true_i}");
            assert!(det.metric > 0.6, "metric {}", det.metric);
        }
    }

    /// End-to-end PBCH RE handling: map known QPSK data + DMRS onto the SSB grid,
    /// pass through a flat channel with noise, then extract, estimate the channel
    /// and equalize — the recovered soft bits must match the transmitted bits.
    #[test]
    fn pbch_extract_equalize_recovers_bits() {
        use crate::sync::ssb::{pss_grid, sss_grid};

        let (cell_id, n_id_1, n_id_2, i_ssb) = (623u16, 207u16, 2u8, 3u8);
        let (mu, fft) = (1u8, 256usize);
        let ofdm = Ofdm::new(fft);
        let cp = ofdm.cp_len(3, mu);
        let layout = PbchLayout::new(cell_id);
        let dmrs = pbch_dmrs(cell_id, i_ssb);

        let mut rng = Rng(0x9911_2244_3355);
        let bits: Vec<u8> = (0..2 * PBCH_DATA_LEN)
            .map(|_| (rng.uniform() < 0.5) as u8)
            .collect();
        let qpsk = |b0: u8, b1: u8| {
            Complex32::new((1 - 2 * b0 as i32) as f32, (1 - 2 * b1 as i32) as f32) * FRAC_1_SQRT_2
        };
        let data_syms: Vec<Complex32> = (0..PBCH_DATA_LEN)
            .map(|i| qpsk(bits[2 * i], bits[2 * i + 1]))
            .collect();

        // Build the four SSB symbol grids: PSS, PBCH, SSS+PBCH, PBCH.
        let mut grids = vec![vec![Complex32::new(0.0, 0.0); fft]; 4];
        grids[0] = pss_grid(n_id_2, fft);
        grids[2] = sss_grid(n_id_1, n_id_2, fft);
        for (idx, &(l, k)) in layout.dmrs_re.iter().enumerate() {
            grids[l as usize][ssb_subcarrier_bin(k as usize, fft)] = dmrs[idx];
        }
        for (idx, &(l, k)) in layout.data_re.iter().enumerate() {
            grids[l as usize][ssb_subcarrier_bin(k as usize, fft)] = data_syms[idx];
        }

        let prepad = 200usize;
        let mut sig = vec![Complex32::new(0.0, 0.0); prepad];
        for g in &grids {
            sig.extend(ofdm.modulate_symbol(g, cp));
        }
        sig.extend(std::iter::repeat(Complex32::new(0.0, 0.0)).take(100));

        // Flat channel + AWGN at 30 dB (relative to the unit-power data REs).
        let h = Complex32::from_polar(0.8, 0.7);
        let sigma = h.norm() / 10f32.powf(30.0 / 20.0);
        for s in sig.iter_mut() {
            *s = *s * h
                + Complex32::new(rng.normal(), rng.normal()) * (sigma / std::f32::consts::SQRT_2);
        }

        let pss_useful_start = prepad + cp;
        let (rx_dmrs, rx_data, lay) =
            extract_pbch(&ofdm, &sig, pss_useful_start, mu, cell_id).unwrap();
        assert_eq!(rx_dmrs.len(), PBCH_DMRS_LEN);
        assert_eq!(rx_data.len(), PBCH_DATA_LEN);

        let llrs = equalize_pbch(&rx_dmrs, &rx_data, &lay, cell_id, i_ssb);
        assert_eq!(llrs.len(), 2 * PBCH_DATA_LEN);
        let errors = llrs
            .iter()
            .zip(&bits)
            .filter(|(&l, &b)| (l < 0.0) as u8 != b)
            .count();
        assert_eq!(errors, 0, "recovered {errors} bit errors");
    }
}
