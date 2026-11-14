//! Sounding reference signal (TS 38.211 §6.4.1.4): the low-PAPR sequence of
//! one SRS resource (comb 2 / 4, one port, no group/sequence hopping, no
//! frequency hopping), its RE mapping from `C_SRS` / `B_SRS` /
//! `freqDomainPosition` / `freqDomainShift` / comb offset / cyclic shift,
//! and the CP-OFDM slot waveform.

use crate::pucch::{modulate_slot_grids, PHI_12};
use crate::Ofdm;
use num_complex::Complex32;
use std::f32::consts::PI;

pub use ferrite_ran::srs::{srs_bandwidth, srs_layout, srs_symbols, SrsResourceParams};

/// TS 38.211 Table 5.2.2.2-1 (length 6), φ(n) in units of π/4.
const PHI_6: [[i8; 6]; 30] = [
    [-3, -1, 3, 3, -1, -3], [-3, 3, -1, -1, 3, -3], [-3, -3, -3, 3, 1, -3], [1, 1, 1, 3, -1, -3], [1, 1, 1, -3, -1, 3],
    [-3, 1, -1, -3, -3, -3], [-3, 1, 3, -3, -3, -3], [-3, -1, 1, -3, 1, -1], [-3, -1, -3, 1, -3, -3], [-3, -3, 1, -3, 3, -3],
    [-3, 1, 3, 1, -3, -3], [-3, -1, -3, 1, 1, -3], [1, 1, 3, -1, -3, 3], [1, 1, 3, 3, -1, 3], [1, 1, 1, -3, 3, -1],
    [1, 1, 1, -1, 3, -3], [-3, -1, -1, -1, 3, -1], [-3, -3, -1, 1, -1, -3], [-3, -3, -3, 1, -3, -1], [-3, 1, 1, -3, -1, -3],
    [-3, 3, -3, 1, 1, -3], [-3, 1, -3, -3, -3, -1], [1, 1, -3, 3, 1, 3], [1, 1, -3, -3, 1, -3], [1, 1, 3, -1, 3, 3],
    [1, 1, -3, 1, 3, 3], [1, 1, -1, -1, 3, -1], [1, 1, -1, 3, -1, -1], [1, 1, -1, 3, -3, -1], [1, 1, -3, 1, -1, -1],
];

/// TS 38.211 Table 5.2.2.2-3 (length 18).
const PHI_18: [[i8; 18]; 30] = [
    [-1, 3, -1, -3, 3, 1, -3, -1, 3, -3, -1, -1, 1, 1, 1, -1, -1, -1],
    [3, -3, 3, -1, 1, 3, -3, -1, -3, -3, -1, -3, 3, 1, -1, 3, -3, 3],
    [-3, 3, 1, -1, -1, 3, -3, -1, 1, 1, 1, 1, 1, -1, 3, -1, -3, -1],
    [-3, -3, 3, 3, 3, 1, -3, 1, 3, 3, 1, -3, -3, 3, -1, -3, -1, 1],
    [1, 1, -1, -1, -3, -1, 1, -3, -3, -3, 1, -3, -1, -1, 1, -1, 3, 1],
    [3, -3, 1, 1, 3, -1, 1, -1, -1, -3, 1, 1, -1, 3, 3, -3, 3, -1],
    [-3, 3, -1, 1, 3, 1, -3, -1, 1, 1, -3, 1, 3, 3, -1, -3, -3, -3],
    [1, 1, -3, 3, 3, 1, 3, -3, 3, -1, 1, 1, -1, 1, -3, -3, -1, 3],
    [-3, 1, -3, -3, 1, -3, -3, 3, 1, -3, -1, -3, -3, -3, -1, 1, 1, 3],
    [3, -1, 3, 1, -3, -3, -1, 1, -3, -3, 3, 3, 3, 1, 3, -3, 3, -3],
    [-3, -3, -3, 1, -3, 3, 1, 1, 3, -3, -3, 1, 3, -1, 3, -3, -3, 3],
    [-3, -3, 3, 3, 3, -1, -1, -3, -1, -1, -1, 3, 1, -3, -3, -1, 3, -1],
    [-3, -1, -3, -3, 1, 1, -1, -3, -1, -3, -1, -1, 3, 3, -1, 3, 1, 3],
    [1, 1, -3, -3, -3, -3, 1, 3, -3, 3, 3, 1, -3, -1, 3, -1, -3, 1],
    [-3, 3, -1, -3, -1, -3, 1, 1, -3, -3, -1, -1, 3, -3, 1, 3, 1, 1],
    [3, 1, -3, 1, -3, 3, 3, -1, -3, -3, -1, -3, -3, 3, -3, -1, 1, 3],
    [-3, -1, -3, -1, -3, 1, 3, -3, -1, 3, 3, 3, 1, -1, -3, 3, -1, -3],
    [-3, -1, 3, 3, -1, 3, -1, -3, -1, 1, -1, -3, -1, -1, -1, 3, 3, 1],
    [-3, 1, -3, -1, -1, 3, 1, -3, -3, -3, -1, -3, -3, 1, 1, 1, -1, -1],
    [3, 3, 3, -3, -1, -3, -1, 3, -1, 1, -1, -3, 1, -3, -3, -1, 3, 3],
    [-3, 1, 1, -3, 1, 1, 3, -3, -1, -3, -1, 3, -3, 3, -1, -1, -1, -3],
    [1, -3, -1, -3, 3, 3, -1, -3, 1, -3, -3, -1, -3, -1, 1, 3, 3, 3],
    [-3, -3, 1, -1, -1, 1, 1, -3, -1, 3, 3, 3, 3, -1, 3, 1, 3, 1],
    [3, -1, -3, 1, -3, -3, -3, 3, 3, -1, 1, -3, -1, 3, 1, 1, 3, 3],
    [3, -1, -1, 1, -3, -1, -3, -1, -3, -3, -1, -3, 1, 1, 1, -3, -3, 3],
    [-3, -3, 1, -3, 3, 3, 3, -1, 3, 1, 1, -3, -3, -3, 3, -3, -1, -1],
    [-3, -1, -1, -3, 1, -3, 3, -1, -1, -3, 3, 3, -3, -1, 3, -1, -1, -1],
    [-3, -3, 3, 3, -3, 1, 3, -1, -3, 1, -1, -3, 3, -3, -1, -1, -1, 3],
    [-1, -3, 1, -3, -3, -3, 1, 1, 3, 3, -3, 3, 3, -3, -1, 3, -3, 1],
    [-3, 3, 1, -1, -1, -1, -1, 1, -1, 3, 3, -3, -1, 1, 3, -1, 3, -1],
];

/// TS 38.211 Table 5.2.2.2-4 (length 24).
const PHI_24: [[i8; 24]; 30] = [
    [-1, -3, 3, -1, 3, 1, 3, -1, 1, -3, -1, -3, -1, 1, 3, -3, -1, -3, 3, 3, 3, -3, -3, -3],
    [-1, -3, 3, 1, 1, -3, 1, -3, -3, 1, -3, -1, -1, 3, -3, 3, 3, 3, -3, 1, 3, 3, -3, -3],
    [-1, -3, -3, 1, -1, -1, -3, 1, 3, -1, -3, -1, -1, -3, 1, 1, 3, 1, -3, -1, -1, 3, -3, -3],
    [1, -3, 3, -1, -3, -1, 3, 3, 1, -1, 1, 1, 3, -3, -1, -3, -3, -3, -1, 3, -3, -1, -3, -3],
    [-1, 3, -3, -3, -1, 3, -1, -1, 1, 3, 1, 3, -1, -1, -3, 1, 3, 1, -1, -3, 1, -1, -3, -3],
    [-3, -1, 1, -3, -3, 1, 1, -3, 3, -1, -1, -3, 1, 3, 1, -1, -3, -1, -3, 1, -3, -3, -3, -3],
    [-3, 3, 1, 3, -1, 1, -3, 1, -3, 1, -1, -3, -1, -3, -3, -3, -3, -1, -1, -1, 1, 1, -3, -3],
    [-3, 1, 3, -1, 1, -1, 3, -3, 3, -1, -3, -1, -3, 3, -1, -1, -1, -3, -1, -1, -3, 3, 3, -3],
    [-3, 1, -3, 3, -1, -1, -1, -3, 3, 1, -1, -3, -1, 1, 3, -1, 1, -1, 1, -3, -3, -3, -3, -3],
    [1, 1, -1, -3, -1, 1, 1, -3, 1, -1, 1, -3, 3, -3, -3, 3, -1, -3, 1, 3, -3, 1, -3, -3],
    [-3, -3, -3, -1, 3, -3, 3, 1, 3, 1, -3, -1, -1, -3, 1, 1, 3, 1, -1, -3, 3, 1, 3, -3],
    [-3, 3, -1, 3, 1, -1, -1, -1, 3, 3, 1, 1, 1, 3, 3, 1, -3, -3, -1, 1, -3, 1, 3, -3],
    [3, -3, 3, -1, -3, 1, 3, 1, -1, -1, -3, -1, 3, -3, 3, -1, -1, 3, 3, -3, -3, 3, -3, -3],
    [-3, 3, -1, 3, -1, 3, 3, 1, 1, -3, 1, 3, -3, 3, -3, -3, -1, 1, 3, -3, -1, -1, -3, -3],
    [-3, 1, -3, -1, -1, 3, 1, 3, -3, 1, -1, 3, 3, -1, -3, 3, -3, -1, -1, -3, -3, -3, 3, -3],
    [-3, -1, -1, -3, 1, -3, -3, -1, -1, 3, -1, 1, -1, 3, 1, -3, -1, 3, 1, 1, -1, -1, -3, -3],
    [-3, -3, 1, -1, 3, 3, -3, -1, 1, -1, -1, 1, 1, -1, -1, 3, -3, 1, -3, 1, -1, -1, -1, -3],
    [3, -1, 3, -1, 1, -3, 1, 1, -3, -3, 3, -3, -1, -1, -1, -1, -1, -3, -3, -1, 1, 1, -3, -3],
    [-3, 1, -3, 1, -3, -3, 1, -3, 1, -3, -3, -3, -3, -3, 1, -3, -3, 1, 1, -3, 1, 1, -3, -3],
    [-3, -3, 3, 3, 1, -1, -1, -1, 1, -3, -1, 1, -1, 3, -3, -1, -3, -1, -1, 1, -3, 3, -1, -3],
    [-3, -3, -1, -1, -1, -3, 1, -1, -3, -1, 3, -3, 1, -3, 3, -3, 3, 3, 1, -1, -1, 1, -3, -3],
    [3, -1, 1, -1, 3, -3, 1, 1, 3, -1, -3, 3, 1, -3, 3, -1, -1, -1, -1, 1, -3, -3, -3, -3],
    [-3, 1, -3, 3, -3, 1, -3, 3, 1, -1, -3, -1, -3, -3, -3, -3, 1, 3, -1, 1, 3, 3, 3, -3],
    [-3, -1, 1, -3, -1, -1, 1, 1, 1, 3, 3, -1, 1, -1, 1, -1, -1, -3, -3, -3, 3, 1, -1, -3],
    [-3, 3, -1, -3, -1, -1, -1, 3, -1, -1, 3, -3, -1, 3, -3, 3, -3, -1, 3, 1, 1, -1, -3, -3],
    [-3, 1, -1, -3, -3, -1, 1, -3, -1, -3, 1, 1, -1, 1, 1, 3, 3, 3, -1, 1, -1, 1, -1, -3],
    [-1, 3, -1, -1, 3, 3, -1, -1, -1, 3, -1, -3, 1, 3, 1, 1, -3, -3, -3, -1, -3, -1, -3, -3],
    [3, -3, -3, -1, 3, 3, -3, -1, 3, 1, 1, 1, 3, -1, 3, -3, -1, 3, -1, 3, 1, -1, -3, -3],
    [-3, 1, -3, 1, -3, 1, 1, 3, 1, -3, -3, -1, 1, 3, -1, -3, 3, 1, -1, -3, -3, -3, -3, -3],
    [3, -3, -1, 1, 3, -1, -1, -3, -1, 3, -1, -3, -1, -3, 3, -1, 3, 1, 1, -3, 3, -3, -3, -3],
];

/// Largest prime below `n`.
fn prime_below(n: usize) -> usize {
    let mut p = n - 1;
    while p > 2 {
        if (2..).take_while(|d| d * d <= p).all(|d| p % d != 0) {
            return p;
        }
        p -= 1;
    }
    2
}

/// The low-PAPR base sequence r̄_{u,v}(n), n = 0..M_ZC (TS 38.211 §5.2.2):
/// φ-table sequences for lengths 6, 12, 18, 24, the length-30 closed form
/// `exp(−jπ(u+1)(n+1)(n+2)/31)` and Zadoff-Chu for ≥ 36 (`q` from `u`, `v`,
/// N_ZC = largest prime below M_ZC). Returns `None` for an unsupported length.
pub fn low_papr_base_sequence(u: u8, v: u8, m_zc: usize) -> Option<Vec<Complex32>> {
    let u = (u % 30) as usize;
    let from_phi = |phi: &[i8]| phi.iter().map(|&p| Complex32::from_polar(1.0, PI * p as f32 / 4.0)).collect::<Vec<_>>();
    match m_zc {
        6 => Some(from_phi(&PHI_6[u])),
        12 => Some(from_phi(&PHI_12[u])),
        18 => Some(from_phi(&PHI_18[u])),
        24 => Some(from_phi(&PHI_24[u])),
        30 => Some((0..30).map(|n| Complex32::from_polar(1.0, -PI * ((u + 1) * (n + 1) * (n + 2)) as f32 / 31.0)).collect()),
        n if n >= 36 => {
            let n_zc = prime_below(n);
            let q_bar = n_zc as f64 * (u as f64 + 1.0) / 31.0;
            let q = ((q_bar + 0.5).floor() + v as f64 * (-1f64).powi((2.0 * q_bar).floor() as i32)) as u64;
            let two_n = 2 * n_zc as u64;
            Some(
                (0..n)
                    .map(|i| {
                        let m = (i % n_zc) as u64;
                        let x = (q * m * (m + 1)) % two_n;
                        Complex32::from_polar(1.0, -PI * x as f32 / n_zc as f32)
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Modulate one SRS slot for `p` on the UL carrier of `carrier_rb` RBs with
/// its RB 0 at CRB `crb_offset`; returns the CP-OFDM samples with §5.4 phase
/// compensation, or `None` if the configuration is unsupported.
#[allow(clippy::too_many_arguments)]
pub fn srs_modulate_slot(ofdm: &Ofdm, p: &SrsResourceParams, carrier_rb: usize, crb_offset: usize, slot_in_frame: u32, mu: u8, center_freq_hz: f64, fs: f64) -> Option<Vec<Complex32>> {
    let n = ofdm.fft_size();
    let (m_sc, k0) = srs_layout(p)?;
    // Group u = (f_gh + n_ID) mod 30 with f_gh = 0 (no hopping), v = 0.
    let u = (p.sequence_id % 30) as u8;
    let base = low_papr_base_sequence(u, 0, m_sc)?;
    let n_cs_max = if p.k_tc == 4 { 12.0 } else { 8.0 };
    let alpha = 2.0 * PI * p.cyclic_shift as f32 / n_cs_max;
    let center = carrier_rb * 6;
    let bin = |sc: isize| (sc - center as isize).rem_euclid(n as isize) as usize;
    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 14];
    let amp = 1.0 / (m_sc as f32).sqrt().max(1.0) * (m_sc as f32).sqrt(); // unit per RE
    for &l in &srs_symbols(p) {
        for (k, r) in base.iter().enumerate() {
            let sc = k0 as isize - crb_offset as isize * 12 + (p.k_tc as usize * k) as isize;
            if sc < 0 || sc as usize >= carrier_rb * 12 {
                continue;
            }
            let rot = Complex32::from_polar(1.0, alpha * k as f32);
            grids[l][bin(sc)] = r * rot * amp;
        }
    }
    Some(modulate_slot_grids(ofdm, &grids, slot_in_frame, mu, center_freq_hz, fs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_table_spot_checks() {
        assert_eq!(srs_bandwidth(0, 0), (4, 1));
        assert_eq!(srs_bandwidth(13, 1), (24, 2));
        assert_eq!(srs_bandwidth(21, 3), (4, 5));
        assert_eq!(srs_bandwidth(63, 0), (272, 1));
        assert_eq!(srs_bandwidth(63, 3), (4, 2));
    }

    #[test]
    fn base_sequences_have_unit_magnitude_and_zc_properties() {
        for m in [6usize, 12, 18, 24, 30, 36, 48, 72, 96, 144] {
            let s = low_papr_base_sequence(7, 0, m).unwrap();
            assert_eq!(s.len(), m);
            assert!(s.iter().all(|x| (x.norm() - 1.0).abs() < 1e-5));
        }
        // Below 36 only the tabulated lengths exist.
        assert!(low_papr_base_sequence(0, 0, 7).is_none());
        assert!(low_papr_base_sequence(0, 0, 32).is_none());
        // ZC: a cyclic autocorrelation at lag ≠ 0 over N_ZC is zero.
        let m = 36;
        let s = low_papr_base_sequence(3, 0, m).unwrap();
        let n_zc = prime_below(m);
        let lag1: Complex32 = (0..n_zc).map(|i| s[i] * s[(i + 1) % n_zc].conj()).sum();
        assert!(lag1.norm() < 1e-3 * n_zc as f32, "{}", lag1.norm());
        assert_eq!(prime_below(36), 31);
        assert_eq!(prime_below(48), 47);
    }

    #[test]
    fn layout_and_symbols() {
        // c_srs 0 (4 RB), comb 4 → 12 subcarriers; shift 0, position 0, offset 1.
        let p = SrsResourceParams { k_tc: 4, comb_offset: 1, cyclic_shift: 0, start_position: 0, nrof_symbols: 1, repetition_factor: 1, freq_domain_position: 0, freq_domain_shift: 0, c_srs: 0, b_srs: 0, b_hop: 0, sequence_id: 1 };
        assert_eq!(srs_layout(&p), Some((12, 1)));
        assert_eq!(srs_symbols(&p), vec![13]);
        let p2 = SrsResourceParams { start_position: 2, nrof_symbols: 2, freq_domain_shift: 3, ..p };
        assert_eq!(srs_symbols(&p2), vec![11, 12]);
        assert_eq!(srs_layout(&p2), Some((12, 37)));
        let ofdm = Ofdm::new(512);
        let w = srs_modulate_slot(&ofdm, &p2, 24, 0, 3, 1, 0.0, 15.36e6).unwrap();
        assert!(!w.is_empty());
        let pw: f32 = w.iter().map(|x| x.norm_sqr()).sum::<f32>() / w.len() as f32;
        assert!(pw > 0.0);
    }
}
