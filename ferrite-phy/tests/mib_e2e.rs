//! End-to-end Milestone-1 test: a complete SSB (PSS + SSS + DMRS + polar-coded
//! PBCH) is synthesized, distorted by a flat channel, CFO, and noise, and the
//! receiver must blindly recover cell ID, SSB index, and the exact MIB.

use ferrite_phy::coding::bch::Mib;
use ferrite_phy::sync::cfo::correct_cfo;
use ferrite_phy::sync::pbch::{pbch_dmrs_index, L_MAX_FR1_ABOVE_3GHZ, L_MAX_FR1_BELOW_3GHZ};
use ferrite_phy::sync::ssb::build_ssb_waveform;
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use num_complex::Complex32;
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

#[allow(clippy::too_many_arguments)]
fn run_case(
    mu: u8,
    l_max: u8,
    cell_id: u16,
    i_ssb: u8,
    half_frame: u8,
    sfn: u16,
    cfo: f32,
    snr_db: f32,
    seed: u64,
) {
    const FFT: usize = 256;
    let fs = FFT as f64 * f64::from(15_000u32 << mu);
    let ofdm = Ofdm::new(FFT);
    let searcher = CellSearcher::new(FFT, mu, l_max);
    let mut rng = Rng(seed);

    let mib = Mib {
        sfn,
        scs_common_is_30_or_120: mu == 1,
        ssb_subcarrier_offset: 2,
        dmrs_typea_pos3: false,
        pdcch_config_sib1: 0x64,
        cell_barred: false,
        intra_freq_reselection_allowed: true,
        half_frame,
        k_ssb_msb: 0,
    };

    let ssb = build_ssb_waveform(
        &mib,
        cell_id,
        pbch_dmrs_index(i_ssb, half_frame, l_max),
        l_max,
        &ofdm,
        mu,
    );
    let prepad = 333usize;
    let mut sig = vec![Complex32::new(0.0, 0.0); prepad];
    sig.extend_from_slice(&ssb);
    sig.extend(std::iter::repeat_n(Complex32::new(0.0, 0.0), 200));

    // Flat channel, CFO, AWGN.
    let h = Complex32::from_polar(0.8, -1.9);
    let rms = (ssb.iter().map(|s| s.norm_sqr()).sum::<f32>() / ssb.len() as f32).sqrt();
    let sigma = h.norm() * rms / 10f32.powf(snr_db / 20.0);
    for (m, s) in sig.iter_mut().enumerate() {
        *s = *s * h * Complex32::from_polar(1.0, TAU * cfo * m as f32 / fs as f32);
        *s += Complex32::new(rng.normal(), rng.normal()) * (sigma / SQRT_2);
    }

    // Receiver: search, CFO-correct, decode.
    let found = searcher.search(&sig).expect("no cell found");
    assert_eq!(found.cell_id, cell_id, "wrong PCI");

    let mut corrected = sig.clone();
    correct_cfo(&mut corrected, found.cfo_hz, fs);
    let dec = searcher
        .decode_mib(&corrected, &found)
        .expect("MIB decode failed");

    assert_eq!(dec.i_ssb, i_ssb, "wrong SSB index");
    assert_eq!(dec.half_frame, half_frame, "wrong half frame");
    assert_eq!(dec.mib, mib, "wrong MIB");
}

#[test]
fn recovers_mib_clean() {
    run_case(
        1,
        L_MAX_FR1_ABOVE_3GHZ,
        623,
        3,
        0,
        0x155,
        0.0,
        40.0,
        0xA0_0001,
    );
}

#[test]
fn recovers_mib_with_cfo_and_noise() {
    run_case(
        1,
        L_MAX_FR1_ABOVE_3GHZ,
        101,
        6,
        1,
        0x2BC,
        1_700.0,
        12.0,
        0xA0_0002,
    );
}

#[test]
fn recovers_mib_various_cells() {
    for (i, &(pci, issb, sfn)) in [(0u16, 0u8, 0u16), (1007, 7, 0x3FF), (500, 2, 8)]
        .iter()
        .enumerate()
    {
        run_case(
            1,
            L_MAX_FR1_ABOVE_3GHZ,
            pci,
            issb,
            0,
            sfn,
            600.0,
            20.0,
            0xB000 + i as u64,
        );
    }
}

/// 15 kHz SSB (Case A) below 3 GHz: `L_max = 4`, so the DMRS index carries the
/// half-frame bit and only two candidate-index bits.
#[test]
fn recovers_mib_mu0_l_max_4() {
    for (i, &(pci, issb, hf, sfn)) in [
        (623u16, 0u8, 0u8, 0x155u16),
        (101, 3, 1, 0x2BC),
        (500, 2, 1, 8),
    ]
    .iter()
    .enumerate()
    {
        run_case(
            0,
            L_MAX_FR1_BELOW_3GHZ,
            pci,
            issb,
            hf,
            sfn,
            300.0,
            15.0,
            0xC000 + i as u64,
        );
    }
}
