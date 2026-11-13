//! Full Milestone-1 demo: synthesize a complete SSB (PSS + SSS + PBCH DMRS +
//! polar-coded MIB), impair it with a flat channel, CFO, and noise, then run
//! the blind receiver: cell search → CFO correction → SSB-index detection →
//! PBCH equalization → polar SCL decode → MIB.
//!
//! Run with: `cargo run -p ferrite-phy --example cell_search`

use ferrite_phy::coding::bch::Mib;
use ferrite_phy::sync::cfo::correct_cfo;
use ferrite_phy::sync::pbch::L_MAX_FR1_ABOVE_3GHZ;
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

fn main() {
    const FFT: usize = 256;
    const MU: u8 = 1;
    let fs = FFT as f64 * 30_000.0;
    let ofdm = Ofdm::new(FFT);
    let searcher = CellSearcher::new(FFT, MU, L_MAX_FR1_ABOVE_3GHZ);
    let mut rng = Rng(0xFE55_17E5);

    let (cell_id, i_ssb) = (623u16, 5u8);
    let mib = Mib {
        sfn: 0x2A7,
        scs_common_is_30_or_120: true,
        ssb_subcarrier_offset: 6,
        dmrs_typea_pos3: false,
        pdcch_config_sib1: 0xA4,
        cell_barred: false,
        intra_freq_reselection_allowed: true,
        half_frame: 1,
        k_ssb_msb: 0,
    };

    println!("Ferrite — 5G NR cell search + MIB decode (fs = {:.2} MHz, N = {FFT}, mu = {MU})", fs / 1e6);
    println!("TX: PCI {cell_id}, i_SSB {i_ssb}, SFN {:#05x} ({})", mib.sfn, mib.sfn);
    println!();
    println!("  {:>7} {:>7} | {:>5} {:>6} {:>10} {:>5} {:>6} {:>8}", "CFO/kHz", "SNR/dB", "PCI", "i_SSB", "cfo_est/Hz", "SFN", "pdcch", "result");

    let ssb = build_ssb_waveform(&mib, cell_id, i_ssb, L_MAX_FR1_ABOVE_3GHZ, &ofdm, MU);
    let rms = (ssb.iter().map(|s| s.norm_sqr()).sum::<f32>() / ssb.len() as f32).sqrt();

    for &(cfo, snr_db) in &[(0.0f32, 40.0f32), (1_200.0, 15.0), (2_600.0, 8.0)] {
        let mut sig = vec![Complex32::new(0.0, 0.0); 411];
        sig.extend_from_slice(&ssb);
        sig.extend(std::iter::repeat_n(Complex32::new(0.0, 0.0), 300));

        let h = Complex32::from_polar(0.8, -1.9);
        let sigma = h.norm() * rms / 10f32.powf(snr_db / 20.0);
        for (m, s) in sig.iter_mut().enumerate() {
            *s = *s * h * Complex32::from_polar(1.0, TAU * cfo * m as f32 / fs as f32);
            *s += Complex32::new(rng.normal(), rng.normal()) * (sigma / SQRT_2);
        }

        let Some(found) = searcher.search(&sig) else {
            println!("  {cfo:>7.0} {snr_db:>7.1} | no cell found");
            continue;
        };
        let mut corrected = sig.clone();
        correct_cfo(&mut corrected, found.cfo_hz, fs);

        match searcher.decode_mib(&corrected, &found) {
            Some(dec) => {
                let ok = found.cell_id == cell_id && dec.i_ssb == i_ssb && dec.mib == mib;
                println!(
                    "  {cfo:>7.0} {snr_db:>7.1} | {:>5} {:>6} {:>10.0} {:>5} {:>#6x} {:>8}",
                    found.cell_id,
                    dec.i_ssb,
                    found.cfo_hz,
                    dec.mib.sfn,
                    dec.mib.pdcch_config_sib1,
                    if ok { "MIB OK" } else { "MISMATCH" }
                );
            }
            None => println!(
                "  {cfo:>7.0} {snr_db:>7.1} | {:>5} {:>6} {:>10.0}   CRC failed",
                found.cell_id, "-", found.cfo_hz
            ),
        }
    }
}
