//! Write a Ferrite-generated SSB waveform to an IQ file (interleaved f32),
//! for cross-validation against an independent receiver (e.g. srsRAN's
//! `ssb_file_test`).
//!
//! Usage: cargo run -p ferrite-phy --example emit_ssb -- <out.iq> [fft_size]
//!
//! The SSB (PCI 623, i_SSB 0, SFN 340, 30 kHz Case C) is placed at DC, at
//! sample rate `fft_size * 30 kHz` (default 256 → 7.68 MHz), padded with
//! silence before and after.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_phy::coding::bch::Mib;
use ferrite_phy::sync::pbch::L_MAX_FR1_ABOVE_3GHZ;
use ferrite_phy::sync::ssb::{build_ssb_waveform, ssb_sample_offset_in_frame, SsbCase};
use ferrite_phy::Ofdm;
use ferrite_radio::file::FileSink;
use ferrite_radio::SampleSink;
use num_complex::Complex32;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "ferrite_ssb.iq".into());
    let fft: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(256);
    let fs = fft as f64 * 30_000.0;
    const MU: u8 = 1;

    let (cell_id, i_ssb) = (623u16, 0u8);
    let mib = Mib {
        sfn: 340,
        scs_common_is_30_or_120: true,
        ssb_subcarrier_offset: 0,
        dmrs_typea_pos3: false,
        pdcch_config_sib1: 0xA4,
        cell_barred: false,
        intra_freq_reselection_allowed: true,
        half_frame: 0,
        k_ssb_msb: 0,
    };

    let ofdm = Ofdm::new(fft);
    let ssb = build_ssb_waveform(&mib, cell_id, i_ssb, L_MAX_FR1_ABOVE_3GHZ, &ofdm, MU);

    // Pad to a half frame (5 ms) with the SSB at its Case C first-candidate
    // position (symbol 2 of the first slot, TS 38.213 §4.1).
    let first_symbol = SsbCase::C.candidate_symbols(3.5e9)[usize::from(i_ssb)];
    let ssb_start = ssb_sample_offset_in_frame(first_symbol, 0, MU, &ofdm);
    let half_frame_len = (fs * 0.005) as usize;

    let mut sig = vec![Complex32::new(0.0, 0.0); half_frame_len];
    sig[ssb_start..ssb_start + ssb.len()].copy_from_slice(&ssb);

    let mut sink = FileSink::create(&path, fs).unwrap();
    sink.write(&sig).unwrap();
    println!(
        "wrote {path}: {} samples @ {:.2} MHz, PCI {cell_id}, i_SSB {i_ssb}, SFN {}, SSB t_offset {}",
        sig.len(),
        fs / 1e6,
        mib.sfn,
        ssb_start
    );
}
