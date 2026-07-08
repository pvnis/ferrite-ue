//! Live SSB scanner: pull downlink baseband from a gNB over ZMQ, scan the GSCN
//! sync raster around the carrier for an SSB, and decode the MIB.
//!
//! Usage:
//!   ssb-scan [--tx tcp://127.0.0.1:2000] [--rx tcp://127.0.0.1:2001]
//!            [--srate 15.36e6] [--center-mhz 3390.0] [--ms 40]
//!
//! The gNB's `tx_port` is where *it* transmits (we connect and pull DL); its
//! `rx_port` is where it pulls uplink (we bind and serve zeros to keep its
//! clock advancing).

use ferrite_phy::sync::cfo::correct_cfo;
use ferrite_phy::sync::CellSearcher;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_radio::SampleSource;
use num_complex::Complex32;
use std::f64::consts::TAU;

/// GSCN raster step for 3–24.25 GHz (38.101-1 §5.4.3.1): 1.44 MHz.
const GSCN_STEP_HZ: f64 = 1.44e6;
/// SSB occupies 240 × 30 kHz = 7.2 MHz; its centre must stay inside the band.
const SSB_HALF_BW_HZ: f64 = 3.6e6;

fn arg(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| default.to_string())
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2000");
    let rx = arg("--rx", "tcp://127.0.0.1:2001");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let capture_ms: f64 = arg("--ms", "40").parse().unwrap();

    // 30 kHz SCS at the native stream rate: fft = fs / 30 kHz.
    let fft = (fs / 30_000.0).round() as usize;
    assert_eq!(fft as f64 * 30_000.0, fs, "srate must be a multiple of 30 kHz");
    let searcher = CellSearcher::new(fft, 1);

    // Serve zeros on the gNB's rx port from a background thread.
    let mut ul = ZmqSink::bind(&rx, fs, 1024).expect("bind UL port");
    std::thread::spawn(move || loop {
        if ul.serve_zeros().is_err() {
            break;
        }
    });

    println!("connecting to gNB DL at {tx} (fs = {:.2} MHz, fft = {fft}) ...", fs / 1e6);
    let mut dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL port");

    let n_samples = (fs * capture_ms / 1e3) as usize;
    let mut capture = vec![Complex32::default(); n_samples];
    dl.read_exact(&mut capture).expect("capture failed");
    let power: f32 =
        capture.iter().map(|s| s.norm_sqr()).sum::<f32>() / capture.len() as f32;
    println!("captured {n_samples} samples ({capture_ms} ms), mean power {power:.3e}");

    // Candidate SSB centres: GSCN points within the carrier bandwidth.
    // GSCN raster (3–24.25 GHz): F = 3000 MHz + N · 1.44 MHz.
    let n_lo = ((center_hz - SSB_HALF_BW_HZ * 1.2 - 3.0e9) / GSCN_STEP_HZ).ceil() as i64;
    let n_hi = ((center_hz + SSB_HALF_BW_HZ * 1.2 - 3.0e9) / GSCN_STEP_HZ).floor() as i64;

    let mut best: Option<(f64, ferrite_phy::sync::CellSearchResult, Vec<Complex32>)> = None;
    for n in n_lo..=n_hi {
        let f_ssb = 3.0e9 + n as f64 * GSCN_STEP_HZ;
        let df = f_ssb - center_hz; // shift SSB to DC: multiply by e^{-j2π·df·t}
        let mut shifted = capture.clone();
        for (m, s) in shifted.iter_mut().enumerate() {
            let ph = -TAU * df * m as f64 / fs;
            *s *= Complex32::new(ph.cos() as f32, ph.sin() as f32);
        }
        match searcher.search(&shifted) {
            Some(r) => {
                println!(
                    "  GSCN cand {f_ssb:>12.2} Hz (df {df:>+10.0}): pss {:.3} sss {:.3} PCI {}",
                    r.pss_metric, r.sss_metric, r.cell_id
                );
                if best.as_ref().map_or(true, |(_, b, _)| r.pss_metric > b.pss_metric) {
                    best = Some((f_ssb, r, shifted));
                }
            }
            None => println!("  GSCN cand {f_ssb:>12.2} Hz (df {df:>+10.0}): no detection"),
        }
    }

    let Some((f_ssb, found, shifted)) = best else {
        println!("no SSB found");
        std::process::exit(1);
    };
    println!(
        "\nbest: SSB @ {:.2} MHz  PCI {}  timing {}  cfo {:+.0} Hz  (pss {:.3}, sss {:.3})",
        f_ssb / 1e6,
        found.cell_id,
        found.timing_index,
        found.cfo_hz,
        found.pss_metric,
        found.sss_metric
    );

    let mut corrected = shifted;
    correct_cfo(&mut corrected, found.cfo_hz, fs);
    match searcher.decode_mib(&corrected, &found) {
        Some((mib, i_ssb)) => {
            println!("MIB decoded (i_SSB {i_ssb}):");
            println!("  SFN                    : {}", mib.sfn);
            println!("  SCS common             : {}", if mib.scs_common_is_30_or_120 { "30/120 kHz" } else { "15/60 kHz" });
            println!("  ssb-SubcarrierOffset   : {} (k_SSB MSB {})", mib.ssb_subcarrier_offset, mib.k_ssb_msb);
            println!("  dmrs-TypeA-Position    : {}", if mib.dmrs_typea_pos3 { "pos3" } else { "pos2" });
            println!("  pdcch-ConfigSIB1       : {:#04x} (coreset0 {}, ss0 {})", mib.pdcch_config_sib1, mib.pdcch_config_sib1 >> 4, mib.pdcch_config_sib1 & 0xF);
            println!("  cellBarred             : {}", mib.cell_barred);
            println!("  intraFreqReselection   : {}", if mib.intra_freq_reselection_allowed { "allowed" } else { "notAllowed" });
            println!("  halfFrame              : {}", mib.half_frame);
        }
        None => {
            println!("MIB decode failed (CRC)");
            std::process::exit(2);
        }
    }
}
