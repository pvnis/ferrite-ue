//! Probe an SDR through seify: enumerate, open, configure, read a burst, report power.
//!
//! De-risks the seify → SoapySDR → device path before wiring the SDR into the UE.
//!
//! Run (against the USRP on the LAN, for example):
//!   cargo run -p ferrite-radio --example sdr_probe --features seify -- \
//!       "driver=uhd,addr=128.178.122.165" 3.5e9 30.72e6 40
//! Args: [device-args] [freq_hz] [sample_rate_hz] [rx_gain_db]  (all optional)

use ferrite_radio::seify::{SeifyConfig, SeifyRadio};
use ferrite_radio::SampleSource;

fn main() {
    let a: Vec<String> = std::env::args().collect();

    println!("=== seify::enumerate() ===");
    match seify::enumerate() {
        Ok(devs) if !devs.is_empty() => devs.iter().for_each(|d| println!("  {d}")),
        Ok(_) => println!("  (no devices found)"),
        Err(e) => println!("  enumerate error: {e}"),
    }

    let cfg = SeifyConfig {
        args: a.get(1).cloned().unwrap_or_default(),
        frequency: a.get(2).and_then(|s| s.parse().ok()).unwrap_or(3.5e9),
        sample_rate: a.get(3).and_then(|s| s.parse().ok()).unwrap_or(30.72e6),
        rx_gain: a.get(4).and_then(|s| s.parse().ok()).unwrap_or(40.0),
        ..Default::default()
    };
    println!("\n=== opening args={:?} freq={} Hz rate={} Hz rx_gain={} dB ===",
        cfg.args, cfg.frequency, cfg.sample_rate, cfg.rx_gain);
    let radio = match SeifyRadio::open(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
    };
    println!("opened OK; sample_rate = {} Hz", radio.sample_rate());

    let mut rx = radio.rx().expect("activate RX stream");
    let want = (cfg.sample_rate * 5e-3) as usize; // ~5 ms
    let mut buf = vec![num_complex::Complex32::default(); want];
    let mut got = 0;
    while got < want {
        match rx.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }
    let avg_pow = buf[..got].iter().map(|c| c.norm_sqr()).sum::<f32>() / got.max(1) as f32;
    let peak = buf[..got].iter().map(|c| c.norm()).fold(0.0f32, f32::max);
    println!(
        "read {got} samples; avg power {avg_pow:.3e} ({:.1} dBFS), peak {peak:.3}",
        10.0 * avg_pow.max(1e-30).log10()
    );
}
