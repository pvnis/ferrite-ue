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
    // Drain continuously for ~200 ms, tolerating transient overruns (the device FIFO fills
    // while we're not reading; a single-shot read gives an unreliable few-hundred-sample power).
    let block = 8192;
    let mut blk = vec![num_complex::Complex32::default(); block];
    let mut sum_pow = 0.0f64;
    let mut peak = 0.0f32;
    let mut got = 0usize;
    let mut overruns = 0u32;
    let want = (cfg.sample_rate * 200e-3) as usize; // ~200 ms of good samples
    while got < want {
        match rx.read(&mut blk) {
            Ok(0) => break,
            Ok(n) => {
                for c in &blk[..n] {
                    sum_pow += c.norm_sqr() as f64;
                    peak = peak.max(c.norm());
                }
                got += n;
            }
            Err(_) => {
                overruns += 1;
                if overruns > 100000 {
                    break;
                }
            }
        }
    }
    let avg_pow = (sum_pow / got.max(1) as f64) as f32;
    println!(
        "read {got} samples ({overruns} overruns); avg power {avg_pow:.3e} ({:.1} dBFS), peak {peak:.3}",
        10.0 * avg_pow.max(1e-30).log10()
    );

    // Optional raw record: args[5]=output file, args[6]=seconds (default 1.0). Reads straight into
    // RAM (no per-block work) so the SDR FIFO doesn't overrun, then writes once — a clean, gap-free
    // capture for full offline cell-search + SIB1 decode. Interleaved f32 (re,im), no header.
    if let Some(out) = a.get(5) {
        use std::io::Write;
        let secs: f64 = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(1.0);
        let total = (cfg.sample_rate * secs) as usize;
        println!("recording {secs}s ({total} samples) to {out} ...");
        let mut rec: Vec<num_complex::Complex32> = Vec::with_capacity(total + block);
        let mut ov = 0u64;
        while rec.len() < total {
            match rx.read(&mut blk) {
                Ok(0) => break,
                Ok(n) => rec.extend_from_slice(&blk[..n]),
                Err(_) => { ov += 1; if ov > 1_000_000 { break; } }
            }
        }
        let mut bytes = Vec::with_capacity(rec.len() * 8);
        for c in &rec { bytes.extend(c.re.to_le_bytes()); bytes.extend(c.im.to_le_bytes()); }
        std::fs::File::create(out).and_then(|mut f| f.write_all(&bytes)).expect("write recording");
        println!("recorded {} samples ({ov} overruns) -> {out}", rec.len());
    }
}
