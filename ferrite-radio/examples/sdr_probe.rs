//! Probe an SDR through SoapySDR: enumerate, open, configure, stream for a while, report
//! power, sample-index continuity (gaps = overflows) and the hardware time.
//!
//! De-risks the soapysdr → module → device path before wiring the SDR into the UE.
//!
//! Run (LimeSDR XTRX on PCIe, for example):
//!   cargo run -p ferrite-radio --example sdr_probe --features soapy -- \
//!       "driver=limesuiteng,addr=/dev/limepcie0" 3.5e9 15.36e6 40
//! Args: [device-args] [freq_hz] [sample_rate_hz] [rx_gain_db] [record_file] [record_s]

use ferrite_radio::soapy::{SoapyConfig, SoapyRadio};
use ferrite_radio::SampleSource;

fn main() {
    let a: Vec<String> = std::env::args().collect();

    println!("=== SoapySDR devices ===");
    match SoapyRadio::enumerate() {
        Ok(devs) if !devs.is_empty() => devs.iter().for_each(|d| println!("  {d}")),
        Ok(_) => println!("  (no devices found)"),
        Err(e) => println!("  enumerate error: {e}"),
    }

    let cfg = SoapyConfig {
        args: a.get(1).cloned().unwrap_or_default(),
        rx_frequency: a.get(2).and_then(|s| s.parse().ok()).unwrap_or(3.5e9),
        tx_frequency: a.get(2).and_then(|s| s.parse().ok()).unwrap_or(3.5e9),
        sample_rate: a.get(3).and_then(|s| s.parse().ok()).unwrap_or(30.72e6),
        rx_gain: a.get(4).and_then(|s| s.parse().ok()).unwrap_or(40.0),
        ..Default::default()
    };
    println!(
        "\n=== opening args={:?} freq={} Hz rate={} Hz rx_gain={} dB ===",
        cfg.args, cfg.rx_frequency, cfg.sample_rate, cfg.rx_gain
    );
    let radio = match SoapyRadio::open(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
    };
    let (time_rate, source) = radio.time_rate();
    println!(
        "opened OK; device reports {} Hz; timestamps advance at {time_rate} Hz ({source:?}); hardware time {:?} samples",
        radio.sample_rate(),
        radio.hardware_time().ok()
    );

    let mut rx = match radio.streams() {
        Ok((rx, _tx)) => rx,
        Err(e) => {
            eprintln!("RX stream failed: {e}");
            std::process::exit(1);
        }
    };
    // Stream ~200 ms, checking that every buffer's sample index follows the previous one.
    let block = 8192;
    let mut blk = vec![num_complex::Complex32::default(); block];
    let (mut sum_pow, mut peak, mut got) = (0.0f64, 0.0f32, 0usize);
    let (mut expected, mut gaps, mut gap_samples, mut first) = (None::<u64>, 0u32, 0u64, None);
    let want = (radio.sample_rate() * 200e-3) as usize;
    while got < want {
        let n = match rx.read(&mut blk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        };
        if let Some(ts) = rx.timestamp() {
            first.get_or_insert(ts);
            if let Some(exp) = expected {
                if ts != exp {
                    gaps += 1;
                    gap_samples += ts.abs_diff(exp);
                }
            }
            expected = Some(ts + n as u64);
        }
        for c in &blk[..n] {
            sum_pow += c.norm_sqr() as f64;
            peak = peak.max(c.norm());
        }
        got += n;
    }
    let avg_pow = (sum_pow / got.max(1) as f64) as f32;
    println!(
        "read {got} samples; avg power {avg_pow:.3e} ({:.1} dBFS), peak {peak:.3}",
        10.0 * avg_pow.max(1e-30).log10()
    );
    match first {
        Some(f) => println!(
            "timestamps: first {f}, {gaps} gaps totalling {gap_samples} samples, {} driver overflows",
            rx.overflows()
        ),
        None => println!("timestamps: none (the module reports no stream time)"),
    }

    // Optional raw record: args[5]=output file, args[6]=seconds (default 1.0). Reads straight
    // into RAM so the SDR FIFO does not overrun, then writes once — a clean, gap-free capture
    // for offline cell search + SIB1 decode. Interleaved f32 (re,im), no header.
    if let Some(out) = a.get(5) {
        use std::io::Write;
        let secs: f64 = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(1.0);
        let total = (radio.sample_rate() * secs) as usize;
        println!("recording {secs}s ({total} samples) to {out} ...");
        let mut rec: Vec<num_complex::Complex32> = Vec::with_capacity(total + block);
        while rec.len() < total {
            match rx.read(&mut blk) {
                Ok(0) | Err(_) => break,
                Ok(n) => rec.extend_from_slice(&blk[..n]),
            }
        }
        let mut bytes = Vec::with_capacity(rec.len() * 8);
        for c in &rec {
            bytes.extend(c.re.to_le_bytes());
            bytes.extend(c.im.to_le_bytes());
        }
        if let Err(e) = std::fs::File::create(out).and_then(|mut f| f.write_all(&bytes)) {
            eprintln!("write {out}: {e}");
            std::process::exit(1);
        }
        println!(
            "recorded {} samples ({} overflows) -> {out}",
            rec.len(),
            rx.overflows()
        );
    }
}
