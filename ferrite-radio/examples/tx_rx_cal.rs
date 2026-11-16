//! Measure a device's RX→TX sample offset (`--tx-rx-offset` for `ferrite-ue`).
//!
//! A known burst is transmitted at device sample `T` (`write_at`) and looked for in
//! the receive stream (TX→RX coupling: a cable with attenuation, or the two antennas
//! of one device). It appears at `T + δ`, where δ is the TX chain latency plus the RX
//! chain latency in the device's own time base; that sum is exactly the offset the
//! UE's uplink timing must be fed earlier by (`SampleClock`: `u = d − TA − δ`).
//! Repeated several times; the median and spread are printed.
//!
//! Run (LimeSDR XTRX on PCIe, for example):
//!   cargo run -p ferrite-radio --example tx_rx_cal --features soapy --release -- \
//!       "driver=limesuiteng,addr=/dev/limepcie0" 3.5e9 15.36e6 40 30 [repeats]
//! Args: [device-args] [freq_hz] [sample_rate_hz] [rx_gain_db] [tx_gain_db] [repeats]

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_radio::soapy::{SoapyConfig, SoapyRadio};
use ferrite_radio::{SampleSink, SampleSource};
use num_complex::Complex32;

/// A unit-power BPSK burst from a small LCG: flat spectrum, sharp autocorrelation.
fn burst(len: usize) -> Vec<Complex32> {
    let mut x = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let b = if x >> 31 == 1 { 1.0 } else { -1.0 };
            Complex32::new(0.5 * b, 0.0)
        })
        .collect()
}

/// Lag of the correlation peak of `pattern` inside `capture`, and the peak-to-mean ratio.
fn find(capture: &[Complex32], pattern: &[Complex32]) -> (usize, f32) {
    let mut best = (0usize, 0.0f32);
    let mut sum = 0.0f32;
    let mut n = 0usize;
    for lag in 0..capture.len().saturating_sub(pattern.len()) {
        let c: Complex32 = capture[lag..lag + pattern.len()]
            .iter()
            .zip(pattern)
            .map(|(a, b)| a * b.conj())
            .sum();
        let m = c.norm_sqr();
        sum += m;
        n += 1;
        if m > best.1 {
            best = (lag, m);
        }
    }
    let mean = if n > 0 { sum / n as f32 } else { 1.0 };
    (best.0, best.1 / mean.max(1e-20))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: f64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let cfg = SoapyConfig {
        args: a.get(1).cloned().unwrap_or_default(),
        rx_frequency: arg(2, 3.5e9),
        tx_frequency: arg(2, 3.5e9),
        sample_rate: arg(3, 15.36e6),
        rx_gain: arg(4, 40.0),
        tx_gain: arg(5, 30.0),
        ..Default::default()
    };
    let repeats = arg(6, 5.0) as usize;
    let radio = match SoapyRadio::open(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
    };
    let fs = radio.sample_rate();
    let (mut rx, mut tx) = match radio.streams() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("streams failed: {e}");
            std::process::exit(1);
        }
    };
    let pattern = burst(2048);
    // Search window: the burst may land up to this far from where it was timed.
    let window = (fs * 200e-6) as usize;
    let lead = (fs * 20e-3) as u64; // schedule 20 ms ahead of the receive head
    let mut buf = vec![Complex32::default(); 8192];
    let mut offsets = Vec::new();
    for rep in 0..repeats {
        // Receive head now.
        let n = rx.read(&mut buf).unwrap_or(0);
        let Some(ts) = rx.timestamp() else {
            eprintln!("no RX timestamps; cannot calibrate");
            std::process::exit(1);
        };
        let t_tx = ts + n as u64 + lead;
        if let Err(e) = tx.write_at(&pattern, t_tx, true) {
            eprintln!("timed write failed: {e}");
            std::process::exit(1);
        }
        // Capture [t_tx − window, t_tx + pattern + window).
        let cap_start = t_tx - window as u64;
        let cap_len = pattern.len() + 2 * window;
        let mut cap: Vec<Complex32> = Vec::with_capacity(cap_len);
        let mut cap_pos: Option<u64> = None;
        let mut power = 0.0f64;
        loop {
            let n = match rx.read(&mut buf) {
                Ok(0) | Err(_) => {
                    eprintln!("RX ended");
                    std::process::exit(1);
                }
                Ok(n) => n,
            };
            let Some(ts) = rx.timestamp() else { continue };
            let end = ts + n as u64;
            if end <= cap_start {
                continue;
            }
            if cap_pos.is_none() {
                if ts > cap_start {
                    eprintln!("gap at capture start (overflow?); retrying");
                    break;
                }
                cap_pos = Some(cap_start);
            }
            let from = (cap_start.max(ts) - ts) as usize;
            let take = (n - from).min(cap_len - cap.len());
            cap.extend_from_slice(&buf[from..from + take]);
            power += buf[from..from + take]
                .iter()
                .map(|s| s.norm_sqr() as f64)
                .sum::<f64>();
            if cap.len() >= cap_len {
                break;
            }
        }
        if cap.len() < cap_len {
            continue;
        }
        let (lag, ratio) = find(&cap, &pattern);
        let delta = lag as i64 - window as i64;
        let dbfs = 10.0 * (power / cap_len as f64).max(1e-20).log10();
        println!(
            "run {rep}: burst at T+{delta} samples ({:.2} µs), peak/mean {ratio:.0}, capture {dbfs:.1} dBFS{}",
            delta as f64 / fs * 1e6,
            if ratio < 50.0 { "  [weak: increase gain / coupling]" } else { "" }
        );
        if ratio >= 50.0 {
            offsets.push(delta);
        }
    }
    if offsets.is_empty() {
        eprintln!("no reliable detections");
        std::process::exit(1);
    }
    offsets.sort_unstable();
    let median = offsets[offsets.len() / 2];
    println!(
        "\nRX→TX offset: {median} samples ({:.2} µs) over {} runs, spread {}..{} → ferrite-ue --tx-rx-offset {median}",
        median as f64 / fs * 1e6,
        offsets.len(),
        offsets[0],
        offsets[offsets.len() - 1]
    );
}
