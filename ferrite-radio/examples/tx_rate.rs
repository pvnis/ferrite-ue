//! Measure the sustainable BladeRF TX sample rate, full-duplex (RX draining concurrently,
//! like the live UE). Isolates the "TX underflow" question from cell search. Sweeps write
//! block sizes. Run: cargo run -p ferrite-radio --example tx_rate --features soapy -- <serial> [rate]

use ferrite_radio::soapy::{SoapyConfig, SoapyRadio};
use ferrite_radio::{SampleSink, SampleSource};
use num_complex::Complex32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let serial = a.get(1).cloned().expect("usage: tx_rate <serial> [rate]");
    let fs: f64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(30.72e6);

    let radio = SoapyRadio::open(&SoapyConfig {
        args: format!("driver=bladerf,serial={serial}"),
        sample_rate: fs,
        frequency: 3414.99e6,
        rx_gain: 40.0,
        tx_gain: 50.0,
        ..Default::default()
    })
    .expect("open");
    println!(
        "device {serial} @ {} Msps; reported sample_rate={}",
        fs / 1e6,
        radio.sample_rate()
    );

    // RX drain thread (mimics the live UE: continuous RX must run alongside TX).
    let rx_on = Arc::new(AtomicBool::new(true));
    let rx_n = Arc::new(AtomicU64::new(0));
    {
        let (rx_on, rx_n) = (rx_on.clone(), rx_n.clone());
        let mut rx = radio.rx().expect("rx");
        std::thread::spawn(move || {
            let mut buf = vec![Complex32::default(); 32768];
            while rx_on.load(Ordering::Relaxed) {
                if let Ok(n) = rx.read(&mut buf) {
                    rx_n.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        });
    }

    let mut tx = radio.tx().expect("tx");
    for &blk in &[1920usize, 16384, 65536, 262144] {
        let buf = vec![Complex32::new(0.1, 0.0); blk];
        // warm up
        for _ in 0..20 {
            let mut o = 0;
            while o < blk {
                if let Ok(k) = tx.write(&buf[o..]) {
                    o += k;
                }
            }
        }
        let rx0 = rx_n.load(Ordering::Relaxed);
        let t0 = std::time::Instant::now();
        let mut written = 0u64;
        while t0.elapsed().as_secs_f64() < 2.0 {
            let mut o = 0;
            while o < blk {
                if let Ok(k) = tx.write(&buf[o..]) {
                    o += k;
                }
            }
            written += blk as u64;
        }
        let dt = t0.elapsed().as_secs_f64();
        let rx_rate = (rx_n.load(Ordering::Relaxed) - rx0) as f64 / dt / 1e6;
        println!(
            "blk={blk:>7}: TX {:.2} Msps   (RX concurrently {:.2} Msps)   [target {:.1}]",
            written as f64 / dt / 1e6,
            rx_rate,
            fs / 1e6
        );
    }
    rx_on.store(false, Ordering::Relaxed);
}
