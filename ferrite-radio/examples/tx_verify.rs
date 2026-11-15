//! Verify the SDR TX path actually transmits, using a second BladeRF as a monitor.
//! TX a CW tone on device A (serial arg 1) and measure RX power on device B (serial arg 2)
//! at the same frequency, with the tone ON vs OFF. A large ON−OFF delta ⇒ TX works (and the
//! two antennas couple). Away from the gNB frequency so the gNB DL doesn't confound it.
//!
//! Run: cargo run -p ferrite-radio --example tx_verify --features soapy -- <txSerial> <rxSerial> [freq_hz] [tx_gain]

use ferrite_radio::soapy::{SoapyConfig, SoapyRadio};
use ferrite_radio::{SampleSink, SampleSource};
use num_complex::Complex32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let tx_serial = a
        .get(1)
        .cloned()
        .expect("usage: tx_verify <txSerial> <rxSerial> [freq] [gain]");
    let rx_serial = a.get(2).cloned().expect("need rxSerial");
    let freq: f64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(3450e6);
    let tx_gain: f64 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(60.0);
    let fs = 30.72e6;

    let txr = SoapyRadio::open(&SoapyConfig {
        args: format!("driver=bladerf,serial={tx_serial}"),
        sample_rate: fs,
        rx_frequency: freq,
        tx_frequency: freq,
        tx_gain,
        rx_gain: 30.0,
        ..Default::default()
    })
    .expect("open TX device");
    let rxr = SoapyRadio::open(&SoapyConfig {
        args: format!("driver=bladerf,serial={rx_serial}"),
        sample_rate: fs,
        rx_frequency: freq,
        tx_frequency: freq,
        rx_gain: 50.0,
        ..Default::default()
    })
    .expect("open RX device");
    println!(
        "TX {tx_serial} (gain {tx_gain}) → RX {rx_serial} @ {} MHz",
        freq / 1e6
    );

    let on = Arc::new(AtomicBool::new(false));
    // TX thread: continuously push either a +1 MHz tone (when ON) or zeros (when OFF).
    let on_t = on.clone();
    let (_tx_rx, mut tx) = txr.streams().expect("activate TX");
    let (mut rx, _rx_tx) = rxr.streams().expect("activate RX");
    std::thread::spawn(move || {
        let block = 8192usize;
        let mut n = 0u64;
        let w = std::f64::consts::TAU * 1e6 / fs; // +1 MHz tone
        let mut buf = vec![Complex32::default(); block];
        loop {
            let tone = on_t.load(Ordering::Relaxed);
            for s in buf.iter_mut() {
                *s = if tone {
                    let ph = w * n as f64;
                    Complex32::new(0.5 * ph.cos() as f32, 0.5 * ph.sin() as f32)
                } else {
                    Complex32::new(0.0, 0.0)
                };
                n += 1;
            }
            let mut off = 0;
            while off < block {
                if let Ok(k) = tx.write(&buf[off..]) {
                    off += k;
                }
            }
        }
    });

    // Measure RX power in a band around the tone (+1 MHz → FFT bin) with tone OFF then ON.
    let measure = |rx: &mut ferrite_radio::soapy::SoapyRx| -> f32 {
        let block = 8192usize;
        let mut buf = vec![Complex32::default(); block];
        let mut sum = 0f64;
        let mut cnt = 0u64;
        // De-rotate the +1 MHz tone to DC and integrate → concentrates the tone's power.
        let w = -std::f64::consts::TAU * 1e6 / fs;
        let mut n = 0u64;
        for _ in 0..80 {
            if let Ok(g) = rx.read(&mut buf) {
                let mut acc = Complex32::new(0.0, 0.0);
                for s in &buf[..g] {
                    let ph = (w * n as f64) as f32;
                    acc += *s * Complex32::from_polar(1.0, ph);
                    n += 1;
                }
                sum += (acc.norm_sqr() / g.max(1) as f32) as f64;
                cnt += 1;
            }
        }
        (sum / cnt.max(1) as f64) as f32
    };
    on.store(false, Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let off_p = measure(&mut rx);
    on.store(true, Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let on_p = measure(&mut rx);
    println!(
        "tone OFF: {:.1} dB   tone ON: {:.1} dB   delta: {:.1} dB",
        10.0 * off_p.max(1e-30).log10(),
        10.0 * on_p.max(1e-30).log10(),
        10.0 * (on_p / off_p.max(1e-30)).max(1e-30).log10()
    );
    println!(
        "{}",
        if on_p > off_p * 4.0 {
            "→ TX VERIFIED: the tone is received (TX transmits, antennas couple)."
        } else {
            "→ inconclusive: no clear tone (TX not transmitting, or antennas don't couple)."
        }
    );
}
