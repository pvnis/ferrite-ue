//! Continuous sync against a live gNB over ZMQ: acquire the cell, then track
//! it frame-by-frame, printing SFN / timing / CFO / MIB status.
//!
//! A dedicated radio thread drains the DL stream continuously (the gNB's DU is
//! wall-clock driven and must never be back-pressured); acquisition and
//! tracking consume from the buffer at their own pace.
//!
//! Usage:
//!   sync-track [--tx tcp://127.0.0.1:2000] [--rx tcp://127.0.0.1:2001]
//!              [--srate 15.36e6] [--center-mhz 3390.0] [--frames 200]

use ferrite_phy::sync::CellSearcher;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_ue::stream::BufferedStream;
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;

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
    let n_frames: usize = arg("--frames", "200").parse().unwrap();

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();

    // UL zero-server (keeps the gNB's receive chain clocked).
    let mut ul = ZmqSink::bind(&rx, fs, 1024).expect("bind UL port");
    std::thread::spawn(move || loop {
        if ul.serve_zeros().is_err() {
            break;
        }
    });

    println!("connecting to {tx} (fs {:.2} MHz, frame {frame_len} samples)", fs / 1e6);
    let dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");
    let mut stream = BufferedStream::spawn(dl, 32 * 1024);

    // ---- Acquisition: 12 ms guarantees a complete SSB at 10 ms periodicity. ----
    let acq_len = frame_len * 6 / 5;
    let mut capture = vec![Complex32::default(); acq_len];
    stream.read_exact(&mut capture).expect("capture failed");
    let t0 = std::time::Instant::now();
    let (df, _res, shifted) =
        gscn_scan(&capture, fs, center_hz, &searcher).expect("no SSB on the GSCN raster");
    let acq = sync.acquire(&shifted).expect("acquisition failed");
    println!(
        "acquired in {:.1}s: PCI {}  SSB @ {:.2} MHz (df {df:+.0} Hz)  i_SSB {}  SFN {}  cfo {:+.1} Hz",
        t0.elapsed().as_secs_f32(),
        acq.cell_id,
        (center_hz + df) / 1e6,
        acq.i_ssb,
        acq.mib.sfn,
        acq.cfo_hz
    );

    // The radio thread kept draining during the scan, so no samples were lost:
    // skipping `skip_to_frame` lands exactly on the next frame boundary and
    // the tracker's SFN counter (anchored in `acquire`) stays consistent.
    stream.skip(acq.skip_to_frame).expect("skip failed");
    let mut expect_sfn = acq.next_sfn;

    // ---- Track ----
    let mut frame = vec![Complex32::default(); frame_len];
    let (mut ok, mut mib_ok, mut lost) = (0usize, 0usize, 0usize);
    for k in 0..n_frames {
        let start_idx = stream.position();
        if stream.read_exact(&mut frame).is_err() {
            println!("stream ended at frame {k}");
            break;
        }
        let shifted = freq_shift(&frame, -df, fs, start_idx);
        match sync.track(&shifted) {
            Some(rep) => {
                ok += 1;
                if rep.mib_ok {
                    mib_ok += 1;
                }
                if k % 20 == 0 || !rep.mib_ok {
                    println!(
                        "  frame {k:>4}: SFN {:>4}  t_err {:+3}  cfo {:+7.1} Hz  pss {:.3}  MIB {}",
                        rep.sfn,
                        rep.timing_err,
                        rep.cfo_hz,
                        rep.pss_metric,
                        if rep.mib_ok { "ok" } else { "FAIL" }
                    );
                }
                expect_sfn = (rep.sfn + 1) & 0x3FF;
            }
            None => {
                lost += 1;
                println!("  frame {k:>4}: LOST LOCK (expected SFN {expect_sfn})");
            }
        }
    }
    println!("\ntracked {ok}/{n_frames} frames, MIB verified {mib_ok}/{ok}, lock lost {lost}x");
    if lost > 0 || mib_ok < ok {
        std::process::exit(1);
    }
}
