//! Transmit a PRACH Msg1 to the OCUDU gNB over ZMQ and let its PRACH detector
//! see it. Syncs to the downlink, then runs a locked read-DL / serve-UL loop so
//! the uplink sample counter tracks the downlink timeline (the gNB requests UL
//! and transmits DL in lockstep), and injects the format-C0 preamble at the
//! slot-19 occasion each frame.
//!
//! Usage: prach-tx [--tx …:2100] [--rx …:2101] [--srate 15.36e6]
//!   [--center-mhz 3390.0] [--preamble 0] [--amp 0.5]
//!   [--offset 0] [--sweep 0]  (sweep>0 auto-scans the UL↔DL offset by that step)

use ferrite_phy::prach::{
    prach_ncs_unrestricted, prach_occasion_waveform, prach_preamble_seq, PrachOccasion, PrachScs, PrachSeqLen,
};
use ferrite_phy::sync::CellSearcher;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_radio::SampleSource;
use ferrite_ue::sync::{gscn_scan, FrameSync};
use num_complex::Complex32;

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2100");
    let rx = arg("--rx", "tcp://127.0.0.1:2101");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let preamble: usize = arg("--preamble", "0").parse().unwrap();
    let amp: f32 = arg("--amp", "0.5").parse().unwrap();
    let mut offset: i64 = arg("--offset", "0").parse().unwrap();
    let sweep: i64 = arg("--sweep", "0").parse().unwrap();

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len() as i64;

    // --- Cell PRACH config (from gNB SIB1): index 159 → format C0, 30 kHz,
    // root seq idx 1, N_CS 0 (zeroCorrelationZone 0), msg1-FrequencyStart 5. ---
    let seq_len = PrachSeqLen::Short;
    let n_cs = prach_ncs_unrestricted(PrachScs::Short, 0).unwrap(); // 0
    let x_uv = prach_preamble_seq(1, preamble, n_cs, seq_len);
    let occ = PrachOccasion { fft_size: 512, grid_size: 24 * 12, k_start: 62, cp_samples: 310, nof_symbols: 1 };
    let mut prach = prach_occasion_waveform(&x_uv, &occ);
    // Scale to a peak amplitude of `amp` (ZMQ is lossless; power just needs to
    // be well above the noise floor the detector normalises against).
    let peak = prach.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
    for s in &mut prach {
        *s *= amp / peak;
    }
    let prach_len = prach.len() as i64;
    // Occasion offset within a frame: slot 19 (subframe 9, 2nd slot) starts at
    // 9.5 ms; symbol 2 follows the slot's symbols 0 (long CP 44) and 1 (36).
    let slot19 = (fs * 9.5e-3).round() as i64; // 145920 @ 15.36 Msps
    let occ_off = slot19 + (44 + 512) + (36 + 512); // 147024

    let block_len = 1920usize; // 80 blocks / frame
    let mut ul = ZmqSink::bind(&rx, fs, block_len).expect("bind UL");
    let dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");

    // --- Sync: pull DL blocks (serving UL zeros in lockstep) until we have
    // ~1.2 frames, then acquire. Keeping UL 1:1 with DL preserves alignment. ---
    let cap_len = (frame_len as usize) * 6 / 5;
    let mut cap: Vec<Complex32> = Vec::with_capacity(cap_len + block_len);
    let mut dl = dl;
    let mut ul_counter = 0u64;
    let mut blk = vec![Complex32::default(); block_len];
    let fill_dl = |dl: &mut ZmqSource, blk: &mut [Complex32]| {
        let mut got = 0;
        while got < blk.len() {
            got += dl.read(&mut blk[got..]).expect("dl read");
        }
    };
    while cap.len() < cap_len {
        fill_dl(&mut dl, &mut blk);
        cap.extend_from_slice(&blk);
        loop {
            if ul.serve_with(&mut ul_counter, |_, _| {}).expect("ul") {
                break;
            }
        }
    }
    let pos_after_cap = ul_counter as i64; // DL position == UL counter (locked)
    let (df, _r, shifted) = gscn_scan(&cap, fs, center_hz, &searcher).expect("no SSB");
    let acq = sync.acquire(&shifted).expect("acquire");
    println!(
        "synced: PCI {} SFN {} — PRACH C0 preamble {preamble}, occasion off {occ_off} in frame",
        acq.cell_id, acq.mib.sfn
    );
    let _ = df;

    // Frame boundary (SFN acq.next_sfn) sits at DL position `skip_to_frame`.
    // Occasions (every frame; detector runs each frame at slot 19) are at
    //   base + k·frame_len,  base = skip_to_frame + occ_off + offset.
    let base0 = acq.skip_to_frame as i64 + occ_off;
    let mut served_since_sweep = 0i64;
    println!("transmitting (offset {offset}, sweep step {sweep}); watch the gNB log for detected_preambles");

    loop {
        // Keep the downlink flowing so the gNB clock (and UL requests) advance.
        fill_dl(&mut dl, &mut blk);
        let base = base0 + offset;
        loop {
            let served = ul
                .serve_with(&mut ul_counter, |c, block| {
                    let c = c as i64;
                    let bl = block.len() as i64;
                    // Any occasion overlapping [c, c+bl)?
                    let mut k = (c - prach_len - base).div_euclid(frame_len);
                    if k < 0 {
                        k = 0;
                    }
                    for kk in k..=k + 1 {
                        let o = base + kk * frame_len;
                        if o >= c + bl || o + prach_len <= c {
                            continue;
                        }
                        for i in 0..prach_len {
                            let abs = o + i;
                            if abs >= c && abs < c + bl {
                                block[(abs - c) as usize] = prach[i as usize];
                            }
                        }
                    }
                })
                .expect("ul");
            if served {
                break;
            }
        }

        // Progress + optional auto-sweep of the UL↔DL calibration offset.
        served_since_sweep += block_len as i64;
        if served_since_sweep >= 4 * frame_len {
            served_since_sweep = 0;
            let tx_count = ((ul_counter as i64 - pos_after_cap).max(0) / frame_len) as u64;
            let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
            println!("  wall={wall:.3}  offset={offset}  (frames tx'd ≈{tx_count})");
            if sweep != 0 {
                offset = (offset + sweep).rem_euclid(frame_len);
            }
        }
    }
}
