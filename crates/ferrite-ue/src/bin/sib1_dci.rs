//! Live SIB1-DCI catcher: sync to a gNB over ZMQ, then blind-decode the
//! SI-RNTI DCI (format 1_0) from CORESET#0 at the Type0-PDCCH monitoring
//! occasions (slots 0/1 of even SFNs for {O=0, M=1}).
//!
//! Usage: sib1-dci [--tx ...] [--rx ...] [--srate 15.36e6]
//!                 [--center-mhz 3390.0] [--frames 100]

use ferrite_phy::coding::dci::{
    dci_1_0_si_size, dci_decode, pdcch_descramble_llr, BITS_PER_CCE,
};
use ferrite_phy::pdcch::{equalize_candidate, type0_candidates, Coreset0};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_ue::stream::BufferedStream;
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;

const SI_RNTI: u16 = 0xFFFF;

fn arg(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| default.to_string())
}

/// Parse DCI format 1_0 scrambled by SI-RNTI (38.212 §7.3.1.2.1).
fn parse_dci_1_0_si(bits: &[u8], n_rb: usize) -> String {
    let mut i = 0;
    let mut take = |n: usize| -> u32 {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from(bits[i]);
            i += 1;
        }
        v
    };
    let riv_bits =
        usize::BITS as usize - ((n_rb * (n_rb + 1) / 2) - 1).leading_zeros() as usize;
    let riv = take(riv_bits) as usize;
    let tdra = take(4);
    let vrb2prb = take(1);
    let mcs = take(5);
    let rv = take(2);
    let si = take(1);
    let _reserved = take(15);

    // RIV → (start, length): RIV = N(L−1)+S if L−1 ≤ ⌊N/2⌋, else N(N−L+1)+(N−1−S).
    let (l_rbs, s_rb) = {
        let (l, s) = (riv / n_rb + 1, riv % n_rb);
        if l <= n_rb - s {
            (l, s)
        } else {
            (n_rb + 1 - l + 1, n_rb - 1 - s)
        }
    };
    format!(
        "freq RA: RB {s_rb}+{l_rbs} (RIV {riv}), TDRA {tdra}, vrb2prb {vrb2prb}, \
         MCS {mcs}, RV {rv}, SI {}",
        if si == 0 { "SIB1" } else { "other-SI" }
    )
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2000");
    let rx = arg("--rx", "tcp://127.0.0.1:2001");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let n_frames: usize = arg("--frames", "100").parse().unwrap();
    let debug = std::env::args().any(|a| a == "--debug");

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();
    let ofdm = Ofdm::new(fft);

    let mut ul = ZmqSink::bind(&rx, fs, 1024).expect("bind UL");
    std::thread::spawn(move || loop {
        if ul.serve_zeros().is_err() {
            break;
        }
    });
    let dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");
    let mut stream = BufferedStream::spawn(dl, 32 * 1024);

    // Acquire.
    let mut capture = vec![Complex32::default(); frame_len * 6 / 5];
    stream.read_exact(&mut capture).expect("capture");
    let (df, _r, shifted) =
        gscn_scan(&capture, fs, center_hz, &searcher).expect("no SSB found");
    let acq = sync.acquire(&shifted).expect("acquire");
    let mib = acq.mib;
    let k_ssb = (mib.k_ssb_msb << 4) | mib.ssb_subcarrier_offset;
    let coreset = Coreset0::from_index_30_30_minbw5_10(mib.pdcch_config_sib1 >> 4)
        .expect("unsupported coreset0 index");
    println!(
        "acquired PCI {} SFN {}  k_SSB {k_ssb}  coreset0: {} RB x {} sym, offset {} RB",
        acq.cell_id, mib.sfn, coreset.n_rb, coreset.n_symb, coreset.offset_rb
    );
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = move |sc: usize| (first_sc + sc as i32).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    let candidates = type0_candidates(coreset.n_cce());
    println!(
        "monitoring {} candidates (DCI size {a_len} bits) in slots 0/1 of even SFNs",
        candidates.len()
    );

    stream.skip(acq.skip_to_frame).expect("skip");

    let slot_len = frame_len / 20; // 0.5 ms at mu=1
    let mut frame = vec![Complex32::default(); frame_len];
    let mut found = 0usize;
    for _ in 0..n_frames {
        let start_idx = stream.position();
        stream.read_exact(&mut frame).expect("stream ended");
        let frame_shifted = freq_shift(&frame, -df, fs, start_idx);
        let Some(rep) = sync.track(&frame_shifted) else {
            println!("lost lock");
            break;
        };
        if rep.sfn % 2 != 0 {
            continue;
        }
        for slot in 0..2u32 {
            // Demodulate the CORESET symbols of this slot.
            let base = slot as usize * slot_len;
            let mut grids = Vec::with_capacity(coreset.n_symb);
            let mut off = base;
            for l in 0..coreset.n_symb {
                // Symbol index within the subframe for CP length purposes.
                let sym_in_subframe = (slot as usize % 2) * 14 + l;
                let cp = ofdm.cp_len(sym_in_subframe, 1);
                grids.push(ofdm.demodulate_symbol(&frame_shifted[off..], cp));
                off += cp + fft;
            }
            for cand in &candidates {
                // Diagnostic: normalized DMRS correlation for this candidate —
                // ≈1 when a PDCCH with our assumed DMRS occupies these REGs.
                if debug {
                    use ferrite_phy::pdcch::{candidate_layout, pdcch_dmrs};
                    let lay = candidate_layout(&coreset, acq.cell_id, cand);
                    let refs: Vec<_> = (0..coreset.n_symb)
                        .map(|l| pdcch_dmrs(acq.cell_id, slot, l as u32, coreset.n_rb))
                        .collect();
                    // Per-symbol DMRS correlation.
                    let mut per_sym = vec![(Complex32::new(0.0, 0.0), 0f32); coreset.n_symb];
                    for &(l, k, m) in &lay.dmrs {
                        let rx = grids[l][sc_to_bin(k)];
                        per_sym[l].0 += rx * refs[l][m].conj();
                        per_sym[l].1 += rx.norm_sqr();
                    }
                    let energy: f32 = per_sym.iter().map(|s| s.1).sum();
                    if energy < 0.5 {
                        continue;
                    }
                    let sym_corr: Vec<f32> = per_sym
                        .iter()
                        .map(|(a, e)| {
                            a.norm() / (e.sqrt() * (lay.dmrs.len() as f32 / coreset.n_symb as f32).sqrt())
                        })
                        .collect();
                    println!(
                        "    SFN {:>4}.{slot} AL{} cce0={}: per-symbol dmrs_corr {:?}  E {:.2e}",
                        rep.sfn, cand.agg_level, cand.cces[0], sym_corr, energy
                    );
                }
                let mut llrs = equalize_candidate(
                    &grids,
                    sc_to_bin,
                    &coreset,
                    acq.cell_id,
                    slot,
                    cand,
                );
                debug_assert_eq!(llrs.len(), cand.agg_level * BITS_PER_CCE);
                pdcch_descramble_llr(&mut llrs, u32::from(acq.cell_id));
                if let Some(bits) = dci_decode(&llrs, SI_RNTI, a_len) {
                    found += 1;
                    println!(
                        "SFN {:>4} slot {slot}: SI-RNTI DCI @ AL{} CCEs {:?}",
                        rep.sfn, cand.agg_level, cand.cces
                    );
                    println!("  raw: {}", bits.iter().map(|b| b.to_string()).collect::<String>());
                    println!("  {}", parse_dci_1_0_si(&bits, coreset.n_rb));
                }
            }
        }
        if found >= 3 {
            break;
        }
    }
    println!("\n{found} SI-RNTI DCI(s) decoded");
    if found == 0 {
        std::process::exit(1);
    }
}
