//! Random Access Response (Msg2). Transmit the PRACH preamble (sweeping the
//! UL↔DL offset) and, on the downlink, monitor the RA search space (CORESET0,
//! AL4, RA-RNTI) every slot for a DCI 1_0 → decode the RAR PDSCH → parse the
//! MAC RAR (timing advance, Msg3 grant, TC-RNTI).
//!
//! Usage: rar-rx [--tx …:2100] [--rx …:2101] [--center-mhz 3390.0]
//!   [--preamble 0] [--amp 0.5] [--sweep 192]

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::coding::dlsch::dlsch_decode_single;
use ferrite_phy::pdcch::{equalize_candidate, Candidate, Coreset0};
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use ferrite_phy::prach::{prach_ncs_unrestricted, prach_occasion_waveform, prach_preamble_seq, PrachOccasion, PrachScs, PrachSeqLen};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_radio::SampleSource;
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

fn riv_decode(riv: usize, n: usize) -> (usize, usize) {
    let l0 = riv / n + 1;
    let s0 = riv % n;
    if l0 <= n - s0 { (s0, l0) } else { (n - 1 - s0, n - l0 + 2) }
}

/// Parse a MAC RAR PDU (bytes) for the RAR matching `rapid`; returns
/// (timing-advance command, 27-bit Msg3 UL grant, TC-RNTI). 38.321 §6.1.5/6.2.3.
fn parse_rar(tb: &[u8], rapid: u8) -> Option<(u16, u32, u16)> {
    let mut i = 0;
    loop {
        let sub = *tb.get(i)?;
        let (e, t) = ((sub >> 7) & 1, (sub >> 6) & 1);
        i += 1;
        if t == 0 {
            // Backoff-indicator subheader (1 byte, no payload).
            if e == 0 {
                return None;
            }
            continue;
        }
        let this = sub & 0x3f;
        let p = tb.get(i..i + 7)?;
        if this == rapid {
            // R(1) TA(12) UL-grant(27) TC-RNTI(16)
            let ta = (((p[0] & 0x7f) as u16) << 5) | (p[1] >> 3) as u16;
            let ul_grant = (((p[1] & 0x07) as u32) << 24) | ((p[2] as u32) << 16) | ((p[3] as u32) << 8) | p[4] as u32;
            let tc_rnti = ((p[5] as u16) << 8) | p[6] as u16;
            return Some((ta, ul_grant, tc_rnti));
        }
        i += 7;
        if e == 0 {
            return None;
        }
    }
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2100");
    let rx = arg("--rx", "tcp://127.0.0.1:2101");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let preamble: usize = arg("--preamble", "0").parse().unwrap();
    let amp: f32 = arg("--amp", "0.5").parse().unwrap();
    let sweep: i64 = arg("--sweep", "192").parse().unwrap();

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();
    let ofdm = Ofdm::new(fft);
    let ra_rnti: u16 = 0x10b; // 267 = 1 + s_id + 14·t_id for this occasion

    // PRACH preamble waveform (cell config: format C0, 30 kHz, root idx 1, N_CS 0).
    let x_uv = prach_preamble_seq(1, preamble, prach_ncs_unrestricted(PrachScs::Short, 0).unwrap(), PrachSeqLen::Short);
    let occ = PrachOccasion { fft_size: 512, grid_size: 24 * 12, k_start: 62, cp_samples: 310, nof_symbols: 1 };
    let mut prach = prach_occasion_waveform(&x_uv, &occ);
    let peak = prach.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
    for s in &mut prach {
        *s *= amp / peak;
    }
    let prach_len = prach.len() as i64;
    let occ_off = (fs * 9.5e-3).round() as i64 + (44 + 512) + (36 + 512);

    let block_len = 1920usize;
    let mut ul = ZmqSink::bind(&rx, fs, block_len).expect("bind UL");
    let mut dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");
    let mut ul_counter = 0u64;
    let mut blk = vec![Complex32::default(); block_len];
    let fill_dl = |dl: &mut ZmqSource, blk: &mut [Complex32]| {
        let mut got = 0;
        while got < blk.len() {
            got += dl.read(&mut blk[got..]).expect("dl read");
        }
    };
    let serve_ul = |ul: &mut ZmqSink, counter: &mut u64, base: i64| {
        loop {
            let ok = ul
                .serve_with(counter, |c, block| {
                    let (c, bl) = (c as i64, block.len() as i64);
                    let k0 = ((c - prach_len - base).div_euclid(frame_len as i64)).max(0);
                    for kk in k0..=k0 + 1 {
                        let o = base + kk * frame_len as i64;
                        for i in 0..prach_len {
                            let abs = o + i;
                            if abs >= c && abs < c + bl {
                                block[(abs - c) as usize] = prach[i as usize];
                            }
                        }
                    }
                })
                .expect("ul");
            if ok {
                break;
            }
        }
    };

    // Sync.
    let cap_len = frame_len * 6 / 5;
    let mut cap: Vec<Complex32> = Vec::with_capacity(cap_len + block_len);
    while cap.len() < cap_len {
        fill_dl(&mut dl, &mut blk);
        cap.extend_from_slice(&blk);
        serve_ul(&mut ul, &mut ul_counter, i64::MAX / 2); // no PRACH yet
    }
    let (df, _r, shifted) = gscn_scan(&cap, fs, center_hz, &searcher).expect("no SSB");
    let acq = sync.acquire(&shifted).expect("acquire");
    let k_ssb = (acq.mib.k_ssb_msb << 4) | acq.mib.ssb_subcarrier_offset;
    let coreset = Coreset0::from_index_30_30_minbw5_10(acq.mib.pdcch_config_sib1 >> 4).expect("coreset0");
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = move |sc: i32| (first_sc + sc).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    let ra_cand = Candidate { agg_level: 4, cces: (0..4).collect() }; // AL4, CCE 0
    println!("synced PCI {} — TX PRACH preamble {preamble}, monitoring RA-RNTI {ra_rnti:#05x}", acq.cell_id);

    // Align to the frame boundary: discard skip_to_frame DL samples (serving UL
    // in lockstep; the final partial read leaves a constant UL↔DL offset the
    // sweep absorbs). Subsequent full-block reads stay frame-aligned so track works.
    let mut to_skip = acq.skip_to_frame;
    while to_skip >= block_len {
        fill_dl(&mut dl, &mut blk);
        serve_ul(&mut ul, &mut ul_counter, i64::MAX / 2);
        to_skip -= block_len;
    }
    if to_skip > 0 {
        fill_dl(&mut dl, &mut blk[..to_skip]);
        serve_ul(&mut ul, &mut ul_counter, i64::MAX / 2);
    }
    // First aligned frame boundary is at the current UL counter; occasions follow.
    let base0 = ul_counter as i64 + occ_off;
    let mut offset: i64 = 0;
    let slot_len = frame_len / 20;
    let mut frame = vec![Complex32::default(); frame_len];

    loop {
        // Read one downlink frame while serving the uplink (PRACH) in lockstep.
        let frame_start = ul_counter as i64;
        let mut filled = 0;
        while filled < frame_len {
            let n = (frame_len - filled).min(block_len);
            fill_dl(&mut dl, &mut blk[..n]);
            frame[filled..filled + n].copy_from_slice(&blk[..n]);
            filled += n;
            serve_ul(&mut ul, &mut ul_counter, base0 + offset);
        }
        if sweep != 0 {
            offset = (offset + sweep).rem_euclid(frame_len as i64);
        }
        let fsh = freq_shift(&frame, -df, fs, frame_start as usize);
        let Some(rep) = sync.track(&fsh) else { continue };

        // Monitor the RA search space (CORESET0 symbols 0..n_symb). The RAR
        // lands a few slots after the PRACH; skip the PRACH slots to save work.
        for slot in 0..16u32 {
            let base = slot as usize * slot_len;
            let mut cgrids = Vec::new();
            let mut off = base;
            for l in 0..coreset.n_symb {
                let cp = ofdm.cp_len((slot as usize % 2) * 14 + l, 1);
                if off + cp + fft > fsh.len() {
                    break;
                }
                cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
                off += cp + fft;
            }
            if cgrids.len() < coreset.n_symb {
                continue;
            }
            let mut llrs = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot, &ra_cand);
            pdcch_descramble_llr(&mut llrs, u32::from(acq.cell_id));
            let Some(bits) = dci_decode(&llrs, ra_rnti, a_len) else { continue };

            let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
            let riv = bits[..riv_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
            let tdra = bits[riv_bits..riv_bits + 4].iter().fold(0u8, |a, &b| a << 1 | b);
            let mcs = bits[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &b| a << 1 | b);
            let (rb_start, n_rb) = riv_decode(riv, coreset.n_rb);
            let (s_sym, l_sym) = ([2usize, 2, 2, 2, 2][tdra.min(4) as usize], [12usize, 10, 9, 7, 5][tdra.min(4) as usize]);
            let (qm, r) = mcs_params(mcs);
            println!("*** SFN {} slot {slot}: RA-RNTI DCI  RB {rb_start}+{n_rb}  sym {s_sym}+{l_sym}  MCS {mcs}", rep.sfn);

            let alloc = PdschAlloc {
                rb_start, n_rb, sym_start: s_sym, n_sym: l_sym,
                dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0,
            };
            let Some(grids) = demod_slot(&ofdm, &fsh, base, slot as usize % 2, 1) else { continue };
            // TBS for the RAR (small): gNB logs tbs=9 bytes. Try both orderings.
            let tbs = 72usize;
            for tf in [false, true] {
                let px = extract_pdsch(&grids, sc_to_bin, &alloc, acq.cell_id, slot, 0, ra_rnti, acq.cell_id, tf);
                let mut llr = px.llrs.clone();
                descramble_llrs(&mut llr, pdsch_scramble_c_init(ra_rnti, acq.cell_id));
                if let Some(tbbits) = dlsch_decode_single(&llr, tbs, r, qm as usize, 0, 40) {
                    let tbb: Vec<u8> = tbbits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
                    println!("  RAR TB: {}", tbb.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    if let Some((ta, grant, tc)) = parse_rar(&tbb, preamble as u8) {
                        println!("  *** RAR DECODED: TA={ta}  Msg3-grant={grant:#09x}  TC-RNTI={tc:#06x} ***");
                        return;
                    }
                    break;
                }
            }
        }
    }
}
