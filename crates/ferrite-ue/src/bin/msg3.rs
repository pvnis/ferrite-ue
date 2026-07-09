//! Msg3 (PUSCH) transmit. Runs the random-access procedure: PRACH → RAR → Msg3.
//! Sweeps the PRACH offset until a RAR is decoded, then freezes the offset,
//! builds the Msg3 PUSCH from the RAR's grant/TC-RNTI, and injects it into the
//! uplink at the granted slot (RAR slot + msg3_delay). Decodes slot-by-slot so
//! the RAR is known before the Msg3 slot's uplink is served.
//!
//! Usage: msg3 [--tx …:2100] [--rx …:2101] [--center-mhz 3390.0] [--sweep 384]

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::coding::dlsch::{dlsch_decode_single, dlsch_encode_single};
use ferrite_phy::pdcch::{equalize_candidate, Candidate, Coreset0};
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use ferrite_phy::prach::{prach_ncs_unrestricted, prach_occasion_waveform, prach_preamble_seq, PrachOccasion, PrachScs, PrachSeqLen};
use ferrite_phy::pusch::{pusch_e_len, pusch_modulate_slot, PuschAlloc};
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

fn parse_rar(tb: &[u8], rapid: u8) -> Option<(u16, u32, u16)> {
    let mut i = 0;
    loop {
        let sub = *tb.get(i)?;
        let (e, t) = ((sub >> 7) & 1, (sub >> 6) & 1);
        i += 1;
        if t == 0 {
            if e == 0 { return None; }
            continue;
        }
        let this = sub & 0x3f;
        let p = tb.get(i..i + 7)?;
        if this == rapid {
            let ta = (((p[0] & 0x7f) as u16) << 5) | (p[1] >> 3) as u16;
            let grant = (((p[1] & 0x07) as u32) << 24) | ((p[2] as u32) << 16) | ((p[3] as u32) << 8) | p[4] as u32;
            let tc = ((p[5] as u16) << 8) | p[6] as u16;
            return Some((ta, grant, tc));
        }
        i += 7;
        if e == 0 { return None; }
    }
}

/// Build the 11-byte Msg3 MAC PDU: CCCH subheader + 6-byte RRCSetupRequest +
/// padding. Content is arbitrary for the gNB CRC/contention-resolution echo.
fn msg3_tb() -> Vec<u8> {
    let bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
    bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect()
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2100");
    let rx = arg("--rx", "tcp://127.0.0.1:2101");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let preamble: usize = arg("--preamble", "0").parse().unwrap();
    let amp: f32 = arg("--amp", "0.5").parse().unwrap();
    let sweep0: i64 = arg("--sweep", "384").parse().unwrap();
    let msg3_delay: i64 = arg("--msg3-delay", "7").parse().unwrap();
    let fshift: f64 = arg("--fshift", "0").parse().unwrap();

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();
    let ofdm = Ofdm::new(fft);
    let ra_rnti: u16 = 0x10b;
    let carrier_rb = 24usize;

    // PRACH preamble waveform.
    let x_uv = prach_preamble_seq(1, preamble, prach_ncs_unrestricted(PrachScs::Short, 0).unwrap(), PrachSeqLen::Short);
    let occ = PrachOccasion { fft_size: 512, grid_size: carrier_rb * 12, k_start: 62, cp_samples: 310, nof_symbols: 1 };
    let mut prach = prach_occasion_waveform(&x_uv, &occ);
    let peak = prach.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
    for s in &mut prach {
        *s *= amp / peak;
    }
    let prach_len = prach.len() as i64;
    let occ_off = (fs * 9.5e-3).round() as i64 + (44 + 512) + (36 + 512);

    let block_len = 1920usize;
    let slot_len = (frame_len / 20) as i64;
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

    // Pending Msg3 injection (ul position, samples), shared via the serve closure.
    // Uplink fill = periodic PRACH (base + offset) + any pending one-shot burst.
    let serve = |ul: &mut ZmqSink, counter: &mut u64, base: i64, pend: &Option<(i64, Vec<Complex32>)>| {
        loop {
            let ok = ul.serve_with(counter, |c, block| {
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
                if let Some((pos, wave)) = pend {
                    for (i, &s) in wave.iter().enumerate() {
                        let abs = pos + i as i64;
                        if abs >= c && abs < c + bl {
                            block[(abs - c) as usize] = s;
                        }
                    }
                }
            }).expect("ul");
            if ok { break; }
        }
    };

    // Sync.
    let cap_len = frame_len * 6 / 5;
    let mut cap: Vec<Complex32> = Vec::with_capacity(cap_len + block_len);
    while cap.len() < cap_len {
        fill_dl(&mut dl, &mut blk);
        cap.extend_from_slice(&blk);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None);
    }
    let (df, _r, shifted) = gscn_scan(&cap, fs, center_hz, &searcher).expect("no SSB");
    let acq = sync.acquire(&shifted).expect("acquire");
    let k_ssb = (acq.mib.k_ssb_msb << 4) | acq.mib.ssb_subcarrier_offset;
    let coreset = Coreset0::from_index_30_30_minbw5_10(acq.mib.pdcch_config_sib1 >> 4).expect("coreset0");
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = move |sc: i32| (first_sc + sc).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    let ra_cand = Candidate { agg_level: 4, cces: (0..4).collect() };
    println!("synced PCI {} — RA procedure: PRACH→RAR→Msg3", acq.cell_id);

    // Align to the frame boundary.
    let mut to_skip = acq.skip_to_frame;
    while to_skip >= block_len {
        fill_dl(&mut dl, &mut blk);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None);
        to_skip -= block_len;
    }
    if to_skip > 0 {
        fill_dl(&mut dl, &mut blk[..to_skip]);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None);
    }

    let blocks_per_slot = slot_len as usize / block_len; // 4
    let align_ul = ul_counter as i64; // first frame-boundary UL position
    let mut offset: i64 = 0;
    let mut frames_at_offset = 0i64;
    let mut sweep = sweep0;
    let mut pend: Option<(i64, Vec<Complex32>)> = None;
    let mut slot_buf = vec![Complex32::default(); slot_len as usize];
    let mut slot_idx = 0u32; // 0..20 within the frame

    loop {
        let slot_start_ul = ul_counter as i64;
        // Read one slot of DL, serving UL (PRACH + pending Msg3) in lockstep.
        // PRACH base = first frame boundary + occasion offset + sweep offset.
        for b in 0..blocks_per_slot {
            fill_dl(&mut dl, &mut blk);
            slot_buf[b * block_len..(b + 1) * block_len].copy_from_slice(&blk);
            serve(&mut ul, &mut ul_counter, align_ul + occ_off + offset, &pend);
        }

        // Decode this slot's RA search space.
        let fsh = freq_shift(&slot_buf, -df, fs, slot_start_ul as usize);
        let mut cgrids = Vec::new();
        let mut off = 0usize;
        for l in 0..coreset.n_symb {
            let cp = ofdm.cp_len((slot_idx as usize % 2) * 14 + l, 1);
            cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
            off += cp + fft;
        }
        let mut llrs = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &ra_cand);
        pdcch_descramble_llr(&mut llrs, u32::from(acq.cell_id));
        if let Some(bits) = dci_decode(&llrs, ra_rnti, a_len) {
            let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
            let riv = bits[..riv_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
            let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
            let mcs = bits[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &b| a << 1 | b);
            let (qm, r) = mcs_params(mcs);
            let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0 };
            if let Some(grids) = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1) {
                for tf in [false, true] {
                    let px = extract_pdsch(&grids, sc_to_bin, &alloc, acq.cell_id, slot_idx, 0, ra_rnti, acq.cell_id, tf);
                    let mut llr = px.llrs.clone();
                    descramble_llrs(&mut llr, pdsch_scramble_c_init(ra_rnti, acq.cell_id));
                    if let Some(tbb) = dlsch_decode_single(&llr, 72, r, qm as usize, 0, 40) {
                        let tb: Vec<u8> = tbb.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
                        if let Some((ta, grant, tc)) = parse_rar(&tb, preamble as u8) {
                            // Grant → Msg3 PUSCH allocation.
                            let freq_riv = ((grant >> 12) & 0x3fff) as usize;
                            let (m_rb0, m_nrb) = riv_decode(freq_riv, carrier_rb);
                            // Accept only a RAR that belongs to the CURRENT offset
                            // (dwell has settled) so its TA precisely corrects Msg3.
                            let settled = sweep == 0 || frames_at_offset >= 3;
                            if settled && pend.is_none() {
                                println!("RAR: TA={ta} grant={grant:#x} TC-RNTI={tc:#06x} → Msg3 RB[{m_rb0},{}] (offset {offset})", m_rb0 + m_nrb);
                                sweep = 0; // freeze the aligned offset
                                let _ = grant;
                                let m_alloc = PuschAlloc { rb_start: m_rb0, n_rb: m_nrb, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb, crb_offset: 2 };
                                let tb3 = msg3_tb();
                                let ulsch = dlsch_encode_single(&tb3, pusch_e_len(&m_alloc), 0.117, 2, 0);
                                let msg3_slot = slot_idx as i64 + msg3_delay;
                                let wave0 = pusch_modulate_slot(&ofdm, &ulsch, &m_alloc, acq.cell_id, (msg3_slot % 20) as u32, (msg3_slot % 2) as usize, tc);
                                // Optionally frequency-shift the uplink by k·df (the DL SSB
                                // offset) to test whether the UL grid is carrier- vs SSB-centred.
                                let pos0 = slot_start_ul + msg3_delay * slot_len + offset - ta as i64 * 4;
                                let mut wave = if fshift != 0.0 {
                                    freq_shift(&wave0, fshift * df, fs, pos0 as usize)
                                } else {
                                    wave0
                                };
                                // Scale to a peak amplitude of `amp` (like the PRACH) so the
                                // signal is well above the receiver's nose floor.
                                let wpk = wave.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                                for s in &mut wave {
                                    *s *= amp / wpk;
                                }
                                // Uplink position of the Msg3 slot (same skew/offset as
                                // PRACH), advanced by the timing advance (N_TA = TA·4 samples).
                                // Cycle a coarse timing offset to probe alignment (the frozen
                                // PRACH offset can sit anywhere in the wide detection window).
                                println!("  → Msg3 at ul {pos0} (slot {msg3_slot})");
                                let pos = pos0;
                                pend = Some((pos, wave));
                            }
                            break;
                        }
                    }
                }
            }
        }

        slot_idx = (slot_idx + 1) % 20;
        if slot_idx == 0 {
            frames_at_offset += 1;
            // Dwell ≥5 frames per offset so the RAR round-trip (~1.5 frames)
            // returns for THIS offset before stepping on.
            if sweep != 0 && frames_at_offset >= 5 {
                offset = (offset + sweep).rem_euclid(frame_len as i64);
                frames_at_offset = 0;
            }
        }
        // Drop the pending Msg3 once its window has passed.
        if let Some((pos, wave)) = &pend {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                println!("  Msg3 transmitted (window passed); watch gNB for PUSCH crc=OK");
                pend = None;
            }
        }
    }
}
