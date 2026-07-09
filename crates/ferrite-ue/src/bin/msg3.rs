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
use ferrite_ue::rrc::{msg3_mac_pdu, parse_dl_mac_pdu, rrc_setup_request, CAUSE_MO_SIGNALLING, LCID_DL_CON_RES};
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
fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect()
}

/// PDSCH transport block size (bits) for a single layer, TS 38.214 §5.1.3.2.
/// `n_re` = data REs, `r` = target code rate (fraction), `qm` = modulation order.
fn tbs_from_nre(n_re: usize, r: f64, qm: usize) -> usize {
    // Table 5.1.3.2-1 (N_info <= 3824).
    const TBL: &[usize] = &[
        24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 208, 224,
        240, 256, 272, 288, 304, 320, 336, 352, 368, 384, 408, 432, 456, 480, 504, 528, 552, 576, 608, 640, 672, 704,
        736, 768, 808, 848, 888, 928, 984, 1032, 1064, 1128, 1160, 1192, 1224, 1256, 1288, 1320, 1352, 1416, 1480, 1544,
        1608, 1672, 1736, 1800, 1864, 1928, 2024, 2088, 2152, 2216, 2280, 2408, 2472, 2536, 2600, 2664, 2728, 2792,
        2856, 2976, 3104, 3240, 3368, 3496, 3624, 3752, 3824,
    ];
    let n_info = (n_re as f64 * r * qm as f64).floor() as usize;
    if n_info <= 3824 {
        let n = (((n_info as f64).log2().floor() as i64) - 6).max(3) as u32;
        let n_info_p = (24).max((1 << n) * (n_info / (1 << n)));
        *TBL.iter().find(|&&t| t >= n_info_p).unwrap_or(&3824)
    } else {
        // Larger blocks (not needed for Msg4, kept for completeness).
        let n = ((n_info - 24) as f64).log2().floor() as u32 - 5;
        let step = 1 << n;
        let n_info_p = step * ((n_info - 24 + step / 2) / step);
        let c = if r <= 0.25 { (n_info_p + 24).div_ceil(3816) } else if n_info_p > 8424 { (n_info_p + 24).div_ceil(8424) } else { 1 };
        c * (8 * ((n_info_p + 24).div_ceil(8 * c))) - 24
    }
}

/// Decode the Msg4 PDSCH (RRCSetup + Contention Resolution) and check the
/// ConRes CE against our Msg3 CCCH SDU. `dci` are the decoded DCI 1_0 bits.
/// Try to decode a Msg4 PDSCH for `tc` in the current slot and, if the ConRes CE
/// matches our Msg3 CCCH, report the win and the RRCSetup. Returns true on match.
#[allow(clippy::too_many_arguments)]
fn try_decode_msg4(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize + Copy,
    cell_id: u16,
    slot_idx: u32,
    tc: u16,
    ccch_sdu: &[u8; 6],
) -> Option<Vec<u8>> {
    // Msg4 allocation (fallback DCI 1_0 defaults): PRB[0,21), symbols[2,14),
    // QPSK MCS7 (Qm2, R=526/1024), 2 CDM groups, non-interleaved VRB-to-PRB.
    let (rb0, nrb, qm, r) = (0usize, 21usize, 2usize, 526.0 / 1024.0);
    let n_re = nrb * 12 * (12 - 3);
    let tbs = tbs_from_nre(n_re, r, qm);
    let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm, n_bwp: 0 };
    // CORESET0 RB0 = CRB0 here (base 0, confirmed by the SIB1 sanity). Data RE
    // mapping order is l,k' (time_first) for these common PDSCHs; try both.
    let dbg = std::env::var("MSG4DBG").is_ok();
    let tb = [true, false].into_iter().find_map(|time_first| {
        let px = extract_pdsch(grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, tc, cell_id, time_first);
        let mut llr = px.llrs.clone();
        descramble_llrs(&mut llr, pdsch_scramble_c_init(tc, cell_id));
        let (bits, conv, crc) = ferrite_phy::coding::dlsch::dlsch_decode_single_bits(&llr, tbs, r, qm, 0, 40);
        if dbg {
            eprintln!("  [msg4] tc={tc:#06x} slot {slot_idx} tf={time_first} dmrs={:.2} conv={conv} crc={crc}", px.dmrs_metric);
        }
        if !crc {
            return None;
        }
        let tb: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
        if tb.iter().all(|&b| b == 0) {
            None
        } else {
            Some(tb)
        }
    })?;
    let subs = parse_dl_mac_pdu(&tb);
    println!("  · Msg4 PDSCH crc=OK (non-zero!) tc={tc:#06x} slot {slot_idx} lcids={:?} head={}",
        subs.iter().map(|s| s.lcid).collect::<Vec<_>>(),
        tb.iter().take(12).map(|b| format!("{b:02x}")).collect::<String>());
    if subs.iter().any(|s| s.lcid == LCID_DL_CON_RES && s.payload.as_slice() == &ccch_sdu[..]) {
        println!("✦✦ Msg4 CONTENTION RESOLUTION WON (TC-RNTI={tc:#06x}, slot {slot_idx})");
        for s in &subs {
            if s.lcid == LCID_DL_CON_RES {
                println!("   ConRes CE = {} (== our Msg3 CCCH)", s.payload.iter().map(|b| format!("{b:02x}")).collect::<String>());
            } else if s.lcid == 0 {
                println!("   DL-CCCH RRCSetup ({} bytes): {}", s.payload.len(), s.payload.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
        }
        return Some(tb);
    }
    None
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
    let injected = std::cell::Cell::new(0i64); // diagnostic: pend samples actually written
    // Uplink fill = periodic PRACH (base + offset) + Msg3 burst (`pend`) + PUCCH
    // HARQ-ACK burst (`pend_pucch`). Msg3 (PRB 4-6) and PUCCH (PRB 0/23) never
    // overlap in frequency, so both can be present in the same UL slot.
    let serve = |ul: &mut ZmqSink,
                 counter: &mut u64,
                 base: i64,
                 pend: &Option<(i64, Vec<Complex32>)>,
                 pend_pucch: &Option<(i64, Vec<Complex32>)>| {
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
                for burst in [pend, pend_pucch] {
                    if let Some((pos, wave)) = burst {
                        for (i, &s) in wave.iter().enumerate() {
                            let abs = pos + i as i64;
                            if abs >= c && abs < c + bl {
                                block[(abs - c) as usize] = s;
                                injected.set(injected.get() + 1);
                            }
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None, &None);
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None, &None);
        to_skip -= block_len;
    }
    if to_skip > 0 {
        fill_dl(&mut dl, &mut blk[..to_skip]);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &None, &None);
    }

    let blocks_per_slot = slot_len as usize / block_len; // 4
    let align_ul = ul_counter as i64; // first frame-boundary UL position
    let mut offset: i64 = 0;
    let mut frames_at_offset = 0i64;
    let mut sweep = sweep0;
    let mut pend: Option<(i64, Vec<Complex32>)> = None;
    let mut slot_buf = vec![Complex32::default(); slot_len as usize];
    let mut slot_idx = 0u32; // 0..20 within the frame
    // Msg3 launch timing: pos0 (below) lands ~1900 samples late (occ_off models the
    // PRACH RO ~3.5 symbols late + per-run ZMQ startup skew), and the gNB's decode
    // window is NARROW (< a CP). So cycle a per-attempt `toff` correction over a fine
    // grid until the Msg3 lands in the window (crc=OK in the gNB log). Not yet
    // auto-locked to Msg4 — sweep step must be ≤ ~50 samples or it steps over.
    let toff_lo: i64 = arg("--toff-lo", "-2800").parse().unwrap();
    let toff_hi: i64 = arg("--toff-hi", "-600").parse().unwrap();
    let toff_step: i64 = arg("--toff-step", "25").parse().unwrap();
    let toffs: Vec<i64> = (toff_lo..=toff_hi).step_by(toff_step.max(1) as usize).collect();
    println!("toff sweep {toff_lo}..{toff_hi} step {toff_step} ({} pts)", toffs.len());
    let mut attempt = 0usize;

    // Msg3 payload: a real RRCSetupRequest (fixed random ue-Identity so the Msg4
    // Contention Resolution Identity CE, which echoes the first 48 bits of this
    // CCCH SDU, can be matched). LCID52 CCCH48 + 6-byte SDU + padding to TBS 11.
    let ue_random: u64 = 0x00c0_ffee_42 & ((1 << 39) - 1);
    let ccch_sdu = rrc_setup_request(ue_random, CAUSE_MO_SIGNALLING);
    println!("Msg3 RRCSetupRequest ue-Identity={ue_random:#012x} ccch={}", ccch_sdu.iter().map(|b| format!("{b:02x}")).collect::<String>());

    // Msg4 (contention resolution) is DCI 1_0 scrambled by the TC-RNTI in the RA
    // search space, AL2 CCE 0..1. Track recently-sent TC-RNTIs and probe for it.
    // Track (TC-RNTI, toff) for recently-sent Msg3s; when a Msg4 confirms one
    // succeeded, lock that toff so every subsequent Msg3 lands in the window.
    let mut recent_tc: std::collections::VecDeque<(u16, i64)> = std::collections::VecDeque::new();
    let mut locked_toff: Option<i64> = None;
    let mut msg4_wins = 0u32;
    // PUCCH HARQ-ACK for Msg4 (contention resolution). `last_ta` is the RAR TA
    // used to advance UL timing; `pend_pucch` is the pending PUCCH F1 burst.
    let mut last_ta: i64 = 5;
    let mut pend_pucch: Option<(i64, Vec<Complex32>)> = None;
    let pucch_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 23, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 0, occ_index: 0, n_id: acq.cell_id, carrier_rb,
    };

    loop {
        let slot_start_ul = ul_counter as i64;
        // Read one slot of DL, serving UL (PRACH + pending Msg3) in lockstep.
        // PRACH base = first frame boundary + occasion offset + sweep offset.
        for b in 0..blocks_per_slot {
            fill_dl(&mut dl, &mut blk);
            slot_buf[b * block_len..(b + 1) * block_len].copy_from_slice(&blk);
            serve(&mut ul, &mut ul_counter, align_ul + occ_off + offset, &pend, &pend_pucch);
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
                                last_ta = ta as i64;
                                let _ = grant;
                                // carrier RB0 = point A (CRB0), so the DM-RS gold sequence
                                // is referenced directly to the carrier RB (crb_offset 0).
                                let m_alloc = PuschAlloc { rb_start: m_rb0, n_rb: m_nrb, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb, crb_offset: 0 };
                                let tb3 = bytes_to_bits(&msg3_mac_pdu(&ccch_sdu, 11));
                                let ulsch = dlsch_encode_single(&tb3, pusch_e_len(&m_alloc), 0.117, 2, 0);
                                let msg3_slot = slot_idx as i64 + msg3_delay;
                                let dmrs_slot = msg3_slot % 20;
                                // §5.4 phase compensation at the carrier centre (center_hz):
                                // the gNB's OFDM demod removes it, so an uncompensated UL
                                // decorrelates the DM-RS across symbols. Critical for decode.
                                let wave0 = pusch_modulate_slot(&ofdm, &ulsch, &m_alloc, acq.cell_id, dmrs_slot as u32, (msg3_slot % 2) as usize, tc, center_hz, fs);
                                let pos0 = slot_start_ul + msg3_delay * slot_len + offset - ta as i64 * 4;
                                let toff = locked_toff.unwrap_or_else(|| toffs[attempt % toffs.len()]);
                                let mut wave = if fshift != 0.0 {
                                    freq_shift(&wave0, fshift * df, fs, (pos0 + toff) as usize)
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
                                attempt += 1;
                                let pos = pos0 + toff;
                                pend = Some((pos, wave));
                                recent_tc.push_back((tc, toff));
                                while recent_tc.len() > 24 {
                                    recent_tc.pop_front();
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Msg4 (contention resolution): decode the TC-RNTI PDSCH directly at DL
        // slots for any recently-sent TC-RNTI (LDPC+CRC is more robust than the
        // blind AL2 PDCCH decode). ConRes CE match ⇒ that Msg3 won → attach on.
        // Msg4 lands at DL slots ≡ {1,5} (mod 10) for this TDD pattern. The DM-RS
        // is cell-specific (tc-independent), so measure the 21-RB PDSCH DM-RS once;
        // only if a real PDSCH is present do we run the per-TC LDPC decode.
        if matches!(slot_idx % 10, 1 | 5) && !recent_tc.is_empty() {
            if let Some(grids) = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1) {
                let probe = PdschAlloc { rb_start: 0, n_rb: 21, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: 2, n_bwp: 0 };
                let metric = extract_pdsch(&grids, sc_to_bin, &probe, acq.cell_id, slot_idx, 0, 0, acq.cell_id, false).dmrs_metric;
                if metric > 0.9 {
                    let cands: Vec<(u16, i64)> = recent_tc.iter().rev().copied().collect();
                    for (tcx, toffx) in cands {
                        if try_decode_msg4(&grids, sc_to_bin, acq.cell_id, slot_idx, tcx, &ccch_sdu).is_some() {
                            msg4_wins += 1;
                            if locked_toff != Some(toffx) {
                                locked_toff = Some(toffx);
                                sweep = 0;
                                println!("  ⇒ toff LOCKED at {toffx} (Msg3 now reliable); Msg4 wins={msg4_wins}");
                            }
                            // HARQ-ACK the Msg4 on PUCCH F1 at the next UL slot
                            // (7 for a DL slot ≤5, else 17). Same UL timing as Msg3.
                            if pend_pucch.is_none() {
                                let pucch_slot = if slot_idx < 10 { 7 } else { 17 };
                                let mut pw = ferrite_phy::pucch::pucch_f1_modulate_slot(
                                    &ofdm, &pucch_cfg, &[1], pucch_slot as u32, center_hz, fs);
                                let pk = pw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                                for s in &mut pw { *s *= amp / pk; }
                                let pos = slot_start_ul + (pucch_slot as i64 - slot_idx as i64) * slot_len
                                    + offset + toffx - last_ta * 4;
                                println!("  → PUCCH ACK for TC-RNTI={tcx:#06x} at ul {pos} (slot {pucch_slot})");
                                pend_pucch = Some((pos, pw));
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
                println!("  Msg3 window passed: injected {}/{} samples (ul_counter {} vs pos {})",
                    injected.get(), wave.len(), ul_counter, pos);
                injected.set(0);
                pend = None;
            }
        }
        // Drop the pending PUCCH once its window has passed.
        if let Some((pos, wave)) = &pend_pucch {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                pend_pucch = None;
            }
        }
    }
}
