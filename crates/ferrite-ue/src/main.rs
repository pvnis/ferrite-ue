//! Ferrite UE — the entry point. Drives the whole attach procedure over the
//! ZMQ radio link to the OCUDU gNB: cell search → PRACH → RAR → Msg3 → Msg4
//! (contention resolution) → PUCCH/SR → RRCSetupComplete + NAS RegistrationRequest
//! → 5G-AKA (AuthenticationRequest/Response). Runs a locked read-DL/serve-UL loop
//! and decodes slot-by-slot so each downlink message is known before the uplink
//! it schedules is served.
//!
//! Run:   ferrite-ue [--tx tcp://…:2100] [--rx tcp://…:2101] [--center-mhz 3390.0]
//!                   [--imsi …] [--ki …] [--opc …] …  (see `Config` for all flags)
//! The gNB (radio/PHY config) and qcore (5G core) must be up first.

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::coding::dlsch::{dlsch_decode_single, dlsch_encode_single};
use ferrite_phy::pdcch::{equalize_candidate, equalize_candidate_c1, uss_candidates, Candidate, Coreset0};
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use ferrite_phy::prach::{prach_ncs_unrestricted, prach_occasion_waveform, prach_preamble_seq, PrachOccasion, PrachScs, PrachSeqLen};
use ferrite_phy::pusch::{pusch_e_len, pusch_modulate_slot, PuschAlloc};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_radio::SampleSource;
use ferrite_ue::milenage::{algo_key, k_amf, k_ausf, k_seaf, milenage, res_star};
use ferrite_ue::nas::{auth_response, nas_msg_type, nas_protect, parse_auth_request, registration_complete, registration_request, security_mode_complete, strip_security_header};
use ferrite_ue::rrc::{dl_dcch_type, mac_short_bsr, msg3_mac_pdu, parse_dl_dcch_nas, parse_dl_mac_pdu, parse_srb1_dl_rrc, parse_srb1_dl_rrc_sn, rlc_status_mac_pdu, rrc_reconfiguration_complete, rrc_security_mode_complete, rrc_setup_complete, rrc_setup_request, rrc_ul_information_transfer, srb1_msg5_pdu, CAUSE_MO_SIGNALLING, LCID_DL_CON_RES};
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;
use std::collections::VecDeque;

/// Parse a fixed-length hex string into a byte array.
fn hexn<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// All run-time configuration, parsed once from the command line. Every field
/// has a working default for the local OCUDU/qcore test setup.
struct Config {
    /// ZMQ endpoint for the downlink (gNB TX → UE) and uplink (UE → gNB RX).
    tx: String,
    rx: String,
    /// Sample rate (Hz) and carrier centre frequency (Hz).
    fs: f64,
    center_hz: f64,
    /// PRACH preamble index and UL TX peak amplitude.
    preamble: usize,
    amp: f32,
    /// PRACH offset sweep step; Msg3 slot delay; optional UL frequency shift.
    sweep0: i64,
    msg3_delay: i64,
    fshift: f64,
    /// Msg3 timing-offset (`toff`) search window: lo..=hi step.
    toff_lo: i64,
    toff_hi: i64,
    toff_step: i64,
    /// Subscriber identity + 5G-AKA (Milenage) credentials and serving-network name.
    imsi: String,
    ki: [u8; 16],
    opc: [u8; 16],
    snn: String,
}

impl Config {
    fn from_args() -> Self {
        Config {
            tx: arg("--tx", "tcp://127.0.0.1:2100"),
            rx: arg("--rx", "tcp://127.0.0.1:2101"),
            fs: arg("--srate", "15.36e6").parse().unwrap(),
            center_hz: arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6,
            preamble: arg("--preamble", "0").parse().unwrap(),
            amp: arg("--amp", "0.5").parse().unwrap(),
            sweep0: arg("--sweep", "384").parse().unwrap(),
            msg3_delay: arg("--msg3-delay", "7").parse().unwrap(),
            fshift: arg("--fshift", "0").parse().unwrap(),
            toff_lo: arg("--toff-lo", "-2800").parse().unwrap(),
            toff_hi: arg("--toff-hi", "-600").parse().unwrap(),
            toff_step: arg("--toff-step", "25").parse().unwrap(),
            imsi: arg("--imsi", "001010167891203"),
            ki: hexn(&arg("--ki", "5122250214c33e723a5dd523fc145fc0")),
            opc: hexn(&arg("--opc", "981d464c7c52eb6e5036234984ad0bcf")),
            snn: arg("--snn", "5G:mnc001.mcc001.3gppnetwork.org"),
        }
    }
}

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
    let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm, n_bwp: 0 , nof_cdm_groups: 2};
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

/// Decode a connected-mode DL PDSCH for `crnti` at RB `[rb_start, rb_start+n_rb)`
/// (SRB1: AuthenticationRequest / SecurityModeCommand / …). The frequency comes
/// from the DCI 1_1 assignment; the MCS is brute-forced (LDPC+CRC rejects wrong
/// guesses), covering the gNB's varying allocations. 1 CDM group, 12 symbols.
/// Returns the raw MAC TB on success.
fn try_decode_dl_srb1(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize + Copy,
    cell_id: u16,
    slot_idx: u32,
    crnti: u16,
    rb_start: usize,
    n_rb: usize,
    mcs: u8,
) -> Option<Vec<u8>> {
    // The MCS comes from the DCI 1_1 assignment; only the DM-RS CDM-group count
    // (1 group ⇒ data on the odd SCs of DM-RS symbols; 2 groups ⇒ none) is tried
    // both ways. n_re follows the CDM-group choice.
    for cdm in [1usize, 2] {
        let n_re = n_rb * ((12 - 3) * 12 + if cdm == 1 { 3 * 6 } else { 0 });
        {
            let (qm, r) = mcs_params(mcs);
            let (qm, r) = (qm as usize, r);
            let tbs = tbs_from_nre(n_re, r, qm);
            let alloc = PdschAlloc { rb_start, n_rb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm, n_bwp: 0, nof_cdm_groups: cdm };
            let hit = [true, false].into_iter().find_map(|time_first| {
                let px = extract_pdsch(grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, time_first);
                let mut llr = px.llrs.clone();
                descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
                let (bits, _conv, crc) = ferrite_phy::coding::dlsch::dlsch_decode_single_bits(&llr, tbs, r, qm, 0, 40);
                if !crc {
                    return None;
                }
                let tb: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
                // A wrong (mcs, cdm) guess can still pass the 24-bit CRC on a
                // retransmission; require the TB to unstack to a plausible DL-DCCH
                // RRC PDU (known c1 type; a dlInformationTransfer must carry a 0x7e
                // NAS) so the brute-force keeps trying until the real decode.
                let rrc = parse_srb1_dl_rrc(&tb)?;
                let ok = match dl_dcch_type(&rrc) {
                    Some(5) => parse_dl_dcch_nas(&rrc).is_some_and(|n| n.first() == Some(&0x7e)),
                    Some(0 | 2 | 4) => true,
                    _ => false,
                };
                if ok { Some(tb) } else { None }
            });
            if hit.is_some() {
                return hit;
            }
        }
    }
    None
}

fn main() {
    run(Config::from_args());
}

fn run(cfg: Config) {
    let Config {
        tx, rx, fs, center_hz, preamble, amp, sweep0, msg3_delay, fshift,
        toff_lo, toff_hi, toff_step, imsi, ki, opc, snn,
    } = cfg;

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
                 bursts: &[&Option<(i64, Vec<Complex32>)>],
                 acks: &[(i64, Vec<Complex32>)]| {
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
                let place = |pos: i64, wave: &[Complex32], block: &mut [Complex32]| {
                    for (i, &s) in wave.iter().enumerate() {
                        let abs = pos + i as i64;
                        if abs >= c && abs < c + bl {
                            block[(abs - c) as usize] = s;
                            injected.set(injected.get() + 1);
                        }
                    }
                };
                for burst in bursts.iter().copied() {
                    if let Some((pos, wave)) = burst {
                        place(*pos, wave, block);
                    }
                }
                // Pending HARQ-ACK PUCCH bursts (a queue: several can be in flight
                // since k1 is 4-12 slots ahead and DL PDSCHs arrive back to back).
                for (pos, wave) in acks {
                    place(*pos, wave, block);
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[]);
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[]);
        to_skip -= block_len;
    }
    if to_skip > 0 {
        fill_dl(&mut dl, &mut blk[..to_skip]);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[]);
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
    let mut pend_sr: Option<(i64, Vec<Complex32>)> = None;
    let mut pend_acks: Vec<(i64, Vec<Complex32>)> = Vec::new(); // in-flight DL HARQ-ACKs
    let pucch_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 23, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 0, occ_index: 0, n_id: acq.cell_id, carrier_rb,
    };
    // Connected-mode HARQ-ACK uses the DEDICATED PUCCH F1 resource: prb0, cs0,
    // occ0, symb[0,14), NO intra-slot hop (prb2=prb1) — unlike the common Msg4
    // resource above which hops to prb23.
    let harq_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 0, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 0, occ_index: 0, n_id: acq.cell_id, carrier_rb,
    };
    // SR PUCCH resource (from the RRCSetup dedicated config): F1, PRB 0 (no hop),
    // cs 6, occ 3, symb[0,14), monitored at slot 7. A positive SR = tx this (d=1).
    let sr_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 0, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 6, occ_index: 3, n_id: acq.cell_id, carrier_rb,
    };
    // Once contention resolution is won, drive the connected UE: send an SR to
    // request a grant for Msg5 (RRCSetupComplete). Stop new RA once connected.
    let mut connected: Option<u16> = None;
    let mut pend_msg5: Option<(i64, Vec<Complex32>)> = None;
    // Connected-mode UL: a queue of RRC PDUs to send on successive grants
    // (RRCSetupComplete, then the AuthenticationResponse, …), with a shared
    // SRB1 RLC/PDCP sequence number that increments per PDU.
    let mut ul_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut srb1_sn: u16 = 0;
    // NAS registration state machine: each DL NAS message queues a UL reply.
    let mut auth_done = false; // AuthenticationResponse queued
    let mut smc_done = false; // SecurityModeComplete queued
    let mut as_sec_done = false; // RRC securityModeComplete queued (AS security)
    let mut recfg_done = false; // rrcReconfigurationComplete queued
    let mut k_amf_st: Option<[u8; 32]> = None; // K_AMF, for K_gNB derivation
    let mut k_rrcint: Option<[u8; 16]> = None; // 128-NIA2 RRC integrity key (AS)
    let mut reg_done = false; // RegistrationComplete queued
    let mut nas_ul_count: u32 = 0; // NAS COUNT for uplink integrity protection
    let mut k_nasint: Option<[u8; 16]> = None; // 128-NIA2 key, derived after AKA
    let mut dl_rlc_next: u16 = 0; // next expected DL RLC SN (for RLC STATUS ACK)
    let mut pending_status: Option<u16> = None; // ACK_SN to report so the gNB DL advances
    // Msg5 payload: RRCSetupComplete carrying a NAS RegistrationRequest (SUCI).
    let rrc_sc = rrc_setup_complete(0, 1, &registration_request(&imsi));

    loop {
        let slot_start_ul = ul_counter as i64;
        // Read one slot of DL, serving UL (PRACH + pending Msg3) in lockstep.
        // PRACH base = first frame boundary + occasion offset + sweep offset.
        for b in 0..blocks_per_slot {
            fill_dl(&mut dl, &mut blk);
            slot_buf[b * block_len..(b + 1) * block_len].copy_from_slice(&blk);
            // Stop the periodic PRACH once connected: otherwise each frame's
            // preamble spawns a fresh TC-RNTI at the gNB, and the accumulated RA
            // UEs congest the PDCCH ("No space in PDCCH") so our connected UE can
            // no longer be granted UL/DL. i64::MAX/2 pushes PRACH out of range.
            let prach_base = if connected.is_some() { i64::MAX / 2 } else { align_ul + occ_off + offset };
            serve(&mut ul, &mut ul_counter, prach_base, &[&pend, &pend_pucch, &pend_sr, &pend_msg5], &pend_acks);
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
        // Connected: decode the C-RNTI UL grant and send the next queued SRB1 RRC
        // PDU on the granted PUSCH, k2 slots later. The gNB grants the FIRST UL
        // (RRCSetupComplete) via a CORESET0 fallback DCI 0_0 (AL4 CCE0), then moves
        // to the UE-specific search space (CORESET1, DCI 0_1) for everything after.
        // DCI 0_0 (37b) and 0_1 (36b) share their leading fields — id(1) freq-RIV
        // (9,N=24) time(4) hop(1) mcs(5) ndi(1) — so one parser handles both; only
        // the payload size and the search space differ. CORESET1 spans the whole
        // BWP (CRB0-23) like CORESET0 here, so it reuses cgrids/sc_to_bin.
        const DCI_0_1_SIZE: usize = 36;
        if let Some(crnti) = connected {
            // Decode a UL grant every slot (not only when we have data): a grant the
            // UE leaves empty is decoded as noise (crc=KO) and enough consecutive KOs
            // trip the gNB's "MAC max KOs" radio-link failure. So always fill a
            // decoded grant with a valid MAC PDU (reporting an empty buffer when idle).
            if pend_msg5.is_none() {
                let c0 = Candidate { agg_level: 4, cces: (0..4).collect() };
                let mut m = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &c0);
                pdcch_descramble_llr(&mut m, u32::from(acq.cell_id));
                let dci = dci_decode(&m, crnti, a_len).or_else(|| {
                    // CORESET1 UE-specific search space: DCI 0_1 (non-interleaved,
                    // AL2×4 + AL4×2 candidates). n_ID/n_RNTI for scrambling = cell_id/0.
                    uss_candidates(coreset.n_cce(), 1, crnti, slot_idx, &[(2, 4), (4, 2)])
                        .into_iter()
                        .find_map(|cand| {
                            let mut mm = equalize_candidate_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, coreset.n_symb, acq.cell_id, slot_idx, &cand);
                            pdcch_descramble_llr(&mut mm, u32::from(acq.cell_id));
                            dci_decode(&mm, crnti, DCI_0_1_SIZE)
                        })
                });
                if let Some(bits) = dci {
                    // UL grant. Both formats share id(1) + FDRA(9, type-1 RIV/N=24)
                    // at bits[1..10]; after that DCI 0_0 has time(4)+hop(1) then MCS,
                    // while DCI 0_1 (this config) has only a 3-bit time field and no
                    // hop flag, so its MCS/NDI sit 2 bits earlier. Verified live vs the
                    // gNB's scheduled grant (MCS/RV/HARQ aligned).
                    if bits[0] == 0 {
                        let mcs_lo = if bits.len() == DCI_0_1_SIZE { 13 } else { 15 };
                        let riv = bits[1..10].iter().fold(0usize, |a, &b| a << 1 | b as usize);
                        let (g_rb0, g_nrb) = riv_decode(riv, carrier_rb);
                        let mcs = bits[mcs_lo..mcs_lo + 5].iter().fold(0u8, |a, &b| a << 1 | b);
                        let ndi = bits[mcs_lo + 5];
                        let (qm, r) = mcs_params(mcs);
                        let m5_slot = slot_idx as i64 + 4; // k2 = 4 → PUSCH at slot 7
                        let n_data_sym = 14 - 3;
                        let e = g_nrb * 12 * n_data_sym * qm as usize;
                        let tbs = tbs_from_nre(g_nrb * 12 * n_data_sym, r, qm as usize);
                        let tbs_bytes = tbs / 8;
                        // The queued RRC PDU framed for SRB1 costs MAC(2)+RLC(2)+PDCP(2)
                        // +MAC-I(4) = 10 bytes of overhead. If it doesn't fit the grant
                        // (the gNB grants a minimal TB after an SR and waits for a BSR),
                        // send a Short BSR to solicit a larger grant instead.
                        let (mac, kind) = if let Some(ack) = pending_status {
                            // Acknowledge received DL RLC SDUs so the gNB stops
                            // retransmitting and delivers the next one.
                            pending_status = None;
                            (rlc_status_mac_pdu(ack, tbs_bytes), format!("RLC STATUS ack={ack}"))
                        } else if ul_queue.is_empty() {
                            // Idle grant: a valid, decodable PDU that reports an empty
                            // buffer so the gNB stops granting (and no crc=KO).
                            (mac_short_bsr(0, tbs_bytes), String::new())
                        } else if ul_queue.front().unwrap().len() + 10 > tbs_bytes {
                            let need = ul_queue.front().unwrap().len() + 10;
                            // Over-report the buffer so the gNB grants MORE RBs — its UL
                            // MCS drops under the (lossless-channel) KO noise, so a
                            // truthful ~52B report yields sub-52B grants that never fit
                            // the SRB1 PDU. A big report forces a wide grant we can pad.
                            (mac_short_bsr(need.max(220), tbs_bytes), format!("Short BSR (need {need}B)"))
                        } else {
                            let rrc = ul_queue.pop_front().unwrap();
                            let m = srb1_msg5_pdu(&rrc, srb1_sn, srb1_sn, tbs_bytes, k_rrcint.as_ref());
                            let k = if srb1_sn == 0 { "RRCSetupComplete".into() } else { format!("UL-DCCH(NAS) SN{srb1_sn}") };
                            srb1_sn += 1;
                            (m, k)
                        };
                        let m5_alloc = PuschAlloc { rb_start: g_rb0, n_rb: g_nrb, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, carrier_rb, crb_offset: 0 };
                        let ulsch = dlsch_encode_single(&bytes_to_bits(&mac), e, r, qm as usize, 0);
                        let mut m5 = pusch_modulate_slot(&ofdm, &ulsch, &m5_alloc, acq.cell_id, (m5_slot % 20) as u32, (m5_slot % 2) as usize, crnti, center_hz, fs);
                        let pk = m5.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                        for s in &mut m5 { *s *= amp / pk; }
                        let pos = slot_start_ul + (m5_slot - slot_idx as i64) * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * 4;
                        if !kind.is_empty() {
                            println!("  → {kind}: grant RB[{g_rb0},{}) MCS{mcs} ndi={ndi} tbs={tbs_bytes} at ul {pos} (slot {m5_slot})", g_rb0 + g_nrb);
                        }
                        pend_msg5 = Some((pos, m5));
                    }
                }
            }
        }

        let mut llrs = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &ra_cand);
        pdcch_descramble_llr(&mut llrs, u32::from(acq.cell_id));
        if let Some(bits) = dci_decode(&llrs, ra_rnti, a_len) {
            let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
            let riv = bits[..riv_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
            let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
            let mcs = bits[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &b| a << 1 | b);
            let (qm, r) = mcs_params(mcs);
            let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0 , nof_cdm_groups: 2};
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
                            if settled && pend.is_none() && connected.is_none() {
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

        // Connected DL: decode the SRB1 PDSCH at DL slots and drive the NAS
        // registration state machine (AuthReq → SMC → RegistrationAccept). The DL
        // allocation is variable, so read it from the DCI 1_1 assignment in the
        // CORESET1 USS (frequency = FDRA bits[1..10]); fall back to the fixed
        // rb[0,10/11) (the AuthReq) if no DCI decodes. MCS is brute-forced.
        if connected.is_some() && !reg_done && srb1_sn >= 1 {
            if matches!(slot_idx % 10, 0..=5) {
                let crnti = connected.unwrap();
                // Decode DCI 1_1 in the CORESET1 USS → (rb_start, n_rb, MCS, k1, PRI).
                // Layout (from the gNB dci_1_1_pack, this config): id[0] FDRA[1..10]
                // time[10] MCS[11..16] NDI[16] RV[17..19] HARQ[19..23] DAI[23..25]
                // TPC[25..27] PRI[27..30] k1[30..33] antenna[33..37] SRS[37..39] DMRS[39].
                let bits5 = |b: &[u8], lo: usize, n: usize| b[lo..lo + n].iter().fold(0u8, |a, &x| a << 1 | x);
                let mut allocs: Vec<(usize, usize, u8, u8, u8)> = uss_candidates(coreset.n_cce(), 1, crnti, slot_idx, &[(2, 4), (4, 2)])
                    .into_iter()
                    .filter_map(|cand| {
                        let mut mm = equalize_candidate_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, coreset.n_symb, acq.cell_id, slot_idx, &cand);
                        pdcch_descramble_llr(&mut mm, u32::from(acq.cell_id));
                        dci_decode(&mm, crnti, 40).filter(|b| b[0] == 1).map(|b| {
                            let riv = b[1..10].iter().fold(0usize, |a, &x| a << 1 | x as usize);
                            let (rb0, nrb) = riv_decode(riv, carrier_rb);
                            let a = (rb0, nrb, bits5(&b, 11, 5), bits5(&b, 30, 3), bits5(&b, 27, 3));
                            if auth_done { println!("  [dbg] DCI1_1 slot{slot_idx} rb[{},{}) mcs{} k1={} pri={}", a.0, a.0 + a.1, a.2, a.3, a.4); }
                            a
                        })
                    })
                    .collect();
                // Fallbacks when the DCI 1_1 doesn't decode: cover the connected-mode
                // DL allocations the gNB actually uses (rb[0,{10,11,13}) at a few low
                // MCS; the CDM-group is tried both ways in try_decode). No HARQ-ACK
                // (k1 unknown) for these.
                for (nrb, mcs) in [(10, 2), (11, 2), (13, 2), (11, 1), (13, 1), (10, 0), (13, 0), (20, 2)] {
                    allocs.push((0, nrb, mcs, 0xff, 0));
                }
                let allocs_len = allocs.len();
                if let Some(grids) = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1) {
                    let mut any_metric = false;
                    let mut decoded_ok = false;
                    for (rb0, nrb, mcs, k1, pri) in allocs {
                        let (qm, _) = mcs_params(mcs);
                        let probe = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0, nof_cdm_groups: 1 };
                        let metric = extract_pdsch(&grids, sc_to_bin, &probe, acq.cell_id, slot_idx, 0, 0, acq.cell_id, false).dmrs_metric;
                        if metric > 0.9 {
                            any_metric = true;
                            if let Some(tb) = try_decode_dl_srb1(&grids, sc_to_bin, acq.cell_id, slot_idx, crnti, rb0, nrb, mcs) {
                                decoded_ok = true;
                                // HARQ-ACK the PDSCH k1 slots later on the dedicated PUCCH
                                // F1 resource (prb0/cs0/occ0, no hop), so the gNB stops
                                // retransmitting and delivers the next SDU. ACK EVERY
                                // decoded PDSCH (incl. retransmissions) — a queue, since
                                // k1 is 4-12 slots ahead so several are in flight.
                                if k1 != 0xff {
                                    let _ = pri; // PRI selects the resource; only cs0/occ0 here
                                    // The 3-bit k1 field indexes the dl-DataToUL-ACK list
                                    // (from the gNB config): [4,5,6,7,8,9,11,12].
                                    const K1_LIST: [i64; 8] = [4, 5, 6, 7, 8, 9, 11, 12];
                                    let k1a = K1_LIST[k1 as usize & 7];
                                    let ack_slot = slot_idx as i64 + k1a;
                                    let mut aw = ferrite_phy::pucch::pucch_f1_modulate_slot(
                                        &ofdm, &harq_cfg, &[1], (ack_slot % 20) as u32, center_hz, fs);
                                    let pk = aw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                                    for s in &mut aw { *s *= amp / pk; }
                                    let pos = slot_start_ul + k1a * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * 4;
                                    if pend_acks.len() < 8 {
                                        pend_acks.push((pos, aw));
                                    }
                                }
                                let Some((rlc_sn, rrc)) = parse_srb1_dl_rrc_sn(&tb) else { break };
                                // On a NEW DL RLC SDU, arm an RLC STATUS ACK so the
                                // gNB advances (don't re-arm on retransmissions, which
                                // would starve our own UL data).
                                if rlc_sn >= dl_rlc_next {
                                    dl_rlc_next = rlc_sn + 1;
                                    pending_status = Some(dl_rlc_next);
                                }
                                let dtype = dl_dcch_type(&rrc);
                                println!("★ DL RRC (slot {slot_idx} rlcSN {rlc_sn}): c1={dtype:?} {}",
                                    rrc.iter().map(|b| format!("{b:02x}")).collect::<String>());
                                // RRC securityModeCommand (4): activate AS security. Derive
                                // K_gNB → K_RRCint; verify the DL PDCP MAC-I (validates the
                                // key) trying UL-NAS-COUNT candidates; reply RRC
                                // securityModeComplete (integrity-protected PDCP MAC-I).
                                if dtype == Some(4) && !as_sec_done {
                                    as_sec_done = true;
                                    if let (Some(kamf), Some((pdcp_sn, pmsg, pmac))) = (&k_amf_st, ferrite_ue::rrc::parse_srb1_dl_pdcp(&tb)) {
                                        let tid = ferrite_ue::rrc::dl_dcch_transaction_id(&rrc);
                                        let mut found = None;
                                        for c in 0..4u32 {
                                            let kg = ferrite_ue::milenage::k_gnb(kamf, c);
                                            let ki = algo_key(&kg, 4, 2); // RRC-int, 128-NIA2
                                            let exp = ferrite_ue::milenage::nia2_mac(&ki, pdcp_sn as u32, 0, 1, &pmsg);
                                            if exp == pmac { found = Some((c, ki)); break; }
                                        }
                                        match found {
                                            Some((c, ki)) => {
                                                k_rrcint = Some(ki);
                                                println!("   RRC SMC MAC=OK (K_gNB ul_nas_count={c}) → activating AS security");
                                                ul_queue.push_back(rrc_security_mode_complete(tid));
                                                println!("   ⇒ queued RRC SecurityModeComplete (tid {tid})");
                                            }
                                            None => println!("   RRC SMC MAC=BAD for ul_nas_count 0..3 (K_gNB derivation off)"),
                                        }
                                    }
                                    break;
                                }
                                // rrcReconfiguration (0): reply rrcReconfigurationComplete
                                // (its piggybacked NAS RegistrationAccept is handled below).
                                if dtype == Some(0) && !recfg_done {
                                    recfg_done = true;
                                    let tid = ferrite_ue::rrc::dl_dcch_transaction_id(&rrc);
                                    ul_queue.push_back(rrc_reconfiguration_complete(tid));
                                    println!("   ⇒ queued RRCReconfigurationComplete (tid {tid}) — ATTACH near-complete");
                                    break;
                                }
                                let Some(nas) = parse_dl_dcch_nas(&rrc).filter(|_| dtype == Some(5)) else { break };
                                let (sht, dl_mac, dl_seq, inner) = strip_security_header(&nas);
                                let mtype = nas_msg_type(inner);
                                println!("   NAS sht={sht} type={:02x?} {}",
                                    mtype, inner.iter().map(|b| format!("{b:02x}")).collect::<String>());
                                match mtype {
                                    // AuthenticationRequest → run 5G-AKA, derive the NAS
                                    // integrity key, queue the AuthenticationResponse.
                                    Some(0x56) if !auth_done => {
                                        if let Some(ar) = parse_auth_request(inner) {
                                            auth_done = true;
                                            let amf: [u8; 2] = ar.autn[6..8].try_into().unwrap();
                                            let z = milenage(&ki, &opc, &ar.rand, &[0; 6], &amf);
                                            let mut sqn = [0u8; 6];
                                            for i in 0..6 { sqn[i] = ar.autn[i] ^ z.ak[i]; }
                                            let sqn_xor_ak: [u8; 6] = ar.autn[0..6].try_into().unwrap();
                                            let m = milenage(&ki, &opc, &ar.rand, &sqn, &amf);
                                            let mac_ok = m.mac_a == ar.autn[8..16];
                                            let rs = res_star(&m.ck, &m.ik, &snn, &ar.rand, &m.res);
                                            // Derive K_AMF → K_NASint (TS 33.501): 128-NIA2.
                                            let kausf = k_ausf(&m.ck, &m.ik, &snn, &sqn_xor_ak);
                                            let kseaf = k_seaf(&kausf, &snn);
                                            let kamf = k_amf(&kseaf, &imsi, &ar.abba);
                                            k_nasint = Some(algo_key(&kamf, 2, 2));
                                            k_amf_st = Some(kamf);
                                            println!("   AKA: MAC={} RES*={}", if mac_ok { "OK" } else { "BAD" },
                                                rs.iter().map(|b| format!("{b:02x}")).collect::<String>());
                                            if mac_ok {
                                                ul_queue.push_back(rrc_ul_information_transfer(&auth_response(&rs)));
                                                println!("   ⇒ queued AuthenticationResponse");
                                            }
                                        }
                                    }
                                    // SecurityModeCommand → verify its DL integrity MAC
                                    // (validates K_NASint), send an integrity-protected
                                    // SecurityModeComplete replaying the RegistrationRequest.
                                    Some(0x5d) if auth_done && !smc_done => {
                                        smc_done = true;
                                        if let Some(ni) = &k_nasint {
                                            let exp = ferrite_ue::milenage::nia2_mac(ni, dl_seq as u32, 1, 1, &nas[6..]);
                                            println!("   SMC integrity MAC={}", if exp == dl_mac { "OK" } else { "BAD" });
                                            let inner = security_mode_complete(&imsi);
                                            let prot = nas_protect(0x04, ni, nas_ul_count, 0, &inner);
                                            nas_ul_count += 1;
                                            ul_queue.push_back(rrc_ul_information_transfer(&prot));
                                            println!("   ⇒ queued SecurityModeComplete (count {})", nas_ul_count - 1);
                                        }
                                    }
                                    // RegistrationAccept → send RegistrationComplete = attach done.
                                    Some(0x42) if smc_done && !reg_done => {
                                        reg_done = true;
                                        if let Some(ni) = &k_nasint {
                                            let prot = nas_protect(0x02, ni, nas_ul_count, 0, &registration_complete());
                                            nas_ul_count += 1;
                                            ul_queue.push_back(rrc_ul_information_transfer(&prot));
                                            println!("   ⇒ queued RegistrationComplete — ATTACH COMPLETE");
                                        }
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                    if auth_done && any_metric && !decoded_ok {
                        println!("  [dbg] PDSCH present slot{slot_idx} but NO decode ({} allocs tried)", allocs_len);
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
                let probe = PdschAlloc { rb_start: 0, n_rb: 21, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: 2, n_bwp: 0 , nof_cdm_groups: 2};
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
                            if connected.is_none() {
                                connected = Some(tcx);
                                ul_queue.push_back(rrc_sc.clone()); // Msg5 = first UL PDU
                                println!("  ⇒ CONNECTED as C-RNTI {tcx:#06x} — will SR for Msg5 grant");
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Send a Scheduling Request each frame at slot 7 whenever an SRB1 PDU is
        // queued (RRCSetupComplete, then the AuthenticationResponse) to solicit
        // a UL grant. Stops once the queue drains so we don't over-request.
        if connected.is_some() && (!ul_queue.is_empty() || pending_status.is_some()) && slot_idx == 0 && pend_sr.is_none() {
            let sr_slot = 7i64;
            let mut sw = ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &sr_cfg, &[], sr_slot as u32, center_hz, fs);
            let pk = sw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
            for s in &mut sw { *s *= amp / pk; }
            let pos = slot_start_ul + (sr_slot - slot_idx as i64) * slot_len
                + offset + locked_toff.unwrap_or(0) - last_ta * 4;
            pend_sr = Some((pos, sw));
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
        // Drop the pending PUCCH / SR once their windows have passed.
        if let Some((pos, wave)) = &pend_pucch {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                pend_pucch = None;
            }
        }
        if let Some((pos, wave)) = &pend_sr {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                pend_sr = None;
            }
        }
        // Drop HARQ-ACK bursts whose UL window has passed.
        pend_acks.retain(|(pos, wave)| (ul_counter as i64) <= pos + wave.len() as i64 + slot_len);
        if let Some((pos, wave)) = &pend_msg5 {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                pend_msg5 = None;
            }
        }
    }
}
