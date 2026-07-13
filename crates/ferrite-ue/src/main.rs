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
use ferrite_phy::pdcch::{all_candidates, coreset_candidate_coherence, equalize_candidate, equalize_candidate_c1_cached, estimate_coreset_c1, Candidate, Coreset0};
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use ferrite_phy::prach::{prach_ncs_unrestricted, prach_occasion_waveform, prach_preamble_seq, PrachOccasion, PrachScs, PrachSeqLen};
use ferrite_phy::pusch::{pusch_e_len, pusch_modulate_slot, PuschAlloc};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_radio::SampleSource;
use ferrite_ue::milenage::{algo_key, k_amf, k_ausf, k_seaf, milenage, res_star};
use ferrite_ue::rt::{InjectionTable, ReadyWaveform};
use ferrite_ue::stream::BufferedStream;
use std::sync::atomic::{AtomicI64, Ordering::Relaxed as Rlx};
use std::sync::{Arc, Mutex};
use ferrite_ue::nas::{auth_response, nas_msg_type, nas_protect, nas_transport_payload, parse_auth_request, registration_complete, registration_request, security_mode_complete, strip_security_header, ul_nas_transport_pdu_session};
use ferrite_ue::userplane::{drb_mac_wrap, drb_ul_pdu, ipv4_icmp_echo_request, pdcp_data_pdu, rlc_um_segment};
use ferrite_ue::rrc::{dl_dcch_type, mac_short_bsr, msg3_mac_pdu, parse_dl_dcch_nas, parse_dl_mac_pdu, parse_srb1_dl_rrc, rlc_status_mac_pdu, rrc_reconfiguration_complete, rrc_security_mode_complete, rrc_setup_complete, rrc_ue_capability_information, rrc_setup_request, rrc_ul_information_transfer, srb1_dl_rrc_reasm, srb1_msg5_pdu, RlcReassembler, CAUSE_MO_SIGNALLING, LCID_DL_CON_RES};
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use ferrite_ue::tun::{configure_tun, open_tun};
use num_complex::Complex32;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};

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
    /// User-plane ping: the UE's assigned IP (from the PDU Session Accept) and the
    /// ICMP echo target. If `ue_ip` is None, no ping is attempted after attach.
    ue_ip: Option<[u8; 4]>,
    ping_target: [u8; 4],
    /// If set, create a TUN interface (this name) and carry real host IP traffic
    /// over the DRB instead of the built-in ping. `netns` optionally moves it into
    /// a network namespace. Needs privileges (run under sudo).
    tun: Option<String>,
    netns: Option<String>,
    tun_mtu: u32,
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
            ue_ip: arg_opt("--ue-ip").as_deref().map(parse_ipv4),
            ping_target: parse_ipv4(&arg("--ping-target", "10.255.0.1")),
            tun: arg_opt("--tun"),
            netns: arg_opt("--netns"),
            tun_mtu: arg("--tun-mtu", "1400").parse().unwrap(),
        }
    }
}

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

fn arg_opt(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

/// Parse a dotted-quad IPv4 address into 4 octets.
fn parse_ipv4(s: &str) -> [u8; 4] {
    let mut o = [0u8; 4];
    for (i, p) in s.split('.').enumerate().take(4) {
        o[i] = p.parse().expect("ipv4 octet");
    }
    o
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
        let (bits, conv, crc) = ferrite_phy::coding::dlsch::dlsch_decode_single_bits(&llr, tbs, r, qm, 0, 10);
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
/// Per-HARQ-process DL soft-combining buffer: the accumulated circular-buffer LLRs
/// for the transport block currently in flight on this HARQ process, plus the code
/// parameters they were built with (a change ⇒ the gNB reused the process for a new
/// TB, so the buffer is reset).
struct HarqDl {
    tbs: usize,
    qm: usize,
    acc: Vec<f32>,
    n_rx: usize,
}

/// Pack MSB-first bits into bytes.
fn pack_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect()
}

/// Accept a decoded TB only if it is a plausible DRB IP packet or a known DL-DCCH RRC
/// PDU — rejects a wrong (mcs, cdm) guess that slips the CRC on a retransmission.
fn plausible_dl_tb(tb: &[u8]) -> bool {
    if ferrite_ue::userplane::looks_like_drb_ip(tb) {
        return true;
    }
    let Some(rrc) = parse_srb1_dl_rrc(tb) else { return false };
    match dl_dcch_type(&rrc) {
        Some(5) => parse_dl_dcch_nas(&rrc).is_some_and(|n| n.first() == Some(&0x7e)),
        Some(0 | 2 | 4 | 6) => true, // rrcReconfig / rrcRelease / securityModeCommand / ueCapabilityEnquiry
        _ => false,
    }
}

/// Extract the 6-bit Timing Advance Command from a DL-SCH MAC PDU's TA Command MAC CE
/// (38.321: LCID 61, one payload octet = 2-bit TAG id + 6-bit T_A), if present. Walks
/// the subPDU subheaders in order and stops at padding; returns None if there is no TA
/// command or the layout isn't understood.
fn parse_ta_command_ce(tb: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < tb.len() {
        let (lcid, f) = (tb[i] & 0x3f, (tb[i] >> 6) & 1);
        match lcid {
            63 => return None,                             // padding: rest is padding
            61 => return tb.get(i + 1).map(|&v| v & 0x3f), // TA Command CE: 1-octet payload
            60 | 59 => i += 1,                             // (Long) DRX Command: 0-octet payload
            62 => i += 1 + 6,                              // Contention Resolution Identity: 6 octets
            1..=32 => {                                    // logical-channel SDU: R/F/LCID + L(+SDU)
                let (len, hdr) = if f == 1 {
                    (((*tb.get(i + 1)? as usize) << 8) | *tb.get(i + 2)? as usize, 3)
                } else {
                    (*tb.get(i + 1)? as usize, 2)
                };
                i += hdr + len;
            }
            _ => return None, // unknown subheader: bail safely
        }
    }
    None
}

/// Time-domain shape of a connected-mode DL PDSCH: (sym_start, n_sym, DM-RS symbols),
/// selected by the DCI's 1-bit time-domain-resource-assignment (the cell's TDA list has
/// exactly two rows). Row 0 = the full [2,14) with DM-RS {2,7,11}; row 1 = [2,8) with
/// DM-RS {2,7} (both from the gNB's scheduler log dl_dmrs_symb_pos). The short row is
/// used in the TDD special slot (slot 6 — only 8 DL symbols) for FIRST transmissions,
/// but HARQ retransmissions of such a TB keep the short shape in NORMAL slots too (same
/// TBS ⇒ same allocation), so the shape must come from the DCI, not the slot index:
/// inferring it from the slot wedged the attach whenever the slot-6 first TX was missed
/// (every retx then extracted as 12-symbol and could never CRC → registration timeout).
fn dl_pdsch_shape(short: bool) -> (usize, usize, Vec<usize>) {
    if short {
        (2, 6, vec![2, 7])
    } else {
        (2, 12, vec![2, 7, 11])
    }
}

/// The pure per-layout PDSCH work: extract at one (CDM-groups, time-first) layout,
/// descramble, and standalone-LDPC-decode at the DCI's RV. No shared state — safe to run
/// layouts (and fallback allocation guesses) in parallel on the rayon pool. Returns the
/// descrambled LLRs + TBS (for the caller's HARQ combining) and the TB when CRC passes.
#[allow(clippy::too_many_arguments)]
fn pdsch_standalone(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize + Copy + Sync,
    cell_id: u16,
    slot_idx: u32,
    crnti: u16,
    rb_start: usize,
    n_rb: usize,
    qm: usize,
    r: f64,
    rv: u8,
    cdm: usize,
    time_first: bool,
    short: bool,
) -> (Vec<f32>, usize, Option<Vec<u8>>) {
    use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
    let (sym_start, n_sym, dmrs) = dl_pdsch_shape(short);
    // REs: data symbols get all 12 subcarriers; with a single CDM group the DM-RS symbols
    // also carry data on their 6 non-DM-RS subcarriers.
    let n_re = n_rb * ((n_sym - dmrs.len()) * 12 + if cdm == 1 { dmrs.len() * 6 } else { 0 });
    let tbs = tbs_from_nre(n_re, r, qm);
    let alloc = PdschAlloc { rb_start, n_rb, sym_start, n_sym, dmrs_symbols: dmrs, qm, n_bwp: 0, nof_cdm_groups: cdm };
    let px = extract_pdsch(grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, time_first);
    let mut llr = px.llrs;
    descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
    // Standalone decode at the DCI's RV (rv=0 hardcoded would make retransmissions undecodable).
    // max_iter 10 (was 40): the LDPC early-exits on success (1-3 iters on this clean channel),
    // so max_iter is only ever burned in full by decodes that CANNOT succeed (wrong layout/RV/
    // TBS guess). At 40, those failures cost ~4× more, and during a retx flood (a PDSCH in
    // every slot) they push the per-job wall past the 500µs slot — the pipeline backs up
    // 10-70 slots, every HARQ-ACK misses its k1 window, and the flood feeds itself.
    let (bits, _c, crc) = dlsch_decode_single_bits(&llr, tbs, r, qm, rv, 10);
    let tb = crc.then(|| pack_bits(&bits));
    (llr, tbs, tb)
}

/// Decode one DL PDSCH into its transport block. `rv`/`h_id` come from the DCI
/// (0xff `h_id` = fallback guess, no combining). On top of a standalone decode at the
/// correct RV, HARQ soft-combining accumulates each (re)transmission's circular-buffer
/// LLRs into `harq_dl[h_id]` and decodes the sum, recovering TBs that no single
/// (re)transmission could. `lock` pins the cell-fixed DM-RS layout (CDM groups,
/// time-first) after the first success so combining uses a consistent extraction.
#[allow(clippy::too_many_arguments)]
fn try_decode_dl_srb1(
    grids: &[Vec<Complex32>],
    sc_to_bin: impl Fn(i32) -> usize + Copy + Sync,
    cell_id: u16,
    slot_idx: u32,
    crnti: u16,
    rb_start: usize,
    n_rb: usize,
    mcs: u8,
    rv: u8,
    h_id: u8,
    short: bool,
    lock: &mut Option<(usize, bool)>,
    harq_dl: &mut std::collections::HashMap<u8, HarqDl>,
) -> Option<(Vec<u8>, bool)> {
    let (qm, r) = mcs_params(mcs);
    let (qm, r) = (qm as usize, r);
    use ferrite_phy::coding::dlsch::{dlsch_cb_llr, dlsch_decode_cb};
    use rayon::prelude::*;
    // The time-first RE-mapping ORDER is cell-fixed — lock it after the first success and
    // skip the wrong order every slot thereafter (halves the extract+LDPC work, the dominant
    // PDSCH-decode cost). The CDM-group count, though, varies per grant (small grants use 1,
    // larger ones like RRCReconfiguration use 2), so still sweep both CDM values.
    let layouts: Vec<(usize, bool)> = [(1usize, true), (1, false), (2, true), (2, false)]
        .into_iter()
        .filter(|&(_, tf)| lock.map_or(true, |(_, ltf)| tf == ltf))
        .collect();
    // The per-layout work (extract + descramble + standalone LDPC at the DCI's RV) is pure —
    // run the layouts in parallel (the dominant PDSCH-decode cost, so this halves the worker's
    // per-slot wall time with a lock, quarters it without). The decision + HARQ-combining logic
    // below stays sequential in the original layout order, so behavior is unchanged.
    let results: Vec<(usize, bool, Vec<f32>, usize, Option<Vec<u8>>)> = layouts
        .par_iter()
        .map(|&(cdm, time_first)| {
            let (llr, tbs, tb) = pdsch_standalone(grids, sc_to_bin, cell_id, slot_idx, crnti, rb_start, n_rb, qm, r, rv, cdm, time_first, short);
            (cdm, time_first, llr, tbs, tb)
        })
        .collect();
    for (cdm, time_first, llr, tbs, tb) in results {
        if let Some(tb) = tb {
            // A recognizable PDU (DRB IP / SRB1 RRC): the right layout — lock it, deliver
            // it up the stack, and HARQ-ACK it.
            if plausible_dl_tb(&tb) {
                *lock = Some((cdm, time_first));
                harq_dl.remove(&h_id); // HARQ process delivered
                return Some((tb, true));
            }
            // A faithful CRC-pass on the KNOWN-GOOD (locked) layout whose content we don't
            // deliver up the stack (a MAC CE like the Timing Advance Command, or a
            // padding-only PDU). HARQ-ACK is a PHY-layer acknowledgement of TB reception
            // (CRC), NOT a statement that the MAC found the content useful — so this MUST
            // still be ACKed, else the gNB sees DTX and retransmits it forever (the ~90%
            // DTX / retx-flood that was starving the DRB). Return ack-only (deliver=false).
            if *lock == Some((cdm, time_first)) {
                harq_dl.remove(&h_id);
                return Some((tb, false));
            }
            continue;
        }
        // HARQ soft-combining: accumulate this RV's circular buffer into the per-process
        // buffer and decode the running sum. Only for the locked (cell-fixed) layout, a
        // real HARQ process, and a single-CB block (cb empty ⇒ multi-CB, skip). rv==0
        // starts a new TB, so reset the buffer.
        if h_id != 0xff && *lock == Some((cdm, time_first)) {
            let cb = dlsch_cb_llr(&llr, tbs, r, qm, rv);
            if cb.is_empty() {
                continue;
            }
            let e = harq_dl.entry(h_id).or_insert_with(|| HarqDl { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 });
            if e.tbs != tbs || e.qm != qm || e.acc.len() != cb.len() || rv == 0 {
                *e = HarqDl { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 };
            }
            for (a, &c) in e.acc.iter_mut().zip(&cb) {
                *a += c;
            }
            e.n_rx += 1;
            // Only worth an LDPC pass once ≥2 (re)transmissions have accumulated.
            if e.n_rx >= 2 {
                let (cbits, _c, ccrc) = dlsch_decode_cb(&e.acc, tbs, r, 10);
                if ccrc {
                    // Combining only runs on the locked layout, so a CRC-pass here is
                    // faithful: ACK it always; deliver only if it's a recognizable PDU.
                    let tb = pack_bits(&cbits);
                    let deliver = plausible_dl_tb(&tb);
                    harq_dl.remove(&h_id);
                    return Some((tb, deliver));
                }
            }
        }
    }
    None
}

/// A DL PDSCH decoded (CRC OK) in a connected-mode slot: the transport block plus the
/// HARQ-ACK timing (`k1` slots ahead, `dai` C-DAI). `k1 == 0xff` ⇒ a fallback (no-DCI)
/// decode that must not be ACKed. `deliver` is false when the TB was correctly received
/// but carries only content the stack doesn't consume (a MAC CE / padding) — it is still
/// HARQ-ACKed (CRC OK) but not handed up.
struct DlDecoded {
    k1: u8,
    dai: u8,
    bytes: Vec<u8>,
    deliver: bool,
}

/// One connected DL slot handed to the RX-PHY worker thread: the frequency-shifted
/// slot samples plus the timing context needed to demodulate and to place the ACK.
struct DlJob {
    slot_idx: u32,
    slot_start_ul: i64,
    crnti: u16,
    fsh: Vec<Complex32>,
}

/// The worker's decode of one slot, returned to the timeline thread: the transport
/// block (if any), the measured CQI, echoed with the slot's timing so the stack can
/// place the HARQ-ACK relative to the DECODED slot.
struct DlResult {
    slot_idx: u32,
    slot_start_ul: i64,
    decoded: Option<DlDecoded>,
    cqi: Option<u8>,
}

/// A UL waveform-build request handed from the timeline thread (T0) to the TX-build stage,
/// which modulates it and pushes the samples to the [`InjectionTable`] at `pos`. Moving the
/// (expensive, bursty) PUCCH/PUSCH modulation off T0 keeps its per-slot drain light so a burst
/// of decoded results can't stall the decode→ACK pipeline. `now` is T0's serving-position
/// snapshot for the injection deadline check.
enum TxReq {
    /// PUCCH Format 1: `harq` picks the HARQ-ACK resource (bits = ACK codebook) vs the SR
    /// resource (bits empty = positive SR).
    PucchF1 { harq: bool, bits: Vec<u8>, slot_mod20: u32, pos: i64, now: i64 },
    /// PUCCH Format 2: a CSI (wideband CQI) report.
    PucchF2 { cfg: ferrite_phy::pucch::PucchF2, bits: Vec<u8>, slot_mod20: u32, pos: i64, now: i64 },
    /// PUSCH (+ optional multiplexed UCI HARQ-ACK).
    Pusch {
        ulsch: Vec<u8>, alloc: PuschAlloc, slot_mod20: u32, slot_parity: usize, crnti: u16,
        ack: Vec<u8>, beta: f32, tb_bits: usize, pos: i64, now: i64,
    },
}

/// [perf] Nanoseconds per phase of `decode_dl`, summed across slots; drained by the RX-PHY
/// worker each report. DEMOD = OFDM (CORESET + full slot), DCI = the blind PDCCH search
/// (fixed cost, data-rate-independent), PDSCH = present-gate + PDSCH/LDPC decode.
static PERF_DEMOD_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PERF_DCI_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PERF_PDSCH_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Pure RX-PHY decode of one connected-mode DL slot — the CPU-heavy work the concurrency
/// rework (Phase 2) moves off the timeline thread. Demodulates the frequency-shifted slot
/// `fsh`, blind-decodes the DCI (1_0 in CORESET0, else the exhaustive CORESET1 search),
/// measures the NZP-CSI-RS, and decodes the granted PDSCH with HARQ soft-combining.
/// Returns the first plausible transport block (≤1 PDSCH/slot for us) and the measured
/// wideband CQI. `harq_dl`/`dl_dmrs_lock` are the only cross-slot state and so must be
/// owned by a single ordered caller. Behaviour matches the previous inline decode exactly.
#[allow(clippy::too_many_arguments)]
fn decode_dl(
    fsh: &[Complex32],
    ofdm: &Ofdm,
    coreset: &Coreset0,
    cell_id: u16,
    carrier_rb: usize,
    sc_to_bin: impl Fn(i32) -> usize + Copy + Sync,
    a_len: usize,
    ra_cand: &Candidate,
    crnti: u16,
    slot_idx: u32,
    harq_dl: &mut std::collections::HashMap<u8, HarqDl>,
    dl_dmrs_lock: &mut Option<(usize, bool)>,
    backlog: bool,
) -> (Option<DlDecoded>, Option<u8>) {
    let fft = ofdm.fft_size();
    // CORESET grids: the first coreset.n_symb OFDM symbols of the slot.
    let t_demod = std::time::Instant::now();
    let mut cgrids = Vec::new();
    let mut off = 0usize;
    for l in 0..coreset.n_symb {
        let cp = ofdm.cp_len((slot_idx as usize % 2) * 14 + l, 1);
        cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
        off += cp + fft;
    }
    PERF_DEMOD_NS.fetch_add(t_demod.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    let t_dci = std::time::Instant::now();
    let bits5 = |b: &[u8], lo: usize, n: usize| b[lo..lo + n].iter().fold(0u8, |a, &x| a << 1 | x);
    // (rb_start, n_rb, MCS, k1 (0xff = don't ACK), C-DAI, RV, HARQ id (0xff = fallback),
    //  short time allocation — the DCI's 1-bit TDRA row: false = symb [2,14), true = [2,8)).
    let mut allocs: Vec<(usize, usize, u8, u8, u8, u8, u8, bool)> = Vec::new();
    // PRIMARY: DCI 1_0 in CORESET0 (common SS, AL4 CCE0), reliable — same path as the RAR.
    // Always the full [2,14) allocation (its 4-bit default-table TDRA row 0 in this cell).
    {
        let mut m = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), coreset, cell_id, slot_idx, ra_cand);
        pdcch_descramble_llr(&mut m, u32::from(cell_id));
        if let Some(b) = dci_decode(&m, crnti, a_len).filter(|b| b[0] == 1) {
            let riv = b[1..10].iter().fold(0usize, |a, &x| a << 1 | x as usize);
            let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
            allocs.push((rb0, nrb, bits5(&b, 15, 5), bits5(&b, 34, 3) + 1, bits5(&b, 27, 2), bits5(&b, 21, 2), bits5(&b, 23, 4), false));
        }
    }
    // SECONDARY: DCI 1_1 in the CORESET1 USS (DRB DL) — exhaustive blind decode off one
    // cached channel estimate; only when no DCI 1_0 decoded (≤1 PDSCH/slot for us).
    if allocs.is_empty() {
        use rayon::prelude::*;
        let h_reg = estimate_coreset_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, coreset.n_symb, cell_id, slot_idx);
        // Coherence-gate first (cheap; most of the 15 candidates carry no PDCCH), then
        // blind-decode the survivors in parallel — each equalize + polar decode is pure, and a
        // CRC pass (RNTI-masked) is genuine whichever candidate finds it first.
        let cands: Vec<Candidate> = all_candidates(coreset.n_cce(), &[1, 2, 4, 8])
            .into_iter()
            .filter(|cand| coreset_candidate_coherence(&h_reg, cand, coreset.n_symb) >= 0.5)
            .collect();
        if let Some(b) = cands.par_iter().find_map_any(|cand| {
            let mut mm = equalize_candidate_c1_cached(&cgrids, |sc: usize| sc_to_bin(sc as i32), coreset.n_symb, cand, &h_reg);
            pdcch_descramble_llr(&mut mm, u32::from(cell_id));
            dci_decode(&mm, crnti, 40).filter(|b| b[0] == 1)
        }) {
            const K1: [u8; 8] = [4, 5, 6, 7, 8, 9, 11, 12];
            let riv = b[1..10].iter().fold(0usize, |a, &x| a << 1 | x as usize);
            let (rb0, nrb) = riv_decode(riv, carrier_rb);
            // b[10] = the 1-bit TDRA (2-row list): row 1 is the short [2,8) allocation the
            // scheduler uses for the TDD special slot AND for every HARQ retransmission of a
            // TB first sent there (retx keep the TBS ⇒ keep the time allocation, in any slot).
            allocs.push((rb0, nrb, bits5(&b, 11, 5), K1[(bits5(&b, 30, 3) & 7) as usize], bits5(&b, 23, 2), bits5(&b, 17, 2), bits5(&b, 19, 4), b[10] == 1));
        }
    }
    // Fallback (no DCI decoded): brute-force rb[0,N) x MCS 0-2 (CRC + plausibility reject
    // wrong guesses). OFF by default (opt-in via FERRITE_FB=1, pre-layout-lock + no-backlog
    // gated): the DCI 1_0/1_1 paths now cover every connected DL PDSCH including the AuthReq
    // this sweep was written for, a missed DCI is harmless (the gNB retransmits WITH a fresh
    // DCI), and the sweep can't even be ACKed (k1 unknown ⇒ 0xff) — while being the worker's
    // multi-ms worst case: one spike during a retx burst fills the job queue, drops the next
    // rv=0 slots, and self-feeds a retx storm (measured: 4-5ms job → 20-40 slots of decode
    // lag → 96% of HARQ-ACKs miss their k1 window → registration times out).
    if allocs.is_empty() && !backlog && dl_dmrs_lock.is_none() && std::env::var_os("FERRITE_FB").is_some() {
        for &nrb in &[2usize, 5, 13, 17, 18, 24] {
            for mcs in [0u8, 1, 2] {
                allocs.push((0, nrb, mcs, 0xff, 0, 0, 0xff, false));
            }
        }
    }
    PERF_DCI_NS.fetch_add(t_dci.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    let t_ds = std::time::Instant::now();
    let grids = demod_slot(ofdm, fsh, 0, slot_idx as usize % 2, 1);
    PERF_DEMOD_NS.fetch_add(t_ds.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    let Some(grids) = grids else {
        return (None, None);
    };
    let t_pdsch = std::time::Instant::now();
    // NZP-CSI-RS measurement (row 1, k0=1, symbol 4) → wideband CQI, only in the even-frame
    // slots 2-4 where the CSI-RS is present (a high SINR gates it, no SFN tracking needed).
    let mut cqi = None;
    if matches!(slot_idx, 2..=4) {
        let sinr = ferrite_phy::csi::measure_csi_rs_sinr(&grids[4], |sc: usize| sc_to_bin(sc as i32), cell_id, slot_idx, 4, carrier_rb, 1);
        if sinr > 15.0 {
            cqi = Some(ferrite_phy::csi::sinr_to_cqi(sinr));
        }
    }
    // Cheap presence gate: every connected DL PDSCH starts at RB 0. Probe with the DM-RS
    // symbols COMMON to both time allocations ({2,7} — the [2,8) shape's full set, a subset
    // of [2,14)'s {2,7,11}) so a short PDSCH in any slot still passes.
    let present = extract_pdsch(&grids, sc_to_bin, &PdschAlloc { rb_start: 0, n_rb: 2, sym_start: 2, n_sym: 6, dmrs_symbols: vec![2, 7], qm: 2, n_bwp: 0, nof_cdm_groups: 1 }, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric > 0.9;
    if !present {
        PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        return (None, cqi);
    }
    if allocs.len() == 1 {
        // Steady state (a DCI decoded): one allocation — probe, then decode with the layout
        // sweep parallelized inside try_decode_dl_srb1 (HARQ combining included).
        let (rb0, nrb, mcs, k1, dai, rv, h_id, short) = allocs[0];
        let (qm, _) = mcs_params(mcs);
        let (p_start, p_nsym, p_dmrs) = dl_pdsch_shape(short);
        let probe = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: p_start, n_sym: p_nsym, dmrs_symbols: p_dmrs, qm: qm as usize, n_bwp: 0, nof_cdm_groups: 1 };
        if extract_pdsch(&grids, sc_to_bin, &probe, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric > 0.9 {
            if let Some((tb, deliver)) = try_decode_dl_srb1(&grids, sc_to_bin, cell_id, slot_idx, crnti, rb0, nrb, mcs, rv, h_id, short, dl_dmrs_lock, harq_dl) {
                PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                return (Some(DlDecoded { k1, dai, bytes: tb, deliver }), cqi);
            }
        }
    } else {
        // Fallback (no DCI decoded): brute-force guesses, h_id=0xff ⇒ no HARQ combining, so the
        // whole (guess × layout) grid is pure — flat-parallel sweep, first hit in guess order
        // wins (this was the worker's multi-ms spike: up to 18 probes + serial LDPC passes).
        use rayon::prelude::*;
        let lock0 = *dl_dmrs_lock;
        let layouts: Vec<(usize, bool)> = [(1usize, true), (1, false), (2, true), (2, false)]
            .into_iter()
            .filter(|&(_, tf)| lock0.map_or(true, |(_, ltf)| tf == ltf))
            .collect();
        let items: Vec<(usize, usize, u8, usize, bool)> = allocs
            .iter()
            .flat_map(|&(rb0, nrb, mcs, ..)| layouts.iter().map(move |&(cdm, tf)| (rb0, nrb, mcs, cdm, tf)))
            .collect();
        let hit = items.par_iter().find_map_first(|&(rb0, nrb, mcs, cdm, tf)| {
            let (qm, r) = mcs_params(mcs);
            // Fallback guesses are pre-lock first transmissions: the long [2,14) shape.
            let probe = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0, nof_cdm_groups: 1 };
            if extract_pdsch(&grids, sc_to_bin, &probe, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric <= 0.9 {
                return None;
            }
            let (_llr, _tbs, tb) = pdsch_standalone(&grids, sc_to_bin, cell_id, slot_idx, crnti, rb0, nrb, qm as usize, r, 0, cdm, tf, false);
            let tb = tb?;
            if plausible_dl_tb(&tb) {
                return Some((tb, true, Some((cdm, tf))));
            }
            if lock0 == Some((cdm, tf)) {
                return Some((tb, false, None));
            }
            None
        });
        if let Some((tb, deliver, newlock)) = hit {
            if let Some(nl) = newlock {
                *dl_dmrs_lock = Some(nl);
            }
            PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            return (Some(DlDecoded { k1: 0xff, dai: 0, bytes: tb, deliver }), cqi);
        }
    }
    PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    (None, cqi)
}

/// Pin the current thread to `cpu` and give it real-time SCHED_FIFO priority, so other
/// processes / OS jitter can't preempt the timeline and decode threads and spike the
/// decode→ACK pipeline lag (which makes HARQ-ACKs miss their UL injection window). This
/// is the difference between holding a 500 µs slot period and drifting under load.
/// Best-effort: needs CAP_SYS_NICE (run as root); logs and continues on failure. Opt-in
/// via `FERRITE_RT=1` so a normal run is unaffected.
fn set_rt_thread(cpu: usize, prio: i32, name: &str) {
    if std::env::var_os("FERRITE_RT").is_none() {
        return;
    }
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        let param = libc::sched_param { sched_priority: prio };
        if libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) != 0 {
            eprintln!("[rt] {name}: SCHED_FIFO(prio {prio}) failed — run as root for CAP_SYS_NICE");
        } else {
            eprintln!("[rt] {name}: cpu {cpu}, SCHED_FIFO prio {prio}");
        }
    }
}

fn main() {
    run(Config::from_args());
}

fn run(cfg: Config) {
    let Config {
        tx, rx, fs, center_hz, preamble, amp, sweep0, msg3_delay, fshift,
        toff_lo, toff_hi, toff_step, imsi, ki, opc, snn, ue_ip, ping_target,
        tun, netns, tun_mtu,
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
                 acks: &[(i64, Vec<Complex32>)],
                 uls: &[(i64, Vec<Complex32>)]| {
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
                // Pending PUSCH bursts (a queue: fill EVERY UL grant the gNB gives,
                // else the unfilled grants decode as noise → the gNB collapses UL MCS).
                for (pos, wave) in uls {
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[], &[]);
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
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[], &[]);
        to_skip -= block_len;
    }
    if to_skip > 0 {
        fill_dl(&mut dl, &mut blk[..to_skip]);
        serve(&mut ul, &mut ul_counter, i64::MAX / 2, &[], &[], &[]);
    }

    // Hand the DL socket to a dedicated drain thread and read it read-ahead from here on.
    // In the ZMQ lockstep the gNB's DU runs on wall-clock and stalls (error-spirals) if its
    // TX buffer backs up — which is exactly what happens when the timeline thread pauses on
    // the UL-serve or a decode burst and stops reading DL. Draining continuously in the
    // background keeps the gNB producing smoothly, absorbing the per-slot jitter (the srsUE
    // radio↔PHY decoupling that lets it hold ~520µs where the tight read→process→serve loop
    // collapses). The gNB's ~1ms TX lead caps the buffer depth, so it stays bounded.
    let mut dl_stream = BufferedStream::spawn(dl, block_len);

    let blocks_per_slot = slot_len as usize / block_len; // 4
    let align_ul = ul_counter as i64; // first frame-boundary UL position
    let mut offset: i64 = 0;
    let mut frames_at_offset = 0i64;
    let mut sweep = sweep0;

    // ── Decoupled, real-time-paced radio thread ──────────────────────────────────────────
    // Move the ZmqSink onto its own thread so T0 (this loop) never stalls on the gNB's UL pull.
    // The thread serves UL from a position-keyed InjectionTable (filled by T0 via `inj`) plus the
    // periodic PRACH (shared `prach_base`, MAX/2 once connected), and PACES the serving to real
    // time (μ=1 → slot_len samples per 500µs). The pace is the crucial bit: without it the gNB
    // free-runs its scheduler faster than it can fill DL grants (~395µs → empty grants → decode
    // collapse). Pacing the UL caps the gNB's DL to ~rx_to_tx_max_delay ahead of real time — the
    // same operating point srsUE holds (~521µs). T0 publishes the serving position in `ul_pos`
    // for its own deadline checks.
    let ul_pos = Arc::new(AtomicI64::new(align_ul));
    // T0's downlink slot position, published each iteration. The radio thread gates its UL serve
    // to stay within `lead` slots of this: a T0 stall then stalls the serve too (bounding the DL
    // buffer), so T0's slot clock can't drift hundreds of slots behind the serving position and
    // mis-place every UL waveform — but the serve I/O still stays off T0's critical path.
    let t0_pos = Arc::new(AtomicI64::new(align_ul));
    let prach_base = Arc::new(AtomicI64::new(align_ul + occ_off + offset));
    let inj: Arc<Mutex<InjectionTable>> = Arc::new(Mutex::new(InjectionTable::new()));
    {
        let (ul_pos_t, t0_pos_t, prach_base_t, inj_t) = (ul_pos.clone(), t0_pos.clone(), prach_base.clone(), inj.clone());
        let prach = prach.clone();
        let frame_len_i = frame_len as i64;
        // How many slots the UL serve may run ahead of T0's DL consumption. Every slot of lead
        // eats directly into the k1=4 HARQ-ACK budget (an ACK produced at T0 must land at a
        // position the radio hasn't served yet), so default 0: serving trails T0 by up to a
        // block, the gNB's rx_to_tx window still keeps ~1 slot of DL buffered ahead of T0, and
        // the ACK margin is ~k1-2.5 slots. (2 completes the attach too but leaves <1 slot of
        // ACK margin — ping collapses on any decode jitter.)
        let lead: i64 = std::env::var("FERRITE_LEAD").ok().and_then(|v| v.parse().ok()).unwrap_or(0) * slot_len;
        // Wall-clock µs/slot the serve paces to (default 500 = real time). Caps the gNB's rate so
        // its scheduler doesn't free-run past what it can fill (empty grants → decode collapse).
        let pace_us: f64 = std::env::var("FERRITE_PACE_US").ok().and_then(|v| v.parse().ok()).unwrap_or(500.0);
        let pace_ratio = pace_us / 500.0;
        std::thread::Builder::new().name("ferrite-radio".into()).spawn(move || {
            set_rt_thread(4, 25, "radio");
            let start = std::time::Instant::now();
            let mut c = align_ul as u64;
            loop {
                // Gate: don't serve a block T0 hasn't reached yet (+lead). This paces the gNB to
                // T0's DL consumption and keeps the buffer bounded, without T0 doing the serve.
                while c as i64 > t0_pos_t.load(Rlx) + lead {
                    std::thread::sleep(std::time::Duration::from_micros(20));
                }
                // Pace: never serve faster than the target rate (caps the gNB to ~real time).
                let served = (c as i64 - align_ul).max(0) as f64;
                let target = std::time::Duration::from_secs_f64(served / fs * pace_ratio);
                let el = start.elapsed();
                if el < target {
                    std::thread::sleep(target - el);
                }
                let ok = ul
                    .serve_with(&mut c, |cc, block| {
                        let (cc, bl) = (cc as i64, block.len() as i64);
                        let base = prach_base_t.load(Rlx);
                        if base < i64::MAX / 4 {
                            let k0 = ((cc - prach_len - base).div_euclid(frame_len_i)).max(0);
                            for kk in k0..=k0 + 1 {
                                let o = base + kk * frame_len_i;
                                for i in 0..prach_len {
                                    let abs = o + i;
                                    if abs >= cc && abs < cc + bl {
                                        block[(abs - cc) as usize] = prach[i as usize];
                                    }
                                }
                            }
                        }
                        inj_t.lock().unwrap().fill(cc, block);
                    })
                    .expect("ul serve");
                if ok {
                    ul_pos_t.store(c as i64, Rlx);
                }
            }
        })
        .expect("spawn radio thread");
    }
    // T0's slot clock in the UL sample frame (advances one slot per loop iteration, matching the
    // gNB's slot rate since T0 reads DL at that rate from the buffer).
    let mut slot_start_ul_t0 = align_ul;

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
    // These track only the UL *position* of in-flight bursts (modulated on the TX-build thread,
    // served by the InjectionTable); T0 keeps them for the arm-once gate + a queue-depth cap.
    let mut pend_sr: Option<i64> = None;
    let mut pend_csi: Option<i64> = None; // pending CSI report (PUCCH F2)
    let mut pend_acks: Vec<i64> = Vec::new(); // in-flight DL HARQ-ACKs
    // Latest CQI measured from the NZP-CSI-RS (row 1, k0=1, symbol 4). Set only when a
    // valid CSI-RS is seen (high SINR); the CSI-RS is transmitted in even frames slots
    // 2-4, so this is Some exactly in the frames whose slot-8 report the gNB reads —
    // which is why gating the report on it needs no SFN tracking.
    let mut pending_cqi: Option<u8> = None;
    // Dynamic HARQ-ACK codebook: accumulate per UL-slot ACK bits keyed by their UL
    // sample position; each entry holds (slot-in-frame, [ACK bit per C-DAI 0..3]).
    // Several DL PDSCHs (e.g. the two segments of one DL SDU) map to the SAME UL slot
    // and must be bundled into one 1-2 bit PUCCH, ordered by DAI — else the gNB (which
    // expects harq_bit_len bits) can't read the ACK and stalls the DL HARQ.
    let mut ack_book: std::collections::HashMap<i64, (u32, [Option<u8>; 4])> = std::collections::HashMap::new();
    // A UL grant decoded this slot, modulated only AFTER the DL decode so a HARQ-ACK
    // whose UL slot coincides with this PUSCH can be multiplexed onto it (UCI-on-PUSCH)
    // instead of a PUCCH: (UL pos, PUSCH slot, rate-matched UL-SCH, alloc, TB bits).
    let mut pending_pusch: Option<(i64, i64, Vec<u8>, PuschAlloc, usize)> = None;
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

    // ── TX-build thread ──────────────────────────────────────────────────────────────────
    // Modulate the connected-mode UL (PUCCH SR/ACK/CSI, PUSCH) off T0 and push the samples to
    // the InjectionTable. The modulation is the heavy, bursty part of T0's per-slot drain
    // (a burst of decoded results → a burst of ACKs/PUSCH to modulate → 1.7ms spike → stalls
    // the decode→ACK pipeline → late ACKs). T0 now just decides WHAT to send (cheap) and hands
    // a `TxReq` here; this thread modulates and injects at the absolute position T0 computed.
    let (tx_req_tx, tx_req_rx) = ferrite_ue::rt::bounded::<TxReq>(64);
    {
        let inj_t = inj.clone();
        let (harq_cfg_t, sr_cfg_t) = (harq_cfg.clone(), sr_cfg.clone());
        let cell_id = acq.cell_id;
        std::thread::Builder::new().name("ferrite-txbuild".into()).spawn(move || {
            set_rt_thread(5, 15, "txbuild");
            let ofdm = Ofdm::new(fft);
            let norm = |w: &mut Vec<Complex32>| {
                let pk = w.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                for s in w.iter_mut() { *s *= amp / pk; }
            };
            while let Ok(req) = tx_req_rx.recv() {
                let (mut wave, pos, now) = match req {
                    TxReq::PucchF1 { harq, bits, slot_mod20, pos, now } => {
                        let cfg = if harq { &harq_cfg_t } else { &sr_cfg_t };
                        (ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, cfg, &bits, slot_mod20, center_hz, fs), pos, now)
                    }
                    TxReq::PucchF2 { cfg, bits, slot_mod20, pos, now } => {
                        (ferrite_phy::pucch::pucch_f2_modulate_slot(&ofdm, &cfg, &bits, slot_mod20, center_hz, fs), pos, now)
                    }
                    TxReq::Pusch { ulsch, alloc, slot_mod20, slot_parity, crnti, ack, beta, tb_bits, pos, now } => {
                        (ferrite_phy::pusch::pusch_modulate_slot_uci(&ofdm, &ulsch, &alloc, cell_id, slot_mod20, slot_parity, crnti, center_hz, fs, &ack, beta, tb_bits), pos, now)
                    }
                };
                norm(&mut wave);
                inj_t.lock().unwrap().push(ReadyWaveform { pos, samples: wave }, now);
            }
        }).expect("spawn txbuild thread");
    }

    // Once contention resolution is won, drive the connected UE: send an SR to
    // request a grant for Msg5 (RRCSetupComplete). Stop new RA once connected.
    let mut connected: Option<u16> = None;
    let mut pend_ul: Vec<i64> = Vec::new(); // in-flight PUSCH burst positions (fill every grant)
    // Connected-mode UL: a queue of RRC PDUs to send on successive grants
    // (RRCSetupComplete, then the AuthenticationResponse, …), with a shared
    // SRB1 RLC/PDCP sequence number that increments per PDU.
    let mut ul_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut srb1_sn: u16 = 0;
    // NAS registration state machine: each DL NAS message queues a UL reply.
    let mut auth_done = false; // AuthenticationResponse queued
    let mut smc_done = false; // SecurityModeComplete queued
    let mut as_sec_done = false; // RRC securityModeComplete queued (AS security)
    let mut cap_done = false; // UECapabilityInformation queued
    let mut recfg_done = false; // rrcReconfigurationComplete queued
    let mut k_amf_st: Option<[u8; 32]> = None; // K_AMF, for K_gNB derivation
    let mut k_rrcint: Option<[u8; 16]> = None; // 128-NIA2 RRC integrity key (AS)
    let mut reg_done = false; // RegistrationComplete queued
    const PDU_SESSION_ID: u8 = 5; // UE-chosen PDU session identity
    let mut nas_ul_count: u32 = 0; // NAS COUNT for uplink integrity protection
    let mut k_nasint: Option<[u8; 16]> = None; // 128-NIA2 key, derived after AKA
    let mut dl_rlc_next: u16 = 0; // next expected DL RLC SN (for RLC STATUS ACK)
    let mut pending_status: Option<u16> = None; // ACK_SN to report so the gNB DL advances
    let mut srb1_reasm = RlcReassembler::new(); // reassembles segmented DL SRB1 SDUs
    // User plane (DRB 1 / LCID 4): once the DRB is up, send ICMP echo requests and
    // watch the DL for the reply. `ue_ip` = the address the PDU session assigned us.
    let mut drb_up = false; // RRCReconfiguration (DRB) applied
    let mut ue_ip = ue_ip; // assigned IP: from --ue-ip, else the PDU Session Accept
    let mut ping_seq: u16 = 0; // ICMP echo sequence number
    let mut pdcp_tx_sn: u32 = 0; // DRB uplink PDCP SN
    let mut ping_acked = false; // an echo reply was received
    let mut drb_reasm = ferrite_ue::userplane::RlcUmReassembler::new();
    const PING_ID: u16 = 0xfe11;
    // TUN mode: shuttle real host IP packets over the DRB. `tun_ul` queues packets
    // read from the TUN; `um_tx` is the SDU currently being segmented onto grants.
    let mut tun_fd: Option<File> = None;
    let mut tun_ul: VecDeque<Vec<u8>> = VecDeque::new();
    let mut um_tx: Option<(Vec<u8>, usize, u16)> = None; // (PDCP PDU, bytes sent, UM SN)
    let mut um_sn: u16 = 0;
    let mut dl_seen: VecDeque<u32> = VecDeque::new(); // recent DL PDCP SNs (drop HARQ dup)
    // DL RX-PHY decode runs on a WORKER thread (Phase 2): the timeline loop offloads each
    // connected DL slot and picks up the result a few slots later (k1 >= 4 covers the
    // pipeline latency), so the heavy LDPC + HARQ combining + blind DCI search no longer
    // stall the ZMQ I/O. The worker owns the only cross-slot decode state (the HARQ
    // soft-combining buffers `harq_dl` and the cell-fixed DM-RS layout `dl_dmrs_lock`) and
    // processes slots strictly in order, keeping the accumulator coherent.
    // Job queue depth 2 (was 8): the queue depth IS the decode→ACK pipeline lag bound
    // (lag ≈ (depth+1) × per-job wall). At 8, any transient spike fills the queue and the lag
    // sits at 8-10 slots — past the k1=4 ACK window — so every ACK is late, every TB is
    // retransmitted, and the flood keeps the queue full: a self-sustaining storm. At 2, a
    // burst drops the excess slots instead (the gNB retransmits them WITH a fresh DCI, and
    // those retx get decoded and ACKed on time) — the storm converges. Real-time triage:
    // decoding 80% of slots on time beats decoding 100% of them too late.
    let (dl_job_tx, dl_job_rx) = ferrite_ue::rt::bounded::<DlJob>(2);
    let (dl_res_tx, dl_res_rx) = ferrite_ue::rt::bounded::<DlResult>(8);
    {
        let (w_coreset, w_cell, w_carrier, w_alen, w_racand, w_firstsc) =
            (coreset, acq.cell_id, carrier_rb, a_len, ra_cand.clone(), first_sc);
        std::thread::Builder::new()
            .name("ferrite-rxphy".into())
            .spawn(move || {
                set_rt_thread(3, 20, "rxphy"); // dedicated core, below the timeline thread
                // Small dedicated rayon pool for the intra-slot parallelism (PDCCH candidates,
                // PDSCH layouts). NOT the global pool: its default (= all 16 cores) of spinning
                // workers oversubscribes the machine against T0/radio/gNB and slows everything
                // ~2× (measured: T0 freqshift 45→93µs, period 500→1069µs). 4 threads = the
                // pre-layout-lock sweep (4 (CDM, time-first) layouts) in ONE parallel batch —
                // the pre-lock slots are the attach-critical ones, where a slow job drops the
                // next slot, leaves a DAI gap in the ACK codebook, and corrupts the first
                // UCI-on-PUSCH (gNB reads more ACK bits than the UE mux'd → data REs shift →
                // CRC KO on the AuthenticationResponse).
                let pool = ferrite_ue::rt::rayon_pool(4);
                let ofdm = Ofdm::new(fft);
                let sc_to_bin = move |sc: i32| (w_firstsc + sc).rem_euclid(fft as i32) as usize;
                let mut harq_dl: std::collections::HashMap<u8, HarqDl> = std::collections::HashMap::new();
                let mut dl_dmrs_lock: Option<(usize, bool)> = None;
                // [perf] per-slot RX-PHY timing: decode_dl total vs its OFDM-demod (lower PHY).
                use std::sync::atomic::Ordering::Relaxed;
                let (mut w_n, mut w_decode_ns, mut w_ok) = (0u64, 0u64, 0u64);
                let (mut w_send_ns, mut w_wall_ns, mut w_max_ns) = (0u64, 0u64, 0u64);
                let mut w_last: Option<std::time::Instant> = None;
                let perf_on = std::env::var_os("FERRITE_PERF").is_some();
                while let Ok(job) = dl_job_rx.recv() {
                    // [perf] wall time between jobs (loop turnaround incl. recv wait) to find
                    // time lost outside decode_dl (send-block, allocator, scheduling).
                    let now = std::time::Instant::now();
                    if let Some(l) = w_last {
                        w_wall_ns += (now - l).as_nanos() as u64;
                    }
                    w_last = Some(now);
                    let DlJob { slot_idx, slot_start_ul, crnti, fsh } = job;
                    let t = std::time::Instant::now();
                    let backlog = !dl_job_rx.is_empty(); // jobs waiting → shed the opportunistic work
                    let (decoded, cqi) = pool.install(|| decode_dl(&fsh, &ofdm, &w_coreset, w_cell, w_carrier, sc_to_bin, w_alen, &w_racand, crnti, slot_idx, &mut harq_dl, &mut dl_dmrs_lock, backlog));
                    let job_ns = t.elapsed().as_nanos() as u64;
                    w_decode_ns += job_ns;
                    w_max_ns = w_max_ns.max(job_ns);
                    w_n += 1;
                    // [perf] one-shot: dump a granted-slot fsh so dl-bench can time the
                    // decode offline. Header: slot_idx, crnti (u32 LE) then f32 re/im pairs.
                    if decoded.as_ref().is_some_and(|d| d.k1 != 0xff) && std::env::var_os("FERRITE_DUMP_FSH").is_some() && !std::path::Path::new("/tmp/ferrite_fsh.bin").exists() {
                        let mut b = Vec::with_capacity(8 + fsh.len() * 8);
                        b.extend_from_slice(&slot_idx.to_le_bytes());
                        b.extend_from_slice(&(crnti as u32).to_le_bytes());
                        for s in &fsh { b.extend_from_slice(&s.re.to_le_bytes()); b.extend_from_slice(&s.im.to_le_bytes()); }
                        let _ = std::fs::write("/tmp/ferrite_fsh.bin", &b);
                        eprintln!("[dl-bench] dumped granted-slot fsh: slot={slot_idx} crnti={crnti:#x} len={}", fsh.len());
                    }
                    if decoded.as_ref().is_some_and(|d| d.k1 != 0xff) { w_ok += 1; }
                    if perf_on && w_n % 1000 == 0 {
                        let demod_ns = PERF_DEMOD_NS.swap(0, Relaxed);
                        let dci_ns = PERF_DCI_NS.swap(0, Relaxed);
                        let pdsch_ns = PERF_PDSCH_NS.swap(0, Relaxed);
                        let us = |ns: u64| ns as f64 / 1000.0 / 1e3;
                        eprintln!("[perf-ue-rxphy] {w_n} slots ({w_ok} CRC-OK): decode_dl {:.1} µs/slot (max {:.0}) = OFDM-demod {:.1} + DCI-blind-search {:.1} + PDSCH-decode {:.1}; loop-wall {:.1} send-block {:.1}",
                            us(w_decode_ns), w_max_ns as f64 / 1e3, us(demod_ns), us(dci_ns), us(pdsch_ns), us(w_wall_ns), us(w_send_ns));
                        w_decode_ns = 0; w_wall_ns = 0; w_send_ns = 0; w_max_ns = 0;
                    }
                    let t_send = std::time::Instant::now();
                    if dl_res_tx.send(DlResult { slot_idx, slot_start_ul, decoded, cqi }).is_err() {
                        break;
                    }
                    w_send_ns += t_send.elapsed().as_nanos() as u64;
                }
            })
            .expect("spawn rxphy worker");
    }
    // Msg5 payload: RRCSetupComplete carrying a NAS RegistrationRequest (SUCI).
    let rrc_sc = rrc_setup_complete(0, 1, &registration_request(&imsi));

    // The timeline thread is the hard-real-time pace-setter — give it the top priority and a
    // dedicated core so nothing preempts the read-DL / serve-UL loop.
    set_rt_thread(2, 30, "timeline");
    // [perf] T0 (timeline) per-slot wall-clock: total slot period (the achieved slot rate,
    // gated by the ZMQ lockstep), of which ZMQ I/O (the read+serve lockstep wait) and the
    // freq-shift+CORESET OFDM demod (T0's lower-PHY share).
    let (mut perf_last, mut perf_have_last) = (std::time::Instant::now(), false);
    let (mut perf_n, mut perf_period_ns, mut perf_io_ns, mut perf_demod_ns) = (0u64, 0u64, 0u64, 0u64);
    let (mut perf_fs_ns, mut perf_ulgrant_ns, mut perf_ra_ns, mut perf_drain_ns) = (0u64, 0u64, 0u64, 0u64);
    let mut perf_fill_ns = 0u64; // DL-read (fill_dl) wait — the lockstep round-trip to the gNB
    // [perf] HARQ-ACK injection outcomes (cumulative): total produced, "late" = target UL
    // position already behind ul_counter when produced (its block was already served → the
    // ACK can never be injected → gNB sees DTX), and "qfull" = dropped because pend_acks
    // was full. This is the UE-side deadline-miss counter the InjectionTable would track.
    let (mut ack_total, mut ack_late, mut ack_qfull) = (0u64, 0u64, 0u64);
    // [perf] decode→drain pipeline lag in slots (current slot − decoded slot when drained):
    // this is the depth the HARQ-ACK must beat (needs lag < k1). Sum/max/count per window.
    let (mut lag_sum, mut lag_max, mut lag_n) = (0u64, 0u64, 0u64);
    let (mut dlag_sum, mut dlag_max, mut dlag_n) = (0u64, 0u64, 0u64); // lag for DECODED drains only
    let mut job_drops = 0u64; // DL jobs dropped because the worker queue was full (worker behind)
    // [perf] instrumentation is off unless FERRITE_PERF is set (the per-slot timers run
    // cheaply either way; only the periodic stderr reports are gated).
    let perf_on = std::env::var_os("FERRITE_PERF").is_some();
    // [perf] optional pad-sleep per slot (µs) to test how T0 pace affects the ZMQ lockstep.
    let perf_pad_us: u64 = std::env::var("FERRITE_PAD_US").ok().and_then(|v| v.parse().ok()).unwrap_or(0);

    loop {
        if perf_pad_us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(perf_pad_us));
        }
        let perf_iter = std::time::Instant::now();
        if perf_have_last {
            perf_period_ns += (perf_iter - perf_last).as_nanos() as u64;
        }
        perf_last = perf_iter;
        perf_have_last = true;
        // T0's slot position in the UL frame (its own clock, advanced once per slot). The radio
        // thread serves UL asynchronously; `ul_counter` shadows the *serving* position (behind
        // T0) so the deadline/late checks measure against what's actually been sent.
        let slot_start_ul = slot_start_ul_t0;
        slot_start_ul_t0 += slot_len;
        t0_pos.store(slot_start_ul_t0, Rlx); // publish DL consumption for the radio's serve gate
        prach_base.store(if connected.is_some() { i64::MAX / 2 } else { align_ul + occ_off + offset }, Rlx);
        let ul_counter = ul_pos.load(Rlx) as u64;
        if std::env::var_os("FERRITE_DRIFT").is_some() && connected.is_some() && slot_idx % 5 == 0 {
            eprintln!("[drift] t0={slot_start_ul} serving={ul_counter} diff={}", slot_start_ul - ul_counter as i64);
        }
        // TUN mode: drain any IP packets the OS wants to send and queue them for
        // the DRB uplink (non-blocking; each read() returns one packet, IFF_NO_PI).
        if let Some(tun) = tun_fd.as_mut() {
            let mut buf = [0u8; 2048];
            for _ in 0..16 {
                match tun.read(&mut buf) {
                    Ok(n) if n > 0 => tun_ul.push_back(buf[..n].to_vec()),
                    _ => break, // WouldBlock or EOF
                }
            }
        }
        // Read one slot of DL, serving UL (PRACH + pending Msg3) in lockstep.
        // PRACH base = first frame boundary + occasion offset + sweep offset.
        let perf_io = std::time::Instant::now();
        for b in 0..blocks_per_slot {
            let perf_fill = std::time::Instant::now();
            dl_stream.read_exact(&mut blk).expect("dl stream ended");
            perf_fill_ns += perf_fill.elapsed().as_nanos() as u64;
            slot_buf[b * block_len..(b + 1) * block_len].copy_from_slice(&blk);
        }
        perf_io_ns += perf_io.elapsed().as_nanos() as u64;

        // Decode this slot's RA search space.
        let perf_fs = std::time::Instant::now();
        let fsh = freq_shift(&slot_buf, -df, fs, slot_start_ul as usize);
        perf_fs_ns += perf_fs.elapsed().as_nanos() as u64;
        let perf_dm = std::time::Instant::now();
        let mut cgrids = Vec::new();
        let mut off = 0usize;
        for l in 0..coreset.n_symb {
            let cp = ofdm.cp_len((slot_idx as usize % 2) * 14 + l, 1);
            cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
            off += cp + fft;
        }
        perf_demod_ns += perf_dm.elapsed().as_nanos() as u64;
        let perf_ulgrant = std::time::Instant::now();
        perf_n += 1;
        if perf_n % 1000 == 0 {
            if perf_on {
                let a = |ns: u64| ns as f64 / perf_n as f64 / 1e3; // µs/slot
                let p = perf_period_ns as f64 / perf_n as f64;
                eprintln!("[perf-ue-t0] {perf_n} slots: period {:.0}µs ({:.0}/s) = zmq-io {:.0} (fill-dl {:.0} + serve {:.0}) + freqshift {:.0} + coreset-demod {:.0} + ul-grant-pdcch {:.0} + ra-search {:.0} + drain+tx {:.0} µs",
                    p / 1e3, 1e9 / p, a(perf_io_ns), a(perf_fill_ns), a(perf_io_ns.saturating_sub(perf_fill_ns)), a(perf_fs_ns), a(perf_demod_ns), a(perf_ulgrant_ns), a(perf_ra_ns), a(perf_drain_ns));
                eprintln!("[perf-ue-ack] HARQ-ACK cumulative: produced={ack_total} late(missed-window)={ack_late} qfull-dropped={ack_qfull} job-drops={job_drops}; all-drain-lag avg={:.1} max={lag_max}; DECODED-drain-lag avg={:.1} max={dlag_max} ({dlag_n})",
                    lag_sum as f64 / lag_n.max(1) as f64, dlag_sum as f64 / dlag_n.max(1) as f64);
            }
            lag_sum = 0; lag_max = 0; lag_n = 0; dlag_sum = 0; dlag_max = 0; dlag_n = 0;
            perf_n = 0; perf_period_ns = 0; perf_io_ns = 0; perf_demod_ns = 0;
            perf_fs_ns = 0; perf_ulgrant_ns = 0; perf_ra_ns = 0; perf_drain_ns = 0; perf_fill_ns = 0;
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
            // Decode the UL grant EVERY slot and fill it: an unfilled grant decodes
            // as noise (crc=KO) and a burst of KOs makes the gNB collapse UL MCS (and
            // eventually trips "MAC max KOs" RLF). The gNB grants back-to-back to drain
            // a buffer, so keep a QUEUE of in-flight PUSCH bursts, not just one.
            if pend_ul.len() < 16 {
                let c0 = Candidate { agg_level: 4, cces: (0..4).collect() };
                let mut m = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &c0);
                pdcch_descramble_llr(&mut m, u32::from(acq.cell_id));
                let dci = dci_decode(&m, crnti, a_len).or_else(|| {
                    // CORESET1 search space: DCI 0_1 (non-interleaved). Blind-decode
                    // every AL1/2/4/8 candidate — with CQI feedback the gNB uses AL1 at
                    // Y=0 CCEs the rnti-hashed USS wouldn't cover. Scrambling n_ID/n_RNTI
                    // = cell_id/0.
                    let h_reg = estimate_coreset_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, coreset.n_symb, acq.cell_id, slot_idx);
                    all_candidates(coreset.n_cce(), &[1, 2, 4, 8])
                        .into_iter()
                        // Gate on DM-RS coherence: skip the equalize + polar decode for the
                        // candidates (most of them) that carry no PDCCH.
                        .filter(|cand| coreset_candidate_coherence(&h_reg, cand, coreset.n_symb) >= 0.5)
                        .find_map(|cand| {
                            let mut mm = equalize_candidate_c1_cached(&cgrids, |sc: usize| sc_to_bin(sc as i32), coreset.n_symb, &cand, &h_reg);
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
                        } else if !ul_queue.is_empty() && ul_queue.front().unwrap().len() + 10 > tbs_bytes {
                            let need = ul_queue.front().unwrap().len() + 10;
                            // Over-report the buffer so the gNB grants MORE RBs — its UL
                            // MCS drops under the (lossless-channel) KO noise, so a
                            // truthful ~52B report yields sub-52B grants that never fit
                            // the SRB1 PDU. A big report forces a wide grant we can pad.
                            (mac_short_bsr(need.max(220), tbs_bytes), format!("Short BSR (need {need}B)"))
                        } else if !ul_queue.is_empty() {
                            let rrc = ul_queue.pop_front().unwrap();
                            let m = srb1_msg5_pdu(&rrc, srb1_sn, srb1_sn, tbs_bytes, k_rrcint.as_ref());
                            let k = if srb1_sn == 0 { "RRCSetupComplete".into() } else { format!("UL-DCCH(NAS) SN{srb1_sn}") };
                            srb1_sn += 1;
                            (m, k)
                        } else if drb_up && tun_fd.is_some() && (um_tx.is_some() || !tun_ul.is_empty()) {
                            // TUN mode: carry a real host IP packet over the DRB (LCID 4),
                            // segmenting it across UL grants (RLC UM) if it doesn't fit one.
                            if um_tx.is_none() {
                                let ip = tun_ul.pop_front().unwrap();
                                um_tx = Some((pdcp_data_pdu(pdcp_tx_sn, &ip), 0, um_sn));
                                pdcp_tx_sn += 1;
                                um_sn = um_sn.wrapping_add(1);
                            }
                            let (pdcp, off, sn) = um_tx.take().unwrap();
                            let remaining = pdcp.len() - off;
                            if tbs_bytes < remaining + 3 && tbs_bytes < 100 {
                                // Grant too small for meaningful progress → solicit a bigger one.
                                um_tx = Some((pdcp, off, sn));
                                (mac_short_bsr((remaining + 3).max(220), tbs_bytes), format!("DRB BSR (need {remaining}B)"))
                            } else {
                                let (rlc, new_off) = rlc_um_segment(&pdcp, off, sn, tbs_bytes.saturating_sub(3));
                                let m = drb_mac_wrap(&rlc, tbs_bytes);
                                let s = format!("DRB UL {new_off}/{} B (sn {sn})", pdcp.len());
                                if new_off < pdcp.len() {
                                    um_tx = Some((pdcp, new_off, sn));
                                }
                                (m, s)
                            }
                        } else if let (true, true, false, Some(uip)) = (tun.is_none(), drb_up, ping_acked, ue_ip) {
                            if ping_seq < 20 {
                                // User plane: send an ICMP echo on DRB 1 (LCID 4) and
                                // await the reply. Resend on each grant until acked.
                                let ip = ipv4_icmp_echo_request(uip, ping_target, PING_ID, ping_seq, b"ferrite-ping");
                                let m = drb_ul_pdu(pdcp_tx_sn, &ip, tbs_bytes);
                                pdcp_tx_sn += 1;
                                let s = format!("ICMP echo req seq {ping_seq} → {}.{}.{}.{}",
                                    ping_target[0], ping_target[1], ping_target[2], ping_target[3]);
                                ping_seq += 1;
                                (m, s)
                            } else {
                                (mac_short_bsr(0, tbs_bytes), String::new())
                            }
                        } else {
                            // Idle grant: a valid, decodable PDU that reports an empty
                            // buffer so the gNB stops granting (and no crc=KO).
                            (mac_short_bsr(0, tbs_bytes), String::new())
                        };
                        let m5_alloc = PuschAlloc { rb_start: g_rb0, n_rb: g_nrb, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, carrier_rb, crb_offset: 0 };
                        let ulsch = dlsch_encode_single(&bytes_to_bits(&mac), e, r, qm as usize, 0);
                        let pos = slot_start_ul + (m5_slot - slot_idx as i64) * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * 4;
                        if !kind.is_empty() {
                            println!("  → {kind}: grant RB[{g_rb0},{}) MCS{mcs} ndi={ndi} tbs={tbs_bytes} at ul {pos} (slot {m5_slot})", g_rb0 + g_nrb);
                        }
                        // Modulate after the DL decode (below), so a co-scheduled HARQ-ACK
                        // can be multiplexed onto this PUSCH.
                        pending_pusch = Some((pos, m5_slot, ulsch, m5_alloc, tbs_bytes * 8));
                    }
                }
            }
        }
        perf_ulgrant_ns += perf_ulgrant.elapsed().as_nanos() as u64;

        let perf_ra = std::time::Instant::now();
        // The RA-RNTI (RAR/Msg2) search is only meaningful during attach: once connected,
        // PRACH is off (no RAR can arrive), so skip the equalize + blind DCI decode + Msg2
        // PDSCH demod entirely — ~90 µs/slot of pure waste in steady state.
        if connected.is_none() {
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
                    if let Some(tbb) = dlsch_decode_single(&llr, 72, r, qm as usize, 0, 10) {
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
                                inj.lock().unwrap().push(ReadyWaveform { pos, samples: wave.clone() }, ul_counter as i64);
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
        } // end: if connected.is_none() (RA/RAR search)

        // Connected DL: decode the SRB1 PDSCH at DL slots and drive the NAS
        // registration state machine (AuthReq → SMC → RegistrationAccept). The DL
        // allocation is variable, so read it from the DCI 1_1 assignment in the
        // CORESET1 USS (frequency = FDRA bits[1..10]); fall back to the fixed
        // rb[0,10/11) (the AuthReq) if no DCI decodes. MCS is brute-forced.
        // Offload this connected DL slot's RX decode to the worker thread (pipelined);
        // the result is picked up below, a few slots later.
        perf_ra_ns += perf_ra.elapsed().as_nanos() as u64;
        let perf_drain = std::time::Instant::now();
        // Dispatch every slot with DL symbols: 0-5 (full D) AND 6 (the TDD special slot,
        // 8 DL symbols — the gNB schedules PDSCH there too, e.g. the RRC SMC).
        if connected.is_some() && srb1_sn >= 1 && matches!(slot_idx % 10, 0..=6) {
            let crnti = connected.unwrap();
            if dl_job_tx.try_send(DlJob { slot_idx, slot_start_ul, crnti, fsh: fsh.clone() }).is_err() {
                job_drops += 1; // queue full: the worker is behind — this DL slot is never decoded
            }
        }
        // Drain completed decode results and run the RRC/NAS/MAC stack on each. slot_idx /
        // slot_start_ul are shadowed to the DECODED slot's values, so the HARQ-ACK still
        // targets that slot's n+k1 (the other timeline params are constant in steady state).
        // `for … in Option` yields the one decoded TB, keeping the body's `break`s valid.
        while let Ok(res) = dl_res_rx.try_recv() {
            if res.cqi.is_some() {
                pending_cqi = res.cqi;
            }
            let (r_slot_idx, r_slot_start_ul) = (res.slot_idx, res.slot_start_ul);
            // Absolute dispatch→drain lag in slots (slot_start_ul is monotonic; the old
            // `slot_idx % 20` arithmetic wrapped and under-reported lag ≥ 20 slots).
            let lag = ((slot_start_ul - r_slot_start_ul) / slot_len).max(0) as u64;
            lag_sum += lag;
            lag_max = lag_max.max(lag);
            lag_n += 1;
            #[allow(for_loops_over_fallibles)]
            for DlDecoded { k1, dai, bytes: tb, deliver } in res.decoded {
                dlag_sum += lag; dlag_max = dlag_max.max(lag); dlag_n += 1;
                let slot_idx = r_slot_idx;
                let slot_start_ul = r_slot_start_ul;
                                // Record a positive HARQ-ACK for this PDSCH into the codebook
                                // at its UL slot (n+k1), positioned by C-DAI. It's modulated
                                // and sent as a bundled 1-2 bit PUCCH once its UL slot nears
                                // (below), so several PDSCHs sharing one UL slot ACK together.
                                // ACK reflects a successful PHY decode (CRC OK) regardless of
                                // whether the MAC content is delivered — a TB carrying only a
                                // MAC CE / padding is still ACKed.
                                if k1 != 0xff {
                                    let k1a = k1 as i64; // already the actual k1 in slots
                                    let ack_slot = slot_idx as i64 + k1a;
                                    let pos = slot_start_ul + k1a * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * 4;
                                    let e = ack_book.entry(pos).or_insert(((ack_slot % 20) as u32, [None; 4]));
                                    e.1[(dai & 3) as usize] = Some(1); // 1 = ACK
                                }
                                // ACK-only TB (no deliverable SDU): apply a Timing Advance
                                // Command MAC CE if present (keeps UL aligned so the gNB stops
                                // re-issuing it), then done — nothing to hand up the stack.
                                if !deliver {
                                    if let Some(ta) = parse_ta_command_ce(&tb) {
                                        // N_TA += (T_A - 31) · 16·64/2^μ; last_ta is in those
                                        // same RAR-TA units, so the delta is simply (T_A - 31).
                                        last_ta += ta as i64 - 31;
                                    }
                                    break;
                                }
                                // DRB 1 (LCID 4) DL user data: an IP packet, written to
                                // the TUN (or matched against the built-in ping).
                                if let Some((sn, ip)) = ferrite_ue::userplane::parse_drb_dl_ip(&mut drb_reasm, &tb) {
                                    // Drop HARQ-retransmitted duplicates (same PDCP SN):
                                    // the gNB retransmits DL until ACKed, and RLC UM has no
                                    // dedup of its own, so the same packet can decode twice.
                                    if dl_seen.contains(&sn) {
                                        break;
                                    }
                                    dl_seen.push_back(sn);
                                    if dl_seen.len() > 64 {
                                        dl_seen.pop_front();
                                    }
                                    if let Some(tun) = tun_fd.as_mut() {
                                        // Hand the packet to the OS via the TUN interface.
                                        let _ = tun.write(&ip);
                                    } else if let Some(r) = ferrite_ue::userplane::parse_ipv4_icmp_echo_reply(&ip) {
                                        ping_acked = true;
                                        println!("🏓 PING REPLY from {}.{}.{}.{} id={:#06x} seq={} — END-TO-END PING WORKS",
                                            r.src[0], r.src[1], r.src[2], r.src[3], r.id, r.seq);
                                    } else {
                                        println!("   DRB DL IP packet ({} B): {}", ip.len(),
                                            ip.iter().take(20).map(|b| format!("{b:02x}")).collect::<String>());
                                    }
                                    break;
                                }
                                let Some((rlc_sn, rrc_opt)) = srb1_dl_rrc_reasm(&mut srb1_reasm, &tb) else { break };
                                // A segment arrived but the SDU isn't whole yet: wait for
                                // the rest before ACKing (a large RRCReconfiguration is
                                // split across RLC AM segments) — don't advance the window.
                                let Some(rrc) = rrc_opt else { break };
                                // On a NEW, fully-reassembled DL RLC SDU, arm an RLC STATUS
                                // ACK so the gNB advances (don't re-arm on retransmissions,
                                // which would starve our own UL data).
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
                                    drb_up = true; // the DRB (LCID 4) is now configured
                                    // Learn our assigned IP from the PDU Session Accept
                                    // piggybacked in this reconfiguration (unless --ue-ip set).
                                    if ue_ip.is_none() {
                                        ue_ip = ferrite_ue::rrc::reconfig_pdu_session_ip(&rrc);
                                        if let Some(ip) = ue_ip {
                                            println!("   UE IP {}.{}.{}.{} (from PDU Session Accept)", ip[0], ip[1], ip[2], ip[3]);
                                        }
                                    }
                                    // TUN mode: create the interface now that the DRB is up
                                    // and our IP is known, so the OS can drive real traffic.
                                    if let (Some(name), Some(ip), None) = (&tun, ue_ip, &tun_fd) {
                                        match open_tun(name) {
                                            Ok(f) => {
                                                let _ = configure_tun(name, ip, tun_mtu, netns.as_deref());
                                                tun_fd = Some(f);
                                                let where_ = netns.as_deref().map(|n| format!(" in netns {n}")).unwrap_or_default();
                                                println!("   TUN {name} up ({}.{}.{}.{}/mtu {tun_mtu}){where_} — carrying host traffic over the DRB",
                                                    ip[0], ip[1], ip[2], ip[3]);
                                            }
                                            Err(e) => println!("   TUN {name} creation FAILED: {e} (run under sudo?)"),
                                        }
                                    }
                                    let tid = ferrite_ue::rrc::dl_dcch_transaction_id(&rrc);
                                    ul_queue.push_back(rrc_reconfiguration_complete(tid));
                                    println!("   ⇒ queued RRCReconfigurationComplete (tid {tid}) — DRB up");
                                    break;
                                }
                                // ueCapabilityEnquiry (6): answer with a minimal
                                // ueCapabilityInformation (no extra capabilities).
                                if dtype == Some(6) && !cap_done {
                                    cap_done = true;
                                    let tid = ferrite_ue::rrc::dl_dcch_transaction_id(&rrc);
                                    ul_queue.push_back(rrc_ue_capability_information(tid));
                                    println!("   ⇒ queued UECapabilityInformation (tid {tid})");
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
                                    // RegistrationAccept → send RegistrationComplete = attach done,
                                    // then immediately request an IPv4 PDU session (user plane).
                                    Some(0x42) if smc_done && !reg_done => {
                                        reg_done = true;
                                        if let Some(ni) = &k_nasint {
                                            let prot = nas_protect(0x02, ni, nas_ul_count, 0, &registration_complete());
                                            nas_ul_count += 1;
                                            ul_queue.push_back(rrc_ul_information_transfer(&prot));
                                            println!("   ⇒ queued RegistrationComplete — ATTACH COMPLETE");
                                            let pdu = ul_nas_transport_pdu_session(PDU_SESSION_ID, 1, "internet");
                                            let prot2 = nas_protect(0x02, ni, nas_ul_count, 0, &pdu);
                                            nas_ul_count += 1;
                                            ul_queue.push_back(rrc_ul_information_transfer(&prot2));
                                            println!("   ⇒ queued PDU Session Establishment Request (psi {PDU_SESSION_ID})");
                                        }
                                    }
                                    // DL NAS Transport → carries the SMF's PDU Session
                                    // Establishment Accept/Reject (5GSM) in its payload container.
                                    Some(0x68) => {
                                        if let Some(sm) = nas_transport_payload(inner) {
                                            let smtype = sm.get(3).copied();
                                            println!("   ⇒ DL NAS Transport 5GSM type={smtype:?} payload={}",
                                                sm.iter().map(|b| format!("{b:02x}")).collect::<String>());
                                        }
                                    }
                                    _ => {}
                                }
                                break;
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
                                inj.lock().unwrap().push(ReadyWaveform { pos, samples: pw.clone() }, ul_counter as i64);
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
        let want_ping = tun.is_none() && drb_up && !ping_acked && ue_ip.is_some() && ping_seq < 20;
        let want_drb = drb_up && tun_fd.is_some() && (um_tx.is_some() || !tun_ul.is_empty());
        if connected.is_some() && (!ul_queue.is_empty() || pending_status.is_some() || want_ping || want_drb) && slot_idx == 0 && pend_sr.is_none() {
            let sr_slot = 7i64;
            let pos = slot_start_ul + (sr_slot - slot_idx as i64) * slot_len
                + offset + locked_toff.unwrap_or(0) - last_ta * 4;
            // SR kept in T0: cheap (one PUCCH F1/frame) and latency-critical (drives grants).
            let mut sw = ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &sr_cfg, &[], sr_slot as u32, center_hz, fs);
            let pk = sw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
            for s in &mut sw { *s *= amp / pk; }
            inj.lock().unwrap().push(ReadyWaveform { pos, samples: sw }, ul_counter as i64);
            pend_sr = Some(pos);
        }

        // Periodic CSI report: send the measured CQI on the PUCCH F2 (PRB 23, symb
        // [0,2)) at slot 8. Queue it at slot 6 (2 slots ahead) once the frame's
        // CSI-RS has been measured (slots 2-4). pending_cqi is Some only in frames
        // where a valid CSI-RS was seen (even frames), which is exactly when the gNB
        // reads the slot-8 report — so no SFN parity check is needed.
        if connected.is_some() && slot_idx == 6 && pend_csi.is_none() {
            if let Some(cqi) = pending_cqi.take() {
                let csi_slot = 8i64;
                let cfg = ferrite_phy::pucch::PucchF2 {
                    prb_start: 23, nof_prb: 1, start_symbol: 0, nof_symbols: 2,
                    rnti: connected.unwrap(), n_id: acq.cell_id, n_id0: acq.cell_id, carrier_rb,
                };
                // 4-bit wideband CQI, MSB first.
                let bits = vec![(cqi >> 3) & 1, (cqi >> 2) & 1, (cqi >> 1) & 1, cqi & 1];
                let pos = slot_start_ul + (csi_slot - slot_idx as i64) * slot_len
                    + offset + locked_toff.unwrap_or(0) - last_ta * 4;
                let _ = tx_req_tx.try_send(TxReq::PucchF2 { cfg, bits, slot_mod20: csi_slot as u32, pos, now: ul_counter as i64 });
                pend_csi = Some(pos);
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
        // Drop the pending PUCCH / SR once their windows have passed.
        if let Some((pos, wave)) = &pend_pucch {
            if ul_counter as i64 > pos + wave.len() as i64 + slot_len {
                pend_pucch = None;
            }
        }
        if let Some(pos) = pend_sr {
            if ul_counter as i64 > pos + 2 * slot_len {
                pend_sr = None;
            }
        }
        if let Some(pos) = pend_csi {
            if ul_counter as i64 > pos + 2 * slot_len {
                pend_csi = None;
            }
        }
        // Build the UL grant's PUSCH now that the DL codebook is populated. If a
        // HARQ-ACK is due at this PUSCH's UL slot, multiplex it onto the PUSCH
        // (UCI-on-PUSCH) — the gNB expects it there, not on the PUCCH — and remove it
        // from the codebook so it isn't also sent on a PUCCH.
        if let Some((pos, m5_slot, ulsch, m5_alloc, tb_bits)) = pending_pusch.take() {
            let ack: Vec<u8> = ack_book.remove(&pos).map(|(_, book)| {
                let size = book.iter().rposition(Option::is_some).map(|i| i + 1).unwrap_or(0);
                (0..size).map(|i| book[i].unwrap_or(0)).collect()
            }).unwrap_or_default();
            const BETA_HARQ: f32 = 20.0; // beta_offset_harq_ack index 11
            let crnti = connected.unwrap_or(0);
            let _ = tx_req_tx.try_send(TxReq::Pusch {
                ulsch, alloc: m5_alloc, slot_mod20: (m5_slot % 20) as u32, slot_parity: (m5_slot % 2) as usize,
                crnti, ack, beta: BETA_HARQ, tb_bits, pos, now: ul_counter as i64,
            });
            pend_ul.push(pos);
        }
        // Modulate + queue any HARQ-ACK codebook entries whose UL slot is approaching
        // (a couple slots out, so all their contributing DL PDSCHs have been decoded).
        // The bundle is sized by the highest C-DAI seen (missing positions → NACK bit 0),
        // ordered by C-DAI, so the gNB reads the exact harq_bit_len bits it expects.
        // Modulate ACKs whose UL slot is within ~3 slots of T0's own progress (their contributing
        // DL PDSCHs are decoded by then); the radio thread serves them at their absolute position.
        let due: Vec<i64> = ack_book.keys().copied().filter(|&pos| pos <= slot_start_ul + 3 * slot_len).collect();
        for pos in due {
            let (slot_mod20, book) = ack_book.remove(&pos).unwrap();
            let size = book.iter().rposition(Option::is_some).map(|i| i + 1).unwrap_or(0);
            if size == 0 {
                continue;
            }
            ack_total += 1;
            if pos < ul_counter as i64 {
                ack_late += 1; // its UL block was already served — can never be injected
                if std::env::var_os("FERRITE_DRIFT").is_some() && ack_late < 16 {
                    eprintln!("[ack-late] pos={pos} serving={ul_counter} pos-serving={} pos-t0(slots)={} last_ta={last_ta} ta*4(slots)={}",
                        pos - ul_counter as i64, (pos - slot_start_ul) / slot_len, (last_ta * 4) / slot_len);
                }
            }
            let bits: Vec<u8> = (0..size).map(|i| book[i].unwrap_or(0)).collect();
            if pend_acks.len() < 12 {
                // HARQ-ACK kept in T0: cheap (1-2 bit PUCCH F1) and the most latency-critical UL
                // (a TX-thread hop delays it past its k1 window). Modulate + inject inline.
                let mut aw = ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &harq_cfg, &bits, slot_mod20, center_hz, fs);
                let pk = aw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                for s in &mut aw { *s *= amp / pk; }
                inj.lock().unwrap().push(ReadyWaveform { pos, samples: aw }, ul_counter as i64);
                pend_acks.push(pos);
            } else {
                ack_qfull += 1;
            }
        }
        // Drop HARQ-ACK and PUSCH position trackers whose UL window has passed (the actual
        // waveforms are dropped by the InjectionTable once served); a PUCCH/PUSCH spans one slot.
        pend_acks.retain(|&pos| (ul_counter as i64) <= pos + 2 * slot_len);
        pend_ul.retain(|&pos| (ul_counter as i64) <= pos + 2 * slot_len);
        perf_drain_ns += perf_drain.elapsed().as_nanos() as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live-captured TA-command PDU `3d 1a 3f 00…` = [TA Command CE (LCID 61),
    /// TAG 0, T_A 26][padding]. Parse must extract T_A = 26 (0x1a & 0x3f).
    #[test]
    fn ta_command_ce_parsed() {
        let mut tb = vec![0u8; 42];
        tb[0] = 0x3d; // R|F|LCID=61 (Timing Advance Command)
        tb[1] = 0x1a; // TAG=0, T_A=26
        tb[2] = 0x3f; // padding (LCID 63)
        assert_eq!(parse_ta_command_ce(&tb), Some(26));
    }

    /// A TA command after a logical-channel SDU is still found (subheader walk).
    #[test]
    fn ta_command_ce_after_sdu() {
        // [lcid=1, L=3, "abc"][TA CE, T_A=5][padding]
        let tb = [0x01, 0x03, b'a', b'b', b'c', 0x3d, 0x05, 0x3f, 0x00];
        assert_eq!(parse_ta_command_ce(&tb), Some(5));
    }

    /// No TA command in a plain SDU-only / padding PDU.
    #[test]
    fn ta_command_ce_absent() {
        assert_eq!(parse_ta_command_ce(&[0x01, 0x02, 0xaa, 0xbb, 0x3f, 0x00]), None);
        assert_eq!(parse_ta_command_ce(&[0x3f, 0, 0, 0]), None); // padding only
    }
}
