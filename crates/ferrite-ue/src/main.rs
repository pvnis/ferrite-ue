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
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, extract_pdsch_rm, pdsch_scramble_c_init, PdschAlloc};
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
use ferrite_ue::userplane::{drb_mac_wrap_bsr, drb_ul_pdu, ipv4_icmp_echo_request, pdcp_data_pdu, rlc_um_segment};
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
) -> Option<(Vec<u8>, bool)> {
    // Msg4 allocation (fallback DCI 1_0): PRB[0,N), symbols[2,14), QPSK MCS7
    // (Qm2, R=526/1024), 2 CDM groups, non-interleaved VRB-to-PRB. The gNB sizes N
    // to fit the RRCSetup within CORESET0 — 21 RB on the 10 MHz cell, 22 on the 20 MHz
    // cell — so sweep the plausible widths (LDPC+CRC rejects the wrong ones). CORESET0
    // RB0 = CRB0 here (base 0). The winning tf/data-mapping is CELL-FIXED, so it seeds
    // the connected-mode worker's DM-RS layout sweep (halving its cold first-decode cost).
    let (rb0, qm, r) = (0usize, 2usize, 526.0 / 1024.0);
    let dbg = std::env::var("MSG4DBG").is_ok();
    let (tb, tf_won) = [21usize, 22, 20, 23, 24, 18].into_iter().find_map(|nrb| {
        let n_re = nrb * 12 * (12 - 3);
        let tbs = tbs_from_nre(n_re, r, qm);
        let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm, n_bwp: 0, nof_cdm_groups: 2 };
        [true, false].into_iter().find_map(|time_first| {
            let px = extract_pdsch(grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, tc, cell_id, time_first);
            let mut llr = px.llrs.clone();
            descramble_llrs(&mut llr, pdsch_scramble_c_init(tc, cell_id));
            let (bits, conv, crc) = ferrite_phy::coding::dlsch::dlsch_decode_single_bits(&llr, tbs, r, qm, 0, 10);
            if dbg {
                eprintln!("  [msg4] tc={tc:#06x} slot {slot_idx} nrb={nrb} tf={time_first} dmrs={:.2} conv={conv} crc={crc}", px.dmrs_metric);
            }
            if !crc {
                return None;
            }
            let tb: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
            if tb.iter().all(|&b| b == 0) {
                None
            } else {
                Some((tb, time_first))
            }
        })
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
        return Some((tb, tf_won));
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

/// Structurally valid DL-SCH MAC PDU: a subheader chain of known LCIDs whose lengths
/// exactly tile the TB (padding closes it). This accepts TBs that carry an RLC
/// SEGMENT — mid-reassembly pieces the gNB produces when its post-NACK link
/// adaptation shrinks the grants — which `plausible_dl_tb` (full-PDU check) rejects.
/// Without it a genuinely-decoded segment TB is discarded as a suspected false CRC
/// pass on an unverified layout, NACKs forever, and the retx flood wedges the attach.
/// Used only to allow an ACK (deliver=false), never to deliver content or move the
/// layout lock, so a residual CRC16-collision false accept costs one RLC retx at most.
fn plausible_mac_pdu(tb: &[u8]) -> bool {
    let mut i = 0;
    let mut subpdus = 0usize;
    while i < tb.len() {
        let (lcid, f) = (tb[i] & 0x3f, (tb[i] >> 6) & 1);
        match lcid {
            63 => return subpdus > 0, // padding: rest of the TB
            61 => i += 2,             // TA Command CE
            60 | 59 => i += 1,        // (Long) DRX Command
            62 => i += 1 + 6,         // Contention Resolution Identity
            1..=32 => {
                let (len, hdr) = if f == 1 {
                    let (Some(&h), Some(&l)) = (tb.get(i + 1), tb.get(i + 2)) else { return false };
                    (((h as usize) << 8) | l as usize, 3)
                } else {
                    let Some(&l) = tb.get(i + 1) else { return false };
                    (l as usize, 2)
                };
                i += hdr + len;
            }
            _ => return false,
        }
        if i > tb.len() {
            return false;
        }
        subpdus += 1;
    }
    subpdus > 0
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

/// The SLIV of the full [2,14) type-A allocation — the fallback shape (DCI 1_0's
/// default-table row 0, and any DL before the TDRA lists are known).
const SLIV_FULL: u8 = 53;
/// The SLIV of the bring-up cell's short [2,8) row (row 1 of its SIB1 list).
const SLIV_SHORT: u8 = 72;

/// Time-domain shape of a connected-mode DL PDSCH: (sym_start, n_sym, DM-RS symbols)
/// from the scheduled row's SLIV. The row comes from the DCI's TDRA field via the
/// configured pdsch-TimeDomainAllocationList (dedicated, else SIB1) — short rows are
/// used in the TDD special slot for FIRST transmissions, but HARQ retransmissions of
/// such a TB keep the short shape in NORMAL slots too (same TBS ⇒ same allocation), so
/// the shape must come from the DCI, not the slot index: inferring it from the slot
/// wedged the attach whenever the special-slot first TX was missed (every retx then
/// extracted as 12-symbol and could never CRC → registration timeout).
/// DM-RS: TS 38.211 Table 7.4.1.1.2-3, single-symbol, mapping type A (ld = S + L),
/// typeA-position = pos2, dmrs-AdditionalPosition = pos2 — the OCUDU defaults; live
/// anchors: ld 8 → {2,7} (bring-up cell), ld 10 → {2,6,9} (DDDSU cell, gNB dmrs_mask),
/// ld 14 → {2,7,11}.
fn dl_pdsch_shape(sliv: u8) -> (usize, usize, Vec<usize>) {
    let (s, l) = ferrite_ue::sib1::sliv_to_sl(sliv);
    let dmrs: &[usize] = match s + l {
        ..=7 => &[2],
        8 | 9 => &[2, 7],
        10 => &[2, 6, 9],
        11 => &[2, 7, 10],
        _ => &[2, 7, 11],
    };
    (s, l, dmrs.to_vec())
}

/// The cell's periodic CSI-RS geometry (TS 38.211 §7.4.1.5): which REs the gNB
/// rate-matches connected-mode PDSCH around (TS 38.214 §5.1.4), which slots have any
/// CSI-RS, and where to measure the TRS for the CQI report. Built from the parsed
/// masterCellGroup NZP/ZP resource lists (`CSI_RM`, set once at Msg4); until then the
/// transcribed pattern of the bring-up cell applies (`DEFAULT_CSI_RM`). Slot keys are
/// `offset_slots % 20` — the resources are 40-slot periodic and the caller's CSI
/// frame-parity anchor handles the other 20 (see `csi_parity` in `decode_dl`).
struct CsiRm {
    /// (slot-in-frame, OFDM symbol, 12-bit per-RB subcarrier mask) per CSI-RS symbol
    /// instance, NZP and ZP — the PDSCH rate-match pattern. The resources span the
    /// whole BWP, so the per-RB mask repeats across RBs.
    res: Vec<(u32, usize, u16)>,
    /// The CQI measurement instances: (slot, symbol, k0) of each density-3 row-1 TRS —
    /// a full {k0, k0+4, k0+8} comb (single-RE rows mix PDSCH data into the measurement
    /// and can't anchor the frame parity).
    meas: Vec<(u32, usize, usize)>,
}

impl CsiRm {
    /// Translate the parsed NZP + ZP resource lists (TS 38.211 Table 7.4.1.5.3-1 rows
    /// 1, 2 and 4 — the ones OCUDU emits) into per-slot RE masks.
    fn from_cellgroup(cg: &ferrite_ue::cellgroup::CellGroupParams) -> Self {
        let mut rm = CsiRm { res: Vec::new(), meas: Vec::new() };
        for r in cg.nzp_csi_rs.iter().chain(cg.zp_csi_rs.iter()) {
            let slot = u32::from(r.offset_slots) % 20;
            let bit = r.freq_bits.trailing_zeros() as usize; // lowest set bit = k0/group
            let mask: u16 = match r.row {
                // Row 1 (density 3): k ∈ {k0, k0+4, k0+8}.
                1 => 0b_0001_0001_0001 << bit,
                // Row 2: the single subcarrier k0.
                2 => 1 << bit,
                // Row 4: a group of 4 subcarriers starting at 4·j.
                4 => 0b1111 << (4 * bit),
                _ => continue,
            };
            for sym in std::iter::once(r.symbol).chain(r.symbol2) {
                rm.res.push((slot, sym as usize, mask));
                if r.row == 1 && r.density == 3 {
                    rm.meas.push((slot, sym as usize, bit));
                }
            }
        }
        rm
    }

    fn has_slot(&self, slot: u32) -> bool {
        self.res.iter().any(|&(s, _, _)| s == slot)
    }
}

/// Set once from the parsed masterCellGroup at Msg4 (read by the RX-PHY worker).
static CSI_RM: std::sync::OnceLock<CsiRm> = std::sync::OnceLock::new();
/// The bring-up cell's pattern, read live from the gNB's FAPI debug output (values
/// only): slots 2,3 = TRS row 1 density 3 k0=1 (k ∈ {1,5,9}) at symbols 4 and 8;
/// slot 4 = NZP row 2 k=1 at symbol 4 + ZP row 4 k ∈ {4..8} at symbol 8. SIB1
/// (slot 1) and RAR (slot 10) never land in these slots.
static DEFAULT_CSI_RM: std::sync::LazyLock<CsiRm> = std::sync::LazyLock::new(|| CsiRm {
    res: vec![
        (2, 4, 0b_0010_0010_0010), (2, 8, 0b_0010_0010_0010),
        (3, 4, 0b_0010_0010_0010), (3, 8, 0b_0010_0010_0010),
        (4, 4, 0b_0000_0000_0010), (4, 8, 0b_0000_1111_0000),
    ],
    meas: vec![(2, 4, 1), (3, 4, 1)],
});

fn csi_rm() -> &'static CsiRm {
    CSI_RM.get().unwrap_or(&DEFAULT_CSI_RM)
}

/// Is (slot, symbol, subcarrier-in-RB) a CSI-RS RE the PDSCH rate-matches around?
fn csi_rs_rm_re(slot: u32, l: usize, k: usize) -> bool {
    csi_rm().res.iter().any(|&(s, sym, mask)| s == slot && sym == l && mask >> (k % 12) & 1 == 1)
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
    sliv: u8,
    rm_csi: bool,
    tb_shape: (u8, usize, u8),
) -> (Vec<f32>, usize, Option<Vec<u8>>) {
    use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
    let (sym_start, n_sym, dmrs) = dl_pdsch_shape(sliv);
    // TBS and base graph follow the TB's INITIAL transmission (TS 38.214 §5.1.3.2):
    // `tb_shape` = (mcs, n_rb, sliv) of the first transmission of this HARQ process's
    // TB. A retransmission may arrive with an ADAPTED (lower) MCS — the gNB's link
    // adaptation reacts to the NACK — and a different allocation, but the TB keeps its
    // original size. Recomputing TBS from the retx DCI (the old behaviour) made every
    // adapted retx undecodable (wrong info length, e.g. true TBS 42 B computed as 11 B),
    // which turned any first NACK into an unrecoverable retx storm. For a first
    // transmission the caller passes this DCI's own (mcs, n_rb, sliv) — identical maths.
    // NOTE: the CSI-RS rate matching below does NOT reduce the TBS RE count — TS 38.214's
    // N'_RE ignores CSI-RS; only the extracted (rate-matched) LLR length E shrinks.
    let (i_mcs, i_nrb, i_sliv) = tb_shape;
    let (i_qm, i_r) = mcs_params(i_mcs);
    let (_, i_nsym, i_dmrs) = dl_pdsch_shape(i_sliv);
    let n_re = i_nrb * ((i_nsym - i_dmrs.len()) * 12 + if cdm == 1 { i_dmrs.len() * 6 } else { 0 });
    let tbs = tbs_from_nre(n_re, i_r, i_qm as usize);
    let _ = r;
    let alloc = PdschAlloc { rb_start, n_rb, sym_start, n_sym, dmrs_symbols: dmrs, qm, n_bwp: 0, nof_cdm_groups: cdm };
    let skip = |l: usize, k: usize| csi_rs_rm_re(slot_idx, l, k);
    let px = extract_pdsch_rm(grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, time_first,
        rm_csi.then_some(&skip as &dyn Fn(usize, usize) -> bool));
    let mut llr = px.llrs;
    descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
    // Standalone decode at the DCI's RV (rv=0 hardcoded would make retransmissions undecodable).
    // max_iter 10 (was 40): the LDPC early-exits on success (1-3 iters on this clean channel),
    // so max_iter is only ever burned in full by decodes that CANNOT succeed (wrong layout/RV/
    // TBS guess). At 40, those failures cost ~4× more, and during a retx flood (a PDSCH in
    // every slot) they push the per-job wall past the 500µs slot — the pipeline backs up
    // 10-70 slots, every HARQ-ACK misses its k1 window, and the flood feeds itself.
    let (bits, _c, crc) = dlsch_decode_single_bits(&llr, tbs, i_r, qm, rv, 10);
    let tb = crc.then(|| pack_bits(&bits));
    if std::env::var("FERRITE_DBG_SLOT").ok().and_then(|v| v.parse::<u32>().ok()) == Some(slot_idx) {
        eprintln!("[std] slot={slot_idx} rb[{rb_start},+{n_rb}) qm={qm} rv={rv} cdm={cdm} tf={time_first} sliv={sliv} shape={tb_shape:?} tbs={tbs} e={} crc={crc}", llr.len());
    }
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
    sliv: u8,
    rm_csi: bool,
    // (mcs, n_rb, sliv) of this TB's INITIAL transmission (= this DCI's own values for a
    // first transmission) — TBS/base-graph follow it, not the retx DCI. See pdsch_standalone.
    tb_shape: (u8, usize, u8),
    // NDI unchanged vs the last DCI on this HARQ process ⇒ this is a retransmission.
    is_retx: bool,
    // Cell-fixed time-first order proven by the Msg4 decode — halves the pre-lock sweep.
    tf_hint: Option<bool>,
    // The gNB's typical first-transmission MCS (feeds the shape hypothesis below).
    hyp_mcs: u8,
    lock: &mut Option<(usize, bool)>,
    harq_dl: &mut std::collections::HashMap<u8, HarqDl>,
) -> Option<(Vec<u8>, bool, (u8, usize, u8))> {
    let (qm, r) = mcs_params(mcs);
    let (qm, r) = (qm as usize, r);
    use ferrite_phy::coding::dlsch::{dlsch_cb_llr, dlsch_decode_cb};
    use rayon::prelude::*;
    // Sweep ALL four (CDM-groups × time-first) layouts. The time-first order is NOT
    // cell-fixed across CDM values (verified offline on a live capture: a cdm=1 small-TB
    // PDSCH decodes ONLY at tf=true while the cdm=2 PDSCHs of the same cell decode at
    // tf=false) — filtering tf by a lock taken from a cdm=2 decode made every cdm=1 grant
    // undecodable. find_map_any returns at the first winner, so the sweep's wall cost is
    // ~one decode; the losers only occupy pool threads (cheap for the small TBs that
    // dominate; the rare wide-band first tx pays once until its HARQ process resolves).
    let _ = tf_hint;
    let layouts: Vec<(usize, bool)> = vec![(1, true), (1, false), (2, true), (2, false)];
    // The per-layout work (extract + descramble + standalone LDPC at the DCI's RV) is pure.
    // FAST PATH: run the layouts in parallel and return on the FIRST that CRCs, WITHOUT waiting
    // for the wrong-CDM layout to run its LDPC to full max_iter (~500µs for a wide-band BG1 TB —
    // that wait is what made big-TB decode overrun the 500µs slot, overflow the worker queue and
    // drop the DL burst). `find_map_any` returns as soon as any layout succeeds; the loser keeps
    // running on its pool thread but no longer gates this decode's latency. `lock0` is a
    // read-only copy so the parallel closure needn't borrow `&mut lock`.
    let lock0 = *lock;
    // Retransmission (NDI unchanged) with the layout already locked: skip the multi-layout
    // standalone sweep — rv 1/3 are rarely self-decodable, so on failure the sweep burns 2
    // full-max_iter LDPC passes PLUS the combine path's re-extract (~4 passes ≈ 2 slots), and
    // during a retx flood that arrives every slot, which is exactly when the worker can least
    // afford it (late ACKs feed the flood). The combine path below extracts the locked layout
    // ONCE and decodes the accumulated sum — for a retx whose earlier transmissions we dropped,
    // the sum IS this transmission alone, so nothing is lost vs the standalone attempt.
    let retx_combine_only = is_retx && h_id != 0xff && lock0.is_some();
    let hit = if retx_combine_only { None } else { layouts.par_iter().find_map_any(|&(cdm, time_first)| {
        let (_llr, _tbs, tb) = pdsch_standalone(grids, sc_to_bin, cell_id, slot_idx, crnti, rb_start, n_rb, qm, r, rv, cdm, time_first, sliv, rm_csi, tb_shape);
        let tb = tb?;
        // Deliverable PDU (DRB IP / SRB1 RRC) on the right layout → lock it and deliver up the
        // stack. A CRC-pass on the already-locked layout that isn't a recognizable PDU (a MAC CE
        // / padding) is still a faithful TB reception → ACK-only (must be ACKed or the gNB DTXs
        // and retransmits forever). A CRC-pass on some other, unlocked layout that isn't
        // plausible is ignored.
        if plausible_dl_tb(&tb) {
            Some((cdm, time_first, tb, true))
        } else if lock0 == Some((cdm, time_first)) || plausible_mac_pdu(&tb) {
            Some((cdm, time_first, tb, false))
        } else {
            None
        }
    }) };
    if let Some((cdm, time_first, tb, deliver)) = hit {
        if deliver {
            *lock = Some((cdm, time_first));
        }
        harq_dl.remove(&h_id); // HARQ process delivered / faithfully received
        return Some((tb, deliver, tb_shape));
    }
    // SLOW PATH — no standalone success, i.e. a retransmission that needs HARQ soft-combining.
    // Re-extract JUST the locked (cell-fixed) layout, accumulate this RV's circular buffer into
    // the per-process buffer, and decode the running sum (recovering a TB no single (re)tx could).
    // Only reached on retx, which the fast first-transmission path above should keep rare.
    if h_id != 0xff {
        if let Some((lcdm, ltf)) = lock0 {
            let (llr, tbs, _tb) = pdsch_standalone(grids, sc_to_bin, cell_id, slot_idx, crnti, rb_start, n_rb, qm, r, rv, lcdm, ltf, sliv, rm_csi, tb_shape);
            let cb = dlsch_cb_llr(&llr, tbs, r, qm, rv);
            if !cb.is_empty() {
                let e = harq_dl.entry(h_id).or_insert_with(|| HarqDl { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 });
                if e.tbs != tbs || e.qm != qm || e.acc.len() != cb.len() || rv == 0 {
                    *e = HarqDl { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 };
                }
                for (a, &c) in e.acc.iter_mut().zip(&cb) {
                    *a += c;
                }
                e.n_rx += 1;
                // Combine-only retx path: always attempt the sum (n_rx==1 means the rv=0
                // was dropped and the sum IS this transmission — the standalone attempt
                // this path replaced). Sweep-first path: only from the 2nd reception on
                // (the 1st already failed standalone above; re-decoding the same LLRs
                // alone would just burn another max_iter).
                if e.n_rx >= 2 || retx_combine_only {
                    let (cbits, _c, ccrc) = dlsch_decode_cb(&e.acc, tbs, r, 10);
                    if ccrc {
                        let tb = pack_bits(&cbits);
                        let deliver = plausible_dl_tb(&tb);
                        harq_dl.remove(&h_id);
                        return Some((tb, deliver, tb_shape));
                    }
                }
            }
        }
    }
    // Shape hypotheses: the primary shape failed every path, which happens when the
    // per-process shape record is WRONG for this transmission. Two real cases (both
    // observed live, both otherwise permanent):
    //  · NDI double-toggle: we missed an entire TB generation on this process (dropped
    //    slots), so a NEW TB reuses the recorded NDI value and is misclassified as a
    //    retx of the OLD TB → decoded with a stale shape (e.g. TBS 336 vs actual 88).
    //    Antidote: the DCI's OWN shape.
    //  · Dropped-initial adaptation: the initial DCI was dropped and this is a
    //    link-adapted retx, so the DCI's (lowered) MCS gives the wrong TBS.
    //    Antidote: the gNB's usual first-transmission MCS on this allocation.
    // Each extra attempt is one standalone sweep; on success the caller re-records the
    // shape that decoded, so the process returns to the fast blind-ACK/combine paths.
    if h_id != 0xff {
        let mut shapes: Vec<(u8, usize, u8)> = Vec::new();
        // The combine-only fast path above skipped the standalone sweep AND its combine
        // extraction trusts the locked layout — which is per-grant-wrong when the CDM
        // group count differs (observed live: a cdm=1 retx never decodes against a cdm=2
        // lock, silently). Recover with the full-sweep standalone attempt it skipped.
        if retx_combine_only {
            shapes.push(tb_shape);
        }
        let dci_shape = (mcs, n_rb, sliv);
        if dci_shape != tb_shape {
            shapes.push(dci_shape);
        }
        let hyp = (hyp_mcs, n_rb, sliv);
        if tb_shape.0 < hyp_mcs && hyp != dci_shape {
            shapes.push(hyp);
        }
        for cand_shape in shapes {
            let hyp_hit = layouts.par_iter().find_map_any(|&(cdm, time_first)| {
                let (_llr, _tbs, tb) = pdsch_standalone(grids, sc_to_bin, cell_id, slot_idx, crnti, rb_start, n_rb, qm, r, rv, cdm, time_first, sliv, rm_csi, cand_shape);
                let tb = tb?;
                if plausible_dl_tb(&tb) {
                    Some((cdm, time_first, tb, true))
                } else if lock0 == Some((cdm, time_first)) || plausible_mac_pdu(&tb) {
                    Some((cdm, time_first, tb, false))
                } else {
                    None
                }
            });
            if let Some((cdm, time_first, tb, deliver)) = hyp_hit {
                if deliver {
                    *lock = Some((cdm, time_first));
                }
                harq_dl.remove(&h_id);
                return Some((tb, deliver, cand_shape));
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
    /// Frame parity from the monotonic slot position (slot_start_ul advances exactly one
    /// slot_len per slot, so this survives job drops) — gates the 20 ms-periodic CSI-RS
    /// rate matching in `decode_dl`.
    frame_even: bool,
    crnti: u16,
    /// The DL assignment T0's blind search found in this slot's PDCCH (rb0, nrb, mcs, k1,
    /// C-DAI, rv, h_id, TDRA-row SLIV, ndi) — T0 searches the CORESETs once per slot for its
    /// UL grant anyway, so the worker reuses the result instead of repeating the ~200µs
    /// search (which was the margin that blew its 500µs budget under a retx flood).
    dl_dci: Option<(usize, usize, u8, u8, u8, u8, u8, u8, u8)>,
    /// The cell-fixed time-first RE order proven by the Msg4 decode (see `msg4_tf`).
    tf_hint: Option<bool>,
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
    /// PUSCH (+ optional multiplexed UCI HARQ-ACK). Carries the already-encoded UL-SCH:
    /// the LDPC encode stays on T0 — moving it here (tried) added enough latency that the
    /// waveform could land inside its serve window and garble the PUSCH; T0's encode spike
    /// is tolerable now that the depth-2 job queue absorbs the pace-catch-up bursts.
    Pusch {
        ulsch: Vec<u8>, alloc: PuschAlloc, slot_mod20: u32, slot_parity: usize,
        crnti: u16, ack: Vec<u8>, beta: f32, tb_bits: usize, pos: i64, now: i64,
        /// CSI part 1 (wideband CQI) bits + their RE placement — non-empty when this
        /// PUSCH lands on a CSI-report occasion (the gNB reserves the REs; the ulsch
        /// is already encoded to the reduced E).
        csi: Vec<u8>, csi_res: Vec<(usize, usize)>,
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
    cell_id: u16,
    carrier_rb: usize,
    sc_to_bin: impl Fn(i32) -> usize + Copy + Sync,
    crnti: u16,
    slot_idx: u32,
    // The DL assignment T0's per-slot blind search found (T0 searches for its UL grant
    // anyway; the worker reusing it removes a duplicate ~200µs search from its budget).
    dl_dci: Option<(usize, usize, u8, u8, u8, u8, u8, u8, u8)>,
    harq_dl: &mut std::collections::HashMap<u8, HarqDl>,
    // Per-HARQ-process delivered state: h_id → NDI of the last TB this process CRC-OK'd.
    // A later DCI with the same (h_id, NDI) is a retransmission of that TB → ACK from the
    // DCI alone, no decode (see the short-circuit below).
    harq_done: &mut std::collections::HashMap<u8, u8>,
    // Per-HARQ-process INITIAL-transmission shape: h_id → (ndi, mcs, n_rb, sliv) recorded
    // at first sight of each new TB. A retransmission (same NDI) keeps the TB's original
    // TBS even when the gNB adapts the MCS/allocation down — decode with the stored shape.
    harq_init: &mut std::collections::HashMap<u8, (u8, u8, usize, u8)>,
    // CSI-RS frame-parity anchor: the cell's CSI-RS/TRS are 20 ms periodic (every OTHER
    // frame) but slot_idx only spans one frame, so PDSCH-around-CSI-RS rate matching
    // (see `csi_rs_rm_re`) applies only when this slot's frame parity matches the parity
    // where CSI-RS was DETECTED (SINR ≫ 0 on the TRS REs — a lossless-channel discriminator).
    // `frame_even` comes from the monotonic slot position, so job drops can't desync it.
    frame_even: bool,
    csi_parity: &mut Option<bool>,
    // Cell-fixed time-first order proven by the Msg4 decode (pre-lock sweep seed).
    tf_hint: Option<bool>,
    // The gNB's typical first-transmission MCS, learned from successful first decodes —
    // feeds try_decode_dl_srb1's shape hypothesis for retx whose initial DCI we dropped.
    init_mcs_typ: &mut u8,
    dl_dmrs_lock: &mut Option<(usize, bool)>,
    backlog: bool,
) -> (Option<DlDecoded>, Option<u8>) {
    // (rb_start, n_rb, MCS, k1 (0xff = don't ACK), C-DAI, RV, HARQ id (0xff = fallback),
    //  the TDRA row's SLIV (the time-domain shape; SLIV_FULL = the [2,14) fallback) —
    //  and NDI, the 1-bit new-data indicator that distinguishes a retransmission from a
    //  fresh TB on the same HARQ process). From T0's blind search (in the DlJob).
    let mut allocs: Vec<(usize, usize, u8, u8, u8, u8, u8, u8, u8)> = Vec::new();
    if let Some(a) = dl_dci {
        allocs.push(a);
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
                allocs.push((0, nrb, mcs, 0xff, 0, 0, 0xff, SLIV_FULL, 0));
            }
        }
    }
    // HARQ retransmission of a TB this process already decoded (NDI not toggled,
    // TS 38.321 §5.3.2): the gNB is only retransmitting because our ACK didn't land.
    // ACK straight from the DCI — skip the PDSCH demod + LDPC entirely. This collapses
    // a retx storm at its source: each flood slot costs ~120µs of PDCCH search instead
    // of a full decode, so the worker keeps up and every ACK lands inside its k1 window
    // (without this, a burst of retx saturates the depth-1 job queue → dropped slots →
    // more DTX → more retx — the self-sustaining storm that wedged the NAS attach).
    let diag = std::env::var_os("FERRITE_DRIFT").is_some();
    // ONLY under backlog: with worker headroom, decode the retx fully instead. The
    // (h_id, NDI) match is ambiguous — if we silently missed an entire TB generation
    // on this process, a NEW TB reuses the recorded NDI value and a blind ACK here
    // swallows it unseen (observed live: the post-SMC SecurityModeCommand blind-ACKed
    // 5 times → never delivered → the gNB declared the UE lost). A full decode of a
    // true retx costs ~300µs we have; of a misclassified new TB, it DELIVERS it.
    if backlog {
        if let [(.., k1, dai, _, h_id, _, ndi)] = allocs[..] {
            if h_id != 0xff && harq_done.get(&h_id) == Some(&ndi) {
                if diag {
                    eprintln!("[dl] slot={slot_idx} h{h_id}/n{ndi} k1={k1} blind-ACK (retx of delivered TB)");
                }
                return (Some(DlDecoded { k1, dai, bytes: Vec::new(), deliver: false }), None);
            }
        }
    }
    // Nothing to do this slot: no DL assignment, no fallback guesses, and no CSI-RS
    // occasion to measure (slots 2-4) → skip the full-slot OFDM demod entirely.
    if allocs.is_empty() && !matches!(slot_idx, 2..=4) {
        // Diagnostic (FERRITE_DRIFT): a PDSCH with no DCI found means T0's blind search
        // missed it — probe cheaply and dump the first such slot for offline analysis.
        if diag && slot_idx != 1 && !std::path::Path::new("/tmp/ferrite_nodci.bin").exists() {
            if let Some(grids) = demod_slot(ofdm, fsh, 0, slot_idx as usize % 2, 1) {
                let probe = PdschAlloc { rb_start: 0, n_rb: 2, sym_start: 2, n_sym: 6, dmrs_symbols: vec![2, 7], qm: 2, n_bwp: 0, nof_cdm_groups: 1 };
                if extract_pdsch(&grids, sc_to_bin, &probe, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric > 0.9 {
                    eprintln!("[dl] slot={slot_idx} PDSCH present, NO DCI FOUND — dumping /tmp/ferrite_nodci.bin");
                    let mut b = Vec::with_capacity(36 + fsh.len() * 8);
                    for v in [slot_idx, crnti as u32, 0, 0, 0, 0, 0, 0, sc_to_bin(0) as u32] {
                        b.extend_from_slice(&v.to_le_bytes());
                    }
                    for s in fsh { b.extend_from_slice(&s.re.to_le_bytes()); b.extend_from_slice(&s.im.to_le_bytes()); }
                    let _ = std::fs::write("/tmp/ferrite_nodci.bin", &b);
                }
            }
        }
        return (None, None);
    }
    let t_ds = std::time::Instant::now();
    let grids = demod_slot(ofdm, fsh, 0, slot_idx as usize % 2, 1);
    PERF_DEMOD_NS.fetch_add(t_ds.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    let Some(grids) = grids else {
        return (None, None);
    };
    let t_pdsch = std::time::Instant::now();
    // NZP-CSI-RS (TRS) measurement → wideband CQI, at the config's TRS instances (a high
    // SINR gates it, no SFN tracking needed). Only the density-3 row-1 TRS combs anchor
    // the CSI frame parity — a single-RE row mixes PDSCH data into the measurement and
    // can't be trusted as a detector.
    let mut cqi = None;
    let mut rm_csi = false;
    if csi_rm().has_slot(slot_idx) {
        if let Some(&(_, sym, k0)) = csi_rm().meas.iter().find(|m| m.0 == slot_idx) {
            let sinr = ferrite_phy::csi::measure_csi_rs_sinr(&grids[sym], |sc: usize| sc_to_bin(sc as i32), cell_id, slot_idx, sym as u32, carrier_rb, k0);
            if sinr > 15.0 {
                cqi = Some(ferrite_phy::csi::sinr_to_cqi(sinr));
                *csi_parity = Some(frame_even);
            }
        }
        // PDSCH in a CSI-RS slot of a CSI frame is rate-matched around the CSI-RS REs.
        rm_csi = csi_parity.is_some_and(|p| p == frame_even);
    }
    // Cheap presence gate: every connected DL PDSCH starts at RB 0. Probe with the DM-RS
    // symbol COMMON to every type-A shape (the front-loaded l0 = 2 — additional positions
    // move with the allocation length, e.g. {2,7} vs {2,6,9}) so any shape still passes.
    let present = extract_pdsch(&grids, sc_to_bin, &PdschAlloc { rb_start: 0, n_rb: 2, sym_start: 2, n_sym: 6, dmrs_symbols: vec![2], qm: 2, n_bwp: 0, nof_cdm_groups: 1 }, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric > 0.9;
    if !present {
        if diag && !allocs.is_empty() {
            let (rb0, nrb, _, _, _, rv, h_id, sliv, ndi) = allocs[0];
            eprintln!("[dl] slot={slot_idx} h{h_id}/n{ndi} rv={rv} rb[{rb0},{}) sliv={sliv} PRESENT-GATE FAIL", rb0 + nrb);
        }
        PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        return (None, cqi);
    }
    if allocs.len() == 1 {
        // Steady state (a DCI decoded): one allocation — probe, then decode with the layout
        // sweep parallelized inside try_decode_dl_srb1 (HARQ combining included).
        let (rb0, nrb, mcs, k1, dai, rv, h_id, sliv, ndi) = allocs[0];
        // First sight of a new TB (NDI toggled or unknown process) → record its shape;
        // NDI unchanged → a retransmission: TBS follows the RECORDED initial shape (the
        // gNB adapts MCS down after a NACK but the TB keeps its size — recomputing TBS
        // from the retx DCI made every adapted retx undecodable and storms unrecoverable).
        let mut tb_shape = (mcs, nrb, sliv);
        let mut is_retx = false;
        if h_id != 0xff {
            match harq_init.get(&h_id) {
                Some(&(i_ndi, i_mcs, i_nrb, i_sliv)) if i_ndi == ndi => {
                    is_retx = true;
                    tb_shape = (i_mcs, i_nrb, i_sliv);
                }
                _ => {
                    harq_init.insert(h_id, (ndi, mcs, nrb, sliv));
                }
            }
        }
        let (qm, _) = mcs_params(mcs);
        let (p_start, p_nsym, p_dmrs) = dl_pdsch_shape(sliv);
        let probe = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: p_start, n_sym: p_nsym, dmrs_symbols: p_dmrs, qm: qm as usize, n_bwp: 0, nof_cdm_groups: 1 };
        if extract_pdsch(&grids, sc_to_bin, &probe, cell_id, slot_idx, 0, 0, cell_id, false).dmrs_metric > 0.9 {
            if let Some((tb, deliver, shape_used)) = try_decode_dl_srb1(&grids, sc_to_bin, cell_id, slot_idx, crnti, rb0, nrb, mcs, rv, h_id, sliv, rm_csi, tb_shape, is_retx, tf_hint, *init_mcs_typ, dl_dmrs_lock, harq_dl) {
                if h_id != 0xff {
                    // Mark (h_id, NDI) delivered so its retransmissions ACK without decode,
                    // and record the shape that actually decoded (the hypothesis may have
                    // corrected a wrong first-sight-at-retx shape).
                    harq_done.insert(h_id, ndi);
                    harq_init.insert(h_id, (ndi, shape_used.0, shape_used.1, shape_used.2));
                    // Learn the gNB's first-transmission MCS from genuine first decodes.
                    if !is_retx && shape_used == tb_shape && mcs >= 4 {
                        *init_mcs_typ = mcs;
                    }
                }
                PERF_PDSCH_NS.fetch_add(t_pdsch.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                return (Some(DlDecoded { k1, dai, bytes: tb, deliver }), cqi);
            } else if diag {
                eprintln!("[dl] slot={slot_idx} h{h_id}/n{ndi} rv={rv} rb[{rb0},{}) mcs={mcs} sliv={sliv} DECODE FAIL", rb0 + nrb);
                // One-shot: dump the failing slot's samples + params for offline analysis
                // (crates/ferrite-ue/src/bin — the pdsch_fail tool).
                if !std::path::Path::new("/tmp/ferrite_fail.bin").exists() {
                    let mut b = Vec::with_capacity(28 + fsh.len() * 8);
                    for v in [slot_idx, crnti as u32, rb0 as u32, nrb as u32, mcs as u32, rv as u32, h_id as u32, u32::from(sliv), sc_to_bin(0) as u32] {
                        b.extend_from_slice(&v.to_le_bytes());
                    }
                    for s in fsh { b.extend_from_slice(&s.re.to_le_bytes()); b.extend_from_slice(&s.im.to_le_bytes()); }
                    let _ = std::fs::write("/tmp/ferrite_fail.bin", &b);
                    eprintln!("[dl] dumped failing slot to /tmp/ferrite_fail.bin");
                }
            }
        } else if diag {
            eprintln!("[dl] slot={slot_idx} h{h_id}/n{ndi} rv={rv} rb[{rb0},{}) sliv={sliv} PROBE FAIL", rb0 + nrb);
        }
    } else {
        if diag && allocs.is_empty() {
            eprintln!("[dl] slot={slot_idx} PDSCH present, NO DCI FOUND");
        }
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
            let (_llr, _tbs, tb) = pdsch_standalone(&grids, sc_to_bin, cell_id, slot_idx, crnti, rb0, nrb, qm as usize, r, 0, cdm, tf, SLIV_FULL, rm_csi, (mcs, nrb, SLIV_FULL));
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
    // Initial DL/UL BWP (= carrier) RB count and the gNB's auto-selected PRACH RB
    // offset (msg1-FrequencyStart), keyed by the FFT (= channel bandwidth) at µ=1 /
    // 30 kHz SCS. CORESET0 stays 24 RB either way (it comes from the MIB index); this
    // is the WIDER connected-mode BWP, used for the DCI RIV decode and PUCCH/PUSCH/CSI.
    // 10 MHz → 24 RB / PRACH start 5; 20 MHz → 51 RB / PRACH start 11.
    let (carrier_rb, msg1_freq_start) = match fft {
        1024 => (51usize, 11usize),
        _ => (24usize, 5usize),
    };

    // PRACH preamble waveform. Sample counts (FFT, CP) scale with the sample rate;
    // k_start = 12·msg1-FrequencyStart + k_bar (k_bar = 2 for the short L_ra=139
    // formats) = the PRACH's first occupied subcarrier in the initial UL BWP grid.
    let scale = (fft / 512) as i64;
    // DCI type-1 frequency-domain RIV field width for the initial UL BWP (TS 38.212
    // §7.3.1.1): ceil(log2(N·(N+1)/2)). 9 bits at 24 RB (10 MHz), 11 at 51 RB (20 MHz).
    // The fallback DCI 0_0's frequency field (and thus every field after it) widens with
    // the BWP, so it can't be hardcoded to 9.
    let ul_freq_bits = (0usize..).find(|&b| (1usize << b) >= carrier_rb * (carrier_rb + 1) / 2).unwrap();
    // Timing-advance command T_A → uplink samples: N_TA = T_A · 16 · 64 / 2^µ · T_c,
    // which at µ=1 is T_A · 4 samples at 15.36 MHz and scales with the sample rate.
    let ta_samp = 4 * scale;
    let x_uv = prach_preamble_seq(1, preamble, prach_ncs_unrestricted(PrachScs::Short, 0).unwrap(), PrachSeqLen::Short);
    let occ = PrachOccasion { fft_size: fft, grid_size: carrier_rb * 12, k_start: 12 * msg1_freq_start + 2, cp_samples: 310 * fft / 512, nof_symbols: 1 };
    let mut prach = prach_occasion_waveform(&x_uv, &occ);
    let peak = prach.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
    for s in &mut prach {
        *s *= amp / peak;
    }
    let prach_len = prach.len() as i64;
    let occ_off = (fs * 9.5e-3).round() as i64 + ((44 + 512) + (36 + 512)) * scale;

    let block_len = 1920usize;
    let slot_len = (frame_len / 20) as i64;
    let mut ul = ZmqSink::bind(&rx, fs, block_len).expect("bind UL");
    let mut dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");
    let mut ul_counter = 0u64;
    let mut blk = vec![Complex32::default(); block_len];

    let fill_dl = |dl: &mut ZmqSource, blk: &mut [Complex32]| {
        let mut got = 0;
        while got < blk.len() {
            // The ZMQ DL socket is non-blocking: at startup the gNB may not be producing yet
            // (EAGAIN). Retry rather than panic — this setup read races the gNB coming up, and a
            // hard `.expect` here was an intermittent attach failure (panic "dl read: EAGAIN").
            match dl.read(&mut blk[got..]) {
                Ok(n) => got += n,
                Err(_) => std::thread::sleep(std::time::Duration::from_micros(50)),
            }
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
        // position the radio hasn't served yet); NEGATIVE lead gates the serve BEHIND T0,
        // handing that many extra slots of margin to every ACK/PUSCH the pipeline produces.
        // Default -2: the ZMQ-lockstep gNB tolerates the serve trailing (its rx_to_tx window
        // exists for exactly this), and the 2-slot cushion absorbs the decode+drain jitter
        // that otherwise put k1=4 HARQ-ACKs behind the served position under load (verified:
        // late(missed-window) fell from ~100-200 per attach to 0). Positive values re-tighten.
        let lead: i64 = std::env::var("FERRITE_LEAD").ok().and_then(|v| v.parse().ok()).unwrap_or(-2) * slot_len;
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
    // The measured wideband CQI + the slot position it drained at: CSI-report occasions
    // share the CSI-RS's 40-slot grid, so a measurement is only a valid "this frame is
    // a report occasion" witness within its own frame (~17 slots). A stale value
    // leaking into an off-parity frame made the UE multiplex CSI onto a PUSCH whose
    // grant reserved no CSI REs — data-E mismatch, crc=KO at full SNR.
    let mut pending_cqi: Option<(u8, i64)> = None;
    // Dynamic HARQ-ACK codebook: accumulate per UL-slot ACK bits keyed by the ABSOLUTE
    // UL SLOT INDEX (slot_start_ul / slot_len + k1); each entry holds (slot-in-frame,
    // [ACK bit per C-DAI 0..3]). Several DL PDSCHs (e.g. the two segments of one DL SDU)
    // map to the SAME UL slot and must be bundled into one 1-2 bit PUCCH, ordered by DAI
    // — else the gNB (which expects harq_bit_len bits) can't read the ACK and stalls the
    // DL HARQ. Keyed by the NEAREST-SLOT ROUNDING of the position, `(pos + slot_len/2)
    // div slot_len`, NOT the exact position: the position includes `- last_ta*4`, so a
    // TA command landing between the ACK's insertion and the PUSCH grant's lookup
    // shifted the two computed positions apart (±tens of samples) — the UCI mux missed
    // the entry (NACK muxed), the orphaned ACK then modulated as a standalone PUCCH F1
    // overlapping the PUSCH's slot, and the two waveforms collided in the injection
    // table (gNB: the recurring first-PUSCH sinr −24 dB crc=KO that burned an RLC
    // recovery round out of the 3 s registration budget). Rounding at every site makes
    // the keys agree by construction (the wobble is ≪ half a slot); slot-index
    // arithmetic does NOT work here — the slot_idx and slot_start_ul streams are
    // phase-offset, so index-derived keys disagreed by one between sites. The entry
    // stores its insert-time position (a ±20-sample TA skew is well inside the CP).
    let mut ack_book: std::collections::HashMap<i64, (u32, i64, [Option<u8>; 4])> = std::collections::HashMap::new();
    // The PUCCH-resource-indicator of the last DL DCI targeting each ACK slot (same
    // nearest-slot key as ack_book): picks the set-1 F2 resource when that slot's
    // HARQ-ACK codebook exceeds 2 bits (TS 38.213 §9.2.3). Recorded at the DCI parse
    // (T0 owns both); pruned alongside the books.
    let mut pri_book: std::collections::HashMap<i64, u8> = std::collections::HashMap::new();
    // Absolute UL slots whose UCI a PUSCH has already claimed — an ACK draining later
    // for such a slot must be dropped, not sent as a standalone (colliding) PUCCH.
    let mut uci_claimed: VecDeque<i64> = VecDeque::new();
    // A UL grant decoded this slot, modulated only AFTER the DL decode so a HARQ-ACK
    // whose UL slot coincides with this PUSCH can be multiplexed onto it (UCI-on-PUSCH)
    // instead of a PUCCH: (UL pos, PUSCH slot, rate-matched UL-SCH, alloc, TB bits,
    // UL T-DAI). The T-DAI is Some(0..=3) for a DCI 0_1 grant (it carries the 2-bit
    // total-DAI that sizes the UCI HARQ-ACK codebook even if the UE dropped the PDSCH),
    // None for a DCI 0_0 fallback grant (no DAI field).
    let mut pending_pusch: Option<(i64, i64, Vec<u8>, PuschAlloc, usize, Option<u8>, Vec<u8>, Vec<(usize, usize)>)> = None;
    // UL HARQ awareness: h_id → (NDI, TBS bytes, MAC PDU) of the last transport block
    // sent on that process. A grant whose NDI is UNCHANGED (and TBS matches) is a
    // retransmission request — the gNB soft-combines it with its stored LLRs, so the UE
    // must resend the SAME bits (rate-matched at the grant's rv), not the next queued
    // content. Sending fresh content on a retx grant poisons the process: the combined
    // buffer decodes to garbage at any SNR until the gNB gives up (seen as an unbounded
    // crc=KO chain on one h_id under the warm-grant load).
    let mut ul_harq: std::collections::HashMap<u8, (u8, usize, Vec<u8>)> = std::collections::HashMap::new();
    let pucch_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 23, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 0, occ_index: 0, n_id: acq.cell_id, carrier_rb,
    };
    // Connected-mode HARQ-ACK uses the DEDICATED PUCCH F1 resource: prb0, cs0,
    // occ0, symb[0,14), NO intra-slot hop (prb2=prb1) — unlike the common Msg4
    // resource above which hops to prb23.
    let mut harq_cfg = ferrite_phy::pucch::PucchF1 {
        prb1: 0, prb2: 0, start_symbol: 0, nof_symbols: 14,
        init_cyclic_shift: 0, occ_index: 0, n_id: acq.cell_id, carrier_rb,
    };
    // SR PUCCH resource. The hardcode is the 10 MHz auto-config (PRB 0, cs 6, occ 3);
    // it is overwritten from the parsed masterCellGroup SR resource at the Msg4 win,
    // which matters on the wider 20 MHz BWP (full-width PUCCH layout puts the SR at
    // e.g. PRB 4, cs 0, occ 0). A positive SR = tx this (d=1).
    let mut sr_cfg = ferrite_phy::pucch::PucchF1 {
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
            // Warm-up: fault in the modulator paths (FFT plans, gold sequences, buffers)
            // before the first real request — a cold first PUSCH modulate arrived at the
            // injection table after the radio had begun serving its block, so the gNB saw
            // a partial waveform (sinr −24 dB → crc=KO) and the lost RLC STATUS cost an
            // RLC recovery round out of the AMF's 3 s registration budget, every attach.
            {
                let walloc = PuschAlloc { rb_start: 0, n_rb: 4, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb, crb_offset: 0 };
                let wul = dlsch_encode_single(&vec![0u8; 256], pusch_e_len(&walloc), 0.245, 2, 0);
                let _ = ferrite_phy::pusch::pusch_modulate_slot_uci(&ofdm, &wul, &walloc, cell_id, 19, 1, 0x4601, center_hz, fs, &[1], 20.0, 256);
                let _ = ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &harq_cfg_t, &[1], 7, center_hz, fs);
                let wf2 = ferrite_phy::pucch::PucchF2 { prb_start: 23, nof_prb: 1, start_symbol: 0, nof_symbols: 2, rnti: 0x4601, n_id: cell_id, n_id0: cell_id, carrier_rb };
                let _ = ferrite_phy::pucch::pucch_f2_modulate_slot(&ofdm, &wf2, &[1, 0, 1, 0], 8, center_hz, fs);
            }
            while let Ok(req) = tx_req_rx.recv() {
                let (mut wave, pos, now, tag) = match req {
                    TxReq::PucchF1 { harq, bits, slot_mod20, pos, now } => {
                        let cfg = if harq { &harq_cfg_t } else { &sr_cfg_t };
                        (ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, cfg, &bits, slot_mod20, center_hz, fs), pos, now, "tx-pucch1")
                    }
                    TxReq::PucchF2 { cfg, bits, slot_mod20, pos, now } => {
                        (ferrite_phy::pucch::pucch_f2_modulate_slot(&ofdm, &cfg, &bits, slot_mod20, center_hz, fs), pos, now, "tx-csi")
                    }
                    TxReq::Pusch { ulsch, alloc, slot_mod20, slot_parity, crnti, ack, beta, tb_bits, pos, now, csi, csi_res } => {
                        (ferrite_phy::pusch::pusch_modulate_slot_uci_csi(&ofdm, &ulsch, &alloc, cell_id, slot_mod20, slot_parity, crnti, center_hz, fs, &ack, beta, tb_bits, &csi, &csi_res), pos, now, "pusch")
                    }
                };
                norm(&mut wave);
                inj_t.lock().unwrap().push(ReadyWaveform { pos, samples: wave, tag }, now);
            }
        }).expect("spawn txbuild thread");
    }

    // Cell timing configuration from SIB1, decoded live during the RA phase: the TDD
    // UL/DL pattern drives the slot gates (DL dispatch, Msg4 monitoring, PUCCH slot
    // choice) and the pusch-TimeDomainAllocationList maps each UL grant's TDRA field
    // to its k2. Until SIB1 parses (or if an exotic cell defeats the parser), the
    // `map_or` fallbacks at each use site keep the transcribed bring-up constants.
    let mut sib1_cfg: Option<ferrite_ue::sib1::Sib1Params> = None;
    // Dedicated config from the RRCSetup masterCellGroup (parsed at the Msg4 win):
    // the k1 (dl-DataToUL-ACK) list, the DCI 0_1/1_1 field geometry, the SR and
    // CSI-report occasions and the CSI-RS rate-match pattern. Same fallback rule
    // as sib1_cfg: every use site keeps the transcribed constant when None.
    let mut cg_cfg: Option<ferrite_ue::cellgroup::CellGroupParams> = None;
    // Once contention resolution is won, drive the connected UE: send an SR to
    // request a grant for Msg5 (RRCSetupComplete). Stop new RA once connected.
    let mut connected: Option<u16> = None;
    // The cell-fixed data RE-mapping order (time-first) proven by the Msg4 decode —
    // seeds the worker's DM-RS layout sweep so its first connected decode doesn't
    // burn the full 4-layout cold sweep (~2 ms → 3-4 dropped slots right at the
    // Auth-Request burst, whose lost initial DCIs made the retx storm unrecoverable).
    let mut msg4_tf: Option<bool> = None;
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
    // Built-in ping as an RTT probe: send times per seq, and the 1 Hz send gate.
    let mut ping_sent_at: Vec<std::time::Instant> = Vec::new();
    let mut next_ping_at = std::time::Instant::now();
    // Warm-grant window: while user-plane traffic is active (a packet moved within
    // the last second), idle grants report a small non-zero BSR instead of 0, so the
    // gNB keeps granting every UL occasion and the next packet rides an
    // already-issued grant (~k2 + pipeline) instead of paying the SR round-trip
    // (up to a full SR period + grant latency). Padding fills do NOT refresh the
    // window, so an idle UE goes quiet after 1 s.
    let mut last_up_activity = std::time::Instant::now() - std::time::Duration::from_secs(60);
    let up_active = |t: &std::time::Instant| t.elapsed() < std::time::Duration::from_secs(1);
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
    // Job queue depth 2. The queue depth adds to the decode→ACK pipeline lag, which must
    // beat the gNB's MINIMUM k1 (=4) — at ~500µs/job (decode incl. its own DCI search) each
    // queue level cost a FULL slot of lag, so depth 2 put k1=4/5 ACKs behind the serving
    // position (~25-50% late) and depth had to stay 1. NOW a job is ~26µs steady / ~300µs
    // under a retx flood (T0's search result rides in the DlJob; retx blind-ACK / combine-
    // only paths), so a queued job adds ~0.3 slots — and the depth-2 slack is what absorbs
    // the attach-phase DL burst (7 fresh pre-lock decodes back to back at ~600µs each),
    // whose depth-1 drops lost initial DCIs, corrupted the shared UL-slot ACK bundles, and
    // piled the codebook into PUCCH-F2 territory the UE can't transmit (the storm seed).
    let (dl_job_tx, dl_job_rx) = ferrite_ue::rt::bounded::<DlJob>(2);
    let (dl_res_tx, dl_res_rx) = ferrite_ue::rt::bounded::<DlResult>(8);
    {
        let (w_cell, w_carrier, w_alen, w_firstsc) = (acq.cell_id, carrier_rb, a_len, first_sc);
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
                let mut harq_done: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
                let mut harq_init: std::collections::HashMap<u8, (u8, u8, usize, u8)> = std::collections::HashMap::new();
                let mut csi_parity: Option<bool> = None;
                let mut init_mcs_typ: u8 = 9; // the gNB's observed first-tx MCS at top CQI
                let mut dl_dmrs_lock: Option<(usize, bool)> = None;
                // Warm-up: fault in the whole decode path (LDPC lifting tables, FFT plans,
                // channel-estimate/equalize buffers, allocator arenas, the pool's threads)
                // before the first real job — the first cold decode measured ~2.2 ms (4+
                // slots), which dropped the next slots' jobs right at the start of the NAS
                // phase and could seed a retx storm. Zero-LLR blocks exercise the BG2
                // (small-TB) and BG1 (wide-band) LDPC paths to a CRC fail; full decode_dl
                // passes on noise slots exercise the OFDM demod + blind DCI search + probes.
                {
                    use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
                    let t = std::time::Instant::now();
                    pool.install(|| {
                        use rayon::prelude::*;
                        [(3000usize, 800usize), (13000, 6200)].par_iter().for_each(|&(n, tbs)| {
                            let _ = dlsch_decode_single_bits(&vec![0.1f32; n], tbs, 0.5, 2, 0, 10);
                        });
                    });
                    // The polar (DCI) decoder never runs on noise slots — the DM-RS coherence
                    // gate filters noise candidates first — so warm it directly at every
                    // aggregation-level LLR length and payload size used live.
                    for e_llr in [108usize, 216, 432, 864] {
                        for a in [w_alen, 36, 40] {
                            let _ = dci_decode(&vec![0.1f32; e_llr], 0x4601, a);
                        }
                    }
                    let slot_samples: usize = (0..14).map(|l| ofdm.cp_len(l, 1) + fft).sum();
                    let mut seed = 0x2545f491u32;
                    let noise: Vec<Complex32> = (0..slot_samples).map(|_| {
                        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                        Complex32::new((seed >> 16) as f32 / 65536.0 - 0.5, (seed & 0xffff) as f32 / 65536.0 - 0.5) * 0.02
                    }).collect();
                    for warm_slot in [2u32, 7, 11] {
                        let _ = pool.install(|| decode_dl(&noise, &ofdm, w_cell, w_carrier, sc_to_bin, 0x4601, warm_slot, None, &mut harq_dl, &mut harq_done, &mut harq_init, true, &mut csi_parity, None, &mut init_mcs_typ, &mut dl_dmrs_lock, false));
                    }
                    // The gates above never reach the real PDSCH path on noise (no DCI, no
                    // DM-RS), so run pdsch_standalone directly at the shapes the attach
                    // actually sees — faulting in extract_pdsch's channel-estimate buffers,
                    // the DM-RS gold sequences, and the LDPC lifting tables at the REAL
                    // block sizes (they're per-Z: warming one TBS leaves the others cold —
                    // the first live decode still measured ~1.9 ms before this).
                    if let Some(grids) = demod_slot(&ofdm, &noise, 0, 0, 1) {
                        pool.install(|| {
                            use rayon::prelude::*;
                            let shapes: Vec<(usize, u8, usize)> = [(21usize, 9u8), (4, 9), (24, 16), (2, 2), (13, 9)]
                                .iter().flat_map(|&(nrb, mcs)| [(nrb, mcs, 1usize), (nrb, mcs, 2)]).collect();
                            shapes.par_iter().for_each(|&(nrb, mcs, cdm)| {
                                let (qm, r) = mcs_params(mcs);
                                let _ = pdsch_standalone(&grids, sc_to_bin, w_cell, 2, 0x4601, 0, nrb, qm as usize, r, 0, cdm, true, SLIV_FULL, false, (mcs, nrb, SLIV_FULL));
                            });
                        });
                    }
                    // The warm-up must leave no decode state behind.
                    harq_dl.clear();
                    harq_done.clear();
                    harq_init.clear();
                    csi_parity = None;
                    dl_dmrs_lock = None;
                    if std::env::var_os("FERRITE_PERF").is_some() {
                        eprintln!("[perf-ue-rxphy] decoder warm-up: {:.1} ms", t.elapsed().as_secs_f64() * 1e3);
                    }
                }
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
                    let DlJob { slot_idx, slot_start_ul, frame_even, crnti, dl_dci, tf_hint, fsh } = job;
                    let t = std::time::Instant::now();
                    let backlog = !dl_job_rx.is_empty(); // jobs waiting → shed the opportunistic work
                    let (decoded, cqi) = pool.install(|| decode_dl(&fsh, &ofdm, w_cell, w_carrier, sc_to_bin, crnti, slot_idx, dl_dci, &mut harq_dl, &mut harq_done, &mut harq_init, frame_even, &mut csi_parity, tf_hint, &mut init_mcs_typ, &mut dl_dmrs_lock, backlog));
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
    // Pace T0's slot consumption to real time (matches the radio thread's UL pace). The DL
    // read-ahead buffer lets T0 burn through several buffered slots back-to-back; when it does,
    // its slot clock (and the gated UL serve) race ~2-3 slots ahead of the decode→ACK pipeline,
    // so the HARQ-ACK for the slot just decoded is already at/behind the served position — fatal
    // for the gNB's minimum k1=4. Pacing T0 keeps its clock with the worker (the buffer still
    // absorbs the gNB's production jitter), so the ACK is produced ~2 slots ahead of serving.
    let mut t0_start = std::time::Instant::now();
    let mut t0_n = 0u64;
    let t0_pace: f64 = std::env::var("FERRITE_PACE_US").ok().and_then(|v| v.parse().ok()).unwrap_or(500.0) * 1e-6;

    // Precomputed-phasor mixer for the per-slot DL frequency shift (the constant
    // −df to baseband the SSB). Vectorises the hot path that the serial recurrence
    // of `freq_shift` could not — the dominant T0 cost at 20 MHz (~400 µs → ~100 µs).
    let fsh_shifter = ferrite_ue::sync::FreqShifter::new(-df, fs, slot_len as usize);
    let mut fsh: Vec<Complex32> = Vec::with_capacity(slot_len as usize);

    loop {
        if perf_pad_us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(perf_pad_us));
        }
        // Real-time pace: never run T0's slot clock ahead of wall-clock (see above).
        if connected.is_some() {
            let target = std::time::Duration::from_secs_f64(t0_n as f64 * t0_pace);
            let el = t0_start.elapsed();
            if el < target {
                std::thread::sleep(target - el);
            } else if el > target + std::time::Duration::from_secs_f64(t0_pace) {
                // Behind by more than a slot (a slow iteration: UL-SCH encode, NAS crypto,
                // a print). Do NOT sprint to catch up — back-to-back iterations dispatch
                // back-to-back DL jobs, overflow the depth-1 worker queue, and the dropped
                // slots corrupt their shared UL-slot ACK bundles (→ retx storm). Re-anchor
                // the pace baseline instead: the wall clock slips by the deficit, which the
                // ZMQ-lockstep gNB (throttled by our reads/serves) absorbs harmlessly.
                t0_start = std::time::Instant::now();
                t0_n = 0;
            }
            t0_n += 1;
        } else {
            // During RA/attach run free (the timing sweep needs to iterate fast); keep the pace
            // baseline fresh so it starts from zero at the first connected slot.
            t0_start = std::time::Instant::now();
            t0_n = 0;
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
                    Ok(n) if n > 0 => {
                        tun_ul.push_back(buf[..n].to_vec());
                        last_up_activity = std::time::Instant::now();
                    }
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
        fsh_shifter.shift_into(&slot_buf, slot_start_ul as usize, &mut fsh);
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
        // DCI 0_0 (37b) and 0_1 share their leading fields — id(1) freq-RIV
        // (9,N=24) time(4) hop(1) mcs(5) ndi(1) — so one parser handles both; only
        // the payload size and the search space differ. CORESET1 spans the whole
        // BWP (CRB0-23) like CORESET0 here, so it reuses cgrids/sc_to_bin.
        //
        // DCI 0_1/1_1 field geometry derives from the configured lists (TS 38.212
        // §7.3.1): the TDRA field is ceil(log2(rows)) bits over the dedicated TDRA
        // list when present, else the SIB1 common one; the PDSCH-to-HARQ-timing
        // field is ceil(log2(len(dl-DataToUL-ACK))). Every field after the TDRA
        // shifts with its width, and the total payload sizes gate the blind decode
        // — THE thing that breaks on a different TDD pattern with transcribed
        // constants. Fallback = this bring-up cell's geometry (3-bit UL TDRA,
        // 1-bit DL TDRA, 3-bit k1 → 36/40 bits).
        let bitw = |n: usize| (usize::BITS - (n.max(2) - 1).leading_zeros()) as usize;
        let w_ul = cg_cfg.as_ref().map(|c| c.pusch_tdra.len()).filter(|&n| n > 0)
            .or_else(|| sib1_cfg.as_ref().map(|s| s.pusch_tdra.len()).filter(|&n| n > 0))
            .map_or(3, bitw);
        let w_dl = cg_cfg.as_ref().map(|c| c.pdsch_tdra.len()).filter(|&n| n > 0)
            .or_else(|| sib1_cfg.as_ref().map(|s| s.pdsch_tdra.len()).filter(|&n| n > 0))
            .map_or(1, bitw);
        let w_k1 = cg_cfg.as_ref().map_or(3, |c| bitw(c.k1_list.len()));
        // Sizes generalise from the 10 MHz (24 RB → 9 freq bits) empirical widths by the
        // BWP-sized frequency field: 33+w_ul = 24 + 9 + w_ul, 36+w_dl+w_k1 = 27 + 9 + …
        let dci_0_1_size = 24 + ul_freq_bits + w_ul;
        let dci_1_1_size = 27 + ul_freq_bits + w_dl + w_k1;
        if std::env::var_os("FERRITE_DLDBG").is_some() && connected.is_some() && slot_idx == 0 {
            eprintln!("[dldbg] sizes: 0_0(a_len)={a_len} 0_1={dci_0_1_size} 1_1={dci_1_1_size} ul_freq_bits={ul_freq_bits} w_ul={w_ul} w_dl={w_dl} w_k1={w_k1}");
        }
        // The SR / CSI-report occasion slots, from the parsed dedicated config; fallback =
        // the first/second-full-UL-slot heuristics, then the transcribed slots 7/8. (The
        // configured periods can be 40 slots; serving every frame is harmless — the gNB
        // simply doesn't monitor the off-period frames.) Hoisted here because the HARQ-ACK
        // drain below multiplexes SR/CSI onto a PUCCH F2 when the occasions coincide with
        // an ACK slot (routine on a TDD pattern with one UL slot, e.g. DDDSU).
        let sr_slot = cg_cfg
            .as_ref()
            .and_then(|c| c.sr)
            .map(|(_, o, _)| i64::from(o % 20))
            .or_else(|| sib1_cfg.as_ref().and_then(|s| (0..20).find(|&t| s.has_full_ul(t))).map(i64::from))
            .unwrap_or(7);
        // SR occasions repeat every `sr_period` slots (capped at the frame — a 40-slot
        // period served every frame just means the gNB ignores the off-parity ones).
        // A short configured period (e.g. 10 slots = 5 ms) gives several occasions per
        // frame; serving all of them is what cuts the idle-UE grant latency.
        let sr_period = cg_cfg.as_ref().and_then(|c| c.sr).map_or(20, |(p, _, _)| i64::from(p).min(20));
        let csi_slot = cg_cfg
            .as_ref()
            .and_then(|c| c.csi_report)
            .map(|(_, o, _)| i64::from(o % 20))
            .or_else(|| sib1_cfg.as_ref().and_then(|s| (0..20).filter(|&t| s.has_full_ul(t)).nth(1)).map(i64::from))
            .unwrap_or(8);
        // The DL assignment found by T0's blind search this slot, shipped to the RX-PHY
        // worker in its DlJob: (rb0, nrb, mcs, k1, C-DAI, rv, h_id, TDRA-row SLIV, ndi).
        let mut dl_dci: Option<(usize, usize, u8, u8, u8, u8, u8, u8, u8)> = None;
        if let Some(crnti) = connected {
            // ONE blind search covers BOTH directions: the UL grant (DCI 0_0/0_1, acted
            // on below — an unfilled grant decodes as noise (crc=KO) and a burst of KOs
            // collapses the gNB's UL MCS / trips RLF) and the DL assignment (DCI 1_0/1_1,
            // handed to the RX-PHY worker so it doesn't repeat this ~200µs search per
            // slot: under a retx flood that duplicate was the margin that pushed the
            // worker past the 500µs slot budget → dropped jobs → the flood fed itself).
            let mut ul_bits: Option<Vec<u8>> = None;
            {
                let bits5 = |b: &[u8], lo: usize, n: usize| b[lo..lo + n].iter().fold(0u8, |a, &x| a << 1 | x);
                // CORESET0 CSS (AL4 CCE0): fallback DCI 0_0 (UL) or 1_0 (DL).
                let c0 = Candidate { agg_level: 4, cces: (0..4).collect() };
                let mut m = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &c0);
                pdcch_descramble_llr(&mut m, u32::from(acq.cell_id));
                if let Some(b) = dci_decode(&m, crnti, a_len) {
                    if b[0] == 0 {
                        ul_bits = Some(b);
                    } else {
                        // DL 1_0: always the full [2,14) shape (4-bit default-table TDRA
                        // row 0 in this cell), k1 = 3-bit field + 1, NDI at b[20],
                        // PUCCH-resource-indicator (3 bits) at b[31..34].
                        let riv = b[1..10].iter().fold(0usize, |a, &x| a << 1 | x as usize);
                        let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
                        let k1 = bits5(&b, 34, 3) + 1;
                        let dai = bits5(&b, 27, 2);
                        let apos = slot_start_ul + k1 as i64 * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
                        let akey = (apos + slot_len / 2).div_euclid(slot_len);
                        pri_book.insert(akey, bits5(&b, 31, 3));
                        // Pre-book a NACK at this PDSCH's C-DAI position: if its decode
                        // fails (or drains too late), the occasion still transmits a
                        // correctly-sized codebook — the gNB reads total DTX (no PUCCH at
                        // all) as rv=0 forever, while a NACK keeps the other TBs' ACK
                        // positions aligned and lets rv cycle. The decode drain upgrades
                        // this entry to an ACK.
                        let e = ack_book.entry(akey).or_insert((((slot_idx as i64 + k1 as i64) % 20) as u32, apos, [None; 4]));
                        e.2[(dai & 3) as usize].get_or_insert(0);
                        dl_dci = Some((rb0, nrb, bits5(&b, 15, 5), k1, dai, bits5(&b, 21, 2), bits5(&b, 23, 4), SLIV_FULL, b[20]));
                    }
                }
                // CORESET1 USS sweep for whichever direction is still missing: DCI 0_1
                // (36 b, UL) and 1_1 (40 b, DL) on the same equalized candidate LLRs.
                // Coherence-gated; with CQI feedback the gNB uses AL1 at Y=0 CCEs the
                // rnti-hashed USS wouldn't cover, so all AL1/2/4/8 candidates are tried.
                if ul_bits.is_none() || dl_dci.is_none() {
                    let dbg_slot = std::env::var("FERRITE_DBG_T0SLOT").ok().and_then(|v| v.parse::<u32>().ok()) == Some(slot_idx);
                    let mut dbg_power = 0.0f32;
                    if dbg_slot {
                        dbg_power = cgrids.iter().flat_map(|g| g.iter()).map(|c| c.norm_sqr()).sum();
                        let pt: f32 = fsh.iter().map(|c| c.norm_sqr()).sum();
                        eprintln!("[t0dbg] slot={slot_idx} coreset-power={dbg_power:.1} slot-power={pt:.1}");
                    }
                    // CORESET1 geometry from the parsed dedicated config. The search
                    // originally assumed CORESET0's 24 RB / 2 symb / 8 CCE; at 20 MHz
                    // CORESET1 spans 48 RB (8 six-RB groups) → 16 CCE. n_cce =
                    // popcount·duration (= n_rb·n_symb/6, n_rb = popcount·6). It is
                    // contiguous from CRB 0 on both cells, so sc_to_bin and the DM-RS
                    // estimate over carrier_rb (a superset) are unchanged.
                    let (c1_n_symb, c1_n_cce) = cg_cfg.as_ref().map_or(
                        (coreset.n_symb, coreset.n_cce()),
                        |c| (c.coreset1_duration as usize,
                             c.coreset1_freq_bits.count_ones() as usize * c.coreset1_duration as usize));
                    let h_reg = estimate_coreset_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, c1_n_symb, acq.cell_id, slot_idx);
                    for cand in all_candidates(c1_n_cce, &[1, 2, 4, 8]) {
                        if ul_bits.is_some() && dl_dci.is_some() {
                            break;
                        }
                        let coh = coreset_candidate_coherence(&h_reg, &cand, c1_n_symb);
                        if dbg_slot {
                            eprintln!("[t0dbg] slot={slot_idx} cand al={} cce0={} coh={coh:.2}", cand.agg_level, cand.cces[0]);
                        }
                        // Coherence gate (skip equalize+decode for empty candidates). A
                        // real PDCCH reads ~1 on a narrow CORESET but lower on the wide
                        // 20 MHz CORESET1 (48 RB): the −df DL shift + residual timing put a
                        // phase ramp across the band, so the cross-REG coherence drops even
                        // though the per-RB equalizer still recovers the bits. 0.3 stays
                        // above the AL1 noise floor (~1/6) while catching those. Overridable.
                        let coh_gate: f32 = std::env::var("FERRITE_COHGATE").ok().and_then(|v| v.parse().ok()).unwrap_or(0.1);
                        if coh < coh_gate {
                            continue;
                        }
                        let mut mm = equalize_candidate_c1_cached(&cgrids, |sc: usize| sc_to_bin(sc as i32), c1_n_symb, &cand, &h_reg);
                        pdcch_descramble_llr(&mut mm, u32::from(acq.cell_id));
                        if ul_bits.is_none() {
                            if let Some(b) = dci_decode(&mm, crnti, dci_0_1_size).filter(|b| b[0] == 0) {
                                ul_bits = Some(b);
                                continue;
                            }
                        }
                        if dl_dci.is_none() {
                            if let Some(b) = dci_decode(&mm, crnti, dci_1_1_size).filter(|b| b[0] == 1) {
                                // DL 1_1 layout: id(1) fdra(9) tdra(w_dl) mcs(5) ndi(1)
                                // rv(2) harq(4) dai(2) tpc(2) pucch-res(3) k1(w_k1) —
                                // everything after bit 10 shifts with the TDRA width.
                                // The row's SLIV gives the time shape (a HARQ retx of a
                                // short-shape TB keeps the short row in normal slots);
                                // k1 indexes the dl-DataToUL-ACK list.
                                const K1_FB: [u8; 8] = [4, 5, 6, 7, 8, 9, 11, 12];
                                // DCI 1_1: id(1) freq(F) tdra(w_dl) mcs(5) ndi(1) rv(2)
                                // harq(4) dai(2) tpc(2) pucch-res(3) k1(w_k1). F = the
                                // BWP-sized freq field (9 bits @24 RB, 11 @51 RB), so every
                                // field is anchored at 1+F, not the hardcoded 10.
                                let f = ul_freq_bits;
                                let riv = b[1..1 + f].iter().fold(0usize, |a, &x| a << 1 | x as usize);
                                let (rb0, nrb) = riv_decode(riv, carrier_rb);
                                let row = b[1 + f..1 + f + w_dl].iter().fold(0usize, |a, &x| a << 1 | x as usize);
                                let k1_idx = bits5(&b, 20 + f + w_dl, w_k1) as usize;
                                let k1 = cg_cfg.as_ref().and_then(|c| c.k1_list.get(k1_idx)).copied()
                                    .unwrap_or(K1_FB[k1_idx & 7]);
                                let sliv = cg_cfg.as_ref().map(|c| &c.pdsch_tdra).filter(|l| !l.is_empty())
                                    .or_else(|| sib1_cfg.as_ref().map(|s| &s.pdsch_tdra))
                                    .and_then(|l| l.get(row))
                                    .map_or(if row == 1 { SLIV_SHORT } else { SLIV_FULL }, |r| r.sliv);
                                let apos = slot_start_ul + k1 as i64 * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
                                let akey = (apos + slot_len / 2).div_euclid(slot_len);
                                pri_book.insert(akey, bits5(&b, 17 + f + w_dl, 3));
                                let dai = bits5(&b, 13 + f + w_dl, 2);
                                // NACK pre-booking — see the DCI 1_0 site above.
                                let e = ack_book.entry(akey).or_insert((((slot_idx as i64 + k1 as i64) % 20) as u32, apos, [None; 4]));
                                e.2[(dai & 3) as usize].get_or_insert(0);
                                if std::env::var_os("FERRITE_DLDBG").is_some() {
                                    eprintln!("[dldbg] slot={slot_idx} DCI 1_1 found: rb[{rb0},{}) mcs={} k1={k1} sliv={sliv} ndi={}", rb0 + nrb, bits5(&b, 1 + f + w_dl, 5), b[6 + f + w_dl]);
                                }
                                dl_dci = Some((rb0, nrb, bits5(&b, 1 + f + w_dl, 5), k1, dai, bits5(&b, 7 + f + w_dl, 2), bits5(&b, 9 + f + w_dl, 4), sliv, b[6 + f + w_dl]));
                            }
                        }
                    }
                    if dbg_slot && dbg_power > 1.0 && ul_bits.is_none() && dl_dci.is_none()
                        && !std::path::Path::new("/tmp/ferrite_nodci.bin").exists()
                    {
                        eprintln!("[t0dbg] slot={slot_idx} POWER BUT NO DCI — dumping /tmp/ferrite_nodci.bin");
                        let mut bts = Vec::with_capacity(36 + fsh.len() * 8);
                        for v in [slot_idx, crnti as u32, 0, 0, 0, 0, 0, 0, sc_to_bin(0) as u32] {
                            bts.extend_from_slice(&v.to_le_bytes());
                        }
                        for sm in &fsh { bts.extend_from_slice(&sm.re.to_le_bytes()); bts.extend_from_slice(&sm.im.to_le_bytes()); }
                        let _ = std::fs::write("/tmp/ferrite_nodci.bin", &bts);
                    }
                }
            }
            // Fill the UL grant (queue-bounded: the gNB grants back-to-back to drain
            // a buffer, so keep a QUEUE of in-flight PUSCH bursts, not just one).
            if pend_ul.len() < 16 {
                if let Some(bits) = ul_bits {
                    // UL grant. Both formats share id(1) + FDRA(9, type-1 RIV/N=24)
                    // at bits[1..10]; after that DCI 0_0 has time(4)+hop(1) then MCS,
                    // while DCI 0_1 (this config) has only a 3-bit time field and no
                    // hop flag, so its MCS/NDI sit 2 bits earlier. Verified live vs the
                    // gNB's scheduled grant (MCS/RV/HARQ aligned).
                    {
                        let is_0_1 = bits.len() == dci_0_1_size;
                        // DCI 0_0: id(1) freq(F) time(4) hop(1) mcs(5)…; DCI 0_1:
                        // id(1) freq(F) tdra(w_ul) mcs(5)… — F = ul_freq_bits (BWP-sized).
                        let mcs_lo = if is_0_1 { 1 + ul_freq_bits + w_ul } else { 6 + ul_freq_bits };
                        let riv = bits[1..1 + ul_freq_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
                        let (g_rb0, g_nrb) = riv_decode(riv, carrier_rb);
                        let mcs = bits[mcs_lo..mcs_lo + 5].iter().fold(0u8, |a, &b| a << 1 | b);
                        let ndi = bits[mcs_lo + 5];
                        // rv(2) and harq-process(4) follow the NDI in both formats.
                        let g_rv = bits[mcs_lo + 6..mcs_lo + 8].iter().fold(0u8, |a, &b| a << 1 | b);
                        let g_hid = bits[mcs_lo + 8..mcs_lo + 12].iter().fold(0u8, |a, &b| a << 1 | b);
                        // DCI 0_1 layout: id(1) fdra(9) tdra(w_ul) mcs(5) ndi(1) rv(2)
                        // harq(4) → 1st-DAI (2 bits) at 22 + w_ul. This UL total-DAI
                        // = (HARQ-ACK bit count − 1) mod 4, so it lets us size the
                        // UCI-on-PUSCH codebook (below) from the grant itself — robust to
                        // a dropped DL PDSCH (we NACK-pad) instead of sizing purely from
                        // our own decode. DCI 0_0 has no DAI field. (Reading this at a
                        // fixed 25 on a 2-bit-TDRA cell grabbed [dai LSB, tpc] → phantom
                        // ACK bits punctured the PUSCH → every DRB PUSCH crc=KO at 50 dB.)
                        let t_dai: Option<u8> = is_0_1
                            .then(|| bits[13 + ul_freq_bits + w_ul..15 + ul_freq_bits + w_ul].iter().fold(0u8, |a, &b| a << 1 | b));
                        let (qm, r) = mcs_params(mcs);
                        // k2 from the DCI's TDRA field via the SIB1 pusch-TimeDomain-
                        // AllocationList (this cell: rows [4,5,6,7,11] — row 0's k2=4 is
                        // the old hardcoded constant; other rows appear when the granting
                        // DL slot sits further from the UL slots, and matter for any
                        // shorter TDD pattern). DCI 0_0 carries 4 TDRA bits, 0_1 w_ul.
                        let tdra_lo = 1 + ul_freq_bits;
                        let tdra_hi = if is_0_1 { tdra_lo + w_ul } else { tdra_lo + 4 };
                        let tdra = bits[tdra_lo..tdra_hi].iter().fold(0usize, |a, &b| a << 1 | b as usize);
                        let k2 = sib1_cfg.as_ref().map_or(4, |s| s.k2_for_row(tdra)) as i64;
                        let m5_slot = slot_idx as i64 + k2;
                        let n_data_sym = 14 - 3;
                        let e = g_nrb * 12 * n_data_sym * qm as usize;
                        let tbs = tbs_from_nre(g_nrb * 12 * n_data_sym, r, qm as usize);
                        let tbs_bytes = tbs / 8;
                        // The queued RRC PDU framed for SRB1 costs MAC(2)+RLC(2)+PDCP(2)
                        // +MAC-I(4) = 10 bytes of overhead. If it doesn't fit the grant
                        // (the gNB grants a minimal TB after an SR and waits for a BSR),
                        // send a Short BSR to solicit a larger grant instead.
                        // A PUSCH on a CSI-report occasion carries the CSI part 1
                        // (TS 38.212 §6.2.7): the gNB reserves Q'_CSI REs on it and
                        // rate-matches the UL-SCH around them. The occasion is EXACT in
                        // absolute (gNB SFN) slots: (SFN·20 + slot) mod period == offset.
                        // The UE knows the true SFN — the stream was frame-aligned to
                        // acq.next_sfn at slot 0 — so `csi_occasion` matches the gNB's
                        // reservation frame-for-frame. (Matching only slot-in-frame
                        // mod 20 fires on BOTH frame parities of the 40-slot grid; on the
                        // off parity the gNB reserves NO CSI REs (FAPI ocsi1=0) and the
                        // multiplexed CSI shifts the data → crc=KO at any SNR — that
                        // corrupted every off-parity AuthenticationResponse (re)tx →
                        // registration timeout.)
                        let pusch_abs_slot = slot_start_ul / slot_len + (m5_slot - slot_idx as i64);
                        let csi_occasion = cg_cfg.as_ref().and_then(|c| c.csi_report).is_some_and(|(p, o, _)| {
                            (acq.next_sfn as i64 * 20 + pusch_abs_slot).rem_euclid(p as i64) == o as i64
                        });
                        let csi_bits: Vec<u8> = if connected.is_some()
                            && csi_occasion
                            && pending_cqi.is_some()
                            && cg_cfg.as_ref().is_some_and(|c| c.beta_csi1_index.is_some())
                        {
                            let (cqi, _) = pending_cqi.take().unwrap();
                            vec![(cqi >> 3) & 1, (cqi >> 2) & 1, (cqi >> 1) & 1, cqi & 1]
                        } else {
                            Vec::new()
                        };
                        let beta_csi = cg_cfg.as_ref()
                            .and_then(|c| c.beta_csi1_index)
                            .map_or(6.25, ferrite_phy::pusch::beta_offset_csi);
                        let is_retx = ul_harq.get(&g_hid).is_some_and(|(n, t, _)| *n == ndi && *t == tbs_bytes);
                        let (mac, kind) = if is_retx {
                            // Retransmission grant: resend the process's stored TB at the
                            // grant's rv so the gNB's soft-combine converges.
                            (ul_harq[&g_hid].2.clone(), format!("UL retx h{g_hid} rv{g_rv}"))
                        } else if let Some(ack) = pending_status {
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
                            last_up_activity = std::time::Instant::now();
                            let remaining = pdcp.len() - off;
                            // Bytes queued behind this packet (each still needs PDCP+RLC+MAC).
                            let queued: usize = tun_ul.iter().map(|p| p.len() + 8).sum();
                            if tbs_bytes < remaining + 3 && tbs_bytes < 100 {
                                // Grant too small for meaningful progress → solicit a bigger one,
                                // reporting the WHOLE DRB buffer so the gNB grants enough at once.
                                um_tx = Some((pdcp, off, sn));
                                (mac_short_bsr((remaining + queued + 3).max(220), tbs_bytes), format!("DRB BSR (need {}B)", remaining + queued))
                            } else {
                                // Reserve 2 bytes for a piggyback BSR whenever more data remains
                                // (this packet's tail or other queued packets) so the gNB keeps
                                // granting continuously instead of one grant per SR/BSR round-trip.
                                let more = (remaining > tbs_bytes.saturating_sub(3)) || queued > 0 || !tun_ul.is_empty();
                                let rsv = if more { 5 } else { 3 }; // MAC subheader (3) + BSR (2)
                                let (rlc, new_off) = rlc_um_segment(&pdcp, off, sn, tbs_bytes.saturating_sub(rsv));
                                let after = pdcp.len() - new_off + queued; // total still buffered
                                let m = drb_mac_wrap_bsr(&rlc, if after > 0 { after + 3 } else { 0 }, tbs_bytes);
                                let s = format!("DRB UL {new_off}/{} B (sn {sn}, buf {after})", pdcp.len());
                                if new_off < pdcp.len() {
                                    um_tx = Some((pdcp, new_off, sn));
                                }
                                (m, s)
                            }
                        } else if let (true, true, Some(uip), true) =
                            (tun.is_none(), drb_up, ue_ip, ping_seq < 20 && std::time::Instant::now() >= next_ping_at)
                        {
                            // Built-in ping as a 1 Hz RTT probe: 20 echoes, one per
                            // second, each sent ONCE (the reply handler prints the RTT).
                            // The warm-grant window keeps grants flowing between sends.
                            let ip = ipv4_icmp_echo_request(uip, ping_target, PING_ID, ping_seq, b"ferrite-ping");
                            let m = drb_ul_pdu(pdcp_tx_sn, &ip, tbs_bytes);
                            pdcp_tx_sn += 1;
                            let s = format!("ICMP echo req seq {ping_seq} → {}.{}.{}.{}",
                                ping_target[0], ping_target[1], ping_target[2], ping_target[3]);
                            ping_sent_at.push(std::time::Instant::now());
                            next_ping_at = std::time::Instant::now() + std::time::Duration::from_secs(1);
                            last_up_activity = std::time::Instant::now();
                            ping_seq += 1;
                            (m, s)
                        } else if up_active(&last_up_activity) {
                            // Warm grant: traffic moved within the last second — report a
                            // small non-zero buffer so the gNB keeps granting every UL
                            // occasion (the next packet rides one instead of paying the
                            // SR round-trip). Padding does not refresh the window.
                            (mac_short_bsr(220, tbs_bytes), String::new())
                        } else {
                            // Idle grant: a valid, decodable PDU that reports an empty
                            // buffer so the gNB stops granting (and no crc=KO).
                            (mac_short_bsr(0, tbs_bytes), String::new())
                        };
                        let m5_alloc = PuschAlloc { rb_start: g_rb0, n_rb: g_nrb, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, carrier_rb, crb_offset: 0 };
                        ul_harq.insert(g_hid, (ndi, tbs_bytes, mac.clone()));
                        // CSI-on-PUSCH shrinks the data rate-match length (the TBS is
                        // unaffected — like the DL CSI-RS rule, N'_RE ignores the UCI).
                        // Q'_CSI uses ΣK_r = the LDPC code-block sizes INCLUDING filler.
                        let csi_res: Vec<(usize, usize)> = if csi_bits.is_empty() { Vec::new() } else {
                            let sp = ferrite_phy::coding::dlsch::seg_params(tbs, r);
                            ferrite_phy::pusch::csi1_pusch_res(&m5_alloc.dmrs_symbols, g_nrb, csi_bits.len(), beta_csi, 1.0, sp.c * sp.k)
                        };
                        let e = e - 2 * csi_res.len();
                        let ulsch = dlsch_encode_single(&bytes_to_bits(&mac), e, r, qm as usize, g_rv);
                        if std::env::var_os("FERRITE_ULDBG").is_some() {
                            eprintln!("[uldbg] slot={m5_slot} rb[{g_rb0},+{g_nrb}) mcs={mcs} tbs={tbs_bytes} e={e} rv={g_rv} h{g_hid}/n{ndi} csi={} retx={is_retx} kind={kind}", csi_res.len());
                        }
                        let pos = slot_start_ul + (m5_slot - slot_idx as i64) * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
                        if !kind.is_empty() {
                            println!("  → {kind}: grant RB[{g_rb0},{}) MCS{mcs} ndi={ndi} tbs={tbs_bytes} at ul {pos} (slot {m5_slot})", g_rb0 + g_nrb);
                        }
                        // Modulate after the DL decode (below), so a co-scheduled HARQ-ACK
                        // can be multiplexed onto this PUSCH.
                        pending_pusch = Some((pos, m5_slot, ulsch, m5_alloc, tbs_bytes * 8, t_dai, csi_bits, csi_res));
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
        // Decode SIB1 once (SI-RNTI in the Type0 common search space): the TDD pattern
        // and the k2 table configure the slot logic for the rest of the attach. SIB1
        // repeats every 20 ms, so this searches each pre-connect DL slot until it parses.
        if sib1_cfg.is_none() {
            const SI_RNTI: u16 = 0xFFFF;
            let mut si_bits = None;
            for cand in ferrite_phy::pdcch::type0_candidates(coreset.n_cce()) {
                let mut m = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot_idx, &cand);
                pdcch_descramble_llr(&mut m, u32::from(acq.cell_id));
                if let Some(b) = dci_decode(&m, SI_RNTI, a_len) {
                    si_bits = Some(b);
                    break;
                }
            }
            if let Some(b) = si_bits {
                let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
                let riv = b[..riv_bits].iter().fold(0usize, |a, &x| a << 1 | x as usize);
                let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
                let mcs = b[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &x| a << 1 | x);
                let (qm, r) = mcs_params(mcs);
                if let Some(grids) = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1) {
                    // SIB1 PDSCH: TDRA row 1 → [2,14) type A, DM-RS {2,7,11}, l,k' order.
                    let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: qm as usize, n_bwp: 0, nof_cdm_groups: 2 };
                    let px = extract_pdsch(&grids, sc_to_bin, &alloc, acq.cell_id, slot_idx, 0, SI_RNTI, acq.cell_id, true);
                    if px.dmrs_metric > 0.9 {
                        let mut llr = px.llrs;
                        descramble_llrs(&mut llr, pdsch_scramble_c_init(SI_RNTI, acq.cell_id));
                        use ferrite_phy::pdsch_params::{ndmrs_per_prb, transport_block_size};
                        let tbs = transport_block_size(12 * 12 - ndmrs_per_prb(3), nrb, qm, r, 1);
                        if let Some(tbb) = dlsch_decode_single(&llr, tbs, r, qm as usize, 0, 10) {
                            let tb: Vec<u8> = tbb.chunks(8).map(|c| c.iter().fold(0u8, |a, &x| a << 1 | x)).collect();
                            if let Some(p) = ferrite_ue::sib1::parse_sib1(&tb) {
                                println!(
                                    "SIB1: PLMN {}{}{}-{}, TAC {}, band n{}, TDD {}: {} slots = {}D + special({}dl/{}ul sym) + {}U{}; k2 rows {:?}; prach idx {}",
                                    p.mcc[0], p.mcc[1], p.mcc[2],
                                    p.mnc.iter().map(|d| d.to_string()).collect::<String>(),
                                    p.tac, p.band, if p.tdd_pattern2.is_some() { "p1+p2" } else { "p1" },
                                    p.tdd_period_slots(), p.tdd.dl_slots, p.tdd.dl_symbols, p.tdd.ul_symbols, p.tdd.ul_slots,
                                    p.tdd_pattern2.map(|q| format!(" | p2 {}D+{}U", q.dl_slots, q.ul_slots)).unwrap_or_default(),
                                    p.pusch_tdra.iter().map(|t| t.k).collect::<Vec<_>>(),
                                    p.prach_config_index,
                                );
                                sib1_cfg = Some(p);
                            }
                        }
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
                                // Msg3 timing (TS 38.213 §8.3 / 38.214 §6.1.2.1): the RAR UL
                                // grant's 4-bit PUSCH time-resource field indexes the SIB1
                                // k2 list; Msg3 goes at n + k2 + Δ with Δ=3 for µ=1. On this
                                // cell row 0 (k2=4) gives the old constant 7; the DDDSU cell
                                // signals row 1 (k2=6 → 9). Fallback: the --msg3-delay CLI.
                                let time_row = ((grant >> 8) & 0xf) as usize;
                                let msg3_del = sib1_cfg
                                    .as_ref()
                                    .map_or(msg3_delay, |s| s.k2_for_row(time_row) as i64 + 3);
                                println!("RAR: TA={ta} grant={grant:#x} TC-RNTI={tc:#06x} → Msg3 RB[{m_rb0},{}] slot +{msg3_del} (offset {offset})", m_rb0 + m_nrb);
                                sweep = 0; // freeze the aligned offset
                                last_ta = ta as i64;
                                // carrier RB0 = point A (CRB0), so the DM-RS gold sequence
                                // is referenced directly to the carrier RB (crb_offset 0).
                                let m_alloc = PuschAlloc { rb_start: m_rb0, n_rb: m_nrb, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb, crb_offset: 0 };
                                let tb3 = bytes_to_bits(&msg3_mac_pdu(&ccch_sdu, 11));
                                let ulsch = dlsch_encode_single(&tb3, pusch_e_len(&m_alloc), 0.117, 2, 0);
                                let msg3_slot = slot_idx as i64 + msg3_del;
                                let dmrs_slot = msg3_slot % 20;
                                // §5.4 phase compensation at the carrier centre (center_hz):
                                // the gNB's OFDM demod removes it, so an uncompensated UL
                                // decorrelates the DM-RS across symbols. Critical for decode.
                                let wave0 = pusch_modulate_slot(&ofdm, &ulsch, &m_alloc, acq.cell_id, dmrs_slot as u32, (msg3_slot % 2) as usize, tc, center_hz, fs);
                                let pos0 = slot_start_ul + msg3_del * slot_len + offset - ta as i64 * ta_samp;
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
                                if std::env::var_os("FERRITE_MSG3DBG").is_some() {
                                    eprintln!("[msg3dbg] slot_idx={slot_idx} msg3_slot={msg3_slot} dmrs_slot={dmrs_slot} par={} rb0={m_rb0} pos-ul={} pos-ss={}",
                                        msg3_slot % 2, pos - ul_counter as i64, pos - slot_start_ul);
                                }
                                inj.lock().unwrap().push(ReadyWaveform { pos, samples: wave.clone(), tag: "msg3" }, ul_counter as i64);
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
        // Dispatch every slot that can carry a PDSCH for us, per the SIB1 TDD pattern
        // (full-DL slots plus a special slot with ≥8 DL symbols — the gNB schedules
        // PDSCH there too, e.g. the RRC SMC). Fallback: the bring-up cell's slots 0-6.
        let slot_has_pdsch = sib1_cfg.as_ref().map_or(matches!(slot_idx % 10, 0..=6), |s| s.has_pdsch(slot_idx));
        if connected.is_some() && srb1_sn >= 1 && slot_has_pdsch {
            let crnti = connected.unwrap();
            if dl_job_tx.try_send(DlJob { slot_idx, slot_start_ul, frame_even: (slot_start_ul / slot_len / 20) % 2 == 0, crnti, dl_dci, tf_hint: msg4_tf, fsh: fsh.clone() }).is_err() {
                job_drops += 1; // queue full: the worker is behind — this DL slot is never decoded
                if std::env::var_os("FERRITE_DRIFT").is_some() && job_drops <= 40 {
                    eprintln!("[job-drop] #{job_drops} slot={slot_idx} t0={slot_start_ul}");
                }
            }
        }
        // Drain completed decode results and run the RRC/NAS/MAC stack on each. slot_idx /
        // slot_start_ul are shadowed to the DECODED slot's values, so the HARQ-ACK still
        // targets that slot's n+k1 (the other timeline params are constant in steady state).
        // `for … in Option` yields the one decoded TB, keeping the body's `break`s valid.
        while let Ok(res) = dl_res_rx.try_recv() {
            if let Some(q) = res.cqi {
                pending_cqi = Some((q, res.slot_start_ul));
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
                                    let pos = slot_start_ul + k1a * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
                                    // Key by the nearest-slot rounding (TA-proof; see ack_book).
                                    let key = (pos + slot_len / 2).div_euclid(slot_len);
                                    let e = ack_book.entry(key).or_insert(((ack_slot % 20) as u32, pos, [None; 4]));
                                    e.2[(dai & 3) as usize] = Some(1); // 1 = ACK
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
                                        if !ping_acked {
                                            println!("🏓 PING REPLY from {}.{}.{}.{} id={:#06x} seq={} — END-TO-END PING WORKS",
                                                r.src[0], r.src[1], r.src[2], r.src[3], r.id, r.seq);
                                        }
                                        ping_acked = true;
                                        last_up_activity = std::time::Instant::now();
                                        if let Some(t0) = ping_sent_at.get(r.seq as usize) {
                                            println!("🏓 seq={} time={:.1} ms", r.seq, t0.elapsed().as_secs_f64() * 1e3);
                                        }
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
                                // ACK so the gNB advances. Re-arm on RE-DELIVERIES too: the
                                // peer only re-delivers an SN because our previous STATUS was
                                // lost (e.g. that PUSCH CRC-failed), so withholding it wedges
                                // its RLC AM window on this SN forever (observed live: the
                                // Auth Request re-delivered for 40 s while the NAS was stuck).
                                // The gNB stops re-delivering as soon as one STATUS lands, so
                                // this can't starve our own UL for more than a grant or two.
                                dl_rlc_next = dl_rlc_next.max(rlc_sn + 1);
                                pending_status = Some(dl_rlc_next);
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
        if sib1_cfg.as_ref().map_or(matches!(slot_idx % 10, 1 | 5), |s| s.has_pdsch(slot_idx)) && !recent_tc.is_empty() {
            if let Some(grids) = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1) {
                let probe = PdschAlloc { rb_start: 0, n_rb: 21, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm: 2, n_bwp: 0 , nof_cdm_groups: 2};
                let metric = extract_pdsch(&grids, sc_to_bin, &probe, acq.cell_id, slot_idx, 0, 0, acq.cell_id, false).dmrs_metric;
                if metric > 0.9 {
                    let cands: Vec<(u16, i64)> = recent_tc.iter().rev().copied().collect();
                    for (tcx, toffx) in cands {
                        if let Some((tb4, tf4)) = try_decode_msg4(&grids, sc_to_bin, acq.cell_id, slot_idx, tcx, &ccch_sdu) {
                            // Parse the RRCSetup masterCellGroup (the dedicated config):
                            // k1 list, DCI 0_1/1_1 geometry, SR/CSI occasions, CSI-RS
                            // rate-match pattern. On failure every use site falls back
                            // to the transcribed bring-up constants, exactly as pre-parse.
                            if cg_cfg.is_none() {
                                for s in parse_dl_mac_pdu(&tb4) {
                                    if s.lcid != 0 {
                                        continue;
                                    }
                                    match ferrite_ue::cellgroup::parse_rrc_setup(&s.payload) {
                                        Some(cg) => {
                                            println!("   masterCellGroup: k1={:?} pucch-res={} sr={:?} csi-report={:?} nzp-csi-rs={} zp-csi-rs={}",
                                                cg.k1_list, cg.pucch_resources.len(), cg.sr, cg.csi_report,
                                                cg.nzp_csi_rs.len(), cg.zp_csi_rs.len());
                                            // Wire the connected-mode PUCCH F1 configs from the parsed
                                            // resources (the hardcodes are 10 MHz auto-config; the wider
                                            // 20 MHz BWP uses different PRBs/shifts). SR = its own
                                            // resource; HARQ-ACK = resource-set-0 resource 0 (id 0).
                                            let to_f1 = |r: &ferrite_ue::cellgroup::PucchResource| ferrite_phy::pucch::PucchF1 {
                                                prb1: r.prb as usize,
                                                prb2: r.second_hop_prb.unwrap_or(r.prb) as usize,
                                                start_symbol: r.start_symbol as usize,
                                                nof_symbols: r.n_symbols as usize,
                                                init_cyclic_shift: r.cs_or_prbs as usize,
                                                occ_index: r.occ as usize,
                                                n_id: acq.cell_id, carrier_rb,
                                            };
                                            if let Some((_, _, srid)) = cg.sr {
                                                if let Some(r) = cg.pucch_resources.iter().find(|r| r.id == srid) {
                                                    sr_cfg = to_f1(r);
                                                    println!("   SR PUCCH ← res {srid}: prb{} cs{} occ{}", r.prb, r.cs_or_prbs, r.occ);
                                                }
                                            }
                                            if let Some(r) = cg.pucch_resources.iter().find(|r| r.id == 0 && r.format == 1) {
                                                harq_cfg = to_f1(r);
                                            }
                                            println!("   CORESET1: freq={:#014x} dur={} interleaved={} popcount={}",
                                                cg.coreset1_freq_bits, cg.coreset1_duration, cg.coreset1_interleaved,
                                                cg.coreset1_freq_bits.count_ones());
                                            let _ = CSI_RM.set(CsiRm::from_cellgroup(&cg));
                                            cg_cfg = Some(cg);
                                        }
                                        None => println!("   masterCellGroup parse FAILED — keeping transcribed constants"),
                                    }
                                }
                            }
                            // The data RE-mapping order (time-first) is cell-fixed: seed the
                            // RX-PHY worker's layout sweep with the one Msg4 just proved.
                            msg4_tf = Some(tf4);
                            msg4_wins += 1;
                            if locked_toff != Some(toffx) {
                                locked_toff = Some(toffx);
                                sweep = 0;
                                println!("  ⇒ toff LOCKED at {toffx} (Msg3 now reliable); Msg4 wins={msg4_wins}");
                            }
                            // Contention is won: any still-queued Msg3 pre-injections are
                            // stale, and their waveforms would garble whatever lands in
                            // their slots (the injection fill is last-write-wins).
                            inj.lock().unwrap().retract("msg3");
                            // HARQ-ACK the Msg4 on PUCCH F1 at the next UL slot
                            // (7 for a DL slot ≤5, else 17). Same UL timing as Msg3.
                            if pend_pucch.is_none() {
                                // The next full-UL slot per the SIB1 TDD pattern (fallback:
                                // this cell's UL slots 7-9/17-19). May exceed the frame —
                                // the position delta uses the raw value, the modulation the
                                // slot-in-frame.
                                let pucch_slot = sib1_cfg
                                    .as_ref()
                                    .map_or(if slot_idx < 10 { 7 } else { 17 }, |s| s.next_ul_slot_after(slot_idx));
                                let pos = slot_start_ul + (pucch_slot as i64 - slot_idx as i64) * slot_len
                                    + offset + toffx - last_ta * ta_samp;
                                let key = (pos + slot_len / 2).div_euclid(slot_len);
                                if let Some(e) = ack_book.get_mut(&key) {
                                    // Connected-mode T0 already saw this Msg4 retx's DCI 1_0
                                    // and pre-booked a NACK: upgrade it — the codebook drain
                                    // sends the ACK, and a second (msg4ack) waveform in the
                                    // same slot would overwrite it sample-for-sample.
                                    e.2[0] = Some(1);
                                } else if !uci_claimed.contains(&key) {
                                    let mut pw = ferrite_phy::pucch::pucch_f1_modulate_slot(
                                        &ofdm, &pucch_cfg, &[1], pucch_slot % 20, center_hz, fs);
                                    let pk = pw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                                    for s in &mut pw { *s *= amp / pk; }
                                    println!("  → PUCCH ACK for TC-RNTI={tcx:#06x} at ul {pos} (slot {pucch_slot})");
                                    inj.lock().unwrap().push(ReadyWaveform { pos, samples: pw.clone(), tag: "msg4ack" }, ul_counter as i64);
                                    pend_pucch = Some((pos, pw));
                                }
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

        // Send a Scheduling Request each frame whenever an SRB1 PDU is queued
        // (RRCSetupComplete, then the AuthenticationResponse) to solicit a UL grant.
        // Stops once the queue drains so we don't over-request. The SR occasion slot
        // is the FIRST full-UL slot of the frame: OCUDU's auto-derived SR resource
        // keeps the same PUCCH F1 (PRB 0, cs 6, occ 3) across TDD patterns and moves
        // only the slot (verified: slot 7 on the 5 ms 6D+3U cell, slot 4 on the
        // 2.5 ms DDDSU cell). This mirrors the gNB's dedicated RRCSetup config until
        // ferrite parses masterCellGroup for real.
        let want_ping = tun.is_none() && drb_up && ue_ip.is_some() && ping_seq < 20;
        let want_drb = drb_up && tun_fd.is_some() && (um_tx.is_some() || !tun_ul.is_empty());
        let want_sr = connected.is_some()
            && (!ul_queue.is_empty() || pending_status.is_some() || want_ping || want_drb);
        // Fire the standalone SR 3 slots before its occasion (late enough that any HARQ-ACK
        // book for that slot has formed): if the slot's UCI is already owned by an ACK book
        // (the F2 below carries the SR bit) or a PUSCH (BSR carries the buffer state), the
        // standalone F1 would overlap their samples in the injection table — skip it.
        let sr_target = (slot_idx as i64 + 3) % 20;
        if want_sr && (sr_target - sr_slot).rem_euclid(sr_period) == 0 && pend_sr.is_none() {
            let pos = slot_start_ul + 3 * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
            let key = (pos + slot_len / 2).div_euclid(slot_len);
            let msg4ack_owns = pend_pucch.as_ref()
                .is_some_and(|(p, _)| (p + slot_len / 2).div_euclid(slot_len) == key);
            if !ack_book.contains_key(&key) && !uci_claimed.contains(&key) && !msg4ack_owns {
                // SR kept in T0: cheap (one PUCCH F1/occasion) and latency-critical (drives
                // grants). Modulated for the occasion slot (the base sequence is per-slot).
                let mut sw = ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &sr_cfg, &[], sr_target as u32, center_hz, fs);
                let pk = sw.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
                for s in &mut sw { *s *= amp / pk; }
                inj.lock().unwrap().push(ReadyWaveform { pos, samples: sw, tag: "sr" }, ul_counter as i64);
                pend_sr = Some(pos);
            }
        }

        // Periodic CSI report: send the measured CQI on the PUCCH F2 (PRB 23, symb
        // [0,2)) at the SECOND full-UL slot of the frame — OCUDU's auto-derived CSI
        // report resource, like the SR one, keeps the F2 resource fixed and moves the
        // slot with the TDD pattern (slot 8 on the 5 ms cell, slot 9 on DDDSU).
        // Queue it 2 slots ahead, once the frame's CSI-RS has been measured.
        // pending_cqi is Some only in frames where a valid CSI-RS was seen (even
        // frames), which is exactly when the gNB reads the report — no SFN parity
        // check is needed.
        // Standalone periodic CSI report on its PUCCH F2 resource (the parsed
        // CSI-ReportConfig, see csi_slot above). If the occasion slot's UCI is owned by
        // an ACK book (the HARQ-ACK F2 below appends the CQI) or a PUSCH, skip — a
        // second waveform would overlap theirs in the injection table.
        // Same exact-SFN occasion grid as the CSI-on-PUSCH path above (target slot = 2
        // ahead): the report only lands where the gNB expects it. Firing on the off
        // parity sends a report the gNB isn't reading (wasted F2).
        let csi_tgt_abs = slot_start_ul / slot_len + 2;
        let csi_occ_f2 = cg_cfg.as_ref().and_then(|c| c.csi_report).is_some_and(|(p, o, _)| {
            (acq.next_sfn as i64 * 20 + csi_tgt_abs).rem_euclid(p as i64) == o as i64
        });
        if connected.is_some() && (csi_slot - slot_idx as i64).rem_euclid(20) == 2 && pend_csi.is_none()
            && csi_occ_f2 && pending_cqi.is_some()
        {
            let ckey = (slot_start_ul + 2 * slot_len + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp
                + slot_len / 2).div_euclid(slot_len);
            let msg4ack_owns = pend_pucch.as_ref()
                .is_some_and(|(p, _)| (p + slot_len / 2).div_euclid(slot_len) == ckey);
            if !ack_book.contains_key(&ckey) && !uci_claimed.contains(&ckey) && !msg4ack_owns {
                let (cqi, _) = pending_cqi.take().unwrap();
                let f2 = cg_cfg.as_ref().and_then(|c| {
                    let (_, _, rid) = c.csi_report?;
                    c.pucch_resources.iter().find(|r| r.id == rid).copied()
                });
                let cfg = ferrite_phy::pucch::PucchF2 {
                    prb_start: f2.map_or(23, |r| r.prb as usize),
                    nof_prb: f2.map_or(1, |r| r.cs_or_prbs as usize),
                    start_symbol: f2.map_or(0, |r| r.start_symbol as usize),
                    nof_symbols: f2.map_or(2, |r| r.n_symbols as usize),
                    rnti: connected.unwrap(), n_id: acq.cell_id, n_id0: acq.cell_id, carrier_rb,
                };
                // 4-bit wideband CQI, MSB first.
                let bits = vec![(cqi >> 3) & 1, (cqi >> 2) & 1, (cqi >> 1) & 1, cqi & 1];
                let pos = slot_start_ul + 2 * slot_len
                    + offset + locked_toff.unwrap_or(0) - last_ta * ta_samp;
                let _ = tx_req_tx.try_send(TxReq::PucchF2 { cfg, bits, slot_mod20: csi_slot as u32, pos, now: ul_counter as i64 });
                pend_csi = Some(pos);
            }
        }

        slot_idx = (slot_idx + 1) % 20;
        if slot_idx == 0 {
            // Orphaned PRI entries (DCIs whose PDSCH never decoded → no ACK book to
            // consume them): drop anything a frame behind the serve.
            pri_book.retain(|&k, _| k * slot_len >= ul_counter as i64 - 20 * slot_len);
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
        if let Some((pos, m5_slot, ulsch, m5_alloc, tb_bits, t_dai, csi, csi_res)) = pending_pusch.take() {
            // The codebook lookup is by the nearest-slot rounding of the position, not
            // the exact position — last_ta can change between the DL decode that
            // inserted the ACK and this grant, aliasing the two apart (the missed lookup
            // NACK-padded the UCI while the orphaned ACK collided as a separate PUCCH).
            let key = (pos + slot_len / 2).div_euclid(slot_len);
            let book = ack_book.remove(&key).map(|(_, _, b)| b);
            let book_nonempty = book.is_some_and(|b| b.iter().any(Option::is_some));
            let ack: Vec<u8> = match t_dai {
                // DCI 0_1: size the HARQ-ACK codebook from the grant's UL total-DAI,
                // not from our own decode, so a dropped/late PDSCH still muxes the exact
                // number of bits the gNB reads (NACK for the ones we missed) instead of
                // shifting the PUSCH data REs → CRC KO. T-DAI = (count−1) mod 4:
                //   0→1  1→2  2→3   3→ 0 (empty codebook) or the wrap to 4 when a
                // decoded ACK is actually due here. During attach the count is only ever
                // 0 or 1, so 3 = "no HARQ-ACK on this PUSCH".
                Some(v) => {
                    let n = match v { 0 => 1, 1 => 2, 2 => 3, _ => if book_nonempty { 4 } else { 0 } };
                    if std::env::var_os("FERRITE_DRIFT").is_some() {
                        eprintln!("[uci] pos={pos} t_dai={v} n_ack={n} book_nonempty={book_nonempty}");
                    }
                    (0..n).map(|i| book.and_then(|b| b.get(i).copied().flatten()).unwrap_or(0)).collect()
                }
                // DCI 0_0 fallback grant (no DAI): size from our decoded codebook.
                None => book.map(|b| {
                    let size = b.iter().rposition(Option::is_some).map(|i| i + 1).unwrap_or(0);
                    (0..size).map(|i| b[i].unwrap_or(0)).collect()
                }).unwrap_or_default(),
            };
            const BETA_HARQ: f32 = 20.0; // beta_offset_harq_ack index 11
            let crnti = connected.unwrap_or(0);
            let _ = tx_req_tx.try_send(TxReq::Pusch {
                ulsch, alloc: m5_alloc, slot_mod20: (m5_slot % 20) as u32, slot_parity: (m5_slot % 2) as usize,
                crnti, ack, beta: BETA_HARQ, tb_bits, pos, now: ul_counter as i64,
                csi, csi_res,
            });
            pend_ul.push(pos);
            // This PUSCH now owns UL slot `key`'s UCI. An ACK whose decode drains AFTER
            // this point (k1 and k2 grants often sit in the SAME DL slot, and the decode
            // pipeline is ~1-2 slots deep) must NOT go out as a standalone PUCCH — it
            // would overlap this PUSCH's samples in the injection table and garble both
            // (the recurring first-PUSCH sinr −24 dB KO). The bit was NACK-padded into
            // the PUSCH UCI, so the gNB simply retransmits that TB (the retx paths make
            // that cheap); the late ACK entry is dropped by the due-loop below.
            uci_claimed.push_back(key);
            if uci_claimed.len() > 8 {
                uci_claimed.pop_front();
            }
        }
        // Modulate + queue any HARQ-ACK codebook entries whose UL slot is approaching
        // (a couple slots out, so all their contributing DL PDSCHs have been decoded).
        // The bundle is sized by the highest C-DAI seen (missing positions → NACK bit 0),
        // ordered by C-DAI, so the gNB reads the exact harq_bit_len bits it expects.
        // Modulate ACKs whose UL slot is within ~3 slots of T0's own progress (their contributing
        // DL PDSCHs are decoded by then); the radio thread serves them at their absolute position.
        let due: Vec<i64> = ack_book.iter().filter(|(_, &(_, pos, _))| pos <= slot_start_ul + 3 * slot_len).map(|(&k, _)| k).collect();
        for key in due {
            let (slot_mod20, pos, book) = ack_book.remove(&key).unwrap();
            let pri = pri_book.remove(&key).unwrap_or(0) as usize;
            // A PUSCH already owns this UL slot's UCI (see uci_claimed above), or a
            // Msg4-ACK PUCCH is already queued there: drop the late-drained ACK instead
            // of colliding a second waveform into that slot.
            if uci_claimed.contains(&key)
                || pend_pucch.as_ref().is_some_and(|(p, _)| (p + slot_len / 2).div_euclid(slot_len) == key)
            {
                continue;
            }
            let size = book.iter().rposition(Option::is_some).map(|i| i + 1).unwrap_or(0);
            if size == 0 {
                continue;
            }
            ack_total += 1;
            if pos < ul_counter as i64 {
                ack_late += 1; // its UL block was already served — can never be injected
                if std::env::var_os("FERRITE_DRIFT").is_some() && ack_late < 16 {
                    eprintln!("[ack-late] pos={pos} serving={ul_counter} pos-serving={} pos-t0(slots)={} last_ta={last_ta} ta*4(slots)={}",
                        pos - ul_counter as i64, (pos - slot_start_ul) / slot_len, (last_ta * ta_samp) / slot_len);
                }
            }
            let mut bits: Vec<u8> = (0..size).map(|i| book[i].unwrap_or(0)).collect();
            if pend_acks.len() >= 12 {
                ack_qfull += 1;
                continue;
            }
            // UCI multiplexing (TS 38.213 §9.2.5, the OCUDU-shaped subset): a >2-bit
            // codebook — or any codebook sharing its slot with the CSI occasion — moves
            // to the set-1 PUCCH F2 resource picked by the DCI's PUCCH-resource
            // indicator, appending the SR bit if this slot is the SR occasion and the
            // 4-bit CQI if it's the CSI one. Routine on a one-UL-slot TDD pattern
            // (DDDSU: the gNB reads ack+sr+csi off one F2 and DTXes anything else).
            let sr_here = i64::from(slot_mod20) == sr_slot;
            // Exact-SFN occasion (`key` is this ACK's absolute slot): only append the
            // CQI when this slot is a real CSI-report occasion the gNB reads.
            let csi_here = cg_cfg.as_ref().and_then(|c| c.csi_report).is_some_and(|(p, o, _)| {
                (acq.next_sfn as i64 * 20 + key).rem_euclid(p as i64) == o as i64
            }) && pending_cqi.is_some();
            let mut wave = if bits.len() > 2 || csi_here {
                if sr_here {
                    bits.push(u8::from(want_sr));
                    pend_sr = Some(pos); // the F2 carries this occasion's SR
                }
                if csi_here {
                    let (cqi, _) = pending_cqi.take().unwrap();
                    bits.extend([(cqi >> 3) & 1, (cqi >> 2) & 1, (cqi >> 1) & 1, cqi & 1]);
                }
                // OCUDU's resource set 1 (>2 UCI bits) = the F2 resources, ids 8..15,
                // indexed by the PRI. Fallback: the layout both live cells share
                // (PRB 1, 2 symbols starting at 2·PRI).
                let f2 = cg_cfg.as_ref().and_then(|c| c.pucch_resources.iter().find(|r| r.format == 2 && usize::from(r.id) == 8 + pri).copied());
                let cfg = ferrite_phy::pucch::PucchF2 {
                    prb_start: f2.map_or(1, |r| r.prb as usize),
                    nof_prb: f2.map_or(1, |r| r.cs_or_prbs as usize),
                    start_symbol: f2.map_or(2 * pri, |r| r.start_symbol as usize),
                    nof_symbols: f2.map_or(2, |r| r.n_symbols as usize),
                    rnti: connected.unwrap_or(0), n_id: acq.cell_id, n_id0: acq.cell_id, carrier_rb,
                };
                ferrite_phy::pucch::pucch_f2_modulate_slot(&ofdm, &cfg, &bits, slot_mod20, center_hz, fs)
            } else if sr_here && want_sr {
                // 1-2 ACK bits + positive SR: transmit the ACK on the SR's F1 resource —
                // the gNB reads the resource choice itself as the SR (§9.2.5.1).
                pend_sr = Some(pos);
                ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &sr_cfg, &bits, slot_mod20, center_hz, fs)
            } else {
                // HARQ-ACK kept in T0: cheap (1-2 bit PUCCH F1) and the most latency-critical UL
                // (a TX-thread hop delays it past its k1 window). Modulate + inject inline.
                ferrite_phy::pucch::pucch_f1_modulate_slot(&ofdm, &harq_cfg, &bits, slot_mod20, center_hz, fs)
            };
            let pk = wave.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
            for s in &mut wave { *s *= amp / pk; }
            inj.lock().unwrap().push(ReadyWaveform { pos, samples: wave, tag: "ack" }, ul_counter as i64);
            pend_acks.push(pos);
            // This waveform now owns the slot: a book that re-forms for the same key
            // (a late DCI inside the ≤3-slot drain window) must be dropped, not pushed
            // over this one — the fill is last-write-wins and would garble the slot.
            uci_claimed.push_back(key);
            if uci_claimed.len() > 8 {
                uci_claimed.pop_front();
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
