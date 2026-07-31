//! Offline SIB1 decode from a RAW SDR recording (sdr_probe's record mode): the PROVEN
//! sib1.rs cell-search→SI-RNTI DCI→PDSCH path, adapted to (a) read interleaved-f32 IQ from a
//! file, (b) correct the BladeRF↔gNB CFO, (c) re-align per frame from track()'s timing_err
//! (real clocks drift ~1.3 samp/frame), and (d) search ALL slots with a fine-timing sweep.
//! If this fails on a clean gap-free capture, the SIB1 decode bug is real (not the live loop).
//!
//! Usage: sdr_sib1 <raw.bin> [--srate 30.72e6] [--center-mhz 3414.99]

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
use ferrite_phy::pdcch::{equalize_candidate, type0_candidates, Coreset0};
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::{mcs_params, ndmrs_per_prb, transport_block_size};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;
use std::io::Read;

const SI_RNTI: u16 = 0xFFFF;

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

fn riv_decode(riv: usize, n: usize) -> (usize, usize) {
    let l0 = riv / n + 1;
    let s0 = riv % n;
    if l0 <= n - s0 { (s0, l0) } else { (n - 1 - s0, n - l0 + 2) }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: sdr_sib1 <raw.bin> [--srate ..] [--center-mhz ..]");
    let fs: f64 = arg("--srate", "30.72e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3414.99").parse::<f64>().unwrap() * 1e6;

    let mut bytes = Vec::new();
    std::fs::File::open(&path).unwrap().read_to_end(&mut bytes).unwrap();
    let iq: Vec<Complex32> = bytes.chunks_exact(8)
        .map(|c| Complex32::new(
            f32::from_le_bytes(c[0..4].try_into().unwrap()),
            f32::from_le_bytes(c[4..8].try_into().unwrap())))
        .collect();
    println!("loaded {} samples ({:.2}s @ {fs} Hz)", iq.len(), iq.len() as f64 / fs);

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();
    let slot_len = frame_len / 20;
    let ofdm = Ofdm::new(fft);

    // Cell search: find df ONCE with gscn_scan (expensive raster scan), then retry the cheap
    // acquire() over sliding windows — a single window can clip the SSB or land where
    // pss_pos < pss_off, both of which make acquire() return None.
    let cap_len = (frame_len * 6 / 5).min(iq.len());
    let df_override: f64 = arg("--df", "0").parse().unwrap(); // Hz; nonzero overrides gscn_scan
    let df = if df_override != 0.0 { df_override } else {
        let mut df = None;
        for start in (0..iq.len().saturating_sub(cap_len)).step_by(frame_len).take(8) {
            if let Some((d, _r, _s)) = gscn_scan(&iq[start..start + cap_len], fs, center_hz, &searcher) { df = Some(d); break; }
        }
        df.unwrap_or_else(|| { eprintln!("cell search FAILED: no PSS found in any window"); std::process::exit(2); })
    };
    let (acq, cap_start) = {
        let mut result = None;
        let mut acq_tries = 0u32;
        for start in (0..iq.len().saturating_sub(cap_len)).step_by(frame_len / 4).take(60) {
            acq_tries += 1;
            let shifted = freq_shift(&iq[start..start + cap_len], -df, fs, 0);
            if let Some(acq) = sync.acquire(&shifted) { result = Some((acq, start)); break; }
        }
        match result {
            Some(r) => r,
            None => { eprintln!("cell search FAILED: PSS present (df={df}) but MIB never decoded over {acq_tries} windows"); std::process::exit(2); }
        }
    };
    eprintln!("[cell] acquired from window @ {cap_start} (df={df})");
    let cell_id = acq.cell_id;
    let mib = acq.mib;
    let cfo = acq.cfo_hz;
    let k_ssb = (mib.k_ssb_msb << 4) | mib.ssb_subcarrier_offset;
    let coreset = Coreset0::from_index_30_30_minbw5_10(mib.pdcch_config_sib1 >> 4).expect("coreset0");
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = move |sc: i32| (first_sc + sc).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    let cands = type0_candidates(coreset.n_cce());
    println!(
        "PCI {cell_id} sfn {} half_frame {} k_ssb {k_ssb} pdcch_cfg_sib1 {:#04x} (cs0_idx {} ss0 {}) coreset0 {}RB×{}sym off {} first_sc {first_sc} a_len {a_len}; df {df} cfo {cfo}",
        mib.sfn, mib.half_frame, mib.pdcch_config_sib1, mib.pdcch_config_sib1 >> 4, mib.pdcch_config_sib1 & 0xf,
        coreset.n_rb, coreset.n_symb, coreset.offset_rb,
    );

    // demod n_symb CORESET symbols of `slot` from freq-shifted frame `fsh`, window shifted by d.
    let demod_cs = |fsh: &[Complex32], slot: usize, d: i64| -> Vec<Vec<Complex32>> {
        let mut off = (slot * slot_len) as i64 + d;
        let mut g = Vec::new();
        for l in 0..coreset.n_symb {
            let cp = ofdm.cp_len((slot % 2) * 14 + l, 1);
            let s = off.max(0) as usize;
            g.push(if s + cp + fft <= fsh.len() { ofdm.demodulate_symbol(&fsh[s..], cp) } else { vec![Complex32::default(); fft] });
            off += (cp + fft) as i64;
        }
        g
    };

    // --census: instead of decoding, accumulate per-(slot,symbol) carrier energy over ALL frames
    // to map the gNB's complete transmission structure (SSB / CSI-RS / TRS / any PDCCH-PDSCH) and
    // quantify the SSB-vs-CORESET0 power gap. Full-slot (14-symbol) demod.
    let census = std::env::args().any(|a| a == "--census");
    let demod_full = |fsh: &[Complex32], slot: usize| -> Vec<Vec<Complex32>> {
        let mut off = (slot * slot_len) as i64;
        let mut g = Vec::new();
        for l in 0..14 {
            let cp = ofdm.cp_len((slot % 2) * 14 + l, 1);
            let s = off.max(0) as usize;
            g.push(if s + cp + fft <= fsh.len() { ofdm.demodulate_symbol(&fsh[s..], cp) } else { vec![Complex32::default(); fft] });
            off += (cp + fft) as i64;
        }
        g
    };
    // mean |g|^2 over the carrier (sc -153..459, excl |sc|<=3 to skip LO/DC leakage).
    let carrier_pow = |g: &[Complex32]| -> f64 {
        let mut p = 0f64; let mut n = 0u32;
        for sc in -153i32..459 { if sc.abs() > 3 { p += g[sc.rem_euclid(fft as i32) as usize].norm_sqr() as f64; n += 1; } }
        p / n.max(1) as f64
    };
    let mut cen = vec![[0f64; 14]; 20];
    let mut cen_n = 0u32;

    // skip_to_frame is relative to the END of the acquisition buffer `cap`, so the first
    // aligned frame starts at cap.len() + skip_to_frame (cap.len() = frame_len·6/5 = 1 frame +
    // 4 slots; omitting it put the SSB at "slot 4" and offset every slot number by 4).
    let mut pos = cap_start + cap_len + acq.skip_to_frame;
    let mut frame_no = 0usize;
    let mut decoded = 0u32;
    let mut dci_hits = 0u32;
    let n_frames = (iq.len() - pos) / frame_len;
    while pos + frame_len <= iq.len() {
        let frame = &iq[pos..pos + frame_len];
        let fsh = freq_shift(frame, -df - cfo, fs, pos);
        let rep = sync.track(&fsh);
        let sfn = rep.as_ref().map(|r| r.sfn);
        if census {
            if frame_no < 3 {
                if let Some(r) = searcher.search(&fsh) {
                    eprintln!("[census] frame {frame_no}: PSS @ {}/{frame_len} = slot {} (metric {:.2})", r.timing_index, r.timing_index / slot_len, r.pss_metric);
                }
            }
            for slot in 0..20usize {
                let g = demod_full(&fsh, slot);
                for l in 0..14 { cen[slot][l] += carrier_pow(&g[l]); }
            }
            cen_n += 1;
            pos = match rep { Some(r) => (pos as i64 + frame_len as i64 + r.timing_err).max(0) as usize, None => pos + frame_len };
            frame_no += 1;
            if frame_no >= n_frames { break; }
            continue;
        }
        // Search every slot (fine-timing ±16) for the SI-RNTI DCI.
        // fine-timing offsets, iterated by increasing |d| so the reported d is the true centre
        // (SIB1 decodes at d=0 with correct alignment; the sweep just adds drift tolerance).
        let mut ds: Vec<i64> = (-16i64..=16).step_by(4).collect();
        ds.sort_by_key(|d| d.abs());
        for slot in 0..20u32 {
            let mut found: Option<(i64, Vec<u8>)> = None;
            'd: for &d in &ds {
                let cg = demod_cs(&fsh, slot as usize, d);
                for cand in &cands {
                    let mut m = equalize_candidate(&cg, |sc: usize| sc_to_bin(sc as i32), &coreset, cell_id, slot, cand);
                    pdcch_descramble_llr(&mut m, u32::from(cell_id));
                    if let Some(b) = dci_decode(&m, SI_RNTI, a_len) { found = Some((d, b)); break 'd; }
                }
            }
            let Some((d, bits)) = found else { continue };
            dci_hits += 1;
            // Parse DCI 1_0 (SI-RNTI).
            let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
            let riv = bits[..riv_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
            let tdra = bits[riv_bits..riv_bits + 4].iter().fold(0u8, |a, &b| a << 1 | b);
            let mcs = bits[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &b| a << 1 | b);
            let (rb0, nrb) = riv_decode(riv, coreset.n_rb);
            let (s_sym, l_sym) = ([2usize, 2, 2, 2, 2][tdra.min(4) as usize], [12usize, 10, 9, 7, 5][tdra.min(4) as usize]);
            let (qm, r) = mcs_params(mcs);
            println!("frame {frame_no} sfn {sfn:?} slot {slot} d={d}: SIB1 DCI  RB {rb0}+{nrb} sym {s_sym}+{l_sym} MCS {mcs} (Qm {qm} R {r:.3})");
            // PDSCH decode (scan DM-RS base for the CRB offset, both mapping orders + QPSK symmetries).
            let Some(grids) = demod_slot(&ofdm, &fsh, slot as usize * slot_len, slot as usize % 2, 1) else { continue };
            let dmrs_symbols = vec![2usize, 7, 11];
            let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start: s_sym, n_sym: l_sym, dmrs_symbols: dmrs_symbols.clone(), qm: qm as usize, n_bwp: 0, nof_cdm_groups: 2 };
            let best_base = (0..coreset.n_rb + 40)
                .map(|b| (b, extract_pdsch(&grids, sc_to_bin, &alloc, cell_id, slot, 6 * b, SI_RNTI, cell_id, false).dmrs_metric))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap().0;
            let tbs = transport_block_size(12 * l_sym - ndmrs_per_prb(dmrs_symbols.len()), nrb, qm, r, 1);
            'ok: for time_first in [false, true] {
                let p = extract_pdsch(&grids, sc_to_bin, &alloc, cell_id, slot, 6 * best_base, SI_RNTI, cell_id, time_first);
                let mut base = p.llrs.clone();
                descramble_llrs(&mut base, pdsch_scramble_c_init(SI_RNTI, cell_id));
                let transforms: [fn(f32, f32) -> (f32, f32); 8] = [
                    |re, im| (re, im), |re, im| (-im, re), |re, im| (-re, -im), |re, im| (im, -re),
                    |re, im| (re, -im), |re, im| (-re, im), |re, im| (im, re), |re, im| (-im, -re)];
                for t in transforms {
                    let llrs: Vec<f32> = base.chunks_exact(2).flat_map(|c| { let (a, b) = t(c[0], c[1]); [a, b] }).collect();
                    let (bits, _conv, crc) = dlsch_decode_single_bits(&llrs, tbs, r, qm as usize, 0, 40);
                    if crc {
                        let hex: String = bits.chunks(8).take(16).map(|c| format!("{:02x}", c.iter().fold(0u8, |a, &b| a << 1 | b))).collect();
                        println!("  *** SIB1 DECODED, CRC OK, {tbs}-bit TB, dmrs {:.2} EVM {:.3}, base {best_base}, order tf={time_first}  TB[0..16]={hex}", p.dmrs_metric, p.evm);
                        decoded += 1;
                        break 'ok;
                    }
                }
            }
        }
        // Re-align to counter clock drift; fall back to a plain frame step if track failed.
        pos = match rep { Some(r) => (pos as i64 + frame_len as i64 + r.timing_err).max(0) as usize, None => pos + frame_len };
        frame_no += 1;
        if frame_no >= n_frames { break; }
    }
    if census {
        // Convert to dB relative to the quietest (slot,symbol) = the noise floor.
        for c in cen.iter_mut() { for v in c.iter_mut() { *v /= cen_n.max(1) as f64; } }
        let floor = cen.iter().flatten().cloned().fold(f64::INFINITY, f64::min).max(1e-30);
        println!("\n=== transmission census over {cen_n} frames: carrier power per (slot,symbol), dB above noise ===");
        println!("        {}", (0..14).map(|l| format!("s{l:<2}")).collect::<String>());
        for slot in 0..20 {
            let row: String = (0..14).map(|l| {
                let db = 10.0 * (cen[slot][l] / floor).log10();
                if db < 3.0 { "  . ".to_string() } else { format!("{db:3.0} ") }
            }).collect();
            println!("slot {slot:>2}: {row}");
        }
        // Auto-detect the SSB slot = the slot with the strongest 4-consecutive-symbol block
        // (sym s..s+4), then report the SSB vs its own CORESET0 (sym s-2..s) power gap.
        let ssb_slot = (0..20).max_by(|&a, &b| {
            let blk = |sl: usize| (0..11).map(|s| (0..4).map(|k| cen[sl][s + k]).sum::<f64>()).fold(0.0, f64::max);
            blk(a).partial_cmp(&blk(b)).unwrap()
        }).unwrap();
        let ssb_sym = (0..11).max_by(|&a, &b| {
            let e = |s: usize| (0..4).map(|k| cen[ssb_slot][s + k]).sum::<f64>();
            e(a).partial_cmp(&e(b)).unwrap()
        }).unwrap();
        let ssb = (ssb_sym..ssb_sym + 4).map(|l| cen[ssb_slot][l]).sum::<f64>() / 4.0;
        // CORESET0 is 2 symbols just before the SSB (multiplexing pattern 1, ss0=0).
        let cs0 = if ssb_sym >= 2 { (ssb_sym - 2..ssb_sym).map(|l| cen[ssb_slot][l]).sum::<f64>() / 2.0 } else { floor };
        println!("\nSSB detected at slot {ssb_slot}, sym {ssb_sym}-{}: {:.1} dB above noise", ssb_sym + 3, 10.0 * (ssb / floor).log10());
        println!("CORESET0 (slot {ssb_slot}, sym {}-{}) = {:.1} dB above noise; SSB-to-CORESET0 gap = {:.1} dB",
            ssb_sym.saturating_sub(2), ssb_sym.saturating_sub(1), 10.0 * (cs0 / floor).log10(), 10.0 * (ssb / cs0.max(floor)).log10());
        println!("(PDCCH/PDSCH → block of >3 dB cells; CSI-RS/TRS → isolated symbols. A ~equal SSB/CORESET0");
        println!(" gap would mean the PDCCH is present; a large gap means the SIB1 PDCCH is not transmitted.)");
        return;
    }
    println!("\nscanned {frame_no} frames: {dci_hits} SI-RNTI DCI hits, {decoded} SIB1 CRC-OK decodes");
    if decoded == 0 { std::process::exit(1); }
}
