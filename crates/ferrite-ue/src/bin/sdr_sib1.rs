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

    // Cell search on the first ~1.2 frames.
    let cap = &iq[..(frame_len * 6 / 5).min(iq.len())];
    let (df, _r, shifted) = gscn_scan(cap, fs, center_hz, &searcher).expect("no SSB");
    let acq = sync.acquire(&shifted).expect("acquire");
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

    let mut pos = acq.skip_to_frame;
    let mut frame_no = 0usize;
    let mut decoded = 0u32;
    let mut dci_hits = 0u32;
    let n_frames = (iq.len() - pos) / frame_len;
    while pos + frame_len <= iq.len() {
        let frame = &iq[pos..pos + frame_len];
        let fsh = freq_shift(frame, -df - cfo, fs, pos);
        let rep = sync.track(&fsh);
        let sfn = rep.as_ref().map(|r| r.sfn);
        // Search every slot (fine-timing ±16) for the SI-RNTI DCI.
        for slot in 0..20u32 {
            let mut found: Option<(i64, Vec<u8>)> = None;
            'd: for d in (-16i64..=16).step_by(4) {
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
    println!("\nscanned {frame_no} frames: {dci_hits} SI-RNTI DCI hits, {decoded} SIB1 CRC-OK decodes");
    if decoded == 0 { std::process::exit(1); }
}
