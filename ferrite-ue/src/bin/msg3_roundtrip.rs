//! Self-decode the Msg3 PUSCH waveform to isolate the FFT-1024 (20 MHz) failure.
//!
//! Modulates a Msg3 exactly as `main.rs` does (carrier-centred, §5.4 phase comp),
//! then demodulates it back the way the gNB's lower PHY would — CP strip, FFT,
//! remove the §5.4 phase comp — and checks the DM-RS correlation and the data CRC.
//! If the round-trip is clean at FFT 512 but broken at FFT 1024, the bug is in the
//! 1024 modulation path; the per-symbol DM-RS magnitude vs the cross-symbol channel
//! consistency localises it to the grid mapping vs the phase compensation.
//!
//! Usage: msg3-roundtrip <fft>   (512 = 10 MHz params, 1024 = 20 MHz params)

use ferrite_phy::coding::dlsch::{dlsch_decode_single_bits, dlsch_encode_single};
use ferrite_phy::pdsch::{descramble_llrs, pdsch_dmrs, pdsch_scramble_c_init};
use ferrite_phy::pusch::{pusch_e_len, pusch_modulate_slot, PuschAlloc};
use ferrite_phy::Ofdm;
use num_complex::Complex32;

fn main() {
    let fft: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1024);
    // Match main.rs's Msg3 for each bandwidth: (carrier BWP RB, RAR-granted rb_start).
    let (carrier_rb, rb_start) = if fft == 1024 { (51usize, 8usize) } else { (24usize, 4usize) };
    let (n_rb, cell, tc, slot) = (3usize, 1u16, 0x4601u16, 17u32);
    let dmrs = vec![2usize, 7, 11];
    let fs = fft as f64 * 30_000.0;
    let center_hz = 3390e6f64;
    let ofdm = Ofdm::new(fft);
    let n = fft;

    // TB + encode, exactly as main.rs (11-byte Msg3, R=0.117, QPSK).
    let tb_bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
    let tb: Vec<u8> = tb_bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
    let alloc = PuschAlloc { rb_start, n_rb, dmrs_symbols: dmrs.clone(), qm: 2, carrier_rb, crb_offset: 0 };
    let e = pusch_e_len(&alloc);
    let ulsch = dlsch_encode_single(&tb, e, 0.117, 2, 0);
    let tbs = tb.len();

    let wave = pusch_modulate_slot(&ofdm, &ulsch, &alloc, cell, slot, (slot % 2) as usize, tc, center_hz, fs);

    // `msg3-roundtrip <fft> <out.f32>` emits the raw slot waveform (interleaved f32
    // re,im) for cross-correlating against a gNB RX dump, instead of self-decoding.
    if let Some(path) = std::env::args().nth(2) {
        let mut bytes = Vec::with_capacity(wave.len() * 8);
        for s in &wave {
            bytes.extend_from_slice(&s.re.to_le_bytes());
            bytes.extend_from_slice(&s.im.to_le_bytes());
        }
        std::fs::write(&path, &bytes).unwrap();
        eprintln!("wrote {} samples to {path}", wave.len());
        return;
    }
    println!("fft={fft} fs={fs:.0} carrier_rb={carrier_rb} rb[{rb_start},{}) wave={} samples (slot_len {})",
        rb_start + n_rb, wave.len(), fft * 14 + (0..14).map(|l| ofdm.cp_len((slot % 2) as usize * 14 + l, 1)).sum::<usize>());

    // Demodulate: walk symbols, CP-strip + FFT, then REMOVE the §5.4 phase comp
    // (multiply by the conjugate of what modulate applied) → the RX grid per symbol.
    let sib = (slot % 2) as usize;
    let mut sub_off: usize = (0..sib * 14).map(|k| ofdm.cp_len(k, 1) + n).sum();
    let mut off = 0usize;
    let mut grids: Vec<Vec<Complex32>> = Vec::with_capacity(14);
    for l in 0..14 {
        let cp = ofdm.cp_len(sib * 14 + l, 1);
        let mut g = ofdm.demodulate_symbol(&wave[off..off + cp + n], cp);
        let t_start = (sub_off + cp) as f64 / fs;
        let phase = 2.0 * std::f64::consts::PI * center_hz * t_start; // +φ removes the −φ TX comp
        let coeff = Complex32::new(phase.cos() as f32, phase.sin() as f32);
        for s in &mut g {
            *s *= coeff;
        }
        grids.push(g);
        off += cp + n;
        sub_off += cp + n;
    }

    let center = carrier_rb * 6;
    let bin = |sc: usize| (sc as i32 - center as i32).rem_euclid(n as i32) as usize;

    // DM-RS check: per symbol, correlate the received DM-RS REs (even subcarriers of
    // the allocation) against the expected sequence → channel estimate + residual.
    let dmrs_len = 6 * (alloc.crb_offset + carrier_rb);
    let mut est_phase: Vec<Complex32> = Vec::new();
    for &l in &dmrs {
        let refs = pdsch_dmrs(cell, slot, l as u32, dmrs_len);
        let (mut acc, mut sig, mut nse) = (Complex32::new(0.0, 0.0), 0.0f32, 0.0f32);
        let mut hs: Vec<Complex32> = Vec::new();
        for rb in 0..n_rb {
            for j in 0..6 {
                let sc = 12 * (rb_start + rb) + 2 * j;
                let rx = grids[l][bin(sc)];
                let re = refs[6 * (alloc.crb_offset + rb_start + rb) + j];
                let h = rx * re.conj(); // channel estimate (|ref|=1)
                acc += h;
                hs.push(h);
            }
        }
        let hbar = acc / hs.len() as f32;
        for h in &hs {
            sig += hbar.norm_sqr();
            nse += (h - hbar).norm_sqr();
        }
        est_phase.push(hbar);
        let sinr_db = 10.0 * (sig / nse.max(1e-12)).log10();
        println!("  DM-RS sym {l}: |h|={:.3} arg={:+.3}rad  per-RE SINR={sinr_db:.1} dB", hbar.norm(), hbar.arg());
    }
    // Cross-symbol channel consistency (a phase-comp error shows here, not per-symbol).
    let hmean = est_phase.iter().copied().sum::<Complex32>() / est_phase.len() as f32;
    let cross_res: f32 = est_phase.iter().map(|h| (h - hmean).norm_sqr()).sum::<f32>() / est_phase.len() as f32;
    let cross_sinr = 10.0 * (hmean.norm_sqr() / cross_res.max(1e-12)).log10();
    println!("  cross-symbol channel SINR = {cross_sinr:.1} dB (low ⇒ per-symbol phase inconsistent)");

    // Data decode: equalise each data RE by the nearest DM-RS symbol's channel estimate,
    // build LLRs (k'-first then l), descramble, LDPC-decode, check CRC.
    let hchan = hmean; // flat channel (lossless); a single estimate suffices
    let data_syms: Vec<usize> = (0..14).filter(|l| !dmrs.contains(l)).collect();
    let n_sc = 12 * n_rb;
    let mut llr = vec![0f32; e];
    let mut di = 0usize;
    for &l in &data_syms {
        for kp in 0..n_sc {
            let sc = 12 * rb_start + kp;
            let eq = grids[l][bin(sc)] / hchan;
            if di + 1 < e {
                // QPSK LLR: bit=0 → +1/√2, so LLR>0 favours bit 0 (= +re/+im).
                llr[di] = eq.re * 4.0;
                llr[di + 1] = eq.im * 4.0;
                di += 2;
            }
        }
    }
    descramble_llrs(&mut llr, pdsch_scramble_c_init(tc, cell));
    let (_bits, _conv, crc) = dlsch_decode_single_bits(&llr, tbs, 0.117, 2, 0, 20);
    println!("  DATA decode: crc={} {}", crc, if crc { "✓ SELF-DECODES" } else { "✗ FAILS" });
}
