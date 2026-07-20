//! Offline analysis of SDR frame dumps (FERRITE_DUMP): aligned, freq-shifted frames
//! (SSB at DC), raw interleaved f32 IQ, `frame_len` complex per frame. Maps the power
//! spectrum, per-symbol energy, and the SIB1 PDCCH (CORESET0) correlation/decode so we
//! can see whether the SIB1 PDCCH is present and where — without live reruns.
//!
//! Usage: sdr_analyze <dump.bin> [cell_id=2] [k_ssb=18] [coreset0_idx=2]

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::pdcch::{equalize_candidate, pdcch_dmrs, type0_candidates, Coreset0};
use ferrite_phy::Ofdm;
use num_complex::Complex32;
use std::io::Read;

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("usage: sdr_analyze <dump.bin> [cell_id] [k_ssb] [coreset0_idx]");
    let cell_id: u16 = a.next().and_then(|s| s.parse().ok()).unwrap_or(2);
    let k_ssb: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(18);
    let cs_idx: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(2);

    let fft = 1024usize;
    let frame_len = 307200usize;
    let slot_len = frame_len / 20; // 15360

    let mut bytes = Vec::new();
    std::fs::File::open(&path).unwrap().read_to_end(&mut bytes).unwrap();
    let iq: Vec<Complex32> = bytes
        .chunks_exact(8)
        .map(|c| Complex32::new(
            f32::from_le_bytes(c[0..4].try_into().unwrap()),
            f32::from_le_bytes(c[4..8].try_into().unwrap()),
        ))
        .collect();
    let n_frames = iq.len() / frame_len;
    println!("loaded {n_frames} frames ({} samples); cell_id={cell_id} k_ssb={k_ssb} coreset0_idx={cs_idx}", iq.len());

    let ofdm = Ofdm::new(fft);

    // The dump alternates SSB / no-SSB frames (SSB period 20 ms). Auto-select the frame whose
    // slot 0 has the strongest time-domain PSS so the calibration sections look at a real SSB.
    let fsel = {
        use ferrite_phy::sync::ssb::pss_time_reference;
        let tref = pss_time_reference((cell_id % 3) as u8, &ofdm);
        (0..n_frames).max_by(|&x, &y| {
            let peak = |f: usize| (0..slot_len).map(|o| {
                let mut acc = Complex32::new(0.0, 0.0);
                let mut pw = 0f32;
                for (i, r) in tref.iter().enumerate() { let s = iq[f * frame_len + o + i]; acc += s * r.conj(); pw += s.norm_sqr(); }
                acc.norm() / pw.sqrt().max(1e-12)
            }).fold(0f32, f32::max);
            peak(x).partial_cmp(&peak(y)).unwrap()
        }).unwrap_or(0)
    };
    println!("auto-selected SSB frame index = {fsel} (of {n_frames})");
    let fr = &iq[fsel * frame_len..(fsel + 1) * frame_len]; // the selected SSB frame
    let coreset = Coreset0::from_index_30_30_minbw5_10(cs_idx).unwrap();
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = |sc: i32| (first_sc + sc).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    println!("coreset0: {}RB x {}sym off_rb={} first_sc={first_sc} a_len={a_len}", coreset.n_rb, coreset.n_symb, coreset.offset_rb);

    // Demod all 14 symbols of a slot into per-symbol FFT grids.
    let demod = |frame: &[Complex32], slot: usize| -> Vec<Vec<Complex32>> {
        let base = slot * slot_len;
        let mut grids = Vec::new();
        let mut off = base;
        for l in 0..14 {
            let cp = ofdm.cp_len((slot % 2) * 14 + l, 1);
            grids.push(ofdm.demodulate_symbol(&frame[off..], cp));
            off += cp + fft;
        }
        grids
    };

    // 0a) Map the SSB burst: slide the PSS over the whole selected frame and report every
    //     strong peak. Multiple peaks ⇒ an SSB burst (L>1 beams); their spacing/positions
    //     reveal the true frame structure and which slot the SIB1 CORESET0 associates with.
    {
        use ferrite_phy::sync::ssb::pss_time_reference;
        let tref = pss_time_reference((cell_id % 3) as u8, &ofdm);
        let mut corrs = vec![0f32; frame_len];
        for o in 0..frame_len - 1024 {
            let mut acc = Complex32::new(0.0, 0.0);
            let mut pw = 0f32;
            for (i, r) in tref.iter().enumerate() { let s = fr[o + i]; acc += s * r.conj(); pw += s.norm_sqr(); }
            corrs[o] = acc.norm() / pw.sqrt().max(1e-12);
        }
        println!("\n=== SSB burst map (PSS peaks > 0.35 over selected frame {fsel}) ===");
        let mut o = 0usize;
        while o < frame_len - 1024 {
            if corrs[o] > 0.35 {
                // local peak within a 2000-sample window
                let (mut bo, mut bc) = (o, corrs[o]);
                for k in o..(o + 2000).min(frame_len - 1024) { if corrs[k] > bc { bc = corrs[k]; bo = k; } }
                let slot = bo / slot_len;
                let sym_in_slot = {
                    // rough symbol index within the slot
                    let mut acc = slot * slot_len; let mut s = 0;
                    for l in 0..14 { let cp = ofdm.cp_len((slot % 2) * 14 + l, 1); if acc + cp <= bo { s = l; } acc += cp + fft; }
                    s
                };
                println!("  PSS peak {bc:.3} @ sample {bo} = slot {slot}, ~symbol {sym_in_slot}");
                o = bo + 2000;
            } else { o += 1; }
        }
    }

    // 0) Reconcile time vs frequency: slide the unit-energy time-domain PSS reference over
    //    slot 0 of frame 0 (what CellSearcher does), find the peak; then FFT that exact
    //    1024-sample useful-part window and correlate the frequency-domain PSS grid. If time
    //    is strong but frequency is weak at the same spot, the OFDM demod window/FFT is the issue.
    {
        use ferrite_phy::sync::ssb::pss_time_reference;
        let n_id_2 = (cell_id % 3) as u8;
        let tref = pss_time_reference(n_id_2, &ofdm); // 1024 samples, unit energy, no CP
        let mut best = (0usize, 0f32);
        for o in 0..slot_len {
            let mut acc = Complex32::new(0.0, 0.0);
            let mut pw = 0f32;
            for (i, r) in tref.iter().enumerate() {
                let s = fr[o + i];
                acc += s * r.conj();
                pw += s.norm_sqr();
            }
            let c = acc.norm() / pw.sqrt().max(1e-12); // tref already unit-energy
            if c > best.1 { best = (o, c); }
        }
        println!("\n=== time-domain PSS slide (frame 0, slot 0) ===");
        println!("  PEAK time PSS corr={:.3} @ sample {}", best.1, best.0);
        // FFT the useful part starting at the peak (o is the useful-part start since tref has no CP).
        let grid = ofdm.demodulate_symbol(&fr[best.0..], 0);
        let mut acc = Complex32::new(0.0, 0.0);
        let mut pw = 0f32;
        for (i, &v) in ferrite_phy::sync::pss::pss(n_id_2).iter().enumerate() {
            let bin = ((56 + i) as i32 - 120).rem_euclid(fft as i32) as usize;
            acc += grid[bin] * Complex32::new(v as f32, 0.0);
            pw += grid[bin].norm_sqr();
        }
        println!("  freq PSS corr of that exact window @ DC-centred bins = {:.3}", acc.norm() / (pw.sqrt() * (127f32).sqrt()).max(1e-9));
    }

    // 1) Power spectrum: average |grid[bin]|^2 over slot-0 symbols 0..1 of every frame,
    //    printed as a coarse histogram (bins folded to signed frequency around DC) so the
    //    carrier extent and where CORESET0 sits are visible.
    let spec_slot: usize = std::env::var("SPEC_SLOT").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut spec = vec![0f64; fft];
    let mut cnt = 0u32;
    {
        let g = demod(fr, spec_slot); // selected SSB frame, an active DL slot
        for l in 0..14 {
            for (bin, s) in spec.iter_mut().enumerate() {
                *s += g[l][bin].norm_sqr() as f64;
            }
            cnt += 1;
        }
    }
    println!("\n(power spectrum below is for slot {spec_slot} of frame {fsel}, all 14 symbols)");
    for s in &mut spec { *s /= cnt.max(1) as f64; }
    // Fold to signed subcarrier index [-512,512): bin b>fft/2 is negative freq.
    let signed = |b: usize| if b >= fft / 2 { b as i32 - fft as i32 } else { b as i32 };
    // Coarse 32-bucket histogram over [-512,512).
    println!("\n=== slot-0 CORESET-symbol power spectrum (32 buckets over ±512 sc, dB) ===");
    let buckets = 32usize;
    let mut hist = vec![0f64; buckets];
    let mut hcnt = vec![0u32; buckets];
    for b in 0..fft {
        let sc = signed(b);
        let idx = (((sc + 512) as usize) * buckets / 1024).min(buckets - 1);
        hist[idx] += spec[b];
        hcnt[idx] += 1;
    }
    let peak = hist.iter().cloned().fold(0f64, f64::max).max(1e-30);
    for i in 0..buckets {
        let sc_lo = (i as i32) * 1024 / buckets as i32 - 512;
        let avg = hist[i] / hcnt[i].max(1) as f64;
        let db = 10.0 * (avg / peak).max(1e-9).log10();
        let bars = ((db + 40.0).max(0.0) / 40.0 * 40.0) as usize;
        println!("sc {sc_lo:>5}: {db:6.1} dB {}", "#".repeat(bars));
    }

    // 2) Per-symbol total power over the CORESET0 band, slot 0 & slot 1, frame 0 —
    //    shows which symbols carry the SSB vs CORESET.
    println!("\n=== per-symbol power in CORESET0 band (frame 0) ===");
    for slot in 0..2usize {
        let g = demod(fr, slot);
        let mut line = format!("slot {slot}: ");
        for l in 0..14 {
            let mut p = 0f64;
            for sc in 0..(coreset.n_rb * 12) as i32 {
                p += g[l][sc_to_bin(sc)].norm_sqr() as f64;
            }
            line.push_str(&format!("{:5.2} ", (p / (coreset.n_rb * 12) as f64).sqrt()));
        }
        println!("{line}");
    }

    // 2b) SSB calibration: correlate the known PSS/SSS grids against the demodulated grid
    //     (SSB centred at DC). PSS at slot-0 symbol 2, SSS at symbol 4 (Case C, 30 kHz).
    //     Sweep the symbol index to locate the SSB in the grid; a high correlation confirms
    //     the grid demod + frequency reference are correct (⇒ absent PDCCH is real, not a
    //     demod bug). n_id_2 = cell_id % 3, n_id_1 = cell_id / 3.
    use ferrite_phy::sync::ssb::{extract_sync_subcarriers, pss_grid, sss_grid};
    let n_id_2 = (cell_id % 3) as u8;
    let n_id_1 = cell_id / 3;
    let pss_ref = extract_sync_subcarriers(&pss_grid(n_id_2, fft));
    let sss_ref = extract_sync_subcarriers(&sss_grid(n_id_1, n_id_2, fft));
    let corr127 = |rx: &[Complex32], reff: &[Complex32]| -> f32 {
        let mut acc = Complex32::new(0.0, 0.0);
        let mut pw = 0f32;
        for (r, e) in rx.iter().zip(reff) {
            acc += r * e.conj();
            pw += r.norm_sqr();
        }
        acc.norm() / (pw.sqrt() * (reff.iter().map(|c| c.norm_sqr()).sum::<f32>()).sqrt()).max(1e-9)
    };
    println!("\n=== SSB calibration (frame 0, slot 0): PSS/SSS grid correlation per symbol ===");
    let g0 = demod(fr, 0);
    for l in 0..14 {
        let rx = extract_sync_subcarriers(&g0[l]);
        let cp = corr127(&rx, &pss_ref);
        let cs = corr127(&rx, &sss_ref);
        println!("  sym {l:>2}: PSS corr={cp:.3}  SSS corr={cs:.3}");
    }

    // 2c) Locate the PSS in the grid by sweeping the raw FFT-window start (cp=0, bypassing
    //     cp_len) over the first ~2.5 symbols, and the frequency-bin offset. Reveals whether
    //     the failure is timing (window offset) or an integer-subcarrier frequency error.
    println!("\n=== PSS grid-correlation 2D sweep (frame 0): FFT start × freq-bin offset ===");
    let mut best = (0usize, 0i32, 0f32);
    for s in (0..4000usize).step_by(4) {
        let grid = ofdm.demodulate_symbol(&fr[s..], 0);
        for d in -20i32..=20 {
            // correlate PSS with a frequency-bin offset d
            let mut acc = Complex32::new(0.0, 0.0);
            let mut pw = 0f32;
            for (i, &v) in ferrite_phy::sync::pss::pss(n_id_2).iter().enumerate() {
                let bin = ((56 + i) as i32 - 120 + d).rem_euclid(fft as i32) as usize;
                let rx = grid[bin];
                acc += rx * Complex32::new(v as f32, 0.0);
                pw += rx.norm_sqr();
            }
            let c = acc.norm() / (pw.sqrt() * (127f32).sqrt()).max(1e-9);
            if c > best.2 { best = (s, d, c); }
        }
    }
    println!("  PEAK PSS grid corr={:.3} @ fft_start={} freq_bin_offset={}", best.2, best.0, best.1);
    // Show the correlation profile vs freq offset at the best start.
    {
        let grid = ofdm.demodulate_symbol(&fr[best.0..], 0);
        let mut line = String::new();
        for d in -12i32..=12 {
            let mut acc = Complex32::new(0.0, 0.0);
            let mut pw = 0f32;
            for (i, &v) in ferrite_phy::sync::pss::pss(n_id_2).iter().enumerate() {
                let bin = ((56 + i) as i32 - 120 + d).rem_euclid(fft as i32) as usize;
                acc += grid[bin] * Complex32::new(v as f32, 0.0);
                pw += grid[bin].norm_sqr();
            }
            let c = acc.norm() / (pw.sqrt() * (127f32).sqrt()).max(1e-9);
            line.push_str(&format!("d{d}={c:.2} "));
        }
        println!("  freq profile @ start {}: {line}", best.0);
    }

    // 3b) FINE-TIMING PDCCH: on the selected SSB frame, sweep a per-slot sample offset `d`
    //     added to every symbol's FFT window and, for each, correlate the CORESET0 PDCCH DMRS
    //     and attempt the SI-RNTI DCI decode. A working d confirms the failure is FFT-window
    //     timing (fixable with fine timing tracking), and by how many samples we are off.
    println!("\n=== fine-timing PDCCH sweep on SSB frame {fsel}, slot 0 (offset d) ===");
    let demod_off = |frame: &[Complex32], slot: usize, d: i64| -> Vec<Vec<Complex32>> {
        let mut grids = Vec::new();
        let mut off = (slot * slot_len) as i64 + d;
        for l in 0..14 {
            let cp = ofdm.cp_len((slot % 2) * 14 + l, 1);
            let start = off.max(0) as usize;
            if start + cp + fft <= frame.len() {
                grids.push(ofdm.demodulate_symbol(&frame[start..], cp));
            } else {
                grids.push(vec![Complex32::new(0.0, 0.0); fft]); // past buffer end — pad
            }
            off += (cp + fft) as i64;
        }
        grids
    };
    let cands = type0_candidates(coreset.n_cce());
    for d in -30i64..=30 {
        let g = demod_off(fr, 0, d);
        let cg: Vec<Vec<Complex32>> = (0..coreset.n_symb).map(|l| g[l].clone()).collect();
        let corr: f32 = (0..coreset.n_symb).map(|l| {
            let refs = pdcch_dmrs(cell_id, 0, l as u32, coreset.n_rb);
            let mut acc = Complex32::new(0.0, 0.0);
            let mut pw = 0f32;
            for rb in 0..coreset.n_rb {
                for p in 0..3 {
                    let sc = 12 * rb as i32 + 1 + 4 * p as i32;
                    let rx = cg[l][sc_to_bin(sc)];
                    acc += rx * refs[3 * rb + p].conj();
                    pw += rx.norm_sqr();
                }
            }
            acc.norm() / (pw.sqrt() * (coreset.n_rb as f32 * 3.0).sqrt()).max(1e-9)
        }).sum::<f32>() / coreset.n_symb as f32;
        let mut dci = false;
        for cand in &cands {
            let mut m = equalize_candidate(&cg, |sc: usize| sc_to_bin(sc as i32), &coreset, cell_id, 0, cand);
            pdcch_descramble_llr(&mut m, u32::from(cell_id));
            if dci_decode(&m, 0xFFFF, a_len).is_some() { dci = true; break; }
        }
        if corr > 0.25 || dci {
            println!("  d={d:>3}: mean DMRS corr={corr:.3}  DCI={}", if dci { "DECODED ***" } else { "-" });
        }
    }

    // 3) DL activity map + exhaustive SIB1 PDCCH search over ALL 20 slots of every frame.
    //    Activity map: per slot, mean sample amplitude across the whole FFT for symbol 0 —
    //    a high value marks a DL (transmitting) slot. Then correlate the CORESET0 PDCCH DMRS
    //    and attempt the SI-RNTI DCI decode in every slot (with a small fine-timing sweep),
    //    catching SIB1 wherever/whenever it is (long period / non-slot-0 occasion).
    println!("\n=== DL activity map (mean |sym0| over full FFT, per slot; '#' > 2x noise) ===");
    let mut noise = 0f64;
    let mut nn = 0u32;
    for f in 0..n_frames {
        let mut line = format!("f{f:>2}: ");
        for slot in 0..20 {
            let g = demod(&iq[f * frame_len..], slot);
            // Max mean-amplitude over ALL 14 symbols (catches PDCCH/PDSCH in any symbol).
            let amp: f64 = (0..14).map(|l| g[l].iter().map(|c| c.norm() as f64).sum::<f64>() / fft as f64)
                .fold(0f64, f64::max);
            noise += amp; nn += 1;
            let mark = if amp > 0.06 { '#' } else if amp > 0.045 { '+' } else { '.' };
            line.push(mark);
        }
        if f < 12 { println!("{line}"); }
    }
    println!("(mean amp over all slots/frames = {:.3})", noise / nn.max(1) as f64);

    println!("\n=== exhaustive SIB1 PDCCH search (all slots, all frames, fine-timing ±16) ===");
    let cands = type0_candidates(coreset.n_cce());
    let mut hits = 0u32;
    let mut best_corr = 0f32;
    let mut best_where = (0usize, 0usize, 0i64);
    for f in 0..n_frames {
        for slot in 0..20u32 {
            for d in (-16i64..=16).step_by(4) {
                let g = demod_off(&iq[f * frame_len..(f + 1) * frame_len], slot as usize, d);
                let cg: Vec<Vec<Complex32>> = (0..coreset.n_symb).map(|l| g[l].clone()).collect();
                let corr: f32 = (0..coreset.n_symb).map(|l| {
                    let refs = pdcch_dmrs(cell_id, slot, l as u32, coreset.n_rb);
                    let mut acc = Complex32::new(0.0, 0.0);
                    let mut pw = 0f32;
                    for rb in 0..coreset.n_rb {
                        for p in 0..3 {
                            let sc = 12 * rb as i32 + 1 + 4 * p as i32;
                            let rx = cg[l][sc_to_bin(sc)];
                            acc += rx * refs[3 * rb + p].conj();
                            pw += rx.norm_sqr();
                        }
                    }
                    acc.norm() / (pw.sqrt() * (coreset.n_rb as f32 * 3.0).sqrt()).max(1e-9)
                }).sum::<f32>() / coreset.n_symb as f32;
                if corr > best_corr { best_corr = corr; best_where = (f, slot as usize, d); }
                let mut got = false;
                for cand in &cands {
                    let mut m = equalize_candidate(&cg, |sc: usize| sc_to_bin(sc as i32), &coreset, cell_id, slot, cand);
                    pdcch_descramble_llr(&mut m, u32::from(cell_id));
                    if dci_decode(&m, 0xFFFF, a_len).is_some() { got = true; break; }
                }
                if got || corr > 0.4 {
                    hits += 1;
                    println!("  frame {f} slot {slot} d={d}: DMRS corr={corr:.3}  DCI={}", if got { "DECODED ***" } else { "-" });
                }
            }
        }
    }
    println!("hits={hits}; best DMRS corr={best_corr:.3} @ frame {} slot {} d={}", best_where.0, best_where.1, best_where.2);
}
