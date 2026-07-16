//! Offline analysis of a live DECODE-FAIL slot dumped by the UE (FERRITE_DRIFT →
//! /tmp/ferrite_fail.bin: 8×u32 LE header [slot, crnti, rb0, nrb, mcs, rv, h_id, short]
//! then f32 re/im pairs of the frequency-shifted slot). Reruns the exact live decode
//! across every (CDM × time-first) layout and several TBS/shape hypotheses, reporting
//! DM-RS metric, EVM, LDPC convergence and CRC per combination — localizing whether the
//! failure is extraction geometry, TBS, scrambling, or content.
//!
//! Usage: pdsch-fail [/tmp/ferrite_fail.bin]

use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
use ferrite_phy::ofdm::Ofdm;
use ferrite_phy::pdsch::{demod_slot, descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use num_complex::Complex32;

// tbs_from_nre (mirrors main.rs)
fn tbs_from_nre(n_re: usize, r: f64, qm: usize) -> usize {
    const TBL: &[usize] = &[24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,208,224,240,256,272,288,304,320,336,352,368,384,408,432,456,480,504,528,552,576,608,640,672,704,736,768,808,848,888,928,984,1032,1064,1128,1160,1192,1224,1256,1288,1320,1352,1416,1480,1544,1608,1672,1736,1800,1864,1928,2024,2088,2152,2216,2280,2408,2472,2536,2600,2664,2728,2792,2856,2976,3104,3240,3368,3496,3624,3752,3824];
    let n_info = (n_re as f64 * r * qm as f64).floor() as usize;
    let n = (((n_info as f64).log2().floor() as i64) - 6).max(3) as u32;
    let n_info_p = 24.max((1usize << n) * (n_info / (1usize << n)));
    *TBL.iter().find(|&&t| t >= n_info_p).unwrap_or(&3824)
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/ferrite_fail.bin".into());
    let b = std::fs::read(&path).unwrap();
    let u = |i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
    let (slot_idx, crnti, rb0, nrb, mcs, rv, h_id, sliv, bin0) =
        (u(0), u(1) as u16, u(2) as usize, u(3) as usize, u(4) as u8, u(5) as u8, u(6), u(7) as u8, u(8) as i32);
    let fsh: Vec<Complex32> = b[36..]
        .chunks_exact(8)
        .map(|c| Complex32::new(
            f32::from_le_bytes(c[0..4].try_into().unwrap()),
            f32::from_le_bytes(c[4..8].try_into().unwrap()),
        ))
        .collect();
    // Header field 7 is the SLIV (main.rs dumps `u32::from(sliv)`); derive the shape from it.
    // fft from the sample count: slot_len = 15·fft at µ=1 (14 syms + CPs).
    let fft = fsh.len() / 15;
    println!("slot={slot_idx} crnti={crnti:#06x} rb[{rb0},{}) mcs={mcs} rv={rv} h{h_id} sliv={sliv} fft={fft} samples={}",
        rb0 + nrb, fsh.len());

    let ofdm = Ofdm::new(fft);
    let sc_to_bin = move |sc: i32| (bin0 + sc).rem_euclid(fft as i32) as usize;
    let cell_id = 1u16;
    println!("bin0={bin0}");

    let grids = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1).expect("demod");

    let (qm0, r0) = mcs_params(mcs);
    println!("DCI shape: qm={qm0} r={:.4}", r0);
    // Shape from the SLIV (mirrors main.rs dl_pdsch_shape).
    let (sym_start, n_sym) = ferrite_ue::sib1::sliv_to_sl(sliv);
    let dmrs: Vec<usize> = match sym_start + n_sym {
        ..=7 => vec![2],
        8 | 9 => vec![2, 7],
        10 => vec![2, 6, 9],
        11 => vec![2, 7, 10],
        _ => vec![2, 7, 11],
    };
    let dmrs: Vec<usize> = std::env::var("DMRS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().parse().unwrap()).collect())
        .unwrap_or(dmrs);
    println!("SLIV {sliv} -> S={sym_start} L={n_sym} dmrs={dmrs:?}");

    // Timing sweep: re-demod the raw slot at small FFT-window offsets and report the
    // cdm=1 data EVM + CRC. A residual DL timing offset shows up as data symbols
    // adjacent to DM-RS being corrupted; a small window shift should clear it.
    {
        let (qm_i, r_i) = mcs_params(9);
        const PAD: i32 = 64;
        let mut padded = vec![Complex32::new(0.0, 0.0); PAD as usize];
        padded.extend_from_slice(&fsh);
        padded.extend(std::iter::repeat(Complex32::new(0.0, 0.0)).take(128));
        println!("--- timing sweep (cdm=1, DCI shape) ---");
        let n_re = nrb * ((n_sym - dmrs.len()) * 12 + dmrs.len() * 6);
        let tbs = tbs_from_nre(n_re, r_i, qm_i as usize);
        for off in [-24i32, -16, -12, -8, -4, -2, 0, 2, 4, 8, 12, 16, 24] {
            let start = (PAD + off) as usize;
            let Some(g) = demod_slot(&ofdm, &padded, start, slot_idx as usize % 2, 1) else { continue };
            let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start, n_sym, dmrs_symbols: dmrs.clone(), qm: qm0 as usize, n_bwp: 0, nof_cdm_groups: 1 };
            let px = extract_pdsch(&g, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, true);
            let mut llr = px.llrs.clone();
            descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
            let (_b, _c, crc) = dlsch_decode_single_bits(&llr, tbs, r_i, qm0 as usize, rv, 40);
            println!("  off={off:+} dmrs={:.3} evm={:.3} slope={:.4} crc={crc}", px.dmrs_metric, px.evm, px.dbg_slope);
        }
    }

    // Slope-ambiguity sweep (2-DM-RS case): the true CFO slope is base + k·2π/gap.
    // Recompute h_avg + equalize for each candidate and report data EVM + CRC.
    if dmrs.len() == 2 {
        use num_complex::Complex32 as C;
        use std::f32::consts::{FRAC_1_SQRT_2, TAU};
        let (qm_i, r_i) = mcs_params(9);
        let n_re = nrb * ((n_sym - 2) * 12 + 2 * 6);
        let tbs = tbs_from_nre(n_re, r_i, qm_i as usize);
        let gap = (dmrs[1] - dmrs[0]) as f32;
        // per-(dmrs-sym, rb) channel
        let mut h = vec![vec![C::new(0.0, 0.0); nrb]; 2];
        for (si, &l) in dmrs.iter().enumerate() {
            let full_ref = ferrite_phy::pdsch::pdsch_dmrs(cell_id, slot_idx, l as u32, 6 * (rb0 + nrb + 1));
            for rb in 0..nrb {
                let mut acc = C::new(0.0, 0.0);
                for j in 0..6 { acc += grids[dmrs[si]][sc_to_bin((12 * (rb0 + rb) + 2 * j) as i32)] * full_ref[6 * (rb0 + rb) + j].conj(); }
                h[si][rb] = acc / 6.0;
            }
        }
        let base = (h[1].iter().copied().sum::<C>().arg() - h[0].iter().copied().sum::<C>().arg()) / gap;
        let dmrs_set: std::collections::HashSet<usize> = dmrs.iter().copied().collect();
        println!("--- slope-ambiguity sweep (base={base:.4}, step=2π/{gap}={:.4}) ---", TAU / gap);
        for k in -3..=3 {
            let slope = base + k as f32 * TAU / gap;
            let mut h_avg = vec![C::new(0.0, 0.0); nrb];
            for (si, &ls) in dmrs.iter().enumerate() {
                let d = C::from_polar(1.0, -slope * ls as f32);
                for rb in 0..nrb { h_avg[rb] += h[si][rb] * d; }
            }
            for hr in &mut h_avg { *hr /= 2.0; }
            let (mut e, mut n) = (0f32, 0usize);
            let mut llr: Vec<f32> = Vec::new();
            for l in sym_start..sym_start + n_sym {
                for kp in 0..(12 * nrb) {
                    let sc = kp % 12;
                    let is_data = if !dmrs_set.contains(&l) { true } else { sc % 2 == 1 };
                    if !is_data { continue; }
                    let rb = kp / 12;
                    let chan = h_avg[rb] * C::from_polar(1.0, slope * l as f32);
                    let z = grids[l][sc_to_bin((12 * (rb0 + rb) + sc) as i32)] * chan.conj();
                    let m = z.norm().max(1e-12);
                    e += (z / m - C::new(z.re.signum(), z.im.signum()) * FRAC_1_SQRT_2).norm_sqr(); n += 1;
                    llr.push(z.re); llr.push(z.im);
                }
            }
            descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
            let (_b, _c, crc) = dlsch_decode_single_bits(&llr, tbs, r_i, qm0 as usize, rv, 40);
            println!("  k={k:+} slope={slope:+.4} evm={:.3} crc={crc}", (e / n as f32).sqrt());
        }
    }

    // Hypotheses: the DCI's own shape, and initial-tx shapes at higher MCS.
    for hyp_mcs in [mcs, 8, 9] {
        let (qm_i, r_i) = mcs_params(hyp_mcs);
        for (cdm, tf) in [(1usize, true), (1, false), (2, true), (2, false)] {
            let n_re = nrb * ((n_sym - dmrs.len()) * 12 + if cdm == 1 { dmrs.len() * 6 } else { 0 });
            let tbs = tbs_from_nre(n_re, r_i, qm_i as usize);
            let alloc = PdschAlloc { rb_start: rb0, n_rb: nrb, sym_start, n_sym, dmrs_symbols: dmrs.clone(), qm: qm0 as usize, n_bwp: 0, nof_cdm_groups: cdm };
            let px = extract_pdsch(&grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, tf);
            let mut llr = px.llrs.clone();
            descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
            let (_bits, conv, crc) = dlsch_decode_single_bits(&llr, tbs, r_i, qm0 as usize, rv, std::env::var("ITER").ok().and_then(|v| v.parse().ok()).unwrap_or(40));
            println!("hyp_mcs={hyp_mcs} cdm={cdm} tf={tf} tbs={tbs} e={} dmrs={:.3} evm={:.3} slope={:.4} conv={conv} crc={crc}",
                px.n_data_re * qm0 as usize, px.dmrs_metric, px.evm, px.dbg_slope);
        }
    }

    // Per-OFDM-symbol EVM for the gNB's actual config (cdm=1): re-estimate the per-RB
    // channel + CFO slope exactly as extract_pdsch, then bucket the equalized-symbol
    // error by OFDM symbol to localize which symbols carry the bad REs.
    println!("--- per-symbol EVM (cdm=1) ---");
    use num_complex::Complex32 as C;
    use std::f32::consts::FRAC_1_SQRT_2;
    let cdm = 1usize;
    let mut h = vec![vec![C::new(0.0, 0.0); nrb]; dmrs.len()];
    for (si, &l) in dmrs.iter().enumerate() {
        let full_ref = ferrite_phy::pdsch::pdsch_dmrs(cell_id, slot_idx, l as u32, 6 * (rb0 + nrb + 1));
        for rb in 0..nrb {
            let mut acc = C::new(0.0, 0.0);
            for j in 0..6 {
                let k = (12 * (rb0 + rb) + 2 * j) as i32;
                acc += grids[l][sc_to_bin(k)] * full_ref[6 * (rb0 + rb) + j].conj();
            }
            h[si][rb] = acc / 6.0;
        }
    }
    let sym_phase: Vec<f32> = h.iter().map(|hr| hr.iter().copied().sum::<C>().arg()).collect();
    let slope = if dmrs.len() == 2 { (sym_phase[1] - sym_phase[0]) / (dmrs[1] as f32 - dmrs[0] as f32) } else { 0.0 };
    let mut h_avg = vec![C::new(0.0, 0.0); nrb];
    for (si, &ls) in dmrs.iter().enumerate() {
        let derot = C::from_polar(1.0, -slope * ls as f32);
        for rb in 0..nrb { h_avg[rb] += h[si][rb] * derot; }
    }
    for hr in &mut h_avg { *hr /= dmrs.len() as f32; }
    let dmrs_set: std::collections::HashSet<usize> = dmrs.iter().copied().collect();
    // nearest DM-RS symbol index for each data symbol.
    let nearest = |l: usize| -> usize {
        (0..dmrs.len()).min_by_key(|&si| (dmrs[si] as i32 - l as i32).abs()).unwrap()
    };
    for l in sym_start..sym_start + n_sym {
        let (mut e_model, mut e_near, mut e_raw) = (0f32, 0f32, 0f32);
        let mut n = 0usize;
        for kp in 0..(12 * nrb) {
            let sc = kp % 12;
            let is_data = if !dmrs_set.contains(&l) { true } else { cdm == 1 && sc % 2 == 1 };
            if !is_data { continue; }
            let rb = kp / 12;
            let k = (12 * (rb0 + rb) + sc) as i32;
            let rx = grids[l][sc_to_bin(k)];
            let ev = |z: C| { let m = z.norm().max(1e-12); (z / m - C::new(z.re.signum(), z.im.signum()) * FRAC_1_SQRT_2).norm_sqr() };
            // (a) current model: h_avg · e^{j slope l}
            e_model += ev(rx * (h_avg[rb] * C::from_polar(1.0, slope * l as f32)).conj());
            // (b) nearest DM-RS symbol's raw per-RB channel, no slope
            e_near += ev(rx * h[nearest(l)][rb].conj());
            // (c) nearest DM-RS symbol de-rotated by slope to this symbol
            let si = nearest(l);
            e_raw += ev(rx * (h[si][rb] * C::from_polar(1.0, slope * (l as f32 - dmrs[si] as f32))).conj());
            n += 1;
        }
        // QPSK-removed residual: (rx/h)^4 has 4× the residual rotation and no data.
        // High |mean| coherence ⇒ a CLEAN constant rotation (phase bug); low ⇒ scatter.
        let mut q4 = C::new(0.0, 0.0);
        let mut q4n = 0usize;
        for kp in 0..(12 * nrb) {
            let sc = kp % 12;
            let is_data = if !dmrs_set.contains(&l) { true } else { cdm == 1 && sc % 2 == 1 };
            if !is_data { continue; }
            let rb = kp / 12;
            let z = grids[l][sc_to_bin((12 * (rb0 + rb) + sc) as i32)] * h[0][rb].conj();
            let u = (z / z.norm().max(1e-12)).powu(4);
            q4 += u; q4n += 1;
        }
        let coh = q4.norm() / q4n.max(1) as f32;
        let resid_deg = q4.arg().to_degrees() / 4.0;
        if n > 0 {
            println!("  sym {l}: model={:.3} nearest={:.3} coh4={coh:.3} resid≈{resid_deg:+.1}° n={n}{}",
                (e_model / n as f32).sqrt(), (e_near / n as f32).sqrt(),
                if dmrs_set.contains(&l) { " (dmrs-sym odd-sc)" } else { "" });
        }
    }
}
