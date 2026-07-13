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
    let (slot_idx, crnti, rb0, nrb, mcs, rv, h_id, short, bin0) =
        (u(0), u(1) as u16, u(2) as usize, u(3) as usize, u(4) as u8, u(5) as u8, u(6), u(7) != 0, u(8) as i32);
    let fsh: Vec<Complex32> = b[36..]
        .chunks_exact(8)
        .map(|c| Complex32::new(
            f32::from_le_bytes(c[0..4].try_into().unwrap()),
            f32::from_le_bytes(c[4..8].try_into().unwrap()),
        ))
        .collect();
    println!("slot={slot_idx} crnti={crnti:#06x} rb[{rb0},{}) mcs={mcs} rv={rv} h{h_id} short={short} samples={}",
        rb0 + nrb, fsh.len());

    // The live cell: fft 512; bin0 (dumped) is the FFT bin of CORESET0 subcarrier 0.
    let fft = 512;
    let ofdm = Ofdm::new(fft);
    let sc_to_bin = move |sc: i32| (bin0 + sc).rem_euclid(fft as i32) as usize;
    let cell_id = 1u16;
    println!("bin0={bin0}");

    let grids = demod_slot(&ofdm, &fsh, 0, slot_idx as usize % 2, 1).expect("demod");

    let (qm0, r0) = mcs_params(mcs);
    println!("DCI shape: qm={qm0} r={:.4}", r0);
    let (sym_start, n_sym, dmrs): (usize, usize, Vec<usize>) =
        if short { (2, 6, vec![2, 7]) } else { (2, 12, vec![2, 7, 11]) };

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
            println!("hyp_mcs={hyp_mcs} cdm={cdm} tf={tf} tbs={tbs} e={} dmrs={:.3} evm={:.3} conv={conv} crc={crc}",
                px.n_data_re * qm0 as usize, px.dmrs_metric, px.evm);
        }
    }
}
