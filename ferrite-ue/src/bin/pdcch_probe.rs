//! Offline PDCCH analysis of a "PDSCH present, NO DCI FOUND" slot dumped by the UE
//! (/tmp/ferrite_nodci.bin, same header as ferrite_fail.bin). Replays T0's exact
//! CORESET1 blind sweep — coherence gate, equalize, polar decode at 36 and 40 bits —
//! for EVERY candidate, printing per-candidate results so a missed DCI localizes to
//! the gate, the equalizer, or the polar decode.
//!
//! Usage: pdcch-probe [/tmp/ferrite_nodci.bin]

use ferrite_phy::coding::dci::{dci_decode, pdcch_descramble_llr};
use ferrite_phy::ofdm::Ofdm;
use ferrite_phy::pdcch::{all_candidates, coreset_candidate_coherence, equalize_candidate_c1_cached, estimate_coreset_c1};
use num_complex::Complex32;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/ferrite_nodci.bin".into());
    let b = std::fs::read(&path).unwrap();
    let u = |i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
    let (slot_idx, crnti, bin0) = (u(0), u(1) as u16, u(8) as i32);
    let fsh: Vec<Complex32> = b[36..]
        .chunks_exact(8)
        .map(|c| Complex32::new(
            f32::from_le_bytes(c[0..4].try_into().unwrap()),
            f32::from_le_bytes(c[4..8].try_into().unwrap()),
        ))
        .collect();
    println!("slot={slot_idx} crnti={crnti:#06x} bin0={bin0} samples={}", fsh.len());

    let fft = 512usize;
    let ofdm = Ofdm::new(fft);
    let sc_to_bin = move |sc: i32| (bin0 + sc).rem_euclid(fft as i32) as usize;
    let (cell_id, carrier_rb, n_symb, n_cce) = (1u16, 24usize, 2usize, 8usize);

    // CORESET grids: first n_symb symbols (T0's cgrids).
    let mut cgrids = Vec::new();
    let mut off = 0usize;
    for l in 0..n_symb {
        let cp = ofdm.cp_len((slot_idx as usize % 2) * 14 + l, 1);
        cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
        off += cp + fft;
    }

    let h_reg = estimate_coreset_c1(&cgrids, |sc: usize| sc_to_bin(sc as i32), carrier_rb, n_symb, cell_id, slot_idx);
    for cand in all_candidates(n_cce, &[1, 2, 4, 8]) {
        let coh = coreset_candidate_coherence(&h_reg, &cand, n_symb);
        let mut mm = equalize_candidate_c1_cached(&cgrids, |sc: usize| sc_to_bin(sc as i32), n_symb, &cand, &h_reg);
        pdcch_descramble_llr(&mut mm, u32::from(cell_id));
        let d36 = dci_decode(&mm, crnti, 36).map(|b| b.iter().map(|x| x.to_string()).collect::<String>());
        let d40 = dci_decode(&mm, crnti, 40).map(|b| b.iter().map(|x| x.to_string()).collect::<String>());
        println!("AL{} cces={:?} coh={coh:.3} gate={} dci36={:?} dci40={:?}",
            cand.agg_level, (cand.cces.first(), cand.cces.last()), if coh >= 0.5 { "PASS" } else { "skip" }, d36, d40);
    }
}
