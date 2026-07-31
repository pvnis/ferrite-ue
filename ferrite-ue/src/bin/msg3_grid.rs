//! Dump the Msg3 PUSCH resource grid (data + DM-RS) with CRB-subcarrier
//! coordinates so an OCUDU pusch_processor harness can decode it directly,
//! isolating the grid (mapping/DMRS/scramble/coding) from the OFDM/timing.
//!
//! Output lines: <crb_subcarrier> <symbol> <re> <im>. Fixed Msg3 config.

use ferrite_phy::coding::dlsch::dlsch_encode_single;
use ferrite_phy::pdsch::{pdsch_dmrs, pdsch_scramble_c_init};
use ferrite_phy::sequence::gold_sequence;
use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

fn qpsk(b0: u8, b1: u8) -> Complex32 {
    Complex32::new((1 - 2 * b0 as i32) as f32 * FRAC_1_SQRT_2, (1 - 2 * b1 as i32) as f32 * FRAC_1_SQRT_2)
}

fn main() {
    let (cell, tc, slot) = (1u16, 0x4601u16, 17u32);
    let (rb_start, n_rb, carrier_rb, crb_off) = (4usize, 3usize, 24usize, 0usize);
    let dmrs = [2usize, 7, 11];

    let tb_bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
    let tb: Vec<u8> = tb_bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
    let e = (14 - dmrs.len()) * n_rb * 12 * 2;
    let ulsch = dlsch_encode_single(&tb, e, 0.117, 2, 0);
    let c = gold_sequence(pdsch_scramble_c_init(tc, cell), ulsch.len());
    let g: Vec<u8> = ulsch.iter().zip(&c).map(|(a, b)| a ^ b).collect();
    let data: Vec<Complex32> = g.chunks_exact(2).map(|p| qpsk(p[0], p[1])).collect();

    let dmset: std::collections::HashSet<usize> = dmrs.iter().copied().collect();
    let data_syms: Vec<usize> = (0..14).filter(|l| !dmset.contains(l)).collect();

    // Data — §6.3.1.6 order: increasing k first (inner), then l (outer).
    let mut di = 0;
    for &l in &data_syms {
        for kp in 0..(12 * n_rb) {
            let crb_sc = 12 * (crb_off + rb_start + kp / 12) + kp % 12;
            let v = data[di];
            di += 1;
            println!("{crb_sc} {l} {:.6} {:.6}", v.re, v.im);
        }
    }
    // DM-RS — CDM group 0, CRB-referenced.
    for &l in &dmrs {
        let refs = pdsch_dmrs(cell, slot, l as u32, 6 * (crb_off + carrier_rb));
        for rb in 0..n_rb {
            for j in 0..6 {
                let crb_sc = 12 * (crb_off + rb_start + rb) + 2 * j;
                let v = refs[6 * (crb_off + rb_start + rb) + j];
                println!("{crb_sc} {l} {:.6} {:.6}", v.re, v.im);
            }
        }
    }
}
