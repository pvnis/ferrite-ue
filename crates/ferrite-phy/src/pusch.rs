//! PUSCH (uplink shared channel) modulation for Msg3 — CP-OFDM, no transform
//! precoding. Scramble the UL-SCH bits (TS 38.211 §6.3.1.1), QPSK-map, place
//! data and DM-RS on the allocated RBs/symbols, and IFFT each OFDM symbol.
//!
//! UL-SCH channel coding is identical to DL-SCH (reuse `coding::dlsch`), and the
//! PUSCH DM-RS sequence uses the same `c_init` as PDSCH (reuse `pdsch_dmrs`).

use crate::pdsch::{pdsch_dmrs, pdsch_scramble_c_init};
use crate::sequence::gold_sequence;
use crate::Ofdm;
use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

/// Msg3 PUSCH resource allocation on the initial UL BWP (relative to the UL
/// carrier, which is centred at DC in the IFFT).
#[derive(Clone, Debug)]
pub struct PuschAlloc {
    /// First RB, relative to the UL carrier.
    pub rb_start: usize,
    /// Number of RBs.
    pub n_rb: usize,
    /// Slot symbols carrying single-symbol DM-RS (config type 1, CDM group 0).
    pub dmrs_symbols: Vec<usize>,
    /// Modulation order (2 = QPSK).
    pub qm: usize,
    /// UL carrier size in RBs (for DC-centred subcarrier→bin mapping).
    pub carrier_rb: usize,
}

fn qpsk(b0: u8, b1: u8) -> Complex32 {
    Complex32::new((1 - 2 * b0 as i32) as f32 * FRAC_1_SQRT_2, (1 - 2 * b1 as i32) as f32 * FRAC_1_SQRT_2)
}

/// Modulate one PUSCH slot (14 OFDM symbols) carrying `ulsch` rate-matched bits.
/// Returns the CP-OFDM time-domain samples for the slot. `slot_in_frame` drives
/// the DM-RS sequence, `slot_in_subframe` (0/1 at μ=1) the cyclic-prefix pattern.
pub fn pusch_modulate_slot(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    tc_rnti: u16,
) -> Vec<Complex32> {
    let n = ofdm.fft_size();
    let center = alloc.carrier_rb * 6; // DC subcarrier index of the UL carrier
    let bin = |sc: usize| (sc as i32 - center as i32).rem_euclid(n as i32) as usize;

    // Scramble (§6.3.1.1): c_init = n_RNTI·2^15 + n_ID (n_RNTI = TC-RNTI, n_ID = PCI).
    let c = gold_sequence(pdsch_scramble_c_init(tc_rnti, cell_id), ulsch.len());
    let g: Vec<u8> = ulsch.iter().zip(&c).map(|(a, b)| a ^ b).collect();
    let data: Vec<Complex32> = g.chunks_exact(2).map(|p| qpsk(p[0], p[1])).collect();

    let dmrs_set: std::collections::HashSet<usize> = alloc.dmrs_symbols.iter().copied().collect();
    let data_syms: Vec<usize> = (0..14).filter(|l| !dmrs_set.contains(l)).collect();

    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 14];
    // Data in §6.3.1.6 order: increasing k' (subcarrier over RBs), then l.
    let mut di = 0;
    for kp in 0..(12 * alloc.n_rb) {
        let sc = 12 * alloc.rb_start + kp;
        for &l in &data_syms {
            if di < data.len() {
                grids[l][bin(sc)] = data[di];
                di += 1;
            }
        }
    }
    // DM-RS (config type 1, CDM group 0: even subcarriers), PRB-domain sequence.
    for &l in &alloc.dmrs_symbols {
        let refs = pdsch_dmrs(cell_id, slot_in_frame, l as u32, alloc.carrier_rb * 6);
        for rb in 0..alloc.n_rb {
            for j in 0..6 {
                let sc = 12 * (alloc.rb_start + rb) + 2 * j;
                grids[l][bin(sc)] = refs[6 * (alloc.rb_start + rb) + j];
            }
        }
    }

    let mut out = Vec::with_capacity(14 * (n + 40));
    for (l, grid) in grids.iter().enumerate() {
        let cp = ofdm.cp_len(slot_in_subframe * 14 + l, 1);
        out.extend(ofdm.modulate_symbol(grid, cp));
    }
    out
}

/// Number of PUSCH data REs and rate-match length `E = N_RE·Qm` for an
/// allocation (2 DM-RS CDM groups without data → no data on DM-RS symbols).
pub fn pusch_e_len(alloc: &PuschAlloc) -> usize {
    let data_syms = 14 - alloc.dmrs_symbols.len();
    data_syms * alloc.n_rb * 12 * alloc.qm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::dlsch::{dlsch_decode_single, dlsch_encode_single};
    use crate::pdsch::descramble_llrs;

    /// Modulate a Msg3-sized PUSCH, demodulate it, equalise trivially (no
    /// channel), descramble, and recover the transport block.
    #[test]
    fn pusch_msg3_round_trip() {
        let ofdm = Ofdm::new(512);
        let alloc = PuschAlloc { rb_start: 4, n_rb: 3, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb: 24 };
        let e = pusch_e_len(&alloc);
        assert_eq!(e, 792);
        let (cell_id, tc_rnti, r) = (1u16, 0x4601u16, 0.117);

        // Msg3 TB: 11 bytes (88 bits).
        let tb_bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
        let tb: Vec<u8> = tb_bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
        let ulsch = dlsch_encode_single(&tb, e, r, 2, 0);

        let slot = pusch_modulate_slot(&ofdm, &ulsch, &alloc, cell_id, 5, 1, tc_rnti);

        // Demodulate: extract the data REs (skip DM-RS symbols), form soft bits.
        let center = alloc.carrier_rb as i32 * 6;
        let bin = |sc: usize| (sc as i32 - center).rem_euclid(512) as usize;
        let dmrs: std::collections::HashSet<usize> = alloc.dmrs_symbols.iter().copied().collect();
        let mut grids = Vec::new();
        let mut off = 0;
        for l in 0..14 {
            let cp = ofdm.cp_len(14 + l, 1);
            grids.push(ofdm.demodulate_symbol(&slot[off..], cp));
            off += cp + 512;
        }
        let mut llr: Vec<f32> = Vec::new();
        for kp in 0..(12 * alloc.n_rb) {
            let sc = 12 * alloc.rb_start + kp;
            for l in 0..14 {
                if dmrs.contains(&l) {
                    continue;
                }
                let z = grids[l][bin(sc)];
                llr.push(z.re);
                llr.push(z.im);
            }
        }
        descramble_llrs(&mut llr, pdsch_scramble_c_init(tc_rnti, cell_id));
        let out = dlsch_decode_single(&llr, 88, r, 2, 0, 40).expect("decode");
        let out_bytes: Vec<u8> = out.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b)).collect();
        assert_eq!(out_bytes, tb_bytes);
    }
}
