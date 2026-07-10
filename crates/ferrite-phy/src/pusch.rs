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
    /// CRB of the carrier's RB 0 (= offsetToPointA in this SCS). The PUSCH DM-RS
    /// sequence is referenced to CRB 0 / point A (§6.4.1.1.1.2), so the sequence
    /// index is `6·(crb_offset + PRB) + j`, not `6·PRB + j`.
    pub crb_offset: usize,
}

fn qpsk(b0: u8, b1: u8) -> Complex32 {
    Complex32::new((1 - 2 * b0 as i32) as f32 * FRAC_1_SQRT_2, (1 - 2 * b1 as i32) as f32 * FRAC_1_SQRT_2)
}

/// Modulate one PUSCH slot (14 OFDM symbols) carrying `ulsch` rate-matched bits.
/// Returns the CP-OFDM time-domain samples for the slot. `slot_in_frame` drives
/// the DM-RS sequence, `slot_in_subframe` (0/1 at μ=1) the cyclic-prefix pattern.
///
/// `center_freq_hz` applies the TS 38.211 §5.4 per-symbol phase compensation
/// (multiply symbol l by `exp(-j2π·f_c·t_start,l)`, `t_start` from the subframe
/// start): the gNB's OFDM demodulator removes this using the carrier centre
/// frequency, so an uncompensated uplink decodes at a garbage SINR. Pass 0.0 to
/// disable (e.g. for the self-consistent round-trip test). `fs` is the sample rate.
#[allow(clippy::too_many_arguments)]
pub fn pusch_modulate_slot(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    tc_rnti: u16,
    center_freq_hz: f64,
    fs: f64,
) -> Vec<Complex32> {
    pusch_modulate_slot_uci(ofdm, ulsch, alloc, cell_id, slot_in_frame, slot_in_subframe, tc_rnti, center_freq_hz, fs, &[], 0.0, 0)
}

/// As `pusch_modulate_slot`, but multiplex up to 2 HARQ-ACK bits onto the PUSCH
/// (UCI-on-PUSCH, TS 38.212 §6.2.7 / 38.213 §9.3): the gNB moves the DL HARQ-ACK
/// onto a scheduled PUSCH instead of the PUCCH. For ≤2 bits the ACK PUNCTURES the
/// UL-SCH (the UL-SCH rate-match is unchanged; the ACK REs overwrite data REs), so
/// only the ACK RE placement + encoding differ. `beta_harq` = beta_offset_harq_ack
/// value, `tb_bits` = UL-SCH transport-block size (bits) for Q'_ACK. `harq_ack`
/// empty ⇒ identical to `pusch_modulate_slot`.
#[allow(clippy::too_many_arguments)]
pub fn pusch_modulate_slot_uci(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    tc_rnti: u16,
    center_freq_hz: f64,
    fs: f64,
    harq_ack: &[u8],
    beta_harq: f32,
    tb_bits: usize,
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
    // Data in §6.3.1.6 order: increasing k' (subcarrier over RBs) first, then l.
    // i.e. fill a whole OFDM symbol across subcarriers before moving to the next.
    let mut di = 0;
    for &l in &data_syms {
        for kp in 0..(12 * alloc.n_rb) {
            let sc = 12 * alloc.rb_start + kp;
            if di < data.len() {
                grids[l][bin(sc)] = data[di];
                di += 1;
            }
        }
    }
    // DM-RS (config type 1, CDM group 0: even subcarriers). Sequence referenced
    // to CRB 0 (point A): index by 6·(crb_offset + PRB) + j.
    for &l in &alloc.dmrs_symbols {
        let refs = pdsch_dmrs(cell_id, slot_in_frame, l as u32, 6 * (alloc.crb_offset + alloc.carrier_rb));
        for rb in 0..alloc.n_rb {
            for j in 0..6 {
                let sc = 12 * (alloc.rb_start + rb) + 2 * j;
                grids[l][bin(sc)] = refs[6 * (alloc.crb_offset + alloc.rb_start + rb) + j];
            }
        }
    }

    // UCI-on-PUSCH: overwrite (puncture) the selected data REs with the HARQ-ACK
    // QPSK symbols. Each ACK RE is at data index `di` in the k'-first, then-l map;
    // the scrambling bits are c[2·di], c[2·di+1] (same sequence as the data). For
    // 1 bit the two QPSK components repeat the (scrambled) bit (placeholder y); for
    // 2 bits the [a0,a1,a0⊕a1] small block code is spread over the REs.
    if !harq_ack.is_empty() {
        let o_ack = harq_ack.len().min(2);
        let n_sc = 12 * alloc.n_rb;
        let res = harq_ack_pusch_res(&alloc.dmrs_symbols, alloc.n_rb, o_ack, beta_harq, tb_bits);
        let code = |k: usize| -> u8 {
            match o_ack {
                1 => harq_ack[0],
                _ => [harq_ack[0], harq_ack[1], harq_ack[0] ^ harq_ack[1]][k % 3],
            }
        };
        for (i, &(l, sc_a)) in res.iter().enumerate() {
            let di = data_syms.iter().position(|&x| x == l).unwrap() * n_sc + sc_a;
            let (m0, m1) = (c[2 * di], c[2 * di + 1]);
            let sym = if o_ack == 1 {
                let b = harq_ack[0] ^ m0; // placeholder y: both components carry a0⊕c0
                qpsk(b, b)
            } else {
                qpsk(code(2 * i) ^ m0, code(2 * i + 1) ^ m1)
            };
            grids[l][bin(12 * alloc.rb_start + sc_a)] = sym;
        }
    }

    let mut out = Vec::with_capacity(14 * (n + 40));
    // Sample offset from the subframe start to this slot's first symbol.
    let mut sub_off: usize = (0..slot_in_subframe * 14).map(|k| ofdm.cp_len(k, 1) + n).sum();
    for (l, grid) in grids.iter().enumerate() {
        let cp = ofdm.cp_len(slot_in_subframe * 14 + l, 1);
        let sym = ofdm.modulate_symbol(grid, cp);
        if center_freq_hz != 0.0 {
            // §5.4 phase compensation: t_start = start of the useful part.
            let t_start = (sub_off + cp) as f64 / fs;
            let phase = -2.0 * std::f64::consts::PI * center_freq_hz * t_start;
            let coeff = Complex32::new(phase.cos() as f32, phase.sin() as f32);
            out.extend(sym.iter().map(|s| s * coeff));
        } else {
            out.extend(sym);
        }
        sub_off += cp + n;
    }
    out
}

/// HARQ-ACK-on-PUSCH RE placement for 1-2 ACK bits (QPSK), matching OCUDU's
/// `ulsch_demultiplex` (TS 38.212 §6.2.7): reserve Q'_rvd REs across the non-DM-RS
/// symbols starting after the first DM-RS symbol (strided so each symbol carries a
/// fair share), then place the actual Q'_ACK REs on a strided subset of the reserved
/// ones. Returns each ACK RE as `(symbol, subcarrier-within-alloc)`, in gNB order.
fn harq_ack_pusch_res(dmrs_symbols: &[usize], n_rb: usize, o_ack: usize, beta: f32, tb_bits: usize) -> Vec<(usize, usize)> {
    let n_sc = 12 * n_rb;
    let dmrs: std::collections::HashSet<usize> = dmrs_symbols.iter().copied().collect();
    let data_syms: Vec<usize> = (0..14).filter(|l| !dmrs.contains(l)).collect();
    let first_dmrs = *dmrs_symbols.iter().min().unwrap();
    let l1 = match data_syms.iter().find(|&&l| l > first_dmrs) {
        Some(&l) => l,
        None => return Vec::new(),
    };
    let nof_re_uci = data_syms.len() * n_sc;
    let nof_re_uci_l0 = data_syms.iter().filter(|&&l| l > first_dmrs).count() * n_sc;
    let crc = if tb_bits <= 3824 { 16 } else { 24 };
    let sum_cb = (tb_bits + crc) as f32;
    // Q'_ACK = min(ceil(O_ACK·β·M_uci / ΣK), ceil(α·M_uci_l0)), α = 1.
    let q_of = |oa: usize| -> usize {
        let left = ((oa as f32) * beta * nof_re_uci as f32 / sum_cb).ceil() as usize;
        left.min(nof_re_uci_l0)
    };
    let q_ack = q_of(o_ack).max(1);
    // For <2 ACK bits the reserved count is computed as if there were 2.
    let q_rvd = if o_ack < 2 { q_of(2).max(q_ack) } else { q_ack };

    let mut res = Vec::new();
    let (mut rvd_placed, mut ack_placed) = (0usize, 0usize);
    for &l in data_syms.iter().filter(|&&l| l >= l1) {
        let m_uci = n_sc;
        // Step 1: reserve REs in this symbol (strided across all subcarriers).
        let rem_rvd = q_rvd - rvd_placed;
        let reserved: Vec<usize> = if rem_rvd > 0 {
            let (d, cnt) = if rem_rvd < m_uci { (m_uci / rem_rvd, rem_rvd) } else { (1, m_uci) };
            rvd_placed += cnt;
            (0..cnt).map(|i| i * d).collect()
        } else {
            Vec::new()
        };
        // Step 5: place the actual HARQ-ACK on a strided subset of the reserved REs.
        let rem_ack = q_ack - ack_placed;
        if !reserved.is_empty() && rem_ack > 0 {
            let m_rvd = reserved.len();
            let (d2, cnt2) = if rem_ack < m_rvd { (m_rvd / rem_ack, rem_ack) } else { (1, m_rvd) };
            for i in 0..cnt2 {
                res.push((l, reserved[i * d2]));
            }
            ack_placed += cnt2;
        }
        if ack_placed >= q_ack {
            break;
        }
    }
    res
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

    /// HARQ-ACK-on-PUSCH RE placement for 1 bit: dmrs [2,7,11], β=20, TB 1600 bits,
    /// 20 RB → Q'_ACK = ceil(20·2640/1616) = 33 REs, all in symbol 3 (the first
    /// symbol after the first DM-RS), strided at subcarriers 0,6,12,…
    #[test]
    fn harq_ack_pusch_re_placement() {
        let res = harq_ack_pusch_res(&[2, 7, 11], 20, 1, 20.0, 1600);
        assert_eq!(res.len(), 33);
        assert!(res.iter().all(|&(l, sc)| l == 3 && sc < 240));
        assert_eq!(&res[..3], &[(3, 0), (3, 6), (3, 12)]);
    }

    /// Modulate a Msg3-sized PUSCH, demodulate it, equalise trivially (no
    /// channel), descramble, and recover the transport block.
    #[test]
    fn pusch_msg3_round_trip() {
        let ofdm = Ofdm::new(512);
        let alloc = PuschAlloc { rb_start: 4, n_rb: 3, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb: 24, crb_offset: 0 };
        let e = pusch_e_len(&alloc);
        assert_eq!(e, 792);
        let (cell_id, tc_rnti, r) = (1u16, 0x4601u16, 0.117);

        // Msg3 TB: 11 bytes (88 bits).
        let tb_bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
        let tb: Vec<u8> = tb_bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
        let ulsch = dlsch_encode_single(&tb, e, r, 2, 0);

        let slot = pusch_modulate_slot(&ofdm, &ulsch, &alloc, cell_id, 5, 1, tc_rnti, 0.0, 15.36e6);

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
        for l in 0..14 {
            if dmrs.contains(&l) {
                continue;
            }
            for kp in 0..(12 * alloc.n_rb) {
                let sc = 12 * alloc.rb_start + kp;
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
