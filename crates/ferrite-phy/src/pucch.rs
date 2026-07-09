//! PUCCH Format 1 transmit — the HARQ-ACK the UE sends to acknowledge Msg4
//! (contention-resolution) so the gNB completes RACH. CP-OFDM, 1 PRB, one or two
//! HARQ bits, intra-slot frequency hopping. TS 38.211 §6.3.2.2/§6.3.2.4/§6.4.1.3.
//!
//! Structure (occ handled generally, but the common resource uses occ 0):
//! - Base low-PAPR sequence r_{u,v}(n) = e^{jπ·φ₁₂[u][n]/4}, u = n_id mod 30, v = 0.
//! - Per-symbol cyclic shift α_l = 2π·n_cs(l)/12 from a gold sequence seeded by
//!   n_id (§6.3.2.2.2), applied as e^{jα_l·n}.
//! - Alternating symbols: DM-RS on even, data (d·r) on odd, within each hop; the
//!   OCC w_i(m) spreads across the like symbols of a hop.

use crate::sequence::gold_sequence;
use crate::Ofdm;
use num_complex::Complex32;
use std::f32::consts::{FRAC_1_SQRT_2, PI};

/// TS 38.211 Table 5.2.2.2-2: φ(n) for the length-12 low-PAPR base sequence,
/// indexed by group u ∈ 0..30. r_{u,0}(n) = exp(jπ·φ/4).
#[rustfmt::skip]
pub const PHI_12: [[i8; 12]; 30] = [
    [-3, 1, -3, -3, -3, 3, -3, -1, 1, 1, 1, -3], [-3, 3, 1, -3, 1, 3, -1, -1, 1, 3, 3, 3],
    [-3, 3, 3, 1, -3, 3, -1, 1, 3, -3, 3, -3],   [-3, -3, -1, 3, 3, 3, -3, 3, -3, 1, -1, -3],
    [-3, -1, -1, 1, 3, 1, 1, -1, 1, -1, -3, 1],  [-3, -3, 3, 1, -3, -3, -3, -1, 3, -1, 1, 3],
    [1, -1, 3, -1, -1, -1, -3, -1, 1, 1, 1, -3], [-1, -3, 3, -1, -3, -3, -3, -1, 1, -1, 1, -3],
    [-3, -1, 3, 1, -3, -1, -3, 3, 1, 3, 3, 1],   [-3, -1, -1, -3, -3, -1, -3, 3, 1, 3, -1, -3],
    [-3, 3, -3, 3, 3, -3, -1, -1, 3, 3, 1, -3],  [-3, -1, -3, -1, -1, -3, 3, 3, -1, -1, 1, -3],
    [-3, -1, 3, -3, -3, -1, -3, 1, -1, -3, 3, 3],[-3, 1, -1, -1, 3, 3, -3, -1, -1, -3, -1, -3],
    [1, 3, -3, 1, 3, 3, 3, 1, -1, 1, -1, 3],     [-3, 1, 3, -1, -1, -3, -3, -1, -1, 3, 1, -3],
    [-1, -1, -1, -1, 1, -3, -1, 3, 3, -1, -3, 1],[-1, 1, 1, -1, 1, 3, 3, -1, -1, -3, 1, -3],
    [-3, 1, 3, 3, -1, -1, -3, 3, 3, -3, 3, -3],  [-3, -3, 3, -3, -1, 3, 3, 3, -1, -3, 1, -3],
    [3, 1, 3, 1, 3, -3, -1, 1, 3, 1, -1, -3],    [-3, 3, 1, 3, -3, 1, 1, 1, 1, 3, -3, 3],
    [-3, 3, 3, 3, -1, -3, -3, -1, -3, 1, 3, -3], [3, -1, -3, 3, -3, -1, 3, 3, 3, -3, -1, -3],
    [-3, -1, 1, -3, 1, 3, 3, 3, -1, -3, 3, 3],   [-3, 3, 1, -1, 3, 3, -3, 1, -1, 1, -1, 1],
    [-1, 1, 3, -3, 1, -1, 1, -1, -1, -3, 1, -1], [-3, -3, 3, 3, 3, -3, -1, 1, -3, 3, 1, -3],
    [1, -1, 3, 1, 1, -1, -1, -1, 1, 3, -3, 1],   [-3, 3, -3, 3, -3, -3, 3, -1, -1, 1, 3, -3],
];

/// TS 38.211 Table 6.3.2.4.1-2: φ for the orthogonal cover code w_i(m) =
/// exp(j·2π·φ/N_SF), indexed by [N_SF-1][i][m].
#[rustfmt::skip]
const OCC_PHI: [[[i8; 7]; 7]; 7] = [
    [[0,0,0,0,0,0,0],[0;7],[0;7],[0;7],[0;7],[0;7],[0;7]],
    [[0,0,0,0,0,0,0],[0,1,0,0,0,0,0],[0;7],[0;7],[0;7],[0;7],[0;7]],
    [[0,0,0,0,0,0,0],[0,1,2,0,0,0,0],[0,2,1,0,0,0,0],[0;7],[0;7],[0;7],[0;7]],
    [[0,0,0,0,0,0,0],[0,2,0,2,0,0,0],[0,0,2,2,0,0,0],[0,2,2,0,0,0,0],[0;7],[0;7],[0;7]],
    [[0,0,0,0,0,0,0],[0,1,2,3,4,0,0],[0,2,4,1,3,0,0],[0,3,1,4,2,0,0],[0,4,3,2,1,0,0],[0;7],[0;7]],
    [[0,0,0,0,0,0,0],[0,1,2,3,4,5,0],[0,2,4,0,2,4,0],[0,3,0,3,0,3,0],[0,4,2,0,4,2,0],[0,5,4,3,2,1,0],[0;7]],
    [[0,0,0,0,0,0,0],[0,1,2,3,4,5,6],[0,2,4,6,1,3,5],[0,3,6,2,5,1,4],[0,4,1,5,2,6,3],[0,5,3,1,6,4,2],[0,6,5,4,3,2,1]],
];

/// PUCCH Format 1 resource / config.
#[derive(Clone, Debug)]
pub struct PucchF1 {
    /// First-hop PRB (BWP-relative).
    pub prb1: usize,
    /// Second-hop PRB (intra-slot frequency hopping).
    pub prb2: usize,
    /// First OFDM symbol and symbol count (usually 0, 14).
    pub start_symbol: usize,
    pub nof_symbols: usize,
    /// Initial cyclic shift m0.
    pub init_cyclic_shift: usize,
    /// Time-domain OCC index i.
    pub occ_index: usize,
    /// Hopping/scrambling identity n_id (usually PCI).
    pub n_id: u16,
    /// UL carrier size in RBs (for DC-centred subcarrier→bin mapping).
    pub carrier_rb: usize,
}

/// Base sequence with cyclic shift: r^α(n) = exp(j·2π·α·n/12) · exp(jπ·φ₁₂[u][n]/4).
fn base_seq_shifted(u: usize, alpha: usize) -> [Complex32; 12] {
    let mut out = [Complex32::new(0.0, 0.0); 12];
    for (n, o) in out.iter_mut().enumerate() {
        let phase = PI * PHI_12[u][n] as f32 / 4.0 + 2.0 * PI * alpha as f32 * n as f32 / 12.0;
        *o = Complex32::new(phase.cos(), phase.sin());
    }
    out
}

/// Per-symbol cyclic shift α_l (0..11), TS 38.211 §6.3.2.2.2. Gold sequence
/// c seeded by `n_id`; n_cs(l) = Σ_{m=0}^{7} c(8·(14·n_slot + l) + m)·2^m.
fn alpha_index(n_id: u16, n_slot: u32, symbol: usize, m0: usize) -> usize {
    let base = 14 * n_slot as usize + symbol;
    let need = 8 * (base + 1);
    let c = gold_sequence(n_id as u32, need);
    let mut n_cs = 0usize;
    for m in 0..8 {
        n_cs |= (c[8 * base + m] as usize) << m;
    }
    (m0 + n_cs) % 12
}

/// BPSK/QPSK modulation of the HARQ-ACK bits (TS 38.211 §5.1). 1 bit → BPSK.
/// An empty slice is a positive Scheduling Request (no UCI): d(0) = 1.
fn modulate_ack(bits: &[u8]) -> Complex32 {
    match bits.len() {
        0 => Complex32::new(1.0, 0.0), // positive SR: sequence sent unmodulated
        1 => {
            let b = bits[0];
            let v = (1 - 2 * b as i32) as f32 * FRAC_1_SQRT_2;
            Complex32::new(v, v)
        }
        _ => {
            let (b0, b1) = (bits[0], bits[1]);
            Complex32::new((1 - 2 * b0 as i32) as f32 * FRAC_1_SQRT_2, (1 - 2 * b1 as i32) as f32 * FRAC_1_SQRT_2)
        }
    }
}

/// Modulate one PUCCH Format 1 slot carrying `ack_bits` (1 = ACK). Returns the
/// CP-OFDM time-domain samples for the slot, with §5.4 phase compensation applied
/// (the gNB's OFDM demodulator removes it). `slot_in_frame` seeds the shift
/// hopping; `fs`/`center_freq_hz` drive the phase compensation.
pub fn pucch_f1_modulate_slot(
    ofdm: &Ofdm,
    cfg: &PucchF1,
    ack_bits: &[u8],
    slot_in_frame: u32,
    center_freq_hz: f64,
    fs: f64,
) -> Vec<Complex32> {
    let n = ofdm.fft_size();
    let center = cfg.carrier_rb * 6;
    let bin = |sc: usize| (sc as i32 - center as i32).rem_euclid(n as i32) as usize;
    let u = (cfg.n_id % 30) as usize;
    let d = modulate_ack(ack_bits);

    // Split the symbols into two hops (first ⌊N/2⌋ / rest). Within a hop, even
    // relative symbols are DM-RS, odd are data. OCC spreads over like symbols.
    let hopping = cfg.prb1 != cfg.prb2;
    let n1 = if hopping { cfg.nof_symbols / 2 } else { cfg.nof_symbols };
    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 14];

    let place_hop = |grids: &mut Vec<Vec<Complex32>>, hop_start: usize, hop_len: usize, prb: usize| {
        // Count DM-RS (even rel) and data (odd rel) symbols in the hop.
        let n_dmrs = hop_len.div_ceil(2);
        let n_data = hop_len / 2;
        let (mut i_dmrs, mut i_data) = (0usize, 0usize);
        for rel in 0..hop_len {
            let l = cfg.start_symbol + hop_start + rel;
            let alpha = alpha_index(cfg.n_id, slot_in_frame, l, cfg.init_cyclic_shift);
            let seq = base_seq_shifted(u, alpha);
            let is_dmrs = rel % 2 == 0;
            let (n_sf, m, sym_val) = if is_dmrs {
                let m = i_dmrs;
                i_dmrs += 1;
                (n_dmrs, m, Complex32::new(1.0, 0.0))
            } else {
                let m = i_data;
                i_data += 1;
                (n_data, m, d)
            };
            // OCC w_i(m) = exp(j·2π·φ/N_SF).
            let occ_phi = OCC_PHI[n_sf - 1][cfg.occ_index][m] as f32;
            let wphase = 2.0 * PI * occ_phi / n_sf as f32;
            let w = Complex32::new(wphase.cos(), wphase.sin());
            for (k, &s) in seq.iter().enumerate() {
                grids[l][bin(12 * prb + k)] = w * sym_val * s;
            }
        }
    };
    place_hop(&mut grids, 0, n1, cfg.prb1);
    if hopping {
        place_hop(&mut grids, n1, cfg.nof_symbols - n1, cfg.prb2);
    }

    // OFDM with per-symbol §5.4 phase compensation (same as PUSCH).
    let slot_in_subframe = (slot_in_frame % 2) as usize;
    let mut out = Vec::with_capacity(14 * (n + 40));
    let mut sub_off: usize = (0..slot_in_subframe * 14).map(|k| ofdm.cp_len(k, 1) + n).sum();
    for (l, grid) in grids.iter().enumerate() {
        let cp = ofdm.cp_len(slot_in_subframe * 14 + l, 1);
        let sym = ofdm.modulate_symbol(grid, cp);
        if center_freq_hz != 0.0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_seq_unit_magnitude() {
        let s = base_seq_shifted(1, 5);
        for c in s {
            assert!((c.norm() - 1.0).abs() < 1e-5);
        }
    }

    #[test]
    fn slot_length_and_hop_placement() {
        let ofdm = Ofdm::new(512);
        let cfg = PucchF1 {
            prb1: 0, prb2: 23, start_symbol: 0, nof_symbols: 14,
            init_cyclic_shift: 0, occ_index: 0, n_id: 1, carrier_rb: 24,
        };
        let wave = pucch_f1_modulate_slot(&ofdm, &cfg, &[1], 17, 0.0, 15.36e6);
        assert_eq!(wave.len(), 7680); // one slot at μ=1, 15.36 Msps
    }

    #[test]
    fn ack_nack_differ() {
        let ofdm = Ofdm::new(512);
        let cfg = PucchF1 {
            prb1: 0, prb2: 23, start_symbol: 0, nof_symbols: 14,
            init_cyclic_shift: 0, occ_index: 0, n_id: 1, carrier_rb: 24,
        };
        let a = pucch_f1_modulate_slot(&ofdm, &cfg, &[1], 17, 0.0, 15.36e6);
        let b = pucch_f1_modulate_slot(&ofdm, &cfg, &[0], 17, 0.0, 15.36e6);
        let diff: f32 = a.iter().zip(&b).map(|(x, y)| (x - y).norm()).sum();
        assert!(diff > 1.0);
    }
}
