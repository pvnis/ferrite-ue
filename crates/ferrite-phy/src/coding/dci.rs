//! DCI coding for the PDCCH (3GPP TS 38.212 §7.3).
//!
//! Chain: payload `a` → CRC24C computed over `1×24 || a` (the 24 prepended
//! ones are not transmitted) → last 16 parity bits XOR-masked with the RNTI →
//! polar (`n_max = 9`, `I_IL = 1`, `n_PC = 0`) → sub-block interleave → bit
//! selection to `E = 108·L` bits (aggregation level `L` CCEs, 54 data REs and
//! thus 108 bits per CCE).
//!
//! Decoding is blind: the UE tries each candidate location/aggregation level
//! and accepts the one whose CRC (after RNTI unmasking) checks.

use crate::coding::crc::CRC24C;
use crate::coding::polar::{
    code_length, info_mask_rm, input_deinterleave, input_interleave, polar_encode, scl_decode,
};
use crate::coding::ratematch::{de_rate_match, rate_match, subblock_interleave};

/// Coded bits per CCE: 6 REGs × 9 data REs × 2 bits (QPSK).
pub const BITS_PER_CCE: usize = 108;

/// DCI format 1_0 payload size (bits) when CRC-scrambled by SI-RNTI, monitored
/// in a CSS with CORESET0 of `n_rb` resource blocks (38.212 §7.3.1.2.1):
/// frequency-domain RA `⌈log2(N(N+1)/2)⌉` + TDRA 4 + VRB-to-PRB 1 + MCS 5 +
/// RV 2 + SI indicator 1 + reserved 15.
pub fn dci_1_0_si_size(n_rb: usize) -> usize {
    let riv_bits = usize::BITS as usize - ((n_rb * (n_rb + 1) / 2) - 1).leading_zeros() as usize;
    riv_bits + 4 + 1 + 5 + 2 + 1 + 15
}

/// Compute the (RNTI-masked) CRC parity bits for payload `a` (§7.3.2).
fn dci_crc(a: &[u8], rnti: u16) -> Vec<u8> {
    let mut prefixed = vec![1u8; 24];
    prefixed.extend_from_slice(a);
    let mut p = CRC24C.compute(&prefixed);
    for i in 0..16 {
        p[8 + i] ^= ((rnti >> (15 - i)) & 1) as u8; // x_rnti,0 = RNTI MSB
    }
    p
}

/// Encode a DCI payload to `e` coded bits for the given RNTI.
pub fn dci_encode(a: &[u8], rnti: u16, e: usize) -> Vec<u8> {
    let k = a.len() + 24;
    let n = code_length(k, e, 9);
    let mut c = a.to_vec();
    c.extend(dci_crc(a, rnti));
    let c_prime = input_interleave(&c);
    let mask = info_mask_rm(n, k, e);
    let d = polar_encode(&c_prime, &mask);
    let y = subblock_interleave(&d);
    rate_match(&y, e, k)
}

/// Attempt to decode a DCI of payload length `a_len` from `llrs` (positive ⇒
/// bit 0), checking the CRC against `rnti`. Returns the payload bits on
/// success.
pub fn dci_decode(llrs: &[f32], rnti: u16, a_len: usize) -> Option<Vec<u8>> {
    let k = a_len + 24;
    let e = llrs.len();
    let n = code_length(k, e, 9);
    let d_llr = de_rate_match(llrs, n, k);
    let mask = info_mask_rm(n, k, e);
    let check = |info: &[u8]| -> bool {
        let c = input_deinterleave(info);
        c[a_len..] == dci_crc(&c[..a_len], rnti)[..]
    };
    let (info, crc_ok) = scl_decode(&d_llr, &mask, 8, check);
    if !crc_ok {
        return None;
    }
    let c = input_deinterleave(&info);
    Some(c[..a_len].to_vec())
}

/// PDCCH coded-bit scrambling sequence applied to LLRs (38.211 §7.3.2.3):
/// flip LLR signs where the Gold bit is 1. For a CORESET configured by the
/// MIB (CORESET0), `c_init = N_cell_ID`.
pub fn pdcch_descramble_llr(llrs: &mut [f32], c_init: u32) {
    let c = crate::sequence::gold_sequence(c_init, llrs.len());
    for (l, &bit) in llrs.iter_mut().zip(&c) {
        if bit == 1 {
            *l = -*l;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn bit(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            (x >> 40) as u8 & 1
        }
        fn uniform(&mut self) -> f32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            ((x >> 11) as f32) / ((1u64 << 53) as f32)
        }
        fn normal(&mut self) -> f32 {
            let u1 = self.uniform().max(1e-9);
            let u2 = self.uniform();
            (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
        }
    }

    #[test]
    fn si_dci_size_for_coreset0_widths() {
        // N_RB = 24: RIV over 300 values → 9 bits → total 37.
        assert_eq!(dci_1_0_si_size(24), 37);
        // N_RB = 48: RIV over 1176 → 11 bits → total 39.
        assert_eq!(dci_1_0_si_size(48), 39);
    }

    #[test]
    fn code_length_matches_spec_cases() {
        // DCI AL4: E=432, K=61 → N=512 (no n1 reduction: 432 > 9/8·256).
        assert_eq!(code_length(61, 432, 9), 512);
        // DCI AL8: E=864, K=61 → N=512 (n_max caps at 9).
        assert_eq!(code_length(61, 864, 9), 512);
        // DCI AL2: E=216, K=61 → N=256.
        assert_eq!(code_length(61, 216, 9), 256);
        // BCH: E=864, K=56 → N=512.
        assert_eq!(code_length(56, 864, 9), 512);
        // n1 reduction case: E=288 = 9/8·256, K small → n1 = 8.
        assert_eq!(code_length(40, 288, 9), 256);
    }

    /// Round trip at every Type0-CSS aggregation level, noiseless. AL4/AL2
    /// exercise puncturing; AL8/AL16 exercise repetition.
    #[test]
    fn dci_roundtrip_all_aggregation_levels() {
        let a_len = dci_1_0_si_size(24);
        let rnti = 0xFFFF; // SI-RNTI
        let mut rng = Rng(0xD0C1_0001);
        for al in [2usize, 4, 8, 16] {
            let e = al * BITS_PER_CCE;
            let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
            let coded = dci_encode(&a, rnti, e);
            assert_eq!(coded.len(), e);
            let llrs: Vec<f32> = coded.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
            let dec = dci_decode(&llrs, rnti, a_len).unwrap_or_else(|| panic!("AL{al} failed"));
            assert_eq!(dec, a, "AL{al}");
        }
    }

    /// Blind-decode discipline: a wrong RNTI or wrong payload size must not
    /// produce a CRC pass.
    #[test]
    fn wrong_rnti_or_size_rejected() {
        let a_len = dci_1_0_si_size(24);
        let mut rng = Rng(0xD0C1_0002);
        let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
        let coded = dci_encode(&a, 0xFFFF, 4 * BITS_PER_CCE);
        let llrs: Vec<f32> = coded.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
        assert!(dci_decode(&llrs, 0xFFFE, a_len).is_none(), "wrong RNTI");
        assert!(dci_decode(&llrs, 0xFFFF, a_len + 2).is_none(), "wrong size");
    }

    /// AL4 (punctured) under noise: the DCI working point.
    #[test]
    fn dci_al4_decodes_under_noise() {
        let a_len = dci_1_0_si_size(24);
        let rnti = 0xFFFF;
        let mut rng = Rng(0xD0C1_0003);
        let a: Vec<u8> = (0..a_len).map(|_| rng.bit()).collect();
        let coded = dci_encode(&a, rnti, 4 * BITS_PER_CCE);

        let sigma = 0.7f32; // ~3 dB per coded bit
        let llrs: Vec<f32> = coded
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let r = s + rng.normal() * sigma;
                2.0 * r / (sigma * sigma)
            })
            .collect();
        assert_eq!(dci_decode(&llrs, rnti, a_len).expect("decode failed"), a);
    }
}
