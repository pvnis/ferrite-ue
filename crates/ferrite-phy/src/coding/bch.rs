//! BCH transport channel: PBCH payload handling and the full encode/decode
//! chain (3GPP TS 38.212 §7.1, TS 38.211 §7.3.3.1, TS 38.331 MIB).
//!
//! Pipeline (transmit order; receive inverts it):
//!
//! ```text
//! MIB(24b) + 8 timing bits ──7.1.1 interleave G──▶ a
//!   ──7.1.2 scramble (c_init=cellId, v=SFN LSBs)──▶ a'
//!   ──7.1.3 CRC24C──▶ K=56 ──5.3.1.1 interleave──▶ polar N=512
//!   ──5.4.1 sub-block + repetition──▶ E=864
//!   ──38.211 7.3.3.1 scramble (v=i_SSB)──▶ QPSK on the SSB grid
//! ```

use crate::coding::crc::CRC24C;
use crate::coding::polar::{
    info_mask, input_deinterleave, input_interleave, polar_encode, scl_decode,
};
use crate::coding::ratematch::{de_rate_match, rate_match, subblock_interleave};
use crate::coding::tables::PBCH_PAYLOAD_G;
use crate::sequence::gold_sequence;

/// PBCH payload size after the 8 timing bits are appended (Ā = 24, A = 32).
pub const PBCH_A: usize = 32;
/// Polar code length for the BCH (`n_max = 9` → N = 512, §7.1.4).
pub const PBCH_N: usize = 512;
/// Info length K = A + 24 CRC bits (§7.1.3).
pub const PBCH_K: usize = PBCH_A + 24;
/// Rate-matched length (§7.1.5).
pub const PBCH_E: usize = 864;

/// Decoded contents of a PBCH: the MIB plus the extra timing payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mib {
    /// Full 10-bit system frame number (6 MSBs from the MIB + 4 appended LSBs).
    pub sfn: u16,
    /// `subCarrierSpacingCommon`: false → 15/60 kHz, true → 30/120 kHz.
    pub scs_common_is_30_or_120: bool,
    /// `ssb-SubcarrierOffset` (4 bits, k_SSB LSBs; MSB arrives in the timing bits).
    pub ssb_subcarrier_offset: u8,
    /// `dmrs-TypeA-Position`: false → pos2, true → pos3.
    pub dmrs_typea_pos3: bool,
    /// `pdcch-ConfigSIB1`: controlResourceSetZero (high nibble) and
    /// searchSpaceZero (low nibble).
    pub pdcch_config_sib1: u8,
    /// `cellBarred`: true → barred.
    pub cell_barred: bool,
    /// `intraFreqReselection`: true → allowed.
    pub intra_freq_reselection_allowed: bool,
    /// Half-frame bit (0 = first half, 1 = second half).
    pub half_frame: u8,
    /// MSB of `k_SSB` (from the timing payload, L_max ≤ 8 FR1).
    pub k_ssb_msb: u8,
}

impl Mib {
    /// Serialize to the 32 PBCH payload bits `ā_0..ā_31` (before interleaving):
    /// the 24-bit BCCH-BCH-Message (choice bit + MIB fields, UPER order) followed
    /// by the 8 additional timing bits of §7.1.1.
    pub fn to_payload_bits(&self) -> [u8; PBCH_A] {
        let mut bits = [0u8; PBCH_A];
        let mut i = 0;
        let push = |v: u32, n: usize, bits: &mut [u8; PBCH_A], i: &mut usize| {
            for s in (0..n).rev() {
                bits[*i] = ((v >> s) & 1) as u8;
                *i += 1;
            }
        };
        // BCCH-BCH-Message: CHOICE { mib (0), messageClassExtension (1) }.
        push(0, 1, &mut bits, &mut i);
        // MIB fields (TS 38.331), UPER field order.
        push(u32::from(self.sfn >> 4), 6, &mut bits, &mut i); // systemFrameNumber: 6 MSBs
        push(u32::from(self.scs_common_is_30_or_120), 1, &mut bits, &mut i);
        push(u32::from(self.ssb_subcarrier_offset & 0xF), 4, &mut bits, &mut i);
        push(u32::from(self.dmrs_typea_pos3), 1, &mut bits, &mut i);
        push(u32::from(self.pdcch_config_sib1), 8, &mut bits, &mut i);
        // 38.331 enum values: cellBarred {barred(0), notBarred(1)} and
        // intraFreqReselection {allowed(0), notAllowed(1)} — both encode the
        // *negation* of the natural boolean (caught by srsRAN cross-validation).
        push(u32::from(!self.cell_barred), 1, &mut bits, &mut i);
        push(u32::from(!self.intra_freq_reselection_allowed), 1, &mut bits, &mut i);
        push(0, 1, &mut bits, &mut i); // spare
        debug_assert_eq!(i, 24);
        // §7.1.1 additional timing bits: SFN 4th,3rd,2nd,1st LSB; HRF; k_SSB MSB;
        // two reserved bits (L_max = 8).
        push(u32::from(self.sfn & 0xF), 4, &mut bits, &mut i);
        push(u32::from(self.half_frame & 1), 1, &mut bits, &mut i);
        push(u32::from(self.k_ssb_msb & 1), 1, &mut bits, &mut i);
        push(0, 2, &mut bits, &mut i);
        debug_assert_eq!(i, PBCH_A);
        bits
    }

    /// Parse from the 32 de-interleaved, descrambled payload bits.
    pub fn from_payload_bits(bits: &[u8; PBCH_A]) -> Option<Mib> {
        let mut i = 0;
        let take = |n: usize, i: &mut usize| -> u32 {
            let mut v = 0u32;
            for _ in 0..n {
                v = (v << 1) | u32::from(bits[*i]);
                *i += 1;
            }
            v
        };
        let choice = take(1, &mut i);
        if choice != 0 {
            return None; // messageClassExtension: not a plain MIB
        }
        let sfn_msbs = take(6, &mut i) as u16;
        let scs = take(1, &mut i) != 0;
        let ssb_sc_off = take(4, &mut i) as u8;
        let dmrs_pos = take(1, &mut i) != 0;
        let pdcch_cfg = take(8, &mut i) as u8;
        let barred = take(1, &mut i) == 0; // cellBarred: barred(0), notBarred(1)
        let ifr = take(1, &mut i) == 0; // intraFreqReselection: allowed(0), notAllowed(1)
        let _spare = take(1, &mut i);
        let sfn_lsbs = take(4, &mut i) as u16;
        let hrf = take(1, &mut i) as u8;
        let k_ssb_msb = take(1, &mut i) as u8;
        let _reserved = take(2, &mut i);
        debug_assert_eq!(i, PBCH_A);
        Some(Mib {
            sfn: (sfn_msbs << 4) | sfn_lsbs,
            scs_common_is_30_or_120: scs,
            ssb_subcarrier_offset: ssb_sc_off,
            dmrs_typea_pos3: dmrs_pos,
            pdcch_config_sib1: pdcch_cfg,
            cell_barred: barred,
            intra_freq_reselection_allowed: ifr,
            half_frame: hrf,
            k_ssb_msb,
        })
    }
}

/// §7.1.1 payload interleaving. In `ā` order, bit classes are: SFN bits at
/// positions 1..=6 and 24..=27, the HRF bit at 28, SSB/k_SSB bits at 29..=31,
/// everything else "other". Class counters start at j_SFN=0, j_HRF=10,
/// j_SSB=11, j_other=14; interleaved position is `G(j)`.
fn payload_interleave_map() -> [usize; PBCH_A] {
    let g = |j: usize| usize::from(PBCH_PAYLOAD_G[j]);
    let mut map = [0usize; PBCH_A];
    let (mut j_sfn, mut j_ssb, mut j_other) = (0usize, 11usize, 14usize);
    for (i, slot) in map.iter_mut().enumerate() {
        if (1..=6).contains(&i) || (24..=27).contains(&i) {
            *slot = g(j_sfn);
            j_sfn += 1;
        } else if i == 28 {
            *slot = g(10);
        } else if (29..=31).contains(&i) {
            *slot = g(j_ssb);
            j_ssb += 1;
        } else {
            *slot = g(j_other);
            j_other += 1;
        }
    }
    map
}

/// Apply §7.1.1: `a[G(j)] = ā[i]`.
pub fn payload_interleave(abar: &[u8; PBCH_A]) -> [u8; PBCH_A] {
    let map = payload_interleave_map();
    let mut a = [0u8; PBCH_A];
    for (i, &pos) in map.iter().enumerate() {
        a[pos] = abar[i];
    }
    a
}

/// Invert §7.1.1.
pub fn payload_deinterleave(a: &[u8; PBCH_A]) -> [u8; PBCH_A] {
    let map = payload_interleave_map();
    let mut abar = [0u8; PBCH_A];
    for (i, &pos) in map.iter().enumerate() {
        abar[i] = a[pos];
    }
    abar
}

/// Positions (in interleaved `a` order) exempt from §7.1.2 scrambling for
/// L_max ≤ 8: the 2nd and 3rd LSB of the SFN and the half-frame bit.
fn unscrambled_positions() -> [usize; 3] {
    let g = |j: usize| usize::from(PBCH_PAYLOAD_G[j]);
    // SFN bits occupy G(0)..G(9) in decreasing significance (bit9..bit0); the
    // 2nd and 3rd LSBs are bit1 and bit2 → j = 8 and 7. HRF is at G(10).
    [g(7), g(8), g(10)]
}

/// §7.1.2 first scrambling (involution — applying twice restores the input).
/// `v = 2·(3rd LSB of SFN) + (2nd LSB of SFN)`; `M = A - 3` for L_max ≤ 8.
pub fn payload_scramble(a: &[u8; PBCH_A], cell_id: u16, sfn: u16) -> [u8; PBCH_A] {
    let exempt = unscrambled_positions();
    let m = PBCH_A - 3;
    let v = usize::from((sfn >> 1) & 3); // (3rd LSB, 2nd LSB) as a 2-bit value
    let c = gold_sequence(u32::from(cell_id), v * m + m);
    let mut out = *a;
    let mut j = 0;
    for (i, bit) in out.iter_mut().enumerate() {
        if !exempt.contains(&i) {
            *bit ^= c[v * m + j];
            j += 1;
        }
    }
    out
}

/// 38.211 §7.3.3.1 second scrambling of the `E` rate-matched bits (involution).
/// `v` = 3 LSBs of the SSB index for `L_max > 4`.
pub fn coded_scramble(bits: &mut [u8], cell_id: u16, i_ssb: u8) {
    let v = usize::from(i_ssb & 0x7);
    let m_bit = bits.len();
    let c = gold_sequence(u32::from(cell_id), (v + 1) * m_bit);
    for (i, b) in bits.iter_mut().enumerate() {
        *b ^= c[v * m_bit + i];
    }
}

/// Same descrambling applied to LLRs: flip the sign where the scrambling bit is 1.
pub fn coded_descramble_llr(llrs: &mut [f32], cell_id: u16, i_ssb: u8) {
    let v = usize::from(i_ssb & 0x7);
    let m_bit = llrs.len();
    let c = gold_sequence(u32::from(cell_id), (v + 1) * m_bit);
    for (i, l) in llrs.iter_mut().enumerate() {
        if c[v * m_bit + i] == 1 {
            *l = -*l;
        }
    }
}

/// Encode a MIB into the 864 PBCH bits (before QPSK), for tests and TX paths.
pub fn bch_encode(mib: &Mib, cell_id: u16, i_ssb: u8) -> Vec<u8> {
    let abar = mib.to_payload_bits();
    let a = payload_interleave(&abar);
    let a_scr = payload_scramble(&a, cell_id, mib.sfn);
    let c = CRC24C.attach(&a_scr);
    let c_prime = input_interleave(&c);
    let mask = info_mask(PBCH_N, PBCH_K);
    let d = polar_encode(&c_prime, &mask);
    let y = subblock_interleave(&d);
    let mut e = rate_match(&y, PBCH_E, PBCH_K);
    coded_scramble(&mut e, cell_id, i_ssb);
    e
}

/// Decode 864 PBCH LLRs (positive ⇒ bit 0) into a MIB.
///
/// Returns `None` if the CRC fails for every SCL path or the payload is not a
/// plain MIB. `i_ssb` comes from DMRS detection; `cell_id` from PSS/SSS.
pub fn bch_decode(llrs: &[f32], cell_id: u16, i_ssb: u8) -> Option<Mib> {
    assert_eq!(llrs.len(), PBCH_E);
    let mut llrs = llrs.to_vec();
    coded_descramble_llr(&mut llrs, cell_id, i_ssb);
    let d_llr = de_rate_match(&llrs, PBCH_N, PBCH_K);
    let mask = info_mask(PBCH_N, PBCH_K);
    let (c_prime, crc_ok) = scl_decode(&d_llr, &mask, 8, |bits| {
        CRC24C.check(&input_deinterleave(bits))
    });
    if !crc_ok {
        return None;
    }
    let c = input_deinterleave(&c_prime);
    let a_scr: [u8; PBCH_A] = c[..PBCH_A].try_into().unwrap();

    // The SFN 2nd/3rd LSBs are unscrambled, so v is readable directly from the
    // received bits: they sit at interleaved positions G(8) and G(7).
    let g = |j: usize| usize::from(PBCH_PAYLOAD_G[j]);
    let sfn_bit1 = a_scr[g(8)]; // 2nd LSB
    let sfn_bit2 = a_scr[g(7)]; // 3rd LSB
    let v_sfn = u16::from(sfn_bit2) << 2 | u16::from(sfn_bit1) << 1;

    let a = payload_scramble(&a_scr, cell_id, v_sfn);
    let abar = payload_deinterleave(&a);
    let mib = Mib::from_payload_bits(&abar)?;
    debug_assert_eq!(mib.sfn & 0x6, v_sfn & 0x6);
    Some(mib)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mib(sfn: u16) -> Mib {
        Mib {
            sfn,
            scs_common_is_30_or_120: true,
            ssb_subcarrier_offset: 6,
            dmrs_typea_pos3: false,
            pdcch_config_sib1: 0xA4,
            cell_barred: false,
            intra_freq_reselection_allowed: true,
            half_frame: 1,
            k_ssb_msb: 0,
        }
    }

    #[test]
    fn payload_bits_roundtrip() {
        let mib = test_mib(0x2B7);
        let bits = mib.to_payload_bits();
        assert_eq!(Mib::from_payload_bits(&bits), Some(mib));
    }

    #[test]
    fn payload_interleave_roundtrip() {
        let mib = test_mib(123);
        let abar = mib.to_payload_bits();
        assert_eq!(payload_deinterleave(&payload_interleave(&abar)), abar);
    }

    #[test]
    fn payload_scramble_is_involution_and_keeps_v_bits() {
        let mib = test_mib(0x155);
        let a = payload_interleave(&mib.to_payload_bits());
        let s = payload_scramble(&a, 623, mib.sfn);
        assert_eq!(payload_scramble(&s, 623, mib.sfn), a);
        // The three exempt positions must be untouched.
        for pos in unscrambled_positions() {
            assert_eq!(s[pos], a[pos], "exempt bit at {pos} was scrambled");
        }
        assert_ne!(s, a, "scrambling must change something");
    }

    /// Full chain, noiseless: encode → hard LLRs → decode must return the MIB,
    /// for several SFNs (exercising all four v values) and SSB indices.
    #[test]
    fn bch_encode_decode_noiseless() {
        let cell_id = 623;
        for (sfn, i_ssb) in [(0u16, 0u8), (1, 3), (0x0AA, 5), (0x3FF, 7), (0x154, 2)] {
            let mib = test_mib(sfn);
            let e = bch_encode(&mib, cell_id, i_ssb);
            assert_eq!(e.len(), PBCH_E);
            let llrs: Vec<f32> = e.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
            let dec = bch_decode(&llrs, cell_id, i_ssb).expect("decode failed");
            assert_eq!(dec, mib, "sfn={sfn} i_ssb={i_ssb}");
        }
    }

    /// Full chain under Gaussian noise at a plausible working point.
    #[test]
    fn bch_encode_decode_noisy() {
        struct Rng(u64);
        impl Rng {
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
        let mut rng = Rng(0xB0C0_0007);
        let (cell_id, i_ssb) = (101u16, 4u8);
        let mib = test_mib(0x21C);
        let e = bch_encode(&mib, cell_id, i_ssb);

        let sigma = 0.9f32; // ~0.9 dB Eb-ish region; rate 56/864 is very robust
        let llrs: Vec<f32> = e
            .iter()
            .map(|&b| {
                let s = 1.0 - 2.0 * b as f32;
                let r = s + rng.normal() * sigma;
                2.0 * r / (sigma * sigma)
            })
            .collect();
        let dec = bch_decode(&llrs, cell_id, i_ssb).expect("decode failed");
        assert_eq!(dec, mib);
    }

    /// A wrong cell id (wrong descrambling) must not produce a CRC-valid MIB.
    #[test]
    fn wrong_cell_id_fails_crc() {
        let mib = test_mib(0x0F0);
        let e = bch_encode(&mib, 623, 1);
        let llrs: Vec<f32> = e.iter().map(|&b| if b == 0 { 8.0 } else { -8.0 }).collect();
        assert_eq!(bch_decode(&llrs, 624, 1), None);
    }
}
