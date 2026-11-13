//! CSI-RS (TS 38.211 §7.4.1.5): the NZP-CSI-RS sequence, the per-RB RE
//! patterns of Table 7.4.1.5.3-1 rows 1/2/4 (used both to measure the
//! downlink SINR for the CQI report, TS 38.214 §5.2, and to rate-match the
//! PDSCH around ZP/NZP resources, TS 38.214 §5.1.4), and the SINR→CQI mapping.

use crate::sequence::gold_sequence;
use ferrite_common::SlotPoint;
use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

/// Row of Table 7.4.1.5.3-1 (single-port rows and the 4-port row OCUDU uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiRsRow {
    /// 1 port, density 3: `k ∈ {k0, k0+4, k0+8}` in one symbol.
    Row1,
    /// 1 port, density 1 (or 0.5): the single subcarrier `k0`.
    Row2,
    /// 4 ports, density 1: subcarriers `4j..4j+4` (CDM group of 4), one symbol.
    Row4,
}

/// Per-RB subcarrier mask (bit `k` = subcarrier `k` of every RB) of a CSI-RS
/// resource (TS 38.211 §7.4.1.5.3), from the row and the
/// `frequencyDomainAllocation` bits: for `row1` the 4-bit field with the lowest
/// set bit `i` meaning `k0 = i`; `row2` the 12-bit field with `k0` = lowest set
/// bit; `row4` the 3-bit field selecting the 4-subcarrier group `j`.
/// `freq_bits` holds the field with bit 0 = the field's lowest bit (`b_0`).
pub fn csi_rs_re_mask(row: CsiRsRow, freq_bits: u16) -> u16 {
    let bit = freq_bits.trailing_zeros().min(15) as u16;
    match row {
        CsiRsRow::Row1 => 0b_0001_0001_0001 << bit,
        CsiRsRow::Row2 => 1 << bit,
        CsiRsRow::Row4 => 0b1111 << (4 * bit),
    }
}

/// Whether `slot` is a CSI-RS occasion of a resource with
/// `periodicityAndOffset` (`period_slots`, `offset_slots`).
pub fn csi_rs_slots(period_slots: u32, offset_slots: u32, slot: SlotPoint) -> bool {
    slot.is_occasion(period_slots, offset_slots)
}

/// A periodic CSI-RS resource's footprint for PDSCH rate matching: slot
/// periodicity and the REs it occupies per RB in each of its symbols over
/// `[start_rb, start_rb + n_rb)` (CRBs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiRsPattern {
    pub period_slots: u32,
    pub offset_slots: u32,
    /// OFDM symbols of the resource (`firstOFDMSymbolInTimeDomain` and, for
    /// two-symbol rows, `firstOFDMSymbolInTimeDomain2`).
    pub symbols: Vec<usize>,
    /// First CRB (`startingRB`) and number of RBs (`nrofRBs`).
    pub start_rb: usize,
    pub n_rb: usize,
    /// Per-RB subcarrier mask (see [`csi_rs_re_mask`]).
    pub re_mask: u16,
}

impl CsiRsPattern {
    /// Whether RE `(symbol, crb, k_in_rb)` of `slot` belongs to this resource.
    pub fn occupies(&self, slot: SlotPoint, symbol: usize, crb: usize, k_in_rb: usize) -> bool {
        csi_rs_slots(self.period_slots, self.offset_slots, slot)
            && self.symbols.contains(&symbol)
            && (self.start_rb..self.start_rb + self.n_rb).contains(&crb)
            && (self.re_mask >> (k_in_rb % 12)) & 1 == 1
    }
}

/// Whether any of `patterns` occupies RE `(symbol, crb, k)` in `slot` — the
/// `rm_skip` predicate of [`crate::pdsch::extract_pdsch`] (with the caller
/// translating its BWP-relative PRB to a CRB).
pub fn csi_rs_rate_match(patterns: &[CsiRsPattern], slot: SlotPoint, symbol: usize, crb: usize, k_in_rb: usize) -> bool {
    patterns.iter().any(|p| p.occupies(slot, symbol, crb, k_in_rb))
}

/// The NZP-CSI-RS sequence `r(0..len)` for one OFDM symbol (§7.4.1.5.2):
/// `c_init = (2^10·(14·n_slot + l + 1)·(2·n_ID + 1) + n_ID) mod 2^31`, QPSK.
/// Index `m' = ⌊n·α⌋ + k' + ⌊k̄·ρ/12⌋` is `3·n + i` for density 3 (row 1) and
/// `n` for density 1 (row 2), with `n` the CRB index; pass `len` to cover the
/// highest CRB of the resource.
pub fn csi_rs_sequence(n_id: u16, slot: u32, symbol: u32, len: usize) -> Vec<Complex32> {
    let c_init = (((1u64 << 10) * (14 * u64::from(slot) + u64::from(symbol) + 1) * (2 * u64::from(n_id) + 1)
        + u64::from(n_id))
        % (1u64 << 31)) as u32;
    let c = gold_sequence(c_init, 2 * len);
    (0..len)
        .map(|m| {
            Complex32::new(
                (1 - 2 * i32::from(c[2 * m])) as f32 * FRAC_1_SQRT_2,
                (1 - 2 * i32::from(c[2 * m + 1])) as f32 * FRAC_1_SQRT_2,
            )
        })
        .collect()
}

/// A single-port NZP-CSI-RS resource used for SINR measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiRsMeasurement {
    /// Row 1 (density 3) or row 2 (density 1).
    pub row: CsiRsRow,
    /// `scramblingID`.
    pub n_id: u16,
    /// Subcarrier `k0` within the RB.
    pub k0: usize,
    /// OFDM symbol.
    pub symbol: usize,
    /// First CRB and number of RBs of the resource.
    pub start_rb: usize,
    pub n_rb: usize,
}

/// Measure the downlink SINR (dB) from a single-port NZP-CSI-RS in one
/// symbol's demodulated grid (`sc_to_bin` maps a CRB-domain subcarrier,
/// `12·crb + k`, to an FFT bin; `slot` is the slot in the frame).
///
/// Row 1 (density 3): per-RB least-squares channel from its 3 REs; the signal
/// power is the mean `|ĥ_rb|²` and the noise the residual of each RE about its
/// RB estimate (robust to a slow phase slope across RBs). Row 2 (one RE per
/// RB): the noise is the half-difference power between adjacent RBs'
/// estimates.
pub fn measure_csi_rs_sinr(grid: &[Complex32], sc_to_bin: impl Fn(usize) -> usize, res: &CsiRsMeasurement, slot: u32) -> f32 {
    let density = match res.row {
        CsiRsRow::Row1 => 3,
        CsiRsRow::Row2 => 1,
        CsiRsRow::Row4 => panic!("row 4 is a 4-port resource; not a single-port SINR measurement"),
    };
    let seq = csi_rs_sequence(res.n_id, slot, res.symbol as u32, density * (res.start_rb + res.n_rb));
    let rbs = res.start_rb..res.start_rb + res.n_rb;
    let (mut sig, mut noise, mut n_noise) = (0.0f32, 0.0f32, 0usize);
    if density == 3 {
        for n in rbs {
            let mut h = [Complex32::new(0.0, 0.0); 3];
            for (i, hi) in h.iter_mut().enumerate() {
                *hi = grid[sc_to_bin(12 * n + res.k0 + 4 * i)] * seq[3 * n + i].conj(); // |seq| = 1
            }
            let rb_h = (h[0] + h[1] + h[2]) / 3.0;
            sig += rb_h.norm_sqr();
            for hi in &h {
                noise += (hi - rb_h).norm_sqr();
                n_noise += 1;
            }
        }
    } else {
        let h: Vec<Complex32> = rbs.map(|n| grid[sc_to_bin(12 * n + res.k0)] * seq[n].conj()).collect();
        sig = h.iter().map(|x| x.norm_sqr()).sum();
        for w in h.windows(2) {
            noise += (w[1] - w[0]).norm_sqr() / 2.0;
            n_noise += 1;
        }
    }
    sig /= res.n_rb.max(1) as f32;
    noise /= n_noise.max(1) as f32;
    if noise <= 1e-9 {
        return 40.0; // essentially noiseless (lossless channel)
    }
    10.0 * (sig / noise).log10()
}

/// Map an effective SINR (dB) to a wideband CQI index (CQI table 1, 4-bit). Rough
/// AWGN thresholds; the gNB clamps the resulting MCS to its configured cap anyway.
pub fn sinr_to_cqi(sinr_db: f32) -> u8 {
    // Threshold (dB) above which each CQI index 1..15 is reported.
    const T: [f32; 15] = [
        -6.0, -4.0, -2.0, 0.0, 2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0,
    ];
    let mut cqi = 0u8;
    for (i, &t) in T.iter().enumerate() {
        if sinr_db >= t {
            cqi = (i + 1) as u8;
        }
    }
    cqi
}

#[cfg(test)]
mod tests {
    /// The TRS patterns OCUDU configures (row 1, k0 = 2, symbols 4 and 8,
    /// period 20 slots, offsets 12/13) must mark REs 2/6/10 of every RB in
    /// slot 2 of odd frames at 15 kHz, and nothing elsewhere.
    #[test]
    fn trs_rate_match_occasions() {
        use super::*;
        use ferrite_common::{Numerology, SlotPoint};
        let mu0 = Numerology::from_scs_khz(15).unwrap();
        let pats: Vec<CsiRsPattern> = [(4usize, 12u32), (8, 12), (4, 13), (8, 13)]
            .into_iter()
            .map(|(l, off)| CsiRsPattern { period_slots: 20, offset_slots: off, symbols: vec![l], start_rb: 0, n_rb: 52, re_mask: 0b010001000100 })
            .collect();
        let trs_slot = SlotPoint::new(mu0, 279, 2);
        assert!(trs_slot.is_occasion(20, 12), "index {} ", trs_slot.index());
        assert!(csi_rs_rate_match(&pats, trs_slot, 4, 0, 2));
        assert!(csi_rs_rate_match(&pats, trs_slot, 8, 51, 10));
        assert!(!csi_rs_rate_match(&pats, trs_slot, 4, 0, 3));
        assert!(!csi_rs_rate_match(&pats, trs_slot, 5, 0, 2));
        assert!(!csi_rs_rate_match(&pats, SlotPoint::new(mu0, 128, 8), 4, 0, 2));
        assert!(csi_rs_rate_match(&pats, SlotPoint::new(mu0, 279, 3), 8, 3, 6));
    }

    use super::*;
    use ferrite_common::Numerology;

    /// A perfectly-received CSI-RS (grid = h·sequence at the RE locations) measures a
    /// very high SINR and maps to the maximum CQI — for both single-port rows and a
    /// resource that does not start at CRB 0.
    #[test]
    fn measure_lossless_csi_rs() {
        let (n_id, slot, symbol) = (1u16, 3u32, 4usize);
        let h = Complex32::new(0.8, -0.6); // an arbitrary flat channel
        for (row, start_rb, n_rb, k0) in [(CsiRsRow::Row1, 0usize, 24usize, 1usize), (CsiRsRow::Row1, 5, 20, 2), (CsiRsRow::Row2, 3, 30, 7)] {
            let density = if row == CsiRsRow::Row1 { 3 } else { 1 };
            let seq = csi_rs_sequence(n_id, slot, symbol as u32, density * (start_rb + n_rb));
            let mut grid = vec![Complex32::new(0.0, 0.0); 12 * (start_rb + n_rb)];
            for n in start_rb..start_rb + n_rb {
                for i in 0..density {
                    grid[12 * n + k0 + 4 * i] = h * seq[density * n + i];
                }
            }
            let res = CsiRsMeasurement { row, n_id, k0, symbol, start_rb, n_rb };
            let sinr = measure_csi_rs_sinr(&grid, |sc| sc, &res, slot);
            assert!(sinr >= 30.0, "lossless SINR should be high, got {sinr}");
            assert_eq!(sinr_to_cqi(sinr), 15);
        }
    }

    #[test]
    fn noisy_csi_rs_measures_finite_sinr() {
        let (n_id, slot, symbol, n_rb, k0) = (5u16, 1u32, 4usize, 24usize, 1usize);
        let seq = csi_rs_sequence(n_id, slot, symbol as u32, 3 * n_rb);
        let mut grid = vec![Complex32::new(0.0, 0.0); 12 * n_rb];
        let mut seed = 0xC51u64;
        let mut noise = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (((seed >> 40) as f32) / (1u64 << 24) as f32 - 0.5) * 0.3
        };
        for n in 0..n_rb {
            for i in 0..3 {
                grid[12 * n + k0 + 4 * i] = seq[3 * n + i] + Complex32::new(noise(), noise());
            }
        }
        let res = CsiRsMeasurement { row: CsiRsRow::Row1, n_id, k0, symbol, start_rb: 0, n_rb };
        let sinr = measure_csi_rs_sinr(&grid, |sc| sc, &res, slot);
        assert!((5.0..30.0).contains(&sinr), "sinr {sinr}");
    }

    #[test]
    fn cqi_thresholds() {
        assert_eq!(sinr_to_cqi(-10.0), 0);
        assert_eq!(sinr_to_cqi(0.5), 4);
        assert_eq!(sinr_to_cqi(100.0), 15);
    }

    /// The bring-up cell's pattern (read from the gNB's FAPI output): TRS row 1
    /// density 3 k0 = 1 (k ∈ {1, 5, 9}), NZP row 2 k = 1, ZP row 4 group 1
    /// (k ∈ 4..8).
    #[test]
    fn re_masks_match_live_cell() {
        assert_eq!(csi_rs_re_mask(CsiRsRow::Row1, 0b0010), 0b_0010_0010_0010);
        assert_eq!(csi_rs_re_mask(CsiRsRow::Row2, 1 << 1), 0b_0000_0000_0010);
        assert_eq!(csi_rs_re_mask(CsiRsRow::Row4, 0b010), 0b_0000_1111_0000);
    }

    #[test]
    fn pattern_rate_matching_predicate() {
        let n = Numerology::KHZ30;
        let p = CsiRsPattern {
            period_slots: 40,
            offset_slots: 22,
            symbols: vec![4, 8],
            start_rb: 0,
            n_rb: 52,
            re_mask: csi_rs_re_mask(CsiRsRow::Row1, 0b0010),
        };
        // SFN 1 slot 2 → index 22 → occasion; SFN 3 slot 2 → 62 → occasion.
        assert!(csi_rs_slots(40, 22, SlotPoint::new(n, 1, 2)));
        assert!(p.occupies(SlotPoint::new(n, 3, 2), 4, 10, 5));
        assert!(!p.occupies(SlotPoint::new(n, 3, 2), 4, 10, 4));
        assert!(!p.occupies(SlotPoint::new(n, 3, 2), 5, 10, 5));
        assert!(!p.occupies(SlotPoint::new(n, 3, 3), 4, 10, 5));
        assert!(!p.occupies(SlotPoint::new(n, 3, 2), 4, 52, 5));
        assert!(csi_rs_rate_match(std::slice::from_ref(&p), SlotPoint::new(n, 1, 2), 8, 51, 9));
    }
}
