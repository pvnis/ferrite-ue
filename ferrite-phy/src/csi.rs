//! CSI-RS (TS 38.211 §7.4.1.5): the NZP-CSI-RS sequence, the per-RB RE
//! patterns of Table 7.4.1.5.3-1 rows 1/2/3/4 (used both to measure the
//! downlink SINR for the CQI report, TS 38.214 §5.2, and to rate-match the
//! PDSCH around ZP/NZP resources, TS 38.214 §5.1.4), the SINR→CQI mapping,
//! and the two-port channel measurement with rank / PMI selection against
//! the Type I single-panel codebook (TS 38.214 Table 5.2.2.2.1-1).

use crate::sequence::gold_sequence;
use ferrite_common::SlotPoint;
use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

/// Row of Table 7.4.1.5.3-1 (single-port rows and the 2/4-port rows OCUDU uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiRsRow {
    /// 1 port, density 3: `k ∈ {k0, k0+4, k0+8}` in one symbol.
    Row1,
    /// 1 port, density 1 (or 0.5): the single subcarrier `k0`.
    Row2,
    /// 2 ports, density 1: one FD-CDM2 group on subcarriers `k0, k0+1`
    /// (`other` bitmap, bit `i` → `k0 = 2i`), one symbol.
    Row3,
    /// 4 ports, density 1: subcarriers `4j..4j+4` (CDM group of 4), one symbol.
    Row4,
}

/// Per-RB subcarrier mask (bit `k` = subcarrier `k` of every RB) of a CSI-RS
/// resource (TS 38.211 §7.4.1.5.3), from the row and the
/// `frequencyDomainAllocation` bits: for `row1` the 4-bit field with the lowest
/// set bit `i` meaning `k0 = i`; `row2` the 12-bit field with `k0` = lowest set
/// bit; `row3` the 6-bit `other` field with `k0 = 2i`; `row4` the 3-bit field
/// selecting the 4-subcarrier group `j`.
/// `freq_bits` holds the field with bit 0 = the field's lowest bit (`b_0`).
pub fn csi_rs_re_mask(row: CsiRsRow, freq_bits: u16) -> u16 {
    let bit = freq_bits.trailing_zeros().min(15) as u16;
    match row {
        CsiRsRow::Row1 => 0b_0001_0001_0001 << bit,
        CsiRsRow::Row2 => 1 << bit,
        CsiRsRow::Row3 => 0b11 << (2 * bit).min(10),
        CsiRsRow::Row4 => 0b1111 << (4 * bit),
    }
}

/// Subcarrier `k0` of a resource from its `frequencyDomainAllocation` bits
/// (the lowest set bit `i`: `k0 = i` for rows 1/2, `2i` for row 3, `4i` for
/// row 4).
pub fn csi_rs_k0(row: CsiRsRow, freq_bits: u16) -> usize {
    let bit = freq_bits.trailing_zeros().min(15) as usize;
    match row {
        CsiRsRow::Row1 | CsiRsRow::Row2 => bit,
        CsiRsRow::Row3 => 2 * bit,
        CsiRsRow::Row4 => 4 * bit,
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
pub fn csi_rs_rate_match(
    patterns: &[CsiRsPattern],
    slot: SlotPoint,
    symbol: usize,
    crb: usize,
    k_in_rb: usize,
) -> bool {
    patterns
        .iter()
        .any(|p| p.occupies(slot, symbol, crb, k_in_rb))
}

/// The NZP-CSI-RS sequence `r(0..len)` for one OFDM symbol (§7.4.1.5.2):
/// `c_init = (2^10·(14·n_slot + l + 1)·(2·n_ID + 1) + n_ID) mod 2^31`, QPSK.
/// Index `m' = ⌊n·α⌋ + k' + ⌊k̄·ρ/12⌋` is `3·n + i` for density 3 (row 1) and
/// `n` for density 1 (row 2), with `n` the CRB index; pass `len` to cover the
/// highest CRB of the resource.
pub fn csi_rs_sequence(n_id: u16, slot: u32, symbol: u32, len: usize) -> Vec<Complex32> {
    let c_init = (((1u64 << 10)
        * (14 * u64::from(slot) + u64::from(symbol) + 1)
        * (2 * u64::from(n_id) + 1)
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

/// An NZP-CSI-RS resource used for channel measurement: single-port rows 1/2
/// (SINR / CQI) or the two-port row 3 (rank, PMI and CQI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiRsMeasurement {
    /// Row 1 (density 3), row 2 (density 1) or row 3 (two ports).
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
pub fn measure_csi_rs_sinr(
    grid: &[Complex32],
    sc_to_bin: impl Fn(usize) -> usize,
    res: &CsiRsMeasurement,
    slot: u32,
) -> f32 {
    let density = match res.row {
        CsiRsRow::Row1 => 3,
        CsiRsRow::Row2 => 1,
        // Multi-port resources go through [`measure_csi_rs_ports`]: report
        // "no signal" here rather than abort the timeline thread.
        CsiRsRow::Row3 | CsiRsRow::Row4 => return f32::NEG_INFINITY,
    };
    let seq = csi_rs_sequence(
        res.n_id,
        slot,
        res.symbol as u32,
        density * (res.start_rb + res.n_rb),
    );
    let rbs = res.start_rb..res.start_rb + res.n_rb;
    let (mut sig, mut noise, mut n_noise) = (0.0f32, 0.0f32, 0usize);
    if density == 3 {
        for n in rbs {
            let mut h = [Complex32::new(0.0, 0.0); 3];
            for (i, hi) in h.iter_mut().enumerate() {
                *hi = grid[sc_to_bin(12 * n + res.k0 + 4 * i)] * seq[3 * n + i].conj();
                // |seq| = 1
            }
            let rb_h = (h[0] + h[1] + h[2]) / 3.0;
            sig += rb_h.norm_sqr();
            for hi in &h {
                noise += (hi - rb_h).norm_sqr();
                n_noise += 1;
            }
        }
    } else {
        let h: Vec<Complex32> = rbs
            .map(|n| grid[sc_to_bin(12 * n + res.k0)] * seq[n].conj())
            .collect();
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

/// The channel state measured on a two-port CSI-RS occasion: the effective
/// post-equalisation SINR behind the CQI, and the rank and Type I
/// single-panel `i2` the UE recommends.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CsiEstimate {
    pub sinr_db: f32,
    pub cqi: u8,
    pub ri: u8,
    pub pmi: u8,
}

/// Type I single-panel codebook for two CSI-RS ports (TS 38.214 Table
/// 5.2.2.2.1-1): rank 1 `W = [1, φ_n]ᵀ/√2` (`n = i2 ∈ 0..4`), rank 2
/// `W = [[1, 1], [φ_n, −φ_n]]/2` (`n ∈ 0..2`), `φ_n = e^{jπn/2}`. Returns
/// the columns of `W`, one `[w_port0, w_port1]` per layer.
pub fn two_port_precoder(rank: u8, i2: u8) -> Vec<[Complex32; 2]> {
    let phi = Complex32::from_polar(1.0, std::f32::consts::FRAC_PI_2 * f32::from(i2));
    if rank >= 2 {
        let half = Complex32::new(0.5, 0.0);
        vec![[half, phi * 0.5], [half, -phi * 0.5]]
    } else {
        vec![[Complex32::new(FRAC_1_SQRT_2, 0.0), phi * FRAC_1_SQRT_2]]
    }
}

/// Number of `i2` hypotheses of the two-port codebook for `rank`.
pub fn two_port_pmi_count(rank: u8) -> u8 {
    if rank >= 2 {
        2
    } else {
        4
    }
}

/// Measure a two-port NZP-CSI-RS (row 3: ports 3000/3001 FD-CDM2 on
/// subcarriers `k0, k0+1`, sequence index `m' = 2n + k'`, TS 38.211
/// §7.4.1.5.3) on every receive antenna — `grids[a]` is antenna `a`'s
/// demodulated grid of the resource's symbol — and choose the rank and `i2`
/// that maximise the sum of the per-layer `log2(1 + SINR)` over the RBs
/// (TS 38.214 §5.2.2.1: the UE reports the RI/PMI yielding the highest
/// throughput under the codebook). Per RB and antenna the two port channels
/// come from the CDM despreading; the noise variance is the RB-to-RB spread
/// of every (antenna, port) estimate (capped at 40 dB SNR on a lossless
/// channel). The rank-1 SINR is the MRC gain of the precoded channel, the
/// rank-2 SINRs the per-layer post-MMSE values. `max_rank` caps the rank
/// (`ri-Restriction`; the number of receive antennas caps it as well).
pub fn measure_csi_rs_ports(
    grids: &[&[Complex32]],
    sc_to_bin: impl Fn(usize) -> usize,
    res: &CsiRsMeasurement,
    slot: u32,
    max_rank: u8,
) -> CsiEstimate {
    let none = CsiEstimate {
        sinr_db: f32::NEG_INFINITY,
        cqi: 0,
        ri: 1,
        pmi: 0,
    };
    let n_ant = grids.len().min(2);
    if n_ant == 0 || res.n_rb == 0 || res.row != CsiRsRow::Row3 {
        return none;
    }
    let seq = csi_rs_sequence(
        res.n_id,
        slot,
        res.symbol as u32,
        2 * (res.start_rb + res.n_rb),
    );
    // h[rb][antenna][port].
    let zero = Complex32::new(0.0, 0.0);
    let h: Vec<[[Complex32; 2]; 2]> = (res.start_rb..res.start_rb + res.n_rb)
        .map(|n| {
            let mut hn = [[zero; 2]; 2];
            for (a, grid) in grids.iter().take(n_ant).enumerate() {
                let y0 = grid[sc_to_bin(12 * n + res.k0)] * seq[2 * n].conj();
                let y1 = grid[sc_to_bin(12 * n + res.k0 + 1)] * seq[2 * n + 1].conj();
                // Port 0 has w_f = [+1, +1], port 1 w_f = [+1, −1]; |seq| = 1.
                hn[a] = [(y0 + y1) / 2.0, (y0 - y1) / 2.0];
            }
            hn
        })
        .collect();
    let entries = || h.iter().flat_map(|hn| hn[..n_ant].iter().flatten());
    let sig = entries().map(|x| x.norm_sqr()).sum::<f32>() / (h.len() * n_ant * 2) as f32;
    let (mut noise, mut n_noise) = (0.0f32, 0usize);
    for w in h.windows(2) {
        for a in 0..n_ant {
            for p in 0..2 {
                noise += (w[1][a][p] - w[0][a][p]).norm_sqr() / 2.0;
                n_noise += 1;
            }
        }
    }
    let noise = (noise / n_noise.max(1) as f32).max(sig * 1e-4).max(1e-12);
    let mut best: Option<(f32, u8, u8, f32)> = None;
    for rank in 1..=max_rank.clamp(1, 2).min(n_ant as u8) {
        for i2 in 0..two_port_pmi_count(rank) {
            let w = two_port_precoder(rank, i2);
            let (mut se, mut sinr_sum) = (0.0f32, 0.0f32);
            for hn in &h {
                // Precoded channel per antenna and layer: g[a][l] = Σ_p H[a][p]·W[p][l].
                let g = |a: usize, l: usize| hn[a][0] * w[l][0] + hn[a][1] * w[l][1];
                if rank == 1 {
                    let gain: f32 = (0..n_ant).map(|a| g(a, 0).norm_sqr()).sum();
                    let sinr = gain / noise;
                    se += (1.0 + sinr).log2();
                    sinr_sum += sinr;
                } else {
                    // Post-MMSE SINR per layer: 1 / [(I + GᴴG/σ²)⁻¹]_ll − 1.
                    let gg = |l: usize, m: usize| {
                        (0..n_ant)
                            .map(|a| g(a, l).conj() * g(a, m))
                            .sum::<Complex32>()
                            / noise
                    };
                    let (m00, m11, m01) = (gg(0, 0) + 1.0, gg(1, 1) + 1.0, gg(0, 1));
                    let det = m00 * m11 - m01 * m01.conj();
                    if det.norm() < 1e-20 {
                        continue;
                    }
                    for other in [m11, m00] {
                        let inv_ll = (other / det).re.max(1e-9);
                        let sinr = (1.0 / inv_ll - 1.0).max(0.0);
                        se += (1.0 + sinr).log2();
                        sinr_sum += sinr;
                    }
                }
            }
            if best.is_none_or(|b| se > b.0) {
                let layers = (h.len() * usize::from(rank)) as f32;
                best = Some((se, rank, i2, sinr_sum / layers));
            }
        }
    }
    let Some((_, ri, pmi, sinr)) = best else {
        return none;
    };
    let sinr_db = 10.0 * sinr.max(1e-9).log10();
    CsiEstimate {
        sinr_db,
        cqi: sinr_to_cqi(sinr_db),
        ri,
        pmi,
    }
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
            .map(|(l, off)| CsiRsPattern {
                period_slots: 20,
                offset_slots: off,
                symbols: vec![l],
                start_rb: 0,
                n_rb: 52,
                re_mask: 0b010001000100,
            })
            .collect();
        let trs_slot = SlotPoint::new(mu0, 279, 2);
        assert!(trs_slot.is_occasion(20, 12), "index {} ", trs_slot.index());
        assert!(csi_rs_rate_match(&pats, trs_slot, 4, 0, 2));
        assert!(csi_rs_rate_match(&pats, trs_slot, 8, 51, 10));
        assert!(!csi_rs_rate_match(&pats, trs_slot, 4, 0, 3));
        assert!(!csi_rs_rate_match(&pats, trs_slot, 5, 0, 2));
        assert!(!csi_rs_rate_match(
            &pats,
            SlotPoint::new(mu0, 128, 8),
            4,
            0,
            2
        ));
        assert!(csi_rs_rate_match(
            &pats,
            SlotPoint::new(mu0, 279, 3),
            8,
            3,
            6
        ));
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
        for (row, start_rb, n_rb, k0) in [
            (CsiRsRow::Row1, 0usize, 24usize, 1usize),
            (CsiRsRow::Row1, 5, 20, 2),
            (CsiRsRow::Row2, 3, 30, 7),
        ] {
            let density = if row == CsiRsRow::Row1 { 3 } else { 1 };
            let seq = csi_rs_sequence(n_id, slot, symbol as u32, density * (start_rb + n_rb));
            let mut grid = vec![Complex32::new(0.0, 0.0); 12 * (start_rb + n_rb)];
            for n in start_rb..start_rb + n_rb {
                for i in 0..density {
                    grid[12 * n + k0 + 4 * i] = h * seq[density * n + i];
                }
            }
            let res = CsiRsMeasurement {
                row,
                n_id,
                k0,
                symbol,
                start_rb,
                n_rb,
            };
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
        let res = CsiRsMeasurement {
            row: CsiRsRow::Row1,
            n_id,
            k0,
            symbol,
            start_rb: 0,
            n_rb,
        };
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
        assert!(csi_rs_rate_match(
            std::slice::from_ref(&p),
            SlotPoint::new(n, 1, 2),
            8,
            51,
            9
        ));
    }

    /// Two-port row-3 occasion on two antennas through the channel `hm[a][p]`.
    fn two_port_grids(
        hm: [[Complex32; 2]; 2],
        res: &CsiRsMeasurement,
        slot: u32,
    ) -> Vec<Vec<Complex32>> {
        let seq = csi_rs_sequence(
            res.n_id,
            slot,
            res.symbol as u32,
            2 * (res.start_rb + res.n_rb),
        );
        let mut g = vec![vec![Complex32::new(0.0, 0.0); 12 * 52]; 2];
        for n in res.start_rb..res.start_rb + res.n_rb {
            for (a, ga) in g.iter_mut().enumerate() {
                // Port 0 w_f = [+1, +1], port 1 w_f = [+1, −1]; sequence index 2n + k'.
                ga[12 * n + res.k0] = (hm[a][0] + hm[a][1]) * seq[2 * n];
                ga[12 * n + res.k0 + 1] = (hm[a][0] - hm[a][1]) * seq[2 * n + 1];
            }
        }
        g
    }

    fn two_port_res() -> CsiRsMeasurement {
        CsiRsMeasurement {
            row: CsiRsRow::Row3,
            n_id: 1,
            k0: 2,
            symbol: 4,
            start_rb: 3,
            n_rb: 40,
        }
    }

    /// OCUDU's two-port resource: `other "000010"` → `k0 = 2`, REs 2 and 3.
    #[test]
    fn row3_re_mask_and_k0_from_the_other_bitmap() {
        assert_eq!(csi_rs_re_mask(CsiRsRow::Row3, 0b000010), 0b1100);
        assert_eq!(csi_rs_k0(CsiRsRow::Row3, 0b000010), 2);
        assert_eq!(csi_rs_re_mask(CsiRsRow::Row3, 0b100000), 0b1100_0000_0000);
        assert_eq!(csi_rs_k0(CsiRsRow::Row4, 0b010), 4);
        assert_eq!(csi_rs_k0(CsiRsRow::Row1, 0b0100), 2);
    }

    /// Rank / PMI selection on the two-port codebook: the lab's identity
    /// channel yields rank 2 at the maximum CQI; a rank-one channel yields
    /// rank 1 with the `i2` that co-phases the two ports; the rank cap and a
    /// single receive antenna force rank 1.
    #[test]
    fn two_port_measurement_picks_rank_and_pmi() {
        let r = two_port_res();
        let c = Complex32::new;
        let measure = |hm, ants: usize, max_rank| {
            let g = two_port_grids(hm, &r, 7);
            let views: Vec<&[Complex32]> = g.iter().take(ants).map(Vec::as_slice).collect();
            measure_csi_rs_ports(&views, |sc| sc, &r, 7, max_rank)
        };
        let identity = [[c(1.0, 0.0), c(0.0, 0.0)], [c(0.0, 0.0), c(1.0, 0.0)]];
        let e = measure(identity, 2, 2);
        assert_eq!(e.ri, 2, "{e:?}");
        assert!(e.sinr_db > 30.0 && e.cqi == 15, "{e:?}");
        assert_eq!(measure(identity, 2, 1).ri, 1);
        assert_eq!(measure(identity, 1, 2).ri, 1);
        // Ports in phase: i2 = 0 (φ = 1).
        let e = measure(
            [[c(1.0, 0.0), c(1.0, 0.0)], [c(0.5, 0.0), c(0.5, 0.0)]],
            2,
            2,
        );
        assert_eq!((e.ri, e.pmi), (1, 0), "{e:?}");
        // Ports in antiphase: i2 = 2 (φ = −1).
        let e = measure(
            [[c(1.0, 0.0), c(-1.0, 0.0)], [c(0.5, 0.0), c(-0.5, 0.0)]],
            2,
            2,
        );
        assert_eq!((e.ri, e.pmi), (1, 2), "{e:?}");
        // Port 1 lagging by 90° (h1 = −j·h0): φ = j co-phases them, i2 = 1.
        let e = measure(
            [[c(1.0, 0.0), c(0.0, -1.0)], [c(0.5, 0.0), c(0.0, -0.5)]],
            2,
            2,
        );
        assert_eq!((e.ri, e.pmi), (1, 1), "{e:?}");
        // Codebook columns: unit total power per layer, rank-2 columns orthogonal.
        for rank in [1u8, 2] {
            for i2 in 0..two_port_pmi_count(rank) {
                let w = two_port_precoder(rank, i2);
                for col in &w {
                    let p: f32 = col.iter().map(|x| x.norm_sqr()).sum();
                    assert!(
                        (p - 1.0 / f32::from(rank)).abs() < 1e-6,
                        "rank {rank} i2 {i2}: {p}"
                    );
                }
                if rank == 2 {
                    let dot = w[0][0].conj() * w[1][0] + w[0][1].conj() * w[1][1];
                    assert!(dot.norm() < 1e-6);
                }
            }
        }
        // A non-row-3 resource or no antennas: no estimate.
        let r1 = CsiRsMeasurement {
            row: CsiRsRow::Row1,
            ..r
        };
        assert_eq!(measure_csi_rs_ports(&[], |sc| sc, &r1, 7, 2).ri, 1);
    }
}
