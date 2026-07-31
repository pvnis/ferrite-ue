//! NZP-CSI-RS measurement (TS 38.211 §7.4.1.5) and SINR→CQI mapping. The gNB sends
//! a non-zero-power CSI-RS the UE measures to report a wideband CQI, so the gNB can
//! adapt the downlink MCS. This cell uses row 1 (1 port, density 3): 3 REs per RB at
//! subcarriers k0, k0+4, k0+8 of one OFDM symbol, no CDM.

use crate::sequence::gold_sequence;
use num_complex::Complex32;
use std::f32::consts::FRAC_1_SQRT_2;

/// The NZP-CSI-RS sequence for one OFDM symbol (TS 38.211 §7.4.1.5.2), density 3 →
/// `3·n_rb` QPSK REs. `n_id` = scramblingID, `slot` = slot-in-frame, `symbol` = the
/// CSI-RS symbol. c_init = (2^10·(14·n_slot + l + 1)·(2·n_id+1) + n_id) mod 2^31.
pub fn csi_rs_sequence(n_id: u16, slot: u32, symbol: u32, n_rb: usize) -> Vec<Complex32> {
    let c_init = (((1u64 << 10) * (14 * slot as u64 + symbol as u64 + 1) * (2 * n_id as u64 + 1)
        + n_id as u64)
        % (1u64 << 31)) as u32;
    let seq_len = 3 * n_rb; // density 3
    let c = gold_sequence(c_init, 2 * seq_len);
    (0..seq_len)
        .map(|m| {
            Complex32::new(
                (1 - 2 * c[2 * m] as i32) as f32 * FRAC_1_SQRT_2,
                (1 - 2 * c[2 * m + 1] as i32) as f32 * FRAC_1_SQRT_2,
            )
        })
        .collect()
}

/// Measure the downlink SINR (dB) from the NZP-CSI-RS (row 1, density 3) in one
/// symbol's demodulated grid. Per-RB least-squares channel estimate from the 3 REs;
/// the signal power is the mean |ĥ_rb|² and the noise the residual of each RE about
/// its RB estimate (robust to a slow channel/timing phase slope across RBs).
pub fn measure_csi_rs_sinr(
    grid: &[Complex32],
    sc_to_bin: impl Fn(usize) -> usize,
    n_id: u16,
    slot: u32,
    symbol: u32,
    n_rb: usize,
    k0: usize,
) -> f32 {
    let seq = csi_rs_sequence(n_id, slot, symbol, n_rb);
    let (mut sig, mut noise) = (0.0f32, 0.0f32);
    for n in 0..n_rb {
        let mut h = [Complex32::new(0.0, 0.0); 3];
        for (i, hi) in h.iter_mut().enumerate() {
            let sc = 12 * n + k0 + 4 * i;
            *hi = grid[sc_to_bin(sc)] * seq[3 * n + i].conj(); // |seq| = 1
        }
        let rb_h = (h[0] + h[1] + h[2]) / 3.0;
        sig += rb_h.norm_sqr();
        for hi in &h {
            noise += (hi - rb_h).norm_sqr();
        }
    }
    sig /= n_rb as f32;
    noise /= (3 * n_rb) as f32;
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
    use super::*;

    /// A perfectly-received CSI-RS (grid = h·sequence at the RE locations) measures a
    /// very high SINR and maps to the maximum CQI.
    #[test]
    fn measure_lossless_csi_rs() {
        let (n_rb, k0, n_id, slot, symbol) = (24usize, 1usize, 1u16, 3u32, 4u32);
        let seq = csi_rs_sequence(n_id, slot, symbol, n_rb);
        let h = Complex32::new(0.8, -0.6); // an arbitrary flat channel
        let mut grid = vec![Complex32::new(0.0, 0.0); 12 * n_rb];
        for n in 0..n_rb {
            for i in 0..3 {
                grid[12 * n + k0 + 4 * i] = h * seq[3 * n + i];
            }
        }
        let sinr = measure_csi_rs_sinr(&grid, |sc| sc, n_id, slot, symbol, n_rb, k0);
        assert!(sinr >= 30.0, "lossless SINR should be high, got {sinr}");
        assert_eq!(sinr_to_cqi(sinr), 15);
    }

    #[test]
    fn cqi_thresholds() {
        assert_eq!(sinr_to_cqi(-10.0), 0);
        assert_eq!(sinr_to_cqi(0.5), 4);
        assert_eq!(sinr_to_cqi(100.0), 15);
    }
}
