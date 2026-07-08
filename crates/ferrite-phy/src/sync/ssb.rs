//! SS/PBCH block resource mapping (3GPP TS 38.211 §7.4.3).
//!
//! The SSB is 4 OFDM symbols × 240 subcarriers. The PSS (symbol 0) and SSS
//! (symbol 2) each occupy the middle 127 subcarriers (`k = 56..=182`). For cell
//! search we tune to the SSB centre frequency and place the 240-subcarrier block
//! centred at DC, so SSB subcarrier `j` maps to FFT frequency offset `j - 120`.

use num_complex::Complex32;

use crate::ofdm::Ofdm;
use crate::sync::pss::pss;
use crate::sync::sss::sss;

/// Number of subcarriers spanned by an SSB (§7.4.3.1).
pub const SSB_SUBCARRIERS: usize = 240;
/// First SSB subcarrier carrying PSS/SSS (127 wide), per Table 7.4.3.1-1.
pub const SYNC_SC_START: usize = 56;
/// PSS/SSS width in subcarriers.
pub const SYNC_SC_WIDTH: usize = 127;
/// SSB subcarrier index placed at DC when centring the block.
const SSB_DC_SC: i32 = 120;

/// FFT bin index (natural order) for SSB subcarrier `ssb_sc`, centred at DC.
fn bin_for_ssb_sc(ssb_sc: usize, fft_size: usize) -> usize {
    let offset = ssb_sc as i32 - SSB_DC_SC;
    offset.rem_euclid(fft_size as i32) as usize
}

/// FFT bin (natural order) for SSB subcarrier `ssb_sc` (0..240), block centred
/// at DC. Public entry point used by the PBCH resource mapping.
pub fn ssb_subcarrier_bin(ssb_sc: usize, fft_size: usize) -> usize {
    bin_for_ssb_sc(ssb_sc, fft_size)
}

/// Frequency-domain grid (length `fft_size`, natural FFT order) carrying the PSS
/// for `n_id_2`, with the SSB centred at DC. Empty subcarriers are zero.
pub fn pss_grid(n_id_2: u8, fft_size: usize) -> Vec<Complex32> {
    let mut grid = vec![Complex32::new(0.0, 0.0); fft_size];
    for (i, &v) in pss(n_id_2).iter().enumerate() {
        grid[bin_for_ssb_sc(SYNC_SC_START + i, fft_size)] = Complex32::new(v as f32, 0.0);
    }
    grid
}

/// Frequency-domain grid carrying the SSS for the given cell-ID components.
pub fn sss_grid(n_id_1: u16, n_id_2: u8, fft_size: usize) -> Vec<Complex32> {
    let mut grid = vec![Complex32::new(0.0, 0.0); fft_size];
    for (i, &v) in sss(n_id_1, n_id_2).iter().enumerate() {
        grid[bin_for_ssb_sc(SYNC_SC_START + i, fft_size)] = Complex32::new(v as f32, 0.0);
    }
    grid
}

/// Time-domain PSS reference (one OFDM symbol, no CP), normalized to unit energy
/// for use as a matched filter in [`crate::sync::detect`].
pub fn pss_time_reference(n_id_2: u8, ofdm: &Ofdm) -> Vec<Complex32> {
    let grid = pss_grid(n_id_2, ofdm.fft_size());
    let mut t = ofdm.modulate_symbol(&grid, 0);
    let energy: f32 = t.iter().map(|s| s.norm_sqr()).sum();
    if energy > 0.0 {
        let inv = 1.0 / energy.sqrt();
        for s in &mut t {
            *s *= inv;
        }
    }
    t
}

/// Extract the 127 PSS/SSS subcarriers (SSB subcarriers 56..=182) from a
/// demodulated frequency-domain grid (natural FFT order, DC at index 0).
pub fn extract_sync_subcarriers(grid: &[Complex32]) -> Vec<Complex32> {
    let fft_size = grid.len();
    (0..SYNC_SC_WIDTH)
        .map(|i| grid[bin_for_ssb_sc(SYNC_SC_START + i, fft_size)])
        .collect()
}

/// Build the complete 4-symbol SSB time-domain waveform (with cyclic prefixes)
/// for a cell: PSS, SSS, PBCH DMRS, and the polar-encoded, QPSK-modulated MIB.
/// This is the transmit side of the whole sync chain — used by tests to close
/// the loop and later by gNB-emulation tooling.
pub fn build_ssb_waveform(
    mib: &crate::coding::bch::Mib,
    cell_id: u16,
    i_ssb: u8,
    ofdm: &Ofdm,
    mu: u8,
) -> Vec<Complex32> {
    use crate::coding::bch::bch_encode;
    use crate::sync::pbch::{pbch_dmrs, PbchLayout};
    use std::f32::consts::FRAC_1_SQRT_2;

    let n = ofdm.fft_size();
    let n_id_2 = (cell_id % 3) as u8;
    let n_id_1 = cell_id / 3;

    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 4];
    grids[0] = pss_grid(n_id_2, n);
    grids[2] = sss_grid(n_id_1, n_id_2, n);

    let layout = PbchLayout::new(cell_id);
    for (idx, &(l, k)) in layout.dmrs_re.iter().enumerate() {
        grids[l as usize][bin_for_ssb_sc(k as usize, n)] = pbch_dmrs(cell_id, i_ssb)[idx];
    }
    let bits = bch_encode(mib, cell_id, i_ssb);
    for (idx, &(l, k)) in layout.data_re.iter().enumerate() {
        // QPSK per 38.211 §5.1.3: d = [(1-2b0) + j(1-2b1)] / √2.
        let (b0, b1) = (bits[2 * idx], bits[2 * idx + 1]);
        grids[l as usize][bin_for_ssb_sc(k as usize, n)] = Complex32::new(
            (1 - 2 * i32::from(b0)) as f32 * FRAC_1_SQRT_2,
            (1 - 2 * i32::from(b1)) as f32 * FRAC_1_SQRT_2,
        );
    }

    let cp = ofdm.cp_len(3, mu);
    let mut wave = Vec::with_capacity(4 * (n + cp));
    for g in &grids {
        wave.extend(ofdm.modulate_symbol(g, cp));
    }
    wave
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_round_trips_pss_grid() {
        // Placing then extracting must return the ±1 PSS values on the real axis.
        let grid = pss_grid(2, 256);
        let sc = extract_sync_subcarriers(&grid);
        assert_eq!(sc.len(), SYNC_SC_WIDTH);
        assert!(sc.iter().all(|c| c.re.abs() == 1.0 && c.im == 0.0));
    }

    #[test]
    fn pss_occupies_127_subcarriers() {
        let grid = pss_grid(0, 256);
        let nonzero = grid.iter().filter(|c| c.norm_sqr() > 0.0).count();
        assert_eq!(nonzero, SYNC_SC_WIDTH);
    }

    #[test]
    fn reference_is_unit_energy() {
        let ofdm = Ofdm::new(256);
        let r = pss_time_reference(1, &ofdm);
        let e: f32 = r.iter().map(|s| s.norm_sqr()).sum();
        assert!((e - 1.0).abs() < 1e-5, "energy {e}");
    }
}
