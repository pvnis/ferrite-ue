//! SS/PBCH block resource mapping (3GPP TS 38.211 §7.4.3) and the SSB
//! candidate positions within a half frame (TS 38.213 §4.1).
//!
//! The SSB is 4 OFDM symbols × 240 subcarriers. The PSS (symbol 0) and SSS
//! (symbol 2) each occupy the middle 127 subcarriers (`k = 56..=182`). For cell
//! search we tune to the SSB centre frequency and place the 240-subcarrier block
//! centred at DC, so SSB subcarrier `j` maps to FFT frequency offset `j - 120`.

use ferrite_common::DuplexMode;
use num_complex::Complex32;

use crate::numerology::symbols_per_subframe;
use crate::ofdm::Ofdm;
use crate::sync::pss::pss;
use crate::sync::sss::sss;

/// Number of subcarriers spanned by an SSB (§7.4.3.1).
pub const SSB_SUBCARRIERS: usize = 240;
/// First SSB subcarrier carrying PSS/SSS (127 wide), per Table 7.4.3.1-1.
pub const SYNC_SC_START: usize = 56;
/// PSS/SSS width in subcarriers.
pub const SYNC_SC_WIDTH: usize = 127;
/// Number of OFDM symbols in an SSB.
pub const SSB_SYMBOLS: usize = 4;
/// SSB subcarrier index placed at DC when centring the block.
const SSB_DC_SC: i32 = 120;

/// SSB time-domain pattern (TS 38.213 §4.1), i.e. the SSB subcarrier spacing
/// and the set of candidate first symbols within a half frame. FR1 only
/// (Cases D/E are the FR2 120/240 kHz patterns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SsbCase {
    /// 15 kHz SSB: first symbols `{2, 8} + 14·n`.
    A,
    /// 30 kHz SSB, paired spectrum (FDD): first symbols `{4, 8, 16, 20} + 28·n`.
    B,
    /// 30 kHz SSB, unpaired spectrum (TDD): first symbols `{2, 8} + 14·n`.
    C,
}

impl SsbCase {
    /// Select the SSB case from the SSB subcarrier spacing and the band's duplex
    /// mode (TS 38.101-1 Table 5.4.3.3-1 lists the case per band): 15 kHz → A;
    /// 30 kHz → B for paired (FDD, e.g. n5/n66) and C for unpaired (TDD, e.g.
    /// n41/n77/n78/n79) spectrum. `None` for an SCS that is not an FR1 SSB SCS.
    pub fn from_scs(ssb_scs_khz: u32, duplex: DuplexMode) -> Option<SsbCase> {
        match (ssb_scs_khz, duplex) {
            (15, _) => Some(SsbCase::A),
            (30, DuplexMode::Fdd) => Some(SsbCase::B),
            (30, DuplexMode::Tdd) => Some(SsbCase::C),
            _ => None,
        }
    }

    /// Numerology index `mu` of the SSB (0 for 15 kHz, 1 for 30 kHz).
    pub const fn mu(self) -> u8 {
        match self {
            SsbCase::A => 0,
            SsbCase::B | SsbCase::C => 1,
        }
    }

    /// First OFDM symbols (indexed from the start of the half frame, at the SSB
    /// numerology) of the candidate SSBs, in ascending time order — the
    /// candidate index is the position in the returned vector. Transcribed from
    /// TS 38.213 §4.1:
    ///
    /// * Case A: `{2, 8} + 14·n`; `n = 0, 1` for `f_c ≤ 3 GHz`, `n = 0..=3` for
    ///   FR1 above 3 GHz.
    /// * Case B: `{4, 8, 16, 20} + 28·n`; `n = 0` for `f_c ≤ 3 GHz`, `n = 0, 1`
    ///   for FR1 above 3 GHz.
    /// * Case C: `{2, 8} + 14·n`; paired spectrum: `n = 0, 1` for `f_c ≤ 3 GHz`,
    ///   `n = 0..=3` above; unpaired spectrum: `n = 0, 1` for `f_c ≤ 2.4 GHz`,
    ///   `n = 0..=3` for FR1 above 2.4 GHz.
    ///
    /// Case C is the unpaired-spectrum pattern, so the 2.4 GHz threshold applies
    /// to it (Case B carries the paired 30 kHz pattern with the 3 GHz threshold).
    pub fn candidate_symbols(self, carrier_hz: f64) -> Vec<usize> {
        let (bases, stride, n_count): (&[usize], usize, usize) = match self {
            SsbCase::A => (&[2, 8], 14, if carrier_hz <= 3e9 { 2 } else { 4 }),
            SsbCase::B => (&[4, 8, 16, 20], 28, if carrier_hz <= 3e9 { 1 } else { 2 }),
            SsbCase::C => (&[2, 8], 14, if carrier_hz <= 2.4e9 { 2 } else { 4 }),
        };
        let out: Vec<usize> = (0..n_count)
            .flat_map(|n| bases.iter().map(move |&b| b + stride * n))
            .collect();
        // None of the FR1 candidates starts at, or spans, a long-CP symbol
        // (symbol 0 or 7·2^mu of a subframe), so every SSB symbol has the normal
        // CP; `build_ssb_waveform` / `extract_pbch` rely on this.
        debug_assert!(out
            .iter()
            .all(|&s| (s..s + SSB_SYMBOLS).all(|l| !is_long_cp_symbol(l, self.mu()))));
        out
    }

    /// `L_max`, the number of candidate SSBs in a half frame (TS 38.213 §4.1):
    /// 4 or 8 in FR1. Equal to `candidate_symbols(carrier_hz).len()`.
    pub fn l_max(self, carrier_hz: f64) -> u8 {
        self.candidate_symbols(carrier_hz).len() as u8
    }
}

/// `L_max` for an FR1 carrier irrespective of the SSB case: 4 for `f_c ≤ 3 GHz`,
/// 8 above (TS 38.213 §4.1). For Case C between 2.4 and 3 GHz use
/// [`SsbCase::l_max`], which yields 8 there.
pub fn l_max_fr1(carrier_hz: f64) -> u8 {
    if carrier_hz <= 3e9 {
        4
    } else {
        8
    }
}

/// Whether symbol `symbol_in_half_frame` (at numerology `mu`) carries the long
/// cyclic prefix, i.e. is symbol 0 or `7·2^mu` of its subframe (§5.3.1).
fn is_long_cp_symbol(symbol_in_half_frame: usize, mu: u8) -> bool {
    let l = symbol_in_half_frame % symbols_per_subframe(mu);
    l == 0 || l == 7 << mu
}

/// Sample offset, from the start of the 10 ms frame, of the cyclic prefix of
/// an SSB's first symbol: candidate `first_symbol` (from
/// [`SsbCase::candidate_symbols`], indexed within the half frame) in half frame
/// `half_frame` (0/1), at SSB numerology `mu`.
pub fn ssb_sample_offset_in_frame(first_symbol: usize, half_frame: u8, mu: u8, ofdm: &Ofdm) -> usize {
    let per_sf = symbols_per_subframe(mu);
    let subframe = usize::from(half_frame) * 5 + first_symbol / per_sf;
    subframe * ofdm.samples_per_subframe(mu) + ofdm.symbol_offset_in_subframe(first_symbol % per_sf, mu)
}

/// Sample offset, from the frame start, of the PSS symbol's *useful part* for
/// the given SSB candidate (the quantity the PSS correlator reports).
pub fn pss_useful_offset_in_frame(first_symbol: usize, half_frame: u8, mu: u8, ofdm: &Ofdm) -> usize {
    let cp = ofdm.cp_len(first_symbol % symbols_per_subframe(mu), mu);
    ssb_sample_offset_in_frame(first_symbol, half_frame, mu, ofdm) + cp
}

/// Sample index of the start of the frame containing a detected SSB, given the
/// PSS useful-part sample index (`CellSearchResult::timing_index`), the SSB
/// candidate's first symbol and half frame (from the PBCH decode), and the SSB
/// numerology. The frame start equals the PSS index minus the sum of `CP + N`
/// over every symbol from the frame start up to the SSB's first symbol
/// (including the 5 ms half-frame offset) minus the PSS's own CP; it can be
/// negative when the buffer started mid-frame.
pub fn frame_start_from_pss(
    pss_sample_index: usize,
    candidate_first_symbol: usize,
    half_frame: u8,
    mu: u8,
    ofdm: &Ofdm,
) -> i64 {
    pss_sample_index as i64 - pss_useful_offset_in_frame(candidate_first_symbol, half_frame, mu, ofdm) as i64
}

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
/// the loop and by gNB-emulation tooling.
///
/// `i_ssb_bar` is the PBCH DMRS index `ī_SSB` (§7.4.1.4.1): the candidate index
/// for `L_max = 8`, or `candidate + 4·n_hf` for `L_max = 4`; `l_max` selects the
/// PBCH scrambling (§7.3.3.1, 2 or 3 LSBs). All four symbols use the normal CP
/// because no FR1 SSB candidate spans a long-CP symbol (see
/// [`SsbCase::candidate_symbols`]).
pub fn build_ssb_waveform(
    mib: &crate::coding::bch::Mib,
    cell_id: u16,
    i_ssb_bar: u8,
    l_max: u8,
    ofdm: &Ofdm,
    mu: u8,
) -> Vec<Complex32> {
    use crate::coding::bch::bch_encode;
    use crate::sync::pbch::{pbch_dmrs, pbch_scrambling_index, PbchLayout};
    use std::f32::consts::FRAC_1_SQRT_2;

    let n = ofdm.fft_size();
    let n_id_2 = (cell_id % 3) as u8;
    let n_id_1 = cell_id / 3;

    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; SSB_SYMBOLS];
    grids[0] = pss_grid(n_id_2, n);
    grids[2] = sss_grid(n_id_1, n_id_2, n);

    let layout = PbchLayout::new(cell_id);
    let dmrs = pbch_dmrs(cell_id, i_ssb_bar);
    for (idx, &(l, k)) in layout.dmrs_re.iter().enumerate() {
        grids[l as usize][bin_for_ssb_sc(k as usize, n)] = dmrs[idx];
    }
    let bits = bch_encode(mib, cell_id, pbch_scrambling_index(i_ssb_bar, l_max));
    for (idx, &(l, k)) in layout.data_re.iter().enumerate() {
        // QPSK per 38.211 §5.1.3: d = [(1-2b0) + j(1-2b1)] / √2.
        let (b0, b1) = (bits[2 * idx], bits[2 * idx + 1]);
        grids[l as usize][bin_for_ssb_sc(k as usize, n)] = Complex32::new(
            (1 - 2 * i32::from(b0)) as f32 * FRAC_1_SQRT_2,
            (1 - 2 * i32::from(b1)) as f32 * FRAC_1_SQRT_2,
        );
    }

    let cp = ofdm.cp_len(1, mu); // normal CP (see above)
    let mut wave = Vec::with_capacity(SSB_SYMBOLS * (n + cp));
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

    #[test]
    fn candidate_symbols_match_38_213() {
        assert_eq!(SsbCase::A.candidate_symbols(1.8e9), vec![2, 8, 16, 22]);
        assert_eq!(SsbCase::A.candidate_symbols(3.5e9), vec![2, 8, 16, 22, 30, 36, 44, 50]);
        assert_eq!(SsbCase::B.candidate_symbols(1.9e9), vec![4, 8, 16, 20]);
        assert_eq!(SsbCase::B.candidate_symbols(3.5e9), vec![4, 8, 16, 20, 32, 36, 44, 48]);
        assert_eq!(SsbCase::C.candidate_symbols(2.3e9), vec![2, 8, 16, 22]);
        // Unpaired spectrum: 8 candidates already between 2.4 and 3 GHz (n41).
        assert_eq!(SsbCase::C.candidate_symbols(2.6e9).len(), 8);
        assert_eq!(SsbCase::C.candidate_symbols(3.5e9), vec![2, 8, 16, 22, 30, 36, 44, 50]);
        assert_eq!(SsbCase::C.l_max(3.5e9), 8);
        assert_eq!(SsbCase::A.l_max(1.8e9), 4);
        assert_eq!(l_max_fr1(2.6e9), 4);
        assert_eq!(l_max_fr1(3.3e9), 8);
    }

    #[test]
    fn case_selection_by_band_type() {
        assert_eq!(SsbCase::from_scs(15, DuplexMode::Fdd), Some(SsbCase::A));
        assert_eq!(SsbCase::from_scs(15, DuplexMode::Tdd), Some(SsbCase::A));
        assert_eq!(SsbCase::from_scs(30, DuplexMode::Fdd), Some(SsbCase::B));
        assert_eq!(SsbCase::from_scs(30, DuplexMode::Tdd), Some(SsbCase::C));
        assert_eq!(SsbCase::from_scs(60, DuplexMode::Tdd), None);
    }

    #[test]
    fn frame_timing_of_candidates() {
        let ofdm = Ofdm::new(256);
        // Case C candidate 0 at mu=1: symbols 0 (long CP) and 1 precede it.
        let cp_long = ofdm.cp_len(0, 1);
        let cp = ofdm.cp_len(1, 1);
        assert_eq!(ssb_sample_offset_in_frame(2, 0, 1, &ofdm), (cp_long + 256) + (cp + 256));
        assert_eq!(pss_useful_offset_in_frame(2, 0, 1, &ofdm), (cp_long + 256) + (cp + 256) + cp);
        // Candidate at symbol 30 (mu=1): subframe 1, symbol 2 of that subframe.
        assert_eq!(
            ssb_sample_offset_in_frame(30, 0, 1, &ofdm),
            ofdm.samples_per_subframe(1) + ofdm.symbol_offset_in_subframe(2, 1)
        );
        // Second half frame adds 5 ms.
        assert_eq!(
            ssb_sample_offset_in_frame(8, 1, 0, &ofdm) - ssb_sample_offset_in_frame(8, 0, 0, &ofdm),
            5 * ofdm.samples_per_subframe(0)
        );
        // Inverse: a PSS found at the expected offset puts the frame start at 0.
        let pss = pss_useful_offset_in_frame(22, 1, 1, &ofdm);
        assert_eq!(frame_start_from_pss(pss + 1000, 22, 1, 1, &ofdm), 1000);
        assert_eq!(frame_start_from_pss(pss - 7, 22, 1, 1, &ofdm), -7);
    }
}
