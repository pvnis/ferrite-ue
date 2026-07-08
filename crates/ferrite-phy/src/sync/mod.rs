//! Synchronization signals and the SS/PBCH block (SSB).
//!
//! The SSB (3GPP TS 38.211 §7.4.3) is a 4-symbol, 240-subcarrier block carrying
//! the PSS, SSS, and PBCH. Cell search proceeds:
//!
//! 1. correlate against the three PSS to get coarse timing and `N_ID^(2)`;
//! 2. detect the SSS to get `N_ID^(1)`, hence the physical cell ID;
//! 3. decode the PBCH to recover the MIB.
//!
//! This module provides the reference sequence generators; detection lives
//! alongside the OFDM front-end (added next).

pub mod cfo;
pub mod detect;
pub mod pbch;
pub mod pss;
pub mod search;
pub mod ssb;
pub mod sss;

pub use detect::{PssDetection, PssDetector};
pub use search::{detect_sss, CellSearchResult, CellSearcher, SssDetection};

/// Number of `N_ID^(1)` values (SSS), per §7.4.2.1.
pub const N_ID_1_COUNT: u16 = 336;
/// Number of `N_ID^(2)` values (PSS), per §7.4.2.1.
pub const N_ID_2_COUNT: u8 = 3;

/// Physical-layer cell identity `N_cell_ID = 3 * N_ID^(1) + N_ID^(2)` (§7.4.2.1).
///
/// Returns `None` if either component is out of range.
pub fn physical_cell_id(n_id_1: u16, n_id_2: u8) -> Option<u16> {
    if n_id_1 >= N_ID_1_COUNT || u16::from(n_id_2) >= u16::from(N_ID_2_COUNT) {
        return None;
    }
    Some(3 * n_id_1 + u16::from(n_id_2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_id_range() {
        assert_eq!(physical_cell_id(0, 0), Some(0));
        assert_eq!(physical_cell_id(335, 2), Some(1007)); // max, matches 1008 IDs
        assert_eq!(physical_cell_id(336, 0), None);
        assert_eq!(physical_cell_id(0, 3), None);
    }
}
