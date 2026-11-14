//! SS/PBCH block time-domain patterns (TS 38.213 §4.1): the SSB case per
//! subcarrier spacing and duplex mode, and the candidate first symbols within
//! a half frame.

use ferrite_common::DuplexMode;

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
        (0..n_count)
            .flat_map(|n| bases.iter().map(move |&b| b + stride * n))
            .collect()
    }

    /// `L_max`, the number of candidate SSBs in a half frame (TS 38.213 §4.1):
    /// 4 or 8 in FR1. Equal to `candidate_symbols(carrier_hz).len()`.
    pub fn l_max(self, carrier_hz: f64) -> u8 {
        self.candidate_symbols(carrier_hz).len() as u8
    }
}

/// Number of OFDM symbols in an SSB (TS 38.211 §7.4.3.1).
pub const SSB_SYMBOLS: usize = 4;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_tables() {
        assert_eq!(SsbCase::A.candidate_symbols(2e9), vec![2, 8, 16, 22]);
        assert_eq!(SsbCase::A.candidate_symbols(3.5e9).len(), 8);
        assert_eq!(SsbCase::B.candidate_symbols(2e9), vec![4, 8, 16, 20]);
        assert_eq!(
            SsbCase::C.candidate_symbols(3.5e9),
            vec![2, 8, 16, 22, 30, 36, 44, 50]
        );
        assert_eq!(SsbCase::C.l_max(2.6e9), 8);
        assert_eq!(l_max_fr1(2.6e9), 4);
        assert_eq!(SsbCase::from_scs(30, DuplexMode::Tdd), Some(SsbCase::C));
        assert_eq!(SsbCase::from_scs(60, DuplexMode::Tdd), None);
    }
}
