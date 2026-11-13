//! Frequency helpers: NR-ARFCN (TS 38.104 §5.4.2.1), GSCN sync raster
//! (§5.4.3.1), and the subset of the FR1 operating-band table (TS 38.101-1
//! Table 5.2-1) the UE needs to know a band's duplex mode and SSB SCS.

/// Duplex mode of an operating band.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DuplexMode {
    Fdd,
    Tdd,
}

/// `N_TA_offset` class (TS 38.133 Table 7.1.2-2) when SIB1 does not signal
/// `n-TimingAdvanceOffset`: FR1 defaults to 25600 T_c; FDD bands flagged for
/// LTE-NR coexistence use 39936; FR2 uses 13792.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtaOffsetClass {
    Fr1,
    Fr1LteCoexistence,
    Fr2,
}

impl NtaOffsetClass {
    pub fn tc(self) -> u32 {
        match self {
            NtaOffsetClass::Fr1 => 25600,
            NtaOffsetClass::Fr1LteCoexistence => 39936,
            NtaOffsetClass::Fr2 => 13792,
        }
    }
}

/// Operating band properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandInfo {
    pub band: u16,
    pub duplex: DuplexMode,
    /// Uplink ARFCN range (inclusive).
    pub ul_arfcn: (u32, u32),
    /// Downlink ARFCN range (inclusive).
    pub dl_arfcn: (u32, u32),
    /// SSB subcarrier spacing(s) this band allows (kHz).
    pub ssb_scs_khz: &'static [u32],
}

/// FR1 bands the UE knows about (TS 38.101-1 Table 5.2-1). Extend as needed.
pub const BANDS: &[BandInfo] = &[
    BandInfo { band: 1, duplex: DuplexMode::Fdd, ul_arfcn: (384000, 396000), dl_arfcn: (422000, 434000), ssb_scs_khz: &[15] },
    BandInfo { band: 2, duplex: DuplexMode::Fdd, ul_arfcn: (370000, 382000), dl_arfcn: (386000, 398000), ssb_scs_khz: &[15] },
    BandInfo { band: 3, duplex: DuplexMode::Fdd, ul_arfcn: (342000, 357000), dl_arfcn: (361000, 376000), ssb_scs_khz: &[15] },
    BandInfo { band: 5, duplex: DuplexMode::Fdd, ul_arfcn: (164800, 169800), dl_arfcn: (173800, 178800), ssb_scs_khz: &[15, 30] },
    BandInfo { band: 7, duplex: DuplexMode::Fdd, ul_arfcn: (500000, 514000), dl_arfcn: (524000, 538000), ssb_scs_khz: &[15] },
    BandInfo { band: 8, duplex: DuplexMode::Fdd, ul_arfcn: (176000, 183000), dl_arfcn: (185000, 192000), ssb_scs_khz: &[15] },
    BandInfo { band: 20, duplex: DuplexMode::Fdd, ul_arfcn: (166400, 172400), dl_arfcn: (158200, 164200), ssb_scs_khz: &[15] },
    BandInfo { band: 28, duplex: DuplexMode::Fdd, ul_arfcn: (140600, 149600), dl_arfcn: (151600, 160600), ssb_scs_khz: &[15] },
    BandInfo { band: 38, duplex: DuplexMode::Tdd, ul_arfcn: (514000, 524000), dl_arfcn: (514000, 524000), ssb_scs_khz: &[30] },
    BandInfo { band: 40, duplex: DuplexMode::Tdd, ul_arfcn: (460000, 480000), dl_arfcn: (460000, 480000), ssb_scs_khz: &[30] },
    BandInfo { band: 41, duplex: DuplexMode::Tdd, ul_arfcn: (499200, 537999), dl_arfcn: (499200, 537999), ssb_scs_khz: &[15, 30] },
    BandInfo { band: 48, duplex: DuplexMode::Tdd, ul_arfcn: (636667, 646666), dl_arfcn: (636667, 646666), ssb_scs_khz: &[30] },
    BandInfo { band: 66, duplex: DuplexMode::Fdd, ul_arfcn: (342000, 356000), dl_arfcn: (422000, 440000), ssb_scs_khz: &[15, 30] },
    BandInfo { band: 71, duplex: DuplexMode::Fdd, ul_arfcn: (132600, 139600), dl_arfcn: (123400, 130400), ssb_scs_khz: &[15] },
    BandInfo { band: 77, duplex: DuplexMode::Tdd, ul_arfcn: (620000, 680000), dl_arfcn: (620000, 680000), ssb_scs_khz: &[30] },
    BandInfo { band: 78, duplex: DuplexMode::Tdd, ul_arfcn: (620000, 653333), dl_arfcn: (620000, 653333), ssb_scs_khz: &[30] },
    BandInfo { band: 79, duplex: DuplexMode::Tdd, ul_arfcn: (693334, 733333), dl_arfcn: (693334, 733333), ssb_scs_khz: &[30] },
];

impl BandInfo {
    pub fn lookup(band: u16) -> Option<&'static BandInfo> {
        BANDS.iter().find(|b| b.band == band)
    }

    /// The uplink ARFCN paired with a downlink ARFCN in this band (TDD: the same;
    /// FDD: the same offset into the UL range).
    pub fn ul_arfcn_for_dl(&self, dl_arfcn: u32) -> u32 {
        match self.duplex {
            DuplexMode::Tdd => dl_arfcn,
            DuplexMode::Fdd => self.ul_arfcn.0 + (dl_arfcn - self.dl_arfcn.0),
        }
    }
}

/// NR-ARFCN → frequency in Hz (TS 38.104 Table 5.4.2.1-1).
pub fn arfcn_to_hz(arfcn: u32) -> f64 {
    let (f_ref_off, delta_f, n_ref_off) = if arfcn < 600_000 {
        (0.0, 5e3, 0)
    } else if arfcn < 2_016_667 {
        (3e9, 15e3, 600_000)
    } else {
        (24_250.08e6, 60e3, 2_016_667)
    };
    f_ref_off + delta_f * (arfcn - n_ref_off) as f64
}

/// Frequency in Hz → nearest NR-ARFCN.
pub fn hz_to_arfcn(hz: f64) -> u32 {
    if hz < 3e9 {
        (hz / 5e3).round() as u32
    } else if hz < 24_250.08e6 {
        600_000 + ((hz - 3e9) / 15e3).round() as u32
    } else {
        2_016_667 + ((hz - 24_250.08e6) / 60e3).round() as u32
    }
}

/// GSCN → SSB centre frequency in Hz (TS 38.104 Table 5.4.3.1-1).
/// 0–3 GHz: `N·1.2 MHz + M·50 kHz` with GSCN = 3N + (M−3)/2, M ∈ {1,3,5};
/// 3–24.25 GHz: `3 GHz + N·1.44 MHz`, GSCN = 7499 + N.
pub fn gscn_to_hz(gscn: u32) -> f64 {
    if gscn < 7499 {
        let n = (gscn + 1) / 3; // GSCN = 3N + (M-3)/2 → N = (GSCN+1)/3 for M∈{1,3,5}
        let m_idx = (gscn + 1) % 3; // 0,1,2 → M = 1,3,5
        let m = 1 + 2 * m_idx;
        n as f64 * 1.2e6 + m as f64 * 50e3
    } else if gscn <= 22255 {
        3e9 + (gscn - 7499) as f64 * 1.44e6
    } else {
        24_250.08e6 + (gscn - 22256) as f64 * 17.28e6
    }
}

/// All GSCN values whose SSB centre lies within `[lo_hz, hi_hz]`.
pub fn gscn_range(lo_hz: f64, hi_hz: f64) -> Vec<u32> {
    let mut out = Vec::new();
    // Coarse bounds then filter exactly.
    let (g_lo, g_hi) = (hz_to_gscn(lo_hz).saturating_sub(3), hz_to_gscn(hi_hz) + 3);
    for g in g_lo..=g_hi {
        let f = gscn_to_hz(g);
        if f >= lo_hz && f <= hi_hz {
            out.push(g);
        }
    }
    out
}

/// Frequency in Hz → nearest GSCN.
pub fn hz_to_gscn(hz: f64) -> u32 {
    if hz < 3e9 {
        // Find N, M minimising |N·1.2e6 + M·50e3 − hz|.
        let n = (hz / 1.2e6).floor() as i64;
        let mut best = (0u32, f64::MAX);
        for nn in (n - 1).max(0)..=n + 1 {
            for (mi, m) in [1u32, 3, 5].iter().enumerate() {
                let f = nn as f64 * 1.2e6 + *m as f64 * 50e3;
                let err = (f - hz).abs();
                if err < best.1 {
                    best = ((3 * nn as u32 + mi as u32).saturating_sub(1), err);
                }
            }
        }
        best.0
    } else if hz < 24_250.08e6 {
        7499 + ((hz - 3e9) / 1.44e6).round() as u32
    } else {
        22256 + ((hz - 24_250.08e6) / 17.28e6).round() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arfcn_roundtrip() {
        assert_eq!(arfcn_to_hz(626000), 3_390_000_000.0);
        assert_eq!(hz_to_arfcn(3.39e9), 626000);
        assert_eq!(arfcn_to_hz(368500), 1_842_500_000.0);
        assert_eq!(hz_to_arfcn(1.8425e9), 368500);
    }

    #[test]
    fn gscn_both_ranges() {
        // Above 3 GHz: GSCN 7499 = 3 GHz; +1 = +1.44 MHz.
        assert_eq!(gscn_to_hz(7499), 3e9);
        assert_eq!(gscn_to_hz(7500), 3e9 + 1.44e6);
        assert_eq!(hz_to_gscn(3e9 + 1.44e6 * 270.0), 7499 + 270);
        // Below 3 GHz: GSCN 4517 → N=1506, M=1 → 1807.25 MHz (a band n3 SSB).
        let f = gscn_to_hz(4517);
        assert!((f - 1_807.25e6).abs() < 1.0, "{f}");
        assert_eq!(hz_to_gscn(f), 4517);
        let r = gscn_range(1.80e9, 1.81e9);
        assert!(r.contains(&4517));
        assert!(r.iter().all(|&g| gscn_to_hz(g) >= 1.80e9 && gscn_to_hz(g) <= 1.81e9));
    }

    #[test]
    fn band_lookup() {
        let n3 = BandInfo::lookup(3).unwrap();
        assert_eq!(n3.duplex, DuplexMode::Fdd);
        assert_eq!(n3.ul_arfcn_for_dl(368500), 349500);
        assert_eq!(BandInfo::lookup(78).unwrap().duplex, DuplexMode::Tdd);
    }
}
