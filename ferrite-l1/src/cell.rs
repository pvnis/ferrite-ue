//! Cell geometry: the mapping between common resource blocks (TS 38.211
//! §4.4.4) and FFT bins of the sampled downlink / uplink streams.
//!
//! The DL stream is centred on the DL carrier (its DC is the centre of the
//! `carrierBandwidth` RBs starting at `offsetToCarrier` from point A); the UL
//! stream on the UL carrier. Point A itself never has to be expressed in Hz:
//! every channel is placed by CRB. Before SIB1 is known the CRB numbering is
//! relative to CORESET#0's lowest RB (`from_coreset0`), as TS 38.211 §7.4.1.1.2
//! allows for the SIB1 PDSCH.

use crate::config::{Carrier, PhyConfig};
use ferrite_common::Numerology;

#[derive(Clone, Debug)]
pub struct CellGeometry {
    pub fs: f64,
    pub numerology: Numerology,
    pub fft: usize,
    pub ul: Carrier,
    /// Subcarrier index of DL CRB 0 / subcarrier 0 relative to the DL stream DC.
    pub dl_base_sc: i64,
    /// SSB centre (subcarrier 120) offset from the DL carrier centre in Hz, for
    /// the sync mixer.
    pub ssb_df_hz: f64,
    /// DL carrier centre frequency in Hz (the receive-side TS 38.211 §5.4
    /// phase compensation needs it).
    pub dl_center_hz: f64,
}

impl CellGeometry {
    /// Full geometry from a SIB1-derived configuration.
    pub fn new(fs: f64, dl_center_hz: f64, cfg: &PhyConfig) -> Self {
        let numerology = cfg.numerology;
        let fft = (fs / numerology.scs_hz() as f64).round() as usize;
        let dl_base_sc = -(12 * cfg.dl_carrier.offset_crb as i64 + 6 * cfg.dl_carrier.n_rb as i64);
        let scs = numerology.scs_hz() as f64;
        // SSB subcarrier 0 = CRB `ssb_crb` subcarrier 0 + k_SSB (15 kHz units).
        let ssb_sc0_hz =
            (dl_base_sc + 12 * cfg.ssb_crb as i64) as f64 * scs + cfg.ssb.k_ssb as f64 * 15e3;
        let ssb_df_hz = ssb_sc0_hz + 120.0 * cfg.ssb.scs.scs_hz() as f64;
        Self {
            fs,
            numerology,
            fft,
            ul: cfg.ul_carrier,
            dl_base_sc,
            ssb_df_hz,
            dl_center_hz,
        }
    }

    /// Pre-SIB1 geometry: CRB 0 := CORESET#0's lowest RB, whose first subcarrier
    /// sits `coreset0_sc_from_dc` data-SCS subcarriers from the DL stream DC.
    pub fn from_coreset0(
        fs: f64,
        dl_center_hz: f64,
        numerology: Numerology,
        coreset0_sc_from_dc: i64,
        ssb_df_hz: f64,
    ) -> Self {
        let fft = (fs / numerology.scs_hz() as f64).round() as usize;
        Self {
            fs,
            numerology,
            fft,
            ul: Carrier {
                offset_crb: 0,
                n_rb: 0,
            },
            dl_base_sc: coreset0_sc_from_dc,
            ssb_df_hz,
            dl_center_hz,
        }
    }

    /// FFT bin (natural order) of DL CRB-domain subcarrier `12·crb + k`, as a
    /// closure for the PHY extractors.
    pub fn dl_sc_to_bin(&self) -> impl Fn(usize) -> usize + Copy + Send + Sync {
        let (base, fft) = (self.dl_base_sc, self.fft as i64);
        move |sc: usize| (sc as i64 + base).rem_euclid(fft) as usize
    }
}
