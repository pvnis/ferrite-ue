//! Other system information (TS 38.331 §6.2.2 `SystemInformation`, §6.3.1
//! SIB2 / SIB3): the `BCCH-DL-SCH-Message` alternative that is not SIB1.
//!
//! SIB2 (cell reselection parameters) and SIB3 (intra-frequency neighbour
//! lists) are decoded structurally. SIBs defined as extension alternatives
//! of `sib-TypeAndInfo` (SIB10 and up, e.g. SIB19 for NTN) are kept as raw
//! octets with their type number. SIB4–SIB9 are root alternatives without
//! a length prefix, so a message carrying one of them decodes as
//! [`crate::DecodeErrorKind::Unsupported`] until a decoder exists.

use crate::meas::{q_offset, ss_rssi_measurement, ssb_mtc, ssb_to_measure, threshold_nr, SsRssiMeasurement, SsbMtc, SsbToMeasure, ThresholdNr};
use crate::sib1::{decode_multi_band_list, NrMultiBandInfo};
use crate::uper::{BitReader, Ctx, DecodeResult};

/// `MobilityStateParameters`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MobilityStateParameters {
    /// `t-Evaluation` in seconds (30, 60, 120, 180, 240).
    pub t_evaluation_s: u16,
    pub t_hyst_normal_s: u16,
    pub n_cell_change_medium: u8,
    pub n_cell_change_high: u8,
}

/// `speedStateReselectionPars`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpeedStateReselectionPars {
    pub mobility_state_parameters: MobilityStateParameters,
    /// `q-HystSF` medium / high in dB (−6, −4, −2, 0).
    pub q_hyst_sf_medium_db: i8,
    pub q_hyst_sf_high_db: i8,
}

/// `SIB2.cellReselectionInfoCommon`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CellReselectionInfoCommon {
    pub nrof_ss_blocks_to_average: Option<u8>,
    pub abs_thresh_ss_blocks_consolidation: Option<ThresholdNr>,
    pub range_to_best_cell_db: Option<i8>,
    /// `q-Hyst` in dB.
    pub q_hyst_db: u8,
    pub speed_state_reselection_pars: Option<SpeedStateReselectionPars>,
}

/// `SIB2.cellReselectionServingFreqInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CellReselectionServingFreqInfo {
    pub s_non_intra_search_p: Option<u8>,
    pub s_non_intra_search_q: Option<u8>,
    pub thresh_serving_low_p: u8,
    pub thresh_serving_low_q: Option<u8>,
    pub cell_reselection_priority: u8,
    /// `cellReselectionSubPriority` in tenths (2, 4, 6, 8).
    pub cell_reselection_sub_priority: Option<u8>,
}

/// `SIB2.intraFreqCellReselectionInfo`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IntraFreqCellReselectionInfo {
    pub q_rx_lev_min: i8,
    pub q_rx_lev_min_sul: Option<i8>,
    pub q_qual_min: Option<i8>,
    pub s_intra_search_p: u8,
    pub s_intra_search_q: Option<u8>,
    pub t_reselection_nr_s: u8,
    pub frequency_band_list: Vec<NrMultiBandInfo>,
    pub frequency_band_list_sul: Vec<NrMultiBandInfo>,
    pub p_max: Option<i8>,
    pub smtc: Option<SsbMtc>,
    pub ss_rssi_measurement: Option<SsRssiMeasurement>,
    pub ssb_to_measure: Option<SsbToMeasure>,
    pub derive_ssb_index_from_cell: bool,
}

/// `SIB2`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Sib2 {
    pub cell_reselection_info_common: CellReselectionInfoCommon,
    pub cell_reselection_serving_freq_info: CellReselectionServingFreqInfo,
    pub intra_freq_cell_reselection_info: IntraFreqCellReselectionInfo,
}

/// `SIB3.intraFreqNeighCellList` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntraFreqNeighCellInfo {
    pub pci: u16,
    pub q_offset_cell_db: i8,
    pub q_rx_lev_min_offset_cell: Option<u8>,
    pub q_rx_lev_min_offset_cell_sul: Option<u8>,
    pub q_qual_min_offset_cell: Option<u8>,
}

/// `SIB3`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Sib3 {
    pub intra_freq_neigh_cell_list: Vec<IntraFreqNeighCellInfo>,
    /// `intraFreqExcludedCellList` as `(start PCI, range size)` pairs.
    pub intra_freq_excluded_cell_list: Vec<(u16, u16)>,
}

/// One `sib-TypeAndInfo` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sib {
    Sib2(Sib2),
    Sib3(Sib3),
    /// A SIB carried as an extension alternative: the SIB number (10..) and
    /// its UPER octets.
    Raw { sib_type: u8, octets: Vec<u8> },
}

impl Sib {
    /// The SIB number.
    pub fn sib_type(&self) -> u8 {
        match self {
            Sib::Sib2(_) => 2,
            Sib::Sib3(_) => 3,
            Sib::Raw { sib_type, .. } => *sib_type,
        }
    }
}

/// `SystemInformation` (the `BCCH-DL-SCH-Message` carrying other SI).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SystemInformation {
    pub sibs: Vec<Sib>,
}

/// SIB numbers of the `sib-TypeAndInfo` extension alternatives, in order.
const EXT_SIB_TYPES: [u8; 12] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

impl SystemInformation {
    /// Decode a `BCCH-DL-SCH-Message` transport block holding a
    /// `systemInformation` (padding included). A SIB1 block decodes as
    /// `Unsupported("systemInformationBlockType1")`.
    pub fn decode(tb: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(tb)).ctx("SystemInformation")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        if r.bit()? {
            return r.unsupported("systemInformationBlockType1");
        }
        // criticalExtensions CHOICE { systemInformation, criticalExtensionsFuture-r16 }
        if r.bit()? {
            return r.unsupported("criticalExtensionsFuture-r16");
        }
        let [_late, _non_crit] = r.opt_bits::<2>()?;
        let sibs = r.seq_of(1, 32, |r| {
            let ext = r.bit()?;
            if ext {
                // Extension alternative: open type (length-prefixed octets).
                let idx = r.normally_small()? as usize;
                let octets = r.octet_string()?;
                let sib_type = EXT_SIB_TYPES.get(idx).copied().unwrap_or(0);
                return Ok(Sib::Raw { sib_type, octets });
            }
            match r.enu(8)? {
                0 => Ok(Sib::Sib2(Sib2::decode(r).ctx("sib2")?)),
                1 => Ok(Sib::Sib3(Sib3::decode(r).ctx("sib3")?)),
                n => r.unsupported(["sib4", "sib5", "sib6", "sib7", "sib8", "sib9"][n as usize - 2]),
            }
        })?;
        Ok(Self { sibs })
    }
}

impl Sib2 {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        // cellReselectionInfoCommon
        let cext = r.bit()?;
        let o = r.opt_bits::<4>()?;
        let nrof_ss_blocks_to_average = r.opt(o[0], |r| r.u8(2, 16))?;
        let abs_thresh_ss_blocks_consolidation = r.opt(o[1], threshold_nr)?;
        let range_to_best_cell_db = r.opt(o[2], q_offset)?;
        const Q_HYST: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24];
        let q_hyst_db = Q_HYST[r.enu(16)? as usize];
        let speed_state_reselection_pars = r.opt(o[3], |r| {
            const T: [u16; 5] = [30, 60, 120, 180, 240];
            let t_evaluation_s = T.get(r.enu(8)? as usize).copied().unwrap_or(30);
            let t_hyst_normal_s = T.get(r.enu(8)? as usize).copied().unwrap_or(30);
            let n_cell_change_medium = r.u8(1, 16)?;
            let n_cell_change_high = r.u8(1, 16)?;
            const SF: [i8; 4] = [-6, -4, -2, 0];
            let q_hyst_sf_medium_db = SF[r.enu(4)? as usize];
            let q_hyst_sf_high_db = SF[r.enu(4)? as usize];
            Ok(SpeedStateReselectionPars { mobility_state_parameters: MobilityStateParameters { t_evaluation_s, t_hyst_normal_s, n_cell_change_medium, n_cell_change_high }, q_hyst_sf_medium_db, q_hyst_sf_high_db })
        })?;
        if cext {
            r.skip_ext_additions()?;
        }
        let cell_reselection_info_common = CellReselectionInfoCommon { nrof_ss_blocks_to_average, abs_thresh_ss_blocks_consolidation, range_to_best_cell_db, q_hyst_db, speed_state_reselection_pars };
        // cellReselectionServingFreqInfo
        let sext = r.bit()?;
        let o = r.opt_bits::<4>()?;
        let s_non_intra_search_p = r.opt(o[0], |r| r.u8(0, 31))?;
        let s_non_intra_search_q = r.opt(o[1], |r| r.u8(0, 31))?;
        let thresh_serving_low_p = r.u8(0, 31)?;
        let thresh_serving_low_q = r.opt(o[2], |r| r.u8(0, 31))?;
        let cell_reselection_priority = r.u8(0, 7)?;
        let cell_reselection_sub_priority = r.opt(o[3], |r| Ok(2 * (r.enu(4)? as u8 + 1)))?;
        if sext {
            r.skip_ext_additions()?;
        }
        let cell_reselection_serving_freq_info = CellReselectionServingFreqInfo { s_non_intra_search_p, s_non_intra_search_q, thresh_serving_low_p, thresh_serving_low_q, cell_reselection_priority, cell_reselection_sub_priority };
        // intraFreqCellReselectionInfo
        let iext = r.bit()?;
        let o = r.opt_bits::<9>()?;
        let q_rx_lev_min = r.int(-70, -22)? as i8;
        let q_rx_lev_min_sul = r.opt(o[0], |r| Ok(r.int(-70, -22)? as i8))?;
        let q_qual_min = r.opt(o[1], |r| Ok(r.int(-43, -12)? as i8))?;
        let s_intra_search_p = r.u8(0, 31)?;
        let s_intra_search_q = r.opt(o[2], |r| r.u8(0, 31))?;
        let t_reselection_nr_s = r.u8(0, 7)?;
        let frequency_band_list = if o[3] { decode_multi_band_list(r).ctx("frequencyBandList")? } else { Vec::new() };
        let frequency_band_list_sul = if o[4] { decode_multi_band_list(r).ctx("frequencyBandListSUL")? } else { Vec::new() };
        let p_max = r.opt(o[5], |r| Ok(r.int(-30, 33)? as i8))?;
        let smtc = r.opt(o[6], ssb_mtc)?;
        let ss_rssi_measurement = r.opt(o[7], ss_rssi_measurement)?;
        let ssb_to_measure = r.opt(o[8], ssb_to_measure)?;
        let derive_ssb_index_from_cell = r.boolean()?;
        if iext {
            r.skip_ext_additions()?;
        }
        let intra_freq_cell_reselection_info = IntraFreqCellReselectionInfo {
            q_rx_lev_min,
            q_rx_lev_min_sul,
            q_qual_min,
            s_intra_search_p,
            s_intra_search_q,
            t_reselection_nr_s,
            frequency_band_list,
            frequency_band_list_sul,
            p_max,
            smtc,
            ss_rssi_measurement,
            ssb_to_measure,
            derive_ssb_index_from_cell,
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self { cell_reselection_info_common, cell_reselection_serving_freq_info, intra_freq_cell_reselection_info })
    }
}

impl Sib3 {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_neigh, has_excluded, _late] = r.opt_bits::<3>()?;
        let intra_freq_neigh_cell_list = if has_neigh {
            r.seq_of(1, 16, |r| {
                let cext = r.bit()?;
                let [o1, o2, o3] = r.opt_bits::<3>()?;
                let pci = r.u16(0, 1007)?;
                let q_offset_cell_db = q_offset(r)?;
                let q_rx_lev_min_offset_cell = r.opt(o1, |r| r.u8(1, 8))?;
                let q_rx_lev_min_offset_cell_sul = r.opt(o2, |r| r.u8(1, 8))?;
                let q_qual_min_offset_cell = r.opt(o3, |r| r.u8(1, 8))?;
                if cext {
                    r.skip_ext_additions()?;
                }
                Ok(IntraFreqNeighCellInfo { pci, q_offset_cell_db, q_rx_lev_min_offset_cell, q_rx_lev_min_offset_cell_sul, q_qual_min_offset_cell })
            })?
        } else {
            Vec::new()
        };
        let intra_freq_excluded_cell_list = if has_excluded {
            const RANGE: [u16; 15] = [4, 8, 12, 16, 24, 32, 48, 64, 84, 96, 128, 168, 252, 504, 1008];
            r.seq_of(1, 16, |r| {
                let [has_range] = r.opt_bits::<1>()?;
                let start = r.u16(0, 1007)?;
                let range = r.opt(has_range, |r| Ok(RANGE.get(r.enu(16)? as usize).copied().unwrap_or(1)))?;
                Ok((start, range.unwrap_or(1)))
            })?
        } else {
            Vec::new()
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self { intra_freq_neigh_cell_list, intra_freq_excluded_cell_list })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uper::BitWriter;

    /// A hand-built SystemInformation with a SIB2 (OCUDU-like defaults) and a
    /// raw SIB19, decoded end to end.
    #[test]
    fn system_information_with_sib2_and_raw_sib19() {
        let mut w = BitWriter::new();
        w.bit(false); // c1
        w.bit(false); // systemInformation
        w.bit(false); // criticalExtensions: systemInformation
        w.opt_bits(&[false, false]);
        w.len_constrained(2, 1, 32);
        // --- sib2
        w.bit(false); // not extended
        w.enu(0, 8);
        w.bit(false); // SIB2 ext
        // cellReselectionInfoCommon: no optionals, q-Hyst dB3
        w.bit(false);
        w.opt_bits(&[false, false, false, false]);
        w.enu(3, 16);
        // cellReselectionServingFreqInfo: threshServingLowP 0, priority 6
        w.bit(false);
        w.opt_bits(&[false, false, false, false]);
        w.uint(0, 0, 31);
        w.uint(6, 0, 7);
        // intraFreqCellReselectionInfo: qRxLevMin -70 (= -140 dBm), sIntraSearchP 31, tReselection 1, smtc sf20/0/sf5, deriveSSB true
        w.bit(false);
        w.opt_bits(&[false, false, false, false, false, false, true, false, false]);
        w.int(-70, -70, -22);
        w.uint(31, 0, 31);
        w.uint(1, 0, 7);
        w.enu(2, 6);
        w.uint(0, 0, 19);
        w.enu(4, 5);
        w.boolean(true);
        // --- sib19 as extension alternative index 9, 3 octets
        w.bit(true);
        w.normally_small(9);
        w.octet_string(&[0x01, 0x02, 0x03]);
        let bytes = w.finish();
        let si = SystemInformation::decode(&bytes).expect("decode");
        assert_eq!(si.sibs.len(), 2);
        let Sib::Sib2(s2) = &si.sibs[0] else { panic!("sib2") };
        assert_eq!(s2.cell_reselection_info_common.q_hyst_db, 3);
        assert_eq!(s2.cell_reselection_serving_freq_info.cell_reselection_priority, 6);
        assert_eq!(s2.intra_freq_cell_reselection_info.q_rx_lev_min, -70);
        assert_eq!(s2.intra_freq_cell_reselection_info.s_intra_search_p, 31);
        assert_eq!(s2.intra_freq_cell_reselection_info.smtc, Some(SsbMtc { periodicity_sf: 20, offset_sf: 0, duration_sf: 5 }));
        assert!(s2.intra_freq_cell_reselection_info.derive_ssb_index_from_cell);
        assert_eq!(si.sibs[1], Sib::Raw { sib_type: 19, octets: vec![1, 2, 3] });
    }

    #[test]
    fn sib1_block_is_not_system_information() {
        // c1 = systemInformationBlockType1 (bit 1 after the class bit).
        let e = SystemInformation::decode(&[0x40]).unwrap_err();
        assert!(format!("{e}").contains("systemInformationBlockType1"), "{e}");
    }
}
