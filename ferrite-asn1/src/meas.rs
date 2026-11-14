//! Measurement configuration and reporting IEs (TS 38.331 §6.3.5):
//! `MeasConfig` (decoded from `RRCReconfiguration`) and `MeasResults`
//! (encoded into `MeasurementReport`).
//!
//! Scope: NR measurement objects (SSB and CSI-RS carrier parameters, cell
//! lists, offsets), NR report configurations (periodical and the A1–A6
//! events), measurement identities, quantity (L3 filter) configuration,
//! s-Measure and measurement gaps. Inter-RAT objects, sidelink, CLI, CGI/SFTD
//! and conditional-trigger report types decode as
//! [`crate::DecodeErrorKind::Unsupported`]. Release-16+ extension additions
//! are skipped.

use crate::uper::{BitReader, BitWriter, Ctx, DecodeResult, SetupRelease};

// ---------------------------------------------------------------------------
// Measurement objects
// ---------------------------------------------------------------------------

/// `SSB-MTC`: the SSB measurement timing configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsbMtc {
    /// Periodicity in subframes (5, 10, 20, 40, 80, 160).
    pub periodicity_sf: u16,
    pub offset_sf: u16,
    /// Duration in subframes (1..5).
    pub duration_sf: u8,
}

/// `SSB-MTC2`: a shorter periodicity for the listed cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsbMtc2 {
    pub pci_list: Vec<u16>,
    /// Periodicity in subframes (5, 10, 20, 40, 80); `None` for spare values.
    pub periodicity_sf: Option<u16>,
}

/// `SSB-ToMeasure`: which SSB indexes to measure (bit `i` = SSB index `i`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsbToMeasure {
    Short(u8),
    Medium(u8),
    Long(u64),
}

/// `SS-RSSI-Measurement`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsRssiMeasurement {
    /// `measurementSlots` bits, MSB first (1..80 bits).
    pub measurement_slots: Vec<bool>,
    pub end_symbol: u8,
}

/// `SSB-ConfigMobility`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SsbConfigMobility {
    pub ssb_to_measure: Option<SetupRelease<SsbToMeasure>>,
    pub derive_ssb_index_from_cell: bool,
    pub ss_rssi_measurement: Option<SsRssiMeasurement>,
}

/// `ThresholdNR` (ranges as the RSRP/RSRQ/SINR-Range indexes, 0..127).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ThresholdNr {
    pub rsrp: Option<u8>,
    pub rsrq: Option<u8>,
    pub sinr: Option<u8>,
}

/// `Q-OffsetRangeList` in dB (every entry defaults to 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct QOffsetRangeList {
    pub rsrp_offset_ssb_db: i8,
    pub rsrq_offset_ssb_db: i8,
    pub sinr_offset_ssb_db: i8,
    pub rsrp_offset_csi_rs_db: i8,
    pub rsrq_offset_csi_rs_db: i8,
    pub sinr_offset_csi_rs_db: i8,
}

/// `Q-OffsetRange` values in dB, by enumeration index.
const Q_OFFSET_DB: [i8; 31] = [
    -24, -22, -20, -18, -16, -14, -12, -10, -8, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 8, 10,
    12, 14, 16, 18, 20, 22, 24,
];

/// `CellsToAddMod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellsToAddMod {
    pub pci: u16,
    pub cell_individual_offset: QOffsetRangeList,
}

/// `PCI-RangeElement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciRangeElement {
    pub index: u8,
    pub start: u16,
    /// `range` as the number of PCIs (`None` = the single PCI `start`).
    pub range: Option<u16>,
}

/// `MeasObjectNR`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MeasObjectNr {
    pub ssb_frequency: Option<u32>,
    /// SSB subcarrier spacing in kHz.
    pub ssb_scs_khz: Option<u16>,
    pub smtc1: Option<SsbMtc>,
    pub smtc2: Option<SsbMtc2>,
    pub ref_freq_csi_rs: Option<u32>,
    pub ssb_config_mobility: Option<SsbConfigMobility>,
    pub abs_thresh_ss_blocks_consolidation: Option<ThresholdNr>,
    pub abs_thresh_csi_rs_consolidation: Option<ThresholdNr>,
    pub nrof_ss_blocks_to_average: Option<u8>,
    pub nrof_csi_rs_resources_to_average: Option<u8>,
    pub quantity_config_index: u8,
    pub offset_mo: QOffsetRangeList,
    pub cells_to_remove_list: Vec<u16>,
    pub cells_to_add_mod_list: Vec<CellsToAddMod>,
    pub excluded_cells_to_remove_list: Vec<u8>,
    pub excluded_cells_to_add_mod_list: Vec<PciRangeElement>,
    pub allowed_cells_to_remove_list: Vec<u8>,
    pub allowed_cells_to_add_mod_list: Vec<PciRangeElement>,
}

/// `MeasObjectToAddMod` (NR objects only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasObjectToAddMod {
    pub meas_object_id: u8,
    pub meas_object: MeasObjectNr,
}

// ---------------------------------------------------------------------------
// Report configurations
// ---------------------------------------------------------------------------

/// `NR-RS-Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsType {
    Ssb,
    CsiRs,
}

/// `MeasReportQuantity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MeasReportQuantity {
    pub rsrp: bool,
    pub rsrq: bool,
    pub sinr: bool,
}

/// `MeasTriggerQuantity`: a threshold as a range index (0..127).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasTriggerQuantity {
    Rsrp(u8),
    Rsrq(u8),
    Sinr(u8),
}

/// `MeasTriggerQuantityOffset`: an offset in 0.5 dB steps (−30..30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasTriggerQuantityOffset {
    Rsrp(i8),
    Rsrq(i8),
    Sinr(i8),
}

/// `EventTriggerConfig.eventId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventId {
    A1 {
        threshold: MeasTriggerQuantity,
    },
    A2 {
        threshold: MeasTriggerQuantity,
    },
    A3 {
        offset: MeasTriggerQuantityOffset,
        use_allowed_cell_list: bool,
    },
    A4 {
        threshold: MeasTriggerQuantity,
        use_allowed_cell_list: bool,
    },
    A5 {
        threshold1: MeasTriggerQuantity,
        threshold2: MeasTriggerQuantity,
        use_allowed_cell_list: bool,
    },
    A6 {
        offset: MeasTriggerQuantityOffset,
        use_allowed_cell_list: bool,
    },
}

/// The event part of an `EventTriggerConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventTrigger {
    pub event: EventId,
    pub report_on_leave: bool,
    /// Hysteresis in 0.5 dB steps (0..30).
    pub hysteresis: u8,
    pub time_to_trigger_ms: u16,
}

/// `TimeToTrigger` values (ms) by enumeration index.
const TIME_TO_TRIGGER_MS: [u16; 16] = [
    0, 40, 64, 80, 100, 128, 160, 256, 320, 480, 512, 640, 1024, 1280, 2560, 5120,
];
/// `ReportInterval` values (ms) by enumeration index.
const REPORT_INTERVAL_MS: [u32; 14] = [
    120, 240, 480, 640, 1024, 2048, 5120, 10240, 20480, 40960, 60_000, 360_000, 720_000, 1_800_000,
];

/// `ReportConfigNR` (periodical or event-triggered).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportConfigNr {
    /// `None` = periodical.
    pub event: Option<EventTrigger>,
    pub rs_type: RsType,
    pub report_interval_ms: u32,
    /// `None` = infinity.
    pub report_amount: Option<u8>,
    pub report_quantity_cell: MeasReportQuantity,
    pub max_report_cells: u8,
    pub report_quantity_rs_indexes: Option<MeasReportQuantity>,
    pub max_nrof_rs_indexes_to_report: Option<u8>,
    pub include_beam_measurements: bool,
    /// Periodical: `useWhiteCellList`; event-triggered: `reportAddNeighMeas`.
    pub use_allowed_cell_list: bool,
}

/// `ReportConfigToAddMod` (NR configurations only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportConfigToAddMod {
    pub report_config_id: u8,
    pub report_config: ReportConfigNr,
}

// ---------------------------------------------------------------------------
// Identities, quantities, gaps
// ---------------------------------------------------------------------------

/// `MeasIdToAddMod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasIdToAddMod {
    pub meas_id: u8,
    pub meas_object_id: u8,
    pub report_config_id: u8,
}

/// `FilterConfig`: L3 filter coefficients `k` (fc0..fc19), default 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    pub rsrp: u8,
    pub rsrq: u8,
    pub rs_sinr: u8,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            rsrp: 4,
            rsrq: 4,
            rs_sinr: 4,
        }
    }
}

/// `FilterCoefficient` values by enumeration index.
const FILTER_COEF: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 15, 17, 19];

/// `QuantityConfigRS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct QuantityConfigRs {
    pub ssb: FilterConfig,
    pub csi_rs: FilterConfig,
}

/// `QuantityConfigNR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct QuantityConfigNr {
    pub cell: QuantityConfigRs,
    pub rs_index: Option<QuantityConfigRs>,
}

/// `GapConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapConfig {
    pub gap_offset: u8,
    /// Gap length in units of 0.5 ms (3, 6, 7, 8, 11, 12).
    pub mgl_half_ms: u8,
    /// Gap repetition period in ms (20, 40, 80, 160).
    pub mgrp_ms: u8,
    /// Timing advance in units of 0.25 ms (0, 1, 2).
    pub mgta_quarter_ms: u8,
}

/// `s-MeasureConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SMeasureConfig {
    SsbRsrp(u8),
    CsiRsrp(u8),
}

/// `MeasConfig`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MeasConfig {
    pub meas_object_to_remove_list: Vec<u8>,
    pub meas_object_to_add_mod_list: Vec<MeasObjectToAddMod>,
    pub report_config_to_remove_list: Vec<u8>,
    pub report_config_to_add_mod_list: Vec<ReportConfigToAddMod>,
    pub meas_id_to_remove_list: Vec<u8>,
    pub meas_id_to_add_mod_list: Vec<MeasIdToAddMod>,
    pub s_measure_config: Option<SMeasureConfig>,
    pub quantity_config: Option<Vec<QuantityConfigNr>>,
    pub meas_gap_fr2: Option<SetupRelease<GapConfig>>,
    /// `gapSharingFR2` scheme (0..3).
    pub meas_gap_sharing_fr2: Option<SetupRelease<u8>>,
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

pub(crate) fn q_offset(r: &mut BitReader) -> DecodeResult<i8> {
    Ok(Q_OFFSET_DB[r.enu(31)? as usize])
}

fn q_offset_range_list(r: &mut BitReader) -> DecodeResult<QOffsetRangeList> {
    let p = r.opt_bits::<6>()?;
    let mut v = [0i8; 6];
    for (i, present) in p.iter().enumerate() {
        if *present {
            v[i] = q_offset(r)?;
        }
    }
    Ok(QOffsetRangeList {
        rsrp_offset_ssb_db: v[0],
        rsrq_offset_ssb_db: v[1],
        sinr_offset_ssb_db: v[2],
        rsrp_offset_csi_rs_db: v[3],
        rsrq_offset_csi_rs_db: v[4],
        sinr_offset_csi_rs_db: v[5],
    })
}

pub(crate) fn threshold_nr(r: &mut BitReader) -> DecodeResult<ThresholdNr> {
    let [p, q, s] = r.opt_bits::<3>()?;
    Ok(ThresholdNr {
        rsrp: r.opt(p, |r| r.u8(0, 127))?,
        rsrq: r.opt(q, |r| r.u8(0, 127))?,
        sinr: r.opt(s, |r| r.u8(0, 127))?,
    })
}

pub(crate) fn ssb_mtc(r: &mut BitReader) -> DecodeResult<SsbMtc> {
    const PERIOD: [u16; 6] = [5, 10, 20, 40, 80, 160];
    let idx = r.enu(6)? as usize;
    let periodicity_sf = PERIOD[idx];
    let offset_sf = r.u16(0, periodicity_sf - 1)?;
    let duration_sf = r.enu(5)? as u8 + 1;
    Ok(SsbMtc {
        periodicity_sf,
        offset_sf,
        duration_sf,
    })
}

fn ssb_mtc2(r: &mut BitReader) -> DecodeResult<SsbMtc2> {
    let [has_pci] = r.opt_bits::<1>()?;
    let pci_list = if has_pci {
        r.seq_of(1, 64, |r| r.u16(0, 1007))?
    } else {
        Vec::new()
    };
    let p = r.enu(8)?;
    let periodicity_sf = [5u16, 10, 20, 40, 80].get(p as usize).copied();
    Ok(SsbMtc2 {
        pci_list,
        periodicity_sf,
    })
}

pub(crate) fn ssb_to_measure(r: &mut BitReader) -> DecodeResult<SsbToMeasure> {
    Ok(match r.enu(3)? {
        0 => SsbToMeasure::Short(r.bitstring(4)? as u8),
        1 => SsbToMeasure::Medium(r.bitstring(8)? as u8),
        _ => SsbToMeasure::Long(r.bitstring(64)?),
    })
}

pub(crate) fn ss_rssi_measurement(r: &mut BitReader) -> DecodeResult<SsRssiMeasurement> {
    let n = r.len_constrained(1, 80)?;
    let mut measurement_slots = Vec::with_capacity(n);
    for _ in 0..n {
        measurement_slots.push(r.bit()?);
    }
    Ok(SsRssiMeasurement {
        measurement_slots,
        end_symbol: r.u8(0, 3)?,
    })
}

fn ssb_config_mobility(r: &mut BitReader) -> DecodeResult<SsbConfigMobility> {
    let ext = r.bit()?;
    let [has_to_measure, has_rssi] = r.opt_bits::<2>()?;
    let ssb_to_measure = r.opt(has_to_measure, |r| r.setup_release(ssb_to_measure))?;
    let derive_ssb_index_from_cell = r.boolean()?;
    let ss_rssi_measurement = r.opt(has_rssi, ss_rssi_measurement)?;
    if ext {
        r.skip_ext_additions()?;
    }
    Ok(SsbConfigMobility {
        ssb_to_measure,
        derive_ssb_index_from_cell,
        ss_rssi_measurement,
    })
}

fn pci_range_elements(r: &mut BitReader) -> DecodeResult<Vec<PciRangeElement>> {
    const RANGE: [u16; 15] = [
        4, 8, 12, 16, 24, 32, 48, 64, 84, 96, 128, 168, 252, 504, 1008,
    ];
    r.seq_of(1, 8, |r| {
        let index = r.u8(1, 8)?;
        let [has_range] = r.opt_bits::<1>()?;
        let start = r.u16(0, 1007)?;
        let range = r.opt(has_range, |r| {
            Ok(RANGE.get(r.enu(16)? as usize).copied().unwrap_or(1))
        })?;
        Ok(PciRangeElement {
            index,
            start,
            range,
        })
    })
}

impl MeasObjectNr {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<15>()?;
        let ssb_frequency = r.opt(o[0], |r| r.uint(0, 3_279_165))?;
        let ssb_scs_khz = r.opt(o[1], |r| {
            Ok([15u16, 30, 60, 120, 240]
                .get(r.enu(8)? as usize)
                .copied()
                .unwrap_or(15))
        })?;
        let smtc1 = r.opt(o[2], ssb_mtc).ctx("smtc1")?;
        let smtc2 = r.opt(o[3], ssb_mtc2).ctx("smtc2")?;
        let ref_freq_csi_rs = r.opt(o[4], |r| r.uint(0, 3_279_165))?;
        // referenceSignalConfig (no extension marker).
        let [has_ssb_mob, has_csi_mob] = r.opt_bits::<2>()?;
        let ssb_config_mobility = r
            .opt(has_ssb_mob, ssb_config_mobility)
            .ctx("ssb-ConfigMobility")?;
        if has_csi_mob {
            return r.unsupported("csi-rs-ResourceConfigMobility");
        }
        let abs_thresh_ss_blocks_consolidation = r.opt(o[5], threshold_nr)?;
        let abs_thresh_csi_rs_consolidation = r.opt(o[6], threshold_nr)?;
        let nrof_ss_blocks_to_average = r.opt(o[7], |r| r.u8(2, 16))?;
        let nrof_csi_rs_resources_to_average = r.opt(o[8], |r| r.u8(2, 16))?;
        let quantity_config_index = r.u8(1, 2)?;
        let offset_mo = q_offset_range_list(r)?;
        let cells_to_remove_list = if o[9] {
            r.seq_of(1, 32, |r| r.u16(0, 1007))?
        } else {
            Vec::new()
        };
        let cells_to_add_mod_list = if o[10] {
            r.seq_of(1, 32, |r| {
                Ok(CellsToAddMod {
                    pci: r.u16(0, 1007)?,
                    cell_individual_offset: q_offset_range_list(r)?,
                })
            })?
        } else {
            Vec::new()
        };
        let excluded_cells_to_remove_list = if o[11] {
            r.seq_of(1, 8, |r| r.u8(1, 8))?
        } else {
            Vec::new()
        };
        let excluded_cells_to_add_mod_list = if o[12] {
            pci_range_elements(r)?
        } else {
            Vec::new()
        };
        let allowed_cells_to_remove_list = if o[13] {
            r.seq_of(1, 8, |r| r.u8(1, 8))?
        } else {
            Vec::new()
        };
        let allowed_cells_to_add_mod_list = if o[14] {
            pci_range_elements(r)?
        } else {
            Vec::new()
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            ssb_frequency,
            ssb_scs_khz,
            smtc1,
            smtc2,
            ref_freq_csi_rs,
            ssb_config_mobility,
            abs_thresh_ss_blocks_consolidation,
            abs_thresh_csi_rs_consolidation,
            nrof_ss_blocks_to_average,
            nrof_csi_rs_resources_to_average,
            quantity_config_index,
            offset_mo,
            cells_to_remove_list,
            cells_to_add_mod_list,
            excluded_cells_to_remove_list,
            excluded_cells_to_add_mod_list,
            allowed_cells_to_remove_list,
            allowed_cells_to_add_mod_list,
        })
    }
}

fn meas_report_quantity(r: &mut BitReader) -> DecodeResult<MeasReportQuantity> {
    Ok(MeasReportQuantity {
        rsrp: r.boolean()?,
        rsrq: r.boolean()?,
        sinr: r.boolean()?,
    })
}

fn trigger_quantity(r: &mut BitReader) -> DecodeResult<MeasTriggerQuantity> {
    Ok(match r.enu(3)? {
        0 => MeasTriggerQuantity::Rsrp(r.u8(0, 127)?),
        1 => MeasTriggerQuantity::Rsrq(r.u8(0, 127)?),
        _ => MeasTriggerQuantity::Sinr(r.u8(0, 127)?),
    })
}

fn trigger_quantity_offset(r: &mut BitReader) -> DecodeResult<MeasTriggerQuantityOffset> {
    Ok(match r.enu(3)? {
        0 => MeasTriggerQuantityOffset::Rsrp(r.int(-30, 30)? as i8),
        1 => MeasTriggerQuantityOffset::Rsrq(r.int(-30, 30)? as i8),
        _ => MeasTriggerQuantityOffset::Sinr(r.int(-30, 30)? as i8),
    })
}

fn event_tail(r: &mut BitReader) -> DecodeResult<(bool, u8, u16)> {
    let report_on_leave = r.boolean()?;
    let hysteresis = r.u8(0, 30)?;
    let ttt = TIME_TO_TRIGGER_MS[r.enu(16)? as usize];
    Ok((report_on_leave, hysteresis, ttt))
}

impl ReportConfigNr {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        // reportType CHOICE { periodical, eventTriggered, ... }
        if r.bit()? {
            return r.unsupported("reportType extension alternative");
        }
        let event_triggered = r.bit()?;
        let ext = r.bit()?;
        let event;
        let (has_rs_idx, has_max_idx, has_extra) = if event_triggered {
            let o = r.opt_bits::<3>()?;
            if r.bit()? {
                return r.unsupported("eventId extension alternative");
            }
            let which = r.enu(6)?;
            let (id, tail) = match which {
                0 => {
                    let threshold = trigger_quantity(r)?;
                    (EventId::A1 { threshold }, event_tail(r)?)
                }
                1 => {
                    let threshold = trigger_quantity(r)?;
                    (EventId::A2 { threshold }, event_tail(r)?)
                }
                2 => {
                    let offset = trigger_quantity_offset(r)?;
                    let tail = event_tail(r)?;
                    (
                        EventId::A3 {
                            offset,
                            use_allowed_cell_list: r.boolean()?,
                        },
                        tail,
                    )
                }
                3 => {
                    let threshold = trigger_quantity(r)?;
                    let tail = event_tail(r)?;
                    (
                        EventId::A4 {
                            threshold,
                            use_allowed_cell_list: r.boolean()?,
                        },
                        tail,
                    )
                }
                4 => {
                    let threshold1 = trigger_quantity(r)?;
                    let threshold2 = trigger_quantity(r)?;
                    let tail = event_tail(r)?;
                    (
                        EventId::A5 {
                            threshold1,
                            threshold2,
                            use_allowed_cell_list: r.boolean()?,
                        },
                        tail,
                    )
                }
                _ => {
                    let offset = trigger_quantity_offset(r)?;
                    let tail = event_tail(r)?;
                    (
                        EventId::A6 {
                            offset,
                            use_allowed_cell_list: r.boolean()?,
                        },
                        tail,
                    )
                }
            };
            event = Some(EventTrigger {
                event: id,
                report_on_leave: tail.0,
                hysteresis: tail.1,
                time_to_trigger_ms: tail.2,
            });
            (o[0], o[1], o[2])
        } else {
            let o = r.opt_bits::<2>()?;
            event = None;
            (o[0], o[1], false)
        };
        let rs_type = if r.bit()? { RsType::CsiRs } else { RsType::Ssb };
        let report_interval_ms = REPORT_INTERVAL_MS[r.enu(14)? as usize];
        let report_amount = match r.enu(8)? {
            7 => None,
            n => Some(1u8 << n),
        };
        let report_quantity_cell = meas_report_quantity(r)?;
        let max_report_cells = r.u8(1, 8)?;
        let report_quantity_rs_indexes = r.opt(has_rs_idx, meas_report_quantity)?;
        let max_nrof_rs_indexes_to_report = r.opt(has_max_idx, |r| r.u8(1, 32))?;
        let include_beam_measurements = r.boolean()?;
        // Periodical: useWhiteCellList BOOLEAN; event: reportAddNeighMeas ENUMERATED {setup} OPTIONAL (0 bits).
        let use_allowed_cell_list = if event_triggered {
            has_extra
        } else {
            r.boolean()?
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            event,
            rs_type,
            report_interval_ms,
            report_amount,
            report_quantity_cell,
            max_report_cells,
            report_quantity_rs_indexes,
            max_nrof_rs_indexes_to_report,
            include_beam_measurements,
            use_allowed_cell_list,
        })
    }
}

fn filter_config(r: &mut BitReader) -> DecodeResult<FilterConfig> {
    let p = r.opt_bits::<3>()?;
    let mut v = [4u8; 3];
    for (i, present) in p.iter().enumerate() {
        if *present {
            v[i] = match r.enu_ext(16)? {
                Some(idx) => FILTER_COEF.get(idx as usize).copied().unwrap_or(4),
                None => 4,
            };
        }
    }
    Ok(FilterConfig {
        rsrp: v[0],
        rsrq: v[1],
        rs_sinr: v[2],
    })
}

fn quantity_config_rs(r: &mut BitReader) -> DecodeResult<QuantityConfigRs> {
    Ok(QuantityConfigRs {
        ssb: filter_config(r)?,
        csi_rs: filter_config(r)?,
    })
}

fn gap_config(r: &mut BitReader) -> DecodeResult<GapConfig> {
    let ext = r.bit()?;
    let gap_offset = r.u8(0, 159)?;
    let mgl_half_ms = [3u8, 6, 7, 8, 11, 12][r.enu(6)? as usize];
    let mgrp_ms = [20u8, 40, 80, 160][r.enu(4)? as usize];
    let mgta_quarter_ms = r.enu(3)? as u8;
    if ext {
        r.skip_ext_additions()?;
    }
    Ok(GapConfig {
        gap_offset,
        mgl_half_ms,
        mgrp_ms,
        mgta_quarter_ms,
    })
}

impl MeasConfig {
    /// Decode a `MeasConfig` at the reader's position.
    pub fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<10>()?;
        let meas_object_to_remove_list = if o[0] {
            r.seq_of(1, 64, |r| r.u8(1, 64))?
        } else {
            Vec::new()
        };
        let meas_object_to_add_mod_list = if o[1] {
            r.seq_of(1, 64, |r| {
                let meas_object_id = r.u8(1, 64)?;
                if r.bit()? {
                    return r.unsupported("measObject extension alternative (non-NR)");
                }
                let meas_object = MeasObjectNr::decode(r).ctx("measObjectNR")?;
                Ok(MeasObjectToAddMod {
                    meas_object_id,
                    meas_object,
                })
            })?
        } else {
            Vec::new()
        };
        let report_config_to_remove_list = if o[2] {
            r.seq_of(1, 64, |r| r.u8(1, 64))?
        } else {
            Vec::new()
        };
        let report_config_to_add_mod_list = if o[3] {
            r.seq_of(1, 64, |r| {
                let report_config_id = r.u8(1, 64)?;
                if r.bit()? {
                    return r.unsupported("reportConfig extension alternative (non-NR)");
                }
                let report_config = ReportConfigNr::decode(r).ctx("reportConfigNR")?;
                Ok(ReportConfigToAddMod {
                    report_config_id,
                    report_config,
                })
            })?
        } else {
            Vec::new()
        };
        let meas_id_to_remove_list = if o[4] {
            r.seq_of(1, 64, |r| r.u8(1, 64))?
        } else {
            Vec::new()
        };
        let meas_id_to_add_mod_list = if o[5] {
            r.seq_of(1, 64, |r| {
                Ok(MeasIdToAddMod {
                    meas_id: r.u8(1, 64)?,
                    meas_object_id: r.u8(1, 64)?,
                    report_config_id: r.u8(1, 64)?,
                })
            })?
        } else {
            Vec::new()
        };
        let s_measure_config = r.opt(o[6], |r| {
            Ok(if r.bit()? {
                SMeasureConfig::CsiRsrp(r.u8(0, 127)?)
            } else {
                SMeasureConfig::SsbRsrp(r.u8(0, 127)?)
            })
        })?;
        let quantity_config = r
            .opt(o[7], |r| {
                let qext = r.bit()?;
                let [has_nr] = r.opt_bits::<1>()?;
                let list = if has_nr {
                    r.seq_of(1, 2, |r| {
                        let [has_idx] = r.opt_bits::<1>()?;
                        Ok(QuantityConfigNr {
                            cell: quantity_config_rs(r)?,
                            rs_index: r.opt(has_idx, quantity_config_rs)?,
                        })
                    })?
                } else {
                    Vec::new()
                };
                if qext {
                    r.skip_ext_additions()?;
                }
                Ok(list)
            })
            .ctx("quantityConfig")?;
        let meas_gap_fr2 = r
            .opt(o[8], |r| {
                let gext = r.bit()?;
                let [has_fr2] = r.opt_bits::<1>()?;
                let g = r.opt(has_fr2, |r| r.setup_release(gap_config))?;
                if gext {
                    r.skip_ext_additions()?;
                }
                Ok(g)
            })
            .ctx("measGapConfig")?
            .flatten();
        let meas_gap_sharing_fr2 = r
            .opt(o[9], |r| {
                let gext = r.bit()?;
                let [has_fr2] = r.opt_bits::<1>()?;
                let g = r.opt(has_fr2, |r| r.setup_release(|r| Ok(r.enu(4)? as u8)))?;
                if gext {
                    r.skip_ext_additions()?;
                }
                Ok(g)
            })
            .ctx("measGapSharingConfig")?
            .flatten();
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            meas_object_to_remove_list,
            meas_object_to_add_mod_list,
            report_config_to_remove_list,
            report_config_to_add_mod_list,
            meas_id_to_remove_list,
            meas_id_to_add_mod_list,
            s_measure_config,
            quantity_config,
            meas_gap_fr2,
            meas_gap_sharing_fr2,
        })
    }
}

// ---------------------------------------------------------------------------
// Measurement results (uplink)
// ---------------------------------------------------------------------------

/// `MeasQuantityResults` as range indexes (0..127).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MeasQuantityResults {
    pub rsrp: Option<u8>,
    pub rsrq: Option<u8>,
    pub sinr: Option<u8>,
}

/// `MeasResultNR` (cell-level results only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MeasResultNr {
    pub pci: Option<u16>,
    pub results_ssb_cell: Option<MeasQuantityResults>,
    pub results_csi_rs_cell: Option<MeasQuantityResults>,
}

/// `MeasResultServMO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasResultServMo {
    pub serv_cell_id: u8,
    pub serving_cell: MeasResultNr,
    pub best_neigh_cell: Option<MeasResultNr>,
}

/// `MeasResults` (NR neighbours only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasResults {
    pub meas_id: u8,
    pub serving: Vec<MeasResultServMo>,
    pub neigh_cells_nr: Vec<MeasResultNr>,
}

fn encode_quantity_results(w: &mut BitWriter, q: &MeasQuantityResults) {
    w.opt_bits(&[q.rsrp.is_some(), q.rsrq.is_some(), q.sinr.is_some()]);
    for v in [q.rsrp, q.rsrq, q.sinr].into_iter().flatten() {
        w.uint(u32::from(v), 0, 127);
    }
}

fn encode_result_nr(w: &mut BitWriter, m: &MeasResultNr) {
    w.bit(false); // extension
    w.opt_bits(&[m.pci.is_some()]);
    if let Some(p) = m.pci {
        w.uint(u32::from(p), 0, 1007);
    }
    // measResult SEQUENCE { cellResults, rsIndexResults OPTIONAL }
    w.opt_bits(&[false]);
    w.opt_bits(&[
        m.results_ssb_cell.is_some(),
        m.results_csi_rs_cell.is_some(),
    ]);
    if let Some(q) = &m.results_ssb_cell {
        encode_quantity_results(w, q);
    }
    if let Some(q) = &m.results_csi_rs_cell {
        encode_quantity_results(w, q);
    }
}

impl MeasResults {
    /// Encode at the writer's position.
    pub fn encode(&self, w: &mut BitWriter) {
        w.bit(false); // extension
        w.opt_bits(&[!self.neigh_cells_nr.is_empty()]);
        w.uint(u32::from(self.meas_id), 1, 64);
        w.seq_of(&self.serving, 1, 32, |w, s| {
            w.bit(false); // extension
            w.opt_bits(&[s.best_neigh_cell.is_some()]);
            w.uint(u32::from(s.serv_cell_id), 0, 31);
            encode_result_nr(w, &s.serving_cell);
            if let Some(b) = &s.best_neigh_cell {
                encode_result_nr(w, b);
            }
        });
        if !self.neigh_cells_nr.is_empty() {
            w.bit(false); // measResultNeighCells extension
            w.bit(false); // measResultListNR
            w.seq_of(&self.neigh_cells_nr, 1, 8, encode_result_nr);
        }
    }

    /// Decode (for round-trip tests and tooling).
    pub fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_neigh] = r.opt_bits::<1>()?;
        let meas_id = r.u8(1, 64)?;
        let serving = r.seq_of(1, 32, |r| {
            let sext = r.bit()?;
            let [has_best] = r.opt_bits::<1>()?;
            let serv_cell_id = r.u8(0, 31)?;
            let serving_cell = decode_result_nr(r)?;
            let best_neigh_cell = r.opt(has_best, decode_result_nr)?;
            if sext {
                r.skip_ext_additions()?;
            }
            Ok(MeasResultServMo {
                serv_cell_id,
                serving_cell,
                best_neigh_cell,
            })
        })?;
        let neigh_cells_nr = if has_neigh {
            if r.bit()? {
                return r.unsupported("measResultNeighCells extension alternative");
            }
            if r.bit()? {
                return r.unsupported("measResultListEUTRA");
            }
            r.seq_of(1, 8, decode_result_nr)?
        } else {
            Vec::new()
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            meas_id,
            serving,
            neigh_cells_nr,
        })
    }
}

fn decode_quantity_results(r: &mut BitReader) -> DecodeResult<MeasQuantityResults> {
    let [p, q, s] = r.opt_bits::<3>()?;
    Ok(MeasQuantityResults {
        rsrp: r.opt(p, |r| r.u8(0, 127))?,
        rsrq: r.opt(q, |r| r.u8(0, 127))?,
        sinr: r.opt(s, |r| r.u8(0, 127))?,
    })
}

fn decode_result_nr(r: &mut BitReader) -> DecodeResult<MeasResultNr> {
    let ext = r.bit()?;
    let [has_pci] = r.opt_bits::<1>()?;
    let pci = r.opt(has_pci, |r| r.u16(0, 1007))?;
    let [has_rs_idx] = r.opt_bits::<1>()?;
    let [has_ssb, has_csi] = r.opt_bits::<2>()?;
    let results_ssb_cell = r.opt(has_ssb, decode_quantity_results)?;
    let results_csi_rs_cell = r.opt(has_csi, decode_quantity_results)?;
    if has_rs_idx {
        return r.unsupported("rsIndexResults");
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Ok(MeasResultNr {
        pci,
        results_ssb_cell,
        results_csi_rs_cell,
    })
}

// ---------------------------------------------------------------------------
// Range conversions (TS 38.133 §10.1.6 / §10.1.11 / §10.1.16)
// ---------------------------------------------------------------------------

/// `RSRP-Range` index for an RSRP in dBm (1 dB steps from −156 dBm).
pub fn rsrp_range(dbm: f32) -> u8 {
    (dbm.floor() + 157.0).clamp(0.0, 127.0) as u8
}

/// `RSRQ-Range` index for an RSRQ in dB (0.5 dB steps from −43 dB).
pub fn rsrq_range(db: f32) -> u8 {
    ((2.0 * (db + 43.0)).floor() + 1.0).clamp(0.0, 127.0) as u8
}

/// `SINR-Range` index for an SINR in dB (0.5 dB steps from −23 dB).
pub fn sinr_range(db: f32) -> u8 {
    ((2.0 * (db + 23.0)).floor() + 1.0).clamp(0.0, 127.0) as u8
}

/// The dBm value at the bottom of an `RSRP-Range` index (the reverse of
/// [`rsrp_range`]; for thresholds).
pub fn rsrp_range_dbm(idx: u8) -> f32 {
    f32::from(idx) - 157.0
}

/// The dB value at the bottom of an `RSRQ-Range` index.
pub fn rsrq_range_db(idx: u8) -> f32 {
    (f32::from(idx) - 1.0) / 2.0 - 43.0
}

/// The dB value at the bottom of a `SINR-Range` index.
pub fn sinr_range_db(idx: u8) -> f32 {
    (f32::from(idx) - 1.0) / 2.0 - 23.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `MeasConfig` by hand (the writer mirrors the reader) and decode
    /// it: one SSB measurement object, a periodical and an A3 report config,
    /// two measurement ids, a quantity config and s-Measure.
    #[test]
    fn meas_config_round_trip() {
        let mut w = BitWriter::new();
        w.bit(false); // ext
        w.opt_bits(&[
            false, true, false, true, false, true, true, true, false, false,
        ]);
        // measObjectToAddModList: one entry.
        w.len_constrained(1, 1, 64);
        w.uint(1, 1, 64); // measObjectId
        w.bit(false); // measObjectNR
        w.bit(false); // ext
                      // optionals: ssbFrequency, ssbSCS, smtc1, (no smtc2), (no refFreqCSI), absThreshSS, (no csi thresh), nrofSS, (no csi avg), cellsToRemove(no), cellsToAddMod(yes), rest no
        w.opt_bits(&[
            true, true, true, false, false, true, false, true, false, false, true, false, false,
            false, false,
        ]);
        w.uint(626000, 0, 3_279_165);
        w.enu(1, 8); // kHz30
        w.enu(2, 6); // sf20
        w.uint(3, 0, 19);
        w.enu(4, 5); // sf5
                     // referenceSignalConfig: ssb-ConfigMobility present
        w.opt_bits(&[true, false]);
        w.bit(false); // ext
        w.opt_bits(&[true, false]);
        w.bit(true); // setup
        w.enu(1, 3); // mediumBitmap
        w.bitstring(0b1010_0000, 8);
        w.boolean(true); // deriveSSB-IndexFromCell
                         // absThreshSS-BlocksConsolidation: rsrp only
        w.opt_bits(&[true, false, false]);
        w.uint(40, 0, 127);
        w.uint(4, 2, 16); // nrofSS-BlocksToAverage
        w.uint(1, 1, 2); // quantityConfigIndex
                         // offsetMO: all defaults
        w.opt_bits(&[false; 6]);
        // cellsToAddModList: one cell with rsrpOffsetSSB = +2 dB
        w.len_constrained(1, 1, 32);
        w.uint(7, 0, 1007);
        w.opt_bits(&[true, false, false, false, false, false]);
        w.enu(17, 31); // dB2
                       // reportConfigToAddModList: periodical (id 1) and A3 (id 2).
        w.len_constrained(2, 1, 64);
        w.uint(1, 1, 64);
        w.bit(false); // reportConfigNR
        w.bit(false); // reportType not extended
        w.bit(false); // periodical
        w.bit(false); // ext
        w.opt_bits(&[false, false]);
        w.bit(false); // rsType ssb
        w.enu(4, 14); // ms1024
        w.enu(7, 8); // infinity
        w.boolean(true);
        w.boolean(true);
        w.boolean(false);
        w.uint(1, 1, 8);
        w.boolean(false); // includeBeamMeasurements
        w.boolean(false); // useWhiteCellList
        w.uint(2, 1, 64);
        w.bit(false);
        w.bit(false);
        w.bit(true); // eventTriggered
        w.bit(false); // ext
        w.opt_bits(&[false, false, false]);
        w.bit(false); // eventId not extended
        w.enu(2, 6); // A3
        w.enu(0, 3); // rsrp offset
        w.int(6, -30, 30);
        w.boolean(false); // reportOnLeave
        w.uint(0, 0, 30); // hysteresis
        w.enu(4, 16); // ms100
        w.boolean(false); // useWhiteCellList
        w.bit(false); // rsType ssb
        w.enu(4, 14);
        w.enu(7, 8);
        w.boolean(true);
        w.boolean(false);
        w.boolean(false);
        w.uint(4, 1, 8);
        w.boolean(false);
        // measIdToAddModList
        w.len_constrained(2, 1, 64);
        w.uint(1, 1, 64);
        w.uint(1, 1, 64);
        w.uint(1, 1, 64);
        w.uint(2, 1, 64);
        w.uint(1, 1, 64);
        w.uint(2, 1, 64);
        // s-MeasureConfig: ssb-RSRP 50
        w.bit(false);
        w.uint(50, 0, 127);
        // quantityConfig: one QuantityConfigNR, cell: ssb fc8/default/default, csi defaults.
        w.bit(false); // ext
        w.opt_bits(&[true]);
        w.len_constrained(1, 1, 2);
        w.opt_bits(&[false]);
        w.opt_bits(&[true, false, false]);
        w.enu_ext(8, 16); // fc8
        w.opt_bits(&[false, false, false]);
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        let m = MeasConfig::decode(&mut r).expect("decode");
        assert_eq!(m.meas_object_to_add_mod_list.len(), 1);
        let o = &m.meas_object_to_add_mod_list[0].meas_object;
        assert_eq!(o.ssb_frequency, Some(626000));
        assert_eq!(o.ssb_scs_khz, Some(30));
        assert_eq!(
            o.smtc1,
            Some(SsbMtc {
                periodicity_sf: 20,
                offset_sf: 3,
                duration_sf: 5
            })
        );
        assert_eq!(
            o.ssb_config_mobility.as_ref().unwrap().ssb_to_measure,
            Some(SetupRelease::Setup(SsbToMeasure::Medium(0b1010_0000)))
        );
        assert_eq!(o.abs_thresh_ss_blocks_consolidation.unwrap().rsrp, Some(40));
        assert_eq!(o.nrof_ss_blocks_to_average, Some(4));
        assert_eq!(o.cells_to_add_mod_list[0].pci, 7);
        assert_eq!(
            o.cells_to_add_mod_list[0]
                .cell_individual_offset
                .rsrp_offset_ssb_db,
            2
        );
        assert_eq!(m.report_config_to_add_mod_list.len(), 2);
        let p = m.report_config_to_add_mod_list[0].report_config;
        assert_eq!(p.event, None);
        assert_eq!(p.report_interval_ms, 1024);
        assert_eq!(p.report_amount, None);
        assert_eq!(
            p.report_quantity_cell,
            MeasReportQuantity {
                rsrp: true,
                rsrq: true,
                sinr: false
            }
        );
        let e = m.report_config_to_add_mod_list[1]
            .report_config
            .event
            .unwrap();
        assert_eq!(
            e.event,
            EventId::A3 {
                offset: MeasTriggerQuantityOffset::Rsrp(6),
                use_allowed_cell_list: false
            }
        );
        assert_eq!(e.time_to_trigger_ms, 100);
        assert_eq!(
            m.meas_id_to_add_mod_list[1],
            MeasIdToAddMod {
                meas_id: 2,
                meas_object_id: 1,
                report_config_id: 2
            }
        );
        assert_eq!(m.s_measure_config, Some(SMeasureConfig::SsbRsrp(50)));
        assert_eq!(m.quantity_config.as_ref().unwrap()[0].cell.ssb.rsrp, 8);
        assert_eq!(m.quantity_config.as_ref().unwrap()[0].cell.ssb.rsrq, 4);
        assert!(r.remaining() < 8, "only byte-alignment padding may remain");
    }

    #[test]
    fn meas_results_round_trip() {
        let res = MeasResults {
            meas_id: 1,
            serving: vec![MeasResultServMo {
                serv_cell_id: 0,
                serving_cell: MeasResultNr {
                    pci: Some(1),
                    results_ssb_cell: Some(MeasQuantityResults {
                        rsrp: Some(77),
                        rsrq: Some(60),
                        sinr: Some(100),
                    }),
                    results_csi_rs_cell: None,
                },
                best_neigh_cell: None,
            }],
            neigh_cells_nr: vec![MeasResultNr {
                pci: Some(2),
                results_ssb_cell: Some(MeasQuantityResults {
                    rsrp: Some(70),
                    rsrq: None,
                    sinr: None,
                }),
                results_csi_rs_cell: None,
            }],
        };
        let mut w = BitWriter::new();
        res.encode(&mut w);
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(MeasResults::decode(&mut r).unwrap(), res);
    }

    #[test]
    fn ranges() {
        assert_eq!(rsrp_range(-200.0), 0);
        assert_eq!(rsrp_range(-156.0), 1);
        assert_eq!(rsrp_range(-80.0), 77);
        assert_eq!(rsrp_range(-30.0), 127);
        assert_eq!(rsrq_range(-43.0), 1);
        assert_eq!(rsrq_range(-10.5), 66);
        assert_eq!(rsrq_range(20.0), 127);
        assert_eq!(sinr_range(-23.0), 1);
        assert_eq!(sinr_range(0.0), 47);
        assert_eq!(sinr_range(40.0), 127);
        assert_eq!(rsrp_range_dbm(77), -80.0);
        assert_eq!(rsrq_range_db(66), -10.5);
        assert_eq!(sinr_range_db(47), 0.0);
    }
}
