//! `CSI-MeasConfig` and its resource / report IEs (TS 38.331 §6.3.2): the
//! NZP/ZP CSI-RS resources that shape PDSCH rate matching and the periodic
//! CSI report the UE must send on PUCCH.

use crate::common::{CsiFrequencyOccupation, CsiRsResourceMapping, PeriodicityAndOffset};
use crate::uper::{BitReader, Ctx, DecodeResult};

/// `NZP-CSI-RS-Resource ::= SEQUENCE { nzp-CSI-RS-ResourceId NZP-CSI-RS-ResourceId,
/// resourceMapping CSI-RS-ResourceMapping, powerControlOffset INTEGER (-8..15),
/// powerControlOffsetSS ENUMERATED { db-3, db0, db3, db6 } OPTIONAL, scramblingID
/// ScramblingId, periodicityAndOffset CSI-ResourcePeriodicityAndOffset OPTIONAL,
/// qcl-InfoPeriodicCSI-RS TCI-StateId OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NzpCsiRsResource {
    pub nzp_csi_rs_resource_id: u8,
    pub resource_mapping: CsiRsResourceMapping,
    pub power_control_offset: i8,
    pub power_control_offset_ss_db: Option<i8>,
    pub scrambling_id: u16,
    pub periodicity_and_offset: Option<PeriodicityAndOffset>,
    pub qcl_info_periodic_csi_rs: Option<u8>,
}

impl NzpCsiRsResource {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_ss, has_po, has_qcl] = r.opt_bits::<3>()?;
        let nzp_csi_rs_resource_id = r.u8(0, 191)?;
        let resource_mapping = CsiRsResourceMapping::decode(r).ctx("resourceMapping")?;
        let power_control_offset = r.int(-8, 15)? as i8;
        let power_control_offset_ss_db =
            r.opt(has_ss, |r| Ok([-3i8, 0, 3, 6][r.enu(4)? as usize]))?;
        let scrambling_id = r.u16(0, 1023)?;
        let periodicity_and_offset = r.opt(has_po, PeriodicityAndOffset::decode_csi_resource)?;
        let qcl_info_periodic_csi_rs = r.opt(has_qcl, |r| r.u8(0, 127))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            nzp_csi_rs_resource_id,
            resource_mapping,
            power_control_offset,
            power_control_offset_ss_db,
            scrambling_id,
            periodicity_and_offset,
            qcl_info_periodic_csi_rs,
        })
    }
}

/// `NZP-CSI-RS-ResourceSet ::= SEQUENCE { nzp-CSI-ResourceSetId NZP-CSI-RS-ResourceSetId,
/// nzp-CSI-RS-Resources SEQUENCE (SIZE (1..maxNrofNZP-CSI-RS-ResourcesPerSet)) OF
/// NZP-CSI-RS-ResourceId, repetition ENUMERATED { on, off } OPTIONAL,
/// aperiodicTriggeringOffset INTEGER (0..6) OPTIONAL, trs-Info ENUMERATED { true } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NzpCsiRsResourceSet {
    pub nzp_csi_resource_set_id: u8,
    pub nzp_csi_rs_resources: Vec<u8>,
    /// `Some(true)` = repetition on.
    pub repetition: Option<bool>,
    pub aperiodic_triggering_offset: Option<u8>,
    pub trs_info: bool,
}

impl NzpCsiRsResourceSet {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_rep, has_aper, trs] = r.opt_bits::<3>()?;
        let nzp_csi_resource_set_id = r.u8(0, 63)?;
        let nzp_csi_rs_resources = r.seq_of(1, 64, |r| r.u8(0, 191))?;
        let repetition = r.opt(has_rep, |r| Ok(r.enu(2)? == 0))?;
        let aperiodic_triggering_offset = r.opt(has_aper, |r| r.u8(0, 6))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            nzp_csi_resource_set_id,
            nzp_csi_rs_resources,
            repetition,
            aperiodic_triggering_offset,
            trs_info: trs,
        })
    }
}

/// `csi-IM-ResourceElementPattern CHOICE { pattern0 SEQUENCE { subcarrierLocation-p0 ENUMERATED
/// { s0, s2, s4, s6, s8, s10 }, symbolLocation-p0 INTEGER (0..12) }, pattern1 SEQUENCE {
/// subcarrierLocation-p1 ENUMERATED { s0, s4, s8 }, symbolLocation-p1 INTEGER (0..13) } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiImResourceElementPattern {
    Pattern0 {
        subcarrier_location: u8,
        symbol_location: u8,
    },
    Pattern1 {
        subcarrier_location: u8,
        symbol_location: u8,
    },
}

/// `CSI-IM-Resource ::= SEQUENCE { csi-IM-ResourceId CSI-IM-ResourceId,
/// csi-IM-ResourceElementPattern CHOICE {…} OPTIONAL, freqBand CSI-FrequencyOccupation OPTIONAL,
/// periodicityAndOffset CSI-ResourcePeriodicityAndOffset OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiImResource {
    pub csi_im_resource_id: u8,
    pub csi_im_resource_element_pattern: Option<CsiImResourceElementPattern>,
    pub freq_band: Option<CsiFrequencyOccupation>,
    pub periodicity_and_offset: Option<PeriodicityAndOffset>,
}

impl CsiImResource {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_pat, has_fb, has_po] = r.opt_bits::<3>()?;
        let csi_im_resource_id = r.u8(0, 31)?;
        let csi_im_resource_element_pattern = r.opt(has_pat, |r| {
            Ok(if !r.bit()? {
                let subcarrier_location = 2 * r.enu(6)? as u8;
                let symbol_location = r.u8(0, 12)?;
                CsiImResourceElementPattern::Pattern0 {
                    subcarrier_location,
                    symbol_location,
                }
            } else {
                let subcarrier_location = 4 * r.enu(3)? as u8;
                let symbol_location = r.u8(0, 13)?;
                CsiImResourceElementPattern::Pattern1 {
                    subcarrier_location,
                    symbol_location,
                }
            })
        })?;
        let freq_band = r.opt(has_fb, CsiFrequencyOccupation::decode)?;
        let periodicity_and_offset = r.opt(has_po, PeriodicityAndOffset::decode_csi_resource)?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            csi_im_resource_id,
            csi_im_resource_element_pattern,
            freq_band,
            periodicity_and_offset,
        })
    }
}

/// `CSI-IM-ResourceSet ::= SEQUENCE { csi-IM-ResourceSetId CSI-IM-ResourceSetId, csi-IM-Resources
/// SEQUENCE (SIZE(1..maxNrofCSI-IM-ResourcesPerSet)) OF CSI-IM-ResourceId, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiImResourceSet {
    pub csi_im_resource_set_id: u8,
    pub csi_im_resources: Vec<u8>,
}

/// `CSI-SSB-ResourceSet ::= SEQUENCE { csi-SSB-ResourceSetId CSI-SSB-ResourceSetId,
/// csi-SSB-ResourceList SEQUENCE (SIZE(1..maxNrofCSI-SSB-ResourcePerSet)) OF SSB-Index, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiSsbResourceSet {
    pub csi_ssb_resource_set_id: u8,
    pub csi_ssb_resource_list: Vec<u8>,
}

/// `csi-RS-ResourceSetList CHOICE { nzp-CSI-RS-SSB SEQUENCE { nzp-CSI-RS-ResourceSetList
/// SEQUENCE (SIZE (1..maxNrofNZP-CSI-RS-ResourceSetsPerConfig)) OF NZP-CSI-RS-ResourceSetId
/// OPTIONAL, csi-SSB-ResourceSetList SEQUENCE (SIZE (1..maxNrofCSI-SSB-ResourceSetsPerConfig))
/// OF CSI-SSB-ResourceSetId OPTIONAL }, csi-IM-ResourceSetList SEQUENCE (SIZE
/// (1..maxNrofCSI-IM-ResourceSetsPerConfig)) OF CSI-IM-ResourceSetId }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsiResourceSetList {
    NzpCsiRsSsb {
        nzp_csi_rs_resource_set_list: Vec<u8>,
        csi_ssb_resource_set_list: Vec<u8>,
    },
    CsiImResourceSetList(Vec<u8>),
}

/// `resourceType ENUMERATED { aperiodic, semiPersistent, periodic }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiResourceType {
    Aperiodic,
    SemiPersistent,
    Periodic,
}

/// `CSI-ResourceConfig ::= SEQUENCE { csi-ResourceConfigId CSI-ResourceConfigId,
/// csi-RS-ResourceSetList CHOICE {…}, bwp-Id BWP-Id, resourceType ENUMERATED {…}, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiResourceConfig {
    pub csi_resource_config_id: u8,
    pub csi_rs_resource_set_list: CsiResourceSetList,
    pub bwp_id: u8,
    pub resource_type: CsiResourceType,
}

impl CsiResourceConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let csi_resource_config_id = r.u8(0, 111)?;
        let csi_rs_resource_set_list = if !r.bit()? {
            let [has_nzp, has_ssb] = r.opt_bits::<2>()?;
            let nzp = if has_nzp {
                r.seq_of(1, 16, |r| r.u8(0, 63))?
            } else {
                vec![]
            };
            let ssb = if has_ssb {
                r.seq_of(1, 1, |r| r.u8(0, 63))?
            } else {
                vec![]
            };
            CsiResourceSetList::NzpCsiRsSsb {
                nzp_csi_rs_resource_set_list: nzp,
                csi_ssb_resource_set_list: ssb,
            }
        } else {
            CsiResourceSetList::CsiImResourceSetList(r.seq_of(1, 16, |r| r.u8(0, 63))?)
        };
        let bwp_id = r.u8(0, 4)?;
        let resource_type = match r.enu(3)? {
            0 => CsiResourceType::Aperiodic,
            1 => CsiResourceType::SemiPersistent,
            _ => CsiResourceType::Periodic,
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            csi_resource_config_id,
            csi_rs_resource_set_list,
            bwp_id,
            resource_type,
        })
    }
}

/// `PUCCH-CSI-Resource ::= SEQUENCE { uplinkBandwidthPartId BWP-Id, pucch-Resource PUCCH-ResourceId }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchCsiResource {
    pub uplink_bandwidth_part_id: u8,
    pub pucch_resource: u8,
}

/// `reportConfigType CHOICE { periodic SEQUENCE { reportSlotConfig
/// CSI-ReportPeriodicityAndOffset, pucch-CSI-ResourceList SEQUENCE (SIZE (1..maxNrofBWPs)) OF
/// PUCCH-CSI-Resource }, semiPersistentOnPUCCH SEQUENCE { … same … }, semiPersistentOnPUSCH
/// SEQUENCE { reportSlotConfig ENUMERATED { sl5, sl10, sl20, sl40, sl80, sl160, sl320 },
/// reportSlotOffsetList SEQUENCE (SIZE (1..maxNrofUL-Allocations)) OF INTEGER (0..32), p0alpha
/// P0-PUSCH-AlphaSetId }, aperiodic SEQUENCE { reportSlotOffsetList … } }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsiReportConfigType {
    Periodic {
        report_slot_config: PeriodicityAndOffset,
        pucch_csi_resource_list: Vec<PucchCsiResource>,
    },
    SemiPersistentOnPucch {
        report_slot_config: PeriodicityAndOffset,
        pucch_csi_resource_list: Vec<PucchCsiResource>,
    },
    SemiPersistentOnPusch {
        report_slot_period: u16,
        report_slot_offset_list: Vec<u8>,
        p0alpha: u8,
    },
    Aperiodic {
        report_slot_offset_list: Vec<u8>,
    },
}

/// `reportQuantity CHOICE { none NULL, cri-RI-PMI-CQI NULL, cri-RI-i1 NULL, cri-RI-i1-CQI
/// SEQUENCE { pdsch-BundleSizeForCSI ENUMERATED { n2, n4 } OPTIONAL }, cri-RI-CQI NULL, cri-RSRP
/// NULL, ssb-Index-RSRP NULL, cri-RI-LI-PMI-CQI NULL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiReportQuantity {
    None,
    CriRiPmiCqi,
    CriRiI1,
    CriRiI1Cqi {
        pdsch_bundle_size_for_csi: Option<u8>,
    },
    CriRiCqi,
    CriRsrp,
    SsbIndexRsrp,
    CriRiLiPmiCqi,
}

/// `reportFreqConfiguration SEQUENCE { cqi-FormatIndicator ENUMERATED { widebandCQI, subbandCQI }
/// OPTIONAL, pmi-FormatIndicator ENUMERATED { widebandPMI, subbandPMI } OPTIONAL,
/// csi-ReportingBand CHOICE { subbands3 BIT STRING(SIZE(3)), …, subbands19-v1530 BIT STRING(SIZE(19)) }
/// OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReportFreqConfiguration {
    /// `Some(true)` = subband CQI.
    pub subband_cqi: Option<bool>,
    /// `Some(true)` = subband PMI.
    pub subband_pmi: Option<bool>,
    /// `(number of subbands, bitmap MSB-first in the low bits)`.
    pub csi_reporting_band: Option<(u8, u32)>,
}

/// `groupBasedBeamReporting CHOICE { enabled NULL, disabled SEQUENCE { nrofReportedRS
/// ENUMERATED { n1, n2, n3, n4 } OPTIONAL } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBasedBeamReporting {
    Enabled,
    Disabled { nrof_reported_rs: Option<u8> },
}

/// `cqi-Table ENUMERATED { table1, table2, table3, table4-r17 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqiTable {
    Table1,
    Table2,
    Table3,
    Table4,
}

/// `CSI-ReportConfig ::= SEQUENCE { reportConfigId CSI-ReportConfigId, carrier ServCellIndex
/// OPTIONAL, resourcesForChannelMeasurement CSI-ResourceConfigId, csi-IM-ResourcesForInterference
/// CSI-ResourceConfigId OPTIONAL, nzp-CSI-RS-ResourcesForInterference CSI-ResourceConfigId OPTIONAL,
/// reportConfigType CHOICE {…}, reportQuantity CHOICE {…}, reportFreqConfiguration SEQUENCE {…}
/// OPTIONAL, timeRestrictionForChannelMeasurements ENUMERATED { configured, notConfigured },
/// timeRestrictionForInterferenceMeasurements ENUMERATED {…}, codebookConfig CodebookConfig
/// OPTIONAL, dummy ENUMERATED { dynamic, semiStatic } OPTIONAL, groupBasedBeamReporting CHOICE
/// {…}, cqi-Table ENUMERATED {…} OPTIONAL, subbandSize ENUMERATED { value1, value2 },
/// non-PMI-PortIndication SEQUENCE (SIZE (1..maxNrofNZP-CSI-RS-ResourcesPerConfig)) OF
/// PortIndexFor8Ranks OPTIONAL, ... }`.
///
/// `codebookConfig` and `non-PMI-PortIndication` are not supported (decode error when present).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiReportConfig {
    pub report_config_id: u8,
    pub carrier: Option<u8>,
    pub resources_for_channel_measurement: u8,
    pub csi_im_resources_for_interference: Option<u8>,
    pub nzp_csi_rs_resources_for_interference: Option<u8>,
    pub report_config_type: CsiReportConfigType,
    pub report_quantity: CsiReportQuantity,
    pub report_freq_configuration: Option<ReportFreqConfiguration>,
    pub time_restriction_for_channel_measurements: bool,
    pub time_restriction_for_interference_measurements: bool,
    /// `dummy ENUMERATED { dynamic, semiStatic }`: `Some(true)` = dynamic.
    pub dummy_dynamic: Option<bool>,
    pub group_based_beam_reporting: GroupBasedBeamReporting,
    pub cqi_table: Option<CqiTable>,
    /// `subbandSize`: 1 (value1) or 2 (value2).
    pub subband_size: u8,
}

impl CsiReportConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_carrier, has_im, has_nzp_i, has_freq, has_cb, has_dummy, has_cqi_t, has_nonpmi] =
            r.opt_bits::<8>()?;
        let report_config_id = r.u8(0, 47)?;
        let carrier = r.opt(has_carrier, |r| r.u8(0, 31))?;
        let resources_for_channel_measurement = r.u8(0, 111)?;
        let csi_im_resources_for_interference = r.opt(has_im, |r| r.u8(0, 111))?;
        let nzp_csi_rs_resources_for_interference = r.opt(has_nzp_i, |r| r.u8(0, 111))?;
        let pucch_list = |r: &mut BitReader| {
            r.seq_of(1, 4, |r| {
                Ok(PucchCsiResource {
                    uplink_bandwidth_part_id: r.u8(0, 4)?,
                    pucch_resource: r.u8(0, 127)?,
                })
            })
        };
        let report_config_type = match r.uint(0, 3)? {
            0 => {
                let report_slot_config = PeriodicityAndOffset::decode_csi_report(r)?;
                CsiReportConfigType::Periodic {
                    report_slot_config,
                    pucch_csi_resource_list: pucch_list(r)?,
                }
            }
            1 => {
                let report_slot_config = PeriodicityAndOffset::decode_csi_report(r)?;
                CsiReportConfigType::SemiPersistentOnPucch {
                    report_slot_config,
                    pucch_csi_resource_list: pucch_list(r)?,
                }
            }
            2 => {
                let report_slot_period = 5u16 << r.enu(7)?;
                let report_slot_offset_list = r.seq_of(1, 16, |r| r.u8(0, 32))?;
                let p0alpha = r.u8(0, 29)?;
                CsiReportConfigType::SemiPersistentOnPusch {
                    report_slot_period,
                    report_slot_offset_list,
                    p0alpha,
                }
            }
            _ => CsiReportConfigType::Aperiodic {
                report_slot_offset_list: r.seq_of(1, 16, |r| r.u8(0, 32))?,
            },
        };
        let report_quantity = match r.uint(0, 7)? {
            0 => CsiReportQuantity::None,
            1 => CsiReportQuantity::CriRiPmiCqi,
            2 => CsiReportQuantity::CriRiI1,
            3 => {
                let [has_bs] = r.opt_bits::<1>()?;
                let pdsch_bundle_size_for_csi =
                    r.opt(has_bs, |r| Ok([2u8, 4][r.enu(2)? as usize]))?;
                CsiReportQuantity::CriRiI1Cqi {
                    pdsch_bundle_size_for_csi,
                }
            }
            4 => CsiReportQuantity::CriRiCqi,
            5 => CsiReportQuantity::CriRsrp,
            6 => CsiReportQuantity::SsbIndexRsrp,
            _ => CsiReportQuantity::CriRiLiPmiCqi,
        };
        let report_freq_configuration = r.opt(has_freq, |r| {
            let [has_cqi_f, has_pmi_f, has_band] = r.opt_bits::<3>()?;
            let subband_cqi = r.opt(has_cqi_f, |r| Ok(r.enu(2)? == 1))?;
            let subband_pmi = r.opt(has_pmi_f, |r| Ok(r.enu(2)? == 1))?;
            let csi_reporting_band = r.opt(has_band, |r| {
                // CHOICE { subbands3 .. subbands18, subbands19-v1530 }: 17 alternatives,
                // alternative i carries a BIT STRING (SIZE (i+3)).
                let alt = r.uint(0, 16)?;
                let n = alt as u8 + 3;
                Ok((n, r.bitstring(n as u32)? as u32))
            })?;
            Ok(ReportFreqConfiguration {
                subband_cqi,
                subband_pmi,
                csi_reporting_band,
            })
        })?;
        let time_restriction_for_channel_measurements = r.enu(2)? == 0;
        let time_restriction_for_interference_measurements = r.enu(2)? == 0;
        if has_cb {
            return r.unsupported("codebookConfig");
        }
        let dummy_dynamic = r.opt(has_dummy, |r| Ok(r.enu(2)? == 0))?;
        let group_based_beam_reporting = if !r.bit()? {
            GroupBasedBeamReporting::Enabled
        } else {
            let [has_n] = r.opt_bits::<1>()?;
            GroupBasedBeamReporting::Disabled {
                nrof_reported_rs: r.opt(has_n, |r| Ok(r.enu(4)? as u8 + 1))?,
            }
        };
        let cqi_table = r.opt(has_cqi_t, |r| {
            Ok(match r.enu(4)? {
                0 => CqiTable::Table1,
                1 => CqiTable::Table2,
                2 => CqiTable::Table3,
                _ => CqiTable::Table4,
            })
        })?;
        let subband_size = r.enu(2)? as u8 + 1;
        if has_nonpmi {
            return r.unsupported("non-PMI-PortIndication");
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            report_config_id,
            carrier,
            resources_for_channel_measurement,
            csi_im_resources_for_interference,
            nzp_csi_rs_resources_for_interference,
            report_config_type,
            report_quantity,
            report_freq_configuration,
            time_restriction_for_channel_measurements,
            time_restriction_for_interference_measurements,
            dummy_dynamic,
            group_based_beam_reporting,
            cqi_table,
            subband_size,
        })
    }
}

/// `CSI-MeasConfig ::= SEQUENCE { nzp-CSI-RS-ResourceToAddModList …, nzp-CSI-RS-ResourceToReleaseList …,
/// nzp-CSI-RS-ResourceSetToAddModList …, nzp-CSI-RS-ResourceSetToReleaseList …, csi-IM-ResourceToAddModList …,
/// csi-IM-ResourceToReleaseList …, csi-IM-ResourceSetToAddModList …, csi-IM-ResourceSetToReleaseList …,
/// csi-SSB-ResourceSetToAddModList …, csi-SSB-ResourceSetToReleaseList …, csi-ResourceConfigToAddModList …,
/// csi-ResourceConfigToReleaseList …, csi-ReportConfigToAddModList …, csi-ReportConfigToReleaseList …,
/// reportTriggerSize INTEGER (0..6) OPTIONAL, aperiodicTriggerStateList SetupRelease {…} OPTIONAL,
/// semiPersistentOnPUSCH-TriggerStateList SetupRelease {…} OPTIONAL, ... }` (all lists OPTIONAL).
///
/// The two trigger-state lists are not supported (decode error when present).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CsiMeasConfig {
    pub nzp_csi_rs_resource_to_add_mod_list: Vec<NzpCsiRsResource>,
    pub nzp_csi_rs_resource_to_release_list: Vec<u8>,
    pub nzp_csi_rs_resource_set_to_add_mod_list: Vec<NzpCsiRsResourceSet>,
    pub nzp_csi_rs_resource_set_to_release_list: Vec<u8>,
    pub csi_im_resource_to_add_mod_list: Vec<CsiImResource>,
    pub csi_im_resource_to_release_list: Vec<u8>,
    pub csi_im_resource_set_to_add_mod_list: Vec<CsiImResourceSet>,
    pub csi_im_resource_set_to_release_list: Vec<u8>,
    pub csi_ssb_resource_set_to_add_mod_list: Vec<CsiSsbResourceSet>,
    pub csi_ssb_resource_set_to_release_list: Vec<u8>,
    pub csi_resource_config_to_add_mod_list: Vec<CsiResourceConfig>,
    pub csi_resource_config_to_release_list: Vec<u8>,
    pub csi_report_config_to_add_mod_list: Vec<CsiReportConfig>,
    pub csi_report_config_to_release_list: Vec<u8>,
    pub report_trigger_size: Option<u8>,
}

impl CsiMeasConfig {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<17>()?;
        let mut c = Self::default();
        if o[0] {
            c.nzp_csi_rs_resource_to_add_mod_list = r
                .seq_of(1, 192, NzpCsiRsResource::decode)
                .ctx("nzp-CSI-RS-ResourceToAddModList")?;
        }
        if o[1] {
            c.nzp_csi_rs_resource_to_release_list = r.seq_of(1, 192, |r| r.u8(0, 191))?;
        }
        if o[2] {
            c.nzp_csi_rs_resource_set_to_add_mod_list = r
                .seq_of(1, 64, NzpCsiRsResourceSet::decode)
                .ctx("nzp-CSI-RS-ResourceSetToAddModList")?;
        }
        if o[3] {
            c.nzp_csi_rs_resource_set_to_release_list = r.seq_of(1, 64, |r| r.u8(0, 63))?;
        }
        if o[4] {
            c.csi_im_resource_to_add_mod_list = r
                .seq_of(1, 32, CsiImResource::decode)
                .ctx("csi-IM-ResourceToAddModList")?;
        }
        if o[5] {
            c.csi_im_resource_to_release_list = r.seq_of(1, 32, |r| r.u8(0, 31))?;
        }
        if o[6] {
            c.csi_im_resource_set_to_add_mod_list = r
                .seq_of(1, 64, |r| {
                    let e = r.bit()?;
                    let csi_im_resource_set_id = r.u8(0, 63)?;
                    let csi_im_resources = r.seq_of(1, 8, |r| r.u8(0, 31))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(CsiImResourceSet {
                        csi_im_resource_set_id,
                        csi_im_resources,
                    })
                })
                .ctx("csi-IM-ResourceSetToAddModList")?;
        }
        if o[7] {
            c.csi_im_resource_set_to_release_list = r.seq_of(1, 64, |r| r.u8(0, 63))?;
        }
        if o[8] {
            c.csi_ssb_resource_set_to_add_mod_list = r
                .seq_of(1, 64, |r| {
                    let e = r.bit()?;
                    let csi_ssb_resource_set_id = r.u8(0, 63)?;
                    let csi_ssb_resource_list = r.seq_of(1, 64, |r| r.u8(0, 63))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(CsiSsbResourceSet {
                        csi_ssb_resource_set_id,
                        csi_ssb_resource_list,
                    })
                })
                .ctx("csi-SSB-ResourceSetToAddModList")?;
        }
        if o[9] {
            c.csi_ssb_resource_set_to_release_list = r.seq_of(1, 64, |r| r.u8(0, 63))?;
        }
        if o[10] {
            c.csi_resource_config_to_add_mod_list = r
                .seq_of(1, 112, CsiResourceConfig::decode)
                .ctx("csi-ResourceConfigToAddModList")?;
        }
        if o[11] {
            c.csi_resource_config_to_release_list = r.seq_of(1, 112, |r| r.u8(0, 111))?;
        }
        if o[12] {
            c.csi_report_config_to_add_mod_list = r
                .seq_of(1, 48, CsiReportConfig::decode)
                .ctx("csi-ReportConfigToAddModList")?;
        }
        if o[13] {
            c.csi_report_config_to_release_list = r.seq_of(1, 48, |r| r.u8(0, 47))?;
        }
        c.report_trigger_size = r.opt(o[14], |r| r.u8(0, 6))?;
        if o[15] {
            return r.unsupported("aperiodicTriggerStateList");
        }
        if o[16] {
            return r.unsupported("semiPersistentOnPUSCH-TriggerStateList");
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(c)
    }

    /// The first periodic PUCCH CSI report: `(report slot config, first PUCCH resource)`.
    pub fn periodic_report(&self) -> Option<(PeriodicityAndOffset, PucchCsiResource)> {
        self.csi_report_config_to_add_mod_list
            .iter()
            .find_map(|c| match &c.report_config_type {
                CsiReportConfigType::Periodic {
                    report_slot_config,
                    pucch_csi_resource_list,
                } => Some((*report_slot_config, *pucch_csi_resource_list.first()?)),
                _ => None,
            })
    }
}
