//! `SystemInformationBlockType1` (TS 38.331 §6.2.2 / §6.3.1): a hand-rolled
//! UPER decode of `BCCH-DL-SCH-Message → systemInformationBlockType1` into
//! structured types that mirror the ASN.1.
//!
//! Every IE up to and including `uac-BarringInfo` is walked (UPER has no skip
//! markers, so nothing can be jumped over); release-16+ extension additions
//! are skipped as open types. The decoder is validated bit-exactly against a
//! live OCUDU capture (see the tests) and must parse FDD cells, where
//! `tdd-UL-DL-ConfigurationCommon` is absent.

use crate::common::{
    decode_tdra_list, Bwp, ControlResourceSet, PlmnIdentity, ScsSpecificCarrier, SearchSpace,
    SubcarrierSpacing, TdraRow, TimeAlignmentTimer,
};
use crate::uper::{BitReader, Ctx, DecodeResult, SetupRelease};

pub use crate::common::sliv_to_sl;

/// What a slot is, per the TDD pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Dl,
    Ul,
    /// The flexible/special slot: `dl_symbols` DL at the start, `ul_symbols` UL at
    /// the end, guard in between.
    Special,
}

/// One `TDD-UL-DL-Pattern ::= SEQUENCE { dl-UL-TransmissionPeriodicity ENUMERATED
/// { ms0p5, ms0p625, ms1, ms1p25, ms2, ms2p5, ms5, ms10 }, nrofDownlinkSlots INTEGER
/// (0..maxNrofSlots), nrofDownlinkSymbols INTEGER (0..maxNrofSymbols-1), nrofUplinkSlots,
/// nrofUplinkSymbols, ..., [[ dl-UL-TransmissionPeriodicity-v1530 ENUMERATED { ms3, ms4 }
/// OPTIONAL ]] }`, with the periodicity converted to slots at the reference SCS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TddPattern {
    /// `dl-UL-TransmissionPeriodicity` in microseconds (v1530 value applied when present).
    pub periodicity_us: u32,
    /// Pattern length in slots at the reference SCS.
    pub period_slots: u32,
    /// Leading full-downlink slots.
    pub dl_slots: u32,
    /// Downlink symbols at the start of the slot after the full-DL slots.
    pub dl_symbols: u32,
    /// Trailing full-uplink slots.
    pub ul_slots: u32,
    /// Uplink symbols at the end of the slot before the full-UL slots.
    pub ul_symbols: u32,
}

impl TddPattern {
    fn decode(r: &mut BitReader, ref_scs_khz: u32) -> DecodeResult<Self> {
        let ext = r.bit()?;
        const PERIOD_US: [u32; 8] = [500, 625, 1000, 1250, 2000, 2500, 5000, 10000];
        let mut periodicity_us = PERIOD_US[r.enu(8)? as usize];
        let dl_slots = r.uint(0, 320)?;
        let dl_symbols = r.uint(0, 13)?;
        let ul_slots = r.uint(0, 320)?;
        let ul_symbols = r.uint(0, 13)?;
        if ext {
            r.ext_additions(|i, sub| {
                if i == 0 {
                    let [has] = sub.opt_bits::<1>()?;
                    if has {
                        periodicity_us = [3000, 4000][sub.enu(2)? as usize];
                    }
                }
                Ok(())
            })?;
        }
        let slot_us = 1000 * 15 / ref_scs_khz;
        let period_slots = periodicity_us / slot_us;
        Ok(Self {
            periodicity_us,
            period_slots,
            dl_slots,
            dl_symbols,
            ul_slots,
            ul_symbols,
        })
    }

    pub fn kind(&self, slot: u32) -> SlotKind {
        if self.period_slots == 0 {
            return SlotKind::Dl;
        }
        let s = slot % self.period_slots;
        if s < self.dl_slots {
            SlotKind::Dl
        } else if s >= self.period_slots - self.ul_slots.min(self.period_slots) {
            SlotKind::Ul
        } else {
            SlotKind::Special
        }
    }

    /// Slot can carry a PDCCH + PDSCH for us: full DL, or a special slot with at
    /// least the short PDSCH shape (CORESET symbols 0-1 + PDSCH [2,8)).
    pub fn has_pdsch(&self, slot: u32) -> bool {
        match self.kind(slot) {
            SlotKind::Dl => true,
            SlotKind::Special => self.dl_symbols >= 8,
            SlotKind::Ul => false,
        }
    }

    /// Slot can carry a full-slot PUSCH/PUCCH (14 symbols).
    pub fn has_full_ul(&self, slot: u32) -> bool {
        self.kind(slot) == SlotKind::Ul
    }

    /// The first full-UL slot strictly after `slot` (absolute slot arithmetic).
    pub fn next_ul_slot_after(&self, slot: u32) -> u32 {
        (slot + 1..slot + 1 + self.period_slots)
            .find(|&s| self.has_full_ul(s))
            .unwrap_or(slot + 1)
    }
}

/// `TDD-UL-DL-ConfigCommon ::= SEQUENCE { referenceSubcarrierSpacing SubcarrierSpacing,
/// pattern1 TDD-UL-DL-Pattern, pattern2 TDD-UL-DL-Pattern OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TddUlDlConfigCommon {
    pub reference_subcarrier_spacing: SubcarrierSpacing,
    pub pattern1: TddPattern,
    pub pattern2: Option<TddPattern>,
}

impl TddUlDlConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_p2] = r.opt_bits::<1>()?;
        let reference_subcarrier_spacing = SubcarrierSpacing::decode(r)?;
        let khz = reference_subcarrier_spacing.khz();
        let pattern1 = TddPattern::decode(r, khz).ctx("pattern1")?;
        let pattern2 = r
            .opt(has_p2, |r| TddPattern::decode(r, khz))
            .ctx("pattern2")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            reference_subcarrier_spacing,
            pattern1,
            pattern2,
        })
    }

    /// The combined TDD period in slots (pattern1 + pattern2 when present).
    pub fn period_slots(&self) -> u32 {
        self.pattern1.period_slots + self.pattern2.map_or(0, |p| p.period_slots)
    }

    fn which(&self, slot: u32) -> (&TddPattern, u32) {
        let s = slot % self.period_slots().max(1);
        match self.pattern2 {
            Some(ref p2) if s >= self.pattern1.period_slots => (p2, s - self.pattern1.period_slots),
            _ => (&self.pattern1, s),
        }
    }

    /// Slot kind across the combined pattern.
    pub fn slot_kind(&self, slot: u32) -> SlotKind {
        let (p, s) = self.which(slot);
        p.kind(s)
    }

    pub fn has_pdsch(&self, slot: u32) -> bool {
        let (p, s) = self.which(slot);
        p.has_pdsch(s)
    }

    pub fn has_full_ul(&self, slot: u32) -> bool {
        let (p, s) = self.which(slot);
        p.has_full_ul(s)
    }

    /// First full-UL slot strictly after `slot` (mod the combined period).
    pub fn next_ul_slot_after(&self, slot: u32) -> u32 {
        (slot + 1..=slot + self.period_slots())
            .find(|&s| self.has_full_ul(s))
            .unwrap_or(slot + 1)
    }
}

/// `cellSelectionInfo SEQUENCE { q-RxLevMin Q-RxLevMin, q-RxLevMinOffset INTEGER (1..8)
/// OPTIONAL, q-RxLevMinSUL Q-RxLevMin OPTIONAL, q-QualMin Q-QualMin OPTIONAL,
/// q-QualMinOffset INTEGER (1..8) OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellSelectionInfo {
    pub q_rx_lev_min: i8,
    pub q_rx_lev_min_offset: Option<u8>,
    pub q_rx_lev_min_sul: Option<i8>,
    pub q_qual_min: Option<i8>,
    pub q_qual_min_offset: Option<u8>,
}

/// `PLMN-IdentityInfo ::= SEQUENCE { plmn-IdentityList SEQUENCE (SIZE (1..maxPLMN)) OF
/// PLMN-Identity, trackingAreaCode TrackingAreaCode OPTIONAL, ranac RAN-AreaCode OPTIONAL,
/// cellIdentity CellIdentity, cellReservedForOperatorUse ENUMERATED { reserved, notReserved }, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlmnIdentityInfo {
    pub plmn_identity_list: Vec<PlmnIdentity>,
    /// 24-bit TAC.
    pub tracking_area_code: Option<u32>,
    pub ranac: Option<u8>,
    /// 36-bit NR cell identity.
    pub cell_identity: u64,
    pub cell_reserved_for_operator_use: bool,
}

/// `CellAccessRelatedInfo ::= SEQUENCE { plmn-IdentityInfoList PLMN-IdentityInfoList,
/// cellReservedForOtherUse ENUMERATED { true } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellAccessRelatedInfo {
    pub plmn_identity_info_list: Vec<PlmnIdentityInfo>,
    pub cell_reserved_for_other_use: bool,
}

/// `ConnEstFailureControl ::= SEQUENCE { connEstFailCount ENUMERATED { n1, n2, n3, n4 },
/// connEstFailOffsetValidity ENUMERATED { s30, s60, s120, s240, s300, s420, s600, s900 },
/// connEstFailOffset INTEGER (0..15) OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnEstFailureControl {
    pub conn_est_fail_count: u8,
    pub conn_est_fail_offset_validity_s: u16,
    pub conn_est_fail_offset: Option<u8>,
}

/// `SIB-TypeInfo ::= SEQUENCE { type ENUMERATED { sibType2, …, sibType9, sibType10-v1610,
/// …, sibType14-v1610, spare3, spare2, spare1, ... }, valueTag INTEGER (0..31) OPTIONAL,
/// areaScope ENUMERATED { true } OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SibTypeInfo {
    /// SIB number (2..=14); `None` for a spare or extended value.
    pub sib_type: Option<u8>,
    pub value_tag: Option<u8>,
    pub area_scope: bool,
}

/// `SchedulingInfo ::= SEQUENCE { si-BroadcastStatus ENUMERATED { broadcasting, notBroadcasting },
/// si-Periodicity ENUMERATED { rf8, rf16, rf32, rf64, rf128, rf256, rf512 },
/// sib-MappingInfo SIB-Mapping }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulingInfo {
    pub si_broadcasting: bool,
    pub si_periodicity_rf: u16,
    pub sib_mapping_info: Vec<SibTypeInfo>,
}

/// `SI-SchedulingInfo ::= SEQUENCE { schedulingInfoList SEQUENCE (SIZE (1..maxSI-Message)) OF
/// SchedulingInfo, si-WindowLength ENUMERATED { s5, s10, s20, s40, s80, s160, s320, s640,
/// s1280, s2560-v1710, s5120-v1710 }, si-RequestConfig SI-RequestConfig OPTIONAL,
/// si-RequestConfigSUL OPTIONAL, systemInformationAreaID BIT STRING (SIZE (24)) OPTIONAL, ... }`.
/// The SI-request configurations are walked but only their presence is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiSchedulingInfo {
    pub scheduling_info_list: Vec<SchedulingInfo>,
    pub si_window_length_slots: u16,
    pub si_request_config_present: bool,
    pub si_request_config_sul_present: bool,
    pub system_information_area_id: Option<u32>,
}

/// `NR-NS-PmaxValue ::= SEQUENCE { additionalPmax P-Max OPTIONAL, additionalSpectrumEmission
/// AdditionalSpectrumEmission }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NrNsPmaxValue {
    pub additional_pmax: Option<i8>,
    pub additional_spectrum_emission: u8,
}

/// `NR-MultiBandInfo ::= SEQUENCE { freqBandIndicatorNR FreqBandIndicatorNR OPTIONAL,
/// nr-NS-PmaxList NR-NS-PmaxList OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NrMultiBandInfo {
    pub freq_band_indicator_nr: Option<u16>,
    pub nr_ns_pmax_list: Vec<NrNsPmaxValue>,
}

/// `FrequencyInfoDL-SIB ::= SEQUENCE { frequencyBandList MultiFrequencyBandListNR-SIB,
/// offsetToPointA INTEGER (0..2199), scs-SpecificCarrierList SEQUENCE (SIZE (1..maxSCSs)) OF
/// SCS-SpecificCarrier }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrequencyInfoDlSib {
    pub frequency_band_list: Vec<NrMultiBandInfo>,
    pub offset_to_point_a: u16,
    pub scs_specific_carrier_list: Vec<ScsSpecificCarrier>,
}

/// `PDCCH-ConfigCommon ::= SEQUENCE { controlResourceSetZero ControlResourceSetZero OPTIONAL,
/// commonControlResourceSet ControlResourceSet OPTIONAL, searchSpaceZero SearchSpaceZero
/// OPTIONAL, commonSearchSpaceList SEQUENCE (SIZE(1..4)) OF SearchSpace OPTIONAL,
/// searchSpaceSIB1 SearchSpaceId OPTIONAL, searchSpaceOtherSystemInformation SearchSpaceId
/// OPTIONAL, pagingSearchSpace SearchSpaceId OPTIONAL, ra-SearchSpace SearchSpaceId OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PdcchConfigCommon {
    pub control_resource_set_zero: Option<u8>,
    pub common_control_resource_set: Option<ControlResourceSet>,
    pub search_space_zero: Option<u8>,
    pub common_search_space_list: Vec<SearchSpace>,
    pub search_space_sib1: Option<u8>,
    pub search_space_other_system_information: Option<u8>,
    pub paging_search_space: Option<u8>,
    pub ra_search_space: Option<u8>,
}

impl PdcchConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<8>()?;
        let control_resource_set_zero = r.opt(o[0], |r| r.u8(0, 15))?;
        let common_control_resource_set = r
            .opt(o[1], ControlResourceSet::decode)
            .ctx("commonControlResourceSet")?;
        let search_space_zero = r.opt(o[2], |r| r.u8(0, 15))?;
        let common_search_space_list = if o[3] {
            r.seq_of(1, 4, SearchSpace::decode)
                .ctx("commonSearchSpaceList")?
        } else {
            vec![]
        };
        let search_space_sib1 = r.opt(o[4], |r| r.u8(0, 39))?;
        let search_space_other_system_information = r.opt(o[5], |r| r.u8(0, 39))?;
        let paging_search_space = r.opt(o[6], |r| r.u8(0, 39))?;
        let ra_search_space = r.opt(o[7], |r| r.u8(0, 39))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            control_resource_set_zero,
            common_control_resource_set,
            search_space_zero,
            common_search_space_list,
            search_space_sib1,
            search_space_other_system_information,
            paging_search_space,
            ra_search_space,
        })
    }
}

/// `PDSCH-ConfigCommon ::= SEQUENCE { pdsch-TimeDomainAllocationList
/// PDSCH-TimeDomainResourceAllocationList OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PdschConfigCommon {
    pub pdsch_time_domain_allocation_list: Vec<TdraRow>,
}

impl PdschConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_list] = r.opt_bits::<1>()?;
        let list = if has_list {
            decode_tdra_list(r)?
        } else {
            vec![]
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            pdsch_time_domain_allocation_list: list,
        })
    }
}

/// `BWP-DownlinkCommon ::= SEQUENCE { genericParameters BWP, pdcch-ConfigCommon
/// SetupRelease { PDCCH-ConfigCommon } OPTIONAL, pdsch-ConfigCommon SetupRelease
/// { PDSCH-ConfigCommon } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpDownlinkCommon {
    pub generic_parameters: Bwp,
    pub pdcch_config_common: Option<SetupRelease<PdcchConfigCommon>>,
    pub pdsch_config_common: Option<SetupRelease<PdschConfigCommon>>,
}

impl BwpDownlinkCommon {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_pdcch, has_pdsch] = r.opt_bits::<2>()?;
        let generic_parameters = Bwp::decode(r).ctx("genericParameters")?;
        let pdcch_config_common = r
            .opt(has_pdcch, |r| r.setup_release(PdcchConfigCommon::decode))
            .ctx("pdcch-ConfigCommon")?;
        let pdsch_config_common = r
            .opt(has_pdsch, |r| r.setup_release(PdschConfigCommon::decode))
            .ctx("pdsch-ConfigCommon")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            generic_parameters,
            pdcch_config_common,
            pdsch_config_common,
        })
    }
}

/// `BCCH-Config ::= SEQUENCE { modificationPeriodCoeff ENUMERATED { n2, n4, n8, n16 }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BcchConfig {
    pub modification_period_coeff: u8,
}

/// `nAndPagingFrameOffset CHOICE { oneT NULL, halfT INTEGER (0..1), quarterT INTEGER (0..3),
/// oneEighthT INTEGER (0..7), oneSixteenthT INTEGER (0..15) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingFrameOffset {
    OneT,
    HalfT(u8),
    QuarterT(u8),
    OneEighthT(u8),
    OneSixteenthT(u8),
}

/// `firstPDCCH-MonitoringOccasionOfPO CHOICE { sCS15KHZoneT SEQUENCE (SIZE (1..maxPO-perPF))
/// OF INTEGER (0..139), sCS30KHZoneT-SCS15KHZhalfT … (0..279), … (0..559), … (0..1119),
/// … (0..2239), … (0..4479), … (0..8959), … (0..17919) }`: the alternative index and the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstPdcchMonitoringOccasionOfPo {
    pub alternative: u8,
    pub occasions: Vec<u16>,
}

impl FirstPdcchMonitoringOccasionOfPo {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        const HI: [u16; 8] = [139, 279, 559, 1119, 2239, 4479, 8959, 17919];
        let alternative = r.u8(0, 7)?;
        let hi = HI[alternative as usize];
        let occasions = r.seq_of(1, 4, |r| r.u16(0, hi))?;
        Ok(Self {
            alternative,
            occasions,
        })
    }
}

/// `PCCH-Config ::= SEQUENCE { defaultPagingCycle PagingCycle, nAndPagingFrameOffset CHOICE
/// {…}, ns ENUMERATED { four, two, one }, firstPDCCH-MonitoringOccasionOfPO CHOICE {…}
/// OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcchConfig {
    /// `PagingCycle ::= ENUMERATED { rf32, rf64, rf128, rf256 }` in radio frames.
    pub default_paging_cycle_rf: u16,
    pub n_and_paging_frame_offset: PagingFrameOffset,
    pub ns: u8,
    pub first_pdcch_monitoring_occasion_of_po: Option<FirstPdcchMonitoringOccasionOfPo>,
}

/// `DownlinkConfigCommonSIB ::= SEQUENCE { frequencyInfoDL FrequencyInfoDL-SIB,
/// initialDownlinkBWP BWP-DownlinkCommon, bcch-Config BCCH-Config, pcch-Config PCCH-Config, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownlinkConfigCommonSib {
    pub frequency_info_dl: FrequencyInfoDlSib,
    pub initial_downlink_bwp: BwpDownlinkCommon,
    pub bcch_config: BcchConfig,
    pub pcch_config: PcchConfig,
}

/// `FrequencyInfoUL-SIB ::= SEQUENCE { frequencyBandList MultiFrequencyBandListNR-SIB
/// OPTIONAL, absoluteFrequencyPointA ARFCN-ValueNR OPTIONAL, scs-SpecificCarrierList
/// SEQUENCE (SIZE (1..maxSCSs)) OF SCS-SpecificCarrier, p-Max P-Max OPTIONAL,
/// frequencyShift7p5khz ENUMERATED { true } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrequencyInfoUlSib {
    pub frequency_band_list: Vec<NrMultiBandInfo>,
    pub absolute_frequency_point_a: Option<u32>,
    pub scs_specific_carrier_list: Vec<ScsSpecificCarrier>,
    pub p_max: Option<i8>,
    pub frequency_shift_7p5khz: bool,
}

/// `RACH-ConfigGeneric ::= SEQUENCE { prach-ConfigurationIndex INTEGER (0..255), msg1-FDM
/// ENUMERATED { one, two, four, eight }, msg1-FrequencyStart INTEGER (0..maxNrofPhysicalResourceBlocks-1),
/// zeroCorrelationZoneConfig INTEGER (0..15), preambleReceivedTargetPower INTEGER (-202..-60),
/// preambleTransMax ENUMERATED { n3, n4, n5, n6, n7, n8, n10, n20, n50, n100, n200 },
/// powerRampingStep ENUMERATED { dB0, dB2, dB4, dB6 }, ra-ResponseWindow ENUMERATED { sl1, sl2,
/// sl4, sl8, sl10, sl20, sl40, sl80 }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RachConfigGeneric {
    pub prach_configuration_index: u8,
    pub msg1_fdm: u8,
    pub msg1_frequency_start: u16,
    pub zero_correlation_zone_config: u8,
    pub preamble_received_target_power: i16,
    pub preamble_trans_max: u8,
    pub power_ramping_step_db: u8,
    pub ra_response_window_slots: u8,
}

/// `ssb-perRACH-OccasionAndCB-PreamblesPerSSB CHOICE { oneEighth ENUMERATED { n4, n8, …, n64 },
/// oneFourth …, oneHalf …, one …, two ENUMERATED { n4, …, n32 }, four INTEGER (1..16),
/// eight INTEGER (1..8), sixteen INTEGER (1..4) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsbPerRachOccasion {
    OneEighth,
    OneFourth,
    OneHalf,
    One,
    Two,
    Four,
    Eight,
    Sixteen,
}

impl SsbPerRachOccasion {
    /// Number of SSBs per RACH occasion, as a rational `(num, den)`.
    pub fn ratio(self) -> (u8, u8) {
        match self {
            Self::OneEighth => (1, 8),
            Self::OneFourth => (1, 4),
            Self::OneHalf => (1, 2),
            Self::One => (1, 1),
            Self::Two => (2, 1),
            Self::Four => (4, 1),
            Self::Eight => (8, 1),
            Self::Sixteen => (16, 1),
        }
    }
}

/// `groupBconfigured SEQUENCE { ra-Msg3SizeGroupA ENUMERATED { b56, b144, b208, b256, b282,
/// b480, b640, b800, b1000, b72, spare6..spare1 }, messagePowerOffsetGroupB ENUMERATED
/// { minusinfinity, dB0, dB5, dB8, dB10, dB12, dB15, dB18 }, numberOfRA-PreamblesGroupA
/// INTEGER (1..64) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupBConfigured {
    /// Msg3 size threshold in bits (0 for a spare value).
    pub ra_msg3_size_group_a_bits: u16,
    /// `None` is `minusinfinity`.
    pub message_power_offset_group_b_db: Option<u8>,
    pub number_of_ra_preambles_group_a: u8,
}

/// `prach-RootSequenceIndex CHOICE { l839 INTEGER (0..837), l139 INTEGER (0..137) }`
/// (the Rel-16 `l571`/`l1151` alternatives live in an extension addition and are not kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrachRootSequenceIndex {
    L839(u16),
    L139(u8),
}

/// `restrictedSetConfig ENUMERATED { unrestrictedSet, restrictedSetTypeA, restrictedSetTypeB }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestrictedSetConfig {
    UnrestrictedSet,
    RestrictedSetTypeA,
    RestrictedSetTypeB,
}

/// `RACH-ConfigCommon ::= SEQUENCE { rach-ConfigGeneric RACH-ConfigGeneric,
/// totalNumberOfRA-Preambles INTEGER (1..63) OPTIONAL, ssb-perRACH-OccasionAndCB-PreamblesPerSSB
/// CHOICE {…} OPTIONAL, groupBconfigured SEQUENCE {…} OPTIONAL, ra-ContentionResolutionTimer
/// ENUMERATED { sf8, sf16, sf24, sf32, sf40, sf48, sf56, sf64 }, rsrp-ThresholdSSB RSRP-Range
/// OPTIONAL, rsrp-ThresholdSSB-SUL RSRP-Range OPTIONAL, prach-RootSequenceIndex CHOICE {…},
/// msg1-SubcarrierSpacing SubcarrierSpacing OPTIONAL, restrictedSetConfig ENUMERATED {…},
/// msg3-transformPrecoder ENUMERATED { enabled } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RachConfigCommon {
    pub rach_config_generic: RachConfigGeneric,
    pub total_number_of_ra_preambles: Option<u8>,
    /// `(ssb-perRACH-Occasion, CB-PreamblesPerSSB)`.
    pub ssb_per_rach_occasion_and_cb_preambles_per_ssb: Option<(SsbPerRachOccasion, u8)>,
    pub group_b_configured: Option<GroupBConfigured>,
    pub ra_contention_resolution_timer_sf: u8,
    pub rsrp_threshold_ssb: Option<u8>,
    pub rsrp_threshold_ssb_sul: Option<u8>,
    pub prach_root_sequence_index: PrachRootSequenceIndex,
    pub msg1_subcarrier_spacing: Option<SubcarrierSpacing>,
    pub restricted_set_config: RestrictedSetConfig,
    pub msg3_transform_precoder: bool,
}

impl RachConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<7>()?;
        let rach_config_generic = {
            let gext = r.bit()?;
            let prach_configuration_index = r.u8(0, 255)?;
            let msg1_fdm = 1u8 << r.enu(4)?;
            let msg1_frequency_start = r.u16(0, 274)?;
            let zero_correlation_zone_config = r.u8(0, 15)?;
            let preamble_received_target_power = r.int(-202, -60)? as i16;
            const TRANS_MAX: [u8; 11] = [3, 4, 5, 6, 7, 8, 10, 20, 50, 100, 200];
            let preamble_trans_max = TRANS_MAX[r.enu(11)? as usize];
            let power_ramping_step_db = 2 * r.enu(4)? as u8;
            const RAR_WINDOW: [u8; 8] = [1, 2, 4, 8, 10, 20, 40, 80];
            let ra_response_window_slots = RAR_WINDOW[r.enu(8)? as usize];
            if gext {
                r.skip_ext_additions()?;
            }
            RachConfigGeneric {
                prach_configuration_index,
                msg1_fdm,
                msg1_frequency_start,
                zero_correlation_zone_config,
                preamble_received_target_power,
                preamble_trans_max,
                power_ramping_step_db,
                ra_response_window_slots,
            }
        };
        let total_number_of_ra_preambles = r.opt(o[0], |r| r.u8(1, 63))?;
        let ssb_per_rach_occasion_and_cb_preambles_per_ssb = r.opt(o[1], |r| {
            Ok(match r.uint(0, 7)? {
                0 => (SsbPerRachOccasion::OneEighth, 4 * (r.enu(16)? as u8 + 1)),
                1 => (SsbPerRachOccasion::OneFourth, 4 * (r.enu(16)? as u8 + 1)),
                2 => (SsbPerRachOccasion::OneHalf, 4 * (r.enu(16)? as u8 + 1)),
                3 => (SsbPerRachOccasion::One, 4 * (r.enu(16)? as u8 + 1)),
                4 => (SsbPerRachOccasion::Two, 4 * (r.enu(8)? as u8 + 1)),
                5 => (SsbPerRachOccasion::Four, r.u8(1, 16)?),
                6 => (SsbPerRachOccasion::Eight, r.u8(1, 8)?),
                _ => (SsbPerRachOccasion::Sixteen, r.u8(1, 4)?),
            })
        })?;
        let group_b_configured = r.opt(o[2], |r| {
            const SIZES: [u16; 16] = [
                56, 144, 208, 256, 282, 480, 640, 800, 1000, 72, 0, 0, 0, 0, 0, 0,
            ];
            let ra_msg3_size_group_a_bits = SIZES[r.enu(16)? as usize];
            const OFFSETS: [Option<u8>; 8] = [
                None,
                Some(0),
                Some(5),
                Some(8),
                Some(10),
                Some(12),
                Some(15),
                Some(18),
            ];
            let message_power_offset_group_b_db = OFFSETS[r.enu(8)? as usize];
            let number_of_ra_preambles_group_a = r.u8(1, 64)?;
            Ok(GroupBConfigured {
                ra_msg3_size_group_a_bits,
                message_power_offset_group_b_db,
                number_of_ra_preambles_group_a,
            })
        })?;
        let ra_contention_resolution_timer_sf = 8 * (r.enu(8)? as u8 + 1);
        let rsrp_threshold_ssb = r.opt(o[3], |r| r.u8(0, 127))?;
        let rsrp_threshold_ssb_sul = r.opt(o[4], |r| r.u8(0, 127))?;
        let prach_root_sequence_index = if !r.bit()? {
            PrachRootSequenceIndex::L839(r.u16(0, 837)?)
        } else {
            PrachRootSequenceIndex::L139(r.u8(0, 137)?)
        };
        let msg1_subcarrier_spacing = r.opt(o[5], SubcarrierSpacing::decode)?;
        let restricted_set_config = match r.enu(3)? {
            0 => RestrictedSetConfig::UnrestrictedSet,
            1 => RestrictedSetConfig::RestrictedSetTypeA,
            _ => RestrictedSetConfig::RestrictedSetTypeB,
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            rach_config_generic,
            total_number_of_ra_preambles,
            ssb_per_rach_occasion_and_cb_preambles_per_ssb,
            group_b_configured,
            ra_contention_resolution_timer_sf,
            rsrp_threshold_ssb,
            rsrp_threshold_ssb_sul,
            prach_root_sequence_index,
            msg1_subcarrier_spacing,
            restricted_set_config,
            msg3_transform_precoder: o[6],
        })
    }
}

/// `PUSCH-ConfigCommon ::= SEQUENCE { groupHoppingEnabledTransformPrecoding ENUMERATED
/// { enabled } OPTIONAL, pusch-TimeDomainAllocationList PUSCH-TimeDomainResourceAllocationList
/// OPTIONAL, msg3-DeltaPreamble INTEGER (-1..6) OPTIONAL, p0-NominalWithGrant INTEGER
/// (-202..24) OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PuschConfigCommon {
    pub group_hopping_enabled_transform_precoding: bool,
    pub pusch_time_domain_allocation_list: Vec<TdraRow>,
    pub msg3_delta_preamble: Option<i8>,
    pub p0_nominal_with_grant: Option<i16>,
}

impl PuschConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [gh, has_list, has_msg3, has_p0] = r.opt_bits::<4>()?;
        let list = if has_list {
            decode_tdra_list(r)?
        } else {
            vec![]
        };
        let msg3_delta_preamble = r.opt(has_msg3, |r| Ok(r.int(-1, 6)? as i8))?;
        let p0_nominal_with_grant = r.opt(has_p0, |r| Ok(r.int(-202, 24)? as i16))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            group_hopping_enabled_transform_precoding: gh,
            pusch_time_domain_allocation_list: list,
            msg3_delta_preamble,
            p0_nominal_with_grant,
        })
    }
}

/// `pucch-GroupHopping ENUMERATED { neither, enable, disable }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PucchGroupHopping {
    Neither,
    Enable,
    Disable,
}

/// `PUCCH-ConfigCommon ::= SEQUENCE { pucch-ResourceCommon INTEGER (0..15) OPTIONAL,
/// pucch-GroupHopping ENUMERATED {…}, hoppingId INTEGER (0..1023) OPTIONAL, p0-nominal
/// INTEGER (-202..24) OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchConfigCommon {
    pub pucch_resource_common: Option<u8>,
    pub pucch_group_hopping: PucchGroupHopping,
    pub hopping_id: Option<u16>,
    pub p0_nominal: Option<i16>,
}

impl PucchConfigCommon {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_res, has_hop, has_p0] = r.opt_bits::<3>()?;
        let pucch_resource_common = r.opt(has_res, |r| r.u8(0, 15))?;
        let pucch_group_hopping = match r.enu(3)? {
            0 => PucchGroupHopping::Neither,
            1 => PucchGroupHopping::Enable,
            _ => PucchGroupHopping::Disable,
        };
        let hopping_id = r.opt(has_hop, |r| r.u16(0, 1023))?;
        let p0_nominal = r.opt(has_p0, |r| Ok(r.int(-202, 24)? as i16))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            pucch_resource_common,
            pucch_group_hopping,
            hopping_id,
            p0_nominal,
        })
    }
}

/// `BWP-UplinkCommon ::= SEQUENCE { genericParameters BWP, rach-ConfigCommon SetupRelease
/// { RACH-ConfigCommon } OPTIONAL, pusch-ConfigCommon SetupRelease { PUSCH-ConfigCommon }
/// OPTIONAL, pucch-ConfigCommon SetupRelease { PUCCH-ConfigCommon } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpUplinkCommon {
    pub generic_parameters: Bwp,
    pub rach_config_common: Option<SetupRelease<RachConfigCommon>>,
    pub pusch_config_common: Option<SetupRelease<PuschConfigCommon>>,
    pub pucch_config_common: Option<SetupRelease<PucchConfigCommon>>,
}

impl BwpUplinkCommon {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_rach, has_pusch, has_pucch] = r.opt_bits::<3>()?;
        let generic_parameters = Bwp::decode(r).ctx("genericParameters")?;
        let rach_config_common = r
            .opt(has_rach, |r| r.setup_release(RachConfigCommon::decode))
            .ctx("rach-ConfigCommon")?;
        let pusch_config_common = r
            .opt(has_pusch, |r| r.setup_release(PuschConfigCommon::decode))
            .ctx("pusch-ConfigCommon")?;
        let pucch_config_common = r
            .opt(has_pucch, |r| r.setup_release(PucchConfigCommon::decode))
            .ctx("pucch-ConfigCommon")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            generic_parameters,
            rach_config_common,
            pusch_config_common,
            pucch_config_common,
        })
    }
}

/// `UplinkConfigCommonSIB ::= SEQUENCE { frequencyInfoUL FrequencyInfoUL-SIB, initialUplinkBWP
/// BWP-UplinkCommon, timeAlignmentTimerCommon TimeAlignmentTimer }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkConfigCommonSib {
    pub frequency_info_ul: FrequencyInfoUlSib,
    pub initial_uplink_bwp: BwpUplinkCommon,
    pub time_alignment_timer_common: TimeAlignmentTimer,
}

impl UplinkConfigCommonSib {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let frequency_info_ul = {
            // FrequencyInfoUL-SIB is extensible (unlike FrequencyInfoDL-SIB) — verified
            // bit-exactly against the live capture.
            let ext = r.bit()?;
            let [has_bands, has_arfcn, has_pmax, has_shift] = r.opt_bits::<4>()?;
            let frequency_band_list = if has_bands {
                decode_multi_band_list(r)?
            } else {
                vec![]
            };
            let absolute_frequency_point_a = r.opt(has_arfcn, |r| r.uint(0, 3279165))?;
            let scs_specific_carrier_list = r.seq_of(1, 5, ScsSpecificCarrier::decode)?;
            let p_max = r.opt(has_pmax, |r| Ok(r.int(-30, 33)? as i8))?;
            if ext {
                r.skip_ext_additions()?;
            }
            FrequencyInfoUlSib {
                frequency_band_list,
                absolute_frequency_point_a,
                scs_specific_carrier_list,
                p_max,
                frequency_shift_7p5khz: has_shift,
            }
        };
        let initial_uplink_bwp = BwpUplinkCommon::decode(r).ctx("initialUplinkBWP")?;
        let time_alignment_timer_common = TimeAlignmentTimer::decode(r)?;
        Ok(Self {
            frequency_info_ul,
            initial_uplink_bwp,
            time_alignment_timer_common,
        })
    }
}

/// `MultiFrequencyBandListNR-SIB ::= SEQUENCE (SIZE (1..maxNrofMultiBands)) OF NR-MultiBandInfo`.
fn decode_multi_band_list(r: &mut BitReader) -> DecodeResult<Vec<NrMultiBandInfo>> {
    r.seq_of(1, 8, |r| {
        let [has_band, has_pmax] = r.opt_bits::<2>()?;
        let freq_band_indicator_nr = r.opt(has_band, |r| r.u16(1, 1024))?;
        let nr_ns_pmax_list = if has_pmax {
            r.seq_of(1, 8, |r| {
                let [has_pm] = r.opt_bits::<1>()?;
                let additional_pmax = r.opt(has_pm, |r| Ok(r.int(-30, 33)? as i8))?;
                let additional_spectrum_emission = r.u8(0, 7)?;
                Ok(NrNsPmaxValue {
                    additional_pmax,
                    additional_spectrum_emission,
                })
            })?
        } else {
            vec![]
        };
        Ok(NrMultiBandInfo {
            freq_band_indicator_nr,
            nr_ns_pmax_list,
        })
    })
}

/// `ssb-PositionsInBurst SEQUENCE { inOneGroup BIT STRING (SIZE (8)), groupPresence BIT STRING
/// (SIZE (8)) OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsbPositionsInBurst {
    /// MSB = SSB index 0 of the group.
    pub in_one_group: u8,
    /// Present for L_max = 64 (FR2); MSB = group 0.
    pub group_presence: Option<u8>,
}

impl SsbPositionsInBurst {
    /// Whether SSB index `i` is transmitted (short/medium/long bitmap semantics
    /// per TS 38.331 `ssb-PositionsInBurst` for `L_max` of 4/8/64).
    pub fn is_transmitted(&self, i: u8, l_max: u8) -> bool {
        match (l_max, self.group_presence) {
            (64, Some(gp)) => {
                let (g, k) = (i / 8, i % 8);
                g < 8 && gp & (0x80 >> g) != 0 && self.in_one_group & (0x80 >> k) != 0
            }
            _ => i < l_max.min(8) && self.in_one_group & (0x80 >> i) != 0,
        }
    }
}

/// `ServingCellConfigCommonSIB ::= SEQUENCE { downlinkConfigCommon DownlinkConfigCommonSIB,
/// uplinkConfigCommon UplinkConfigCommonSIB OPTIONAL, supplementaryUplink UplinkConfigCommonSIB
/// OPTIONAL, n-TimingAdvanceOffset ENUMERATED { n0, n25600, n39936 } OPTIONAL,
/// ssb-PositionsInBurst SEQUENCE {…}, ssb-PeriodicityServingCell ENUMERATED { ms5, ms10, ms20,
/// ms40, ms80, ms160 }, tdd-UL-DL-ConfigurationCommon TDD-UL-DL-ConfigCommon OPTIONAL,
/// ss-PBCH-BlockPower INTEGER (-60..50), ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServingCellConfigCommonSib {
    pub downlink_config_common: DownlinkConfigCommonSib,
    pub uplink_config_common: Option<UplinkConfigCommonSib>,
    pub supplementary_uplink: Option<UplinkConfigCommonSib>,
    /// `n-TimingAdvanceOffset` in units of `T_c`, when signalled (FR1 default: 25600).
    pub n_timing_advance_offset: Option<u32>,
    pub ssb_positions_in_burst: SsbPositionsInBurst,
    pub ssb_periodicity_ms: u8,
    /// Absent on FDD cells.
    pub tdd_ul_dl_configuration_common: Option<TddUlDlConfigCommon>,
    pub ss_pbch_block_power: i8,
}

impl ServingCellConfigCommonSib {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_ul, has_sul, has_nta, has_tdd] = r.opt_bits::<4>()?;
        let downlink_config_common = Self::decode_dl(r).ctx("downlinkConfigCommon")?;
        let uplink_config_common = r
            .opt(has_ul, UplinkConfigCommonSib::decode)
            .ctx("uplinkConfigCommon")?;
        let supplementary_uplink = r
            .opt(has_sul, UplinkConfigCommonSib::decode)
            .ctx("supplementaryUplink")?;
        let n_timing_advance_offset =
            r.opt(has_nta, |r| Ok([0u32, 25600, 39936][r.enu(3)? as usize]))?;
        let ssb_positions_in_burst = {
            let [has_group] = r.opt_bits::<1>()?;
            let in_one_group = r.bitstring(8)? as u8;
            let group_presence = r.opt(has_group, |r| Ok(r.bitstring(8)? as u8))?;
            SsbPositionsInBurst {
                in_one_group,
                group_presence,
            }
        };
        let ssb_periodicity_ms = 5u8 << r.enu(6)?;
        let tdd_ul_dl_configuration_common = r
            .opt(has_tdd, TddUlDlConfigCommon::decode)
            .ctx("tdd-UL-DL-ConfigurationCommon")?;
        let ss_pbch_block_power = r.int(-60, 50)? as i8;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            downlink_config_common,
            uplink_config_common,
            supplementary_uplink,
            n_timing_advance_offset,
            ssb_positions_in_burst,
            ssb_periodicity_ms,
            tdd_ul_dl_configuration_common,
            ss_pbch_block_power,
        })
    }

    fn decode_dl(r: &mut BitReader) -> DecodeResult<DownlinkConfigCommonSib> {
        let ext = r.bit()?;
        let frequency_info_dl = {
            let frequency_band_list = decode_multi_band_list(r).ctx("frequencyBandList")?;
            let offset_to_point_a = r.u16(0, 2199)?;
            let scs_specific_carrier_list = r.seq_of(1, 5, ScsSpecificCarrier::decode)?;
            FrequencyInfoDlSib {
                frequency_band_list,
                offset_to_point_a,
                scs_specific_carrier_list,
            }
        };
        let initial_downlink_bwp = BwpDownlinkCommon::decode(r).ctx("initialDownlinkBWP")?;
        let bcch_config = {
            let e = r.bit()?;
            let modification_period_coeff = 2u8 << r.enu(4)?;
            if e {
                r.skip_ext_additions()?;
            }
            BcchConfig {
                modification_period_coeff,
            }
        };
        let pcch_config = {
            let e = r.bit()?;
            let [has_first] = r.opt_bits::<1>()?;
            let default_paging_cycle_rf = 32u16 << r.enu(4)?;
            let n_and_paging_frame_offset = match r.uint(0, 4)? {
                0 => PagingFrameOffset::OneT,
                1 => PagingFrameOffset::HalfT(r.u8(0, 1)?),
                2 => PagingFrameOffset::QuarterT(r.u8(0, 3)?),
                3 => PagingFrameOffset::OneEighthT(r.u8(0, 7)?),
                _ => PagingFrameOffset::OneSixteenthT(r.u8(0, 15)?),
            };
            let ns = [4u8, 2, 1][r.enu(3)? as usize];
            let first_pdcch_monitoring_occasion_of_po =
                r.opt(has_first, FirstPdcchMonitoringOccasionOfPo::decode)?;
            if e {
                r.skip_ext_additions()?;
            }
            PcchConfig {
                default_paging_cycle_rf,
                n_and_paging_frame_offset,
                ns,
                first_pdcch_monitoring_occasion_of_po,
            }
        };
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(DownlinkConfigCommonSib {
            frequency_info_dl,
            initial_downlink_bwp,
            bcch_config,
            pcch_config,
        })
    }
}

/// `UE-TimersAndConstants ::= SEQUENCE { t300 ENUMERATED { ms100, ms200, ms300, ms400, ms600,
/// ms1000, ms1500, ms2000 }, t301 …, t310 ENUMERATED { ms0, ms50, ms100, ms200, ms500, ms1000,
/// ms2000 }, n310 ENUMERATED { n1, n2, n3, n4, n6, n8, n10, n20 }, t311
/// ENUMERATED { ms1000, ms3000, ms5000, ms10000, ms15000, ms20000, ms30000 }, n311 ENUMERATED
/// { n1, n2, n3, n4, n5, n6, n8, n10 }, t319 ENUMERATED { ms100, …, ms2000 }, ... }` — all in ms / counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UeTimersAndConstants {
    pub t300_ms: u16,
    pub t301_ms: u16,
    pub t310_ms: u16,
    pub n310: u8,
    pub t311_ms: u16,
    pub n311: u8,
    pub t319_ms: u16,
}

impl UeTimersAndConstants {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        const T3XX: [u16; 8] = [100, 200, 300, 400, 600, 1000, 1500, 2000];
        const T310: [u16; 7] = [0, 50, 100, 200, 500, 1000, 2000];
        const N310: [u8; 8] = [1, 2, 3, 4, 6, 8, 10, 20];
        const T311: [u16; 7] = [1000, 3000, 5000, 10000, 15000, 20000, 30000];
        const N311: [u8; 8] = [1, 2, 3, 4, 5, 6, 8, 10];
        let ext = r.bit()?;
        let t300_ms = T3XX[r.enu(8)? as usize];
        let t301_ms = T3XX[r.enu(8)? as usize];
        let t310_ms = T310[r.enu(7)? as usize];
        let n310 = N310[r.enu(8)? as usize];
        let t311_ms = T311[r.enu(7)? as usize];
        let n311 = N311[r.enu(8)? as usize];
        let t319_ms = T3XX[r.enu(8)? as usize];
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            t300_ms,
            t301_ms,
            t310_ms,
            n310,
            t311_ms,
            n311,
            t319_ms,
        })
    }
}

/// `UAC-BarringPerCat ::= SEQUENCE { accessCategory INTEGER (1..maxAccessCat-1),
/// uac-barringInfoSetIndex UAC-BarringInfoSetIndex }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UacBarringPerCat {
    pub access_category: u8,
    pub uac_barring_info_set_index: u8,
}

/// `uac-ACBarringListType CHOICE { uac-ImplicitACBarringList SEQUENCE (SIZE (maxAccessCat-1))
/// OF UAC-BarringInfoSetIndex, uac-ExplicitACBarringList UAC-BarringPerCatList }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UacAcBarringListType {
    Implicit(Vec<u8>),
    Explicit(Vec<UacBarringPerCat>),
}

/// `UAC-BarringPerPLMN ::= SEQUENCE { plmn-IdentityIndex INTEGER (1..maxPLMN),
/// uac-ACBarringListType CHOICE {…} OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacBarringPerPlmn {
    pub plmn_identity_index: u8,
    pub uac_ac_barring_list_type: Option<UacAcBarringListType>,
}

/// `UAC-BarringInfoSet ::= SEQUENCE { uac-BarringFactor ENUMERATED { p00, p05, p10, p15, p20,
/// p25, p30, p40, p50, p60, p70, p75, p80, p85, p90, p95 }, uac-BarringTime ENUMERATED { s4, s8,
/// s16, s32, s64, s128, s256, s512 }, uac-BarringForAccessIdentity BIT STRING (SIZE(7)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UacBarringInfoSet {
    /// Barring factor × 100 (0, 5, 10, … 95).
    pub uac_barring_factor_percent: u8,
    pub uac_barring_time_s: u16,
    /// 7-bit mask, MSB = access identity 1.
    pub uac_barring_for_access_identity: u8,
}

/// `uac-AccessCategory1-SelectionAssistanceInfo CHOICE { plmnCommon
/// UAC-AccessCategory1-SelectionAssistanceInfo, individualPLMNList SEQUENCE (SIZE (2..maxPLMN))
/// OF UAC-AccessCategory1-SelectionAssistanceInfo }` with values `ENUMERATED { a, b, c }` as 0/1/2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UacAccessCategory1SelectionAssistanceInfo {
    PlmnCommon(u8),
    IndividualPlmnList(Vec<u8>),
}

/// `uac-BarringInfo SEQUENCE { uac-BarringForCommon UAC-BarringPerCatList OPTIONAL,
/// uac-BarringPerPLMN-List UAC-BarringPerPLMN-List OPTIONAL, uac-BarringInfoSetList
/// UAC-BarringInfoSetList, uac-AccessCategory1-SelectionAssistanceInfo CHOICE {…} OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UacBarringInfo {
    pub uac_barring_for_common: Vec<UacBarringPerCat>,
    pub uac_barring_per_plmn_list: Vec<UacBarringPerPlmn>,
    pub uac_barring_info_set_list: Vec<UacBarringInfoSet>,
    pub uac_access_category1_selection_assistance_info:
        Option<UacAccessCategory1SelectionAssistanceInfo>,
}

impl UacBarringInfo {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let [has_common, has_per_plmn, has_ac1] = r.opt_bits::<3>()?;
        let per_cat = |r: &mut BitReader| {
            Ok(UacBarringPerCat {
                access_category: r.u8(1, 63)?,
                uac_barring_info_set_index: r.u8(1, 8)?,
            })
        };
        let uac_barring_for_common = if has_common {
            r.seq_of(1, 63, per_cat)?
        } else {
            vec![]
        };
        let uac_barring_per_plmn_list = if has_per_plmn {
            r.seq_of(1, 12, |r| {
                let [has_type] = r.opt_bits::<1>()?;
                let plmn_identity_index = r.u8(1, 12)?;
                let uac_ac_barring_list_type = r.opt(has_type, |r| {
                    Ok(if !r.bit()? {
                        let mut v = Vec::with_capacity(63);
                        for _ in 0..63 {
                            v.push(r.u8(1, 8)?);
                        }
                        UacAcBarringListType::Implicit(v)
                    } else {
                        UacAcBarringListType::Explicit(r.seq_of(1, 63, per_cat)?)
                    })
                })?;
                Ok(UacBarringPerPlmn {
                    plmn_identity_index,
                    uac_ac_barring_list_type,
                })
            })?
        } else {
            vec![]
        };
        let uac_barring_info_set_list = r.seq_of(1, 8, |r| {
            const FACTOR: [u8; 16] = [0, 5, 10, 15, 20, 25, 30, 40, 50, 60, 70, 75, 80, 85, 90, 95];
            let uac_barring_factor_percent = FACTOR[r.enu(16)? as usize];
            let uac_barring_time_s = 4u16 << r.enu(8)?;
            let uac_barring_for_access_identity = r.bitstring(7)? as u8;
            Ok(UacBarringInfoSet {
                uac_barring_factor_percent,
                uac_barring_time_s,
                uac_barring_for_access_identity,
            })
        })?;
        let uac_access_category1_selection_assistance_info = r.opt(has_ac1, |r| {
            Ok(if !r.bit()? {
                UacAccessCategory1SelectionAssistanceInfo::PlmnCommon(r.enu(3)? as u8)
            } else {
                UacAccessCategory1SelectionAssistanceInfo::IndividualPlmnList(r.seq_of(
                    2,
                    12,
                    |r| Ok(r.enu(3)? as u8),
                )?)
            })
        })?;
        Ok(Self {
            uac_barring_for_common,
            uac_barring_per_plmn_list,
            uac_barring_info_set_list,
            uac_access_category1_selection_assistance_info,
        })
    }
}

/// `SIB1 ::= SEQUENCE { cellSelectionInfo SEQUENCE {…} OPTIONAL, cellAccessRelatedInfo
/// CellAccessRelatedInfo, connEstFailureControl ConnEstFailureControl OPTIONAL,
/// si-SchedulingInfo SI-SchedulingInfo OPTIONAL, servingCellConfigCommon
/// ServingCellConfigCommonSIB OPTIONAL, ims-EmergencySupport ENUMERATED { true } OPTIONAL,
/// eCallOverIMS-Support ENUMERATED { true } OPTIONAL, ue-TimersAndConstants
/// UE-TimersAndConstants OPTIONAL, uac-BarringInfo SEQUENCE {…} OPTIONAL, useFullResumeID
/// ENUMERATED { true } OPTIONAL, lateNonCriticalExtension OCTET STRING OPTIONAL,
/// nonCriticalExtension SIB1-v1610-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sib1 {
    pub cell_selection_info: Option<CellSelectionInfo>,
    pub cell_access_related_info: CellAccessRelatedInfo,
    pub conn_est_failure_control: Option<ConnEstFailureControl>,
    pub si_scheduling_info: Option<SiSchedulingInfo>,
    pub serving_cell_config_common: Option<ServingCellConfigCommonSib>,
    pub ims_emergency_support: bool,
    pub ecall_over_ims_support: bool,
    pub ue_timers_and_constants: Option<UeTimersAndConstants>,
    pub uac_barring_info: Option<UacBarringInfo>,
    pub use_full_resume_id: bool,
    /// `lateNonCriticalExtension` octets, if any (not interpreted).
    pub late_non_critical_extension: Option<Vec<u8>>,
    /// `nonCriticalExtension` (SIB1-v1610-IEs) present; its content is not interpreted.
    pub non_critical_extension_present: bool,
}

impl Sib1 {
    /// Decode a SIB1 transport block (`BCCH-DL-SCH-Message`, padding included).
    pub fn decode(tb: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(tb)).ctx("SIB1")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        // BCCH-DL-SCH-Message ::= SEQUENCE { message CHOICE { c1 CHOICE { systemInformation,
        // systemInformationBlockType1 }, messageClassExtension SEQUENCE {} } }
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        if !r.bit()? {
            return r.unsupported("systemInformation (not SIB1)");
        }
        let o = r.opt_bits::<11>()?;
        log::trace!("SIB1 optionals {:?}", o);
        let cell_selection_info = r
            .opt(o[0], |r| {
                let [o1, o2, o3, o4] = r.opt_bits::<4>()?;
                let q_rx_lev_min = r.int(-70, -22)? as i8;
                let q_rx_lev_min_offset = r.opt(o1, |r| r.u8(1, 8))?;
                let q_rx_lev_min_sul = r.opt(o2, |r| Ok(r.int(-70, -22)? as i8))?;
                let q_qual_min = r.opt(o3, |r| Ok(r.int(-43, -12)? as i8))?;
                let q_qual_min_offset = r.opt(o4, |r| r.u8(1, 8))?;
                Ok(CellSelectionInfo {
                    q_rx_lev_min,
                    q_rx_lev_min_offset,
                    q_rx_lev_min_sul,
                    q_qual_min,
                    q_qual_min_offset,
                })
            })
            .ctx("cellSelectionInfo")?;
        let cell_access_related_info = Self::decode_cell_access(r).ctx("cellAccessRelatedInfo")?;
        let conn_est_failure_control = r
            .opt(o[1], |r| {
                let [has_off] = r.opt_bits::<1>()?;
                let conn_est_fail_count = r.enu(4)? as u8 + 1;
                const VALIDITY: [u16; 8] = [30, 60, 120, 240, 300, 420, 600, 900];
                let conn_est_fail_offset_validity_s = VALIDITY[r.enu(8)? as usize];
                let conn_est_fail_offset = r.opt(has_off, |r| r.u8(0, 15))?;
                Ok(ConnEstFailureControl {
                    conn_est_fail_count,
                    conn_est_fail_offset_validity_s,
                    conn_est_fail_offset,
                })
            })
            .ctx("connEstFailureControl")?;
        let si_scheduling_info = r
            .opt(o[2], Self::decode_si_scheduling)
            .ctx("si-SchedulingInfo")?;
        let serving_cell_config_common = r
            .opt(o[3], ServingCellConfigCommonSib::decode)
            .ctx("servingCellConfigCommon")?;
        let ue_timers_and_constants = r
            .opt(o[6], UeTimersAndConstants::decode)
            .ctx("ue-TimersAndConstants")?;
        let uac_barring_info = r.opt(o[7], UacBarringInfo::decode).ctx("uac-BarringInfo")?;
        let late_non_critical_extension = r
            .opt(o[9], |r| r.octet_string())
            .ctx("lateNonCriticalExtension")?;
        Ok(Self {
            cell_selection_info,
            cell_access_related_info,
            conn_est_failure_control,
            si_scheduling_info,
            serving_cell_config_common,
            ims_emergency_support: o[4],
            ecall_over_ims_support: o[5],
            ue_timers_and_constants,
            uac_barring_info,
            use_full_resume_id: o[8],
            late_non_critical_extension,
            non_critical_extension_present: o[10],
        })
    }

    fn decode_cell_access(r: &mut BitReader) -> DecodeResult<CellAccessRelatedInfo> {
        let ext = r.bit()?;
        let [reserved_other] = r.opt_bits::<1>()?;
        let plmn_identity_info_list = r.seq_of(1, 12, |r| {
            let ext_i = r.bit()?;
            let [has_tac, has_ranac] = r.opt_bits::<2>()?;
            let plmn_identity_list = r.seq_of(1, 12, PlmnIdentity::decode)?;
            let tracking_area_code = r.opt(has_tac, |r| Ok(r.bitstring(24)? as u32))?;
            let ranac = r.opt(has_ranac, |r| r.u8(0, 255))?;
            let cell_identity = r.bitstring(36)?;
            let cell_reserved_for_operator_use = r.enu(2)? == 0;
            if ext_i {
                r.skip_ext_additions()?;
            }
            Ok(PlmnIdentityInfo {
                plmn_identity_list,
                tracking_area_code,
                ranac,
                cell_identity,
                cell_reserved_for_operator_use,
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(CellAccessRelatedInfo {
            plmn_identity_info_list,
            cell_reserved_for_other_use: reserved_other,
        })
    }

    fn decode_si_scheduling(r: &mut BitReader) -> DecodeResult<SiSchedulingInfo> {
        let ext = r.bit()?;
        let [has_req, has_req_sul, has_area] = r.opt_bits::<3>()?;
        let scheduling_info_list = r.seq_of(1, 32, |r| {
            let si_broadcasting = r.enu(2)? == 0;
            let si_periodicity_rf = 8u16 << r.enu(7)?;
            let sib_mapping_info = r.seq_of(1, 32, |r| {
                let [has_tag, has_scope] = r.opt_bits::<2>()?;
                let sib_type = r.enu_ext(16)?.and_then(|v| (v < 13).then_some(v as u8 + 2));
                let value_tag = r.opt(has_tag, |r| r.u8(0, 31))?;
                Ok(SibTypeInfo {
                    sib_type,
                    value_tag,
                    area_scope: has_scope,
                })
            })?;
            Ok(SchedulingInfo {
                si_broadcasting,
                si_periodicity_rf,
                sib_mapping_info,
            })
        })?;
        const WIN: [u16; 11] = [5, 10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120];
        let si_window_length_slots = WIN[r.enu(11)? as usize];
        // SI-RequestConfig ::= SEQUENCE { rach-OccasionsSI SEQUENCE { rach-ConfigSI
        // RACH-ConfigGeneric, ssb-perRACH-Occasion ENUMERATED {…} } OPTIONAL,
        // si-RequestPeriod ENUMERATED { one, two, four, six, eight, ten, twelve, sixteen }
        // OPTIONAL, si-RequestResources SEQUENCE (SIZE (1..maxSI-Message)) OF
        // SI-RequestResources } — walked, not kept.
        let skip_si_request = |r: &mut BitReader| -> DecodeResult<()> {
            let [has_ro, has_period] = r.opt_bits::<2>()?;
            if has_ro {
                let gext = r.bit()?;
                r.u8(0, 255)?;
                r.enu(4)?;
                r.u16(0, 274)?;
                r.u8(0, 15)?;
                r.int(-202, -60)?;
                r.enu(11)?;
                r.enu(4)?;
                r.enu(8)?;
                if gext {
                    r.skip_ext_additions()?;
                }
                r.enu(8)?;
            }
            if has_period {
                r.enu(8)?;
            }
            r.seq_of(1, 32, |r| {
                // SI-RequestResources ::= SEQUENCE { ra-PreambleStartIndex INTEGER (0..63),
                // ra-AssociationPeriodIndex INTEGER (0..15) OPTIONAL, ra-ssb-OccasionMaskIndex
                // INTEGER (0..15) OPTIONAL }
                let [a, b] = r.opt_bits::<2>()?;
                r.u8(0, 63)?;
                if a {
                    r.u8(0, 15)?;
                }
                if b {
                    r.u8(0, 15)?;
                }
                Ok(())
            })?;
            Ok(())
        };
        if has_req {
            skip_si_request(r).ctx("si-RequestConfig")?;
        }
        if has_req_sul {
            skip_si_request(r).ctx("si-RequestConfigSUL")?;
        }
        let system_information_area_id = r.opt(has_area, |r| Ok(r.bitstring(24)? as u32))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(SiSchedulingInfo {
            scheduling_info_list,
            si_window_length_slots,
            si_request_config_present: has_req,
            si_request_config_sul_present: has_req_sul,
            system_information_area_id,
        })
    }

    // ---- convenience accessors -------------------------------------------------

    /// The first PLMN of the first `PLMN-IdentityInfo`.
    pub fn plmn(&self) -> Option<&PlmnIdentity> {
        self.cell_access_related_info
            .plmn_identity_info_list
            .first()?
            .plmn_identity_list
            .first()
    }

    /// The TAC of the first `PLMN-IdentityInfo`.
    pub fn tac(&self) -> Option<u32> {
        self.cell_access_related_info
            .plmn_identity_info_list
            .first()?
            .tracking_area_code
    }

    /// The cell identity of the first `PLMN-IdentityInfo`.
    pub fn cell_identity(&self) -> Option<u64> {
        Some(
            self.cell_access_related_info
                .plmn_identity_info_list
                .first()?
                .cell_identity,
        )
    }

    pub fn serving_cell(&self) -> Option<&ServingCellConfigCommonSib> {
        self.serving_cell_config_common.as_ref()
    }

    /// The first DL `freqBandIndicatorNR`.
    pub fn band(&self) -> Option<u16> {
        self.serving_cell()?
            .downlink_config_common
            .frequency_info_dl
            .frequency_band_list
            .iter()
            .find_map(|b| b.freq_band_indicator_nr)
    }

    /// The first DL `SCS-SpecificCarrier`.
    pub fn dl_carrier(&self) -> Option<&ScsSpecificCarrier> {
        self.serving_cell()?
            .downlink_config_common
            .frequency_info_dl
            .scs_specific_carrier_list
            .first()
    }

    pub fn tdd(&self) -> Option<&TddUlDlConfigCommon> {
        self.serving_cell()?.tdd_ul_dl_configuration_common.as_ref()
    }

    pub fn initial_downlink_bwp(&self) -> Option<&BwpDownlinkCommon> {
        Some(
            &self
                .serving_cell()?
                .downlink_config_common
                .initial_downlink_bwp,
        )
    }

    pub fn initial_uplink_bwp(&self) -> Option<&BwpUplinkCommon> {
        Some(
            &self
                .serving_cell()?
                .uplink_config_common
                .as_ref()?
                .initial_uplink_bwp,
        )
    }

    pub fn pdcch_config_common(&self) -> Option<&PdcchConfigCommon> {
        self.initial_downlink_bwp()?
            .pdcch_config_common
            .as_ref()?
            .setup()
    }

    /// `pdsch-TimeDomainAllocationList` (empty ⇒ the TS 38.214 default table applies).
    pub fn pdsch_tdra(&self) -> &[TdraRow] {
        self.initial_downlink_bwp()
            .and_then(|b| b.pdsch_config_common.as_ref()?.setup())
            .map_or(&[], |p| p.pdsch_time_domain_allocation_list.as_slice())
    }

    /// `pusch-TimeDomainAllocationList` (empty ⇒ the TS 38.214 default table applies).
    pub fn pusch_tdra(&self) -> &[TdraRow] {
        self.initial_uplink_bwp()
            .and_then(|b| b.pusch_config_common.as_ref()?.setup())
            .map_or(&[], |p| p.pusch_time_domain_allocation_list.as_slice())
    }

    pub fn rach_config_common(&self) -> Option<&RachConfigCommon> {
        self.initial_uplink_bwp()?
            .rach_config_common
            .as_ref()?
            .setup()
    }

    pub fn pucch_config_common(&self) -> Option<&PucchConfigCommon> {
        self.initial_uplink_bwp()?
            .pucch_config_common
            .as_ref()?
            .setup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{CommonSearchSpaceDci, SearchSpaceType};

    /// The live SIB1 TB captured from the OCUDU gNB (test/gnb_zmq_ferrite.yml).
    /// Ground truth: PLMN 001/01, TAC 7, band n78, 24-RB carrier @30 kHz,
    /// TDD ms5 = 10 slots: 6 DL + special(8 DL sym, 0 UL sym) + 3 UL,
    /// prach-ConfigurationIndex 159.
    const SIB1_HEX: &str = "748101701040040200000e000a680018056109a008200042e02050900c316a61b3704020000080800041a2352412130426931860000042ee18b53224f8050664abff0124e9106e28dc61b8e372c6fbf56c70ea008580d003058b6822800000000000000000";

    fn tb() -> Vec<u8> {
        ferrite_common::from_hex(SIB1_HEX).unwrap()
    }

    #[test]
    fn parses_live_sib1() {
        let s = Sib1::decode(&tb()).expect("SIB1 must parse");
        assert_eq!(
            s.plmn(),
            Some(&PlmnIdentity {
                mcc: Some([0, 0, 1]),
                mnc: vec![0, 1]
            })
        );
        assert_eq!(s.tac(), Some(7));
        assert_eq!(s.band(), Some(78));
        let c = s.dl_carrier().unwrap();
        assert_eq!(c.carrier_bandwidth, 24);
        assert_eq!(c.subcarrier_spacing, SubcarrierSpacing::Khz30);
        let rach = s.rach_config_common().unwrap();
        assert_eq!(rach.rach_config_generic.prach_configuration_index, 159);
        let tdd = s.tdd().unwrap();
        assert_eq!(tdd.reference_subcarrier_spacing, SubcarrierSpacing::Khz30);
        assert_eq!(
            tdd.pattern1,
            TddPattern {
                periodicity_us: 5000,
                period_slots: 10,
                dl_slots: 6,
                dl_symbols: 8,
                ul_slots: 3,
                ul_symbols: 0
            }
        );
        assert_eq!(tdd.pattern2, None);
        // Structural checks on the rest of the walk.
        let pdcch = s.pdcch_config_common().unwrap();
        assert_eq!(pdcch.control_resource_set_zero, None); // CORESET#0 comes from the MIB
        assert_eq!(pdcch.search_space_sib1, Some(0));
        assert_eq!(pdcch.ra_search_space, Some(1));
        assert_eq!(pdcch.paging_search_space, Some(1));
        let ss1 = &pdcch.common_search_space_list[0];
        assert_eq!(ss1.search_space_id, 1);
        assert_eq!(ss1.control_resource_set_id, Some(0));
        assert_eq!(ss1.monitoring_symbols(), vec![0]);
        assert_eq!(ss1.nrof_candidates, Some([0, 0, 1, 0, 0]));
        assert!(matches!(
            ss1.search_space_type,
            Some(SearchSpaceType::Common(CommonSearchSpaceDci {
                dci_format0_0_and_format1_0: true,
                ..
            }))
        ));
        assert!(!s.pdsch_tdra().is_empty());
        assert!(!s.pusch_tdra().is_empty());
        assert_eq!(
            rach.rach_config_generic.preamble_received_target_power,
            -100
        );
        assert_eq!(rach.rach_config_generic.ra_response_window_slots, 20);
        assert_eq!(
            rach.ssb_per_rach_occasion_and_cb_preambles_per_ssb,
            Some((SsbPerRachOccasion::One, 64))
        );
        assert_eq!(
            rach.prach_root_sequence_index,
            PrachRootSequenceIndex::L139(1)
        );
        assert_eq!(rach.msg1_subcarrier_spacing, Some(SubcarrierSpacing::Khz30));
        let pucch = s.pucch_config_common().unwrap();
        assert_eq!(pucch.pucch_resource_common, Some(11));
        assert_eq!(pucch.p0_nominal, Some(-90));
        let scc = s.serving_cell().unwrap();
        assert_eq!(scc.n_timing_advance_offset, Some(25600));
        assert_eq!(scc.ssb_positions_in_burst.in_one_group, 0x80);
        assert!(
            scc.ssb_positions_in_burst.is_transmitted(0, 8)
                && !scc.ssb_positions_in_burst.is_transmitted(1, 8)
        );
        assert_eq!(scc.ssb_periodicity_ms, 10);
        assert_eq!(scc.ss_pbch_block_power, -16);
        assert_eq!(
            scc.uplink_config_common
                .as_ref()
                .unwrap()
                .time_alignment_timer_common,
            TimeAlignmentTimer(None)
        );
        let t = s.ue_timers_and_constants.unwrap();
        assert_eq!((t.t300_ms, t.t310_ms), (1000, 1000));
        assert!(s.si_scheduling_info.is_none() && s.uac_barring_info.is_none());
    }

    #[test]
    fn tdd_pattern_queries() {
        let p = TddPattern {
            periodicity_us: 5000,
            period_slots: 10,
            dl_slots: 6,
            dl_symbols: 8,
            ul_slots: 3,
            ul_symbols: 0,
        };
        // Slots 0-5 DL, 6 special (8 DL symbols → short PDSCH ok), 7-9 UL.
        assert!(p.has_pdsch(0) && p.has_pdsch(5) && p.has_pdsch(6));
        assert!(!p.has_pdsch(7) && !p.has_pdsch(9));
        assert!(!p.has_full_ul(6) && p.has_full_ul(7) && p.has_full_ul(19));
        assert_eq!(p.next_ul_slot_after(1), 7);
        assert_eq!(p.next_ul_slot_after(7), 8);
        assert_eq!(p.next_ul_slot_after(9), 17);
        // DDDSU (2.5 ms): slots 0-2 DL, 3 special (10 DL sym), 4 UL.
        let d = TddPattern {
            periodicity_us: 2500,
            period_slots: 5,
            dl_slots: 3,
            dl_symbols: 10,
            ul_slots: 1,
            ul_symbols: 2,
        };
        assert!(d.has_pdsch(3));
        assert!(d.has_full_ul(4) && d.has_full_ul(9));
        assert_eq!(d.next_ul_slot_after(0), 4);
        assert_eq!(d.next_ul_slot_after(4), 9);
        let cfg = TddUlDlConfigCommon {
            reference_subcarrier_spacing: SubcarrierSpacing::Khz30,
            pattern1: p,
            pattern2: Some(d),
        };
        assert_eq!(cfg.period_slots(), 15);
        assert_eq!(cfg.slot_kind(13), SlotKind::Special);
        assert_eq!(cfg.slot_kind(14), SlotKind::Ul);
        assert_eq!(cfg.next_ul_slot_after(9), 14);
    }

    #[test]
    fn malformed_input_errors_with_path() {
        let mut b = tb();
        b.truncate(20);
        let e = Sib1::decode(&b).unwrap_err();
        assert!(e.path.starts_with("SIB1/"), "{e}");
        assert!(Sib1::decode(&[]).is_err());
    }
}
