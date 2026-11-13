//! TS 38.331 §6.3.2 information elements shared by the system information
//! (`sib1`) and the dedicated configuration (`cellgroup`) codecs: BWP generic
//! parameters, `SearchSpace`, `ControlResourceSet`, the time-domain allocation
//! rows, CSI-RS resource mapping, PLMN identities and the small enumerations
//! that appear in both.
//!
//! Every decoder here is written from the ASN.1 in TS 38.331 (v16/v17); the
//! comments quote the IE definition the bits are read against.

use crate::uper::{BitReader, BitWriter, Ctx, DecodeResult};

/// `SubcarrierSpacing ::= ENUMERATED { kHz15, kHz30, kHz60, kHz120, kHz240,
/// kHz480-v1700, kHz960-v1700, spare1 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubcarrierSpacing {
    Khz15,
    Khz30,
    Khz60,
    Khz120,
    Khz240,
    Khz480,
    Khz960,
    Spare1,
}

impl SubcarrierSpacing {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(match r.enu(8)? {
            0 => Self::Khz15,
            1 => Self::Khz30,
            2 => Self::Khz60,
            3 => Self::Khz120,
            4 => Self::Khz240,
            5 => Self::Khz480,
            6 => Self::Khz960,
            _ => Self::Spare1,
        })
    }

    /// Numerology index µ (`Spare1` maps to 7).
    pub fn mu(self) -> u8 {
        match self {
            Self::Khz15 => 0,
            Self::Khz30 => 1,
            Self::Khz60 => 2,
            Self::Khz120 => 3,
            Self::Khz240 => 4,
            Self::Khz480 => 5,
            Self::Khz960 => 6,
            Self::Spare1 => 7,
        }
    }

    /// Subcarrier spacing in kHz.
    pub fn khz(self) -> u32 {
        15 << self.mu().min(6)
    }
}

/// `BWP ::= SEQUENCE { locationAndBandwidth INTEGER (0..37949),
/// subcarrierSpacing SubcarrierSpacing, cyclicPrefix ENUMERATED { extended } OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bwp {
    pub location_and_bandwidth: u16,
    pub subcarrier_spacing: SubcarrierSpacing,
    /// `cyclicPrefix = extended` present.
    pub extended_cyclic_prefix: bool,
}

impl Bwp {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let [cp] = r.opt_bits::<1>()?;
        let location_and_bandwidth = r.u16(0, 37949)?;
        let subcarrier_spacing = SubcarrierSpacing::decode(r)?;
        Ok(Self {
            location_and_bandwidth,
            subcarrier_spacing,
            extended_cyclic_prefix: cp,
        })
    }

    /// `(RB_start, L_RB)` of the BWP from `locationAndBandwidth` (an RIV over
    /// `N_BWP^size = 275`, TS 38.214 §5.1.2.2.2 / TS 38.213 §12).
    pub fn start_and_len(&self) -> (u16, u16) {
        riv_to_start_len(self.location_and_bandwidth, 275)
    }
}

/// Decode a resource indication value over `n` RBs into `(start, length)`
/// (TS 38.214 §5.1.2.2.2).
pub fn riv_to_start_len(riv: u16, n: u16) -> (u16, u16) {
    let (riv, n) = (riv as u32, n as u32);
    let mut l = riv / n + 1;
    let mut s = riv % n;
    if l + s > n {
        l = n + 2 - l;
        s = n - 1 - s;
    }
    (s as u16, l as u16)
}

/// `SCS-SpecificCarrier ::= SEQUENCE { offsetToCarrier INTEGER (0..2199),
/// subcarrierSpacing SubcarrierSpacing, carrierBandwidth INTEGER (1..275), ...,
/// [[ txDirectCurrentLocation-v1530 INTEGER (0..4095) OPTIONAL ]] }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScsSpecificCarrier {
    pub offset_to_carrier: u16,
    pub subcarrier_spacing: SubcarrierSpacing,
    pub carrier_bandwidth: u16,
    pub tx_direct_current_location: Option<u16>,
}

impl ScsSpecificCarrier {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let offset_to_carrier = r.u16(0, 2199)?;
        let subcarrier_spacing = SubcarrierSpacing::decode(r)?;
        let carrier_bandwidth = r.u16(1, 275)?;
        let mut tx_dc = None;
        if ext {
            r.ext_additions(|i, sub| {
                if i == 0 {
                    let [has] = sub.opt_bits::<1>()?;
                    tx_dc = sub.opt(has, |s| s.u16(0, 4095))?;
                }
                Ok(())
            })?;
        }
        Ok(Self {
            offset_to_carrier,
            subcarrier_spacing,
            carrier_bandwidth,
            tx_direct_current_location: tx_dc,
        })
    }
}

/// `PLMN-Identity ::= SEQUENCE { mcc MCC OPTIONAL, mnc MNC }` with
/// `MCC ::= SEQUENCE (SIZE (3)) OF MCC-MNC-Digit`, `MNC ::= SEQUENCE (SIZE (2..3)) OF
/// MCC-MNC-Digit`, `MCC-MNC-Digit ::= INTEGER (0..9)`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PlmnIdentity {
    pub mcc: Option<[u8; 3]>,
    pub mnc: Vec<u8>,
}

impl PlmnIdentity {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let [has_mcc] = r.opt_bits::<1>()?;
        let mcc = r.opt(has_mcc, |r| Ok([r.u8(0, 9)?, r.u8(0, 9)?, r.u8(0, 9)?]))?;
        let mnc = r.seq_of(2, 3, |r| r.u8(0, 9))?;
        Ok(Self { mcc, mnc })
    }

    pub(crate) fn encode(&self, w: &mut BitWriter) {
        w.bit(self.mcc.is_some());
        if let Some(mcc) = self.mcc {
            for d in mcc {
                w.uint(d as u32, 0, 9);
            }
        }
        w.seq_of(&self.mnc, 2, 3, |w, d| w.uint(*d as u32, 0, 9));
    }
}

/// `TimeAlignmentTimer ::= ENUMERATED { ms500, ms750, ms1280, ms1920, ms2560,
/// ms5120, ms10240, infinity }` — `None` is `infinity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAlignmentTimer(pub Option<u16>);

impl TimeAlignmentTimer {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        const MS: [u16; 7] = [500, 750, 1280, 1920, 2560, 5120, 10240];
        Ok(Self(MS.get(r.enu(8)? as usize).copied()))
    }
}

/// One row of `PDSCH-TimeDomainResourceAllocation` / `PUSCH-TimeDomainResourceAllocation`:
/// `SEQUENCE { k0|k2 INTEGER (0..32) OPTIONAL, mappingType ENUMERATED { typeA, typeB },
/// startSymbolAndLength INTEGER (0..127) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TdraRow {
    /// `k0` (PDSCH) / `k2` (PUSCH) when signalled; the spec default applies
    /// when absent (k0 = 0; k2 = j, i.e. 1 for 15/30 kHz, 2 for 60 kHz, 3 for 120 kHz).
    pub k: Option<u8>,
    /// Mapping type A (`true`) or B.
    pub mapping_type_a: bool,
    /// `startSymbolAndLength` (SLIV).
    pub sliv: u8,
}

impl TdraRow {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let [has_k] = r.opt_bits::<1>()?;
        let k = r.opt(has_k, |r| r.u8(0, 32))?;
        let mapping_type_a = r.enu(2)? == 0;
        let sliv = r.u8(0, 127)?;
        Ok(Self {
            k,
            mapping_type_a,
            sliv,
        })
    }

    /// `(S, L)` of this row's SLIV.
    pub fn start_len(&self) -> (usize, usize) {
        sliv_to_sl(self.sliv)
    }

    /// `k0` with its default (0) applied.
    pub fn k0(&self) -> u8 {
        self.k.unwrap_or(0)
    }

    /// `k2` with the TS 38.214 Table 6.1.2.1.1-2 default `j` for numerology `mu`.
    pub fn k2(&self, mu: u8) -> u8 {
        self.k.unwrap_or(match mu {
            0 | 1 => 1,
            2 => 2,
            _ => 3,
        })
    }
}

/// Decode a SLIV into (start symbol S, length L) — TS 38.214 §5.1.2.1: for
/// (L−1) ≤ 7, SLIV = 14(L−1) + S, else SLIV = 14(14−L+1) + (14−1−S).
pub fn sliv_to_sl(sliv: u8) -> (usize, usize) {
    let (mut l, mut s) = (sliv as usize / 14 + 1, sliv as usize % 14);
    if s + l > 14 {
        l = 14 + 2 - l;
        s = 14 - 1 - s;
    }
    (s, l)
}

/// `PDSCH-TimeDomainResourceAllocationList ::= SEQUENCE (SIZE(1..maxNrofDL-Allocations)) OF …`
/// (also the PUSCH list; both have 16 entries max).
pub(crate) fn decode_tdra_list(r: &mut BitReader) -> DecodeResult<Vec<TdraRow>> {
    r.seq_of(1, 16, TdraRow::decode)
}

/// `monitoringSlotPeriodicityAndOffset CHOICE { sl1 NULL, sl2 INTEGER (0..1), sl4,
/// sl5, sl8, sl10, sl16, sl20, sl40, sl80, sl160, sl320, sl640, sl1280, sl2560 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotPeriodicityAndOffset {
    pub period_slots: u16,
    pub offset: u16,
}

impl SlotPeriodicityAndOffset {
    const PERIODS: [u16; 15] = [1, 2, 4, 5, 8, 10, 16, 20, 40, 80, 160, 320, 640, 1280, 2560];

    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let alt = r.uint(0, 14)? as usize;
        let period_slots = Self::PERIODS[alt];
        let offset = if period_slots > 1 {
            r.u16(0, period_slots - 1)?
        } else {
            0
        };
        Ok(Self {
            period_slots,
            offset,
        })
    }
}

/// `nrofCandidates-SFI` entry / `aggregationLevelN ENUMERATED { n0, n1, n2, n3, n4, n5, n6, n8 }`.
const NROF_CANDIDATES: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 8];

/// `searchSpaceType CHOICE { common SEQUENCE { … }, ue-Specific SEQUENCE { … } }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchSpaceType {
    Common(CommonSearchSpaceDci),
    /// `ue-Specific ::= SEQUENCE { dci-Formats ENUMERATED { formats0-0-And-1-0,
    /// formats0-1-And-1-1 }, ... }` — `true` when the DCI formats are 0_1 / 1_1.
    UeSpecific {
        dci_formats_0_1_and_1_1: bool,
    },
}

/// The DCI formats monitored in a common search space.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommonSearchSpaceDci {
    /// `dci-Format0-0-AndFormat1-0 SEQUENCE { ... } OPTIONAL`.
    pub dci_format0_0_and_format1_0: bool,
    /// `dci-Format2-0 SEQUENCE { nrofCandidates-SFI SEQUENCE { aggregationLevel1
    /// ENUMERATED { n1, n2 } OPTIONAL, … aggregationLevel16 … }, ... } OPTIONAL`:
    /// the number of SFI candidates per aggregation level 1/2/4/8/16.
    pub dci_format2_0: Option<[Option<u8>; 5]>,
    pub dci_format2_1: bool,
    pub dci_format2_2: bool,
    /// `dci-Format2-3 SEQUENCE { dummy1 ENUMERATED { sl1, sl2, sl4, sl5, sl8, sl10,
    /// sl16, sl20 } OPTIONAL, dummy2 ENUMERATED { n1, n2 }, ... } OPTIONAL`.
    pub dci_format2_3: Option<(Option<u8>, u8)>,
}

/// `SearchSpace ::= SEQUENCE { searchSpaceId SearchSpaceId, controlResourceSetId
/// ControlResourceSetId OPTIONAL, monitoringSlotPeriodicityAndOffset CHOICE {…}
/// OPTIONAL, duration INTEGER (2..2559) OPTIONAL, monitoringSymbolsWithinSlot BIT
/// STRING (SIZE (14)) OPTIONAL, nrofCandidates SEQUENCE { aggregationLevel1..16
/// ENUMERATED { n0, n1, n2, n3, n4, n5, n6, n8 } } OPTIONAL, searchSpaceType CHOICE
/// { common …, ue-Specific … } OPTIONAL }` (no extension marker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSpace {
    pub search_space_id: u8,
    pub control_resource_set_id: Option<u8>,
    pub monitoring_slot_periodicity_and_offset: Option<SlotPeriodicityAndOffset>,
    pub duration: Option<u16>,
    /// 14-bit mask, bit 13 (MSB) = symbol 0.
    pub monitoring_symbols_within_slot: Option<u16>,
    /// Candidates per aggregation level 1, 2, 4, 8, 16.
    pub nrof_candidates: Option<[u8; 5]>,
    pub search_space_type: Option<SearchSpaceType>,
}

impl SearchSpace {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let o = r.opt_bits::<6>()?;
        let search_space_id = r.u8(0, 39)?;
        let control_resource_set_id = r.opt(o[0], |r| r.u8(0, 11))?;
        let monitoring_slot_periodicity_and_offset =
            r.opt(o[1], SlotPeriodicityAndOffset::decode)?;
        let duration = r.opt(o[2], |r| r.u16(2, 2559))?;
        let monitoring_symbols_within_slot = r.opt(o[3], |r| Ok(r.bitstring(14)? as u16))?;
        let nrof_candidates = r.opt(o[4], |r| {
            let mut c = [0u8; 5];
            for v in c.iter_mut() {
                *v = NROF_CANDIDATES[r.enu(8)? as usize];
            }
            Ok(c)
        })?;
        let search_space_type = r.opt(o[5], Self::decode_type).ctx("searchSpaceType")?;
        Ok(Self {
            search_space_id,
            control_resource_set_id,
            monitoring_slot_periodicity_and_offset,
            duration,
            monitoring_symbols_within_slot,
            nrof_candidates,
            search_space_type,
        })
    }

    fn decode_type(r: &mut BitReader) -> DecodeResult<SearchSpaceType> {
        if r.bit()? {
            // ue-Specific ::= SEQUENCE { dci-Formats ENUMERATED {..}, ... }
            let ext = r.bit()?;
            let f = r.enu(2)? == 1;
            if ext {
                r.skip_ext_additions()?;
            }
            return Ok(SearchSpaceType::UeSpecific {
                dci_formats_0_1_and_1_1: f,
            });
        }
        let c = r.opt_bits::<5>()?;
        let mut dci = CommonSearchSpaceDci {
            dci_format0_0_and_format1_0: c[0],
            ..Default::default()
        };
        if c[0] {
            // dci-Format0-0-AndFormat1-0 ::= SEQUENCE { ... }
            if r.bit()? {
                r.skip_ext_additions()?;
            }
        }
        if c[1] {
            // dci-Format2-0 ::= SEQUENCE { nrofCandidates-SFI SEQUENCE { 5 × [ENUM{n1,n2}] }, ... }
            let ext = r.bit()?;
            let m = r.opt_bits::<5>()?;
            let mut sfi = [None; 5];
            for (slot, &p) in sfi.iter_mut().zip(m.iter()) {
                if p {
                    *slot = Some(r.enu(2)? as u8 + 1);
                }
            }
            if ext {
                r.skip_ext_additions()?;
            }
            dci.dci_format2_0 = Some(sfi);
        }
        for (i, flag) in [
            (2usize, &mut dci.dci_format2_1),
            (3, &mut dci.dci_format2_2),
        ] {
            if c[i] {
                *flag = true;
                if r.bit()? {
                    r.skip_ext_additions()?;
                }
            }
        }
        if c[4] {
            // dci-Format2-3 ::= SEQUENCE { dummy1 ENUM8 OPTIONAL, dummy2 ENUM2, ... }
            let ext = r.bit()?;
            let [has_d1] = r.opt_bits::<1>()?;
            let d1 = r.opt(has_d1, |r| Ok(r.enu(8)? as u8))?;
            let d2 = r.enu(2)? as u8 + 1;
            if ext {
                r.skip_ext_additions()?;
            }
            dci.dci_format2_3 = Some((d1, d2));
        }
        Ok(SearchSpaceType::Common(dci))
    }

    /// Symbols at which a PDCCH monitoring occasion starts in this search space.
    pub fn monitoring_symbols(&self) -> Vec<u8> {
        let mask = self.monitoring_symbols_within_slot.unwrap_or(1 << 13);
        (0..14u8).filter(|&s| mask & (1 << (13 - s)) != 0).collect()
    }
}

/// `cce-REG-MappingType CHOICE { interleaved SEQUENCE { reg-BundleSize ENUMERATED
/// { n2, n3, n6 }, interleaverSize ENUMERATED { n2, n3, n6 }, shiftIndex INTEGER
/// (0..maxNrofPhysicalResourceBlocks-1) OPTIONAL }, nonInterleaved NULL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CceRegMapping {
    Interleaved {
        reg_bundle_size: u8,
        interleaver_size: u8,
        /// `shiftIndex`; when absent the cell identity is used (TS 38.211 §7.3.2.2).
        shift_index: Option<u16>,
    },
    NonInterleaved,
}

/// `precoderGranularity ENUMERATED { sameAsREG-bundle, allContiguousRBs }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecoderGranularity {
    SameAsRegBundle,
    AllContiguousRbs,
}

/// `ControlResourceSet ::= SEQUENCE { controlResourceSetId ControlResourceSetId,
/// frequencyDomainResources BIT STRING (SIZE (45)), duration INTEGER (1..maxCoReSetDuration),
/// cce-REG-MappingType CHOICE {…}, precoderGranularity ENUMERATED {…},
/// tci-StatesPDCCH-ToAddList SEQUENCE(SIZE (1..maxNrofTCI-StatesPDCCH)) OF TCI-StateId OPTIONAL,
/// tci-StatesPDCCH-ToReleaseList … OPTIONAL, tci-PresentInDCI ENUMERATED {enabled} OPTIONAL,
/// pdcch-DMRS-ScramblingID INTEGER (0..65535) OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlResourceSet {
    pub control_resource_set_id: u8,
    /// 45-bit mask in the low bits of the `u64`, MSB (bit 44) = the first 6-RB group.
    pub frequency_domain_resources: u64,
    pub duration: u8,
    pub cce_reg_mapping_type: CceRegMapping,
    pub precoder_granularity: PrecoderGranularity,
    pub tci_states_pdcch_to_add_list: Vec<u8>,
    pub tci_states_pdcch_to_release_list: Vec<u8>,
    pub tci_present_in_dci: bool,
    pub pdcch_dmrs_scrambling_id: Option<u16>,
}

impl ControlResourceSet {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [tci_add, tci_rel, tci_dci, scr] = r.opt_bits::<4>()?;
        let control_resource_set_id = r.u8(0, 11)?;
        let frequency_domain_resources = r.bitstring(45)?;
        let duration = r.u8(1, 3)?;
        let cce_reg_mapping_type = if !r.bit()? {
            const SIZES: [u8; 3] = [2, 3, 6];
            let reg_bundle_size = SIZES[r.enu(3)? as usize];
            let interleaver_size = SIZES[r.enu(3)? as usize];
            let [has_shift] = r.opt_bits::<1>()?;
            let shift_index = r.opt(has_shift, |r| r.u16(0, 274))?;
            CceRegMapping::Interleaved {
                reg_bundle_size,
                interleaver_size,
                shift_index,
            }
        } else {
            CceRegMapping::NonInterleaved
        };
        let precoder_granularity = match r.enu(2)? {
            0 => PrecoderGranularity::SameAsRegBundle,
            _ => PrecoderGranularity::AllContiguousRbs,
        };
        let tci_states_pdcch_to_add_list = if tci_add {
            r.seq_of(1, 64, |r| r.u8(0, 127))?
        } else {
            vec![]
        };
        let tci_states_pdcch_to_release_list = if tci_rel {
            r.seq_of(1, 64, |r| r.u8(0, 127))?
        } else {
            vec![]
        };
        let pdcch_dmrs_scrambling_id = r.opt(scr, |r| r.u16(0, 65535))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            control_resource_set_id,
            frequency_domain_resources,
            duration,
            cce_reg_mapping_type,
            precoder_granularity,
            tci_states_pdcch_to_add_list,
            tci_states_pdcch_to_release_list,
            tci_present_in_dci: tci_dci,
            pdcch_dmrs_scrambling_id,
        })
    }

    /// Whether 6-RB group `g` (0 = lowest) is part of this CORESET.
    pub fn has_rb_group(&self, g: u8) -> bool {
        g < 45 && self.frequency_domain_resources & (1u64 << (44 - g)) != 0
    }

    /// Number of 6-RB groups (so `N_RB^CORESET = 6 × n_rb_groups()`).
    pub fn n_rb_groups(&self) -> u8 {
        self.frequency_domain_resources.count_ones() as u8
    }
}

/// `ssb-Index SSB-Index` / `csi-RS-Index NZP-CSI-RS-ResourceId` reference signal choice
/// (used by pathloss references, QCL info, radio link monitoring).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceSignal {
    Ssb(u8),
    CsiRs(u8),
}

impl ReferenceSignal {
    /// `CHOICE { ssb-Index SSB-Index (0..63), csi-RS-Index (0..191) }` (ssb first).
    pub(crate) fn decode_ssb_first(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(if !r.bit()? {
            Self::Ssb(r.u8(0, 63)?)
        } else {
            Self::CsiRs(r.u8(0, 191)?)
        })
    }

    /// `CHOICE { csi-rs NZP-CSI-RS-ResourceId, ssb SSB-Index }` (csi-rs first; QCL-Info).
    pub(crate) fn decode_csi_first(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(if !r.bit()? {
            Self::CsiRs(r.u8(0, 191)?)
        } else {
            Self::Ssb(r.u8(0, 63)?)
        })
    }
}

/// `CSI-ResourcePeriodicityAndOffset ::= CHOICE { slots4 INTEGER (0..3), slots5,
/// slots8, slots10, slots16, slots20, slots32, slots40, slots64, slots80, slots160,
/// slots320, slots640 }` and the `CSI-ReportPeriodicityAndOffset` / SRS variants:
/// a periodicity in slots and an offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PeriodicityAndOffset {
    pub period_slots: u16,
    pub offset: u16,
}

impl PeriodicityAndOffset {
    /// `CSI-ResourcePeriodicityAndOffset` (13 alternatives).
    pub(crate) fn decode_csi_resource(r: &mut BitReader) -> DecodeResult<Self> {
        const P: [u16; 13] = [4, 5, 8, 10, 16, 20, 32, 40, 64, 80, 160, 320, 640];
        Self::decode_with(r, &P)
    }

    /// `CSI-ReportPeriodicityAndOffset` (10 alternatives: slots4 … slots320).
    pub(crate) fn decode_csi_report(r: &mut BitReader) -> DecodeResult<Self> {
        const P: [u16; 10] = [4, 5, 8, 10, 16, 20, 40, 80, 160, 320];
        Self::decode_with(r, &P)
    }

    /// `SRS-PeriodicityAndOffset` (17 alternatives: sl1 NULL, sl2 … sl2560).
    pub(crate) fn decode_srs(r: &mut BitReader) -> DecodeResult<Self> {
        const P: [u16; 17] = [
            1, 2, 4, 5, 8, 10, 16, 20, 32, 40, 64, 80, 160, 320, 640, 1280, 2560,
        ];
        Self::decode_with(r, &P)
    }

    fn decode_with(r: &mut BitReader, periods: &[u16]) -> DecodeResult<Self> {
        let alt = r.uint(0, periods.len() as u32 - 1)? as usize;
        let period_slots = periods[alt];
        let offset = if period_slots > 1 {
            r.u16(0, period_slots - 1)?
        } else {
            0
        };
        Ok(Self {
            period_slots,
            offset,
        })
    }
}

/// `CSI-FrequencyOccupation ::= SEQUENCE { startingRB INTEGER (0..maxNrofPhysicalResourceBlocks-1),
/// nrofRBs INTEGER (24..maxNrofPhysicalResourceBlocksPlus1), ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CsiFrequencyOccupation {
    pub starting_rb: u16,
    pub nrof_rbs: u16,
}

impl CsiFrequencyOccupation {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let starting_rb = r.u16(0, 274)?;
        let nrof_rbs = r.u16(24, 276)?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            starting_rb,
            nrof_rbs,
        })
    }
}

/// `frequencyDomainAllocation CHOICE { row1 BIT STRING (SIZE (4)), row2 BIT STRING
/// (SIZE (12)), row4 BIT STRING (SIZE (3)), other BIT STRING (SIZE (6)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CsiRsFrequencyDomainAllocation {
    /// 1, 2, 4, or 0 for `other`.
    pub row: u8,
    /// The bit string MSB-first in the low bits (width 4/12/3/6).
    pub bits: u16,
}

impl CsiRsFrequencyDomainAllocation {
    /// Width of `bits` in bits.
    pub fn width(&self) -> u32 {
        match self.row {
            1 => 4,
            2 => 12,
            4 => 3,
            _ => 6,
        }
    }
}

/// `cdm-Type ENUMERATED { noCDM, fd-CDM2, cdm4-FD2-TD2, cdm8-FD2-TD4 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdmType {
    NoCdm,
    FdCdm2,
    Cdm4Fd2Td2,
    Cdm8Fd2Td4,
}

/// `density CHOICE { dot5 ENUMERATED { evenPRBs, oddPRBs }, one NULL, three NULL, spare NULL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsiRsDensity {
    Dot5EvenPrbs,
    Dot5OddPrbs,
    One,
    Three,
    Spare,
}

/// `CSI-RS-ResourceMapping ::= SEQUENCE { frequencyDomainAllocation CHOICE {…},
/// nrofPorts ENUMERATED { p1, p2, p4, p8, p12, p16, p24, p32 },
/// firstOFDMSymbolInTimeDomain INTEGER (0..13), firstOFDMSymbolInTimeDomain2 INTEGER (2..12)
/// OPTIONAL, cdm-Type ENUMERATED {…}, density CHOICE {…}, freqBand CSI-FrequencyOccupation, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiRsResourceMapping {
    pub frequency_domain_allocation: CsiRsFrequencyDomainAllocation,
    pub nrof_ports: u8,
    pub first_ofdm_symbol_in_time_domain: u8,
    pub first_ofdm_symbol_in_time_domain2: Option<u8>,
    pub cdm_type: CdmType,
    pub density: CsiRsDensity,
    pub freq_band: CsiFrequencyOccupation,
}

impl CsiRsResourceMapping {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_sym2] = r.opt_bits::<1>()?;
        let frequency_domain_allocation = match r.uint(0, 3)? {
            0 => CsiRsFrequencyDomainAllocation {
                row: 1,
                bits: r.bitstring(4)? as u16,
            },
            1 => CsiRsFrequencyDomainAllocation {
                row: 2,
                bits: r.bitstring(12)? as u16,
            },
            2 => CsiRsFrequencyDomainAllocation {
                row: 4,
                bits: r.bitstring(3)? as u16,
            },
            _ => CsiRsFrequencyDomainAllocation {
                row: 0,
                bits: r.bitstring(6)? as u16,
            },
        };
        const PORTS: [u8; 8] = [1, 2, 4, 8, 12, 16, 24, 32];
        let nrof_ports = PORTS[r.enu(8)? as usize];
        let first_ofdm_symbol_in_time_domain = r.u8(0, 13)?;
        let first_ofdm_symbol_in_time_domain2 = r.opt(has_sym2, |r| r.u8(2, 12))?;
        let cdm_type = match r.enu(4)? {
            0 => CdmType::NoCdm,
            1 => CdmType::FdCdm2,
            2 => CdmType::Cdm4Fd2Td2,
            _ => CdmType::Cdm8Fd2Td4,
        };
        let density = match r.uint(0, 3)? {
            0 => {
                if r.enu(2)? == 0 {
                    CsiRsDensity::Dot5EvenPrbs
                } else {
                    CsiRsDensity::Dot5OddPrbs
                }
            }
            1 => CsiRsDensity::One,
            2 => CsiRsDensity::Three,
            _ => CsiRsDensity::Spare,
        };
        let freq_band = CsiFrequencyOccupation::decode(r).ctx("freqBand")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            frequency_domain_allocation,
            nrof_ports,
            first_ofdm_symbol_in_time_domain,
            first_ofdm_symbol_in_time_domain2,
            cdm_type,
            density,
            freq_band,
        })
    }
}

/// `Alpha ::= ENUMERATED { alpha0, alpha04, alpha05, alpha06, alpha07, alpha08, alpha09, alpha1 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alpha(pub u8);

impl Alpha {
    pub(crate) fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(Self(r.enu(8)? as u8))
    }

    /// The pathloss compensation factor α.
    pub fn value(self) -> f32 {
        [0.0, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0][self.0.min(7) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliv_and_riv() {
        assert_eq!(sliv_to_sl(53), (2, 12));
        assert_eq!(sliv_to_sl(72), (2, 6));
        assert_eq!(riv_to_start_len(0, 275), (0, 1));
        // 24 RBs at RB 0: RIV = 275 * 23 + 0.
        assert_eq!(riv_to_start_len(275 * 23, 275), (0, 24));
    }

    #[test]
    fn plmn_round_trip() {
        let p = PlmnIdentity {
            mcc: Some([0, 0, 1]),
            mnc: vec![0, 1],
        };
        let mut w = BitWriter::new();
        p.encode(&mut w);
        let b = w.finish();
        assert_eq!(PlmnIdentity::decode(&mut BitReader::new(&b)).unwrap(), p);
    }
}
