//! `CellGroupConfig` (TS 38.331 §6.3.2): the dedicated MAC/PHY configuration
//! carried in `RRCSetup`/`RRCReconfiguration → masterCellGroup`, decoded into
//! structured types that mirror the ASN.1. Decode-only: the UE never sends it.
//!
//! Branches a standalone UE does not need (`reconfigurationWithSync`, SCell
//! lists, configured grants, beam failure recovery, cross-carrier scheduling,
//! `slotFormatIndicator`, `codebookConfig`, CSI trigger-state lists) fail with
//! [`crate::uper::DecodeErrorKind::Unsupported`] rather than misparse.

use crate::common::{
    decode_tdra_list, Alpha, ControlResourceSet, CsiRsResourceMapping, PeriodicityAndOffset,
    ReferenceSignal, SearchSpace, SubcarrierSpacing, TdraRow, TimeAlignmentTimer,
};
pub use crate::csi::*;
use crate::sib1::{BwpDownlinkCommon, BwpUplinkCommon};
use crate::uper::{BitReader, Ctx, DecodeResult, SetupRelease};
use ferrite_common::Rnti;

// ---------------------------------------------------------------------------
// RLC bearers
// ---------------------------------------------------------------------------

/// `servedRadioBearer CHOICE { srb-Identity SRB-Identity, drb-Identity DRB-Identity }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServedRadioBearer {
    Srb(u8),
    Drb(u8),
}

/// `UL-AM-RLC ::= SEQUENCE { sn-FieldLength SN-FieldLengthAM OPTIONAL, t-PollRetransmit
/// T-PollRetransmit, pollPDU PollPDU, pollByte PollByte, maxRetxThreshold ENUMERATED { t1,
/// t2, t3, t4, t6, t8, t16, t32 } }` with the enumerations resolved to their values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UlAmRlc {
    /// 12 or 18 (`size12`/`size18`); absent ⇒ 12 per TS 38.331.
    pub sn_field_length: Option<u8>,
    pub t_poll_retransmit_ms: u16,
    /// `None` = infinity.
    pub poll_pdu: Option<u32>,
    /// In kilobytes; `None` = infinity.
    pub poll_byte_kb: Option<u32>,
    pub max_retx_threshold: u8,
}

/// `DL-AM-RLC ::= SEQUENCE { sn-FieldLength SN-FieldLengthAM OPTIONAL, t-Reassembly T-Reassembly,
/// t-StatusProhibit T-StatusProhibit }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DlAmRlc {
    pub sn_field_length: Option<u8>,
    pub t_reassembly_ms: u8,
    pub t_status_prohibit_ms: u16,
}

/// `UL-UM-RLC ::= SEQUENCE { sn-FieldLength SN-FieldLengthUM OPTIONAL }` (6 or 12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UlUmRlc {
    pub sn_field_length: Option<u8>,
}

/// `DL-UM-RLC ::= SEQUENCE { sn-FieldLength SN-FieldLengthUM OPTIONAL, t-Reassembly T-Reassembly }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DlUmRlc {
    pub sn_field_length: Option<u8>,
    pub t_reassembly_ms: u8,
}

/// `RLC-Config ::= CHOICE { am SEQUENCE { ul-AM-RLC, dl-AM-RLC }, um-Bi-Directional SEQUENCE
/// { ul-UM-RLC, dl-UM-RLC }, um-Uni-Directional-UL SEQUENCE { ul-UM-RLC }, um-Uni-Directional-DL
/// SEQUENCE { dl-UM-RLC }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlcConfig {
    Am { ul: UlAmRlc, dl: DlAmRlc },
    UmBiDirectional { ul: UlUmRlc, dl: DlUmRlc },
    UmUniDirectionalUl { ul: UlUmRlc },
    UmUniDirectionalDl { dl: DlUmRlc },
}

/// `T-PollRetransmit ::= ENUMERATED { ms5, ms10, …, ms250 (step 5), ms300, ms350, ms400,
/// ms450, ms500, ms800, ms1000, ms2000, ms4000, ms1-v1610, ms2-v1610, ms3-v1610, ms4-v1610, spare1 }`.
fn t_poll_retransmit_ms(idx: u32) -> u16 {
    match idx {
        0..=49 => 5 * (idx as u16 + 1),
        50..=54 => 300 + 50 * (idx as u16 - 50),
        55 => 800,
        56 => 1000,
        57 => 2000,
        58 => 4000,
        59..=62 => idx as u16 - 58,
        _ => 0,
    }
}

/// `PollPDU ::= ENUMERATED { p4, p8, p16, p32, p64, p128, p256, p512, p1024, p2048, p4096,
/// p6144, p8192, p12288, p16384, p20480, p24576, p28672, p32768, p40960, p49152, p57344,
/// p65536, infinity, spare8..spare1 }`.
fn poll_pdu(idx: u32) -> Option<u32> {
    const V: [u32; 23] = [
        4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 6144, 8192, 12288, 16384, 20480, 24576,
        28672, 32768, 40960, 49152, 57344, 65536,
    ];
    V.get(idx as usize).copied()
}

/// `PollByte ::= ENUMERATED { kB1, kB2, kB5, kB8, kB10, kB15, kB25, kB50, kB75, kB100, kB125,
/// kB250, kB375, kB500, kB750, kB1000, kB1250, kB1500, kB2000, kB3000, kB4000, kB4500, kB5000,
/// kB5500, kB6000, kB6500, kB7000, kB7500, mB8, mB9, mB10, mB11, mB12, mB13, mB14, mB15, mB16,
/// mB17, mB18, mB20, mB25, mB30, mB40, infinity, spare20..spare1 }` in kB.
fn poll_byte_kb(idx: u32) -> Option<u32> {
    const V: [u32; 43] = [
        1, 2, 5, 8, 10, 15, 25, 50, 75, 100, 125, 250, 375, 500, 750, 1000, 1250, 1500, 2000, 3000,
        4000, 4500, 5000, 5500, 6000, 6500, 7000, 7500, 8000, 9000, 10000, 11000, 12000, 13000,
        14000, 15000, 16000, 17000, 18000, 20000, 25000, 30000, 40000,
    ];
    V.get(idx as usize).copied()
}

/// `T-Reassembly ::= ENUMERATED { ms0, ms5, …, ms100 (step 5), ms110, …, ms200 (step 10), spare1 }`.
fn t_reassembly_ms(idx: u32) -> u8 {
    match idx {
        0..=20 => 5 * idx as u8,
        21..=30 => 100 + 10 * (idx as u8 - 20),
        _ => 0,
    }
}

/// `T-StatusProhibit ::= ENUMERATED { ms0, ms5, …, ms250 (step 5), ms300, ms350, ms400, ms450,
/// ms500, ms800, ms1000, ms1200, ms1600, ms2000, ms2400, spare2, spare1 }`.
fn t_status_prohibit_ms(idx: u32) -> u16 {
    match idx {
        0..=50 => 5 * idx as u16,
        51..=55 => 300 + 50 * (idx as u16 - 51),
        56 => 800,
        57 => 1000,
        58 => 1200,
        59 => 1600,
        60 => 2000,
        61 => 2400,
        _ => 0,
    }
}

impl RlcConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("RLC-Config extension alternative");
        }
        let sn_am = |r: &mut BitReader| -> DecodeResult<Option<u8>> {
            let [has] = r.opt_bits::<1>()?;
            r.opt(has, |r| Ok([12u8, 18][r.enu(2)? as usize]))
        };
        let sn_um = |r: &mut BitReader| -> DecodeResult<Option<u8>> {
            let [has] = r.opt_bits::<1>()?;
            r.opt(has, |r| Ok([6u8, 12][r.enu(2)? as usize]))
        };
        let ul_um = |r: &mut BitReader| {
            Ok(UlUmRlc {
                sn_field_length: sn_um(r)?,
            })
        };
        let dl_um = |r: &mut BitReader| {
            let sn_field_length = sn_um(r)?;
            let t_reassembly_ms = t_reassembly_ms(r.enu(32)?);
            Ok(DlUmRlc {
                sn_field_length,
                t_reassembly_ms,
            })
        };
        Ok(match r.uint(0, 3)? {
            0 => {
                let sn_field_length = sn_am(r)?;
                let t_poll_retransmit_ms = t_poll_retransmit_ms(r.enu(64)?);
                let poll_pdu = poll_pdu(r.enu(32)?);
                let poll_byte_kb = poll_byte_kb(r.enu(64)?);
                let max_retx_threshold = [1u8, 2, 3, 4, 6, 8, 16, 32][r.enu(8)? as usize];
                let ul = UlAmRlc {
                    sn_field_length,
                    t_poll_retransmit_ms,
                    poll_pdu,
                    poll_byte_kb,
                    max_retx_threshold,
                };
                let sn_field_length = sn_am(r)?;
                let t_reassembly_ms = t_reassembly_ms(r.enu(32)?);
                let t_status_prohibit_ms = t_status_prohibit_ms(r.enu(64)?);
                let dl = DlAmRlc {
                    sn_field_length,
                    t_reassembly_ms,
                    t_status_prohibit_ms,
                };
                RlcConfig::Am { ul, dl }
            }
            1 => {
                let ul = ul_um(r)?;
                let dl = dl_um(r)?;
                RlcConfig::UmBiDirectional { ul, dl }
            }
            2 => RlcConfig::UmUniDirectionalUl { ul: ul_um(r)? },
            _ => RlcConfig::UmUniDirectionalDl { dl: dl_um(r)? },
        })
    }
}

/// `ul-SpecificParameters SEQUENCE { priority INTEGER (1..16), prioritisedBitRate ENUMERATED
/// { kBps0, kBps8, kBps16, kBps32, kBps64, kBps128, kBps256, kBps512, kBps1024, kBps2048,
/// kBps4096, kBps8192, kBps16384, kBps32768, kBps65536, infinity }, bucketSizeDuration ENUMERATED
/// { ms5, ms10, ms20, ms50, ms100, ms150, ms300, ms500, ms1000, spare7..spare1 },
/// allowedServingCells SEQUENCE (SIZE (1..maxNrofServingCells-1)) OF ServCellIndex OPTIONAL,
/// allowedSCS-List SEQUENCE (SIZE (1..maxSCSs)) OF SubcarrierSpacing OPTIONAL, maxPUSCH-Duration
/// ENUMERATED { ms0p02, ms0p04, ms0p0625, ms0p125, ms0p25, ms0p5, ms0p01-v1700, spare1 } OPTIONAL,
/// configuredGrantType1Allowed ENUMERATED { true } OPTIONAL, logicalChannelGroup INTEGER
/// (0..maxLCG-ID) OPTIONAL, schedulingRequestID SchedulingRequestId OPTIONAL, logicalChannelSR-Mask
/// BOOLEAN, logicalChannelSR-DelayTimerApplied BOOLEAN, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UlSpecificParameters {
    pub priority: u8,
    /// In kB/s; `None` = infinity.
    pub prioritised_bit_rate_kbps: Option<u32>,
    pub bucket_size_duration_ms: u16,
    pub allowed_serving_cells: Vec<u8>,
    pub allowed_scs_list: Vec<SubcarrierSpacing>,
    /// Raw enumeration index of `maxPUSCH-Duration`.
    pub max_pusch_duration: Option<u8>,
    pub configured_grant_type1_allowed: bool,
    pub logical_channel_group: Option<u8>,
    pub scheduling_request_id: Option<u8>,
    pub logical_channel_sr_mask: bool,
    pub logical_channel_sr_delay_timer_applied: bool,
}

/// `LogicalChannelConfig ::= SEQUENCE { ul-SpecificParameters SEQUENCE {…} OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalChannelConfig {
    pub ul_specific_parameters: Option<UlSpecificParameters>,
}

impl LogicalChannelConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_ul] = r.opt_bits::<1>()?;
        let ul_specific_parameters = r.opt(has_ul, |r| {
            let uext = r.bit()?;
            let o = r.opt_bits::<6>()?;
            let priority = r.u8(1, 16)?;
            let pbr = r.enu(16)?;
            let prioritised_bit_rate_kbps =
                (pbr < 15).then(|| if pbr == 0 { 0 } else { 8u32 << (pbr - 1) });
            const BSD: [u16; 16] = [5, 10, 20, 50, 100, 150, 300, 500, 1000, 0, 0, 0, 0, 0, 0, 0];
            let bucket_size_duration_ms = BSD[r.enu(16)? as usize];
            let allowed_serving_cells = if o[0] {
                r.seq_of(1, 31, |r| r.u8(0, 31))?
            } else {
                vec![]
            };
            let allowed_scs_list = if o[1] {
                r.seq_of(1, 5, SubcarrierSpacing::decode)?
            } else {
                vec![]
            };
            let max_pusch_duration = r.opt(o[2], |r| Ok(r.enu(8)? as u8))?;
            let logical_channel_group = r.opt(o[4], |r| r.u8(0, 7))?;
            let scheduling_request_id = r.opt(o[5], |r| r.u8(0, 7))?;
            let logical_channel_sr_mask = r.boolean()?;
            let logical_channel_sr_delay_timer_applied = r.boolean()?;
            if uext {
                r.skip_ext_additions()?;
            }
            Ok(UlSpecificParameters {
                priority,
                prioritised_bit_rate_kbps,
                bucket_size_duration_ms,
                allowed_serving_cells,
                allowed_scs_list,
                max_pusch_duration,
                configured_grant_type1_allowed: o[3],
                logical_channel_group,
                scheduling_request_id,
                logical_channel_sr_mask,
                logical_channel_sr_delay_timer_applied,
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            ul_specific_parameters,
        })
    }
}

/// `RLC-BearerConfig ::= SEQUENCE { logicalChannelIdentity LogicalChannelIdentity,
/// servedRadioBearer CHOICE {…} OPTIONAL, reestablishRLC ENUMERATED { true } OPTIONAL,
/// rlc-Config RLC-Config OPTIONAL, mac-LogicalChannelConfig LogicalChannelConfig OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RlcBearerConfig {
    pub logical_channel_identity: u8,
    pub served_radio_bearer: Option<ServedRadioBearer>,
    pub reestablish_rlc: bool,
    pub rlc_config: Option<RlcConfig>,
    pub mac_logical_channel_config: Option<LogicalChannelConfig>,
}

impl RlcBearerConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [served, reest, rlc, lch] = r.opt_bits::<4>()?;
        let logical_channel_identity = r.u8(1, 32)?;
        let served_radio_bearer = r.opt(served, |r| {
            Ok(if !r.bit()? {
                ServedRadioBearer::Srb(r.u8(1, 3)?)
            } else {
                ServedRadioBearer::Drb(r.u8(1, 32)?)
            })
        })?;
        let rlc_config = r.opt(rlc, RlcConfig::decode).ctx("rlc-Config")?;
        let mac_logical_channel_config = r
            .opt(lch, LogicalChannelConfig::decode)
            .ctx("mac-LogicalChannelConfig")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            logical_channel_identity,
            served_radio_bearer,
            reestablish_rlc: reest,
            rlc_config,
            mac_logical_channel_config,
        })
    }
}

// ---------------------------------------------------------------------------
// MAC-CellGroupConfig
// ---------------------------------------------------------------------------

/// `drx-onDurationTimer CHOICE { subMilliSeconds INTEGER (1..31), milliSeconds ENUMERATED {…} }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrxOnDurationTimer {
    /// In 1/32 ms.
    SubMilliSeconds(u8),
    MilliSeconds(u16),
}

/// `shortDRX SEQUENCE { drx-ShortCycle ENUMERATED {…}, drx-ShortCycleTimer INTEGER (1..16) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortDrx {
    pub drx_short_cycle_ms: u16,
    pub drx_short_cycle_timer: u8,
}

/// `DRX-Config ::= SEQUENCE { drx-onDurationTimer CHOICE {…}, drx-InactivityTimer ENUMERATED {…},
/// drx-HARQ-RTT-TimerDL INTEGER (0..56), drx-HARQ-RTT-TimerUL INTEGER (0..56),
/// drx-RetransmissionTimerDL ENUMERATED {…}, drx-RetransmissionTimerUL ENUMERATED {…},
/// drx-LongCycleStartOffset CHOICE { ms10 INTEGER (0..9), …, ms10240 INTEGER (0..10239) },
/// shortDRX SEQUENCE {…} OPTIONAL, drx-SlotOffset INTEGER (0..31) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrxConfig {
    pub drx_on_duration_timer: DrxOnDurationTimer,
    pub drx_inactivity_timer_ms: u16,
    pub drx_harq_rtt_timer_dl: u8,
    pub drx_harq_rtt_timer_ul: u8,
    pub drx_retransmission_timer_dl_slots: u16,
    pub drx_retransmission_timer_ul_slots: u16,
    pub drx_long_cycle_ms: u16,
    pub drx_long_cycle_start_offset: u16,
    pub short_drx: Option<ShortDrx>,
    pub drx_slot_offset: u8,
}

impl DrxConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        const MS32: [u16; 32] = [
            1, 2, 3, 4, 5, 6, 8, 10, 20, 30, 40, 50, 60, 80, 100, 200, 300, 400, 500, 600, 800,
            1000, 1200, 1600, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        const INACT: [u16; 32] = [
            0, 1, 2, 3, 4, 5, 6, 8, 10, 20, 30, 40, 50, 60, 80, 100, 200, 300, 500, 750, 1280,
            1920, 2560, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        const RETX: [u16; 32] = [
            0, 1, 2, 4, 6, 8, 16, 24, 33, 40, 64, 80, 96, 112, 128, 160, 320, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        const LONG: [u16; 20] = [
            10, 20, 32, 40, 60, 64, 70, 80, 128, 160, 256, 320, 512, 640, 1024, 1280, 2048, 2560,
            5120, 10240,
        ];
        const SHORT: [u16; 32] = [
            2, 3, 4, 5, 6, 7, 8, 10, 14, 16, 20, 30, 32, 35, 40, 64, 80, 128, 160, 256, 320, 512,
            640, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let [has_short] = r.opt_bits::<1>()?;
        let drx_on_duration_timer = if !r.bit()? {
            DrxOnDurationTimer::SubMilliSeconds(r.u8(1, 31)?)
        } else {
            DrxOnDurationTimer::MilliSeconds(MS32[r.enu(32)? as usize])
        };
        let drx_inactivity_timer_ms = INACT[r.enu(32)? as usize];
        let drx_harq_rtt_timer_dl = r.u8(0, 56)?;
        let drx_harq_rtt_timer_ul = r.u8(0, 56)?;
        let drx_retransmission_timer_dl_slots = RETX[r.enu(32)? as usize];
        let drx_retransmission_timer_ul_slots = RETX[r.enu(32)? as usize];
        let drx_long_cycle_ms = LONG[r.uint(0, 19)? as usize];
        let drx_long_cycle_start_offset = r.u16(0, drx_long_cycle_ms - 1)?;
        let short_drx = r.opt(has_short, |r| {
            let drx_short_cycle_ms = SHORT[r.enu(32)? as usize];
            let drx_short_cycle_timer = r.u8(1, 16)?;
            Ok(ShortDrx {
                drx_short_cycle_ms,
                drx_short_cycle_timer,
            })
        })?;
        let drx_slot_offset = r.u8(0, 31)?;
        Ok(Self {
            drx_on_duration_timer,
            drx_inactivity_timer_ms,
            drx_harq_rtt_timer_dl,
            drx_harq_rtt_timer_ul,
            drx_retransmission_timer_dl_slots,
            drx_retransmission_timer_ul_slots,
            drx_long_cycle_ms,
            drx_long_cycle_start_offset,
            short_drx,
            drx_slot_offset,
        })
    }
}

/// `SchedulingRequestToAddMod ::= SEQUENCE { schedulingRequestId SchedulingRequestId,
/// sr-ProhibitTimer ENUMERATED { ms1, ms2, ms4, ms8, ms16, ms32, ms64, ms128 } OPTIONAL,
/// sr-TransMax ENUMERATED { n4, n8, n16, n32, n64, spare3, spare2, spare1 } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulingRequestToAddMod {
    pub scheduling_request_id: u8,
    pub sr_prohibit_timer_ms: Option<u8>,
    pub sr_trans_max: u8,
}

/// `SchedulingRequestConfig ::= SEQUENCE { schedulingRequestToAddModList SEQUENCE (SIZE
/// (1..maxNrofSR-ConfigPerCellGroup)) OF SchedulingRequestToAddMod OPTIONAL,
/// schedulingRequestToReleaseList … OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SchedulingRequestConfig {
    pub scheduling_request_to_add_mod_list: Vec<SchedulingRequestToAddMod>,
    pub scheduling_request_to_release_list: Vec<u8>,
}

/// `BSR-Config ::= SEQUENCE { periodicBSR-Timer ENUMERATED { sf1, sf5, sf10, sf16, sf20, sf32,
/// sf40, sf64, sf80, sf128, sf160, sf320, sf640, sf1280, sf2560, infinity }, retxBSR-Timer
/// ENUMERATED { sf10, sf20, sf40, sf80, sf160, sf320, sf640, sf1280, sf2560, sf5120, sf10240,
/// spare5..spare1 }, logicalChannelSR-DelayTimer ENUMERATED { sf20, sf40, sf64, sf128, sf512,
/// sf1024, sf2560, spare1 } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BsrConfig {
    /// `None` = infinity.
    pub periodic_bsr_timer_sf: Option<u16>,
    pub retx_bsr_timer_sf: u16,
    pub logical_channel_sr_delay_timer_sf: Option<u16>,
}

/// `TAG ::= SEQUENCE { tag-Id TAG-Id, timeAlignmentTimer TimeAlignmentTimer, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    pub tag_id: u8,
    pub time_alignment_timer: TimeAlignmentTimer,
}

/// `TAG-Config ::= SEQUENCE { tag-ToReleaseList … OPTIONAL, tag-ToAddModList … OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TagConfig {
    pub tag_to_release_list: Vec<u8>,
    pub tag_to_add_mod_list: Vec<Tag>,
}

/// `PHR-Config ::= SEQUENCE { phr-PeriodicTimer ENUMERATED { sf10, sf20, sf50, sf100, sf200,
/// sf500, sf1000, infinity }, phr-ProhibitTimer ENUMERATED { sf0, sf10, sf20, sf50, sf100, sf200,
/// sf500, sf1000 }, phr-Tx-PowerFactorChange ENUMERATED { dB1, dB3, dB6, infinity }, multiplePHR
/// BOOLEAN, dummy BOOLEAN, phr-Type2OtherCell BOOLEAN, phr-ModeOtherCG ENUMERATED { real,
/// virtual }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhrConfig {
    /// `None` = infinity.
    pub phr_periodic_timer_sf: Option<u16>,
    pub phr_prohibit_timer_sf: u16,
    /// `None` = infinity.
    pub phr_tx_power_factor_change_db: Option<u8>,
    pub multiple_phr: bool,
    pub dummy: bool,
    pub phr_type2_other_cell: bool,
    /// `true` = real, `false` = virtual.
    pub phr_mode_other_cg_real: bool,
}

/// `MAC-CellGroupConfig ::= SEQUENCE { drx-Config SetupRelease { DRX-Config } OPTIONAL,
/// schedulingRequestConfig SchedulingRequestConfig OPTIONAL, bsr-Config BSR-Config OPTIONAL,
/// tag-Config TAG-Config OPTIONAL, phr-Config SetupRelease { PHR-Config } OPTIONAL,
/// skipUplinkTxDynamic BOOLEAN, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacCellGroupConfig {
    pub drx_config: Option<SetupRelease<DrxConfig>>,
    pub scheduling_request_config: Option<SchedulingRequestConfig>,
    pub bsr_config: Option<BsrConfig>,
    pub tag_config: Option<TagConfig>,
    pub phr_config: Option<SetupRelease<PhrConfig>>,
    pub skip_uplink_tx_dynamic: bool,
}

impl MacCellGroupConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [drx, src, bsr, tag, phr] = r.opt_bits::<5>()?;
        let drx_config = r
            .opt(drx, |r| r.setup_release(DrxConfig::decode))
            .ctx("drx-Config")?;
        let scheduling_request_config = r
            .opt(src, |r| {
                let [add, rel] = r.opt_bits::<2>()?;
                let mut c = SchedulingRequestConfig::default();
                if add {
                    c.scheduling_request_to_add_mod_list = r.seq_of(1, 8, |r| {
                        let [has_pro] = r.opt_bits::<1>()?;
                        let scheduling_request_id = r.u8(0, 7)?;
                        let sr_prohibit_timer_ms = r.opt(has_pro, |r| Ok(1u8 << r.enu(8)?))?;
                        const TM: [u8; 8] = [4, 8, 16, 32, 64, 0, 0, 0];
                        let sr_trans_max = TM[r.enu(8)? as usize];
                        Ok(SchedulingRequestToAddMod {
                            scheduling_request_id,
                            sr_prohibit_timer_ms,
                            sr_trans_max,
                        })
                    })?;
                }
                if rel {
                    c.scheduling_request_to_release_list = r.seq_of(1, 8, |r| r.u8(0, 7))?;
                }
                Ok(c)
            })
            .ctx("schedulingRequestConfig")?;
        let bsr_config = r
            .opt(bsr, |r| {
                let e = r.bit()?;
                let [has_delay] = r.opt_bits::<1>()?;
                const PERIODIC: [u16; 16] = [
                    1, 5, 10, 16, 20, 32, 40, 64, 80, 128, 160, 320, 640, 1280, 2560, 0,
                ];
                let p = r.enu(16)?;
                let periodic_bsr_timer_sf = (p < 15).then(|| PERIODIC[p as usize]);
                const RETX: [u16; 16] = [
                    10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120, 10240, 0, 0, 0, 0, 0,
                ];
                let retx_bsr_timer_sf = RETX[r.enu(16)? as usize];
                const DELAY: [u16; 8] = [20, 40, 64, 128, 512, 1024, 2560, 0];
                let logical_channel_sr_delay_timer_sf =
                    r.opt(has_delay, |r| Ok(DELAY[r.enu(8)? as usize]))?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(BsrConfig {
                    periodic_bsr_timer_sf,
                    retx_bsr_timer_sf,
                    logical_channel_sr_delay_timer_sf,
                })
            })
            .ctx("bsr-Config")?;
        let tag_config = r
            .opt(tag, |r| {
                let [rel, add] = r.opt_bits::<2>()?;
                let mut c = TagConfig::default();
                if rel {
                    c.tag_to_release_list = r.seq_of(1, 4, |r| r.u8(0, 3))?;
                }
                if add {
                    c.tag_to_add_mod_list = r.seq_of(1, 4, |r| {
                        let e = r.bit()?;
                        let tag_id = r.u8(0, 3)?;
                        let time_alignment_timer = TimeAlignmentTimer::decode(r)?;
                        if e {
                            r.skip_ext_additions()?;
                        }
                        Ok(Tag {
                            tag_id,
                            time_alignment_timer,
                        })
                    })?;
                }
                Ok(c)
            })
            .ctx("tag-Config")?;
        let phr_config = r
            .opt(phr, |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    const PER: [u16; 8] = [10, 20, 50, 100, 200, 500, 1000, 0];
                    let p = r.enu(8)?;
                    let phr_periodic_timer_sf = (p < 7).then(|| PER[p as usize]);
                    const PRO: [u16; 8] = [0, 10, 20, 50, 100, 200, 500, 1000];
                    let phr_prohibit_timer_sf = PRO[r.enu(8)? as usize];
                    let f = r.enu(4)?;
                    let phr_tx_power_factor_change_db = (f < 3).then(|| [1u8, 3, 6][f as usize]);
                    let multiple_phr = r.boolean()?;
                    let dummy = r.boolean()?;
                    let phr_type2_other_cell = r.boolean()?;
                    let phr_mode_other_cg_real = r.enu(2)? == 0;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PhrConfig {
                        phr_periodic_timer_sf,
                        phr_prohibit_timer_sf,
                        phr_tx_power_factor_change_db,
                        multiple_phr,
                        dummy,
                        phr_type2_other_cell,
                        phr_mode_other_cg_real,
                    })
                })
            })
            .ctx("phr-Config")?;
        let skip_uplink_tx_dynamic = r.boolean()?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            drx_config,
            scheduling_request_config,
            bsr_config,
            tag_config,
            phr_config,
            skip_uplink_tx_dynamic,
        })
    }
}

// ---------------------------------------------------------------------------
// PhysicalCellGroupConfig / SpCellConfig / ServingCellConfig
// ---------------------------------------------------------------------------

/// `pdsch-HARQ-ACK-Codebook ENUMERATED { semiStatic, dynamic }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarqAckCodebook {
    SemiStatic,
    Dynamic,
}

/// `PhysicalCellGroupConfig ::= SEQUENCE { harq-ACK-SpatialBundlingPUCCH ENUMERATED { true }
/// OPTIONAL, harq-ACK-SpatialBundlingPUSCH ENUMERATED { true } OPTIONAL, p-NR-FR1 P-Max OPTIONAL,
/// pdsch-HARQ-ACK-Codebook ENUMERATED {…}, tpc-SRS-RNTI RNTI-Value OPTIONAL, tpc-PUCCH-RNTI
/// RNTI-Value OPTIONAL, tpc-PUSCH-RNTI RNTI-Value OPTIONAL, sp-CSI-RNTI RNTI-Value OPTIONAL,
/// cs-RNTI SetupRelease { RNTI-Value } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalCellGroupConfig {
    pub harq_ack_spatial_bundling_pucch: bool,
    pub harq_ack_spatial_bundling_pusch: bool,
    pub p_nr_fr1: Option<i8>,
    pub pdsch_harq_ack_codebook: HarqAckCodebook,
    pub tpc_srs_rnti: Option<Rnti>,
    pub tpc_pucch_rnti: Option<Rnti>,
    pub tpc_pusch_rnti: Option<Rnti>,
    pub sp_csi_rnti: Option<Rnti>,
    pub cs_rnti: Option<SetupRelease<Rnti>>,
}

impl PhysicalCellGroupConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<8>()?;
        let p_nr_fr1 = r.opt(o[2], |r| Ok(r.int(-30, 33)? as i8))?;
        let pdsch_harq_ack_codebook = if r.enu(2)? == 0 {
            HarqAckCodebook::SemiStatic
        } else {
            HarqAckCodebook::Dynamic
        };
        let rnti = |r: &mut BitReader| Ok(Rnti(r.u16(0, 65535)?));
        let tpc_srs_rnti = r.opt(o[3], rnti)?;
        let tpc_pucch_rnti = r.opt(o[4], rnti)?;
        let tpc_pusch_rnti = r.opt(o[5], rnti)?;
        let sp_csi_rnti = r.opt(o[6], rnti)?;
        let cs_rnti = r.opt(o[7], |r| r.setup_release(rnti))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            harq_ack_spatial_bundling_pucch: o[0],
            harq_ack_spatial_bundling_pusch: o[1],
            p_nr_fr1,
            pdsch_harq_ack_codebook,
            tpc_srs_rnti,
            tpc_pucch_rnti,
            tpc_pusch_rnti,
            sp_csi_rnti,
            cs_rnti,
        })
    }
}

/// `RLF-TimersAndConstants ::= SEQUENCE { t310 ENUMERATED { ms0, ms50, ms100, ms200, ms500,
/// ms1000, ms2000, ms4000, ms6000 }, n310 ENUMERATED { n1, n2, n3, n4, n6, n8, n10, n20 }, n311
/// ENUMERATED { n1, n2, n3, n4, n5, n6, n8, n10 }, ..., [[ t311 ENUMERATED {…} ]] }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RlfTimersAndConstants {
    pub t310_ms: u16,
    pub n310: u8,
    pub n311: u8,
}

/// `TDD-UL-DL-SlotConfig ::= SEQUENCE { slotIndex TDD-UL-DL-SlotIndex, symbols CHOICE {
/// allDownlink NULL, allUplink NULL, explicit SEQUENCE { nrofDownlinkSymbols INTEGER (1..13)
/// OPTIONAL, nrofUplinkSymbols INTEGER (1..13) OPTIONAL } } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TddSlotSymbols {
    AllDownlink,
    AllUplink,
    Explicit {
        nrof_downlink_symbols: Option<u8>,
        nrof_uplink_symbols: Option<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TddUlDlSlotConfig {
    pub slot_index: u16,
    pub symbols: TddSlotSymbols,
}

/// `TDD-UL-DL-ConfigDedicated ::= SEQUENCE { slotSpecificConfigurationsToAddModList SEQUENCE
/// (SIZE (1..maxNrofSlots)) OF TDD-UL-DL-SlotConfig OPTIONAL, slotSpecificConfigurationsToReleaseList
/// … OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TddUlDlConfigDedicated {
    pub slot_specific_configurations_to_add_mod_list: Vec<TddUlDlSlotConfig>,
    pub slot_specific_configurations_to_release_list: Vec<u16>,
}

/// `PDSCH-CodeBlockGroupTransmission ::= SEQUENCE { maxCodeBlockGroupsPerTransportBlock
/// ENUMERATED { n2, n4, n6, n8 }, codeBlockGroupFlushIndicator BOOLEAN, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdschCodeBlockGroupTransmission {
    pub max_code_block_groups_per_transport_block: u8,
    pub code_block_group_flush_indicator: bool,
}

/// `PDSCH-ServingCellConfig ::= SEQUENCE { codeBlockGroupTransmission SetupRelease {…} OPTIONAL,
/// xOverhead ENUMERATED { xOh6, xOh12, xOh18 } OPTIONAL, nrofHARQ-ProcessesForPDSCH ENUMERATED
/// { n2, n4, n6, n10, n12, n16 } OPTIONAL, pucch-Cell ServCellIndex OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdschServingCellConfig {
    pub code_block_group_transmission: Option<SetupRelease<PdschCodeBlockGroupTransmission>>,
    pub x_overhead: Option<u8>,
    /// Absent ⇒ 8 (TS 38.331).
    pub nrof_harq_processes_for_pdsch: Option<u8>,
    pub pucch_cell: Option<u8>,
}

impl PdschServingCellConfig {
    /// `nrofHARQ-ProcessesForPDSCH` with its default of 8.
    pub fn nrof_harq_processes(&self) -> u8 {
        self.nrof_harq_processes_for_pdsch.unwrap_or(8)
    }
}

/// `PDCCH-ServingCellConfig ::= SEQUENCE { slotFormatIndicator SetupRelease { SlotFormatIndicator }
/// OPTIONAL, ... }` — `slotFormatIndicator` is not supported.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PdcchServingCellConfig {}

/// `BWP-Downlink ::= SEQUENCE { bwp-Id BWP-Id, bwp-Common BWP-DownlinkCommon OPTIONAL,
/// bwp-Dedicated BWP-DownlinkDedicated OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpDownlink {
    pub bwp_id: u8,
    pub bwp_common: Option<BwpDownlinkCommon>,
    pub bwp_dedicated: Option<BwpDownlinkDedicated>,
}

/// `ServingCellConfig ::= SEQUENCE { tdd-UL-DL-ConfigurationDedicated OPTIONAL, initialDownlinkBWP
/// BWP-DownlinkDedicated OPTIONAL, downlinkBWP-ToReleaseList OPTIONAL, downlinkBWP-ToAddModList
/// OPTIONAL, firstActiveDownlinkBWP-Id BWP-Id OPTIONAL, bwp-InactivityTimer ENUMERATED {…} OPTIONAL,
/// defaultDownlinkBWP-Id BWP-Id OPTIONAL, uplinkConfig UplinkConfig OPTIONAL, supplementaryUplink
/// UplinkConfig OPTIONAL, pdcch-ServingCellConfig SetupRelease {…} OPTIONAL, pdsch-ServingCellConfig
/// SetupRelease {…} OPTIONAL, csi-MeasConfig SetupRelease { CSI-MeasConfig } OPTIONAL,
/// sCellDeactivationTimer ENUMERATED {…} OPTIONAL, crossCarrierSchedulingConfig OPTIONAL, tag-Id
/// TAG-Id, dummy1 ENUMERATED { enabled } OPTIONAL, pathlossReferenceLinking ENUMERATED { spCell,
/// sCell } OPTIONAL, servingCellMO MeasObjectId OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServingCellConfig {
    pub tdd_ul_dl_configuration_dedicated: Option<TddUlDlConfigDedicated>,
    pub initial_downlink_bwp: Option<BwpDownlinkDedicated>,
    pub downlink_bwp_to_release_list: Vec<u8>,
    pub downlink_bwp_to_add_mod_list: Vec<BwpDownlink>,
    pub first_active_downlink_bwp_id: Option<u8>,
    pub bwp_inactivity_timer_ms: Option<u16>,
    pub default_downlink_bwp_id: Option<u8>,
    pub uplink_config: Option<UplinkConfig>,
    pub supplementary_uplink: Option<UplinkConfig>,
    pub pdcch_serving_cell_config: Option<SetupRelease<PdcchServingCellConfig>>,
    pub pdsch_serving_cell_config: Option<SetupRelease<PdschServingCellConfig>>,
    pub csi_meas_config: Option<SetupRelease<CsiMeasConfig>>,
    pub scell_deactivation_timer_ms: Option<u16>,
    pub tag_id: u8,
    pub dummy1_enabled: bool,
    /// `Some(true)` = spCell, `Some(false)` = sCell.
    pub pathloss_reference_linking_sp_cell: Option<bool>,
    pub serving_cell_mo: Option<u8>,
}

impl ServingCellConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<17>()?;
        let tdd_ul_dl_configuration_dedicated = r
            .opt(o[0], |r| {
                let e = r.bit()?;
                let [add, rel] = r.opt_bits::<2>()?;
                let mut c = TddUlDlConfigDedicated::default();
                if add {
                    c.slot_specific_configurations_to_add_mod_list = r.seq_of(1, 320, |r| {
                        let slot_index = r.u16(0, 319)?;
                        let symbols = match r.uint(0, 2)? {
                            0 => TddSlotSymbols::AllDownlink,
                            1 => TddSlotSymbols::AllUplink,
                            _ => {
                                let [hd, hu] = r.opt_bits::<2>()?;
                                let nrof_downlink_symbols = r.opt(hd, |r| r.u8(1, 13))?;
                                let nrof_uplink_symbols = r.opt(hu, |r| r.u8(1, 13))?;
                                TddSlotSymbols::Explicit {
                                    nrof_downlink_symbols,
                                    nrof_uplink_symbols,
                                }
                            }
                        };
                        Ok(TddUlDlSlotConfig {
                            slot_index,
                            symbols,
                        })
                    })?;
                }
                if rel {
                    c.slot_specific_configurations_to_release_list =
                        r.seq_of(1, 320, |r| r.u16(0, 319))?;
                }
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(c)
            })
            .ctx("tdd-UL-DL-ConfigurationDedicated")?;
        let initial_downlink_bwp = r
            .opt(o[1], BwpDownlinkDedicated::decode)
            .ctx("initialDownlinkBWP")?;
        let downlink_bwp_to_release_list = if o[2] {
            r.seq_of(1, 4, |r| r.u8(0, 4))?
        } else {
            vec![]
        };
        let downlink_bwp_to_add_mod_list = if o[3] {
            r.seq_of(1, 4, |r| {
                let e = r.bit()?;
                let [hc, hd] = r.opt_bits::<2>()?;
                let bwp_id = r.u8(0, 4)?;
                let bwp_common = r.opt(hc, BwpDownlinkCommon::decode)?;
                let bwp_dedicated = r.opt(hd, BwpDownlinkDedicated::decode)?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(BwpDownlink {
                    bwp_id,
                    bwp_common,
                    bwp_dedicated,
                })
            })
            .ctx("downlinkBWP-ToAddModList")?
        } else {
            vec![]
        };
        let first_active_downlink_bwp_id = r.opt(o[4], |r| r.u8(0, 4))?;
        const INACT: [u16; 32] = [
            2, 3, 4, 5, 6, 8, 10, 20, 30, 40, 50, 60, 80, 100, 200, 300, 500, 750, 1280, 1920,
            2560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let bwp_inactivity_timer_ms = r.opt(o[5], |r| Ok(INACT[r.enu(32)? as usize]))?;
        let default_downlink_bwp_id = r.opt(o[6], |r| r.u8(0, 4))?;
        let uplink_config = r.opt(o[7], UplinkConfig::decode).ctx("uplinkConfig")?;
        let supplementary_uplink = r
            .opt(o[8], UplinkConfig::decode)
            .ctx("supplementaryUplink")?;
        let pdcch_serving_cell_config = r
            .opt(o[9], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [sfi] = r.opt_bits::<1>()?;
                    if sfi {
                        return r.unsupported("slotFormatIndicator");
                    }
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PdcchServingCellConfig {})
                })
            })
            .ctx("pdcch-ServingCellConfig")?;
        let pdsch_serving_cell_config = r
            .opt(o[10], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [cbg, xoh, nharq, pcell] = r.opt_bits::<4>()?;
                    let code_block_group_transmission = r.opt(cbg, |r| {
                        r.setup_release(|r| {
                            let ce = r.bit()?;
                            let max_code_block_groups_per_transport_block =
                                2 * (r.enu(4)? as u8 + 1);
                            let code_block_group_flush_indicator = r.boolean()?;
                            if ce {
                                r.skip_ext_additions()?;
                            }
                            Ok(PdschCodeBlockGroupTransmission {
                                max_code_block_groups_per_transport_block,
                                code_block_group_flush_indicator,
                            })
                        })
                    })?;
                    let x_overhead = r.opt(xoh, |r| Ok(6 * (r.enu(3)? as u8 + 1)))?;
                    let nrof_harq_processes_for_pdsch =
                        r.opt(nharq, |r| Ok([2u8, 4, 6, 10, 12, 16][r.enu(6)? as usize]))?;
                    let pucch_cell = r.opt(pcell, |r| r.u8(0, 31))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PdschServingCellConfig {
                        code_block_group_transmission,
                        x_overhead,
                        nrof_harq_processes_for_pdsch,
                        pucch_cell,
                    })
                })
            })
            .ctx("pdsch-ServingCellConfig")?;
        let csi_meas_config = r
            .opt(o[11], |r| r.setup_release(CsiMeasConfig::decode))
            .ctx("csi-MeasConfig")?;
        const DEACT: [u16; 16] = [
            20, 40, 80, 160, 200, 240, 320, 400, 480, 520, 640, 720, 840, 1280, 0, 0,
        ];
        let scell_deactivation_timer_ms = r.opt(o[12], |r| Ok(DEACT[r.enu(16)? as usize]))?;
        if o[13] {
            return r.unsupported("crossCarrierSchedulingConfig");
        }
        let tag_id = r.u8(0, 3)?;
        let pathloss_reference_linking_sp_cell = r.opt(o[15], |r| Ok(r.enu(2)? == 0))?;
        let serving_cell_mo = r.opt(o[16], |r| r.u8(1, 64))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            tdd_ul_dl_configuration_dedicated,
            initial_downlink_bwp,
            downlink_bwp_to_release_list,
            downlink_bwp_to_add_mod_list,
            first_active_downlink_bwp_id,
            bwp_inactivity_timer_ms,
            default_downlink_bwp_id,
            uplink_config,
            supplementary_uplink,
            pdcch_serving_cell_config,
            pdsch_serving_cell_config,
            csi_meas_config,
            scell_deactivation_timer_ms,
            tag_id,
            dummy1_enabled: o[14],
            pathloss_reference_linking_sp_cell,
            serving_cell_mo,
        })
    }
}

/// `SpCellConfig ::= SEQUENCE { servCellIndex ServCellIndex OPTIONAL, reconfigurationWithSync
/// ReconfigurationWithSync OPTIONAL, rlf-TimersAndConstants SetupRelease { RLF-TimersAndConstants }
/// OPTIONAL, rlmInSyncOutOfSyncThreshold ENUMERATED { n1 } OPTIONAL, spCellConfigDedicated
/// ServingCellConfig OPTIONAL, ... }` — `reconfigurationWithSync` is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpCellConfig {
    pub serv_cell_index: Option<u8>,
    pub rlf_timers_and_constants: Option<SetupRelease<RlfTimersAndConstants>>,
    pub rlm_in_sync_out_of_sync_threshold_n1: bool,
    pub sp_cell_config_dedicated: Option<ServingCellConfig>,
}

impl SpCellConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [idx, sync, rlf, rlm, ded] = r.opt_bits::<5>()?;
        let serv_cell_index = r.opt(idx, |r| r.u8(0, 31))?;
        if sync {
            return r.unsupported("reconfigurationWithSync");
        }
        let rlf_timers_and_constants = r
            .opt(rlf, |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    const T310: [u16; 9] = [0, 50, 100, 200, 500, 1000, 2000, 4000, 6000];
                    let t310_ms = T310[r.enu(9)? as usize];
                    let n310 = [1u8, 2, 3, 4, 6, 8, 10, 20][r.enu(8)? as usize];
                    let n311 = [1u8, 2, 3, 4, 5, 6, 8, 10][r.enu(8)? as usize];
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(RlfTimersAndConstants {
                        t310_ms,
                        n310,
                        n311,
                    })
                })
            })
            .ctx("rlf-TimersAndConstants")?;
        let sp_cell_config_dedicated = r
            .opt(ded, ServingCellConfig::decode)
            .ctx("spCellConfigDedicated")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            serv_cell_index,
            rlf_timers_and_constants,
            rlm_in_sync_out_of_sync_threshold_n1: rlm,
            sp_cell_config_dedicated,
        })
    }
}

// ---------------------------------------------------------------------------
// BWP-DownlinkDedicated: PDCCH-Config, PDSCH-Config, SPS, RLM
// ---------------------------------------------------------------------------

/// `DownlinkPreemption ::= SEQUENCE { int-RNTI RNTI-Value, timeFrequencySet ENUMERATED { set0,
/// set1 }, dci-PayloadSize INTEGER (0..maxINT-DCI-PayloadSize), int-ConfigurationPerServingCell
/// SEQUENCE (SIZE (1..maxNrofServingCells)) OF INT-ConfigurationPerServingCell, ... }` with
/// `INT-ConfigurationPerServingCell ::= SEQUENCE { servingCellId, positionInDCI INTEGER (0..125) }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownlinkPreemption {
    pub int_rnti: Rnti,
    pub time_frequency_set: u8,
    pub dci_payload_size: u8,
    /// `(servingCellId, positionInDCI)`.
    pub int_configuration_per_serving_cell: Vec<(u8, u8)>,
}

/// `PUSCH-TPC-CommandConfig ::= SEQUENCE { tpc-Index INTEGER (1..15) OPTIONAL, tpc-IndexSUL
/// INTEGER (1..15) OPTIONAL, targetCell ServCellIndex OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PuschTpcCommandConfig {
    pub tpc_index: Option<u8>,
    pub tpc_index_sul: Option<u8>,
    pub target_cell: Option<u8>,
}

/// `PUCCH-TPC-CommandConfig ::= SEQUENCE { tpc-IndexPCell INTEGER (1..15) OPTIONAL,
/// tpc-IndexPUCCH-SCell INTEGER (1..15) OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PucchTpcCommandConfig {
    pub tpc_index_pcell: Option<u8>,
    pub tpc_index_pucch_scell: Option<u8>,
}

/// `SRS-TPC-CommandConfig ::= SEQUENCE { startingBitOfFormat2-3 INTEGER (1..31) OPTIONAL,
/// fieldTypeFormat2-3 INTEGER (0..1) OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SrsTpcCommandConfig {
    pub starting_bit_of_format2_3: Option<u8>,
    pub field_type_format2_3: Option<u8>,
}

/// `PDCCH-Config ::= SEQUENCE { controlResourceSetToAddModList SEQUENCE (SIZE (1..3)) OF
/// ControlResourceSet OPTIONAL, controlResourceSetToReleaseList … OPTIONAL, searchSpacesToAddModList
/// SEQUENCE (SIZE (1..10)) OF SearchSpace OPTIONAL, searchSpacesToReleaseList … OPTIONAL,
/// downlinkPreemption SetupRelease { DownlinkPreemption } OPTIONAL, tpc-PUSCH SetupRelease
/// { PUSCH-TPC-CommandConfig } OPTIONAL, tpc-PUCCH SetupRelease { PUCCH-TPC-CommandConfig } OPTIONAL,
/// tpc-SRS SetupRelease { SRS-TPC-CommandConfig } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PdcchConfig {
    pub control_resource_set_to_add_mod_list: Vec<ControlResourceSet>,
    pub control_resource_set_to_release_list: Vec<u8>,
    pub search_spaces_to_add_mod_list: Vec<SearchSpace>,
    pub search_spaces_to_release_list: Vec<u8>,
    pub downlink_preemption: Option<SetupRelease<DownlinkPreemption>>,
    pub tpc_pusch: Option<SetupRelease<PuschTpcCommandConfig>>,
    pub tpc_pucch: Option<SetupRelease<PucchTpcCommandConfig>>,
    pub tpc_srs: Option<SetupRelease<SrsTpcCommandConfig>>,
}

impl PdcchConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<8>()?;
        let mut c = Self::default();
        if o[0] {
            c.control_resource_set_to_add_mod_list = r
                .seq_of(1, 3, ControlResourceSet::decode)
                .ctx("controlResourceSetToAddModList")?;
        }
        if o[1] {
            c.control_resource_set_to_release_list = r.seq_of(1, 3, |r| r.u8(0, 11))?;
        }
        if o[2] {
            c.search_spaces_to_add_mod_list = r
                .seq_of(1, 10, SearchSpace::decode)
                .ctx("searchSpacesToAddModList")?;
        }
        if o[3] {
            c.search_spaces_to_release_list = r.seq_of(1, 10, |r| r.u8(0, 39))?;
        }
        c.downlink_preemption = r
            .opt(o[4], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let int_rnti = Rnti(r.u16(0, 65535)?);
                    let time_frequency_set = r.enu(2)? as u8;
                    let dci_payload_size = r.u8(0, 126)?;
                    let int_configuration_per_serving_cell =
                        r.seq_of(1, 32, |r| Ok((r.u8(0, 31)?, r.u8(0, 125)?)))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(DownlinkPreemption {
                        int_rnti,
                        time_frequency_set,
                        dci_payload_size,
                        int_configuration_per_serving_cell,
                    })
                })
            })
            .ctx("downlinkPreemption")?;
        c.tpc_pusch = r
            .opt(o[5], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [a, b, cc] = r.opt_bits::<3>()?;
                    let tpc_index = r.opt(a, |r| r.u8(1, 15))?;
                    let tpc_index_sul = r.opt(b, |r| r.u8(1, 15))?;
                    let target_cell = r.opt(cc, |r| r.u8(0, 31))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PuschTpcCommandConfig {
                        tpc_index,
                        tpc_index_sul,
                        target_cell,
                    })
                })
            })
            .ctx("tpc-PUSCH")?;
        c.tpc_pucch = r
            .opt(o[6], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [a, b] = r.opt_bits::<2>()?;
                    let tpc_index_pcell = r.opt(a, |r| r.u8(1, 15))?;
                    let tpc_index_pucch_scell = r.opt(b, |r| r.u8(1, 15))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PucchTpcCommandConfig {
                        tpc_index_pcell,
                        tpc_index_pucch_scell,
                    })
                })
            })
            .ctx("tpc-PUCCH")?;
        c.tpc_srs = r
            .opt(o[7], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [a, b] = r.opt_bits::<2>()?;
                    let starting_bit_of_format2_3 = r.opt(a, |r| r.u8(1, 31))?;
                    let field_type_format2_3 = r.opt(b, |r| r.u8(0, 1))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(SrsTpcCommandConfig {
                        starting_bit_of_format2_3,
                        field_type_format2_3,
                    })
                })
            })
            .ctx("tpc-SRS")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(c)
    }
}

/// `PTRS-DownlinkConfig ::= SEQUENCE { frequencyDensity SEQUENCE (SIZE (2)) OF INTEGER (1..276)
/// OPTIONAL, timeDensity SEQUENCE (SIZE (3)) OF INTEGER (0..29) OPTIONAL, epre-Ratio INTEGER (0..3)
/// OPTIONAL, resourceElementOffset ENUMERATED { offset01, offset10, offset11 } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PtrsDownlinkConfig {
    pub frequency_density: Option<[u16; 2]>,
    pub time_density: Option<[u8; 3]>,
    pub epre_ratio: Option<u8>,
    pub resource_element_offset: Option<u8>,
}

impl PtrsDownlinkConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [fd, td, epre, reo] = r.opt_bits::<4>()?;
        let frequency_density = r.opt(fd, |r| Ok([r.u16(1, 276)?, r.u16(1, 276)?]))?;
        let time_density = r.opt(td, |r| Ok([r.u8(0, 29)?, r.u8(0, 29)?, r.u8(0, 29)?]))?;
        let epre_ratio = r.opt(epre, |r| r.u8(0, 3))?;
        let resource_element_offset = r.opt(reo, |r| Ok(r.enu(3)? as u8))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            frequency_density,
            time_density,
            epre_ratio,
            resource_element_offset,
        })
    }
}

/// `DMRS-DownlinkConfig ::= SEQUENCE { dmrs-Type ENUMERATED { type2 } OPTIONAL,
/// dmrs-AdditionalPosition ENUMERATED { pos0, pos1, pos3 } OPTIONAL, maxLength ENUMERATED { len2 }
/// OPTIONAL, scramblingID0 INTEGER (0..65535) OPTIONAL, scramblingID1 INTEGER (0..65535) OPTIONAL,
/// phaseTrackingRS SetupRelease { PTRS-DownlinkConfig } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DmrsDownlinkConfig {
    /// `dmrs-Type = type2` present (else type 1).
    pub dmrs_type2: bool,
    /// 0, 1 or 3; absent ⇒ pos2.
    pub dmrs_additional_position: Option<u8>,
    /// `maxLength = len2` present (else single-symbol).
    pub max_length_len2: bool,
    pub scrambling_id0: Option<u16>,
    pub scrambling_id1: Option<u16>,
    pub phase_tracking_rs: Option<SetupRelease<PtrsDownlinkConfig>>,
}

impl DmrsDownlinkConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<6>()?;
        let dmrs_additional_position = r.opt(o[1], |r| Ok([0u8, 1, 3][r.enu(3)? as usize]))?;
        let scrambling_id0 = r.opt(o[3], |r| r.u16(0, 65535))?;
        let scrambling_id1 = r.opt(o[4], |r| r.u16(0, 65535))?;
        let phase_tracking_rs = r
            .opt(o[5], |r| r.setup_release(PtrsDownlinkConfig::decode))
            .ctx("phaseTrackingRS")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            dmrs_type2: o[0],
            dmrs_additional_position,
            max_length_len2: o[2],
            scrambling_id0,
            scrambling_id1,
            phase_tracking_rs,
        })
    }

    /// `dmrs-AdditionalPosition` with its default (pos2) applied.
    pub fn additional_position(&self) -> u8 {
        self.dmrs_additional_position.unwrap_or(2)
    }
}

/// `QCL-Info ::= SEQUENCE { cell ServCellIndex OPTIONAL, bwp-Id BWP-Id OPTIONAL, referenceSignal
/// CHOICE { csi-rs NZP-CSI-RS-ResourceId, ssb SSB-Index }, qcl-Type ENUMERATED { typeA, typeB,
/// typeC, typeD }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QclInfo {
    pub cell: Option<u8>,
    pub bwp_id: Option<u8>,
    pub reference_signal: ReferenceSignal,
    /// 0 = typeA … 3 = typeD.
    pub qcl_type: u8,
}

impl QclInfo {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_cell, has_bwp] = r.opt_bits::<2>()?;
        let cell = r.opt(has_cell, |r| r.u8(0, 31))?;
        let bwp_id = r.opt(has_bwp, |r| r.u8(0, 4))?;
        let reference_signal = ReferenceSignal::decode_csi_first(r)?;
        let qcl_type = r.enu(4)? as u8;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            cell,
            bwp_id,
            reference_signal,
            qcl_type,
        })
    }
}

/// `TCI-State ::= SEQUENCE { tci-StateId TCI-StateId, qcl-Type1 QCL-Info, qcl-Type2 QCL-Info OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TciState {
    pub tci_state_id: u8,
    pub qcl_type1: QclInfo,
    pub qcl_type2: Option<QclInfo>,
}

/// `symbolsInResourceBlock CHOICE { oneSlot BIT STRING (SIZE (14)), twoSlots BIT STRING (SIZE (28)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolsInResourceBlock {
    OneSlot(u16),
    TwoSlots(u32),
}

/// `patternType CHOICE { bitmaps SEQUENCE { resourceBlocks BIT STRING (SIZE (275)),
/// symbolsInResourceBlock CHOICE {…}, periodicityAndPattern CHOICE { n2 BIT STRING (SIZE (2)), n4,
/// n5, n8, n10, n20, n40 } OPTIONAL, ... }, controlResourceSet ControlResourceSetId }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateMatchPatternType {
    Bitmaps {
        /// 275 bits, MSB-first bytes (bit 0 = RB 0).
        resource_blocks: Vec<u8>,
        symbols_in_resource_block: SymbolsInResourceBlock,
        /// `(n, bitmap)` for `periodicityAndPattern`.
        periodicity_and_pattern: Option<(u8, u64)>,
    },
    ControlResourceSet(u8),
}

/// `RateMatchPattern ::= SEQUENCE { rateMatchPatternId RateMatchPatternId, patternType CHOICE {…},
/// subcarrierSpacing SubcarrierSpacing OPTIONAL, dummy ENUMERATED { dynamic, semiStatic }, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateMatchPattern {
    pub rate_match_pattern_id: u8,
    pub pattern_type: RateMatchPatternType,
    pub subcarrier_spacing: Option<SubcarrierSpacing>,
    pub dummy_dynamic: bool,
}

impl RateMatchPattern {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_scs] = r.opt_bits::<1>()?;
        let rate_match_pattern_id = r.u8(0, 3)?;
        let pattern_type = if !r.bit()? {
            let be = r.bit()?;
            let [has_pp] = r.opt_bits::<1>()?;
            let resource_blocks = r.bitstring_bytes(275)?;
            let symbols_in_resource_block = if !r.bit()? {
                SymbolsInResourceBlock::OneSlot(r.bitstring(14)? as u16)
            } else {
                SymbolsInResourceBlock::TwoSlots(r.bitstring(28)? as u32)
            };
            let periodicity_and_pattern = r.opt(has_pp, |r| {
                let n = [2u8, 4, 5, 8, 10, 20, 40][r.uint(0, 6)? as usize];
                Ok((n, r.bitstring(n as u32)?))
            })?;
            if be {
                r.skip_ext_additions()?;
            }
            RateMatchPatternType::Bitmaps {
                resource_blocks,
                symbols_in_resource_block,
                periodicity_and_pattern,
            }
        } else {
            RateMatchPatternType::ControlResourceSet(r.u8(0, 11)?)
        };
        let subcarrier_spacing = r.opt(has_scs, SubcarrierSpacing::decode)?;
        let dummy_dynamic = r.enu(2)? == 0;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            rate_match_pattern_id,
            pattern_type,
            subcarrier_spacing,
            dummy_dynamic,
        })
    }
}

/// `RateMatchPatternGroup ::= SEQUENCE (SIZE (1..maxNrofRateMatchPatternsPerGroup)) OF CHOICE
/// { cellLevel RateMatchPatternId, bwpLevel RateMatchPatternId }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateMatchPatternRef {
    CellLevel(u8),
    BwpLevel(u8),
}

/// `ZP-CSI-RS-Resource ::= SEQUENCE { zp-CSI-RS-ResourceId ZP-CSI-RS-ResourceId, resourceMapping
/// CSI-RS-ResourceMapping, periodicityAndOffset CSI-ResourcePeriodicityAndOffset OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZpCsiRsResource {
    pub zp_csi_rs_resource_id: u8,
    pub resource_mapping: CsiRsResourceMapping,
    pub periodicity_and_offset: Option<PeriodicityAndOffset>,
}

/// `ZP-CSI-RS-ResourceSet ::= SEQUENCE { zp-CSI-RS-ResourceSetId ZP-CSI-RS-ResourceSetId,
/// zp-CSI-RS-ResourceIdList SEQUENCE (SIZE(1..maxNrofZP-CSI-RS-ResourcesPerSet)) OF
/// ZP-CSI-RS-ResourceId, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZpCsiRsResourceSet {
    pub zp_csi_rs_resource_set_id: u8,
    pub zp_csi_rs_resource_id_list: Vec<u8>,
}

impl ZpCsiRsResourceSet {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let e = r.bit()?;
        let zp_csi_rs_resource_set_id = r.u8(0, 15)?;
        let zp_csi_rs_resource_id_list = r.seq_of(1, 16, |r| r.u8(0, 31))?;
        if e {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            zp_csi_rs_resource_set_id,
            zp_csi_rs_resource_id_list,
        })
    }
}

/// `resourceAllocation ENUMERATED { resourceAllocationType0, resourceAllocationType1, dynamicSwitch }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceAllocation {
    Type0,
    Type1,
    DynamicSwitch,
}

impl ResourceAllocation {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(match r.enu(3)? {
            0 => Self::Type0,
            1 => Self::Type1,
            _ => Self::DynamicSwitch,
        })
    }
}

/// `mcs-Table ENUMERATED { qam256, qam64LowSE }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McsTable {
    Qam256,
    Qam64LowSe,
}

impl McsTable {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(if r.enu(2)? == 0 {
            Self::Qam256
        } else {
            Self::Qam64LowSe
        })
    }
}

/// `prb-BundlingType CHOICE { staticBundling SEQUENCE { bundleSize ENUMERATED { n4, wideband }
/// OPTIONAL }, dynamicBundling SEQUENCE { bundleSizeSet1 ENUMERATED { n4, wideband, n2-wideband,
/// n4-wideband } OPTIONAL, bundleSizeSet2 ENUMERATED { n4, wideband } OPTIONAL } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrbBundlingType {
    /// `bundle_size_wideband`: `Some(true)` = wideband, `Some(false)` = n4, `None` = absent (n2).
    Static { bundle_size_wideband: Option<bool> },
    Dynamic {
        bundle_size_set1: Option<u8>,
        bundle_size_set2: Option<u8>,
    },
}

/// `PDSCH-Config ::= SEQUENCE { dataScramblingIdentityPDSCH INTEGER (0..1023) OPTIONAL,
/// dmrs-DownlinkForPDSCH-MappingTypeA SetupRelease { DMRS-DownlinkConfig } OPTIONAL,
/// dmrs-DownlinkForPDSCH-MappingTypeB … OPTIONAL, tci-StatesToAddModList SEQUENCE (SIZE(1..maxNrofTCI-States))
/// OF TCI-State OPTIONAL, tci-StatesToReleaseList … OPTIONAL, vrb-ToPRB-Interleaver ENUMERATED { n2, n4 }
/// OPTIONAL, resourceAllocation ENUMERATED {…}, pdsch-TimeDomainAllocationList SetupRelease {…} OPTIONAL,
/// pdsch-AggregationFactor ENUMERATED { n2, n4, n8 } OPTIONAL, rateMatchPatternToAddModList SEQUENCE
/// (SIZE (1..maxNrofRateMatchPatterns)) OF RateMatchPattern OPTIONAL, rateMatchPatternToReleaseList …
/// OPTIONAL, rateMatchPatternGroup1 RateMatchPatternGroup OPTIONAL, rateMatchPatternGroup2 … OPTIONAL,
/// rbg-Size ENUMERATED { config1, config2 }, mcs-Table ENUMERATED {…} OPTIONAL,
/// maxNrofCodeWordsScheduledByDCI ENUMERATED { n1, n2 } OPTIONAL, prb-BundlingType CHOICE {…},
/// zp-CSI-RS-ResourceToAddModList … OPTIONAL, zp-CSI-RS-ResourceToReleaseList … OPTIONAL,
/// aperiodic-ZP-CSI-RS-ResourceSetsToAddModList … OPTIONAL, …ToReleaseList … OPTIONAL,
/// sp-ZP-CSI-RS-ResourceSetsToAddModList … OPTIONAL, …ToReleaseList … OPTIONAL,
/// p-ZP-CSI-RS-ResourceSet SetupRelease { ZP-CSI-RS-ResourceSet } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdschConfig {
    pub data_scrambling_identity_pdsch: Option<u16>,
    pub dmrs_downlink_for_pdsch_mapping_type_a: Option<SetupRelease<DmrsDownlinkConfig>>,
    pub dmrs_downlink_for_pdsch_mapping_type_b: Option<SetupRelease<DmrsDownlinkConfig>>,
    pub tci_states_to_add_mod_list: Vec<TciState>,
    pub tci_states_to_release_list: Vec<u8>,
    /// 2 or 4 (bundle size); absent ⇒ no VRB-to-PRB interleaving.
    pub vrb_to_prb_interleaver: Option<u8>,
    pub resource_allocation: ResourceAllocation,
    pub pdsch_time_domain_allocation_list: Option<SetupRelease<Vec<TdraRow>>>,
    pub pdsch_aggregation_factor: Option<u8>,
    pub rate_match_pattern_to_add_mod_list: Vec<RateMatchPattern>,
    pub rate_match_pattern_to_release_list: Vec<u8>,
    pub rate_match_pattern_group1: Vec<RateMatchPatternRef>,
    pub rate_match_pattern_group2: Vec<RateMatchPatternRef>,
    /// `rbg-Size`: 1 (config1) or 2 (config2).
    pub rbg_size_config: u8,
    pub mcs_table: Option<McsTable>,
    pub max_nrof_code_words_scheduled_by_dci: Option<u8>,
    pub prb_bundling_type: PrbBundlingType,
    pub zp_csi_rs_resource_to_add_mod_list: Vec<ZpCsiRsResource>,
    pub zp_csi_rs_resource_to_release_list: Vec<u8>,
    pub aperiodic_zp_csi_rs_resource_sets_to_add_mod_list: Vec<ZpCsiRsResourceSet>,
    pub aperiodic_zp_csi_rs_resource_sets_to_release_list: Vec<u8>,
    pub sp_zp_csi_rs_resource_sets_to_add_mod_list: Vec<ZpCsiRsResourceSet>,
    pub sp_zp_csi_rs_resource_sets_to_release_list: Vec<u8>,
    pub p_zp_csi_rs_resource_set: Option<SetupRelease<ZpCsiRsResourceSet>>,
}

impl PdschConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<21>()?;
        let data_scrambling_identity_pdsch = r.opt(o[0], |r| r.u16(0, 1023))?;
        let dmrs_downlink_for_pdsch_mapping_type_a = r
            .opt(o[1], |r| r.setup_release(DmrsDownlinkConfig::decode))
            .ctx("dmrs-DownlinkForPDSCH-MappingTypeA")?;
        let dmrs_downlink_for_pdsch_mapping_type_b = r
            .opt(o[2], |r| r.setup_release(DmrsDownlinkConfig::decode))
            .ctx("dmrs-DownlinkForPDSCH-MappingTypeB")?;
        let tci_states_to_add_mod_list = if o[3] {
            r.seq_of(1, 128, |r| {
                let e = r.bit()?;
                let [has_q2] = r.opt_bits::<1>()?;
                let tci_state_id = r.u8(0, 127)?;
                let qcl_type1 = QclInfo::decode(r)?;
                let qcl_type2 = r.opt(has_q2, QclInfo::decode)?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(TciState {
                    tci_state_id,
                    qcl_type1,
                    qcl_type2,
                })
            })
            .ctx("tci-StatesToAddModList")?
        } else {
            vec![]
        };
        let tci_states_to_release_list = if o[4] {
            r.seq_of(1, 128, |r| r.u8(0, 127))?
        } else {
            vec![]
        };
        let vrb_to_prb_interleaver = r.opt(o[5], |r| Ok([2u8, 4][r.enu(2)? as usize]))?;
        let resource_allocation = ResourceAllocation::decode(r)?;
        let pdsch_time_domain_allocation_list = r
            .opt(o[6], |r| r.setup_release(decode_tdra_list))
            .ctx("pdsch-TimeDomainAllocationList")?;
        let pdsch_aggregation_factor = r.opt(o[7], |r| Ok(2u8 << r.enu(3)?))?;
        let rate_match_pattern_to_add_mod_list = if o[8] {
            r.seq_of(1, 4, RateMatchPattern::decode)
                .ctx("rateMatchPatternToAddModList")?
        } else {
            vec![]
        };
        let rate_match_pattern_to_release_list = if o[9] {
            r.seq_of(1, 4, |r| r.u8(0, 3))?
        } else {
            vec![]
        };
        let group = |r: &mut BitReader| {
            r.seq_of(1, 8, |r| {
                Ok(if !r.bit()? {
                    RateMatchPatternRef::CellLevel(r.u8(0, 3)?)
                } else {
                    RateMatchPatternRef::BwpLevel(r.u8(0, 3)?)
                })
            })
        };
        let rate_match_pattern_group1 = if o[10] { group(r)? } else { vec![] };
        let rate_match_pattern_group2 = if o[11] { group(r)? } else { vec![] };
        let rbg_size_config = r.enu(2)? as u8 + 1;
        let mcs_table = r.opt(o[12], McsTable::decode)?;
        let max_nrof_code_words_scheduled_by_dci = r.opt(o[13], |r| Ok(r.enu(2)? as u8 + 1))?;
        let prb_bundling_type = if !r.bit()? {
            let [has_bs] = r.opt_bits::<1>()?;
            PrbBundlingType::Static {
                bundle_size_wideband: r.opt(has_bs, |r| Ok(r.enu(2)? == 1))?,
            }
        } else {
            let [s1, s2] = r.opt_bits::<2>()?;
            let bundle_size_set1 = r.opt(s1, |r| Ok(r.enu(4)? as u8))?;
            let bundle_size_set2 = r.opt(s2, |r| Ok(r.enu(2)? as u8))?;
            PrbBundlingType::Dynamic {
                bundle_size_set1,
                bundle_size_set2,
            }
        };
        let zp_csi_rs_resource_to_add_mod_list = if o[14] {
            r.seq_of(1, 32, |r| {
                let e = r.bit()?;
                let [has_po] = r.opt_bits::<1>()?;
                let zp_csi_rs_resource_id = r.u8(0, 31)?;
                let resource_mapping = CsiRsResourceMapping::decode(r)?;
                let periodicity_and_offset =
                    r.opt(has_po, PeriodicityAndOffset::decode_csi_resource)?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(ZpCsiRsResource {
                    zp_csi_rs_resource_id,
                    resource_mapping,
                    periodicity_and_offset,
                })
            })
            .ctx("zp-CSI-RS-ResourceToAddModList")?
        } else {
            vec![]
        };
        let zp_csi_rs_resource_to_release_list = if o[15] {
            r.seq_of(1, 32, |r| r.u8(0, 31))?
        } else {
            vec![]
        };
        let aperiodic_zp_csi_rs_resource_sets_to_add_mod_list = if o[16] {
            r.seq_of(1, 16, ZpCsiRsResourceSet::decode)?
        } else {
            vec![]
        };
        let aperiodic_zp_csi_rs_resource_sets_to_release_list = if o[17] {
            r.seq_of(1, 16, |r| r.u8(0, 15))?
        } else {
            vec![]
        };
        let sp_zp_csi_rs_resource_sets_to_add_mod_list = if o[18] {
            r.seq_of(1, 16, ZpCsiRsResourceSet::decode)?
        } else {
            vec![]
        };
        let sp_zp_csi_rs_resource_sets_to_release_list = if o[19] {
            r.seq_of(1, 16, |r| r.u8(0, 15))?
        } else {
            vec![]
        };
        let p_zp_csi_rs_resource_set = r
            .opt(o[20], |r| r.setup_release(ZpCsiRsResourceSet::decode))
            .ctx("p-ZP-CSI-RS-ResourceSet")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            data_scrambling_identity_pdsch,
            dmrs_downlink_for_pdsch_mapping_type_a,
            dmrs_downlink_for_pdsch_mapping_type_b,
            tci_states_to_add_mod_list,
            tci_states_to_release_list,
            vrb_to_prb_interleaver,
            resource_allocation,
            pdsch_time_domain_allocation_list,
            pdsch_aggregation_factor,
            rate_match_pattern_to_add_mod_list,
            rate_match_pattern_to_release_list,
            rate_match_pattern_group1,
            rate_match_pattern_group2,
            rbg_size_config,
            mcs_table,
            max_nrof_code_words_scheduled_by_dci,
            prb_bundling_type,
            zp_csi_rs_resource_to_add_mod_list,
            zp_csi_rs_resource_to_release_list,
            aperiodic_zp_csi_rs_resource_sets_to_add_mod_list,
            aperiodic_zp_csi_rs_resource_sets_to_release_list,
            sp_zp_csi_rs_resource_sets_to_add_mod_list,
            sp_zp_csi_rs_resource_sets_to_release_list,
            p_zp_csi_rs_resource_set,
        })
    }

    /// The dedicated `pdsch-TimeDomainAllocationList` when set up.
    pub fn tdra_list(&self) -> Option<&[TdraRow]> {
        self.pdsch_time_domain_allocation_list
            .as_ref()?
            .setup()
            .map(Vec::as_slice)
    }
}

/// `SPS-Config ::= SEQUENCE { periodicity ENUMERATED { ms10, ms20, ms32, ms40, ms64, ms80, ms128,
/// ms160, ms320, ms640, spare6..spare1 }, nrofHARQ-Processes INTEGER (1..8), n1PUCCH-AN
/// PUCCH-ResourceId OPTIONAL, mcs-Table ENUMERATED { qam64LowSE } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpsConfig {
    pub periodicity_ms: u16,
    pub nrof_harq_processes: u8,
    pub n1_pucch_an: Option<u8>,
    pub mcs_table_qam64_low_se: bool,
}

/// `RadioLinkMonitoringRS ::= SEQUENCE { radioLinkMonitoringRS-Id RadioLinkMonitoringRS-Id, purpose
/// ENUMERATED { beamFailure, rlf, both }, detectionResource CHOICE { ssb-Index SSB-Index, csi-RS-Index
/// NZP-CSI-RS-ResourceId }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioLinkMonitoringRs {
    pub radio_link_monitoring_rs_id: u8,
    /// 0 = beamFailure, 1 = rlf, 2 = both.
    pub purpose: u8,
    pub detection_resource: ReferenceSignal,
}

/// `RadioLinkMonitoringConfig ::= SEQUENCE { failureDetectionResourcesToAddModList SEQUENCE
/// (SIZE(1..maxNrofFailureDetectionResources)) OF RadioLinkMonitoringRS OPTIONAL,
/// failureDetectionResourcesToReleaseList … OPTIONAL, beamFailureInstanceMaxCount ENUMERATED { n1, n2,
/// n3, n4, n5, n6, n8, n10 } OPTIONAL, beamFailureDetectionTimer ENUMERATED { pbfd1, pbfd2, pbfd3,
/// pbfd4, pbfd5, pbfd6, pbfd8, pbfd10 } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RadioLinkMonitoringConfig {
    pub failure_detection_resources_to_add_mod_list: Vec<RadioLinkMonitoringRs>,
    pub failure_detection_resources_to_release_list: Vec<u8>,
    pub beam_failure_instance_max_count: Option<u8>,
    /// In periods of the BFD-RS (`pbfdN`).
    pub beam_failure_detection_timer: Option<u8>,
}

/// `BWP-DownlinkDedicated ::= SEQUENCE { pdcch-Config SetupRelease { PDCCH-Config } OPTIONAL,
/// pdsch-Config SetupRelease { PDSCH-Config } OPTIONAL, sps-Config SetupRelease { SPS-Config }
/// OPTIONAL, radioLinkMonitoringConfig SetupRelease { RadioLinkMonitoringConfig } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpDownlinkDedicated {
    pub pdcch_config: Option<SetupRelease<PdcchConfig>>,
    pub pdsch_config: Option<SetupRelease<PdschConfig>>,
    pub sps_config: Option<SetupRelease<SpsConfig>>,
    pub radio_link_monitoring_config: Option<SetupRelease<RadioLinkMonitoringConfig>>,
}

impl BwpDownlinkDedicated {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [pdcch, pdsch, sps, rlm] = r.opt_bits::<4>()?;
        let pdcch_config = r
            .opt(pdcch, |r| r.setup_release(PdcchConfig::decode))
            .ctx("pdcch-Config")?;
        let pdsch_config = r
            .opt(pdsch, |r| r.setup_release(PdschConfig::decode))
            .ctx("pdsch-Config")?;
        let sps_config = r
            .opt(sps, |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [has_n1, mcs] = r.opt_bits::<2>()?;
                    const P: [u16; 16] =
                        [10, 20, 32, 40, 64, 80, 128, 160, 320, 640, 0, 0, 0, 0, 0, 0];
                    let periodicity_ms = P[r.enu(16)? as usize];
                    let nrof_harq_processes = r.u8(1, 8)?;
                    let n1_pucch_an = r.opt(has_n1, |r| r.u8(0, 127))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(SpsConfig {
                        periodicity_ms,
                        nrof_harq_processes,
                        n1_pucch_an,
                        mcs_table_qam64_low_se: mcs,
                    })
                })
            })
            .ctx("sps-Config")?;
        let radio_link_monitoring_config = r
            .opt(rlm, |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [add, rel, cnt, timer] = r.opt_bits::<4>()?;
                    let mut c = RadioLinkMonitoringConfig::default();
                    if add {
                        c.failure_detection_resources_to_add_mod_list = r.seq_of(1, 10, |r| {
                            let e = r.bit()?;
                            let radio_link_monitoring_rs_id = r.u8(0, 9)?;
                            let purpose = r.enu(3)? as u8;
                            let detection_resource = ReferenceSignal::decode_ssb_first(r)?;
                            if e {
                                r.skip_ext_additions()?;
                            }
                            Ok(RadioLinkMonitoringRs {
                                radio_link_monitoring_rs_id,
                                purpose,
                                detection_resource,
                            })
                        })?;
                    }
                    if rel {
                        c.failure_detection_resources_to_release_list =
                            r.seq_of(1, 10, |r| r.u8(0, 9))?;
                    }
                    c.beam_failure_instance_max_count =
                        r.opt(cnt, |r| Ok([1u8, 2, 3, 4, 5, 6, 8, 10][r.enu(8)? as usize]))?;
                    c.beam_failure_detection_timer = r.opt(timer, |r| {
                        Ok([1u8, 2, 3, 4, 5, 6, 8, 10][r.enu(8)? as usize])
                    })?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(c)
                })
            })
            .ctx("radioLinkMonitoringConfig")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            pdcch_config,
            pdsch_config,
            sps_config,
            radio_link_monitoring_config,
        })
    }
}

// ---------------------------------------------------------------------------
// UplinkConfig / BWP-UplinkDedicated: PUCCH-Config, PUSCH-Config, SRS-Config
// ---------------------------------------------------------------------------

/// `PUSCH-ServingCellConfig ::= SEQUENCE { codeBlockGroupTransmission SetupRelease
/// { PUSCH-CodeBlockGroupTransmission } OPTIONAL, rateMatching ENUMERATED { limitedBufferRM }
/// OPTIONAL, xOverhead ENUMERATED { xoh6, xoh12, xoh18 } OPTIONAL, ... }` with
/// `PUSCH-CodeBlockGroupTransmission ::= SEQUENCE { maxCodeBlockGroupsPerTransportBlock
/// ENUMERATED { n2, n4, n6, n8 }, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PuschServingCellConfig {
    /// `maxCodeBlockGroupsPerTransportBlock` when CBG transmission is set up.
    pub code_block_group_transmission: Option<SetupRelease<u8>>,
    pub rate_matching_limited_buffer_rm: bool,
    pub x_overhead: Option<u8>,
}

/// `BWP-Uplink ::= SEQUENCE { bwp-Id BWP-Id, bwp-Common BWP-UplinkCommon OPTIONAL, bwp-Dedicated
/// BWP-UplinkDedicated OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpUplink {
    pub bwp_id: u8,
    pub bwp_common: Option<BwpUplinkCommon>,
    pub bwp_dedicated: Option<BwpUplinkDedicated>,
}

/// `UplinkConfig ::= SEQUENCE { initialUplinkBWP BWP-UplinkDedicated OPTIONAL,
/// uplinkBWP-ToReleaseList … OPTIONAL, uplinkBWP-ToAddModList SEQUENCE (SIZE (1..maxNrofBWPs)) OF
/// BWP-Uplink OPTIONAL, firstActiveUplinkBWP-Id BWP-Id OPTIONAL, pusch-ServingCellConfig
/// SetupRelease { PUSCH-ServingCellConfig } OPTIONAL, carrierSwitching SetupRelease
/// { SRS-CarrierSwitching } OPTIONAL, ... }` — `carrierSwitching` is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkConfig {
    pub initial_uplink_bwp: Option<BwpUplinkDedicated>,
    pub uplink_bwp_to_release_list: Vec<u8>,
    pub uplink_bwp_to_add_mod_list: Vec<BwpUplink>,
    pub first_active_uplink_bwp_id: Option<u8>,
    pub pusch_serving_cell_config: Option<SetupRelease<PuschServingCellConfig>>,
}

impl UplinkConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<6>()?;
        let initial_uplink_bwp = r
            .opt(o[0], BwpUplinkDedicated::decode)
            .ctx("initialUplinkBWP")?;
        let uplink_bwp_to_release_list = if o[1] {
            r.seq_of(1, 4, |r| r.u8(0, 4))?
        } else {
            vec![]
        };
        let uplink_bwp_to_add_mod_list = if o[2] {
            r.seq_of(1, 4, |r| {
                let e = r.bit()?;
                let [hc, hd] = r.opt_bits::<2>()?;
                let bwp_id = r.u8(0, 4)?;
                let bwp_common = r.opt(hc, BwpUplinkCommon::decode)?;
                let bwp_dedicated = r.opt(hd, BwpUplinkDedicated::decode)?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(BwpUplink {
                    bwp_id,
                    bwp_common,
                    bwp_dedicated,
                })
            })
            .ctx("uplinkBWP-ToAddModList")?
        } else {
            vec![]
        };
        let first_active_uplink_bwp_id = r.opt(o[3], |r| r.u8(0, 4))?;
        let pusch_serving_cell_config = r
            .opt(o[4], |r| {
                r.setup_release(|r| {
                    let e = r.bit()?;
                    let [cbg, rm, xoh] = r.opt_bits::<3>()?;
                    let code_block_group_transmission = r.opt(cbg, |r| {
                        r.setup_release(|r| {
                            let ce = r.bit()?;
                            let n = 2 * (r.enu(4)? as u8 + 1);
                            if ce {
                                r.skip_ext_additions()?;
                            }
                            Ok(n)
                        })
                    })?;
                    let x_overhead = r.opt(xoh, |r| Ok(6 * (r.enu(3)? as u8 + 1)))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(PuschServingCellConfig {
                        code_block_group_transmission,
                        rate_matching_limited_buffer_rm: rm,
                        x_overhead,
                    })
                })
            })
            .ctx("pusch-ServingCellConfig")?;
        if o[5] {
            return r.unsupported("carrierSwitching");
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            initial_uplink_bwp,
            uplink_bwp_to_release_list,
            uplink_bwp_to_add_mod_list,
            first_active_uplink_bwp_id,
            pusch_serving_cell_config,
        })
    }
}

/// `BWP-UplinkDedicated ::= SEQUENCE { pucch-Config SetupRelease { PUCCH-Config } OPTIONAL,
/// pusch-Config SetupRelease { PUSCH-Config } OPTIONAL, configuredGrantConfig SetupRelease
/// { ConfiguredGrantConfig } OPTIONAL, srs-Config SetupRelease { SRS-Config } OPTIONAL,
/// beamFailureRecoveryConfig SetupRelease { BeamFailureRecoveryConfig } OPTIONAL, ... }` —
/// `configuredGrantConfig` and `beamFailureRecoveryConfig` are not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwpUplinkDedicated {
    pub pucch_config: Option<SetupRelease<PucchConfig>>,
    pub pusch_config: Option<SetupRelease<PuschConfig>>,
    pub srs_config: Option<SetupRelease<SrsConfig>>,
}

impl BwpUplinkDedicated {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [pucch, pusch, cg, srs, bfr] = r.opt_bits::<5>()?;
        let pucch_config = r
            .opt(pucch, |r| r.setup_release(PucchConfig::decode))
            .ctx("pucch-Config")?;
        let pusch_config = r
            .opt(pusch, |r| r.setup_release(PuschConfig::decode))
            .ctx("pusch-Config")?;
        if cg {
            return r.unsupported("configuredGrantConfig");
        }
        let srs_config = r
            .opt(srs, |r| r.setup_release(SrsConfig::decode))
            .ctx("srs-Config")?;
        if bfr {
            return r.unsupported("beamFailureRecoveryConfig");
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            pucch_config,
            pusch_config,
            srs_config,
        })
    }
}

/// `PUCCH-ResourceSet ::= SEQUENCE { pucch-ResourceSetId PUCCH-ResourceSetId, resourceList
/// SEQUENCE (SIZE (1..maxNrofPUCCH-ResourcesPerSet)) OF PUCCH-ResourceId, maxPayloadSize INTEGER
/// (4..256) OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PucchResourceSet {
    pub pucch_resource_set_id: u8,
    pub resource_list: Vec<u8>,
    pub max_payload_size: Option<u16>,
}

/// `format CHOICE { format0 PUCCH-format0, format1 PUCCH-format1, format2 PUCCH-format2, format3
/// PUCCH-format3, format4 PUCCH-format4 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PucchFormat {
    /// `PUCCH-format0 ::= SEQUENCE { initialCyclicShift INTEGER (0..11), nrofSymbols INTEGER (1..2),
    /// startingSymbolIndex INTEGER (0..13) }`.
    Format0 {
        initial_cyclic_shift: u8,
        nrof_symbols: u8,
        starting_symbol_index: u8,
    },
    /// `PUCCH-format1 ::= SEQUENCE { initialCyclicShift INTEGER (0..11), nrofSymbols INTEGER (4..14),
    /// startingSymbolIndex INTEGER (0..10), timeDomainOCC INTEGER (0..6) }`.
    Format1 {
        initial_cyclic_shift: u8,
        nrof_symbols: u8,
        starting_symbol_index: u8,
        time_domain_occ: u8,
    },
    /// `PUCCH-format2 ::= SEQUENCE { nrofPRBs INTEGER (1..16), nrofSymbols INTEGER (1..2),
    /// startingSymbolIndex INTEGER (0..13) }`.
    Format2 {
        nrof_prbs: u8,
        nrof_symbols: u8,
        starting_symbol_index: u8,
    },
    /// `PUCCH-format3 ::= SEQUENCE { nrofPRBs INTEGER (1..16), nrofSymbols INTEGER (4..14),
    /// startingSymbolIndex INTEGER (0..10) }`.
    Format3 {
        nrof_prbs: u8,
        nrof_symbols: u8,
        starting_symbol_index: u8,
    },
    /// `PUCCH-format4 ::= SEQUENCE { nrofSymbols INTEGER (4..14), occ-Length ENUMERATED { n2, n4 },
    /// occ-Index ENUMERATED { n0, n1, n2, n3 }, startingSymbolIndex INTEGER (0..10) }`.
    Format4 {
        nrof_symbols: u8,
        occ_length: u8,
        occ_index: u8,
        starting_symbol_index: u8,
    },
}

impl PucchFormat {
    /// The PUCCH format number 0..4.
    pub fn number(&self) -> u8 {
        match self {
            Self::Format0 { .. } => 0,
            Self::Format1 { .. } => 1,
            Self::Format2 { .. } => 2,
            Self::Format3 { .. } => 3,
            Self::Format4 { .. } => 4,
        }
    }

    /// `(startingSymbolIndex, nrofSymbols)`.
    pub fn symbols(&self) -> (u8, u8) {
        match *self {
            Self::Format0 {
                nrof_symbols,
                starting_symbol_index,
                ..
            }
            | Self::Format1 {
                nrof_symbols,
                starting_symbol_index,
                ..
            }
            | Self::Format2 {
                nrof_symbols,
                starting_symbol_index,
                ..
            }
            | Self::Format3 {
                nrof_symbols,
                starting_symbol_index,
                ..
            }
            | Self::Format4 {
                nrof_symbols,
                starting_symbol_index,
                ..
            } => (starting_symbol_index, nrof_symbols),
        }
    }

    /// Number of PRBs (1 for formats 0, 1 and 4).
    pub fn nrof_prbs(&self) -> u8 {
        match *self {
            Self::Format2 { nrof_prbs, .. } | Self::Format3 { nrof_prbs, .. } => nrof_prbs,
            _ => 1,
        }
    }
}

/// `PUCCH-Resource ::= SEQUENCE { pucch-ResourceId PUCCH-ResourceId, startingPRB PRB-Id,
/// intraSlotFrequencyHopping ENUMERATED { enabled } OPTIONAL, secondHopPRB PRB-Id OPTIONAL, format
/// CHOICE {…} }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchResource {
    pub pucch_resource_id: u8,
    pub starting_prb: u16,
    pub intra_slot_frequency_hopping: bool,
    pub second_hop_prb: Option<u16>,
    pub format: PucchFormat,
}

impl PucchResource {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let [hop, has_hop2] = r.opt_bits::<2>()?;
        let pucch_resource_id = r.u8(0, 127)?;
        let starting_prb = r.u16(0, 274)?;
        let second_hop_prb = r.opt(has_hop2, |r| r.u16(0, 274))?;
        let format = match r.uint(0, 4)? {
            0 => PucchFormat::Format0 {
                initial_cyclic_shift: r.u8(0, 11)?,
                nrof_symbols: r.u8(1, 2)?,
                starting_symbol_index: r.u8(0, 13)?,
            },
            1 => PucchFormat::Format1 {
                initial_cyclic_shift: r.u8(0, 11)?,
                nrof_symbols: r.u8(4, 14)?,
                starting_symbol_index: r.u8(0, 10)?,
                time_domain_occ: r.u8(0, 6)?,
            },
            2 => PucchFormat::Format2 {
                nrof_prbs: r.u8(1, 16)?,
                nrof_symbols: r.u8(1, 2)?,
                starting_symbol_index: r.u8(0, 13)?,
            },
            3 => PucchFormat::Format3 {
                nrof_prbs: r.u8(1, 16)?,
                nrof_symbols: r.u8(4, 14)?,
                starting_symbol_index: r.u8(0, 10)?,
            },
            _ => PucchFormat::Format4 {
                nrof_symbols: r.u8(4, 14)?,
                occ_length: [2u8, 4][r.enu(2)? as usize],
                occ_index: r.enu(4)? as u8,
                starting_symbol_index: r.u8(0, 10)?,
            },
        };
        Ok(Self {
            pucch_resource_id,
            starting_prb,
            intra_slot_frequency_hopping: hop,
            second_hop_prb,
            format,
        })
    }
}

/// `PUCCH-MaxCodeRate ::= ENUMERATED { zeroDot08, zeroDot15, zeroDot25, zeroDot35, zeroDot45,
/// zeroDot60, zeroDot80, spare1 }` as the raw index; see [`Self::value`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchMaxCodeRate(pub u8);

impl PucchMaxCodeRate {
    /// The maximum code rate `r` (0 for the spare value).
    pub fn value(self) -> f32 {
        [0.08, 0.15, 0.25, 0.35, 0.45, 0.60, 0.80, 0.0][self.0.min(7) as usize]
    }
}

/// `PUCCH-FormatConfig ::= SEQUENCE { interslotFrequencyHopping ENUMERATED { enabled } OPTIONAL,
/// additionalDMRS ENUMERATED { true } OPTIONAL, maxCodeRate PUCCH-MaxCodeRate OPTIONAL, nrofSlots
/// ENUMERATED { n2, n4, n8 } OPTIONAL, pi2BPSK ENUMERATED { enabled } OPTIONAL,
/// simultaneousHARQ-ACK-CSI ENUMERATED { true } OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PucchFormatConfig {
    pub interslot_frequency_hopping: bool,
    pub additional_dmrs: bool,
    pub max_code_rate: Option<PucchMaxCodeRate>,
    pub nrof_slots: Option<u8>,
    pub pi2_bpsk: bool,
    pub simultaneous_harq_ack_csi: bool,
}

impl PucchFormatConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let o = r.opt_bits::<6>()?;
        let max_code_rate = r.opt(o[2], |r| Ok(PucchMaxCodeRate(r.enu(8)? as u8)))?;
        let nrof_slots = r.opt(o[3], |r| Ok(2u8 << r.enu(3)?))?;
        Ok(Self {
            interslot_frequency_hopping: o[0],
            additional_dmrs: o[1],
            max_code_rate,
            nrof_slots,
            pi2_bpsk: o[4],
            simultaneous_harq_ack_csi: o[5],
        })
    }
}

/// `periodicityAndOffset CHOICE { sym2 NULL, sym6or7 NULL, sl1 NULL, sl2 INTEGER (0..1), sl4,
/// sl5, sl8, sl10, sl16, sl20, sl40, sl80, sl160, sl320, sl640 }` of an SR resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrPeriodicityAndOffset {
    Sym2,
    Sym6or7,
    Slots { period_slots: u16, offset: u16 },
}

/// `SchedulingRequestResourceConfig ::= SEQUENCE { schedulingRequestResourceId
/// SchedulingRequestResourceId, schedulingRequestID SchedulingRequestId, periodicityAndOffset
/// CHOICE {…} OPTIONAL, resource PUCCH-ResourceId OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulingRequestResourceConfig {
    pub scheduling_request_resource_id: u8,
    pub scheduling_request_id: u8,
    pub periodicity_and_offset: Option<SrPeriodicityAndOffset>,
    pub resource: Option<u8>,
}

/// `referenceSignal CHOICE { ssb-Index SSB-Index, csi-RS-Index NZP-CSI-RS-ResourceId, srs SEQUENCE
/// { resource SRS-ResourceId, uplinkBWP BWP-Id } }` (PUCCH / SRS spatial relations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpatialRelationReference {
    Ssb(u8),
    CsiRs(u8),
    Srs { resource: u8, uplink_bwp: u8 },
}

impl SpatialRelationReference {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(match r.uint(0, 2)? {
            0 => Self::Ssb(r.u8(0, 63)?),
            1 => Self::CsiRs(r.u8(0, 191)?),
            _ => Self::Srs {
                resource: r.u8(0, 63)?,
                uplink_bwp: r.u8(0, 4)?,
            },
        })
    }
}

/// `PUCCH-SpatialRelationInfo ::= SEQUENCE { pucch-SpatialRelationInfoId
/// PUCCH-SpatialRelationInfoId, servingCellId ServCellIndex OPTIONAL, referenceSignal CHOICE {…},
/// pucch-PathlossReferenceRS-Id PUCCH-PathlossReferenceRS-Id, p0-PUCCH-Id P0-PUCCH-Id,
/// closedLoopIndex ENUMERATED { i0, i1 } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchSpatialRelationInfo {
    pub pucch_spatial_relation_info_id: u8,
    pub serving_cell_id: Option<u8>,
    pub reference_signal: SpatialRelationReference,
    pub pucch_pathloss_reference_rs_id: u8,
    pub p0_pucch_id: u8,
    pub closed_loop_index: u8,
}

/// `PUCCH-PowerControl ::= SEQUENCE { deltaF-PUCCH-f0 INTEGER (-16..15) OPTIONAL, deltaF-PUCCH-f1 …,
/// deltaF-PUCCH-f2 …, deltaF-PUCCH-f3 …, deltaF-PUCCH-f4 …, p0-Set SEQUENCE (SIZE (1..maxNrofPUCCH-P0-PerSet))
/// OF P0-PUCCH OPTIONAL, pathlossReferenceRSs SEQUENCE (SIZE (1..maxNrofPUCCH-PathlossReferenceRSs)) OF
/// PUCCH-PathlossReferenceRS OPTIONAL, twoPUCCH-PC-AdjustmentStates ENUMERATED { twoStates } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PucchPowerControl {
    pub delta_f_pucch_f0: Option<i8>,
    pub delta_f_pucch_f1: Option<i8>,
    pub delta_f_pucch_f2: Option<i8>,
    pub delta_f_pucch_f3: Option<i8>,
    pub delta_f_pucch_f4: Option<i8>,
    /// `P0-PUCCH ::= SEQUENCE { p0-PUCCH-Id INTEGER (1..8), p0-PUCCH-Value INTEGER (-16..15) }`.
    pub p0_set: Vec<(u8, i8)>,
    /// `PUCCH-PathlossReferenceRS ::= SEQUENCE { pucch-PathlossReferenceRS-Id (0..3), referenceSignal CHOICE {…} }`.
    pub pathloss_reference_rss: Vec<(u8, ReferenceSignal)>,
    pub two_pucch_pc_adjustment_states: bool,
}

/// `PUCCH-Config ::= SEQUENCE { resourceSetToAddModList SEQUENCE (SIZE (1..maxNrofPUCCH-ResourceSets))
/// OF PUCCH-ResourceSet OPTIONAL, resourceSetToReleaseList … OPTIONAL, resourceToAddModList SEQUENCE
/// (SIZE (1..maxNrofPUCCH-Resources)) OF PUCCH-Resource OPTIONAL, resourceToReleaseList … OPTIONAL,
/// format1 SetupRelease { PUCCH-FormatConfig } OPTIONAL, format2 … OPTIONAL, format3 … OPTIONAL,
/// format4 … OPTIONAL, schedulingRequestResourceToAddModList SEQUENCE (SIZE (1..maxNrofSR-Resources))
/// OF SchedulingRequestResourceConfig OPTIONAL, schedulingRequestResourceToReleaseList … OPTIONAL,
/// multi-CSI-PUCCH-ResourceList SEQUENCE (SIZE (1..2)) OF PUCCH-ResourceId OPTIONAL, dl-DataToUL-ACK
/// SEQUENCE (SIZE (1..8)) OF INTEGER (0..15) OPTIONAL, spatialRelationInfoToAddModList SEQUENCE (SIZE
/// (1..maxNrofSpatialRelationInfos)) OF PUCCH-SpatialRelationInfo OPTIONAL,
/// spatialRelationInfoToReleaseList … OPTIONAL, pucch-PowerControl PUCCH-PowerControl OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PucchConfig {
    pub resource_set_to_add_mod_list: Vec<PucchResourceSet>,
    pub resource_set_to_release_list: Vec<u8>,
    pub resource_to_add_mod_list: Vec<PucchResource>,
    pub resource_to_release_list: Vec<u8>,
    pub format1: Option<SetupRelease<PucchFormatConfig>>,
    pub format2: Option<SetupRelease<PucchFormatConfig>>,
    pub format3: Option<SetupRelease<PucchFormatConfig>>,
    pub format4: Option<SetupRelease<PucchFormatConfig>>,
    pub scheduling_request_resource_to_add_mod_list: Vec<SchedulingRequestResourceConfig>,
    pub scheduling_request_resource_to_release_list: Vec<u8>,
    pub multi_csi_pucch_resource_list: Vec<u8>,
    /// k1 values per DCI `PDSCH-to-HARQ_feedback timing indicator` value.
    pub dl_data_to_ul_ack: Vec<u8>,
    pub spatial_relation_info_to_add_mod_list: Vec<PucchSpatialRelationInfo>,
    pub spatial_relation_info_to_release_list: Vec<u8>,
    pub pucch_power_control: Option<PucchPowerControl>,
}

impl PucchConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<15>()?;
        let mut c = Self::default();
        if o[0] {
            c.resource_set_to_add_mod_list = r
                .seq_of(1, 4, |r| {
                    let [has_max] = r.opt_bits::<1>()?;
                    let pucch_resource_set_id = r.u8(0, 3)?;
                    let resource_list = r.seq_of(1, 32, |r| r.u8(0, 127))?;
                    let max_payload_size = r.opt(has_max, |r| r.u16(4, 256))?;
                    Ok(PucchResourceSet {
                        pucch_resource_set_id,
                        resource_list,
                        max_payload_size,
                    })
                })
                .ctx("resourceSetToAddModList")?;
        }
        if o[1] {
            c.resource_set_to_release_list = r.seq_of(1, 4, |r| r.u8(0, 3))?;
        }
        if o[2] {
            c.resource_to_add_mod_list = r
                .seq_of(1, 128, PucchResource::decode)
                .ctx("resourceToAddModList")?;
        }
        if o[3] {
            c.resource_to_release_list = r.seq_of(1, 128, |r| r.u8(0, 127))?;
        }
        let fmt = |r: &mut BitReader| r.setup_release(PucchFormatConfig::decode);
        c.format1 = r.opt(o[4], fmt).ctx("format1")?;
        c.format2 = r.opt(o[5], fmt).ctx("format2")?;
        c.format3 = r.opt(o[6], fmt).ctx("format3")?;
        c.format4 = r.opt(o[7], fmt).ctx("format4")?;
        if o[8] {
            c.scheduling_request_resource_to_add_mod_list = r
                .seq_of(1, 8, |r| {
                    let [has_po, has_res] = r.opt_bits::<2>()?;
                    let scheduling_request_resource_id = r.u8(1, 8)?;
                    let scheduling_request_id = r.u8(0, 7)?;
                    let periodicity_and_offset = r.opt(has_po, |r| {
                        const P: [u16; 15] =
                            [0, 0, 1, 2, 4, 5, 8, 10, 16, 20, 40, 80, 160, 320, 640];
                        let alt = r.uint(0, 14)? as usize;
                        Ok(match alt {
                            0 => SrPeriodicityAndOffset::Sym2,
                            1 => SrPeriodicityAndOffset::Sym6or7,
                            _ => {
                                let period_slots = P[alt];
                                let offset = if period_slots > 1 {
                                    r.u16(0, period_slots - 1)?
                                } else {
                                    0
                                };
                                SrPeriodicityAndOffset::Slots {
                                    period_slots,
                                    offset,
                                }
                            }
                        })
                    })?;
                    let resource = r.opt(has_res, |r| r.u8(0, 127))?;
                    Ok(SchedulingRequestResourceConfig {
                        scheduling_request_resource_id,
                        scheduling_request_id,
                        periodicity_and_offset,
                        resource,
                    })
                })
                .ctx("schedulingRequestResourceToAddModList")?;
        }
        if o[9] {
            c.scheduling_request_resource_to_release_list = r.seq_of(1, 8, |r| r.u8(1, 8))?;
        }
        if o[10] {
            c.multi_csi_pucch_resource_list = r.seq_of(1, 2, |r| r.u8(0, 127))?;
        }
        if o[11] {
            c.dl_data_to_ul_ack = r.seq_of(1, 8, |r| r.u8(0, 15))?;
        }
        if o[12] {
            c.spatial_relation_info_to_add_mod_list = r
                .seq_of(1, 8, |r| {
                    let [has_cell] = r.opt_bits::<1>()?;
                    let pucch_spatial_relation_info_id = r.u8(1, 8)?;
                    let serving_cell_id = r.opt(has_cell, |r| r.u8(0, 31))?;
                    let reference_signal = SpatialRelationReference::decode(r)?;
                    let pucch_pathloss_reference_rs_id = r.u8(0, 3)?;
                    let p0_pucch_id = r.u8(1, 8)?;
                    let closed_loop_index = r.enu(2)? as u8;
                    Ok(PucchSpatialRelationInfo {
                        pucch_spatial_relation_info_id,
                        serving_cell_id,
                        reference_signal,
                        pucch_pathloss_reference_rs_id,
                        p0_pucch_id,
                        closed_loop_index,
                    })
                })
                .ctx("spatialRelationInfoToAddModList")?;
        }
        if o[13] {
            c.spatial_relation_info_to_release_list = r.seq_of(1, 8, |r| r.u8(1, 8))?;
        }
        c.pucch_power_control = r
            .opt(o[14], |r| {
                let e = r.bit()?;
                let p = r.opt_bits::<8>()?;
                let df = |r: &mut BitReader, has: bool| r.opt(has, |r| Ok(r.int(-16, 15)? as i8));
                let delta_f_pucch_f0 = df(r, p[0])?;
                let delta_f_pucch_f1 = df(r, p[1])?;
                let delta_f_pucch_f2 = df(r, p[2])?;
                let delta_f_pucch_f3 = df(r, p[3])?;
                let delta_f_pucch_f4 = df(r, p[4])?;
                let p0_set = if p[5] {
                    r.seq_of(1, 8, |r| Ok((r.u8(1, 8)?, r.int(-16, 15)? as i8)))?
                } else {
                    vec![]
                };
                let pathloss_reference_rss = if p[6] {
                    r.seq_of(1, 4, |r| {
                        Ok((r.u8(0, 3)?, ReferenceSignal::decode_ssb_first(r)?))
                    })?
                } else {
                    vec![]
                };
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(PucchPowerControl {
                    delta_f_pucch_f0,
                    delta_f_pucch_f1,
                    delta_f_pucch_f2,
                    delta_f_pucch_f3,
                    delta_f_pucch_f4,
                    p0_set,
                    pathloss_reference_rss,
                    two_pucch_pc_adjustment_states: p[7],
                })
            })
            .ctx("pucch-PowerControl")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(c)
    }

    /// The PUCCH resource with the given id.
    pub fn resource(&self, id: u8) -> Option<&PucchResource> {
        self.resource_to_add_mod_list
            .iter()
            .find(|p| p.pucch_resource_id == id)
    }

    /// The resource list of PUCCH resource set `set_id` (the DCI PRI indexes it).
    pub fn resource_set(&self, set_id: u8) -> Option<&[u8]> {
        self.resource_set_to_add_mod_list
            .iter()
            .find(|s| s.pucch_resource_set_id == set_id)
            .map(|s| s.resource_list.as_slice())
    }
}

/// `PTRS-UplinkConfig ::= SEQUENCE { transformPrecoderDisabled SEQUENCE { frequencyDensity SEQUENCE
/// (SIZE (2)) OF INTEGER (1..276) OPTIONAL, timeDensity SEQUENCE (SIZE (3)) OF INTEGER (0..29)
/// OPTIONAL, maxNrofPorts ENUMERATED { n1, n2 }, resourceElementOffset ENUMERATED { offset01,
/// offset10, offset11 } OPTIONAL, ptrs-Power ENUMERATED { p00, p01, p10, p11 } } OPTIONAL,
/// transformPrecoderEnabled SEQUENCE { sampleDensity SEQUENCE (SIZE (5)) OF INTEGER (1..276),
/// timeDensityTransformPrecoding ENUMERATED { d2 } OPTIONAL } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PtrsUplinkConfig {
    pub transform_precoder_disabled: Option<PtrsUplinkTpDisabled>,
    pub transform_precoder_enabled: Option<PtrsUplinkTpEnabled>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PtrsUplinkTpDisabled {
    pub frequency_density: Option<[u16; 2]>,
    pub time_density: Option<[u8; 3]>,
    pub max_nrof_ports: u8,
    pub resource_element_offset: Option<u8>,
    pub ptrs_power: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PtrsUplinkTpEnabled {
    pub sample_density: [u16; 5],
    pub time_density_transform_precoding_d2: bool,
}

impl PtrsUplinkConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [dis, en] = r.opt_bits::<2>()?;
        let transform_precoder_disabled = r.opt(dis, |r| {
            let [fd, td, reo] = r.opt_bits::<3>()?;
            let frequency_density = r.opt(fd, |r| Ok([r.u16(1, 276)?, r.u16(1, 276)?]))?;
            let time_density = r.opt(td, |r| Ok([r.u8(0, 29)?, r.u8(0, 29)?, r.u8(0, 29)?]))?;
            let max_nrof_ports = r.enu(2)? as u8 + 1;
            let resource_element_offset = r.opt(reo, |r| Ok(r.enu(3)? as u8))?;
            let ptrs_power = r.enu(4)? as u8;
            Ok(PtrsUplinkTpDisabled {
                frequency_density,
                time_density,
                max_nrof_ports,
                resource_element_offset,
                ptrs_power,
            })
        })?;
        let transform_precoder_enabled = r.opt(en, |r| {
            let [d2] = r.opt_bits::<1>()?;
            let mut sample_density = [0u16; 5];
            for s in sample_density.iter_mut() {
                *s = r.u16(1, 276)?;
            }
            Ok(PtrsUplinkTpEnabled {
                sample_density,
                time_density_transform_precoding_d2: d2,
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            transform_precoder_disabled,
            transform_precoder_enabled,
        })
    }
}

/// `DMRS-UplinkConfig ::= SEQUENCE { dmrs-Type ENUMERATED { type2 } OPTIONAL, dmrs-AdditionalPosition
/// ENUMERATED { pos0, pos1, pos3 } OPTIONAL, phaseTrackingRS SetupRelease { PTRS-UplinkConfig } OPTIONAL,
/// maxLength ENUMERATED { len2 } OPTIONAL, transformPrecodingDisabled SEQUENCE { scramblingID0 INTEGER
/// (0..65535) OPTIONAL, scramblingID1 INTEGER (0..65535) OPTIONAL, ... } OPTIONAL,
/// transformPrecodingEnabled SEQUENCE { nPUSCH-Identity INTEGER (0..1007) OPTIONAL,
/// sequenceGroupHopping ENUMERATED { disabled } OPTIONAL, sequenceHopping ENUMERATED { enabled }
/// OPTIONAL, ... } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DmrsUplinkConfig {
    pub dmrs_type2: bool,
    /// 0, 1 or 3; absent ⇒ pos2.
    pub dmrs_additional_position: Option<u8>,
    pub phase_tracking_rs: Option<SetupRelease<PtrsUplinkConfig>>,
    pub max_length_len2: bool,
    /// `(scramblingID0, scramblingID1)` when `transformPrecodingDisabled` is present.
    pub transform_precoding_disabled: Option<(Option<u16>, Option<u16>)>,
    pub transform_precoding_enabled: Option<TransformPrecodingEnabled>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TransformPrecodingEnabled {
    pub n_pusch_identity: Option<u16>,
    pub sequence_group_hopping_disabled: bool,
    pub sequence_hopping_enabled: bool,
}

impl DmrsUplinkConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<6>()?;
        let dmrs_additional_position = r.opt(o[1], |r| Ok([0u8, 1, 3][r.enu(3)? as usize]))?;
        let phase_tracking_rs = r
            .opt(o[2], |r| r.setup_release(PtrsUplinkConfig::decode))
            .ctx("phaseTrackingRS")?;
        let transform_precoding_disabled = r.opt(o[4], |r| {
            let e = r.bit()?;
            let [s0, s1] = r.opt_bits::<2>()?;
            let id0 = r.opt(s0, |r| r.u16(0, 65535))?;
            let id1 = r.opt(s1, |r| r.u16(0, 65535))?;
            if e {
                r.skip_ext_additions()?;
            }
            Ok((id0, id1))
        })?;
        let transform_precoding_enabled = r.opt(o[5], |r| {
            let e = r.bit()?;
            let [nid, sgh, sh] = r.opt_bits::<3>()?;
            let n_pusch_identity = r.opt(nid, |r| r.u16(0, 1007))?;
            if e {
                r.skip_ext_additions()?;
            }
            Ok(TransformPrecodingEnabled {
                n_pusch_identity,
                sequence_group_hopping_disabled: sgh,
                sequence_hopping_enabled: sh,
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            dmrs_type2: o[0],
            dmrs_additional_position,
            phase_tracking_rs,
            max_length_len2: o[3],
            transform_precoding_disabled,
            transform_precoding_enabled,
        })
    }

    /// `dmrs-AdditionalPosition` with its default (pos2) applied.
    pub fn additional_position(&self) -> u8 {
        self.dmrs_additional_position.unwrap_or(2)
    }
}

/// `P0-PUSCH-AlphaSet ::= SEQUENCE { p0-PUSCH-AlphaSetId P0-PUSCH-AlphaSetId, p0 INTEGER (-16..15)
/// OPTIONAL, alpha Alpha OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P0PuschAlphaSet {
    pub p0_pusch_alpha_set_id: u8,
    pub p0: Option<i8>,
    pub alpha: Option<Alpha>,
}

/// `SRI-PUSCH-PowerControl ::= SEQUENCE { sri-PUSCH-PowerControlId SRI-PUSCH-PowerControlId,
/// sri-PUSCH-PathlossReferenceRS-Id PUSCH-PathlossReferenceRS-Id, sri-P0-PUSCH-AlphaSetId
/// P0-PUSCH-AlphaSetId, sri-PUSCH-ClosedLoopIndex ENUMERATED { i0, i1 } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SriPuschPowerControl {
    pub sri_pusch_power_control_id: u8,
    pub sri_pusch_pathloss_reference_rs_id: u8,
    pub sri_p0_pusch_alpha_set_id: u8,
    pub sri_pusch_closed_loop_index: u8,
}

/// `PUSCH-PowerControl ::= SEQUENCE { tpc-Accumulation ENUMERATED { disabled } OPTIONAL, msg3-Alpha
/// Alpha OPTIONAL, p0-NominalWithoutGrant INTEGER (-202..24) OPTIONAL, p0-AlphaSets SEQUENCE (SIZE
/// (1..maxNrofP0-PUSCH-AlphaSets)) OF P0-PUSCH-AlphaSet OPTIONAL, pathlossReferenceRSToAddModList
/// SEQUENCE (SIZE (1..maxNrofPUSCH-PathlossReferenceRSs)) OF PUSCH-PathlossReferenceRS OPTIONAL,
/// pathlossReferenceRSToReleaseList … OPTIONAL, twoPUSCH-PC-AdjustmentStates ENUMERATED { twoStates }
/// OPTIONAL, deltaMCS ENUMERATED { enabled } OPTIONAL, sri-PUSCH-MappingToAddModList SEQUENCE (SIZE
/// (1..maxNrofSRI-PUSCH-Mappings)) OF SRI-PUSCH-PowerControl OPTIONAL, sri-PUSCH-MappingToReleaseList
/// … OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PuschPowerControl {
    pub tpc_accumulation_disabled: bool,
    pub msg3_alpha: Option<Alpha>,
    pub p0_nominal_without_grant: Option<i16>,
    pub p0_alpha_sets: Vec<P0PuschAlphaSet>,
    /// `PUSCH-PathlossReferenceRS ::= SEQUENCE { pusch-PathlossReferenceRS-Id (0..3), referenceSignal CHOICE {…} }`.
    pub pathloss_reference_rs_to_add_mod_list: Vec<(u8, ReferenceSignal)>,
    pub pathloss_reference_rs_to_release_list: Vec<u8>,
    pub two_pusch_pc_adjustment_states: bool,
    pub delta_mcs_enabled: bool,
    pub sri_pusch_mapping_to_add_mod_list: Vec<SriPuschPowerControl>,
    pub sri_pusch_mapping_to_release_list: Vec<u8>,
}

impl PuschPowerControl {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let o = r.opt_bits::<10>()?;
        let mut c = Self {
            tpc_accumulation_disabled: o[0],
            two_pusch_pc_adjustment_states: o[6],
            delta_mcs_enabled: o[7],
            ..Default::default()
        };
        c.msg3_alpha = r.opt(o[1], Alpha::decode)?;
        c.p0_nominal_without_grant = r.opt(o[2], |r| Ok(r.int(-202, 24)? as i16))?;
        if o[3] {
            c.p0_alpha_sets = r.seq_of(1, 30, |r| {
                let [has_p0, has_a] = r.opt_bits::<2>()?;
                let p0_pusch_alpha_set_id = r.u8(0, 29)?;
                let p0 = r.opt(has_p0, |r| Ok(r.int(-16, 15)? as i8))?;
                let alpha = r.opt(has_a, Alpha::decode)?;
                Ok(P0PuschAlphaSet {
                    p0_pusch_alpha_set_id,
                    p0,
                    alpha,
                })
            })?;
        }
        if o[4] {
            c.pathloss_reference_rs_to_add_mod_list = r.seq_of(1, 4, |r| {
                Ok((r.u8(0, 3)?, ReferenceSignal::decode_ssb_first(r)?))
            })?;
        }
        if o[5] {
            c.pathloss_reference_rs_to_release_list = r.seq_of(1, 4, |r| r.u8(0, 3))?;
        }
        if o[8] {
            c.sri_pusch_mapping_to_add_mod_list = r.seq_of(1, 16, |r| {
                Ok(SriPuschPowerControl {
                    sri_pusch_power_control_id: r.u8(0, 15)?,
                    sri_pusch_pathloss_reference_rs_id: r.u8(0, 3)?,
                    sri_p0_pusch_alpha_set_id: r.u8(0, 29)?,
                    sri_pusch_closed_loop_index: r.enu(2)? as u8,
                })
            })?;
        }
        if o[9] {
            c.sri_pusch_mapping_to_release_list = r.seq_of(1, 16, |r| r.u8(0, 15))?;
        }
        Ok(c)
    }
}

/// `BetaOffsets ::= SEQUENCE { betaOffsetACK-Index1 INTEGER (0..31) OPTIONAL, betaOffsetACK-Index2 …,
/// betaOffsetACK-Index3 …, betaOffsetCSI-Part1-Index1 …, betaOffsetCSI-Part1-Index2 …,
/// betaOffsetCSI-Part2-Index1 …, betaOffsetCSI-Part2-Index2 … }` (absent ⇒ index 11 for ACK, 13 for CSI).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BetaOffsets {
    pub beta_offset_ack_index1: Option<u8>,
    pub beta_offset_ack_index2: Option<u8>,
    pub beta_offset_ack_index3: Option<u8>,
    pub beta_offset_csi_part1_index1: Option<u8>,
    pub beta_offset_csi_part1_index2: Option<u8>,
    pub beta_offset_csi_part2_index1: Option<u8>,
    pub beta_offset_csi_part2_index2: Option<u8>,
}

impl BetaOffsets {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let o = r.opt_bits::<7>()?;
        let mut v = [None; 7];
        for (slot, &p) in v.iter_mut().zip(o.iter()) {
            *slot = r.opt(p, |r| r.u8(0, 31))?;
        }
        Ok(Self {
            beta_offset_ack_index1: v[0],
            beta_offset_ack_index2: v[1],
            beta_offset_ack_index3: v[2],
            beta_offset_csi_part1_index1: v[3],
            beta_offset_csi_part1_index2: v[4],
            beta_offset_csi_part2_index1: v[5],
            beta_offset_csi_part2_index2: v[6],
        })
    }
}

/// `betaOffsets CHOICE { dynamic SEQUENCE (SIZE (4)) OF BetaOffsets, semiStatic BetaOffsets }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BetaOffsetsConfig {
    Dynamic([BetaOffsets; 4]),
    SemiStatic(BetaOffsets),
}

/// `UCI-OnPUSCH ::= SEQUENCE { betaOffsets CHOICE {…} OPTIONAL, scaling ENUMERATED { f0p5, f0p65,
/// f0p8, f1 } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UciOnPusch {
    pub beta_offsets: Option<BetaOffsetsConfig>,
    /// Raw index of `scaling` (0 = 0.5, 1 = 0.65, 2 = 0.8, 3 = 1).
    pub scaling: u8,
}

impl UciOnPusch {
    /// The scaling factor α for UCI multiplexing.
    pub fn scaling_value(&self) -> f32 {
        [0.5, 0.65, 0.8, 1.0][self.scaling.min(3) as usize]
    }
}

/// `codebookSubset ENUMERATED { fullyAndPartialAndNonCoherent, partialAndNonCoherent, nonCoherent }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodebookSubset {
    FullyAndPartialAndNonCoherent,
    PartialAndNonCoherent,
    NonCoherent,
}

/// `PUSCH-Config ::= SEQUENCE { dataScramblingIdentityPUSCH INTEGER (0..1023) OPTIONAL, txConfig
/// ENUMERATED { codebook, nonCodebook } OPTIONAL, dmrs-UplinkForPUSCH-MappingTypeA SetupRelease
/// { DMRS-UplinkConfig } OPTIONAL, dmrs-UplinkForPUSCH-MappingTypeB … OPTIONAL, pusch-PowerControl
/// PUSCH-PowerControl OPTIONAL, frequencyHopping ENUMERATED { intraSlot, interSlot } OPTIONAL,
/// frequencyHoppingOffsetLists SEQUENCE (SIZE (1..4)) OF INTEGER (1..maxNrofPhysicalResourceBlocks-1)
/// OPTIONAL, resourceAllocation ENUMERATED {…}, pusch-TimeDomainAllocationList SetupRelease {…}
/// OPTIONAL, pusch-AggregationFactor ENUMERATED { n2, n4, n8 } OPTIONAL, mcs-Table ENUMERATED
/// { qam256, qam64LowSE } OPTIONAL, mcs-TableTransformPrecoder ENUMERATED {…} OPTIONAL,
/// transformPrecoder ENUMERATED { enabled, disabled } OPTIONAL, codebookSubset ENUMERATED {…}
/// OPTIONAL, maxRank INTEGER (1..4) OPTIONAL, rbg-Size ENUMERATED { config2 } OPTIONAL, uci-OnPUSCH
/// SetupRelease { UCI-OnPUSCH } OPTIONAL, tp-pi2BPSK ENUMERATED { enabled } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PuschConfig {
    pub data_scrambling_identity_pusch: Option<u16>,
    /// `Some(true)` = codebook, `Some(false)` = nonCodebook.
    pub tx_config_codebook: Option<bool>,
    pub dmrs_uplink_for_pusch_mapping_type_a: Option<SetupRelease<DmrsUplinkConfig>>,
    pub dmrs_uplink_for_pusch_mapping_type_b: Option<SetupRelease<DmrsUplinkConfig>>,
    pub pusch_power_control: Option<PuschPowerControl>,
    /// `Some(true)` = intraSlot, `Some(false)` = interSlot.
    pub frequency_hopping_intra_slot: Option<bool>,
    pub frequency_hopping_offset_lists: Vec<u16>,
    pub resource_allocation: ResourceAllocation,
    pub pusch_time_domain_allocation_list: Option<SetupRelease<Vec<TdraRow>>>,
    pub pusch_aggregation_factor: Option<u8>,
    pub mcs_table: Option<McsTable>,
    pub mcs_table_transform_precoder: Option<McsTable>,
    /// `Some(true)` = enabled, `Some(false)` = disabled; absent ⇒ `msg3-transformPrecoder` applies.
    pub transform_precoder_enabled: Option<bool>,
    pub codebook_subset: Option<CodebookSubset>,
    pub max_rank: Option<u8>,
    pub rbg_size_config2: bool,
    pub uci_on_pusch: Option<SetupRelease<UciOnPusch>>,
    pub tp_pi2_bpsk: bool,
}

impl PuschConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<17>()?;
        let data_scrambling_identity_pusch = r.opt(o[0], |r| r.u16(0, 1023))?;
        let tx_config_codebook = r.opt(o[1], |r| Ok(r.enu(2)? == 0))?;
        let dmrs_uplink_for_pusch_mapping_type_a = r
            .opt(o[2], |r| r.setup_release(DmrsUplinkConfig::decode))
            .ctx("dmrs-UplinkForPUSCH-MappingTypeA")?;
        let dmrs_uplink_for_pusch_mapping_type_b = r
            .opt(o[3], |r| r.setup_release(DmrsUplinkConfig::decode))
            .ctx("dmrs-UplinkForPUSCH-MappingTypeB")?;
        let pusch_power_control = r
            .opt(o[4], PuschPowerControl::decode)
            .ctx("pusch-PowerControl")?;
        let frequency_hopping_intra_slot = r.opt(o[5], |r| Ok(r.enu(2)? == 0))?;
        let frequency_hopping_offset_lists = if o[6] {
            r.seq_of(1, 4, |r| r.u16(1, 274))?
        } else {
            vec![]
        };
        let resource_allocation = ResourceAllocation::decode(r)?;
        let pusch_time_domain_allocation_list = r
            .opt(o[7], |r| r.setup_release(decode_tdra_list))
            .ctx("pusch-TimeDomainAllocationList")?;
        let pusch_aggregation_factor = r.opt(o[8], |r| Ok(2u8 << r.enu(3)?))?;
        let mcs_table = r.opt(o[9], McsTable::decode)?;
        let mcs_table_transform_precoder = r.opt(o[10], McsTable::decode)?;
        let transform_precoder_enabled = r.opt(o[11], |r| Ok(r.enu(2)? == 0))?;
        let codebook_subset = r.opt(o[12], |r| {
            Ok(match r.enu(3)? {
                0 => CodebookSubset::FullyAndPartialAndNonCoherent,
                1 => CodebookSubset::PartialAndNonCoherent,
                _ => CodebookSubset::NonCoherent,
            })
        })?;
        let max_rank = r.opt(o[13], |r| r.u8(1, 4))?;
        let uci_on_pusch = r
            .opt(o[15], |r| {
                r.setup_release(|r| {
                    let [has_beta] = r.opt_bits::<1>()?;
                    let beta_offsets = r.opt(has_beta, |r| {
                        Ok(if !r.bit()? {
                            BetaOffsetsConfig::Dynamic([
                                BetaOffsets::decode(r)?,
                                BetaOffsets::decode(r)?,
                                BetaOffsets::decode(r)?,
                                BetaOffsets::decode(r)?,
                            ])
                        } else {
                            BetaOffsetsConfig::SemiStatic(BetaOffsets::decode(r)?)
                        })
                    })?;
                    let scaling = r.enu(4)? as u8;
                    Ok(UciOnPusch {
                        beta_offsets,
                        scaling,
                    })
                })
            })
            .ctx("uci-OnPUSCH")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            data_scrambling_identity_pusch,
            tx_config_codebook,
            dmrs_uplink_for_pusch_mapping_type_a,
            dmrs_uplink_for_pusch_mapping_type_b,
            pusch_power_control,
            frequency_hopping_intra_slot,
            frequency_hopping_offset_lists,
            resource_allocation,
            pusch_time_domain_allocation_list,
            pusch_aggregation_factor,
            mcs_table,
            mcs_table_transform_precoder,
            transform_precoder_enabled,
            codebook_subset,
            max_rank,
            rbg_size_config2: o[14],
            uci_on_pusch,
            tp_pi2_bpsk: o[16],
        })
    }

    /// The dedicated `pusch-TimeDomainAllocationList` when set up.
    pub fn tdra_list(&self) -> Option<&[TdraRow]> {
        self.pusch_time_domain_allocation_list
            .as_ref()?
            .setup()
            .map(Vec::as_slice)
    }
}

/// `resourceType CHOICE { aperiodic SEQUENCE { aperiodicSRS-ResourceTrigger INTEGER (1..maxNrofSRS-TriggerStates-1),
/// csi-RS NZP-CSI-RS-ResourceId OPTIONAL, slotOffset INTEGER (1..32) OPTIONAL, ... }, semi-persistent
/// SEQUENCE { associatedCSI-RS NZP-CSI-RS-ResourceId OPTIONAL, ... }, periodic SEQUENCE { associatedCSI-RS
/// … OPTIONAL, ... } }` of an SRS resource set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrsResourceSetType {
    Aperiodic {
        aperiodic_srs_resource_trigger: u8,
        csi_rs: Option<u8>,
        slot_offset: Option<u8>,
    },
    SemiPersistent {
        associated_csi_rs: Option<u8>,
    },
    Periodic {
        associated_csi_rs: Option<u8>,
    },
}

/// `usage ENUMERATED { beamManagement, codebook, nonCodebook, antennaSwitching }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrsUsage {
    BeamManagement,
    Codebook,
    NonCodebook,
    AntennaSwitching,
}

/// `SRS-ResourceSet ::= SEQUENCE { srs-ResourceSetId SRS-ResourceSetId, srs-ResourceIdList SEQUENCE
/// (SIZE(1..maxNrofSRS-ResourcesPerSet)) OF SRS-ResourceId OPTIONAL, resourceType CHOICE {…}, usage
/// ENUMERATED {…}, alpha Alpha OPTIONAL, p0 INTEGER (-202..24) OPTIONAL, pathlossReferenceRS CHOICE
/// { ssb-Index SSB-Index, csi-RS-Index NZP-CSI-RS-ResourceId } OPTIONAL, srs-PowerControlAdjustmentStates
/// ENUMERATED { sameAsFci2, separateClosedLoop } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrsResourceSet {
    pub srs_resource_set_id: u8,
    pub srs_resource_id_list: Vec<u8>,
    pub resource_type: SrsResourceSetType,
    pub usage: SrsUsage,
    pub alpha: Option<Alpha>,
    pub p0: Option<i16>,
    pub pathloss_reference_rs: Option<ReferenceSignal>,
    pub srs_power_control_adjustment_states: Option<u8>,
}

/// `transmissionComb CHOICE { n2 SEQUENCE { combOffset-n2 INTEGER (0..1), cyclicShift-n2 INTEGER (0..7) },
/// n4 SEQUENCE { combOffset-n4 INTEGER (0..3), cyclicShift-n4 INTEGER (0..11) } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrsTransmissionComb {
    N2 { comb_offset: u8, cyclic_shift: u8 },
    N4 { comb_offset: u8, cyclic_shift: u8 },
}

/// `resourceType CHOICE { aperiodic SEQUENCE { ... }, semi-persistent SEQUENCE { periodicityAndOffset-sp
/// SRS-PeriodicityAndOffset, ... }, periodic SEQUENCE { periodicityAndOffset-p SRS-PeriodicityAndOffset, ... } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrsResourceType {
    Aperiodic,
    SemiPersistent(PeriodicityAndOffset),
    Periodic(PeriodicityAndOffset),
}

/// `SRS-SpatialRelationInfo ::= SEQUENCE { servingCellId ServCellIndex OPTIONAL, referenceSignal CHOICE {…} }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrsSpatialRelationInfo {
    pub serving_cell_id: Option<u8>,
    pub reference_signal: SpatialRelationReference,
}

/// `SRS-Resource ::= SEQUENCE { srs-ResourceId SRS-ResourceId, nrofSRS-Ports ENUMERATED { port1, ports2,
/// ports4 }, ptrs-PortIndex ENUMERATED { n0, n1 } OPTIONAL, transmissionComb CHOICE {…}, resourceMapping
/// SEQUENCE { startPosition INTEGER (0..5), nrofSymbols ENUMERATED { n1, n2, n4 }, repetitionFactor
/// ENUMERATED { n1, n2, n4 } }, freqDomainPosition INTEGER (0..67), freqDomainShift INTEGER (0..268),
/// freqHopping SEQUENCE { c-SRS INTEGER (0..63), b-SRS INTEGER (0..3), b-hop INTEGER (0..3) },
/// groupOrSequenceHopping ENUMERATED { neither, groupHopping, sequenceHopping }, resourceType CHOICE {…},
/// sequenceId INTEGER (0..1023), spatialRelationInfo SRS-SpatialRelationInfo OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrsResource {
    pub srs_resource_id: u8,
    pub nrof_srs_ports: u8,
    pub ptrs_port_index: Option<u8>,
    pub transmission_comb: SrsTransmissionComb,
    pub start_position: u8,
    pub nrof_symbols: u8,
    pub repetition_factor: u8,
    pub freq_domain_position: u8,
    pub freq_domain_shift: u16,
    pub c_srs: u8,
    pub b_srs: u8,
    pub b_hop: u8,
    /// 0 = neither, 1 = groupHopping, 2 = sequenceHopping.
    pub group_or_sequence_hopping: u8,
    pub resource_type: SrsResourceType,
    pub sequence_id: u16,
    pub spatial_relation_info: Option<SrsSpatialRelationInfo>,
}

/// `SRS-Config ::= SEQUENCE { srs-ResourceSetToReleaseList … OPTIONAL, srs-ResourceSetToAddModList
/// SEQUENCE (SIZE(1..maxNrofSRS-ResourceSets)) OF SRS-ResourceSet OPTIONAL, srs-ResourceToReleaseList
/// … OPTIONAL, srs-ResourceToAddModList SEQUENCE (SIZE(1..maxNrofSRS-Resources)) OF SRS-Resource
/// OPTIONAL, tpc-Accumulation ENUMERATED { disabled } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SrsConfig {
    pub srs_resource_set_to_release_list: Vec<u8>,
    pub srs_resource_set_to_add_mod_list: Vec<SrsResourceSet>,
    pub srs_resource_to_release_list: Vec<u8>,
    pub srs_resource_to_add_mod_list: Vec<SrsResource>,
    pub tpc_accumulation_disabled: bool,
}

impl SrsConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [set_rel, set_add, res_rel, res_add, tpc] = r.opt_bits::<5>()?;
        let mut c = Self {
            tpc_accumulation_disabled: tpc,
            ..Default::default()
        };
        if set_rel {
            c.srs_resource_set_to_release_list = r.seq_of(1, 16, |r| r.u8(0, 15))?;
        }
        if set_add {
            c.srs_resource_set_to_add_mod_list = r
                .seq_of(1, 16, Self::decode_set)
                .ctx("srs-ResourceSetToAddModList")?;
        }
        if res_rel {
            c.srs_resource_to_release_list = r.seq_of(1, 64, |r| r.u8(0, 63))?;
        }
        if res_add {
            c.srs_resource_to_add_mod_list = r
                .seq_of(1, 64, Self::decode_resource)
                .ctx("srs-ResourceToAddModList")?;
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(c)
    }

    fn decode_set(r: &mut BitReader) -> DecodeResult<SrsResourceSet> {
        let ext = r.bit()?;
        let [has_ids, has_alpha, has_p0, has_plrs, has_pcadj] = r.opt_bits::<5>()?;
        let srs_resource_set_id = r.u8(0, 15)?;
        let srs_resource_id_list = if has_ids {
            r.seq_of(1, 16, |r| r.u8(0, 63))?
        } else {
            vec![]
        };
        let resource_type = match r.uint(0, 2)? {
            0 => {
                let e = r.bit()?;
                let [has_csi, has_off] = r.opt_bits::<2>()?;
                let aperiodic_srs_resource_trigger = r.u8(1, 3)?;
                let csi_rs = r.opt(has_csi, |r| r.u8(0, 191))?;
                let slot_offset = r.opt(has_off, |r| r.u8(1, 32))?;
                if e {
                    r.skip_ext_additions()?;
                }
                SrsResourceSetType::Aperiodic {
                    aperiodic_srs_resource_trigger,
                    csi_rs,
                    slot_offset,
                }
            }
            alt => {
                let e = r.bit()?;
                let [has_csi] = r.opt_bits::<1>()?;
                let associated_csi_rs = r.opt(has_csi, |r| r.u8(0, 191))?;
                if e {
                    r.skip_ext_additions()?;
                }
                if alt == 1 {
                    SrsResourceSetType::SemiPersistent { associated_csi_rs }
                } else {
                    SrsResourceSetType::Periodic { associated_csi_rs }
                }
            }
        };
        let usage = match r.enu(4)? {
            0 => SrsUsage::BeamManagement,
            1 => SrsUsage::Codebook,
            2 => SrsUsage::NonCodebook,
            _ => SrsUsage::AntennaSwitching,
        };
        let alpha = r.opt(has_alpha, Alpha::decode)?;
        let p0 = r.opt(has_p0, |r| Ok(r.int(-202, 24)? as i16))?;
        let pathloss_reference_rs = r.opt(has_plrs, ReferenceSignal::decode_ssb_first)?;
        let srs_power_control_adjustment_states = r.opt(has_pcadj, |r| Ok(r.enu(2)? as u8))?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(SrsResourceSet {
            srs_resource_set_id,
            srs_resource_id_list,
            resource_type,
            usage,
            alpha,
            p0,
            pathloss_reference_rs,
            srs_power_control_adjustment_states,
        })
    }

    fn decode_resource(r: &mut BitReader) -> DecodeResult<SrsResource> {
        let ext = r.bit()?;
        let [has_ptrs, has_spatial] = r.opt_bits::<2>()?;
        let srs_resource_id = r.u8(0, 63)?;
        let nrof_srs_ports = 1u8 << r.enu(3)?;
        let ptrs_port_index = r.opt(has_ptrs, |r| Ok(r.enu(2)? as u8))?;
        let transmission_comb = if !r.bit()? {
            SrsTransmissionComb::N2 {
                comb_offset: r.u8(0, 1)?,
                cyclic_shift: r.u8(0, 7)?,
            }
        } else {
            SrsTransmissionComb::N4 {
                comb_offset: r.u8(0, 3)?,
                cyclic_shift: r.u8(0, 11)?,
            }
        };
        let start_position = r.u8(0, 5)?;
        let nrof_symbols = 1u8 << r.enu(3)?;
        let repetition_factor = 1u8 << r.enu(3)?;
        let freq_domain_position = r.u8(0, 67)?;
        let freq_domain_shift = r.u16(0, 268)?;
        let c_srs = r.u8(0, 63)?;
        let b_srs = r.u8(0, 3)?;
        let b_hop = r.u8(0, 3)?;
        let group_or_sequence_hopping = r.enu(3)? as u8;
        let resource_type = match r.uint(0, 2)? {
            0 => {
                if r.bit()? {
                    r.skip_ext_additions()?;
                }
                SrsResourceType::Aperiodic
            }
            alt => {
                let e = r.bit()?;
                let po = PeriodicityAndOffset::decode_srs(r)?;
                if e {
                    r.skip_ext_additions()?;
                }
                if alt == 1 {
                    SrsResourceType::SemiPersistent(po)
                } else {
                    SrsResourceType::Periodic(po)
                }
            }
        };
        let sequence_id = r.u16(0, 1023)?;
        let spatial_relation_info = r.opt(has_spatial, |r| {
            let [has_cell] = r.opt_bits::<1>()?;
            let serving_cell_id = r.opt(has_cell, |r| r.u8(0, 31))?;
            let reference_signal = SpatialRelationReference::decode(r)?;
            Ok(SrsSpatialRelationInfo {
                serving_cell_id,
                reference_signal,
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(SrsResource {
            srs_resource_id,
            nrof_srs_ports,
            ptrs_port_index,
            transmission_comb,
            start_position,
            nrof_symbols,
            repetition_factor,
            freq_domain_position,
            freq_domain_shift,
            c_srs,
            b_srs,
            b_hop,
            group_or_sequence_hopping,
            resource_type,
            sequence_id,
            spatial_relation_info,
        })
    }
}

// ---------------------------------------------------------------------------
// CellGroupConfig
// ---------------------------------------------------------------------------

/// `CellGroupConfig ::= SEQUENCE { cellGroupId CellGroupId, rlc-BearerToAddModList SEQUENCE (SIZE(1..maxLC-ID))
/// OF RLC-BearerConfig OPTIONAL, rlc-BearerToReleaseList SEQUENCE (SIZE(1..maxLC-ID)) OF LogicalChannelIdentity
/// OPTIONAL, mac-CellGroupConfig MAC-CellGroupConfig OPTIONAL, physicalCellGroupConfig PhysicalCellGroupConfig
/// OPTIONAL, spCellConfig SpCellConfig OPTIONAL, sCellToAddModList … OPTIONAL, sCellToReleaseList … OPTIONAL,
/// ... }` — the SCell lists are not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellGroupConfig {
    pub cell_group_id: u8,
    pub rlc_bearer_to_add_mod_list: Vec<RlcBearerConfig>,
    pub rlc_bearer_to_release_list: Vec<u8>,
    pub mac_cell_group_config: Option<MacCellGroupConfig>,
    pub physical_cell_group_config: Option<PhysicalCellGroupConfig>,
    pub sp_cell_config: Option<SpCellConfig>,
}

impl CellGroupConfig {
    /// Decode a `CellGroupConfig` from the octets of a `masterCellGroup` container.
    pub fn decode(octets: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(octets)).ctx("CellGroupConfig")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let o = r.opt_bits::<7>()?;
        let cell_group_id = r.u8(0, 3)?;
        log::trace!("CellGroupConfig id={cell_group_id} optionals {:?}", o);
        let rlc_bearer_to_add_mod_list = if o[0] {
            r.seq_of(1, 32, RlcBearerConfig::decode)
                .ctx("rlc-BearerToAddModList")?
        } else {
            vec![]
        };
        let rlc_bearer_to_release_list = if o[1] {
            r.seq_of(1, 32, |r| r.u8(1, 32))?
        } else {
            vec![]
        };
        let mac_cell_group_config = r
            .opt(o[2], MacCellGroupConfig::decode)
            .ctx("mac-CellGroupConfig")?;
        let physical_cell_group_config = r
            .opt(o[3], PhysicalCellGroupConfig::decode)
            .ctx("physicalCellGroupConfig")?;
        let sp_cell_config = r.opt(o[4], SpCellConfig::decode).ctx("spCellConfig")?;
        if o[5] || o[6] {
            return r.unsupported("sCellToAddModList/sCellToReleaseList");
        }
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            cell_group_id,
            rlc_bearer_to_add_mod_list,
            rlc_bearer_to_release_list,
            mac_cell_group_config,
            physical_cell_group_config,
            sp_cell_config,
        })
    }

    // ---- convenience accessors -------------------------------------------------

    pub fn serving_cell(&self) -> Option<&ServingCellConfig> {
        self.sp_cell_config
            .as_ref()?
            .sp_cell_config_dedicated
            .as_ref()
    }

    pub fn initial_downlink_bwp(&self) -> Option<&BwpDownlinkDedicated> {
        self.serving_cell()?.initial_downlink_bwp.as_ref()
    }

    pub fn initial_uplink_bwp(&self) -> Option<&BwpUplinkDedicated> {
        self.serving_cell()?
            .uplink_config
            .as_ref()?
            .initial_uplink_bwp
            .as_ref()
    }

    pub fn pdcch_config(&self) -> Option<&PdcchConfig> {
        self.initial_downlink_bwp()?.pdcch_config.as_ref()?.setup()
    }

    pub fn pdsch_config(&self) -> Option<&PdschConfig> {
        self.initial_downlink_bwp()?.pdsch_config.as_ref()?.setup()
    }

    pub fn pucch_config(&self) -> Option<&PucchConfig> {
        self.initial_uplink_bwp()?.pucch_config.as_ref()?.setup()
    }

    pub fn pusch_config(&self) -> Option<&PuschConfig> {
        self.initial_uplink_bwp()?.pusch_config.as_ref()?.setup()
    }

    pub fn srs_config(&self) -> Option<&SrsConfig> {
        self.initial_uplink_bwp()?.srs_config.as_ref()?.setup()
    }

    pub fn csi_meas_config(&self) -> Option<&CsiMeasConfig> {
        self.serving_cell()?.csi_meas_config.as_ref()?.setup()
    }

    pub fn pdsch_serving_cell_config(&self) -> Option<&PdschServingCellConfig> {
        self.serving_cell()?
            .pdsch_serving_cell_config
            .as_ref()?
            .setup()
    }

    /// `nrofHARQ-ProcessesForPDSCH` (default 8).
    pub fn nrof_harq_processes_for_pdsch(&self) -> u8 {
        self.pdsch_serving_cell_config()
            .map_or(8, |p| p.nrof_harq_processes())
    }

    /// `dl-DataToUL-ACK` (the k1 list), empty when not configured.
    pub fn k1_list(&self) -> &[u8] {
        self.pucch_config()
            .map_or(&[], |p| p.dl_data_to_ul_ack.as_slice())
    }

    /// The first SR resource: `(period, offset, PUCCH resource id)` for slot-periodic SRs.
    pub fn sr_resource(&self) -> Option<&SchedulingRequestResourceConfig> {
        self.pucch_config()?
            .scheduling_request_resource_to_add_mod_list
            .first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rrc::DlCcchMessage;

    /// Live captures: the 5 ms cell and the 2.5 ms DDDSU cell (both 289 bytes).
    const RRC_SETUP_MS5: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2400044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c6050e1fa2b3c4de4d03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8801c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e20000001002000403000404801100520000118800f38e000";
    const RRC_SETUP_DDDSU: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2c00044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c605081fa33c4de6cd03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8a01c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e28000001002000403000404801100520000118900f38e000";

    fn setup(hex: &str) -> CellGroupConfig {
        match DlCcchMessage::decode(&ferrite_common::from_hex(hex).unwrap())
            .expect("RRCSetup must parse")
        {
            DlCcchMessage::RrcSetup(s) => s.master_cell_group,
            other => panic!("not an RRCSetup: {other:?}"),
        }
    }

    fn sr_slot(cg: &CellGroupConfig) -> (u16, u16, u8) {
        let sr = cg.sr_resource().expect("SR config");
        match sr.periodicity_and_offset {
            Some(SrPeriodicityAndOffset::Slots {
                period_slots,
                offset,
            }) => (period_slots, offset, sr.resource.unwrap()),
            other => panic!("unexpected SR periodicity {other:?}"),
        }
    }

    #[test]
    fn parses_ms5_rrc_setup() {
        let cg = setup(RRC_SETUP_MS5);
        // The empirically-known dedicated config of the 5 ms cell:
        assert_eq!(cg.k1_list(), &[4, 5, 6, 7, 8, 9, 11, 12]);
        // OCUDU sends NO dedicated TDRA lists: the DCI 0_1/1_1 TDRA field width falls
        // back to the SIB1 common list (TS 38.214 §5.1.2.1.1).
        assert!(cg.pdsch_config().unwrap().tdra_list().is_none());
        assert!(cg.pusch_config().unwrap().tdra_list().is_none());
        let _ = sr_slot(&cg);
        let pucch = cg.pucch_config().unwrap();
        assert!(!pucch.resource_to_add_mod_list.is_empty());
        assert!(pucch.resource_set(0).is_some() && pucch.resource_set(1).is_some());
        // Periodic CSI report on PUCCH: period 40 slots, offset 8, PUCCH resource 15.
        let (slot, res) = cg.csi_meas_config().unwrap().periodic_report().unwrap();
        assert_eq!(
            (slot.period_slots, slot.offset, res.pucch_resource),
            (40, 8, 15)
        );
        assert_eq!(pucch.resource(15).unwrap().format.number(), 2);
        // Bearers: SRB1 on LCID 1, AM.
        let srb1 = &cg.rlc_bearer_to_add_mod_list[0];
        assert_eq!(srb1.logical_channel_identity, 1);
        assert_eq!(srb1.served_radio_bearer, Some(ServedRadioBearer::Srb(1)));
        assert!(matches!(srb1.rlc_config, Some(RlcConfig::Am { .. })));
        let phy = cg.physical_cell_group_config.as_ref().unwrap();
        assert_eq!(phy.pdsch_harq_ack_codebook, HarqAckCodebook::Dynamic);
        let coresets = &cg
            .pdcch_config()
            .unwrap()
            .control_resource_set_to_add_mod_list;
        assert!(coresets.iter().any(|c| c.control_resource_set_id == 1));
        assert!(!cg
            .csi_meas_config()
            .unwrap()
            .nzp_csi_rs_resource_to_add_mod_list
            .is_empty());
        assert!(cg
            .mac_cell_group_config
            .as_ref()
            .unwrap()
            .bsr_config
            .is_some());
    }

    #[test]
    fn parses_dddsu_rrc_setup() {
        let cg = setup(RRC_SETUP_DDDSU);
        // SR observed live at slot 4 (period 20 offset 4, or an equivalent).
        let (period, offset, _res) = sr_slot(&cg);
        assert_eq!(
            (period + offset) % 5,
            4,
            "SR occasion must be the DDDSU UL slot"
        );
        // Differential vs the 5 ms cell: OCUDU retunes the k1 list to the pattern.
        assert_eq!(cg.k1_list(), &[4, 6, 7, 8, 9, 11, 12, 13]);
        // CSI report also lands on the UL slot (offset 9 ≡ 4 mod 5).
        let (slot, res) = cg.csi_meas_config().unwrap().periodic_report().unwrap();
        assert_eq!(
            (slot.period_slots, slot.offset, res.pucch_resource),
            (40, 9, 15)
        );
    }
}
