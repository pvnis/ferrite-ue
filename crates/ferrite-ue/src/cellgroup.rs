//! RRCSetup / masterCellGroup decode (TS 38.331): a hand-rolled UPER parse of
//! `DL-CCCH-Message → RRCSetup → masterCellGroup (CellGroupConfig)`, extracting the
//! DEDICATED configuration the UE has so far carried as transcribed constants:
//!
//!   · dl-DataToUL-ACK — the k1 list (HARQ-ACK timing per DCI field value)
//!   · PUCCH resources + schedulingRequestResourceConfig — SR slot/resource
//!   · dedicated PDSCH/PUSCH time-domain allocation lists — the DCI 0_1/1_1
//!     TDRA field WIDTHS derive from these list lengths (TS 38.212 §7.3.1),
//!     which is what makes the DCI layout cell-specific
//!   · pdsch-HARQ-ACK-Codebook (semiStatic/dynamic), DM-RS additional positions
//!   · CSI-MeasConfig — the NZP/ZP CSI-RS resources (PDSCH rate-match patterns,
//!     TS 38.214 §5.1.4) and the periodic report slot/resource
//!   · CORESET#1 geometry (frequency bitmap, duration, CCE-REG mapping)
//!
//! Clean-room from the TS 38.331 ASN.1. Same iterate-against-live-capture method
//! as `sib1`: unknown branches refuse loudly (trace + None) rather than misparse,
//! so support grows exactly with what real gNBs emit. Two captures (the 5 ms cell
//! and a 2.5 ms DDDSU cell) cross-validate every field that differs.
//!
//! Set `FERRITE_CG_TRACE=1` for a per-field dump.

use crate::sib1::TdraRow;
use crate::uper::Bits;

macro_rules! trace {
    ($($t:tt)*) => {
        if std::env::var_os("FERRITE_CG_TRACE").is_some() {
            eprintln!("[cg] {}", format!($($t)*));
        }
    };
}

/// One dedicated PUCCH resource.
#[derive(Clone, Copy, Debug, Default)]
pub struct PucchResource {
    pub id: u8,
    pub prb: u16,
    pub second_hop_prb: Option<u16>,
    /// 0..4 = PUCCH format 0..4.
    pub format: u8,
    pub start_symbol: u8,
    pub n_symbols: u8,
    /// Format 0/1: initial cyclic shift; format 2/3: nrofPRBs.
    pub cs_or_prbs: u8,
    /// Format 1: time-domain OCC.
    pub occ: u8,
}

/// A CSI-RS resource (NZP or ZP): everything needed for the PDSCH rate-match and
/// the CQI measurement.
#[derive(Clone, Copy, Debug, Default)]
pub struct CsiRsRes {
    /// Row of TS 38.211 Table 7.4.1.5.3-1 (1, 2, 4 or "other").
    pub row: u8,
    /// The frequencyDomainAllocation bit string (row-dependent width, MSB-first).
    pub freq_bits: u16,
    pub symbol: u8,
    pub symbol2: Option<u8>,
    /// Density: 0 = dot5, 1 = one, 3 = three.
    pub density: u8,
    pub start_rb: u16,
    pub n_rb: u16,
    /// Periodicity in slots and the slot offset.
    pub period_slots: u16,
    pub offset_slots: u16,
}

/// Everything extracted from masterCellGroup.
#[derive(Clone, Debug, Default)]
pub struct CellGroupParams {
    /// dl-DataToUL-ACK: k1 per DCI PDSCH-to-HARQ-timing field value.
    pub k1_list: Vec<u8>,
    pub pucch_resources: Vec<PucchResource>,
    /// (periodicity in slots, offset, PUCCH resource id).
    pub sr: Option<(u16, u16, u8)>,
    /// Dedicated TDRA lists (override the SIB1 common ones when present).
    pub pdsch_tdra: Vec<TdraRow>,
    pub pusch_tdra: Vec<TdraRow>,
    /// pdsch-HARQ-ACK-Codebook: true = dynamic.
    pub harq_codebook_dynamic: bool,
    /// dmrs-AdditionalPosition (DL/UL type A): 0/1/2/3 (2 = pos2, the default).
    pub dl_dmrs_add_pos: u8,
    pub ul_dmrs_add_pos: u8,
    /// CORESET#1: frequency-domain 6-RB groups bitmap (45 bits, MSB first),
    /// duration in symbols, interleaved CCE-REG mapping.
    pub coreset1_freq_bits: u64,
    pub coreset1_duration: u8,
    pub coreset1_interleaved: bool,
    pub nzp_csi_rs: Vec<CsiRsRes>,
    pub zp_csi_rs: Vec<CsiRsRes>,
    /// Periodic CSI report: (periodicity slots, offset, PUCCH resource id).
    pub csi_report: Option<(u16, u16, u8)>,
}

/// Parse a DL-CCCH RRCSetup message (the RRC PDU bytes from the Msg4 MAC SDU).
pub fn parse_rrc_setup(pdu: &[u8]) -> Option<CellGroupParams> {
    let r = &mut Bits::new(pdu);
    // DL-CCCH-Message ::= SEQUENCE { message DL-CCCH-MessageType }
    // DL-CCCH-MessageType ::= CHOICE { c1 CHOICE { rrcReject, rrcSetup, spare2,
    // spare1 }, messageClassExtension }
    if r.bit()? {
        return None; // messageClassExtension
    }
    if r.int(0, 3)? != 1 {
        return None; // not rrcSetup
    }
    // RRCSetup ::= SEQUENCE { rrc-TransactionIdentifier INTEGER(0..3),
    // criticalExtensions CHOICE { rrcSetup RRCSetup-IEs, criticalExtensionsFuture } }
    let _tid = r.int(0, 3)?;
    if r.bit()? {
        return None; // criticalExtensionsFuture
    }
    // RRCSetup-IEs ::= SEQUENCE { radioBearerConfig, masterCellGroup OCTET STRING,
    // [lateNonCriticalExtension], [nonCriticalExtension] }
    let (late, noncrit) = (r.bit()?, r.bit()?);
    parse_radio_bearer_config(r)?;
    // masterCellGroup OCTET STRING (CONTAINING CellGroupConfig): length determinant
    // in octets, then that many octets at the current (unaligned) bit position.
    let len = r.len_det()?;
    let mut mcg = Vec::with_capacity(len);
    for _ in 0..len {
        mcg.push(r.bits(8)? as u8);
    }
    trace!("masterCellGroup: {len} octets");
    let _ = (late, noncrit);
    parse_cell_group_config(&mcg)
}

fn parse_radio_bearer_config(r: &mut Bits) -> Option<()> {
    // RadioBearerConfig ::= SEQUENCE { [srb-ToAddModList], [srb3-ToRelease],
    // [drb-ToAddModList], [drb-ToReleaseList], [securityConfig], ... }
    let ext = r.bit()?;
    let (srb, srb3rel, drb, drbrel, sec) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("radioBearerConfig: srb={srb} srb3rel={srb3rel} drb={drb} drbrel={drbrel} sec={sec}");
    if srb {
        // SRB-ToAddModList ::= SEQUENCE (SIZE (1..2)) OF SRB-ToAddMod
        let n = r.int(1, 2)?;
        for _ in 0..n {
            // SRB-ToAddMod ::= SEQUENCE { srb-Identity INTEGER(1..3),
            // [reestablishPDCP ENUM{true}], [discardOnPDCP ENUM{true}],
            // [pdcp-Config PDCP-Config], ... }
            let e = r.bit()?;
            let (_re, _disc, pdcp) = (r.bit()?, r.bit()?, r.bit()?);
            let id = r.int(1, 3)?;
            trace!("srb-ToAddMod id={id} pdcp={pdcp}");
            if pdcp {
                parse_pdcp_config(r)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if drb || drbrel {
        trace!("drb config in RRCSetup: unsupported");
        return None;
    }
    if sec {
        // SecurityConfig ::= SEQUENCE { [securityAlgorithmConfig], [keyToUse], ... }
        let e = r.bit()?;
        let (alg, key) = (r.bit()?, r.bit()?);
        if alg {
            // SecurityAlgorithmConfig ::= SEQUENCE { cipheringAlgorithm ENUM8+ext,
            // [integrityProtAlgorithm ENUM8+ext], ... }
            let ae = r.bit()?;
            let has_int = r.bit()?;
            r.enu_ext(8)?;
            if has_int {
                r.enu_ext(8)?;
            }
            if ae {
                r.skip_ext_additions()?;
            }
        }
        if key {
            r.enu(2)?; // keyToUse ENUM{master, secondary}
        }
        if e {
            r.skip_ext_additions()?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pdcp_config(r: &mut Bits) -> Option<()> {
    // PDCP-Config ::= SEQUENCE { [drb SEQ{...}], [moreThanOneRLC SEQ{...}],
    // [t-Reordering ENUM], ... }
    let ext = r.bit()?;
    let (drb, more, treo) = (r.bit()?, r.bit()?, r.bit()?);
    if drb || more {
        trace!("pdcp drb/moreThanOneRLC: unsupported");
        return None;
    }
    if treo {
        r.enu(36)?; // T-Reordering: {ms0..ms3000, spare..} = 36 root values
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_cell_group_config(b: &[u8]) -> Option<CellGroupParams> {
    let r = &mut Bits::new(b);
    let mut out = CellGroupParams::default();
    // CellGroupConfig ::= SEQUENCE { cellGroupId (0..3), [rlc-BearerToAddModList],
    // [rlc-BearerToReleaseList], [mac-CellGroupConfig], [physicalCellGroupConfig],
    // [spCellConfig], [sCellToAddModList], [sCellToReleaseList], ... }
    let ext = r.bit()?;
    let mut o = [false; 7];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    let _cgid = r.int(0, 3)?;
    trace!("CellGroupConfig opts: rlcAdd={} rlcRel={} mac={} phy={} spCell={} sAdd={} sRel={}", o[0], o[1], o[2], o[3], o[4], o[5], o[6]);
    if o[0] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            parse_rlc_bearer_config(r)?;
        }
    }
    if o[1] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            r.int(1, 32)?; // LogicalChannelIdentity
        }
    }
    if o[2] {
        parse_mac_cell_group_config(r)?;
    }
    if o[3] {
        parse_physical_cell_group_config(r, &mut out)?;
    }
    if o[4] {
        parse_sp_cell_config(r, &mut out)?;
    }
    if o[5] || o[6] {
        trace!("sCell lists: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(out)
}

fn parse_rlc_bearer_config(r: &mut Bits) -> Option<()> {
    // RLC-BearerConfig ::= SEQUENCE { logicalChannelIdentity (1..32),
    // [servedRadioBearer CHOICE{srb (1..3), drb (1..32)}], [reestablishRLC],
    // [rlc-Config], [mac-LogicalChannelConfig], ... }
    let ext = r.bit()?;
    let (served, reest, rlc, lch) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    let lcid = r.int(1, 32)?;
    trace!("rlc-Bearer lcid={lcid} served={served} rlc={rlc} lch={lch} @{}", r.pos);
    if served {
        if !r.bit()? {
            r.int(1, 3)?; // srb-Identity
        } else {
            r.int(1, 32)?; // drb-Identity
        }
    }
    let _ = reest; // ENUM{true}: presence is the value
    if rlc {
        parse_rlc_config(r)?;
    }
    if lch {
        parse_logical_channel_config(r)?;
        trace!("lch done @{}", r.pos);
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_rlc_config(r: &mut Bits) -> Option<()> {
    // RLC-Config ::= CHOICE { am SEQ{ul-AM-RLC, dl-AM-RLC}, um-Bi-Directional,
    // um-Uni-Directional-UL, um-Uni-Directional-DL, ... }
    if r.bit()? {
        trace!("rlc-Config extension alternative: unsupported");
        return None;
    }
    match r.int(0, 3)? {
        0 => {
            // ul-AM-RLC ::= SEQ { [sn-FieldLength ENUM{size12,size18}],
            // t-PollRetransmit ENUM64, pollPDU ENUM32, pollByte ENUM64,
            // maxRetxThreshold ENUM8 }
            let has_sn = r.bit()?;
            if has_sn {
                r.enu(2)?;
            }
            r.enu(64)?;
            r.enu(32)?;
            r.enu(64)?;
            r.enu(8)?;
            // dl-AM-RLC ::= SEQ { [sn-FieldLength], t-Reassembly ENUM32,
            // t-StatusProhibit ENUM64 }
            let has_sn = r.bit()?;
            if has_sn {
                r.enu(2)?;
            }
            r.enu(32)?;
            r.enu(64)?;
        }
        1 => {
            // um-Bi-Directional: ul-UM-RLC ::= SEQ { [sn-FieldLength ENUM{size6,size12}] },
            // dl-UM-RLC ::= SEQ { [sn-FieldLength], t-Reassembly ENUM32 }
            let has_sn = r.bit()?;
            if has_sn {
                r.enu(2)?;
            }
            let has_sn = r.bit()?;
            if has_sn {
                r.enu(2)?;
            }
            r.enu(32)?;
        }
        _ => {
            trace!("rlc-Config uni-directional: unsupported");
            return None;
        }
    }
    Some(())
}

fn parse_logical_channel_config(r: &mut Bits) -> Option<()> {
    // LogicalChannelConfig ::= SEQUENCE { [ul-SpecificParameters SEQ{...}], ... }
    let ext = r.bit()?;
    let has_ul = r.bit()?;
    if has_ul {
        // ul-SpecificParameters ::= SEQUENCE { priority (1..16),
        // prioritisedBitRate ENUM16, bucketSizeDuration ENUM8,
        // [allowedServingCells], [allowedSCS-List], [maxPUSCH-Duration ENUM8],
        // [configuredGrantType1Allowed ENUM{true}], [logicalChannelGroup (0..7)],
        // [schedulingRequestID (0..7)], logicalChannelSR-Mask BOOLEAN,
        // logicalChannelSR-DelayTimerApplied BOOLEAN, ... }
        let ue = r.bit()?;
        let mut uo = [false; 6];
        for f in uo.iter_mut() {
            *f = r.bit()?;
        }
        r.int(1, 16)?;
        r.enu(16)?;
        r.enu(16)?; // bucketSizeDuration: 9 values + 7 spares = 16 (4 bits!)
        if uo[0] || uo[1] {
            trace!("lch allowedServingCells/SCS: unsupported");
            return None;
        }
        if uo[2] {
            r.enu(8)?;
        }
        // uo[3] configuredGrantType1Allowed: presence is the value
        if uo[4] {
            r.int(0, 7)?;
        }
        if uo[5] {
            r.int(0, 7)?;
        }
        r.bit()?; // logicalChannelSR-Mask
        r.bit()?; // logicalChannelSR-DelayTimerApplied
        if ue {
            r.skip_ext_additions()?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_mac_cell_group_config(r: &mut Bits) -> Option<()> {
    // MAC-CellGroupConfig ::= SEQUENCE { [drx-Config SetupRelease],
    // [schedulingRequestConfig], [bsr-Config], [tag-Config],
    // [phr-Config SetupRelease], skipUplinkTxDynamic BOOLEAN, ... }
    let ext = r.bit()?;
    let (drx, src, bsr, tag, phr) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("mac-CellGroupConfig: drx={drx} src={src} bsr={bsr} tag={tag} phr={phr} @{}", r.pos);
    if drx {
        trace!("drx-Config: unsupported");
        return None;
    }
    if src {
        // SchedulingRequestConfig ::= SEQUENCE { [schedulingRequestToAddModList
        // SEQ(1..8)], [schedulingRequestToReleaseList] }
        let (add, rel) = (r.bit()?, r.bit()?);
        if add {
            let n = r.int(1, 8)?;
            for _ in 0..n {
                // SchedulingRequestToAddMod ::= SEQ { schedulingRequestId (0..7),
                // [sr-ProhibitTimer ENUM8], sr-TransMax ENUM8 }
                let has_pro = r.bit()?;
                r.int(0, 7)?;
                if has_pro {
                    r.enu(8)?;
                }
                r.enu(8)?;
            }
        }
        if rel {
            let n = r.int(1, 8)?;
            for _ in 0..n {
                r.int(0, 7)?;
            }
        }
    }
    if bsr {
        // BSR-Config ::= SEQUENCE { periodicBSR-Timer ENUM16, retxBSR-Timer ENUM16,
        // [logicalChannelSR-DelayTimer ENUM8], ... }
        let e = r.bit()?;
        let has_delay = r.bit()?;
        r.enu(16)?;
        r.enu(16)?;
        if has_delay {
            r.enu(8)?;
        }
        if e {
            r.skip_ext_additions()?;
        }
    }
    if tag {
        // TAG-Config ::= SEQUENCE { [tag-ToReleaseList], [tag-ToAddModList SEQ(1..4)] }
        let (rel, add) = (r.bit()?, r.bit()?);
        if rel {
            let n = r.int(1, 4)?;
            for _ in 0..n {
                r.int(0, 3)?;
            }
        }
        if add {
            let n = r.int(1, 4)?;
            for _ in 0..n {
                // TAG ::= SEQ { tag-Id (0..3), timeAlignmentTimer ENUM8, ... }
                let e = r.bit()?;
                r.int(0, 3)?;
                r.enu(8)?;
                if e {
                    r.skip_ext_additions()?;
                }
            }
        }
    }
    if phr {
        if r.bit()? {
            // PHR-Config ::= SEQ { phr-PeriodicTimer ENUM8, phr-ProhibitTimer ENUM8,
            // phr-Tx-PowerFactorChange ENUM4, multiplePHR BOOL, dummy BOOL,
            // phr-Type2OtherCell BOOL, phr-ModeOtherCG ENUM2, ... }
            let e = r.bit()?;
            r.enu(8)?;
            r.enu(8)?;
            r.enu(4)?;
            r.bit()?;
            r.bit()?;
            r.bit()?;
            r.enu(2)?;
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    r.bit()?; // skipUplinkTxDynamic
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("mac-CellGroupConfig done @{}", r.pos);
    Some(())
}

fn parse_physical_cell_group_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // PhysicalCellGroupConfig ::= SEQUENCE { [harq-ACK-SpatialBundlingPUCCH],
    // [harq-ACK-SpatialBundlingPUSCH], [p-NR-FR1 (-30..33)],
    // pdsch-HARQ-ACK-Codebook ENUM{semiStatic,dynamic}, [tpc-SRS-RNTI],
    // [tpc-PUCCH-RNTI], [tpc-PUSCH-RNTI], [sp-CSI-RNTI], [cs-RNTI SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 8];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    // o[0]/o[1] are ENUM{true}: presence is the value
    if o[2] {
        r.int(-30, 33)?;
    }
    trace!("phy-CellGroupConfig opts {:?} @{}", o, r.pos);
    out.harq_codebook_dynamic = r.enu(2)? == 1;
    trace!("pdsch-HARQ-ACK-Codebook dynamic={}", out.harq_codebook_dynamic);
    for &p in &o[3..7] {
        if p {
            r.int(0, 65535)?;
        }
    }
    if o[7] {
        if r.bit()? {
            r.int(0, 65535)?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_sp_cell_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // SpCellConfig ::= SEQUENCE { [servCellIndex], [reconfigurationWithSync],
    // [rlf-TimersAndConstants SetupRelease], [rlmInSyncOutOfSyncThreshold],
    // [spCellConfigDedicated], ... }
    let ext = r.bit()?;
    let (idx, sync, rlf, rlm, ded) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("spCellConfig: idx={idx} sync={sync} rlf={rlf} rlm={rlm} ded={ded}");
    if idx {
        r.int(0, 31)?;
    }
    if sync {
        trace!("reconfigurationWithSync: unsupported");
        return None;
    }
    if rlf {
        if r.bit()? {
            // RLF-TimersAndConstants ::= SEQ { t310 ENUM8, n310 ENUM8, n311 ENUM8, ... }
            let e = r.bit()?;
            r.enu(8)?;
            r.enu(8)?;
            r.enu(8)?;
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if rlm {
        // ENUM{n1}: presence is the value... it is ENUMERATED {n1} with one value → 0 bits
    }
    if ded {
        parse_serving_cell_config(r, out)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_serving_cell_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // ServingCellConfig ::= SEQUENCE { [tdd-UL-DL-ConfigurationDedicated],
    // [initialDownlinkBWP], [downlinkBWP-ToReleaseList], [downlinkBWP-ToAddModList],
    // [firstActiveDownlinkBWP-Id], [bwp-InactivityTimer], [defaultDownlinkBWP-Id],
    // [uplinkConfig], [supplementaryUplink], [pdcch-ServingCellConfig SetupRelease],
    // [pdsch-ServingCellConfig SetupRelease], [csi-MeasConfig SetupRelease],
    // [sCellDeactivationTimer], [crossCarrierSchedulingConfig], tag-Id (0..3),
    // [dummy], [pathlossReferenceLinking], [servingCellMO], ... }
    let ext = r.bit()?;
    let mut o = [false; 17];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("servingCellConfig opts: tddDed={} initDL={} dlRel={} dlAdd={} firstAct={} inact={} defBwp={} ul={} sul={} pdcchSrv={} pdschSrv={} csi={} deact={} ccs={} dummy={} plrl={} mo={}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15], o[16]);
    if o[0] {
        trace!("tdd-UL-DL-ConfigurationDedicated: unsupported");
        return None;
    }
    if o[1] {
        parse_bwp_downlink_dedicated(r, out)?;
    }
    if o[2] || o[3] {
        trace!("downlink BWP lists: unsupported");
        return None;
    }
    if o[4] {
        r.int(0, 4)?; // firstActiveDownlinkBWP-Id
    }
    if o[5] {
        r.enu(32)?; // bwp-InactivityTimer (31 root values + spare → 32)
    }
    if o[6] {
        r.int(0, 4)?;
    }
    if o[7] {
        parse_uplink_config(r, out)?;
    }
    if o[8] {
        trace!("supplementaryUplink: unsupported");
        return None;
    }
    if o[9] {
        if r.bit()? {
            // PDCCH-ServingCellConfig ::= SEQ { [slotFormatIndicator SetupRelease], ... }
            let e = r.bit()?;
            let sfi = r.bit()?;
            if sfi {
                trace!("slotFormatIndicator: unsupported");
                return None;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[10] {
        if r.bit()? {
            // PDSCH-ServingCellConfig ::= SEQ { [codeBlockGroupTransmission SetupRelease],
            // [xOverhead ENUM3], [nrofHARQ-ProcessesForPDSCH ENUM6], [pucch-Cell], ... }
            let e = r.bit()?;
            let (cbg, xoh, nharq, pcell) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
            if cbg {
                trace!("codeBlockGroupTransmission: unsupported");
                return None;
            }
            if xoh {
                r.enu(3)?;
            }
            if nharq {
                r.enu(6)?;
            }
            if pcell {
                r.int(0, 31)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[11] {
        if r.bit()? {
            parse_csi_meas_config(r, out)?;
        }
    }
    if o[12] {
        r.enu(16)?;
    }
    if o[13] {
        trace!("crossCarrierSchedulingConfig: unsupported");
        return None;
    }
    r.int(0, 3)?; // tag-Id
    // o[14] dummy ENUM{enabled}: presence is the value
    if o[15] {
        r.enu(2)?; // pathlossReferenceLinking
    }
    if o[16] {
        r.int(1, 64)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_bwp_downlink_dedicated(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // BWP-DownlinkDedicated ::= SEQUENCE { [pdcch-Config SetupRelease],
    // [pdsch-Config SetupRelease], [sps-Config SetupRelease],
    // [radioLinkMonitoringConfig SetupRelease], ... }
    let ext = r.bit()?;
    let (pdcch, pdsch, sps, rlm) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("BWP-DownlinkDedicated: pdcch={pdcch} pdsch={pdsch} sps={sps} rlm={rlm}");
    if pdcch {
        if r.bit()? {
            parse_pdcch_config_dedicated(r, out)?;
        }
    }
    if pdsch {
        if r.bit()? {
            parse_pdsch_config_dedicated(r, out)?;
        }
    }
    if sps {
        trace!("sps-Config: unsupported");
        return None;
    }
    if rlm {
        if r.bit()? {
            parse_radio_link_monitoring(r)?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_radio_link_monitoring(r: &mut Bits) -> Option<()> {
    // RadioLinkMonitoringConfig ::= SEQUENCE { [failureDetectionResourcesToAddModList
    // SEQ(1..10)], [failureDetectionResourcesToReleaseList], [beamFailureInstanceMaxCount
    // ENUM8], [beamFailureDetectionTimer ENUM8], ... }
    let ext = r.bit()?;
    let (add, rel, cnt, timer) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    if add {
        let n = r.int(1, 10)?;
        for _ in 0..n {
            // RadioLinkMonitoringRS ::= SEQ { radioLinkMonitoringRS-Id (0..9),
            // purpose ENUM{beamFailure,rlf,both}, detectionResource CHOICE{ssb (0..63),
            // csi-RS (0..191)}, ... }
            let e = r.bit()?;
            r.int(0, 9)?;
            r.enu(3)?;
            if !r.bit()? {
                r.int(0, 63)?;
            } else {
                r.int(0, 191)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if rel {
        let n = r.int(1, 10)?;
        for _ in 0..n {
            r.int(0, 9)?;
        }
    }
    if cnt {
        r.enu(8)?;
    }
    if timer {
        r.enu(8)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pdcch_config_dedicated(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // PDCCH-Config ::= SEQUENCE { [controlResourceSetToAddModList SEQ(1..3)],
    // [controlResourceSetToReleaseList], [searchSpacesToAddModList SEQ(1..10)],
    // [searchSpacesToReleaseList], [downlinkPreemption SetupRelease],
    // [tpc-PUSCH SetupRelease], [tpc-PUCCH SetupRelease], [tpc-SRS SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 8];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("PDCCH-Config: crsAdd={} crsRel={} ssAdd={} ssRel={}", o[0], o[1], o[2], o[3]);
    if o[0] {
        let n = r.int(1, 3)?;
        for _ in 0..n {
            parse_control_resource_set(r, out)?;
        }
    }
    if o[1] {
        let n = r.int(1, 3)?;
        for _ in 0..n {
            r.int(0, 11)?;
        }
    }
    if o[2] {
        let n = r.int(1, 10)?;
        for _ in 0..n {
            crate::sib1::parse_search_space_pub(r)?;
        }
    }
    if o[3] {
        let n = r.int(1, 10)?;
        for _ in 0..n {
            r.int(0, 39)?;
        }
    }
    for &p in &o[4..8] {
        if p {
            trace!("pdcch tpc/preemption: unsupported");
            return None;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_control_resource_set(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // ControlResourceSet ::= SEQUENCE { controlResourceSetId (0..11),
    // frequencyDomainResources BIT STRING(45), duration (1..3),
    // cce-REG-MappingType CHOICE{interleaved SEQ{reg-BundleSize ENUM3,
    // interleaverSize ENUM3, [shiftIndex (0..274)]}, nonInterleaved NULL},
    // precoderGranularity ENUM2, [tci-StatesPDCCH-ToAddList SEQ(1..64)],
    // [tci-StatesPDCCH-ToReleaseList], [tci-PresentInDCI],
    // [pdcch-DMRS-ScramblingID (0..65535)], ... }
    let ext = r.bit()?;
    let (tci_add, tci_rel, _tci_dci, scrambling) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    let id = r.int(0, 11)?;
    let freq = r.bits(45)?;
    let duration = r.int(1, 3)? as u8;
    let interleaved = !r.bit()?; // CHOICE: interleaved=0, nonInterleaved=1
    if interleaved {
        r.enu(3)?;
        r.enu(3)?;
        if r.bit()? {
            r.int(0, 274)?;
        }
    }
    r.enu(2)?; // precoderGranularity
    if tci_add || tci_rel {
        trace!("coreset tci states: unsupported");
        return None;
    }
    if scrambling {
        r.int(0, 65535)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    if id != 0 {
        out.coreset1_freq_bits = freq;
        out.coreset1_duration = duration;
        out.coreset1_interleaved = interleaved;
    }
    trace!("coreset id={id} freq={freq:#013x} dur={duration} interleaved={interleaved}");
    Some(())
}

fn parse_pdsch_config_dedicated(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // PDSCH-Config ::= SEQUENCE { [dataScramblingIdentityPDSCH (0..1023)],
    // [dmrs-DownlinkForPDSCH-MappingTypeA SetupRelease], [dmrs-...TypeB],
    // [tci-StatesToAddModList SEQ(1..128)], [tci-StatesToReleaseList],
    // [vrb-ToPRB-Interleaver ENUM2], resourceAllocation ENUM3,
    // [pdsch-TimeDomainAllocationList SetupRelease], [pdsch-AggregationFactor ENUM3],
    // [rateMatchPatternToAddModList SEQ(1..4)], [rateMatchPatternToReleaseList],
    // [rateMatchPatternGroup1], [rateMatchPatternGroup2], rbg-Size ENUM2,
    // [mcs-Table ENUM2], [maxNrofCodeWordsScheduledByDCI ENUM2],
    // prb-BundlingType CHOICE2, [zp-CSI-RS-ResourceToAddModList SEQ(1..32)],
    // [zp-...ReleaseList], [aperiodic-ZP-...ToAddModList], [Release],
    // [sp-ZP-...ToAddModList], [Release], [p-ZP-CSI-RS-ResourceSet SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 21];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("PDSCH-Config opts: scr={} dmrsA={} dmrsB={} tciAdd={} tciRel={} vrb={} tdra={} agg={} rmAdd={} rmRel={} rmG1={} rmG2={} mcsTab={} maxCW={} zpAdd={} zpRel={} apZpA={} apZpR={} spZpA={} spZpR={} pZp={}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15], o[16], o[17], o[18], o[19], o[20]);
    if o[0] {
        r.int(0, 1023)?;
    }
    if o[1] {
        if r.bit()? {
            out.dl_dmrs_add_pos = parse_dmrs_downlink_config(r)?;
        }
    }
    if o[2] {
        if r.bit()? {
            parse_dmrs_downlink_config(r)?;
        }
    }
    if o[3] {
        let n = r.int(1, 128)?;
        for _ in 0..n {
            parse_tci_state(r)?;
        }
    }
    if o[4] {
        let n = r.int(1, 128)?;
        for _ in 0..n {
            r.int(0, 127)?;
        }
    }
    if o[5] {
        r.enu(2)?;
    }
    r.enu(3)?; // resourceAllocation
    if o[6] {
        if r.bit()? {
            let n = r.int(1, 16)?;
            for _ in 0..n {
                // PDSCH-TimeDomainResourceAllocation ::= SEQ { [k0 (0..32)],
                // mappingType ENUM2, startSymbolAndLength (0..127) }
                let has_k0 = r.bit()?;
                let k0 = if has_k0 { r.int(0, 32)? as u8 } else { 0 };
                let type_a = r.enu(2)? == 0;
                let sliv = r.int(0, 127)? as u8;
                out.pdsch_tdra.push(TdraRow { k: k0, type_a, sliv });
            }
            trace!("dedicated pdsch-TDRA: {:?}", out.pdsch_tdra);
        }
    }
    if o[7] {
        r.enu(3)?;
    }
    if o[8] {
        trace!("rateMatchPatternToAddModList: unsupported");
        return None;
    }
    if o[9] || o[10] || o[11] {
        trace!("rateMatchPattern lists/groups: unsupported");
        return None;
    }
    r.enu(2)?; // rbg-Size
    if o[12] {
        r.enu(2)?;
    }
    if o[13] {
        r.enu(2)?;
    }
    // prb-BundlingType CHOICE { staticBundling SEQ{[bundleSize ENUM2]},
    // dynamicBundling SEQ{...} }
    if !r.bit()? {
        if r.bit()? {
            r.enu(2)?;
        }
    } else {
        trace!("dynamic PRB bundling: unsupported");
        return None;
    }
    if o[14] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            // ZP-CSI-RS-Resource ::= SEQ { zp-CSI-RS-ResourceId (0..31),
            // resourceMapping, [periodicityAndOffset], ... }
            let e = r.bit()?;
            let has_po = r.bit()?;
            r.int(0, 31)?;
            let mut res = parse_csi_rs_resource_mapping(r)?;
            if has_po {
                let (p, off) = parse_csi_periodicity_offset(r)?;
                res.period_slots = p;
                res.offset_slots = off;
            }
            if e {
                r.skip_ext_additions()?;
            }
            out.zp_csi_rs.push(res);
        }
        trace!("zp-CSI-RS @{}: {:?}", r.pos, out.zp_csi_rs);
    }
    if o[15] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            r.int(0, 31)?;
        }
    }
    if o[16] || o[17] || o[18] || o[19] {
        trace!("aperiodic/sp ZP lists: unsupported");
        return None;
    }
    if o[20] {
        if r.bit()? {
            // ZP-CSI-RS-ResourceSet ::= SEQ { zp-CSI-RS-ResourceSetId (0..15),
            // zp-CSI-RS-ResourceIdList SEQ(1..16) OF (0..31), ... }
            let e = r.bit()?;
            r.int(0, 15)?;
            let n = r.int(1, 16)?;
            for _ in 0..n {
                r.int(0, 31)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("PDSCH-Config done @{}", r.pos);
    Some(())
}

/// Returns dmrs-AdditionalPosition (0/1/3; 2 = the spec default when absent).
fn parse_dmrs_downlink_config(r: &mut Bits) -> Option<u8> {
    // DMRS-DownlinkConfig ::= SEQUENCE { [dmrs-Type ENUM{type2}],
    // [dmrs-AdditionalPosition ENUM{pos0,pos1,pos3}], [maxLength ENUM{len2}],
    // [scramblingID0 (0..65535)], [scramblingID1], [phaseTrackingRS SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 6];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    // o[0] dmrs-Type ENUM{type2}: presence is the value
    let mut add_pos = 2u8;
    if o[1] {
        add_pos = match r.enu(3)? {
            0 => 0,
            1 => 1,
            _ => 3,
        };
    }
    // o[2] maxLength ENUM{len2}: presence is the value
    if o[3] {
        r.int(0, 65535)?;
    }
    if o[4] {
        r.int(0, 65535)?;
    }
    if o[5] {
        trace!("phaseTrackingRS: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(add_pos)
}

fn parse_tci_state(r: &mut Bits) -> Option<()> {
    // TCI-State ::= SEQUENCE { tci-StateId (0..127), qcl-Type1 QCL-Info,
    // [qcl-Type2 QCL-Info], ... }
    let ext = r.bit()?;
    let has_q2 = r.bit()?;
    r.int(0, 127)?;
    parse_qcl_info(r)?;
    if has_q2 {
        parse_qcl_info(r)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_qcl_info(r: &mut Bits) -> Option<()> {
    // QCL-Info ::= SEQUENCE { [cell (0..31)], [bwp-Id (0..4)],
    // referenceSignal CHOICE{csi-rs (0..191), ssb (0..63)}, qcl-Type ENUM4, ... }
    let ext = r.bit()?;
    let (cell, bwp) = (r.bit()?, r.bit()?);
    if cell {
        r.int(0, 31)?;
    }
    if bwp {
        r.int(0, 4)?;
    }
    if !r.bit()? {
        r.int(0, 191)?;
    } else {
        r.int(0, 63)?;
    }
    r.enu(4)?;
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_uplink_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // UplinkConfig ::= SEQUENCE { [initialUplinkBWP BWP-UplinkDedicated],
    // [uplinkBWP-ToReleaseList], [uplinkBWP-ToAddModList], [firstActiveUplinkBWP-Id],
    // [pusch-ServingCellConfig SetupRelease], [carrierSwitching SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 6];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("uplinkConfig @{}: initUL={} rel={} add={} firstAct={} puschSrv={} carSw={}", r.pos, o[0], o[1], o[2], o[3], o[4], o[5]);
    if o[0] {
        parse_bwp_uplink_dedicated(r, out)?;
    }
    if o[1] || o[2] {
        trace!("uplink BWP lists: unsupported");
        return None;
    }
    if o[3] {
        r.int(0, 4)?;
    }
    if o[4] {
        if r.bit()? {
            // PUSCH-ServingCellConfig ::= SEQ { [codeBlockGroupTransmission SetupRelease],
            // [rateMatching ENUM{limitedBufferRM}], [xOverhead ENUM3], ... }
            let e = r.bit()?;
            let (cbg, rm, xoh) = (r.bit()?, r.bit()?, r.bit()?);
            if cbg {
                trace!("pusch cbg: unsupported");
                return None;
            }
            let _ = rm; // ENUM{limitedBufferRM}: presence is the value
            if xoh {
                r.enu(3)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[5] {
        trace!("carrierSwitching: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_bwp_uplink_dedicated(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // BWP-UplinkDedicated ::= SEQUENCE { [pucch-Config SetupRelease],
    // [pusch-Config SetupRelease], [configuredGrantConfig SetupRelease],
    // [srs-Config SetupRelease], [beamFailureRecoveryConfig SetupRelease], ... }
    let ext = r.bit()?;
    let (pucch, pusch, cg, srs, bfr) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("BWP-UplinkDedicated: pucch={pucch} pusch={pusch} cg={cg} srs={srs} bfr={bfr}");
    if pucch {
        if r.bit()? {
            parse_pucch_config(r, out)?;
        }
    }
    if pusch {
        if r.bit()? {
            parse_pusch_config_dedicated(r, out)?;
        }
    }
    if cg {
        trace!("configuredGrantConfig: unsupported");
        return None;
    }
    if srs {
        if r.bit()? {
            parse_srs_config(r)?;
        }
    }
    if bfr {
        trace!("beamFailureRecoveryConfig: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pucch_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // PUCCH-Config ::= SEQUENCE { [resourceSetToAddModList SEQ(1..4)],
    // [resourceSetToReleaseList], [resourceToAddModList SEQ(1..128)],
    // [resourceToReleaseList], [format1 SetupRelease], [format2], [format3],
    // [format4], [schedulingRequestResourceToAddModList SEQ(1..8)],
    // [schedulingRequestResourceToReleaseList], [multi-CSI-PUCCH-ResourceList],
    // [dl-DataToUL-ACK SEQ(1..8) OF INTEGER(0..15)],
    // [spatialRelationInfoToAddModList], [spatialRelationInfoToReleaseList],
    // [pucch-PowerControl], ... }
    let ext = r.bit()?;
    let mut o = [false; 15];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("PUCCH-Config opts: rsAdd={} rsRel={} resAdd={} resRel={} f1={} f2={} f3={} f4={} srAdd={} srRel={} multiCsi={} k1={} spAdd={} spRel={} pc={}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14]);
    if o[0] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            // PUCCH-ResourceSet ::= SEQ { pucch-ResourceSetId (0..3),
            // resourceList SEQ(1..32) OF (0..127), [maxPayloadMinus1 (4..256)] }
            let has_max = r.bit()?;
            r.int(0, 3)?;
            let m = r.int(1, 32)?;
            for _ in 0..m {
                r.int(0, 127)?;
            }
            if has_max {
                r.int(4, 256)?;
            }
        }
    }
    if o[1] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            r.int(0, 3)?;
        }
    }
    if o[2] {
        let n = r.int(1, 128)?;
        for _ in 0..n {
            out.pucch_resources.push(parse_pucch_resource(r)?);
        }
        trace!("pucch resources: {} parsed @{} {:?}", out.pucch_resources.len(), r.pos, out.pucch_resources);
    }
    if o[3] {
        let n = r.int(1, 128)?;
        for _ in 0..n {
            r.int(0, 127)?;
        }
    }
    for &p in &o[4..8] {
        if p {
            if r.bit()? {
                parse_pucch_format_config(r)?;
            }
        }
    }
    if o[8] {
        let n = r.int(1, 8)?;
        for _ in 0..n {
            // SchedulingRequestResourceConfig ::= SEQ { schedulingRequestResourceId
            // (1..8), schedulingRequestID (0..7), [periodicityAndOffset CHOICE15],
            // [resource PUCCH-ResourceId] }
            let (has_po, has_res) = (r.bit()?, r.bit()?);
            r.int(1, 8)?;
            r.int(0, 7)?;
            let mut period = 0u16;
            let mut offset = 0u16;
            if has_po {
                // CHOICE { sym2, sym6or7, sl1 (NULL), sl2 (0..1), sl4 (0..3),
                // sl5 (0..4), sl8 (0..7), sl10 (0..9), sl16 (0..15), sl20 (0..19),
                // sl40 (0..39), sl80 (0..79), sl160 (0..159), sl320 (0..319),
                // sl640 (0..639) } — 15 alternatives.
                const P: [u16; 15] = [0, 0, 1, 2, 4, 5, 8, 10, 16, 20, 40, 80, 160, 320, 640];
                let alt = r.int(0, 14)? as usize;
                period = P[alt];
                if period > 1 {
                    offset = r.int(0, period as i64 - 1)? as u16;
                }
            }
            let mut res_id = 0u8;
            if has_res {
                res_id = r.int(0, 127)? as u8;
            }
            out.sr = Some((period, offset, res_id));
            trace!("SR resource: period={period} offset={offset} pucch-res={res_id}");
        }
    }
    if o[9] {
        let n = r.int(1, 8)?;
        for _ in 0..n {
            r.int(1, 8)?;
        }
    }
    if o[10] {
        trace!("multi-CSI-PUCCH-ResourceList: unsupported");
        return None;
    }
    if o[11] {
        let n = r.int(1, 8)?;
        for _ in 0..n {
            out.k1_list.push(r.int(0, 15)? as u8);
        }
        trace!("dl-DataToUL-ACK: {:?}", out.k1_list);
    }
    if o[12] || o[13] {
        trace!("spatialRelationInfo: unsupported");
        return None;
    }
    if o[14] {
        parse_pucch_power_control(r)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pucch_resource(r: &mut Bits) -> Option<PucchResource> {
    // PUCCH-Resource ::= SEQUENCE { pucch-ResourceId (0..127), startingPRB (0..274),
    // [intraSlotFrequencyHopping ENUM{enabled}], [secondHopPRB (0..274)],
    // format CHOICE{format0 SEQ{initialCyclicShift(0..11), nrofSymbols(1..2),
    // startingSymbolIndex(0..13)}, format1 SEQ{initialCyclicShift(0..11),
    // nrofSymbols(4..14), startingSymbolIndex(0..10), timeDomainOCC(0..6)},
    // format2 SEQ{nrofPRBs(1..16), nrofSymbols(1..2), startingSymbolIndex(0..13)},
    // format3 SEQ{nrofPRBs(1..16), nrofSymbols(4..14), startingSymbolIndex(0..10)},
    // format4 SEQ{nrofSymbols(4..14), occ-Length ENUM2, occ-Index ENUM4,
    // startingSymbolIndex(0..10)}} }
    let (_hop, has_hop2) = (r.bit()?, r.bit()?);
    let id = r.int(0, 127)? as u8;
    let prb = r.int(0, 274)? as u16;
    let second_hop_prb = if has_hop2 { Some(r.int(0, 274)? as u16) } else { None };
    let format = r.int(0, 4)? as u8;
    let mut res = PucchResource { id, prb, second_hop_prb, format, ..Default::default() };
    match format {
        0 => {
            res.cs_or_prbs = r.int(0, 11)? as u8;
            res.n_symbols = r.int(1, 2)? as u8;
            res.start_symbol = r.int(0, 13)? as u8;
        }
        1 => {
            res.cs_or_prbs = r.int(0, 11)? as u8;
            res.n_symbols = r.int(4, 14)? as u8;
            res.start_symbol = r.int(0, 10)? as u8;
            res.occ = r.int(0, 6)? as u8;
        }
        2 | 3 => {
            res.cs_or_prbs = r.int(1, 16)? as u8;
            res.n_symbols = if format == 2 { r.int(1, 2)? } else { r.int(4, 14)? } as u8;
            res.start_symbol = r.int(0, if format == 2 { 13 } else { 10 })? as u8;
        }
        _ => {
            res.n_symbols = r.int(4, 14)? as u8;
            r.enu(2)?;
            r.enu(4)?;
            res.start_symbol = r.int(0, 10)? as u8;
        }
    }
    Some(res)
}

fn parse_pucch_format_config(r: &mut Bits) -> Option<()> {
    // PUCCH-FormatConfig ::= SEQUENCE { [interslotFrequencyHopping ENUM{enabled}],
    // [additionalDMRS ENUM{true}], [maxCodeRate ENUM8], [nrofSlots ENUM3],
    // [pi2BPSK ENUM{enabled}], [simultaneousHARQ-ACK-CSI ENUM{true}] }
    let mut o = [false; 6];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    if o[2] {
        r.enu(8)?;
    }
    if o[3] {
        r.enu(3)?;
    }
    Some(())
}

fn parse_pucch_power_control(r: &mut Bits) -> Option<()> {
    // PUCCH-PowerControl ::= SEQUENCE { [deltaF-PUCCH-f0 (-16..15)], [f1], [f2],
    // [f3], [f4], [p0-Set SEQ(1..8)], [pathlossReferenceRSs SEQ(1..4)],
    // [twoPUCCH-PC-AdjustmentStates ENUM{twoStates}], ... }
    let ext = r.bit()?;
    let mut o = [false; 8];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    for &p in &o[0..5] {
        if p {
            r.int(-16, 15)?;
        }
    }
    if o[5] {
        let n = r.int(1, 8)?;
        for _ in 0..n {
            // P0-PUCCH ::= SEQ { p0-PUCCH-Id (1..8), p0-PUCCH-Value (-16..15) }
            r.int(1, 8)?;
            r.int(-16, 15)?;
        }
    }
    if o[6] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            // PUCCH-PathlossReferenceRS ::= SEQ { id (0..3),
            // referenceSignal CHOICE{ssb (0..63), csi-RS (0..191)} }
            r.int(0, 3)?;
            if !r.bit()? {
                r.int(0, 63)?;
            } else {
                r.int(0, 191)?;
            }
        }
    }
    // o[7] ENUM{twoStates}: presence is the value
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pusch_config_dedicated(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // PUSCH-Config ::= SEQUENCE { [dataScramblingIdentityPUSCH (0..1023)],
    // [txConfig ENUM2], [dmrs-UplinkForPUSCH-MappingTypeA SetupRelease],
    // [dmrs-...TypeB], [pusch-PowerControl], [frequencyHopping ENUM2],
    // [frequencyHoppingOffsetLists SEQ(1..4) OF (1..274)], resourceAllocation ENUM3,
    // [pusch-TimeDomainAllocationList SetupRelease], [pusch-AggregationFactor ENUM3],
    // [mcs-Table ENUM2], [mcs-TableTransformPrecoder ENUM2], [transformPrecoder ENUM2],
    // [codebookSubset ENUM3], [maxRank (1..4)], [rbg-Size ENUM{config2}],
    // [uci-OnPUSCH SetupRelease], [tp-pi2BPSK ENUM{enabled}], ... }
    let ext = r.bit()?;
    let mut o = [false; 17];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("PUSCH-Config opts: scr={} tx={} dmrsA={} dmrsB={} pc={} fh={} fhOff={} tdra={} agg={} mcs={} mcsTp={} tp={} cbs={} rank={} rbg={} uci={} pi2={}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15], o[16]);
    if o[0] {
        r.int(0, 1023)?;
    }
    if o[1] {
        r.enu(2)?;
    }
    if o[2] {
        if r.bit()? {
            out.ul_dmrs_add_pos = parse_dmrs_uplink_config(r)?;
        }
        trace!("ul dmrsA done @{}", r.pos);
    }
    if o[3] {
        if r.bit()? {
            parse_dmrs_uplink_config(r)?;
        }
    }
    if o[4] {
        parse_pusch_power_control(r)?;
        trace!("pusch pc done @{}", r.pos);
    }
    if o[5] {
        r.enu(2)?;
    }
    if o[6] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            r.int(1, 274)?;
        }
    }
    r.enu(3)?; // resourceAllocation
    if o[7] {
        if r.bit()? {
            let n = r.int(1, 16)?;
            for _ in 0..n {
                let has_k2 = r.bit()?;
                let k2 = if has_k2 { r.int(0, 32)? as u8 } else { 1 };
                let type_a = r.enu(2)? == 0;
                let sliv = r.int(0, 127)? as u8;
                out.pusch_tdra.push(TdraRow { k: k2, type_a, sliv });
            }
            trace!("dedicated pusch-TDRA: {:?}", out.pusch_tdra);
        }
    }
    if o[8] {
        r.enu(3)?;
    }
    if o[9] {
        r.enu(2)?;
    }
    if o[10] {
        r.enu(2)?;
    }
    if o[11] {
        r.enu(2)?;
    }
    if o[12] {
        r.enu(3)?;
    }
    if o[13] {
        r.int(1, 4)?;
    }
    // o[14] rbg-Size ENUM{config2}: presence is the value
    if o[15] {
        if r.bit()? {
            // UCI-OnPUSCH ::= SEQ { [betaOffsets CHOICE{dynamic SEQ SIZE(4) OF
            // BetaOffsets, semiStatic BetaOffsets}], scaling ENUM4 }
            let has_beta = r.bit()?;
            if has_beta {
                if !r.bit()? {
                    for _ in 0..4 {
                        parse_beta_offsets(r)?;
                    }
                } else {
                    parse_beta_offsets(r)?;
                }
            }
            r.enu(4)?;
        }
    }
    // o[16] tp-pi2BPSK: presence is the value
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_beta_offsets(r: &mut Bits) -> Option<()> {
    // BetaOffsets ::= SEQUENCE { [betaOffsetACK-Index1 (0..31)], [Index2], [Index3],
    // [betaOffsetCSI-Part1-Index1 (0..31)], [Index2], [betaOffsetCSI-Part2-Index1],
    // [Index2] }
    let mut o = [false; 7];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    for &p in &o {
        if p {
            r.int(0, 31)?;
        }
    }
    Some(())
}

/// Returns dmrs-AdditionalPosition (2 = default when absent).
fn parse_dmrs_uplink_config(r: &mut Bits) -> Option<u8> {
    // DMRS-UplinkConfig ::= SEQUENCE { [dmrs-Type ENUM{type2}],
    // [dmrs-AdditionalPosition ENUM{pos0,pos1,pos3}], [phaseTrackingRS SetupRelease],
    // [maxLength ENUM{len2}], [transformPrecodingDisabled SEQ],
    // [transformPrecodingEnabled SEQ], ... }
    let ext = r.bit()?;
    let mut o = [false; 6];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("dmrs-ul opts {:?} @{}", o, r.pos);
    let mut add_pos = 2u8;
    if o[1] {
        add_pos = match r.enu(3)? {
            0 => 0,
            1 => 1,
            _ => 3,
        };
    }
    if o[2] {
        trace!("ul phaseTrackingRS: unsupported");
        return None;
    }
    if o[4] {
        // transformPrecodingDisabled ::= SEQ { [scramblingID0 (0..65535)],
        // [scramblingID1], ... }
        let e = r.bit()?;
        let (s0, s1) = (r.bit()?, r.bit()?);
        if s0 {
            r.int(0, 65535)?;
        }
        if s1 {
            r.int(0, 65535)?;
        }
        if e {
            r.skip_ext_additions()?;
        }
    }
    if o[5] {
        // transformPrecodingEnabled ::= SEQ { [nPUSCH-Identity (0..1007)],
        // [sequenceGroupHopping ENUM{disabled}], [sequenceHopping ENUM{enabled}], ... }
        let e = r.bit()?;
        let (nid, _sgh, _sh) = (r.bit()?, r.bit()?, r.bit()?);
        if nid {
            r.int(0, 1007)?;
        }
        if e {
            r.skip_ext_additions()?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(add_pos)
}

fn parse_pusch_power_control(r: &mut Bits) -> Option<()> {
    // PUSCH-PowerControl ::= SEQUENCE { [tpc-Accumulation ENUM{disabled}],
    // [msg3-Alpha ENUM8], [p0-NominalWithoutGrant (-202..24)],
    // [p0-AlphaSets SEQ(1..30)], [pathlossReferenceRSToAddModList SEQ(1..4)],
    // [pathlossReferenceRSToReleaseList], [twoPUSCH-PC-AdjustmentStates ENUM],
    // [deltaMCS ENUM{enabled}], [sri-PUSCH-MappingToAddModList SEQ(1..16)],
    // [sri-PUSCH-MappingToReleaseList] }
    let mut o = [false; 10];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("pusch-pc opts {:?} @{}", o, r.pos);
    if o[1] {
        r.enu(8)?;
    }
    if o[2] {
        r.int(-202, 24)?;
    }
    if o[3] {
        let n = r.int(1, 30)?;
        for _ in 0..n {
            // P0-PUSCH-AlphaSet ::= SEQ { p0-PUSCH-AlphaSetId (0..29), [p0 (-16..15)],
            // [alpha ENUM8] }
            let (has_p0, has_a) = (r.bit()?, r.bit()?);
            r.int(0, 29)?;
            if has_p0 {
                r.int(-16, 15)?;
            }
            if has_a {
                r.enu(8)?;
            }
        }
    }
    if o[4] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            // PUSCH-PathlossReferenceRS ::= SEQ { id (0..3),
            // referenceSignal CHOICE{ssb, csi-RS} }
            r.int(0, 3)?;
            if !r.bit()? {
                r.int(0, 63)?;
            } else {
                r.int(0, 191)?;
            }
        }
    }
    if o[5] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            r.int(0, 3)?;
        }
    }
    if o[8] {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            // SRI-PUSCH-PowerControl ::= SEQ { sri-PUSCH-PowerControlId (0..15),
            // sri-PUSCH-PathlossReferenceRS-Id (0..3), sri-P0-PUSCH-AlphaSetId (0..29),
            // sri-PUSCH-ClosedLoopIndex ENUM{i0,i1} }
            r.int(0, 15)?;
            r.int(0, 3)?;
            r.int(0, 29)?;
            r.enu(2)?;
        }
    }
    if o[9] {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            r.int(0, 15)?;
        }
    }
    Some(())
}

fn parse_srs_config(r: &mut Bits) -> Option<()> {
    // SRS-Config ::= SEQUENCE { [srs-ResourceSetToReleaseList SEQ(1..16)],
    // [srs-ResourceSetToAddModList SEQ(1..16)], [srs-ResourceToReleaseList],
    // [srs-ResourceToAddModList SEQ(1..64)], [tpc-Accumulation ENUM{disabled}], ... }
    let ext = r.bit()?;
    let (set_rel, set_add, res_rel, res_add, _tpc) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    if set_rel {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            r.int(0, 15)?;
        }
    }
    if set_add {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            parse_srs_resource_set(r)?;
        }
    }
    if res_rel {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            r.int(0, 63)?;
        }
    }
    if res_add {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            parse_srs_resource(r)?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("srs-Config parsed @{}", r.pos);
    Some(())
}

fn parse_srs_resource_set(r: &mut Bits) -> Option<()> {
    // SRS-ResourceSet ::= SEQUENCE { srs-ResourceSetId (0..15),
    // [srs-ResourceIdList SEQ(1..16) OF (0..63)], resourceType CHOICE{aperiodic
    // SEQ{aperiodicSRS-ResourceTrigger (1..3), [csi-RS], [slotOffset (1..32)], ...},
    // semi-persistent SEQ{[associatedCSI-RS], ...}, periodic SEQ{[associatedCSI-RS],
    // ...}}, usage ENUM4, [alpha ENUM8], [p0 (-202..24)], [pathlossReferenceRS
    // CHOICE{ssb, csi-RS}], [srs-PowerControlAdjustmentStates ENUM2], ... }
    let ext = r.bit()?;
    let (has_ids, has_alpha, has_p0, has_plrs, has_pcadj) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    r.int(0, 15)?;
    if has_ids {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            r.int(0, 63)?;
        }
    }
    match r.int(0, 2)? {
        0 => {
            // aperiodic
            let e = r.bit()?;
            let (has_csi, has_off) = (r.bit()?, r.bit()?);
            r.int(1, 3)?;
            if has_csi {
                r.int(0, 191)?;
            }
            if has_off {
                r.int(1, 32)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
        _ => {
            // semi-persistent / periodic: [associatedCSI-RS], ...
            let e = r.bit()?;
            let has_csi = r.bit()?;
            if has_csi {
                r.int(0, 191)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    r.enu(4)?; // usage
    if has_alpha {
        r.enu(8)?;
    }
    if has_p0 {
        r.int(-202, 24)?;
    }
    if has_plrs {
        if !r.bit()? {
            r.int(0, 63)?;
        } else {
            r.int(0, 191)?;
        }
    }
    if has_pcadj {
        r.enu(2)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_srs_resource(r: &mut Bits) -> Option<()> {
    // SRS-Resource ::= SEQUENCE { srs-ResourceId (0..63), nrofSRS-Ports ENUM3,
    // [ptrs-PortIndex ENUM2], transmissionComb CHOICE{n2 SEQ{(0..1),(0..7)},
    // n4 SEQ{(0..3),(0..11)}}, resourceMapping SEQ{startPosition (0..5),
    // nrofSymbols ENUM3, repetitionFactor ENUM3}, freqDomainPosition (0..67),
    // freqDomainShift (0..268), freqHopping SEQ{c-SRS (0..63), b-SRS (0..3),
    // b-hop (0..3)}, groupOrSequenceHopping ENUM3, resourceType CHOICE{aperiodic,
    // semi-persistent SEQ{periodicityAndOffset-sp, ...}, periodic
    // SEQ{periodicityAndOffset-p, ...}}, sequenceId (0..1023),
    // [spatialRelationInfo], ... }
    let ext = r.bit()?;
    let (has_ptrs, has_spatial) = (r.bit()?, r.bit()?);
    r.int(0, 63)?;
    r.enu(3)?; // nrofSRS-Ports
    if has_ptrs {
        r.enu(2)?;
    }
    if !r.bit()? {
        r.int(0, 1)?;
        r.int(0, 7)?;
    } else {
        r.int(0, 3)?;
        r.int(0, 11)?;
    }
    r.int(0, 5)?;
    r.enu(3)?;
    r.enu(3)?;
    r.int(0, 67)?;
    r.int(0, 268)?;
    r.int(0, 63)?;
    r.int(0, 3)?;
    r.int(0, 3)?;
    r.enu(3)?; // groupOrSequenceHopping
    match r.int(0, 2)? {
        0 => {
            // aperiodic
            if r.bit()? {
                r.skip_ext_additions()?;
            }
        }
        _ => {
            // semi-persistent / periodic: SRS-PeriodicityAndOffset CHOICE17
            let e = r.bit()?;
            const P: [u32; 17] = [1, 2, 4, 5, 8, 10, 16, 20, 32, 40, 64, 80, 160, 320, 640, 1280, 2560];
            let alt = r.int(0, 16)? as usize;
            if P[alt] > 1 {
                r.int(0, P[alt] as i64 - 1)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    r.int(0, 1023)?;
    if has_spatial {
        // SRS-SpatialRelationInfo ::= SEQ { [servingCellId (0..31)], referenceSignal
        // CHOICE{ssb-Index (0..63), csi-RS-Index (0..191), srs SEQ{resourceId (0..63),
        // uplinkBWP (0..4)}} }
        let has_cell = r.bit()?;
        if has_cell {
            r.int(0, 31)?;
        }
        match r.int(0, 2)? {
            0 => {
                r.int(0, 63)?;
            }
            1 => {
                r.int(0, 191)?;
            }
            _ => {
                r.int(0, 63)?;
                r.int(0, 4)?;
            }
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_csi_meas_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // CSI-MeasConfig ::= SEQUENCE { [nzp-CSI-RS-ResourceToAddModList SEQ(1..192)],
    // [ToReleaseList], [nzp-CSI-RS-ResourceSetToAddModList SEQ(1..64)], [Release],
    // [csi-IM-ResourceToAddModList SEQ(1..32)], [Release],
    // [csi-IM-ResourceSetToAddModList SEQ(1..64)], [Release],
    // [csi-SSB-ResourceSetToAddModList SEQ(1..64)], [Release],
    // [csi-ResourceConfigToAddModList SEQ(1..112)], [Release],
    // [csi-ReportConfigToAddModList SEQ(1..48)], [Release],
    // [reportTriggerSize (0..6)], [aperiodicTriggerStateList SetupRelease],
    // [semiPersistentOnPUSCH-TriggerStateList SetupRelease], ... }
    let ext = r.bit()?;
    let mut o = [false; 17];
    for f in o.iter_mut() {
        *f = r.bit()?;
    }
    trace!("CSI-MeasConfig opts: nzpAdd={} nzpRel={} nzpSetAdd={} nzpSetRel={} imAdd={} imRel={} imSetAdd={} imSetRel={} ssbSetAdd={} ssbSetRel={} resCfgAdd={} resCfgRel={} repAdd={} repRel={} trig={} aper={} semiP={}",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15], o[16]);
    if o[0] {
        let n = r.int(1, 192)?;
        for _ in 0..n {
            // NZP-CSI-RS-Resource ::= SEQ { nzp-CSI-RS-ResourceId (0..191),
            // resourceMapping, powerControlOffset (-8..15), [powerControlOffsetSS
            // ENUM4], scramblingID (0..1023), [periodicityAndOffset],
            // [qcl-InfoPeriodicCSI-RS TCI-StateId], ... }
            let e = r.bit()?;
            let (has_ss, has_po, has_qcl) = (r.bit()?, r.bit()?, r.bit()?);
            r.int(0, 191)?;
            let mut res = parse_csi_rs_resource_mapping(r)?;
            r.int(-8, 15)?;
            if has_ss {
                r.enu(4)?;
            }
            r.int(0, 1023)?;
            if has_po {
                let (p, off) = parse_csi_periodicity_offset(r)?;
                res.period_slots = p;
                res.offset_slots = off;
            }
            if has_qcl {
                r.int(0, 127)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
            out.nzp_csi_rs.push(res);
        }
        trace!("nzp-CSI-RS: {} resources @{} {:?}", out.nzp_csi_rs.len(), r.pos, out.nzp_csi_rs);
    }
    if o[1] {
        let n = r.int(1, 192)?;
        for _ in 0..n {
            r.int(0, 191)?;
        }
    }
    if o[2] {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            // NZP-CSI-RS-ResourceSet ::= SEQ { nzp-CSI-ResourceSetId (0..63),
            // nzp-CSI-RS-Resources SEQ(1..64) OF (0..191), [repetition ENUM2],
            // [aperiodicTriggeringOffset (0..6)], [trs-Info ENUM{true}], ... }
            let e = r.bit()?;
            let (rep, aper, _trs) = (r.bit()?, r.bit()?, r.bit()?);
            r.int(0, 63)?;
            let m = r.int(1, 64)?;
            for _ in 0..m {
                r.int(0, 191)?;
            }
            if rep {
                r.enu(2)?;
            }
            if aper {
                r.int(0, 6)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[3] {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            r.int(0, 63)?;
        }
    }
    if o[4] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            // CSI-IM-Resource ::= SEQ { csi-IM-ResourceId (0..31),
            // [csi-IM-ResourceElementPattern CHOICE{pattern0 SEQ{subcarrierLocation
            // ENUM6, symbolLocation (0..12)}, pattern1 SEQ{subcarrierLocation ENUM3,
            // symbolLocation (0..13)}}], [freqBand CSI-FrequencyOccupation],
            // [periodicityAndOffset], ... }
            let e = r.bit()?;
            let (has_pat, has_fb, has_po) = (r.bit()?, r.bit()?, r.bit()?);
            r.int(0, 31)?;
            if has_pat {
                if !r.bit()? {
                    r.enu(6)?;
                    r.int(0, 12)?;
                } else {
                    r.enu(3)?;
                    r.int(0, 13)?;
                }
            }
            if has_fb {
                parse_csi_frequency_occupation(r)?;
            }
            if has_po {
                parse_csi_periodicity_offset(r)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[5] {
        let n = r.int(1, 32)?;
        for _ in 0..n {
            r.int(0, 31)?;
        }
    }
    if o[6] {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            // CSI-IM-ResourceSet ::= SEQ { csi-IM-ResourceSetId (0..63),
            // csi-IM-Resources SEQ(1..8) OF (0..31), ... }
            let e = r.bit()?;
            r.int(0, 63)?;
            let m = r.int(1, 8)?;
            for _ in 0..m {
                r.int(0, 31)?;
            }
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[7] {
        let n = r.int(1, 64)?;
        for _ in 0..n {
            r.int(0, 63)?;
        }
    }
    if o[8] || o[9] {
        trace!("csi-SSB sets: unsupported");
        return None;
    }
    if o[10] {
        let n = r.int(1, 112)?;
        for _ in 0..n {
            // CSI-ResourceConfig ::= SEQ { csi-ResourceConfigId (0..111),
            // csi-RS-ResourceSetList CHOICE{nzp-CSI-RS-SSB SEQ{[nzp-CSI-RS-
            // ResourceSetList SEQ(1..16) OF (0..63)], [csi-SSB-ResourceSetList
            // SEQ(1..1) OF (0..63)]}, csi-IM-ResourceSetList SEQ(1..16) OF (0..63)},
            // bwp-Id (0..4), resourceType ENUM{aperiodic,semiPersistent,periodic}, ... }
            let e = r.bit()?;
            r.int(0, 111)?;
            if !r.bit()? {
                let (has_nzp, has_ssb) = (r.bit()?, r.bit()?);
                if has_nzp {
                    let m = r.int(1, 16)?;
                    for _ in 0..m {
                        r.int(0, 63)?;
                    }
                }
                if has_ssb {
                    let m = r.int(1, 1)?;
                    for _ in 0..m {
                        r.int(0, 63)?;
                    }
                }
            } else {
                let m = r.int(1, 16)?;
                for _ in 0..m {
                    r.int(0, 63)?;
                }
            }
            r.int(0, 4)?;
            r.enu(3)?;
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    if o[11] {
        let n = r.int(1, 112)?;
        for _ in 0..n {
            r.int(0, 111)?;
        }
    }
    if o[12] {
        trace!("csi sections pre-report @{}", r.pos);
        let n = r.int(1, 48)?;
        for _ in 0..n {
            parse_csi_report_config(r, out)?;
        }
    }
    if o[13] {
        let n = r.int(1, 48)?;
        for _ in 0..n {
            r.int(0, 47)?;
        }
    }
    if o[14] {
        r.int(0, 6)?;
    }
    if o[15] || o[16] {
        trace!("aperiodic/semiPersistent trigger lists: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_csi_rs_resource_mapping(r: &mut Bits) -> Option<CsiRsRes> {
    // CSI-RS-ResourceMapping ::= SEQUENCE { frequencyDomainAllocation CHOICE{
    // row1 BIT(4), row2 BIT(12), row4 BIT(3), other BIT(6)}, nrofPorts ENUM8,
    // firstOFDMSymbolInTimeDomain (0..13), [firstOFDMSymbolInTimeDomain2 (2..12)],
    // cdm-Type ENUM4, density CHOICE{dot5 ENUM{evenPRBs,oddPRBs}, one NULL,
    // three NULL, spare NULL}, freqBand CSI-FrequencyOccupation, ... }
    let ext = r.bit()?;
    let has_sym2 = r.bit()?;
    let mut res = CsiRsRes::default();
    match r.int(0, 3)? {
        0 => {
            res.row = 1;
            res.freq_bits = r.bits(4)? as u16;
        }
        1 => {
            res.row = 2;
            res.freq_bits = r.bits(12)? as u16;
        }
        2 => {
            res.row = 4;
            res.freq_bits = r.bits(3)? as u16;
        }
        _ => {
            res.row = 0; // "other"
            res.freq_bits = r.bits(6)? as u16;
        }
    }
    r.enu(8)?; // nrofPorts
    res.symbol = r.int(0, 13)? as u8;
    if has_sym2 {
        res.symbol2 = Some(r.int(2, 12)? as u8);
    }
    r.enu(4)?; // cdm-Type
    // density CHOICE (4 alternatives): dot5 carries an ENUM2 payload.
    match r.int(0, 3)? {
        0 => {
            r.enu(2)?;
            res.density = 0;
        }
        1 => res.density = 1,
        2 => res.density = 3,
        _ => res.density = 1,
    }
    let (start_rb, n_rb) = parse_csi_frequency_occupation(r)?;
    res.start_rb = start_rb;
    res.n_rb = n_rb;
    if ext {
        r.skip_ext_additions()?;
    }
    Some(res)
}

fn parse_csi_frequency_occupation(r: &mut Bits) -> Option<(u16, u16)> {
    // CSI-FrequencyOccupation ::= SEQUENCE { startingRB (0..274), nrofRBs (24..276), ... }
    // (startingRB spans maxNrofPhysicalResourceBlocks = 275 values → 9 bits; NOT the
    // 0..2169 offsetToPointA range — that off-by-3 corrupted everything downstream.)
    let ext = r.bit()?;
    let start = r.int(0, 274)? as u16;
    let n = r.int(24, 276)? as u16;
    if ext {
        r.skip_ext_additions()?;
    }
    Some((start, n))
}

fn parse_csi_periodicity_offset(r: &mut Bits) -> Option<(u16, u16)> {
    // CSI-ResourcePeriodicityAndOffset ::= CHOICE { slots4 (0..3), slots5, slots8,
    // slots10, slots16, slots20, slots32, slots40, slots64, slots80, slots160,
    // slots320, slots640 } — 13 alternatives.
    const P: [u16; 13] = [4, 5, 8, 10, 16, 20, 32, 40, 64, 80, 160, 320, 640];
    let alt = r.int(0, 12)? as usize;
    let period = P[alt];
    let offset = r.int(0, period as i64 - 1)? as u16;
    Some((period, offset))
}

fn parse_csi_report_config(r: &mut Bits, out: &mut CellGroupParams) -> Option<()> {
    // CSI-ReportConfig ::= SEQUENCE { reportConfigId (0..47), [carrier (0..31)],
    // resourcesForChannelMeasurement (0..111), [csi-IM-ResourcesForInterference],
    // [nzp-CSI-RS-ResourcesForInterference], reportConfigType CHOICE{periodic
    // SEQ{reportSlotConfig CSI-ReportPeriodicityAndOffset, pucch-CSI-ResourceList
    // SEQ(1..4) OF PUCCH-CSI-Resource}, semiPersistentOnPUCCH, semiPersistentOnPUSCH,
    // aperiodic}, reportQuantity CHOICE8, [reportFreqConfiguration SEQ],
    // timeRestrictionForChannelMeasurements ENUM2, timeRestriction...Interference
    // ENUM2, [codebookConfig], [dummy ENUM2], groupBasedBeamReporting CHOICE{enabled
    // NULL, disabled SEQ{[nrofReportedRS ENUM4]}}, [cqi-Table ENUM3+spare],
    // [subbandSize ENUM2], [non-PMI-PortIndication SEQ], ... }
    let ext = r.bit()?;
    // 8 optionals: subbandSize is MANDATORY (reads as ENUM2 after cqi-Table).
    let (has_carrier, has_im, has_nzp_i, has_freq, has_cb, has_dummy, has_cqi_t, has_nonpmi) =
        (r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("report flags: carrier={has_carrier} im={has_im} nzp_i={has_nzp_i} freq={has_freq} cb={has_cb} dummy={has_dummy} cqiT={has_cqi_t} nonpmi={has_nonpmi} @{}", r.pos);
    r.int(0, 47)?;
    if has_carrier {
        r.int(0, 31)?;
    }
    r.int(0, 111)?;
    if has_im {
        r.int(0, 111)?;
    }
    if has_nzp_i {
        r.int(0, 111)?;
    }
    // reportConfigType CHOICE (4 alternatives)
    match r.int(0, 3)? {
        0 => {
            // periodic: reportSlotConfig CSI-ReportPeriodicityAndOffset (10 alts),
            // pucch-CSI-ResourceList SEQ(1..4) OF { uplinkBandwidthPartId (0..4),
            // pucch-Resource (0..127) }
            const P: [u16; 10] = [4, 5, 8, 10, 16, 20, 40, 80, 160, 320];
            let alt = r.int(0, 9)? as usize;
            let period = P[alt];
            let offset = r.int(0, period as i64 - 1)? as u16;
            let n = r.int(1, 4)?;
            let mut res_id = 0u8;
            for i in 0..n {
                r.int(0, 4)?;
                let id = r.int(0, 127)? as u8;
                if i == 0 {
                    res_id = id;
                }
            }
            out.csi_report = Some((period, offset, res_id));
            trace!("csi report: period={period} offset={offset} pucch-res={res_id} @{}", r.pos);
        }
        _ => {
            trace!("non-periodic csi report: unsupported");
            return None;
        }
    }
    // reportQuantity CHOICE (8 alternatives, NOT extensible — verified by the tail
    // tiling exactly to the octet padding on the live capture)
    let quantity = r.int(0, 7)?;
    trace!("csi quantity={quantity} @{}", r.pos);
    if quantity == 3 {
        // cri-RI-i1-CQI ::= SEQ { [pdsch-BundleSizeForCSI ENUM2] }
        if r.bit()? {
            r.enu(2)?;
        }
        trace!("q3 tail @{}", r.pos);
    }
    if has_freq {
        // reportFreqConfiguration ::= SEQ { [cqi-FormatIndicator ENUM2],
        // [pmi-FormatIndicator ENUM2], [csi-ReportingBand CHOICE18] }
        let (has_cqi_f, has_pmi_f, has_band) = (r.bit()?, r.bit()?, r.bit()?);
        if has_cqi_f {
            r.enu(2)?;
        }
        if has_pmi_f {
            r.enu(2)?;
        }
        if has_band {
            // CHOICE of subbands3..subbands19-v1530: 18 alternatives (extensible),
            // alternative i carries a BIT STRING(i+3).
            if r.bit()? {
                trace!("csi-ReportingBand extension: unsupported");
                return None;
            }
            let alt = r.int(0, 17)?;
            r.bits(alt as u32 + 3)?;
        }
    }
    trace!("freq done @{} (has_freq={has_freq} has_cb={has_cb})", r.pos);
    r.enu(2)?; // timeRestrictionForChannelMeasurements
    r.enu(2)?; // timeRestrictionForInterferenceMeasurements
    if has_cb {
        trace!("codebookConfig: unsupported");
        return None;
    }
    if has_dummy {
        r.enu(2)?;
    }
    // groupBasedBeamReporting CHOICE { enabled NULL, disabled SEQ{[nrofReportedRS ENUM4]} }
    if r.bit()? {
        if r.bit()? {
            r.enu(4)?;
        }
    }
    if has_cqi_t {
        r.enu(4)?; // cqi-Table {table1,table2,table3,spare1}
    }
    r.enu(2)?; // subbandSize (mandatory)
    if has_nonpmi {
        trace!("non-PMI port indication: unsupported");
        return None;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live captures: the 5 ms cell and the 2.5 ms DDDSU cell (both 289 bytes).
    const RRC_SETUP_MS5: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2400044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c6050e1fa2b3c4de4d03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8801c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e20000001002000403000404801100520000118800f38e000";
    const RRC_SETUP_DDDSU: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2c00044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c605081fa33c4de6cd03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8a01c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e28000001002000403000404801100520000118900f38e000";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn parses_ms5_rrc_setup() {
        let p = parse_rrc_setup(&hex(RRC_SETUP_MS5)).expect("ms5 RRCSetup must parse");
        // The empirically-known dedicated config of the 5 ms cell:
        assert_eq!(p.k1_list, vec![4, 5, 6, 7, 8, 9, 11, 12]);
        // OCUDU sends NO dedicated TDRA lists (tdra=false in both PDSCH/PUSCH-Config):
        // the DCI 0_1/1_1 TDRA field width falls back to the SIB1 common list
        // (2 rows on this cell ⇒ the 1-bit field observed live). TS 38.214 §5.1.2.1.1.
        assert!(p.pdsch_tdra.is_empty());
        assert!(p.pusch_tdra.is_empty());
        assert!(p.sr.is_some());
        assert!(!p.pucch_resources.is_empty());
        // Periodic CSI report on PUCCH: period 40 slots, offset 8 (the live slot-8
        // report), on PUCCH resource 15 (the F2 at PRB 23).
        assert_eq!(p.csi_report, Some((40, 8, 15)));
    }

    #[test]
    fn parses_dddsu_rrc_setup() {
        let p = parse_rrc_setup(&hex(RRC_SETUP_DDDSU)).expect("DDDSU RRCSetup must parse");
        // SR observed live at slot 4 (period 20 offset 4, or an equivalent).
        let (period, offset, _res) = p.sr.expect("SR config");
        assert_eq!((period + offset) % 5, 4 % 5, "SR occasion must be the DDDSU UL slot");
        // Differential vs the 5 ms cell: OCUDU retunes the k1 list to the pattern.
        assert_eq!(p.k1_list, vec![4, 6, 7, 8, 9, 11, 12, 13]);
        // CSI report also lands on the UL slot (offset 9 ≡ 4 mod 5).
        assert_eq!(p.csi_report, Some((40, 9, 15)));
    }
}
