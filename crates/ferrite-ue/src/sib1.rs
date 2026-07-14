//! SIB1 decode (TS 38.331): a hand-rolled UPER (X.691 unaligned PER) parse of
//! `BCCH-DL-SCH-Message → SystemInformationBlockType1`, deep enough to extract the
//! cell's **TDD UL/DL pattern** and the common timing tables the UE needs to follow
//! an arbitrary configuration instead of the transcribed constants used so far:
//!
//!   · tdd-UL-DL-ConfigurationCommon → [`TddPattern`] (slot-kind queries)
//!   · pusch-ConfigCommon → the k2 time-domain allocation list (UL grant timing)
//!   · pdsch-ConfigCommon → the k0/SLIV list
//!   · rach-ConfigCommon / pucch-ConfigCommon / PLMN/TAC — parsed in passing
//!     (UPER has no skip markers: every field up to the TDD config must be walked,
//!     so the intermediate values come for free and double as parse validation).
//!
//! Clean-room: written from the ASN.1 module in TS 38.331 §6; no external decoder.
//! UPER rules used (X.691): constrained whole numbers in ⌈log2(range)⌉ bits;
//! extensible types carry a leading extension bit; extension additions are wrapped
//! in length-prefixed open types (and are therefore skippable — the ONLY skippable
//! thing in UPER, which this parser leans on for release-16+ additions).
//!
//! Set `FERRITE_SIB1_TRACE=1` for a per-field dump.

/// One TDD-UL-DL-Pattern (TS 38.331): `periodicity` in slots at the reference SCS,
/// leading full-DL slots, a special slot with `dl_symbols`/`ul_symbols`, trailing
/// full-UL slots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TddPattern {
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

/// What a slot is, per the TDD pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Dl,
    Ul,
    /// The flexible/special slot: `dl_symbols` DL at the start, `ul_symbols` UL at
    /// the end, guard in between.
    Special,
}

impl TddPattern {
    pub fn kind(&self, slot: u32) -> SlotKind {
        let s = slot % self.period_slots;
        if s < self.dl_slots {
            SlotKind::Dl
        } else if s >= self.period_slots - self.ul_slots {
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

/// A time-domain resource allocation row (PDSCH k0 / PUSCH k2 lists).
#[derive(Clone, Copy, Debug, Default)]
pub struct TdraRow {
    /// k0 (PDSCH) or k2 (PUSCH); the spec default applies when absent
    /// (k0 = 0; k2 = 1 for 15/30 kHz).
    pub k: u8,
    /// Mapping type A (true) or B.
    pub type_a: bool,
    /// startSymbolAndLength (SLIV).
    pub sliv: u8,
}

/// Everything this parser extracts from SIB1.
#[derive(Clone, Debug, Default)]
pub struct Sib1Params {
    pub mcc: [u8; 3],
    pub mnc: Vec<u8>,
    pub tac: u32,
    pub cell_identity: u64,
    /// From frequencyInfoDL-SIB.
    pub band: u16,
    pub offset_to_point_a: u16,
    pub carrier_bw_rb: u16,
    pub carrier_scs_khz: u32,
    /// pdsch-TimeDomainAllocationList (empty ⇒ the 38.214 default table applies).
    pub pdsch_tdra: Vec<TdraRow>,
    /// pusch-TimeDomainAllocationList (empty ⇒ the 38.214 default table applies).
    pub pusch_tdra: Vec<TdraRow>,
    /// rach-ConfigGeneric.
    pub prach_config_index: u8,
    pub prach_msg1_freq_start: u16,
    pub prach_zczc: u8,
    pub prach_root_seq: u16,
    /// pucch-ConfigCommon.
    pub pucch_resource_common: Option<u8>,
    pub pucch_hopping_id: Option<u16>,
    /// n-TimingAdvanceOffset (samples semantics per 38.133), if signalled.
    pub n_timing_advance_offset: Option<u32>,
    /// The TDD configuration: reference SCS in kHz and pattern1 (+ optional pattern2,
    /// which concatenates after pattern1).
    pub tdd_ref_scs_khz: u32,
    pub tdd: TddPattern,
    pub tdd_pattern2: Option<TddPattern>,
}

impl Sib1Params {
    /// The combined TDD period in slots (pattern1 + pattern2 when present).
    pub fn tdd_period_slots(&self) -> u32 {
        self.tdd.period_slots + self.tdd_pattern2.map_or(0, |p| p.period_slots)
    }

    /// Slot kind across the combined pattern.
    pub fn slot_kind(&self, slot: u32) -> SlotKind {
        let s = slot % self.tdd_period_slots();
        if s < self.tdd.period_slots {
            self.tdd.kind(s)
        } else {
            self.tdd_pattern2.unwrap().kind(s - self.tdd.period_slots)
        }
    }

    pub fn has_pdsch(&self, slot: u32) -> bool {
        let s = slot % self.tdd_period_slots();
        if s < self.tdd.period_slots {
            self.tdd.has_pdsch(s)
        } else {
            self.tdd_pattern2.unwrap().has_pdsch(s - self.tdd.period_slots)
        }
    }

    pub fn has_full_ul(&self, slot: u32) -> bool {
        let s = slot % self.tdd_period_slots();
        if s < self.tdd.period_slots {
            self.tdd.has_full_ul(s)
        } else {
            self.tdd_pattern2.unwrap().has_full_ul(s - self.tdd.period_slots)
        }
    }

    /// First full-UL slot strictly after `slot` (mod the combined period).
    pub fn next_ul_slot_after(&self, slot: u32) -> u32 {
        (slot + 1..=slot + self.tdd_period_slots())
            .find(|&s| self.has_full_ul(s))
            .unwrap_or(slot + 1)
    }

    /// k2 for a DCI TDRA row index (PUSCH). Row indices address the SIB1 list;
    /// absent list ⇒ the 38.214 Table 6.1.2.1.1-2 default (all rows k2 = j = 1 at
    /// 30 kHz — plus the TDD shift the gNB bakes into its chosen row, so a missing
    /// list on a TDD cell would be surprising; we fall back to the observed cell
    /// default of 4 to stay attachable).
    pub fn k2_for_row(&self, row: usize) -> u8 {
        self.pusch_tdra.get(row).map(|r| r.k).unwrap_or(4)
    }
}

/// X.691 unaligned-PER bit reader. Every read returns `None` past the end, which
/// propagates as a parse failure (`?`).
struct Bits<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn bit(&mut self) -> Option<bool> {
        let byte = *self.b.get(self.pos / 8)?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(v == 1)
    }

    fn bits(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Some(v)
    }

    /// Constrained whole number in `lo..=hi` (§10.5): ⌈log2(range)⌉ bits, offset `lo`.
    fn int(&mut self, lo: i64, hi: i64) -> Option<i64> {
        let range = (hi - lo + 1) as u64;
        if range <= 1 {
            return Some(lo);
        }
        let n = 64 - (range - 1).leading_zeros();
        Some(lo + self.bits(n)? as i64)
    }

    /// Non-extensible ENUMERATED with `n` root values.
    fn enu(&mut self, n: u32) -> Option<u32> {
        Some(self.int(0, n as i64 - 1)? as u32)
    }

    /// Extensible ENUMERATED: extension bit then the root index (extension values
    /// are read as a normally-small number).
    fn enu_ext(&mut self, n_root: u32) -> Option<u32> {
        if self.bit()? {
            // Extended value: normally-small number; the actual identity is unknown
            // to us, return a sentinel beyond the root range.
            let _ = self.normally_small()?;
            return Some(n_root);
        }
        self.enu(n_root)
    }

    /// Normally-small non-negative whole number (§10.6): '0' + 6 bits, else a
    /// length-prefixed unconstrained number (not needed beyond 63 here).
    fn normally_small(&mut self) -> Option<u64> {
        if !self.bit()? {
            self.bits(6)
        } else {
            let len = self.len_det()?;
            self.bits((len * 8).min(64) as u32)
        }
    }

    /// General length determinant (§10.9, unaligned): '0'+7 bits (<128) or
    /// '10'+14 bits (<16384). Fragmentation ('11') unsupported (never hit in SIB1).
    fn len_det(&mut self) -> Option<usize> {
        if !self.bit()? {
            Some(self.bits(7)? as usize)
        } else if !self.bit()? {
            Some(self.bits(14)? as usize)
        } else {
            None
        }
    }

    /// Skip one open-type value (length determinant counts OCTETS).
    fn skip_open(&mut self) -> Option<()> {
        let len = self.len_det()?;
        self.pos += len * 8;
        (self.pos <= self.b.len() * 8).then_some(())
    }

    /// Skip a SEQUENCE's extension additions (call when its extension bit was 1):
    /// a normally-small count-1, that many presence bits, then each present
    /// addition as an open type.
    fn skip_ext_additions(&mut self) -> Option<()> {
        let n = self.normally_small()? + 1;
        let mut present = Vec::with_capacity(n as usize);
        for _ in 0..n {
            present.push(self.bit()?);
        }
        for p in present {
            if p {
                self.skip_open()?;
            }
        }
        Some(())
    }
}

macro_rules! trace {
    ($($t:tt)*) => {
        if std::env::var_os("FERRITE_SIB1_TRACE").is_some() {
            eprintln!("[sib1] {}", format!($($t)*));
        }
    };
}

/// Parse a SIB1 transport block (the DL-SCH TB bytes, padding included) into
/// [`Sib1Params`]. Returns `None` on any structural mismatch.
pub fn parse_sib1(tb: &[u8]) -> Option<Sib1Params> {
    let r = &mut Bits::new(tb);
    let mut out = Sib1Params::default();

    // BCCH-DL-SCH-Message ::= CHOICE { c1 CHOICE { systemInformation,
    // systemInformationBlockType1 }, messageClassExtension }
    if r.bit()? {
        return None; // messageClassExtension
    }
    if !r.bit()? {
        return None; // systemInformation, not SIB1
    }

    // SystemInformationBlockType1 ::= SEQUENCE (no extension marker; 11 OPTIONALs)
    let mut opt = [false; 11];
    for o in opt.iter_mut() {
        *o = r.bit()?;
    }
    let [cell_sel, conn_est, si_sched, scc, ims, ecall, timers, uac, resume, late_ext, non_crit] = opt;
    trace!("SIB1 optionals: cellSel={cell_sel} connEst={conn_est} siSched={si_sched} scc={scc} ims={ims} ecall={ecall} timers={timers} uac={uac} resume={resume} late={late_ext} nonCrit={non_crit}");

    if cell_sel {
        // cellSelectionInfo ::= SEQUENCE { q-RxLevMin, [q-RxLevMinOffset],
        // [q-RxLevMinSUL], [q-QualMin], [q-QualMinOffset] }
        let (o1, o2, o3, o4) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
        let q_rx = r.int(-70, -22)?;
        trace!("q-RxLevMin={q_rx}");
        if o1 {
            r.int(1, 8)?;
        }
        if o2 {
            r.int(-70, -22)?;
        }
        if o3 {
            r.int(-43, -12)?;
        }
        if o4 {
            r.int(1, 8)?;
        }
    }

    // cellAccessRelatedInfo ::= SEQUENCE { plmn-IdentityInfoList,
    // [cellReservedForOtherUse], ... }
    {
        let ext = r.bit()?;
        let reserved_other = r.bit()?;
        // PLMN-IdentityInfoList ::= SEQUENCE (SIZE (1..12)) OF PLMN-IdentityInfo
        let n_info = r.int(1, 12)?;
        for i in 0..n_info {
            // PLMN-IdentityInfo ::= SEQUENCE { plmn-IdentityList, [tac], [ranac],
            // cellIdentity, cellReservedForOperatorUse, ... }
            let ext_i = r.bit()?;
            let (has_tac, has_ranac) = (r.bit()?, r.bit()?);
            let n_plmn = r.int(1, 12)?;
            for _ in 0..n_plmn {
                // PLMN-Identity ::= SEQUENCE { [mcc], mnc }
                let has_mcc = r.bit()?;
                if has_mcc {
                    for d in out.mcc.iter_mut() {
                        *d = r.int(0, 9)? as u8;
                    }
                }
                let n_mnc = r.int(2, 3)?;
                out.mnc = (0..n_mnc).map(|_| r.int(0, 9).map(|v| v as u8)).collect::<Option<_>>()?;
            }
            if has_tac {
                out.tac = r.bits(24)? as u32;
            }
            if has_ranac {
                r.int(0, 255)?;
            }
            out.cell_identity = r.bits(36)?;
            let _op_reserved = r.enu(2)?;
            if ext_i {
                r.skip_ext_additions()?;
            }
            if i == 0 {
                trace!("PLMN mcc={:?} mnc={:?} tac={} cellId={:#x}", out.mcc, out.mnc, out.tac, out.cell_identity);
            }
        }
        let _ = reserved_other; // ENUMERATED{true}: presence IS the value, no bits
        if ext {
            r.skip_ext_additions()?;
        }
    }

    if conn_est {
        // ConnEstFailureControl ::= SEQUENCE { count ENUM4, offsetValidity ENUM8,
        // [connEstFailOffset INTEGER(0..15)] }
        let has_off = r.bit()?;
        r.enu(4)?;
        r.enu(8)?;
        if has_off {
            r.int(0, 15)?;
        }
        trace!("connEstFailureControl parsed");
    }

    if si_sched {
        // SI-SchedulingInfo: not needed and structurally deep — bail out rather
        // than risk a silent misparse of everything after it.
        trace!("si-SchedulingInfo present: unsupported");
        return None;
    }

    if scc {
        parse_serving_cell_config_common(r, &mut out)?;
    }

    // Remaining optionals (timers, uac, …) come after servingCellConfigCommon; we
    // already have everything — no need to parse further.
    let _ = (ims, ecall, timers, uac, resume, late_ext, non_crit);
    Some(out)
}

fn parse_serving_cell_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // ServingCellConfigCommonSIB ::= SEQUENCE { downlinkConfigCommon,
    // [uplinkConfigCommon], [supplementaryUplink], [n-TimingAdvanceOffset],
    // ssb-PositionsInBurst SEQUENCE { inOneGroup BIT STRING(8), [groupPresence] },
    // ssb-PeriodicityServingCell ENUM6, [tdd-UL-DL-ConfigurationCommon],
    // ss-PBCH-BlockPower INTEGER(-60..50), ... }
    let ext = r.bit()?;
    let (has_ul, has_sul, has_nta, has_tdd) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    trace!("SCC: ul={has_ul} sul={has_sul} nta={has_nta} tdd={has_tdd}");

    parse_dl_config_common(r, out)?;

    if has_ul {
        parse_ul_config_common(r, out)?;
    }
    if has_sul {
        // A supplementary uplink would need the same walk; no cell we target uses
        // one — bail out loudly rather than misparse.
        trace!("supplementaryUplink present: unsupported");
        return None;
    }
    if has_nta {
        let v = r.enu(3)?;
        out.n_timing_advance_offset = Some([0u32, 25600, 39936][v as usize]);
    }
    // ssb-PositionsInBurst
    {
        let has_group = r.bit()?;
        let in_one_group = r.bits(8)?;
        trace!("ssb-PositionsInBurst inOneGroup={in_one_group:#04x}");
        if has_group {
            r.bits(8)?;
        }
    }
    let ssb_period = r.enu(6)?;
    trace!("ssb-PeriodicityServingCell idx={ssb_period}");

    if has_tdd {
        // TDD-UL-DL-ConfigCommon ::= SEQUENCE { referenceSubcarrierSpacing,
        // pattern1, [pattern2], ... }
        let tdd_ext = r.bit()?;
        let has_p2 = r.bit()?;
        let ref_scs = r.enu(8)?; // SubcarrierSpacing: kHz15, kHz30, kHz60, ...
        out.tdd_ref_scs_khz = 15u32 << ref_scs.min(4);
        out.tdd = parse_tdd_pattern(r, out.tdd_ref_scs_khz)?;
        if has_p2 {
            out.tdd_pattern2 = Some(parse_tdd_pattern(r, out.tdd_ref_scs_khz)?);
        }
        if tdd_ext {
            r.skip_ext_additions()?;
        }
        trace!("TDD refSCS={}kHz pattern1={:?} pattern2={:?}", out.tdd_ref_scs_khz, out.tdd, out.tdd_pattern2);
    }

    let pwr = r.int(-60, 50)?;
    trace!("ss-PBCH-BlockPower={pwr}");
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_tdd_pattern(r: &mut Bits, ref_scs_khz: u32) -> Option<TddPattern> {
    // TDD-UL-DL-Pattern ::= SEQUENCE { dl-UL-TransmissionPeriodicity ENUM8,
    // nrofDownlinkSlots INTEGER(0..320), nrofDownlinkSymbols INTEGER(0..13),
    // nrofUplinkSlots INTEGER(0..320), nrofUplinkSymbols INTEGER(0..13), ...,
    // [[dl-UL-TransmissionPeriodicity-v1530 ENUM{ms3,ms4} OPTIONAL]] }
    let ext = r.bit()?;
    let period_idx = r.enu(8)?;
    let dl_slots = r.int(0, 320)? as u32;
    let dl_symbols = r.int(0, 13)? as u32;
    let ul_slots = r.int(0, 320)? as u32;
    let ul_symbols = r.int(0, 13)? as u32;
    if ext {
        // The v1530 addition redefines the periodicity to 3/4 ms; a cell that uses
        // it would need the extended value — skip (and accept the small error) is
        // NOT safe, so refuse.
        trace!("TDD pattern v1530 periodicity present: unsupported");
        return None;
    }
    // Periodicity in ms ×1000: ms0p5, ms0p625, ms1, ms1p25, ms2, ms2p5, ms5, ms10.
    const PERIOD_US: [u32; 8] = [500, 625, 1000, 1250, 2000, 2500, 5000, 10000];
    let period_us = PERIOD_US[period_idx as usize];
    let slot_us = 1000 * 15 / ref_scs_khz; // 1 ms / (scs/15kHz)
    let period_slots = period_us / slot_us;
    Some(TddPattern { period_slots, dl_slots, dl_symbols, ul_slots, ul_symbols })
}

fn parse_dl_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // DownlinkConfigCommonSIB ::= SEQUENCE { frequencyInfoDL, initialDownlinkBWP,
    // bcch-Config, pcch-Config, ... }
    let ext = r.bit()?;

    // FrequencyInfoDL-SIB ::= SEQUENCE { frequencyBandList, offsetToPointA
    // INTEGER(0..2199), scs-SpecificCarrierList SEQUENCE (SIZE (1..5)) OF … }
    {
        let n_bands = r.int(1, 8)?;
        for i in 0..n_bands {
            // NR-MultiBandInfo ::= SEQUENCE { [freqBandIndicatorNR INTEGER(1..1024)],
            // [nr-NS-PmaxList] }
            let (has_band, has_pmax) = (r.bit()?, r.bit()?);
            if has_band {
                let band = r.int(1, 1024)? as u16;
                if i == 0 {
                    out.band = band;
                }
            }
            if has_pmax {
                // NR-NS-PmaxList ::= SEQUENCE (SIZE (1..8)) OF NR-NS-PmaxValue;
                // NR-NS-PmaxValue ::= SEQUENCE { [additionalPmax INTEGER(-30..33)],
                // additionalSpectrumEmission INTEGER(0..7) }
                let n = r.int(1, 8)?;
                for _ in 0..n {
                    let has_pm = r.bit()?;
                    if has_pm {
                        r.int(-30, 33)?;
                    }
                    r.int(0, 7)?;
                }
            }
        }
        out.offset_to_point_a = r.int(0, 2199)? as u16;
        let n_carriers = r.int(1, 5)?;
        for i in 0..n_carriers {
            let (off, scs, bw) = parse_scs_specific_carrier(r)?;
            if i == 0 {
                out.carrier_scs_khz = scs;
                out.carrier_bw_rb = bw;
                let _ = off;
            }
        }
        trace!("DL band={} offsetToPointA={} carrier {} RB @ {} kHz", out.band, out.offset_to_point_a, out.carrier_bw_rb, out.carrier_scs_khz);
    }

    // initialDownlinkBWP BWP-DownlinkCommon ::= SEQUENCE { genericParameters BWP,
    // [pdcch-ConfigCommon SetupRelease], [pdsch-ConfigCommon SetupRelease], ... }
    {
        let bwp_ext = r.bit()?;
        let (has_pdcch, has_pdsch) = (r.bit()?, r.bit()?);
        parse_bwp(r)?;
        if has_pdcch {
            if r.bit()? {
                // setup
                parse_pdcch_config_common(r)?;
            }
        }
        if has_pdsch {
            if r.bit()? {
                parse_pdsch_config_common(r, out)?;
            }
        }
        if bwp_ext {
            r.skip_ext_additions()?;
        }
    }

    // bcch-Config ::= SEQUENCE { modificationPeriodCoeff ENUM4, ... }
    {
        let e = r.bit()?;
        r.enu(4)?;
        if e {
            r.skip_ext_additions()?;
        }
    }
    // pcch-Config ::= SEQUENCE { defaultPagingCycle ENUM4, nAndPagingFrameOffset
    // CHOICE5, ns ENUM3, [firstPDCCH-MonitoringOccasionOfPO CHOICE8], ... }
    {
        let e = r.bit()?;
        let has_first = r.bit()?;
        r.enu(4)?;
        match r.int(0, 4)? {
            0 => {}                    // oneT: NULL
            1 => { r.int(0, 1)?; }     // halfT
            2 => { r.int(0, 3)?; }     // quarterT
            3 => { r.int(0, 7)?; }     // oneEighthT
            _ => { r.int(0, 15)?; }    // oneSixteenthT
        }
        r.enu(3)?;
        if has_first {
            // CHOICE of 8 per-SCS SEQUENCE OF lists.
            let alt = r.int(0, 7)?;
            let (max_n, hi): (i64, i64) = match alt {
                0 => (4, 139),
                1 => (4, 279),
                2 => (4, 559),
                3 => (4, 1119),
                4 => (4, 2239),
                5 => (4, 4479),
                6 => (4, 8959),
                _ => (4, 17919),
            };
            let n = r.int(1, max_n)?;
            for _ in 0..n {
                r.int(0, hi)?;
            }
        }
        if e {
            r.skip_ext_additions()?;
        }
    }
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("downlinkConfigCommon parsed @{}", r.pos);
    Some(())
}

fn parse_scs_specific_carrier(r: &mut Bits) -> Option<(u16, u32, u16)> {
    // SCS-SpecificCarrier ::= SEQUENCE { offsetToCarrier INTEGER(0..2199),
    // subcarrierSpacing, carrierBandwidth INTEGER(1..275), ...,
    // [[txDirectCurrentLocation-v1530 OPTIONAL]] }
    let ext = r.bit()?;
    let off = r.int(0, 2199)? as u16;
    let scs = 15u32 << r.enu(8)?.min(4);
    let bw = r.int(1, 275)? as u16;
    if ext {
        r.skip_ext_additions()?;
    }
    Some((off, scs, bw))
}

fn parse_bwp(r: &mut Bits) -> Option<()> {
    // BWP ::= SEQUENCE { locationAndBandwidth INTEGER(0..37949),
    // subcarrierSpacing, [cyclicPrefix ENUM{extended}] }
    let has_cp = r.bit()?;
    let lb = r.int(0, 37949)?;
    let scs = r.enu(8)?;
    let _ = (lb, scs, has_cp); // ENUM{true}-style: cp presence is the value
    trace!("BWP locationAndBandwidth={lb} scsIdx={scs}");
    Some(())
}

fn parse_pdcch_config_common(r: &mut Bits) -> Option<()> {
    // PDCCH-ConfigCommon ::= SEQUENCE { [controlResourceSetZero INTEGER(0..15)],
    // [commonControlResourceSet], [searchSpaceZero INTEGER(0..15)],
    // [commonSearchSpaceList SEQUENCE (SIZE (1..4)) OF SearchSpace],
    // [searchSpaceSIB1], [searchSpaceOtherSystemInformation],
    // [pagingSearchSpace], [ra-SearchSpace], ... }
    let ext = r.bit()?;
    let mut o = [false; 8];
    for b in o.iter_mut() {
        *b = r.bit()?;
    }
    trace!("PDCCH-ConfigCommon opts: crs0={} commonCrs={} ss0={} cssList={} ssSib1={} ssOsi={} ssPaging={} ssRa={}", o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
    if o[0] {
        r.int(0, 15)?;
    }
    if o[1] {
        // A full ControlResourceSet in SIB1 is unusual; refuse rather than misparse.
        trace!("commonControlResourceSet present: unsupported");
        return None;
    }
    if o[2] {
        r.int(0, 15)?;
    }
    if o[3] {
        let n = r.int(1, 4)?;
        for _ in 0..n {
            parse_search_space(r)?;
        }
    }
    for _ in o[4..8].iter().filter(|&&p| p) {
        r.int(0, 39)?; // SearchSpaceId
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_search_space(r: &mut Bits) -> Option<()> {
    // SearchSpace ::= SEQUENCE { searchSpaceId INTEGER(0..39),
    // [controlResourceSetId INTEGER(0..11)], [monitoringSlotPeriodicityAndOffset
    // CHOICE15], [duration INTEGER(2..2559)], [monitoringSymbolsWithinSlot BIT
    // STRING(14)], [nrofCandidates SEQUENCE{5×ENUM8}], [searchSpaceType CHOICE2] }
    // Preamble first (UPER): the 6-bit optional bitmap precedes ALL field values,
    // including the mandatory searchSpaceId.
    let mut o = [false; 6];
    for b in o.iter_mut() {
        *b = r.bit()?;
    }
    let id = r.int(0, 39)?;
    if o[0] {
        r.int(0, 11)?;
    }
    if o[1] {
        // CHOICE of 15 slot periodicities: sl1 NULL, sl2(0..1), sl4(0..3), sl5(0..4),
        // sl8(0..7), sl10(0..9), sl16(0..15), sl20(0..19), sl40, sl80, sl160, sl320,
        // sl640, sl1280, sl2560.
        const HI: [i64; 15] = [0, 1, 3, 4, 7, 9, 15, 19, 39, 79, 159, 319, 639, 1279, 2559];
        let alt = r.int(0, 14)? as usize;
        if HI[alt] > 0 {
            r.int(0, HI[alt])?;
        }
    }
    if o[2] {
        r.int(2, 2559)?;
    }
    if o[3] {
        r.bits(14)?;
    }
    if o[4] {
        for _ in 0..5 {
            r.enu(8)?;
        }
    }
    if o[5] {
        if !r.bit()? {
            // common ::= SEQUENCE { 5 × [SEQUENCE{...}] } — each present member is
            // an extensible, empty-root SEQUENCE except dci-Format2-0/2-3 which
            // carry candidate counts.
            let mut c = [false; 5];
            for b in c.iter_mut() {
                *b = r.bit()?;
            }
            if c[0] {
                // dci-Format0-0-AndFormat1-0 ::= SEQUENCE { ... }
                if r.bit()? {
                    r.skip_ext_additions()?;
                }
            }
            if c[1] {
                // dci-Format2-0 ::= SEQUENCE { nrofCandidates-SFI SEQUENCE {
                // 5 × [ENUM{n1,n2}] }, ... }
                let e = r.bit()?;
                let mut m = [false; 5];
                for b in m.iter_mut() {
                    *b = r.bit()?;
                }
                for p in m.iter().filter(|&&p| p) {
                    let _ = p;
                    r.enu(2)?;
                }
                if e {
                    r.skip_ext_additions()?;
                }
            }
            if c[2] || c[3] {
                for &p in &[c[2], c[3]] {
                    if p {
                        if r.bit()? {
                            r.skip_ext_additions()?;
                        }
                    }
                }
            }
            if c[4] {
                // dci-Format2-3 ::= SEQUENCE { dummy1 ENUM… we refuse — unused here.
                trace!("dci-Format2-3 present: unsupported");
                return None;
            }
        } else {
            // ue-Specific ::= SEQUENCE { dci-Formats ENUM2, ... }
            let e = r.bit()?;
            r.enu(2)?;
            if e {
                r.skip_ext_additions()?;
            }
        }
    }
    trace!("searchSpace id={id} parsed");
    Some(())
}

fn parse_pdsch_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // PDSCH-ConfigCommon ::= SEQUENCE { [pdsch-TimeDomainAllocationList], ... }
    let ext = r.bit()?;
    let has_list = r.bit()?;
    if has_list {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            // PDSCH-TimeDomainResourceAllocation ::= SEQUENCE { [k0 INTEGER(0..32)],
            // mappingType ENUM2, startSymbolAndLength INTEGER(0..127) }
            let has_k0 = r.bit()?;
            let k0 = if has_k0 { r.int(0, 32)? as u8 } else { 0 };
            let type_a = r.enu(2)? == 0;
            let sliv = r.int(0, 127)? as u8;
            out.pdsch_tdra.push(TdraRow { k: k0, type_a, sliv });
        }
        trace!("pdsch-TDRA @{}: {:?}", r.pos, out.pdsch_tdra);
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_ul_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // UplinkConfigCommonSIB ::= SEQUENCE { frequencyInfoUL, initialUplinkBWP,
    // timeAlignmentTimerCommon } (no extension marker, no optionals)
    // FrequencyInfoUL-SIB ::= SEQUENCE { [frequencyBandList],
    // [absoluteFrequencyPointA], scs-SpecificCarrierList, [p-Max],
    // [frequencyShift7p5khz], ... }  — NOTE: unlike FrequencyInfoDL-SIB, this one
    // IS extensible (verified bit-exactly against the live capture: with the ext
    // bit the IE tiles the gap to the RACH anchor precisely; without it, nothing
    // downstream aligns).
    {
        let fiu_ext = r.bit()?;
        let (has_bands, has_arfcn, has_pmax, has_shift) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
        trace!("@{pos} frequencyInfoUL ext={fiu_ext} opts: bands={has_bands} arfcn={has_arfcn} pmax={has_pmax} shift={has_shift}", pos = r.pos - 5);
        if has_bands {
            let n = r.int(1, 8)?;
            for _ in 0..n {
                let (hb, hp) = (r.bit()?, r.bit()?);
                if hb {
                    r.int(1, 1024)?;
                }
                if hp {
                    let m = r.int(1, 8)?;
                    for _ in 0..m {
                        let hpm = r.bit()?;
                        if hpm {
                            r.int(-30, 33)?;
                        }
                        r.int(0, 7)?;
                    }
                }
            }
        }
        if has_arfcn {
            r.int(0, 3279165)?;
        }
        let n = r.int(1, 5)?;
        for _ in 0..n {
            parse_scs_specific_carrier(r)?;
        }
        if has_pmax {
            r.int(-30, 33)?;
        }
        let _ = has_shift; // ENUM{true}: presence is the value
        if fiu_ext {
            r.skip_ext_additions()?;
        }
        trace!("frequencyInfoUL parsed @{}", r.pos);
    }

    // initialUplinkBWP BWP-UplinkCommon ::= SEQUENCE { genericParameters BWP,
    // [rach-ConfigCommon SetupRelease], [pusch-ConfigCommon SetupRelease],
    // [pucch-ConfigCommon SetupRelease], ... }
    {
        let ext = r.bit()?;
        let (has_rach, has_pusch, has_pucch) = (r.bit()?, r.bit()?, r.bit()?);
        trace!("initialUplinkBWP @{}: ext={ext} rach={has_rach} pusch={has_pusch} pucch={has_pucch}", r.pos);
        parse_bwp(r)?;
        if has_rach {
            if r.bit()? {
                parse_rach_config_common(r, out)?;
            }
        }
        if has_pusch {
            if r.bit()? {
                parse_pusch_config_common(r, out)?;
            }
        }
        if has_pucch {
            if r.bit()? {
                parse_pucch_config_common(r, out)?;
            }
        }
        if ext {
            r.skip_ext_additions()?;
        }
    }

    r.enu(8)?; // timeAlignmentTimerCommon
    Some(())
}

fn parse_rach_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // RACH-ConfigCommon ::= SEQUENCE { rach-ConfigGeneric,
    // [totalNumberOfRA-Preambles INTEGER(1..63)],
    // [ssb-perRACH-OccasionAndCB-PreamblesPerSSB CHOICE8], [groupBconfigured],
    // ra-ContentionResolutionTimer ENUM8, [rsrp-ThresholdSSB],
    // [rsrp-ThresholdSSB-SUL], prach-RootSequenceIndex CHOICE{l839, l139},
    // [msg1-SubcarrierSpacing], restrictedSetConfig ENUM3,
    // [msg3-transformPrecoder], ... }
    let ext = r.bit()?;
    let mut o = [false; 7];
    for b in o.iter_mut() {
        *b = r.bit()?;
    }
    // RACH-ConfigGeneric ::= SEQUENCE { prach-ConfigurationIndex INTEGER(0..255),
    // msg1-FDM ENUM4, msg1-FrequencyStart INTEGER(0..274),
    // zeroCorrelationZoneConfig INTEGER(0..15), preambleReceivedTargetPower
    // INTEGER(-202..-60), preambleTransMax ENUM11, powerRampingStep ENUM4,
    // ra-ResponseWindow ENUM8, ... }
    {
        let ge = r.bit()?;
        out.prach_config_index = r.int(0, 255)? as u8;
        r.enu(4)?;
        out.prach_msg1_freq_start = r.int(0, 274)? as u16;
        out.prach_zczc = r.int(0, 15)? as u8;
        r.int(-202, -60)?;
        r.enu(11)?;
        r.enu(4)?;
        r.enu(8)?;
        if ge {
            r.skip_ext_additions()?;
        }
        trace!("rach-ConfigGeneric @{}: index={} freqStart={} zczc={}", r.pos, out.prach_config_index, out.prach_msg1_freq_start, out.prach_zczc);
    }
    if o[0] {
        r.int(1, 63)?;
    }
    if o[1] {
        // CHOICE of 8: first 5 are ENUMs, last 3 constrained ints.
        match r.int(0, 7)? {
            0..=3 => {
                r.enu(16)?;
            }
            4 => {
                r.enu(8)?;
            }
            5 => {
                r.int(1, 16)?;
            }
            6 => {
                r.int(1, 8)?;
            }
            _ => {
                r.int(1, 4)?;
            }
        }
    }
    if o[2] {
        // groupBconfigured ::= SEQUENCE { ra-Msg3SizeGroupA ENUM16,
        // messagePowerOffsetGroupB ENUM8, numberOfRA-PreamblesGroupA INTEGER(1..64) }
        r.enu(16)?;
        r.enu(8)?;
        r.int(1, 64)?;
    }
    r.enu(8)?; // ra-ContentionResolutionTimer
    if o[3] {
        r.int(0, 127)?;
    }
    if o[4] {
        r.int(0, 127)?;
    }
    out.prach_root_seq = if !r.bit()? { r.int(0, 837)? as u16 } else { r.int(0, 137)? as u16 };
    if o[5] {
        r.enu(8)?;
    }
    r.enu(3)?; // restrictedSetConfig
    let _ = o[6]; // msg3-transformPrecoder ENUM{true}: presence is the value
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("rach-ConfigCommon parsed (rootSeq={})", out.prach_root_seq);
    Some(())
}

fn parse_pusch_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // PUSCH-ConfigCommon ::= SEQUENCE { [groupHoppingEnabledTransformPrecoding],
    // [pusch-TimeDomainAllocationList], [msg3-DeltaPreamble INTEGER(-1..6)],
    // [p0-NominalWithGrant INTEGER(-202..24)], ... }
    let ext = r.bit()?;
    let (gh, has_list, has_msg3, has_p0) = (r.bit()?, r.bit()?, r.bit()?, r.bit()?);
    let _ = gh; // ENUM{enabled}: presence is the value
    if has_list {
        let n = r.int(1, 16)?;
        for _ in 0..n {
            let has_k2 = r.bit()?;
            let k2 = if has_k2 { r.int(0, 32)? as u8 } else { 1 };
            let type_a = r.enu(2)? == 0;
            let sliv = r.int(0, 127)? as u8;
            out.pusch_tdra.push(TdraRow { k: k2, type_a, sliv });
        }
        trace!("pusch-TDRA: {:?}", out.pusch_tdra);
    }
    if has_msg3 {
        r.int(-1, 6)?;
    }
    if has_p0 {
        r.int(-202, 24)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    Some(())
}

fn parse_pucch_config_common(r: &mut Bits, out: &mut Sib1Params) -> Option<()> {
    // PUCCH-ConfigCommon ::= SEQUENCE { [pucch-ResourceCommon INTEGER(0..15)],
    // pucch-GroupHopping ENUM3, [hoppingId INTEGER(0..1023)],
    // [p0-nominal INTEGER(-202..24)], ... }
    let ext = r.bit()?;
    let (has_res, has_hop, has_p0) = (r.bit()?, r.bit()?, r.bit()?);
    if has_res {
        out.pucch_resource_common = Some(r.int(0, 15)? as u8);
    }
    r.enu(3)?;
    if has_hop {
        out.pucch_hopping_id = Some(r.int(0, 1023)? as u16);
    }
    if has_p0 {
        r.int(-202, 24)?;
    }
    if ext {
        r.skip_ext_additions()?;
    }
    trace!("pucch-ConfigCommon: resourceCommon={:?} hoppingId={:?}", out.pucch_resource_common, out.pucch_hopping_id);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live SIB1 TB captured from the OCUDU gNB (test/gnb_zmq_ferrite.yml).
    /// Ground truth: PLMN 001/01, TAC 7, band n78, 24-RB carrier @30 kHz,
    /// TDD ms5 = 10 slots: 6 DL + special(8 DL sym, 0 UL sym) + 3 UL,
    /// prach-ConfigurationIndex 159.
    const SIB1_HEX: &str = "748101701040040200000e000a680018056109a008200042e02050900c316a61b3704020000080800041a2352412130426931860000042ee18b53224f8050664abff0124e9106e28dc61b8e372c6fbf56c70ea008580d003058b6822800000000000000000";

    fn tb() -> Vec<u8> {
        (0..SIB1_HEX.len() / 2)
            .map(|i| u8::from_str_radix(&SIB1_HEX[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_live_sib1() {
        let p = parse_sib1(&tb()).expect("SIB1 must parse");
        assert_eq!(p.mcc, [0, 0, 1]);
        assert_eq!(p.mnc, vec![0, 1]);
        assert_eq!(p.tac, 7);
        assert_eq!(p.band, 78);
        assert_eq!(p.carrier_bw_rb, 24);
        assert_eq!(p.carrier_scs_khz, 30);
        assert_eq!(p.prach_config_index, 159);
        assert_eq!(p.tdd_ref_scs_khz, 30);
        assert_eq!(
            p.tdd,
            TddPattern { period_slots: 10, dl_slots: 6, dl_symbols: 8, ul_slots: 3, ul_symbols: 0 }
        );
        assert_eq!(p.tdd_pattern2, None);
    }

    #[test]
    fn tdd_pattern_queries() {
        let p = TddPattern { period_slots: 10, dl_slots: 6, dl_symbols: 8, ul_slots: 3, ul_symbols: 0 };
        // Slots 0-5 DL, 6 special (8 DL symbols → short PDSCH ok), 7-9 UL.
        assert!(p.has_pdsch(0) && p.has_pdsch(5) && p.has_pdsch(6));
        assert!(!p.has_pdsch(7) && !p.has_pdsch(9));
        assert!(!p.has_full_ul(6) && p.has_full_ul(7) && p.has_full_ul(19));
        assert_eq!(p.next_ul_slot_after(1), 7);
        assert_eq!(p.next_ul_slot_after(7), 8);
        assert_eq!(p.next_ul_slot_after(9), 17);
        // DDDSU (2.5 ms): slots 0-2 DL, 3 special (10 DL sym), 4 UL.
        let d = TddPattern { period_slots: 5, dl_slots: 3, dl_symbols: 10, ul_slots: 1, ul_symbols: 2 };
        assert!(d.has_pdsch(3));
        assert!(d.has_full_ul(4) && d.has_full_ul(9));
        assert_eq!(d.next_ul_slot_after(0), 4);
        assert_eq!(d.next_ul_slot_after(4), 9);
    }
}
