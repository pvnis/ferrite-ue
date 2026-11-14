//! The MAC entity (TS 38.321 §4.2): ties the sub-entities together behind the
//! FAPI-style PHY interface and the RLC-facing [`UpperLayers`] SAP.
//!
//! Per-slot flow (on SLOT.indication for slot `n`):
//! 1. timers (BSR, SR prohibit, TA, RA windows), LCP token buckets;
//! 2. the RA procedure may ask for a preamble (UL_TTI PRACH) or RNTI changes;
//! 3. everything due in the *target* slot `n + lead` is assembled: a pending
//!    PUSCH (built when its grant was decoded) absorbs the HARQ-ACK / CSI due in
//!    that slot (UCI on PUSCH, TS 38.213 §9.2.5); otherwise a PUCCH carries the
//!    HARQ-ACK codebook, the SR and/or the periodic CSI report.
//!
//! DCI handling: DL assignments pre-book a NACK in the ACK codebook for their
//! `ack_slot` (upgraded to ACK when RX_Data reports CRC OK); UL grants are turned
//! into MAC PDUs immediately (LCP + MAC CEs) and parked until the target slot.

use crate::pdu::*;
use crate::phr::{PhrProcedure, PowerHeadroom};
use crate::{harq::*, lcp::Lcp, ra::*, rar::parse_rar_pdu, sr::SrProcedure, ta::TimingAdvance, MacConfig};
use ferrite_common::{Rnti, RntiKind, SlotPoint};
use ferrite_fapi::*;
use std::collections::BTreeMap;

/// Events MAC reports to RRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacEvent {
    RaSucceeded { c_rnti: Rnti },
    RaFailed,
    /// A BCCH transport block (SIB1 / SI) decoded with the SI-RNTI.
    Bcch(Vec<u8>),
    /// A PCCH transport block (Paging) decoded with the P-RNTI.
    Pcch(Vec<u8>),
    /// Msg4 CCCH SDU (RRCSetup / RRCReject) received.
    Ccch(Vec<u8>),
    /// SR_COUNTER reached sr-TransMax (§5.4.4): the entity started a C-RNTI
    /// random access; RRC may release the PUCCH/SRS configuration.
    SrFailure,
    /// The timeAlignmentTimer expired (§5.2): HARQ buffers flushed, no uplink
    /// but PRACH until the next random access.
    TimeAlignmentExpired,
    /// The PHY lost synchronisation or the radio failed: RRC treats it as a
    /// radio link failure.
    RadioLinkFailure,
}

/// What MAC needs from the layers above (the RLC bearers), implemented by the
/// application's bearer table.
pub trait UpperLayers {
    /// Deliver a received MAC SDU for logical channel `lcid`.
    fn dl_sdu(&mut self, lcid: u8, sdu: &[u8], now: SlotPoint);
    /// Pull at most `max_bytes` of RLC PDU for `lcid` (one PDU, or `None`).
    fn ul_pull(&mut self, lcid: u8, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>>;
    /// Bytes pending (incl. RLC headers) on logical channel `lcid`.
    fn ul_buffer_status(&mut self, lcid: u8) -> usize;
}

/// A PUSCH built from a UL grant, waiting for its target slot.
#[derive(Clone, Debug)]
struct PendingPusch {
    grant: UlGrant,
    tb: Vec<u8>,
    /// True if a BSR was included (to restart the BSR timers at transmission).
    bsr_included: bool,
    bsr_truncated: bool,
}

/// The UE MAC entity.
pub struct MacEntity {
    cfg: MacConfig,
    ra: RaProcedure,
    dl_harq: DlHarqEntity,
    ul_harq: UlHarqEntity,
    ack_book: AckBook,
    bsr: crate::bsr::BsrProcedure,
    phr: PhrProcedure,
    power: PowerHeadroom,
    sr: Vec<SrProcedure>,
    lcp: Lcp,
    ta: TimingAdvance,
    c_rnti: Option<Rnti>,
    tc_rnti: Option<Rnti>,
    pending_pusch: BTreeMap<u64, PendingPusch>,
    /// Latest CSI measurement (cqi, slot measured).
    pending_cqi: Option<(u8, SlotPoint)>,
    /// Pending C-RNTI MAC CE for the next UL PDU (C-RNTI-based RA).
    crnti_ce_pending: bool,
    events: Vec<MacEvent>,
    /// Set once a RA procedure should be started at the next slot (with this CCCH).
    ra_start: Option<[u8; 6]>,
    /// `r_PUCCH` of the last DL DCI (for the common PUCCH resource before dedicated config).
    ack_book_common_r: Option<u8>,
    started: bool,
    stats: MacStats,
}

/// Counters for diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacStats {
    pub dl_tb_ok: u64,
    pub dl_tb_ko: u64,
    pub ul_tb: u64,
    pub ul_retx: u64,
    pub pucch_sent: u64,
    pub sr_sent: u64,
    pub ack_late: u64,
    pub phr_sent: u64,
    pub srs_sent: u64,
}

impl MacEntity {
    pub fn new(cfg: MacConfig) -> Self {
        let spm = cfg.numerology.slots_per_subframe();
        Self {
            ra: RaProcedure::new(&cfg.rach, cfg.numerology, 0x5eed),
            dl_harq: DlHarqEntity::new(cfg.nof_dl_harq),
            ul_harq: UlHarqEntity::new(cfg.nof_ul_harq),
            ack_book: AckBook::default(),
            bsr: crate::bsr::BsrProcedure::new(cfg.periodic_bsr_ms * spm, cfg.retx_bsr_ms * spm),
            phr: PhrProcedure::new(cfg.phr, spm),
            power: PowerHeadroom::default(),
            sr: cfg.sr.iter().map(|s| SrProcedure::new(s, spm)).collect(),
            lcp: Lcp::new(&cfg.logical_channels),
            ta: TimingAdvance::new(cfg.numerology, cfg.time_alignment_timer_ms),
            c_rnti: None,
            tc_rnti: None,
            pending_pusch: BTreeMap::new(),
            pending_cqi: None,
            crnti_ce_pending: false,
            events: Vec::new(),
            ra_start: None,
            ack_book_common_r: None,
            started: false,
            stats: MacStats::default(),
            cfg,
        }
    }

    pub fn stats(&self) -> MacStats {
        self.stats
    }

    pub fn take_events(&mut self) -> Vec<MacEvent> {
        std::mem::take(&mut self.events)
    }

    /// RRC: apply a (re)configuration. Keeps the C-RNTI, HARQ and TA state.
    pub fn reconfigure(&mut self, cfg: MacConfig) {
        let spm = cfg.numerology.slots_per_subframe();
        self.sr = cfg.sr.iter().map(|s| SrProcedure::new(s, spm)).collect();
        self.lcp = Lcp::new(&cfg.logical_channels);
        self.bsr.periodic_slots = cfg.periodic_bsr_ms * spm;
        self.bsr.retx_slots = cfg.retx_bsr_ms * spm;
        self.ta.timer_slots = cfg.time_alignment_timer_ms * spm;
        if cfg.phr != self.cfg.phr {
            self.phr.configure(cfg.phr);
        }
        self.cfg = cfg;
    }

    /// Random-access procedure state (diagnostics).
    pub fn ra_state(&self) -> &RaState {
        &self.ra.state
    }

    /// Time-alignment state (diagnostics).
    pub fn ta_state(&self) -> crate::ta::TaState {
        self.ta.state()
    }

    /// State of every configured SR procedure (diagnostics).
    pub fn sr_states(&self) -> Vec<crate::sr::SrState> {
        self.sr.iter().map(|s| s.state()).collect()
    }

    /// Current C-RNTI, if connected.
    pub fn c_rnti(&self) -> Option<Rnti> {
        self.c_rnti
    }

    /// Power headroom quantities to report (from L1 power control / the stack).
    pub fn set_power_headroom(&mut self, p: PowerHeadroom) {
        self.power = p;
    }

    /// RRC: start a contention-based RA carrying `ccch` (RRCSetupRequest) in Msg3.
    pub fn start_ra(&mut self, ccch: [u8; 6]) {
        self.ra_start = Some(ccch);
    }

    /// RRC: MAC reset (§5.12): back to idle, forget RNTIs and HARQ state.
    pub fn reset(&mut self, phy: &mut dyn MacToPhySink) {
        self.c_rnti = None;
        self.tc_rnti = None;
        self.dl_harq.reset();
        self.ul_harq.reset();
        self.ack_book = AckBook::default();
        self.pending_pusch.clear();
        self.pending_cqi = None;
        self.bsr.cancel();
        self.phr.reset();
        for s in &mut self.sr {
            s.cancel();
        }
        self.ta.reset();
        self.ra = RaProcedure::new(&self.cfg.rach, self.cfg.numerology, 0x5eed);
        phy.send(MacToPhy::TimingAdvance { n_ta_tc: self.ta.n_ta_tc });
        phy.send(MacToPhy::SetRntis { c_rnti: None, tc_rnti: None, ra_rnti: None });
        phy.send(MacToPhy::Stop);
        self.started = false;
    }

    fn send_rntis(&self, phy: &mut dyn MacToPhySink) {
        phy.send(MacToPhy::SetRntis { c_rnti: self.c_rnti, tc_rnti: self.tc_rnti, ra_rnti: self.ra.ra_rnti() });
    }

    // ------------------------------------------------------------------ slots

    fn on_slot(&mut self, now: SlotPoint, phy: &mut dyn MacToPhySink, upper: &mut dyn UpperLayers) {
        if !self.started {
            phy.send(MacToPhy::Start);
            self.started = true;
        }
        self.ack_book.prune(now);
        self.lcp.tick(now);
        let lead = self.cfg.tx_lead_slots as i64;
        self.pending_pusch.retain(|&k, _| SlotPoint::from_index(now.numerology, k).diff(&now) >= -lead);
        // timeAlignmentTimer (§5.2): on expiry flush the HARQ buffers and stop
        // every uplink but the PRACH until a random access re-aligns us.
        if self.ta.on_slot(now) {
            log::warn!("timeAlignmentTimer expired: uplink not aligned");
            self.dl_harq.reset();
            self.ul_harq.reset();
            self.pending_pusch.clear();
            self.ack_book = AckBook::default();
            self.events.push(MacEvent::TimeAlignmentExpired);
        }

        // Start a RA if RRC asked for one.
        if let Some(ccch) = self.ra_start.take() {
            self.ra.start(now, Some(ccch), None);
        }
        // Buffer status → BSR / SR triggers (§5.4.5): one snapshot per slot.
        let with_data: Vec<(u8, Option<u8>)> = self
            .lcp
            .channels()
            .filter(|c| upper.ul_buffer_status(c.lcid) > 0)
            .map(|c| (c.priority, c.sr_id))
            .collect();
        let prios: Vec<u8> = with_data.iter().map(|&(p, _)| p).collect();
        self.bsr.evaluate(now, &prios);
        self.phr.tick(now, self.power.pathloss_db);
        if self.bsr.sr_pending && self.c_rnti.is_some() {
            if self.sr.is_empty() && !self.ra.is_running() {
                // No SR configured: a RA with the C-RNTI (§5.4.4).
                self.ra.start(now, None, self.c_rnti);
                self.crnti_ce_pending = true;
            }
            // §5.4.4: the SR configuration of the logical channel that triggered
            // the BSR (a channel without schedulingRequestID may use any).
            for s in &mut self.sr {
                if with_data.iter().any(|&(_, id)| id.is_none_or(|i| i == s.sr_id)) {
                    s.trigger();
                }
            }
        }
        // SR failure (sr-TransMax) → RA + notify RRC (§5.4.4).
        if self.sr.iter_mut().fold(false, |f, s| s.take_failed() || f) {
            for s in &mut self.sr {
                s.cancel();
            }
            if !self.ra.is_running() {
                self.ra.start(now, None, self.c_rnti);
                self.crnti_ce_pending = true;
            }
            self.events.push(MacEvent::SrFailure);
        }

        // Random access (§5.1).
        let occ_cfg = self.cfg.rach.prach.clone();
        let actions = self.ra.on_slot(now, self.cfg.tx_lead_slots, &|s| occ_cfg.occasions_in_slot(s));
        self.apply_ra_actions(actions, phy);

        // Uplink due in the target slot (§5.2: nothing but PRACH while not
        // time-aligned).
        let target = now.add(self.cfg.tx_lead_slots as u64);
        if self.ta.aligned() {
            self.build_target_slot(target, now, phy);
        }
    }

    fn apply_ra_actions(&mut self, actions: Vec<RaAction>, phy: &mut dyn MacToPhySink) {
        for a in actions {
            match a {
                RaAction::SendPreamble { occasion, preamble, power_offset_db } => {
                    phy.send(MacToPhy::UlTti(UlTtiRequest {
                        slot: occasion.slot,
                        pdus: vec![UlTtiPdu::Prach { occasion, preamble, power_offset_db }],
                    }));
                }
                RaAction::MonitorRaRnti(_) | RaAction::MonitorTcRnti(_) => {
                    if let RaAction::MonitorTcRnti(tc) = a {
                        self.tc_rnti = Some(tc);
                    }
                    self.send_rntis(phy);
                }
                RaAction::Done(Ok(c_rnti)) => {
                    self.c_rnti = Some(c_rnti);
                    self.tc_rnti = None;
                    self.crnti_ce_pending = false;
                    self.send_rntis(phy);
                    self.events.push(MacEvent::RaSucceeded { c_rnti });
                }
                RaAction::Done(Err(())) => {
                    self.tc_rnti = None;
                    self.send_rntis(phy);
                    self.events.push(MacEvent::RaFailed);
                }
            }
        }
    }

    /// Assemble what must be transmitted in `target` (TS 38.213 §9.2.5 UCI
    /// multiplexing: a PUSCH in the slot carries the UCI; else a PUCCH).
    fn build_target_slot(&mut self, target: SlotPoint, now: SlotPoint, phy: &mut dyn MacToPhySink) {
        let pusch = self.pending_pusch.remove(&target.index());
        let has_ack = self.ack_book.has_slot(target);
        let pri = self.ack_book.pri(target).unwrap_or(0);
        // SR occasion?
        let mut sr_res: Option<u8> = None;
        let mut sr_positive = false;
        for s in &mut self.sr {
            if let Some(r) = s.occasion(target) {
                sr_res = Some(r);
                if pusch.is_none() {
                    if let Some(r2) = s.should_send(target) {
                        sr_positive = true;
                        sr_res = Some(r2);
                    }
                }
            }
        }
        // CSI report occasion?
        let csi: Option<(Vec<u8>, u8)> = if self.cfg.csi_enabled {
            self.cfg.csi_reports.iter().find(|c| target.is_occasion(c.period_slots as u32, c.offset_slots as u32)).and_then(|c| {
                let (cqi, when) = self.pending_cqi?;
                // Only report a measurement from the current report period.
                (target.diff(&when) >= 0 && target.diff(&when) < c.period_slots as i64).then(|| (cqi_bits(cqi), c.pucch_resource))
            })
        } else {
            None
        };

        if let Some(mut p) = pusch {
            // UCI on PUSCH: HARQ-ACK sized by the grant's T-DAI, CSI part 1 on a report occasion.
            let ack = if has_ack || p.grant.dai.is_some() { self.ack_book.take(target, p.grant.dai) } else { Vec::new() };
            let csi1 = csi.map(|c| c.0).unwrap_or_default();
            if !csi1.is_empty() {
                self.pending_cqi = None;
            }
            p.tb.truncate(p.tb.len());
            let uci = UciPayload { harq_ack: ack, sr: None, csi1 };
            if p.bsr_included {
                self.bsr.on_bsr_sent(now, p.bsr_truncated);
                for s in &mut self.sr {
                    s.cancel();
                }
            }
            self.stats.ul_tb += 1;
            phy.send(MacToPhy::UlTti(UlTtiRequest { slot: target, pdus: vec![UlTtiPdu::Pusch { grant: p.grant, tb: p.tb, uci }] }));
            return;
        }
        if !has_ack && !sr_positive && csi.is_none() {
            // Nothing else in the slot: a periodic SRS occasion goes out on its
            // own (an SRS overlapping a PUCCH/PUSCH is dropped, TS 38.214 §6.2.1).
            if self.c_rnti.is_some() {
                if let Some(&(id, _, _)) = self.cfg.srs_occasions.iter().find(|(_, p, o)| target.is_occasion(u32::from(*p), u32::from(*o))) {
                    self.stats.srs_sent += 1;
                    phy.send(MacToPhy::UlTti(UlTtiRequest { slot: target, pdus: vec![UlTtiPdu::Srs { resource_id: id }] }));
                }
            }
            return;
        }
        let ack = if has_ack { self.ack_book.take(target, None) } else { Vec::new() };
        let dedicated = !self.cfg.pucch.resources.is_empty();
        let (resource, uci) = if !dedicated {
            // Before a dedicated PUCCH config only the HARQ-ACK on the common resource exists.
            if ack.is_empty() {
                return;
            }
            let r = self.ack_book_common_r.unwrap_or(0);
            (PucchResourceRef::Common { r_pucch: r }, UciPayload { harq_ack: ack, sr: None, csi1: Vec::new() })
        } else {
            self.select_pucch(ack, sr_res, sr_positive, csi, pri)
        };
        if sr_positive {
            self.stats.sr_sent += 1;
        }
        self.stats.pucch_sent += 1;
        phy.send(MacToPhy::UlTti(UlTtiRequest { slot: target, pdus: vec![UlTtiPdu::Pucch { resource, uci }] }));
    }

    /// PUCCH resource selection with dedicated resources (TS 38.213 §9.2.1,
    /// §9.2.3, §9.2.5.1/2).
    fn select_pucch(&mut self, ack: Vec<u8>, sr_res: Option<u8>, sr_positive: bool, csi: Option<(Vec<u8>, u8)>, pri: u8) -> (PucchResourceRef, UciPayload) {
        let n_ack = ack.len();
        let csi_bits = csi.as_ref().map(|c| c.0.clone()).unwrap_or_default();
        let total = n_ack + usize::from(sr_res.is_some()) + csi_bits.len();
        let set_for = |bits: usize| -> Option<&(u8, Vec<u8>, u16)> {
            self.cfg.pucch.resource_sets.iter().find(|(id, _, max)| (*id == 0 && bits <= 2) || (*id != 0 && bits > 2 && bits <= *max as usize))
        };
        if let (0, false, Some(&(_, r))) = (n_ack, sr_positive, csi.as_ref()) {
            // CSI only → the report's resource (F2).
            self.pending_cqi = None;
            return (PucchResourceRef::Dedicated(r), UciPayload { harq_ack: Vec::new(), sr: sr_res.map(|_| false), csi1: csi_bits });
        }
        if n_ack == 0 && sr_positive {
            // SR only → the SR resource.
            return (PucchResourceRef::Dedicated(sr_res.unwrap()), UciPayload { harq_ack: Vec::new(), sr: Some(true), csi1: Vec::new() });
        }
        if n_ack <= 2 && csi.is_none() {
            // ≤2 HARQ-ACK bits: set 0 by PRI; with a positive SR, use the SR's F1
            // resource instead (§9.2.5.1) — the resource choice conveys the SR.
            if sr_positive {
                return (PucchResourceRef::Dedicated(sr_res.unwrap()), UciPayload { harq_ack: ack, sr: Some(true), csi1: Vec::new() });
            }
            let res = set_for(n_ack).and_then(|(_, ids, _)| ids.get(pri as usize).or(ids.last()).copied()).unwrap_or(0);
            return (PucchResourceRef::Dedicated(res), UciPayload { harq_ack: ack, sr: None, csi1: Vec::new() });
        }
        // >2 bits, or HARQ-ACK + CSI: a set-1 (F2) resource by PRI; append SR
        // (if the slot is an SR occasion) and CSI (if simultaneous reporting is allowed).
        let csi1 = if self.cfg.pucch.simultaneous_harq_ack_csi || n_ack == 0 { csi_bits } else { Vec::new() };
        if !csi1.is_empty() {
            self.pending_cqi = None;
        }
        let bits = n_ack + usize::from(sr_res.is_some()) + csi1.len();
        let res = set_for(bits.max(3))
            .and_then(|(_, ids, _)| ids.get(pri as usize).or(ids.last()).copied())
            .or_else(|| csi.as_ref().map(|c| c.1))
            .unwrap_or(0);
        let _ = total;
        (PucchResourceRef::Dedicated(res), UciPayload { harq_ack: ack, sr: sr_res.map(|_| sr_positive), csi1 })
    }

    // ------------------------------------------------------------------- DCI

    fn on_dci(&mut self, slot: SlotPoint, dci: Dci, phy: &mut dyn MacToPhySink, upper: &mut dyn UpperLayers) {
        match dci {
            Dci::Dl(g) => self.on_dl_grant(slot, g),
            Dci::Ul(g) => self.on_ul_grant(slot, g, phy, upper),
            Dci::Other { .. } => {}
        }
        // C-RNTI based RA resolves on any C-RNTI PDCCH (§5.1.5).
        if self.c_rnti.is_some() {
            let acts = self.ra.on_crnti_pdcch();
            self.apply_ra_actions(acts, phy);
        }
    }

    fn on_dl_grant(&mut self, _slot: SlotPoint, g: DlGrant) {
        if !matches!(g.rnti_kind, RntiKind::C | RntiKind::Tc) {
            return; // SI/RA/P: the PHY decodes; nothing to book.
        }
        let (_new, delivered) = self.dl_harq.on_assignment(g.harq_id, g.ndi);
        if let Some(ack_slot) = g.ack_slot {
            self.ack_book_common_r = Some(g.r_pucch_common);
            self.ack_book.book(
                ack_slot,
                AckEntry { rnti: g.rnti, pdsch_slot: g.pdsch_slot, harq_id: g.harq_id, dai: g.dai, ack: delivered.then_some(true), pri: g.pri },
            );
        }
    }

    fn on_ul_grant(&mut self, slot: SlotPoint, g: UlGrant, phy: &mut dyn MacToPhySink, upper: &mut dyn UpperLayers) {
        if g.rnti_kind == RntiKind::Tc && self.ra.msg3_pending() {
            self.send_msg3(g, phy);
            return;
        }
        if g.freq_hopping || !g.ul_sch {
            log::warn!("UL grant with unsupported features (hopping={} ul_sch={}) ignored", g.freq_hopping, g.ul_sch);
            return;
        }
        let tbs_bytes = (g.tbs_bits / 8) as usize;
        let retx = self.ul_harq.is_retx(g.harq_id, g.ndi, g.tbs_bits);
        let (tb, bsr_included, bsr_truncated) = if retx {
            self.stats.ul_retx += 1;
            (self.ul_harq.stored(g.harq_id).to_vec(), false, false)
        } else {
            self.bsr.on_new_data_grant(slot);
            let (tb, inc, trunc) = self.build_ul_pdu(tbs_bytes, slot, upper);
            self.ul_harq.store(g.harq_id, g.ndi, g.tbs_bits, tb.clone());
            (tb, inc, trunc)
        };
        let key = g.pusch_slot.index();
        self.pending_pusch.insert(key, PendingPusch { grant: g, tb, bsr_included, bsr_truncated });
    }

    /// Build a UL-SCH MAC PDU of exactly `tbs` bytes (§5.4.3, §6.1.2): C-RNTI CE,
    /// PHR CE, BSR CE, then MAC SDUs by LCP, then a padding BSR if room, then
    /// padding. (CEs precede SDUs; among them the C-RNTI CE has the highest
    /// priority, §5.4.3.1.3.)
    fn build_ul_pdu(&mut self, tbs: usize, now: SlotPoint, upper: &mut dyn UpperLayers) -> (Vec<u8>, bool, bool) {
        let mut out = Vec::with_capacity(tbs);
        let mut left = tbs;
        if self.crnti_ce_pending {
            if let Some(c) = self.c_rnti {
                if left >= 3 {
                    push_crnti_ce(&mut out, c.0);
                    left -= 3;
                }
            }
        }
        if self.phr.pending && left >= 3 {
            push_single_phr(&mut out, self.power.ph_db, self.power.pcmax_dbm);
            left -= 3;
            self.phr.on_sent(now, self.power.pathloss_db);
            self.stats.phr_sent += 1;
        }
        // Buffer status per LCG.
        let mut lcg_bytes: BTreeMap<u8, usize> = BTreeMap::new();
        for c in self.lcp.channels().copied().collect::<Vec<_>>() {
            let b = upper.ul_buffer_status(c.lcid);
            if b > 0 {
                *lcg_bytes.entry(c.lcg).or_default() += b;
            }
        }
        let bsr_due = self.bsr.pending != crate::bsr::BsrTrigger::None;
        let n_lcg = lcg_bytes.len();
        let bsr_size = if n_lcg > 1 { 2 + 1 + n_lcg } else { 2 };
        let reserve_bsr = bsr_due && left >= bsr_size;
        let mut bsr_included = false;
        let mut bsr_truncated = false;
        let budget = if reserve_bsr { left - bsr_size } else { left };
        // LCP over the budget (subheaders counted per SDU as 2/3 bytes).
        let alloc = self.lcp.allocate(budget.saturating_sub(2), &mut |lcid| upper.ul_buffer_status(lcid));
        for (lcid, bytes) in alloc {
            let room = left.saturating_sub(if reserve_bsr { bsr_size } else { 0 });
            if room < 3 {
                break;
            }
            let max = bytes.min(room - if bytes >= 254 { 3 } else { 2 });
            if let Some(pdu) = upper.ul_pull(lcid, max, now) {
                let cost = sdu_subpdu_len(pdu.len());
                if cost > room {
                    break;
                }
                push_sdu_subpdu(&mut out, lcid, &pdu);
                left -= cost;
            }
        }
        // BSR (regular/periodic, or padding BSR when ≥ the CE size remains).
        // Bytes per LCG and the best (lowest) channel priority in each LCG.
        let mut remaining: BTreeMap<u8, usize> = BTreeMap::new();
        let mut lcg_priority: BTreeMap<u8, u8> = BTreeMap::new();
        for c in self.lcp.channels().copied().collect::<Vec<_>>() {
            let b = upper.ul_buffer_status(c.lcid);
            if b > 0 {
                *remaining.entry(c.lcg).or_default() += b;
                let p = lcg_priority.entry(c.lcg).or_insert(u8::MAX);
                *p = (*p).min(c.priority);
            }
        }
        let any_left = remaining.values().any(|&b| b > 0);
        if left >= 2 && (bsr_due || any_left) {
            let entries: Vec<(u8, usize)> = remaining.iter().map(|(&l, &b)| (l, b)).collect();
            if entries.len() <= 1 {
                let (lcg, b) = entries.first().copied().unwrap_or((0, 0));
                push_short_bsr(&mut out, lcg, b, false);
            } else if left >= 3 + entries.len() {
                push_long_bsr(&mut out, &entries, false);
            } else {
                // Not enough room for the long BSR (§5.4.5): a Short Truncated BSR
                // for the LCG holding the highest-priority channel with data.
                let (lcg, b) = *entries.iter().min_by_key(|(l, _)| lcg_priority.get(l).copied().unwrap_or(u8::MAX)).unwrap_or(&entries[0]);
                push_short_bsr(&mut out, lcg, b, true);
                bsr_truncated = true;
            }
            bsr_included = true;
        }
        pad_to(&mut out, tbs);
        out.truncate(tbs);
        (out, bsr_included, bsr_truncated)
    }

    // --------------------------------------------------------------- RX data

    fn on_rx_data(&mut self, d: RxDataIndication, phy: &mut dyn MacToPhySink, upper: &mut dyn UpperLayers) {
        let ok = d.tb.is_some();
        if ok {
            self.stats.dl_tb_ok += 1;
        } else {
            self.stats.dl_tb_ko += 1;
        }
        match d.rnti_kind {
            RntiKind::Si => {
                if let Some(tb) = d.tb {
                    self.events.push(MacEvent::Bcch(tb));
                }
            }
            RntiKind::Ra => {
                let Some(tb) = d.tb else { return };
                if let Some(rar) = parse_rar_pdu(&tb) {
                    if let Some((rar, actions)) = self.ra.on_rar(&rar) {
                        self.apply_ra_actions(actions, phy);
                        self.ta.apply_rar(rar.ta, d.pdsch_slot);
                        phy.send(MacToPhy::TimingAdvance { n_ta_tc: self.ta.n_ta_tc });
                        // The PHY owns the PUSCH configuration: it resolves the RAR
                        // UL grant (TS 38.213 §8.2 / §8.3) and answers with a
                        // TC-RNTI UL grant that `on_ul_grant` turns into Msg3.
                        phy.send(MacToPhy::RarGrant { rar_slot: d.pdsch_slot, tc_rnti: Rnti(rar.tc_rnti), grant: rar.grant });
                    }
                }
            }
            RntiKind::Tc | RntiKind::C => {
                if !self.ack_book.set_result(d.pdsch_slot, d.harq_id, ok) {
                    self.stats.ack_late += 1;
                    log::debug!("HARQ-ACK for PDSCH {} harq {} arrived after its PUCCH was requested (ok={ok})", d.pdsch_slot, d.harq_id);
                }
                let Some(tb) = d.tb else { return };
                if self.dl_harq.is_delivered(d.harq_id) {
                    // A retransmission of a TB already handed up (§5.3.2.2).
                    return;
                }
                self.dl_harq.mark_delivered(d.harq_id);
                for sub in parse_dl_pdu(&tb) {
                    match sub {
                        DlSubPdu::Sdu { lcid, sdu } => {
                            if lcid == crate::LCID_DL_CCCH {
                                self.events.push(MacEvent::Ccch(sdu));
                            } else {
                                upper.dl_sdu(lcid, &sdu, d.pdsch_slot);
                            }
                        }
                        DlSubPdu::TaCommand { ta, .. } => {
                            self.ta.apply_ce(ta, d.pdsch_slot);
                            phy.send(MacToPhy::TimingAdvance { n_ta_tc: self.ta.n_ta_tc });
                        }
                        DlSubPdu::ContentionResolution(id) => {
                            let acts = self.ra.on_contention_resolution_id(&id);
                            self.apply_ra_actions(acts, phy);
                        }
                        DlSubPdu::DrxCommand | DlSubPdu::LongDrxCommand | DlSubPdu::Other { .. } => {}
                    }
                }
            }
            RntiKind::P => {
                if let Some(tb) = d.tb {
                    // The paging PDSCH carries one PCCH SDU in a MAC PDU with a
                    // single subPDU (§6.1.5: no header), as for BCCH.
                    self.events.push(MacEvent::Pcch(tb));
                }
            }
        }
    }

    /// Msg3 (§5.1.4 / §5.4.2.2): the CCCH SDU (or the C-RNTI CE for a C-RNTI
    /// RA) on the Msg3 grant the PHY resolved from the RAR.
    fn send_msg3(&mut self, grant: UlGrant, phy: &mut dyn MacToPhySink) {
        let tbs_bits = grant.tbs_bits;
        let tbs = (tbs_bits / 8) as usize;
        let mut tb = Vec::with_capacity(tbs);
        if let Some(ccch) = self.ra.msg3_ccch {
            push_ccch(&mut tb, &ccch);
        } else if let Some(c) = self.c_rnti {
            push_crnti_ce(&mut tb, c.0);
            self.crnti_ce_pending = false;
        }
        pad_to(&mut tb, tbs);
        tb.truncate(tbs);
        // Msg3 uses HARQ process 0 with NDI 0; a DCI 0_0 with the TC-RNTI and
        // NDI 0 is then a retransmission request (§5.4.2.1).
        self.ul_harq.store(0, 0, tbs_bits, tb.clone());
        self.ra.on_msg3_scheduled(grant.pusch_slot);
        self.stats.ul_tb += 1;
        phy.send(MacToPhy::UlTti(UlTtiRequest { slot: grant.pusch_slot, pdus: vec![UlTtiPdu::Pusch { grant, tb, uci: UciPayload::default() }] }));
    }
}

/// 4-bit wideband CQI, MSB first.
fn cqi_bits(cqi: u8) -> Vec<u8> {
    vec![(cqi >> 3) & 1, (cqi >> 2) & 1, (cqi >> 1) & 1, cqi & 1]
}

impl MacEntity {
    /// Handle one PHY → MAC message with access to the RLC bearers.
    pub fn handle_with(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink, upper: &mut dyn UpperLayers) {
        match msg {
            PhyToMac::Slot(s) => self.on_slot(s.slot, phy, upper),
            PhyToMac::Dci(d) => self.on_dci(d.slot, d.dci, phy, upper),
            PhyToMac::RxData(d) => self.on_rx_data(d, phy, upper),
            PhyToMac::Csi(c) => self.pending_cqi = Some((c.cqi, c.slot)),
            PhyToMac::Rach(r) => {
                let acts = self.ra.on_prach_sent(r.slot);
                self.apply_ra_actions(acts, phy);
            }
            PhyToMac::Error(e) => match e {
                ErrorIndication::TxDropped { slot, pdu } => log::warn!("PHY dropped {pdu} for slot {slot}"),
                ErrorIndication::SyncLost | ErrorIndication::Radio => self.events.push(MacEvent::RadioLinkFailure),
            },
        }
    }
}
