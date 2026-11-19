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
use crate::phr::PhrProcedure;
use crate::power::{PucchShape, UlPowerControl};
use crate::{
    harq::*, lcp::Lcp, ra::*, rar::parse_rar_pdu, sr::SrProcedure, ta::TimingAdvance, MacConfig,
};
use ferrite_common::{Rnti, RntiKind, SlotPoint};
use ferrite_fapi::*;
use std::collections::BTreeMap;

/// Events MAC reports to RRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacEvent {
    RaSucceeded {
        c_rnti: Rnti,
    },
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
    /// Radio link monitoring indication from the PHY (TS 38.331 §5.3.10:
    /// RRC counts N310 / N311 and runs T310).
    Sync {
        in_sync: bool,
    },
    /// Switch the active bandwidth part (§5.15): a DCI bandwidth-part
    /// indicator, the bwp-InactivityTimer expiry (to the default BWP) or a
    /// random access started on a BWP without PRACH (to the initial BWP).
    /// RRC applies the BWP's configuration with a CONFIG.request.
    BwpSwitch {
        dl_bwp: Option<u8>,
        ul_bwp: Option<u8>,
    },
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
    /// Uplink power control (TS 38.213 §7): loop states and the pathloss.
    power: UlPowerControl,
    sr: Vec<SrProcedure>,
    lcp: Lcp,
    ta: TimingAdvance,
    drx: crate::drx::Drx,
    /// bwp-InactivityTimer expiry (§5.15); `bwp_timer_arm` starts it at the
    /// next slot after a (re)configuration onto a non-default BWP.
    bwp_inactivity_until: Option<SlotPoint>,
    bwp_timer_arm: bool,
    c_rnti: Option<Rnti>,
    tc_rnti: Option<Rnti>,
    pending_pusch: BTreeMap<u64, PendingPusch>,
    /// Latest CSI measurement and the slot it was taken in.
    latest_csi: Option<(CsiValues, SlotPoint)>,
    /// Rank and PMI from the latest multi-port CSI-RS measurement; a
    /// single-port (TRS) measurement updates the CQI but keeps these.
    csi_rank: Option<(u8, Pmi)>,
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
    /// Slots outside DRX Active Time (no C-RNTI PDCCH monitoring).
    pub drx_sleep_slots: u64,
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
            power: UlPowerControl::new(cfg.power.clone()),
            sr: cfg.sr.iter().map(|s| SrProcedure::new(s, spm)).collect(),
            lcp: Lcp::new(&cfg.logical_channels),
            ta: TimingAdvance::new(cfg.numerology, cfg.time_alignment_timer_ms),
            drx: crate::drx::Drx::new(cfg.drx),
            bwp_inactivity_until: None,
            bwp_timer_arm: cfg.bwp_inactivity_timer_ms.is_some()
                && cfg.dl_bwp_id != cfg.default_dl_bwp_id,
            c_rnti: None,
            tc_rnti: None,
            pending_pusch: BTreeMap::new(),
            latest_csi: None,
            csi_rank: None,
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
        if cfg.power != self.cfg.power {
            self.power.reconfigure(cfg.power.clone());
        }
        if cfg.phr != self.cfg.phr {
            self.phr.configure(cfg.phr);
        }
        if cfg.drx != self.cfg.drx {
            self.drx.configure(cfg.drx);
        }
        // §5.15: the bwp-InactivityTimer runs while a non-default BWP is active.
        self.bwp_inactivity_until = None;
        self.bwp_timer_arm =
            cfg.bwp_inactivity_timer_ms.is_some() && cfg.dl_bwp_id != cfg.default_dl_bwp_id;
        self.cfg = cfg;
    }

    /// §5.15: (re)start the bwp-InactivityTimer on a PDCCH addressed to the
    /// C-RNTI (DL assignment or UL grant) on the active BWP.
    fn restart_bwp_timer(&mut self, now: SlotPoint) {
        if let Some(ms) = self.cfg.bwp_inactivity_timer_ms {
            if self.cfg.dl_bwp_id != self.cfg.default_dl_bwp_id {
                self.bwp_inactivity_until = Some(now.add(u64::from(self.cfg.ms_to_slots(ms))));
            }
        }
    }

    /// DRX state (diagnostics).
    pub fn drx_state(&self) -> crate::drx::DrxState {
        self.drx.state()
    }

    /// Random-access procedure state (diagnostics).
    pub fn ra_state(&self) -> &RaState {
        self.ra.state()
    }

    /// RA transitions made and refused (see [`crate::ra::RaMachine`]).
    pub fn ra_fsm_stats(&self) -> ferrite_common::fsm::FsmStats {
        self.ra.fsm_stats()
    }

    /// Transitions made and refused across the MAC machines (RA, SR, TA,
    /// DRX): a refusal is a bug in the entity or a table.
    pub fn fsm_stats(&self) -> ferrite_common::fsm::FsmStats {
        let mut t = ferrite_common::fsm::FsmStats::default();
        let parts = [
            self.ra.fsm_stats(),
            self.ta.fsm_stats(),
            self.drx.fsm_stats(),
            self.dl_harq.fsm_stats(),
            self.ul_harq.fsm_stats(),
        ]
        .into_iter()
        .chain(self.sr.iter().map(|s| s.fsm_stats()));
        for p in parts {
            t.transitions += p.transitions;
            t.violations += p.violations;
        }
        t
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
    /// A serving-cell SS-RSRP in dBm for the pathloss estimate.
    pub fn on_rsrp_dbm(&mut self, rsrp_dbm: f32) {
        self.power.on_rsrp_dbm(rsrp_dbm);
    }

    /// The power-control state (for tests and reporting).
    pub fn power_control(&self) -> &UlPowerControl {
        &self.power
    }

    /// PUCCH shape for `Δ_TF`: dedicated resources from the configuration, the
    /// common resource from its table row.
    fn pucch_shape(&self, resource: PucchResourceRef, uci: &UciPayload) -> PucchShape {
        let uci_bits = (uci.harq_ack.len() + usize::from(uci.sr.is_some()) + uci.csi1.len()) as u32;
        match resource {
            PucchResourceRef::Dedicated(id) => {
                self.cfg.pucch.shapes.iter().find(|s| s.0 == id).map_or(
                    PucchShape {
                        format: 1,
                        n_rb: 1,
                        n_symbols: 14,
                        uci_bits,
                    },
                    |&(_, format, n_symbols, n_rb)| PucchShape {
                        format,
                        n_rb: u32::from(n_rb),
                        n_symbols: u32::from(n_symbols),
                        uci_bits,
                    },
                )
            }
            PucchResourceRef::Common { .. } => {
                let (format, n_symbols) = self.cfg.pucch.common_shape;
                PucchShape {
                    format,
                    n_rb: 1,
                    n_symbols: u32::from(n_symbols),
                    uci_bits,
                }
            }
        }
    }

    /// RRC: start a contention-based RA carrying `ccch` (RRCSetupRequest) in Msg3.
    pub fn start_ra(&mut self, ccch: [u8; 6]) {
        self.ra_start = Some(ccch);
    }

    /// §5.15: a random access on a BWP without PRACH occasions switches to the
    /// initial BWP first (only the initial UL BWP carries the cell's PRACH).
    fn ensure_initial_bwp_for_ra(&mut self) {
        if self.cfg.dl_bwp_id != 0 {
            self.events.push(MacEvent::BwpSwitch {
                dl_bwp: Some(0),
                ul_bwp: Some(0),
            });
        }
    }

    /// RRC: MAC reset (§5.12): back to idle, forget RNTIs and HARQ state.
    pub fn reset(&mut self, phy: &mut dyn MacToPhySink) {
        self.c_rnti = None;
        self.tc_rnti = None;
        self.dl_harq.reset();
        self.ul_harq.reset();
        self.ack_book = AckBook::default();
        self.pending_pusch.clear();
        self.latest_csi = None;
        self.csi_rank = None;
        self.bsr.cancel();
        self.phr.reset();
        for s in &mut self.sr {
            s.reset();
        }
        self.ta.reset();
        self.drx.reset();
        self.ra = RaProcedure::new(&self.cfg.rach, self.cfg.numerology, 0x5eed);
        phy.send(MacToPhy::PdcchMonitoring { c_rnti: true });
        phy.send(MacToPhy::TimingAdvance {
            n_ta_tc: self.ta.n_ta_tc,
        });
        phy.send(MacToPhy::SetRntis {
            c_rnti: None,
            tc_rnti: None,
            ra_rnti: None,
        });
        phy.send(MacToPhy::Stop);
        self.started = false;
    }

    fn send_rntis(&self, phy: &mut dyn MacToPhySink) {
        phy.send(MacToPhy::SetRntis {
            c_rnti: self.c_rnti,
            tc_rnti: self.tc_rnti,
            ra_rnti: self.ra.ra_rnti(),
        });
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
        self.pending_pusch
            .retain(|&k, _| SlotPoint::from_index(now.numerology, k).diff(&now) >= -lead);
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
            self.ensure_initial_bwp_for_ra();
            self.ra.start(now, Some(ccch), None);
        }
        // bwp-InactivityTimer (§5.15): stopped during a random access, expiry
        // switches back to the default BWP.
        if self.bwp_timer_arm {
            self.bwp_timer_arm = false;
            self.restart_bwp_timer(now);
        }
        if self.ra.is_running() {
            self.bwp_inactivity_until = None;
        } else if self.bwp_inactivity_until.is_some_and(|t| now.diff(&t) >= 0) {
            self.bwp_inactivity_until = None;
            log::info!(
                "bwp-InactivityTimer expired: back to the default BWP {}",
                self.cfg.default_dl_bwp_id
            );
            self.events.push(MacEvent::BwpSwitch {
                dl_bwp: Some(self.cfg.default_dl_bwp_id),
                ul_bwp: Some(self.cfg.default_dl_bwp_id),
            });
        }
        // DRX (§5.7): Active Time decides whether the PHY monitors the C-RNTI
        // PDCCH candidates in this slot (and whether CSI / SRS go out).
        let was_active = self.drx.is_active();
        let sr_pending = self
            .sr
            .iter()
            .any(|s| matches!(s.state(), crate::sr::SrState::Pending { .. }));
        let dl_harq = &self.dl_harq;
        let active = self
            .drx
            .on_slot(now, self.ra.is_running(), sr_pending, |h| {
                !dl_harq.is_delivered(h)
            });
        if active != was_active {
            log::debug!("DRX: {} at {now}", if active { "active" } else { "sleep" });
            phy.send(MacToPhy::PdcchMonitoring { c_rnti: active });
        }
        if !active {
            self.stats.drx_sleep_slots += 1;
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
        self.phr.tick(now, self.power.pathloss_db());
        if self.bsr.sr_pending && self.c_rnti.is_some() {
            if self.sr.is_empty() && !self.ra.is_running() {
                // No SR configured: a RA with the C-RNTI (§5.4.4).
                self.ensure_initial_bwp_for_ra();
                self.ra.start(now, None, self.c_rnti);
                self.crnti_ce_pending = true;
            }
            // §5.4.4: the SR configuration of the logical channel that triggered
            // the BSR (a channel without schedulingRequestID may use any).
            for s in &mut self.sr {
                if with_data
                    .iter()
                    .any(|&(_, id)| id.is_none_or(|i| i == s.sr_id))
                {
                    s.trigger();
                }
            }
        }
        // SR failure (sr-TransMax) → RA + notify RRC (§5.4.4).
        // Every configuration's flag must be consumed, so no short-circuit.
        let sr_failed = self
            .sr
            .iter_mut()
            .map(|s| s.take_failed())
            .filter(|&f| f)
            .count()
            > 0;
        if sr_failed {
            for s in &mut self.sr {
                s.cancel();
            }
            if !self.ra.is_running() {
                self.ensure_initial_bwp_for_ra();
                self.ra.start(now, None, self.c_rnti);
                self.crnti_ce_pending = true;
            }
            self.events.push(MacEvent::SrFailure);
        }

        // Random access (§5.1).
        let occ_cfg = self.cfg.rach.prach.clone();
        let actions = self.ra.on_slot(now, self.cfg.tx_lead_slots, &|s| {
            occ_cfg.occasions_in_slot(s)
        });
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
                RaAction::SendPreamble {
                    occasion,
                    preamble,
                    power_offset_db: _,
                } => {
                    let power_dbm = self.power.prach_dbm(self.ra.preamble_power_ramping_counter);
                    if let Some(p) = power_dbm {
                        log::debug!(
                            "UL power: PRACH attempt {} → {p:.1} dBm (PL {:.1} dB)",
                            self.ra.preamble_power_ramping_counter,
                            self.power.pathloss_db()
                        );
                    }
                    phy.send(MacToPhy::UlTti(UlTtiRequest {
                        slot: occasion.slot,
                        pdus: vec![UlTtiPdu::Prach {
                            occasion,
                            preamble,
                            power_dbm,
                        }],
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
        // CSI report occasion? Not outside DRX Active Time (§5.7).
        // Every configured occasion carries a report (the gNB decodes one there
        // whatever we do; leaving it out of a PUSCH breaks that PUSCH's data):
        // the latest measurement, which by the time the slot is built may be
        // older than the CSI-RS just before it (the CSI reference resource is
        // ≥ 4·2^μ slots before the report anyway, TS 38.214 §5.2.2.5), or
        // CQI 0 ("out of range") before the first one.
        let csi: Option<(Vec<u8>, u8)> = if self.cfg.csi_enabled && self.drx.is_active() {
            let v = self.latest_csi.map_or(
                CsiValues {
                    cqi: 0,
                    ri: 1,
                    pmi: Pmi::default(),
                },
                |(v, _)| v,
            );
            self.cfg
                .csi_reports
                .iter()
                .find(|c| target.is_occasion(c.period_slots as u32, c.offset_slots as u32))
                .map(|c| (csi_report_bits(c, v), c.pucch_resource))
        } else {
            None
        };

        if let Some(mut p) = pusch {
            // UCI on PUSCH: HARQ-ACK sized by the grant's T-DAI, CSI part 1 on a report occasion.
            let ack = if has_ack || p.grant.dai.is_some() {
                self.ack_book.take(target, p.grant.dai)
            } else {
                Vec::new()
            };
            let csi1 = csi.map(|c| c.0).unwrap_or_default();
            p.tb.truncate(p.tb.len());
            let uci = UciPayload {
                harq_ack: ack,
                sr: None,
                csi1,
            };
            if p.bsr_included {
                self.bsr.on_bsr_sent(now, p.bsr_truncated);
                for s in &mut self.sr {
                    s.cancel();
                }
            }
            self.stats.ul_tb += 1;
            let power_dbm = self.power.pusch_dbm(u32::from(p.grant.n_prb), false);
            if let Some(pw) = power_dbm {
                log::debug!(
                    "UL power: PUSCH {} RB → {pw:.1} dBm (PL {:.1} dB, f {:.0} dB)",
                    p.grant.n_prb,
                    self.power.pathloss_db(),
                    self.power.f_pusch_db()
                );
            }
            phy.send(MacToPhy::UlTti(UlTtiRequest {
                slot: target,
                pdus: vec![UlTtiPdu::Pusch {
                    grant: p.grant,
                    tb: p.tb,
                    uci,
                    power_dbm,
                }],
            }));
            return;
        }
        if !has_ack && !sr_positive && csi.is_none() {
            // Nothing else in the slot: a periodic SRS occasion goes out on its
            // own (an SRS overlapping a PUCCH/PUSCH is dropped, TS 38.214 §6.2.1);
            // outside DRX Active Time only if configured to (§5.7 says no; see
            // `MacConfig::srs_outside_active_time`).
            if self.c_rnti.is_some() && (self.drx.is_active() || self.cfg.srs_outside_active_time) {
                if let Some(&(id, _, _, n_rb)) = self
                    .cfg
                    .srs_occasions
                    .iter()
                    .find(|(_, p, o, _)| target.is_occasion(u32::from(*p), u32::from(*o)))
                {
                    self.stats.srs_sent += 1;
                    let power_dbm = self.power.srs_dbm(u32::from(n_rb));
                    phy.send(MacToPhy::UlTti(UlTtiRequest {
                        slot: target,
                        pdus: vec![UlTtiPdu::Srs {
                            resource_id: id,
                            power_dbm,
                        }],
                    }));
                }
            }
            return;
        }
        let ack = if has_ack {
            self.ack_book.take(target, None)
        } else {
            Vec::new()
        };
        let dedicated = !self.cfg.pucch.resources.is_empty();
        let (resource, uci) = if !dedicated {
            // Before a dedicated PUCCH config only the HARQ-ACK on the common resource exists.
            if ack.is_empty() {
                return;
            }
            let r = self.ack_book_common_r.unwrap_or(0);
            (
                PucchResourceRef::Common { r_pucch: r },
                UciPayload {
                    harq_ack: ack,
                    sr: None,
                    csi1: Vec::new(),
                },
            )
        } else {
            self.select_pucch(ack, sr_res, sr_positive, csi, pri)
        };
        if sr_positive {
            self.stats.sr_sent += 1;
        }
        self.stats.pucch_sent += 1;
        let power_dbm = self.power.pucch_dbm(self.pucch_shape(resource, &uci));
        phy.send(MacToPhy::UlTti(UlTtiRequest {
            slot: target,
            pdus: vec![UlTtiPdu::Pucch {
                resource,
                uci,
                power_dbm,
            }],
        }));
    }

    /// PUCCH resource selection with dedicated resources (TS 38.213 §9.2.1,
    /// §9.2.3, §9.2.5.1/2).
    fn select_pucch(
        &mut self,
        ack: Vec<u8>,
        sr_res: Option<u8>,
        sr_positive: bool,
        csi: Option<(Vec<u8>, u8)>,
        pri: u8,
    ) -> (PucchResourceRef, UciPayload) {
        let n_ack = ack.len();
        let csi_bits = csi.as_ref().map(|c| c.0.clone()).unwrap_or_default();
        let total = n_ack + usize::from(sr_res.is_some()) + csi_bits.len();
        let set_for = |bits: usize| -> Option<&(u8, Vec<u8>, u16)> {
            self.cfg.pucch.resource_sets.iter().find(|(id, _, max)| {
                (*id == 0 && bits <= 2) || (*id != 0 && bits > 2 && bits <= *max as usize)
            })
        };
        if let (0, false, Some(&(_, r))) = (n_ack, sr_positive, csi.as_ref()) {
            // CSI only → the report's resource (F2).
            return (
                PucchResourceRef::Dedicated(r),
                UciPayload {
                    harq_ack: Vec::new(),
                    sr: sr_res.map(|_| false),
                    csi1: csi_bits,
                },
            );
        }
        if let (0, true, Some(r)) = (n_ack, sr_positive, sr_res) {
            // SR only → the SR resource.
            return (
                PucchResourceRef::Dedicated(r),
                UciPayload {
                    harq_ack: Vec::new(),
                    sr: Some(true),
                    csi1: Vec::new(),
                },
            );
        }
        if n_ack <= 2 && csi.is_none() {
            // ≤2 HARQ-ACK bits: set 0 by PRI; with a positive SR, use the SR's F1
            // resource instead (§9.2.5.1) — the resource choice conveys the SR.
            if let (true, Some(r)) = (sr_positive, sr_res) {
                return (
                    PucchResourceRef::Dedicated(r),
                    UciPayload {
                        harq_ack: ack,
                        sr: Some(true),
                        csi1: Vec::new(),
                    },
                );
            }
            let res = set_for(n_ack)
                .and_then(|(_, ids, _)| ids.get(pri as usize).or(ids.last()).copied())
                .unwrap_or(0);
            return (
                PucchResourceRef::Dedicated(res),
                UciPayload {
                    harq_ack: ack,
                    sr: None,
                    csi1: Vec::new(),
                },
            );
        }
        // >2 bits, or HARQ-ACK + CSI: a set-1 (F2) resource by PRI; append SR
        // (if the slot is an SR occasion) and CSI (if simultaneous reporting is allowed).
        let csi1 = if self.cfg.pucch.simultaneous_harq_ack_csi || n_ack == 0 {
            csi_bits
        } else {
            Vec::new()
        };
        let bits = n_ack + usize::from(sr_res.is_some()) + csi1.len();
        let res = set_for(bits.max(3))
            .and_then(|(_, ids, _)| ids.get(pri as usize).or(ids.last()).copied())
            .or_else(|| csi.as_ref().map(|c| c.1))
            .unwrap_or(0);
        let _ = total;
        (
            PucchResourceRef::Dedicated(res),
            UciPayload {
                harq_ack: ack,
                sr: sr_res.map(|_| sr_positive),
                csi1,
            },
        )
    }

    // ------------------------------------------------------------------- DCI

    fn on_dci(
        &mut self,
        slot: SlotPoint,
        dci: Dci,
        phy: &mut dyn MacToPhySink,
        upper: &mut dyn UpperLayers,
    ) {
        match dci {
            Dci::Dl(g) => self.on_dl_grant(slot, g),
            Dci::Ul(g) => self.on_ul_grant(slot, g, phy, upper),
            Dci::Other { .. } => {}
            Dci::BwpSwitch { dl_bwp, ul_bwp } => {
                log::info!("DCI bandwidth-part indicator: switching to DL BWP {dl_bwp:?} / UL BWP {ul_bwp:?}");
                self.events.push(MacEvent::BwpSwitch { dl_bwp, ul_bwp });
            }
        }
        // C-RNTI based RA resolves on any C-RNTI PDCCH (§5.1.5).
        if self.c_rnti.is_some() {
            let acts = self.ra.on_crnti_pdcch();
            self.apply_ra_actions(acts, phy);
        }
    }

    fn on_dl_grant(&mut self, slot: SlotPoint, g: DlGrant) {
        if !matches!(g.rnti_kind, RntiKind::C | RntiKind::Tc) {
            return; // SI/RA/P: the PHY decodes; nothing to book.
        }
        // The DCI's TPC steers the PUCCH loop (TS 38.213 §7.2.1).
        self.power.on_pucch_tpc(g.tpc);
        let (_new, delivered) = self.dl_harq.on_assignment(g.harq_id, g.ndi);
        if g.rnti_kind == RntiKind::C {
            self.drx.on_crnti_pdcch(slot);
            self.restart_bwp_timer(slot);
            if let Some(ack_slot) = g.ack_slot {
                self.drx.on_dl_assignment(g.harq_id, ack_slot);
            }
        }
        if let Some(ack_slot) = g.ack_slot {
            self.ack_book_common_r = Some(g.r_pucch_common);
            self.ack_book.book(
                ack_slot,
                AckEntry {
                    rnti: g.rnti,
                    pdsch_slot: g.pdsch_slot,
                    harq_id: g.harq_id,
                    dai: g.dai,
                    ack: delivered.then_some(true),
                    pri: g.pri,
                },
            );
        }
    }

    fn on_ul_grant(
        &mut self,
        slot: SlotPoint,
        g: UlGrant,
        phy: &mut dyn MacToPhySink,
        upper: &mut dyn UpperLayers,
    ) {
        if g.rnti_kind == RntiKind::Tc && self.ra.msg3_pending() {
            // The RAR grant: `f(0)` comes from the ramp and the RAR TPC, set
            // when the RAR was parsed.
            self.send_msg3(g, phy);
            return;
        }
        if g.freq_hopping || !g.ul_sch {
            log::warn!(
                "UL grant with unsupported features (hopping={} ul_sch={}) ignored",
                g.freq_hopping,
                g.ul_sch
            );
            return;
        }
        let tbs_bytes = (g.tbs_bits / 8) as usize;
        let retx = self.ul_harq.is_retx(g.harq_id, g.ndi, g.tbs_bits);
        // A UL DCI's TPC (Table 7.1.1-1) for the PUSCH loop (TS 38.213 §7.1.1).
        if matches!(g.rnti_kind, RntiKind::C | RntiKind::Tc) {
            self.power.on_pusch_tpc(g.tpc);
        }
        if g.rnti_kind == RntiKind::C {
            self.drx.on_crnti_pdcch(slot);
            self.drx.on_ul_grant(g.harq_id, g.pusch_slot);
            self.restart_bwp_timer(slot);
        }
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
        self.pending_pusch.insert(
            key,
            PendingPusch {
                grant: g,
                tb,
                bsr_included,
                bsr_truncated,
            },
        );
    }

    /// Build a UL-SCH MAC PDU of exactly `tbs` bytes (§5.4.3, §6.1.2). Room is
    /// given in LCP priority order (§5.4.3.1.3: C-RNTI CE, PHR CE, the BSR's
    /// reservation, then MAC SDUs), but the layout is the UL one of §6.1.2:
    /// MAC SDUs first, then the CEs (C-RNTI, PHR, BSR), then padding.
    fn build_ul_pdu(
        &mut self,
        tbs: usize,
        now: SlotPoint,
        upper: &mut dyn UpperLayers,
    ) -> (Vec<u8>, bool, bool) {
        let mut out = Vec::with_capacity(tbs);
        // CEs other than the BSR: room taken now, placed after the SDUs.
        let mut ces = Vec::new();
        let mut left = tbs;
        if self.crnti_ce_pending {
            if let Some(c) = self.c_rnti {
                if left >= 3 {
                    push_crnti_ce(&mut ces, c.0);
                    left -= 3;
                }
            }
        }
        if self.phr.pending && left >= 3 {
            // Type 1 PH for the virtual reference PUSCH (TS 38.213 §7.7.1).
            let ph = self.power.headroom(None);
            push_single_phr(&mut ces, ph.ph_db, ph.pcmax_dbm);
            left -= 3;
            self.phr.on_sent(now, ph.pathloss_db);
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
        let alloc = self.lcp.allocate(budget.saturating_sub(2), &mut |lcid| {
            upper.ul_buffer_status(lcid)
        });
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
        // §6.1.2: UL MAC CEs follow the MAC SDUs.
        out.extend_from_slice(&ces);
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
                let (lcg, b) = *entries
                    .iter()
                    .min_by_key(|(l, _)| lcg_priority.get(l).copied().unwrap_or(u8::MAX))
                    .unwrap_or(&entries[0]);
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

    fn on_rx_data(
        &mut self,
        d: RxDataIndication,
        phy: &mut dyn MacToPhySink,
        upper: &mut dyn UpperLayers,
    ) {
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
                        // f(0) = g(0) = ΔP_rampup + δ_msg2 (TS 38.213 §7.1.1, §7.2.1).
                        self.power
                            .on_rar(self.ra.preamble_power_ramping_counter, rar.grant.tpc);
                        self.apply_ra_actions(actions, phy);
                        self.ta.apply_rar(rar.ta, d.pdsch_slot);
                        phy.send(MacToPhy::TimingAdvance {
                            n_ta_tc: self.ta.n_ta_tc,
                        });
                        // The PHY owns the PUSCH configuration: it resolves the RAR
                        // UL grant (TS 38.213 §8.2 / §8.3) and answers with a
                        // TC-RNTI UL grant that `on_ul_grant` turns into Msg3.
                        phy.send(MacToPhy::RarGrant {
                            rar_slot: d.pdsch_slot,
                            tc_rnti: Rnti(rar.tc_rnti),
                            grant: rar.grant,
                        });
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
                            phy.send(MacToPhy::TimingAdvance {
                                n_ta_tc: self.ta.n_ta_tc,
                            });
                        }
                        DlSubPdu::ContentionResolution(id) => {
                            let acts = self.ra.on_contention_resolution_id(&id);
                            self.apply_ra_actions(acts, phy);
                        }
                        DlSubPdu::DrxCommand => self.drx.on_drx_command(d.pdsch_slot, false),
                        DlSubPdu::LongDrxCommand => self.drx.on_drx_command(d.pdsch_slot, true),
                        DlSubPdu::Other { .. } => {}
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
            // A 48-bit SDU by type: always a valid CCCH length.
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
        let power_dbm = self.power.pusch_dbm(u32::from(grant.n_prb), true);
        phy.send(MacToPhy::UlTti(UlTtiRequest {
            slot: grant.pusch_slot,
            pdus: vec![UlTtiPdu::Pusch {
                grant,
                tb,
                uci: UciPayload::default(),
                power_dbm,
            }],
        }));
    }
}

/// 4-bit wideband CQI, MSB first.
/// Fold a CSI indication into the report values: a multi-port measurement
/// sets the rank / PMI (remembered in `rank`), a single-port one carries the
/// CQI only and keeps the last multi-port rank / PMI (rank 1 if none yet).
fn merge_csi(rank: &mut Option<(u8, Pmi)>, c: &CsiIndication) -> CsiValues {
    if c.nof_ports >= 2 {
        *rank = Some((c.ri.max(1), c.pmi));
    }
    let (ri, pmi) = rank.unwrap_or((1, Pmi::default()));
    CsiValues {
        cqi: c.cqi,
        ri,
        pmi,
    }
}

/// One CSI measurement as the PHY reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsiValues {
    pub cqi: u8,
    /// Rank indicator, 1-based.
    pub ri: u8,
    /// Type I single-panel PMI.
    pub pmi: Pmi,
}

fn push_bits(out: &mut Vec<u8>, v: u32, n: usize) {
    for i in (0..n).rev() {
        out.push(((v >> i) & 1) as u8);
    }
}

/// A wideband CSI report on PUCCH (TS 38.212 §6.3.1.1.2, Table 6.3.1.1.2-7):
/// one codeword `CRI | RI | zero padding | PMI | wideband CQI`, sized for the
/// rank with the widest PMI so its length does not depend on the reported
/// rank. CRI is 0 bits (one CSI-RS resource); RI is `⌈log2(allowed ranks)⌉`
/// bits indexing the ranks the `ri-Restriction` allows.
fn csi_report_bits(cfg: &crate::CsiReportMacConfig, v: CsiValues) -> Vec<u8> {
    use ferrite_fapi::config::CsiReportQuantity as Q;
    let mut out = Vec::new();
    let ranks = &cfg.allowed_ranks;
    let cb = cfg.codebook;
    let with_ri = matches!(cfg.quantity, Q::RiCqi | Q::RiPmiCqi) && ranks.len() > 1;
    let with_pmi = cfg.quantity == Q::RiPmiCqi;
    let ri = if ranks.contains(&v.ri) {
        v.ri
    } else {
        ranks[0]
    };
    if with_ri {
        let idx = ranks.iter().position(|&r| r == ri).unwrap_or(0) as u32;
        push_bits(&mut out, idx, cb.ri_bits(ranks.len()));
    }
    if with_pmi {
        // TS 38.212 Table 6.3.1.1.2-1 fields i1,1 | i1,2 | i1,3 | i2, padded
        // in front to the widest PMI of the allowed ranks.
        let widest = ranks
            .iter()
            .map(|&r| cb.pmi_sizes(r).total())
            .max()
            .unwrap_or(0);
        let s = cb.pmi_sizes(ri);
        push_bits(&mut out, 0, widest - s.total());
        push_bits(&mut out, u32::from(v.pmi.i11), s.i11);
        push_bits(&mut out, u32::from(v.pmi.i12), s.i12);
        push_bits(&mut out, u32::from(v.pmi.i13), s.i13);
        push_bits(&mut out, u32::from(v.pmi.i2), s.i2);
    }
    push_bits(&mut out, u32::from(v.cqi & 0xf), 4);
    out
}

impl MacEntity {
    /// Handle one PHY → MAC message with access to the RLC bearers.
    pub fn handle_with(
        &mut self,
        msg: PhyToMac,
        phy: &mut dyn MacToPhySink,
        upper: &mut dyn UpperLayers,
    ) {
        match msg {
            PhyToMac::Slot(s) => self.on_slot(s.slot, phy, upper),
            PhyToMac::Dci(d) => self.on_dci(d.slot, d.dci, phy, upper),
            PhyToMac::RxData(d) => self.on_rx_data(d, phy, upper),
            PhyToMac::Csi(c) => {
                let v = merge_csi(&mut self.csi_rank, &c);
                self.latest_csi = Some((v, c.slot));
            }
            PhyToMac::Rach(r) => {
                let acts = self.ra.on_prach_sent(r.slot);
                self.apply_ra_actions(acts, phy);
            }
            PhyToMac::Sync(s) => self.events.push(MacEvent::Sync { in_sync: s.in_sync }),
            PhyToMac::Error(e) => match e {
                ErrorIndication::TxDropped { slot, pdu } => {
                    log::warn!("PHY dropped {pdu} for slot {slot}")
                }
                ErrorIndication::SyncLost | ErrorIndication::Radio => {
                    self.events.push(MacEvent::RadioLinkFailure)
                }
            },
        }
    }
}

#[cfg(test)]
mod csi_report_tests {
    use super::*;
    use ferrite_fapi::config::CsiReportQuantity as Q;

    /// A two-port PMI (`i2` only).
    fn p(i2: u8) -> Pmi {
        Pmi {
            i2,
            ..Pmi::default()
        }
    }

    /// A single-port TRS measurement after a two-port one keeps the rank and
    /// PMI the two-port measurement recommended, and only refreshes the CQI.
    #[test]
    fn single_port_measurement_keeps_the_multi_port_rank() {
        let ind = |cqi, ri, pmi, nof_ports| CsiIndication {
            slot: SlotPoint::new(ferrite_common::Numerology::from_scs_khz(30).unwrap(), 0, 4),
            sinr_db: 30.0,
            cqi,
            ri,
            pmi,
            nof_ports,
            rsrp_dbfs: -20.0,
        };
        let mut rank = None;
        let v = merge_csi(&mut rank, &ind(12, 1, p(0), 1));
        assert_eq!((v.cqi, v.ri, v.pmi), (12, 1, p(0)));
        let v = merge_csi(&mut rank, &ind(15, 2, p(1), 2));
        assert_eq!((v.cqi, v.ri, v.pmi), (15, 2, p(1)));
        let v = merge_csi(&mut rank, &ind(13, 1, p(0), 1));
        assert_eq!((v.cqi, v.ri, v.pmi), (13, 2, p(1)));
        let v = merge_csi(&mut rank, &ind(14, 1, p(3), 2));
        assert_eq!((v.cqi, v.ri, v.pmi), (14, 1, p(3)));
    }

    fn cfg(q: Q, ports: u8, ranks: &[u8]) -> crate::CsiReportMacConfig {
        crate::CsiReportMacConfig {
            period_slots: 20,
            offset_slots: 0,
            pucch_resource: 8,
            quantity: q,
            codebook: match ports {
                1 => Codebook::OnePort,
                2 => Codebook::TwoPort,
                _ => Codebook::SinglePanel {
                    n1: ports / 2,
                    n2: 1,
                },
            },
            allowed_ranks: ranks.to_vec(),
        }
    }

    #[test]
    fn one_port_report_is_the_cqi_alone() {
        let b = csi_report_bits(
            &cfg(Q::RiPmiCqi, 1, &[1]),
            CsiValues {
                cqi: 9,
                ri: 1,
                pmi: p(0),
            },
        );
        assert_eq!(b, vec![1, 0, 0, 1]);
        assert_eq!(
            csi_report_bits(
                &cfg(Q::Cqi, 2, &[1, 2]),
                CsiValues {
                    cqi: 15,
                    ri: 2,
                    pmi: p(1)
                }
            ),
            vec![1, 1, 1, 1]
        );
    }

    #[test]
    fn two_port_report_has_a_fixed_seven_bit_layout() {
        // Rank 1: RI = 0 (first allowed rank), PMI i2 2 bits, CQI 4 bits.
        let b = csi_report_bits(
            &cfg(Q::RiPmiCqi, 2, &[1, 2]),
            CsiValues {
                cqi: 8,
                ri: 1,
                pmi: p(3),
            },
        );
        assert_eq!(b, vec![0, 1, 1, 1, 0, 0, 0]);
        // Rank 2: RI = 1, one padding bit, PMI 1 bit, CQI.
        let b = csi_report_bits(
            &cfg(Q::RiPmiCqi, 2, &[1, 2]),
            CsiValues {
                cqi: 8,
                ri: 2,
                pmi: p(1),
            },
        );
        assert_eq!(b, vec![1, 0, 1, 1, 0, 0, 0]);
        // A rank the restriction does not allow falls back to the lowest allowed one.
        let b = csi_report_bits(
            &cfg(Q::RiPmiCqi, 2, &[1]),
            CsiValues {
                cqi: 8,
                ri: 2,
                pmi: p(1),
            },
        );
        assert_eq!(
            b,
            vec![0, 1, 1, 0, 0, 0],
            "no RI field with one allowed rank, PMI 2 bits"
        );
        // RI without PMI.
        assert_eq!(
            csi_report_bits(
                &cfg(Q::RiCqi, 2, &[1, 2]),
                CsiValues {
                    cqi: 1,
                    ri: 2,
                    pmi: p(0)
                }
            ),
            vec![1, 0, 0, 0, 1]
        );
    }

    /// Four ports (N1 = 2, N2 = 1) with every rank allowed (OCUDU's 4T
    /// default): RI 2 bits, then the PMI padded to the widest (5 bits at
    /// rank 1 and 2, 4 at ranks 3 / 4), then the CQI — 11 bits whatever the
    /// rank, as the gNB sizes the report.
    #[test]
    fn four_port_report_layout() {
        let c = cfg(Q::RiPmiCqi, 4, &[1, 2, 3, 4]);
        let v = |ri, pmi| CsiValues { cqi: 9, ri, pmi };
        // Rank 1: RI 00, i1,1 = 5 (101), i2 = 2 (10), CQI 1001.
        let b = csi_report_bits(
            &c,
            v(
                1,
                Pmi {
                    i11: 5,
                    i2: 2,
                    ..Pmi::default()
                },
            ),
        );
        assert_eq!(b, vec![0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1]);
        // Rank 2: RI 01, i1,1 = 3 (011), i1,3 = 1, i2 = 1.
        let b = csi_report_bits(
            &c,
            v(
                2,
                Pmi {
                    i11: 3,
                    i13: 1,
                    i2: 1,
                    ..Pmi::default()
                },
            ),
        );
        assert_eq!(b, vec![0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1]);
        // Rank 3: RI 10, one padding bit, i1,1 = 0 (000), i2 = 0.
        let b = csi_report_bits(&c, v(3, Pmi::default()));
        assert_eq!(b, vec![1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1]);
        // Ranks 1–2 only (a gNB configured for two layers): RI 1 bit.
        assert_eq!(
            csi_report_bits(&cfg(Q::RiPmiCqi, 4, &[1, 2]), v(1, Pmi::default())).len(),
            10
        );
    }
}
