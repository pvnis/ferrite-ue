//! Random Access procedure (TS 38.321 §5.1), contention-based 4-step RA.
//!
//! ```text
//!             start                occasion found           RACH.indication
//!  Idle ───────────▶ SelectResource ─────────────▶ PreambleRequested ─────────▶ RarWindow
//!    ▲                     ▲                                                        │ RAR(RAPID) matched
//!    │                     │ window / timer expired, backoff, counter < max          ▼
//!    │                     └──────────────────────────────────────────────────── Msg3Pending
//!    │  preambleTransMax                                                            │ PHY resolved the grant
//!    │  reached                                                                     ▼
//!    └─ Failed                        Succeeded ◀── ConRes CE / C-RNTI PDCCH ── ContentionResolution
//! ```
//! Power ramping, backoff, the RAR window and the contention-resolution timer
//! are all here; the PHY only ever sees "send preamble p on occasion o" and
//! resolves the RAR UL grant into a Msg3 PUSCH grant (`MacToPhy::RarGrant`).

use ferrite_common::{Rnti, SlotPoint};
use ferrite_fapi::PrachOccasion;

/// RA procedure state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaState {
    Idle,
    /// Waiting for the next suitable PRACH occasion (after `not_before`).
    SelectResource {
        not_before: SlotPoint,
    },
    /// UL_TTI.request issued for `occasion`; waiting for RACH.indication.
    PreambleRequested {
        occasion: PrachOccasion,
        preamble: u8,
    },
    /// Preamble transmitted; RAR window open until `window_end` (exclusive).
    RarWindow {
        ra_rnti: Rnti,
        preamble: u8,
        window_end: SlotPoint,
    },
    /// RAR matched; the PHY is resolving its UL grant into the Msg3 PUSCH
    /// grant (a TC-RNTI UL grant). Treated as a RAR-window failure if nothing
    /// arrives by `deadline`.
    Msg3Pending {
        tc_rnti: Rnti,
        deadline: SlotPoint,
    },
    /// Msg3 handed to the PHY; contention resolution timer runs from the Msg3
    /// slot (`timer_end`).
    ContentionResolution {
        tc_rnti: Rnti,
        timer_end: SlotPoint,
    },
    Succeeded {
        c_rnti: Rnti,
    },
    Failed,
}

/// What the procedure wants from MAC/PHY after a step.
#[derive(Clone, Debug, PartialEq)]
pub enum RaAction {
    /// Send this preamble on this occasion with this power offset (dB above
    /// `preambleReceivedTargetPower`).
    SendPreamble {
        occasion: PrachOccasion,
        preamble: u8,
        power_offset_db: f32,
    },
    /// Start monitoring RA-RNTI (`Some`) / stop (`None`).
    MonitorRaRnti(Option<Rnti>),
    /// Start monitoring TC-RNTI for Msg4.
    MonitorTcRnti(Rnti),
    /// Procedure finished: `Ok(c_rnti)` or `Err(())` after preambleTransMax.
    Done(Result<Rnti, ()>),
}

/// The RA procedure.
#[derive(Clone, Debug)]
pub struct RaProcedure {
    pub state: RaState,
    /// PREAMBLE_TRANSMISSION_COUNTER (starts at 1 on the first attempt).
    pub preamble_tx_counter: u32,
    pub preamble_power_ramping_counter: u32,
    pub preamble_trans_max: u32,
    pub power_ramping_step_db: u8,
    pub ra_response_window_slots: u16,
    pub contention_resolution_slots: u32,
    pub nof_cb_preambles: u8,
    /// The 48-bit CCCH SDU sent in Msg3, for contention resolution.
    pub msg3_ccch: Option<[u8; 6]>,
    /// Set when the RA is for a UE that already has a C-RNTI (Msg3 carries the
    /// C-RNTI MAC CE; contention resolution is the C-RNTI-addressed PDCCH).
    pub crnti_ra: Option<Rnti>,
    /// Backoff (ms) from the last RAR BI, applied before the next attempt.
    pub backoff_ms: u16,
    /// Pseudo-random state for preamble selection / backoff draw.
    rng: u64,
}

impl RaProcedure {
    pub fn new(cfg: &crate::RachConfig, numerology: ferrite_common::Numerology, seed: u64) -> Self {
        Self {
            state: RaState::Idle,
            preamble_tx_counter: 1,
            preamble_power_ramping_counter: 1,
            preamble_trans_max: cfg.preamble_trans_max,
            power_ramping_step_db: cfg.power_ramping_step_db,
            ra_response_window_slots: cfg.ra_response_window_slots,
            contention_resolution_slots: (cfg.contention_resolution_ms
                * numerology.slots_per_subframe())
            .max(1),
            nof_cb_preambles: cfg.nof_cb_preambles.max(1),
            msg3_ccch: None,
            crnti_ra: None,
            backoff_ms: 0,
            rng: seed | 1,
        }
    }

    fn next_random(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn is_running(&self) -> bool {
        !matches!(
            self.state,
            RaState::Idle | RaState::Succeeded { .. } | RaState::Failed
        )
    }

    /// §5.1.1 initialisation: start a new procedure at `now`. `ccch` is the
    /// Msg3 CCCH SDU (RRCSetupRequest) for initial access; `crnti` for a
    /// C-RNTI-based RA (e.g. SR failure).
    pub fn start(&mut self, now: SlotPoint, ccch: Option<[u8; 6]>, crnti: Option<Rnti>) {
        self.preamble_tx_counter = 1;
        self.preamble_power_ramping_counter = 1;
        self.backoff_ms = 0;
        self.msg3_ccch = ccch;
        self.crnti_ra = crnti;
        self.state = RaState::SelectResource { not_before: now };
    }

    /// Current power offset above the target (§5.1.3): (counter − 1) · step.
    pub fn power_offset_db(&self) -> f32 {
        (self.preamble_power_ramping_counter.saturating_sub(1) * self.power_ramping_step_db as u32)
            as f32
    }

    /// Per-slot step. `occasions_from` yields the PRACH occasions in a slot;
    /// `lead` is how many slots ahead the PHY needs the request.
    pub fn on_slot(
        &mut self,
        now: SlotPoint,
        lead: u16,
        occasions_in: &dyn Fn(SlotPoint) -> Vec<PrachOccasion>,
    ) -> Vec<RaAction> {
        let mut actions = Vec::new();
        match self.state.clone() {
            RaState::SelectResource { not_before } => {
                // §5.1.2: pick the next occasion at least `lead` slots ahead.
                let from = if now.diff(&not_before) >= 0 {
                    now
                } else {
                    not_before
                };
                let from = from.add(lead as u64 + 1);
                for d in 0..(2 * 10 * now.slots_per_frame() as u64) {
                    let s = from.add(d);
                    let occ = occasions_in(s);
                    if let Some(o) = occ.first() {
                        let o = *o;
                        let preamble = (self.next_random() % self.nof_cb_preambles as u64) as u8;
                        self.state = RaState::PreambleRequested {
                            occasion: o,
                            preamble,
                        };
                        log::debug!("RA: attempt {} preamble {preamble} on slot {} (symbol {}, f {}, t {}, RA-RNTI {}) requested at slot {now}", self.preamble_tx_counter, o.slot, o.start_symbol, o.freq_index, o.time_index, o.ra_rnti.0);
                        actions.push(RaAction::SendPreamble {
                            occasion: o,
                            preamble,
                            power_offset_db: self.power_offset_db(),
                        });
                        break;
                    }
                }
            }
            RaState::RarWindow { window_end, .. } => {
                if now.diff(&window_end) >= 0 {
                    // §5.1.4: window expired without a matching RAR.
                    log::debug!("RA: RAR window expired at slot {now}");
                    actions.push(RaAction::MonitorRaRnti(None));
                    self.retry(now, &mut actions);
                }
            }
            RaState::Msg3Pending { deadline, .. } => {
                if now.diff(&deadline) >= 0 {
                    // The PHY never resolved the RAR grant: treat as no RAR.
                    log::warn!("RA: Msg3 grant not resolved by slot {now}");
                    self.retry(now, &mut actions);
                }
            }
            RaState::ContentionResolution { timer_end, .. } if now.diff(&timer_end) >= 0 => {
                // §5.1.5: contention resolution timer expiry.
                self.retry(now, &mut actions);
            }
            _ => {}
        }
        actions
    }

    fn retry(&mut self, now: SlotPoint, actions: &mut Vec<RaAction>) {
        self.preamble_tx_counter += 1;
        if self.preamble_tx_counter > self.preamble_trans_max {
            self.state = RaState::Failed;
            actions.push(RaAction::Done(Err(())));
            return;
        }
        self.preamble_power_ramping_counter += 1;
        // §5.1.4: backoff uniformly in [0, PREAMBLE_BACKOFF].
        let backoff_slots = if self.backoff_ms > 0 {
            let ms = self.next_random() % (self.backoff_ms as u64 + 1);
            ms * now.numerology.slots_per_subframe() as u64
        } else {
            0
        };
        self.state = RaState::SelectResource {
            not_before: now.add(backoff_slots),
        };
    }

    /// RACH.indication: the preamble went out in `slot`. Opens the RAR window
    /// (§5.1.4: starts at the first PDCCH occasion after the PRACH occasion end;
    /// approximated as the next slot).
    pub fn on_prach_sent(&mut self, slot: SlotPoint) -> Vec<RaAction> {
        let RaState::PreambleRequested { occasion, preamble } = self.state.clone() else {
            return Vec::new();
        };
        let window_end = slot.add(1 + self.ra_response_window_slots as u64);
        log::debug!("RA: preamble sent in slot {slot}, RAR window until {window_end}");
        self.state = RaState::RarWindow {
            ra_rnti: occasion.ra_rnti,
            preamble,
            window_end,
        };
        vec![RaAction::MonitorRaRnti(Some(occasion.ra_rnti))]
    }

    /// A RAR PDU addressed to our RA-RNTI arrived (§5.1.4). Returns the matching
    /// RAR (the caller hands its UL grant to the PHY for resolution) if the
    /// RAPID matches; the procedure then waits for the Msg3 grant.
    pub fn on_rar(&mut self, pdu: &crate::rar::RarPdu) -> Option<(crate::rar::Rar, Vec<RaAction>)> {
        let RaState::RarWindow {
            preamble,
            window_end,
            ..
        } = self.state
        else {
            return None;
        };
        if let Some(bi) = pdu.backoff_ms {
            self.backoff_ms = bi;
        }
        let rar = pdu.rars.iter().find(|r| r.rapid == preamble)?;
        let actions = vec![
            RaAction::MonitorRaRnti(None),
            RaAction::MonitorTcRnti(Rnti(rar.tc_rnti)),
        ];
        self.state = RaState::Msg3Pending {
            tc_rnti: Rnti(rar.tc_rnti),
            deadline: window_end.add(self.ra_response_window_slots as u64),
        };
        Some((*rar, actions))
    }

    /// Waiting for the PHY to resolve the RAR grant into the Msg3 grant.
    pub fn msg3_pending(&self) -> bool {
        matches!(self.state, RaState::Msg3Pending { .. })
    }

    /// Msg3 was handed to the PHY for `msg3_slot`: start the contention
    /// resolution timer (§5.1.5, from the Msg3 transmission).
    pub fn on_msg3_scheduled(&mut self, msg3_slot: SlotPoint) {
        if let RaState::Msg3Pending { tc_rnti, .. } = self.state {
            self.state = RaState::ContentionResolution {
                tc_rnti,
                timer_end: msg3_slot.add(1 + self.contention_resolution_slots as u64),
            };
        }
    }

    /// A DL-SCH PDU addressed to the TC-RNTI carried a Contention Resolution
    /// Identity CE: §5.1.5 — success if it matches our CCCH SDU.
    pub fn on_contention_resolution_id(&mut self, id: &[u8; 6]) -> Vec<RaAction> {
        let RaState::ContentionResolution { tc_rnti, .. } = self.state else {
            return Vec::new();
        };
        if self.msg3_ccch.as_ref() == Some(id) {
            self.state = RaState::Succeeded { c_rnti: tc_rnti };
            vec![RaAction::Done(Ok(tc_rnti))]
        } else {
            Vec::new()
        }
    }

    /// A PDCCH addressed to our C-RNTI arrived while resolving a C-RNTI RA:
    /// §5.1.5 — contention resolution successful.
    pub fn on_crnti_pdcch(&mut self) -> Vec<RaAction> {
        if let (RaState::ContentionResolution { .. }, Some(c)) = (&self.state, self.crnti_ra) {
            self.state = RaState::Succeeded { c_rnti: c };
            return vec![RaAction::Done(Ok(c))];
        }
        Vec::new()
    }

    /// The ra-RNTI currently being monitored, if any.
    pub fn ra_rnti(&self) -> Option<Rnti> {
        match self.state {
            RaState::RarWindow { ra_rnti, .. } => Some(ra_rnti),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::Numerology;
    use ferrite_fapi::config::PrachConfig;

    fn cfg() -> crate::RachConfig {
        crate::RachConfig {
            preamble_trans_max: 3,
            power_ramping_step_db: 4,
            target_power_dbm: -100,
            ra_response_window_slots: 20,
            contention_resolution_ms: 64,
            nof_cb_preambles: 64,
            cb_preambles_per_ssb: 64,
            prach: PrachConfig {
                phy: ferrite_ran::prach_config::PrachConfig {
                    index: 159,
                    duplex: ferrite_common::DuplexMode::Tdd,
                    mu: 1,
                    msg1_scs_mu: 1,
                    msg1_fdm: 1,
                    msg1_frequency_start: 5,
                },
                tdd: None,
                ssb_symbols: Vec::new(),
                ssb_period_ms: 20,
                zero_correlation_zone: 0,
                root_sequence_index: 1,
                restricted_set: 0,
                total_preambles: 64,
                target_power_dbm: -100,
                power_ramping_step_db: 4,
            },
        }
    }

    #[test]
    fn full_success_path() {
        let c = cfg();
        let mut ra = RaProcedure::new(&c, Numerology::KHZ30, 7);
        let now = SlotPoint::new(Numerology::KHZ30, 0, 0);
        ra.start(now, Some([1, 2, 3, 4, 5, 6]), None);
        let occ = |s: SlotPoint| c.prach.occasions_in_slot(s);
        let a = ra.on_slot(now, 3, &occ);
        let RaAction::SendPreamble {
            occasion, preamble, ..
        } = a[0].clone()
        else {
            panic!("{a:?}")
        };
        assert_eq!(occasion.slot.slot, 19); // subframe 9, slot 1
        assert!(preamble < 64);
        let a = ra.on_prach_sent(occasion.slot);
        assert_eq!(a, vec![RaAction::MonitorRaRnti(Some(occasion.ra_rnti))]);
        let pdu = crate::rar::RarPdu {
            backoff_ms: None,
            rars: vec![crate::rar::Rar {
                rapid: preamble,
                ta: 3,
                grant: crate::rar::RarUlGrant {
                    freq_hopping: false,
                    fdra: 0,
                    time_resource: 0,
                    mcs: 0,
                    tpc: 7,
                    csi_request: false,
                },
                tc_rnti: 0x4601,
            }],
        };
        let (rar, a) = ra.on_rar(&pdu).unwrap();
        assert_eq!(rar.tc_rnti, 0x4601);
        assert!(a.contains(&RaAction::MonitorTcRnti(Rnti(0x4601))));
        ra.on_msg3_scheduled(occasion.slot.add(10));
        assert!(matches!(ra.state, RaState::ContentionResolution { .. }));
        assert!(ra.on_contention_resolution_id(&[9; 6]).is_empty());
        let a = ra.on_contention_resolution_id(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(a, vec![RaAction::Done(Ok(Rnti(0x4601)))]);
    }

    #[test]
    fn window_expiry_ramps_and_fails_after_max() {
        let c = cfg();
        let mut ra = RaProcedure::new(&c, Numerology::KHZ30, 1);
        let occ = |s: SlotPoint| c.prach.occasions_in_slot(s);
        let mut now = SlotPoint::new(Numerology::KHZ30, 0, 0);
        ra.start(now, Some([0; 6]), None);
        let mut attempts = 0;
        for _ in 0..2000 {
            let acts = ra.on_slot(now, 3, &occ);
            for a in acts {
                match a {
                    RaAction::SendPreamble {
                        occasion,
                        power_offset_db,
                        ..
                    } => {
                        assert_eq!(power_offset_db, (attempts * 4) as f32);
                        attempts += 1;
                        // Pretend the PHY sends it at the occasion slot.
                        let _ = ra.on_prach_sent(occasion.slot);
                    }
                    RaAction::Done(r) => {
                        assert!(r.is_err());
                        assert_eq!(attempts, 3);
                        return;
                    }
                    _ => {}
                }
            }
            now = now.add(1);
        }
        panic!("did not fail");
    }
}
