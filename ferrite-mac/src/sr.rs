//! Scheduling Request procedure (TS 38.321 §5.4.4): `Idle → Pending → Idle`
//! (a BSR went out) or `Pending → Failed` (sr-TransMax reached, the entity
//! then starts a random access and clears the state with `take_failed`).

use ferrite_common::fsm::{Fsm, FsmStats, Machine, Rule};
use ferrite_common::SlotPoint;

/// SR state (TS 38.321 §5.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrState {
    /// No SR pending.
    Idle,
    /// An SR is pending: `counter` = SR_COUNTER, `prohibit_until` = sr-ProhibitTimer expiry.
    Pending {
        counter: u32,
        prohibit_until: Option<SlotPoint>,
    },
    /// SR_COUNTER reached sr-TransMax: MAC must release PUCCH/SRS, clear the
    /// configured grants and start a random access (`take_failed`).
    Failed,
}

impl SrState {
    /// The state without its data, as the transition table sees it.
    pub fn phase(&self) -> SrPhase {
        match self {
            SrState::Idle => SrPhase::Idle,
            SrState::Pending { .. } => SrPhase::Pending,
            SrState::Failed => SrPhase::Failed,
        }
    }
}

/// [`SrState`] without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrPhase {
    Idle,
    Pending,
    Failed,
}

/// What moves the SR procedure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrTrigger {
    /// A regular BSR could not be sent: SR triggered.
    Triggered,
    /// SR_COUNTER reached sr-TransMax.
    TransMaxReached,
    /// A MAC PDU with a BSR went out: pending SRs cancelled.
    BsrSent,
    /// The entity started the random access for the failure.
    RandomAccessStarted,
    /// MAC reset or reconfiguration.
    Reset,
}

/// The SR machine.
pub struct SrMachine;

impl Machine for SrMachine {
    const NAME: &'static str = "SR";
    type State = SrState;
    type Kind = SrPhase;
    type Event = SrTrigger;
    const KINDS: &'static [SrPhase] = &[SrPhase::Idle, SrPhase::Pending, SrPhase::Failed];
    const EVENTS: &'static [SrTrigger] = &[
        SrTrigger::Triggered,
        SrTrigger::TransMaxReached,
        SrTrigger::BsrSent,
        SrTrigger::RandomAccessStarted,
        SrTrigger::Reset,
    ];
    const INITIAL: SrPhase = SrPhase::Idle;
    const RULES: &'static [Rule<SrPhase, SrTrigger>] = &[
        Rule {
            from: &[SrPhase::Idle],
            event: SrTrigger::Triggered,
            to: SrPhase::Pending,
            clause: "38.321 §5.4.4",
        },
        Rule {
            from: &[SrPhase::Pending],
            event: SrTrigger::TransMaxReached,
            to: SrPhase::Failed,
            clause: "38.321 §5.4.4 (SR_COUNTER = sr-TransMax)",
        },
        Rule {
            from: &[SrPhase::Pending],
            event: SrTrigger::BsrSent,
            to: SrPhase::Idle,
            clause: "38.321 §5.4.4 (MAC PDU with a BSR)",
        },
        Rule {
            from: &[SrPhase::Failed],
            event: SrTrigger::RandomAccessStarted,
            to: SrPhase::Idle,
            clause: "38.321 §5.4.4 (initiate RA, cancel all pending SRs)",
        },
        Rule {
            from: &[SrPhase::Pending, SrPhase::Failed],
            event: SrTrigger::Reset,
            to: SrPhase::Idle,
            clause: "38.321 §5.12 (MAC reset)",
        },
    ];
    fn kind(s: &SrState) -> SrPhase {
        s.phase()
    }
}

#[derive(Clone, Debug)]
pub struct SrProcedure {
    pub sr_id: u8,
    pub prohibit_slots: u32,
    pub trans_max: u32,
    /// (period, offset, pucch resource id) occasions.
    pub resources: Vec<(u16, u16, u8)>,
    state: Fsm<SrMachine>,
}

impl SrProcedure {
    pub fn new(cfg: &crate::SrConfig, slots_per_ms: u32) -> Self {
        Self {
            sr_id: cfg.sr_id,
            prohibit_slots: cfg.prohibit_ms.saturating_mul(slots_per_ms),
            trans_max: cfg.trans_max,
            resources: cfg.resources.clone(),
            state: Fsm::new(SrState::Idle),
        }
    }

    pub fn state(&self) -> SrState {
        *self.state.state()
    }

    /// Transitions made and refused (a refusal is a bug: see [`SrMachine`]).
    pub fn fsm_stats(&self) -> FsmStats {
        self.state.stats()
    }

    fn go(&mut self, trigger: SrTrigger, to: SrState) -> bool {
        match self.state.transition(trigger, to) {
            Ok(t) => {
                if let Some(t) = t {
                    log::debug!("{t} (SR id {})", self.sr_id);
                }
                true
            }
            Err(v) => {
                log::error!("{v} (SR id {})", self.sr_id);
                false
            }
        }
    }

    /// Trigger an SR (a regular BSR could not be sent). A pending SR is kept
    /// (its counter continues); a failed one stays failed until `take_failed`.
    pub fn trigger(&mut self) {
        if self.state() == SrState::Idle {
            self.go(
                SrTrigger::Triggered,
                SrState::Pending {
                    counter: 0,
                    prohibit_until: None,
                },
            );
        }
    }

    /// A MAC PDU with a BSR went out: cancel a pending SR. A failure
    /// (sr-TransMax reached) is kept until the entity starts the random
    /// access for it ([`SrProcedure::take_failed`]).
    pub fn cancel(&mut self) {
        if self.state().phase() == SrPhase::Pending {
            self.go(SrTrigger::BsrSent, SrState::Idle);
        }
    }

    /// MAC reset: back to `Idle` from anywhere.
    pub fn reset(&mut self) {
        if self.state() != SrState::Idle {
            self.go(SrTrigger::Reset, SrState::Idle);
        }
    }

    /// `true` once (and resets to `Idle`) when sr-TransMax was reached.
    pub fn take_failed(&mut self) -> bool {
        self.state() == SrState::Failed && self.go(SrTrigger::RandomAccessStarted, SrState::Idle)
    }

    /// Is `slot` an SR occasion? Returns the PUCCH resource id.
    pub fn occasion(&self, slot: SlotPoint) -> Option<u8> {
        self.resources
            .iter()
            .find(|(p, o, _)| slot.is_occasion(*p as u32, *o as u32))
            .map(|r| r.2)
    }

    /// Decide whether to transmit an SR at `slot` (an occasion). Returns the
    /// PUCCH resource id when a positive SR must be sent. Implements the
    /// prohibit timer and SR_COUNTER / sr-TransMax (§5.4.4).
    pub fn should_send(&mut self, slot: SlotPoint) -> Option<u8> {
        let SrState::Pending {
            counter,
            prohibit_until,
        } = self.state()
        else {
            return None;
        };
        let res = self.occasion(slot)?;
        if let Some(t) = prohibit_until {
            if slot.diff(&t) < 0 {
                return None;
            }
        }
        if counter >= self.trans_max {
            self.go(SrTrigger::TransMaxReached, SrState::Failed);
            return None;
        }
        let prohibit = (self.prohibit_slots > 0).then(|| slot.add(self.prohibit_slots as u64));
        // Sent on this occasion: SR_COUNTER + 1, sr-ProhibitTimer started
        // (same state, new data).
        self.state.update(SrState::Pending {
            counter: counter.saturating_add(1),
            prohibit_until: prohibit,
        });
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_well_formed() {
        assert_eq!(ferrite_common::fsm::check::<SrMachine>(), Ok(()));
    }
    use ferrite_common::Numerology;

    #[test]
    fn sr_occasions_and_transmax() {
        let cfg = crate::SrConfig {
            sr_id: 0,
            prohibit_ms: 0,
            trans_max: 2,
            resources: vec![(10, 7, 3)],
        };
        let mut sr = SrProcedure::new(&cfg, 2);
        sr.trigger();
        let s = |n: u16| SlotPoint::new(Numerology::KHZ30, 0, n);
        assert_eq!(sr.should_send(s(6)), None);
        assert_eq!(sr.should_send(s(7)), Some(3));
        assert_eq!(sr.should_send(s(17)), Some(3));
        // Slot 7 of the next frame: SR_COUNTER has reached sr-TransMax.
        assert_eq!(sr.should_send(s(7)), None);
        assert_eq!(sr.state(), SrState::Failed);
        assert!(sr.take_failed());
        assert_eq!(sr.state(), SrState::Idle);
    }

    /// A BSR going out after sr-TransMax was reached must not erase the
    /// failure: the entity still has to start the random access (§5.4.4).
    #[test]
    fn a_bsr_does_not_cancel_a_failure() {
        let cfg = crate::SrConfig {
            sr_id: 0,
            prohibit_ms: 0,
            trans_max: 1,
            resources: vec![(10, 7, 3)],
        };
        let mut sr = SrProcedure::new(&cfg, 2);
        sr.trigger();
        let s = |n: u16| SlotPoint::new(Numerology::KHZ30, 0, n);
        assert_eq!(sr.should_send(s(7)), Some(3));
        assert_eq!(sr.should_send(s(17)), None);
        assert_eq!(sr.state(), SrState::Failed);
        sr.cancel(); // a MAC PDU with a BSR in the same slot
        assert!(sr.take_failed(), "the failure survives the BSR");
        sr.trigger();
        sr.reset();
        assert_eq!(sr.state(), SrState::Idle);
        assert_eq!(sr.fsm_stats().violations, 0);
    }
}

/// Model-checking harness (`cargo kani -p ferrite-mac`): induction over
/// the SR procedure.
#[cfg(kani)]
mod proofs {
    use super::*;
    use ferrite_common::Numerology;

    fn any_slot() -> SlotPoint {
        let i: u32 = kani::any();
        SlotPoint::from_index(Numerology::KHZ30, u64::from(i % (1024 * 20)))
    }

    /// From any state with SR_COUNTER ≤ sr-TransMax, any input keeps it
    /// there, moves only along [`SrMachine`]'s table and never panics; and
    /// a failure is only left through the random access or a reset (a BSR
    /// does not erase it).
    #[kani::proof]
    #[kani::unwind(8)]
    fn sr_step_preserves_the_invariant() {
        let trans_max: u32 = kani::any();
        kani::assume((1..=64).contains(&trans_max));
        let cfg = crate::SrConfig {
            sr_id: 0,
            prohibit_ms: kani::any::<u32>() % 128,
            trans_max,
            resources: vec![(10, 7, 3)],
        };
        let mut sr = SrProcedure::new(&cfg, 2);
        sr.state = Fsm::assume_in(match kani::any::<u8>() % 3 {
            0 => SrState::Idle,
            1 => SrState::Pending {
                counter: kani::any(),
                prohibit_until: if kani::any() { Some(any_slot()) } else { None },
            },
            _ => SrState::Failed,
        });
        let ok = |sr: &SrProcedure| match sr.state() {
            SrState::Pending { counter, .. } => counter <= trans_max,
            _ => true,
        };
        kani::assume(ok(&sr));
        let was_failed = sr.state() == SrState::Failed;
        let mut failure_taken = false;
        let input = kani::any::<u8>() % 5;
        match input {
            0 => sr.trigger(),
            1 => {
                sr.should_send(any_slot());
            }
            2 => sr.cancel(),
            3 => failure_taken = sr.take_failed(),
            _ => sr.reset(),
        }
        assert_eq!(sr.fsm_stats().violations, 0);
        assert!(ok(&sr));
        if was_failed && sr.state() != SrState::Failed {
            // Only the random access (reported once) or a reset ends a failure.
            assert!(failure_taken || input == 4);
        }
        kani::cover!(failure_taken, "failure handed to the random access");
        kani::cover!(
            sr.state() == SrState::Failed && !was_failed,
            "sr-TransMax reached"
        );
    }
}
