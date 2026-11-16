//! Timing advance maintenance (TS 38.321 §5.2, TS 38.213 §4.2).
//!
//! `NotAligned` until the RAR's absolute TA command, then `Aligned` while the
//! `timeAlignmentTimer` runs (every TA Command CE restarts it; `infinity` never
//! expires). On expiry the entity flushes its HARQ buffers, drops PUCCH/SRS
//! and only transmits PRACH until the next random access (§5.2).

use ferrite_common::fsm::{Fsm, FsmStats, Machine, Rule};
use ferrite_common::{slot::ta, Numerology, SlotPoint};

/// Uplink time-alignment state of the (primary) timing advance group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaState {
    /// No valid N_TA: only the PRACH may be transmitted.
    NotAligned,
    /// N_TA valid; `expiry` is the timeAlignmentTimer end (`None` = infinity).
    Aligned { expiry: Option<SlotPoint> },
}

/// [`TaState`] without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaPhase {
    NotAligned,
    Aligned,
}

/// What moves the time-alignment state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaTrigger {
    /// Timing Advance in a RAR or a TA Command MAC CE: timeAlignmentTimer
    /// (re)started.
    Command,
    TimerExpiry,
    /// MAC reset.
    Reset,
}

/// The time-alignment machine.
pub struct TaMachine;

impl Machine for TaMachine {
    const NAME: &'static str = "TA";
    type State = TaState;
    type Kind = TaPhase;
    type Event = TaTrigger;
    const KINDS: &'static [TaPhase] = &[TaPhase::NotAligned, TaPhase::Aligned];
    const EVENTS: &'static [TaTrigger] =
        &[TaTrigger::Command, TaTrigger::TimerExpiry, TaTrigger::Reset];
    const INITIAL: TaPhase = TaPhase::NotAligned;
    const RULES: &'static [Rule<TaPhase, TaTrigger>] = &[
        Rule {
            from: &[TaPhase::NotAligned],
            event: TaTrigger::Command,
            to: TaPhase::Aligned,
            clause: "38.321 §5.2 (TA command: start timeAlignmentTimer)",
        },
        Rule {
            from: &[TaPhase::Aligned],
            event: TaTrigger::TimerExpiry,
            to: TaPhase::NotAligned,
            clause: "38.321 §5.2 (timeAlignmentTimer expiry)",
        },
        Rule {
            from: &[TaPhase::Aligned],
            event: TaTrigger::Reset,
            to: TaPhase::NotAligned,
            clause: "38.321 §5.12 (MAC reset)",
        },
    ];
    fn kind(s: &TaState) -> TaPhase {
        match s {
            TaState::NotAligned => TaPhase::NotAligned,
            TaState::Aligned { .. } => TaPhase::Aligned,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimingAdvance {
    /// Absolute N_TA in T_c units.
    pub n_ta_tc: i64,
    pub timer_slots: u32,
    state: Fsm<TaMachine>,
    numerology: Numerology,
}

impl TimingAdvance {
    pub fn new(numerology: Numerology, timer_ms: u32) -> Self {
        Self {
            n_ta_tc: 0,
            timer_slots: timer_ms.saturating_mul(numerology.slots_per_subframe()),
            state: Fsm::new(TaState::NotAligned),
            numerology,
        }
    }

    pub fn state(&self) -> TaState {
        *self.state.state()
    }

    /// Transitions made and refused (a refusal is a bug: see [`TaMachine`]).
    pub fn fsm_stats(&self) -> FsmStats {
        self.state.stats()
    }

    fn go(&mut self, trigger: TaTrigger, to: TaState) -> bool {
        match self.state.transition(trigger, to) {
            Ok(t) => {
                if let Some(t) = t {
                    log::debug!("{t}");
                }
                true
            }
            Err(v) => {
                log::error!("{v}");
                false
            }
        }
    }

    /// Apply the RAR 12-bit TA command (absolute).
    pub fn apply_rar(&mut self, ta_cmd: u16, now: SlotPoint) {
        self.n_ta_tc = ta::n_ta_from_rar(ta_cmd as u32, self.numerology);
        self.restart(now);
    }

    /// Apply a 6-bit TA Command MAC CE (relative).
    pub fn apply_ce(&mut self, ta_cmd: u8, now: SlotPoint) {
        let before = self.n_ta_tc;
        self.n_ta_tc = ta::n_ta_apply_ce(self.n_ta_tc, ta_cmd, self.numerology);
        log::debug!(
            "TA command {ta_cmd} at {now}: N_TA {before} → {} T_c",
            self.n_ta_tc
        );
        self.restart(now);
    }

    fn restart(&mut self, now: SlotPoint) {
        self.go(
            TaTrigger::Command,
            TaState::Aligned {
                expiry: (self.timer_slots > 0).then(|| now.add(self.timer_slots as u64)),
            },
        );
    }

    /// Per-slot step: `true` exactly once when the timeAlignmentTimer expires.
    pub fn on_slot(&mut self, now: SlotPoint) -> bool {
        if let TaState::Aligned { expiry: Some(t) } = self.state() {
            if now.diff(&t) >= 0 {
                return self.go(TaTrigger::TimerExpiry, TaState::NotAligned);
            }
        }
        false
    }

    /// True while the uplink is time-aligned.
    pub fn aligned(&self) -> bool {
        matches!(self.state(), TaState::Aligned { .. })
    }

    pub fn reset(&mut self) {
        self.n_ta_tc = 0;
        if self.aligned() {
            self.go(TaTrigger::Reset, TaState::NotAligned);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_well_formed() {
        assert_eq!(ferrite_common::fsm::check::<TaMachine>(), Ok(()));
    }

    #[test]
    fn timer_expiry_drops_alignment() {
        let s = |n: u16| SlotPoint::new(Numerology::KHZ30, 0, n);
        let mut t = TimingAdvance::new(Numerology::KHZ30, 2); // 2 ms = 4 slots
        assert!(!t.aligned());
        t.apply_rar(10, s(0));
        assert!(t.aligned());
        assert!(!t.on_slot(s(3)));
        assert!(t.on_slot(s(4)));
        assert!(!t.aligned());
        assert!(!t.on_slot(s(5)));
        // Infinity: never expires.
        let mut inf = TimingAdvance::new(Numerology::KHZ30, 0);
        inf.apply_ce(31, s(0));
        assert!(inf.aligned() && !inf.on_slot(s(100)));
    }
}
