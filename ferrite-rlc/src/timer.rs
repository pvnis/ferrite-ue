//! Slot-clock timers. RLC timers are configured in milliseconds (TS 38.331
//! `T-Reassembly`, `T-PollRetransmit`, `T-StatusProhibit`) and run on the slot
//! clock: `ms · slots_per_subframe` slots at the entity's numerology.

use ferrite_common::{Numerology, SlotPoint};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timer {
    /// Duration in slots.
    dur: i64,
    start: Option<SlotPoint>,
}

impl Timer {
    pub fn new(ms: u32, numerology: Numerology) -> Self {
        Self { dur: ms as i64 * numerology.slots_per_subframe() as i64, start: None }
    }

    /// (Re)start the timer at `now`.
    pub fn start(&mut self, now: SlotPoint) {
        self.start = Some(now);
    }

    /// Stop and reset.
    pub fn stop(&mut self) {
        self.start = None;
    }

    /// Started and its expiry not yet processed (the spec's "is running" for
    /// timers whose expiry has actions; those are processed in `tick`).
    pub fn is_running(&self) -> bool {
        self.start.is_some()
    }

    /// Started and not yet past its duration at `now` (used for
    /// t-StatusProhibit, whose expiry has no action).
    pub fn running_at(&self, now: SlotPoint) -> bool {
        self.start.is_some_and(|s| now.diff(&s) < self.dur)
    }

    /// Started and past its duration at `now`.
    pub fn expired(&self, now: SlotPoint) -> bool {
        self.start.is_some_and(|s| now.diff(&s) >= self.dur)
    }
}
