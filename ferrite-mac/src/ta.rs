//! Timing advance maintenance (TS 38.321 §5.2, TS 38.213 §4.2).

use ferrite_common::{slot::ta, Numerology, SlotPoint};

#[derive(Clone, Debug)]
pub struct TimingAdvance {
    /// Absolute N_TA in T_c units.
    pub n_ta_tc: i64,
    pub timer_slots: u32,
    expiry: Option<SlotPoint>,
    numerology: Numerology,
}

impl TimingAdvance {
    pub fn new(numerology: Numerology, timer_ms: u32) -> Self {
        Self { n_ta_tc: 0, timer_slots: timer_ms * numerology.slots_per_subframe(), expiry: None, numerology }
    }

    /// Apply the RAR 12-bit TA command (absolute).
    pub fn apply_rar(&mut self, ta_cmd: u16, now: SlotPoint) {
        self.n_ta_tc = ta::n_ta_from_rar(ta_cmd as u32, self.numerology);
        self.restart(now);
    }

    /// Apply a 6-bit TA Command MAC CE (relative).
    pub fn apply_ce(&mut self, ta_cmd: u8, now: SlotPoint) {
        self.n_ta_tc = ta::n_ta_apply_ce(self.n_ta_tc, ta_cmd, self.numerology);
        self.restart(now);
    }

    fn restart(&mut self, now: SlotPoint) {
        self.expiry = if self.timer_slots > 0 { Some(now.add(self.timer_slots as u64)) } else { None };
    }

    /// True while uplink is time-aligned (timer running or infinite).
    pub fn aligned(&self, now: SlotPoint) -> bool {
        match self.expiry {
            None => self.timer_slots == 0,
            Some(t) => now.diff(&t) < 0,
        }
    }

    pub fn reset(&mut self) {
        self.n_ta_tc = 0;
        self.expiry = None;
    }
}
