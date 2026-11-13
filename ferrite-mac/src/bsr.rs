//! Buffer Status Reporting (TS 38.321 §5.4.5).
//!
//! Triggers: new data for a channel with higher priority than any with data
//! (regular BSR), `retxBSR-Timer` expiry with data (regular), `periodicBSR-Timer`
//! expiry (periodic), padding room (padding BSR). A regular BSR without a grant
//! triggers an SR (§5.4.4).

use ferrite_common::SlotPoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BsrTrigger {
    None,
    Regular,
    Periodic,
}

#[derive(Clone, Debug)]
pub struct BsrProcedure {
    pub periodic_slots: u32,
    pub retx_slots: u32,
    periodic_expiry: Option<SlotPoint>,
    retx_expiry: Option<SlotPoint>,
    pub pending: BsrTrigger,
    /// Highest-priority (lowest number) channel that had data at the last check,
    /// for the "higher priority than any with data" rule.
    last_prio_with_data: Option<u8>,
    /// Set when a regular BSR was triggered and no grant can carry it: SR needed.
    pub sr_pending: bool,
}

impl BsrProcedure {
    pub fn new(periodic_slots: u32, retx_slots: u32) -> Self {
        Self { periodic_slots, retx_slots, periodic_expiry: None, retx_expiry: None, pending: BsrTrigger::None, last_prio_with_data: None, sr_pending: false }
    }

    /// Evaluate the buffer state. `prios_with_data` lists the priorities (1 =
    /// highest) of channels that currently have data. Call once per slot.
    pub fn evaluate(&mut self, now: SlotPoint, prios_with_data: &[u8]) {
        let best = prios_with_data.iter().copied().min();
        if let Some(b) = best {
            // New data on a channel with higher priority than all that had data.
            if self.last_prio_with_data.map_or(true, |p| b < p) {
                self.trigger_regular();
            }
        }
        self.last_prio_with_data = best;
        if let Some(t) = self.periodic_expiry {
            if now.diff(&t) >= 0 {
                self.periodic_expiry = None;
                if self.pending == BsrTrigger::None && best.is_some() {
                    self.pending = BsrTrigger::Periodic;
                }
            }
        }
        if let Some(t) = self.retx_expiry {
            if now.diff(&t) >= 0 {
                self.retx_expiry = None;
                if best.is_some() {
                    self.trigger_regular();
                }
            }
        }
        if best.is_none() {
            self.last_prio_with_data = None;
        }
    }

    fn trigger_regular(&mut self) {
        self.pending = BsrTrigger::Regular;
        self.sr_pending = true;
    }

    /// A BSR was included in a MAC PDU transmitted at `now` (§5.4.5): restart
    /// the timers, clear the trigger (and the SR need).
    pub fn on_bsr_sent(&mut self, now: SlotPoint, truncated: bool) {
        if self.periodic_slots > 0 {
            self.periodic_expiry = Some(now.add(self.periodic_slots as u64));
        }
        if self.retx_slots > 0 {
            self.retx_expiry = Some(now.add(self.retx_slots as u64));
        }
        if !truncated {
            self.pending = BsrTrigger::None;
        }
        self.sr_pending = false;
    }

    /// Any UL grant that carries new data restarts retxBSR-Timer (§5.4.5).
    pub fn on_new_data_grant(&mut self, now: SlotPoint) {
        if self.retx_slots > 0 {
            self.retx_expiry = Some(now.add(self.retx_slots as u64));
        }
    }

    /// Cancel all triggered BSRs (e.g. all data fitted and no BSR needed).
    pub fn cancel(&mut self) {
        self.pending = BsrTrigger::None;
        self.sr_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::Numerology;

    #[test]
    fn regular_then_periodic() {
        let mut b = BsrProcedure::new(10, 80);
        let s = |n: u16| SlotPoint::new(Numerology::KHZ30, 0, n);
        b.evaluate(s(0), &[]);
        assert_eq!(b.pending, BsrTrigger::None);
        b.evaluate(s(1), &[4]);
        assert_eq!(b.pending, BsrTrigger::Regular);
        assert!(b.sr_pending);
        b.on_bsr_sent(s(2), false);
        assert_eq!(b.pending, BsrTrigger::None);
        for n in 3..12 {
            b.evaluate(s(n), &[4]);
            assert_eq!(b.pending, BsrTrigger::None, "slot {n}");
        }
        b.evaluate(s(12), &[4]);
        assert_eq!(b.pending, BsrTrigger::Periodic);
        // A higher-priority channel getting data re-triggers a regular BSR.
        b.evaluate(s(13), &[4, 1]);
        assert_eq!(b.pending, BsrTrigger::Regular);
    }
}
