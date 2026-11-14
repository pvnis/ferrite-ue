//! Scheduling Request procedure (TS 38.321 §5.4.4): `Idle → Pending → Idle`
//! (a BSR went out) or `Pending → Failed` (sr-TransMax reached, the entity
//! then starts a random access and clears the state with `take_failed`).

use ferrite_common::SlotPoint;

/// SR state (TS 38.321 §5.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrState {
    /// No SR pending.
    Idle,
    /// An SR is pending: `counter` = SR_COUNTER, `prohibit_until` = sr-ProhibitTimer expiry.
    Pending { counter: u32, prohibit_until: Option<SlotPoint> },
    /// SR_COUNTER reached sr-TransMax: MAC must release PUCCH/SRS, clear the
    /// configured grants and start a random access (`take_failed`).
    Failed,
}

#[derive(Clone, Debug)]
pub struct SrProcedure {
    pub sr_id: u8,
    pub prohibit_slots: u32,
    pub trans_max: u32,
    /// (period, offset, pucch resource id) occasions.
    pub resources: Vec<(u16, u16, u8)>,
    state: SrState,
}

impl SrProcedure {
    pub fn new(cfg: &crate::SrConfig, slots_per_ms: u32) -> Self {
        Self {
            sr_id: cfg.sr_id,
            prohibit_slots: cfg.prohibit_ms.saturating_mul(slots_per_ms),
            trans_max: cfg.trans_max,
            resources: cfg.resources.clone(),
            state: SrState::Idle,
        }
    }

    pub fn state(&self) -> SrState {
        self.state
    }

    /// Trigger an SR (a regular BSR could not be sent). A pending SR is kept
    /// (its counter continues); a failed one stays failed until `take_failed`.
    pub fn trigger(&mut self) {
        if self.state == SrState::Idle {
            self.state = SrState::Pending { counter: 0, prohibit_until: None };
        }
    }

    /// Cancel every pending SR (a BSR went out, or the entity is reset).
    pub fn cancel(&mut self) {
        self.state = SrState::Idle;
    }


    /// `true` once (and resets to `Idle`) when sr-TransMax was reached.
    pub fn take_failed(&mut self) -> bool {
        if self.state == SrState::Failed {
            self.state = SrState::Idle;
            true
        } else {
            false
        }
    }

    /// Is `slot` an SR occasion? Returns the PUCCH resource id.
    pub fn occasion(&self, slot: SlotPoint) -> Option<u8> {
        self.resources.iter().find(|(p, o, _)| slot.is_occasion(*p as u32, *o as u32)).map(|r| r.2)
    }

    /// Decide whether to transmit an SR at `slot` (an occasion). Returns the
    /// PUCCH resource id when a positive SR must be sent. Implements the
    /// prohibit timer and SR_COUNTER / sr-TransMax (§5.4.4).
    pub fn should_send(&mut self, slot: SlotPoint) -> Option<u8> {
        let SrState::Pending { counter, prohibit_until } = self.state else { return None };
        let res = self.occasion(slot)?;
        if let Some(t) = prohibit_until {
            if slot.diff(&t) < 0 {
                return None;
            }
        }
        if counter >= self.trans_max {
            self.state = SrState::Failed;
            return None;
        }
        let prohibit = (self.prohibit_slots > 0).then(|| slot.add(self.prohibit_slots as u64));
        self.state = SrState::Pending { counter: counter + 1, prohibit_until: prohibit };
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::Numerology;

    #[test]
    fn sr_occasions_and_transmax() {
        let cfg = crate::SrConfig { sr_id: 0, prohibit_ms: 0, trans_max: 2, resources: vec![(10, 7, 3)] };
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
}
