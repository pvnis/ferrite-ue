//! Scheduling Request procedure (TS 38.321 §5.4.4).

use ferrite_common::SlotPoint;

#[derive(Clone, Debug)]
pub struct SrProcedure {
    pub sr_id: u8,
    pub prohibit_slots: u32,
    pub trans_max: u32,
    /// (period, offset, pucch resource id) occasions.
    pub resources: Vec<(u16, u16, u8)>,
    pub pending: bool,
    pub sr_counter: u32,
    prohibit_until: Option<SlotPoint>,
    /// Set when SR_COUNTER reached sr-TransMax: MAC must start a RA and reset.
    pub failed: bool,
}

impl SrProcedure {
    pub fn new(cfg: &crate::SrConfig, slots_per_ms: u32) -> Self {
        Self {
            sr_id: cfg.sr_id,
            prohibit_slots: cfg.prohibit_ms * slots_per_ms,
            trans_max: cfg.trans_max,
            resources: cfg.resources.clone(),
            pending: false,
            sr_counter: 0,
            prohibit_until: None,
            failed: false,
        }
    }

    /// Trigger an SR (a regular BSR could not be sent).
    pub fn trigger(&mut self) {
        if !self.pending {
            self.pending = true;
            self.sr_counter = 0;
        }
    }

    pub fn cancel(&mut self) {
        self.pending = false;
        self.sr_counter = 0;
        self.prohibit_until = None;
    }

    /// Is `slot` an SR occasion? Returns the PUCCH resource id.
    pub fn occasion(&self, slot: SlotPoint) -> Option<u8> {
        self.resources.iter().find(|(p, o, _)| slot.is_occasion(*p as u32, *o as u32)).map(|r| r.2)
    }

    /// Decide whether to transmit an SR at `slot` (an occasion). Returns the
    /// PUCCH resource id when a positive SR must be sent. Implements the
    /// prohibit timer and SR_COUNTER / sr-TransMax (§5.4.4).
    pub fn should_send(&mut self, slot: SlotPoint) -> Option<u8> {
        if !self.pending || self.failed {
            return None;
        }
        let res = self.occasion(slot)?;
        if let Some(t) = self.prohibit_until {
            if slot.diff(&t) < 0 {
                return None;
            }
        }
        if self.sr_counter >= self.trans_max {
            self.failed = true;
            self.pending = false;
            return None;
        }
        self.sr_counter += 1;
        if self.prohibit_slots > 0 {
            self.prohibit_until = Some(slot.add(self.prohibit_slots as u64));
        }
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
        assert_eq!(sr.should_send(s(27 % 20)), Some(3).filter(|_| false).or(None)); // slot 7 of frame 1: counter exhausted
        assert!(sr.failed);
    }
}
