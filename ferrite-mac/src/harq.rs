//! HARQ entities (TS 38.321 §5.3.2, §5.4.2) and the HARQ-ACK codebook
//! (TS 38.213 §9.1.3, dynamic / Type-2).
//!
//! Soft combining is a PHY matter (the PHY keeps the per-process LLR buffers
//! and reports CRC per transmission); MAC keeps the *process* bookkeeping:
//! NDI history, delivered flag, and the per-slot ACK codebook.

use ferrite_common::{Rnti, SlotPoint};
use std::collections::BTreeMap;

/// One DL HARQ process (§5.3.2).
#[derive(Clone, Copy, Debug, Default)]
pub struct DlHarqProcess {
    /// NDI of the last received DCI on this process, if any.
    pub ndi: Option<u8>,
    /// The TB with that NDI was delivered to the disassembly entity.
    pub delivered: bool,
    /// TBS of the TB in flight (bits).
    pub tbs_bits: u32,
}

/// Downlink HARQ entity.
#[derive(Clone, Debug)]
pub struct DlHarqEntity {
    processes: Vec<DlHarqProcess>,
}

impl DlHarqEntity {
    pub fn new(n: u8) -> Self {
        Self { processes: vec![DlHarqProcess::default(); n.max(1) as usize] }
    }

    /// Classify a DL assignment: returns `(is_new_data, already_delivered)`.
    /// A toggled (or first) NDI means a new TB; the same NDI is a retransmission,
    /// which may already have been delivered (then it is ACKed without decode).
    pub fn on_assignment(&mut self, harq_id: u8, ndi: u8, tbs_bits: u32) -> (bool, bool) {
        let n = self.processes.len();
        let p = &mut self.processes[harq_id as usize % n];
        match p.ndi {
            Some(prev) if prev == ndi => (false, p.delivered),
            _ => {
                *p = DlHarqProcess { ndi: Some(ndi), delivered: false, tbs_bits };
                (true, false)
            }
        }
    }

    pub fn tbs_bits(&self, harq_id: u8) -> u32 {
        self.processes[harq_id as usize % self.processes.len()].tbs_bits
    }

    pub fn is_delivered(&self, harq_id: u8) -> bool {
        self.processes[harq_id as usize % self.processes.len()].delivered
    }

    pub fn mark_delivered(&mut self, harq_id: u8) {
        let n = self.processes.len();
        self.processes[harq_id as usize % n].delivered = true;
    }

    pub fn reset(&mut self) {
        for p in &mut self.processes {
            *p = DlHarqProcess::default();
        }
    }
}

/// One UL HARQ process (§5.4.2): the stored TB for retransmissions.
#[derive(Clone, Debug, Default)]
pub struct UlHarqProcess {
    pub ndi: Option<u8>,
    pub tbs_bits: u32,
    pub tb: Vec<u8>,
}

/// Uplink HARQ entity.
#[derive(Clone, Debug)]
pub struct UlHarqEntity {
    processes: Vec<UlHarqProcess>,
}

impl UlHarqEntity {
    pub fn new(n: u8) -> Self {
        Self { processes: vec![UlHarqProcess::default(); n.max(1) as usize] }
    }

    /// Is a grant with this NDI/TBS a retransmission of the stored TB?
    pub fn is_retx(&self, harq_id: u8, ndi: u8, tbs_bits: u32) -> bool {
        let p = &self.processes[harq_id as usize % self.processes.len()];
        p.ndi == Some(ndi) && p.tbs_bits == tbs_bits && !p.tb.is_empty()
    }

    pub fn stored(&self, harq_id: u8) -> &[u8] {
        &self.processes[harq_id as usize % self.processes.len()].tb
    }

    pub fn store(&mut self, harq_id: u8, ndi: u8, tbs_bits: u32, tb: Vec<u8>) {
        let n = self.processes.len();
        self.processes[harq_id as usize % n] = UlHarqProcess { ndi: Some(ndi), tbs_bits, tb };
    }

    pub fn reset(&mut self) {
        for p in &mut self.processes {
            *p = UlHarqProcess::default();
        }
    }
}

/// A pending HARQ-ACK for one PDSCH, keyed by its UL (ACK) slot.
#[derive(Clone, Debug, PartialEq)]
pub struct AckEntry {
    pub rnti: Rnti,
    pub pdsch_slot: SlotPoint,
    pub harq_id: u8,
    pub dai: u8,
    /// `None` until the decode result arrived (then ACK=1/NACK=0).
    pub ack: Option<bool>,
    pub pri: u8,
}

/// The per-ACK-slot HARQ-ACK codebook (dynamic, TS 38.213 §9.1.3.1): entries
/// ordered by counter DAI; gaps (missed DCIs) are NACKed.
#[derive(Clone, Debug, Default)]
pub struct AckBook {
    slots: BTreeMap<u64, Vec<AckEntry>>,
}

impl AckBook {
    /// Pre-book a NACK when the DCI is decoded (so a lost/late decode still
    /// yields a correctly sized codebook).
    pub fn book(&mut self, ack_slot: SlotPoint, entry: AckEntry) {
        let v = self.slots.entry(ack_slot.index()).or_default();
        if let Some(e) = v.iter_mut().find(|e| e.pdsch_slot == entry.pdsch_slot && e.harq_id == entry.harq_id) {
            *e = entry;
        } else {
            v.push(entry);
        }
    }

    /// Record the decode result for a PDSCH (by its slot + HARQ id).
    pub fn set_result(&mut self, pdsch_slot: SlotPoint, harq_id: u8, ack: bool) -> bool {
        for v in self.slots.values_mut() {
            if let Some(e) = v.iter_mut().find(|e| e.pdsch_slot == pdsch_slot && e.harq_id == harq_id) {
                e.ack = Some(ack);
                return true;
            }
        }
        false
    }

    pub fn has_slot(&self, ack_slot: SlotPoint) -> bool {
        self.slots.contains_key(&ack_slot.index())
    }

    /// The PRI of the last DCI targeting `ack_slot` (TS 38.213 §9.2.3: the
    /// PUCCH resource follows the last DCI).
    pub fn pri(&self, ack_slot: SlotPoint) -> Option<u8> {
        self.slots.get(&ack_slot.index()).and_then(|v| v.iter().max_by_key(|e| (e.pdsch_slot.index(), e.dai)).map(|e| e.pri))
    }

    /// Take the codebook for `ack_slot`: bits ordered by DAI with gaps NACKed.
    /// `total_dai` (from a DCI 0_1 UL grant, (count−1) mod 4) can extend the size.
    pub fn take(&mut self, ack_slot: SlotPoint, total_dai: Option<u8>) -> Vec<u8> {
        let entries = self.slots.remove(&ack_slot.index()).unwrap_or_default();
        codebook_from(&entries, total_dai)
    }

    /// Drop codebooks whose ACK slot is already in the past.
    pub fn prune(&mut self, now: SlotPoint) {
        let idx = now.index();
        let total = now.slots_per_frame() as u64 * 1024;
        self.slots.retain(|&k, _| {
            let d = (k as i64 - idx as i64).rem_euclid(total as i64);
            let d = if d > total as i64 / 2 { d - total as i64 } else { d };
            d >= 0
        });
    }
}

/// Build the dynamic codebook bits from the booked entries (§9.1.3.1 with a
/// single serving cell: one bit per PDSCH, ordered by the DAI sequence).
fn codebook_from(entries: &[AckEntry], total_dai: Option<u8>) -> Vec<u8> {
    if entries.is_empty() {
        return match total_dai {
            // T-DAI = (N−1) mod 4 with N unknown-but-≥1; without any DCI seen we
            // cannot know N beyond the residue — assume the smallest consistent N.
            Some(t) if t < 3 => vec![0; t as usize + 1],
            _ => Vec::new(),
        };
    }
    // Order by PDSCH slot then DAI; unwrap the 2-bit counter into a running index.
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| (e.pdsch_slot.index(), e.dai));
    let mut bits: Vec<u8> = Vec::new();
    let mut expected_dai = sorted[0].dai & 3;
    // If the first DCI's counter isn't 0 we missed the earlier ones.
    for _ in 0..(expected_dai as usize) {
        bits.push(0);
    }
    for e in &sorted {
        while (e.dai & 3) != expected_dai {
            bits.push(0); // a missed PDSCH between consecutive DAIs
            expected_dai = (expected_dai + 1) & 3;
        }
        bits.push(u8::from(e.ack == Some(true)));
        expected_dai = (expected_dai + 1) & 3;
    }
    if let Some(t) = total_dai {
        // Extend to the smallest N ≥ len with (N−1) mod 4 == t.
        while ((bits.len() as u8).wrapping_sub(1) & 3) != (t & 3) {
            bits.push(0);
            if bits.len() > 32 {
                break;
            }
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::Numerology;

    fn sp(s: u16) -> SlotPoint {
        SlotPoint::new(Numerology::KHZ30, 0, s)
    }

    #[test]
    fn dl_ndi_classification() {
        let mut h = DlHarqEntity::new(16);
        assert_eq!(h.on_assignment(3, 1, 100), (true, false));
        assert_eq!(h.on_assignment(3, 1, 100), (false, false));
        h.mark_delivered(3);
        assert_eq!(h.on_assignment(3, 1, 100), (false, true));
        assert_eq!(h.on_assignment(3, 0, 200), (true, false));
        assert_eq!(h.tbs_bits(3), 200);
    }

    #[test]
    fn codebook_orders_and_fills_gaps() {
        let mut b = AckBook::default();
        let ack = sp(7);
        let e = |dai: u8, s: u16, ack: Option<bool>| AckEntry { rnti: Rnti(1), pdsch_slot: sp(s), harq_id: dai, dai, ack, pri: 0 };
        b.book(ack, e(0, 1, Some(true)));
        b.book(ack, e(2, 3, Some(true))); // DAI 1 missed
        assert!(b.set_result(sp(1), 0, true));
        assert_eq!(b.take(ack, None), vec![1, 0, 1]);
        assert!(!b.has_slot(ack));
        // Total DAI extension: 3 PDSCHs seen, T-DAI says (N−1) mod 4 = 3 → N=4.
        b.book(ack, e(0, 1, Some(true)));
        b.book(ack, e(1, 2, Some(false)));
        b.book(ack, e(2, 3, None));
        assert_eq!(b.take(ack, Some(3)), vec![1, 0, 0, 0]);
        // Nothing booked but a grant says one ACK bit is expected.
        assert_eq!(b.take(ack, Some(0)), vec![0]);
        assert_eq!(b.take(ack, Some(3)), Vec::<u8>::new());
    }

    #[test]
    fn ul_retx_detection() {
        let mut u = UlHarqEntity::new(16);
        u.store(2, 0, 288, vec![1, 2, 3]);
        assert!(u.is_retx(2, 0, 288));
        assert!(!u.is_retx(2, 1, 288));
        assert!(!u.is_retx(2, 0, 100));
        assert_eq!(u.stored(2), &[1, 2, 3]);
    }
}
