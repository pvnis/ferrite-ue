//! HARQ entities (TS 38.321 §5.3.2, §5.4.2) and the HARQ-ACK codebook
//! (TS 38.213 §9.1.3, dynamic / Type-2).
//!
//! Soft combining is a PHY matter (the PHY keeps the per-process LLR buffers
//! and reports CRC per transmission); MAC keeps the *process* bookkeeping:
//! NDI history, delivered flag, and the per-slot ACK codebook.

use ferrite_common::fsm::{Fsm, FsmStats, Machine, Rule};
use ferrite_common::{Rnti, SlotPoint};
use std::collections::BTreeMap;

/// One DL HARQ process (§5.3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DlHarqProcess {
    /// NDI of the last received DCI on this process, if any.
    pub ndi: Option<u8>,
    /// The TB with that NDI was delivered to the disassembly entity.
    pub delivered: bool,
}

/// [`DlHarqProcess`] without its NDI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlHarqPhase {
    /// No assignment yet (or after a MAC reset).
    Idle,
    /// A TB is being received (initial transmission or retransmissions).
    Receiving,
    /// That TB was decoded and delivered; retransmissions are ACKed unread.
    Delivered,
}

/// What moves a DL HARQ process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlHarqTrigger {
    /// An assignment with a toggled (or first) NDI: a new TB.
    NewData,
    /// The TB passed its CRC and went to the disassembly entity.
    Decoded,
    /// MAC reset.
    Reset,
}

/// The DL HARQ process machine.
pub struct DlHarqMachine;

impl Machine for DlHarqMachine {
    const NAME: &'static str = "DL HARQ";
    type State = DlHarqProcess;
    type Kind = DlHarqPhase;
    type Event = DlHarqTrigger;
    const KINDS: &'static [DlHarqPhase] = &[
        DlHarqPhase::Idle,
        DlHarqPhase::Receiving,
        DlHarqPhase::Delivered,
    ];
    const EVENTS: &'static [DlHarqTrigger] = &[
        DlHarqTrigger::NewData,
        DlHarqTrigger::Decoded,
        DlHarqTrigger::Reset,
    ];
    const INITIAL: DlHarqPhase = DlHarqPhase::Idle;
    const RULES: &'static [Rule<DlHarqPhase, DlHarqTrigger>] = {
        use DlHarqPhase::*;
        use DlHarqTrigger::*;
        &[
            Rule {
                from: &[Idle, Delivered],
                event: NewData,
                to: Receiving,
                clause: "38.321 §5.3.2.2 (NDI toggled: new transmission)",
            },
            Rule {
                from: &[Receiving],
                event: Decoded,
                to: Delivered,
                clause: "38.321 §5.3.2.2 (successfully decoded: deliver)",
            },
            Rule {
                from: &[Receiving, Delivered],
                event: Reset,
                to: Idle,
                clause: "38.321 §5.12 (MAC reset: NDI considered toggled)",
            },
        ]
    };
    fn kind(s: &DlHarqProcess) -> DlHarqPhase {
        match (s.ndi, s.delivered) {
            (None, _) => DlHarqPhase::Idle,
            (Some(_), false) => DlHarqPhase::Receiving,
            (Some(_), true) => DlHarqPhase::Delivered,
        }
    }
}

/// Enter `to` on `t` (refusals logged; a refusal is a bug, see
/// [`ferrite_common::fsm`]).
fn go<M: Machine>(f: &mut Fsm<M>, t: M::Event, to: M::State) {
    match f.transition(t, to) {
        Ok(Some(t)) => log::trace!("{t}"),
        Ok(None) => {}
        Err(v) => log::error!("{v}"),
    }
}

fn sum_stats<'a, M: Machine>(fs: impl Iterator<Item = &'a Fsm<M>>) -> FsmStats {
    fs.fold(FsmStats::default(), |a, f| FsmStats {
        transitions: a.transitions + f.stats().transitions,
        violations: a.violations + f.stats().violations,
    })
}

/// Downlink HARQ entity.
#[derive(Clone, Debug)]
pub struct DlHarqEntity {
    processes: Vec<Fsm<DlHarqMachine>>,
}

impl DlHarqEntity {
    pub fn new(n: u8) -> Self {
        Self {
            processes: (0..n.max(1))
                .map(|_| Fsm::new(DlHarqProcess::default()))
                .collect(),
        }
    }

    fn process(&mut self, harq_id: u8) -> &mut Fsm<DlHarqMachine> {
        let n = self.processes.len();
        &mut self.processes[harq_id as usize % n]
    }

    /// Classify a DL assignment: returns `(is_new_data, already_delivered)`.
    /// A toggled (or first) NDI means a new TB; the same NDI is a retransmission,
    /// which may already have been delivered (then it is ACKed without decode).
    pub fn on_assignment(&mut self, harq_id: u8, ndi: u8) -> (bool, bool) {
        let p = self.process(harq_id);
        let cur = *p.state();
        match cur.ndi {
            Some(prev) if prev == ndi => (false, cur.delivered),
            _ => {
                go(
                    p,
                    DlHarqTrigger::NewData,
                    DlHarqProcess {
                        ndi: Some(ndi),
                        delivered: false,
                    },
                );
                (true, false)
            }
        }
    }

    pub fn is_delivered(&self, harq_id: u8) -> bool {
        self.processes[harq_id as usize % self.processes.len()]
            .state()
            .delivered
    }

    pub fn mark_delivered(&mut self, harq_id: u8) {
        let p = self.process(harq_id);
        let cur = *p.state();
        if cur.ndi.is_some() && !cur.delivered {
            go(
                p,
                DlHarqTrigger::Decoded,
                DlHarqProcess {
                    delivered: true,
                    ..cur
                },
            );
        }
    }

    pub fn reset(&mut self) {
        for p in &mut self.processes {
            if p.kind() != DlHarqPhase::Idle {
                go(p, DlHarqTrigger::Reset, DlHarqProcess::default());
            }
        }
    }

    /// Transitions made and refused over the processes.
    pub fn fsm_stats(&self) -> FsmStats {
        sum_stats(self.processes.iter())
    }
}

/// One UL HARQ process (§5.4.2): the stored TB for retransmissions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UlHarqProcess {
    pub ndi: Option<u8>,
    pub tbs_bits: u32,
    pub tb: Vec<u8>,
}

/// [`UlHarqProcess`] without its TB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UlHarqPhase {
    /// Nothing stored.
    Empty,
    /// A TB is stored for retransmissions on this process.
    Holding,
}

/// What moves a UL HARQ process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UlHarqTrigger {
    /// A new TB went out (NDI toggled, or the first grant).
    NewTransmission,
    /// MAC reset (the HARQ buffers are flushed).
    Reset,
}

/// The UL HARQ process machine.
pub struct UlHarqMachine;

impl Machine for UlHarqMachine {
    const NAME: &'static str = "UL HARQ";
    type State = UlHarqProcess;
    type Kind = UlHarqPhase;
    type Event = UlHarqTrigger;
    const KINDS: &'static [UlHarqPhase] = &[UlHarqPhase::Empty, UlHarqPhase::Holding];
    const EVENTS: &'static [UlHarqTrigger] =
        &[UlHarqTrigger::NewTransmission, UlHarqTrigger::Reset];
    const INITIAL: UlHarqPhase = UlHarqPhase::Empty;
    const RULES: &'static [Rule<UlHarqPhase, UlHarqTrigger>] = &[
        Rule {
            from: &[UlHarqPhase::Empty],
            event: UlHarqTrigger::NewTransmission,
            to: UlHarqPhase::Holding,
            clause: "38.321 §5.4.2.2 (new transmission: store the MAC PDU)",
        },
        Rule {
            from: &[UlHarqPhase::Holding],
            event: UlHarqTrigger::Reset,
            to: UlHarqPhase::Empty,
            clause: "38.321 §5.12 (MAC reset: flush the HARQ buffers)",
        },
    ];
    fn kind(s: &UlHarqProcess) -> UlHarqPhase {
        if s.tb.is_empty() {
            UlHarqPhase::Empty
        } else {
            UlHarqPhase::Holding
        }
    }
}

/// Uplink HARQ entity.
#[derive(Clone, Debug)]
pub struct UlHarqEntity {
    processes: Vec<Fsm<UlHarqMachine>>,
}

impl UlHarqEntity {
    pub fn new(n: u8) -> Self {
        Self {
            processes: (0..n.max(1))
                .map(|_| Fsm::new(UlHarqProcess::default()))
                .collect(),
        }
    }

    fn get(&self, harq_id: u8) -> &UlHarqProcess {
        self.processes[harq_id as usize % self.processes.len()].state()
    }

    /// Is a grant with this NDI/TBS a retransmission of the stored TB?
    pub fn is_retx(&self, harq_id: u8, ndi: u8, tbs_bits: u32) -> bool {
        let p = self.get(harq_id);
        p.ndi == Some(ndi) && p.tbs_bits == tbs_bits && !p.tb.is_empty()
    }

    pub fn stored(&self, harq_id: u8) -> &[u8] {
        &self.get(harq_id).tb
    }

    pub fn store(&mut self, harq_id: u8, ndi: u8, tbs_bits: u32, tb: Vec<u8>) {
        let n = self.processes.len();
        go(
            &mut self.processes[harq_id as usize % n],
            UlHarqTrigger::NewTransmission,
            UlHarqProcess {
                ndi: Some(ndi),
                tbs_bits,
                tb,
            },
        );
    }

    pub fn reset(&mut self) {
        for p in &mut self.processes {
            if p.kind() != UlHarqPhase::Empty {
                go(p, UlHarqTrigger::Reset, UlHarqProcess::default());
            }
        }
    }

    /// Transitions made and refused over the processes.
    pub fn fsm_stats(&self) -> FsmStats {
        sum_stats(self.processes.iter())
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
        if let Some(e) = v
            .iter_mut()
            .find(|e| e.pdsch_slot == entry.pdsch_slot && e.harq_id == entry.harq_id)
        {
            *e = entry;
        } else {
            v.push(entry);
        }
    }

    /// Record the decode result for a PDSCH (by its slot + HARQ id).
    pub fn set_result(&mut self, pdsch_slot: SlotPoint, harq_id: u8, ack: bool) -> bool {
        for v in self.slots.values_mut() {
            if let Some(e) = v
                .iter_mut()
                .find(|e| e.pdsch_slot == pdsch_slot && e.harq_id == harq_id)
            {
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
        self.slots.get(&ack_slot.index()).and_then(|v| {
            v.iter()
                .max_by_key(|e| (e.pdsch_slot.index(), e.dai))
                .map(|e| e.pri)
        })
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
            let d = if d > total as i64 / 2 {
                d - total as i64
            } else {
                d
            };
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
    bits.resize(bits.len() + expected_dai as usize, 0);
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
        assert_eq!(h.on_assignment(3, 1), (true, false));
        assert_eq!(h.on_assignment(3, 1), (false, false));
        h.mark_delivered(3);
        assert_eq!(h.on_assignment(3, 1), (false, true));
        assert_eq!(h.on_assignment(3, 0), (true, false));
        assert!(!h.is_delivered(3));
    }

    #[test]
    fn codebook_orders_and_fills_gaps() {
        let mut b = AckBook::default();
        let ack = sp(7);
        let e = |dai: u8, s: u16, ack: Option<bool>| AckEntry {
            rnti: Rnti(1),
            pdsch_slot: sp(s),
            harq_id: dai,
            dai,
            ack,
            pri: 0,
        };
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
