//! HARQ entities (TS 38.321 §5.4.2): per-process state for the downlink and
//! uplink HARQ processes the UE runs.
//!
//! The MAC owns the *process* bookkeeping — which HARQ id carries which TB, its
//! NDI/redundancy history, the recorded first-transmission shape, and (DL) the
//! accumulated soft-combine buffer. The physical layer supplies the per-RV soft
//! bits (`cb`) and performs the LDPC decode of the accumulated sum; this module
//! only tracks and combines, so it stays free of any PHY dependency.

use std::collections::HashMap;

/// One DL HARQ process's soft-combining buffer: the accumulated circular-buffer
/// LLRs of the transport block currently in flight on the process, tagged with
/// the code parameters they were built with (a change ⇒ the gNB reused the
/// process for a new TB, so the buffer is reset).
struct HarqDlBuf {
    tbs: usize,
    qm: usize,
    acc: Vec<f32>,
    n_rx: usize,
}

/// Downlink HARQ entity: the per-process soft-combine buffers plus the
/// bookkeeping used to classify a (re)transmission (recorded first-tx shape,
/// delivered NDI for blind-ACK of an already-received TB).
#[derive(Default)]
pub struct DlHarq {
    /// Soft-combine buffers, per HARQ process id.
    combine: HashMap<u8, HarqDlBuf>,
    /// First-transmission shape `(ndi, mcs, n_rb, sliv)` — a retx keeps the TB's
    /// original size/allocation even when the gNB link-adapts the retx MCS.
    shape: HashMap<u8, (u8, u8, usize, u8)>,
    /// NDI of the TB last delivered on this process: a retx of it can be
    /// blind-ACKed (CRC-OK already) without re-decoding.
    done: HashMap<u8, u8>,
}

impl DlHarq {
    /// Accumulate this (re)transmission's circular-buffer soft bits `cb` into the
    /// process buffer and return the running reception count. Resets the buffer
    /// on `rv == 0` (a fresh transmission) or a code-parameter change (the
    /// process was reused for a different TB).
    pub fn accumulate(&mut self, h_id: u8, tbs: usize, qm: usize, rv: u8, cb: &[f32]) -> usize {
        let e = self
            .combine
            .entry(h_id)
            .or_insert_with(|| HarqDlBuf { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 });
        if e.tbs != tbs || e.qm != qm || e.acc.len() != cb.len() || rv == 0 {
            *e = HarqDlBuf { tbs, qm, acc: vec![0.0; cb.len()], n_rx: 0 };
        }
        for (a, &c) in e.acc.iter_mut().zip(cb) {
            *a += c;
        }
        e.n_rx += 1;
        e.n_rx
    }

    /// The accumulated soft-combine buffer for `h_id` (to hand to the LDPC
    /// decoder), if a buffer exists.
    pub fn combined(&self, h_id: u8) -> Option<&[f32]> {
        self.combine.get(&h_id).map(|e| e.acc.as_slice())
    }

    /// Discard the soft-combine buffer for a process (its TB was delivered or
    /// faithfully received).
    pub fn clear_process(&mut self, h_id: u8) {
        self.combine.remove(&h_id);
    }

    /// NDI of the TB last delivered on this process, if any (a retx with the same
    /// NDI can be ACKed without decoding).
    pub fn delivered_ndi(&self, h_id: u8) -> Option<u8> {
        self.done.get(&h_id).copied()
    }

    /// Mark a process's TB delivered at NDI `ndi` and record the shape that
    /// decoded it (used to re-classify its later retransmissions).
    pub fn mark_delivered(&mut self, h_id: u8, ndi: u8, mcs: u8, n_rb: usize, sliv: u8) {
        self.done.insert(h_id, ndi);
        self.shape.insert(h_id, (ndi, mcs, n_rb, sliv));
    }

    /// The recorded `(ndi, mcs, n_rb, sliv)` first-transmission shape for a
    /// process, if any.
    pub fn recorded(&self, h_id: u8) -> Option<(u8, u8, usize, u8)> {
        self.shape.get(&h_id).copied()
    }

    /// Record the first-transmission shape of a newly-seen TB on this process.
    pub fn record_first_tx(&mut self, h_id: u8, ndi: u8, mcs: u8, n_rb: usize, sliv: u8) {
        self.shape.insert(h_id, (ndi, mcs, n_rb, sliv));
    }

    /// Forget all process state (on re-establishment / a new C-RNTI).
    pub fn reset(&mut self) {
        self.combine.clear();
        self.shape.clear();
        self.done.clear();
    }
}

/// Uplink HARQ entity: the stored transport block per process so a retransmission
/// grant can resend the exact same TB at the DCI's redundancy version (fresh
/// content would poison the gNB's soft combine).
#[derive(Default)]
pub struct UlHarq {
    /// `(ndi, tbs_bytes, stored TB)` per HARQ process id.
    proc: HashMap<u8, (u8, usize, Vec<u8>)>,
}

impl UlHarq {
    /// True if a grant for `h_id` with this `ndi`/`tbs` is a retransmission of the
    /// stored TB (same NDI and size) rather than a new transmission.
    pub fn is_retx(&self, h_id: u8, ndi: u8, tbs_bytes: usize) -> bool {
        self.proc.get(&h_id).is_some_and(|(n, t, _)| *n == ndi && *t == tbs_bytes)
    }

    /// The stored transport block for a process (to resend on a retx grant).
    pub fn stored(&self, h_id: u8) -> Option<&[u8]> {
        self.proc.get(&h_id).map(|(_, _, tb)| tb.as_slice())
    }

    /// Store a freshly-built transport block for a process.
    pub fn store(&mut self, h_id: u8, ndi: u8, tbs_bytes: usize, tb: Vec<u8>) {
        self.proc.insert(h_id, (ndi, tbs_bytes, tb));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dl_soft_combine_accumulates_and_resets() {
        let mut h = DlHarq::default();
        assert_eq!(h.accumulate(0, 100, 2, 0, &[1.0, 1.0]), 1);
        assert_eq!(h.accumulate(0, 100, 2, 2, &[1.0, 1.0]), 2); // combines
        assert_eq!(h.combined(0), Some([2.0, 2.0].as_slice()));
        // rv==0 resets the buffer (new transmission).
        assert_eq!(h.accumulate(0, 100, 2, 0, &[1.0, 1.0]), 1);
        assert_eq!(h.combined(0), Some([1.0, 1.0].as_slice()));
        h.clear_process(0);
        assert_eq!(h.combined(0), None);
    }

    #[test]
    fn dl_shape_and_delivered() {
        let mut h = DlHarq::default();
        h.record_first_tx(3, 1, 9, 5, 53);
        assert_eq!(h.recorded(3), Some((1, 9, 5, 53)));
        assert_eq!(h.delivered_ndi(3), None);
        h.mark_delivered(3, 1, 9, 5, 53);
        assert_eq!(h.delivered_ndi(3), Some(1));
        h.reset();
        assert_eq!(h.recorded(3), None);
    }

    #[test]
    fn ul_retx_store_and_fetch() {
        let mut u = UlHarq::default();
        u.store(2, 0, 285, vec![0xaa, 0xbb]);
        assert!(u.is_retx(2, 0, 285));
        assert!(!u.is_retx(2, 1, 285)); // NDI toggled = new TB
        assert!(!u.is_retx(2, 0, 100)); // different size
        assert_eq!(u.stored(2), Some([0xaa, 0xbb].as_slice()));
    }
}
