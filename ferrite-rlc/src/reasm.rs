//! Byte-segment reassembly of one RLC SDU (TS 38.322 §5.2.2.2.3 / §5.2.3.2.3).
//!
//! Segments arrive keyed by Segment Offset, possibly out of order, duplicated,
//! overlapping (a retransmission re-segmented differently) or with the last
//! segment first. The receiver keeps a byte buffer plus a sorted list of
//! covered `[start, end)` intervals; the SDU is complete once a single interval
//! covers `[0, total)` where `total` is learnt from the segment with SI = last.

/// Reassembly state of a single SDU.
#[derive(Clone, Debug, Default)]
pub struct RxSdu {
    buf: Vec<u8>,
    /// Sorted, merged, non-overlapping covered intervals `[start, end)`.
    cov: Vec<(usize, usize)>,
    /// SDU length, known once the last segment (or a complete SDU) was received.
    total: Option<usize>,
}

impl RxSdu {
    /// Insert the bytes of a segment starting at offset `so`. `is_last` marks
    /// the segment carrying the final byte (SI = 00 or 10). Returns `false` if
    /// the segment added no new bytes (full duplicate, empty, or inconsistent
    /// with an already-known SDU length).
    pub fn insert(&mut self, so: usize, data: &[u8], is_last: bool) -> bool {
        if data.is_empty() {
            return false;
        }
        let end = so + data.len();
        match self.total {
            Some(t) if end > t || (is_last && end != t) => return false,
            _ => {}
        }
        if is_last {
            self.total = Some(end);
        }
        if self.covers(so, end) {
            return false;
        }
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[so..end].copy_from_slice(data);
        self.cov.push((so, end));
        self.cov.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.cov.len());
        for &(s, e) in &self.cov {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.cov = merged;
        true
    }

    /// Whether every byte of `[so, end)` has already been received.
    pub fn covers(&self, so: usize, end: usize) -> bool {
        self.cov.iter().any(|&(s, e)| s <= so && end <= e)
    }

    /// All bytes of the SDU received.
    pub fn is_complete(&self) -> bool {
        match (self.total, self.cov.as_slice()) {
            (Some(t), [(0, e)]) => *e == t,
            _ => false,
        }
    }

    /// "There is at least one missing byte segment before the last byte of all
    /// received segments" (the t-Reassembly start condition).
    pub fn has_gap_before_last(&self) -> bool {
        self.cov.len() > 1 || self.cov.first().is_some_and(|&(s, _)| s > 0)
    }

    /// Missing byte ranges `(start, end)` in offset order, `end == None` meaning
    /// "to the (still unknown) end of the SDU". Empty for a complete SDU.
    pub fn gaps(&self) -> Vec<(usize, Option<usize>)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        for &(s, e) in &self.cov {
            if s > cursor {
                out.push((cursor, Some(s)));
            }
            cursor = e;
        }
        match self.total {
            Some(t) if cursor < t => out.push((cursor, Some(t))),
            None => out.push((cursor, None)),
            _ => {}
        }
        out
    }

    /// Take the reassembled SDU (only meaningful when `is_complete()`).
    pub fn into_sdu(mut self) -> Vec<u8> {
        if let Some(t) = self.total {
            self.buf.truncate(t);
        }
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_and_overlap() {
        let sdu: Vec<u8> = (0..50u8).collect();
        let mut r = RxSdu::default();
        assert!(r.insert(40, &sdu[40..], true));
        assert!(!r.is_complete());
        assert!(r.has_gap_before_last());
        assert_eq!(r.gaps(), vec![(0, Some(40))]);
        assert!(r.insert(0, &sdu[..20], false));
        assert_eq!(r.gaps(), vec![(20, Some(40))]);
        // Overlapping retransmission re-segmented differently.
        assert!(r.insert(10, &sdu[10..45], false));
        assert!(r.is_complete());
        assert!(r.gaps().is_empty());
        // Duplicate adds nothing.
        assert!(!r.insert(0, &sdu[..20], false));
        assert_eq!(r.into_sdu(), sdu);
    }

    #[test]
    fn unknown_end_gap_and_inconsistent_last() {
        let mut r = RxSdu::default();
        assert!(r.insert(0, &[1, 2, 3], false));
        assert!(!r.has_gap_before_last());
        assert_eq!(r.gaps(), vec![(3, None)]);
        assert!(r.insert(3, &[4], true));
        assert!(r.is_complete());
        // A second "last" with a different length is rejected.
        assert!(!r.insert(4, &[5], true));
        assert!(!r.insert(0, &[], false));
        assert_eq!(r.into_sdu(), [1, 2, 3, 4]);
    }
}
