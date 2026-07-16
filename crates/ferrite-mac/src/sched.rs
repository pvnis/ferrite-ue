//! MAC uplink scheduling state (TS 38.321 §5.4): the buffer-status-report keep
//! -alive that governs how the UE answers UL grants when it has no logical
//! -channel data of its own to send.
//!
//! The logical-channel prioritisation (which SDU source fills a grant) is driven
//! by the higher layers that own those sources (RRC on SRB1, the user-plane DRB,
//! the built-in ping); this entity owns the *scheduling* state those decisions
//! fall back on — the warm-grant window and the BSR framing used to keep the gNB
//! granting (or to solicit a bigger grant), plus the idle report that lets it
//! stop.

use crate::ce::mac_short_bsr;
use std::time::{Duration, Instant};

/// Buffer occupancy (bytes) reported by the "warm" keep-alive BSR: a small
/// non-zero value that keeps the gNB granting every UL occasion (so the next
/// packet rides a grant instead of paying an SR round-trip) without over-
/// soliciting. It is also the floor for a solicitation report — the lossless
/// channel's KO noise drops the UL MCS, so a truthful tiny report yields grants
/// too small for an SRB1/DRB PDU.
const WARM_BSR_BYTES: usize = 220;

/// How long after UL activity the UE keeps reporting the warm buffer.
const WARM_WINDOW: Duration = Duration::from_secs(1);

/// Uplink MAC scheduling state: the warm-grant window and the BSR framing the
/// grant-answering loop falls back on.
pub struct MacUlScheduler {
    last_activity: Instant,
}

impl MacUlScheduler {
    /// A scheduler starting idle (the warm window already expired).
    pub fn new() -> Self {
        Self { last_activity: Instant::now() - Duration::from_secs(60) }
    }

    /// Note that UL data moved — (re)opens the warm-grant window.
    pub fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// True while the warm-grant window is open (UL data moved recently), so the
    /// UE should keep the gNB granting.
    pub fn is_warm(&self) -> bool {
        self.last_activity.elapsed() < WARM_WINDOW
    }

    /// The MAC PDU to answer a grant with when there is no logical-channel data
    /// to send: a warm keep-alive BSR while the window is open, else an idle
    /// (empty-buffer) BSR that lets the gNB stop granting. Both are valid,
    /// decodable PDUs (never leaving the grant undecodable).
    pub fn fallback_pdu(&self, tbs: usize) -> Vec<u8> {
        mac_short_bsr(if self.is_warm() { WARM_BSR_BYTES } else { 0 }, tbs)
    }

    /// A BSR that reports at least `need` bytes (floored at the warm level) to
    /// solicit a larger grant when the queued PDU doesn't fit this one.
    pub fn solicit_pdu(&self, need: usize, tbs: usize) -> Vec<u8> {
        mac_short_bsr(need.max(WARM_BSR_BYTES), tbs)
    }
}

impl Default for MacUlScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_window_and_fallback() {
        let mut s = MacUlScheduler::new();
        assert!(!s.is_warm()); // starts idle
        // Idle fallback reports an empty buffer (index 0).
        assert_eq!(s.fallback_pdu(4)[1], 0);
        s.note_activity();
        assert!(s.is_warm());
        // Warm fallback reports the 220 B level (a non-zero BSR index).
        assert_ne!(s.fallback_pdu(4)[1], 0);
    }

    #[test]
    fn solicit_floors_at_warm_level() {
        let s = MacUlScheduler::new();
        // need below the floor still reports the warm level.
        assert_eq!(s.solicit_pdu(10, 4), mac_short_bsr(220, 4));
        // need above the floor reports need.
        assert_eq!(s.solicit_pdu(500, 4), mac_short_bsr(500, 4));
    }
}
