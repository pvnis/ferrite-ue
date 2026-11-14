//! UM RLC entity (TS 38.322 §5.2.2, §6.2.2.3).

use std::collections::{BTreeMap, VecDeque};

use ferrite_common::{Numerology, SlotPoint};

use crate::header::{Si, UmdHeader};
use crate::reasm::RxSdu;
use crate::timer::Timer;
use crate::{sn_mod, SnLen, UmConfig};

#[derive(Debug)]
enum UmRx {
    /// Segments received, SDU not yet complete.
    Pending(RxSdu),
    /// Reassembled and delivered; kept so the "first SN not delivered" walks
    /// of §5.2.2.2.3/4 can skip it until it leaves the reassembly window.
    Delivered,
}

#[derive(Debug)]
pub(crate) struct UmEntity {
    sn_len: SnLen,
    modulus: u32,
    /// UM_Window_Size (§7.2): 32 for 6-bit SN, 2048 for 12-bit.
    window: u32,
    // --- transmitting side (§7.1) ---
    tx_queue: VecDeque<Vec<u8>>,
    /// SDU under segmentation and the offset of its next byte to send.
    tx_cur: Option<(Vec<u8>, usize)>,
    tx_next: u32,
    // --- receiving side (§7.1) ---
    rx_next_reassembly: u32,
    rx_timer_trigger: u32,
    rx_next_highest: u32,
    rx: BTreeMap<u32, UmRx>,
    t_reassembly: Timer,
    delivered: VecDeque<Vec<u8>>,
}

impl UmEntity {
    pub fn new(cfg: UmConfig, numerology: Numerology) -> Self {
        let modulus = cfg.sn_len.modulus();
        Self {
            sn_len: cfg.sn_len,
            modulus,
            window: modulus / 2,
            tx_queue: VecDeque::new(),
            tx_cur: None,
            tx_next: 0,
            rx_next_reassembly: 0,
            rx_timer_trigger: 0,
            rx_next_highest: 0,
            rx: BTreeMap::new(),
            t_reassembly: Timer::new(cfg.t_reassembly_ms, numerology),
            delivered: VecDeque::new(),
        }
    }

    pub fn tx_sdu(&mut self, sdu: Vec<u8>) {
        if sdu.len() > u16::MAX as usize {
            log::warn!(
                "rlc um: discarding {}-byte SDU (exceeds SO range)",
                sdu.len()
            );
            return;
        }
        self.tx_queue.push_back(sdu);
    }

    fn first_seg_hdr(&self) -> usize {
        UmdHeader::size(Si::First, self.sn_len)
    }

    /// §5.2.2.1: one UMD PDU, segmenting the SDU at the head of the queue so
    /// that header + data fits in `max_bytes`.
    pub fn pull_pdu(&mut self, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        self.run_timers(now);
        if self.tx_cur.is_none() {
            self.tx_cur = self.tx_queue.pop_front().map(|s| (s, 0));
        }
        let (sdu, off) = self.tx_cur.as_ref()?;
        let (sdu, off) = (sdu.as_slice(), *off);
        let len = sdu.len();
        // A complete SDU fits: SI=00, no SN consumed (§5.2.2.1 increments
        // TX_Next only for segmented SDUs).
        if off == 0 && len < max_bytes {
            let mut pdu = Vec::with_capacity(1 + len);
            UmdHeader {
                si: Si::Full,
                sn: 0,
                so: 0,
            }
            .encode(self.sn_len, &mut pdu);
            pdu.extend_from_slice(sdu);
            self.tx_cur = None;
            return Some(pdu);
        }
        let hdr = if off == 0 {
            self.first_seg_hdr()
        } else {
            self.first_seg_hdr() + 2
        };
        if max_bytes <= hdr {
            return None;
        }
        let take = (max_bytes - hdr).min(len - off);
        let end = off + take;
        let si = Si::of_range(off, end, len);
        let mut pdu = Vec::with_capacity(hdr + take);
        UmdHeader {
            si,
            sn: self.tx_next,
            so: off as u16,
        }
        .encode(self.sn_len, &mut pdu);
        pdu.extend_from_slice(&sdu[off..end]);
        if end == len {
            self.tx_next = (self.tx_next + 1) % self.modulus;
            self.tx_cur = None;
        } else if let Some(cur) = self.tx_cur.as_mut() {
            cur.1 = end;
        }
        Some(pdu)
    }

    /// §5.5: queued SDUs (+ one-octet header each) and the remainder of the SDU
    /// under segmentation (+ segment header).
    pub fn buffer_status(&self) -> usize {
        let queued: usize = self.tx_queue.iter().map(|s| s.len() + 1).sum();
        let cur = self.tx_cur.as_ref().map_or(0, |(s, off)| {
            s.len() - off + self.first_seg_hdr() + if *off > 0 { 2 } else { 0 }
        });
        queued + cur
    }

    // ----------------------------------------------------------------------
    // Receiving side
    // ----------------------------------------------------------------------

    /// Position of `sn` relative to the lower edge of the reassembly window
    /// `[RX_Next_Highest − UM_Window_Size, RX_Next_Highest)`.
    fn rel(&self, sn: u32) -> u32 {
        sn_mod(
            sn,
            self.rx_next_highest.wrapping_sub(self.window),
            self.modulus,
        )
    }

    fn outside_window(&self, sn: u32) -> bool {
        self.rel(sn) >= self.window
    }

    fn is_delivered(&self, sn: u32) -> bool {
        matches!(self.rx.get(&sn), Some(UmRx::Delivered))
    }

    /// First SN ≥ `from` that has not been reassembled and delivered.
    fn first_not_delivered(&self, from: u32) -> u32 {
        let mut sn = from;
        let mut guard = 0;
        while self.is_delivered(sn) && guard < self.window {
            sn = (sn + 1) % self.modulus;
            guard += 1;
        }
        sn
    }

    /// Missing byte segment of the SDU at `sn` before the last received byte.
    fn gap_before_last(&self, sn: u32) -> bool {
        match self.rx.get(&sn) {
            Some(UmRx::Pending(r)) => r.has_gap_before_last(),
            _ => false,
        }
    }

    /// §5.2.2.2.2 / §5.2.2.2.3.
    pub fn rx_pdu(&mut self, pdu: &[u8], now: SlotPoint) {
        self.run_timers(now);
        let Some((h, hl)) = UmdHeader::decode(self.sn_len, pdu) else {
            log::warn!("rlc um: malformed UMD PDU ({} bytes)", pdu.len());
            return;
        };
        let data = &pdu[hl..];
        if data.is_empty() {
            return;
        }
        if h.si == Si::Full {
            self.delivered.push_back(data.to_vec());
            return;
        }
        let x = h.sn;
        // §5.2.2.2.2: (RX_Next_Highest − UM_Window_Size) <= x < RX_Next_Reassembly → discard.
        if self.rel(x) < self.rel(self.rx_next_reassembly) {
            return;
        }
        let was_outside = self.outside_window(x);
        // Place in the reception buffer.
        match self
            .rx
            .entry(x)
            .or_insert_with(|| UmRx::Pending(RxSdu::default()))
        {
            UmRx::Pending(r) => {
                r.insert(h.so as usize, data, h.si == Si::Last);
            }
            UmRx::Delivered => return,
        }
        // §5.2.2.2.3
        if was_outside {
            self.rx_next_highest = (x + 1) % self.modulus;
            let lo = self.rx_next_highest.wrapping_sub(self.window);
            let (w, m) = (self.window, self.modulus);
            self.rx.retain(|&sn, _| sn_mod(sn, lo, m) < w);
            if self.outside_window(self.rx_next_reassembly) {
                self.rx_next_reassembly = self.first_not_delivered(lo & (m - 1));
            }
        }
        if let Some(UmRx::Pending(r)) = self.rx.get(&x) {
            if r.is_complete() {
                if let Some(UmRx::Pending(r)) = self.rx.insert(x, UmRx::Delivered) {
                    self.delivered.push_back(r.into_sdu());
                }
                if x == self.rx_next_reassembly {
                    self.rx_next_reassembly = self.first_not_delivered((x + 1) % self.modulus);
                }
            }
        }
        self.update_reassembly_timer(now);
    }

    /// The t-Reassembly stop/start rules shared by §5.2.2.2.3 and §5.2.2.2.4.
    fn update_reassembly_timer(&mut self, now: SlotPoint) {
        let m = self.modulus;
        let rnr = self.rx_next_reassembly;
        if self.t_reassembly.is_running() {
            let trig = self.rx_timer_trigger;
            let trig_le_rnr = self.rel(trig) <= self.rel(rnr);
            let trig_outside = self.outside_window(trig) && trig != self.rx_next_highest;
            let only_next = self.rx_next_highest == (rnr + 1) % m && !self.gap_before_last(rnr);
            if trig_le_rnr || trig_outside || only_next {
                self.t_reassembly.stop();
            }
        }
        if !self.t_reassembly.is_running() {
            let ahead = sn_mod(self.rx_next_highest, rnr, m);
            if ahead > 1 || (ahead == 1 && self.gap_before_last(rnr)) {
                self.t_reassembly.start(now);
                self.rx_timer_trigger = self.rx_next_highest;
            }
        }
    }

    /// §5.2.2.2.4: t-Reassembly expiry.
    fn on_reassembly_expiry(&mut self, now: SlotPoint) {
        let m = self.modulus;
        self.rx_next_reassembly = self.first_not_delivered(self.rx_timer_trigger);
        let rnr_rel = self.rel(self.rx_next_reassembly);
        let lo = self.rx_next_highest.wrapping_sub(self.window);
        self.rx
            .retain(|&sn, st| matches!(st, UmRx::Delivered) || sn_mod(sn, lo, m) >= rnr_rel);
        let ahead = sn_mod(self.rx_next_highest, self.rx_next_reassembly, m);
        if ahead > 1 || (ahead == 1 && self.gap_before_last(self.rx_next_reassembly)) {
            self.t_reassembly.start(now);
            self.rx_timer_trigger = self.rx_next_highest;
        }
    }

    fn run_timers(&mut self, now: SlotPoint) {
        if self.t_reassembly.expired(now) {
            self.t_reassembly.stop();
            self.on_reassembly_expiry(now);
        }
    }

    pub fn tick(&mut self, now: SlotPoint) {
        self.run_timers(now);
    }

    pub fn pop_rx_sdu(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }

    /// §5.1.2.
    pub fn reestablish(&mut self) {
        self.tx_queue.clear();
        self.tx_cur = None;
        self.tx_next = 0;
        self.rx_next_reassembly = 0;
        self.rx_timer_trigger = 0;
        self.rx_next_highest = 0;
        self.rx.clear();
        self.t_reassembly.stop();
        self.delivered.clear();
    }
}
