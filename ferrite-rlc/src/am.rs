//! AM RLC entity (TS 38.322 §5.2.3, §5.3, §6.2.2.4, §6.2.2.5, §6.2.3).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ferrite_common::{Numerology, SlotPoint};

use crate::header::{is_status_pdu, AmdHeader, Nack, Si, StatusPdu, SO_END_ALL};
use crate::reasm::RxSdu;
use crate::timer::Timer;
use crate::{sn_mod, AmConfig, RlcEvent, SnLen};

/// An SDU with an assigned SN, kept until positively acknowledged.
#[derive(Debug)]
struct TxSdu {
    data: Vec<u8>,
    /// Bytes `[0, sent)` have been submitted to lower layer at least once.
    sent: usize,
    /// RETX_COUNT (§7.1); `None` until first considered for retransmission.
    retx_count: Option<u32>,
    max_reported: bool,
}

/// A byte range `[start, end)` of an SDU pending retransmission (§5.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetxSeg {
    sn: u32,
    start: usize,
    end: usize,
}

#[derive(Debug)]
pub(crate) struct AmEntity {
    sn_len: SnLen,
    modulus: u32,
    /// AM_Window_Size (§7.2): 2^(sn_len − 1).
    window: u32,
    poll_pdu: Option<u32>,
    poll_byte: Option<u32>,
    max_retx_threshold: u32,
    last_now: Option<SlotPoint>,
    events: Vec<RlcEvent>,
    // --- transmitting side (§7.1) ---
    tx_queue: VecDeque<Vec<u8>>,
    tx_sdus: BTreeMap<u32, TxSdu>,
    retx: VecDeque<RetxSeg>,
    tx_next_ack: u32,
    tx_next: u32,
    poll_sn: u32,
    pdu_without_poll: u32,
    byte_without_poll: u32,
    /// A poll must be included in the next AMD PDU (§5.3.3.4).
    force_poll: bool,
    t_poll_retransmit: Timer,
    // --- receiving side (§7.1) ---
    rx_next: u32,
    rx_next_status_trigger: u32,
    rx_highest_status: u32,
    rx_next_highest: u32,
    rx: BTreeMap<u32, RxSdu>,
    t_reassembly: Timer,
    t_status_prohibit: Timer,
    status_triggered: bool,
    /// A poll whose STATUS report is delayed until the receiver has seen past
    /// the polled SN (§5.3.4).
    delayed_poll: Option<u32>,
    delivered: VecDeque<Vec<u8>>,
}

impl AmEntity {
    pub fn new(cfg: AmConfig, numerology: Numerology) -> Self {
        let modulus = cfg.sn_len.modulus();
        Self {
            sn_len: cfg.sn_len,
            modulus,
            window: modulus / 2,
            poll_pdu: cfg.poll_pdu,
            poll_byte: cfg.poll_byte,
            max_retx_threshold: cfg.max_retx_threshold,
            last_now: None,
            events: Vec::new(),
            tx_queue: VecDeque::new(),
            tx_sdus: BTreeMap::new(),
            retx: VecDeque::new(),
            tx_next_ack: 0,
            tx_next: 0,
            poll_sn: 0,
            pdu_without_poll: 0,
            byte_without_poll: 0,
            force_poll: false,
            t_poll_retransmit: Timer::new(cfg.t_poll_retransmit_ms, numerology),
            rx_next: 0,
            rx_next_status_trigger: 0,
            rx_highest_status: 0,
            rx_next_highest: 0,
            rx: BTreeMap::new(),
            t_reassembly: Timer::new(cfg.t_reassembly_ms, numerology),
            t_status_prohibit: Timer::new(cfg.t_status_prohibit_ms, numerology),
            status_triggered: false,
            delayed_poll: None,
            delivered: VecDeque::new(),
        }
    }

    fn hdr_base(&self) -> usize {
        AmdHeader::base_size(self.sn_len)
    }

    pub fn tx_sdu(&mut self, sdu: Vec<u8>) {
        if sdu.len() > u16::MAX as usize {
            log::warn!("rlc am: discarding {}-byte SDU (exceeds SO range)", sdu.len());
            return;
        }
        self.tx_queue.push_back(sdu);
    }

    pub fn events(&mut self) -> Vec<RlcEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn pop_rx_sdu(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }

    pub fn unacked_sdus(&self) -> usize {
        self.tx_sdus.len()
    }

    // ----------------------------------------------------------------------
    // Transmitting side
    // ----------------------------------------------------------------------

    /// The SDU at TX_Next exists and has not been fully submitted.
    fn partial_at_tx_next(&self) -> bool {
        self.tx_sdus.get(&self.tx_next).is_some_and(|s| s.sent < s.data.len())
    }

    /// No new data available for transmission (transmission buffer empty).
    fn tx_buffer_empty(&self) -> bool {
        self.tx_queue.is_empty() && !self.partial_at_tx_next()
    }

    /// TX_Next falls outside the transmitting window: no new SDU may start.
    fn window_stalled(&self) -> bool {
        sn_mod(self.tx_next, self.tx_next_ack, self.modulus) >= self.window
    }

    /// Highest SN among the AMD PDUs submitted to lower layer, if any.
    fn highest_submitted_sn(&self) -> Option<u32> {
        if self.tx_sdus.get(&self.tx_next).is_some_and(|s| s.sent > 0) {
            Some(self.tx_next)
        } else if self.tx_next != self.tx_next_ack {
            Some(self.tx_next.wrapping_sub(1) & (self.modulus - 1))
        } else {
            None
        }
    }

    /// §5.3.3.2: decide the P field of an AMD PDU being submitted; `new_bytes`
    /// is the data size when the PDU carries not-previously-transmitted data.
    fn poll_decision(&mut self, new_bytes: Option<usize>, now: SlotPoint) -> bool {
        let mut poll = self.force_poll;
        if let Some(b) = new_bytes {
            self.pdu_without_poll += 1;
            self.byte_without_poll = self.byte_without_poll.saturating_add(b as u32);
            if self.poll_pdu.is_some_and(|p| self.pdu_without_poll >= p)
                || self.poll_byte.is_some_and(|p| self.byte_without_poll >= p)
            {
                poll = true;
            }
        }
        // Both buffers empty after this PDU, or window stalling.
        let tx_empty = self.tx_buffer_empty();
        if (tx_empty && self.retx.is_empty()) || (!tx_empty && self.window_stalled()) {
            poll = true;
        }
        if poll {
            self.pdu_without_poll = 0;
            self.byte_without_poll = 0;
            self.force_poll = false;
            if let Some(sn) = self.highest_submitted_sn() {
                self.poll_sn = sn;
            }
            self.t_poll_retransmit.start(now);
        }
        poll
    }

    fn encode_amd(&self, sn: u32, start: usize, end: usize, len: usize, poll: bool, data: &[u8]) -> Vec<u8> {
        let si = Si::of_range(start, end, len);
        let mut pdu = Vec::with_capacity(AmdHeader::size(si, self.sn_len) + data.len());
        AmdHeader { poll, si, sn, so: start as u16 }.encode(self.sn_len, &mut pdu);
        pdu.extend_from_slice(data);
        pdu
    }

    /// §5.3.4 (STATUS first), §5.3.2 (retransmissions), §5.2.3.1 (new data).
    pub fn pull_pdu(&mut self, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        self.run_timers(now);
        if self.status_triggered && !self.t_status_prohibit.running_at(now) {
            if max_bytes < StatusPdu::HEADER_SIZE {
                return None;
            }
            let status = self.build_status(max_bytes);
            self.status_triggered = false;
            self.t_status_prohibit.start(now);
            return Some(status.encode(self.sn_len));
        }
        if let Some(pdu) = self.pull_retx(max_bytes, now) {
            return Some(pdu);
        }
        self.pull_new(max_bytes, now)
    }

    fn pull_retx(&mut self, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        loop {
            let seg = *self.retx.front()?;
            let Some(sdu) = self.tx_sdus.get(&seg.sn) else {
                self.retx.pop_front();
                continue;
            };
            let len = sdu.data.len();
            let (start, end) = (seg.start.min(len), seg.end.min(len));
            if start >= end {
                self.retx.pop_front();
                continue;
            }
            let hdr = self.hdr_base() + if start > 0 { 2 } else { 0 };
            if max_bytes <= hdr {
                return None;
            }
            let take = (max_bytes - hdr).min(end - start);
            let new_end = start + take;
            let data = sdu.data[start..new_end].to_vec();
            self.retx.pop_front();
            if new_end < end {
                self.retx.push_front(RetxSeg { sn: seg.sn, start: new_end, end });
            }
            let poll = self.poll_decision(None, now);
            return Some(self.encode_amd(seg.sn, start, new_end, len, poll, &data));
        }
    }

    fn pull_new(&mut self, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        let sn = self.tx_next;
        if !self.partial_at_tx_next() {
            if self.tx_queue.is_empty() || self.window_stalled() {
                return None;
            }
            let data = self.tx_queue.pop_front()?;
            self.tx_sdus.insert(sn, TxSdu { data, sent: 0, retx_count: None, max_reported: false });
        }
        let sdu = self.tx_sdus.get(&sn)?;
        let (len, start) = (sdu.data.len(), sdu.sent);
        let hdr = self.hdr_base() + if start > 0 { 2 } else { 0 };
        if max_bytes <= hdr {
            return None;
        }
        let take = (max_bytes - hdr).min(len - start);
        let end = start + take;
        let data = sdu.data[start..end].to_vec();
        if let Some(s) = self.tx_sdus.get_mut(&sn) {
            s.sent = end;
        }
        if end == len {
            self.tx_next = (self.tx_next + 1) % self.modulus;
        }
        let poll = self.poll_decision(Some(take), now);
        Some(self.encode_amd(sn, start, end, len, poll, &data))
    }

    /// §5.5.
    pub fn buffer_status(&self) -> usize {
        let base = self.hdr_base();
        let queued: usize = self.tx_queue.iter().map(|s| s.len() + base).sum();
        let partial = self
            .tx_sdus
            .get(&self.tx_next)
            .filter(|s| s.sent < s.data.len())
            .map_or(0, |s| s.data.len() - s.sent + base + if s.sent > 0 { 2 } else { 0 });
        let retx: usize = self
            .retx
            .iter()
            .map(|r| r.end.saturating_sub(r.start) + base + if r.start > 0 { 2 } else { 0 })
            .sum();
        let status = if self.status_triggered && !self.last_now.is_some_and(|n| self.t_status_prohibit.running_at(n)) {
            self.build_status(usize::MAX).size(self.sn_len)
        } else {
            0
        };
        queued + partial + retx + status
    }

    /// §5.3.2: consider `[start, end)` of SDU `sn` for retransmission.
    /// `incremented` collects SNs whose RETX_COUNT was already incremented by
    /// the same STATUS PDU.
    fn consider_retx(&mut self, sn: u32, start: usize, end: usize, incremented: &mut BTreeSet<u32>) {
        let Some(sdu) = self.tx_sdus.get_mut(&sn) else { return };
        // Only transmitted bytes can be retransmitted.
        let end = end.min(sdu.sent);
        if start >= end {
            return;
        }
        let already_pending = self.retx.iter().any(|r| r.sn == sn && r.start <= start && end <= r.end);
        match sdu.retx_count {
            None => sdu.retx_count = Some(0),
            Some(c) if !already_pending && !incremented.contains(&sn) => {
                sdu.retx_count = Some(c + 1);
                incremented.insert(sn);
            }
            _ => {}
        }
        if sdu.retx_count.is_some_and(|c| c >= self.max_retx_threshold) && !sdu.max_reported {
            sdu.max_reported = true;
            log::warn!("rlc am: maxRetxThreshold reached for SN {sn}");
            self.events.push(RlcEvent::MaxRetxReached { sn });
        }
        if !already_pending {
            self.retx.push_back(RetxSeg { sn, start, end });
        }
    }

    /// §5.3.3.3 and §5.2.3.1: a STATUS PDU from the peer.
    fn handle_status(&mut self, st: &StatusPdu) {
        let m = self.modulus;
        let base = self.tx_next_ack;
        let span = sn_mod(self.tx_next, base, m);
        let ack_rel = sn_mod(st.ack_sn, base, m);
        if ack_rel > span {
            log::warn!("rlc am: STATUS ACK_SN {} outside [TX_Next_Ack {}, TX_Next {}]", st.ack_sn, base, self.tx_next);
            return;
        }
        // Expand the NACKs into (sn, start, end) ranges; collect NACKed SNs.
        let mut nacked: Vec<(u32, usize, Option<usize>)> = Vec::new();
        let mut nacked_sns: BTreeSet<u32> = BTreeSet::new();
        for n in &st.nacks {
            let count = n.range.map_or(1, |r| r.max(1) as u32);
            for i in 0..count {
                let sn = (n.sn + i) % m;
                if sn_mod(sn, base, m) >= ack_rel {
                    continue;
                }
                let (start, end) = match n.so {
                    None => (0, None),
                    Some((s, e)) => {
                        let s = if i == 0 { s as usize } else { 0 };
                        let e = if i + 1 == count && e != SO_END_ALL { Some(e as usize + 1) } else { None };
                        (s, e)
                    }
                };
                nacked.push((sn, start, end));
                nacked_sns.insert(sn);
            }
        }
        // Positive acknowledgements: every SN below ACK_SN not NACKed.
        for rel in 0..ack_rel {
            let sn = (base + rel) % m;
            if !nacked_sns.contains(&sn) && self.tx_sdus.remove(&sn).is_some() {
                self.retx.retain(|r| r.sn != sn);
            }
        }
        // §5.3.3.3: the poll was answered (positively or negatively).
        if sn_mod(self.poll_sn, base, m) < ack_rel {
            self.t_poll_retransmit.stop();
        }
        // Negative acknowledgements.
        let mut incremented = BTreeSet::new();
        for (sn, start, end) in nacked {
            let Some(len) = self.tx_sdus.get(&sn).map(|s| s.data.len()) else { continue };
            self.consider_retx(sn, start, end.unwrap_or(len).min(len), &mut incremented);
        }
        // Advance TX_Next_Ack to the lowest unacknowledged SN.
        while self.tx_next_ack != self.tx_next && !self.tx_sdus.contains_key(&self.tx_next_ack) {
            self.tx_next_ack = (self.tx_next_ack + 1) % m;
        }
    }

    /// §5.3.3.4: t-PollRetransmit expiry.
    fn on_poll_retransmit_expiry(&mut self) {
        let tx_empty = self.tx_buffer_empty();
        if (tx_empty && self.retx.is_empty()) || (!tx_empty && self.window_stalled()) {
            // The highest SN submitted to lower layer, or — if that one has
            // already been acknowledged — the highest SN still unacknowledged.
            let (base, m) = (self.tx_next_ack, self.modulus);
            let candidate = self
                .highest_submitted_sn()
                .filter(|sn| self.tx_sdus.contains_key(sn))
                .or_else(|| self.tx_sdus.keys().copied().max_by_key(|&sn| sn_mod(sn, base, m)));
            if let Some(sn) = candidate {
                let sent = self.tx_sdus.get(&sn).map_or(0, |s| s.sent);
                let mut incremented = BTreeSet::new();
                self.consider_retx(sn, 0, sent, &mut incremented);
            }
        }
        self.force_poll = true;
    }

    // ----------------------------------------------------------------------
    // Receiving side
    // ----------------------------------------------------------------------

    fn rx_rel(&self, sn: u32) -> u32 {
        sn_mod(sn, self.rx_next, self.modulus)
    }

    fn is_complete(&self, sn: u32) -> bool {
        self.rx.get(&sn).is_some_and(RxSdu::is_complete)
    }

    fn gap_before_last(&self, sn: u32) -> bool {
        self.rx.get(&sn).is_some_and(RxSdu::has_gap_before_last)
    }

    /// First SN ≥ `from` for which not all bytes have been received.
    fn first_incomplete(&self, from: u32) -> u32 {
        let mut sn = from;
        let mut guard = 0;
        while self.is_complete(sn) && guard < self.window {
            sn = (sn + 1) % self.modulus;
            guard += 1;
        }
        sn
    }

    /// §5.3.4: a poll for SN `x` triggers a STATUS report once the receiver
    /// has passed it (x < RX_Highest_Status or x ≥ RX_Next + AM_Window_Size).
    fn poll_satisfied(&self, x: u32) -> bool {
        let rel = self.rx_rel(x);
        rel >= self.window || rel < self.rx_rel(self.rx_highest_status)
    }

    fn check_delayed_poll(&mut self) {
        if self.delayed_poll.is_some_and(|x| self.poll_satisfied(x)) {
            self.delayed_poll = None;
            self.status_triggered = true;
        }
    }

    /// §5.2.3.2.2 / §5.2.3.2.3 / §5.3.4 (polling trigger).
    fn handle_amd(&mut self, h: AmdHeader, data: &[u8]) {
        let x = h.sn;
        let so = h.so as usize;
        let rel = self.rx_rel(x);
        let duplicate = self
            .rx
            .get(&x)
            .is_some_and(|r| r.is_complete() || r.covers(so, so + data.len()));
        if rel >= self.window || data.is_empty() || duplicate {
            // §5.3.4: a poll on a discarded PDU still triggers a STATUS report.
            if h.poll {
                self.status_triggered = true;
            }
            return;
        }
        let is_last = matches!(h.si, Si::Full | Si::Last);
        let inserted = self.rx.entry(x).or_default().insert(so, data, is_last);
        if !inserted {
            if h.poll {
                self.status_triggered = true;
            }
            return;
        }
        // §5.2.3.2.3
        if rel >= self.rx_rel(self.rx_next_highest) {
            self.rx_next_highest = (x + 1) % self.modulus;
        }
        if self.is_complete(x) {
            if x == self.rx_highest_status {
                self.rx_highest_status = self.first_incomplete((x + 1) % self.modulus);
            }
            if x == self.rx_next {
                while let Some(r) = self.rx.get(&self.rx_next).filter(|r| r.is_complete()) {
                    let _ = r;
                    if let Some(r) = self.rx.remove(&self.rx_next) {
                        self.delivered.push_back(r.into_sdu());
                    }
                    self.rx_next = (self.rx_next + 1) % self.modulus;
                }
                if self.rx_rel(self.rx_highest_status) >= self.window {
                    self.rx_highest_status = self.rx_next;
                }
            }
        }
        self.update_reassembly_timer();
        if h.poll {
            if self.poll_satisfied(x) {
                self.status_triggered = true;
            } else {
                self.delayed_poll = Some(x);
            }
        }
        self.check_delayed_poll();
    }

    /// The t-Reassembly rules of §5.2.3.2.3 (evaluated with `last_now`).
    fn update_reassembly_timer(&mut self) {
        let Some(now) = self.last_now else { return };
        let m = self.modulus;
        if self.t_reassembly.is_running() {
            let trig = self.rx_next_status_trigger;
            let trig_rel = self.rx_rel(trig);
            let stop = trig == self.rx_next
                || (trig == (self.rx_next + 1) % m && !self.gap_before_last(self.rx_next))
                || (trig_rel >= self.window && trig != (self.rx_next + self.window) % m);
            if stop {
                self.t_reassembly.stop();
            }
        }
        if !self.t_reassembly.is_running() {
            let ahead = self.rx_rel(self.rx_next_highest);
            if ahead > 1 || (ahead == 1 && self.gap_before_last(self.rx_next)) {
                self.t_reassembly.start(now);
                self.rx_next_status_trigger = self.rx_next_highest;
            }
        }
    }

    /// §5.2.3.2.4: t-Reassembly expiry.
    fn on_reassembly_expiry(&mut self, now: SlotPoint) {
        let m = self.modulus;
        let trig = if self.rx_rel(self.rx_next_status_trigger) >= self.window {
            self.rx_next
        } else {
            self.rx_next_status_trigger
        };
        let hs = self.first_incomplete(trig);
        if self.rx_rel(hs) > self.rx_rel(self.rx_highest_status) {
            self.rx_highest_status = hs;
        }
        self.status_triggered = true;
        let ahead = sn_mod(self.rx_next_highest, self.rx_highest_status, m);
        if ahead > 1 || (ahead == 1 && self.gap_before_last(self.rx_highest_status)) {
            self.t_reassembly.start(now);
            self.rx_next_status_trigger = self.rx_next_highest;
        }
        self.check_delayed_poll();
    }

    /// §5.3.4: build the STATUS PDU for the SNs in `[RX_Next, RX_Highest_Status)`,
    /// truncated to `max_bytes` (ACK_SN then moves to the first SN not
    /// reported as missing).
    fn build_status(&self, max_bytes: usize) -> StatusPdu {
        let m = self.modulus;
        let mut entries: Vec<Nack> = Vec::new();
        let mut sn = self.rx_next;
        let end_rel = self.rx_rel(self.rx_highest_status);
        while self.rx_rel(sn) < end_rel {
            match self.rx.get(&sn) {
                None => {
                    // Run of entirely missing SDUs → NACK range.
                    let first = sn;
                    let mut count = 0u32;
                    while self.rx_rel(sn) < end_rel && !self.rx.contains_key(&sn) && count < 255 {
                        count += 1;
                        sn = (sn + 1) % m;
                    }
                    entries.push(Nack { sn: first, so: None, range: (count > 1).then_some(count as u8) });
                }
                Some(r) => {
                    if !r.is_complete() {
                        for (start, end) in r.gaps() {
                            let so_start = start.min(SO_END_ALL as usize) as u16;
                            let so_end = end.map_or(SO_END_ALL, |e| (e - 1).min(SO_END_ALL as usize) as u16);
                            entries.push(Nack { sn, so: Some((so_start, so_end)), range: None });
                        }
                    }
                    sn = (sn + 1) % m;
                }
            }
        }
        let mut status = StatusPdu { ack_sn: self.rx_highest_status, nacks: Vec::new() };
        let mut size = StatusPdu::HEADER_SIZE;
        for e in entries {
            let s = e.size(self.sn_len);
            if size + s > max_bytes {
                status.ack_sn = e.sn;
                break;
            }
            size += s;
            status.nacks.push(e);
        }
        status
    }

    pub fn rx_pdu(&mut self, pdu: &[u8], now: SlotPoint) {
        self.run_timers(now);
        if is_status_pdu(pdu) {
            match StatusPdu::decode(self.sn_len, pdu) {
                Some(st) => self.handle_status(&st),
                None => log::warn!("rlc am: malformed STATUS PDU ({} bytes)", pdu.len()),
            }
            return;
        }
        match AmdHeader::decode(self.sn_len, pdu) {
            Some((h, hl)) => self.handle_amd(h, &pdu[hl..]),
            None => log::warn!("rlc am: malformed AMD PDU ({} bytes)", pdu.len()),
        }
    }

    fn run_timers(&mut self, now: SlotPoint) {
        self.last_now = Some(now);
        if self.t_reassembly.expired(now) {
            self.t_reassembly.stop();
            self.on_reassembly_expiry(now);
        }
        if self.t_poll_retransmit.expired(now) {
            self.t_poll_retransmit.stop();
            self.on_poll_retransmit_expiry();
        }
    }

    pub fn tick(&mut self, now: SlotPoint) {
        self.run_timers(now);
    }

    /// §5.1.2.
    pub fn reestablish(&mut self) {
        self.events.clear();
        self.tx_queue.clear();
        self.tx_sdus.clear();
        self.retx.clear();
        self.tx_next_ack = 0;
        self.tx_next = 0;
        self.poll_sn = 0;
        self.pdu_without_poll = 0;
        self.byte_without_poll = 0;
        self.force_poll = false;
        self.t_poll_retransmit.stop();
        self.rx_next = 0;
        self.rx_next_status_trigger = 0;
        self.rx_highest_status = 0;
        self.rx_next_highest = 0;
        self.rx.clear();
        self.t_reassembly.stop();
        self.t_status_prohibit.stop();
        self.status_triggered = false;
        self.delayed_poll = None;
        self.delivered.clear();
    }
}
