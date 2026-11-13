//! Entity-level tests: UM segmentation/reassembly, AM duplex simulation over a
//! lossy reordering channel, STATUS/poll/retransmission behaviour.
use super::*;
use ferrite_common::{Numerology, SlotPoint};

const MU: Numerology = Numerology::KHZ30;

fn at(slot: u64) -> SlotPoint {
    SlotPoint::from_index(MU, slot)
}

fn um(sn_len: SnLen, t_reassembly_ms: u32) -> RlcEntity {
    RlcEntity::new(RlcMode::Um(UmConfig { sn_len, t_reassembly_ms }), MU)
}

fn am_with(sn_len: SnLen, max_retx_threshold: u32, t_poll_retransmit_ms: u32) -> RlcEntity {
    RlcEntity::new(
        RlcMode::Am(AmConfig {
            sn_len,
            t_poll_retransmit_ms,
            poll_pdu: Some(4),
            poll_byte: Some(1000),
            max_retx_threshold,
            t_reassembly_ms: 10,
            t_status_prohibit_ms: 5,
        }),
        MU,
    )
}

fn am(sn_len: SnLen) -> RlcEntity {
    am_with(sn_len, 4, 20)
}

fn sdu(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_mul(31).wrapping_add((i * 7) as u8)).collect()
}

/// Tiny deterministic PRNG (xorshift64*) for the channel simulations.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ------------------------------------------------------------------------
// TM
// ------------------------------------------------------------------------

#[test]
fn tm_passthrough() {
    let mut e = RlcEntity::new(RlcMode::Tm, MU);
    e.tx_sdu(vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(e.buffer_status(), 6);
    assert!(e.pull_pdu(5, at(0)).is_none(), "TM never segments");
    assert_eq!(e.pull_pdu(6, at(0)).unwrap(), [1, 2, 3, 4, 5, 6]);
    assert!(e.pull_pdu(100, at(0)).is_none());
    e.rx_pdu(&[9, 9], at(0));
    assert_eq!(e.pop_rx_sdu().unwrap(), [9, 9]);
    assert!(e.events().is_empty());
}

// ------------------------------------------------------------------------
// UM
// ------------------------------------------------------------------------

#[test]
fn um_complete_sdu_has_one_octet_header_and_no_sn() {
    let mut tx = um(SnLen::Bits12, 35);
    let mut rx = um(SnLen::Bits12, 35);
    for i in 0..5u8 {
        tx.tx_sdu(sdu(i, 20));
    }
    assert_eq!(tx.buffer_status(), 5 * 21);
    for i in 0..5u8 {
        let p = tx.pull_pdu(100, at(0)).unwrap();
        assert_eq!(p[0], 0x00);
        assert_eq!(p.len(), 21);
        rx.rx_pdu(&p, at(0));
        assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(i, 20));
    }
    assert!(tx.pull_pdu(100, at(0)).is_none());
    assert_eq!(tx.buffer_status(), 0);
}

fn um_roundtrip(sn_len: SnLen, grant: usize, count: usize, len: usize) {
    let mut tx = um(sn_len, 35);
    let mut rx = um(sn_len, 35);
    let mut got = Vec::new();
    for i in 0..count {
        tx.tx_sdu(sdu(i as u8, len));
    }
    let mut slot = 0;
    while let Some(p) = tx.pull_pdu(grant, at(slot)) {
        assert!(p.len() <= grant);
        rx.rx_pdu(&p, at(slot));
        while let Some(s) = rx.pop_rx_sdu() {
            got.push(s);
        }
        slot += 1;
    }
    assert_eq!(got.len(), count);
    for (i, s) in got.iter().enumerate() {
        assert_eq!(*s, sdu(i as u8, len), "sdu {i}");
    }
    assert_eq!(tx.buffer_status(), 0);
}

#[test]
fn um_segmentation_roundtrip_small_grants() {
    // Enough SDUs to wrap the 6-bit SN space several times.
    um_roundtrip(SnLen::Bits6, 7, 200, 40);
    um_roundtrip(SnLen::Bits12, 7, 60, 40);
    um_roundtrip(SnLen::Bits12, 90, 30, 500);
    // Grant exactly one more than the first-segment header carries one byte.
    um_roundtrip(SnLen::Bits12, 5, 3, 9);
    um_roundtrip(SnLen::Bits6, 4, 3, 5);
}

#[test]
fn um_segment_headers_carry_si_and_so() {
    let mut tx = um(SnLen::Bits12, 35);
    tx.tx_sdu(sdu(1, 30));
    assert!(tx.pull_pdu(2, at(0)).is_none(), "header only does not fit a byte");
    let p1 = tx.pull_pdu(12, at(0)).unwrap(); // first: 2-byte hdr + 10
    assert_eq!(p1.len(), 12);
    assert_eq!(p1[0] >> 6, 0b01);
    assert_eq!(tx.buffer_status(), 20 + 4);
    let p2 = tx.pull_pdu(14, at(0)).unwrap(); // middle: 4-byte hdr + 10, SO=10
    assert_eq!(p2[0] >> 6, 0b11);
    assert_eq!(&p2[2..4], &[0, 10]);
    let p3 = tx.pull_pdu(100, at(0)).unwrap(); // last: SO=20
    assert_eq!(p3[0] >> 6, 0b10);
    assert_eq!(&p3[2..4], &[0, 20]);
    assert_eq!(p3.len(), 14);
    // Reassemble out of order.
    let mut rx = um(SnLen::Bits12, 35);
    rx.rx_pdu(&p3, at(0));
    rx.rx_pdu(&p1, at(0));
    assert!(rx.pop_rx_sdu().is_none());
    rx.rx_pdu(&p2, at(0));
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(1, 30));
    // Duplicates after delivery are ignored.
    rx.rx_pdu(&p2, at(0));
    assert!(rx.pop_rx_sdu().is_none());
}

#[test]
fn um_t_reassembly_discards_incomplete_sdu_and_moves_on() {
    let mut tx = um(SnLen::Bits12, 10); // 10 ms = 20 slots at mu=1
    let mut rx = um(SnLen::Bits12, 10);
    tx.tx_sdu(sdu(1, 30));
    tx.tx_sdu(sdu(2, 30));
    let a1 = tx.pull_pdu(17, at(0)).unwrap();
    let a2 = tx.pull_pdu(100, at(0)).unwrap();
    let b1 = tx.pull_pdu(17, at(0)).unwrap();
    let b2 = tx.pull_pdu(100, at(0)).unwrap();
    rx.rx_pdu(&a1, at(0)); // SN0 first segment; a2 lost
    rx.rx_pdu(&b1, at(1)); // SN1 first segment → t-Reassembly starts
    rx.rx_pdu(&b2, at(2)); // SN1 complete, delivered immediately (§5.2.2.2.3)
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(2, 30));
    for s in 3..30 {
        rx.tick(at(s));
    }
    // Expired: SN0 discarded. Its late last segment is now below
    // RX_Next_Reassembly and dropped.
    rx.rx_pdu(&a2, at(31));
    assert!(rx.pop_rx_sdu().is_none());
    // Normal operation continues.
    tx.tx_sdu(sdu(3, 30));
    let c1 = tx.pull_pdu(17, at(32)).unwrap();
    let c2 = tx.pull_pdu(100, at(32)).unwrap();
    rx.rx_pdu(&c1, at(32));
    rx.rx_pdu(&c2, at(32));
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(3, 30));
}

#[test]
fn um_malformed_pdus_are_dropped() {
    let mut rx = um(SnLen::Bits12, 35);
    rx.rx_pdu(&[], at(0));
    rx.rx_pdu(&[0x40], at(0)); // first segment, truncated SN
    rx.rx_pdu(&[0x80, 0x01, 0x00], at(0)); // last segment, truncated SO
    rx.rx_pdu(&[0x40, 0x01], at(0)); // first segment with no data
    assert!(rx.pop_rx_sdu().is_none());
    rx.reestablish();
}

// ------------------------------------------------------------------------
// AM: a lossy, reordering duplex channel between two entities
// ------------------------------------------------------------------------

struct Channel {
    rng: Rng,
    loss_pct: u64,
    max_delay: u64,
    /// (deliver-at slot, direction a→b?, pdu)
    inflight: Vec<(u64, bool, Vec<u8>)>,
    dropped: usize,
}

impl Channel {
    fn send(&mut self, now: u64, a_to_b: bool, pdu: Vec<u8>) {
        if self.rng.below(100) < self.loss_pct {
            self.dropped += 1;
            return;
        }
        let delay = 1 + self.rng.below(self.max_delay.max(1));
        self.inflight.push((now + delay, a_to_b, pdu));
    }

    fn deliver(&mut self, now: u64, a: &mut RlcEntity, b: &mut RlcEntity) {
        let mut i = 0;
        while i < self.inflight.len() {
            if self.inflight[i].0 <= now {
                let (_, a_to_b, pdu) = self.inflight.swap_remove(i);
                if a_to_b {
                    b.rx_pdu(&pdu, at(now));
                } else {
                    a.rx_pdu(&pdu, at(now));
                }
            } else {
                i += 1;
            }
        }
    }
}

/// Run two AM entities against each other for `slots` slots, feeding `count`
/// SDUs in each direction, and assert loss-free in-order delivery.
fn am_duplex(sn_len: SnLen, seed: u64, loss_pct: u64, count: usize, slots: u64) {
    // A high maxRetxThreshold: with heavy loss and reordering a STATUS can
    // re-NACK an SDU whose retransmission is still in flight, and each such
    // NACK legitimately increments RETX_COUNT (§5.3.2).
    let mut a = am_with(sn_len, 64, 20);
    let mut b = am_with(sn_len, 64, 20);
    let mut ch = Channel { rng: Rng(seed), loss_pct, max_delay: 6, inflight: Vec::new(), dropped: 0 };
    let mut rng = Rng(seed ^ 0xDEAD_BEEF);
    let (mut sent_a, mut sent_b) = (0usize, 0usize);
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    for now in 0..slots {
        a.tick(at(now));
        b.tick(at(now));
        if now % 3 == 0 && sent_a < count {
            a.tx_sdu(sdu(sent_a as u8, 1 + rng.below(400) as usize));
            sent_a += 1;
        }
        if now % 5 == 0 && sent_b < count {
            b.tx_sdu(sdu(sent_b as u8 ^ 0x55, 1 + rng.below(300) as usize));
            sent_b += 1;
        }
        // Each side gets one grant per slot and may fill it with several PDUs.
        for (side, a_to_b) in [(&mut a, true), (&mut b, false)] {
            let mut grant = 30 + rng.below(250) as usize;
            while let Some(p) = side.pull_pdu(grant, at(now)) {
                assert!(p.len() <= grant);
                grant -= p.len();
                ch.send(now, a_to_b, p);
            }
        }
        ch.deliver(now, &mut a, &mut b);
        while let Some(s) = b.pop_rx_sdu() {
            got_b.push(s);
        }
        while let Some(s) = a.pop_rx_sdu() {
            got_a.push(s);
        }
    }
    assert!(ch.dropped > 0 || loss_pct == 0);
    assert_eq!(sent_a, count);
    assert_eq!(got_b.len(), count, "B received all of A's SDUs (dropped {})", ch.dropped);
    assert_eq!(got_a.len(), count, "A received all of B's SDUs");
    for (i, s) in got_b.iter().enumerate() {
        assert_eq!(s[0], sdu(i as u8, 1)[0], "B: SDU {i} in order");
    }
    for (i, s) in got_a.iter().enumerate() {
        assert_eq!(s[0], sdu(i as u8 ^ 0x55, 1)[0], "A: SDU {i} in order");
    }
    assert!(a.events().is_empty() && b.events().is_empty());
    assert_eq!(a.unacked_sdus(), 0, "everything A sent was acknowledged");
    assert_eq!(b.unacked_sdus(), 0);
    assert_eq!(a.buffer_status(), 0);
    assert_eq!(b.buffer_status(), 0);
}

#[test]
fn am_duplex_lossless_reordering() {
    am_duplex(SnLen::Bits12, 1, 0, 200, 1500);
}

#[test]
fn am_duplex_lossy_12bit() {
    am_duplex(SnLen::Bits12, 7, 15, 300, 6000);
    am_duplex(SnLen::Bits12, 42, 30, 120, 6000);
}

#[test]
fn am_duplex_lossy_18bit() {
    am_duplex(SnLen::Bits18, 99, 15, 300, 6000);
}

#[test]
fn am_duplex_sn_wrap_12bit() {
    // 4500 SDUs wraps the 12-bit SN space; keep loss modest so it completes.
    am_duplex(SnLen::Bits12, 3, 5, 4500, 24000);
}

// ------------------------------------------------------------------------
// AM: targeted behaviour
// ------------------------------------------------------------------------

/// Pull all PDUs that fit in `grant` from `e` at `now`.
fn drain(e: &mut RlcEntity, grant: usize, now: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(p) = e.pull_pdu(grant, at(now)) {
        out.push(p);
    }
    out
}

#[test]
fn am_headers_and_poll_on_buffer_empty() {
    let mut tx = am(SnLen::Bits12);
    tx.tx_sdu(sdu(1, 10));
    tx.tx_sdu(sdu(2, 10));
    assert_eq!(tx.buffer_status(), 24);
    let p1 = tx.pull_pdu(100, at(0)).unwrap();
    // D/C=1, P=0 (more data pending), SI=00, SN=0.
    assert_eq!(&p1[..2], &[0x80, 0x00]);
    let p2 = tx.pull_pdu(100, at(0)).unwrap();
    // Last PDU empties the buffer → P=1, SN=1.
    assert_eq!(&p2[..2], &[0xC0, 0x01]);
    assert_eq!(tx.unacked_sdus(), 2);
    assert_eq!(tx.buffer_status(), 0, "transmitted-but-unacked data is not buffer status");
}

#[test]
fn am_poll_pdu_counter() {
    let mut tx = am(SnLen::Bits12); // pollPDU = 4
    for i in 0..10u8 {
        tx.tx_sdu(sdu(i, 5));
    }
    let pdus = drain(&mut tx, 100, 0);
    assert_eq!(pdus.len(), 10);
    let polls: Vec<bool> = pdus.iter().map(|p| p[0] & 0x40 != 0).collect();
    // 4th, 8th (pollPDU) and 10th (buffer empty).
    assert_eq!(polls, [false, false, false, true, false, false, false, true, false, true]);
}

#[test]
fn am_status_reports_nack_ranges_and_segments() {
    // A long t-PollRetransmit on the transmitter so the STATUS below arrives
    // before it expires (its expiry would queue a retransmission on its own).
    let mut tx = am_with(SnLen::Bits12, 4, 500);
    let mut rx = am(SnLen::Bits12);
    for i in 0..8u8 {
        tx.tx_sdu(sdu(i, 30));
    }
    // SN 0..6 whole; SN 7 as three segments.
    let pdus: Vec<Vec<u8>> = (0..7).map(|_| tx.pull_pdu(100, at(0)).unwrap()).collect();
    let s7a = tx.pull_pdu(12, at(0)).unwrap();
    let s7b = tx.pull_pdu(14, at(0)).unwrap();
    assert_eq!(AmdHeader::decode(SnLen::Bits12, &s7b).unwrap().0.si, Si::Middle);
    let s7c = tx.pull_pdu(100, at(0)).unwrap();
    assert!(tx.pull_pdu(100, at(0)).is_none());
    // Deliver SN 0, 1, 4, 6 whole; SN 7 first + last segment (middle lost).
    for i in [0usize, 1, 4, 6] {
        rx.rx_pdu(&pdus[i], at(1));
    }
    rx.rx_pdu(&s7a, at(1));
    rx.rx_pdu(&s7c, at(1));
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(0, 30));
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(1, 30));
    assert!(rx.pop_rx_sdu().is_none(), "in-sequence delivery holds SN 4, 6");
    // Nothing is reported before t-Reassembly (10 ms = 20 slots) expires.
    assert!(rx.pull_pdu(100, at(2)).is_none());
    // t-Reassembly started when SN 4 arrived (trigger = RX_Next_Highest = 5);
    // its first expiry (slot 21) moves RX_Highest_Status to 5 and restarts the
    // timer with trigger 8, which expires at slot 41 (§5.2.3.2.4).
    for s in 2..=41 {
        rx.tick(at(s));
    }
    assert!(rx.buffer_status() > 0, "a triggered STATUS counts as data volume");
    let st = rx.pull_pdu(100, at(42)).unwrap();
    let st = StatusPdu::decode(SnLen::Bits12, &st).unwrap();
    assert_eq!(st.ack_sn, 8);
    assert_eq!(
        st.nacks,
        vec![
            Nack { sn: 2, so: None, range: Some(2) },
            Nack { sn: 5, so: None, range: None },
            Nack { sn: 7, so: Some((10, 19)), range: None },
        ]
    );
    // t-StatusProhibit (5 ms = 10 slots) holds a second report.
    assert!(rx.pull_pdu(100, at(43)).is_none());
    // Feed the STATUS back: retransmissions come out first, in NACK order,
    // and only the missing segment of SN 7.
    tx.rx_pdu(&st.encode(SnLen::Bits12), at(43));
    assert_eq!(tx.unacked_sdus(), 4);
    assert_eq!(tx.buffer_status(), 3 * 32 + 10 + 4);
    let r = drain(&mut tx, 100, 44);
    assert_eq!(r.len(), 4);
    assert_eq!(AmdHeader::decode(SnLen::Bits12, &r[0]).unwrap().0.sn, 2);
    assert_eq!(AmdHeader::decode(SnLen::Bits12, &r[1]).unwrap().0.sn, 3);
    assert_eq!(AmdHeader::decode(SnLen::Bits12, &r[2]).unwrap().0.sn, 5);
    let (h, hl) = AmdHeader::decode(SnLen::Bits12, &r[3]).unwrap();
    assert_eq!((h.sn, h.si, h.so), (7, Si::Middle, 10));
    assert_eq!(&r[3][hl..], &sdu(7, 30)[10..20]);
    assert!(r[3][0] & 0x40 != 0, "last retransmission with empty buffers polls");
    for p in &r {
        rx.rx_pdu(p, at(45));
    }
    for i in 2..8u8 {
        assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(i, 30), "sdu {i}");
    }
    // The poll's STATUS acknowledges everything once the prohibit timer lapses.
    for s in 46..60 {
        rx.tick(at(s));
    }
    let st = StatusPdu::decode(SnLen::Bits12, &rx.pull_pdu(100, at(60)).unwrap()).unwrap();
    assert_eq!(st, StatusPdu { ack_sn: 8, nacks: vec![] });
    tx.rx_pdu(&st.encode(SnLen::Bits12), at(61));
    assert_eq!(tx.unacked_sdus(), 0);
}

#[test]
fn am_retransmission_is_resegmented_to_fit() {
    let mut tx = am(SnLen::Bits12);
    tx.tx_sdu(sdu(9, 100));
    let p = tx.pull_pdu(200, at(0)).unwrap();
    assert_eq!(p.len(), 102);
    // NACK the whole SDU.
    let st = StatusPdu { ack_sn: 1, nacks: vec![Nack { sn: 0, so: None, range: None }] };
    tx.rx_pdu(&st.encode(SnLen::Bits12), at(1));
    let mut rx = am(SnLen::Bits12);
    let mut n = 0;
    while let Some(p) = tx.pull_pdu(40, at(2)) {
        assert!(p.len() <= 40);
        rx.rx_pdu(&p, at(2));
        n += 1;
    }
    assert_eq!(n, 3);
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(9, 100));
}

#[test]
fn am_status_truncates_to_grant() {
    let mut rx = am(SnLen::Bits12);
    let mut tx = am(SnLen::Bits12);
    for i in 0..12u8 {
        tx.tx_sdu(sdu(i, 4));
    }
    let pdus = drain(&mut tx, 100, 0);
    // Alternate SNs missing: 1,3,5,7,9 missing; 0,2,4,6,8,10,11 received.
    for (i, p) in pdus.iter().enumerate() {
        if i % 2 == 0 || i == 11 {
            rx.rx_pdu(p, at(0));
        }
    }
    // First t-Reassembly expiry (trigger = 3) reports only SN 1; the restarted
    // timer (trigger = 12) covers the rest (§5.2.3.2.4) — tick through both.
    for s in 0..=45 {
        rx.tick(at(s));
    }
    // Full report would be 3 + 5·2 = 13 bytes; an 8-byte grant holds 2 NACKs.
    let st = StatusPdu::decode(SnLen::Bits12, &rx.pull_pdu(8, at(46)).unwrap()).unwrap();
    assert_eq!(st.nacks.len(), 2);
    assert_eq!(st.ack_sn, 5, "ACK_SN moves to the first unreported missing SN");
    assert_eq!(st.nacks[0].sn, 1);
    assert_eq!(st.nacks[1].sn, 3);
}

#[test]
fn am_t_poll_retransmit_retransmits_and_max_retx_event() {
    let mut tx = am(SnLen::Bits12); // t-PollRetransmit 20 ms = 40 slots, maxRetx 4
    tx.tx_sdu(sdu(1, 10));
    let p = tx.pull_pdu(100, at(0)).unwrap();
    assert!(p[0] & 0x40 != 0);
    assert!(tx.pull_pdu(100, at(1)).is_none());
    let mut retx = 0;
    let mut now = 1;
    while tx.events().is_empty() {
        now += 1;
        assert!(now < 1000, "max retx event never raised");
        tx.tick(at(now));
        if let Some(p) = tx.pull_pdu(100, at(now)) {
            let (h, _) = AmdHeader::decode(SnLen::Bits12, &p).unwrap();
            assert_eq!(h.sn, 0);
            assert!(h.poll, "retransmission after t-PollRetransmit carries a poll");
            retx += 1;
        }
    }
    // RETX_COUNT: 0 on first retx, then 1, 2, 3, 4 == threshold → 5 retransmissions.
    assert_eq!(retx, 5);
    assert_eq!(tx.events(), vec![], "event reported once");
    // Reestablishment clears everything.
    tx.reestablish();
    assert_eq!(tx.unacked_sdus(), 0);
    assert_eq!(tx.buffer_status(), 0);
}

#[test]
fn am_window_stall_and_ack_release() {
    // 12-bit SN: AM_Window_Size = 2048. Fill the window with 1-byte SDUs.
    let mut tx = am(SnLen::Bits12);
    for i in 0..2050u32 {
        tx.tx_sdu(vec![i as u8]);
    }
    let pdus = drain(&mut tx, 100, 0);
    assert_eq!(pdus.len(), 2048, "window stall at AM_Window_Size");
    assert!(pdus[2047][0] & 0x40 != 0, "poll when stalling");
    assert_eq!(tx.unacked_sdus(), 2048);
    // ACK the first 100 → window slides.
    tx.rx_pdu(&StatusPdu { ack_sn: 100, nacks: vec![] }.encode(SnLen::Bits12), at(1));
    assert_eq!(tx.unacked_sdus(), 1948);
    let more = drain(&mut tx, 100, 2);
    assert_eq!(more.len(), 2);
    assert_eq!(AmdHeader::decode(SnLen::Bits12, &more[0]).unwrap().0.sn, 2048);
    // ACK_SN beyond TX_Next is ignored.
    tx.rx_pdu(&StatusPdu { ack_sn: 3000, nacks: vec![] }.encode(SnLen::Bits12), at(3));
    assert_eq!(tx.unacked_sdus(), 1950);
}

#[test]
fn am_duplicates_and_out_of_window_are_discarded() {
    let mut tx = am(SnLen::Bits12);
    let mut rx = am(SnLen::Bits12);
    tx.tx_sdu(sdu(1, 10));
    let p = tx.pull_pdu(100, at(0)).unwrap();
    rx.rx_pdu(&p, at(0));
    rx.rx_pdu(&p, at(0));
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(1, 10));
    assert!(rx.pop_rx_sdu().is_none());
    // The duplicate carried a poll on a discarded PDU → STATUS triggered.
    let st = StatusPdu::decode(SnLen::Bits12, &rx.pull_pdu(100, at(1)).unwrap()).unwrap();
    assert_eq!(st.ack_sn, 1);
    // Out of window (SN 3000 with RX_Next = 1).
    let mut far = p.clone();
    far[0] = 0x80 | 0x0B;
    far[1] = 0xB8;
    rx.rx_pdu(&far, at(2));
    assert!(rx.pop_rx_sdu().is_none());
    // Malformed inputs.
    rx.rx_pdu(&[], at(2));
    rx.rx_pdu(&[0x80], at(2));
    rx.rx_pdu(&[0x00, 0x01], at(2));
    rx.rx_pdu(&[0x00, 0x01, 0x80, 0x00], at(2));
    rx.rx_pdu(&[0xB0, 0x02, 0x00], at(2));
    assert!(rx.pop_rx_sdu().is_none());
}

#[test]
fn am_18bit_segment_roundtrip() {
    let mut tx = am(SnLen::Bits18);
    let mut rx = am(SnLen::Bits18);
    tx.tx_sdu(sdu(4, 50));
    let mut pdus = Vec::new();
    while let Some(p) = tx.pull_pdu(20, at(0)) {
        pdus.push(p);
    }
    assert_eq!(pdus.len(), 4); // 17 + 15 + 15 + 3
    assert_eq!(AmdHeader::decode(SnLen::Bits18, &pdus[1]).unwrap().0.so, 17);
    for p in pdus.iter().rev() {
        rx.rx_pdu(p, at(1));
    }
    assert_eq!(rx.pop_rx_sdu().unwrap(), sdu(4, 50));
}

#[test]
fn invalid_sn_lengths_are_clamped() {
    let u = RlcEntity::new(RlcMode::Um(UmConfig { sn_len: SnLen::Bits18, t_reassembly_ms: 1 }), MU);
    assert!(matches!(u.mode(), RlcMode::Um(_)));
    let a = RlcEntity::new(RlcMode::Am(AmConfig { sn_len: SnLen::Bits6, ..AmConfig::srb_default() }), MU);
    assert!(matches!(a.mode(), RlcMode::Am(_)));
}

