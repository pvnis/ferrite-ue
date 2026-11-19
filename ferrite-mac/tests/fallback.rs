//! MAC entity in the cases a lab run at the cell edge hit (2026-11-19): a
//! Msg4 the gNB retransmits after the UE resolved the contention, and a
//! random access with the C-RNTI after an SR failure.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_common::{Numerology, Rnti, RntiKind, SlotPoint};
use ferrite_fapi::config::PrachConfig;
use ferrite_fapi::*;
use ferrite_mac::*;

struct FakeUpper {
    pending: Vec<u8>,
}

impl UpperLayers for FakeUpper {
    fn dl_sdu(&mut self, _lcid: u8, _sdu: &[u8], _now: SlotPoint) {}
    fn ul_pull(&mut self, _lcid: u8, max_bytes: usize, _now: SlotPoint) -> Option<Vec<u8>> {
        if self.pending.is_empty() {
            return None;
        }
        let n = max_bytes.min(self.pending.len());
        Some(self.pending.drain(..n).collect())
    }
    fn ul_buffer_status(&mut self, _lcid: u8) -> usize {
        self.pending.len()
    }
}

/// SR every 10 slots at offset 7 (PUCCH resource 1), the lab cell's shape.
fn config(sr_trans_max: u32) -> MacConfig {
    let mut c = MacConfig::initial(
        Numerology::KHZ30,
        RachConfig {
            preamble_trans_max: 7,
            power_ramping_step_db: 4,
            target_power_dbm: -100,
            ra_response_window_slots: 20,
            contention_resolution_ms: 64,
            nof_cb_preambles: 64,
            cb_preambles_per_ssb: 64,
            prach: PrachConfig {
                phy: ferrite_ran::prach_config::PrachConfig {
                    index: 159,
                    duplex: ferrite_common::DuplexMode::Tdd,
                    mu: 1,
                    msg1_scs_mu: 1,
                    msg1_fdm: 1,
                    msg1_frequency_start: 5,
                },
                tdd: None,
                ssb_symbols: Vec::new(),
                ssb_period_ms: 20,
                zero_correlation_zone: 0,
                root_sequence_index: 1,
                restricted_set: 0,
                total_preambles: 64,
                target_power_dbm: -100,
                power_ramping_step_db: 4,
            },
        },
        3,
    );
    c.pucch.resource_sets = vec![(0, vec![0, 1], 2), (1, vec![8], 11)];
    c.pucch.resources = vec![(0, 1, 2), (1, 1, 2), (8, 2, 11)];
    c.sr = vec![SrConfig {
        sr_id: 0,
        prohibit_ms: 0,
        trans_max: sr_trans_max,
        resources: vec![(10, 7, 1)],
    }];
    c
}

fn step(mac: &mut MacEntity, up: &mut FakeUpper, msg: PhyToMac) -> Vec<MacToPhy> {
    let mut out = Vec::new();
    mac.handle_with(msg, &mut out, up);
    out
}

fn tick(mac: &mut MacEntity, up: &mut FakeUpper, s: SlotPoint) -> Vec<MacToPhy> {
    step(mac, up, PhyToMac::Slot(SlotIndication { slot: s }))
}

/// Run slots from `from` until the MAC requests a PRACH; the slot after.
fn until_prach(
    mac: &mut MacEntity,
    up: &mut FakeUpper,
    from: SlotPoint,
) -> (PrachOccasion, u8, SlotPoint) {
    let mut s = from;
    for _ in 0..2_000 {
        for m in tick(mac, up, s) {
            if let MacToPhy::UlTti(r) = m {
                for p in r.pdus {
                    if let UlTtiPdu::Prach {
                        occasion, preamble, ..
                    } = p
                    {
                        return (occasion, preamble, s.add(1));
                    }
                }
            }
        }
        s = s.add(1);
    }
    panic!("no PRACH requested");
}

/// The RAR for `preamble` (TA 5, a 3-RB grant at RB 4) assigning `tc`.
fn rar(
    mac: &mut MacEntity,
    up: &mut FakeUpper,
    occ: &PrachOccasion,
    preamble: u8,
    tc: u16,
) -> SlotPoint {
    step(
        mac,
        up,
        PhyToMac::Rach(RachIndication {
            slot: occ.slot,
            ra_rnti: occ.ra_rnti,
            preamble,
        }),
    );
    let riv = (3 - 1) * 24 + 4;
    let g: u32 = ((riv as u32) << 12) | (7 << 1);
    let ta: u16 = 5;
    let mut pdu = vec![0x40 | preamble];
    pdu.push(((ta >> 5) & 0x7f) as u8);
    pdu.push((((ta & 0x1f) as u8) << 3) | ((g >> 24) & 7) as u8);
    pdu.extend_from_slice(&[(g >> 16) as u8, (g >> 8) as u8, g as u8]);
    pdu.extend_from_slice(&tc.to_be_bytes());
    let at = occ.slot.add(5);
    step(
        mac,
        up,
        PhyToMac::RxData(RxDataIndication {
            rnti: occ.ra_rnti,
            rnti_kind: RntiKind::Ra,
            harq_id: 0,
            ndi: 0,
            pdsch_slot: at,
            tb: Some(pdu),
            sinr_db: 30.0,
        }),
    );
    at
}

fn ul_grant(rnti: u16, kind: RntiKind, pusch_slot: SlotPoint, harq_id: u8, ndi: u8) -> UlGrant {
    UlGrant {
        rnti: Rnti(rnti),
        rnti_kind: kind,
        pusch_slot,
        prb_start: 4,
        n_prb: 3,
        time: TimeAlloc {
            mapping_type_a: true,
            start_symbol: 0,
            n_symbols: 14,
        },
        mcs: Mcs {
            index: 0,
            qm: 2,
            r_x1024: Some(120),
        },
        tbs_bits: 88,
        harq_id,
        ndi,
        rv: 0,
        dai: None,
        tpc: 1,
        csi_request: 0,
        ul_sch: true,
        cdm_groups_wo_data: 2,
        dmrs_add_pos: 2,
        freq_hopping: false,
        transform_precoding: None,
    }
}

fn dl_grant(kind: RntiKind, pdsch_slot: SlotPoint, ndi: u8) -> DlGrant {
    DlGrant {
        rnti: Rnti(0x4601),
        rnti_kind: kind,
        pdsch_slot,
        prb_start: 0,
        n_prb: 21,
        time: TimeAlloc {
            mapping_type_a: true,
            start_symbol: 2,
            n_symbols: 12,
        },
        mcs: Mcs {
            index: 7,
            qm: 2,
            r_x1024: Some(526),
        },
        tbs_bits: 2664,
        harq_id: 0,
        ndi,
        rv: 0,
        ack_slot: Some(pdsch_slot.add(4)),
        dai: 0,
        pri: 0,
        tpc: 1,
        cdm_groups_wo_data: 2,
        n_layers: 1,
        dmrs_ports: vec![0],
        dmrs_add_pos: 2,
        vrb_to_prb_interleaved: false,
        r_pucch_common: 0,
    }
}

fn dci(mac: &mut MacEntity, up: &mut FakeUpper, slot: SlotPoint, dci: Dci) -> Vec<MacToPhy> {
    step(mac, up, PhyToMac::Dci(DciIndication { slot, dci }))
}

/// Initial access to RRC_CONNECTED with C-RNTI 0x4601; the Msg4 slot.
fn connect(mac: &mut MacEntity, up: &mut FakeUpper) -> SlotPoint {
    let ccch = [0x1f, 0xaa, 0xbb, 0xcc, 0xdd, 0x06];
    mac.start_ra(ccch);
    let (occ, preamble, _) = until_prach(mac, up, SlotPoint::from_index(Numerology::KHZ30, 0));
    let rar_slot = rar(mac, up, &occ, preamble, 0x4601);
    let msg3_slot = rar_slot.add(7);
    dci(
        mac,
        up,
        rar_slot,
        Dci::Ul(ul_grant(0x4601, RntiKind::Tc, msg3_slot, 0, 0)),
    );
    let m4 = msg3_slot.add(6);
    dci(mac, up, m4, Dci::Dl(dl_grant(RntiKind::Tc, m4, 0)));
    let mut pdu = vec![62];
    pdu.extend_from_slice(&ccch);
    pdu.extend_from_slice(&[0, 3, 0x20, 0x40, 0x08, 63, 0, 0]);
    step(
        mac,
        up,
        PhyToMac::RxData(RxDataIndication {
            rnti: Rnti(0x4601),
            rnti_kind: RntiKind::Tc,
            harq_id: 0,
            ndi: 0,
            pdsch_slot: m4,
            tb: Some(pdu),
            sinr_db: 30.0,
        }),
    );
    assert!(mac
        .take_events()
        .iter()
        .any(|e| matches!(e, MacEvent::RaSucceeded { .. })));
    m4
}

/// The HARQ-ACK bits of the PUCCHs requested while running `slots`.
fn pucch_acks(
    mac: &mut MacEntity,
    up: &mut FakeUpper,
    from: SlotPoint,
    slots: u64,
) -> Vec<(SlotPoint, Vec<u8>)> {
    let mut out = Vec::new();
    let mut s = from;
    for _ in 0..slots {
        for m in tick(mac, up, s) {
            if let MacToPhy::UlTti(r) = m {
                for p in r.pdus {
                    if let UlTtiPdu::Pucch { uci, .. } = p {
                        if !uci.harq_ack.is_empty() {
                            out.push((r.slot, uci.harq_ack));
                        }
                    }
                }
            }
        }
        s = s.add(1);
    }
    out
}

/// The gNB missed the Msg4 HARQ-ACK and retransmits Msg4 (same HARQ process
/// and NDI) after the UE resolved the contention, so the UE decodes the DCI
/// with its C-RNTI. The TB was delivered: the answer is ACK, whatever the
/// decode of the retransmission gives (TS 38.321 §5.3.2.2). A NACK kept the
/// gNB retransmitting until it had applied the dedicated configuration in
/// fallback, after which OCUDU never scheduled the UE again.
#[test]
fn msg4_retransmission_after_resolution_is_acked() {
    let mut mac = MacEntity::new(config(64));
    let mut up = FakeUpper {
        pending: Vec::new(),
    };
    let m4 = connect(&mut mac, &mut up);
    let retx = m4.add(10);
    dci(
        &mut mac,
        &mut up,
        retx,
        Dci::Dl(dl_grant(RntiKind::C, retx, 0)),
    );
    // The re-decode fails (no soft combining across the TC → C-RNTI switch).
    step(
        &mut mac,
        &mut up,
        PhyToMac::RxData(RxDataIndication {
            rnti: Rnti(0x4601),
            rnti_kind: RntiKind::C,
            harq_id: 0,
            ndi: 0,
            pdsch_slot: retx,
            tb: None,
            sinr_db: 0.0,
        }),
    );
    let acks = pucch_acks(&mut mac, &mut up, m4.add(5), 12);
    assert!(acks.contains(&(retx.add(4), vec![1])), "{acks:?}");
}

/// After an SR failure the MAC runs a random access with the C-RNTI MAC CE
/// in Msg3 (§5.4.4). Its Msg3 must go out even on an SR occasion (no SR
/// overlaps a UL-SCH resource; the PUCCH request used to replace Msg3), and
/// only a PDCCH to the C-RNTI with a UL grant resolves the contention
/// (§5.1.5) — any PDCCH, the SIB1's included, did before.
#[test]
fn crnti_random_access_after_sr_failure() {
    let mut mac = MacEntity::new(config(1));
    let mut up = FakeUpper {
        pending: Vec::new(),
    };
    let m4 = connect(&mut mac, &mut up);
    up.pending = vec![0x55; 40];
    let (occ, preamble, next) = until_prach(&mut mac, &mut up, m4.add(1));
    assert!(mac
        .take_events()
        .iter()
        .any(|e| matches!(e, MacEvent::SrFailure)));
    let rar_slot = rar(&mut mac, &mut up, &occ, preamble, 0x4602);
    // Msg3 on an SR occasion (slot ≡ 7 mod 10).
    let mut msg3_slot = rar_slot.add(7);
    while msg3_slot.index() % 10 != 7 {
        msg3_slot = msg3_slot.add(1);
    }
    let mut s = next;
    while s.diff(&rar_slot) <= 0 {
        tick(&mut mac, &mut up, s);
        s = s.add(1);
    }
    let out = dci(
        &mut mac,
        &mut up,
        rar_slot,
        Dci::Ul(ul_grant(0x4602, RntiKind::Tc, msg3_slot, 0, 0)),
    );
    let mut in_msg3_slot: Vec<&'static str> = out
        .iter()
        .filter_map(|m| match m {
            MacToPhy::UlTti(r) if r.slot == msg3_slot => Some("pusch"),
            _ => None,
        })
        .collect();
    while s.diff(&msg3_slot) <= 0 {
        for m in tick(&mut mac, &mut up, s) {
            if let MacToPhy::UlTti(r) = m {
                if r.slot == msg3_slot {
                    for p in &r.pdus {
                        in_msg3_slot.push(match p {
                            UlTtiPdu::Pucch { .. } => "pucch",
                            UlTtiPdu::Pusch { .. } => "pusch",
                            _ => "other",
                        });
                    }
                }
            }
        }
        s = s.add(1);
    }
    assert_eq!(in_msg3_slot, vec!["pusch"], "Msg3's slot");
    // An SI-RNTI DCI (SIB1) does not resolve the contention …
    let si = DlGrant {
        rnti: Rnti(0xffff),
        rnti_kind: RntiKind::Si,
        ack_slot: None,
        ..dl_grant(RntiKind::Si, s, 0)
    };
    dci(&mut mac, &mut up, s, Dci::Dl(si));
    assert!(!mac
        .take_events()
        .iter()
        .any(|e| matches!(e, MacEvent::RaSucceeded { .. })));
    // … a UL grant for the C-RNTI does.
    dci(
        &mut mac,
        &mut up,
        s,
        Dci::Ul(ul_grant(0x4601, RntiKind::C, s.add(4), 1, 1)),
    );
    assert!(mac.take_events().iter().any(|e| matches!(
        e,
        MacEvent::RaSucceeded {
            c_rnti: Rnti(0x4601)
        }
    )));
}
