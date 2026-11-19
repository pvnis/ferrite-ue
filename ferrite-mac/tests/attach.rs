//! MAC entity against a scripted PHY: RA → RAR → Msg3 → Msg4 contention
//! resolution → UL grant → PUSCH with a MAC SDU, plus a DL assignment whose
//! HARQ-ACK goes out on a PUCCH at n + k1.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_common::{Numerology, Rnti, RntiKind, SlotPoint};
use ferrite_fapi::config::PrachConfig;
use ferrite_fapi::*;
use ferrite_mac::*;

struct FakeUpper {
    pending: Vec<u8>,
    rx: Vec<(u8, Vec<u8>)>,
}

impl UpperLayers for FakeUpper {
    fn dl_sdu(&mut self, lcid: u8, sdu: &[u8], _now: SlotPoint) {
        self.rx.push((lcid, sdu.to_vec()));
    }
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

fn config() -> MacConfig {
    let n = Numerology::KHZ30;
    let mut c = MacConfig::initial(
        n,
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
        trans_max: 64,
        resources: vec![(10, 7, 1)],
    }];
    c
}

fn slot(n: u64) -> SlotPoint {
    SlotPoint::from_index(Numerology::KHZ30, n)
}

fn step(mac: &mut MacEntity, up: &mut FakeUpper, msg: PhyToMac) -> Vec<MacToPhy> {
    let mut out = Vec::new();
    mac.handle_with(msg, &mut out, up);
    for m in &out {
        if let MacToPhy::UlTti(r) = m {
            for p in &r.pdus {
                if let UlTtiPdu::Pusch { tb, .. } = p {
                    check_ul_layout(tb);
                }
            }
        }
    }
    out
}

/// TS 38.321 §6.1.2: in a UL MAC PDU the subPDUs with MAC SDUs come first,
/// then those with MAC CEs, then padding.
fn check_ul_layout(tb: &[u8]) {
    let lcids = ferrite_mac::pdu::ul_subpdu_lcids(tb).expect("well-formed UL MAC PDU");
    let is_ce = |l: u8| (53..=62).contains(&l);
    let first_ce = lcids.iter().position(|&l| is_ce(l)).unwrap_or(lcids.len());
    assert!(
        lcids[first_ce..].iter().all(|&l| is_ce(l) || l == 63),
        "MAC SDU after a MAC CE: LCIDs {lcids:?}"
    );
}

#[test]
fn attach_flow() {
    // PHR configured (reported periodically): its CE shares PUSCHs with
    // MAC SDUs, which `check_ul_layout` holds to the §6.1.2 order.
    let mut cfg = config();
    cfg.phr = Some(ferrite_mac::phr::PhrMacConfig {
        periodic_ms: Some(10),
        prohibit_ms: 0,
        tx_power_factor_change_db: None,
    });
    let mut mac = MacEntity::new(cfg);
    let mut up = FakeUpper {
        pending: Vec::new(),
        rx: Vec::new(),
    };
    let ccch = [0x1f, 0xaa, 0xbb, 0xcc, 0xdd, 0x06];
    mac.start_ra(ccch);
    // Slots until a PRACH request appears.
    let mut prach: Option<(PrachOccasion, u8)> = None;
    let mut n = 0u64;
    while prach.is_none() && n < 100 {
        for m in step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: slot(n) }),
        ) {
            if let MacToPhy::UlTti(req) = m {
                for p in req.pdus {
                    if let UlTtiPdu::Prach {
                        occasion, preamble, ..
                    } = p
                    {
                        prach = Some((occasion, preamble));
                    }
                }
            }
        }
        n += 1;
    }
    let (occ, preamble) = prach.expect("PRACH requested");
    assert_eq!(occ.slot.slot, 19);
    // PHY reports the preamble sent; MAC must now monitor the RA-RNTI.
    let out = step(
        &mut mac,
        &mut up,
        PhyToMac::Rach(RachIndication {
            slot: occ.slot,
            ra_rnti: occ.ra_rnti,
            preamble,
        }),
    );
    assert!(out
        .iter()
        .any(|m| matches!(m, MacToPhy::SetRntis { ra_rnti: Some(r), .. } if *r == occ.ra_rnti)));
    // RAR: TA 5, grant fdra RIV for 3 RBs at RB 4 (N=24), time 0, mcs 0, tpc 7, tc-rnti 0x4601.
    let riv = (3 - 1) * 24 + 4; // RIV = N(L-1)+S for L-1 <= N/2
    let g: u32 = ((riv as u32) << 12) | (7 << 1);
    let ta: u16 = 5;
    let mut rar = vec![0x40 | preamble];
    rar.push(((ta >> 5) & 0x7f) as u8);
    rar.push((((ta & 0x1f) as u8) << 3) | ((g >> 24) & 7) as u8);
    rar.extend_from_slice(&[(g >> 16) as u8, (g >> 8) as u8, g as u8]);
    rar.extend_from_slice(&0x4601u16.to_be_bytes());
    let rar_slot = occ.slot.add(5);
    let out = step(
        &mut mac,
        &mut up,
        PhyToMac::RxData(RxDataIndication {
            rnti: occ.ra_rnti,
            rnti_kind: RntiKind::Ra,
            harq_id: 0,
            ndi: 0,
            pdsch_slot: rar_slot,
            tb: Some(rar),
            sinr_db: 30.0,
        }),
    );
    assert!(out
        .iter()
        .any(|m| matches!(m, MacToPhy::TimingAdvance { n_ta_tc } if *n_ta_tc == 5 * 512)));
    assert!(out.iter().any(|m| matches!(
        m,
        MacToPhy::SetRntis {
            tc_rnti: Some(Rnti(0x4601)),
            ..
        }
    )));
    // MAC parses the RAR grant fields and asks the PHY to resolve them.
    let rar_grant = out
        .iter()
        .find_map(|m| {
            if let MacToPhy::RarGrant {
                rar_slot: s,
                tc_rnti,
                grant,
            } = m
            {
                Some((*s, *tc_rnti, *grant))
            } else {
                None
            }
        })
        .expect("RAR grant handed to the PHY");
    assert_eq!(rar_grant.0, rar_slot);
    assert_eq!(rar_grant.1, Rnti(0x4601));
    assert_eq!(
        rar_grant.2,
        RarUlGrant {
            freq_hopping: false,
            fdra: riv as u16,
            time_resource: 0,
            mcs: 0,
            tpc: 7,
            csi_request: false
        }
    );
    // The PHY's answer: the Msg3 grant (k2 = 4, Δ = 3 at 30 kHz), 3 RBs at RB 4.
    let msg3_grant = UlGrant {
        rnti: Rnti(0x4601),
        rnti_kind: RntiKind::Tc,
        pusch_slot: rar_slot.add(4 + 3),
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
        harq_id: 0,
        ndi: 0,
        rv: 0,
        dai: None,
        tpc: 7,
        csi_request: 0,
        ul_sch: true,
        cdm_groups_wo_data: 2,
        dmrs_add_pos: 2,
        freq_hopping: false,
        transform_precoding: None,
    };
    let out = step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: rar_slot,
            dci: Dci::Ul(msg3_grant),
        }),
    );
    let msg3 = out.iter().find_map(|m| match m {
        MacToPhy::UlTti(r) => r.pdus.iter().find_map(|p| {
            if let UlTtiPdu::Pusch { grant, tb, .. } = p {
                Some((r.slot, grant.clone(), tb.clone()))
            } else {
                None
            }
        }),
        _ => None,
    });
    let (msg3_slot, grant, tb) = msg3.expect("Msg3 scheduled");
    assert_eq!(msg3_slot, rar_slot.add(4 + 3));
    assert_eq!(grant.rnti, Rnti(0x4601));
    assert_eq!((grant.prb_start, grant.n_prb), (4, 3));
    assert_eq!(tb.len(), 11);
    assert_eq!(tb[0], 52); // CCCH48 subheader
    assert_eq!(&tb[1..7], &ccch);
    // Msg4: DCI 1_0 for the TC-RNTI then the PDSCH with the ConRes CE + CCCH SDU.
    let m4_slot = msg3_slot.add(6);
    let dl = DlGrant {
        rnti: Rnti(0x4601),
        rnti_kind: RntiKind::Tc,
        common_search_space: true,
        pdsch_slot: m4_slot,
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
        ndi: 0,
        rv: 0,
        ack_slot: Some(m4_slot.add(4)),
        dai: 0,
        pri: 0,
        tpc: 1,
        cdm_groups_wo_data: 2,
        n_layers: 1,
        dmrs_ports: vec![0],
        dmrs_add_pos: 2,
        vrb_to_prb_interleaved: false,
        r_pucch_common: 0,
    };
    step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: m4_slot,
            dci: Dci::Dl(dl.clone()),
        }),
    );
    let mut pdu = vec![62];
    pdu.extend_from_slice(&ccch);
    pdu.extend_from_slice(&[0, 3, 0x20, 0x40, 0x08, 63, 0, 0]);
    let out = step(
        &mut mac,
        &mut up,
        PhyToMac::RxData(RxDataIndication {
            rnti: Rnti(0x4601),
            rnti_kind: RntiKind::Tc,
            harq_id: 0,
            ndi: 0,
            pdsch_slot: m4_slot,
            tb: Some(pdu),
            sinr_db: 30.0,
        }),
    );
    assert!(out.iter().any(|m| matches!(
        m,
        MacToPhy::SetRntis {
            c_rnti: Some(Rnti(0x4601)),
            tc_rnti: None,
            ..
        }
    )));
    let evs = mac.take_events();
    assert!(evs.iter().any(|e| matches!(
        e,
        MacEvent::RaSucceeded {
            c_rnti: Rnti(0x4601)
        }
    )));
    assert!(evs
        .iter()
        .any(|e| matches!(e, MacEvent::Ccch(c) if c == &[0x20, 0x40, 0x08])));
    // Run slots up to the ACK slot − lead: a PUCCH with ACK=1 must be requested.
    let mut pucch = None;
    let mut s = m4_slot.add(1);
    for _ in 0..8 {
        for m in step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: s }),
        ) {
            if let MacToPhy::UlTti(r) = m {
                for p in r.pdus {
                    if let UlTtiPdu::Pucch { resource, uci, .. } = p {
                        pucch = Some((r.slot, resource, uci));
                    }
                }
            }
        }
        s = s.add(1);
    }
    let (ps, res, uci) = pucch.expect("HARQ-ACK PUCCH");
    assert_eq!(ps, m4_slot.add(4));
    assert_eq!(uci.harq_ack, vec![1]);
    assert!(matches!(res, PucchResourceRef::Dedicated(0)));
    // Uplink data: a UL grant must produce a PUSCH carrying the SDU and a BSR.
    up.pending = vec![0xab; 40];
    let ul = UlGrant {
        rnti: Rnti(0x4601),
        rnti_kind: RntiKind::C,
        pusch_slot: s.add(4),
        prb_start: 0,
        n_prb: 5,
        time: TimeAlloc {
            mapping_type_a: true,
            start_symbol: 0,
            n_symbols: 14,
        },
        mcs: Mcs {
            index: 9,
            qm: 2,
            r_x1024: Some(679),
        },
        tbs_bits: 640,
        harq_id: 1,
        ndi: 1,
        rv: 0,
        dai: Some(3),
        tpc: 1,
        csi_request: 0,
        ul_sch: true,
        cdm_groups_wo_data: 2,
        dmrs_add_pos: 1,
        freq_hopping: false,
        transform_precoding: None,
    };
    step(
        &mut mac,
        &mut up,
        PhyToMac::Slot(SlotIndication { slot: s }),
    );
    step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: s,
            dci: Dci::Ul(ul.clone()),
        }),
    );
    let mut pusch = None;
    for _ in 0..4 {
        s = s.add(1);
        for m in step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: s }),
        ) {
            if let MacToPhy::UlTti(r) = m {
                for p in r.pdus {
                    if let UlTtiPdu::Pusch { grant, tb, uci, .. } = p {
                        pusch = Some((r.slot, grant, tb, uci));
                    }
                }
            }
        }
    }
    let (pslot, g, tb, uci) = pusch.expect("PUSCH");
    assert_eq!(pslot, ul.pusch_slot);
    assert_eq!(g.harq_id, 1);
    assert_eq!(tb.len(), 80);
    let subs = ferrite_mac::pdu::parse_dl_pdu(&tb); // same subheader layout
    assert!(subs
        .iter()
        .any(|x| matches!(x, ferrite_mac::pdu::DlSubPdu::Sdu { lcid: 1, sdu } if sdu.len() == 40)));
    assert!(uci.harq_ack.is_empty()); // T-DAI 3 with nothing booked → no ACK bits
    assert_eq!(mac.stats().ul_tb, 2);

    // A periodic CSI report occasion that falls on a PUSCH before any CSI
    // measurement still carries a report (CQI 0, "out of range"): the gNB
    // decodes one there whatever the UE does, and a PUSCH without it fails.
    let target = s.add(6);
    let mut c = config();
    c.csi_enabled = true;
    c.csi_reports = vec![CsiReportMacConfig {
        period_slots: 40,
        offset_slots: (target.index() % 40) as u16,
        pucch_resource: 8,
        quantity: ferrite_fapi::config::CsiReportQuantity::Cqi,
        codebook: ferrite_ran::codebook::Codebook::OnePort,
        allowed_ranks: vec![1],
    }];
    mac.reconfigure(c);
    let ul2 = UlGrant {
        pusch_slot: target,
        harq_id: 2,
        dai: None,
        ..ul.clone()
    };
    step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: s,
            dci: Dci::Ul(ul2),
        }),
    );
    let mut csi_pusch = None;
    for _ in 0..8 {
        s = s.add(1);
        for m in step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: s }),
        ) {
            if let MacToPhy::UlTti(r) = m {
                for p in r.pdus {
                    if let UlTtiPdu::Pusch { uci, .. } = p {
                        csi_pusch = Some((r.slot, uci));
                    }
                }
            }
        }
    }
    let (cs, cuci) = csi_pusch.expect("PUSCH on the CSI occasion");
    assert_eq!(cs, target);
    assert_eq!(cuci.csi1, vec![0, 0, 0, 0]);
    assert_eq!(mac.ra_fsm_stats().violations, 0);
    assert_eq!(mac.fsm_stats().violations, 0);
    assert!(mac.ra_fsm_stats().transitions >= 5);
}

/// TS 38.321 §5.15: on a non-default BWP the bwp-InactivityTimer runs,
/// restarts on every C-RNTI PDCCH and switches back to the default BWP on
/// expiry; a DCI bandwidth-part indicator and a random access switch too.
#[test]
fn bwp_inactivity_timer_and_switch_requests() {
    let mut c = config();
    c.dl_bwp_id = 1;
    c.default_dl_bwp_id = 0;
    c.bwp_inactivity_timer_ms = Some(10); // 20 slots
    let mut mac = MacEntity::new(c);
    let mut up = FakeUpper {
        pending: Vec::new(),
        rx: Vec::new(),
    };
    let switches = |mac: &mut MacEntity| {
        mac.take_events()
            .into_iter()
            .filter(|e| matches!(e, MacEvent::BwpSwitch { .. }))
            .collect::<Vec<_>>()
    };
    for n in 0..19 {
        step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: slot(n) }),
        );
    }
    assert!(switches(&mut mac).is_empty());
    // A C-RNTI DL assignment at slot 19 restarts the timer.
    let dl = DlGrant {
        rnti: Rnti(0x4601),
        rnti_kind: RntiKind::C,
        common_search_space: false,
        pdsch_slot: slot(19),
        prb_start: 0,
        n_prb: 4,
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
        tbs_bits: 500,
        harq_id: 0,
        ndi: 1,
        rv: 0,
        ack_slot: None,
        dai: 0,
        pri: 0,
        tpc: 1,
        cdm_groups_wo_data: 2,
        n_layers: 1,
        dmrs_ports: vec![0],
        dmrs_add_pos: 2,
        vrb_to_prb_interleaved: false,
        r_pucch_common: 0,
    };
    step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: slot(19),
            dci: Dci::Dl(dl),
        }),
    );
    for n in 19..38 {
        step(
            &mut mac,
            &mut up,
            PhyToMac::Slot(SlotIndication { slot: slot(n) }),
        );
    }
    assert!(
        switches(&mut mac).is_empty(),
        "restarted at slot 19: no expiry before 39"
    );
    step(
        &mut mac,
        &mut up,
        PhyToMac::Slot(SlotIndication { slot: slot(39) }),
    );
    assert_eq!(
        switches(&mut mac),
        vec![MacEvent::BwpSwitch {
            dl_bwp: Some(0),
            ul_bwp: Some(0)
        }]
    );
    // A DCI with a bandwidth-part indicator is passed up as a switch request.
    step(
        &mut mac,
        &mut up,
        PhyToMac::Dci(DciIndication {
            slot: slot(40),
            dci: Dci::BwpSwitch {
                dl_bwp: Some(2),
                ul_bwp: None,
            },
        }),
    );
    assert_eq!(
        switches(&mut mac),
        vec![MacEvent::BwpSwitch {
            dl_bwp: Some(2),
            ul_bwp: None
        }]
    );
    // A random access from a non-initial BWP asks for the initial one first.
    mac.start_ra([0x1f, 1, 2, 3, 4, 5]);
    step(
        &mut mac,
        &mut up,
        PhyToMac::Slot(SlotIndication { slot: slot(41) }),
    );
    assert_eq!(
        switches(&mut mac),
        vec![MacEvent::BwpSwitch {
            dl_bwp: Some(0),
            ul_bwp: Some(0)
        }]
    );
    assert_eq!(mac.ra_fsm_stats().violations, 0);
    assert_eq!(mac.fsm_stats().violations, 0);
}
