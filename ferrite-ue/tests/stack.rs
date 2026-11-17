//! The L2/L3 stack as the PHY sees it: FAPI messages in, FAPI messages out.
//! Drives [`ferrite_ue::stack::Stack`] with the captured SIB1 and slot
//! indications and checks that the layers are wired together: SIB1 → CONFIG
//! to the PHY, NAS registration → RRC connection → MAC random access, and the
//! retry policy after a failed attempt.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_common::{DuplexMode, Numerology, Rnti, RntiKind, SlotPoint};
use ferrite_fapi::*;
use ferrite_rrc::derive::MibInfo;
use ferrite_rrc::RrcState;
use ferrite_ue::config::{RadioConfig, UeConfig};
use ferrite_ue::stack::{Stack, StackEvent};

const SIB1_HEX: &str = "748101701040040200000e000a680018056109a008200042e02050900c316a61b3704020000080800041a2352412130426931860000042ee18b53224f8050664abff0124e9106e28dc61b8e372c6fbf56c70ea008580d003058b6822800000000000000000";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn slot(n: u64) -> SlotPoint {
    SlotPoint::from_index(Numerology::KHZ30, n)
}

fn mib() -> MibInfo {
    let cs0 = ferrite_phy::coreset0::coreset0_config(30, 30, 10, 2).unwrap();
    MibInfo {
        pci: 1,
        mu: 1,
        dmrs_typea_pos: 2,
        k_ssb: 0,
        coreset0_index: 2,
        ss0_index: 0,
        ssb_index: 0,
        ssb_scs_khz: 30,
        ssb_arfcn: 626000,
        coreset0_n_rb: cs0.n_rb as u16,
        coreset0_n_symb: cs0.n_symb as u8,
        coreset0_offset_rb: cs0.offset_rb,
    }
}

fn config() -> UeConfig {
    UeConfig {
        radio: RadioConfig::Zmq {
            tx: vec![String::new()],
            rx: String::new(),
        },
        fs: 15.36e6,
        dl_center_hz: 3.5e9,
        ul_center_hz: 3.5e9,
        band: 78,
        duplex: DuplexMode::Tdd,
        ssb_scs_khz: 30,
        gscn_hint: None,
        imsi: "001010000000001".into(),
        ki: [0x11; 16],
        opc: [0x22; 16],
        dnn: "internet".into(),
        ping_count: 0,
        ping_target: [0; 4],
        ping_interval_ms: 1000,
        ping_rounds: 1,
        ping_round_gap_s: 0,
        tun: None,
        netns: None,
        timeout_s: 0,
        exit_after_ping: false,
        independent_lo: false,
        emulate_lo_ppm: None,
        tx_lead: 2,
        ul_stream_lead_slots: 0,
        tx_rx_offset: 0,
        prach_offset: 0,
        rx_power_offset_db: 0.0,
        tx_full_scale_dbm: None,
        rlf_at_s: 0,
        rlm_outage: None,
        t3512_s: None,
        log: "info".into(),
        pcap: None,
        pcap_mac_udp: false,
    }
}

fn sib1(at: u64) -> PhyToMac {
    PhyToMac::RxData(RxDataIndication {
        rnti: Rnti(0xffff),
        rnti_kind: RntiKind::Si,
        harq_id: 0,
        ndi: 0,
        pdsch_slot: slot(at),
        tb: Some(hex(SIB1_HEX)),
        sinr_db: 30.0,
    })
}

fn events(stack: &mut Stack) -> Vec<StackEvent> {
    let mut v = Vec::new();
    while let Some(e) = stack.take_event() {
        v.push(e);
    }
    v
}

fn prach_requests(out: &[MacToPhy]) -> usize {
    out.iter().filter(|m| matches!(m, MacToPhy::UlTti(r) if r.pdus.iter().any(|p| matches!(p, UlTtiPdu::Prach { .. })))).count()
}

#[test]
fn sib1_configures_the_phy_and_starts_registration() {
    let mut stack = Stack::new(config(), Some(mib()));
    let mut phy: Vec<MacToPhy> = Vec::new();
    stack.handle(sib1(4), &mut phy);
    // CONFIG.request with the SIB1-derived cell configuration.
    let cfg = phy
        .iter()
        .find_map(|m| {
            if let MacToPhy::Config(c) = m {
                Some(c)
            } else {
                None
            }
        })
        .expect("CONFIG.request");
    assert_eq!(cfg.dl_bwp.n_rb, 24);
    assert!(cfg.tdd.is_some());
    assert_eq!(cfg.ssb.pci, 1);
    let ev = events(&mut stack);
    assert!(ev.iter().any(|e| matches!(e, StackEvent::CellConfigured { plmn, tac } if plmn == "00101" && *tac == 7)), "{ev:?}");
    // NAS started the registration → RRC asked for a connection → MAC runs the random access.
    assert_eq!(stack.rrc_state(), RrcState::Connecting);
    let mut prach = 0;
    for n in 5..400 {
        phy.clear();
        stack.handle(PhyToMac::Slot(SlotIndication { slot: slot(n) }), &mut phy);
        prach += prach_requests(&phy);
        if prach > 0 {
            break;
        }
    }
    assert!(prach > 0, "no PRACH request within 400 slots");
}

#[test]
fn failed_attempt_is_retried_after_a_backoff() {
    let mut stack = Stack::new(config(), Some(mib()));
    let mut phy: Vec<MacToPhy> = Vec::new();
    stack.handle(sib1(0), &mut phy);
    events(&mut stack);
    // Nobody answers the preambles: MAC gives up after preambleTransMax, RRC
    // reports the failure, and the stack must try again later.
    let mut failed_at = None;
    let mut prach_after_failure = 0;
    for n in 1..40_000u64 {
        phy.clear();
        stack.handle(PhyToMac::Slot(SlotIndication { slot: slot(n) }), &mut phy);
        if failed_at.is_none() {
            if events(&mut stack)
                .iter()
                .any(|e| matches!(e, StackEvent::Failed(_)))
            {
                failed_at = Some(n);
                assert_eq!(stack.rrc_state(), RrcState::Idle);
            }
        } else {
            prach_after_failure += prach_requests(&phy);
            if prach_after_failure > 0 {
                break;
            }
        }
    }
    let failed_at = failed_at.expect("the attempt must fail without a RAR");
    assert!(
        prach_after_failure > 0,
        "no new random access after the failure at slot {failed_at}"
    );
    assert_eq!(stack.rrc_state(), RrcState::Connecting);
}
