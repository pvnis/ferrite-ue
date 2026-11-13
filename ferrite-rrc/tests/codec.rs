//! Codec bindings against the live OCUDU captures (n78 TDD 10 MHz cell):
//! SIB1 → common configuration, RRCSetup → dedicated configuration + bearers.

use ferrite_common::DuplexMode;
use ferrite_l1::config::{PucchFormat, SearchSpaceKind};
use ferrite_rrc::derive::{cell_from_sib1, decode_dl_ccch, DlCcch, MibInfo, RadioInfo};
use ferrite_rrc::{RbId, RlcSetup};

const SIB1_HEX: &str = "748101701040040200000e000a680018056109a008200042e02050900c316a61b3704020000080800041a2352412130426931860000042ee18b53224f8050664abff0124e9106e28dc61b8e372c6fbf56c70ea008580d003058b6822800000000000000000";
const RRC_SETUP_HEX: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2400044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c6050e1fa2b3c4de4d03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8801c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e20000001002000403000404801100520000118800f38e000";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn mib() -> MibInfo {
    let cs0 = ferrite_phy::coreset0::coreset0_config(30, 30, 10, 2).unwrap();
    MibInfo { pci: 1, mu: 1, dmrs_typea_pos: 2, k_ssb: 0, coreset0_index: 2, ss0_index: 0, ssb_index: 0, ssb_scs_khz: 30, ssb_arfcn: 626000, coreset0_n_rb: cs0.n_rb as u16, coreset0_n_symb: cs0.n_symb as u8, coreset0_offset_rb: cs0.offset_rb }
}

fn radio() -> RadioInfo {
    RadioInfo { fs: 15.36e6, duplex: DuplexMode::Tdd, band: 78 }
}

#[test]
fn sib1_gives_common_config() {
    let cell = cell_from_sib1(&hex(SIB1_HEX), &mib(), &radio(), 2).expect("SIB1");
    assert_eq!(cell.plmn, "00101");
    assert_eq!(cell.numerology.mu, 1);
    let p = &cell.phy;
    assert_eq!(p.dl_carrier.n_rb, 24);
    assert_eq!(p.dl_bwp.n_rb, 24);
    assert!(p.tdd.is_some(), "TDD cell");
    let cs0 = p.coresets.iter().find(|c| c.id == 0).expect("CORESET0");
    assert_eq!(cs0.rb_mask.len(), 24);
    assert_eq!(cs0.start_crb as i32, p.ssb_crb as i32 - mib().coreset0_offset_rb);
    assert!(p.prach.phy.index > 0);
    assert!(!p.pusch_tdra_common.is_empty() || p.pdsch_tdra_common.is_empty());
    assert_eq!(cell.mac.rach.ul_bwp_rb, 24);
    assert_eq!(cell.mac.rach.msg3_delta, 3);
    assert_eq!(cell.mac.tx_lead_slots, 2);
    // An FDD radio must reject the TDD cell.
    let fdd = RadioInfo { duplex: DuplexMode::Fdd, ..radio() };
    assert!(cell_from_sib1(&hex(SIB1_HEX), &mib(), &fdd, 2).is_err());
}

#[test]
fn rrc_setup_gives_dedicated_config_and_srb1() {
    let cell = cell_from_sib1(&hex(SIB1_HEX), &mib(), &radio(), 2).expect("SIB1");
    let DlCcch::Setup { tid: _, phy, mac, bearers } = decode_dl_ccch(&hex(RRC_SETUP_HEX), &cell, 2).expect("RRCSetup") else {
        panic!("not a setup");
    };
    let srb1 = bearers.iter().find(|b| b.rb == RbId::Srb(1)).expect("SRB1");
    assert_eq!(srb1.lcid, 1);
    assert!(matches!(srb1.rlc, RlcSetup::Am { sn_len: 12, .. }));
    assert!(srb1.pdcp_integrity);
    // Dedicated PDCCH: a UE-specific search space on CORESET 1.
    assert!(phy.coresets.iter().any(|c| c.id == 1));
    assert!(phy.search_spaces.iter().any(|s| s.kind != SearchSpaceKind::Common));
    // PUCCH: resource sets 0 (F1) and 1 (F2), SR and k1 list.
    assert!(phy.pucch.resources.iter().any(|r| matches!(r.format, PucchFormat::F1 { .. })));
    assert!(phy.pucch.resources.iter().any(|r| matches!(r.format, PucchFormat::F2 { .. })));
    assert!(phy.pucch.resource_sets.len() >= 2);
    assert!(!phy.pucch.k1_list.is_empty());
    assert!(!phy.pucch.sr_resources.is_empty());
    assert!(!mac.sr.is_empty() && !mac.sr[0].resources.is_empty());
    assert_eq!(mac.pucch.resource_sets.len(), phy.pucch.resource_sets.len());
    assert!(mac.logical_channels.iter().any(|l| l.lcid == 1 && l.priority == 1));
    // CSI: the serving cell config carries a periodic report and TRS.
    assert!(!phy.csi_reports.is_empty());
    assert!(phy.pdsch.csi_rs_rate_match.iter().any(|r| !r.zero_power));
    assert!(mac.csi_enabled);
}
