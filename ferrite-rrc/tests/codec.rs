//! Codec bindings against the live OCUDU captures (n78 TDD 10 MHz cell):
//! SIB1 → common configuration, RRCSetup → dedicated configuration + bearers.

use ferrite_common::DuplexMode;
use ferrite_fapi::config::{PucchFormat, SearchSpaceKind};
use ferrite_rrc::derive::{cell_from_sib1, decode_dl_ccch, DlCcch, RadioInfo};
use ferrite_rrc::{RbId, RlcSetup};

mod common;
use common::{hex, mib, radio, RRC_SETUP_HEX, SIB1_HEX};

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
