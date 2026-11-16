//! Codec bindings against the live OCUDU captures (n78 TDD 10 MHz cell):
//! SIB1 → common configuration, RRCSetup → dedicated configuration + bearers.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
    assert_eq!(
        cs0.start_crb as i32,
        p.ssb_crb as i32 - mib().coreset0_offset_rb
    );
    assert!(p.prach.phy.index > 0);
    assert!(!p.pusch_tdra_common.is_empty() || p.pdsch_tdra_common.is_empty());
    assert_eq!(cell.mac.tx_lead_slots, 2);
    // An FDD radio must reject the TDD cell.
    let fdd = RadioInfo {
        duplex: DuplexMode::Fdd,
        ..radio()
    };
    assert!(cell_from_sib1(&hex(SIB1_HEX), &mib(), &fdd, 2).is_err());
}

#[test]
fn rrc_setup_gives_dedicated_config_and_srb1() {
    let cell = cell_from_sib1(&hex(SIB1_HEX), &mib(), &radio(), 2).expect("SIB1");
    let DlCcch::Setup {
        tid: _,
        phy,
        mac,
        bearers,
        ..
    } = decode_dl_ccch(&hex(RRC_SETUP_HEX), &cell, 2).expect("RRCSetup")
    else {
        panic!("not a setup");
    };
    let srb1 = bearers.iter().find(|b| b.rb == RbId::Srb(1)).expect("SRB1");
    assert_eq!(srb1.lcid, 1);
    assert!(matches!(srb1.rlc, RlcSetup::Am { sn_len: 12, .. }));
    assert!(srb1.pdcp_integrity);
    // Dedicated PDCCH: a UE-specific search space on CORESET 1.
    assert!(phy.coresets.iter().any(|c| c.id == 1));
    assert!(phy
        .search_spaces
        .iter()
        .any(|s| s.kind != SearchSpaceKind::Common));
    // PUCCH: resource sets 0 (F1) and 1 (F2), SR and k1 list.
    assert!(phy
        .pucch
        .resources
        .iter()
        .any(|r| matches!(r.format, PucchFormat::F1 { .. })));
    assert!(phy
        .pucch
        .resources
        .iter()
        .any(|r| matches!(r.format, PucchFormat::F2 { .. })));
    assert!(phy.pucch.resource_sets.len() >= 2);
    assert!(!phy.pucch.k1_list.is_empty());
    assert!(!phy.pucch.sr_resources.is_empty());
    assert!(!mac.sr.is_empty() && !mac.sr[0].resources.is_empty());
    assert_eq!(mac.pucch.resource_sets.len(), phy.pucch.resource_sets.len());
    assert!(mac
        .logical_channels
        .iter()
        .any(|l| l.lcid == 1 && l.priority == 1));
    // CSI: the serving cell config carries a periodic report and TRS.
    assert!(!phy.csi_reports.is_empty());
    assert!(phy.pdsch.csi_rs_rate_match.iter().any(|r| !r.zero_power));
    assert!(mac.csi_enabled);
}

/// A second DL BWP added to the captured RRCSetup's CellGroupConfig: its
/// generic parameters place it on the carrier, its dedicated part is applied
/// on top of the common configuration, `firstActiveDownlinkBWP-Id` selects it
/// and the MAC gets the bwp-InactivityTimer / default BWP.
#[test]
fn cell_group_with_a_second_bwp() {
    use ferrite_asn1::{cellgroup as cg, common as cm, rrc, sib1};
    use ferrite_rrc::derive::cell_group_bwps;
    let cell = cell_from_sib1(&hex(SIB1_HEX), &mib(), &radio(), 2).expect("SIB1");
    let rrc::DlCcchMessage::RrcSetup(setup) =
        rrc::DlCcchMessage::decode(&hex(RRC_SETUP_HEX)).expect("decode")
    else {
        panic!("not a setup")
    };
    let mut c = setup.master_cell_group.clone();
    let scc = c
        .sp_cell_config
        .as_mut()
        .unwrap()
        .sp_cell_config_dedicated
        .as_mut()
        .unwrap();
    let initial = scc.initial_downlink_bwp.clone();
    // BWP 1: CRBs 2..22 of the carrier, same PDCCH/PDSCH dedicated config as the initial BWP.
    scc.downlink_bwp_to_add_mod_list.push(cg::BwpDownlink {
        bwp_id: 1,
        bwp_common: Some(sib1::BwpDownlinkCommon {
            generic_parameters: cm::Bwp {
                location_and_bandwidth: ferrite_ran::riv::riv_encode(2, 20, 275) as u16,
                subcarrier_spacing: cm::SubcarrierSpacing::Khz30,
                extended_cyclic_prefix: false,
            },
            pdcch_config_common: None,
            pdsch_config_common: None,
        }),
        bwp_dedicated: initial,
    });
    scc.first_active_downlink_bwp_id = Some(1);
    scc.default_downlink_bwp_id = Some(0);
    scc.bwp_inactivity_timer_ms = Some(10);
    let b = cell_group_bwps(&cell, &c);
    assert_eq!(b.by_id.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
    assert_eq!(b.active_id, 1);
    let (p1, m1) = &b.by_id[&1];
    assert_eq!(
        (p1.dl_bwp.id, p1.dl_bwp.start_crb, p1.dl_bwp.n_rb),
        (1, cell.phy.dl_carrier.offset_crb + 2, 20)
    );
    assert_eq!(
        p1.ul_bwp.id, 0,
        "no UL BWP 1: paired with the initial UL BWP"
    );
    assert_eq!(p1.nof_dl_bwp_rrc, 1);
    assert!(
        p1.search_spaces
            .iter()
            .any(|s| s.kind != SearchSpaceKind::Common),
        "dedicated search space on BWP 1"
    );
    assert_eq!(
        (
            m1.dl_bwp_id,
            m1.default_dl_bwp_id,
            m1.bwp_inactivity_timer_ms
        ),
        (1, 0, Some(10))
    );
    let (p0, m0) = &b.by_id[&0];
    assert_eq!((p0.dl_bwp.id, p0.dl_bwp.n_rb), (0, 24));
    assert_eq!(m0.dl_bwp_id, 0);
    assert_eq!(b.active.0.dl_bwp.id, 1);
    // The plain capture keeps a single BWP.
    let b = cell_group_bwps(&cell, &setup.master_cell_group);
    assert_eq!(b.by_id.len(), 1);
    assert_eq!(b.active_id, 0);
    assert_eq!(b.active.0.nof_dl_bwp_rrc, 0);
}
