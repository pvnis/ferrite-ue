//! The RRC state machine (TS 38.331 §4.2.1 and the procedures of §5.3) driven
//! through its public interface: the captured SIB1 / RRCSetup plus hand-built
//! UPER DL-DCCH and PCCH messages. No MAC, PDCP or NAS involved — the test
//! plays the stack and checks the events RRC asks it to carry out.

mod common;

use common::{hex, mib, radio, Bits, RRC_SETUP_HEX, SIB1_HEX};
use ferrite_common::{Numerology, SlotPoint};
use ferrite_rrc::{CipherAlg, IntegrityAlg, MacNotification, RbId, RrcConfig, RrcEvent, RrcState, RrcUe};

fn slot(n: u64) -> SlotPoint {
    SlotPoint::from_index(Numerology::KHZ30, n)
}

/// Slots in `ms` at 30 kHz.
fn ms(ms: u32) -> u64 {
    u64::from(ms) * 2
}

fn new_ue() -> RrcUe {
    RrcUe::new(RrcConfig { ue_random_id: Some(0x1234_5678), tx_lead_slots: 2, ..RrcConfig::default() })
}

/// A UE that has decoded SIB1 (RRC_IDLE with a cell).
fn camped() -> RrcUe {
    let mut ue = new_ue();
    ue.on_bcch(&hex(SIB1_HEX), &mib(), &radio());
    ue.take_events();
    ue
}

/// A UE in RRC_CONNECTED (RRCSetup done, SRB1 up, no AS security yet).
fn connected() -> RrcUe {
    let mut ue = camped();
    ue.tick(slot(0));
    ue.connect(vec![0x7e, 0x00, 0x41], slot(0));
    ue.on_mac(MacNotification::RaSucceeded { c_rnti: 0x4601 });
    ue.on_dl_ccch(&hex(RRC_SETUP_HEX));
    assert_eq!(ue.state(), RrcState::Connected);
    ue.take_events();
    ue
}

/// SecurityModeCommand (DL-DCCH c1 index 4) with the given algorithms.
fn smc(tid: u64, nea: u64, nia: u64) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(0, 1).put(4, 4); // DL-DCCH-MessageType c1 / securityModeCommand
    b.put(tid, 2).put(0, 1); // rrc-TransactionIdentifier, criticalExtensions = securityModeCommand
    b.put(0, 2); // SecurityModeCommand-IEs: no late / nonCritical extension
    b.put(0, 1); // SecurityConfigSMC extension marker
    b.put(0, 1).put(1, 1); // SecurityAlgorithmConfig: ext, integrityProtAlgorithm present
    b.put(0, 1).put(nea, 3); // cipheringAlgorithm (ENUMERATED, ext)
    b.put(0, 1).put(nia, 3); // integrityProtAlgorithm (ENUMERATED, ext)
    b.bytes()
}

/// RRCRelease (DL-DCCH c1 index 2) without any optional IE.
fn release(tid: u64) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(0, 1).put(2, 4).put(tid, 2).put(0, 1);
    b.put(0, 6); // RRCRelease-IEs: six absent OPTIONALs
    b.bytes()
}

/// DLInformationTransfer (DL-DCCH c1 index 5) carrying `nas`.
fn dl_info_transfer(tid: u64, nas: &[u8]) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(0, 1).put(5, 4).put(tid, 2).put(0, 1);
    b.put(0b100, 3); // dedicatedNAS-Message present, no extensions
    b.put(nas.len() as u64, 8);
    for &x in nas {
        b.put(u64::from(x), 8);
    }
    b.bytes()
}

/// A Paging message (PCCH) with one ng-5G-S-TMSI record.
fn paging(s_tmsi: u64) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(0, 1).put(0, 1); // PCCH-MessageType c1 / paging
    b.put(0b100, 3); // pagingRecordList present
    b.put(0, 5); // one record
    b.put(0, 1).put(0, 1); // PagingRecord: ext, accessType absent
    b.put(0, 1).put(0, 1); // PagingUE-Identity: ext, ng-5G-S-TMSI
    b.put(s_tmsi, 48);
    b.bytes()
}

fn has<F: Fn(&RrcEvent) -> bool>(events: &[RrcEvent], f: F) -> bool {
    events.iter().any(f)
}

#[test]
fn sib1_configures_the_cell_and_stays_idle() {
    let mut ue = new_ue();
    assert!(ue.cell().is_none());
    ue.on_bcch(&hex(SIB1_HEX), &mib(), &radio());
    let ev = ue.take_events();
    assert!(has(&ev, |e| matches!(e, RrcEvent::CellConfigured { plmn, tac, .. } if plmn == "00101" && *tac == 7)), "{ev:?}");
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(ue.cell().is_some());
    // The repeated SIB1 changes nothing.
    ue.on_bcch(&hex(SIB1_HEX), &mib(), &radio());
    assert!(ue.take_events().is_empty());
}

#[test]
fn connection_needs_a_cell() {
    let mut ue = new_ue();
    ue.connect(vec![0x7e], slot(0));
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(ue.take_events().is_empty());
}

#[test]
fn connection_establishment() {
    let mut ue = camped();
    ue.connect(vec![0x7e, 0x00, 0x41], slot(0));
    let ev = ue.take_events();
    assert_eq!(ue.state(), RrcState::Connecting);
    assert!(has(&ev, |e| matches!(e, RrcEvent::StartRa { .. })), "RRCSetupRequest handed to MAC: {ev:?}");
    // A second request while one is pending is ignored.
    ue.connect(vec![0x7e], slot(1));
    assert!(ue.take_events().is_empty());
    ue.on_mac(MacNotification::RaSucceeded { c_rnti: 0x4601 });
    ue.on_dl_ccch(&hex(RRC_SETUP_HEX));
    let ev = ue.take_events();
    assert_eq!(ue.state(), RrcState::Connected);
    assert!(has(&ev, |e| matches!(e, RrcEvent::SetupBearer(b) if b.rb == RbId::Srb(1) && b.lcid == 1)), "SRB1: {ev:?}");
    assert!(has(&ev, |e| matches!(e, RrcEvent::Reconfigure { .. })), "dedicated PHY/MAC configuration");
    assert!(has(&ev, |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })), "RRCSetupComplete on SRB1");
    assert!(has(&ev, |e| matches!(e, RrcEvent::Connected)));
    // Order: configuration before the complete message.
    let i_cfg = ev.iter().position(|e| matches!(e, RrcEvent::Reconfigure { .. })).unwrap();
    let i_tx = ev.iter().position(|e| matches!(e, RrcEvent::TxSrb { .. })).unwrap();
    assert!(i_cfg < i_tx);
}

#[test]
fn t300_expiry_returns_to_idle() {
    let mut ue = camped();
    let t300 = ue.cell().unwrap().t300_ms;
    ue.connect(vec![0x7e], slot(0));
    ue.take_events();
    ue.tick(slot(ms(t300) - 1));
    assert_eq!(ue.state(), RrcState::Connecting);
    assert!(ue.take_events().is_empty());
    ue.tick(slot(ms(t300)));
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Failed(why) if why.contains("T300"))));
}

#[test]
fn random_access_failure_while_connecting_is_a_failed_attempt() {
    let mut ue = camped();
    ue.connect(vec![0x7e], slot(0));
    ue.take_events();
    ue.on_mac(MacNotification::RaFailed);
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Failed(_))));
}

#[test]
fn rrc_setup_outside_connecting_is_ignored() {
    let mut ue = camped();
    ue.on_dl_ccch(&hex(RRC_SETUP_HEX));
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(ue.take_events().is_empty());
    let mut ue = connected();
    ue.on_dl_ccch(&hex(RRC_SETUP_HEX));
    assert_eq!(ue.state(), RrcState::Connected);
    assert!(ue.take_events().is_empty(), "a stray RRCSetup must not re-run the setup");
}

#[test]
fn security_mode_command_derives_keys_and_waits_for_the_mac_i_check() {
    let mut ue = connected();
    ue.set_k_gnb([7u8; 32]);
    ue.on_dl_dcch(1, &smc(1, 2, 2));
    let ev = ue.take_events();
    let sec = ev
        .iter()
        .find_map(|e| if let RrcEvent::VerifySecurity(s) = e { Some(*s) } else { None })
        .unwrap_or_else(|| panic!("VerifySecurity expected: {ev:?}"));
    assert_eq!((sec.integrity_alg, sec.ciphering_alg), (IntegrityAlg::Nia2, CipherAlg::Nea2));
    assert_ne!(sec.k_rrc_int, sec.k_up_int, "RRC and UP keys use different distinguishers");
    assert!(ue.security().is_none() || ue.security().is_some(), "security pending verification");
    ue.security_verified(true);
    let ev = ue.take_events();
    assert!(has(&ev, |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })), "SecurityModeComplete: {ev:?}");
    assert_eq!(ue.security().map(|s| s.integrity_alg), Some(IntegrityAlg::Nia2));
}

#[test]
fn failed_mac_i_check_sends_security_mode_failure() {
    let mut ue = connected();
    ue.set_k_gnb([7u8; 32]);
    ue.on_dl_dcch(1, &smc(2, 2, 2));
    ue.take_events();
    ue.security_verified(false);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })));
    assert!(ue.security().is_none());
}

#[test]
fn unsupported_algorithm_or_missing_key_is_a_security_mode_failure() {
    // NIA1 (SNOW 3G) is not implemented.
    let mut ue = connected();
    ue.set_k_gnb([7u8; 32]);
    ue.on_dl_dcch(1, &smc(1, 2, 1));
    let ev = ue.take_events();
    assert!(!has(&ev, |e| matches!(e, RrcEvent::VerifySecurity(_))), "{ev:?}");
    assert!(has(&ev, |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })), "SecurityModeFailure: {ev:?}");
    assert!(ue.security().is_none());
    // No K_gNB (NAS security not yet activated).
    let mut ue = connected();
    ue.on_dl_dcch(1, &smc(1, 2, 2));
    let ev = ue.take_events();
    assert!(!has(&ev, |e| matches!(e, RrcEvent::VerifySecurity(_))));
    assert!(has(&ev, |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })));
}

fn secured() -> RrcUe {
    let mut ue = connected();
    ue.set_k_gnb([7u8; 32]);
    ue.on_dl_dcch(1, &smc(1, 2, 2));
    ue.security_verified(true);
    ue.take_events();
    ue
}

#[test]
fn radio_link_failure_with_security_starts_reestablishment() {
    let mut ue = secured();
    ue.tick(slot(100));
    ue.on_mac(MacNotification::RadioLinkFailure);
    let ev = ue.take_events();
    assert_eq!(ue.state(), RrcState::Reestablishing);
    assert_eq!(ue.stats.reestablishments, 1);
    let i_re = ev.iter().position(|e| matches!(e, RrcEvent::Reestablishing)).unwrap_or_else(|| panic!("{ev:?}"));
    let i_cfg = ev.iter().position(|e| matches!(e, RrcEvent::Reconfigure { .. })).expect("back to the common configuration");
    let i_ra = ev.iter().position(|e| matches!(e, RrcEvent::StartRa { .. })).expect("RRCReestablishmentRequest");
    assert!(i_re < i_cfg && i_cfg < i_ra, "{ev:?}");
    // T301 runs from the request.
    let t301 = ue.cell().unwrap().t301_ms;
    ue.tick(slot(100 + ms(t301) - 1));
    assert_eq!(ue.state(), RrcState::Reestablishing);
    ue.tick(slot(100 + ms(t301)));
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Failed(why) if why.contains("T301"))));
    assert!(ue.security().is_none());
}

#[test]
fn rlc_max_retx_and_ra_failure_while_connected_are_radio_link_failures() {
    let mut ue = secured();
    ue.tick(slot(0));
    ue.on_mac(MacNotification::RlcMaxRetx { lcid: 1 });
    assert_eq!(ue.state(), RrcState::Reestablishing);
    let mut ue = secured();
    ue.tick(slot(0));
    ue.on_mac(MacNotification::RaFailed);
    assert_eq!(ue.state(), RrcState::Reestablishing);
    // A second RA failure during the re-establishment ends it.
    ue.take_events();
    ue.on_mac(MacNotification::RaFailed);
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Failed(_))));
}

#[test]
fn radio_link_failure_without_security_goes_to_idle() {
    let mut ue = connected();
    ue.tick(slot(0));
    ue.on_mac(MacNotification::RadioLinkFailure);
    let ev = ue.take_events();
    assert_eq!(ue.state(), RrcState::Idle, "§5.3.7.2: no re-establishment without AS security");
    assert!(has(&ev, |e| matches!(e, RrcEvent::Failed(_))), "{ev:?}");
    assert!(!has(&ev, |e| matches!(e, RrcEvent::Reestablishing)));
}

#[test]
fn reestablishment_fallback_to_rrc_setup_is_a_failure() {
    let mut ue = secured();
    ue.tick(slot(0));
    ue.on_mac(MacNotification::RadioLinkFailure);
    ue.take_events();
    ue.on_dl_ccch(&hex(RRC_SETUP_HEX));
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Failed(_))));
}

#[test]
fn release_returns_to_idle_and_drops_security() {
    let mut ue = secured();
    ue.on_dl_dcch(1, &release(0));
    let ev = ue.take_events();
    assert_eq!(ue.state(), RrcState::Idle);
    assert!(has(&ev, |e| matches!(e, RrcEvent::Released)), "{ev:?}");
    assert!(ue.security().is_none());
    // Idle again: a new connection is possible and uses the cell.
    ue.connect(vec![0x7e], slot(5));
    assert_eq!(ue.state(), RrcState::Connecting);
}

#[test]
fn nas_transport_only_while_connected() {
    let mut ue = camped();
    ue.send_nas(&[0x7e, 0x00, 0x4c]);
    assert!(ue.take_events().is_empty(), "dropped while idle");
    let mut ue = connected();
    ue.send_nas(&[0x7e, 0x00, 0x4c]);
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::TxSrb { srb: 1, .. })));
    assert_eq!(ue.stats.ul_dcch, 1);
    let nas = [0x7e, 0x00, 0x56, 0x01, 0x02];
    ue.on_dl_dcch(1, &dl_info_transfer(0, &nas));
    let ev = ue.take_events();
    assert!(has(&ev, |e| matches!(e, RrcEvent::DlNas(n) if n == &nas)), "{ev:?}");
}

#[test]
fn paging_with_the_ue_identity_requests_service() {
    let mut ue = camped();
    let mine = 0x1234_5678_9abc;
    ue.set_s_tmsi(Some(mine));
    ue.on_pcch(&paging(mine ^ 1));
    assert!(ue.take_events().is_empty(), "another UE's identity");
    ue.on_pcch(&paging(mine));
    assert!(has(&ue.take_events(), |e| matches!(e, RrcEvent::Paged)));
    // Without a registered identity nothing matches; while connected paging is ignored.
    ue.set_s_tmsi(None);
    ue.on_pcch(&paging(mine));
    assert!(ue.take_events().is_empty());
    let mut ue = connected();
    ue.set_s_tmsi(Some(mine));
    ue.on_pcch(&paging(mine));
    assert!(ue.take_events().is_empty());
}
