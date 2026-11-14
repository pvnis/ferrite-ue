//! Scripted registration + PDU session against a fake 5G core that runs the
//! network side of 5G-AKA from the same K/OPc, verifies every uplink MAC and
//! deciphers with the negotiated algorithms.

use ferrite_nas::milenage::k_gnb;
use ferrite_nas::mm::{
    self, decode_mm, AuthenticationRequest, ConfigurationUpdateCommand,
    DeregistrationRequestUeTerminated, DeregistrationType, DlNasTransport, GprsTimer3, Guti,
    IdentityRequest, MmMessage, MobileIdentity, NgKsi, Plmn, RegistrationAccept,
    RegistrationReject, RegistrationRequest, SecurityHeaderType, SecurityModeCommand, Tai,
    UeSecurityCapability,
};
use ferrite_nas::security::{
    generate_auth_vector, verify_auts, AuthVector, NasSecurityContext, UsimKeys,
};
use ferrite_nas::sm::{
    decode_sm, PduAddress, PduSessionEstablishmentAccept, PduSessionEstablishmentReject,
    PduSessionReleaseCommand, PduSessionType, QosRule, SessionAmbr, SmMessage,
};
use ferrite_nas::{
    CmState, ConnectionCause, DeregisteredSub, MmState, NasConfig, NasError, NasEvent, NasUe,
    RegisteredSub, SmState, Snssai, UeIdentity,
};

const IMSI: &str = "001010167891203";
const K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
const OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];
const SNN: &str = "5G:mnc001.mcc001.3gppnetwork.org";
const ABBA: [u8; 2] = [0, 0];

fn plmn() -> Plmn {
    Plmn {
        mcc: 1,
        mnc: 1,
        mnc_digits: 2,
    }
}

fn guti() -> Guti {
    Guti {
        plmn: plmn(),
        amf_region_id: 2,
        amf_set_id: 1,
        amf_pointer: 0,
        tmsi: 0x0102_0304,
    }
}

/// Network side: AMF + AUSF/UDM in one struct.
struct FakeCore {
    keys: UsimKeys,
    sqn: u64,
    ea: u8,
    ia: u8,
    ctx: Option<NasSecurityContext>,
    av: Option<AuthVector>,
    rr: Option<RegistrationRequest>,
    initial_rr_bytes: Option<Vec<u8>>,
    log: Vec<String>,
    k_amf: Option<[u8; 32]>,
}

impl FakeCore {
    fn new(ea: u8, ia: u8) -> Self {
        FakeCore {
            keys: UsimKeys { k: K, opc: OPC },
            sqn: 0x20,
            ea,
            ia,
            ctx: None,
            av: None,
            rr: None,
            initial_rr_bytes: None,
            log: Vec::new(),
            k_amf: None,
        }
    }

    fn supi_from_rr(rr: &RegistrationRequest) -> String {
        match &rr.mobile_identity {
            MobileIdentity::Suci { plmn, msin, .. } => {
                format!("{:03}{:02}{}", plmn.mcc, plmn.mnc, msin)
            }
            other => panic!("expected SUCI, got {other:?}"),
        }
    }

    /// Unwrap (verify + decipher) a UL PDU into its plain message. For the
    /// SECURITY MODE COMPLETE (SHT 4) the new context is used.
    fn rx(&mut self, pdu: &[u8]) -> Vec<u8> {
        let (hdr, inner) = mm::split_security_header(pdu).expect("well-formed UL PDU");
        match hdr {
            None => inner.to_vec(),
            Some(h) => {
                let ctx = self.ctx.as_mut().expect("protected UL before context");
                ctx.unprotect(pdu, &h).expect("UL MAC verifies")
            }
        }
    }

    fn tx(&mut self, plain: Vec<u8>, sht: SecurityHeaderType) -> Vec<u8> {
        match self.ctx.as_mut() {
            Some(c) => c.protect(sht, &plain).0,
            None => plain,
        }
    }

    fn auth_request(&mut self, supi: &str) -> Vec<u8> {
        let av = generate_auth_vector(
            &self.keys,
            [0x5a; 16],
            self.sqn,
            [0x80, 0x00],
            SNN,
            supi,
            &ABBA,
        );
        let m = AuthenticationRequest {
            ngksi: NgKsi {
                mapped: false,
                ksi: 0,
            },
            abba: ABBA.to_vec(),
            rand: Some(av.rand),
            autn: Some(av.autn),
            eap_message: None,
        };
        self.av = Some(av);
        m.encode()
    }

    /// Handle one UL PDU, returning DL PDUs.
    fn on_ul(&mut self, pdu: &[u8]) -> Vec<Vec<u8>> {
        let plain = self.rx(pdu);
        let msg = decode_mm(&plain).expect("decodable UL message");
        self.log.push(format!("{msg:?}").chars().take(40).collect());
        match msg {
            MmMessage::RegistrationRequest(rr) => {
                assert_eq!(rr.ngksi, NgKsi::NO_KEY);
                let supi = Self::supi_from_rr(&rr);
                assert_eq!(supi, IMSI);
                self.initial_rr_bytes = Some(plain.clone());
                self.rr = Some(rr);
                vec![self.auth_request(&supi)]
            }
            MmMessage::AuthenticationResponse(ar) => {
                let av = self.av.as_ref().expect("AV outstanding");
                assert_eq!(ar.res_star, Some(av.xres_star), "RES* mismatch");
                self.sqn += 1;
                self.k_amf = Some(av.k_amf);
                let ctx = NasSecurityContext::new(av.k_amf, 0, self.ea, self.ia)
                    .unwrap()
                    .as_network();
                self.ctx = Some(ctx);
                let smc = SecurityModeCommand {
                    ea: self.ea,
                    ia: self.ia,
                    ngksi: NgKsi {
                        mapped: false,
                        ksi: 0,
                    },
                    replayed_ue_security_capability: UeSecurityCapability::default(),
                    imeisv_requested: true,
                    eps_algorithms: None,
                    hdp: false,
                    rinmr: true,
                    eap_message: None,
                    abba: Some(ABBA.to_vec()),
                };
                vec![self.tx(smc.encode(), SecurityHeaderType::IntegrityNewContext)]
            }
            MmMessage::AuthenticationFailure(f) => {
                assert_eq!(f.cause, mm::cause::SYNCH_FAILURE);
                let av = self.av.as_ref().unwrap();
                let sqn_ms = verify_auts(&self.keys, &av.rand, &f.auts.expect("AUTS"))
                    .expect("MAC-S verifies");
                self.sqn = sqn_ms + 1;
                let supi = IMSI.to_string();
                vec![self.auth_request(&supi)]
            }
            MmMessage::SecurityModeComplete(c) => {
                assert_eq!(c.imeisv.as_deref(), Some("3534900698735912"));
                assert_eq!(
                    c.nas_message_container, self.initial_rr_bytes,
                    "replayed RR must match"
                );
                let ra = RegistrationAccept {
                    result: 1,
                    sms_allowed: false,
                    nssaa_pending: false,
                    guti: Some(guti()),
                    tai_list: vec![Tai {
                        plmn: plmn(),
                        tac: 1,
                    }],
                    allowed_nssai: vec![Snssai { sst: 1, sd: None }],
                    t3512: Some(GprsTimer3 { unit: 5, value: 1 }), // 1 minute
                    ..Default::default()
                };
                vec![self.tx(ra.encode(), SecurityHeaderType::IntegrityCiphered)]
            }
            MmMessage::RegistrationComplete => vec![],
            MmMessage::UlNasTransport(t) => {
                let sm = decode_sm(&t.payload_container).expect("5GSM payload");
                match sm {
                    SmMessage::EstablishmentRequest(r) => {
                        assert_eq!(t.dnn.as_deref(), Some("internet"));
                        assert_eq!(t.request_type, Some(mm::request_type::INITIAL_REQUEST));
                        assert_eq!(t.pdu_session_id, Some(r.psi));
                        assert_eq!(r.pdu_session_type, Some(PduSessionType::Ipv4));
                        let acc = PduSessionEstablishmentAccept {
                            psi: r.psi,
                            pti: r.pti,
                            pdu_session_type: PduSessionType::Ipv4,
                            ssc_mode: 1,
                            qos_rules: vec![QosRule::default_match_all(7)],
                            session_ambr: SessionAmbr {
                                dl_unit: 6,
                                dl: 100,
                                ul_unit: 6,
                                ul: 100,
                            },
                            cause: None,
                            pdu_address: Some(PduAddress {
                                ipv4: Some([10, 45, 0, 2]),
                                ..Default::default()
                            }),
                            rq_timer: None,
                            snssai: Some(Snssai { sst: 1, sd: None }),
                            always_on: None,
                            qos_flow_descriptions: vec![],
                            epco: None,
                            dnn: Some("internet".into()),
                        };
                        let dl = DlNasTransport {
                            payload_container_type: 1,
                            payload_container: acc.encode(),
                            pdu_session_id: Some(r.psi),
                            additional_information: None,
                            cause: None,
                            back_off_timer: None,
                        };
                        vec![self.tx(dl.encode(), SecurityHeaderType::IntegrityCiphered)]
                    }
                    SmMessage::ReleaseRequest(r) => {
                        let cmd = PduSessionReleaseCommand {
                            psi: r.psi,
                            pti: r.pti,
                            cause: 36,
                            back_off_timer: None,
                            access_type: None,
                            epco: None,
                        };
                        let dl = DlNasTransport {
                            payload_container_type: 1,
                            payload_container: cmd.encode(),
                            pdu_session_id: Some(r.psi),
                            additional_information: None,
                            cause: None,
                            back_off_timer: None,
                        };
                        vec![self.tx(dl.encode(), SecurityHeaderType::IntegrityCiphered)]
                    }
                    SmMessage::ReleaseComplete(_) => vec![],
                    other => panic!("unexpected 5GSM {other:?}"),
                }
            }
            MmMessage::DeregistrationRequestUeOriginating(d) => {
                assert!(matches!(d.mobile_identity, MobileIdentity::Guti(g) if g == guti()));
                if d.dereg_type.switch_off {
                    vec![]
                } else {
                    vec![self.tx(
                        mm::deregistration_accept(false),
                        SecurityHeaderType::IntegrityCiphered,
                    )]
                }
            }
            MmMessage::DeregistrationAcceptUeTerminated => vec![],
            MmMessage::ConfigurationUpdateComplete => vec![],
            MmMessage::IdentityResponse(r) => {
                assert!(matches!(r.mobile_identity, MobileIdentity::Suci { .. }));
                vec![]
            }
            other => panic!("unexpected UL {other:?}"),
        }
    }
}

/// Run UL PDUs through the core and the core's replies through the UE until
/// both sides are quiet.
fn pump(ue: &mut NasUe, core: &mut FakeCore, mut ul: Vec<Vec<u8>>) {
    let mut guard = 0;
    while !ul.is_empty() {
        guard += 1;
        assert!(guard < 50, "message loop");
        let mut next = Vec::new();
        for pdu in ul {
            for dl in core.on_ul(&pdu) {
                next.extend(ue.on_dl_nas(&dl).expect("UE accepts DL"));
            }
        }
        ul = next;
    }
}

fn ue(cfg: NasConfig) -> NasUe {
    NasUe::new(UeIdentity::from_imsi(IMSI, K, OPC), cfg)
}

fn full_flow(ea: u8, ia: u8) -> (NasUe, FakeCore) {
    let mut u = ue(NasConfig {
        imeisv: Some("3534900698735912".into()),
        ..Default::default()
    });
    let mut core = FakeCore::new(ea, ia);
    u.tick(1_000);
    let rr = u.start_registration();
    assert_eq!(
        rr,
        ferrite_nas::msgs::registration_request(IMSI),
        "initial RR is the proven byte layout"
    );
    pump(&mut u, &mut core, vec![rr]);

    assert!(u.is_registered(), "{:?}", u.state());
    assert_eq!(u.guti(), Some(guti()));
    let ev = u.events();
    assert_eq!(
        ev[0],
        NasEvent::SecurityActivated {
            ul_nas_count_at_activation: 0
        }
    );
    assert_eq!(ev[1], NasEvent::RegistrationComplete { guti: Some(guti()) });
    assert_eq!(
        ev[2],
        NasEvent::PduSessionUp {
            psi: 5,
            ipv4: Some([10, 45, 0, 2]),
            ipv6: None,
            dnn: "internet".into(),
            default_qfi: 7
        }
    );
    assert_eq!(ev.len(), 3);
    assert_eq!(u.k_gnb(0), Some(k_gnb(&core.k_amf.unwrap(), 0)));
    assert_eq!(u.ul_nas_count_at_activation(), Some(0));
    // SMComplete = count 0, RegistrationComplete = 1, UL NAS Transport = 2.
    assert_eq!(u.security_context().unwrap().next_ul_count(), 3);
    assert_eq!(u.sessions()[0].state, SmState::Active);
    assert_eq!(u.sqn_ms(), Some(0x20));
    (u, core)
}

#[test]
fn registration_and_pdu_session_nea0_nia2() {
    let (u, core) = full_flow(0, 2);
    assert!(core
        .log
        .iter()
        .any(|l| l.starts_with("SecurityModeComplete")));
    assert_eq!(
        u.security_context().unwrap().ea,
        ferrite_nas::security::CipherAlg::Nea0
    );
}

#[test]
fn registration_and_pdu_session_nea2_nia2() {
    let (u, _) = full_flow(2, 2);
    assert_eq!(
        u.security_context().unwrap().ea,
        ferrite_nas::security::CipherAlg::Nea2
    );
}

#[test]
fn configuration_update_identity_and_network_deregistration() {
    let (mut u, mut core) = full_flow(2, 2);
    // Configuration update with ack requested.
    let cuc = ConfigurationUpdateCommand {
        ack_requested: true,
        tai_list: vec![Tai {
            plmn: plmn(),
            tac: 9,
        }],
        ..Default::default()
    };
    let dl = core.tx(cuc.encode(), SecurityHeaderType::IntegrityCiphered);
    let ul = u.on_dl_nas(&dl).unwrap();
    assert_eq!(ul.len(), 1);
    assert_eq!(core.rx(&ul[0]), mm::configuration_update_complete());
    assert_eq!(u.tai_list()[0].tac, 9);
    assert!(matches!(
        u.events()[..],
        [NasEvent::ConfigurationUpdated { .. }]
    ));
    // Identity request (protected) → SUCI.
    let dl = core.tx(
        IdentityRequest {
            identity_type: mm::identity_type::SUCI,
        }
        .encode(),
        SecurityHeaderType::IntegrityCiphered,
    );
    let ul = u.on_dl_nas(&dl).unwrap();
    assert!(core.on_ul(&ul[0]).is_empty());
    // 5GMM STATUS from the network is tolerated.
    let dl = core.tx(
        mm::MmStatus { cause: 98 }.encode(),
        SecurityHeaderType::IntegrityCiphered,
    );
    assert!(u.on_dl_nas(&dl).unwrap().is_empty());
    // Network-initiated deregistration.
    let d = DeregistrationRequestUeTerminated {
        dereg_type: DeregistrationType {
            access_type: 1,
            reregistration_required: false,
            switch_off: false,
        },
        cause: None,
        t3346: None,
    };
    let dl = core.tx(d.encode(), SecurityHeaderType::IntegrityCiphered);
    let ul = u.on_dl_nas(&dl).unwrap();
    assert_eq!(core.rx(&ul[0]), mm::deregistration_accept(true));
    assert!(u.is_deregistered(), "{:?}", u.state());
    assert_eq!(
        u.events(),
        vec![NasEvent::PduSessionDown { psi: 5 }, NasEvent::Deregistered]
    );
    // The context survives (no cause): re-registration goes out with the GUTI, SHT 1.
    let rr = u.start_registration();
    assert_eq!(rr[1], 1);
    let plain = core.rx(&rr);
    let rr = RegistrationRequest::decode(&plain).unwrap();
    assert_eq!(rr.mobile_identity, MobileIdentity::Guti(guti()));
    assert_eq!(rr.ngksi.ksi, 0);
}

#[test]
fn ue_deregistration_and_session_release() {
    let (mut u, mut core) = full_flow(0, 2);
    let rel = u.release_pdu_session(5).expect("release");
    pump(&mut u, &mut core, vec![rel]);
    assert_eq!(u.events(), vec![NasEvent::PduSessionDown { psi: 5 }]);
    assert_eq!(u.sessions()[0].state, SmState::Inactive);
    // Re-establish on demand.
    let req = u.request_pdu_session(5).expect("re-request");
    pump(&mut u, &mut core, vec![req]);
    assert!(matches!(
        u.events()[0],
        NasEvent::PduSessionUp { psi: 5, .. }
    ));
    // Deregister (from 5GMM-IDLE the request first needs a connection).
    assert!(u.deregister().is_none());
    assert_eq!(
        u.events(),
        vec![NasEvent::ConnectionNeeded {
            cause: ConnectionCause::MoSignalling
        }]
    );
    let d = u
        .take_pending_initial_message()
        .expect("queued DEREGISTRATION REQUEST");
    assert_eq!(u.state(), MmState::DeregistrationInitiated);
    u.on_connection_established();
    pump(&mut u, &mut core, vec![d]);
    assert!(u.is_deregistered(), "{:?}", u.state());
    assert_eq!(
        u.events(),
        vec![NasEvent::PduSessionDown { psi: 5 }, NasEvent::Deregistered]
    );
}

#[test]
fn sqn_resynchronisation() {
    // The USIM has already seen SQN 0x100; the core starts at 0x20 → AUTS.
    let mut u = ue(NasConfig {
        initial_sqn_ms: Some(0x100),
        imeisv: Some("3534900698735912".into()),
        ..Default::default()
    });
    let mut core = FakeCore::new(0, 2);
    let rr = u.start_registration();
    pump(&mut u, &mut core, vec![rr]);
    assert!(u.is_registered(), "{:?}", u.state());
    assert_eq!(
        core.sqn, 0x102,
        "core resynchronised to SQN_MS + 1 then incremented"
    );
    assert_eq!(u.sqn_ms(), Some(0x101));
    assert!(core
        .log
        .iter()
        .any(|l| l.starts_with("AuthenticationFailure")));
}

#[test]
fn replay_and_unprotected_messages_are_rejected() {
    let (mut u, mut core) = full_flow(2, 2);
    let dl = core.tx(
        mm::MmStatus { cause: 1 }.encode(),
        SecurityHeaderType::IntegrityCiphered,
    );
    assert!(u.on_dl_nas(&dl).is_ok());
    assert_eq!(u.on_dl_nas(&dl), Err(NasError::Replay));
    let mut bad = core.tx(
        mm::MmStatus { cause: 1 }.encode(),
        SecurityHeaderType::IntegrityCiphered,
    );
    bad[4] ^= 0xff;
    assert_eq!(u.on_dl_nas(&bad), Err(NasError::MacFailure));
    // A plain REGISTRATION ACCEPT after security activation is discarded.
    let ra = RegistrationAccept {
        result: 1,
        ..Default::default()
    }
    .encode();
    assert_eq!(u.on_dl_nas(&ra), Err(NasError::Unprotected(0x42)));
    assert!(u.is_registered(), "{:?}", u.state());
}

#[test]
fn registration_reject_and_timers() {
    let mut u = ue(NasConfig::default());
    let _ = u.start_registration();
    let rj = RegistrationReject {
        cause: 11,
        t3346: None,
        t3502: None,
        eap_message: None,
        rejected_nssai: None,
    };
    assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
    assert!(u.is_deregistered(), "{:?}", u.state());
    assert_eq!(
        u.events(),
        vec![NasEvent::RegistrationRejected(11), NasEvent::Deregistered]
    );

    // Periodic registration update after T3512 (1 minute from the accept):
    // the UE is in 5GMM-IDLE, so it asks for a connection and hands the
    // REGISTRATION REQUEST over as the initial NAS message.
    let (mut u, mut core) = full_flow(0, 2);
    assert_eq!(u.cm_state(), CmState::Idle);
    assert!(u.tick(1_000 + 60_000).is_empty());
    assert_eq!(
        u.events(),
        vec![NasEvent::ConnectionNeeded {
            cause: ConnectionCause::MoSignalling
        }]
    );
    let rr_pdu = u
        .take_pending_initial_message()
        .expect("pending REGISTRATION REQUEST");
    assert!(u.take_pending_initial_message().is_none());
    let plain = core.rx(&rr_pdu);
    let rr = RegistrationRequest::decode(&plain).unwrap();
    assert_eq!(rr.reg_type, mm::RegistrationType::PeriodicUpdating);
    assert_eq!(rr.pdu_session_status, Some(1 << 5));
    assert_eq!(u.state(), MmState::RegistrationInitiated);
    u.on_connection_established();
    let ra = RegistrationAccept {
        result: 1,
        ..Default::default()
    };
    let dl = core.tx(ra.encode(), SecurityHeaderType::IntegrityCiphered);
    let ul = u.on_dl_nas(&dl).unwrap();
    assert_eq!(
        ul.len(),
        1,
        "only REGISTRATION COMPLETE after a periodic update"
    );
    assert_eq!(u.state(), MmState::Registered(RegisteredSub::NormalService));
    assert_eq!(
        u.events(),
        vec![NasEvent::RegistrationUpdated { guti: Some(guti()) }]
    );
    // T3512 does not run while connected; it restarts on release.
    assert!(u.tick(1_000 + 60_000 + 70_000).is_empty());
    u.on_connection_released();
    assert!(u.tick(1_000 + 60_000 + 70_000 + 59_000).is_empty());
    assert!(u.tick(1_000 + 60_000 + 70_000 + 60_000).is_empty());
    assert_eq!(
        u.events(),
        vec![NasEvent::ConnectionNeeded {
            cause: ConnectionCause::MoSignalling
        }]
    );
}

#[test]
fn pdu_session_reject_and_t3580_retry() {
    let mut u = ue(NasConfig {
        auto_pdu_session: None,
        imeisv: Some("3534900698735912".into()),
        ..Default::default()
    });
    let mut core = FakeCore::new(0, 2);
    let rr = u.start_registration();
    pump(&mut u, &mut core, vec![rr]);
    assert!(u.is_registered(), "{:?}", u.state());
    let _ = u.events();
    let req = u.request_pdu_session(3).expect("request");
    // No answer: T3580 retransmits with the same PTI.
    let plain = core.rx(&req);
    let out = u.tick(1_000 + 16_000);
    assert_eq!(out.len(), 1);
    let plain2 = core.rx(&out[0]);
    assert_eq!(plain[..], plain2[..], "retransmission is identical");
    // Reject it.
    let rej = PduSessionEstablishmentReject {
        psi: 3,
        pti: 1,
        cause: 27,
        back_off_timer: None,
        allowed_ssc_mode: None,
        epco: None,
    };
    let dl = DlNasTransport {
        payload_container_type: 1,
        payload_container: rej.encode(),
        pdu_session_id: Some(3),
        additional_information: None,
        cause: None,
        back_off_timer: None,
    };
    let dl = core.tx(dl.encode(), SecurityHeaderType::IntegrityCiphered);
    assert!(u.on_dl_nas(&dl).unwrap().is_empty());
    assert_eq!(
        u.events(),
        vec![NasEvent::PduSessionRejected { psi: 3, cause: 27 }]
    );
    assert_eq!(u.sessions()[0].state, SmState::Inactive);
    // DL NAS TRANSPORT with a 5GMM cause (payload not forwarded).
    let req = u.request_pdu_session(3).expect("request again");
    let _ = core.rx(&req);
    let dl = DlNasTransport {
        payload_container_type: 1,
        payload_container: vec![],
        pdu_session_id: Some(3),
        additional_information: None,
        cause: Some(91),
        back_off_timer: Some(GprsTimer3 { unit: 3, value: 1 }),
    };
    let dl = core.tx(dl.encode(), SecurityHeaderType::IntegrityCiphered);
    assert!(u.on_dl_nas(&dl).unwrap().is_empty());
    assert_eq!(
        u.events(),
        vec![NasEvent::PduSessionRejected { psi: 3, cause: 91 }]
    );
}

/// A registered, connected UE with its fake core.
fn connected_flow() -> (NasUe, FakeCore) {
    let (mut u, core) = full_flow(0, 2);
    u.on_connection_established();
    (u, core)
}

#[test]
fn registration_reject_congestion_backs_off_with_t3346() {
    let mut u = ue(NasConfig::default());
    u.on_connection_established();
    let _ = u.start_registration();
    let rj = RegistrationReject {
        cause: 22,
        t3346: Some(mm::GprsTimer2 { unit: 0, value: 1 }),
        t3502: None,
        eap_message: None,
        rejected_nssai: None,
    }; // 1 × 2 s
    assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
    assert_eq!(
        u.state(),
        MmState::Deregistered(DeregisteredSub::AttemptingRegistration)
    );
    assert!(u.barred());
    // Nothing happens before T3346 runs out; then the registration is retried.
    assert!(u.tick(1_500).is_empty());
    assert!(u.barred());
    let out = u.tick(2_100);
    assert!(!u.barred());
    assert_eq!(out.len(), 1, "REGISTRATION REQUEST after T3346");
    assert_eq!(u.state(), MmState::RegistrationInitiated);
    let _ = u.events();
}

#[test]
fn registration_reject_abnormal_cause_uses_the_attempt_counter() {
    let mut u = ue(NasConfig::default());
    u.on_connection_established();
    let _ = u.start_registration();
    let rj = RegistrationReject {
        cause: 111,
        t3346: None,
        t3502: None,
        eap_message: None,
        rejected_nssai: None,
    };
    assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
    assert_eq!(
        u.state(),
        MmState::Deregistered(DeregisteredSub::AttemptingRegistration)
    );
    assert!(u.tick(9_000).is_empty());
    assert_eq!(u.tick(10_000).len(), 1, "T3511 → retry");
    // Four more failures → T3502 instead of T3511.
    let mut t = 10_000;
    for _ in 0..4 {
        assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
        t += 10_000;
        u.tick(t);
    }
    assert!(
        u.tick(t + 60_000).is_empty(),
        "T3502 (12 min) running, no retry after 1 min"
    );
    assert_eq!(u.tick(t + 12 * 60_000).len(), 1, "retry after T3502");
}

#[test]
fn service_reject_implicitly_deregistered_registers_again() {
    let (mut u, mut core) = connected_flow();
    u.on_connection_released();
    let sr = u.service_request(1).expect("SERVICE REQUEST");
    let _ = core.rx(&sr);
    u.on_connection_established();
    let rj = mm::ServiceReject {
        cause: 10,
        pdu_session_status: None,
        t3346: None,
    };
    // SERVICE REJECT may be sent without integrity protection.
    let out = u.on_dl_nas(&rj.encode()).unwrap();
    assert_eq!(
        out.len(),
        1,
        "a fresh REGISTRATION REQUEST on the same connection"
    );
    let rr = RegistrationRequest::decode(&out[0]).unwrap();
    assert_eq!(rr.reg_type, mm::RegistrationType::Initial);
    assert!(
        matches!(rr.mobile_identity, MobileIdentity::Suci { .. }),
        "GUTI and context were deleted"
    );
    let ev = u.events();
    assert!(
        ev.contains(&NasEvent::ServiceRejected(10)) && ev.contains(&NasEvent::Deregistered),
        "{ev:?}"
    );
    assert_eq!(u.state(), MmState::RegistrationInitiated);
}

#[test]
fn service_reject_restricted_area_and_congestion() {
    let (mut u, _core) = connected_flow();
    u.on_connection_released();
    let _ = u.service_request(1).unwrap();
    u.on_connection_established();
    let rj = mm::ServiceReject {
        cause: 28,
        pdu_session_status: None,
        t3346: None,
    };
    assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
    assert_eq!(
        u.state(),
        MmState::Registered(RegisteredSub::NonAllowedService)
    );
    let _ = u.events();
    u.on_connection_released();
    let _ = u.service_request(1).unwrap();
    let rj = mm::ServiceReject {
        cause: 22,
        pdu_session_status: None,
        t3346: Some(mm::GprsTimer2 { unit: 0, value: 5 }),
    };
    assert!(u.on_dl_nas(&rj.encode()).unwrap().is_empty());
    assert!(u.barred());
    assert!(u.service_request(1).is_none(), "barred by T3346");
    assert!(u.is_registered());
}

#[test]
fn network_deregistration_with_reregistration_required() {
    let (mut u, mut core) = connected_flow();
    let d = DeregistrationRequestUeTerminated {
        dereg_type: DeregistrationType {
            access_type: 1,
            reregistration_required: true,
            switch_off: false,
        },
        cause: None,
        t3346: None,
    };
    let dl = core.tx(d.encode(), SecurityHeaderType::IntegrityCiphered);
    let out = u.on_dl_nas(&dl).unwrap();
    assert_eq!(
        out.len(),
        2,
        "DEREGISTRATION ACCEPT then REGISTRATION REQUEST"
    );
    let plain = core.rx(&out[1]);
    let rr = RegistrationRequest::decode(&plain).unwrap();
    assert_eq!(rr.reg_type, mm::RegistrationType::Initial);
    assert!(
        matches!(rr.mobile_identity, MobileIdentity::Guti(_)),
        "context kept: GUTI used"
    );
    assert_eq!(u.state(), MmState::RegistrationInitiated);
    // Without re-registration and with cause #7 the USIM is invalid: nothing follows.
    let (mut u, mut core) = connected_flow();
    let d = DeregistrationRequestUeTerminated {
        dereg_type: DeregistrationType {
            access_type: 1,
            reregistration_required: false,
            switch_off: false,
        },
        cause: Some(7),
        t3346: None,
    };
    let dl = core.tx(d.encode(), SecurityHeaderType::IntegrityCiphered);
    assert_eq!(u.on_dl_nas(&dl).unwrap().len(), 1);
    assert_eq!(u.state(), MmState::Deregistered(DeregisteredSub::NoSupi));
    assert!(u.guti().is_none() && u.security_context().is_none());
    u.on_connection_released();
    assert!(u.tick(10_000_000).is_empty());
    assert!(!u
        .events()
        .iter()
        .any(|e| matches!(e, NasEvent::ConnectionNeeded { .. })));
}

#[test]
fn configuration_update_registration_requested_after_release() {
    let (mut u, mut core) = connected_flow();
    let c = ConfigurationUpdateCommand {
        ack_requested: true,
        registration_requested: true,
        ..Default::default()
    };
    let dl = core.tx(c.encode(), SecurityHeaderType::IntegrityCiphered);
    assert_eq!(
        u.on_dl_nas(&dl).unwrap().len(),
        1,
        "CONFIGURATION UPDATE COMPLETE"
    );
    assert!(u.is_registered());
    let _ = u.events();
    // The registration starts once the network releases the connection.
    u.on_connection_released();
    assert_eq!(
        u.events(),
        vec![NasEvent::ConnectionNeeded {
            cause: ConnectionCause::MoSignalling
        }]
    );
    let rr =
        RegistrationRequest::decode(&core.rx(&u.take_pending_initial_message().unwrap())).unwrap();
    assert_eq!(rr.reg_type, mm::RegistrationType::MobilityUpdating);
}

#[test]
fn new_tracking_area_triggers_a_mobility_update() {
    let (mut u, mut core) = connected_flow();
    let inside = u.tai_list()[0];
    u.set_current_tai(inside);
    assert!(u.events().is_empty());
    let outside = Tai {
        plmn: inside.plmn,
        tac: inside.tac.wrapping_add(1),
    };
    u.set_current_tai(outside);
    // Connected: the request goes out through the NAS directly? No — set_current_tai
    // queues it like any procedure started by the UE; connected → nothing pending.
    let ev = u.events();
    assert!(ev.is_empty(), "{ev:?}");
    assert_eq!(u.state(), MmState::RegistrationInitiated);
    // Idle UE: a connection is requested.
    let (mut u, _core) = full_flow(0, 2);
    let inside = u.tai_list()[0];
    u.set_current_tai(Tai {
        plmn: inside.plmn,
        tac: inside.tac.wrapping_add(1),
    });
    assert_eq!(
        u.events(),
        vec![NasEvent::ConnectionNeeded {
            cause: ConnectionCause::MoSignalling
        }]
    );
    let rr =
        RegistrationRequest::decode(&core.rx(&u.take_pending_initial_message().unwrap())).unwrap();
    assert_eq!(rr.reg_type, mm::RegistrationType::MobilityUpdating);
}

#[test]
fn notification_is_answered_with_the_session_status() {
    let (mut u, mut core) = connected_flow();
    let dl = core.tx(
        mm::Notification { access_type: 1 }.encode(),
        SecurityHeaderType::IntegrityCiphered,
    );
    let out = u.on_dl_nas(&dl).unwrap();
    assert_eq!(out.len(), 1);
    let plain = core.rx(&out[0]);
    assert_eq!(plain[2], mm::msg_type::NOTIFICATION_RESPONSE);
    assert_eq!(&plain[3..], &[0x50, 2, 0x20, 0x00], "PDU session 5 active");
}

#[test]
fn pdu_session_modification_command_is_completed() {
    let (mut u, mut core) = connected_flow();
    // PDU SESSION MODIFICATION COMMAND psi 5 pti 0 with a session AMBR IE.
    let sm = vec![
        0x2e, 5, 0, 0xcb, 0x2a, 6, 0x06, 0x00, 0x01, 0x06, 0x00, 0x01,
    ];
    let t = DlNasTransport {
        payload_container_type: 1,
        payload_container: sm,
        pdu_session_id: Some(5),
        cause: None,
        additional_information: None,
        back_off_timer: None,
    };
    let dl = core.tx(t.encode(), SecurityHeaderType::IntegrityCiphered);
    let out = u.on_dl_nas(&dl).unwrap();
    assert_eq!(out.len(), 1);
    let plain = core.rx(&out[0]);
    let ul = mm::UlNasTransport::decode(&plain).unwrap();
    assert_eq!(
        ul.payload_container,
        vec![0x2e, 5, 0, 0xcc],
        "PDU SESSION MODIFICATION COMPLETE"
    );
    assert_eq!(ul.pdu_session_id, Some(5));
}

// ---------------------------------------------------------------------------
// Independent decoder: every uplink message is read back with oxirush-nas.
// ---------------------------------------------------------------------------

mod oracle {
    use super::*;
    use oxirush_nas::nas_5gs::{GmmMessage, Message, RegistrationTypeValue, ServiceTypeValue};
    use oxirush_nas::Validate;

    fn decode(plain: &[u8]) -> Message {
        let m = Message::decode(plain)
            .unwrap_or_else(|e| panic!("oxirush-nas rejects {plain:02x?}: {e}"));
        let findings = m.validate();
        assert!(findings.is_empty(), "{m}: {findings:?}");
        m
    }

    #[test]
    fn initial_registration_request() {
        let mut u = ue(NasConfig::default());
        let rr = u.start_registration();
        let m = decode(&rr);
        let Message::Gmm(_, GmmMessage::RegistrationRequest(r)) = &m else {
            panic!("{m}")
        };
        assert_eq!(
            r.fgs_registration_type.registration_type(),
            Some(RegistrationTypeValue::InitialRegistration)
        );
        assert!(r.fgs_mobile_identity.as_suci().is_some(), "{m}");
        assert!(m.to_string().contains("EA0 EA2 / IA0 IA2"), "{m}");
    }

    #[test]
    fn protected_uplink_messages() {
        let (mut u, mut core) = connected_flow();
        // SERVICE REQUEST (mo-Data) with the 5G-S-TMSI.
        u.on_connection_released();
        let sr = core.rx(&u.service_request(1).unwrap());
        let m = decode(&sr);
        let Message::Gmm(_, GmmMessage::ServiceRequest(r)) = &m else {
            panic!("{m}")
        };
        assert_eq!(r.service_type.service_type(), Some(ServiceTypeValue::Data));
        assert_eq!(r.fg_s_tmsi.as_s_tmsi().map(|t| t.tmsi()), Some(guti().tmsi));
        u.on_connection_established();
        let _ = u.on_dl_nas(
            &core.tx(
                mm::ServiceAccept {
                    pdu_session_status: None,
                    pdu_session_reactivation_result: None,
                    t3448: None,
                }
                .encode(),
                SecurityHeaderType::IntegrityCiphered,
            ),
        );
        // Periodic REGISTRATION REQUEST with the GUTI.
        u.on_connection_released();
        u.tick(1_000 + 60_000);
        let rr = core.rx(&u.take_pending_initial_message().unwrap());
        let m = decode(&rr);
        let Message::Gmm(_, GmmMessage::RegistrationRequest(r)) = &m else {
            panic!("{m}")
        };
        assert_eq!(
            r.fgs_registration_type.registration_type(),
            Some(RegistrationTypeValue::PeriodicRegistrationUpdating)
        );
        assert_eq!(
            r.fgs_mobile_identity.as_guti().map(|g| g.tmsi()),
            Some(guti().tmsi)
        );
        // DEREGISTRATION REQUEST (switch off).
        let (mut u, mut core) = connected_flow();
        let d = core.rx(&u.deregister_with(true).unwrap());
        let m = decode(&d);
        let Message::Gmm(_, GmmMessage::DeregistrationRequestUeOriginating(r)) = &m else {
            panic!("{m}")
        };
        assert!(r.de_registration_type.switch_off());
        assert!(r.fgs_mobile_identity.as_guti().is_some());
        // NOTIFICATION RESPONSE and PDU SESSION MODIFICATION COMPLETE in UL NAS TRANSPORT.
        let (mut u, mut core) = connected_flow();
        let out = u
            .on_dl_nas(&core.tx(
                mm::Notification { access_type: 1 }.encode(),
                SecurityHeaderType::IntegrityCiphered,
            ))
            .unwrap();
        let m = decode(&core.rx(&out[0]));
        assert!(
            matches!(m, Message::Gmm(_, GmmMessage::NotificationResponse(_))),
            "{m}"
        );
        let sm = vec![0x2e, 5, 0, 0xcb];
        let t = DlNasTransport {
            payload_container_type: 1,
            payload_container: sm,
            pdu_session_id: Some(5),
            cause: None,
            additional_information: None,
            back_off_timer: None,
        };
        let out = u
            .on_dl_nas(&core.tx(t.encode(), SecurityHeaderType::IntegrityCiphered))
            .unwrap();
        let m = decode(&core.rx(&out[0]));
        let Message::Gmm(_, GmmMessage::UlNasTransport(ul)) = &m else {
            panic!("{m}")
        };
        let inner = ul
            .payload_container
            .decode_as_n1_sm_message()
            .expect("5GSM payload");
        assert!(
            matches!(
                inner,
                Message::Gsm(
                    _,
                    oxirush_nas::nas_5gs::GsmMessage::PduSessionModificationComplete(_)
                )
            ),
            "{inner}"
        );
    }
}
