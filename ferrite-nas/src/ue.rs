//! The UE-side 5GMM / 5GSM state machine (TS 24.501 §5 / §6).
//!
//! [`NasUe`] is driven by three inputs: [`NasUe::start_registration`],
//! downlink NAS PDUs via [`NasUe::on_dl_nas`], and the wall clock via
//! [`NasUe::tick`]. It returns uplink NAS PDUs (already security protected
//! where required) and queues [`NasEvent`]s for the application. It never
//! touches RRC: the PDUs are opaque octet strings for the RRC layer to carry
//! in `RRCSetupComplete` / `ULInformationTransfer`.
//!
//! Registration against a real core (TS 24.501 §5.5.1.2):
//!
//! ```text
//! UE                                        AMF
//!  | REGISTRATION REQUEST (SUCI, ngKSI=7)     |   plain
//!  |----------------------------------------->|
//!  |           AUTHENTICATION REQUEST (RAND, AUTN, ABBA)   plain
//!  |<-----------------------------------------|
//!  | AUTHENTICATION RESPONSE (RES*)           |   plain
//!  |----------------------------------------->|
//!  |           SECURITY MODE COMMAND          |   SHT 3 (new context)
//!  |<-----------------------------------------|
//!  | SECURITY MODE COMPLETE (replayed RR)     |   SHT 4, UL COUNT 0
//!  |----------------------------------------->|
//!  |           REGISTRATION ACCEPT (GUTI ...) |   SHT 2
//!  |<-----------------------------------------|
//!  | REGISTRATION COMPLETE                    |   SHT 2
//!  | UL NAS TRANSPORT (PDU SESSION EST. REQ)  |   SHT 2
//!  |----------------------------------------->|
//!  |           DL NAS TRANSPORT (PDU SESSION EST. ACCEPT: IP)   SHT 2
//!  |<-----------------------------------------|
//! ```

use crate::ie::NasError;
use crate::milenage::k_gnb;
use crate::mm::{
    cause, configuration_update_complete, decode_mm, deregistration_accept, identity_type,
    mm_message_type, msg_type, payload_container_type, registration_complete, request_type,
    security_mode_reject, split_security_header, AuthenticationFailure, AuthenticationRequest,
    AuthenticationResponse, ConfigurationUpdateCommand, DeregistrationRequestUeOriginating,
    DeregistrationRequestUeTerminated, DeregistrationType, DlNasTransport, Guti, IdentityRequest,
    IdentityResponse, MmMessage, MmStatus, MobileIdentity, NgKsi, Plmn, RegistrationAccept,
    RegistrationReject, RegistrationRequest, RegistrationType, SecurityHeader, SecurityHeaderType,
    SecurityModeCommand, SecurityModeComplete, ServiceRequest, Snssai, Tai, UeSecurityCapability,
    UlNasTransport,
};
use crate::security::{run_5g_aka, AkaOutcome, NasSecurityContext, UsimKeys};
use crate::sm::{
    self, decode_sm, PduSessionEstablishmentRequest, PduSessionReleaseComplete,
    PduSessionReleaseRequest, PduSessionType, SmMessage, SmStatus,
};

/// Subscriber identity and credentials.
#[derive(Debug, Clone)]
pub struct UeIdentity {
    /// 15-digit IMSI.
    pub imsi: String,
    /// Subscriber key K.
    pub k: [u8; 16],
    /// OPc (operator variant key, already combined with K).
    pub opc: [u8; 16],
    pub mcc: u16,
    pub mnc: u16,
    /// Number of MNC digits in the IMSI (2 or 3).
    pub mnc_digits: u8,
    /// SUCI routing indicator (TS 23.003 §2.2B), 0 = "0000".
    pub routing_indicator: u16,
}

impl UeIdentity {
    /// Build from an IMSI assuming a 2-digit MNC (use [`Self::with_mnc_digits`]
    /// for a 3-digit MNC). Non-digit characters in `imsi` are ignored.
    pub fn from_imsi(imsi: &str, k: [u8; 16], opc: [u8; 16]) -> Self {
        let digits: String = imsi.chars().filter(char::is_ascii_digit).collect();
        let mut id = UeIdentity {
            imsi: digits,
            k,
            opc,
            mcc: 0,
            mnc: 0,
            mnc_digits: 2,
            routing_indicator: 0,
        };
        id.parse_plmn();
        id
    }

    /// Re-derive MCC/MNC from the IMSI with the given MNC length.
    pub fn with_mnc_digits(mut self, n: u8) -> Self {
        self.mnc_digits = if n == 3 { 3 } else { 2 };
        self.parse_plmn();
        self
    }

    fn parse_plmn(&mut self) {
        let d: Vec<u16> = self.imsi.bytes().map(|b| (b - b'0') as u16).collect();
        let num = |s: &[u16]| s.iter().fold(0u16, |a, &x| a * 10 + x);
        self.mcc = num(d.get(0..3).unwrap_or(&[]));
        self.mnc = num(d.get(3..3 + self.mnc_digits as usize).unwrap_or(&[]));
    }

    /// Home PLMN.
    pub fn plmn(&self) -> Plmn {
        Plmn {
            mcc: self.mcc,
            mnc: self.mnc,
            mnc_digits: self.mnc_digits,
        }
    }

    /// The null-scheme SUCI.
    pub fn suci(&self) -> MobileIdentity {
        MobileIdentity::suci_from_imsi(&self.imsi, self.mnc_digits, self.routing_indicator)
    }

    fn keys(&self) -> UsimKeys {
        UsimKeys {
            k: self.k,
            opc: self.opc,
        }
    }
}

/// NAS configuration.
#[derive(Debug, Clone)]
pub struct NasConfig {
    /// Serving network name; derived from the home PLMN when `None`.
    pub snn: Option<String>,
    /// Data network name for PDU sessions.
    pub dnn: String,
    /// Requested NSSAI; the first entry is the S-NSSAI used for PDU sessions.
    pub requested_nssai: Vec<Snssai>,
    /// Include the Requested NSSAI IE in REGISTRATION REQUEST. Off by
    /// default: the proven minimal message does not carry it.
    pub include_requested_nssai: bool,
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: u8,
    pub security_capability: UeSecurityCapability,
    /// First octet of the 5GMM capability IE.
    pub mm_capability: u8,
    /// Automatically establish this PDU session after registration.
    pub auto_pdu_session: Option<u8>,
    /// UE's usage setting IE (true = data centric); omitted when `None`.
    pub ue_usage_setting: Option<bool>,
    /// IMEISV, sent in SECURITY MODE COMPLETE when requested.
    pub imeisv: Option<String>,
    /// Always replay the initial REGISTRATION REQUEST in the NAS message
    /// container of SECURITY MODE COMPLETE (not only when RINMR is set).
    pub replay_initial_message: bool,
    /// Enforce SQN freshness (TS 33.102 C.2) and trigger resynchronisation.
    pub sqn_check: bool,
    /// Highest SQN already seen by the USIM (persisted state), if any.
    pub initial_sqn_ms: Option<u64>,
    /// Maximum registration / deregistration / PDU session attempts.
    pub max_attempts: u8,
}

impl Default for NasConfig {
    fn default() -> Self {
        NasConfig {
            snn: None,
            dnn: "internet".into(),
            requested_nssai: vec![Snssai { sst: 1, sd: None }],
            include_requested_nssai: false,
            pdu_session_type: PduSessionType::Ipv4,
            ssc_mode: 1,
            security_capability: UeSecurityCapability::default(),
            mm_capability: 0x07,
            auto_pdu_session: Some(5),
            ue_usage_setting: None,
            imeisv: None,
            replay_initial_message: true,
            sqn_check: true,
            initial_sqn_ms: None,
            max_attempts: 5,
        }
    }
}

/// 5GMM state (TS 24.501 §5.1.3.2, UE side, collapsed to what the UE runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmState {
    Deregistered,
    /// REGISTRATION REQUEST sent, waiting for the network (T3510 running).
    RegistrationInitiated,
    /// AUTHENTICATION RESPONSE sent.
    Authenticating,
    /// SECURITY MODE COMPLETE sent, waiting for REGISTRATION ACCEPT.
    SecurityMode,
    Registered,
    /// SERVICE REQUEST sent (T3517 running).
    ServiceRequestInitiated,
    /// DEREGISTRATION REQUEST sent (T3521 running).
    DeregistrationInitiated,
}

/// 5GSM state of one PDU session (TS 24.501 §6.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmState {
    Inactive,
    ActivePending,
    Active,
    InactivePending,
}

/// A PDU session as seen by the UE.
#[derive(Debug, Clone)]
pub struct PduSession {
    pub psi: u8,
    pub pti: u8,
    pub state: SmState,
    pub ipv4: Option<[u8; 4]>,
    /// Link-local IPv6 address built from the interface identifier.
    pub ipv6: Option<[u8; 16]>,
    pub dnn: String,
    pub default_qfi: u8,
    attempts: u8,
    /// T3580 / T3582 expiry.
    timer: Option<u64>,
}

/// Events for the application / RRC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasEvent {
    /// REGISTRATION ACCEPT received and REGISTRATION COMPLETE sent.
    RegistrationComplete { guti: Option<Guti> },
    /// REGISTRATION REJECT with this 5GMM cause.
    RegistrationRejected(u8),
    /// The registration procedure was abandoned after `max_attempts` T3510 expiries.
    RegistrationTimeout,
    /// A PDU session is active.
    PduSessionUp {
        psi: u8,
        ipv4: Option<[u8; 4]>,
        ipv6: Option<[u8; 16]>,
        dnn: String,
        default_qfi: u8,
    },
    /// A PDU session was released (network or UE initiated).
    PduSessionDown { psi: u8 },
    /// PDU session establishment was rejected (5GSM cause, 0 = timeout).
    PduSessionRejected { psi: u8, cause: u8 },
    /// The UE is deregistered (network or UE initiated, or after a reject).
    Deregistered,
    /// SECURITY MODE COMPLETE was sent: K_AMF and the UL NAS COUNT it was
    /// protected with (TS 33.501 A.9 K_gNB input).
    SecurityActivated {
        k_amf: [u8; 32],
        ul_nas_count_at_activation: u32,
    },
    /// AUTHENTICATION REJECT received, or authentication aborted.
    AuthenticationFailed,
    /// SECURITY MODE REJECT sent with this cause.
    SecurityModeRejected { cause: u8 },
    /// CONFIGURATION UPDATE COMMAND processed.
    ConfigurationUpdated,
}

/// TS 24.501 Table 10.2.1 timer values (milliseconds).
pub mod timers {
    pub const T3510_MS: u64 = 15_000;
    pub const T3511_MS: u64 = 10_000;
    pub const T3502_MS: u64 = 12 * 60_000;
    pub const T3517_MS: u64 = 15_000;
    pub const T3519_MS: u64 = 60_000;
    pub const T3520_MS: u64 = 6_000;
    pub const T3521_MS: u64 = 15_000;
    pub const T3580_MS: u64 = 16_000;
    pub const T3582_MS: u64 = 16_000;
    /// Default T3512 when the network does not provide one (54 min).
    pub const T3512_DEFAULT_MS: u64 = 54 * 60_000;
}

/// The NAS UE.
pub struct NasUe {
    id: UeIdentity,
    cfg: NasConfig,
    state: MmState,
    now: u64,
    ctx: Option<NasSecurityContext>,
    /// K_AMF / ngKSI from the last successful 5G-AKA, not yet taken into use.
    pending_keys: Option<([u8; 32], u8)>,
    sqn_ms: Option<u64>,
    guti: Option<Guti>,
    tai_list: Vec<Tai>,
    allowed_nssai: Vec<Snssai>,
    last_tai: Option<Tai>,
    /// The plain initial NAS message, replayed in SECURITY MODE COMPLETE.
    initial_message: Option<Vec<u8>>,
    sessions: Vec<PduSession>,
    next_pti: u8,
    events: Vec<NasEvent>,
    ul_count_at_activation: Option<u32>,
    t3510: Option<u64>,
    t3512: Option<u64>,
    t3512_len: u64,
    t3517: Option<u64>,
    t3520: Option<u64>,
    t3521: Option<u64>,
    reg_attempts: u8,
    dereg_attempts: u8,
    periodic_update: bool,
}

impl NasUe {
    /// Create a deregistered UE.
    pub fn new(id: UeIdentity, cfg: NasConfig) -> Self {
        let sqn_ms = cfg.initial_sqn_ms;
        NasUe {
            id,
            cfg,
            state: MmState::Deregistered,
            now: 0,
            ctx: None,
            pending_keys: None,
            sqn_ms,
            guti: None,
            tai_list: Vec::new(),
            allowed_nssai: Vec::new(),
            last_tai: None,
            initial_message: None,
            sessions: Vec::new(),
            next_pti: 1,
            events: Vec::new(),
            ul_count_at_activation: None,
            t3510: None,
            t3512: None,
            t3512_len: timers::T3512_DEFAULT_MS,
            t3517: None,
            t3520: None,
            t3521: None,
            reg_attempts: 0,
            dereg_attempts: 0,
            periodic_update: false,
        }
    }

    // -- accessors ----------------------------------------------------------

    /// Current 5GMM state.
    pub fn state(&self) -> MmState {
        self.state
    }

    /// The current 5G-GUTI, if any.
    pub fn guti(&self) -> Option<Guti> {
        self.guti
    }

    /// Registration area.
    pub fn tai_list(&self) -> &[Tai] {
        &self.tai_list
    }

    /// Allowed NSSAI from the last REGISTRATION ACCEPT.
    pub fn allowed_nssai(&self) -> &[Snssai] {
        &self.allowed_nssai
    }

    /// The PDU sessions.
    pub fn sessions(&self) -> &[PduSession] {
        &self.sessions
    }

    /// The current NAS security context.
    pub fn security_context(&self) -> Option<&NasSecurityContext> {
        self.ctx.as_ref()
    }

    /// Highest SQN accepted by the USIM (persist this across runs).
    pub fn sqn_ms(&self) -> Option<u64> {
        self.sqn_ms
    }

    /// The UL NAS COUNT SECURITY MODE COMPLETE was sent with.
    pub fn ul_nas_count_at_activation(&self) -> Option<u32> {
        self.ul_count_at_activation
    }

    /// K_gNB (TS 33.501 A.9) for the given uplink NAS COUNT; the initial AS
    /// context uses the count of SECURITY MODE COMPLETE.
    pub fn k_gnb(&self, ul_nas_count: u32) -> Option<[u8; 32]> {
        self.ctx.as_ref().map(|c| k_gnb(&c.k_amf, ul_nas_count))
    }

    /// Serving network name.
    pub fn snn(&self) -> String {
        self.cfg
            .snn
            .clone()
            .unwrap_or_else(|| self.id.plmn().serving_network_name())
    }

    /// Set the current TAI (from SIB1) for the Last visited registered TAI IE.
    pub fn set_current_tai(&mut self, tai: Tai) {
        self.last_tai = Some(tai);
    }

    /// Drain queued events.
    pub fn events(&mut self) -> Vec<NasEvent> {
        std::mem::take(&mut self.events)
    }

    // -- uplink helpers -----------------------------------------------------

    /// Protect a plain message with the current context (SHT 2) or send it
    /// plain when no context exists.
    fn tx(&mut self, plain: Vec<u8>) -> Vec<u8> {
        self.tx_sht(plain, SecurityHeaderType::IntegrityCiphered)
    }

    fn tx_sht(&mut self, plain: Vec<u8>, sht: SecurityHeaderType) -> Vec<u8> {
        match self.ctx.as_mut() {
            Some(c) => c.protect(sht, &plain).0,
            None => plain,
        }
    }

    fn alloc_pti(&mut self) -> u8 {
        let p = self.next_pti;
        self.next_pti = if self.next_pti >= 254 {
            1
        } else {
            self.next_pti + 1
        };
        p
    }

    fn security_capability(&self) -> UeSecurityCapability {
        self.cfg.security_capability
    }

    fn build_registration_request(&self, reg_type: RegistrationType) -> RegistrationRequest {
        let (identity, ngksi) = match (&self.ctx, self.guti) {
            (Some(c), Some(g)) => (
                MobileIdentity::Guti(g),
                NgKsi {
                    mapped: false,
                    ksi: c.ngksi,
                },
            ),
            _ => (self.id.suci(), NgKsi::NO_KEY),
        };
        let mut rr = RegistrationRequest::initial(identity);
        rr.reg_type = reg_type;
        rr.ngksi = ngksi;
        rr.mm_capability = Some(self.cfg.mm_capability);
        rr.ue_security_capability = Some(self.security_capability());
        if self.cfg.include_requested_nssai && !self.cfg.requested_nssai.is_empty() {
            rr.requested_nssai = Some(self.cfg.requested_nssai.clone());
        }
        rr.ue_usage_setting = self.cfg.ue_usage_setting;
        if reg_type != RegistrationType::Initial {
            rr.last_visited_tai = self.last_tai;
            let active: u16 = self
                .sessions
                .iter()
                .filter(|s| s.state == SmState::Active && s.psi < 16)
                .fold(0, |a, s| a | (1 << s.psi));
            if active != 0 {
                rr.pdu_session_status = Some(active);
                rr.uplink_data_status = Some(active);
            }
        }
        rr
    }

    // -- procedures ---------------------------------------------------------

    /// Start (or restart) the registration procedure (TS 24.501 §5.5.1.2.2)
    /// and return the REGISTRATION REQUEST for RRCSetupComplete. With an
    /// existing security context the message carries the 5G-GUTI and is
    /// integrity protected (SHT 1); otherwise the SUCI is sent in plain.
    pub fn start_registration(&mut self) -> Vec<u8> {
        self.reg_attempts = 0;
        self.periodic_update = false;
        self.send_registration_request(RegistrationType::Initial)
    }

    fn send_registration_request(&mut self, reg_type: RegistrationType) -> Vec<u8> {
        let plain = self.build_registration_request(reg_type).encode();
        self.initial_message = Some(plain.clone());
        self.state = MmState::RegistrationInitiated;
        self.t3510 = Some(self.now + timers::T3510_MS);
        self.t3512 = None;
        log::info!(
            "NAS: REGISTRATION REQUEST ({reg_type:?}, attempt {})",
            self.reg_attempts + 1
        );
        self.tx_sht(plain, SecurityHeaderType::Integrity)
    }

    /// Request a PDU session (TS 24.501 §6.4.1.2): returns the UL NAS
    /// TRANSPORT carrying a PDU SESSION ESTABLISHMENT REQUEST, or `None`
    /// when not registered or the session already exists.
    pub fn request_pdu_session(&mut self, psi: u8) -> Option<Vec<u8>> {
        if self.state != MmState::Registered || !(1..=15).contains(&psi) {
            return None;
        }
        if self
            .sessions
            .iter()
            .any(|s| s.psi == psi && s.state != SmState::Inactive)
        {
            return None;
        }
        self.sessions.retain(|s| s.psi != psi);
        let pti = self.alloc_pti();
        self.sessions.push(PduSession {
            psi,
            pti,
            state: SmState::ActivePending,
            ipv4: None,
            ipv6: None,
            dnn: self.cfg.dnn.clone(),
            default_qfi: 0,
            attempts: 0,
            timer: Some(self.now + timers::T3580_MS),
        });
        Some(self.establishment_request_pdu(psi, pti))
    }

    fn establishment_request_pdu(&mut self, psi: u8, pti: u8) -> Vec<u8> {
        let smreq = PduSessionEstablishmentRequest::new(
            psi,
            pti,
            self.cfg.pdu_session_type,
            self.cfg.ssc_mode,
        );
        let ul = UlNasTransport {
            payload_container_type: payload_container_type::N1_SM_INFORMATION,
            payload_container: smreq.encode(),
            pdu_session_id: Some(psi),
            old_pdu_session_id: None,
            request_type: Some(request_type::INITIAL_REQUEST),
            snssai: self.cfg.requested_nssai.first().copied(),
            dnn: Some(self.cfg.dnn.clone()),
        };
        log::info!(
            "NAS: PDU SESSION ESTABLISHMENT REQUEST psi={psi} pti={pti} dnn={}",
            self.cfg.dnn
        );
        self.tx(ul.encode())
    }

    /// Release a PDU session (TS 24.501 §6.4.3): UL NAS TRANSPORT with a
    /// PDU SESSION RELEASE REQUEST.
    pub fn release_pdu_session(&mut self, psi: u8) -> Option<Vec<u8>> {
        if self.state != MmState::Registered {
            return None;
        }
        let pti = self.alloc_pti();
        let s = self
            .sessions
            .iter_mut()
            .find(|s| s.psi == psi && s.state == SmState::Active)?;
        s.state = SmState::InactivePending;
        s.pti = pti;
        s.attempts = 0;
        s.timer = Some(self.now + timers::T3582_MS);
        let rel = PduSessionReleaseRequest {
            psi,
            pti,
            cause: Some(sm::cause::REGULAR_DEACTIVATION),
        };
        Some(self.ul_transport_sm(psi, rel.encode()))
    }

    fn ul_transport_sm(&mut self, psi: u8, sm_pdu: Vec<u8>) -> Vec<u8> {
        let ul = UlNasTransport {
            payload_container_type: payload_container_type::N1_SM_INFORMATION,
            payload_container: sm_pdu,
            pdu_session_id: Some(psi),
            old_pdu_session_id: None,
            request_type: None,
            snssai: None,
            dnn: None,
        };
        self.tx(ul.encode())
    }

    /// UE-initiated deregistration (TS 24.501 §5.5.2.2), normal (not switch
    /// off): waits for DEREGISTRATION ACCEPT with T3521 retries.
    pub fn deregister(&mut self) -> Option<Vec<u8>> {
        self.deregister_with(false)
    }

    /// Deregistration with an explicit switch-off flag; with `switch_off`
    /// the UE deregisters locally without waiting for an accept.
    pub fn deregister_with(&mut self, switch_off: bool) -> Option<Vec<u8>> {
        if !matches!(
            self.state,
            MmState::Registered | MmState::ServiceRequestInitiated
        ) {
            return None;
        }
        self.dereg_attempts = 0;
        Some(self.send_deregistration_request(switch_off))
    }

    fn send_deregistration_request(&mut self, switch_off: bool) -> Vec<u8> {
        let (identity, ngksi) = match (&self.ctx, self.guti) {
            (Some(c), Some(g)) => (
                MobileIdentity::Guti(g),
                NgKsi {
                    mapped: false,
                    ksi: c.ngksi,
                },
            ),
            (Some(c), None) => (
                self.id.suci(),
                NgKsi {
                    mapped: false,
                    ksi: c.ngksi,
                },
            ),
            _ => (self.id.suci(), NgKsi::NO_KEY),
        };
        let req = DeregistrationRequestUeOriginating {
            dereg_type: DeregistrationType {
                access_type: 1,
                reregistration_required: false,
                switch_off,
            },
            ngksi,
            mobile_identity: identity,
        };
        let pdu = self.tx(req.encode());
        if switch_off {
            self.local_deregister();
        } else {
            self.state = MmState::DeregistrationInitiated;
            self.t3521 = Some(self.now + timers::T3521_MS);
        }
        pdu
    }

    /// SERVICE REQUEST (TS 24.501 §5.6.1), integrity protected, with the
    /// 5G-S-TMSI and the status of the active PDU sessions. `None` when
    /// there is no security context or GUTI.
    pub fn service_request(&mut self, service_type: u8) -> Option<Vec<u8>> {
        if self.state != MmState::Registered {
            return None;
        }
        let g = self.guti?;
        let ksi = self.ctx.as_ref()?.ngksi;
        let active: u16 = self
            .sessions
            .iter()
            .filter(|s| s.state == SmState::Active && s.psi < 16)
            .fold(0, |a, s| a | (1 << s.psi));
        let sr = ServiceRequest {
            ngksi: NgKsi { mapped: false, ksi },
            service_type,
            s_tmsi: MobileIdentity::STmsi {
                amf_set_id: g.amf_set_id,
                amf_pointer: g.amf_pointer,
                tmsi: g.tmsi,
            },
            uplink_data_status: (active != 0).then_some(active),
            pdu_session_status: (active != 0).then_some(active),
        };
        self.state = MmState::ServiceRequestInitiated;
        self.t3517 = Some(self.now + timers::T3517_MS);
        Some(self.tx_sht(sr.encode(), SecurityHeaderType::Integrity))
    }

    fn local_deregister(&mut self) {
        for s in self.sessions.iter_mut() {
            if s.state != SmState::Inactive {
                s.state = SmState::Inactive;
                self.events.push(NasEvent::PduSessionDown { psi: s.psi });
            }
        }
        self.state = MmState::Deregistered;
        self.t3510 = None;
        self.t3512 = None;
        self.t3517 = None;
        self.t3520 = None;
        self.t3521 = None;
        self.events.push(NasEvent::Deregistered);
    }

    // -- downlink -----------------------------------------------------------

    /// Messages accepted without integrity protection once a security
    /// context exists (TS 24.501 §4.4.4.2).
    fn plain_allowed(t: u8) -> bool {
        matches!(
            t,
            msg_type::IDENTITY_REQUEST
                | msg_type::AUTHENTICATION_REQUEST
                | msg_type::AUTHENTICATION_RESULT
                | msg_type::AUTHENTICATION_REJECT
                | msg_type::REGISTRATION_REJECT
                | msg_type::DEREGISTRATION_ACCEPT_UE_ORIG
                | msg_type::SERVICE_REJECT
        )
    }

    /// Handle a downlink NAS PDU. Returns the uplink PDUs to send. Errors
    /// mean the message was discarded (malformed, MAC failure, replay,
    /// unprotected when protection is mandatory).
    pub fn on_dl_nas(&mut self, pdu: &[u8]) -> Result<Vec<Vec<u8>>, NasError> {
        let (hdr, inner) = split_security_header(pdu)?;
        let plain = match hdr {
            None => {
                let t = mm_message_type(inner).ok_or(NasError::BadHeader)?;
                if self.ctx.is_some() && !Self::plain_allowed(t) {
                    log::warn!("NAS: discarding unprotected message type {t:#04x}");
                    return Err(NasError::Unprotected(t));
                }
                inner.to_vec()
            }
            Some(h) if h.sht.is_new_context() => {
                // The SMC is integrity protected only; parse it first to learn
                // the algorithms, then verify with the new context.
                if h.sht != SecurityHeaderType::IntegrityNewContext {
                    return Err(NasError::BadHeader);
                }
                let smc = SecurityModeCommand::decode(inner)?;
                return self.on_security_mode_command(pdu, &h, smc);
            }
            Some(h) => {
                let ctx = self.ctx.as_mut().ok_or(NasError::NoSecurityContext)?;
                ctx.unprotect(pdu, &h)?
            }
        };
        let msg = decode_mm(&plain)?;
        Ok(self.dispatch(msg))
    }

    fn dispatch(&mut self, msg: MmMessage) -> Vec<Vec<u8>> {
        match msg {
            MmMessage::AuthenticationRequest(ar) => self.on_authentication_request(ar),
            MmMessage::AuthenticationReject => {
                log::warn!("NAS: AUTHENTICATION REJECT");
                self.pending_keys = None;
                self.ctx = None;
                self.guti = None;
                self.events.push(NasEvent::AuthenticationFailed);
                self.local_deregister();
                vec![]
            }
            MmMessage::AuthenticationResult(_) => {
                log::info!("NAS: AUTHENTICATION RESULT (EAP) ignored");
                vec![]
            }
            MmMessage::RegistrationAccept(ra) => self.on_registration_accept(ra),
            MmMessage::RegistrationReject(rj) => self.on_registration_reject(rj),
            MmMessage::DeregistrationRequestUeTerminated(d) => self.on_deregistration_request(d),
            MmMessage::DeregistrationAcceptUeOriginating => {
                log::info!("NAS: DEREGISTRATION ACCEPT");
                self.local_deregister();
                vec![]
            }
            MmMessage::IdentityRequest(r) => self.on_identity_request(r),
            MmMessage::ConfigurationUpdateCommand(c) => self.on_configuration_update(c),
            MmMessage::ServiceAccept(a) => {
                log::info!("NAS: SERVICE ACCEPT");
                self.t3517 = None;
                self.state = MmState::Registered;
                if let Some(status) = a.pdu_session_status {
                    self.sync_pdu_session_status(status);
                }
                vec![]
            }
            MmMessage::ServiceReject(r) => {
                log::warn!("NAS: SERVICE REJECT cause #{}", r.cause);
                self.t3517 = None;
                self.state = MmState::Registered;
                if matches!(
                    r.cause,
                    3 | 6 | 7 | 11 | 12 | 13 | 15 | 27 | 72 | 73 | 74 | 75 | 76
                ) {
                    self.guti = None;
                    self.ctx = None;
                    self.local_deregister();
                }
                vec![]
            }
            MmMessage::DlNasTransport(t) => self.on_dl_nas_transport(t),
            MmMessage::Status(s) => {
                log::warn!("NAS: 5GMM STATUS cause #{}", s.cause);
                vec![]
            }
            MmMessage::Notification(n) => {
                log::info!("NAS: NOTIFICATION access type {}", n.access_type);
                vec![]
            }
            MmMessage::SecurityModeCommand(_) => {
                log::warn!("NAS: SECURITY MODE COMMAND without new-context header; ignored");
                vec![]
            }
            MmMessage::Unknown { msg_type } => {
                log::warn!(
                    "NAS: unknown 5GMM message type {msg_type:#04x}; sending 5GMM STATUS #97"
                );
                vec![self.tx(MmStatus {
                    cause: cause::MESSAGE_TYPE_NON_EXISTENT,
                }
                .encode())]
            }
            other => {
                log::warn!("NAS: uplink-only message received in downlink: {other:?}; ignored");
                vec![]
            }
        }
    }

    fn on_authentication_request(&mut self, ar: AuthenticationRequest) -> Vec<Vec<u8>> {
        let (Some(rand), Some(autn)) = (ar.rand, ar.autn) else {
            log::warn!("NAS: AUTHENTICATION REQUEST without RAND/AUTN (EAP?) not supported");
            return vec![];
        };
        let snn = self.snn();
        let sqn_ms = if self.cfg.sqn_check {
            self.sqn_ms
        } else {
            None
        };
        match run_5g_aka(
            &self.id.keys(),
            &rand,
            &autn,
            &snn,
            &self.id.imsi,
            &ar.abba,
            sqn_ms,
        ) {
            AkaOutcome::Success(keys) => {
                log::info!(
                    "NAS: 5G-AKA ok (ngKSI {}, SQN {:#x})",
                    ar.ngksi.ksi,
                    keys.sqn
                );
                self.sqn_ms = Some(keys.sqn);
                self.pending_keys = Some((keys.k_amf, ar.ngksi.ksi));
                if matches!(
                    self.state,
                    MmState::RegistrationInitiated | MmState::Authenticating
                ) {
                    self.state = MmState::Authenticating;
                }
                self.t3520 = None;
                let resp = AuthenticationResponse {
                    res_star: Some(keys.res_star),
                    eap_message: None,
                };
                vec![self.tx(resp.encode())]
            }
            AkaOutcome::MacFailure => {
                log::warn!("NAS: 5G-AKA MAC failure");
                self.t3520 = Some(self.now + timers::T3520_MS);
                vec![self.tx(AuthenticationFailure {
                    cause: cause::MAC_FAILURE,
                    auts: None,
                }
                .encode())]
            }
            AkaOutcome::SyncFailure { auts } => {
                log::warn!("NAS: 5G-AKA synchronisation failure, sending AUTS");
                self.t3520 = Some(self.now + timers::T3520_MS);
                vec![self.tx(AuthenticationFailure {
                    cause: cause::SYNCH_FAILURE,
                    auts: Some(auts),
                }
                .encode())]
            }
        }
    }

    fn on_security_mode_command(
        &mut self,
        pdu: &[u8],
        hdr: &SecurityHeader,
        smc: SecurityModeCommand,
    ) -> Result<Vec<Vec<u8>>, NasError> {
        // Pick the K_AMF the SMC refers to: the fresh one from AKA, or the
        // current one when only the algorithms change (same ngKSI).
        let (k_amf, fresh) = match (self.pending_keys, &self.ctx) {
            (Some((k, ksi)), _) if ksi == smc.ngksi.ksi => (k, true),
            (_, Some(c)) if c.ngksi == smc.ngksi.ksi => (c.k_amf, false),
            _ => {
                log::warn!(
                    "NAS: SECURITY MODE COMMAND for unknown ngKSI {}",
                    smc.ngksi.ksi
                );
                return Err(NasError::NoSecurityContext);
            }
        };
        let mut ctx = match NasSecurityContext::new(k_amf, smc.ngksi.ksi, smc.ea, smc.ia) {
            Ok(c) => c,
            Err(e) => {
                log::warn!(
                    "NAS: SECURITY MODE COMMAND selects NEA{}/NIA{}: rejecting",
                    smc.ea,
                    smc.ia
                );
                let c = cause::SECURITY_MODE_REJECTED_UNSPECIFIED;
                self.events
                    .push(NasEvent::SecurityModeRejected { cause: c });
                let _ = e;
                return Ok(vec![self.tx(security_mode_reject(c))]);
            }
        };
        if !fresh {
            if let Some(old) = &self.ctx {
                ctx.ul_count = old.ul_count;
                ctx.dl_count = old.dl_count;
            }
        }
        ctx.unprotect(pdu, hdr)?;
        let mine = self.security_capability();
        let theirs = smc.replayed_ue_security_capability;
        if mine.ea != theirs.ea || mine.ia != theirs.ia {
            log::warn!(
                "NAS: replayed UE security capabilities mismatch ({:02x}{:02x} vs {:02x}{:02x})",
                theirs.ea,
                theirs.ia,
                mine.ea,
                mine.ia
            );
            let c = cause::UE_SECURITY_CAPABILITIES_MISMATCH;
            self.events
                .push(NasEvent::SecurityModeRejected { cause: c });
            return Ok(vec![self.tx(security_mode_reject(c))]);
        }
        if smc.ia == 0 {
            log::warn!("NAS: NIA0 selected for a non-emergency registration: rejecting");
            let c = cause::SECURITY_MODE_REJECTED_UNSPECIFIED;
            self.events
                .push(NasEvent::SecurityModeRejected { cause: c });
            return Ok(vec![self.tx(security_mode_reject(c))]);
        }
        log::info!(
            "NAS: SECURITY MODE COMMAND ok: NEA{} / NIA{}, ngKSI {}",
            smc.ea,
            smc.ia,
            smc.ngksi.ksi
        );
        let complete = SecurityModeComplete {
            imeisv: if smc.imeisv_requested {
                self.cfg.imeisv.clone()
            } else {
                None
            },
            nas_message_container: if smc.rinmr || self.cfg.replay_initial_message {
                self.initial_message.clone()
            } else {
                None
            },
        };
        let (out, count) = ctx.protect(
            SecurityHeaderType::IntegrityCipheredNewContext,
            &complete.encode(),
        );
        self.ul_count_at_activation = Some(count);
        self.ctx = Some(ctx);
        self.pending_keys = None;
        if matches!(
            self.state,
            MmState::RegistrationInitiated | MmState::Authenticating
        ) {
            self.state = MmState::SecurityMode;
        }
        self.events.push(NasEvent::SecurityActivated {
            k_amf,
            ul_nas_count_at_activation: count,
        });
        Ok(vec![out])
    }

    fn on_registration_accept(&mut self, ra: RegistrationAccept) -> Vec<Vec<u8>> {
        if !matches!(
            self.state,
            MmState::RegistrationInitiated
                | MmState::Authenticating
                | MmState::SecurityMode
                | MmState::Registered
        ) {
            log::warn!(
                "NAS: REGISTRATION ACCEPT in state {:?}; ignored",
                self.state
            );
            return vec![];
        }
        if self.ctx.is_none() {
            log::warn!("NAS: REGISTRATION ACCEPT without a security context; ignored");
            return vec![];
        }
        if let Some(g) = ra.guti {
            self.guti = Some(g);
        }
        if !ra.tai_list.is_empty() {
            self.tai_list = ra.tai_list.clone();
        }
        if !ra.allowed_nssai.is_empty() {
            self.allowed_nssai = ra.allowed_nssai.clone();
        }
        if let Some(t) = ra.t3512.and_then(|t| t.to_ms()) {
            self.t3512_len = t;
        }
        if let Some(status) = ra.pdu_session_status {
            self.sync_pdu_session_status(status);
        }
        self.t3510 = None;
        self.t3512 = Some(self.now + self.t3512_len);
        self.reg_attempts = 0;
        let was_periodic = self.periodic_update;
        self.periodic_update = false;
        self.state = MmState::Registered;
        log::info!(
            "NAS: REGISTRATION ACCEPT (result {}, GUTI {:?})",
            ra.result,
            ra.guti.is_some()
        );
        let mut out = vec![self.tx(registration_complete())];
        if !was_periodic {
            self.events
                .push(NasEvent::RegistrationComplete { guti: self.guti });
            if let Some(psi) = self.cfg.auto_pdu_session {
                if let Some(p) = self.request_pdu_session(psi) {
                    out.push(p);
                }
            }
        }
        out
    }

    fn on_registration_reject(&mut self, rj: RegistrationReject) -> Vec<Vec<u8>> {
        log::warn!("NAS: REGISTRATION REJECT cause #{}", rj.cause);
        self.t3510 = None;
        self.pending_keys = None;
        if matches!(
            rj.cause,
            3 | 6 | 7 | 11 | 12 | 13 | 15 | 27 | 72 | 73 | 74 | 75 | 76
        ) {
            self.guti = None;
            self.ctx = None;
        }
        self.events.push(NasEvent::RegistrationRejected(rj.cause));
        self.local_deregister();
        vec![]
    }

    fn on_deregistration_request(&mut self, d: DeregistrationRequestUeTerminated) -> Vec<Vec<u8>> {
        log::info!(
            "NAS: network DEREGISTRATION REQUEST (cause {:?}, re-registration {})",
            d.cause,
            d.dereg_type.reregistration_required
        );
        let out = vec![self.tx(deregistration_accept(true))];
        if matches!(d.cause, Some(3 | 6 | 7 | 11 | 12 | 13 | 15 | 27)) {
            self.guti = None;
            self.ctx = None;
        }
        self.local_deregister();
        out
    }

    fn on_identity_request(&mut self, r: IdentityRequest) -> Vec<Vec<u8>> {
        let identity = match r.identity_type {
            identity_type::SUCI => self.id.suci(),
            identity_type::IMEISV | identity_type::IMEI => match &self.cfg.imeisv {
                Some(i) => MobileIdentity::Imeisv(i.clone()),
                None => MobileIdentity::NoIdentity,
            },
            identity_type::GUTI => match self.guti {
                Some(g) => MobileIdentity::Guti(g),
                None => MobileIdentity::NoIdentity,
            },
            _ => MobileIdentity::NoIdentity,
        };
        log::info!(
            "NAS: IDENTITY REQUEST type {} → {:?}",
            r.identity_type,
            identity
        );
        vec![self.tx(IdentityResponse {
            mobile_identity: identity,
        }
        .encode())]
    }

    fn on_configuration_update(&mut self, c: ConfigurationUpdateCommand) -> Vec<Vec<u8>> {
        if let Some(g) = c.guti {
            self.guti = Some(g);
        }
        if !c.tai_list.is_empty() {
            self.tai_list = c.tai_list;
        }
        if let Some(n) = c.allowed_nssai {
            self.allowed_nssai = n;
        }
        log::info!(
            "NAS: CONFIGURATION UPDATE COMMAND (ack {}, registration {})",
            c.ack_requested,
            c.registration_requested
        );
        self.events.push(NasEvent::ConfigurationUpdated);
        if c.ack_requested {
            vec![self.tx(configuration_update_complete())]
        } else {
            vec![]
        }
    }

    /// Drop sessions the network reports as inactive in a PDU session status IE.
    fn sync_pdu_session_status(&mut self, status: u16) {
        for s in self.sessions.iter_mut() {
            if s.state == SmState::Active && s.psi < 16 && status & (1 << s.psi) == 0 {
                s.state = SmState::Inactive;
                self.events.push(NasEvent::PduSessionDown { psi: s.psi });
            }
        }
    }

    fn on_dl_nas_transport(&mut self, t: DlNasTransport) -> Vec<Vec<u8>> {
        if t.payload_container_type != payload_container_type::N1_SM_INFORMATION {
            log::info!(
                "NAS: DL NAS TRANSPORT container type {} ignored",
                t.payload_container_type
            );
            return vec![];
        }
        if let Some(c) = t.cause {
            log::warn!(
                "NAS: DL NAS TRANSPORT 5GMM cause #{c} (psi {:?})",
                t.pdu_session_id
            );
            if let Some(psi) = t.pdu_session_id {
                if let Some(s) = self.sessions.iter_mut().find(|s| s.psi == psi) {
                    if s.state == SmState::ActivePending {
                        s.state = SmState::Inactive;
                        s.timer = None;
                        self.events
                            .push(NasEvent::PduSessionRejected { psi, cause: c });
                    }
                }
            }
            return vec![];
        }
        let sm = match decode_sm(&t.payload_container) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("NAS: malformed 5GSM payload: {e}");
                return vec![];
            }
        };
        match sm {
            SmMessage::EstablishmentAccept(a) => {
                let ipv6 = a.pdu_address.and_then(|p| p.ipv6_iid).map(|iid| {
                    let mut v = [0u8; 16];
                    v[0] = 0xfe;
                    v[1] = 0x80;
                    v[8..].copy_from_slice(&iid);
                    v
                });
                let ipv4 = a.pdu_address.and_then(|p| p.ipv4);
                let qfi = a.default_qfi().unwrap_or(1);
                let dnn = a.dnn.clone().unwrap_or_else(|| self.cfg.dnn.clone());
                let Some(s) = self.sessions.iter_mut().find(|s| s.psi == a.psi) else {
                    log::warn!(
                        "NAS: PDU SESSION ESTABLISHMENT ACCEPT for unknown psi {}",
                        a.psi
                    );
                    return vec![];
                };
                s.state = SmState::Active;
                s.ipv4 = ipv4;
                s.ipv6 = ipv6;
                s.dnn = dnn.clone();
                s.default_qfi = qfi;
                s.timer = None;
                log::info!(
                    "NAS: PDU session {} up: ipv4 {:?} qfi {qfi} dnn {dnn}",
                    a.psi,
                    ipv4
                );
                self.events.push(NasEvent::PduSessionUp {
                    psi: a.psi,
                    ipv4,
                    ipv6,
                    dnn,
                    default_qfi: qfi,
                });
                vec![]
            }
            SmMessage::EstablishmentReject(r) => {
                log::warn!(
                    "NAS: PDU SESSION ESTABLISHMENT REJECT psi {} cause #{}",
                    r.psi,
                    r.cause
                );
                if let Some(s) = self.sessions.iter_mut().find(|s| s.psi == r.psi) {
                    s.state = SmState::Inactive;
                    s.timer = None;
                }
                self.events.push(NasEvent::PduSessionRejected {
                    psi: r.psi,
                    cause: r.cause,
                });
                vec![]
            }
            SmMessage::ReleaseCommand(c) => {
                log::info!(
                    "NAS: PDU SESSION RELEASE COMMAND psi {} cause #{}",
                    c.psi,
                    c.cause
                );
                if let Some(s) = self.sessions.iter_mut().find(|s| s.psi == c.psi) {
                    s.state = SmState::Inactive;
                    s.timer = None;
                }
                self.events.push(NasEvent::PduSessionDown { psi: c.psi });
                let done = PduSessionReleaseComplete {
                    psi: c.psi,
                    pti: c.pti,
                    cause: None,
                };
                vec![self.ul_transport_sm(c.psi, done.encode())]
            }
            SmMessage::ReleaseReject(r) => {
                log::warn!(
                    "NAS: PDU SESSION RELEASE REJECT psi {} cause #{}",
                    r.psi,
                    r.cause
                );
                if let Some(s) = self.sessions.iter_mut().find(|s| s.psi == r.psi) {
                    if s.state == SmState::InactivePending {
                        s.state = SmState::Active;
                        s.timer = None;
                    }
                }
                vec![]
            }
            SmMessage::Status(s) => {
                log::warn!("NAS: 5GSM STATUS psi {} cause #{}", s.psi, s.cause);
                vec![]
            }
            SmMessage::Unknown(h) => {
                log::warn!(
                    "NAS: unknown 5GSM message type {:#04x}; sending 5GSM STATUS #97",
                    h.msg_type
                );
                let st = SmStatus {
                    psi: h.psi,
                    pti: h.pti,
                    cause: sm::cause::MESSAGE_TYPE_NON_EXISTENT,
                };
                vec![self.ul_transport_sm(h.psi, st.encode())]
            }
            other => {
                log::warn!("NAS: uplink-only 5GSM message in downlink: {other:?}; ignored");
                vec![]
            }
        }
    }

    // -- timers -------------------------------------------------------------

    /// Advance the clock and run expired timers. Returns UL PDUs to send
    /// (retransmissions, periodic registration).
    pub fn tick(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        self.now = now_ms;
        let mut out = Vec::new();
        if self.t3510.is_some_and(|t| now_ms >= t) {
            self.t3510 = None;
            self.reg_attempts += 1;
            if self.reg_attempts < self.cfg.max_attempts {
                log::warn!("NAS: T3510 expired, retrying registration");
                let rt = if self.periodic_update {
                    RegistrationType::PeriodicUpdating
                } else {
                    RegistrationType::Initial
                };
                out.push(self.send_registration_request(rt));
            } else {
                log::error!(
                    "NAS: registration abandoned after {} attempts",
                    self.reg_attempts
                );
                self.pending_keys = None;
                self.events.push(NasEvent::RegistrationTimeout);
                self.local_deregister();
            }
        }
        if self.t3520.is_some_and(|t| now_ms >= t) {
            self.t3520 = None;
            log::error!("NAS: T3520 expired, authentication aborted");
            self.events.push(NasEvent::AuthenticationFailed);
            self.local_deregister();
        }
        if self.t3521.is_some_and(|t| now_ms >= t) {
            self.t3521 = None;
            self.dereg_attempts += 1;
            if self.dereg_attempts < self.cfg.max_attempts {
                log::warn!("NAS: T3521 expired, retrying deregistration");
                out.push(self.send_deregistration_request(false));
            } else {
                log::warn!("NAS: deregistration not acknowledged, deregistering locally");
                self.local_deregister();
            }
        }
        if self.t3517.is_some_and(|t| now_ms >= t) {
            self.t3517 = None;
            log::warn!("NAS: T3517 expired");
            self.state = MmState::Registered;
        }
        if self.t3512.is_some_and(|t| now_ms >= t) && self.state == MmState::Registered {
            self.t3512 = None;
            log::info!("NAS: T3512 expired, periodic registration update");
            self.reg_attempts = 0;
            self.periodic_update = true;
            out.push(self.send_registration_request(RegistrationType::PeriodicUpdating));
        }
        // 5GSM timers.
        let mut retries = Vec::new();
        for s in self.sessions.iter_mut() {
            if s.timer.is_some_and(|t| now_ms >= t) {
                s.timer = None;
                s.attempts += 1;
                if s.attempts < self.cfg.max_attempts {
                    s.timer = Some(now_ms + timers::T3580_MS);
                    retries.push((s.psi, s.pti, s.state));
                } else {
                    let psi = s.psi;
                    match s.state {
                        SmState::ActivePending => self
                            .events
                            .push(NasEvent::PduSessionRejected { psi, cause: 0 }),
                        SmState::InactivePending => {
                            self.events.push(NasEvent::PduSessionDown { psi })
                        }
                        _ => {}
                    }
                    s.state = SmState::Inactive;
                }
            }
        }
        for (psi, pti, state) in retries {
            match state {
                SmState::ActivePending => out.push(self.establishment_request_pdu(psi, pti)),
                SmState::InactivePending => {
                    let rel = PduSessionReleaseRequest {
                        psi,
                        pti,
                        cause: Some(sm::cause::REGULAR_DEACTIVATION),
                    };
                    out.push(self.ul_transport_sm(psi, rel.encode()));
                }
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ue() -> NasUe {
        NasUe::new(
            UeIdentity::from_imsi("001010167891203", [1; 16], [2; 16]),
            NasConfig::default(),
        )
    }

    #[test]
    fn identity_parsing() {
        let id = UeIdentity::from_imsi("001010167891203", [0; 16], [0; 16]);
        assert_eq!((id.mcc, id.mnc, id.mnc_digits), (1, 1, 2));
        let id3 = id.clone().with_mnc_digits(3);
        assert_eq!((id3.mcc, id3.mnc), (1, 10));
        assert_eq!(
            id.plmn().serving_network_name(),
            "5G:mnc001.mcc001.3gppnetwork.org"
        );
        let short = UeIdentity::from_imsi("12", [0; 16], [0; 16]);
        assert_eq!(short.mcc, 0);
        let _ = short.suci().encode();
    }

    #[test]
    fn initial_registration_matches_legacy_bytes() {
        let mut u = ue();
        let rr = u.start_registration();
        assert_eq!(rr, crate::msgs::registration_request("001010167891203"));
        assert_eq!(u.state(), MmState::RegistrationInitiated);
        assert!(u.request_pdu_session(5).is_none());
        assert!(u.deregister().is_none());
        assert!(u.k_gnb(0).is_none());
    }

    #[test]
    fn t3510_retries_then_gives_up() {
        let mut u = ue();
        let _ = u.start_registration();
        let mut sent = 0;
        for i in 1..=10u64 {
            sent += u.tick(i * timers::T3510_MS).len();
        }
        assert_eq!(sent, 4);
        assert_eq!(u.state(), MmState::Deregistered);
        assert!(u.events().contains(&NasEvent::RegistrationTimeout));
    }

    #[test]
    fn malformed_dl_is_an_error_not_a_panic() {
        let mut u = ue();
        let _ = u.start_registration();
        for pdu in [
            &[][..],
            &[0x7e][..],
            &[0x7e, 0x02, 1, 2, 3][..],
            &[0x7e, 0x00, 0x56][..],
            &[0x2e, 0, 0, 0][..],
        ] {
            assert!(u.on_dl_nas(pdu).is_err());
        }
        // Protected message without a context.
        assert_eq!(
            u.on_dl_nas(&[0x7e, 0x02, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x42, 0x01, 0x01]),
            Err(NasError::NoSecurityContext)
        );
        // Unknown plain message → 5GMM STATUS #97.
        let out = u.on_dl_nas(&[0x7e, 0x00, 0x99]).unwrap();
        assert_eq!(out, vec![vec![0x7e, 0x00, 0x64, 97]]);
    }
}
