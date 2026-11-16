//! The NAS state machines' declarations (see [`ferrite_common::fsm`]): 5GMM
//! ([`MmMachine`], over the full state × substate), 5GMM-IDLE / CONNECTED
//! ([`CmMachine`]) and the 5GSM state of one PDU session ([`SmMachine`]).
//! [`NasUe`](crate::NasUe) changes these states only through the tables.

use crate::ue::{CmState, DeregisteredSub as D, MmState, RegisteredSub as R, SmState};
use ferrite_common::fsm::{Machine, Rule};

/// What moves the 5GMM state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmTrigger {
    /// REGISTRATION REQUEST sent (initial, mobility or periodic), T3510.
    RegistrationRequested,
    /// AUTHENTICATION RESPONSE sent (5G AKA succeeded).
    AuthenticationCompleted,
    /// SECURITY MODE COMPLETE sent.
    SecurityModeCompleted,
    /// REGISTRATION ACCEPT received.
    RegistrationAccepted,
    /// T3510 expiry or a lower-layer failure: an attempt without a
    /// definitive answer.
    RegistrationFailed,
    /// REGISTRATION REJECT received.
    RegistrationRejected,
    /// T3520 expired: authentication aborted.
    AuthenticationAborted,
    /// AUTHENTICATION REJECT received: the USIM is invalid for 5GS.
    AuthenticationRejected,
    /// SERVICE REQUEST sent, T3517.
    ServiceRequested,
    ServiceAccepted,
    ServiceRejected,
    /// T3517 expiry, or the connection went away first.
    ServiceRequestAbandoned,
    /// UE-initiated DEREGISTRATION REQUEST (normal), T3521.
    DeregistrationRequested,
    /// UE-initiated DEREGISTRATION REQUEST with switch off: local at once.
    SwitchOff,
    DeregistrationAccepted,
    /// T3521 expired the last time: deregistered locally.
    DeregistrationAbandoned,
    /// Network-initiated DEREGISTRATION REQUEST.
    NetworkDeregistration,
    /// T3512 expiry: a periodic registration update is due.
    UpdateDue,
}

/// What moves the 5GMM-IDLE / 5GMM-CONNECTED state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmTrigger {
    ConnectionEstablished,
    ConnectionReleased,
}

/// What moves the 5GSM state of a PDU session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmTrigger {
    /// PDU SESSION ESTABLISHMENT REQUEST sent, T3580.
    EstablishmentRequested,
    EstablishmentAccepted,
    /// PDU SESSION ESTABLISHMENT REJECT, or a 5GMM cause in the DL NAS
    /// TRANSPORT that carried the request back.
    EstablishmentRejected,
    /// T3580 expired the last time.
    EstablishmentAbandoned,
    /// PDU SESSION RELEASE REQUEST sent, T3582.
    ReleaseRequested,
    ReleaseRejected,
    /// T3582 expired the last time.
    ReleaseAbandoned,
    /// PDU SESSION RELEASE COMMAND received.
    NetworkRelease,
    /// A PDU session status IE lists the session as inactive.
    StatusSync,
    /// Local release on deregistration.
    LocalRelease,
}

/// The 5GMM machine (kinds: the state with its substate).
pub struct MmMachine;
/// The 5GMM-IDLE / 5GMM-CONNECTED machine.
pub struct CmMachine;
/// The 5GSM machine of one PDU session.
pub struct SmMachine;

use MmState::{
    Authenticating, Deregistered, DeregistrationInitiated, Registered, RegistrationInitiated,
    SecurityMode, ServiceRequestInitiated,
};

/// The registration procedure's states.
const IN_REGISTRATION: &[MmState] = &[RegistrationInitiated, Authenticating, SecurityMode];
/// Every 5GMM-REGISTERED substate the UE enters.
const REGISTERED: &[MmState] = &[
    Registered(R::NormalService),
    Registered(R::NonAllowedService),
    Registered(R::AttemptingRegistrationUpdate),
    Registered(R::UpdateNeeded),
];
/// Where a registration may start: 5GMM-DEREGISTERED with a usable USIM and
/// PLMN, any registered substate (an update), a restart of the procedure.
const MAY_REGISTER: &[MmState] = &[
    Deregistered(D::InitialRegistrationNeeded),
    Deregistered(D::NormalService),
    Deregistered(D::AttemptingRegistration),
    Registered(R::NormalService),
    Registered(R::NonAllowedService),
    Registered(R::AttemptingRegistrationUpdate),
    Registered(R::UpdateNeeded),
    Authenticating,
    SecurityMode,
];
/// Every state but 5GMM-DEREGISTERED.
const NOT_DEREGISTERED: &[MmState] = &[
    RegistrationInitiated,
    Authenticating,
    SecurityMode,
    Registered(R::NormalService),
    Registered(R::NonAllowedService),
    Registered(R::AttemptingRegistrationUpdate),
    Registered(R::UpdateNeeded),
    ServiceRequestInitiated,
    DeregistrationInitiated,
];
/// Every kind the UE enters. `Registered(LimitedService)` and
/// `Registered(PlmnSearch)` exist in the type but no procedure enters them.
const MM_KINDS: &[MmState] = &[
    Deregistered(D::InitialRegistrationNeeded),
    Deregistered(D::NormalService),
    Deregistered(D::LimitedService),
    Deregistered(D::AttemptingRegistration),
    Deregistered(D::PlmnSearch),
    Deregistered(D::NoSupi),
    RegistrationInitiated,
    Authenticating,
    SecurityMode,
    Registered(R::NormalService),
    Registered(R::NonAllowedService),
    Registered(R::AttemptingRegistrationUpdate),
    Registered(R::UpdateNeeded),
    ServiceRequestInitiated,
    DeregistrationInitiated,
];

const fn mm(
    from: &'static [MmState],
    event: MmTrigger,
    to: MmState,
    clause: &'static str,
) -> Rule<MmState, MmTrigger> {
    Rule {
        from,
        event,
        to,
        clause,
    }
}

const REJECT: &str = "24.501 §5.5.1.2.5, §5.5.1.3.5 (cause → substate)";

impl Machine for MmMachine {
    const NAME: &'static str = "5GMM";
    type State = MmState;
    type Kind = MmState;
    type Event = MmTrigger;
    const KINDS: &'static [MmState] = MM_KINDS;
    const EVENTS: &'static [MmTrigger] = &[
        MmTrigger::RegistrationRequested,
        MmTrigger::AuthenticationCompleted,
        MmTrigger::SecurityModeCompleted,
        MmTrigger::RegistrationAccepted,
        MmTrigger::RegistrationFailed,
        MmTrigger::RegistrationRejected,
        MmTrigger::AuthenticationAborted,
        MmTrigger::AuthenticationRejected,
        MmTrigger::ServiceRequested,
        MmTrigger::ServiceAccepted,
        MmTrigger::ServiceRejected,
        MmTrigger::ServiceRequestAbandoned,
        MmTrigger::DeregistrationRequested,
        MmTrigger::SwitchOff,
        MmTrigger::DeregistrationAccepted,
        MmTrigger::DeregistrationAbandoned,
        MmTrigger::NetworkDeregistration,
        MmTrigger::UpdateDue,
    ];
    const INITIAL: MmState = Deregistered(D::InitialRegistrationNeeded);
    const RULES: &'static [Rule<MmState, MmTrigger>] = {
        use MmTrigger::*;
        &[
            // Registration (§5.5.1).
            mm(
                MAY_REGISTER,
                RegistrationRequested,
                RegistrationInitiated,
                "24.501 §5.5.1.2.2, §5.5.1.3.2",
            ),
            mm(
                &[RegistrationInitiated],
                AuthenticationCompleted,
                Authenticating,
                "24.501 §5.4.1.3",
            ),
            mm(
                &[RegistrationInitiated, Authenticating],
                SecurityModeCompleted,
                SecurityMode,
                "24.501 §5.4.2.3",
            ),
            mm(
                &[
                    RegistrationInitiated,
                    Authenticating,
                    SecurityMode,
                    Registered(R::NonAllowedService),
                    Registered(R::AttemptingRegistrationUpdate),
                    Registered(R::UpdateNeeded),
                ],
                RegistrationAccepted,
                Registered(R::NormalService),
                "24.501 §5.5.1.2.4, §5.5.1.3.4",
            ),
            mm(
                IN_REGISTRATION,
                RegistrationFailed,
                Deregistered(D::AttemptingRegistration),
                "24.501 §5.5.1.2.7 (initial registration)",
            ),
            mm(
                IN_REGISTRATION,
                RegistrationFailed,
                Registered(R::AttemptingRegistrationUpdate),
                "24.501 §5.5.1.3.7 (registration update)",
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Deregistered(D::NormalService),
                REJECT,
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Deregistered(D::LimitedService),
                REJECT,
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Deregistered(D::AttemptingRegistration),
                REJECT,
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Deregistered(D::PlmnSearch),
                REJECT,
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Deregistered(D::NoSupi),
                REJECT,
            ),
            mm(
                IN_REGISTRATION,
                RegistrationRejected,
                Registered(R::AttemptingRegistrationUpdate),
                "24.501 §5.5.1.3.5 (#22 and other causes of an update: sessions kept)",
            ),
            mm(
                NOT_DEREGISTERED,
                AuthenticationAborted,
                Deregistered(D::AttemptingRegistration),
                "ferrite: T3520 expiry counted as a failed attempt (24.501 §5.4.1.3.7 c)",
            ),
            mm(
                IN_REGISTRATION,
                AuthenticationAborted,
                Registered(R::AttemptingRegistrationUpdate),
                "ferrite: T3520 expiry counted as a failed attempt (24.501 §5.4.1.3.7 c)",
            ),
            mm(
                NOT_DEREGISTERED,
                AuthenticationRejected,
                Deregistered(D::NoSupi),
                "24.501 §5.4.1.3.5",
            ),
            mm(
                &[
                    Registered(R::NormalService),
                    Registered(R::NonAllowedService),
                    Registered(R::AttemptingRegistrationUpdate),
                ],
                UpdateDue,
                Registered(R::UpdateNeeded),
                "24.501 §5.3.7 (T3512)",
            ),
            // Service request (§5.6.1).
            mm(
                REGISTERED,
                ServiceRequested,
                ServiceRequestInitiated,
                "24.501 §5.6.1.2",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceAccepted,
                Registered(R::NormalService),
                "24.501 §5.6.1.4",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Registered(R::NormalService),
                "24.501 §5.6.1.5",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Registered(R::NonAllowedService),
                "24.501 §5.6.1.5 (#28)",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Deregistered(D::NormalService),
                "24.501 §5.6.1.5 (#9, #10: register afresh)",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Deregistered(D::NoSupi),
                "24.501 §5.6.1.5",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Deregistered(D::PlmnSearch),
                "24.501 §5.6.1.5",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRejected,
                Deregistered(D::LimitedService),
                "24.501 §5.6.1.5",
            ),
            mm(
                &[ServiceRequestInitiated],
                ServiceRequestAbandoned,
                Registered(R::NormalService),
                "24.501 §5.6.1.7 (T3517 expiry, lower-layer release)",
            ),
            // Deregistration (§5.5.2).
            mm(
                &[
                    Registered(R::NormalService),
                    Registered(R::NonAllowedService),
                    Registered(R::AttemptingRegistrationUpdate),
                    Registered(R::UpdateNeeded),
                    ServiceRequestInitiated,
                ],
                DeregistrationRequested,
                DeregistrationInitiated,
                "24.501 §5.5.2.2.1",
            ),
            mm(
                &[
                    Registered(R::NormalService),
                    Registered(R::NonAllowedService),
                    Registered(R::AttemptingRegistrationUpdate),
                    Registered(R::UpdateNeeded),
                    ServiceRequestInitiated,
                ],
                SwitchOff,
                Deregistered(D::NormalService),
                "24.501 §5.5.2.2.1 (switch off)",
            ),
            mm(
                &[DeregistrationInitiated],
                DeregistrationAccepted,
                Deregistered(D::NormalService),
                "24.501 §5.5.2.2.2",
            ),
            mm(
                &[DeregistrationInitiated],
                DeregistrationAbandoned,
                Deregistered(D::NormalService),
                "24.501 §5.5.2.2.6 (T3521 fifth expiry)",
            ),
            mm(
                NOT_DEREGISTERED,
                NetworkDeregistration,
                Deregistered(D::NormalService),
                "24.501 §5.5.2.3.2",
            ),
            mm(
                NOT_DEREGISTERED,
                NetworkDeregistration,
                Deregistered(D::AttemptingRegistration),
                "24.501 §5.5.2.3.2 (cause)",
            ),
            mm(
                NOT_DEREGISTERED,
                NetworkDeregistration,
                Deregistered(D::LimitedService),
                "24.501 §5.5.2.3.2 (cause)",
            ),
            mm(
                NOT_DEREGISTERED,
                NetworkDeregistration,
                Deregistered(D::PlmnSearch),
                "24.501 §5.5.2.3.2 (cause)",
            ),
            mm(
                NOT_DEREGISTERED,
                NetworkDeregistration,
                Deregistered(D::NoSupi),
                "24.501 §5.5.2.3.2 (cause)",
            ),
        ]
    };
    fn kind(s: &MmState) -> MmState {
        *s
    }
}

impl Machine for CmMachine {
    const NAME: &'static str = "5GMM-CM";
    type State = CmState;
    type Kind = CmState;
    type Event = CmTrigger;
    const KINDS: &'static [CmState] = &[CmState::Idle, CmState::Connected];
    const EVENTS: &'static [CmTrigger] = &[
        CmTrigger::ConnectionEstablished,
        CmTrigger::ConnectionReleased,
    ];
    const INITIAL: CmState = CmState::Idle;
    const RULES: &'static [Rule<CmState, CmTrigger>] = &[
        Rule {
            from: &[CmState::Idle],
            event: CmTrigger::ConnectionEstablished,
            to: CmState::Connected,
            clause: "24.501 §5.3.1.1",
        },
        Rule {
            from: &[CmState::Connected],
            event: CmTrigger::ConnectionReleased,
            to: CmState::Idle,
            clause: "24.501 §5.3.1.3",
        },
    ];
    fn kind(s: &CmState) -> CmState {
        *s
    }
}

const fn sm(
    from: &'static [SmState],
    event: SmTrigger,
    to: SmState,
    clause: &'static str,
) -> Rule<SmState, SmTrigger> {
    Rule {
        from,
        event,
        to,
        clause,
    }
}

impl Machine for SmMachine {
    const NAME: &'static str = "5GSM";
    type State = SmState;
    type Kind = SmState;
    type Event = SmTrigger;
    const KINDS: &'static [SmState] = &[
        SmState::Inactive,
        SmState::ActivePending,
        SmState::Active,
        SmState::InactivePending,
    ];
    const EVENTS: &'static [SmTrigger] = &[
        SmTrigger::EstablishmentRequested,
        SmTrigger::EstablishmentAccepted,
        SmTrigger::EstablishmentRejected,
        SmTrigger::EstablishmentAbandoned,
        SmTrigger::ReleaseRequested,
        SmTrigger::ReleaseRejected,
        SmTrigger::ReleaseAbandoned,
        SmTrigger::NetworkRelease,
        SmTrigger::StatusSync,
        SmTrigger::LocalRelease,
    ];
    const INITIAL: SmState = SmState::Inactive;
    const RULES: &'static [Rule<SmState, SmTrigger>] = {
        use SmState::*;
        use SmTrigger::*;
        &[
            sm(
                &[Inactive],
                EstablishmentRequested,
                ActivePending,
                "24.501 §6.4.1.2",
            ),
            sm(
                &[ActivePending],
                EstablishmentAccepted,
                Active,
                "24.501 §6.4.1.3",
            ),
            sm(
                &[ActivePending],
                EstablishmentRejected,
                Inactive,
                "24.501 §6.4.1.4, §5.4.5.3.3 (5GMM cause)",
            ),
            sm(
                &[ActivePending],
                EstablishmentAbandoned,
                Inactive,
                "24.501 §6.4.1.6 (T3580 fifth expiry)",
            ),
            sm(
                &[Active],
                ReleaseRequested,
                InactivePending,
                "24.501 §6.4.3.2",
            ),
            sm(
                &[InactivePending],
                ReleaseRejected,
                Active,
                "24.501 §6.4.3.4",
            ),
            sm(
                &[InactivePending],
                ReleaseAbandoned,
                Inactive,
                "24.501 §6.4.3.5 (T3582 fifth expiry)",
            ),
            sm(
                &[ActivePending, Active, InactivePending],
                NetworkRelease,
                Inactive,
                "24.501 §6.3.3.3",
            ),
            sm(
                &[Active],
                StatusSync,
                Inactive,
                "24.501 §5.6.1.4, §5.5.1.2.4 (PDU session status)",
            ),
            sm(
                &[ActivePending, Active, InactivePending],
                LocalRelease,
                Inactive,
                "24.501 §5.5.2.2.2, §5.5.2.3.2 (local release on deregistration)",
            ),
        ]
    };
    fn kind(s: &SmState) -> SmState {
        *s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::fsm;

    #[test]
    fn tables_are_well_formed() {
        assert_eq!(fsm::check::<MmMachine>(), Ok(()));
        assert_eq!(fsm::check::<CmMachine>(), Ok(()));
        assert_eq!(fsm::check::<SmMachine>(), Ok(()));
    }

    /// No 5GMM state is a trap: every one can reach 5GMM-DEREGISTERED and
    /// 5GMM-REGISTERED.NORMAL-SERVICE except where the specification bars
    /// registration until switch off or a new PLMN / TA (NO-SUPI, PLMN
    /// SEARCH, LIMITED SERVICE).
    #[test]
    fn registration_is_reachable_unless_barred() {
        let reaches = |from: MmState, target: MmState| {
            let mut seen = vec![from];
            let mut i = 0;
            while let Some(&k) = seen.get(i) {
                for (f, _, t) in fsm::edges::<MmMachine>() {
                    if f == k && !seen.contains(&t) {
                        seen.push(t);
                    }
                }
                i += 1;
            }
            seen.contains(&target)
        };
        for &k in MM_KINDS {
            let barred = matches!(
                k,
                Deregistered(D::NoSupi | D::PlmnSearch | D::LimitedService)
            );
            assert_eq!(reaches(k, Registered(R::NormalService)), !barred, "{k:?}");
            assert!(
                reaches(k, Deregistered(D::NormalService)) || barred,
                "{k:?}"
            );
        }
    }
}
