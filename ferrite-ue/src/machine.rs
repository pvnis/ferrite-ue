//! The stack's own state machines (see [`ferrite_common::fsm`]): the AS
//! security context the stack holds for the bearers ([`SecMachine`]) and
//! the connection lifecycle it drives ([`ConnMachine`]).

use ferrite_common::fsm::{Machine, Rule};
use ferrite_rrc::AsSecurity;

/// The AS security context (TS 33.501 §6.7, TS 38.331 §5.3.4 / §5.3.7).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SecState {
    /// No AS security (before the SecurityModeCommand, after release).
    #[default]
    Inactive,
    /// Keys verified and installed on the bearers.
    Active(AsSecurity),
    /// Re-establishment: the old keys are dropped, the refreshed ones not yet
    /// verified (SRB1 carries the RRCReestablishment unprotected meanwhile).
    Suspended,
}

// Keys never go to a log: only the phase is printed.
impl std::fmt::Debug for SecState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", SecMachine::kind(self))
    }
}

/// [`SecState`] without the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecPhase {
    Inactive,
    Active,
    Suspended,
}

/// What moves the AS security context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecTrigger {
    /// The SecurityModeCommand's MAC-I verified with K_RRCint.
    SmcVerified,
    /// RRC re-establishment started.
    Reestablishing,
    /// The RRCReestablishment's MAC-I verified with the refreshed keys.
    ReestablishmentVerified,
    /// RRC release, connection failure or a failed re-establishment.
    ConnectionEnded,
}

/// The AS security machine.
pub struct SecMachine;

impl Machine for SecMachine {
    const NAME: &'static str = "AS security";
    type State = SecState;
    type Kind = SecPhase;
    type Event = SecTrigger;
    const KINDS: &'static [SecPhase] = &[SecPhase::Inactive, SecPhase::Active, SecPhase::Suspended];
    const EVENTS: &'static [SecTrigger] = &[
        SecTrigger::SmcVerified,
        SecTrigger::Reestablishing,
        SecTrigger::ReestablishmentVerified,
        SecTrigger::ConnectionEnded,
    ];
    const INITIAL: SecPhase = SecPhase::Inactive;
    const RULES: &'static [Rule<SecPhase, SecTrigger>] = {
        use SecPhase::*;
        use SecTrigger::*;
        &[
            Rule {
                from: &[Inactive],
                event: SmcVerified,
                to: Active,
                clause: "38.331 §5.3.4.3",
            },
            Rule {
                from: &[Active],
                event: Reestablishing,
                to: Suspended,
                clause: "38.331 §5.3.7.4 (re-establish PDCP of SRB1, suspend the others)",
            },
            Rule {
                from: &[Suspended],
                event: ReestablishmentVerified,
                to: Active,
                clause: "38.331 §5.3.7.5 (K_NG-RAN*: refreshed keys)",
            },
            Rule {
                from: &[Active, Suspended],
                event: ConnectionEnded,
                to: Inactive,
                clause: "38.331 §5.3.11 (going to RRC_IDLE: discard the AS keys)",
            },
        ]
    };
    fn kind(s: &SecState) -> SecPhase {
        match s {
            SecState::Inactive => SecPhase::Inactive,
            SecState::Active(_) => SecPhase::Active,
            SecState::Suspended => SecPhase::Suspended,
        }
    }
}

/// The connection lifecycle the stack drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPhase {
    /// No cell configured yet.
    NotStarted,
    /// An RRC connection is being established.
    Connecting,
    Connected,
    /// RRC_IDLE: the NAS decides when to connect again (a registration
    /// retry on T3511 / T3502, a service request).
    Idle,
}

/// What moves the connection lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnTrigger {
    /// RRC connection request (registration, service request, a NAS
    /// signalling connection).
    Connect,
    /// RRCSetup completed (or re-establishment succeeded).
    Established,
    /// RRCRelease.
    Released,
    /// Establishment or the connection failed (random access, T300, RLF
    /// without re-establishment, a failed re-establishment).
    Failed,
}

/// The connection machine.
pub struct ConnMachine;

impl Machine for ConnMachine {
    const NAME: &'static str = "Connection";
    type State = ConnPhase;
    type Kind = ConnPhase;
    type Event = ConnTrigger;
    const KINDS: &'static [ConnPhase] = &[
        ConnPhase::NotStarted,
        ConnPhase::Connecting,
        ConnPhase::Connected,
        ConnPhase::Idle,
    ];
    const EVENTS: &'static [ConnTrigger] = &[
        ConnTrigger::Connect,
        ConnTrigger::Established,
        ConnTrigger::Released,
        ConnTrigger::Failed,
    ];
    const INITIAL: ConnPhase = ConnPhase::NotStarted;
    const RULES: &'static [Rule<ConnPhase, ConnTrigger>] = {
        use ConnPhase::*;
        use ConnTrigger::*;
        &[
            Rule {
                from: &[NotStarted, Idle],
                event: Connect,
                to: Connecting,
                clause: "38.331 §5.3.3.2 (upper layers request an RRC connection)",
            },
            Rule {
                from: &[Connecting],
                event: Established,
                to: Connected,
                clause: "38.331 §5.3.3.4",
            },
            Rule {
                from: &[Connected],
                event: Released,
                to: Idle,
                clause: "38.331 §5.3.8.3",
            },
            Rule {
                from: &[Connecting, Connected],
                event: Failed,
                to: Idle,
                clause: "38.331 §5.3.3.7, §5.3.7.7 (failure reported to the NAS: 24.501 §5.5.1.2.7, §5.6.1.7)",
            },
        ]
    };
    fn kind(s: &ConnPhase) -> ConnPhase {
        *s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::fsm::check;

    #[test]
    fn tables_are_well_formed() {
        assert_eq!(check::<SecMachine>(), Ok(()));
        assert_eq!(check::<ConnMachine>(), Ok(()));
    }
}
