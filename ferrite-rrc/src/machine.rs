//! The RRC state machine's declaration (see [`ferrite_common::fsm`]): the
//! triggers and the transition table [`RrcUe`](crate::RrcUe) is held to.
//!
//! Timers belong to states: T300 runs only in `Connecting`, T301 only in
//! `Reestablishing`, T310 only in `Connected` (and stops on any state
//! change). The entity clears them when it leaves their state.

use crate::RrcState;
use ferrite_common::fsm::{Machine, Rule};

/// What moves the RRC state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RrcTrigger {
    /// NAS asked for a connection: RRCSetupRequest, T300 started.
    Connect,
    /// RRCSetup received in response to RRCSetupRequest.
    RrcSetup,
    /// RRCReject received.
    RrcReject,
    T300Expiry,
    /// MAC reported a random access problem.
    RaFailure,
    /// RRCRelease received.
    Release,
    /// Radio link failure: T310 expiry, a random access problem or RLC
    /// maximum retransmissions while connected.
    RadioLinkFailure,
    /// RRCReestablishment received and its MAC-I verified with the new keys.
    ReestablishmentVerified,
    /// RRCReestablishment failed its integrity check, or arrived without a
    /// security context to derive the new keys from.
    ReestablishmentFailure,
    /// RRCSetup received in response to RRCReestablishmentRequest.
    RrcSetupFallback,
    T301Expiry,
}

/// The RRC machine.
pub struct RrcMachine;

const fn r(
    from: &'static [RrcState],
    event: RrcTrigger,
    to: RrcState,
    clause: &'static str,
) -> Rule<RrcState, RrcTrigger> {
    Rule {
        from,
        event,
        to,
        clause,
    }
}

use RrcState::{Connected, Connecting, Idle, Reestablishing};
use RrcTrigger::*;

impl Machine for RrcMachine {
    const NAME: &'static str = "RRC";
    type State = RrcState;
    type Kind = RrcState;
    type Event = RrcTrigger;
    const KINDS: &'static [RrcState] = &[Idle, Connecting, Connected, Reestablishing];
    const EVENTS: &'static [RrcTrigger] = &[
        Connect,
        RrcSetup,
        RrcReject,
        T300Expiry,
        RaFailure,
        Release,
        RadioLinkFailure,
        ReestablishmentVerified,
        ReestablishmentFailure,
        RrcSetupFallback,
        T301Expiry,
    ];
    const INITIAL: RrcState = Idle;
    const RULES: &'static [Rule<RrcState, RrcTrigger>] = &[
        // Connection establishment (§5.3.3).
        r(&[Idle], Connect, Connecting, "38.331 §5.3.3.2"),
        r(&[Connecting], RrcSetup, Connected, "38.331 §5.3.3.4"),
        r(&[Connecting], RrcReject, Idle, "38.331 §5.3.15"),
        r(&[Connecting], T300Expiry, Idle, "38.331 §5.3.3.7"),
        r(
            &[Connecting],
            RaFailure,
            Idle,
            "ferrite: attempt ended at the MAC's RA problem (38.321 §5.1.4); 38.331 keeps T300 running",
        ),
        // Release (§5.3.8).
        r(&[Connected], Release, Idle, "38.331 §5.3.8.3"),
        // Radio link failure (§5.3.10.3): re-establish with AS security,
        // otherwise go to RRC_IDLE.
        r(
            &[Connected],
            RadioLinkFailure,
            Reestablishing,
            "38.331 §5.3.10.3, §5.3.7.2 (AS security active)",
        ),
        r(
            &[Connected],
            RadioLinkFailure,
            Idle,
            "38.331 §5.3.10.3 (AS security not active)",
        ),
        // Re-establishment (§5.3.7).
        r(
            &[Reestablishing],
            ReestablishmentVerified,
            Connected,
            "38.331 §5.3.7.5",
        ),
        r(
            &[Reestablishing],
            ReestablishmentFailure,
            Idle,
            "38.331 §5.3.7.5 (integrity check failed)",
        ),
        r(&[Reestablishing], T301Expiry, Idle, "38.331 §5.3.7 (T301 expiry)"),
        r(&[Reestablishing], RrcReject, Idle, "38.331 §5.3.15"),
        r(
            &[Reestablishing],
            RrcSetupFallback,
            Idle,
            "ferrite: abort and reconnect; 38.331 §5.3.3.4 continues with the RRCSetup",
        ),
        r(
            &[Reestablishing],
            RaFailure,
            Idle,
            "ferrite: attempt ended at the MAC's RA problem (38.321 §5.1.4); 38.331 keeps T301 running",
        ),
    ];
    fn kind(s: &RrcState) -> RrcState {
        *s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::fsm;

    #[test]
    fn table_is_well_formed() {
        assert_eq!(fsm::check::<RrcMachine>(), Ok(()));
    }

    /// No state is a trap: every non-idle state can return to Idle.
    #[test]
    fn every_state_can_return_to_idle() {
        for k in RrcMachine::KINDS.iter().filter(|k| **k != Idle) {
            assert!(
                RrcMachine::RULES
                    .iter()
                    .any(|r| r.from.contains(k) && r.to == Idle),
                "{k:?} has no way back to Idle"
            );
        }
    }

    #[test]
    fn diagram_lists_every_rule() {
        let d = fsm::mermaid::<RrcMachine>();
        assert_eq!(d.lines().count(), 2 + fsm::edges::<RrcMachine>().len());
    }
}
