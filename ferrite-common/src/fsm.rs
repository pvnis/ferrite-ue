//! Declared state machines.
//!
//! Every protocol state machine in Ferrite states its transitions as data: a
//! [`Machine`] lists its states, its events and a table of [`Rule`]s
//! `(from, event) → to`, each with the specification clause it implements.
//! The entity keeps its state in an [`Fsm`], and the only way to change it is
//! [`Fsm::transition`], which checks the move against the table. A move the
//! table does not allow is refused (the state stays as it was), counted, and
//! returned as a [`Violation`] for the caller to log: it is a bug in the
//! entity or in the table, never something to panic over.
//!
//! The table is what one reviews against the specification and what the
//! checks run on: [`check`] (well-formedness and reachability, run by each
//! machine's unit tests), [`mermaid`] (the diagram in the architecture
//! document), and the Kani harnesses that prove an entity only ever moves
//! along its table.
//!
//! A state may carry data (a deadline, an RNTI); the table is written over its
//! fieldless [`Machine::kind`], so the rules stay finite and enumerable.

use core::fmt;

/// One allowed transition: on `event` in `from`, the machine may enter `to`.
/// Several rules may share `(from, event)` when a guard in the entity picks
/// the target (e.g. RLF with or without AS security).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule<K, E> {
    pub from: K,
    pub event: E,
    pub to: K,
    /// Where the transition comes from, e.g. `"38.331 §5.3.3.4"`; a
    /// deliberate deviation says so (`"ferrite: …"`).
    pub clause: &'static str,
}

/// A state machine's declaration.
pub trait Machine: 'static {
    /// Short name used in logs (`"RRC"`, `"RA"`).
    const NAME: &'static str;
    /// The full state, possibly carrying data.
    type State: Clone + fmt::Debug;
    /// The state's fieldless kind, over which the table is written.
    type Kind: Copy + Eq + fmt::Debug + 'static;
    /// What triggers a transition.
    type Event: Copy + Eq + fmt::Debug + 'static;
    /// Every kind, for the checks.
    const KINDS: &'static [Self::Kind];
    /// Every event, for the checks.
    const EVENTS: &'static [Self::Event];
    /// The kind a new machine starts in.
    const INITIAL: Self::Kind;
    /// The transition table.
    const RULES: &'static [Rule<Self::Kind, Self::Event>];
    fn kind(state: &Self::State) -> Self::Kind;
}

/// The rule allowing `from → to` on `event`, if any.
pub fn rule<M: Machine>(
    from: M::Kind,
    event: M::Event,
    to: M::Kind,
) -> Option<&'static Rule<M::Kind, M::Event>> {
    M::RULES
        .iter()
        .find(|r| r.from == from && r.event == event && r.to == to)
}

/// A transition that was made.
pub struct Transition<M: Machine> {
    pub from: M::Kind,
    pub event: M::Event,
    pub to: M::Kind,
    pub clause: &'static str,
}

// Hand-written impls: derives would bound the marker type `M` itself.
impl<M: Machine> Clone for Transition<M> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M: Machine> Copy for Transition<M> {}
impl<M: Machine> fmt::Debug for Transition<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<M: Machine> fmt::Display for Transition<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?} → {:?} on {:?} [{}]",
            M::NAME,
            self.from,
            self.to,
            self.event,
            self.clause
        )
    }
}

/// A transition the table does not allow (refused; the state is unchanged).
pub struct Violation<M: Machine> {
    pub from: M::Kind,
    pub event: M::Event,
    pub to: M::Kind,
}

impl<M: Machine> Clone for Violation<M> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M: Machine> Copy for Violation<M> {}
impl<M: Machine> PartialEq for Violation<M> {
    fn eq(&self, o: &Self) -> bool {
        self.from == o.from && self.event == o.event && self.to == o.to
    }
}
impl<M: Machine> fmt::Debug for Violation<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<M: Machine> fmt::Display for Violation<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?} → {:?} on {:?} is not in the transition table (refused)",
            M::NAME,
            self.from,
            self.to,
            self.event
        )
    }
}

/// Transition counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsmStats {
    pub transitions: u64,
    pub violations: u64,
}

/// A machine's current state, changed only through [`Fsm::transition`].
pub struct Fsm<M: Machine> {
    state: M::State,
    stats: FsmStats,
}

impl<M: Machine> Clone for Fsm<M> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            stats: self.stats,
        }
    }
}
impl<M: Machine> fmt::Debug for Fsm<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({:?})", M::NAME, self.state)
    }
}

impl<M: Machine> Fsm<M> {
    /// Start in `state`, whose kind must be [`Machine::INITIAL`] (otherwise
    /// the machine starts in a state the table cannot reach; [`Fsm::new`]
    /// still accepts it, and [`Fsm::stats`] counts it as a violation).
    pub fn new(state: M::State) -> Self {
        let violations = u64::from(M::kind(&state) != M::INITIAL);
        Self {
            state,
            stats: FsmStats {
                transitions: 0,
                violations,
            },
        }
    }

    /// A machine already in `state`, without a counted violation: for
    /// model-checking harnesses that start from an arbitrary state (an
    /// inductive step) instead of replaying a path to it.
    #[cfg(kani)]
    pub fn assume_in(state: M::State) -> Self {
        Self {
            state,
            stats: FsmStats::default(),
        }
    }

    pub fn state(&self) -> &M::State {
        &self.state
    }

    pub fn kind(&self) -> M::Kind {
        M::kind(&self.state)
    }

    pub fn stats(&self) -> FsmStats {
        self.stats
    }

    /// Enter `to` on `event` if the table allows it.
    pub fn transition(
        &mut self,
        event: M::Event,
        to: M::State,
    ) -> Result<Transition<M>, Violation<M>> {
        let from = M::kind(&self.state);
        let to_kind = M::kind(&to);
        match rule::<M>(from, event, to_kind) {
            Some(r) => {
                self.state = to;
                self.stats.transitions += 1;
                Ok(Transition {
                    from,
                    event,
                    to: to_kind,
                    clause: r.clause,
                })
            }
            None => {
                self.stats.violations += 1;
                Err(Violation {
                    from,
                    event,
                    to: to_kind,
                })
            }
        }
    }

    /// Replace the data of the current state without changing its kind
    /// (e.g. a new deadline); refused (`false`) if the kind would change.
    pub fn update(&mut self, state: M::State) -> bool {
        if M::kind(&state) == M::kind(&self.state) {
            self.state = state;
            true
        } else {
            self.stats.violations += 1;
            false
        }
    }
}

/// The kinds reachable from [`Machine::INITIAL`] through the table.
pub fn reachable<M: Machine>() -> Vec<M::Kind> {
    let mut seen = vec![M::INITIAL];
    let mut i = 0;
    while let Some(&k) = seen.get(i) {
        for r in M::RULES.iter().filter(|r| r.from == k) {
            if !seen.contains(&r.to) {
                seen.push(r.to);
            }
        }
        i += 1;
    }
    seen
}

/// Well-formedness of a machine's table: every rule uses listed kinds and
/// events, no rule is a self-loop or a duplicate, every rule names its
/// clause, every event is used, and every kind is reachable from the
/// initial one. Returns every problem found.
pub fn check<M: Machine>() -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if !M::KINDS.contains(&M::INITIAL) {
        problems.push(format!("initial {:?} not listed", M::INITIAL));
    }
    for (i, r) in M::RULES.iter().enumerate() {
        if !M::KINDS.contains(&r.from) || !M::KINDS.contains(&r.to) {
            problems.push(format!("rule {i} uses an unlisted kind: {r:?}"));
        }
        if !M::EVENTS.contains(&r.event) {
            problems.push(format!("rule {i} uses an unlisted event: {r:?}"));
        }
        if r.from == r.to {
            problems.push(format!("rule {i} is a self-loop: {r:?}"));
        }
        if r.clause.is_empty() {
            problems.push(format!("rule {i} has no clause: {r:?}"));
        }
        if M::RULES[..i]
            .iter()
            .any(|p| p.from == r.from && p.event == r.event && p.to == r.to)
        {
            problems.push(format!("rule {i} duplicates an earlier one: {r:?}"));
        }
    }
    for e in M::EVENTS {
        if !M::RULES.iter().any(|r| r.event == *e) {
            problems.push(format!("event {e:?} triggers no transition"));
        }
    }
    let seen = reachable::<M>();
    for k in M::KINDS {
        if !seen.contains(k) {
            problems.push(format!("{k:?} is unreachable from {:?}", M::INITIAL));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// The table as a Mermaid state diagram.
pub fn mermaid<M: Machine>() -> String {
    let mut out = format!("stateDiagram-v2\n    [*] --> {:?}\n", M::INITIAL);
    for r in M::RULES {
        out.push_str(&format!("    {:?} --> {:?}: {:?}\n", r.from, r.to, r.event));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Light {
        Off,
        On,
        Broken,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Ev {
        Switch,
        Fail,
    }
    struct Lamp;
    impl Machine for Lamp {
        const NAME: &'static str = "LAMP";
        type State = (Light, u8);
        type Kind = Light;
        type Event = Ev;
        const KINDS: &'static [Light] = &[Light::Off, Light::On, Light::Broken];
        const EVENTS: &'static [Ev] = &[Ev::Switch, Ev::Fail];
        const INITIAL: Light = Light::Off;
        const RULES: &'static [Rule<Light, Ev>] = &[
            Rule {
                from: Light::Off,
                event: Ev::Switch,
                to: Light::On,
                clause: "a",
            },
            Rule {
                from: Light::On,
                event: Ev::Switch,
                to: Light::Off,
                clause: "b",
            },
            Rule {
                from: Light::On,
                event: Ev::Fail,
                to: Light::Broken,
                clause: "c",
            },
        ];
        fn kind(s: &(Light, u8)) -> Light {
            s.0
        }
    }

    #[test]
    fn transitions_follow_the_table() {
        assert_eq!(check::<Lamp>(), Ok(()));
        let mut f = Fsm::<Lamp>::new((Light::Off, 0));
        let t = f.transition(Ev::Switch, (Light::On, 1)).unwrap();
        assert_eq!(t.to_string(), "LAMP Off → On on Switch [a]");
        // Not in the table: refused, state kept, counted.
        let v = f.transition(Ev::Switch, (Light::Broken, 2)).unwrap_err();
        assert_eq!(v.from, Light::On);
        assert_eq!(*f.state(), (Light::On, 1));
        assert!(f.update((Light::On, 5)));
        assert!(!f.update((Light::Off, 5)));
        assert_eq!(
            f.stats(),
            FsmStats {
                transitions: 1,
                violations: 2
            }
        );
        assert!(mermaid::<Lamp>().contains("On --> Broken: Fail"));
    }

    struct Bad;
    impl Machine for Bad {
        const NAME: &'static str = "BAD";
        type State = Light;
        type Kind = Light;
        type Event = Ev;
        const KINDS: &'static [Light] = &[Light::Off, Light::On, Light::Broken];
        const EVENTS: &'static [Ev] = &[Ev::Switch, Ev::Fail];
        const INITIAL: Light = Light::Off;
        const RULES: &'static [Rule<Light, Ev>] = &[
            Rule {
                from: Light::Off,
                event: Ev::Switch,
                to: Light::Off,
                clause: "",
            },
            Rule {
                from: Light::Off,
                event: Ev::Switch,
                to: Light::On,
                clause: "x",
            },
            Rule {
                from: Light::Off,
                event: Ev::Switch,
                to: Light::On,
                clause: "x",
            },
        ];
        fn kind(s: &Light) -> Light {
            *s
        }
    }

    #[test]
    fn check_reports_every_problem() {
        let p = check::<Bad>().unwrap_err();
        let has = |s: &str| p.iter().any(|m| m.contains(s));
        assert!(has("self-loop"), "{p:?}");
        assert!(has("no clause"), "{p:?}");
        assert!(has("duplicates"), "{p:?}");
        assert!(has("Fail triggers no transition"), "{p:?}");
        assert!(has("Broken is unreachable"), "{p:?}");
    }
}
