//! Discontinuous reception (TS 38.321 §5.7).
//!
//! The MAC entity is in *Active Time* while any of drx-onDurationTimer,
//! drx-InactivityTimer, drx-RetransmissionTimerDL/UL or
//! ra-ContentionResolutionTimer runs, or a scheduling request sent on PUCCH is
//! pending. Outside Active Time it does not monitor the PDCCH for the C-RNTI
//! and sends no periodic CSI or SRS; HARQ-ACKs are sent regardless.
//!
//! ```text
//!  Off ──DRX-Config──▶ Long ◀──drx-ShortCycleTimer expiry / Long DRX Command── Short
//!                      Long ──drx-InactivityTimer expiry / DRX Command (short DRX configured)──▶ Short
//!  on-duration: starts at [(SFN×10)+subframe] mod cycle = offset (+ drx-SlotOffset)
//!  inactivity:  (re)started by every PDCCH addressed to the C-RNTI (see `on_crnti_pdcch`)
//!  HARQ RTT → retransmission timer per HARQ process (DL: only when the TB was not decoded)
//! ```

use ferrite_common::SlotPoint;
use std::collections::BTreeMap;

/// `shortDRX`: cycle length and `drx-ShortCycleTimer` (in short cycles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortDrxMacConfig {
    pub cycle_ms: u32,
    pub timer_cycles: u32,
}

/// `DRX-Config` as the MAC entity uses it: durations in slots at the serving
/// numerology, except the HARQ RTT timers (symbols, as signalled) and the
/// cycle lengths / start offset (ms, matched against `(SFN × 10) + subframe`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrxMacConfig {
    pub on_duration_slots: u32,
    /// `drx-InactivityTimer` (0 = no inactivity extension).
    pub inactivity_slots: u32,
    pub harq_rtt_dl_symbols: u8,
    pub harq_rtt_ul_symbols: u8,
    /// `drx-RetransmissionTimerDL/UL` (0 = not used).
    pub retx_dl_slots: u32,
    pub retx_ul_slots: u32,
    pub long_cycle_ms: u32,
    pub start_offset_ms: u32,
    /// `drx-SlotOffset` converted to slots (its 1/32 ms resolution is below a slot).
    pub slot_offset_slots: u32,
    pub short: Option<ShortDrxMacConfig>,
}

/// Which DRX cycle the entity follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrxState {
    /// No DRX configured: always in Active Time.
    Off,
    /// The long DRX cycle.
    Long,
    /// The short DRX cycle, until `drx-ShortCycleTimer` expires at `until`.
    Short { until: SlotPoint },
}

/// [`DrxState`] without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrxPhase {
    Off,
    Long,
    Short,
}

/// What moves the DRX cycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrxTrigger {
    /// DRX configured or released, or MAC reset.
    Configure,
    /// drx-InactivityTimer expiry.
    InactivityExpiry,
    /// drx-ShortCycleTimer expiry.
    ShortCycleExpiry,
    /// DRX Command MAC CE.
    DrxCommand,
    /// Long DRX Command MAC CE.
    LongDrxCommand,
}

/// The DRX cycle machine.
pub struct DrxMachine;

impl ferrite_common::fsm::Machine for DrxMachine {
    const NAME: &'static str = "DRX";
    type State = DrxState;
    type Kind = DrxPhase;
    type Event = DrxTrigger;
    const KINDS: &'static [DrxPhase] = &[DrxPhase::Off, DrxPhase::Long, DrxPhase::Short];
    const EVENTS: &'static [DrxTrigger] = &[
        DrxTrigger::Configure,
        DrxTrigger::InactivityExpiry,
        DrxTrigger::ShortCycleExpiry,
        DrxTrigger::DrxCommand,
        DrxTrigger::LongDrxCommand,
    ];
    const INITIAL: DrxPhase = DrxPhase::Off;
    const RULES: &'static [ferrite_common::fsm::Rule<DrxPhase, DrxTrigger>] = {
        use ferrite_common::fsm::Rule;
        use DrxPhase::*;
        use DrxTrigger::*;
        &[
            Rule {
                from: &[Off, Short],
                event: Configure,
                to: Long,
                clause: "38.321 §5.7 (DRX configured), §5.12",
            },
            Rule {
                from: &[Long, Short],
                event: Configure,
                to: Off,
                clause: "38.331 §5.3.5.5 (DRX released)",
            },
            Rule {
                from: &[Long],
                event: InactivityExpiry,
                to: Short,
                clause: "38.321 §5.7 (short cycle configured)",
            },
            Rule {
                from: &[Short],
                event: InactivityExpiry,
                to: Long,
                clause: "38.321 §5.7 (no short cycle)",
            },
            Rule {
                from: &[Short],
                event: ShortCycleExpiry,
                to: Long,
                clause: "38.321 §5.7",
            },
            Rule {
                from: &[Long],
                event: DrxCommand,
                to: Short,
                clause: "38.321 §5.7 (DRX Command, short cycle configured)",
            },
            Rule {
                from: &[Short],
                event: DrxCommand,
                to: Long,
                clause: "38.321 §5.7 (DRX Command, no short cycle)",
            },
            Rule {
                from: &[Short],
                event: LongDrxCommand,
                to: Long,
                clause: "38.321 §5.7 (Long DRX Command)",
            },
        ]
    };
    fn kind(s: &DrxState) -> DrxPhase {
        match s {
            DrxState::Off => DrxPhase::Off,
            DrxState::Long => DrxPhase::Long,
            DrxState::Short { .. } => DrxPhase::Short,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct HarqTimers {
    /// drx-HARQ-RTT-Timer expiry (the retransmission timer starts then).
    rtt_until: SlotPoint,
    /// drx-RetransmissionTimer expiry once started.
    retx_until: Option<SlotPoint>,
}

/// The DRX procedure of one MAC entity.
pub struct Drx {
    cfg: Option<DrxMacConfig>,
    state: ferrite_common::fsm::Fsm<DrxMachine>,
    on_duration_until: Option<SlotPoint>,
    inactivity_until: Option<SlotPoint>,
    dl: BTreeMap<u8, HarqTimers>,
    ul: BTreeMap<u8, HarqTimers>,
    active: bool,
}

/// `until` is exclusive: a timer set to `now + n` covers `n` slots from `now`.
fn running(t: Option<SlotPoint>, now: SlotPoint) -> bool {
    t.is_some_and(|u| now.diff(&u) < 0)
}

impl Drx {
    pub fn new(cfg: Option<DrxMacConfig>) -> Self {
        let mut d = Self {
            cfg: None,
            state: ferrite_common::fsm::Fsm::new(DrxState::Off),
            on_duration_until: None,
            inactivity_until: None,
            dl: BTreeMap::new(),
            ul: BTreeMap::new(),
            active: true,
        };
        d.configure(cfg);
        d
    }

    /// Apply (or release) a DRX configuration. Timers restart from scratch.
    pub fn configure(&mut self, cfg: Option<DrxMacConfig>) {
        if cfg != self.cfg {
            match &cfg {
                Some(c) => log::info!(
                    "DRX configured: long cycle {} ms offset {} ms, on-duration {} slots, inactivity {} slots, HARQ RTT {}/{} symbols, retx {}/{} slots{}",
                    c.long_cycle_ms,
                    c.start_offset_ms,
                    c.on_duration_slots,
                    c.inactivity_slots,
                    c.harq_rtt_dl_symbols,
                    c.harq_rtt_ul_symbols,
                    c.retx_dl_slots,
                    c.retx_ul_slots,
                    c.short.map_or(String::new(), |s| format!(", short cycle {} ms × {}", s.cycle_ms, s.timer_cycles))
                ),
                None if self.cfg.is_some() => log::info!("DRX released"),
                None => {}
            }
        }
        self.cfg = cfg;
        self.reset();
    }

    /// MAC reset (§5.12): every DRX timer stopped, back to the long cycle.
    pub fn reset(&mut self) {
        let to = if self.cfg.is_some() {
            DrxState::Long
        } else {
            DrxState::Off
        };
        self.go(DrxTrigger::Configure, to);
        self.on_duration_until = None;
        self.inactivity_until = None;
        self.dl.clear();
        self.ul.clear();
        self.active = true;
    }

    pub fn state(&self) -> DrxState {
        *self.state.state()
    }

    /// Transitions made and refused (a refusal is a bug: see [`DrxMachine`]).
    pub fn fsm_stats(&self) -> ferrite_common::fsm::FsmStats {
        self.state.stats()
    }

    fn go(&mut self, trigger: DrxTrigger, to: DrxState) -> bool {
        match self.state.transition(trigger, to) {
            Ok(t) => {
                if let Some(t) = t {
                    log::debug!("{t}");
                }
                true
            }
            Err(v) => {
                log::error!("{v}");
                false
            }
        }
    }

    pub fn configured(&self) -> bool {
        self.cfg.is_some()
    }

    /// Active Time as of the last `on_slot`.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Run the DRX timers for `now` and decide the Active Time of this slot.
    /// `ra_running` covers ra-ContentionResolutionTimer (and the RAR window),
    /// `sr_pending` a scheduling request sent on PUCCH and still pending,
    /// `dl_not_decoded(harq)` whether the DL HARQ process still lacks its TB.
    pub fn on_slot(
        &mut self,
        now: SlotPoint,
        ra_running: bool,
        sr_pending: bool,
        dl_not_decoded: impl Fn(u8) -> bool,
    ) -> bool {
        let Some(cfg) = self.cfg else {
            self.active = true;
            return true;
        };
        // --- timer expiries.
        if self.on_duration_until.is_some() && !running(self.on_duration_until, now) {
            self.on_duration_until = None;
        }
        if self.inactivity_until.is_some() && !running(self.inactivity_until, now) {
            self.inactivity_until = None;
            // §5.7: drx-InactivityTimer expiry → short cycle if configured.
            self.enter_short_cycle(DrxTrigger::InactivityExpiry, now);
        }
        if let DrxState::Short { until } = self.state() {
            if now.diff(&until) >= 0 {
                self.go(DrxTrigger::ShortCycleExpiry, DrxState::Long);
            }
        }
        for (set, is_dl) in [(&mut self.dl, true), (&mut self.ul, false)] {
            set.retain(|&harq, t| {
                match t.retx_until {
                    Some(r) => now.diff(&r) < 0,
                    None if now.diff(&t.rtt_until) >= 0 => {
                        // RTT elapsed: a retransmission may follow (DL: only if
                        // the TB was not decoded; UL: the UE cannot know).
                        let slots = if is_dl {
                            cfg.retx_dl_slots
                        } else {
                            cfg.retx_ul_slots
                        };
                        let start = !is_dl || dl_not_decoded(harq);
                        if start && slots > 0 {
                            t.retx_until = Some(now.add(u64::from(slots)));
                            true
                        } else {
                            false
                        }
                    }
                    None => true,
                }
            });
        }
        // --- cycle start: [(SFN × 10) + subframe] mod cycle = offset.
        let sub = u32::from(now.sfn) * 10 + u32::from(now.subframe());
        let at_start = match self.state() {
            DrxState::Off => false,
            DrxState::Long => {
                sub % cfg.long_cycle_ms.max(1) == cfg.start_offset_ms % cfg.long_cycle_ms.max(1)
            }
            DrxState::Short { .. } => {
                let c = cfg.short.map_or(cfg.long_cycle_ms, |s| s.cycle_ms).max(1);
                sub % c == cfg.start_offset_ms % c
            }
        };
        if at_start && u32::from(now.slot_in_subframe()) == cfg.slot_offset_slots {
            self.on_duration_until = Some(now.add(u64::from(cfg.on_duration_slots.max(1))));
        }
        let retx_running = self
            .dl
            .values()
            .chain(self.ul.values())
            .any(|t| running(t.retx_until, now));
        self.active = running(self.on_duration_until, now)
            || running(self.inactivity_until, now)
            || retx_running
            || ra_running
            || sr_pending;
        self.active
    }

    fn enter_short_cycle(&mut self, trigger: DrxTrigger, now: SlotPoint) {
        let Some(cfg) = self.cfg else { return };
        if let Some(s) = cfg.short {
            let spsf = u64::from(now.numerology.slots_per_subframe());
            self.go(
                trigger,
                DrxState::Short {
                    until: now.add(u64::from(s.cycle_ms) * u64::from(s.timer_cycles) * spsf),
                },
            );
        } else {
            self.go(trigger, DrxState::Long);
        }
    }

    /// A PDCCH addressed to the C-RNTI scheduled a DL or UL transmission:
    /// (re)start drx-InactivityTimer.
    ///
    /// TS 38.321 §5.7 restarts the timer only for a *new* transmission. The
    /// timer is restarted here for retransmission grants as well: a gNB that
    /// does the same (OCUDU's scheduler extends the Active Time on every
    /// allocation) would otherwise schedule the UE after it went to sleep,
    /// and a UE that stays awake a little longer never loses data — the
    /// Active Time implemented is a superset of the specified one.
    pub fn on_crnti_pdcch(&mut self, now: SlotPoint) {
        let Some(cfg) = self.cfg else { return };
        if cfg.inactivity_slots > 0 {
            self.inactivity_until = Some(now.add(u64::from(cfg.inactivity_slots)));
            self.active = true;
        }
    }

    /// Expiry slot of a HARQ RTT timer of `symbols` symbols that starts after
    /// the end of the transmission in `slot` (slot granularity).
    fn rtt_expiry(slot: SlotPoint, symbols: u8) -> SlotPoint {
        slot.add(1 + u64::from(symbols) / 14)
    }

    /// A DL assignment for `harq_id` whose HARQ-ACK goes out in `ack_slot`
    /// (§5.7: drx-HARQ-RTT-TimerDL starts after the feedback; the
    /// retransmission timer stops).
    pub fn on_dl_assignment(&mut self, harq_id: u8, ack_slot: SlotPoint) {
        let Some(cfg) = self.cfg else { return };
        self.dl.insert(
            harq_id,
            HarqTimers {
                rtt_until: Self::rtt_expiry(ack_slot, cfg.harq_rtt_dl_symbols),
                retx_until: None,
            },
        );
    }

    /// An UL grant for `harq_id` whose PUSCH goes out in `pusch_slot`.
    pub fn on_ul_grant(&mut self, harq_id: u8, pusch_slot: SlotPoint) {
        let Some(cfg) = self.cfg else { return };
        self.ul.insert(
            harq_id,
            HarqTimers {
                rtt_until: Self::rtt_expiry(pusch_slot, cfg.harq_rtt_ul_symbols),
                retx_until: None,
            },
        );
    }

    /// DRX Command (`long = false`) / Long DRX Command MAC CE (§5.7, §6.1.3.5/6).
    pub fn on_drx_command(&mut self, now: SlotPoint, long: bool) {
        if self.cfg.is_none() {
            return;
        }
        self.on_duration_until = None;
        self.inactivity_until = None;
        if long {
            self.go(DrxTrigger::LongDrxCommand, DrxState::Long);
        } else {
            self.enter_short_cycle(DrxTrigger::DrxCommand, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_well_formed() {
        assert_eq!(ferrite_common::fsm::check::<DrxMachine>(), Ok(()));
    }
    use ferrite_common::Numerology;

    const MU: Numerology = Numerology::KHZ30;

    fn slot(n: u64) -> SlotPoint {
        SlotPoint::from_index(MU, n)
    }

    fn cfg() -> DrxMacConfig {
        DrxMacConfig {
            on_duration_slots: 4, // 2 ms
            inactivity_slots: 6,
            harq_rtt_dl_symbols: 56, // 4 slots
            harq_rtt_ul_symbols: 0,
            retx_dl_slots: 8,
            retx_ul_slots: 8,
            long_cycle_ms: 80,
            start_offset_ms: 0,
            slot_offset_slots: 0,
            short: None,
        }
    }

    fn tick(d: &mut Drx, n: u64) -> bool {
        d.on_slot(slot(n), false, false, |_| true)
    }

    #[test]
    fn unconfigured_is_always_active() {
        let mut d = Drx::new(None);
        assert_eq!(d.state(), DrxState::Off);
        for n in 0..300 {
            assert!(tick(&mut d, n));
        }
    }

    #[test]
    fn on_duration_at_the_cycle_start() {
        let mut d = Drx::new(Some(cfg()));
        assert_eq!(d.state(), DrxState::Long);
        // 80 ms cycle = 160 slots at 30 kHz; on-duration 4 slots from slot 0.
        let active: Vec<u64> = (0..320).filter(|&n| tick(&mut d, n)).collect();
        assert_eq!(active, vec![0, 1, 2, 3, 160, 161, 162, 163]);
    }

    #[test]
    fn slot_offset_moves_the_on_duration() {
        let mut d = Drx::new(Some(DrxMacConfig {
            slot_offset_slots: 1,
            start_offset_ms: 20,
            ..cfg()
        }));
        let active: Vec<u64> = (0..200).filter(|&n| tick(&mut d, n)).collect();
        // subframe 20 → slot 40, plus one slot offset.
        assert_eq!(active, vec![41, 42, 43, 44]);
    }

    #[test]
    fn crnti_pdcch_extends_active_time_by_the_inactivity_timer() {
        let mut d = Drx::new(Some(cfg()));
        for n in 0..10 {
            tick(&mut d, n);
        }
        assert!(!d.is_active());
        d.on_crnti_pdcch(slot(10));
        let active: Vec<u64> = (10..30).filter(|&n| tick(&mut d, n)).collect();
        assert_eq!(active, vec![10, 11, 12, 13, 14, 15]);
        // A second PDCCH restarts it.
        d.on_crnti_pdcch(slot(30));
        tick(&mut d, 33);
        d.on_crnti_pdcch(slot(33));
        assert!((33..39).all(|n| tick(&mut d, n)));
        assert!(!tick(&mut d, 39));
    }

    #[test]
    fn dl_retransmission_timer_only_for_undecoded_tbs() {
        let mut d = Drx::new(Some(cfg()));
        tick(&mut d, 10);
        // HARQ-ACK (NACK) in slot 20 → RTT (4 slots) ends at 25 → retx timer 25..33.
        d.on_dl_assignment(1, slot(20));
        let active: Vec<u64> = (10..40)
            .filter(|&n| d.on_slot(slot(n), false, false, |_| true))
            .collect();
        assert_eq!(active, (25..33).collect::<Vec<_>>());
        // Decoded TB: no retransmission timer.
        let mut d = Drx::new(Some(cfg()));
        d.on_dl_assignment(2, slot(20));
        assert!(!(10..40).any(|n| d.on_slot(slot(n), false, false, |_| false)));
        // UL: the retransmission timer always follows the RTT.
        let mut d = Drx::new(Some(cfg()));
        d.on_ul_grant(0, slot(20));
        let active: Vec<u64> = (10..40)
            .filter(|&n| d.on_slot(slot(n), false, false, |_| false))
            .collect();
        assert_eq!(active, (21..29).collect::<Vec<_>>());
    }

    #[test]
    fn ra_and_pending_sr_are_active_time() {
        let mut d = Drx::new(Some(cfg()));
        tick(&mut d, 10);
        assert!(!d.is_active());
        assert!(d.on_slot(slot(11), true, false, |_| true));
        assert!(d.on_slot(slot(12), false, true, |_| true));
        assert!(!d.on_slot(slot(13), false, false, |_| true));
    }

    #[test]
    fn drx_command_ends_the_on_duration_and_short_cycle_follows_inactivity() {
        let short = Some(ShortDrxMacConfig {
            cycle_ms: 20,
            timer_cycles: 2,
        });
        let mut d = Drx::new(Some(DrxMacConfig { short, ..cfg() }));
        assert!(tick(&mut d, 0));
        d.on_drx_command(slot(1), false);
        assert!(!tick(&mut d, 1));
        // DRX Command with short DRX configured → short cycle (20 ms = 40
        // slots) for 2 cycles, then back to long.
        assert!(matches!(d.state(), DrxState::Short { .. }));
        let active: Vec<u64> = (1..200).filter(|&n| tick(&mut d, n)).collect();
        assert_eq!(
            active,
            vec![40, 41, 42, 43, 80, 81, 82, 83, 160, 161, 162, 163]
        );
        assert_eq!(d.state(), DrxState::Long);
        // Inactivity expiry also enters the short cycle; Long DRX Command leaves it.
        d.on_crnti_pdcch(slot(200));
        for n in 200..210 {
            tick(&mut d, n);
        }
        assert!(matches!(d.state(), DrxState::Short { .. }));
        d.on_drx_command(slot(210), true);
        assert_eq!(d.state(), DrxState::Long);
    }

    #[test]
    fn reset_and_release() {
        let mut d = Drx::new(Some(cfg()));
        d.on_crnti_pdcch(slot(5));
        d.reset();
        assert!(!tick(&mut d, 6));
        d.configure(None);
        assert_eq!(d.state(), DrxState::Off);
        assert!(tick(&mut d, 7));
    }
}
