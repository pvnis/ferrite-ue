//! Downlink synchronisation tracking: carrier frequency offset (CFO), timing
//! offset and sampling-rate offset (SRO) of the serving cell.
//!
//! The receiver measures, relative to what its sample clock predicts,
//!
//! * a timing error (samples, fractional): the SSS phase slope at every SSB
//!   on top of the integer PSS position, and the PDSCH DM-RS phase slope in
//!   every slot with a decoded PDSCH;
//! * the total CFO (Hz): the SSB cyclic-prefix correlation and the PDSCH
//!   DM-RS phase rotation between DM-RS symbols.
//!
//! [`SyncTracker`] filters them into a timing model `offset + rate·t` and a
//! CFO estimate. The sample clock's anchor only ever moves in whole samples:
//! [`SyncTracker::advance`] integrates the rate and hands out a one-sample
//! step whenever the modelled offset passes ¾ of a sample, instead of
//! stepping on every noisy measurement. Downlink and uplink both follow the
//! anchor, so the uplink transmit timing drifts with the downlink exactly as
//! TS 38.133 §7.1 expects (gradual, small steps).
//!
//! The timing loop is second order (offset and rate, critically damped at
//! `timing_bandwidth_hz`) with gains scaled by the time between measurements,
//! so its bandwidth does not depend on how often the cell schedules a PDSCH.
//! When the radio's LO and sample clock come from one reference (true for
//! every SDR in the lab and for the gNB), a relative frequency error ε
//! appears both as a CFO of −ε·f_c and as a drift of ε·f_s samples per
//! second, and the CFO measurement, which is far more precise, feeds the rate
//! forward; the loop's own rate state then only absorbs what is left.
//!
//! Over the ZMQ transport every measurement is zero and so is the output: no
//! step is ever taken.

/// Tracking-loop parameters.
#[derive(Clone, Debug)]
pub struct TrackerConfig {
    /// Sample rate (Hz) of the stream the anchor counts in.
    pub fs: f64,
    /// Downlink carrier (Hz), for the CFO → SRO feed-forward.
    pub carrier_hz: f64,
    /// LO and sample clock share a reference: drift = −CFO/f_c · f_s.
    pub sro_from_cfo: bool,
    /// Natural frequency of the timing loop (Hz).
    pub timing_bandwidth_hz: f64,
    /// Time constant of the CFO filter (s).
    pub cfo_time_constant_s: f64,
    /// Timing errors beyond this (samples) are not filtered: two consecutive
    /// ones that agree (a gap, a transport jump) re-align at once, a lone one
    /// (a measurement in a deep fade) is dropped.
    pub coarse_limit: f64,
}

impl TrackerConfig {
    pub fn new(fs: f64, carrier_hz: f64) -> Self {
        Self {
            fs,
            carrier_hz,
            sro_from_cfo: true,
            timing_bandwidth_hz: 0.5,
            cfo_time_constant_s: 0.1,
            coarse_limit: 3.0,
        }
    }
}

/// Counters for the periodic statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrackStats {
    /// One-sample anchor steps from the model.
    pub steps: u64,
    /// Coarse re-alignments (confirmed errors beyond `coarse_limit`).
    pub coarse: u64,
    /// Lone timing errors beyond `coarse_limit`, dropped.
    pub outliers: u64,
    pub timing_measurements: u64,
    pub cfo_measurements: u64,
}

/// Where the sample clock was when a measured slot was read: the tracker's
/// total applied anchor shift and the CFO the data path was corrected with.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SyncTag {
    /// DL stream index of the slot.
    pub at: i64,
    /// [`SyncTracker::applied`] when the slot was read.
    pub applied: i64,
    /// CFO (Hz) removed from the samples before the measurement.
    pub cfo_removed_hz: f64,
}

/// Longest gap between measurements the gains are scaled for (s).
const MAX_DT_S: f64 = 0.2;
/// Gap assumed before the first measurement of a kind (s).
const FIRST_DT_S: f64 = 0.02;
/// The modelled offset is handed out as a step beyond this (samples).
const STEP_THRESHOLD: f64 = 0.75;
/// Plausibility limit on the loop's own rate state (ppm).
const MAX_RATE_PPM: f64 = 50.0;
/// Scale of the rate-state gain while the CFO feed-forward is active.
const RESIDUAL_RATE_GAIN: f64 = 0.05;
/// Two coarse errors confirm each other within this (samples).
const COARSE_AGREEMENT: f64 = 1.5;

/// The tracker. See the module documentation.
#[derive(Clone, Debug)]
pub struct SyncTracker {
    cfg: TrackerConfig,
    cfo_hz: f64,
    /// Modelled arrival of the signal relative to the current integer anchor
    /// (samples).
    offset: f64,
    /// Drift on top of the feed-forward (samples per second).
    rate: f64,
    /// Total anchor shift handed out (samples).
    applied: i64,
    last_advance: Option<i64>,
    last_timing: Option<i64>,
    last_cfo: Option<i64>,
    /// A coarse error waiting for confirmation.
    pending_coarse: Option<f64>,
    stats: TrackStats,
}

impl SyncTracker {
    /// Start from the acquisition CFO estimate, the timing aligned.
    pub fn new(cfg: TrackerConfig, cfo_hz: f64) -> Self {
        Self {
            cfg,
            cfo_hz,
            offset: 0.0,
            rate: 0.0,
            applied: 0,
            last_advance: None,
            last_timing: None,
            last_cfo: None,
            pending_coarse: None,
            stats: TrackStats::default(),
        }
    }

    /// Count the drift from DL stream index `at` (the acquisition): the first
    /// [`advance`](Self::advance) then applies it over however long the gap
    /// to the first tracked slot is (a dropped cell-search backlog can be
    /// seconds — 129 samples at 1 ppm and 30.72 MHz over 4.2 s).
    pub fn starting_at(mut self, at: i64) -> Self {
        self.last_advance = Some(at);
        self
    }

    /// Current CFO estimate (Hz; positive = the signal is above nominal).
    pub fn cfo_hz(&self) -> f64 {
        self.cfo_hz
    }

    /// Modelled timing offset relative to the current anchor (samples).
    pub fn offset(&self) -> f64 {
        self.offset
    }

    /// Total drift (samples per second): feed-forward plus loop state.
    pub fn drift(&self) -> f64 {
        self.feed_forward() + self.rate
    }

    /// Total drift in ppm of the sample rate.
    pub fn drift_ppm(&self) -> f64 {
        self.drift() / self.cfg.fs * 1e6
    }

    /// Total anchor shift handed out so far (samples).
    pub fn applied(&self) -> i64 {
        self.applied
    }

    /// One-line state and counters, as the engine logs them (`tracking: …`).
    pub fn summary(&self) -> String {
        let t = self.stats();
        format!(
            "cfo {:.0} Hz, drift {:+.3} ppm, offset {:+.2} samples, {} steps, {} re-alignments, {} outliers ({} timing / {} CFO measurements)",
            self.cfo_hz(),
            self.drift_ppm(),
            self.offset(),
            t.steps,
            t.coarse,
            t.outliers,
            t.timing_measurements,
            t.cfo_measurements
        )
    }

    pub fn stats(&self) -> TrackStats {
        self.stats
    }

    fn feed_forward_active(&self) -> bool {
        self.cfg.sro_from_cfo && self.cfg.carrier_hz > 0.0
    }

    fn feed_forward(&self) -> f64 {
        if self.feed_forward_active() {
            -self.cfo_hz / self.cfg.carrier_hz * self.cfg.fs
        } else {
            0.0
        }
    }

    /// Seconds since `last` (then set to `at`), clamped to `[0, MAX_DT_S]`.
    fn elapsed(fs: f64, last: &mut Option<i64>, at: i64) -> f64 {
        let dt = match *last {
            Some(l) => ((at - l) as f64 / fs).clamp(0.0, MAX_DT_S),
            None => FIRST_DT_S,
        };
        *last = Some(last.map_or(at, |l| l.max(at)));
        dt
    }

    /// A timing measurement: the signal of the slot tagged `tag` arrived
    /// `measured` samples later than that slot's anchor predicted.
    pub fn on_timing(&mut self, tag: SyncTag, measured: f64) {
        if !measured.is_finite() {
            return;
        }
        self.stats.timing_measurements += 1;
        // Anchor steps taken since the slot was read moved the reference.
        let e = measured - (self.applied - tag.applied) as f64 - self.offset;
        let dt = Self::elapsed(self.cfg.fs, &mut self.last_timing, tag.at);
        if e.abs() > self.cfg.coarse_limit {
            match self.pending_coarse.take() {
                Some(p) if (p - e).abs() < COARSE_AGREEMENT => {
                    self.offset += e;
                    self.stats.coarse += 1;
                    log::info!("timing tracking: re-aligned by {e:.1} samples");
                }
                _ => {
                    self.pending_coarse = Some(e);
                    self.stats.outliers += 1;
                    log::debug!("timing tracking: {e:.1}-sample error held for confirmation");
                }
            }
            return;
        }
        self.pending_coarse = None;
        let wn = std::f64::consts::TAU * self.cfg.timing_bandwidth_hz;
        let k1 = (2.0 * std::f64::consts::FRAC_1_SQRT_2 * wn * dt).min(0.5);
        // With the feed-forward the CFO already carries the clock drift, and
        // the rate state only absorbs a residual; at full gain it integrates
        // the timing wander of a fading multipath channel (path powers
        // trading places move the measured arrival by fractions of the delay
        // spread) into a false drift — 0.3–0.6 ppm under TDL-C 300 ns or
        // EVA 60 km/h, with the CFO itself within 1 %.
        let k2 = wn
            * wn
            * dt
            * if self.feed_forward_active() {
                RESIDUAL_RATE_GAIN
            } else {
                1.0
            };
        self.offset += k1 * e;
        let max_rate = MAX_RATE_PPM * 1e-6 * self.cfg.fs;
        self.rate = (self.rate + k2 * e).clamp(-max_rate, max_rate);
    }

    /// A CFO measurement on the slot tagged `tag`: `residual_hz` left after
    /// removing `tag.cfo_removed_hz`.
    pub fn on_cfo(&mut self, tag: SyncTag, residual_hz: f64) {
        if !residual_hz.is_finite() {
            return;
        }
        self.stats.cfo_measurements += 1;
        let dt = Self::elapsed(self.cfg.fs, &mut self.last_cfo, tag.at);
        let g = (dt / self.cfg.cfo_time_constant_s).min(1.0);
        let total = tag.cfo_removed_hz + residual_hz;
        self.cfo_hz += g * (total - self.cfo_hz);
    }

    /// Integrate the drift up to DL index `at` (the start of the next slot to
    /// read) and return the anchor step to apply now (0 or ±n samples).
    pub fn advance(&mut self, at: i64) -> i64 {
        if let Some(last) = self.last_advance {
            if at > last {
                self.offset += self.drift() * (at - last) as f64 / self.cfg.fs;
            }
        }
        self.last_advance = Some(self.last_advance.map_or(at, |l| l.max(at)));
        if self.offset.abs() < STEP_THRESHOLD {
            return 0;
        }
        let step = self.offset.round() as i64;
        self.offset -= step as f64;
        self.applied += step;
        if step.abs() == 1 {
            self.stats.steps += 1;
        }
        step
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FS: f64 = 15.36e6;
    const FC: f64 = 3.5e9;
    const SLOT: i64 = 7680; // 0.5 ms at 15.36 MHz

    fn tag(t: &SyncTracker, at: i64) -> SyncTag {
        SyncTag {
            at,
            applied: t.applied(),
            cfo_removed_hz: t.cfo_hz(),
        }
    }

    /// Without measurements other than zeros (the ZMQ case) nothing moves.
    #[test]
    fn a_perfect_link_never_steps() {
        let mut t = SyncTracker::new(TrackerConfig::new(FS, FC), 0.0);
        for n in 0..10_000 {
            let at = n * SLOT;
            assert_eq!(t.advance(at), 0);
            t.on_timing(tag(&t, at), 0.0);
            t.on_cfo(tag(&t, at), 0.0);
        }
        assert_eq!(t.applied(), 0);
        assert_eq!(t.cfo_hz(), 0.0);
    }

    /// Simulated link: the UE clock is fast by `ppm` (LO and sample clock
    /// locked). The true signal position drifts by ppm·fs samples per second;
    /// the tracker sees SSB measurements every 20 ms and DM-RS ones in a
    /// fraction of the slots, all with noise. Returns the worst tracking
    /// error after the transient and the final tracker.
    fn run(ppm: f64, cfg: TrackerConfig, seconds: f64) -> (f64, SyncTracker) {
        let eps = ppm * 1e-6;
        let true_cfo = -eps * FC;
        // Acquisition left a 300 Hz CFO error.
        let mut t = SyncTracker::new(cfg, true_cfo + 300.0);
        let mut seed = 0x1234_5678u64;
        let mut noise = |sigma: f64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 11) as f64 / (1u64 << 53) as f64 - 0.5) * 2.0 * 3f64.sqrt() * sigma
        };
        let slots = (seconds * 2000.0) as i64;
        let mut worst = 0f64;
        for n in 0..slots {
            let at = n * SLOT;
            t.advance(at);
            // True arrival relative to the integer anchor now in use.
            let truth = eps * at as f64 - t.applied() as f64;
            if n > slots / 4 {
                worst = worst.max((truth - t.offset()).abs());
            }
            let tg = tag(&t, at);
            if n % 40 == 0 {
                t.on_timing(tg, truth + noise(0.2));
                t.on_cfo(tg, true_cfo - tg.cfo_removed_hz + noise(150.0));
            }
            if n % 3 == 0 {
                t.on_timing(tg, truth + noise(0.3));
                t.on_cfo(tg, true_cfo - tg.cfo_removed_hz + noise(40.0));
            }
        }
        (worst, t)
    }

    /// Fading multipath moves the measured arrival around (the strongest
    /// path changes); with the CFO feed-forward that wander must not turn
    /// into a drift estimate.
    #[test]
    fn multipath_timing_wander_is_not_drift() {
        let ppm = 1.0;
        let eps = ppm * 1e-6;
        let true_cfo = -eps * FC;
        let mut t = SyncTracker::new(TrackerConfig::new(FS, FC), true_cfo);
        let mut worst = 0f64;
        for n in 0..(30 * 2000) {
            let at = n * SLOT;
            t.advance(at);
            let s = at as f64 / FS;
            let wander = 1.5 * (std::f64::consts::TAU * 0.3 * s).sin()
                + 0.8 * (std::f64::consts::TAU * 0.11 * s + 1.0).sin();
            let truth = eps * at as f64 - t.applied() as f64;
            let tg = tag(&t, at);
            if n % 3 == 0 {
                t.on_timing(tg, truth + wander);
                t.on_cfo(tg, true_cfo - tg.cfo_removed_hz);
            }
            if n > 10 * 2000 {
                worst = worst.max((t.drift_ppm() - ppm).abs());
            }
        }
        assert!(worst < 0.05, "drift error up to {worst:.3} ppm");
    }

    #[test]
    fn follows_a_locked_clock_drift() {
        for ppm in [-2.0, 0.5, 5.0] {
            let (worst, t) = run(ppm, TrackerConfig::new(FS, FC), 20.0);
            assert!(worst < 0.5, "{ppm} ppm: worst error {worst:.2} samples");
            assert!(
                (t.drift_ppm() - ppm).abs() < 0.05,
                "{ppm} ppm: drift estimate {:.3}",
                t.drift_ppm()
            );
            assert!((t.cfo_hz() + ppm * 1e-6 * FC).abs() < 30.0);
            // One step per sample of accumulated drift, no dithering.
            let expect = (ppm * 1e-6 * FS * 20.0).abs();
            assert!(
                (t.stats().steps as f64) < expect + 6.0,
                "{ppm} ppm: {} steps for {expect:.0} samples of drift",
                t.stats().steps
            );
        }
    }

    /// Without the feed-forward (independent LO), the loop's own rate state
    /// learns the drift.
    #[test]
    fn learns_the_drift_without_feed_forward() {
        let cfg = TrackerConfig {
            sro_from_cfo: false,
            ..TrackerConfig::new(FS, FC)
        };
        let (worst, t) = run(3.0, cfg, 30.0);
        assert!(worst < 0.6, "worst error {worst:.2} samples");
        assert!(
            (t.drift_ppm() - 3.0).abs() < 0.2,
            "drift {:.3}",
            t.drift_ppm()
        );
    }

    /// A measurement made before an anchor step is corrected for it.
    #[test]
    fn stale_measurements_account_for_later_steps() {
        let mut t = SyncTracker::new(
            TrackerConfig {
                sro_from_cfo: false,
                ..TrackerConfig::new(FS, FC)
            },
            0.0,
        );
        t.advance(0);
        let old = tag(&t, 0);
        // The model is pushed past the threshold: one step.
        t.offset = 0.8;
        assert_eq!(t.advance(SLOT), 1);
        // The old slot saw the signal 0.8 samples late; relative to the new
        // anchor that is −0.2, which is what the model says: no correction.
        let before = t.offset();
        t.on_timing(old, 0.8);
        assert!((t.offset() - before).abs() < 1e-9);
    }

    /// A large error confirmed by the next measurement is taken at once and
    /// handed out as one step.
    #[test]
    fn confirmed_coarse_errors_realign_at_once() {
        let mut t = SyncTracker::new(TrackerConfig::new(FS, FC), 0.0);
        t.advance(0);
        t.on_timing(tag(&t, 0), -12.0);
        assert_eq!(t.advance(SLOT), 0, "a lone error is held");
        t.on_timing(tag(&t, SLOT), -11.6);
        assert_eq!(t.advance(2 * SLOT), -12);
        assert_eq!(t.stats().coarse, 1);
        assert_eq!(t.applied(), -12);
    }

    /// A lone outlier (a DM-RS measurement in a fade) moves nothing, and a
    /// good measurement in between cancels the pending one.
    /// Started at the acquisition index, the first advance after a long gap
    /// (a dropped search backlog) hands out the whole drift over it: 1 ppm
    /// (CFO −ppm·f_c, fed forward) for 4.2 s at 30.72 MHz is 129 samples.
    /// Without the start index the gap would be lost.
    #[test]
    fn drift_over_the_acquisition_gap_is_applied() {
        let fs = 30.72e6;
        let cfg = TrackerConfig::new(fs, FC);
        let gap = (4.2 * fs) as i64;
        let mut t = SyncTracker::new(cfg.clone(), -1e-6 * FC).starting_at(0);
        let step = t.advance(gap);
        assert!((step - 129).abs() <= 1, "step {step}");
        let mut late = SyncTracker::new(cfg, -1e-6 * FC);
        assert_eq!(late.advance(gap), 0);
    }

    #[test]
    fn lone_outliers_are_dropped() {
        let mut t = SyncTracker::new(TrackerConfig::new(FS, FC), 0.0);
        t.advance(0);
        t.on_timing(tag(&t, 0), 4.3);
        t.on_timing(tag(&t, SLOT), 0.0);
        t.on_timing(tag(&t, 2 * SLOT), 4.1);
        assert_eq!(t.advance(3 * SLOT), 0);
        assert!(t.offset().abs() < 0.1, "offset {}", t.offset());
        assert_eq!(t.stats().coarse, 0);
        assert_eq!(t.stats().outliers, 2);
    }
}
