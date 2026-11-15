//! Receive automatic gain control.
//!
//! A real front end has to be told how much to amplify: too little and the
//! quantisation noise of the ADC eats the SINR, too much and OFDM peaks clip.
//! The controller keeps the mean power of a downlink slot near a target with
//! hysteresis, changes the gain in whole dB, and holds after a change so that
//! the tracking loops settle on the new level before the next decision. It
//! measures downlink slots only (the SSB slot: over TDD, uplink slots carry the
//! UE's own leakage), through [`power_dbfs`].
//!
//! The device is driven through [`ferrite_radio::GainControl`]; backends
//! without gain (ZMQ, file) have no controller.

use ferrite_common::Iq;

/// Mean power of `samples` relative to full scale (dB).
pub fn power_dbfs(samples: &[Iq]) -> f32 {
    if samples.is_empty() {
        return f32::NEG_INFINITY;
    }
    let mean = samples.iter().map(|s| s.norm_sqr() as f64).sum::<f64>() / samples.len() as f64;
    (10.0 * mean.max(1e-14).log10()) as f32
}

/// Gain decision loop (see the module doc).
#[derive(Clone, Debug)]
pub struct Agc {
    /// Mean slot power to aim for (dBFS). OFDM peaks sit 10–12 dB above the
    /// mean, so −22 dBFS leaves them clear of full scale.
    pub target_dbfs: f32,
    /// No change while the measurement is within this of the target.
    pub hysteresis_db: f32,
    /// Minimum slots between two changes.
    pub hold_slots: u64,
    /// The device's advertised range, narrowed to what it actually accepts
    /// (a request it does not follow marks a floor or a ceiling).
    range: (f64, f64),
    gain_db: f64,
    last_change: Option<u64>,
    requested: Option<f64>,
}

impl Agc {
    pub fn new(range: (f64, f64), initial_gain_db: f64) -> Self {
        Self {
            target_dbfs: -22.0,
            hysteresis_db: 3.0,
            hold_slots: 200,
            range,
            gain_db: initial_gain_db.clamp(range.0, range.1),
            last_change: None,
            requested: None,
        }
    }

    /// The gain the controller believes is applied (dB).
    pub fn gain_db(&self) -> f64 {
        self.gain_db
    }

    /// Feed one downlink-slot power measurement. `slot_index` enforces the hold
    /// time; `None` (cell search, nothing to disturb) decides at once. Returns the
    /// new gain to apply, when one is needed.
    pub fn update(&mut self, power_dbfs: f32, slot_index: Option<u64>) -> Option<f64> {
        if !power_dbfs.is_finite() {
            return None;
        }
        if let (Some(now), Some(last)) = (slot_index, self.last_change) {
            if now.saturating_sub(last) < self.hold_slots {
                return None;
            }
        }
        let err = self.target_dbfs - power_dbfs;
        if err.abs() < self.hysteresis_db {
            return None;
        }
        let new = (self.gain_db + f64::from(err))
            .round()
            .clamp(self.range.0, self.range.1);
        if (new - self.gain_db).abs() < 0.5 {
            return None;
        }
        self.gain_db = new;
        self.last_change = slot_index.or(Some(0));
        self.requested = Some(new);
        Some(new)
    }

    /// Record the gain the device actually settled on after the last request.
    /// A device that stopped short of the request has shown its real limit:
    /// the range is narrowed so the controller does not ask again.
    pub fn applied(&mut self, actual_db: f64) {
        if let Some(req) = self.requested.take() {
            if req > actual_db + 0.5 {
                self.range.1 = actual_db;
            } else if req < actual_db - 0.5 {
                self.range.0 = actual_db;
            }
        }
        self.gain_db = actual_db;
    }

    /// The gain range the controller currently works in.
    pub fn range(&self) -> (f64, f64) {
        self.range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_of_a_constant_signal() {
        let s = vec![Iq::new(0.1, 0.0); 100];
        assert!((power_dbfs(&s) + 20.0).abs() < 1e-3);
        assert_eq!(power_dbfs(&[]), f32::NEG_INFINITY);
    }

    /// Within the hysteresis band nothing happens; outside it the gain moves by
    /// the error, rounded, and stays inside the device range.
    #[test]
    fn steps_toward_the_target_within_the_range() {
        let mut agc = Agc::new((0.0, 70.0), 40.0);
        assert_eq!(agc.update(-23.5, None), None);
        assert_eq!(agc.update(-40.2, None), Some(58.0));
        assert_eq!(agc.gain_db(), 58.0);
        assert_eq!(agc.update(-60.0, None), Some(70.0)); // clamped
        assert_eq!(agc.update(-5.0, None), Some(53.0));
    }

    /// After a change the controller holds for `hold_slots` even if the level
    /// is still off, then acts again.
    #[test]
    fn holds_after_a_change() {
        let mut agc = Agc::new((0.0, 70.0), 40.0);
        agc.hold_slots = 100;
        assert_eq!(agc.update(-40.0, Some(1_000)), Some(58.0));
        assert_eq!(agc.update(-40.0, Some(1_050)), None);
        assert_eq!(agc.update(-30.0, Some(1_100)), Some(66.0));
    }

    /// Non-finite measurements (empty slot) are ignored; a device that rounds
    /// the gain is followed.
    #[test]
    fn ignores_bad_input_and_tracks_the_device() {
        let mut agc = Agc::new((0.0, 70.0), 40.0);
        assert_eq!(agc.update(f32::NEG_INFINITY, None), None);
        assert_eq!(agc.update(-30.0, None), Some(48.0));
        agc.applied(47.0);
        assert_eq!(agc.gain_db(), 47.0);
    }

    /// A device whose advertised range exceeds what it applies (the XTRX
    /// stops at 48 dB) teaches the controller its ceiling: no further requests
    /// for more gain, and a later request to go down works.
    #[test]
    fn learns_the_device_ceiling() {
        let mut agc = Agc::new((-12.0, 70.0), 30.0);
        assert_eq!(agc.update(-65.0, None), Some(70.0));
        agc.applied(48.0);
        assert_eq!(agc.range(), (-12.0, 48.0));
        assert_eq!(agc.update(-53.0, None), None);
        assert_eq!(agc.update(-10.0, None), Some(36.0));
        agc.applied(36.0);
        assert_eq!(agc.range(), (-12.0, 48.0));
    }
}
