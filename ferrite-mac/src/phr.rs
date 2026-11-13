//! Power Headroom Reporting (TS 38.321 §5.4.6).
//!
//! Triggers (single cell, Type 1 PH): `phr-ProhibitTimer` expired or not
//! running *and* the pathloss changed by more than `phr-Tx-PowerFactorChange`
//! since the last report; `phr-PeriodicTimer` expiry; (re)configuration of the
//! PHR function by upper layers. A pending report is carried by the first new
//! UL-SCH transmission that can hold the Single Entry PHR MAC CE, which also
//! (re)starts both timers.
//!
//! The *values* reported — PH and P_CMAX,c — come from whoever knows the
//! transmit power (the L1 power control, once it exists; today a nominal
//! [`PowerHeadroom`] set by the stack), so this module is transport-agnostic.

use ferrite_common::SlotPoint;

/// `PHR-Config` as MAC needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhrMacConfig {
    /// `phr-PeriodicTimer` in ms (`None` = infinity).
    pub periodic_ms: Option<u32>,
    /// `phr-ProhibitTimer` in ms.
    pub prohibit_ms: u32,
    /// `phr-Tx-PowerFactorChange` in dB (`None` = infinity).
    pub tx_power_factor_change_db: Option<u8>,
}

/// The quantities a report carries (Type 1 PH for the PCell, TS 38.213 §7.7).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PowerHeadroom {
    /// PH in dB (P_CMAX,c − the PUSCH power the reference transmission would need).
    pub ph_db: f32,
    /// Configured maximum output power P_CMAX,c in dBm.
    pub pcmax_dbm: f32,
    /// Downlink pathloss estimate in dB (drives the power-change trigger).
    pub pathloss_db: f32,
}

impl Default for PowerHeadroom {
    /// A UE far below its power limit — the right thing to say over a
    /// lossless transport, and conservative over the air until power control
    /// feeds real numbers.
    fn default() -> Self {
        Self { ph_db: 38.0, pcmax_dbm: 23.0, pathloss_db: 0.0 }
    }
}

#[derive(Clone, Debug)]
pub struct PhrProcedure {
    cfg: Option<PhrMacConfig>,
    slots_per_ms: u32,
    periodic_expiry: Option<SlotPoint>,
    prohibit_expiry: Option<SlotPoint>,
    /// Pathloss at the last transmitted report.
    reported_pathloss_db: Option<f32>,
    /// A report is due.
    pub pending: bool,
}

impl PhrProcedure {
    pub fn new(cfg: Option<PhrMacConfig>, slots_per_ms: u32) -> Self {
        let mut p = Self { cfg: None, slots_per_ms, periodic_expiry: None, prohibit_expiry: None, reported_pathloss_db: None, pending: false };
        p.configure(cfg);
        p
    }

    /// Upper layers (re)configured the function: a report is triggered unless
    /// it was disabled (§5.4.6 "configuration or reconfiguration of the power
    /// headroom reporting functionality ... which is not used to disable").
    pub fn configure(&mut self, cfg: Option<PhrMacConfig>) {
        self.cfg = cfg;
        if cfg.is_some() {
            self.pending = true;
        } else {
            self.pending = false;
            self.periodic_expiry = None;
            self.prohibit_expiry = None;
        }
    }

    pub fn is_configured(&self) -> bool {
        self.cfg.is_some()
    }

    /// Per-slot timer evaluation with the current pathloss estimate.
    pub fn tick(&mut self, now: SlotPoint, pathloss_db: f32) {
        let Some(cfg) = self.cfg else { return };
        if self.periodic_expiry.is_some_and(|t| now.diff(&t) >= 0) {
            self.periodic_expiry = None;
            self.pending = true;
        }
        if self.prohibit_expiry.is_some_and(|t| now.diff(&t) >= 0) {
            self.prohibit_expiry = None;
        }
        if self.prohibit_expiry.is_none() {
            if let (Some(th), Some(last)) = (cfg.tx_power_factor_change_db, self.reported_pathloss_db) {
                if (pathloss_db - last).abs() > f32::from(th) {
                    self.pending = true;
                }
            }
        }
    }

    /// A Single Entry PHR MAC CE was included in a new transmission in `now`.
    pub fn on_sent(&mut self, now: SlotPoint, pathloss_db: f32) {
        let Some(cfg) = self.cfg else { return };
        self.pending = false;
        self.reported_pathloss_db = Some(pathloss_db);
        self.periodic_expiry = cfg.periodic_ms.map(|ms| now.add(u64::from((ms * self.slots_per_ms).max(1))));
        self.prohibit_expiry = (cfg.prohibit_ms > 0).then(|| now.add(u64::from(cfg.prohibit_ms * self.slots_per_ms)));
    }

    /// MAC reset (§5.12): timers stopped, nothing pending until reconfigured.
    pub fn reset(&mut self) {
        self.periodic_expiry = None;
        self.prohibit_expiry = None;
        self.reported_pathloss_db = None;
        self.pending = self.cfg.is_some();
    }
}

/// PH field (TS 38.133 Table 10.1.17.1-1): 1 dB steps from −32 dB (index 1) to
/// 22 dB (index 54), 2 dB steps above, 0 = below −32 dB, 63 = 38 dB and up.
pub fn ph_index(ph_db: f32) -> u8 {
    let ph = ph_db.floor();
    if ph < -32.0 {
        0
    } else if ph < 22.0 {
        (ph + 33.0) as u8
    } else if ph < 38.0 {
        55 + ((ph - 22.0) / 2.0) as u8
    } else {
        63
    }
}

/// P_CMAX,c field (TS 38.133 Table 10.1.18.1-1): 1 dBm steps from −29 dBm
/// (index 1) to 33 dBm (index 63), 0 = below −29 dBm.
pub fn pcmax_index(pcmax_dbm: f32) -> u8 {
    let p = pcmax_dbm.floor();
    if p < -29.0 {
        0
    } else {
        ((p + 30.0) as u8).min(63)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::{Numerology, SlotPoint};

    fn slot(n: u64) -> SlotPoint {
        SlotPoint::from_index(Numerology::from_scs_khz(30).unwrap(), n)
    }

    #[test]
    fn field_mapping() {
        assert_eq!(ph_index(-40.0), 0);
        assert_eq!(ph_index(-32.0), 1);
        assert_eq!(ph_index(0.0), 33);
        assert_eq!(ph_index(21.9), 54);
        assert_eq!(ph_index(22.0), 55);
        assert_eq!(ph_index(24.0), 56);
        assert_eq!(ph_index(36.0), 62);
        assert_eq!(ph_index(38.0), 63);
        assert_eq!(pcmax_index(-30.0), 0);
        assert_eq!(pcmax_index(-29.0), 1);
        assert_eq!(pcmax_index(23.0), 53);
        assert_eq!(pcmax_index(33.0), 63);
        assert_eq!(pcmax_index(40.0), 63);
    }

    #[test]
    fn triggers() {
        let cfg = PhrMacConfig { periodic_ms: Some(10), prohibit_ms: 20, tx_power_factor_change_db: Some(3) };
        let mut p = PhrProcedure::new(Some(cfg), 2);
        assert!(p.pending, "configuration triggers a report");
        p.on_sent(slot(0), 100.0);
        assert!(!p.pending);
        // Pathloss change within the prohibit timer: no trigger.
        p.tick(slot(10), 110.0);
        assert!(!p.pending);
        // Periodic timer (10 ms = 20 slots) fires.
        p.tick(slot(20), 100.0);
        assert!(p.pending);
        p.on_sent(slot(20), 100.0);
        // After the prohibit timer (20 ms = 40 slots) a >3 dB change triggers.
        p.tick(slot(61), 103.5);
        assert!(p.pending);
        p.on_sent(slot(61), 103.5);
        p.tick(slot(80), 104.0);
        assert!(!p.pending, "a 0.5 dB change is below the threshold");
        p.tick(slot(81), 104.0);
        assert!(p.pending, "periodic timer again");
        // Infinite timers never fire.
        let mut q = PhrProcedure::new(Some(PhrMacConfig { periodic_ms: None, prohibit_ms: 0, tx_power_factor_change_db: None }), 2);
        q.on_sent(slot(0), 1.0);
        q.tick(slot(100_000), 50.0);
        assert!(!q.pending);
        // Release disables everything.
        q.configure(None);
        q.tick(slot(100_001), 50.0);
        assert!(!q.pending);
    }
}
