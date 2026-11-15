//! Uplink power control (TS 38.213 §7).
//!
//! Every uplink transmission gets a power in dBm:
//!
//! * PRACH (§7.4): `P_PRACH = min(P_CMAX, PREAMBLE_RECEIVED_TARGET_POWER + PL)` with the
//!   MAC's ramp (TS 38.321 §5.1.3) folded into the target; the format-dependent
//!   `Δ_PREAMBLE` is added by the PHY, which knows the format.
//! * PUSCH (§7.1.1): `min(P_CMAX, P_O + 10·log10(2^µ·M_RB) + α·PL + Δ_TF + f(i))`,
//!   `P_O = p0-NominalWithGrant + p0` of the first `P0-PUSCH-AlphaSet`; Msg3 uses
//!   `preambleReceivedTargetPower + msg3-DeltaPreamble` and `msg3-Alpha`;
//!   `f` accumulates the DCI TPC (Table 7.1.1-1) or is absolute, and starts at
//!   `ΔP_rampup + δ_msg2` (the RAR TPC, Table 8.2-2).
//! * PUCCH (§7.2.1): `min(P_CMAX, P_O_PUCCH + 10·log10(2^µ·M_RB) + PL + Δ_F + Δ_TF + g(i))`,
//!   `g` accumulates the DL-DCI TPC and starts like `f`.
//! * SRS (§7.3.1): `min(P_CMAX, P_O_SRS + 10·log10(2^µ·M_SRS) + α_SRS·PL + h(i))`,
//!   `h = f` with the default `srs-PowerControlAdjustmentStates`.
//!
//! The pathloss is `referenceSignalPower − RSRP` with the SS/PBCH block power from
//! SIB1 and the filtered SS-RSRP in dBm, so it needs a receiver calibration; without a
//! transmitter calibration (`UlPowerConfig::enabled` false) every power is `None` and
//! the PHY keeps its default scaling (the ZMQ case, where dBm has no meaning).
//! The Type 1 power headroom (§7.7.1) comes from the same numbers.

use crate::phr::PowerHeadroom;

/// `δ_PUSCH,b,f,c` for accumulation, TS 38.213 Table 7.1.1-1 (also PUCCH, Table 7.2.1-1).
const TPC_ACCUMULATED_DB: [f32; 4] = [-1.0, 0.0, 1.0, 3.0];
/// `δ_PUSCH,b,f,c` absolute, Table 7.1.1-1.
const TPC_ABSOLUTE_DB: [f32; 4] = [-4.0, -1.0, 1.0, 4.0];
/// RAR `TPC command for scheduled PUSCH`, Table 8.2-2.
const RAR_TPC_DB: [f32; 8] = [-6.0, -4.0, -2.0, 0.0, 2.0, 4.0, 6.0, 8.0];

/// Everything the loops need from RRC (SIB1 and the dedicated configuration)
/// and from the radio calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct UlPowerConfig {
    /// A transmitter calibration exists, so powers in dBm are meaningful.
    pub enabled: bool,
    /// `P_CMAX,f,c` (dBm): the configured maximum output power.
    pub pcmax_dbm: f32,
    /// `ss-PBCH-BlockPower` (dBm per RE): the pathloss reference power.
    pub ss_pbch_power_dbm: f32,
    pub mu: u8,
    /// `preambleReceivedTargetPower` (dBm).
    pub preamble_target_dbm: f32,
    /// `powerRampingStep` (dB).
    pub ramping_step_db: f32,
    /// `p0-NominalWithGrant` (dBm).
    pub p0_nominal_pusch_dbm: f32,
    /// `p0` of the first `P0-PUSCH-AlphaSet` (dB).
    pub p0_ue_pusch_db: f32,
    /// `alpha` of the first `P0-PUSCH-AlphaSet`.
    pub alpha_pusch: f32,
    /// `msg3-DeltaPreamble` (dB).
    pub msg3_delta_preamble_db: f32,
    pub msg3_alpha: f32,
    /// `tpc-Accumulation` not disabled.
    pub tpc_accumulation: bool,
    /// `p0-nominal` of `PUCCH-ConfigCommon` (dBm).
    pub p0_nominal_pucch_dbm: f32,
    /// `p0-PUCCH-Value` of the first `P0-PUCCH` (dB).
    pub p0_ue_pucch_db: f32,
    /// `deltaF-PUCCH-f0..f4` (dB).
    pub delta_f_pucch_db: [f32; 5],
    /// `p0` of the SRS resource set (dBm) and its `alpha`.
    pub p0_srs_dbm: f32,
    pub alpha_srs: f32,
}

impl Default for UlPowerConfig {
    /// Spec defaults where there are any; disabled.
    fn default() -> Self {
        Self {
            enabled: false,
            pcmax_dbm: 23.0,
            ss_pbch_power_dbm: -16.0,
            mu: 1,
            preamble_target_dbm: -100.0,
            ramping_step_db: 4.0,
            p0_nominal_pusch_dbm: -76.0,
            p0_ue_pusch_db: 0.0,
            alpha_pusch: 1.0,
            msg3_delta_preamble_db: 0.0,
            msg3_alpha: 1.0,
            tpc_accumulation: true,
            p0_nominal_pucch_dbm: -90.0,
            p0_ue_pucch_db: 0.0,
            delta_f_pucch_db: [0.0; 5],
            p0_srs_dbm: -76.0,
            alpha_srs: 1.0,
        }
    }
}

/// PUCCH transmission parameters that set `Δ_TF` (§7.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PucchShape {
    pub format: u8,
    pub n_rb: u32,
    pub n_symbols: u32,
    /// UCI payload bits (`O_ACK + O_SR + O_CSI`).
    pub uci_bits: u32,
}

/// The closed-loop states and the pathloss estimate.
#[derive(Clone, Debug)]
pub struct UlPowerControl {
    cfg: UlPowerConfig,
    /// Filtered SS-RSRP (dBm).
    rsrp_dbm: Option<f32>,
    /// `f(i)` (PUSCH) and `g(i)` (PUCCH), dB.
    f_pusch_db: f32,
    g_pucch_db: f32,
}

impl UlPowerControl {
    pub fn new(cfg: UlPowerConfig) -> Self {
        Self {
            cfg,
            rsrp_dbm: None,
            f_pusch_db: 0.0,
            g_pucch_db: 0.0,
        }
    }

    /// New RRC parameters; the loop states and the pathloss survive.
    pub fn reconfigure(&mut self, cfg: UlPowerConfig) {
        self.cfg = cfg;
    }

    pub fn config(&self) -> &UlPowerConfig {
        &self.cfg
    }

    /// A serving-cell SS-RSRP sample (dBm); layer-3 filtered with a = 1/2
    /// (`filterCoefficient` fc4).
    pub fn on_rsrp_dbm(&mut self, rsrp_dbm: f32) {
        if !rsrp_dbm.is_finite() {
            return;
        }
        self.rsrp_dbm = Some(match self.rsrp_dbm {
            Some(prev) => 0.5 * prev + 0.5 * rsrp_dbm,
            None => rsrp_dbm,
        });
    }

    /// Downlink pathloss estimate (dB): reference power minus filtered RSRP, 0
    /// until the first measurement.
    pub fn pathloss_db(&self) -> f32 {
        self.rsrp_dbm
            .map_or(0.0, |r| (self.cfg.ss_pbch_power_dbm - r).max(0.0))
    }

    /// Reset the closed loops (a new connection, TS 38.213 §7.1.1: `f(0)` set at RA).
    pub fn reset_loops(&mut self) {
        self.f_pusch_db = 0.0;
        self.g_pucch_db = 0.0;
    }

    /// The RAR arrived after `preamble_counter` attempts, carrying the 3-bit TPC:
    /// `f(0) = g(0) = ΔP_rampup + δ_msg2`.
    pub fn on_rar(&mut self, preamble_counter: u32, tpc: u8) {
        let rampup = preamble_counter.saturating_sub(1) as f32 * self.cfg.ramping_step_db;
        let delta = RAR_TPC_DB[usize::from(tpc & 7)];
        self.f_pusch_db = rampup + delta;
        self.g_pucch_db = rampup + delta;
    }

    /// A 2-bit TPC from a UL DCI.
    pub fn on_pusch_tpc(&mut self, tpc: u8) {
        let i = usize::from(tpc & 3);
        if self.cfg.tpc_accumulation {
            self.f_pusch_db += TPC_ACCUMULATED_DB[i];
        } else {
            self.f_pusch_db = TPC_ABSOLUTE_DB[i];
        }
    }

    /// A 2-bit TPC from a DL DCI (for the PUCCH).
    pub fn on_pucch_tpc(&mut self, tpc: u8) {
        self.g_pucch_db += TPC_ACCUMULATED_DB[usize::from(tpc & 3)];
    }

    pub fn f_pusch_db(&self) -> f32 {
        self.f_pusch_db
    }

    pub fn g_pucch_db(&self) -> f32 {
        self.g_pucch_db
    }

    fn bandwidth_db(&self, n_rb: u32) -> f32 {
        10.0 * (f32::from(1u16 << self.cfg.mu) * n_rb.max(1) as f32).log10()
    }

    fn cap(&self, p: f32) -> Option<f32> {
        self.cfg.enabled.then_some(p.min(self.cfg.pcmax_dbm))
    }

    /// PRACH power for attempt `preamble_counter` (1-based), without `Δ_PREAMBLE`.
    pub fn prach_dbm(&self, preamble_counter: u32) -> Option<f32> {
        let ramp = preamble_counter.saturating_sub(1) as f32 * self.cfg.ramping_step_db;
        self.cap(self.cfg.preamble_target_dbm + ramp + self.pathloss_db())
    }

    /// PUSCH power over `n_rb` RBs; `msg3` selects the RA parameters (j = 0).
    pub fn pusch_dbm(&self, n_rb: u32, msg3: bool) -> Option<f32> {
        let (p0, alpha) = if msg3 {
            (
                self.cfg.preamble_target_dbm + self.cfg.msg3_delta_preamble_db,
                self.cfg.msg3_alpha,
            )
        } else {
            (
                self.cfg.p0_nominal_pusch_dbm + self.cfg.p0_ue_pusch_db,
                self.cfg.alpha_pusch,
            )
        };
        self.cap(p0 + self.bandwidth_db(n_rb) + alpha * self.pathloss_db() + self.f_pusch_db)
    }

    /// PUCCH power for a transmission of `shape`.
    pub fn pucch_dbm(&self, shape: PucchShape) -> Option<f32> {
        let delta_f = self
            .cfg
            .delta_f_pucch_db
            .get(usize::from(shape.format))
            .copied()
            .unwrap_or(0.0);
        self.cap(
            self.cfg.p0_nominal_pucch_dbm
                + self.cfg.p0_ue_pucch_db
                + self.bandwidth_db(shape.n_rb)
                + self.pathloss_db()
                + delta_f
                + pucch_delta_tf_db(shape)
                + self.g_pucch_db,
        )
    }

    /// SRS power over `n_rb` RBs (`h = f`, the default adjustment state).
    pub fn srs_dbm(&self, n_rb: u32) -> Option<f32> {
        self.cap(
            self.cfg.p0_srs_dbm
                + self.bandwidth_db(n_rb)
                + self.cfg.alpha_srs * self.pathloss_db()
                + self.f_pusch_db,
        )
    }

    /// Type 1 power headroom (§7.7.1) for a PUSCH over `n_rb` RBs, or the
    /// virtual one (`M_RB = 1`, no `Δ_TF`) when `None`. Without a calibration
    /// the conservative default stands.
    pub fn headroom(&self, n_rb: Option<u32>) -> PowerHeadroom {
        if !self.cfg.enabled {
            return PowerHeadroom::default();
        }
        let needed = self.cfg.p0_nominal_pusch_dbm
            + self.cfg.p0_ue_pusch_db
            + self.bandwidth_db(n_rb.unwrap_or(1))
            + self.cfg.alpha_pusch * self.pathloss_db()
            + self.f_pusch_db;
        PowerHeadroom {
            ph_db: self.cfg.pcmax_dbm - needed,
            pcmax_dbm: self.cfg.pcmax_dbm,
            pathloss_db: self.pathloss_db(),
        }
    }
}

/// `Δ_TF,b,f,c` for a PUCCH (TS 38.213 §7.2.1): formats 0/1 scale with the symbol
/// count, formats 2/3/4 with the UCI bits per RE.
pub fn pucch_delta_tf_db(s: PucchShape) -> f32 {
    let n_symb = s.n_symbols.max(1) as f32;
    match s.format {
        0 => 10.0 * (2.0 / n_symb).log10(),
        1 => 10.0 * (14.0 / n_symb).log10(),
        f => {
            // Format 2 carries DM-RS on 4 of 12 subcarriers; 3/4 on separate symbols
            // (approximated as the full RBs over the data symbols).
            let sc_ctrl = if f == 2 { 8.0 } else { 12.0 };
            let n_re = s.n_rb.max(1) as f32 * sc_ctrl * n_symb;
            let o = s.uci_bits as f32;
            if s.uci_bits <= 11 {
                10.0 * (6.0 * o.max(1.0) / n_re).log10()
            } else {
                let o_crc = if s.uci_bits <= 19 { 6.0 } else { 11.0 };
                let bpre = (o + o_crc) / n_re;
                10.0 * ((2.0f32.powf(2.4 * bpre) - 1.0).max(1e-6)).log10()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calibrated() -> UlPowerConfig {
        UlPowerConfig {
            enabled: true,
            pcmax_dbm: 23.0,
            ss_pbch_power_dbm: -16.0,
            mu: 1,
            preamble_target_dbm: -100.0,
            ramping_step_db: 4.0,
            p0_nominal_pusch_dbm: -76.0,
            p0_ue_pusch_db: 0.0,
            alpha_pusch: 1.0,
            msg3_delta_preamble_db: 2.0,
            msg3_alpha: 1.0,
            tpc_accumulation: true,
            p0_nominal_pucch_dbm: -90.0,
            p0_ue_pucch_db: 0.0,
            delta_f_pucch_db: [0.0, 0.0, 2.0, 0.0, 0.0],
            p0_srs_dbm: -76.0,
            alpha_srs: 1.0,
        }
    }

    /// Without a calibration every power is `None` and the headroom is the default.
    #[test]
    fn disabled_gives_no_powers() {
        let pc = UlPowerControl::new(UlPowerConfig::default());
        assert_eq!(pc.prach_dbm(1), None);
        assert_eq!(pc.pusch_dbm(10, false), None);
        assert_eq!(pc.headroom(None), PowerHeadroom::default());
    }

    /// PL = reference − filtered RSRP; the PRACH ramps by the step per attempt and
    /// is capped at P_CMAX.
    #[test]
    fn prach_follows_pathloss_and_ramps() {
        let mut pc = UlPowerControl::new(calibrated());
        pc.on_rsrp_dbm(-96.0); // PL 80
        assert_eq!(pc.pathloss_db(), 80.0);
        assert_eq!(pc.prach_dbm(1), Some(-20.0));
        assert_eq!(pc.prach_dbm(3), Some(-12.0));
        pc.on_rsrp_dbm(-146.0); // filtered to -121 → PL 105
        assert_eq!(pc.pathloss_db(), 105.0);
        assert_eq!(pc.prach_dbm(5), Some(21.0)); // -100 + 16 + 105
        pc.on_rsrp_dbm(-200.0);
        assert_eq!(pc.prach_dbm(5), Some(23.0)); // capped at P_CMAX
    }

    /// PUSCH: P0 + 10log10(2^µ·M) + α·PL + f, with f from the RAR (ramp + δ_msg2) and
    /// then the accumulated TPCs; Msg3 uses the RA parameters.
    #[test]
    fn pusch_open_and_closed_loop() {
        let mut pc = UlPowerControl::new(calibrated());
        pc.on_rsrp_dbm(-86.0); // PL 70
                               // 3rd preamble, RAR TPC 5 (+4 dB): f(0) = 8 + 4 = 12.
        pc.on_rar(3, 5);
        assert_eq!(pc.f_pusch_db(), 12.0);
        // Msg3 over 2 RBs: -98 + 10log10(4) + 70 + 12 = -9.98
        let msg3 = pc.pusch_dbm(2, true).unwrap();
        assert!((msg3 - (-98.0 + 6.0206 + 70.0 + 12.0)).abs() < 1e-3);
        // Connected, 24 RBs: -76 + 10log10(48) + 70 + 12 = 22.81
        let p = pc.pusch_dbm(24, false).unwrap();
        assert!((p - (-76.0 + 16.812 + 70.0 + 12.0)).abs() < 1e-2);
        pc.on_pusch_tpc(3); // +3 → capped at 23
        assert_eq!(pc.pusch_dbm(24, false), Some(23.0));
        pc.on_pusch_tpc(0);
        pc.on_pusch_tpc(0);
        pc.on_pusch_tpc(0); // f = 12
        assert!((pc.pusch_dbm(24, false).unwrap() - 22.812).abs() < 1e-2);
        // Absolute mode replaces f.
        let mut cfg = calibrated();
        cfg.tpc_accumulation = false;
        pc.reconfigure(cfg);
        pc.on_pusch_tpc(0);
        assert_eq!(pc.f_pusch_db(), -4.0);
    }

    /// PUCCH: p0 + bandwidth + PL + Δ_F + Δ_TF + g.
    #[test]
    fn pucch_power_and_delta_tf() {
        let mut pc = UlPowerControl::new(calibrated());
        pc.on_rsrp_dbm(-86.0); // PL 70
        pc.on_rar(1, 3); // g = 0
                         // F1, 1 RB, 14 symbols: Δ_TF 0 → -90 + 3.01 + 70 = -16.99
        let f1 = PucchShape {
            format: 1,
            n_rb: 1,
            n_symbols: 14,
            uci_bits: 1,
        };
        assert!((pc.pucch_dbm(f1).unwrap() - (-90.0 + 3.0103 + 70.0)).abs() < 1e-3);
        // F0, 2 symbols: Δ_TF 0; 1 symbol: +3 dB.
        assert_eq!(
            pucch_delta_tf_db(PucchShape {
                format: 0,
                n_rb: 1,
                n_symbols: 2,
                uci_bits: 1
            }),
            0.0
        );
        assert!(
            (pucch_delta_tf_db(PucchShape {
                format: 0,
                n_rb: 1,
                n_symbols: 1,
                uci_bits: 1
            }) - 3.0103)
                .abs()
                < 1e-3
        );
        // F2, 1 RB, 2 symbols, 7 bits: 10log10(6·7/16) = 4.2 dB, plus Δ_F 2.
        let f2 = PucchShape {
            format: 2,
            n_rb: 1,
            n_symbols: 2,
            uci_bits: 7,
        };
        let dtf = pucch_delta_tf_db(f2);
        assert!((dtf - 4.1903).abs() < 1e-3);
        assert!((pc.pucch_dbm(f2).unwrap() - (-90.0 + 3.0103 + 70.0 + 2.0 + dtf)).abs() < 1e-3);
        pc.on_pucch_tpc(2); // +1
        pc.on_pucch_tpc(0); // -1
        pc.on_pucch_tpc(3); // +3
        assert_eq!(pc.g_pucch_db(), 3.0);
    }

    /// SRS follows the PUSCH loop; the headroom is P_CMAX minus the PUSCH need.
    #[test]
    fn srs_and_headroom() {
        let mut pc = UlPowerControl::new(calibrated());
        pc.on_rsrp_dbm(-86.0);
        pc.on_rar(1, 3);
        pc.on_pusch_tpc(2); // f = 1
                            // 4 RBs: -76 + 10log10(8) + 70 + 1 = 4.03
        assert!((pc.srs_dbm(4).unwrap() - (-76.0 + 9.0309 + 70.0 + 1.0)).abs() < 1e-3);
        let ph = pc.headroom(Some(24));
        assert!((ph.ph_db - (23.0 - (-76.0 + 16.812 + 70.0 + 1.0))).abs() < 1e-2);
        assert_eq!(ph.pcmax_dbm, 23.0);
        assert_eq!(ph.pathloss_db, 70.0);
        let virt = pc.headroom(None);
        assert!((virt.ph_db - (23.0 - (-76.0 + 3.0103 + 70.0 + 1.0))).abs() < 1e-3);
    }
}
