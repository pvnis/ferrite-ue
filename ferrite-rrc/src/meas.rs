//! Measurements (TS 38.331 §5.5): the measurement configuration the network
//! installs with `RRCReconfiguration`, the layer-3 filtering of what the PHY
//! measures, the periodical and event-triggered reporting criteria, and the
//! `MeasurementReport` contents.
//!
//! What is measured today is the serving cell's SSB (SS-RSRP/RSRQ/SINR);
//! neighbour cells are not searched yet, so events that compare against
//! neighbours (A3–A6) are evaluated with no candidates and never enter.
//! The configuration, filtering and reporting machinery is cell-count
//! agnostic so that neighbour detection slots in underneath.

use ferrite_asn1::meas::{self as asn, EventId, MeasConfig, MeasObjectNr, MeasTriggerQuantity, ReportConfigNr, RsType};
use ferrite_common::SlotPoint;
use std::collections::BTreeMap;

/// One SSB measurement of a cell, in reporting units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CellMeasurement {
    pub pci: u16,
    pub rsrp_dbm: f32,
    pub rsrq_db: f32,
    pub sinr_db: f32,
}

/// Layer-3 filtered quantities of one cell (§5.5.3.2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Filtered {
    pub rsrp_dbm: f32,
    pub rsrq_db: f32,
    pub sinr_db: f32,
}

impl Filtered {
    fn update(&mut self, m: &CellMeasurement, k: asn::FilterConfig) {
        // F_n = (1 − a)·F_{n−1} + a·M_n, a = 1/2^(k/4), in the dB domain.
        let a = |k: u8| 1.0 / 2f32.powf(f32::from(k) / 4.0);
        let (ap, aq, asn_) = (a(k.rsrp), a(k.rsrq), a(k.rs_sinr));
        self.rsrp_dbm = (1.0 - ap) * self.rsrp_dbm + ap * m.rsrp_dbm;
        self.rsrq_db = (1.0 - aq) * self.rsrq_db + aq * m.rsrq_db;
        self.sinr_db = (1.0 - asn_) * self.sinr_db + asn_ * m.sinr_db;
    }

    fn quantity(&self, q: &MeasTriggerQuantity) -> (f32, f32) {
        match q {
            MeasTriggerQuantity::Rsrp(t) => (self.rsrp_dbm, asn::rsrp_range_dbm(*t)),
            MeasTriggerQuantity::Rsrq(t) => (self.rsrq_db, asn::rsrq_range_db(*t)),
            MeasTriggerQuantity::Sinr(t) => (self.sinr_db, asn::sinr_range_db(*t)),
        }
    }

    fn results(&self, q: asn::MeasReportQuantity) -> asn::MeasQuantityResults {
        asn::MeasQuantityResults {
            rsrp: q.rsrp.then(|| asn::rsrp_range(self.rsrp_dbm)),
            rsrq: q.rsrq.then(|| asn::rsrq_range(self.rsrq_db)),
            sinr: q.sinr.then(|| asn::sinr_range(self.sinr_db)),
        }
    }
}

/// Per-measId reporting state.
#[derive(Clone, Debug)]
struct MeasIdState {
    meas_object_id: u8,
    report_config_id: u8,
    /// Reports sent so far (periodical `reportAmount`, event `reportAmount`).
    reports_sent: u32,
    /// Next periodic report (periodical: `reportInterval`; events: while
    /// triggered, the interval between repeated reports).
    next_report: Option<SlotPoint>,
    /// Event entering condition held since (time-to-trigger running).
    entering_since: Option<SlotPoint>,
    leaving_since: Option<SlotPoint>,
    /// Event triggered (the "cells triggered list" is non-empty).
    triggered: bool,
}

/// The measurement procedure of one UE.
#[derive(Clone, Debug, Default)]
pub struct MeasProcedure {
    objects: BTreeMap<u8, MeasObjectNr>,
    reports: BTreeMap<u8, ReportConfigNr>,
    ids: BTreeMap<u8, MeasIdState>,
    /// `quantityConfigNR-List`, indexed by `quantityConfigIndex − 1`.
    quantity: Vec<asn::QuantityConfigNr>,
    /// Filtered serving-cell quantities per `quantityConfigIndex` (1-based
    /// key), since different objects may filter differently.
    serving: BTreeMap<u8, Filtered>,
    serving_pci: Option<u16>,
    s_measure_rsrp_dbm: Option<f32>,
    /// Reports ready to be sent.
    pending: Vec<asn::MeasResults>,
}

impl MeasProcedure {
    /// Apply a `measConfig` (§5.5.2): removals first, then add/modify. A new or
    /// modified measId restarts its reporting (§5.5.2.3).
    pub fn apply(&mut self, cfg: &MeasConfig) {
        for id in &cfg.meas_object_to_remove_list {
            self.objects.remove(id);
            self.ids.retain(|_, s| s.meas_object_id != *id);
        }
        for id in &cfg.report_config_to_remove_list {
            self.reports.remove(id);
            self.ids.retain(|_, s| s.report_config_id != *id);
        }
        for id in &cfg.meas_id_to_remove_list {
            self.ids.remove(id);
        }
        if let Some(q) = &cfg.quantity_config {
            self.quantity = q.clone();
            // Filtering restarts with a new quantity config (§5.5.2.8).
            self.serving.clear();
        }
        for o in &cfg.meas_object_to_add_mod_list {
            let modified = self.objects.insert(o.meas_object_id, o.meas_object.clone()).is_some();
            if modified {
                for s in self.ids.values_mut().filter(|s| s.meas_object_id == o.meas_object_id) {
                    s.reset();
                }
            }
        }
        for r in &cfg.report_config_to_add_mod_list {
            let modified = self.reports.insert(r.report_config_id, r.report_config).is_some();
            if modified {
                for s in self.ids.values_mut().filter(|s| s.report_config_id == r.report_config_id) {
                    s.reset();
                }
            }
        }
        for m in &cfg.meas_id_to_add_mod_list {
            self.ids.insert(
                m.meas_id,
                MeasIdState { meas_object_id: m.meas_object_id, report_config_id: m.report_config_id, reports_sent: 0, next_report: None, entering_since: None, leaving_since: None, triggered: false },
            );
        }
        self.s_measure_rsrp_dbm = match cfg.s_measure_config {
            Some(asn::SMeasureConfig::SsbRsrp(v)) | Some(asn::SMeasureConfig::CsiRsrp(v)) => Some(asn::rsrp_range_dbm(v)),
            None => self.s_measure_rsrp_dbm,
        };
    }

    /// Forget everything (connection release / re-establishment, §5.3.8.3).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn is_configured(&self) -> bool {
        !self.ids.is_empty()
    }

    /// A new SSB measurement of the serving cell.
    pub fn on_serving_measurement(&mut self, now: SlotPoint, m: &CellMeasurement) {
        self.serving_pci = Some(m.pci);
        let indexes: Vec<u8> = self.objects.values().map(|o| o.quantity_config_index).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let indexes = if indexes.is_empty() { vec![1] } else { indexes };
        for qi in indexes {
            let k = self.quantity.get(usize::from(qi.max(1) - 1)).map_or(asn::FilterConfig::default(), |q| q.cell.ssb);
            let f = self.serving.entry(qi).or_insert(Filtered { rsrp_dbm: m.rsrp_dbm, rsrq_db: m.rsrq_db, sinr_db: m.sinr_db });
            f.update(m, k);
        }
        self.evaluate(now);
    }

    /// Timers (report intervals, time-to-trigger).
    pub fn tick(&mut self, now: SlotPoint) {
        self.evaluate(now);
    }

    /// Reports that became due (encode each into a `MeasurementReport`).
    pub fn take_reports(&mut self) -> Vec<asn::MeasResults> {
        std::mem::take(&mut self.pending)
    }

    fn serving_filtered(&self, object: &MeasObjectNr) -> Option<&Filtered> {
        self.serving.get(&object.quantity_config_index).or_else(|| self.serving.values().next())
    }

    fn evaluate(&mut self, now: SlotPoint) {
        let spm = now.numerology.slots_per_subframe() as u64;
        let ids: Vec<u8> = self.ids.keys().copied().collect();
        for id in ids {
            let st = self.ids[&id].clone();
            let (Some(object), Some(report)) = (self.objects.get(&st.meas_object_id), self.reports.get(&st.report_config_id)) else { continue };
            if report.rs_type != RsType::Ssb {
                continue; // CSI-RS based measurements are not performed yet.
            }
            let Some(f) = self.serving_filtered(object).copied() else { continue };
            let mut st = st;
            let mut send = false;
            match report.event {
                None => {
                    // Periodical (§5.5.4.1 / §5.5.5): first report as soon as a
                    // measurement exists, then every reportInterval, reportAmount times.
                    if report.report_amount.is_some_and(|n| st.reports_sent >= u32::from(n)) {
                        // Done.
                    } else if st.next_report.map_or(true, |t| now.diff(&t) >= 0) {
                        send = true;
                        st.next_report = Some(now.add(u64::from(report.report_interval_ms) * spm));
                    }
                }
                Some(ev) => {
                    // Serving-cell events (A1 / A2); the neighbour-based events
                    // (A3–A6) have no candidate cells yet.
                    let hys = f32::from(ev.hysteresis) / 2.0;
                    let (entering, leaving) = match ev.event {
                        EventId::A1 { threshold } => {
                            let (ms, th) = f.quantity(&threshold);
                            (ms - hys > th, ms + hys < th)
                        }
                        EventId::A2 { threshold } => {
                            let (ms, th) = f.quantity(&threshold);
                            (ms + hys < th, ms - hys > th)
                        }
                        _ => (false, false),
                    };
                    let ttt = u64::from(ev.time_to_trigger_ms) * spm;
                    if !st.triggered {
                        if entering {
                            let since = *st.entering_since.get_or_insert(now);
                            if now.diff(&since) as u64 >= ttt {
                                st.triggered = true;
                                st.reports_sent = 0;
                                st.entering_since = None;
                                send = true;
                                st.next_report = Some(now.add(u64::from(report.report_interval_ms) * spm));
                            }
                        } else {
                            st.entering_since = None;
                        }
                    } else {
                        if leaving {
                            let since = *st.leaving_since.get_or_insert(now);
                            if now.diff(&since) as u64 >= ttt {
                                st.triggered = false;
                                st.leaving_since = None;
                                st.next_report = None;
                                if ev.report_on_leave {
                                    send = true;
                                }
                            }
                        } else {
                            st.leaving_since = None;
                        }
                        if st.triggered && !report.report_amount.is_some_and(|n| st.reports_sent >= u32::from(n)) && st.next_report.is_some_and(|t| now.diff(&t) >= 0) {
                            send = true;
                            st.next_report = Some(now.add(u64::from(report.report_interval_ms) * spm));
                        }
                    }
                }
            }
            if send {
                st.reports_sent += 1;
                let serving_cell = asn::MeasResultNr { pci: self.serving_pci, results_ssb_cell: Some(f.results(report.report_quantity_cell)), results_csi_rs_cell: None };
                self.pending.push(asn::MeasResults { meas_id: id, serving: vec![asn::MeasResultServMo { serv_cell_id: 0, serving_cell, best_neigh_cell: None }], neigh_cells_nr: Vec::new() });
            }
            self.ids.insert(id, st);
        }
    }
}

impl MeasIdState {
    fn reset(&mut self) {
        self.reports_sent = 0;
        self.next_report = None;
        self.entering_since = None;
        self.leaving_since = None;
        self.triggered = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_asn1::meas::*;
    use ferrite_common::Numerology;

    fn slot(n: u64) -> SlotPoint {
        SlotPoint::from_index(Numerology::from_scs_khz(30).unwrap(), n)
    }

    fn config(report: ReportConfigNr) -> MeasConfig {
        MeasConfig {
            meas_object_to_add_mod_list: vec![MeasObjectToAddMod { meas_object_id: 1, meas_object: MeasObjectNr { quantity_config_index: 1, ..Default::default() } }],
            report_config_to_add_mod_list: vec![ReportConfigToAddMod { report_config_id: 1, report_config: report }],
            meas_id_to_add_mod_list: vec![MeasIdToAddMod { meas_id: 1, meas_object_id: 1, report_config_id: 1 }],
            quantity_config: Some(vec![QuantityConfigNr { cell: QuantityConfigRs { ssb: FilterConfig { rsrp: 0, rsrq: 0, rs_sinr: 0 }, csi_rs: FilterConfig::default() }, rs_index: None }]),
            ..Default::default()
        }
    }

    fn periodical() -> ReportConfigNr {
        ReportConfigNr {
            event: None,
            rs_type: RsType::Ssb,
            report_interval_ms: 1024,
            report_amount: Some(2),
            report_quantity_cell: MeasReportQuantity { rsrp: true, rsrq: true, sinr: false },
            max_report_cells: 1,
            report_quantity_rs_indexes: None,
            max_nrof_rs_indexes_to_report: None,
            include_beam_measurements: false,
            use_allowed_cell_list: false,
        }
    }

    #[test]
    fn periodical_reports_immediately_then_on_interval_up_to_amount() {
        let mut p = MeasProcedure::default();
        p.apply(&config(periodical()));
        let m = CellMeasurement { pci: 1, rsrp_dbm: -80.0, rsrq_db: -10.5, sinr_db: 20.0 };
        p.on_serving_measurement(slot(0), &m);
        let r = p.take_reports();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].meas_id, 1);
        assert_eq!(r[0].serving[0].serving_cell.pci, Some(1));
        assert_eq!(r[0].serving[0].serving_cell.results_ssb_cell, Some(MeasQuantityResults { rsrp: Some(77), rsrq: Some(66), sinr: None }));
        p.tick(slot(2000));
        assert!(p.take_reports().is_empty(), "before the interval");
        p.tick(slot(2048));
        assert_eq!(p.take_reports().len(), 1);
        p.tick(slot(4096));
        assert!(p.take_reports().is_empty(), "reportAmount exhausted");
    }

    #[test]
    fn a2_event_with_time_to_trigger_and_leave() {
        let mut rc = periodical();
        rc.event = Some(EventTrigger { event: EventId::A2 { threshold: MeasTriggerQuantity::Rsrp(rsrp_range(-90.0)) }, report_on_leave: true, hysteresis: 2, time_to_trigger_ms: 100 });
        rc.report_amount = None;
        let mut p = MeasProcedure::default();
        p.apply(&config(rc));
        let good = CellMeasurement { pci: 1, rsrp_dbm: -80.0, rsrq_db: -10.0, sinr_db: 20.0 };
        let bad = CellMeasurement { pci: 1, rsrp_dbm: -95.0, rsrq_db: -15.0, sinr_db: 5.0 };
        p.on_serving_measurement(slot(0), &good);
        assert!(p.take_reports().is_empty());
        p.on_serving_measurement(slot(40), &bad);
        assert!(p.take_reports().is_empty(), "TTT (100 ms = 200 slots) not elapsed");
        p.on_serving_measurement(slot(240), &bad);
        assert_eq!(p.take_reports().len(), 1, "entered after TTT");
        p.on_serving_measurement(slot(300), &bad);
        assert!(p.take_reports().is_empty(), "interval not elapsed");
        p.on_serving_measurement(slot(240 + 2048), &bad);
        assert_eq!(p.take_reports().len(), 1, "periodic re-report while triggered");
        p.on_serving_measurement(slot(3000), &good);
        p.on_serving_measurement(slot(3200), &good);
        assert_eq!(p.take_reports().len(), 1, "report on leave after TTT");
        p.on_serving_measurement(slot(6000), &good);
        assert!(p.take_reports().is_empty());
    }

    #[test]
    fn filtering_uses_the_quantity_config() {
        let mut cfg = config(periodical());
        cfg.quantity_config = Some(vec![QuantityConfigNr { cell: QuantityConfigRs { ssb: FilterConfig { rsrp: 4, rsrq: 4, rs_sinr: 4 }, csi_rs: FilterConfig::default() }, rs_index: None }]);
        let mut p = MeasProcedure::default();
        p.apply(&cfg);
        p.on_serving_measurement(slot(0), &CellMeasurement { pci: 1, rsrp_dbm: -80.0, rsrq_db: -10.0, sinr_db: 20.0 });
        p.take_reports();
        p.on_serving_measurement(slot(10), &CellMeasurement { pci: 1, rsrp_dbm: -100.0, rsrq_db: -10.0, sinr_db: 20.0 });
        let f = p.serving[&1];
        // a = 1/2 for k = 4: −80·0.5 + −100·0.5 = −90.
        assert!((f.rsrp_dbm + 90.0).abs() < 1e-3, "{}", f.rsrp_dbm);
    }
}
