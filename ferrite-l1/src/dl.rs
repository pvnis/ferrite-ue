//! Downlink receive processing: PDCCH monitoring (TS 38.213 §10) on the
//! timeline thread, and PDSCH reception with HARQ soft combining (TS 38.212
//! §5.4.2, TS 38.214 §5.1) plus CSI-RS measurement on the worker thread.

use crate::cell::CellGeometry;
use crate::config::{CoresetConfig, PhyConfig, SearchSpaceConfig, SearchSpaceKind};
use crate::fapi::*;
use crate::resolve::DciResolver;
use ferrite_common::{Iq, Rnti, RntiKind, SlotPoint};
use ferrite_phy::coding::dci::{dci_decode, pdcch_descramble_llr};
use ferrite_phy::coding::dlsch;
use ferrite_phy::coreset0::{Coreset0Config, SfnParity, Type0Monitoring};
use ferrite_phy::csi;
use ferrite_phy::dmrs::{pdsch_dmrs_symbols, MappingType};
use ferrite_phy::ofdm::PhaseCompensation;
use ferrite_phy::pdcch::{self, Candidate, CceToRegMapping, Coreset, SearchSpace};
use ferrite_phy::pdsch::{self, PdschAlloc, VrbToPrb};
use ferrite_phy::Ofdm;
use std::collections::HashMap;

/// The RNTIs the monitor looks for.
#[derive(Clone, Copy, Debug, Default)]
pub struct ActiveRntis {
    pub si: bool,
    pub ra: Option<Rnti>,
    pub tc: Option<Rnti>,
    pub c: Option<Rnti>,
    /// P-RNTI monitoring for this UE_ID (5G-S-TMSI mod 1024) in its paging frames.
    pub p_ue_id: Option<u16>,
}

/// Where a search space lives and what it monitors.
struct MonitoredSs {
    ss: SearchSpace,
    kind: SearchSpaceKind,
    coreset_idx: usize,
    is_type0: bool,
}

/// PDCCH monitor for one cell.
pub struct DlMonitor {
    pub ofdm: Ofdm,
    /// Receive-side TS 38.211 §5.4 phase compensation for the DL carrier.
    comp: PhaseCompensation,
    pub geom: CellGeometry,
    coresets: Vec<Coreset>,
    spaces: Vec<MonitoredSs>,
    type0: Option<Type0Monitoring>,
    pub resolver: DciResolver,
    pub rntis: ActiveRntis,
    /// DRX: C-RNTI candidates are searched only while MAC is in Active Time.
    pub monitor_c_rnti: bool,
    paging: Option<crate::config::PagingConfig>,
    /// Coherence gate for the blind decode (fraction, ≈1 for a present PDCCH).
    pub coherence_gate: f32,
    dedicated: bool,
    llr_buf: Vec<f32>,
}

fn coreset_from_cfg(c: &CoresetConfig, cell_id: u16) -> Coreset {
    let mapping = match c.interleaved {
        Some((l, r, shift)) => CceToRegMapping::Interleaved {
            reg_bundle_size: l as usize,
            interleaver_size: r as usize,
            shift_index: shift,
        },
        None => CceToRegMapping::NonInterleaved,
    };
    let rbs: Vec<usize> = c
        .rb_mask
        .iter()
        .enumerate()
        .filter(|(_, &b)| b)
        .map(|(i, _)| c.start_crb as usize + i)
        .collect();
    Coreset {
        id: c.id,
        rbs,
        n_symb: c.duration as usize,
        mapping,
        precoder_granularity: pdcch::PrecoderGranularity::SameAsRegBundle,
        dmrs_scrambling_id: c.dmrs_scrambling_id.unwrap_or(cell_id),
        dmrs_ref_crb: if c.ref_lowest_rb {
            c.start_crb as usize
        } else {
            0
        },
    }
}

fn ss_from_cfg(s: &SearchSpaceConfig) -> SearchSpace {
    SearchSpace {
        id: s.id,
        coreset_id: s.coreset_id,
        period_slots: s.period_slots as u32,
        offset_slots: s.offset_slots as u32,
        duration_slots: s.duration_slots.max(1) as u32,
        first_symbols: s.symbols,
        n_candidates: s.candidates,
        kind: match s.kind {
            SearchSpaceKind::Common => pdcch::SearchSpaceKind::Common,
            SearchSpaceKind::UeSpecificFallback => {
                pdcch::SearchSpaceKind::UeSpecific { fallback: true }
            }
            SearchSpaceKind::UeSpecificNonFallback => {
                pdcch::SearchSpaceKind::UeSpecific { fallback: false }
            }
        },
    }
}

impl DlMonitor {
    /// Build from a PHY configuration. `coreset0_cfg` + `type0` describe the
    /// Type0-PDCCH CSS (SIB1) monitoring; `dedicated` enables DCI 0_1/1_1.
    pub fn new(
        geom: CellGeometry,
        cfg: &PhyConfig,
        cell_id: u16,
        type0: Option<(Coreset0Config, Type0Monitoring)>,
        dedicated: bool,
    ) -> Self {
        let coresets: Vec<Coreset> = cfg
            .coresets
            .iter()
            .map(|c| coreset_from_cfg(c, cell_id))
            .collect();
        let mut spaces: Vec<MonitoredSs> = Vec::new();
        if let Some((_, t0)) = &type0 {
            if let Some(ci) = coresets.iter().position(|c| c.id == 0) {
                spaces.push(MonitoredSs {
                    ss: SearchSpace::type0(t0.first_symbol as usize),
                    kind: SearchSpaceKind::Common,
                    coreset_idx: ci,
                    is_type0: true,
                });
            }
        }
        for s in &cfg.search_spaces {
            if let Some(ci) = coresets.iter().position(|c| c.id == s.coreset_id) {
                spaces.push(MonitoredSs {
                    ss: ss_from_cfg(s),
                    kind: s.kind,
                    coreset_idx: ci,
                    is_type0: false,
                });
            }
        }
        let ofdm = Ofdm::new(geom.fft);
        let comp = PhaseCompensation::new(&ofdm, geom.numerology.mu, geom.dl_center_hz, true);
        Self {
            ofdm,
            comp,
            geom,
            coresets,
            spaces,
            type0: type0.map(|t| t.1),
            resolver: DciResolver::new(cfg, dedicated),
            rntis: ActiveRntis::default(),
            monitor_c_rnti: true,
            paging: cfg.paging,
            coherence_gate: 0.1,
            dedicated,
            llr_buf: Vec::new(),
        }
    }

    /// Is the Type0 CSS monitored in `slot` (TS 38.213 §13: slots n0 and n0+1
    /// of frames with the right SFN parity)?
    fn type0_monitored(&self, slot: SlotPoint) -> bool {
        let Some(t) = &self.type0 else { return false };
        let parity_ok = match t.sfn_parity {
            SfnParity::Even => slot.sfn.is_multiple_of(2),
            SfnParity::Odd => slot.sfn % 2 == 1,
        };
        parity_ok
            && (slot.slot as u32 == t.n0 || slot.slot as u32 == (t.n0 + 1) % slot.slots_per_frame())
    }

    /// Search all monitored search spaces of `slot` in `samples` (one slot,
    /// CFO-corrected) and return the resolved DCIs.
    pub fn monitor(&mut self, slot: SlotPoint, samples: &[Iq]) -> Vec<DciIndication> {
        let mut out = Vec::new();
        let sis = slot.slot_in_subframe() as usize;
        let mut sym_grids: HashMap<usize, Vec<Iq>> = HashMap::new();
        let demod = |l: usize, grids: &mut HashMap<usize, Vec<Iq>>| {
            if let std::collections::hash_map::Entry::Vacant(e) = grids.entry(l) {
                let off = self.ofdm.slot_symbol_offsets(self.geom.numerology.mu, sis)[l];
                let cp = self.ofdm.cp_len(sis * 14 + l, self.geom.numerology.mu);
                let mut g = self.ofdm.demodulate_symbol(&samples[off..], cp);
                self.comp.apply(&mut g, sis * 14 + l);
                e.insert(g);
            }
        };
        let sc_to_bin = self.geom.dl_sc_to_bin();
        // Common search spaces first: a PDCCH sent in CORESET#0 can also be
        // decodable through a UE-specific candidate on a dedicated CORESET
        // whose REGs physically coincide, where the fallback-format fields
        // would be read against the active BWP instead of CORESET#0 (or the
        // payload mistaken for a non-fallback format of the same size). The
        // CSS interpretation is the gNB's; any later decode of the same
        // payload for the same RNTI in this slot is the same PDCCH.
        let mut order: Vec<usize> = (0..self.spaces.len()).collect();
        order.sort_by_key(|&i| self.spaces[i].kind != SearchSpaceKind::Common);
        let mut seen: Vec<(u16, Vec<u8>)> = Vec::new();
        for i in order {
            let monitored = if self.spaces[i].is_type0 {
                self.type0_monitored(slot)
            } else {
                self.spaces[i].ss.is_monitored(slot)
            };
            if !monitored {
                continue;
            }
            let coreset = &self.coresets[self.spaces[i].coreset_idx];
            let n_cce = coreset.n_cce();
            let first_symbols: Vec<usize> = self.spaces[i]
                .ss
                .first_symbols
                .iter()
                .enumerate()
                .filter(|(_, &b)| b)
                .map(|(l, _)| l)
                .collect();
            for &l0 in &first_symbols {
                if l0 + coreset.n_symb > 14 {
                    continue;
                }
                for l in l0..l0 + coreset.n_symb {
                    demod(l, &mut sym_grids);
                }
                let grids: Vec<Vec<Iq>> = (l0..l0 + coreset.n_symb)
                    .map(|l| sym_grids[&l].clone())
                    .collect();
                let est = pdcch::estimate_coreset(&grids, sc_to_bin, coreset, slot.slot as u32);
                // Which RNTIs / formats apply in this search space.
                let mut targets: Vec<(Rnti, RntiKind)> = Vec::new();
                let kind = self.spaces[i].kind;
                let is_type0 = self.spaces[i].is_type0;
                if is_type0 && self.rntis.si {
                    targets.push((Rnti::SI, RntiKind::Si));
                }
                // Paging: the P-RNTI in the paging search space during the UE's
                // paging frames (every monitoring occasion of the frame — a
                // superset of the PO, TS 38.304 §7.1).
                if kind == SearchSpaceKind::Common {
                    if let (Some(pg), Some(ue_id)) = (self.paging, self.rntis.p_ue_id) {
                        let is_paging_ss = if pg.search_space_id == 0 {
                            is_type0
                        } else {
                            !is_type0 && self.spaces[i].ss.id == pg.search_space_id
                        };
                        if is_paging_ss && pg.is_paging_frame(slot.sfn, ue_id) {
                            targets.push((Rnti::P, RntiKind::P));
                        }
                    }
                }
                if kind == SearchSpaceKind::Common && !is_type0 {
                    if let Some(r) = self.rntis.ra {
                        targets.push((r, RntiKind::Ra));
                    }
                    if let Some(r) = self.rntis.tc {
                        targets.push((r, RntiKind::Tc));
                    }
                    if let Some(r) = self.rntis.c.filter(|_| self.monitor_c_rnti) {
                        targets.push((r, RntiKind::C));
                    }
                }
                if kind != SearchSpaceKind::Common {
                    if let Some(r) = self.rntis.c.filter(|_| self.monitor_c_rnti) {
                        targets.push((r, RntiKind::C));
                    }
                }
                if targets.is_empty() {
                    continue;
                }
                let cands: Vec<Candidate> = if is_type0 {
                    pdcch::type0_candidates(n_cce)
                } else {
                    let rnti = targets[0].0;
                    self.spaces[i]
                        .ss
                        .candidates(coreset, rnti.0, slot.slot as u32)
                };
                if log::log_enabled!(log::Level::Trace) {
                    let best = cands
                        .iter()
                        .map(|c| pdcch::candidate_coherence(&est, coreset, c))
                        .fold(0.0f32, f32::max);
                    let pow: f32 = grids
                        .iter()
                        .flat_map(|g| g.iter())
                        .map(|c| c.norm_sqr())
                        .sum();
                    log::trace!("slot {slot} ss {} l0 {l0} type0 {is_type0} cands {} best coherence {best:.2} coreset power {pow:.3}", self.spaces[i].ss.id, cands.len());
                    if pow > 1.0 {
                        // Per-RB DMRS coherence: |Σ rx·ref*| / Σ|rx| over the 3 DMRS REs of each (symbol, RB).
                        for l in 0..coreset.n_symb {
                            let refs = pdcch::pdcch_dmrs_sequence(
                                coreset.dmrs_scrambling_id,
                                slot.slot as u32,
                                l as u32,
                                3 * (coreset.rbs.last().copied().unwrap_or(0) + 1),
                            );
                            let mut line = String::new();
                            for (ri, &crb) in coreset.rbs.iter().enumerate() {
                                let mut acc = ferrite_common::Iq::default();
                                let mut mag = 0.0f32;
                                for kp in 0..3 {
                                    let rx = grids[l][sc_to_bin(12 * crb + 1 + 4 * kp)];
                                    let r = refs[3 * (crb - coreset.dmrs_ref_crb) + kp];
                                    acc += rx * r.conj();
                                    mag += rx.norm();
                                }
                                let c = if mag > 1e-9 { acc.norm() / mag } else { 0.0 };
                                let _ = ri;
                                line.push(
                                    char::from_digit((c * 9.99).floor() as u32, 10).unwrap_or('?'),
                                );
                            }
                            log::trace!("  symbol {l} per-RB dmrs coherence: {line}");
                        }
                    }
                }
                for cand in &cands {
                    if pdcch::candidate_coherence(&est, coreset, cand) < self.coherence_gate {
                        continue;
                    }
                    let mut llr = std::mem::take(&mut self.llr_buf);
                    pdcch::equalize_candidate_cached(
                        &grids, sc_to_bin, coreset, cand, &est, &mut llr,
                    );
                    pdcch_descramble_llr(&mut llr, u32::from(coreset.dmrs_scrambling_id));
                    let cce0 = cand.cces[0];
                    let mut hit = false;
                    for &(rnti, rk) in &targets {
                        let in_css = kind == SearchSpaceKind::Common;
                        // Fallback formats 0_0/1_0 (one size for both; bit 0 tells them apart).
                        let fb_size = if in_css {
                            self.resolver.sizes.f1_0_css.total
                        } else {
                            self.resolver
                                .sizes
                                .f1_0_uss
                                .as_ref()
                                .map_or(self.resolver.sizes.f1_0_css.total, |s| s.total)
                        };
                        // 0_0/1_0 are tried only where they are monitored: in a CSS
                        // or a USS configured for them. A non-fallback USS whose
                        // 0_1 happens to have the fallback size would otherwise
                        // see its 0_1 payloads read with the 0_0 field layout.
                        let try_fallback = in_css || kind == SearchSpaceKind::UeSpecificFallback;
                        if try_fallback {
                            if let Some(bits) = dci_decode(&llr, rnti.0, fb_size) {
                                if seen.iter().any(|(r, b)| *r == rnti.0 && *b == bits) {
                                    log::debug!("dci {rk:?} fallback size {fb_size} al {} cce0 {cce0} ss {} @{slot}: same PDCCH as an earlier search space, ignored", cand.cces.len(), self.spaces[i].ss.id);
                                    hit = true;
                                    break;
                                }
                                // SI/RA/P-RNTI DCIs are always format 1_0 and carry no
                                // format identifier; TC/C-RNTI DCIs start with it (0 = 0_0).
                                let dci =
                                    if !matches!(rk, RntiKind::Tc | RntiKind::C) || bits[0] == 1 {
                                        self.resolver
                                            .resolve_1_0(&bits, rnti, rk, in_css, slot, cce0, n_cce)
                                    } else {
                                        self.resolver.resolve_0_0(&bits, rnti, rk, in_css, slot)
                                    };
                                if let Some(d) = dci {
                                    log::debug!("dci {rk:?} fallback size {fb_size} al {} cce0 {cce0} ss {} @{slot}: {d:?}", cand.cces.len(), self.spaces[i].ss.id);
                                    seen.push((rnti.0, bits));
                                    out.push(DciIndication { slot, dci: d });
                                    hit = true;
                                    break;
                                }
                            }
                        }
                        if kind == SearchSpaceKind::UeSpecificNonFallback
                            && rk == RntiKind::C
                            && self.dedicated
                        {
                            let s11 = self.resolver.sizes.f1_1.as_ref().map(|s| s.total);
                            let s01 = self.resolver.sizes.f0_1.as_ref().map(|s| s.total);
                            let mut sizes = vec![];
                            if let Some(s) = s11 {
                                sizes.push(s);
                            }
                            if let Some(s) = s01 {
                                if Some(s) != s11 {
                                    sizes.push(s);
                                }
                            }
                            for sz in sizes {
                                if let Some(bits) = dci_decode(&llr, rnti.0, sz) {
                                    if seen.iter().any(|(r, b)| *r == rnti.0 && *b == bits) {
                                        log::debug!("dci {rk:?} non-fallback size {sz} al {} cce0 {cce0} ss {} @{slot}: same PDCCH as an earlier search space, ignored", cand.cces.len(), self.spaces[i].ss.id);
                                        hit = true;
                                        break;
                                    }
                                    let dci = if bits[0] == 1 {
                                        self.resolver.resolve_1_1(&bits, rnti, slot, cce0, n_cce)
                                    } else {
                                        self.resolver.resolve_0_1(&bits, rnti, slot)
                                    };
                                    if let Some(d) = dci {
                                        log::debug!("dci {rk:?} non-fallback size {sz} al {} cce0 {cce0} ss {} @{slot}: {d:?}", cand.cces.len(), self.spaces[i].ss.id);
                                        seen.push((rnti.0, bits));
                                        out.push(DciIndication { slot, dci: d });
                                        hit = true;
                                        break;
                                    }
                                }
                            }
                            if hit {
                                break;
                            }
                        }
                    }
                    self.llr_buf = llr;
                    let _ = hit;
                }
                // Diagnostic (trace level): if nothing decoded on a CORESET with
                // power, sweep the slot timing to find the offset that does.
                if log::log_enabled!(log::Level::Trace) && out.is_empty() && is_type0 {
                    let pow: f32 = grids
                        .iter()
                        .flat_map(|g| g.iter())
                        .map(|c| c.norm_sqr())
                        .sum();
                    if pow > 1.0 {
                        let mu = self.geom.numerology.mu;
                        let offs = self.ofdm.slot_symbol_offsets(mu, sis);
                        let fb = self.resolver.sizes.f1_0_css.total;
                        let mut found = Vec::new();
                        for delta in -40i64..=40 {
                            let g2: Vec<Vec<Iq>> = (l0..l0 + coreset.n_symb)
                                .map(|l| {
                                    let off = offs[l] as i64 + delta;
                                    let cp = self.ofdm.cp_len(sis * 14 + l, mu);
                                    if off < 0 || off as usize + cp + self.geom.fft > samples.len()
                                    {
                                        vec![Iq::default(); self.geom.fft]
                                    } else {
                                        let mut g = self
                                            .ofdm
                                            .demodulate_symbol(&samples[off as usize..], cp);
                                        self.comp.apply(&mut g, sis * 14 + l);
                                        g
                                    }
                                })
                                .collect();
                            let est2 =
                                pdcch::estimate_coreset(&g2, sc_to_bin, coreset, slot.slot as u32);
                            for cand in &cands {
                                let mut llr = Vec::new();
                                pdcch::equalize_candidate_cached(
                                    &g2, sc_to_bin, coreset, cand, &est2, &mut llr,
                                );
                                pdcch_descramble_llr(
                                    &mut llr,
                                    u32::from(coreset.dmrs_scrambling_id),
                                );
                                if dci_decode(&llr, Rnti::SI.0, fb).is_some() {
                                    found.push((
                                        delta,
                                        cand.agg_level,
                                        cand.cces[0],
                                        pdcch::candidate_coherence(&est2, coreset, cand),
                                    ));
                                }
                            }
                        }
                        log::trace!(
                            "  timing sweep decodes (delta, AL, cce0, coherence): {found:?}"
                        );
                    }
                }
            }
        }
        out
    }
}

// ----------------------------------------------------------------- worker

/// One PDSCH to decode (the samples of its slot travel with it).
pub struct PdschJob {
    pub slot: SlotPoint,
    /// One slot of samples per receive antenna.
    pub samples: std::sync::Arc<Vec<Vec<Iq>>>,
    pub grant: DlGrant,
    /// Retransmission of an already delivered TB: ACK without decoding.
    pub skip_decode: bool,
    /// When the engine queued the job (latency diagnostics).
    pub queued: std::time::Instant,
}

/// What the worker needs from the configuration.
#[derive(Clone)]
pub struct WorkerConfig {
    pub geom: CellGeometry,
    pub cell_id: u16,
    pub dl_bwp_start: usize,
    pub dl_bwp_rb: usize,
    pub vrb_bundle_size: usize,
    pub coreset0_first_crb: usize,
    pub coreset0_rb: usize,
    pub dmrs_typea_pos: u8,
    pub scrambling_id: Option<u16>,
    pub dmrs_scrambling_id0: Option<u16>,
    pub csi_patterns: Vec<csi::CsiRsPattern>,
    pub csi_meas: Vec<(csi::CsiRsMeasurement, u32, u32)>, // (measurement, period, offset)
    pub csi_rate_match_enabled: bool,
}

struct SoftBuffer {
    tbs: usize,
    /// NDI of the transmission the buffer belongs to: a toggle means a new TB.
    ndi: u8,
    acc: Vec<f32>,
    n_rx: u32,
}

/// The PDSCH worker: owns the HARQ soft buffers (one per RNTI kind + process).
pub struct PdschWorker {
    pub cfg: WorkerConfig,
    ofdm: Ofdm,
    comp: PhaseCompensation,
    buffers: HashMap<(RntiKind, u8), SoftBuffer>,
    pub max_iter: usize,
}

impl PdschWorker {
    pub fn new(cfg: WorkerConfig) -> Self {
        let ofdm = Ofdm::new(cfg.geom.fft);
        let comp =
            PhaseCompensation::new(&ofdm, cfg.geom.numerology.mu, cfg.geom.dl_center_hz, true);
        Self {
            ofdm,
            comp,
            cfg,
            buffers: HashMap::new(),
            max_iter: 12,
        }
    }

    pub fn reconfigure(&mut self, cfg: WorkerConfig) {
        if cfg.geom.fft != self.cfg.geom.fft {
            self.ofdm = Ofdm::new(cfg.geom.fft);
        }
        self.comp = PhaseCompensation::new(
            &self.ofdm,
            cfg.geom.numerology.mu,
            cfg.geom.dl_center_hz,
            true,
        );
        self.cfg = cfg;
        self.buffers.clear();
    }

    /// Measure the configured TRS/CSI-RS in `slot` if there is one
    /// (`grids_all[antenna][symbol]`).
    pub fn measure_csi(
        &self,
        slot: SlotPoint,
        grids_all: &[Vec<Vec<Iq>>],
    ) -> Option<CsiIndication> {
        let grids: &[Vec<Iq>] = &grids_all[0];
        let sc_to_bin = self.cfg.geom.dl_sc_to_bin();
        for (m, period, offset) in &self.cfg.csi_meas {
            if !csi::csi_rs_slots(*period, *offset, slot) {
                continue;
            }
            let sinr = csi::measure_csi_rs_sinr(&grids[m.symbol], sc_to_bin, m, slot.slot as u32);
            let rsrp = grids[m.symbol].iter().map(|c| c.norm_sqr()).sum::<f32>()
                / grids[m.symbol].len().max(1) as f32;
            // Rank: one layer per receive antenna (up to two) until the
            // two-port CSI-RS measurement exists — right for the lab's
            // identity channel, where each antenna sees one gNB port.
            let ri = grids_all.len().min(2) as u8;
            return Some(CsiIndication {
                slot,
                sinr_db: sinr,
                cqi: csi::sinr_to_cqi(sinr),
                rsrp_dbfs: 10.0 * rsrp.max(1e-12).log10(),
                ri,
                pmi: 0,
            });
        }
        None
    }

    pub fn demod(&self, slot: SlotPoint, samples: &[Iq]) -> Option<Vec<Vec<Iq>>> {
        pdsch::demod_slot(
            &self.ofdm,
            samples,
            0,
            slot.slot_in_subframe() as usize,
            self.cfg.geom.numerology.mu,
            Some(&self.comp),
        )
    }

    /// Decode one PDSCH from the demodulated grids of every receive antenna
    /// (`grids_all[antenna][symbol]`).
    pub fn decode(&mut self, job: &PdschJob, grids_all: &[Vec<Vec<Iq>>]) -> RxDataIndication {
        let g = &job.grant;
        let grids: &[Vec<Iq>] = &grids_all[0];
        let fail = |sinr: f32| RxDataIndication {
            rnti: g.rnti,
            rnti_kind: g.rnti_kind,
            harq_id: g.harq_id,
            ndi: g.ndi,
            pdsch_slot: job.slot,
            tb: None,
            sinr_db: sinr,
        };
        if job.skip_decode {
            return RxDataIndication {
                tb: Some(Vec::new()),
                ..fail(0.0)
            };
        }
        let mapping = if g.time.mapping_type_a {
            MappingType::TypeA
        } else {
            MappingType::TypeB
        };
        let Ok(dmrs) = pdsch_dmrs_symbols(
            mapping,
            self.cfg.dmrs_typea_pos,
            g.dmrs_add_pos,
            g.time.start_symbol as usize,
            g.time.n_symbols as usize,
        ) else {
            return fail(0.0);
        };
        // Common (SI/RA/TC in CSS, DCI 1_0): PRBs and DMRS referenced to CORESET0's
        // lowest RB when CORESET0 exists; dedicated: the BWP / CRB 0.
        let common = matches!(g.rnti_kind, RntiKind::Si | RntiKind::Ra | RntiKind::P)
            || (g.rnti_kind == RntiKind::Tc);
        let (bwp_start, dmrs_ref, vrb) = if common && self.cfg.coreset0_rb > 0 {
            let vrb = if g.vrb_to_prb_interleaved {
                VrbToPrb::coreset0(self.cfg.coreset0_rb)
            } else {
                VrbToPrb::NonInterleaved
            };
            (
                self.cfg.coreset0_first_crb,
                self.cfg.coreset0_first_crb,
                vrb,
            )
        } else {
            let vrb = if g.vrb_to_prb_interleaved {
                VrbToPrb::Interleaved {
                    bundle_size: self.cfg.vrb_bundle_size.max(2),
                    n_bwp_start: self.cfg.dl_bwp_start,
                    n_bwp_size: self.cfg.dl_bwp_rb.max(1),
                }
            } else {
                VrbToPrb::NonInterleaved
            };
            (self.cfg.dl_bwp_start, 0, vrb)
        };
        // PRBs in the grant are BWP-relative; re-base when the "BWP" is CORESET0.
        let prb_start = if common && self.cfg.coreset0_rb > 0 {
            (g.prb_start as usize + self.cfg.dl_bwp_start)
                .saturating_sub(self.cfg.coreset0_first_crb)
        } else {
            g.prb_start as usize
        };
        let scrambling_id = if g.rnti_kind == RntiKind::C {
            self.cfg.scrambling_id.unwrap_or(self.cfg.cell_id)
        } else {
            self.cfg.cell_id
        };
        let dmrs_id = if g.rnti_kind == RntiKind::C {
            self.cfg.dmrs_scrambling_id0.unwrap_or(self.cfg.cell_id)
        } else {
            self.cfg.cell_id
        };
        let alloc = PdschAlloc {
            rb_start: prb_start,
            n_rb: g.n_prb as usize,
            bwp_start_crb: bwp_start,
            dmrs_ref_crb: dmrs_ref,
            sym_start: g.time.start_symbol as usize,
            n_sym: g.time.n_symbols as usize,
            dmrs_symbols: dmrs,
            nof_cdm_groups_without_data: g.cdm_groups_wo_data as usize,
            qm: g.mcs.qm as usize,
            vrb_to_prb: vrb,
            n_scid: 0,
            scrambling_id: dmrs_id,
        };
        let geom = &self.cfg.geom;
        let bin = geom.dl_sc_to_bin();
        let sc_to_bin = move |sc: usize| bin(12 * bwp_start + sc);
        let slot_in_frame = job.slot.slot as u32;
        let patterns = &self.cfg.csi_patterns;
        let slot = job.slot;
        let rm_enabled = self.cfg.csi_rate_match_enabled && g.rnti_kind == RntiKind::C;
        let skipped = std::cell::Cell::new(0usize);
        let skip = |l: usize, prb: usize, k: usize| {
            let s = csi::csi_rs_rate_match(patterns, slot, l, bwp_start + prb, k);
            if s {
                skipped.set(skipped.get() + 1);
            }
            s
        };
        let n_layers = usize::from(g.n_layers.max(1));
        let px = if grids_all.len() == 1 && n_layers == 1 {
            pdsch::extract_pdsch(
                grids,
                sc_to_bin,
                &alloc,
                slot_in_frame,
                if rm_enabled { Some(&skip) } else { None },
            )
        } else {
            let ports: Vec<u8> = if g.dmrs_ports.is_empty() {
                vec![0]
            } else {
                g.dmrs_ports.clone()
            };
            pdsch::extract_pdsch_mimo(
                grids_all,
                sc_to_bin,
                &alloc,
                slot_in_frame,
                if rm_enabled { Some(&skip) } else { None },
                &ports,
            )
        };
        let sinr = if px.evm > 1e-6 {
            -20.0 * px.evm.log10()
        } else {
            40.0
        };
        log::debug!(
            "pdsch {:?} {} @{}: rb {}+{} (bwp {} ref {}) sym {}+{} dmrs {:?} cdm {} layers {} ports {:?} ant {} qm {} tbs {} data-re {} rm {} skipped {} of {} patterns dmrs-metric {:.2} evm {:.2} (extracted {:.2} ms after queueing)",
            g.rnti_kind, g.rnti.0, job.slot, alloc.rb_start, alloc.n_rb, bwp_start, dmrs_ref, alloc.sym_start, alloc.n_sym, alloc.dmrs_symbols, alloc.nof_cdm_groups_without_data, n_layers, g.dmrs_ports, grids_all.len(), alloc.qm, g.tbs_bits, px.llrs.len() / alloc.qm.max(1), rm_enabled, skipped.get(), patterns.len(), px.dmrs_metric, px.evm, job.queued.elapsed().as_secs_f64() * 1e3
        );
        if log::log_enabled!(log::Level::Trace) && px.evm > 0.2 {
            // Per-symbol / per-RB EVM against a flat per-RB channel from the
            // first DM-RS symbol, to localise bad REs.
            let prbs = alloc.prbs();
            let l0 = alloc.dmrs_symbols[0];
            let refs = ferrite_phy::pdsch::pdsch_dmrs_sequence(
                alloc.scrambling_id,
                0,
                slot_in_frame,
                l0 as u32,
                alloc.dmrs_seq_base() + 6 * (prbs.iter().copied().max().unwrap_or(0) + 1),
            );
            let boost = if alloc.nof_cdm_groups_without_data >= 2 {
                std::f32::consts::FRAC_1_SQRT_2
            } else {
                1.0
            };
            let h: Vec<Iq> = prbs
                .iter()
                .map(|&p| {
                    (0..6)
                        .map(|j| {
                            grids[l0][sc_to_bin(12 * p + 2 * j)]
                                * refs[alloc.dmrs_seq_base() + 6 * p + j].conj()
                        })
                        .sum::<Iq>()
                        / 6.0
                        * boost
                })
                .collect();
            let evm_of = |l: usize, rb: usize| -> (f32, usize) {
                let (mut e, mut n) = (0f32, 0usize);
                for k in 0..12 {
                    if !alloc.is_data_re(l, k) {
                        continue;
                    }
                    let y = grids[l][sc_to_bin(12 * prbs[rb] + k)] / h[rb];
                    let q = Iq::new(y.re.signum(), y.im.signum()) * std::f32::consts::FRAC_1_SQRT_2;
                    e += (y - q).norm_sqr();
                    n += 1;
                }
                (e, n)
            };
            let per_sym: Vec<String> = (alloc.sym_start..alloc.sym_start + alloc.n_sym)
                .map(|l| {
                    let (e, n) = (0..alloc.n_rb)
                        .map(|rb| evm_of(l, rb))
                        .fold((0.0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
                    format!("{l}:{:.2}", (e / n.max(1) as f32).sqrt())
                })
                .collect();
            let per_rb: Vec<String> = (0..alloc.n_rb)
                .map(|rb| {
                    let (e, n) = (alloc.sym_start..alloc.sym_start + alloc.n_sym)
                        .map(|l| evm_of(l, rb))
                        .fold((0.0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
                    format!("{}:{:.2}", prbs[rb], (e / n.max(1) as f32).sqrt())
                })
                .collect();
            log::trace!("  evm per symbol {}", per_sym.join(" "));
            log::trace!("  evm per rb {}", per_rb.join(" "));
            let pw: Vec<String> = (alloc.sym_start..alloc.sym_start + alloc.n_sym)
                .map(|l| {
                    format!(
                        "{l}:{:.1e}",
                        (0..alloc.n_rb)
                            .flat_map(|rb| (0..12).map(move |k| (rb, k)))
                            .map(|(rb, k)| grids[l][sc_to_bin(12 * prbs[rb] + k)].norm_sqr())
                            .sum::<f32>()
                            / (12 * alloc.n_rb) as f32
                    )
                })
                .collect();
            log::trace!("  power per symbol {}", pw.join(" "));
            // Mean rotation vs the hard decision per symbol (first RB), and raw
            // equalized symbols of the first data symbol.
            let rot: Vec<String> = (alloc.sym_start..alloc.sym_start + alloc.n_sym)
                .map(|l| {
                    let mut acc = Iq::default();
                    let mut mag = 0f32;
                    let mut n = 0;
                    for rb in 0..alloc.n_rb {
                        for k in 0..12 {
                            if !alloc.is_data_re(l, k) {
                                continue;
                            }
                            let y = grids[l][sc_to_bin(12 * prbs[rb] + k)] / h[rb];
                            let q = Iq::new(y.re.signum(), y.im.signum());
                            acc += y * q.conj();
                            mag += y.norm();
                            n += 1;
                        }
                    }
                    format!(
                        "{l}:{:+.0}°/{:.2}",
                        acc.arg().to_degrees(),
                        mag / n.max(1) as f32
                    )
                })
                .collect();
            log::trace!("  rotation/|y| per symbol {}", rot.join(" "));
            let l = alloc.sym_start + 1;
            let ys: Vec<String> = (0..12)
                .map(|k| {
                    let y = grids[l][sc_to_bin(12 * prbs[0] + k)] / h[0];
                    format!("({:+.2},{:+.2})", y.re, y.im)
                })
                .collect();
            log::trace!("  sym {l} rb0 eq: {}", ys.join(" "));
        }
        if px.dmrs_metric < 0.3 {
            return fail(sinr);
        }
        let mut llr = px.llrs;
        pdsch::descramble_llrs(
            &mut llr,
            pdsch::pdsch_scramble_c_init(g.rnti.0, scrambling_id),
        );
        // TBS: a retransmission keeps the initial TB's size (MAC passes it in the grant).
        let tbs = g.tbs_bits as usize;
        let Some(r1024) = g
            .mcs
            .r_x1024
            .or_else(|| self.buffers.get(&(g.rnti_kind, g.harq_id)).map(|_| 0))
        else {
            return fail(sinr);
        };
        let r = if r1024 == 0 {
            0.5
        } else {
            r1024 as f64 / 1024.0
        };
        if tbs == 0 {
            return fail(sinr);
        }
        let qm = g.mcs.qm as usize;
        let key = (g.rnti_kind, g.harq_id);
        // Standalone decode first (fast path); then soft-combine for retransmissions.
        let (bits, _conv, crc) =
            dlsch::dlsch_decode_single_bits(&llr, tbs, r, qm, g.rv, self.max_iter);
        // The all-zero word is a valid LDPC codeword with a zero CRC: a decoder
        // fed garbage can converge on it. No real MAC PDU is all zeros.
        if crc && bits.iter().any(|&b| b != 0) {
            self.buffers.remove(&key);
            return RxDataIndication {
                tb: Some(pack_bits(&bits)),
                ..fail(sinr)
            };
        }
        let cb = dlsch::dlsch_cb_llr(&llr, tbs, r, qm, g.rv);
        if cb.is_empty() {
            return fail(sinr);
        }
        let e = self.buffers.entry(key).or_insert_with(|| SoftBuffer {
            tbs,
            ndi: g.ndi,
            acc: vec![0.0; cb.len()],
            n_rx: 0,
        });
        // A new transport block on this process (NDI toggled, or a different
        // size) starts a fresh soft buffer; same NDI = retransmission to combine.
        if e.tbs != tbs || e.acc.len() != cb.len() || e.ndi != g.ndi {
            *e = SoftBuffer {
                tbs,
                ndi: g.ndi,
                acc: vec![0.0; cb.len()],
                n_rx: 0,
            };
        }
        for (a, c) in e.acc.iter_mut().zip(&cb) {
            *a += c;
        }
        e.n_rx += 1;
        if e.n_rx >= 2 {
            let (cbits, _c, ccrc) = dlsch::dlsch_decode_cb(&e.acc, tbs, r, self.max_iter);
            if ccrc && cbits.iter().any(|&b| b != 0) {
                self.buffers.remove(&key);
                return RxDataIndication {
                    tb: Some(pack_bits(&cbits)),
                    ..fail(sinr)
                };
            }
        }
        fail(sinr)
    }
}

fn pack_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b))
        .collect()
}
