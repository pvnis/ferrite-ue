//! The slot engine: cell search → synchronisation → the per-slot loop that
//! drives the PHY ↔ MAC interface.
//!
//! State machine (one `Synced` cell at a time):
//! ```text
//!  CellSearch ──SSB + MIB──▶ Synced { phase: AwaitSib1 } ──CONFIG.request (SIB1)──▶ Synced { phase: Common }
//!      ▲                           │                                                   │ CONFIG.request (dedicated)
//!      │ RLM: PSS missed for        │                                                   ▼
//!      │ RLM_MAX_MISSED_SSB periods ◀───────────────────────────────────────── Synced { phase: Dedicated }
//! ```
//! Orthogonal to the phase: `tx_enabled` (START/STOP.request from MAC gates
//! every UL_TTI request) and the uplink timing (`SampleClock`, N_TA from MAC).
//! After a sync loss the engine re-searches and rebuilds `Synced` from the
//! MIB alone: MAC receives `ErrorIndication::SyncLost` and RRC must send a new
//! CONFIG.request and SetRntis once the cell is found again.
//! Threads: DL drain (inside `BufferedStream`), UL serve ([`crate::radio`]),
//! the timeline (this loop), one PDSCH worker, one TX builder.

use crate::cell::CellGeometry;
use crate::config::{CsiRsResource, PhyConfig};
use crate::dl::{DlMonitor, PdschJob, PdschSync, PdschWorker, WorkerConfig};
use crate::fapi::*;
use crate::radio::{serve_uplink, DlStream, UlPacing, UlServer, UlShared};
use crate::rt::ReadyWaveform;
use crate::timing::SampleClock;
use crate::track::{SyncTag, SyncTracker, TrackerConfig};
use crate::ul::UlBuilder;
use ferrite_common::fsm::{Fsm, Machine, Rule};
use ferrite_common::{DuplexMode, Error, Iq, Numerology, Result, SlotPoint};
use ferrite_phy::coding::bch::Mib;
use ferrite_phy::coreset0::{self, Coreset0Config};
use ferrite_phy::csi;
use ferrite_phy::sync::scan::{freq_shift, gscn_scan, FrameTracker, FreqShifter};
use ferrite_phy::sync::search::CellSearcher;
use ferrite_phy::sync::ssb::{self, SsbCase};
use ferrite_phy::Ofdm;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

/// Static engine parameters (what the UE knows before touching the air).
#[derive(Clone, Debug)]
pub struct EngineParams {
    pub fs: f64,
    pub dl_center_hz: f64,
    pub ul_center_hz: f64,
    pub ssb_scs_khz: u32,
    pub duplex: DuplexMode,
    pub band: u16,
    pub gscn_hint: Option<u32>,
    /// How many slots ahead MAC must issue UL_TTI requests.
    pub tx_lead_slots: u16,
    /// Backend TX/RX calibration (samples, positive = transmit earlier).
    pub tx_rx_offset: i64,
    /// PRACH-only timing calibration (samples, positive = earlier).
    pub prach_offset: i64,
    pub pacing: UlPacing,
    pub ul_block_len: usize,
    /// Apply CFO correction to the data path (needed over the air).
    pub cfo_correction: bool,
    /// The radio's LO and sample clock share one reference, so the measured
    /// CFO predicts the sampling-rate drift (see [`crate::track`]).
    pub sro_from_cfo: bool,
    /// Maximum cell-search attempts before giving up (0 = forever).
    pub max_search_attempts: u32,
    /// Test aid: `(start_s, duration_ms)` window after engine start during
    /// which radio link monitoring reports out-of-sync whatever the SSB says
    /// (exercises N310 / T310 / N311 and the re-establishment without
    /// touching the data path). `None` in normal operation.
    pub rlm_outage: Option<(u64, u64)>,
}

/// Commands from the application.
#[derive(Clone, Debug)]
pub enum EngineCommand {
    Stop,
}

/// Events the engine reports to the application.
#[derive(Clone, Debug)]
pub enum EngineEvent {
    CellFound {
        pci: u16,
        sfn: u16,
        cfo_hz: f64,
        ssb_df_hz: f64,
        mib: Mib,
        coreset0: (u16, u8, i32),
        ssb_index: u8,
    },
    /// A serving-cell SSB measurement (one per SSB period), in the receiver's
    /// own power scale (dBFS); the stack converts to dBm.
    Measurement {
        pci: u16,
        slot: SlotPoint,
        rsrp_dbfs: f32,
        rsrq_db: f32,
        sinr_db: f32,
        /// Receive gain applied at the time (dB; 0 without gain control), so the
        /// stack can convert dBFS to dBm.
        rx_gain_db: f32,
    },
    SyncLost,
    Stopped,
}

enum TxCmd {
    /// UL_TTI request, the clock to place it with, the C-RNTI, when it was
    /// queued, and the frequency pre-compensation (Hz) to apply.
    Ul(UlTtiRequest, SampleClock, i64, std::time::Instant, f64),
    /// Every UL request queued before this one has been issued: once they
    /// are built, the injection table is final up to the given UL index.
    Mark(i64),
    Reconfigure(Box<(CellGeometry, PhyConfig, u16)>),
    Stop,
}

/// What the PDSCH worker sends back.
enum WorkerOut {
    Mac(PhyToMac),
    Sync(PdschSync),
}

enum WorkerCmd {
    Job(PdschJob),
    /// One slot of samples per receive antenna.
    Measure {
        slot: SlotPoint,
        samples: Arc<Vec<Vec<Iq>>>,
    },
    Reconfigure(Box<WorkerConfig>),
    Stop,
}

/// Everything derived once the cell is known.
struct Synced {
    clock: SampleClock,
    geom: CellGeometry,
    cfg: PhyConfig,
    cell_id: u16,
    monitor: DlMonitor,
    coreset0: Coreset0Config,
    ssb_case: SsbCase,
    i_ssb: u8,
    half_frame: u8,
    /// CFO, timing and drift tracking; every anchor step goes through it.
    track: SyncTracker,
    ssb_period_ms: u16,
    /// Where the cell is in its life: SIB1 pending, common configuration
    /// (CSS only) or dedicated (RRC connected); see [`CellPhaseMachine`].
    phase: Fsm<CellPhaseMachine>,
}

/// Configuration phase of the synchronised cell (set by CONFIG.request).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellPhase {
    /// Only the MIB-derived CORESET#0 / Type0 CSS: waiting for SIB1.
    AwaitSib1,
    /// SIB1 applied: common search spaces, no dedicated resources.
    Common,
    /// Dedicated RRC configuration applied (UE-specific search spaces / PUCCH).
    Dedicated,
}

impl CellPhase {
    /// A CONFIG.request has been applied (SIB1 known).
    fn configured(self) -> bool {
        self != CellPhase::AwaitSib1
    }
}

/// What moves the cell's configuration phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseTrigger {
    /// CONFIG.request with the common (SIB1) configuration only.
    CommonConfig,
    /// CONFIG.request with a dedicated (RRC) configuration.
    DedicatedConfig,
}

/// The cell-phase machine.
pub struct CellPhaseMachine;

impl Machine for CellPhaseMachine {
    const NAME: &'static str = "PHY cell";
    type State = CellPhase;
    type Kind = CellPhase;
    type Event = PhaseTrigger;
    const KINDS: &'static [CellPhase] = &[
        CellPhase::AwaitSib1,
        CellPhase::Common,
        CellPhase::Dedicated,
    ];
    const EVENTS: &'static [PhaseTrigger] =
        &[PhaseTrigger::CommonConfig, PhaseTrigger::DedicatedConfig];
    const INITIAL: CellPhase = CellPhase::AwaitSib1;
    const RULES: &'static [Rule<CellPhase, PhaseTrigger>] = &[
        Rule {
            from: &[CellPhase::AwaitSib1, CellPhase::Dedicated],
            event: PhaseTrigger::CommonConfig,
            to: CellPhase::Common,
            clause: "38.213 §10.1 (common search spaces from SIB1); back from dedicated on release / re-establishment (38.331 §5.3.7.4, §5.3.11)",
        },
        Rule {
            from: &[CellPhase::Common],
            event: PhaseTrigger::DedicatedConfig,
            to: CellPhase::Dedicated,
            clause: "38.331 §5.3.5.5 (CellGroupConfig: dedicated resources)",
        },
    ];
    fn kind(s: &CellPhase) -> CellPhase {
        *s
    }
}

/// The engine's own hold on the cell: consecutive SSB periods without the PSS
/// at the expected position. Independent of RRC's T310 (which gets the
/// per-period [`SyncIndication`]s): after [`RLM_MAX_MISSED_SSB`] misses the
/// slot timing can no longer be trusted and the engine returns to cell search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlmState {
    InSync,
    OutOfSync { misses: u32 },
}

/// What moves the engine's hold on the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlmTrigger {
    /// The SSB was not found at its expected position this period.
    SsbMissed,
    /// The SSB was found.
    SsbFound,
}

/// [`RlmState`] without the miss count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlmPhase {
    InSync,
    OutOfSync,
}

/// The engine's radio-link machine (its own hold on the cell, below RRC).
pub struct RlmMachine;

impl Machine for RlmMachine {
    const NAME: &'static str = "PHY RLM";
    type State = RlmState;
    type Kind = RlmPhase;
    type Event = RlmTrigger;
    const KINDS: &'static [RlmPhase] = &[RlmPhase::InSync, RlmPhase::OutOfSync];
    const EVENTS: &'static [RlmTrigger] = &[RlmTrigger::SsbMissed, RlmTrigger::SsbFound];
    const INITIAL: RlmPhase = RlmPhase::InSync;
    const RULES: &'static [Rule<RlmPhase, RlmTrigger>] = &[
        Rule {
            from: &[RlmPhase::InSync],
            event: RlmTrigger::SsbMissed,
            to: RlmPhase::OutOfSync,
            clause: "ferrite: PSS missed at the expected position (cell search after RLM_MAX_MISSED_SSB)",
        },
        Rule {
            from: &[RlmPhase::OutOfSync],
            event: RlmTrigger::SsbFound,
            to: RlmPhase::InSync,
            clause: "ferrite: PSS found again",
        },
    ];
    fn kind(s: &RlmState) -> RlmPhase {
        match s {
            RlmState::InSync => RlmPhase::InSync,
            RlmState::OutOfSync { .. } => RlmPhase::OutOfSync,
        }
    }
}

impl RlmState {
    fn miss(self) -> Self {
        match self {
            RlmState::InSync => RlmState::OutOfSync { misses: 1 },
            RlmState::OutOfSync { misses } => RlmState::OutOfSync { misses: misses + 1 },
        }
    }
}

/// Consecutive SSB periods without the PSS before the engine gives the cell up
/// and searches again: long enough (≥ 2.5 s at the 10 ms SSB period) for RRC's
/// N310 / T310 to declare the radio link failure first with the network's
/// values (T310 ≤ 2 s).
pub const RLM_MAX_MISSED_SSB: u32 = 250;

/// Radio link monitoring thresholds (TS 38.133 §8.1.1): Q_out is the SSB SINR
/// at which the hypothetical PDCCH BLER is 10 %, Q_in where it is 2 %.
const RLM_Q_OUT_DB: f32 = -8.0;
const RLM_Q_IN_DB: f32 = -6.0;

/// One RLM evaluation (TS 38.133 §8.1.2): `ssb_sinr_db` is `None` when the SSB
/// was not found. `Some(false)` = out-of-sync (below Q_out), `Some(true)` =
/// in-sync (above Q_in), `None` = in the hysteresis band, no indication.
fn rlm_evaluate(ssb_sinr_db: Option<f32>) -> Option<bool> {
    match ssb_sinr_db {
        None => Some(false),
        Some(s) if s < RLM_Q_OUT_DB => Some(false),
        Some(s) if s >= RLM_Q_IN_DB => Some(true),
        Some(_) => None,
    }
}

pub struct Engine<'a> {
    pub params: EngineParams,
    dl: DlStream,
    /// Receive AGC, when the front end has a gain.
    agc: Option<crate::agc::Agc>,
    shared: Arc<UlShared>,
    mac: &'a mut dyn MacHandler,
    cmds: crossbeam_channel::Receiver<EngineCommand>,
    events: crossbeam_channel::Sender<EngineEvent>,
    tx_cmd: crossbeam_channel::Sender<TxCmd>,
    wk_cmd: crossbeam_channel::Sender<WorkerCmd>,
    wk_res: crossbeam_channel::Receiver<WorkerOut>,
    /// Previous slot's samples per antenna (for negative timing slews).
    prev: Vec<Vec<Iq>>,
    prev_start: i64,
    pending_dl: BTreeMap<u64, Vec<DlGrant>>,
    pending_prach: Vec<(SlotPoint, PrachOccasion, u8)>,
    /// PDSCH jobs handed to the worker whose RX_Data has not come back yet.
    outstanding_jobs: usize,
    /// START/STOP.request: whether UL_TTI requests are transmitted.
    tx_enabled: bool,
    prach_sweep: Option<Vec<i64>>,
    prach_sweep_idx: usize,
    pusch_sweep: Option<Vec<i64>>,
    pusch_sweep_idx: usize,
    stats: EngineStats,
    started: std::time::Instant,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EngineStats {
    pub slots: u64,
    pub dcis: u64,
    pub pdsch_jobs: u64,
    pub late_ul: u64,
    /// One-sample anchor steps from the tracking model.
    pub timing_steps: u64,
    /// Coarse timing re-alignments (errors beyond a few samples).
    pub timing_realignments: u64,
    /// Out-of-sync indications sent to RRC.
    pub out_of_sync: u64,
}

/// Run the engine to completion (returns when stopped or the radio fails).
pub fn run(
    params: EngineParams,
    dl: DlStream,
    ul: UlServer,
    mac: &mut dyn MacHandler,
    cmds: crossbeam_channel::Receiver<EngineCommand>,
    events: crossbeam_channel::Sender<EngineEvent>,
) -> Result<EngineStats> {
    let shared = UlShared::new(ul.start_index);
    let spsl = Numerology::from_scs_khz(params.ssb_scs_khz)
        .map(|n| n.samples_per_slot(params.fs))
        .unwrap_or(1) as i64;
    {
        let shared = shared.clone();
        let fs = params.fs;
        std::thread::Builder::new()
            .name("ferrite-ultx".into())
            .spawn(move || serve_uplink(ul, shared, spsl, fs))
            .map_err(Error::Io)?;
    }
    let (tx_cmd, tx_rx) = crossbeam_channel::bounded::<TxCmd>(64);
    let (wk_cmd, wk_rx) = crossbeam_channel::bounded::<WorkerCmd>(8);
    let (wk_res_tx, wk_res) = crossbeam_channel::bounded::<WorkerOut>(64);
    // TX builder thread.
    {
        let shared = shared.clone();
        let ul_center_hz = params.ul_center_hz;
        let fs = params.fs;
        std::thread::Builder::new()
            .name("ferrite-txbuild".into())
            .spawn(move || {
                let mut builder: Option<UlBuilder> = None;
                while let Ok(cmd) = tx_rx.recv() {
                    match cmd {
                        TxCmd::Stop => break,
                        TxCmd::Mark(idx) => shared.committed.store(idx, Relaxed),
                        TxCmd::Reconfigure(b) => {
                            let (geom, cfg, cell_id) = *b;
                            builder = Some(UlBuilder::new(geom, cfg, ul_center_hz, cell_id));
                        }
                        TxCmd::Ul(req, clock, c, queued, ul_shift_hz) => {
                            let waited = queued.elapsed();
                            if waited.as_millis() >= 5 {
                                log::warn!("UL request for slot {} waited {:.1} ms in the build queue", req.slot, waited.as_secs_f64() * 1e3);
                            }
                            let Some(b) = builder.as_ref() else { continue };
                            let crnti = c as u16;
                            for pdu in req.pdus {
                                let t_build = std::time::Instant::now();
                                let built = match &pdu {
                                    UlTtiPdu::Prach { occasion, preamble, power_dbm } => b.prach(&clock, occasion, *preamble, *power_dbm),
                                    UlTtiPdu::Pusch { grant, tb, uci, power_dbm } => b.pusch(&clock, grant, tb, uci, *power_dbm),
                                    UlTtiPdu::Pucch { resource, uci, power_dbm } => b.pucch(&clock, req.slot, *resource, uci, crnti, *power_dbm),
                                    UlTtiPdu::Srs { resource_id, power_dbm } => b.srs(&clock, req.slot, *resource_id, *power_dbm),
                                };
                                match built {
                                    Ok(mut w) => {
                                        if ul_shift_hz != 0.0 {
                                            w.samples = freq_shift(&w.samples, ul_shift_hz, fs, w.start.max(0) as usize);
                                        }
                                        let took = t_build.elapsed();
                                        if took.as_millis() >= 2 {
                                            log::warn!("{} build for slot {} took {:.1} ms", w.tag, req.slot, took.as_secs_f64() * 1e3);
                                        }
                                        let now = shared.served.load(Relaxed);
                                        if w.start < now {
                                            log::warn!("{} for slot {} is late by {} samples", w.tag, req.slot, now - w.start);
                                        }
                                        log::debug!("ul {} slot {}: start {} len {} (served {}, margin {} samples)", w.tag, req.slot, w.start, w.samples.len(), now, w.start - now);
                                        shared.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(ReadyWaveform { pos: w.start, samples: w.samples, tag: w.tag }, now);
                                    }
                                    Err(e) => log::warn!("UL build failed for slot {}: {e}", req.slot),
                                }
                            }
                        }
                    }
                }
            })
            .map_err(Error::Io)?;
    }
    // PDSCH worker thread.
    {
        std::thread::Builder::new()
            .name("ferrite-rxphy".into())
            .spawn(move || {
                let mut worker: Option<PdschWorker> = None;
                while let Ok(cmd) = wk_rx.recv() {
                    match cmd {
                        WorkerCmd::Stop => break,
                        WorkerCmd::Reconfigure(c) => match worker.as_mut() {
                            Some(w) => w.reconfigure(*c),
                            None => worker = Some(PdschWorker::new(*c)),
                        },
                        WorkerCmd::Measure { slot, samples } => {
                            if let Some(w) = worker.as_ref() {
                                let grids: Vec<Vec<Vec<Iq>>> =
                                    samples.iter().filter_map(|s| w.demod(slot, s)).collect();
                                if grids.len() == samples.len() {
                                    if let Some(c) = w.measure_csi(slot, &grids) {
                                        log::debug!(
                                            "CSI {}: sinr {:.1} dB cqi {} ri {} pmi {:?} ({} rx antennas)",
                                            slot,
                                            c.sinr_db,
                                            c.cqi,
                                            c.ri,
                                            c.pmi,
                                            grids.len()
                                        );
                                        let _ = wk_res_tx.send(WorkerOut::Mac(PhyToMac::Csi(c)));
                                    }
                                }
                            }
                        }
                        WorkerCmd::Job(job) => {
                            // Every job is answered with exactly one RX_Data (the
                            // engine waits for them before building the HARQ-ACK).
                            let g = &job.grant;
                            let failed = || RxDataIndication {
                                rnti: g.rnti,
                                rnti_kind: g.rnti_kind,
                                harq_id: g.harq_id,
                                ndi: g.ndi,
                                pdsch_slot: job.slot,
                                tb: None,
                                sinr_db: 0.0,
                            };
                            let r = match worker.as_mut() {
                                None => failed(),
                                Some(w) => {
                                    let grids: Vec<Vec<Vec<Iq>>> = job
                                        .samples
                                        .iter()
                                        .filter_map(|s| w.demod(job.slot, s))
                                        .collect();
                                    if grids.len() != job.samples.len() {
                                        failed()
                                    } else {
                                        if let Some(c) = w.measure_csi(job.slot, &grids) {
                                            let _ = wk_res_tx.send(WorkerOut::Mac(PhyToMac::Csi(c)));
                                        }
                                        let r = w.decode(&job, &grids);
                                        // Only a PDSCH that passed its CRC is
                                        // trusted for tracking.
                                        if let (Some(m), true) = (w.take_sync(), r.tb.is_some()) {
                                            let _ = wk_res_tx.send(WorkerOut::Sync(m));
                                        }
                                        r
                                    }
                                }
                            };
                            if wk_res_tx.send(WorkerOut::Mac(PhyToMac::RxData(r))).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(Error::Io)?;
    }
    let mut eng = Engine {
        params,
        agc: None,
        dl,
        shared,
        mac,
        cmds,
        events,
        tx_cmd,
        wk_cmd,
        wk_res,
        prev: Vec::new(),
        prev_start: 0,
        pending_dl: BTreeMap::new(),
        pending_prach: Vec::new(),
        outstanding_jobs: 0,
        tx_enabled: false,
        prach_sweep: std::env::var("FERRITE_PRACH_SWEEP")
            .ok()
            .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect()),
        prach_sweep_idx: 0,
        pusch_sweep: std::env::var("FERRITE_PUSCH_SWEEP")
            .ok()
            .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect()),
        pusch_sweep_idx: 0,
        stats: EngineStats::default(),
        started: std::time::Instant::now(),
    };
    let r = eng.run_inner();
    eng.shared.stop.store(true, Relaxed);
    let _ = eng.tx_cmd.send(TxCmd::Stop);
    let _ = eng.wk_cmd.send(WorkerCmd::Stop);
    let _ = eng.events.send(EngineEvent::Stopped);
    r.map(|_| eng.stats)
}

impl<'a> Engine<'a> {
    /// Inside the `rlm_outage` test window.
    fn in_rlm_outage(&self) -> bool {
        self.params.rlm_outage.is_some_and(|(start_s, ms)| {
            let t = self.started.elapsed().as_millis() as u64;
            t >= start_s * 1000 && t < start_s * 1000 + ms
        })
    }

    fn stopped(&self) -> bool {
        matches!(
            self.cmds.try_recv(),
            Ok(EngineCommand::Stop) | Err(crossbeam_channel::TryRecvError::Disconnected)
        )
    }

    fn run_inner(&mut self) -> Result<()> {
        loop {
            let synced = self.cell_search()?;
            let Some(mut s) = synced else { return Ok(()) };
            let lost = self.slot_loop(&mut s)?;
            if !lost {
                return Ok(());
            }
            let _ = self.events.send(EngineEvent::SyncLost);
            self.mac
                .handle(PhyToMac::Error(ErrorIndication::SyncLost), &mut Vec::new());
        }
    }

    // --------------------------------------------------------------- search

    /// Receive AGC on a downlink capture: measure, decide, apply.
    fn agc_step(&mut self, samples: &[Iq], slot_index: Option<u64>) {
        let Some(ctrl) = self.dl.gain_control() else {
            return;
        };
        let agc = self.agc.get_or_insert_with(|| {
            let initial = ctrl.rx_gain().unwrap_or(0.0);
            crate::agc::Agc::new(ctrl.rx_gain_range(), initial)
        });
        let power = crate::agc::power_dbfs(samples);
        let old = agc.gain_db();
        if let Some(new) = agc.update(power, slot_index) {
            match ctrl.set_rx_gain(new) {
                Ok(actual) => {
                    agc.applied(actual);
                    if (actual - old).abs() >= 0.5 {
                        log::info!("AGC: receive gain {old} → {actual} dB (power {power:.1} dBFS)");
                    } else {
                        log::info!(
                            "AGC: receive gain stays {actual} dB, device limit (power {power:.1} dBFS, asked {new} dB)"
                        );
                    }
                }
                Err(e) => log::warn!("AGC: setting receive gain {new} dB failed: {e}"),
            }
        }
    }

    fn cell_search(&mut self) -> Result<Option<Synced>> {
        self.shared.gate.store(false, Relaxed);
        let p = self.params.clone();
        let ssb_num = Numerology::from_scs_khz(p.ssb_scs_khz)
            .ok_or_else(|| Error::Config("bad SSB SCS".into()))?;
        let ssb_case = SsbCase::from_scs(p.ssb_scs_khz, p.duplex)
            .ok_or_else(|| Error::Config("no SSB case".into()))?;
        let l_max = ssb::l_max_fr1(p.dl_center_hz);
        let frame_len = ssb_num.samples_per_frame(p.fs);
        let fft_ssb = (p.fs / ssb_num.scs_hz() as f64).round() as usize;
        let cap_len = 3 * frame_len; // ≥ one 20 ms SSB period plus margin
        let mut attempts = 0u32;
        loop {
            if self.stopped() {
                return Ok(None);
            }
            let cap_start = self.dl.position() as i64;
            let mut cap = vec![Iq::default(); cap_len];
            self.dl.read_exact(&mut cap)?;
            attempts += 1;
            self.agc_step(&cap, None);
            let Some(hit) = gscn_scan(
                &cap,
                p.fs,
                p.dl_center_hz,
                p.ssb_scs_khz,
                l_max,
                p.gscn_hint,
            ) else {
                log::info!("cell search: no SSB (attempt {attempts})");
                if p.max_search_attempts > 0 && attempts >= p.max_search_attempts {
                    return Err(Error::Phy("no SSB found".into()));
                }
                continue;
            };
            log::info!(
                "scan hit: gscn {} df {:.0} Hz PCI {} pss {:.2} sss {:.2} cfo {:.0} Hz mib {}",
                hit.gscn,
                hit.df_hz,
                hit.result.cell_id,
                hit.result.pss_metric,
                hit.result.sss_metric,
                hit.result.cfo_hz,
                hit.pbch.is_some()
            );
            let mut tracker = FrameTracker::new(fft_ssb, ssb_case, p.dl_center_hz);
            let Some(acq) = tracker.acquire_from_hit(&hit) else {
                log::info!(
                    "cell search: PCI {} seen but MIB not decoded (attempt {attempts})",
                    hit.result.cell_id
                );
                continue;
            };
            let mib = acq.mib;
            let mu_data = if mib.scs_common_is_30_or_120 { 1 } else { 0 };
            let numerology = Numerology::new(mu_data);
            let frame_start_abs = cap_start + acq.frame_start;
            let anchor = SlotPoint::new(numerology, mib.sfn & 0x3ff, 0);
            let mut clock = SampleClock::new(p.fs, numerology, anchor, frame_start_abs);
            clock.n_ta_offset_tc = 25600;
            clock.tx_rx_offset = p.tx_rx_offset;
            // `prach_offset` < 0 is a delay: the uplink guard (all channels).
            clock.ul_guard = -p.prach_offset;
            // CORESET#0 / Type0 CSS from the MIB (TS 38.213 §13).
            let pdcch_scs = numerology.scs_khz();
            let min_bw = if p.band == 79 { 40 } else { 10 };
            let cs0_idx = mib.pdcch_config_sib1 >> 4;
            let ss0_idx = mib.pdcch_config_sib1 & 0xf;
            let Some(cs0) = coreset0::coreset0_config(p.ssb_scs_khz, pdcch_scs, min_bw, cs0_idx)
            else {
                return Err(Error::Config(format!(
                    "unsupported CORESET0 index {cs0_idx}"
                )));
            };
            let k_ssb = (mib.k_ssb_msb << 4) | mib.ssb_subcarrier_offset;
            let cs0_rel_ssb =
                match coreset0::coreset0_first_subcarrier_rel_ssb(k_ssb, pdcch_scs, &cs0) {
                    Ok(v) => v,
                    Err(e) => return Err(Error::Config(format!("CORESET0 offset: {e:?}"))),
                };
            let scs = numerology.scs_hz() as f64;
            // SSB subcarrier 0 relative to the DL stream DC (data-SCS subcarriers).
            let ssb_sc0 = ((hit.df_hz - 120.0 * ssb_num.scs_hz() as f64) / scs).round() as i64;
            let geom = CellGeometry::from_coreset0(
                p.fs,
                p.dl_center_hz,
                numerology,
                ssb_sc0 + cs0_rel_ssb as i64,
                hit.df_hz,
            );
            let Some(t0) = coreset0::type0_pdcch_monitoring(ss0_idx, acq.i_ssb, mu_data, &cs0)
            else {
                return Err(Error::Config("unsupported searchSpaceZero".into()));
            };
            let cfg = initial_config(
                &p,
                &mib,
                &cs0,
                numerology,
                acq.cell_id,
                cs0_idx,
                ss0_idx,
                k_ssb,
            );
            let mut monitor =
                DlMonitor::new(geom.clone(), &cfg, acq.cell_id, Some((cs0, t0)), false);
            monitor.rntis.si = true;
            let synced = Synced {
                clock,
                geom: geom.clone(),
                cfg: cfg.clone(),
                cell_id: acq.cell_id,
                monitor,
                coreset0: cs0,
                ssb_case,
                i_ssb: acq.i_ssb,
                half_frame: acq.half_frame,
                track: SyncTracker::new(
                    TrackerConfig {
                        sro_from_cfo: self.params.sro_from_cfo,
                        ..TrackerConfig::new(self.params.fs, self.params.dl_center_hz)
                    },
                    acq.cfo_hz,
                )
                .starting_at(frame_start_abs),
                ssb_period_ms: 20,
                phase: Fsm::new(CellPhase::AwaitSib1),
            };
            log::info!(
                "synced PCI {} SFN {} i_ssb {} hf {} cfo {:.0} Hz ssb df {:.0} Hz mu {} CORESET0 idx {} ({} RB, {} sym) ss0 {}",
                acq.cell_id, mib.sfn, acq.i_ssb, acq.half_frame, acq.cfo_hz, hit.df_hz, mu_data, cs0_idx, cs0.n_rb, cs0.n_symb, ss0_idx
            );
            let _ = self.events.send(EngineEvent::CellFound {
                pci: acq.cell_id,
                sfn: mib.sfn,
                cfo_hz: acq.cfo_hz,
                ssb_df_hz: hit.df_hz,
                mib,
                coreset0: (cs0.n_rb as u16, cs0.n_symb as u8, cs0.offset_rb),
                ssb_index: acq.i_ssb,
            });
            self.configure_threads(&synced);
            return Ok(Some(synced));
        }
    }

    /// One result from the PDSCH worker: FAPI indications go to MAC, DM-RS
    /// measurements to the tracker.
    fn worker_out(&mut self, s: &mut Synced, m: WorkerOut, outbox: &mut Vec<MacToPhy>) {
        match m {
            WorkerOut::Mac(m) => {
                if matches!(m, PhyToMac::RxData(_)) {
                    self.outstanding_jobs = self.outstanding_jobs.saturating_sub(1);
                }
                self.mac.handle(m, outbox);
            }
            WorkerOut::Sync(m) => {
                if let Some(d) = m.delay_samples {
                    s.track.on_timing(m.tag, d);
                }
                if let Some(c) = m.cfo_residual_hz {
                    s.track.on_cfo(m.tag, c);
                }
            }
        }
    }

    /// Uplink frequency pre-compensation (Hz). The downlink arrives `cfo`
    /// above where the UE's LO expects it, i.e. the LO (and the transmit
    /// chain derived from the same reference) is low by `cfo / f_DL`; shifting
    /// the uplink baseband up by `cfo · f_UL / f_DL` puts the transmission on
    /// the network's carrier, as TS 38.101-1 §6.4.1 requires (±0.1 ppm of the
    /// received downlink). Not applied where the data path is not corrected
    /// either (the ZMQ transport has no LO).
    fn ul_frequency_correction(&self, s: &Synced) -> f64 {
        if !self.params.cfo_correction || self.params.dl_center_hz <= 0.0 {
            return 0.0;
        }
        s.track.cfo_hz() * self.params.ul_center_hz / self.params.dl_center_hz
    }

    fn configure_threads(&mut self, s: &Synced) {
        let wc = worker_config(
            &s.geom,
            &s.cfg,
            s.cell_id,
            &s.coreset0,
            s.phase.state().configured(),
        );
        let _ = self.wk_cmd.send(WorkerCmd::Reconfigure(Box::new(wc)));
        let _ = self.tx_cmd.send(TxCmd::Reconfigure(Box::new((
            s.geom.clone(),
            s.cfg.clone(),
            s.cell_id,
        ))));
    }

    // ------------------------------------------------------------ slot loop

    /// Read the samples of the slot starting at DL index `start` (length `len`).
    /// Read the slot starting at sample `start` on every antenna into
    /// `out[antenna]`.
    fn read_slot(&mut self, start: i64, len: usize, out: &mut Vec<Vec<Iq>>) -> Result<()> {
        let pos = self.dl.position() as i64;
        if start >= pos {
            self.dl.skip((start - pos) as usize)?;
            self.dl.read_exact_all(len, out)?;
        } else {
            // Earlier than the stream position: take the overlap from the previous slot.
            let back = (pos - start) as usize;
            let prev_len = self.prev.first().map_or(0, Vec::len);
            if back > prev_len {
                return Err(Error::Phy(format!(
                    "timing slew of {back} samples exceeds the kept history"
                )));
            }
            let need = len.saturating_sub(back);
            let mut rest: Vec<Vec<Iq>> = Vec::new();
            self.dl.read_exact_all(need, &mut rest)?;
            out.resize_with(rest.len(), Vec::new);
            for (a, o) in out.iter_mut().enumerate() {
                o.clear();
                o.extend_from_slice(&self.prev[a][prev_len - back..]);
                o.extend_from_slice(&rest[a]);
                o.truncate(len);
            }
        }
        self.prev_start = start;
        self.prev.clone_from(out);
        Ok(())
    }

    /// Returns `Ok(true)` when sync was lost (caller re-searches), `Ok(false)` on stop.
    fn slot_loop(&mut self, s: &mut Synced) -> Result<bool> {
        let fs = self.params.fs;
        // Close the gate (commit mark at the stream origin) so the uplink
        // position is stable while the backlog is measured; it is reopened
        // below once the first slot is known.
        self.shared.committed.store(i64::MIN, Relaxed);
        self.shared.gate.store(true, Relaxed);
        let numerology = s.geom.numerology;
        let sps = s.clock.samples_per_slot();
        // While the cell search ran (gate open) the uplink thread served
        // whatever the lockstep gNB asked for, so the DL stream now holds a
        // backlog the uplink has already passed. Transmissions for slots in
        // that backlog could never be sent: drop it and start at the uplink's
        // position.
        let served = self.shared.served.load(Relaxed);
        let backlog = served - self.dl.position() as i64;
        if backlog > 2 * sps {
            log::info!(
                "dropping {backlog} DL samples ({:.1} ms) of search backlog",
                backlog as f64 / fs * 1e3
            );
            self.dl.skip(backlog as usize)?;
            self.prev.iter_mut().for_each(Vec::clear);
        }
        // Apply the drift accumulated since acquisition (over the dropped
        // backlog too), then re-anchor the clock here: slot ↔ index mapping is
        // modular over the SFN cycle, and a backlog of more than half a cycle
        // (5.12 s) would otherwise alias to the wrong one.
        let pos = self.dl.position() as i64;
        let step = s.track.advance(pos);
        if step != 0 {
            log::info!("timing: {step:+} samples of drift since acquisition");
            s.clock.slew(step);
        }
        let (anchor, anchor_off) = s.clock.slot_at(pos);
        s.clock.set_anchor(anchor, pos - anchor_off);
        // Start at the first whole slot at/after the current stream position.
        let (mut slot, off) = s.clock.slot_at(self.dl.position() as i64);
        if off != 0 {
            slot = slot.add(1);
        }
        // Nothing can be requested before slot + tx_lead any more, so the
        // uplink is final up to there: release it, or the lockstep gNB (which
        // sends at most ~1 ms of DL beyond the UL it has received) could never
        // deliver the first whole slot.
        self.shared.committed.store(
            self.commit_mark(s, slot.add(self.params.tx_lead_slots as u64)),
            Relaxed,
        );
        let mut samples: Vec<Vec<Iq>> = Vec::new();
        let mut shifter: Option<FreqShifter> = None;
        let mut shifted: Vec<Iq> = Vec::with_capacity(sps as usize);
        let mut shifted_all: Vec<Vec<Iq>> = Vec::new();
        let ofdm_ssb = Ofdm::new((fs / (15_000u32 << s.ssb_case.mu()) as f64).round() as usize);
        let searcher = CellSearcher::new(
            ofdm_ssb.fft_size(),
            s.ssb_case.mu(),
            ssb::l_max_fr1(self.params.dl_center_hz),
        );
        let ssb_first_symbol = s
            .ssb_case
            .candidate_symbols(self.params.dl_center_hz)
            .get(s.i_ssb as usize)
            .copied()
            .unwrap_or(2);
        let ssb_off_in_frame = ssb::ssb_sample_offset_in_frame(
            ssb_first_symbol,
            s.half_frame,
            s.ssb_case.mu(),
            &ofdm_ssb,
        ) as i64;
        let mut rlm: Fsm<RlmMachine> = Fsm::new(RlmState::InSync);
        let mut outbox: Vec<MacToPhy> = Vec::new();
        loop {
            if self.stopped() {
                // A final summary: short runs may never reach an SFN 0.
                log::info!("tracking: {}", s.track.summary());
                return Ok(false);
            }
            // The drift model moves the anchor in whole samples.
            let step = s.track.advance(s.clock.dl_index(slot));
            if slot.slot == 0 && slot.sfn == 0 {
                log::info!("tracking: {}", s.track.summary());
            }
            if step != 0 {
                if step.abs() == 1 {
                    self.stats.timing_steps += 1;
                } else {
                    self.stats.timing_realignments += 1;
                }
                s.clock.slew(step);
                log::debug!(
                    "timing step {step:+} at {slot} (drift {:+.3} ppm, cfo {:.0} Hz)",
                    s.track.drift_ppm(),
                    s.track.cfo_hz()
                );
            }
            let start = s.clock.dl_index(slot);
            self.read_slot(start, sps as usize, &mut samples)?;
            let tag = SyncTag {
                at: start,
                applied: s.track.applied(),
                cfo_removed_hz: 0.0,
            };
            if slot.slot == 0 {
                // Keep the anchor within half an SFN cycle of the current slot
                // (slot differences are modular over 1024 frames).
                s.clock.set_anchor(slot, start);
            }
            self.stats.slots += 1;

            // --- SSB tracking (timing + CFO) on SSB frames.
            if slot.sfn % (s.ssb_period_ms / 10).max(1) == 0
                && slot.slot as i64 == ssb_off_in_frame / sps
            {
                let in_slot = (ssb_off_in_frame % sps) as usize;
                self.agc_step(&samples[0], Some(slot.index()));
                let ssb_cfo = s.track.cfo_hz();
                let sh = FreqShifter::new(-s.geom.ssb_df_hz - ssb_cfo, fs, sps as usize);
                sh.shift_into(&samples[0], start as usize, &mut shifted);
                let cp =
                    ofdm_ssb.cp_len(ssb_first_symbol % (14 << s.ssb_case.mu()), s.ssb_case.mu());
                let expect = in_slot + cp;
                let lo = expect.saturating_sub(96);
                let hi = (expect + 96).min(shifted.len());
                let mut ssb_sinr: Option<f32> = None;
                match searcher.search_near(&shifted, (s.cell_id % 3) as u8, lo..hi) {
                    Some(r) if r.pss_metric > 0.3 && r.cell_id == s.cell_id => {
                        // Integer PSS position; the SSS phase slope adds the
                        // fraction when the SSB is measurable.
                        let mut err = r.timing_index as f64 - expect as f64;
                        let ssb_tag = SyncTag {
                            cfo_removed_hz: ssb_cfo,
                            ..tag
                        };
                        s.track.on_cfo(ssb_tag, r.cfo_hz);
                        if let Err(v) = rlm.transition(RlmTrigger::SsbFound, RlmState::InSync) {
                            log::error!("{v}");
                        }
                        // Found but not measurable: treat as a strong SSB.
                        ssb_sinr = Some(f32::INFINITY);
                        if let Some(m) = ferrite_phy::sync::measure::ssb_measure(
                            &ofdm_ssb,
                            &shifted,
                            r.timing_index,
                            s.ssb_case.mu(),
                            r.n_id_1,
                            r.n_id_2,
                        ) {
                            ssb_sinr = Some(m.sinr_db());
                            if m.delay_samples.abs() < 2.0 {
                                err += f64::from(m.delay_samples);
                            }
                            let _ = self.events.try_send(EngineEvent::Measurement {
                                pci: s.cell_id,
                                slot,
                                rsrp_dbfs: m.rsrp_db(),
                                rsrq_db: m.rsrq_db(),
                                sinr_db: m.sinr_db(),
                                rx_gain_db: self.agc.as_ref().map_or(0.0, |a| a.gain_db() as f32),
                            });
                        }
                        s.track.on_timing(tag, err);
                    }
                    _ => {
                        let next = rlm.state().miss();
                        if let Err(v) = rlm.transition(RlmTrigger::SsbMissed, next) {
                            log::error!("{v}");
                        }
                        if let RlmState::OutOfSync { misses } = *rlm.state() {
                            if misses >= RLM_MAX_MISSED_SSB {
                                log::warn!("SSB not found for {misses} periods: sync lost");
                                return Ok(true);
                            }
                        }
                    }
                }
                // Radio link monitoring indication to RRC (via MAC), one per
                // SSB period. The test outage forces out-of-sync.
                if self.in_rlm_outage() {
                    ssb_sinr = None;
                }
                if let Some(in_sync) = rlm_evaluate(ssb_sinr) {
                    if !in_sync {
                        self.stats.out_of_sync += 1;
                    }
                    self.mac.handle(
                        PhyToMac::Sync(SyncIndication { slot, in_sync }),
                        &mut outbox,
                    );
                }
            }
            // --- CFO correction for the data path (every antenna shares the LO).
            let cfo = s.track.cfo_hz();
            let mut data_tag = tag;
            let arc_samples: Arc<Vec<Vec<Iq>>> = if self.params.cfo_correction && cfo.abs() > 1.0 {
                let sh = match shifter.take() {
                    Some(f) if (f.shift_hz() + cfo).abs() <= 0.5 => f,
                    _ => FreqShifter::new(-cfo, fs, sps as usize),
                };
                data_tag.cfo_removed_hz = -sh.shift_hz();
                shifted_all.resize_with(samples.len(), Vec::new);
                for (sa, out) in samples.iter().zip(shifted_all.iter_mut()) {
                    sh.shift_into(sa, start as usize, out);
                }
                shifter = Some(sh);
                Arc::new(shifted_all.clone())
            } else {
                Arc::new(samples.clone())
            };
            // PDCCH monitoring and SSB tracking use antenna 0.
            let data: &[Iq] = &arc_samples[0];

            // --- Earlier PDSCH results first: the HARQ-ACK for a PDSCH is
            // built at the SLOT.indication `k1 − tx_lead` slots after it, and
            // when the DL stream arrives in bursts the engine can get there
            // before the worker (normally ~0.3 ms) has answered.
            while self.outstanding_jobs > 0 {
                match self
                    .wk_res
                    .recv_timeout(std::time::Duration::from_millis(20))
                {
                    Ok(m) => self.worker_out(s, m, &mut outbox),
                    Err(_) => {
                        log::warn!(
                            "{} PDSCH result(s) still outstanding at slot {slot}",
                            self.outstanding_jobs
                        );
                        break;
                    }
                }
            }
            self.drain_outbox(s, &mut outbox, slot)?;

            // --- SLOT.indication (MAC issues its UL_TTI requests for slot + lead).
            self.mac
                .handle(PhyToMac::Slot(SlotIndication { slot }), &mut outbox);
            self.drain_outbox(s, &mut outbox, slot)?;
            // PRACH transmitted?
            let mut rach = Vec::new();
            self.pending_prach.retain(|(occ_slot, occ, pre)| {
                if slot.diff(occ_slot) > 0 {
                    rach.push(PhyToMac::Rach(RachIndication {
                        slot: *occ_slot,
                        ra_rnti: occ.ra_rnti,
                        preamble: *pre,
                    }));
                    false
                } else {
                    true
                }
            });
            for m in rach {
                self.mac.handle(m, &mut outbox);
            }
            self.drain_outbox(s, &mut outbox, slot)?;

            // --- PDCCH monitoring.
            let dcis = s.monitor.monitor(slot, data);
            self.stats.dcis += dcis.len() as u64;
            for d in dcis {
                if let Dci::Dl(g) = &d.dci {
                    self.pending_dl
                        .entry(g.pdsch_slot.index())
                        .or_default()
                        .push(g.clone());
                }
                self.mac.handle(PhyToMac::Dci(d), &mut outbox);
            }
            self.drain_outbox(s, &mut outbox, slot)?;

            // --- PDSCH jobs for this slot (+ CSI measurement occasions).
            let grants = self.pending_dl.remove(&slot.index()).unwrap_or_default();
            let has_csi = s.phase.state().configured()
                && s.cfg.pdsch.csi_rs_rate_match.iter().any(|r| {
                    csi_rs_measured(r).is_some()
                        && csi::csi_rs_slots(r.period_slots as u32, r.offset_slots as u32, slot)
                });
            if grants.is_empty() && has_csi {
                let _ = self.wk_cmd.try_send(WorkerCmd::Measure {
                    slot,
                    samples: arc_samples.clone(),
                });
            }
            for g in grants {
                self.stats.pdsch_jobs += 1;
                let job = PdschJob {
                    slot,
                    samples: arc_samples.clone(),
                    grant: g,
                    skip_decode: false,
                    queued: std::time::Instant::now(),
                    sync: data_tag,
                };
                if self.wk_cmd.try_send(WorkerCmd::Job(job)).is_err() {
                    log::warn!("PDSCH worker queue full: slot {slot} dropped");
                } else {
                    self.outstanding_jobs += 1;
                }
            }
            // Drop stale pending grants (k0 misses).
            self.pending_dl
                .retain(|&k, _| k as i64 >= slot.index() as i64);

            // --- Worker results.
            while let Ok(m) = self.wk_res.try_recv() {
                self.worker_out(s, m, &mut outbox);
            }
            self.drain_outbox(s, &mut outbox, slot)?;

            // --- Commit mark: MAC has now issued every UL_TTI request up to
            // slot + tx_lead, so once the builder has drained them the uplink
            // is final up to the start of the slot after that.
            let mark = self.commit_mark(s, slot.add(self.params.tx_lead_slots as u64 + 1));
            if self.tx_cmd.try_send(TxCmd::Mark(mark)).is_err() {
                log::warn!("TX build queue full at slot {slot}: commit mark delayed");
            }

            slot = slot.add(1);
            let _ = numerology;
        }
    }

    /// UL index up to which the uplink is final when every request for slots
    /// before `first_open` has been issued and built.
    fn commit_mark(&self, s: &Synced, first_open: SlotPoint) -> i64 {
        s.clock.ul_index(first_open)
    }

    /// Apply MAC → PHY messages.
    fn drain_outbox(
        &mut self,
        s: &mut Synced,
        outbox: &mut Vec<MacToPhy>,
        now: SlotPoint,
    ) -> Result<()> {
        // Messages MAC sends while handling our answers to this batch.
        let mut followups: Vec<MacToPhy> = Vec::new();
        for m in outbox.drain(..) {
            match m {
                MacToPhy::RarGrant {
                    rar_slot,
                    tc_rnti,
                    grant,
                } => match s
                    .monitor
                    .resolver
                    .resolve_rar_grant(rar_slot, tc_rnti, &grant)
                {
                    Some(ul) => self.mac.handle(
                        PhyToMac::Dci(DciIndication {
                            slot: rar_slot,
                            dci: Dci::Ul(ul),
                        }),
                        &mut followups,
                    ),
                    None => log::warn!(
                        "RAR UL grant {grant:?} could not be resolved (BWP {} RBs)",
                        s.cfg.ul_bwp.n_rb
                    ),
                },
                MacToPhy::Config(cfg) => {
                    let cfg = *cfg;
                    s.geom = CellGeometry::new(self.params.fs, self.params.dl_center_hz, &cfg);
                    s.clock.n_ta_offset_tc = cfg.n_ta_offset_tc as i64;
                    s.ssb_period_ms = cfg.ssb.period_ms;
                    let dedicated = !cfg
                        .search_spaces
                        .iter()
                        .all(|x| x.kind == crate::config::SearchSpaceKind::Common)
                        || !cfg.pucch.resources.is_empty();
                    let t0 = coreset0::type0_pdcch_monitoring(
                        cfg.ss0_index,
                        s.i_ssb,
                        s.geom.numerology.mu,
                        &s.coreset0,
                    );
                    let rntis = s.monitor.rntis;
                    s.monitor = DlMonitor::new(
                        s.geom.clone(),
                        &cfg,
                        s.cell_id,
                        t0.map(|t| (s.coreset0, t)),
                        dedicated,
                    );
                    s.monitor.rntis = rntis;
                    s.cfg = cfg;
                    let (trigger, to) = if dedicated {
                        (PhaseTrigger::DedicatedConfig, CellPhase::Dedicated)
                    } else {
                        (PhaseTrigger::CommonConfig, CellPhase::Common)
                    };
                    match s.phase.transition(trigger, to) {
                        Ok(Some(t)) => log::info!("{t}"),
                        Ok(None) => {}
                        Err(v) => log::error!("{v}"),
                    }
                    self.configure_threads(s);
                    log::info!("PHY configured: dl carrier {:?} ul carrier {:?} coresets {} search spaces {} dedicated {}", s.cfg.dl_carrier, s.cfg.ul_carrier, s.cfg.coresets.len(), s.cfg.search_spaces.len(), dedicated);
                }
                MacToPhy::Start => {
                    if !self.tx_enabled {
                        log::info!("START.request: uplink transmissions enabled");
                    }
                    self.tx_enabled = true;
                }
                MacToPhy::Stop => {
                    log::info!("STOP.request: uplink transmissions disabled");
                    self.tx_enabled = false;
                }
                MacToPhy::SetRntis {
                    c_rnti,
                    tc_rnti,
                    ra_rnti,
                } => {
                    s.monitor.rntis.c = c_rnti;
                    s.monitor.rntis.tc = tc_rnti;
                    s.monitor.rntis.ra = ra_rnti;
                }
                MacToPhy::TimingAdvance { n_ta_tc } => {
                    s.clock.n_ta_tc = n_ta_tc;
                }
                MacToPhy::Paging { ue_id } => {
                    s.monitor.rntis.p_ue_id = ue_id;
                }
                MacToPhy::PdcchMonitoring { c_rnti } => {
                    s.monitor.monitor_c_rnti = c_rnti;
                }
                MacToPhy::UlTti(req) => {
                    if !self.tx_enabled {
                        self.mac.handle(
                            PhyToMac::Error(ErrorIndication::TxDropped {
                                slot: req.slot,
                                pdu: "ul_tti (STOP)",
                            }),
                            &mut followups,
                        );
                        continue;
                    }
                    let lead = req.slot.diff(&now);
                    if lead < 1 {
                        self.stats.late_ul += 1;
                        self.mac.handle(
                            PhyToMac::Error(ErrorIndication::TxDropped {
                                slot: req.slot,
                                pdu: "ul_tti",
                            }),
                            &mut Vec::new(),
                        );
                        continue;
                    }
                    for pdu in &req.pdus {
                        if let UlTtiPdu::Prach {
                            occasion, preamble, ..
                        } = pdu
                        {
                            self.pending_prach
                                .push((occasion.slot, *occasion, *preamble));
                        }
                    }
                    let crnti = s.monitor.rntis.c.map_or(0, |r| r.0) as i64;
                    let mut clock = s.clock.clone();
                    // Calibration aid: FERRITE_PRACH_SWEEP="-400,-200,0,200" cycles
                    // the UL timing offset (samples) over successive PRACH attempts
                    // so the gNB's detection log reveals the backend's TX/RX
                    // alignment.
                    if req.pdus.iter().any(|p| matches!(p, UlTtiPdu::Prach { .. })) {
                        if let Some(v) = self.prach_sweep.as_ref().filter(|v| !v.is_empty()) {
                            let off = v[self.prach_sweep_idx % v.len()];
                            self.prach_sweep_idx += 1;
                            clock.tx_rx_offset = off;
                            log::info!(
                                "PRACH sweep: slot {} with tx_rx_offset {off} samples",
                                req.slot
                            );
                        }
                    } else if req.pdus.iter().any(|p| matches!(p, UlTtiPdu::Pusch { .. })) {
                        // Same for PUSCH (FERRITE_PUSCH_SWEEP), cycled per PUSCH transmission.
                        if let Some(v) = self.pusch_sweep.as_ref().filter(|v| !v.is_empty()) {
                            let off = v[self.pusch_sweep_idx % v.len()];
                            self.pusch_sweep_idx += 1;
                            clock.tx_rx_offset = off;
                            log::info!(
                                "PUSCH sweep: slot {} with tx_rx_offset {off} samples",
                                req.slot
                            );
                        }
                    }
                    let ul_shift_hz = self.ul_frequency_correction(s);
                    if self
                        .tx_cmd
                        .try_send(TxCmd::Ul(
                            req,
                            clock,
                            crnti,
                            std::time::Instant::now(),
                            ul_shift_hz,
                        ))
                        .is_err()
                    {
                        self.stats.late_ul += 1;
                    }
                }
            }
        }
        if !followups.is_empty() {
            self.drain_outbox(s, &mut followups, now)?;
        }
        Ok(())
    }
}

/// The minimal PHY configuration for SIB1 reception, from the MIB.
#[allow(clippy::too_many_arguments)]
fn initial_config(
    p: &EngineParams,
    mib: &Mib,
    cs0: &Coreset0Config,
    numerology: Numerology,
    cell_id: u16,
    _cs0_idx: u8,
    ss0_idx: u8,
    k_ssb: u8,
) -> PhyConfig {
    let ssb_scs = Numerology::from_scs_khz(p.ssb_scs_khz).unwrap_or(numerology);
    PhyConfig::initial(
        p.duplex,
        numerology,
        ssb_scs,
        cell_id,
        cs0.n_rb,
        cs0.n_symb as u8,
        if mib.dmrs_typea_pos3 { 3 } else { 2 },
        k_ssb,
        ss0_idx,
    )
}

/// The Table 7.4.1.5.3-1 row of a configured CSI-RS resource, if supported.
fn csi_rs_row(r: &CsiRsResource) -> Option<csi::CsiRsRow> {
    match (r.row, r.nof_ports) {
        (1, _) => Some(csi::CsiRsRow::Row1),
        (2, _) => Some(csi::CsiRsRow::Row2),
        (4, _) => Some(csi::CsiRsRow::Row4),
        // `other` with two ports: row 3 (one FD-CDM2 group).
        (0, 2) => Some(csi::CsiRsRow::Row3),
        _ => None,
    }
}

/// Whether the UE measures this resource: the single-port TRS (CQI) and
/// every two- or four-port NZP resource (rows 3 / 4: rank, PMI and CQI).
fn csi_rs_measured(r: &CsiRsResource) -> Option<csi::CsiRsRow> {
    let row = csi_rs_row(r)?;
    let multi_port =
        matches!(row, csi::CsiRsRow::Row3) || (row == csi::CsiRsRow::Row4 && r.nof_ports == 4);
    (!r.zero_power && ((r.trs && row == csi::CsiRsRow::Row1) || (!r.trs && multi_port)))
        .then_some(row)
}

/// The codebook and highest allowed rank a multi-port resource is measured
/// against: the CSI report whose codebook has the resource's port count
/// (two ports: the two-port codebook; four: N1 = 2, N2 = 1, OCUDU's), rank 2
/// at most (two receive antennas).
fn csi_codebook(cfg: &PhyConfig, nof_ports: u8) -> (Codebook, u8) {
    let default = match nof_ports {
        2 => Codebook::TwoPort,
        4 => Codebook::SinglePanel { n1: 2, n2: 1 },
        _ => Codebook::OnePort,
    };
    cfg.csi_reports
        .iter()
        .find(|c| c.codebook.nof_ports() == nof_ports)
        .map_or((default, 2), |c| {
            let max = c.allowed_ranks().into_iter().max().unwrap_or(1);
            (c.codebook, max.min(2))
        })
}

fn worker_config(
    geom: &CellGeometry,
    cfg: &PhyConfig,
    cell_id: u16,
    cs0: &Coreset0Config,
    configured: bool,
) -> WorkerConfig {
    let coreset0_first_crb = cfg
        .coresets
        .iter()
        .find(|c| c.id == 0)
        .map_or(0, |c| c.start_crb as usize);
    let mut patterns = Vec::new();
    let mut meas = Vec::new();
    for r in &cfg.pdsch.csi_rs_rate_match {
        let Some(row) = csi_rs_row(r) else {
            continue;
        };
        let mut symbols = vec![r.first_symbol as usize];
        if let Some(s2) = r.second_symbol {
            symbols.push(s2 as usize);
        }
        patterns.push(csi::CsiRsPattern {
            period_slots: r.period_slots as u32,
            offset_slots: r.offset_slots as u32,
            symbols: symbols.clone(),
            start_rb: r.start_rb as usize,
            n_rb: r.n_rb as usize,
            re_mask: csi::csi_rs_re_mask(row, r.freq_bits),
        });
        if csi_rs_measured(r).is_some() {
            meas.push((
                csi::CsiRsMeasurement {
                    row,
                    n_id: r.scrambling_id,
                    k0: csi::csi_rs_k0(row, r.freq_bits),
                    symbol: r.first_symbol as usize,
                    start_rb: r.start_rb as usize,
                    n_rb: r.n_rb as usize,
                },
                r.period_slots as u32,
                r.offset_slots as u32,
                csi_codebook(cfg, r.nof_ports),
            ));
        }
    }
    for p in &patterns {
        log::info!(
            "CSI-RS rate-match pattern: symbols {:?} rb {}+{} re-mask {:#014b} period {} offset {}",
            p.symbols,
            p.start_rb,
            p.n_rb,
            p.re_mask,
            p.period_slots,
            p.offset_slots
        );
    }
    WorkerConfig {
        geom: geom.clone(),
        cell_id,
        dl_bwp_start: cfg.dl_bwp.start_crb as usize,
        dl_bwp_rb: cfg.dl_bwp.n_rb as usize,
        vrb_bundle_size: cfg.pdsch.vrb_to_prb_interleaver.unwrap_or(2) as usize,
        coreset0_first_crb,
        coreset0_rb: cs0.n_rb,
        dmrs_typea_pos: cfg.ssb.dmrs_typea_pos,
        scrambling_id: None,
        dmrs_scrambling_id0: cfg.pdsch.dmrs_type_a.scrambling_id0,
        csi_patterns: patterns,
        csi_meas: meas,
        csi_rate_match_enabled: configured,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TS 38.133 §8.1: out-of-sync below Q_out, in-sync above Q_in, nothing
    /// in between; a missing SSB is out-of-sync.
    #[test]
    fn rlm_thresholds_have_hysteresis() {
        assert_eq!(rlm_evaluate(None), Some(false));
        assert_eq!(rlm_evaluate(Some(-20.0)), Some(false));
        assert_eq!(rlm_evaluate(Some(RLM_Q_OUT_DB - 0.1)), Some(false));
        assert_eq!(rlm_evaluate(Some(RLM_Q_OUT_DB)), None);
        assert_eq!(rlm_evaluate(Some(-7.0)), None);
        assert_eq!(rlm_evaluate(Some(RLM_Q_IN_DB)), Some(true));
        assert_eq!(rlm_evaluate(Some(30.0)), Some(true));
        assert_eq!(rlm_evaluate(Some(f32::INFINITY)), Some(true));
    }

    #[test]
    fn tables_are_well_formed() {
        assert_eq!(ferrite_common::fsm::check::<CellPhaseMachine>(), Ok(()));
        assert_eq!(ferrite_common::fsm::check::<RlmMachine>(), Ok(()));
    }

    #[test]
    fn engine_gives_the_cell_up_after_rrc_had_its_chance() {
        // SSB period ≥ 10 ms → ≥ 2 s: longer than the largest T310 (2000 ms)
        // plus N310 (≤ 20) indications at that period.
        assert!(RLM_MAX_MISSED_SSB as u64 * 10 >= 2000 + 20 * 10);
        let mut r = RlmState::InSync;
        for _ in 0..RLM_MAX_MISSED_SSB {
            r = r.miss();
        }
        assert_eq!(
            r,
            RlmState::OutOfSync {
                misses: RLM_MAX_MISSED_SSB
            }
        );
    }
}
