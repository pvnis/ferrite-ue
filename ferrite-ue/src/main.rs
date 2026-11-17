//! `ferrite-ue` — the UE binary: parse the configuration, open the radio, run
//! the L1 engine with the stack as its MAC handler, and report progress.

use ferrite_l1::engine::{self, EngineCommand, EngineEvent, EngineParams};
use ferrite_l1::radio::{UlPacing, UlServer};
use ferrite_l1::stream::BufferedStream;
use ferrite_rrc::derive::MibInfo;
use ferrite_ue::config::{RadioConfig, UeConfig};
use ferrite_ue::stack::{Stack, StackEvent};

fn main() {
    let mut cfg = match UeConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cfg.log.clone()))
        .format_timestamp_micros()
        .init();
    log::info!(
        "ferrite-ue: band n{} {:?} DL {:.3} MHz UL {:.3} MHz fs {:.2} MHz SSB SCS {} kHz",
        cfg.band,
        cfg.duplex,
        cfg.dl_center_hz / 1e6,
        cfg.ul_center_hz / 1e6,
        cfg.fs / 1e6,
        cfg.ssb_scs_khz
    );
    let block_len = 1920usize;
    let mu = ferrite_common::Numerology::from_scs_khz(cfg.ssb_scs_khz).map_or(1, |n| n.mu);
    let slot_us = 1000.0 / (1u32 << mu) as f64;
    raise_tx_lead_for_ul_stream(&mut cfg, block_len);
    let (dl, ul) = match open_radio(&cfg, block_len, slot_us) {
        Ok(r) => r,
        Err(e) => {
            log::error!("radio: {e}");
            std::process::exit(2);
        }
    };
    let params = EngineParams {
        fs: cfg.fs,
        dl_center_hz: cfg.dl_center_hz,
        ul_center_hz: cfg.ul_center_hz,
        ssb_scs_khz: cfg.ssb_scs_khz,
        duplex: cfg.duplex,
        band: cfg.band,
        gscn_hint: cfg.gscn_hint,
        tx_lead_slots: cfg.tx_lead,
        ul_stream_lead_slots: cfg.ul_stream_lead_slots,
        tx_rx_offset: cfg.tx_rx_offset,
        prach_offset: cfg.prach_offset,
        pacing: ul.pacing,
        ul_block_len: block_len,
        // Always on: over ZMQ the estimate is exactly 0 Hz and the correction
        // is skipped, unless a channel emulator or `--emulate-lo-ppm` adds one.
        cfo_correction: true,
        // The emulated LO error impairs the frequency only, not the sample clock.
        sro_from_cfo: !cfg.independent_lo && cfg.emulate_lo_ppm.is_none(),
        max_search_attempts: 0,
        rlm_outage: cfg.rlm_outage,
    };
    let (cmd_tx, cmd_rx) = crossbeam_channel::bounded::<EngineCommand>(4);
    let (ev_tx, ev_rx) = crossbeam_channel::bounded::<EngineEvent>(64);
    // A shutdown request first lets the NAS deregister (switch off); the
    // engine stops a moment later (see `Reporting`), or at once when the UE
    // is not registered.
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        let cmd_tx = cmd_tx.clone();
        ctrlc_handler(move || {
            if shutdown.swap(true, std::sync::atomic::Ordering::SeqCst) {
                // Second Ctrl-C: stop now.
                let _ = cmd_tx.try_send(EngineCommand::Stop);
            }
        });
    }
    let mut stack = Stack::new(cfg.clone(), None);
    // MIB facts reach the stack through this channel (polled on the timeline thread).
    let (mib_tx, mib_rx) = crossbeam_channel::bounded::<MibInfo>(2);
    let (meas_tx, meas_rx) = crossbeam_channel::bounded::<Measurement>(8);
    let reporter = {
        let ssb_scs_khz = cfg.ssb_scs_khz;
        let dl_center_hz = cfg.dl_center_hz;
        std::thread::spawn(move || {
            while let Ok(ev) = ev_rx.recv() {
                match ev {
                    EngineEvent::CellFound {
                        pci,
                        sfn,
                        cfo_hz,
                        ssb_df_hz,
                        mib,
                        coreset0,
                        ssb_index,
                    } => {
                        log::info!("cell found: PCI {pci} SFN {sfn} CFO {cfo_hz:.0} Hz SSB offset {:.3} MHz", ssb_df_hz / 1e6);
                        let _ = mib_tx.try_send(MibInfo {
                            pci,
                            mu: if mib.scs_common_is_30_or_120 { 1 } else { 0 },
                            dmrs_typea_pos: if mib.dmrs_typea_pos3 { 3 } else { 2 },
                            k_ssb: (mib.k_ssb_msb << 4) | mib.ssb_subcarrier_offset,
                            coreset0_index: mib.pdcch_config_sib1 >> 4,
                            ss0_index: mib.pdcch_config_sib1 & 0xf,
                            ssb_index,
                            ssb_scs_khz,
                            coreset0_n_rb: coreset0.0,
                            coreset0_n_symb: coreset0.1,
                            coreset0_offset_rb: coreset0.2,
                            ssb_arfcn: ferrite_common::band::hz_to_arfcn(dl_center_hz + ssb_df_hz),
                        });
                    }
                    EngineEvent::Measurement {
                        pci,
                        slot,
                        rsrp_dbfs,
                        rsrq_db,
                        sinr_db,
                        rx_gain_db,
                    } => {
                        log::debug!("ssb measurement PCI {pci} @{slot}: rsrp {rsrp_dbfs:.1} dBFS (gain {rx_gain_db} dB) rsrq {rsrq_db:.1} dB sinr {sinr_db:.1} dB");
                        let _ = meas_tx.try_send(Measurement {
                            pci,
                            slot,
                            rsrp_dbfs,
                            rx_gain_db,
                            rsrq_db,
                            sinr_db,
                        });
                    }
                    EngineEvent::SyncLost => log::warn!("sync lost"),
                    EngineEvent::Stopped => break,
                }
            }
        })
    };
    if cfg.timeout_s > 0 {
        let cmd_tx = cmd_tx.clone();
        let shutdown = shutdown.clone();
        let t = cfg.timeout_s;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(t));
            shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            // Backstop: the engine stops even if no slot indication arrives.
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = cmd_tx.try_send(EngineCommand::Stop);
        });
    }
    let result = {
        let mut handler = Reporting {
            stack: &mut stack,
            cmd_tx: cmd_tx.clone(),
            exit_after_ping: cfg.exit_after_ping,
            done: false,
            mib_rx,
            meas_rx,
            shutdown,
            stop_at: None,
        };
        engine::run(params, dl, ul, &mut handler, cmd_rx, ev_tx)
    };
    let _ = reporter.join();
    match result {
        Ok(stats) => {
            log::info!("engine stopped: {stats:?}; MAC {:?}", stack.mac_stats());
            for line in stack.perf_report() {
                log::info!("{line}");
            }
            stack.flush_capture();
            std::process::exit(if ping_succeeded(&stack) { 0 } else { 1 });
        }
        Err(e) => {
            log::error!("engine failed: {e}");
            stack.flush_capture();
            std::process::exit(1);
        }
    }
}

/// Open the configured radio backend: the downlink stream(s) and the uplink server.
fn open_radio(
    cfg: &UeConfig,
    block_len: usize,
    slot_us: f64,
) -> ferrite_common::Result<(ferrite_l1::radio::DlStream, UlServer)> {
    match &cfg.radio {
        RadioConfig::Zmq { tx, rx } => {
            let chans = tx
                .iter()
                .map(|ep| {
                    ferrite_radio::zmq::ZmqSource::connect(ep, cfg.fs, 5_000).map(|src| {
                        match cfg.emulate_lo_ppm {
                            Some(ppm) => BufferedStream::spawn(
                                ferrite_radio::impair::FrequencyOffset::new(
                                    src,
                                    -ppm * 1e-6 * cfg.dl_center_hz,
                                ),
                                block_len,
                            ),
                            None => BufferedStream::spawn(src, block_len),
                        }
                    })
                })
                .collect::<ferrite_common::Result<Vec<BufferedStream>>>()?;
            if chans.is_empty() {
                return Err(ferrite_common::Error::Config(
                    "at least one downlink endpoint is needed".into(),
                ));
            }
            log::info!("DL: {} receive antenna(s) {:?}", chans.len(), tx);
            let sink = ferrite_radio::zmq::ZmqSink::bind(rx, cfg.fs, block_len)?;
            let mut ul_sink: Box<dyn ferrite_l1::radio::UlSink + Send> =
                Box::new(ferrite_l1::radio::ZmqUlSink(sink));
            if let Some(ppm) = cfg.emulate_lo_ppm {
                log::warn!(
                    "emulating a {ppm} ppm LO error: DL {:+.0} Hz, UL {:+.0} Hz",
                    -ppm * 1e-6 * cfg.dl_center_hz,
                    ppm * 1e-6 * cfg.ul_center_hz
                );
                ul_sink = Box::new(ferrite_l1::radio::MixedUlSink {
                    inner: ul_sink,
                    shift_hz: ppm * 1e-6 * cfg.ul_center_hz,
                    fs: cfg.fs,
                });
            }
            Ok((
                ferrite_l1::radio::DlStream::new(chans),
                UlServer {
                    sink: ul_sink,
                    pacing: UlPacing::Lockstep { pace_us: slot_us },
                    tx_rx_offset: cfg.tx_rx_offset,
                    block_len,
                    start_index: 0,
                },
            ))
        }
        #[cfg(feature = "sdr")]
        RadioConfig::Sdr {
            args,
            rx_gain,
            tx_gain,
            rx_antenna,
            tx_antenna,
            tx_latency_s,
        } => {
            use ferrite_radio::soapy::{SoapyConfig, SoapyRadio};
            use ferrite_radio::time::{Contiguous, TimeBase};
            let sc = SoapyConfig {
                args: args.clone(),
                sample_rate: cfg.fs,
                rx_frequency: cfg.dl_center_hz,
                tx_frequency: cfg.ul_center_hz,
                rx_gain: *rx_gain,
                tx_gain: *tx_gain,
                bandwidth: 0.0,
                rx_antenna: rx_antenna.clone(),
                tx_antenna: tx_antenna.clone(),
            };
            let radio = SoapyRadio::open(&sc)?;
            let (time_rate, source) = radio.time_rate();
            log::info!(
                "SDR {:?}: rate {} Hz (timestamps at {time_rate} Hz, {source:?}), RX {:.3} MHz gain {} dB, TX {:.3} MHz gain {} dB",
                args,
                radio.sample_rate(),
                cfg.dl_center_hz / 1e6,
                rx_gain,
                cfg.ul_center_hz / 1e6,
                tx_gain
            );
            // One time base: the receive side pins stream index 0 to a device
            // sample, the transmit side stamps every block from it.
            let time = TimeBase::default();
            let (rx, tx) = radio.streams()?;
            let gain = radio.rx_gain_control()?;
            let rx = Contiguous::new(rx, time.clone());
            let min_lead = (tx_latency_s * cfg.fs).round() as u64;
            Ok((
                ferrite_l1::radio::DlStream::single(BufferedStream::spawn(rx, block_len))
                    .with_gain_control(Box::new(gain)),
                UlServer {
                    sink: Box::new(ferrite_l1::radio::TimedPushUlSink::new(tx, time, min_lead)),
                    pacing: UlPacing::FreeRunning,
                    tx_rx_offset: cfg.tx_rx_offset,
                    block_len,
                    start_index: 0,
                },
            ))
        }
        #[cfg(not(feature = "sdr"))]
        RadioConfig::Sdr { .. } => Err(ferrite_common::Error::Config(
            "this binary was built without the `sdr` feature (cargo build --features sdr)".into(),
        )),
    }
}

/// Size the decision horizon for `--ul-stream-lead-slots` before the stack
/// and the engine take it. The uplink advance is not known before SIB1 and
/// the RAR, so the sizing assumes the largest `N_TA,offset` (39936 T_c,
/// TS 38.133 Table 7.1.2-2) with `N_TA = 0`; the engine warns if the timing
/// advance later outgrows it.
fn raise_tx_lead_for_ul_stream(cfg: &mut UeConfig, block_len: usize) {
    if cfg.ul_stream_lead_slots == 0 {
        return;
    }
    let sps = ferrite_common::Numerology::from_scs_khz(cfg.ssb_scs_khz)
        .map_or(1, |n| n.samples_per_slot(cfg.fs)) as i64;
    // `--prach-offset` is the negated uplink guard (positive = earlier).
    let advance = ferrite_common::slot::ta::tc_to_samples(39936, cfg.fs)
        + cfg.tx_rx_offset
        + cfg.prach_offset;
    let need = ferrite_l1::radio::tx_lead_for_ul_stream_lead(
        cfg.ul_stream_lead_slots,
        sps,
        block_len,
        advance,
    );
    if need > cfg.tx_lead {
        log::info!(
            "uplink stream lead of {} slot(s): tx lead raised from {} to {need} slots (needs K1, K2 > {need})",
            cfg.ul_stream_lead_slots,
            cfg.tx_lead
        );
        cfg.tx_lead = need;
    } else {
        log::info!(
            "uplink stream lead of {} slot(s) met by the tx lead of {} slots",
            cfg.ul_stream_lead_slots,
            cfg.tx_lead
        );
    }
}

fn ping_succeeded(stack: &Stack) -> bool {
    stack
        .ping_result()
        .is_some_and(|(_, received)| received > 0)
}

/// An SSB measurement on its way from the engine's reporter thread to the stack.
struct Measurement {
    pci: u16,
    slot: ferrite_common::SlotPoint,
    rsrp_dbfs: f32,
    rx_gain_db: f32,
    rsrq_db: f32,
    sinr_db: f32,
}

/// Wraps the stack to print application events and stop the engine when done.
struct Reporting<'a> {
    stack: &'a mut Stack,
    cmd_tx: crossbeam_channel::Sender<EngineCommand>,
    exit_after_ping: bool,
    done: bool,
    mib_rx: crossbeam_channel::Receiver<MibInfo>,
    meas_rx: crossbeam_channel::Receiver<Measurement>,
    /// Set by Ctrl-C, the timeout or the ping probe: deregister, then stop.
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// When the engine is stopped after the deregistration went out.
    stop_at: Option<ferrite_common::SlotPoint>,
}

impl ferrite_fapi::MacHandler for Reporting<'_> {
    fn handle(&mut self, msg: ferrite_fapi::PhyToMac, phy: &mut dyn ferrite_fapi::MacToPhySink) {
        while let Ok(m) = self.mib_rx.try_recv() {
            self.stack.set_mib(m);
        }
        if let ferrite_fapi::PhyToMac::Slot(s) = &msg {
            let now = s.slot;
            if self.shutdown.load(std::sync::atomic::Ordering::SeqCst) && !self.done {
                self.done = true;
                if self.stack.begin_shutdown(now) {
                    // Give the DEREGISTRATION REQUEST (and the RRC connection
                    // it may need) time to go out before the radio stops.
                    let slots = 600 * u64::from(now.numerology.slots_per_subframe());
                    log::info!("shutting down: deregistering first");
                    self.stop_at = Some(now.add(slots));
                } else {
                    let _ = self.cmd_tx.try_send(EngineCommand::Stop);
                }
            }
            if self.stop_at.is_some_and(|t| now.diff(&t) >= 0) {
                self.stop_at = None;
                let _ = self.cmd_tx.try_send(EngineCommand::Stop);
            }
        }
        while let Ok(m) = self.meas_rx.try_recv() {
            self.stack.on_measurement(
                m.pci,
                m.slot,
                m.rsrp_dbfs,
                m.rx_gain_db,
                m.rsrq_db,
                m.sinr_db,
            );
        }
        self.stack.handle(msg, phy);
        while let Some(ev) = self.stack.take_event() {
            match &ev {
                StackEvent::CellConfigured { plmn, tac } => {
                    log::info!("★ cell configured: PLMN {plmn} TAC {tac}")
                }
                StackEvent::RrcConnected => log::info!("★ RRC connected"),
                StackEvent::Registered => log::info!("★ registered"),
                StackEvent::PduSessionUp { ip } => {
                    log::info!("★ PDU session up: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                }
                StackEvent::PingReply { seq, rtt_ms } => {
                    log::info!("🏓 seq={seq} time={rtt_ms:.1} ms")
                }
                StackEvent::PingDone { sent, received } => {
                    log::info!("★ ping done: {received}/{sent} replies");
                    if self.exit_after_ping {
                        self.shutdown
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                StackEvent::RegistrationUpdated => log::info!("★ registration update complete"),
                // With "switch off" the NAS deregisters locally at once; the
                // request itself still needs the shutdown window (and, from
                // idle, an RRC connection) to reach the network.
                StackEvent::Deregistered => log::info!("★ deregistered"),
                StackEvent::Failed(why) => log::warn!("✗ {why}"),
                StackEvent::RrcReleased => log::info!("★ RRC released (idle)"),
                StackEvent::ServiceRequest { cause } => log::info!("★ service request ({cause})"),
                StackEvent::Reestablishing => log::warn!("★ radio link failure: re-establishing"),
                StackEvent::Reestablished => log::info!("★ RRC re-established"),
            }
        }
    }
}

fn ctrlc_handler(f: impl Fn() + Send + Sync + 'static) {
    static HANDLER: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();
    let _ = HANDLER.set(Box::new(f));
    extern "C" fn on_signal(_: libc::c_int) {
        if let Some(h) = HANDLER.get() {
            h();
        }
    }
    unsafe {
        libc::signal(
            libc::SIGINT,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
}
