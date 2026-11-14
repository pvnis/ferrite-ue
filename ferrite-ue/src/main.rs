//! `ferrite-ue` — the UE binary: parse the configuration, open the radio, run
//! the L1 engine with the stack as its MAC handler, and report progress.

use ferrite_l1::engine::{self, EngineCommand, EngineEvent, EngineParams};
use ferrite_l1::radio::{UlPacing, UlServer};
use ferrite_l1::stream::BufferedStream;
use ferrite_rrc::derive::MibInfo;
use ferrite_ue::config::{RadioConfig, UeConfig};
use ferrite_ue::stack::{Stack, StackEvent};

fn main() {
    let cfg = match UeConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cfg.log.clone())).format_timestamp_micros().init();
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
    let (dl, ul): (BufferedStream, UlServer) = match &cfg.radio {
        RadioConfig::Zmq { tx, rx } => {
            let src = ferrite_radio::zmq::ZmqSource::connect(tx, cfg.fs, 5_000).expect("connect DL");
            let sink = ferrite_radio::zmq::ZmqSink::bind(rx, cfg.fs, block_len).expect("bind UL");
            (
                BufferedStream::spawn(src, block_len),
                UlServer {
                    sink: Box::new(ferrite_l1::radio::ZmqUlSink(sink)),
                    pacing: UlPacing::Lockstep { pace_us: slot_us },
                    tx_rx_offset: cfg.tx_rx_offset,
                    block_len,
                    start_index: 0,
                },
            )
        }
        RadioConfig::Sdr { .. } => {
            eprintln!("the SDR backend is not wired into this binary yet");
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
        tx_rx_offset: cfg.tx_rx_offset,
        prach_offset: cfg.prach_offset,
        pacing: UlPacing::Lockstep { pace_us: slot_us },
        ul_block_len: block_len,
        cfo_correction: !matches!(cfg.radio, RadioConfig::Zmq { .. }),
        max_search_attempts: 0,
    };
    let (cmd_tx, cmd_rx) = crossbeam_channel::bounded::<EngineCommand>(4);
    let (ev_tx, ev_rx) = crossbeam_channel::bounded::<EngineEvent>(64);
    {
        let cmd_tx = cmd_tx.clone();
        ctrlc_handler(move || {
            let _ = cmd_tx.try_send(EngineCommand::Stop);
        });
    }
    let mut stack = Stack::new(cfg.clone(), None);
    // MIB facts reach the stack through this channel (polled on the timeline thread).
    let (mib_tx, mib_rx) = crossbeam_channel::bounded::<MibInfo>(2);
    let (meas_tx, meas_rx) = crossbeam_channel::bounded::<(u16, ferrite_common::SlotPoint, f32, f32, f32)>(8);
    let reporter = {
        let ssb_scs_khz = cfg.ssb_scs_khz;
        let dl_center_hz = cfg.dl_center_hz;
        std::thread::spawn(move || {
            while let Ok(ev) = ev_rx.recv() {
                match ev {
                    EngineEvent::CellFound { pci, sfn, cfo_hz, ssb_df_hz, mib, coreset0, ssb_index } => {
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
                    EngineEvent::Measurement { pci, slot, rsrp_dbfs, rsrq_db, sinr_db } => {
                        log::debug!("ssb measurement PCI {pci} @{slot}: rsrp {rsrp_dbfs:.1} dBFS rsrq {rsrq_db:.1} dB sinr {sinr_db:.1} dB");
                        let _ = meas_tx.try_send((pci, slot, rsrp_dbfs, rsrq_db, sinr_db));
                    }
                    EngineEvent::SyncLost => log::warn!("sync lost"),
                    EngineEvent::Stopped => break,
                }
            }
        })
    };
    if cfg.timeout_s > 0 {
        let cmd_tx = cmd_tx.clone();
        let t = cfg.timeout_s;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(t));
            let _ = cmd_tx.try_send(EngineCommand::Stop);
        });
    }
    let result = {
        let mut handler = Reporting { stack: &mut stack, cmd_tx: cmd_tx.clone(), exit_after_ping: cfg.exit_after_ping, done: false, mib_rx, meas_rx };
        engine::run(params, dl, ul, &mut handler, cmd_rx, ev_tx)
    };
    let _ = reporter.join();
    match result {
        Ok(stats) => {
            log::info!("engine stopped: {stats:?}; MAC {:?}", stack.mac.stats());
            std::process::exit(if ping_succeeded(&stack) { 0 } else { 1 });
        }
        Err(e) => {
            log::error!("engine failed: {e}");
            std::process::exit(1);
        }
    }
}

fn ping_succeeded(stack: &Stack) -> bool {
    stack.ping_result.is_some_and(|(_, received)| received > 0)
}

/// Wraps the stack to print application events and stop the engine when done.
struct Reporting<'a> {
    stack: &'a mut Stack,
    cmd_tx: crossbeam_channel::Sender<EngineCommand>,
    exit_after_ping: bool,
    done: bool,
    mib_rx: crossbeam_channel::Receiver<MibInfo>,
    meas_rx: crossbeam_channel::Receiver<(u16, ferrite_common::SlotPoint, f32, f32, f32)>,
}

impl ferrite_fapi::MacHandler for Reporting<'_> {
    fn handle(&mut self, msg: ferrite_fapi::PhyToMac, phy: &mut dyn ferrite_fapi::MacToPhySink) {
        while let Ok(m) = self.mib_rx.try_recv() {
            self.stack.set_mib(m);
        }
        while let Ok((pci, slot, rsrp, rsrq, sinr)) = self.meas_rx.try_recv() {
            self.stack.on_measurement(pci, slot, rsrp, rsrq, sinr);
        }
        self.stack.handle(msg, phy);
        while let Some(ev) = self.stack.events.pop_front() {
            match &ev {
                StackEvent::CellConfigured { plmn, tac } => log::info!("★ cell configured: PLMN {plmn} TAC {tac}"),
                StackEvent::RrcConnected => log::info!("★ RRC connected"),
                StackEvent::Registered => log::info!("★ registered"),
                StackEvent::PduSessionUp { ip } => log::info!("★ PDU session up: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                StackEvent::PingReply { seq, rtt_ms } => log::info!("🏓 seq={seq} time={rtt_ms:.1} ms"),
                StackEvent::PingDone { sent, received } => {
                    log::info!("★ ping done: {received}/{sent} replies");
                    if self.exit_after_ping && !self.done {
                        self.done = true;
                        let _ = self.cmd_tx.try_send(EngineCommand::Stop);
                    }
                }
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
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
}
