//! Live PHY probe: synchronise to a gNB over ZMQ, decode SIB1 through the
//! Type0-PDCCH CSS, print it, and stop. Exercises cell search, the slot
//! clock, CORESET#0 geometry, DCI 1_0 (SI-RNTI) and the PDSCH decoder with no
//! L2/L3 involved.
//!
//!   cargo run -p ferrite-l1 --example sib1_probe -- <dl-arfcn> <srate-MHz> [band] [ssb-scs-kHz]

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_common::{arfcn_to_hz, BandInfo, RntiKind};
use ferrite_l1::engine::{self, EngineCommand, EngineEvent, EngineParams};
use ferrite_l1::fapi::*;
use ferrite_l1::radio::{UlPacing, UlServer, ZmqUlSink};
use ferrite_l1::stream::BufferedStream;

struct Probe {
    cmd: crossbeam_channel::Sender<EngineCommand>,
    slots: u64,
    got: bool,
}

impl MacHandler for Probe {
    fn handle(&mut self, msg: PhyToMac, _phy: &mut dyn MacToPhySink) {
        match msg {
            PhyToMac::Slot(s) => {
                self.slots += 1;
                if self.slots.is_multiple_of(200) {
                    log::info!("slot {} ({} processed)", s.slot, self.slots);
                }
                if self.slots > 1200 && !self.got {
                    log::error!("no SIB1 after {} slots", self.slots);
                    let _ = self.cmd.try_send(EngineCommand::Stop);
                }
            }
            PhyToMac::Dci(d) => log::info!("DCI @ {}: {:?}", d.slot, d.dci),
            PhyToMac::Sync(s) => log::debug!("RLM @ {}: in_sync {}", s.slot, s.in_sync),
            PhyToMac::RxData(r) => {
                log::info!(
                    "RX_Data @ {} {:?} harq {} crc {}",
                    r.pdsch_slot,
                    r.rnti_kind,
                    r.harq_id,
                    r.tb.is_some()
                );
                if r.rnti_kind == RntiKind::Si {
                    if let Some(tb) = r.tb {
                        log::info!("SIB1 TB ({} B): {}", tb.len(), ferrite_common::hex(&tb));
                        match ferrite_asn1::sib1::Sib1::decode(&tb) {
                            Ok(s) => log::info!("SIB1 decoded: {s:#?}"),
                            Err(e) => log::warn!("SIB1 decode error: {e:?}"),
                        }
                        self.got = true;
                        let _ = self.cmd.try_send(EngineCommand::Stop);
                    }
                }
            }
            PhyToMac::Csi(c) => log::info!("CSI {c:?}"),
            PhyToMac::Rach(_) => {}
            PhyToMac::Error(e) => log::warn!("PHY error {e:?}"),
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();
    let args: Vec<String> = std::env::args().collect();
    let arfcn: u32 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(626000);
    let fs: f64 = args
        .get(2)
        .and_then(|a| a.parse::<f64>().ok())
        .unwrap_or(15.36)
        * 1e6;
    let band: u16 = args.get(3).and_then(|a| a.parse().ok()).unwrap_or_else(|| {
        ferrite_common::band::BANDS
            .iter()
            .find(|b| (b.dl_arfcn.0..=b.dl_arfcn.1).contains(&arfcn))
            .map(|b| b.band)
            .unwrap_or(78)
    });
    let info = BandInfo::lookup(band).expect("band");
    let ssb_scs: u32 = args
        .get(4)
        .and_then(|a| a.parse().ok())
        .unwrap_or(info.ssb_scs_khz[0]);
    let gscn_hint: Option<u32> = args.get(5).and_then(|a| a.parse().ok());
    let dl = arfcn_to_hz(arfcn);
    let ul = arfcn_to_hz(info.ul_arfcn_for_dl(arfcn));
    let mu = ferrite_common::Numerology::from_scs_khz(ssb_scs)
        .unwrap()
        .mu;
    let slot_us = 1000.0 / (1u32 << mu) as f64;
    let block = 1920;
    let src =
        ferrite_radio::zmq::ZmqSource::connect("tcp://127.0.0.1:2100", fs, 5_000).expect("DL");
    let sink = ferrite_radio::zmq::ZmqSink::bind("tcp://127.0.0.1:2101", fs, block).expect("UL");
    let server = UlServer {
        sink: Box::new(ZmqUlSink(sink)),
        pacing: UlPacing::Lockstep { pace_us: slot_us },
        tx_rx_offset: 0,
        block_len: block,
        start_index: 0,
    };
    let params = EngineParams {
        fs,
        dl_center_hz: dl,
        ul_center_hz: ul,
        ssb_scs_khz: ssb_scs,
        duplex: info.duplex,
        band,
        gscn_hint,
        tx_lead_slots: 2,
        tx_rx_offset: 0,
        prach_offset: 0,
        pacing: UlPacing::Lockstep { pace_us: slot_us },
        ul_block_len: block,
        cfo_correction: false,
        sro_from_cfo: true,
        max_search_attempts: 10,
        rlm_outage: None,
    };
    let (cmd_tx, cmd_rx) = crossbeam_channel::bounded(4);
    let (ev_tx, ev_rx) = crossbeam_channel::bounded(16);
    std::thread::spawn(move || {
        while let Ok(ev) = ev_rx.recv() {
            if let EngineEvent::CellFound {
                pci,
                sfn,
                cfo_hz,
                ssb_df_hz,
                mib,
                ..
            } = &ev
            {
                log::info!("cell found PCI {pci} SFN {sfn} cfo {cfo_hz:.0} Hz ssb df {ssb_df_hz:.0} Hz MIB {mib:?}");
            }
            if matches!(ev, EngineEvent::Stopped) {
                break;
            }
        }
    });
    let mut probe = Probe {
        cmd: cmd_tx,
        slots: 0,
        got: false,
    };
    let r = engine::run(
        params,
        ferrite_l1::radio::DlStream::single(BufferedStream::spawn(src, block)),
        server,
        &mut probe,
        cmd_rx,
        ev_tx,
    );
    log::info!("engine: {r:?}");
    std::process::exit(if probe.got { 0 } else { 1 });
}
