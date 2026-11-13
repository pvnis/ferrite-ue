//! Radio front-end abstraction for the slot engine.
//!
//! The engine only sees:
//! * a continuously drained downlink sample stream ([`DlStream`], a
//!   [`crate::stream::BufferedStream`] over any `SampleSource`), and
//! * an uplink server ([`UlServer`]) that is fed from the
//!   [`crate::rt::InjectionTable`] by absolute UL sample index.
//!
//! How the uplink is paced is a property of the backend, captured in
//! [`UlPacing`]: the ZMQ gNB pulls blocks in lockstep with the samples it
//! sends, so the UE paces the serve to real time and never serves past the
//! *commit mark* — the UL sample index up to which the engine guarantees the
//! injection table is final (every UL_TTI request for earlier samples has
//! been issued and built). Serving beyond the mark would emit zeros where a
//! transmission is still being built; serving behind it is what gives the
//! lockstep gNB the uplink it needs before it will send more downlink. A
//! real SDR's TX FIFO back-pressures writes and needs neither. The fixed RX→TX sample offset of a
//! backend is reported by [`UlServer::tx_rx_offset`] and consumed by
//! [`crate::timing::SampleClock`]; nothing else about the transport is visible.

use ferrite_common::{Iq, Result};
use ferrite_radio::SampleSink;
use std::sync::atomic::{AtomicI64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use crate::rt::InjectionTable;
use crate::stream::BufferedStream;

/// Downlink stream handed to the engine.
pub type DlStream = BufferedStream;

/// How to pace the uplink serve.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UlPacing {
    /// Lockstep transport (ZMQ): serve at `pace_us` wall-clock per slot and
    /// never past the engine's commit mark ([`UlShared::committed`]).
    Lockstep { pace_us: f64 },
    /// Free-running device clock: serve as fast as the sink accepts.
    FreeRunning,
}

/// One uplink backend: a sink plus its pacing policy and calibration.
pub struct UlServer {
    pub sink: Box<dyn UlSink + Send>,
    pub pacing: UlPacing,
    /// Fixed RX→TX sample offset (see module doc).
    pub tx_rx_offset: i64,
    /// Samples per served block.
    pub block_len: usize,
    /// UL index the first served sample corresponds to.
    pub start_index: i64,
}

/// A sink that serves one block at a time from a fill function (abstracts the
/// pull (ZMQ) vs push (SDR) difference).
pub trait UlSink {
    /// Serve one block: `fill(counter, block)` places samples for absolute UL
    /// index `counter`; advance `counter` by the samples accepted. Returns
    /// `Ok(false)` if nothing was served (no request yet / would block).
    fn serve_block(&mut self, counter: &mut u64, block: &mut [Iq], fill: &mut dyn FnMut(u64, &mut [Iq])) -> Result<bool>;
}

/// ZMQ: the gNB pulls; we answer each request with the next block.
#[cfg(feature = "zmq")]
pub struct ZmqUlSink(pub ferrite_radio::zmq::ZmqSink);

#[cfg(feature = "zmq")]
impl UlSink for ZmqUlSink {
    fn serve_block(&mut self, counter: &mut u64, _block: &mut [Iq], fill: &mut dyn FnMut(u64, &mut [Iq])) -> Result<bool> {
        self.0.serve_with(counter, |c, b| fill(c, b))
    }
}

/// A push sink (SDR): write a full block each call; the device FIFO paces us.
pub struct PushUlSink<S: SampleSink>(pub S);

impl<S: SampleSink> UlSink for PushUlSink<S> {
    fn serve_block(&mut self, counter: &mut u64, block: &mut [Iq], fill: &mut dyn FnMut(u64, &mut [Iq])) -> Result<bool> {
        let n = ferrite_radio::serve_push(&mut self.0, counter, block, |c, b| fill(c, b))?;
        Ok(n > 0)
    }
}

/// Shared state between the engine and the UL serve thread.
pub struct UlShared {
    /// UL index the serve thread has reached (behind the engine).
    pub served: AtomicI64,
    /// UL index up to which the injection table is final (lockstep gating):
    /// the engine advances it (through the TX builder, so that every build
    /// queued before the mark has landed) once per slot.
    pub committed: AtomicI64,
    pub table: Mutex<InjectionTable>,
    pub stop: std::sync::atomic::AtomicBool,
    /// Lockstep gating active (false during cell search, when nothing bounds
    /// the DL consumption yet and the gNB needs uplink to make progress).
    pub gate: std::sync::atomic::AtomicBool,
}

impl UlShared {
    pub fn new(start: i64) -> Arc<Self> {
        Arc::new(Self {
            served: AtomicI64::new(start),
            committed: AtomicI64::new(start),
            table: Mutex::new(InjectionTable::new()),
            stop: std::sync::atomic::AtomicBool::new(false),
            gate: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

/// Run the UL serve loop (on its own thread) until `shared.stop` is set.
pub fn serve_uplink(mut server: UlServer, shared: Arc<UlShared>, samples_per_slot: i64, fs: f64) {
    let mut block = vec![Iq::default(); server.block_len];
    let mut counter = server.start_index as u64;
    let start = std::time::Instant::now();
    let slot_us = samples_per_slot as f64 / fs * 1e6;
    while !shared.stop.load(Relaxed) {
        if let UlPacing::Lockstep { pace_us } = server.pacing {
            // Gate: never serve past the commit mark (a block is served whole,
            // so its end is what must stay within the mark).
            let block_end = counter as i64 + server.block_len as i64;
            let mut waited = 0u32;
            while shared.gate.load(Relaxed) && block_end > shared.committed.load(Relaxed) && !shared.stop.load(Relaxed) {
                std::thread::sleep(std::time::Duration::from_micros(20));
                waited += 1;
                if waited > 500_000 {
                    break; // 10 s: the engine is gone
                }
            }
            // Pace to wall-clock.
            let served = (counter as i64 - server.start_index).max(0) as f64;
            let target = std::time::Duration::from_secs_f64(served / samples_per_slot as f64 * pace_us * 1e-6);
            let el = start.elapsed();
            if el < target {
                std::thread::sleep(target - el);
            }
        }
        let before = counter;
        let ok = {
            let table = &shared.table;
            server.sink.serve_block(&mut counter, &mut block, &mut |c, b| {
                b.iter_mut().for_each(|s| *s = Iq::default());
                table.lock().unwrap().fill(c as i64, b);
            })
        };
        match ok {
            Ok(true) => shared.served.store(counter as i64, Relaxed),
            Ok(false) => {
                // No request pending (ZMQ) — avoid a hot spin.
                if counter == before {
                    std::thread::sleep(std::time::Duration::from_micros(10));
                }
            }
            Err(e) => {
                log::error!("uplink serve failed: {e}");
                break;
            }
        }
    }
    let _ = slot_us;
}
