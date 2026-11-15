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
//! real SDR free-runs on its own clock: the commit mark still bounds the serve
//! (a block is written only once its uplink is final) but nothing paces it —
//! each block is handed to the device stamped with its air time, derived from
//! the shared receive [`TimeBase`] ([`TimedPushUlSink`]), and the device FIFO
//! back-pressures the writer. The fixed RX→TX sample offset of a
//! backend is reported by [`UlServer::tx_rx_offset`] and consumed by
//! [`crate::timing::SampleClock`]; nothing else about the transport is visible.

use ferrite_common::{Error, Iq, Result};
use ferrite_radio::time::TimeBase;
use ferrite_radio::SampleSink;
use std::sync::atomic::{AtomicI64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use crate::rt::InjectionTable;
pub use crate::stream::BufferedStream;

/// Downlink stream handed to the engine.
/// The downlink sample streams, one per receive antenna, read in lockstep
/// (the same sample index on every antenna). Antenna 0 carries the timing:
/// cell search and the SSB tracking read it alone, the slot loop reads all.
pub struct DlStream {
    chans: Vec<BufferedStream>,
    scratch: Vec<Iq>,
}

impl DlStream {
    /// `chans` must hold at least one stream.
    pub fn new(chans: Vec<BufferedStream>) -> Self {
        assert!(!chans.is_empty(), "at least one receive antenna");
        Self {
            chans,
            scratch: Vec::new(),
        }
    }

    pub fn single(chan: BufferedStream) -> Self {
        Self::new(vec![chan])
    }

    pub fn nof_antennas(&self) -> usize {
        self.chans.len()
    }

    /// Samples consumed so far (identical on every antenna).
    pub fn position(&self) -> usize {
        self.chans[0].position()
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        for c in &mut self.chans {
            c.skip(n)?;
        }
        Ok(())
    }

    /// Read antenna 0 into `buf`; the other antennas advance by the same
    /// amount (their samples are dropped).
    pub fn read_exact(&mut self, buf: &mut [Iq]) -> Result<()> {
        self.chans[0].read_exact(buf)?;
        if self.chans.len() > 1 {
            self.scratch.resize(buf.len(), Iq::default());
            for c in &mut self.chans[1..] {
                c.read_exact(&mut self.scratch)?;
            }
        }
        Ok(())
    }

    /// Read `len` samples of every antenna into `out[antenna]`.
    pub fn read_exact_all(&mut self, len: usize, out: &mut Vec<Vec<Iq>>) -> Result<()> {
        out.resize_with(self.chans.len(), Vec::new);
        for (c, o) in self.chans.iter_mut().zip(out.iter_mut()) {
            o.resize(len, Iq::default());
            c.read_exact(o)?;
        }
        Ok(())
    }
}

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
    fn serve_block(
        &mut self,
        counter: &mut u64,
        block: &mut [Iq],
        fill: &mut dyn FnMut(u64, &mut [Iq]),
    ) -> Result<bool>;
}

/// ZMQ: the gNB pulls; we answer each request with the next block.
#[cfg(feature = "zmq")]
pub struct ZmqUlSink(pub ferrite_radio::zmq::ZmqSink);

#[cfg(feature = "zmq")]
impl UlSink for ZmqUlSink {
    fn serve_block(
        &mut self,
        counter: &mut u64,
        _block: &mut [Iq],
        fill: &mut dyn FnMut(u64, &mut [Iq]),
    ) -> Result<bool> {
        self.0.serve_with(counter, |c, b| fill(c, b))
    }
}

/// An untimed push sink: write a full block each call; the device FIFO paces
/// us. Only for sinks without a device time base (a file, a loopback); a real
/// SDR uses [`TimedPushUlSink`].
pub struct PushUlSink<S: SampleSink>(pub S);

impl<S: SampleSink> UlSink for PushUlSink<S> {
    fn serve_block(
        &mut self,
        counter: &mut u64,
        block: &mut [Iq],
        fill: &mut dyn FnMut(u64, &mut [Iq]),
    ) -> Result<bool> {
        let n = ferrite_radio::serve_push(&mut self.0, counter, block, |c, b| fill(c, b))?;
        Ok(n > 0)
    }
}

/// A timed push sink for an SDR: block `counter` goes on the air at device
/// sample `origin + counter`, where `origin` is the device index of downlink
/// stream sample 0 (published by the receive side through the shared
/// [`TimeBase`]). The uplink index is thus tied to the downlink index by the
/// device clock alone, exactly as over the lockstep transport, and the
/// [`crate::timing::SampleClock`] relation `u = d − TA − tx_rx_offset + guard`
/// holds unchanged.
///
/// A block whose air time is less than `min_lead` samples after the newest
/// received sample could not reach the device in time; it is skipped (the
/// counter jumps ahead, the transmission in it is lost and counted) rather than
/// written late, which the device would drop silently. The first block starts
/// at the receive head plus the lead.
pub struct TimedPushUlSink<S: SampleSink> {
    sink: S,
    time: TimeBase,
    min_lead: u64,
    started: bool,
    /// Late events and the samples they skipped.
    pub late: u64,
    pub skipped: u64,
}

impl<S: SampleSink> TimedPushUlSink<S> {
    /// `min_lead`: the device's write-to-air latency in samples, with margin.
    pub fn new(sink: S, time: TimeBase, min_lead: u64) -> Self {
        Self {
            sink,
            time,
            min_lead,
            started: false,
            late: 0,
            skipped: 0,
        }
    }
}

impl<S: SampleSink> UlSink for TimedPushUlSink<S> {
    fn serve_block(
        &mut self,
        counter: &mut u64,
        block: &mut [Iq],
        fill: &mut dyn FnMut(u64, &mut [Iq]),
    ) -> Result<bool> {
        let origin = self
            .time
            .wait_origin(std::time::Duration::from_secs(5))
            .ok_or_else(|| {
                Error::Radio("no receive time base: the SDR delivered nothing".into())
            })?;
        let latest = self.time.latest().unwrap_or(origin);
        let earliest = latest + self.min_lead;
        let due = origin + *counter;
        if due < earliest {
            // Jump to the first index that can still make it; the caller
            // re-checks its commit gate before the next fill.
            let skip = earliest - due;
            *counter += skip;
            if self.started {
                self.late += 1;
                self.skipped += skip;
                if self.late == 1 || self.late.is_multiple_of(200) {
                    log::warn!(
                        "uplink late by {skip} samples ({:.0} µs): skipped ({} late events, {} samples)",
                        skip as f64 / self.sink.sample_rate() * 1e6,
                        self.late,
                        self.skipped
                    );
                }
            } else {
                log::info!(
                    "uplink starts at stream index {counter} (device {})",
                    origin + *counter
                );
            }
            self.started = true;
            return Ok(true);
        }
        self.started = true;
        block.iter_mut().for_each(|s| *s = Iq::default());
        fill(*counter, block);
        let mut off = 0;
        while off < block.len() {
            let n = self
                .sink
                .write_at(&block[off..], origin + *counter + off as u64, false)?;
            if n == 0 {
                break;
            }
            off += n;
        }
        *counter += off as u64;
        Ok(off > 0)
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
        // Gate: never serve past the commit mark (a block is served whole,
        // so its end is what must stay within the mark). Both pacings: a
        // free-running device would otherwise be handed zeros for a slot
        // whose transmission is still being built.
        let block_end = counter as i64 + server.block_len as i64;
        let mut waited = 0u32;
        while shared.gate.load(Relaxed)
            && block_end > shared.committed.load(Relaxed)
            && !shared.stop.load(Relaxed)
        {
            std::thread::sleep(std::time::Duration::from_micros(20));
            waited += 1;
            if waited > 500_000 {
                break; // 10 s: the engine is gone
            }
        }
        if let UlPacing::Lockstep { pace_us } = server.pacing {
            // Pace to wall-clock.
            let served = (counter as i64 - server.start_index).max(0) as f64;
            let target = std::time::Duration::from_secs_f64(
                served / samples_per_slot as f64 * pace_us * 1e-6,
            );
            let el = start.elapsed();
            if el < target {
                std::thread::sleep(target - el);
            }
        }
        let before = counter;
        let ok = {
            let table = &shared.table;
            server
                .sink
                .serve_block(&mut counter, &mut block, &mut |c, b| {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that records every timed write: (device index, samples).
    #[derive(Default)]
    struct Recorder {
        writes: Vec<(u64, Vec<Iq>)>,
        chunk: usize,
    }
    impl SampleSink for Recorder {
        fn sample_rate(&self) -> f64 {
            1e6
        }
        fn write(&mut self, _buf: &[Iq]) -> Result<usize> {
            Err(Error::Radio("untimed write".into()))
        }
        fn write_at(&mut self, buf: &[Iq], at_sample: u64, _end: bool) -> Result<usize> {
            let n = if self.chunk == 0 {
                buf.len()
            } else {
                buf.len().min(self.chunk)
            };
            self.writes.push((at_sample, buf[..n].to_vec()));
            Ok(n)
        }
    }

    fn time_base(origin: u64, latest: u64) -> TimeBase {
        // Drive a Contiguous source once so the base learns origin and head.
        struct One(Option<(u64, usize)>);
        impl ferrite_radio::SampleSource for One {
            fn sample_rate(&self) -> f64 {
                1e6
            }
            fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
                Ok(self.0.take().map_or(0, |(_, n)| n.min(buf.len())))
            }
            fn timestamp(&self) -> Option<u64> {
                None
            }
        }
        struct Stamped(One, u64);
        impl ferrite_radio::SampleSource for Stamped {
            fn sample_rate(&self) -> f64 {
                1e6
            }
            fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
                self.0.read(buf)
            }
            fn timestamp(&self) -> Option<u64> {
                Some(self.1)
            }
        }
        let n = (latest - origin) as usize;
        let tb = TimeBase::default();
        let mut c = ferrite_radio::time::Contiguous::new(
            Stamped(One(Some((origin, n))), origin),
            tb.clone(),
        );
        let mut buf = vec![Iq::default(); n];
        ferrite_radio::SampleSource::read(&mut c, &mut buf).unwrap();
        tb
    }

    /// Blocks go out stamped `origin + counter`, in pieces when the device accepts
    /// partial writes, and the fill sees the absolute uplink index.
    #[test]
    fn timed_blocks_carry_the_device_index() {
        let tb = time_base(10_000, 10_500);
        let mut sink = TimedPushUlSink::new(
            Recorder {
                chunk: 3,
                ..Default::default()
            },
            tb,
            100,
        );
        let mut counter = 0u64;
        let mut block = vec![Iq::default(); 8];
        // First call: aligns to head + lead without writing.
        assert!(sink
            .serve_block(&mut counter, &mut block, &mut |_, _| {})
            .unwrap());
        assert_eq!(counter, 600);
        assert!(sink.sink.writes.is_empty());
        // Second call: writes the block at device 10_600.. in 3-sample pieces.
        let mut seen = None;
        assert!(sink
            .serve_block(&mut counter, &mut block, &mut |c, b| {
                seen = Some(c);
                b[2] = Iq::new(1.0, 0.0);
            })
            .unwrap());
        assert_eq!(seen, Some(600));
        assert_eq!(counter, 608);
        let w = &sink.sink.writes;
        assert_eq!(
            w.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            vec![10_600, 10_603, 10_606]
        );
        assert_eq!(w[0].1[2], Iq::new(1.0, 0.0));
        assert_eq!(sink.late, 0);
    }

    /// A block due before the receive head plus the lead is skipped, not written.
    #[test]
    fn late_blocks_are_skipped_and_counted() {
        let tb = time_base(0, 1_000);
        let mut sink = TimedPushUlSink::new(Recorder::default(), tb, 50);
        let mut counter = 1_050u64; // exactly on time: written
        let mut block = vec![Iq::default(); 10];
        assert!(sink
            .serve_block(&mut counter, &mut block, &mut |_, _| {})
            .unwrap());
        assert_eq!(sink.sink.writes.len(), 1);
        counter = 900; // the engine fell behind
        assert!(sink
            .serve_block(&mut counter, &mut block, &mut |_, _| {})
            .unwrap());
        assert_eq!(counter, 1_050);
        assert_eq!((sink.late, sink.skipped), (1, 150));
        assert_eq!(sink.sink.writes.len(), 1);
    }
}
