//! Pinning a device time base to the contiguous sample index the layers above
//! this crate reason in.
//!
//! A real SDR delivers buffers with a device timestamp and loses samples on an
//! overflow; the slot engine wants one gap-free stream whose index `i` always
//! means the same instant. [`Contiguous`] provides it: output index `i` is device
//! sample `origin + i`, where `origin` is the timestamp of the first buffer. Lost
//! samples are replaced by zeros so the index never slips, and the mapping is
//! published through a shared [`TimeBase`] so the transmit side can time its
//! bursts in the same device clock (`origin + uplink_index`).

use crate::SampleSource;
use ferrite_common::{Iq, Result};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

#[derive(Default)]
struct TimeBaseInner {
    origin: OnceLock<u64>,
    origin_set: (Mutex<bool>, Condvar),
    /// Device index one past the last RX sample delivered (origin-relative
    /// stream position of the stream head, plus the origin).
    latest: AtomicU64,
    /// Samples replaced by zeros so far.
    lost: AtomicU64,
    /// Overflow events seen so far.
    gaps: AtomicU64,
}

/// Shared RX ↔ TX time base of one device: the device sample index that stream
/// index 0 corresponds to, and how far the receive side has got.
#[derive(Clone, Default)]
pub struct TimeBase {
    inner: Arc<TimeBaseInner>,
}

impl TimeBase {
    /// Device sample index of stream index 0, once the first buffer arrived.
    pub fn origin(&self) -> Option<u64> {
        self.inner.origin.get().copied()
    }

    /// Block until the origin is known or `timeout` passes.
    pub fn wait_origin(&self, timeout: Duration) -> Option<u64> {
        if let Some(o) = self.origin() {
            return Some(o);
        }
        let (lock, cv) = &self.inner.origin_set;
        let guard = lock.lock().ok()?;
        let (guard, _) = cv.wait_timeout_while(guard, timeout, |set| !*set).ok()?;
        drop(guard);
        self.origin()
    }

    /// Device index just past the newest received sample (`None` before the first buffer).
    pub fn latest(&self) -> Option<u64> {
        self.origin().map(|_| self.inner.latest.load(Relaxed))
    }

    /// Samples lost to overflows and replaced by zeros.
    pub fn lost(&self) -> u64 {
        self.inner.lost.load(Relaxed)
    }

    /// Overflow events (gaps) seen.
    pub fn gaps(&self) -> u64 {
        self.inner.gaps.load(Relaxed)
    }

    fn set_origin(&self, origin: u64) {
        if self.inner.origin.set(origin).is_ok() {
            let (lock, cv) = &self.inner.origin_set;
            if let Ok(mut set) = lock.lock() {
                *set = true;
            }
            cv.notify_all();
        }
    }
}

/// A gap-free view of a timestamped [`SampleSource`] (see the module doc).
///
/// Sources without a time base pass straight through.
pub struct Contiguous<S> {
    inner: S,
    time: TimeBase,
    /// Device index the next delivered sample is expected to carry.
    next: Option<u64>,
    /// Zeros still owed for a detected gap.
    zeros_due: u64,
    /// Samples read from the device but not yet handed out (behind a gap).
    held: Vec<Iq>,
    held_pos: usize,
    scratch: Vec<Iq>,
    /// Stream index of the first sample of the last `read`.
    last_index: u64,
    position: u64,
}

impl<S: SampleSource> Contiguous<S> {
    pub fn new(inner: S, time: TimeBase) -> Self {
        Self {
            inner,
            time,
            next: None,
            zeros_due: 0,
            held: Vec::new(),
            held_pos: 0,
            scratch: Vec::new(),
            last_index: 0,
            position: 0,
        }
    }

    pub fn time_base(&self) -> &TimeBase {
        &self.time
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Hand out owed zeros, then held samples; returns how many were written.
    fn drain_pending(&mut self, buf: &mut [Iq]) -> usize {
        let mut n = 0;
        if self.zeros_due > 0 {
            let z = (self.zeros_due as usize).min(buf.len());
            buf[..z].iter_mut().for_each(|s| *s = Iq::default());
            self.zeros_due -= z as u64;
            n += z;
        }
        if self.zeros_due == 0 && self.held_pos < self.held.len() {
            let take = (self.held.len() - self.held_pos).min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&self.held[self.held_pos..self.held_pos + take]);
            self.held_pos += take;
            n += take;
            if self.held_pos == self.held.len() {
                self.held.clear();
                self.held_pos = 0;
            }
        }
        n
    }

    /// Account for a buffer of `n` samples stamped `ts`: owe zeros for a gap,
    /// drop the overlap of a step back, advance the expected index.
    fn align(&mut self, ts: u64, n: usize) -> usize {
        let Some(next) = self.next else {
            self.time.set_origin(ts);
            self.next = Some(ts + n as u64);
            return 0;
        };
        let mut skip = 0usize;
        if ts > next {
            let gap = ts - next;
            self.zeros_due += gap;
            self.time.inner.lost.fetch_add(gap, Relaxed);
            self.time.inner.gaps.fetch_add(1, Relaxed);
        } else if ts < next {
            // Time stepped back (the device re-sent samples we already have).
            skip = ((next - ts) as usize).min(n);
        }
        self.next = Some(next.max(ts + n as u64));
        skip
    }
}

impl<S: SampleSource> SampleSource for Contiguous<S> {
    fn sample_rate(&self) -> f64 {
        self.inner.sample_rate()
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        let start = self.position;
        let pending = self.drain_pending(buf);
        if pending > 0 {
            self.last_index = start;
            self.position += pending as u64;
            return Ok(pending);
        }
        self.scratch.resize(buf.len(), Iq::default());
        let n = self.inner.read(&mut self.scratch)?;
        if n == 0 {
            return Ok(0);
        }
        let Some(ts) = self.inner.timestamp() else {
            // No device time base: pass through unchanged.
            buf[..n].copy_from_slice(&self.scratch[..n]);
            self.last_index = start;
            self.position += n as u64;
            return Ok(n);
        };
        let skip = self.align(ts, n);
        if let Some(next) = self.next {
            self.time.inner.latest.store(next, Relaxed);
        }
        let data = &self.scratch[skip..n];
        if self.zeros_due > 0 {
            // Zeros first; the samples wait behind them.
            self.held.clear();
            self.held.extend_from_slice(data);
            self.held_pos = 0;
            let z = self.drain_pending(buf);
            self.last_index = start;
            self.position += z as u64;
            return Ok(z);
        }
        buf[..data.len()].copy_from_slice(data);
        self.last_index = start;
        self.position += data.len() as u64;
        Ok(data.len())
    }

    /// Device index of the first sample of the last read: `origin + stream index`.
    fn timestamp(&self) -> Option<u64> {
        self.time.origin().map(|o| o + self.last_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that delivers scripted (timestamp, samples) buffers.
    struct Scripted {
        bufs: std::collections::VecDeque<(u64, Vec<Iq>)>,
        ts: Option<u64>,
    }
    impl SampleSource for Scripted {
        fn sample_rate(&self) -> f64 {
            1e6
        }
        fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
            let Some((ts, data)) = self.bufs.pop_front() else {
                return Ok(0);
            };
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            self.ts = Some(ts);
            Ok(n)
        }
        fn timestamp(&self) -> Option<u64> {
            self.ts
        }
    }

    fn ramp(start: u64, n: usize) -> Vec<Iq> {
        (0..n)
            .map(|i| Iq::new((start + i as u64) as f32, 0.0))
            .collect()
    }

    fn collect(src: &mut Contiguous<Scripted>, buf_len: usize) -> Vec<Iq> {
        let mut out = Vec::new();
        let mut buf = vec![Iq::default(); buf_len];
        loop {
            let n = src.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// Output index i is device sample origin + i: a lost stretch comes out as
    /// zeros, the data after it lands at its true position, the time base
    /// reports the origin, the head and the loss.
    #[test]
    fn gaps_become_zeros_at_the_right_index() {
        let src = Scripted {
            bufs: [
                (1000, ramp(1000, 8)),
                (1008, ramp(1008, 8)),
                (1021, ramp(1021, 8)),
            ]
            .into_iter()
            .collect(),
            ts: None,
        };
        let time = TimeBase::default();
        let mut c = Contiguous::new(src, time.clone());
        let out = collect(&mut c, 8);
        assert_eq!(time.origin(), Some(1000));
        assert_eq!(out.len(), 29);
        for (i, s) in out.iter().enumerate() {
            let dev = 1000 + i as u64;
            let expect = if (1016..1021).contains(&dev) {
                0.0
            } else {
                dev as f32
            };
            assert_eq!(s.re, expect, "index {i}");
        }
        assert_eq!(time.lost(), 5);
        assert_eq!(time.gaps(), 1);
        assert_eq!(time.latest(), Some(1029));
    }

    /// Owed zeros longer than the caller's buffer are paid out over several reads
    /// and the held data follows intact.
    #[test]
    fn long_gaps_span_reads() {
        let src = Scripted {
            bufs: [(50, ramp(50, 4)), (74, ramp(74, 4))].into_iter().collect(),
            ts: None,
        };
        let mut c = Contiguous::new(src, TimeBase::default());
        let out = collect(&mut c, 4);
        assert_eq!(out.len(), 28);
        assert!(out[4..24].iter().all(|s| *s == Iq::default()));
        assert_eq!(out[24].re, 74.0);
        assert_eq!(out[27].re, 77.0);
        assert_eq!(c.timestamp(), Some(50 + 24));
    }

    /// A buffer stamped before the expected index is an overlap: the repeated
    /// samples are dropped.
    #[test]
    fn overlaps_are_dropped() {
        let src = Scripted {
            bufs: [(0, ramp(0, 6)), (4, ramp(4, 6))].into_iter().collect(),
            ts: None,
        };
        let mut c = Contiguous::new(src, TimeBase::default());
        let out = collect(&mut c, 16);
        let got: Vec<f32> = out.iter().map(|s| s.re).collect();
        assert_eq!(got, (0..10).map(|v| v as f32).collect::<Vec<_>>());
    }

    /// `wait_origin` wakes a waiter when the first buffer arrives.
    #[test]
    fn waiters_wake_on_the_first_buffer() {
        let time = TimeBase::default();
        assert_eq!(time.wait_origin(Duration::from_millis(5)), None);
        let t2 = time.clone();
        let h = std::thread::spawn(move || t2.wait_origin(Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(10));
        time.set_origin(777);
        assert_eq!(h.join().unwrap(), Some(777));
    }
}
