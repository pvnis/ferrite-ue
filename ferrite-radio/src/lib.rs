//! Radio hardware abstraction layer (HAL).
//!
//! Everything above the PHY consumes baseband IQ through [`SampleSource`] and
//! transmits through [`SampleSink`], independent of the underlying transport.
//! Backends live behind feature flags so the core builds without native libs:
//!
//! * [`mod@file`] — read/write interleaved little-endian `f32` IQ (always available);
//! * `soapy` (feature) — SoapySDR devices (LimeSDR, BladeRF, USRP, M2SDR);
//! * `zmq` (feature) — a gNB exposing baseband over ZeroMQ.
//!
//! Time is counted in **samples** everywhere above this crate. A backend with a
//! device time base reports the sample index of what it delivered
//! ([`SampleSource::timestamp`]) and accepts timed bursts by sample index
//! ([`SampleSink::write_at`]); converting to whatever unit the driver uses is
//! the backend's business and happens once per buffer at the edge.

use ferrite_common::{Error, Iq, Result};

pub mod file;
pub mod impair;
#[cfg(feature = "soapy")]
pub mod soapy;
pub mod time;
#[cfg(feature = "zmq")]
pub mod zmq;

/// A source of baseband IQ samples.
pub trait SampleSource {
    /// Nominal sample rate in samples/second.
    fn sample_rate(&self) -> f64;

    /// Fill `buf` with as many samples as available, returning the count
    /// written. A return of `0` indicates end-of-stream.
    fn read(&mut self, buf: &mut [Iq]) -> Result<usize>;

    /// Device sample index of the first sample the last successful [`read`](Self::read)
    /// delivered, when the backend has a device time base (an SDR). `None` for
    /// backends without one (file, ZMQ), whose samples are simply contiguous.
    fn timestamp(&self) -> Option<u64> {
        None
    }

    /// Read exactly `buf.len()` samples, returning `false` if the stream ended
    /// first.
    fn read_exact(&mut self, buf: &mut [Iq]) -> Result<bool> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..])?;
            if n == 0 {
                return Ok(false);
            }
            filled += n;
        }
        Ok(true)
    }
}

/// A sink for baseband IQ samples.
pub trait SampleSink {
    /// Nominal sample rate in samples/second.
    fn sample_rate(&self) -> f64;

    /// Write `buf`, returning the number of samples accepted.
    fn write(&mut self, buf: &[Iq]) -> Result<usize>;

    /// Write `buf` as (part of) a burst whose first sample goes on the air at device
    /// sample index `at_sample` (the same time base as [`SampleSource::timestamp`]);
    /// `end_burst` marks the last buffer of the burst. Backends without a device
    /// time base do not support it.
    fn write_at(&mut self, buf: &[Iq], at_sample: u64, end_burst: bool) -> Result<usize> {
        let _ = (buf, at_sample, end_burst);
        Err(Error::Radio(
            "timed transmission is not supported by this backend".into(),
        ))
    }
}

/// Run-time receive gain of a device front end (an SDR); drives the L1 AGC.
pub trait GainControl {
    /// Receive gain range `(min, max)` in dB.
    fn rx_gain_range(&self) -> (f64, f64);
    /// The receive gain currently applied (dB).
    fn rx_gain(&self) -> Result<f64>;
    /// Apply a receive gain; returns the gain the device settled on.
    fn set_rx_gain(&mut self, db: f64) -> Result<f64>;
}

/// Serve one uplink block by pushing it to `sink`: zero `block`, let `fill` place this
/// block's waveforms at the absolute uplink position `*counter`, write the block, and
/// advance `counter` by the number of samples the sink accepted.
///
/// This is the free-running (**push**) analog of the ZMQ [`zmq::ZmqSink::serve_with`]
/// **pull**. Where the ZMQ gNB requests uplink in lockstep and thereby clocks the timeline,
/// a real SDR free-runs: its TX FIFO backpressures `write`, so a loop of `serve_push` paces
/// itself to the device sample clock — no artificial pacing needed. `fill` places waveforms
/// from a position-keyed table (the same fill the ZMQ path uses), keyed by `*counter`; the
/// caller owns the RX→TX offset (it shifts either the counter's start or the fill positions).
///
/// Returns the number of samples served: `block.len()` normally, fewer only if the sink is
/// closing (a `write` of 0).
pub fn serve_push(
    sink: &mut dyn SampleSink,
    counter: &mut u64,
    block: &mut [Iq],
    fill: impl FnOnce(u64, &mut [Iq]),
) -> Result<usize> {
    // Idle uplink is silence; `fill` overwrites only the sample ranges it transmits.
    block.iter_mut().for_each(|s| *s = Iq::default());
    fill(*counter, block);
    let mut off = 0;
    while off < block.len() {
        let n = sink.write(&block[off..])?;
        if n == 0 {
            break; // sink closed — can't make progress
        }
        off += n;
    }
    *counter += off as u64;
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`SampleSink`] that records the full written stream in order.
    #[derive(Default)]
    struct CapturingSink {
        samples: Vec<Iq>,
    }
    impl SampleSink for CapturingSink {
        fn sample_rate(&self) -> f64 {
            30.72e6
        }
        fn write(&mut self, buf: &[Iq]) -> Result<usize> {
            self.samples.extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    /// `serve_push` places a waveform at its absolute uplink position across block
    /// boundaries, leaving the rest of the stream silent.
    #[test]
    fn serve_push_places_waveforms_at_absolute_positions() {
        let mut sink = CapturingSink::default();
        let mut counter = 0u64;
        let mut block = vec![Iq::default(); 100];
        // A 30-sample burst scheduled at absolute position 250 (spans blocks 2→3).
        let wave: Vec<Iq> = (0..30).map(|i| Iq::new(i as f32 + 1.0, -1.0)).collect();
        let pos = 250u64;
        for _ in 0..5 {
            serve_push(&mut sink, &mut counter, &mut block, |c, blk| {
                for (i, &s) in wave.iter().enumerate() {
                    let abs = pos + i as u64;
                    if abs >= c && abs < c + blk.len() as u64 {
                        blk[(abs - c) as usize] = s;
                    }
                }
            })
            .unwrap();
        }
        assert_eq!(counter, 500);
        assert_eq!(sink.samples.len(), 500);
        for (i, &s) in wave.iter().enumerate() {
            assert_eq!(sink.samples[250 + i], s, "burst sample {i} misplaced");
        }
        assert!(
            sink.samples[..250].iter().all(|s| *s == Iq::default()),
            "pre-burst not silent"
        );
        assert!(
            sink.samples[280..].iter().all(|s| *s == Iq::default()),
            "post-burst not silent"
        );
    }

    /// `serve_push` loops until the whole block is accepted when the sink writes partially.
    #[test]
    fn serve_push_handles_partial_writes() {
        struct PartialSink {
            written: usize,
            chunk: usize,
        }
        impl SampleSink for PartialSink {
            fn sample_rate(&self) -> f64 {
                1.0
            }
            fn write(&mut self, buf: &[Iq]) -> Result<usize> {
                let n = buf.len().min(self.chunk);
                self.written += n;
                Ok(n)
            }
        }
        let mut sink = PartialSink {
            written: 0,
            chunk: 7,
        };
        let mut counter = 0u64;
        let mut block = vec![Iq::default(); 20];
        let served = serve_push(&mut sink, &mut counter, &mut block, |_, _| {}).unwrap();
        assert_eq!(served, 20);
        assert_eq!(counter, 20);
        assert_eq!(sink.written, 20);
    }
}
