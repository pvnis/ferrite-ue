//! Radio hardware abstraction layer (HAL).
//!
//! Everything above the PHY consumes baseband IQ through [`SampleSource`] and
//! transmits through [`SampleSink`], independent of the underlying transport.
//! Backends live behind feature flags so the core builds without native libs:
//!
//! * [`file`] — read/write interleaved little-endian `f32` IQ (always available);
//! * `soapy` (feature) — SoapySDR devices (M2SDR, BladeRF);
//! * `zmq` (feature) — a gNB exposing baseband over ZeroMQ.

use ferrite_common::{Iq, Result};

pub mod file;
#[cfg(feature = "zmq")]
pub mod zmq;

/// A source of baseband IQ samples.
pub trait SampleSource {
    /// Nominal sample rate in samples/second.
    fn sample_rate(&self) -> f64;

    /// Fill `buf` with as many samples as available, returning the count
    /// written. A return of `0` indicates end-of-stream.
    fn read(&mut self, buf: &mut [Iq]) -> Result<usize>;

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
}
