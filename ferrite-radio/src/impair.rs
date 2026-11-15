//! Test aids that impair an ideal transport the way a real radio would, so
//! the receiver's tracking loops can be exercised without hardware.
//!
//! [`FrequencyOffset`] mixes a fixed frequency onto every sample a source
//! delivers, phase-continuous over the stream: over the ZMQ transport it
//! stands in for a local-oscillator error (a UE LO high by ε·f receives the
//! downlink ε·f low). [`mix`] is the same operation on one buffer, for the
//! transmit side.

use crate::SampleSource;
use ferrite_common::{Iq, Result};
use std::f64::consts::TAU;

/// Multiply `buf` by e^{j·2π·shift·n/fs}, `n` counting from `start`.
pub fn mix(buf: &mut [Iq], shift_hz: f64, fs: f64, start: u64) {
    if shift_hz == 0.0 {
        return;
    }
    let dph = (TAU * shift_hz / fs).rem_euclid(TAU);
    // Start phase at full precision; the running phasor's drift over one
    // buffer is negligible.
    let ph0 = (dph * start as f64).rem_euclid(TAU);
    let (mut re, mut im) = (ph0.cos(), ph0.sin());
    let (sr, si) = (dph.cos(), dph.sin());
    for s in buf.iter_mut() {
        *s *= Iq::new(re as f32, im as f32);
        let nr = re * sr - im * si;
        im = re * si + im * sr;
        re = nr;
    }
}

/// A source whose samples are shifted by a fixed frequency.
pub struct FrequencyOffset<S> {
    inner: S,
    shift_hz: f64,
    /// Samples delivered so far (the mixing phase reference).
    n: u64,
}

impl<S: SampleSource> FrequencyOffset<S> {
    pub fn new(inner: S, shift_hz: f64) -> Self {
        Self {
            inner,
            shift_hz,
            n: 0,
        }
    }
}

impl<S: SampleSource> SampleSource for FrequencyOffset<S> {
    fn sample_rate(&self) -> f64 {
        self.inner.sample_rate()
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        let got = self.inner.read(buf)?;
        mix(
            &mut buf[..got],
            self.shift_hz,
            self.inner.sample_rate(),
            self.n,
        );
        self.n += got as u64;
        Ok(got)
    }

    fn timestamp(&self) -> Option<u64> {
        self.inner.timestamp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ones(f64);
    impl SampleSource for Ones {
        fn sample_rate(&self) -> f64 {
            self.0
        }
        fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
            buf.fill(Iq::new(1.0, 0.0));
            Ok(buf.len())
        }
    }

    /// The phase advances by 2π·f/fs per sample, continuously across reads.
    #[test]
    fn mixes_phase_continuously() {
        let fs = 1000.0;
        let mut src = FrequencyOffset::new(Ones(fs), 125.0);
        let mut a = vec![Iq::default(); 3];
        let mut b = vec![Iq::default(); 5];
        assert_eq!(src.read(&mut a).unwrap(), 3);
        assert_eq!(src.read(&mut b).unwrap(), 5);
        for (n, s) in a.iter().chain(&b).enumerate() {
            let want = TAU * 125.0 * n as f64 / fs;
            let got = f64::from(s.im).atan2(f64::from(s.re));
            let d = (got - want + std::f64::consts::PI).rem_euclid(TAU) - std::f64::consts::PI;
            assert!(d.abs() < 1e-5, "sample {n}: phase {got} want {want}");
        }
    }
}
