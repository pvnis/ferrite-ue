//! SDR backend on [SoapySDR](https://github.com/pothosware/SoapySDR) through the
//! `soapysdr` crate.
//!
//! One code path drives any full-duplex SoapySDR device — LimeSDR (LimeSuiteNG),
//! BladeRF, USRP (UHD), LiteX-M2SDR, … — because SoapySDR abstracts the hardware.
//! The RX chain is a [`SampleSource`] that reports the device sample index of every
//! buffer; the TX chain is a [`SampleSink`] with both the continuous push (the device
//! FIFO paces the writer) and timed bursts by sample index.
//!
//! SoapySDR expresses device time in nanoseconds while every device counts samples,
//! so this module converts at the edge, once per buffer, with the *same* algorithm
//! SoapySDR itself uses (`ticksToTimeNs` / `timeNsToTicks`). With one rate on both
//! sides the round trip is the identity for any sample rate below 1 GS/s — the
//! half-nanosecond rounding is far below one sample. Using a different rate on the
//! two sides drifts with absolute time (1e-8 relative is 550 samples after an hour),
//! and modules differ in which rate they convert with: the LimeSuiteNG module uses
//! the *requested* rate while `getSampleRate` returns the actual one (15 359 999 Hz
//! for a 15.36 MHz request on an XTRX). So [`SoapyRadio::open`] measures the
//! module's conversion rate from the stream itself — the timestamp advance over a
//! known number of delivered samples — snaps it to the requested or reported rate
//! when one is within 0.5 Hz, and uses that [`SoapyRadio::time_rate`] for every
//! conversion.
//!
//! Unlike the ZMQ backend — where the gNB clocks both directions in lockstep — a
//! real SDR free-runs at its sample rate, so the higher layers own the timing (cell
//! search does the acquisition; the TX side is a push, not a pull).

use crate::{SampleSink, SampleSource};
use ferrite_common::{Error, Iq, Result};
use soapysdr::{Device, Direction, ErrorCode, RxStream, TxStream};
use std::sync::{Arc, Mutex};

fn radio_err(e: soapysdr::Error) -> Error {
    Error::Radio(format!("{:?}: {}", e.code, e.message))
}

/// Sample index → SoapySDR nanoseconds, bit for bit the library's `ticksToTimeNs`.
pub fn ticks_to_ns(ticks: u64, rate: f64) -> i64 {
    let ratels = (rate as i64).max(1);
    let ticks = ticks as i64;
    let full = ticks / ratels;
    let err = ticks - full * ratels;
    let part = full as f64 * (rate - ratels as f64);
    let frac = ((err as f64 - part) * 1e9) / rate;
    full * 1_000_000_000 + frac.round() as i64
}

/// SoapySDR nanoseconds → sample index, bit for bit the library's `timeNsToTicks`.
pub fn ns_to_ticks(time_ns: i64, rate: f64) -> u64 {
    let ratels = (rate as i64).max(1);
    let full = time_ns / 1_000_000_000;
    let err = time_ns - full * 1_000_000_000;
    let part = full as f64 * (rate - ratels as f64);
    let frac = part + (err as f64 * rate) / 1e9;
    (full * ratels + frac.round() as i64).max(0) as u64
}

/// Whether sample-index → ns → sample-index is the identity at `rate` over the
/// indices a UE run can reach (a few days at 30.72 MS/s), probing every scale.
pub fn time_conversion_is_exact(rate: f64) -> bool {
    let probes = (0..60u32)
        .flat_map(|b| {
            let base = 1u64 << b;
            [base - 1, base, base + 1, base + 7919]
        })
        .chain((0..50_000u64).map(|k| k * 104_729 + 3));
    probes
        .filter(|&t| t < 1u64 << 52)
        .all(|t| ns_to_ticks(ticks_to_ns(t, rate), rate) == t)
}

/// Front-end configuration applied to both chains when the device is opened.
#[derive(Clone, Debug)]
pub struct SoapyConfig {
    /// SoapySDR device-selection args, e.g. `"driver=limesuiteng"`,
    /// `"driver=bladerf,serial=…"` or `"driver=uhd,addr=192.168.40.2"`. Empty ⇒ the
    /// first device SoapySDR enumerates.
    pub args: String,
    /// Sample rate (Hz). 30.72e6 = 20 MHz n78 at µ=1.
    pub sample_rate: f64,
    /// RX centre frequency (Hz): the downlink carrier.
    pub rx_frequency: f64,
    /// TX centre frequency (Hz): the uplink carrier (equal to `rx_frequency` for TDD).
    pub tx_frequency: f64,
    /// RX front-end gain (dB).
    pub rx_gain: f64,
    /// TX front-end gain (dB).
    pub tx_gain: f64,
    /// Analog filter bandwidth (Hz); 0 ⇒ track the sample rate.
    pub bandwidth: f64,
    /// RX antenna port name (device-specific); `None` ⇒ device default.
    pub rx_antenna: Option<String>,
    /// TX antenna port name (device-specific); `None` ⇒ device default.
    pub tx_antenna: Option<String>,
}

impl Default for SoapyConfig {
    fn default() -> Self {
        Self {
            args: String::new(),
            sample_rate: 30.72e6,
            rx_frequency: 3.5e9,
            tx_frequency: 3.5e9,
            rx_gain: 40.0,
            tx_gain: 40.0,
            bandwidth: 0.0,
            rx_antenna: None,
            tx_antenna: None,
        }
    }
}

/// Where the time-conversion rate of an opened device came from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimeRateSource {
    /// The stream timestamps advance at the requested sample rate.
    Requested,
    /// The stream timestamps advance at the rate the device reports.
    Reported,
    /// Neither: the rate measured from the stream is used as is.
    Measured,
}

/// An opened SDR device with both chains configured. Hands out the RX
/// [`SoapyRx`] (a [`SampleSource`]) and the TX [`SoapyTx`] (a [`SampleSink`]).
pub struct SoapyRadio {
    device: Device,
    /// Sample rate the device reports after configuration.
    rate: f64,
    /// The rate the SoapySDR module converts timestamps with — the one value
    /// every conversion in this backend uses.
    time_rate: f64,
    time_rate_source: TimeRateSource,
}

/// Measure the rate at which a module's stream timestamps advance: deliver
/// samples for at least `min_s` seconds, take `samples × 1e9 / Δns` between the
/// first and the last buffer, and restart after an overflow (a gap would bias it).
fn measure_time_rate(stream: &mut RxStream<Iq>, min_s: f64, nominal: f64) -> Result<f64> {
    let mut buf = vec![Iq::default(); 16_384];
    let min_samples = (nominal * min_s) as u64;
    let (mut first_ns, mut count, mut last_ns, mut last_n) = (None::<i64>, 0u64, 0i64, 0u64);
    let mut attempts = 0u32;
    while count < min_samples || first_ns.is_none() {
        let mut chans = [&mut *buf];
        match stream.read(&mut chans, 1_000_000) {
            Ok(0) => return Err(Error::Radio("RX stream ended during calibration".into())),
            Ok(n) => {
                let ns = stream.time_ns();
                if first_ns.is_none() {
                    first_ns = Some(ns);
                    count = 0;
                } else {
                    count += last_n;
                }
                last_ns = ns;
                last_n = n as u64;
            }
            Err(e) if e.code == ErrorCode::Overflow || e.code == ErrorCode::Timeout => {
                attempts += 1;
                if attempts > 50 {
                    return Err(Error::Radio(format!(
                        "RX stream unusable during calibration: {:?}",
                        e.code
                    )));
                }
                first_ns = None;
            }
            Err(e) => return Err(radio_err(e)),
        }
    }
    let delta_ns = last_ns - first_ns.unwrap_or(last_ns);
    if delta_ns <= 0 || count == 0 {
        return Err(Error::Radio(
            "stream timestamps do not advance; no device time base".into(),
        ));
    }
    Ok(count as f64 * 1e9 / delta_ns as f64)
}

/// Snap a measured conversion rate to a candidate within 0.5 Hz, else keep it.
fn snap_time_rate(measured: f64, requested: f64, reported: f64) -> (f64, TimeRateSource) {
    if (measured - requested).abs() <= 0.5 {
        (requested, TimeRateSource::Requested)
    } else if (measured - reported).abs() <= 0.5 {
        (reported, TimeRateSource::Reported)
    } else {
        (measured, TimeRateSource::Measured)
    }
}

impl SoapyRadio {
    /// Enumerate the devices SoapySDR can see (device argument sets).
    pub fn enumerate() -> Result<Vec<String>> {
        Ok(soapysdr::enumerate(())
            .map_err(radio_err)?
            .iter()
            .map(|a| a.to_string())
            .collect())
    }

    /// Open the device selected by `cfg.args` and configure both chains.
    pub fn open(cfg: &SoapyConfig) -> Result<Self> {
        let device = if cfg.args.trim().is_empty() {
            let first = soapysdr::enumerate(())
                .map_err(radio_err)?
                .into_iter()
                .next()
                .ok_or_else(|| Error::Radio("no SDR devices found".into()))?;
            Device::new(first)
        } else {
            Device::new(cfg.args.as_str())
        }
        .map_err(radio_err)?;

        let bw = if cfg.bandwidth > 0.0 {
            cfg.bandwidth
        } else {
            cfg.sample_rate
        };
        for (dir, freq, gain, ant) in [
            (
                Direction::Rx,
                cfg.rx_frequency,
                cfg.rx_gain,
                cfg.rx_antenna.as_deref(),
            ),
            (
                Direction::Tx,
                cfg.tx_frequency,
                cfg.tx_gain,
                cfg.tx_antenna.as_deref(),
            ),
        ] {
            device
                .set_sample_rate(dir, 0, cfg.sample_rate)
                .map_err(radio_err)?;
            device.set_frequency(dir, 0, freq, ()).map_err(radio_err)?;
            device.set_gain(dir, 0, gain).map_err(radio_err)?;
            device.set_bandwidth(dir, 0, bw).map_err(radio_err)?;
            if let Some(a) = ant {
                device.set_antenna(dir, 0, a).map_err(radio_err)?;
            }
        }
        let rate = device.sample_rate(Direction::Rx, 0).map_err(radio_err)?;
        if rate.is_nan() || rate <= 0.0 {
            return Err(Error::Radio(format!("device reports sample rate {rate}")));
        }
        let tx_rate = device.sample_rate(Direction::Tx, 0).map_err(radio_err)?;
        if (tx_rate - rate).abs() > 0.5 {
            return Err(Error::Radio(format!(
                "RX and TX sample rates differ ({rate} vs {tx_rate} Hz); one time base needs one rate"
            )));
        }
        // Which rate does this module convert timestamps with? Measure it.
        let mut probe = device.rx_stream::<Iq>(&[0]).map_err(radio_err)?;
        probe.activate(None).map_err(radio_err)?;
        let measured = measure_time_rate(&mut probe, 0.25, rate);
        probe.deactivate(None).map_err(radio_err)?;
        drop(probe);
        let (time_rate, time_rate_source) = snap_time_rate(measured?, cfg.sample_rate, rate);
        if !time_conversion_is_exact(time_rate) {
            return Err(Error::Radio(format!(
                "sample ↔ ns conversion is not exact at {time_rate} Hz"
            )));
        }
        Ok(Self {
            device,
            rate,
            time_rate,
            time_rate_source,
        })
    }

    /// Sample rate the device reports (Hz).
    pub fn sample_rate(&self) -> f64 {
        self.rate
    }

    /// The rate the module's timestamps advance at, used for every sample ↔ ns
    /// conversion, and where it came from.
    pub fn time_rate(&self) -> (f64, TimeRateSource) {
        (self.time_rate, self.time_rate_source)
    }

    /// Borrow the underlying device (for antennas, gain ranges, sensors, …).
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// The device's hardware time now, in samples (the time base of
    /// [`SampleSource::timestamp`] / [`SampleSink::write_at`]).
    pub fn hardware_time(&self) -> Result<u64> {
        let ns = self.device.get_hardware_time(None).map_err(radio_err)?;
        Ok(ns_to_ticks(ns, self.time_rate))
    }

    /// Set up and activate both chains (channel 0) and return them as a
    /// [`SampleSource`] / [`SampleSink`] pair sharing one device session.
    ///
    /// Both streams are set up before either is activated: some modules (the
    /// LimeSuiteNG one) keep a single stream object for both directions, and
    /// setting up the second direction after the first is running restarts it.
    /// The pair is also torn down together, in an order every module survives
    /// (see [`Session`]).
    pub fn streams(&self) -> Result<(SoapyRx, SoapyTx)> {
        let mut rx = self.device.rx_stream::<Iq>(&[0]).map_err(radio_err)?;
        let mut tx = self.device.tx_stream::<Iq>(&[0]).map_err(radio_err)?;
        rx.activate(None).map_err(radio_err)?;
        tx.activate(None).map_err(radio_err)?;
        let session = Arc::new(Session {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
        });
        Ok((
            SoapyRx {
                session: session.clone(),
                rate: self.rate,
                time_rate: self.time_rate,
                timestamp: None,
                overflows: 0,
            },
            SoapyTx {
                session,
                rate: self.rate,
                time_rate: self.time_rate,
            },
        ))
    }
}

/// The two streams of one device, dropped together: the TX side is deactivated
/// first while the RX stream still exists, then the RX stream (deactivate, close),
/// then the TX stream (close only). Modules with one shared stream object free it
/// on the first close and would dereference it again if the other direction were
/// still active.
struct Session {
    rx: Mutex<RxStream<Iq>>,
    tx: Mutex<TxStream<Iq>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(tx) = self.tx.get_mut() {
            let _ = tx.deactivate(None);
        }
        // Fields drop in declaration order: `rx` before `tx`.
    }
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> Error {
    Error::Radio("stream lock poisoned".into())
}

/// RX half of an SDR device: a continuous baseband stream as a [`SampleSource`].
pub struct SoapyRx {
    session: Arc<Session>,
    rate: f64,
    time_rate: f64,
    timestamp: Option<u64>,
    overflows: u64,
}

impl SoapyRx {
    /// Number of overflows the driver reported (samples were lost in the device;
    /// the [`timestamp`](SampleSource::timestamp) of the next buffer shows how many).
    pub fn overflows(&self) -> u64 {
        self.overflows
    }
}

impl SampleSource for SoapyRx {
    fn sample_rate(&self) -> f64 {
        self.rate
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        // Single channel; 1 s timeout per attempt (a stall this long means the device
        // is wedged). Overflows are counted and the read retried: the stream goes on
        // and the next buffer's timestamp tells the consumer what was lost.
        let mut stream = self.session.rx.lock().map_err(lock_err)?;
        let mut timeouts = 0u32;
        loop {
            let mut chans = [&mut *buf];
            match stream.read(&mut chans, 1_000_000) {
                Ok(n) => {
                    self.timestamp = Some(ns_to_ticks(stream.time_ns(), self.time_rate));
                    return Ok(n);
                }
                Err(e) if e.code == ErrorCode::Overflow => self.overflows += 1,
                Err(e) if e.code == ErrorCode::Timeout && timeouts < 5 => timeouts += 1,
                Err(e) => return Err(radio_err(e)),
            }
        }
    }

    fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
}

/// TX half of an SDR device: a continuous baseband stream exposed as a [`SampleSink`].
pub struct SoapyTx {
    session: Arc<Session>,
    rate: f64,
    time_rate: f64,
}

impl SampleSink for SoapyTx {
    fn sample_rate(&self) -> f64 {
        self.rate
    }

    fn write(&mut self, buf: &[Iq]) -> Result<usize> {
        // Continuous stream: no timestamp, not a burst end. FIFO back-pressure paces.
        let mut stream = self.session.tx.lock().map_err(lock_err)?;
        stream
            .write(&[buf], None, false, 1_000_000)
            .map_err(radio_err)
    }

    fn write_at(&mut self, buf: &[Iq], at_sample: u64, end_burst: bool) -> Result<usize> {
        let at_ns = ticks_to_ns(at_sample, self.time_rate);
        let mut stream = self.session.tx.lock().map_err(lock_err)?;
        stream
            .write(&[buf], Some(at_ns), end_burst, 1_000_000)
            .map_err(radio_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NR sample rates (integer and not) convert sample → ns → sample without
    /// loss, and the ns value is the true time to within one nanosecond.
    #[test]
    fn sample_time_round_trip_is_exact() {
        for rate in [
            7.68e6,
            11.52e6,
            15.36e6,
            23.04e6,
            30.72e6,
            46.08e6,
            61.44e6,
            15_359_999.7,
            30_720_000.4,
            122.88e6,
        ] {
            assert!(time_conversion_is_exact(rate), "rate {rate}");
            for t in [
                0u64,
                1,
                15_360,
                1 << 31,
                3_600 * 30_720_000,
                (1u64 << 45) + 12_345,
            ] {
                let ns = ticks_to_ns(t, rate);
                let truth = t as f64 / rate * 1e9;
                assert!(
                    (ns as f64 - truth).abs() <= 1.0,
                    "rate {rate} t {t}: {ns} vs {truth}"
                );
            }
        }
    }

    /// A one-hour-old index converted with a slightly different rate lands hundreds
    /// of samples off: the reason the backend measures the module's conversion rate.
    #[test]
    fn rate_mismatch_drifts_with_absolute_time() {
        let t = 3_600 * 15_360_000u64;
        let ns = ticks_to_ns(t, 15.36e6);
        let back = ns_to_ticks(ns, 15.36e6 * (1.0 - 1e-8));
        assert!((back as i64 - t as i64).abs() > 100);
    }

    /// The XTRX case: requested 15.36 MHz, reported 15 359 999 Hz, timestamps at
    /// the requested rate; and the two other outcomes.
    #[test]
    fn measured_time_rate_snaps_to_a_candidate() {
        assert_eq!(
            snap_time_rate(15_360_000.03, 15.36e6, 15_359_999.0),
            (15.36e6, TimeRateSource::Requested)
        );
        assert_eq!(
            snap_time_rate(15_359_998.9, 15.36e6, 15_359_999.0),
            (15_359_999.0, TimeRateSource::Reported)
        );
        assert_eq!(
            snap_time_rate(15_359_990.0, 15.36e6, 15_359_999.0),
            (15_359_990.0, TimeRateSource::Measured)
        );
    }
}
