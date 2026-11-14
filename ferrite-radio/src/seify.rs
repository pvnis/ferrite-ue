//! SDR backend via [seify](https://github.com/FutureSDR/seify) over SoapySDR.
//!
//! One code path drives any full-duplex SoapySDR device — BladeRF 2.0 (via
//! SoapyBladeRF), USRP (via UHD), LiteX-M2SDR, … — because SoapySDR abstracts the
//! hardware. Phase 0/1 exposes the RX chain as a [`SampleSource`]; the TX push
//! (timestamped bursts) and the free-running RX/TX time base land in a later phase.
//!
//! Unlike the ZMQ backend — where the gNB clocks both directions in lockstep — a
//! real SDR free-runs at its sample rate, so the higher layers must own the timing
//! (cell search already does the acquisition; the TX side becomes a push, not a pull).

use crate::{SampleSink, SampleSource};
use ferrite_common::{Error, Iq, Result};
use seify::{
    AntennaControl, Args, BandwidthControl, Direction, DynDevice, FrequencyControl, GainControl,
    RxStreamer, SampleRateControl, TxStreamer,
};

fn radio_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Radio(e.to_string())
}

/// Front-end configuration applied to both chains when the device is opened.
#[derive(Clone, Debug)]
pub struct SeifyConfig {
    /// SoapySDR device-selection args, e.g. `"driver=bladerf"` or
    /// `"driver=uhd,addr=192.168.40.2"`. Empty ⇒ the first device seify finds.
    pub args: String,
    /// Sample rate (Hz). 30.72e6 = 20 MHz n78 at µ=1.
    pub sample_rate: f64,
    /// Centre frequency (Hz), shared by RX and TX (a UE is monostatic on the carrier).
    pub frequency: f64,
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

impl Default for SeifyConfig {
    fn default() -> Self {
        Self {
            args: String::new(),
            sample_rate: 30.72e6,
            frequency: 3.5e9,
            rx_gain: 40.0,
            tx_gain: 40.0,
            bandwidth: 0.0,
            rx_antenna: None,
            tx_antenna: None,
        }
    }
}

/// An opened SDR device with both chains configured. Hands out an RX
/// [`SeifyRx`] (a [`SampleSource`]); the TX path is added in a later phase.
pub struct SeifyRadio {
    device: DynDevice,
    sample_rate: f64,
}

impl SeifyRadio {
    /// Open the device selected by `cfg.args` and configure both chains.
    pub fn open(cfg: &SeifyConfig) -> Result<Self> {
        let device = if cfg.args.trim().is_empty() {
            let first = seify::enumerate()
                .map_err(radio_err)?
                .into_iter()
                .next()
                .ok_or_else(|| Error::Radio("no SDR devices found".into()))?;
            DynDevice::from_args(first)
        } else {
            DynDevice::from_args(cfg.args.as_str())
        }
        .map_err(radio_err)?;

        let bw = if cfg.bandwidth > 0.0 {
            cfg.bandwidth
        } else {
            cfg.sample_rate
        };
        for (dir, gain, ant) in [
            (Direction::Rx, cfg.rx_gain, cfg.rx_antenna.as_deref()),
            (Direction::Tx, cfg.tx_gain, cfg.tx_antenna.as_deref()),
        ] {
            device
                .set_sample_rate(dir, 0, cfg.sample_rate)
                .map_err(radio_err)?;
            device
                .set_frequency(dir, 0, cfg.frequency, Args::new())
                .map_err(radio_err)?;
            device.set_gain(dir, 0, gain).map_err(radio_err)?;
            device.set_bandwidth(dir, 0, bw).map_err(radio_err)?;
            if let Some(a) = ant {
                device.set_antenna(dir, 0, a).map_err(radio_err)?;
            }
        }
        Ok(Self {
            device,
            sample_rate: cfg.sample_rate,
        })
    }

    /// Configured sample rate (Hz).
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Borrow the underlying device (for antennas, gain ranges, sensors, …).
    pub fn device(&self) -> &DynDevice {
        &self.device
    }

    /// Activate and return the RX stream (channel 0) as a [`SampleSource`]. Feeds the
    /// same `BufferedStream` read-ahead the ZMQ DL path uses.
    pub fn rx(&self) -> Result<SeifyRx> {
        let mut streamer = self.device.rx_streamer(&[0]).map_err(radio_err)?;
        streamer.activate().map_err(radio_err)?;
        Ok(SeifyRx {
            streamer,
            sample_rate: self.sample_rate,
        })
    }

    /// Activate and return the TX stream (channel 0) as a [`SampleSink`]. Unlike the ZMQ
    /// sink (which the gNB *pulls* in lockstep), this is *pushed*: the device TX FIFO
    /// backpressures `write`, so a continuous fill→write loop paces itself to the sample
    /// clock. The free-running RX/TX time base and the fixed RX→TX offset are handled by
    /// the caller (the driver), not here.
    pub fn tx(&self) -> Result<SeifyTx> {
        let mut streamer = self.device.tx_streamer(&[0]).map_err(radio_err)?;
        streamer.activate().map_err(radio_err)?;
        Ok(SeifyTx {
            streamer,
            sample_rate: self.sample_rate,
        })
    }
}

/// RX half of an SDR device: a continuous baseband stream as a [`SampleSource`].
pub struct SeifyRx {
    streamer: seify::DynRxStreamer,
    sample_rate: f64,
}

impl SampleSource for SeifyRx {
    fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        // Single channel; 1 s timeout (a stall this long means the device is wedged).
        let mut chans = [buf];
        self.streamer.read(&mut chans, 1_000_000).map_err(radio_err)
    }
}

/// TX half of an SDR device: a continuous baseband stream exposed as a [`SampleSink`].
/// The device TX FIFO backpressures `write`, so the fill→write driver loop is self-pacing.
pub struct SeifyTx {
    streamer: seify::DynTxStreamer,
    sample_rate: f64,
}

impl SeifyTx {
    /// Write a burst at an absolute device timestamp (nanoseconds), marking the end of the
    /// burst. Used for timed uplink bursts (PRACH/PUSCH/PUCCH) once the RX→TX time base is
    /// calibrated; the continuous-stream path uses [`SampleSink::write`].
    pub fn write_at(&mut self, buf: &[Iq], at_ns: i64, end_burst: bool) -> Result<usize> {
        let chans = [buf];
        self.streamer
            .write(&chans, Some(at_ns), end_burst, 1_000_000)
            .map_err(radio_err)
    }
}

impl SampleSink for SeifyTx {
    fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    fn write(&mut self, buf: &[Iq]) -> Result<usize> {
        // Continuous stream: no explicit timestamp, not a burst end. FIFO backpressure paces.
        let chans = [buf];
        self.streamer
            .write(&chans, None, false, 1_000_000)
            .map_err(radio_err)
    }
}
