//! UE configuration: command line (clap) with an optional TOML file. Only the
//! radio endpoint, the carrier and the subscriber are configuration; everything
//! about the cell is learned over the air.

use clap::Parser;
use ferrite_common::{arfcn_to_hz, BandInfo, DuplexMode};
use serde::Deserialize;

#[derive(Parser, Debug, Clone)]
#[command(name = "ferrite-ue", about = "Ferrite 5G NR UE", version)]
pub struct Cli {
    /// TOML configuration file (command-line flags override it).
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

    /// Radio backend: `zmq` (gNB over ZeroMQ) or `sdr` (SoapySDR).
    #[arg(long)]
    pub radio: Option<String>,
    /// gNB downlink ZMQ endpoint(s), one per receive antenna, comma
    /// separated (e.g. `tcp://127.0.0.1:2100,tcp://127.0.0.1:2102`).
    #[arg(long)]
    pub tx: Option<String>,
    /// gNB uplink ZMQ endpoint (the UE serves samples here).
    #[arg(long)]
    pub rx: Option<String>,
    /// SoapySDR device arguments, e.g. `driver=limesuiteng` or `driver=bladerf,serial=…`.
    #[arg(long)]
    pub sdr_args: Option<String>,
    /// SDR receive gain (dB, device scale).
    #[arg(long)]
    pub sdr_rx_gain: Option<f64>,
    /// SDR transmit gain (dB, device scale).
    #[arg(long)]
    pub sdr_tx_gain: Option<f64>,
    /// SDR receive antenna port name (device default when omitted).
    #[arg(long)]
    pub sdr_rx_antenna: Option<String>,
    /// SDR transmit antenna port name (device default when omitted).
    #[arg(long)]
    pub sdr_tx_antenna: Option<String>,
    /// SDR write-to-air latency budget (µs): an uplink block due sooner than
    /// this after the newest received sample is skipped instead of handed to
    /// the device late.
    #[arg(long)]
    pub sdr_tx_latency_us: Option<f64>,

    /// Sample rate in MHz (must match the gNB: 11.52, 15.36, 23.04, 30.72, …).
    #[arg(long)]
    pub srate: Option<f64>,
    /// Downlink NR-ARFCN of the carrier centre.
    #[arg(long)]
    pub dl_arfcn: Option<u32>,
    /// Alternatively the carrier centre in MHz.
    #[arg(long)]
    pub center_mhz: Option<f64>,
    /// NR band (derived from the ARFCN when omitted).
    #[arg(long)]
    pub band: Option<u16>,
    /// SSB subcarrier spacing in kHz (derived from the band when omitted).
    #[arg(long)]
    pub ssb_scs: Option<u32>,
    /// GSCN hint for the SSB (speeds up the scan).
    #[arg(long)]
    pub gscn: Option<u32>,

    #[arg(long)]
    pub imsi: Option<String>,
    #[arg(long)]
    pub ki: Option<String>,
    #[arg(long)]
    pub opc: Option<String>,
    #[arg(long)]
    pub dnn: Option<String>,

    /// Built-in ICMP probe: number of echoes (0 disables).
    #[arg(long)]
    pub ping: Option<u32>,
    #[arg(long)]
    pub ping_target: Option<String>,
    #[arg(long)]
    pub ping_interval_ms: Option<u64>,
    /// Repeat the ping probe this many times (rounds), pausing
    /// `--ping-round-gap-s` between rounds (long enough for the gNB's
    /// inactivity release, the next round goes through a service request).
    #[arg(long)]
    pub ping_rounds: Option<u32>,
    #[arg(long)]
    pub ping_round_gap_s: Option<u64>,
    /// Create this TUN interface and carry host IP traffic over the DRB.
    #[arg(long)]
    pub tun: Option<String>,
    #[arg(long)]
    pub netns: Option<String>,
    /// Exit after this many seconds (0 = run until stopped).
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Exit as soon as the ping probe completes.
    #[arg(long)]
    pub exit_after_ping: bool,
    /// The radio's LO is not derived from its sample clock: do not predict
    /// the sampling-rate drift from the measured CFO (the timing loop then
    /// learns it on its own, more slowly).
    #[arg(long)]
    pub independent_lo: bool,
    /// Test aid (ZMQ only): emulate a UE local-oscillator error of this many
    /// ppm, i.e. receive the downlink −ppm·f_DL and transmit the uplink
    /// +ppm·f_UL off frequency. Turns on the CFO correction the ZMQ transport
    /// normally skips; the sample clock is not impaired.
    #[arg(long, allow_hyphen_values = true)]
    pub emulate_lo_ppm: Option<f64>,
    /// UL slots of margin between MAC decisions and transmission.
    #[arg(long)]
    pub tx_lead: Option<u16>,
    /// Lockstep transports (ZMQ): keep the uplink the UE can serve at least
    /// this many slots ahead of the downlink it has received, zeros where
    /// nothing is scheduled, for a peer (a block-wise channel emulator) that
    /// pulls uplink block t before it delivers downlink block t. Raises
    /// `--tx-lead` to the decision horizon this needs, which must stay below
    /// the network's smallest K1/K2. 0 (default) = no requirement.
    #[arg(long)]
    pub ul_stream_lead_slots: Option<u16>,
    /// Radio backend TX/RX timing calibration in samples: how much earlier
    /// than the nominal uplink timing the backend must be fed (positive =
    /// earlier). 0 for the ZMQ lockstep transport.
    #[arg(long, allow_hyphen_values = true)]
    pub tx_rx_offset: Option<i64>,
    /// Uplink timing guard in samples (positive = earlier, negative = later),
    /// applied to every uplink transmission including the PRACH. The default
    /// delays the uplink by 1 µs: it keeps the preamble out of the
    /// negative-delay region of detectors (OCUDU's window starts a few samples
    /// after the slot) over a zero-delay transport, and the timing-advance
    /// command the network answers with removes the same guard from the
    /// PUSCH/PUCCH timing. Over the air the propagation delay does the same.
    #[arg(long, allow_hyphen_values = true)]
    pub prach_offset: Option<i64>,
    /// Receiver power calibration: the dBm of a full-scale (0 dBFS) signal
    /// at 0 dB receive gain, so that SS-RSRP in dBm = dBFS − gain + this.
    /// 0 over ZMQ (no gain); a device constant over the air.
    #[arg(long, allow_hyphen_values = true)]
    pub rx_power_offset_db: Option<f32>,
    /// Transmitter power calibration: the dBm a full-scale (0 dBFS) continuous
    /// signal produces at the configured transmit gain. Enables uplink power
    /// control (TS 38.213 §7): every uplink waveform is scaled to its target
    /// power in dBm. Unset ⇒ waveforms are peak-normalised (the ZMQ case).
    #[arg(long, allow_hyphen_values = true)]
    pub tx_power_offset_db: Option<f32>,
    /// Test aid: inject a radio link failure this many seconds after start
    /// (while connected) to exercise RRC re-establishment. 0 = never.
    #[arg(long)]
    pub rlf_at_s: Option<u64>,
    /// Test aid: from this many seconds after start, the PHY's radio link
    /// monitoring reports out-of-sync for `--rlm-outage-ms` (exercises N310 /
    /// T310 / N311 with the cell's values). Unset = never.
    #[arg(long)]
    pub rlm_outage_s: Option<u64>,
    /// Length of the radio link monitoring outage (ms, default 1500).
    #[arg(long)]
    pub rlm_outage_ms: Option<u64>,
    /// Test aid: run the NAS periodic registration timer T3512 with this
    /// length (seconds) instead of the network's value, so a periodic
    /// registration update happens within a lab run.
    #[arg(long)]
    pub t3512_s: Option<u64>,
    /// Log level (error/warn/info/debug/trace).
    #[arg(long)]
    pub log: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct FileConfig {
    pub radio: Option<String>,
    pub tx: Option<String>,
    pub rx: Option<String>,
    pub sdr_args: Option<String>,
    pub sdr_rx_gain: Option<f64>,
    pub sdr_tx_gain: Option<f64>,
    pub sdr_rx_antenna: Option<String>,
    pub sdr_tx_antenna: Option<String>,
    pub sdr_tx_latency_us: Option<f64>,
    pub srate: Option<f64>,
    pub dl_arfcn: Option<u32>,
    pub center_mhz: Option<f64>,
    pub band: Option<u16>,
    pub ssb_scs: Option<u32>,
    pub gscn: Option<u32>,
    pub imsi: Option<String>,
    pub ki: Option<String>,
    pub opc: Option<String>,
    pub dnn: Option<String>,
    pub ping: Option<u32>,
    pub ping_target: Option<String>,
    pub ping_interval_ms: Option<u64>,
    pub ping_rounds: Option<u32>,
    pub ping_round_gap_s: Option<u64>,
    pub tun: Option<String>,
    pub netns: Option<String>,
    pub timeout: Option<u64>,
    pub tx_lead: Option<u16>,
    pub ul_stream_lead_slots: Option<u16>,
    pub tx_rx_offset: Option<i64>,
    pub prach_offset: Option<i64>,
    pub rx_power_offset_db: Option<f32>,
    pub tx_power_offset_db: Option<f32>,
    pub rlf_at_s: Option<u64>,
    pub rlm_outage_s: Option<u64>,
    pub rlm_outage_ms: Option<u64>,
    pub t3512_s: Option<u64>,
    pub log: Option<String>,
}

/// The resolved configuration.
#[derive(Debug, Clone)]
pub struct UeConfig {
    pub radio: RadioConfig,
    pub fs: f64,
    pub dl_center_hz: f64,
    pub ul_center_hz: f64,
    pub band: u16,
    pub duplex: DuplexMode,
    pub ssb_scs_khz: u32,
    pub gscn_hint: Option<u32>,
    pub imsi: String,
    pub ki: [u8; 16],
    pub opc: [u8; 16],
    pub dnn: String,
    pub ping_count: u32,
    pub ping_target: [u8; 4],
    pub ping_interval_ms: u64,
    pub ping_rounds: u32,
    pub ping_round_gap_s: u64,
    pub tun: Option<String>,
    pub netns: Option<String>,
    pub timeout_s: u64,
    pub exit_after_ping: bool,
    /// LO not locked to the sample clock (no CFO → drift feed-forward).
    pub independent_lo: bool,
    /// Test aid: emulated LO error (ppm) on the ZMQ transport.
    pub emulate_lo_ppm: Option<f64>,
    pub tx_lead: u16,
    /// Required uplink stream lead over the received downlink (slots).
    pub ul_stream_lead_slots: u16,
    pub tx_rx_offset: i64,
    pub prach_offset: i64,
    pub rx_power_offset_db: f32,
    /// `Some(dBm of full scale)` enables uplink power control.
    pub tx_full_scale_dbm: Option<f32>,
    pub rlf_at_s: u64,
    /// Test aid: `(start_s, duration_ms)` radio link monitoring outage.
    pub rlm_outage: Option<(u64, u64)>,
    /// Test aid: T3512 override (seconds).
    pub t3512_s: Option<u64>,
    pub log: String,
}

#[derive(Debug, Clone)]
pub enum RadioConfig {
    /// One downlink endpoint per receive antenna; one uplink endpoint.
    Zmq { tx: Vec<String>, rx: String },
    /// A SoapySDR device: both chains on channel 0.
    Sdr {
        args: String,
        rx_gain: f64,
        tx_gain: f64,
        rx_antenna: Option<String>,
        tx_antenna: Option<String>,
        /// Write-to-air latency budget in seconds.
        tx_latency_s: f64,
    },
}

fn hex16(s: &str, what: &str) -> Result<[u8; 16], String> {
    let v = ferrite_common::from_hex(s).ok_or_else(|| format!("{what}: bad hex"))?;
    v.try_into()
        .map_err(|_| format!("{what}: expected 16 bytes"))
}

impl UeConfig {
    pub fn load() -> Result<Self, String> {
        let cli = Cli::parse();
        let file: FileConfig = match &cli.config {
            Some(p) => toml::from_str(
                &std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
            )
            .map_err(|e| format!("config: {e}"))?,
            None => FileConfig::default(),
        };
        macro_rules! pick {
            ($f:ident, $d:expr) => {
                cli.$f.clone().or(file.$f.clone()).unwrap_or($d)
            };
        }
        let radio_kind = pick!(radio, "zmq".to_string());
        let radio = match radio_kind.as_str() {
            "zmq" => RadioConfig::Zmq {
                tx: pick!(tx, "tcp://127.0.0.1:2100".into())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                rx: pick!(rx, "tcp://127.0.0.1:2101".into()),
            },
            "sdr" => RadioConfig::Sdr {
                args: pick!(sdr_args, String::new()),
                rx_gain: pick!(sdr_rx_gain, 50.0),
                tx_gain: pick!(sdr_tx_gain, 50.0),
                rx_antenna: cli.sdr_rx_antenna.clone().or(file.sdr_rx_antenna.clone()),
                tx_antenna: cli.sdr_tx_antenna.clone().or(file.sdr_tx_antenna.clone()),
                tx_latency_s: pick!(sdr_tx_latency_us, 300.0) * 1e-6,
            },
            other => return Err(format!("unknown radio backend {other}")),
        };
        let fs = pick!(srate, 15.36) * 1e6;
        let (dl_center_hz, dl_arfcn) = match (
            cli.dl_arfcn.or(file.dl_arfcn),
            cli.center_mhz.or(file.center_mhz),
        ) {
            (Some(a), _) => (arfcn_to_hz(a), a),
            (None, Some(m)) => (m * 1e6, ferrite_common::hz_to_arfcn(m * 1e6)),
            (None, None) => (arfcn_to_hz(626000), 626000),
        };
        let band = match cli.band.or(file.band) {
            Some(b) => b,
            None => ferrite_common::band::BANDS
                .iter()
                .find(|b| (b.dl_arfcn.0..=b.dl_arfcn.1).contains(&dl_arfcn))
                .map(|b| b.band)
                .ok_or_else(|| format!("no known band for ARFCN {dl_arfcn}; pass --band"))?,
        };
        let info =
            BandInfo::lookup(band).ok_or_else(|| format!("band n{band} not in the band table"))?;
        let ssb_scs_khz = pick!(ssb_scs, info.ssb_scs_khz[0]);
        let ul_center_hz = arfcn_to_hz(info.ul_arfcn_for_dl(dl_arfcn));
        let imsi = pick!(imsi, "001010167891203".into());
        // TS 23.003 §2.2: at most 15 digits (MCC 3 + MNC 2-3 + MSIN).
        if !(6..=15).contains(&imsi.len()) || !imsi.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("IMSI {imsi:?}: expected 6 to 15 decimal digits"));
        }
        let ki = hex16(&pick!(ki, "5122250214c33e723a5dd523fc145fc0".into()), "ki")?;
        let opc = hex16(
            &pick!(opc, "981d464c7c52eb6e5036234984ad0bcf".into()),
            "opc",
        )?;
        let target = pick!(ping_target, "10.255.0.1".into());
        let mut ping_target = [0u8; 4];
        for (i, p) in target.split('.').take(4).enumerate() {
            ping_target[i] = p.parse().map_err(|_| "bad ping target")?;
        }
        Ok(Self {
            radio,
            fs,
            dl_center_hz,
            ul_center_hz,
            band,
            duplex: info.duplex,
            ssb_scs_khz,
            gscn_hint: cli.gscn.or(file.gscn),
            imsi,
            ki,
            opc,
            dnn: pick!(dnn, "internet".into()),
            ping_count: pick!(ping, 20),
            ping_target,
            ping_interval_ms: pick!(ping_interval_ms, 1000),
            ping_rounds: pick!(ping_rounds, 1).max(1),
            ping_round_gap_s: pick!(ping_round_gap_s, 0),
            tun: cli.tun.clone().or(file.tun.clone()),
            netns: cli.netns.clone().or(file.netns.clone()),
            timeout_s: pick!(timeout, 0),
            exit_after_ping: cli.exit_after_ping,
            independent_lo: cli.independent_lo,
            emulate_lo_ppm: cli.emulate_lo_ppm,
            tx_lead: pick!(tx_lead, 2),
            ul_stream_lead_slots: pick!(ul_stream_lead_slots, 0),
            tx_rx_offset: pick!(tx_rx_offset, 0),
            prach_offset: pick!(prach_offset, -(fs * 1e-6).round() as i64),
            rx_power_offset_db: pick!(rx_power_offset_db, 0.0),
            tx_full_scale_dbm: cli.tx_power_offset_db.or(file.tx_power_offset_db),
            rlf_at_s: pick!(rlf_at_s, 0),
            rlm_outage: cli
                .rlm_outage_s
                .or(file.rlm_outage_s)
                .map(|s| (s, pick!(rlm_outage_ms, 1500))),
            t3512_s: cli.t3512_s.or(file.t3512_s),
            log: pick!(log, "info".into()),
        })
    }
}
