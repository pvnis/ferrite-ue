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

    /// Radio backend: `zmq` (gNB over ZeroMQ) or `sdr` (SoapySDR via seify).
    #[arg(long)]
    pub radio: Option<String>,
    /// gNB downlink ZMQ endpoint (the UE reads samples here).
    #[arg(long)]
    pub tx: Option<String>,
    /// gNB uplink ZMQ endpoint (the UE serves samples here).
    #[arg(long)]
    pub rx: Option<String>,
    /// SDR device arguments (seify), e.g. `driver=soapy,soapy_driver=bladerf`.
    #[arg(long)]
    pub sdr_args: Option<String>,
    #[arg(long)]
    pub sdr_rx_gain: Option<f64>,
    #[arg(long)]
    pub sdr_tx_gain: Option<f64>,

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
    /// UL slots of margin between MAC decisions and transmission.
    #[arg(long)]
    pub tx_lead: Option<u16>,
    /// Radio backend TX/RX timing calibration in samples: how much earlier
    /// than the nominal uplink timing the backend must be fed (positive =
    /// earlier). 0 for the ZMQ lockstep transport.
    #[arg(long, allow_hyphen_values = true)]
    pub tx_rx_offset: Option<i64>,
    /// PRACH-only timing calibration in samples (positive = earlier). The
    /// default delays the preamble by 1 µs: well inside every preamble CP, and
    /// it keeps the preamble out of the negative-delay region of detectors
    /// (OCUDU's window starts a few samples after the slot) over a zero-delay
    /// transport; over the air the propagation delay does the same.
    #[arg(long, allow_hyphen_values = true)]
    pub prach_offset: Option<i64>,
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
    pub tun: Option<String>,
    pub netns: Option<String>,
    pub timeout: Option<u64>,
    pub tx_lead: Option<u16>,
    pub tx_rx_offset: Option<i64>,
    pub prach_offset: Option<i64>,
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
    pub tun: Option<String>,
    pub netns: Option<String>,
    pub timeout_s: u64,
    pub exit_after_ping: bool,
    pub tx_lead: u16,
    pub tx_rx_offset: i64,
    pub prach_offset: i64,
    pub log: String,
}

#[derive(Debug, Clone)]
pub enum RadioConfig {
    Zmq { tx: String, rx: String },
    Sdr { args: String, rx_gain: f64, tx_gain: f64 },
}

fn hex16(s: &str, what: &str) -> Result<[u8; 16], String> {
    let v = ferrite_common::from_hex(s).ok_or_else(|| format!("{what}: bad hex"))?;
    v.try_into().map_err(|_| format!("{what}: expected 16 bytes"))
}

impl UeConfig {
    pub fn load() -> Result<Self, String> {
        let cli = Cli::parse();
        let file: FileConfig = match &cli.config {
            Some(p) => toml::from_str(&std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?).map_err(|e| format!("config: {e}"))?,
            None => FileConfig::default(),
        };
        macro_rules! pick {
            ($f:ident, $d:expr) => {
                cli.$f.clone().or(file.$f.clone()).unwrap_or($d)
            };
        }
        let radio_kind = pick!(radio, "zmq".to_string());
        let radio = match radio_kind.as_str() {
            "zmq" => RadioConfig::Zmq { tx: pick!(tx, "tcp://127.0.0.1:2100".into()), rx: pick!(rx, "tcp://127.0.0.1:2101".into()) },
            "sdr" => RadioConfig::Sdr {
                args: pick!(sdr_args, "driver=soapy".into()),
                rx_gain: pick!(sdr_rx_gain, 50.0),
                tx_gain: pick!(sdr_tx_gain, 50.0),
            },
            other => return Err(format!("unknown radio backend {other}")),
        };
        let fs = pick!(srate, 15.36) * 1e6;
        let (dl_center_hz, dl_arfcn) = match (cli.dl_arfcn.or(file.dl_arfcn), cli.center_mhz.or(file.center_mhz)) {
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
        let info = BandInfo::lookup(band).ok_or_else(|| format!("band n{band} not in the band table"))?;
        let ssb_scs_khz = pick!(ssb_scs, info.ssb_scs_khz[0]);
        let ul_center_hz = arfcn_to_hz(info.ul_arfcn_for_dl(dl_arfcn));
        let imsi = pick!(imsi, "001010167891203".into());
        let ki = hex16(&pick!(ki, "5122250214c33e723a5dd523fc145fc0".into()), "ki")?;
        let opc = hex16(&pick!(opc, "981d464c7c52eb6e5036234984ad0bcf".into()), "opc")?;
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
            tun: cli.tun.clone().or(file.tun.clone()),
            netns: cli.netns.clone().or(file.netns.clone()),
            timeout_s: pick!(timeout, 0),
            exit_after_ping: cli.exit_after_ping,
            tx_lead: pick!(tx_lead, 2),
            tx_rx_offset: pick!(tx_rx_offset, 0),
            prach_offset: pick!(prach_offset, -(fs * 1e-6).round() as i64),
            log: pick!(log, "info".into()),
        })
    }
}
