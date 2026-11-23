//! Sensing tap of a connected UE (nextghq/morty#25): the received REs of
//! every TRS symbol, per receive antenna, as ISAC tap records for
//! `isac-sensor` (nextghq/morty), published on a ZMQ `PUB` socket and/or
//! appended to a recording.
//!
//! The TRS is the single-port, density-3 NZP-CSI-RS of a resource set with
//! `trs-Info` (TS 38.214 §5.1.6.1.1; TS 38.211 §7.4.1.5.3 row 1): three REs per
//! RB, every fourth subcarrier, on one symbol per resource. A record holds one
//! such symbol: `nof_ant × 3·n_rb` complex values in frequency order, antenna
//! after antenna, taken from the demodulated grid after the TS 38.211 §5.4
//! phase compensation. `isac-sensor` regenerates the CSI-RS from the header
//! (TS 38.211 §7.4.1.5.2) counting from CRB 0, so a TRS must start at CRB 0;
//! one that does not is skipped.
//!
//! The record format is the tap record of `sensing_records::tap` in
//! nextghq/morty, version 4 (a receiving UE's): version 3's 56-byte header and
//! a 72-byte UE block, 128 bytes in all, little-endian (layout in morty's
//! `docs/isac_sensor.md`, "Tap records, version 4"). The UE block carries the
//! corrections the UE applied to the slot's samples: the integer timing steps
//! of its anchor and the CFO removed before the FFT (TS 38.133 §7.1.2 keeps the
//! UE's timing on the downlink), and its position when configured.

use crate::dl::WorkerConfig;
use ferrite_common::{Error, Iq, Result, SlotPoint};
use ferrite_phy::csi::CsiRsRow;
use std::io::Write;
use std::path::PathBuf;

/// Record magic.
const MAGIC: [u8; 4] = *b"ISAC";
/// Record format version of a receiving UE.
const VERSION: u16 = 4;
/// Header length of version 4.
const HEADER_LEN: usize = 128;
/// Sequence type of the CSI-RS in the record's `sequence` word.
const SEQUENCE_CSI_RS: u32 = 2;
/// Transmit beam of a record that names none (the illuminator's default).
const DEFAULT_BEAM: u16 = 0xFFFF;
/// TRS comb: one RE every fourth subcarrier.
const COMB: u16 = 4;
/// UE block flags: timing, CFO, gain and position present; samples corrected.
const FLAG_TIMING: u32 = 1 << 0;
const FLAG_CFO: u32 = 1 << 1;
const FLAG_GAIN: u32 = 1 << 3;
const FLAG_POSITION: u32 = 1 << 4;
const FLAG_CORRECTED: u32 = 1 << 8;
/// Records queued between the PHY worker and the sender before new ones drop.
const QUEUE_RECORDS: usize = 256;

/// What the tap writes and where (the `--sense-*` options).
#[derive(Clone, Debug, Default)]
pub struct SenseTapParams {
    /// ZMQ endpoint to bind a `PUB` socket on (`isac-sensor --zmq` connects).
    pub zmq_bind: Option<String>,
    /// Recording to append the records to (`isac-sensor --file`).
    pub record_path: Option<PathBuf>,
    /// Index of the illuminating cell in the sensing site (the DU's cell index).
    pub illuminator: u8,
    /// Receiver index of this UE in the sensing system; it must not be an RU's.
    pub receiver: u8,
    /// The UE antenna's position in the sensing site's frame, metres.
    pub position_m: Option<[f64; 3]>,
    /// TRS occasions per CPI, for the records' CPI index (the O-DU's
    /// `sensing_listener.cpi_occasions`).
    pub cpi_occasions: u32,
}

/// The UE's loop state when a slot was read: what was applied to its samples.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TapLoopState {
    /// Integer timing steps of the sample anchor so far, samples.
    pub applied_samples: i64,
    /// CFO removed from the samples before the FFT, Hz.
    pub cfo_removed_hz: f64,
    /// Receive gain, dB (an SDR's AGC); `None` without gain control.
    pub gain_db: Option<f32>,
}

/// The sensing tap: builds the records in the PHY worker and hands them to a
/// sender thread without blocking.
pub(crate) struct SenseTap {
    params: SenseTapParams,
    queue: crossbeam_channel::Sender<Vec<u8>>,
}

impl SenseTap {
    /// Start the sender thread: it binds the ZMQ socket and opens the
    /// recording, then sends every record it is handed until the tap is
    /// dropped.
    pub(crate) fn start(params: SenseTapParams) -> Result<Self> {
        let mut file = match &params.record_path {
            Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
            None => None,
        };
        let publisher = match &params.zmq_bind {
            Some(endpoint) => Some(publisher(endpoint)?),
            None => None,
        };
        let (queue, records) = crossbeam_channel::bounded::<Vec<u8>>(QUEUE_RECORDS);
        std::thread::Builder::new()
            .name("ferrite-sensetap".into())
            .spawn(move || {
                let mut dropped = 0u64;
                while let Ok(rec) = records.recv() {
                    if let Some(p) = &publisher {
                        match send(p, &rec) {
                            Ok(true) => {}
                            Ok(false) => dropped += 1,
                            Err(e) => log::warn!("sensing tap: {e}"),
                        }
                    }
                    if let Some(f) = file.as_mut() {
                        if let Err(e) = f.write_all(&rec) {
                            log::warn!("sensing tap recording: {e}");
                            file = None;
                        }
                    }
                }
                if let Some(mut f) = file {
                    let _ = f.flush();
                }
                if dropped > 0 {
                    log::info!("sensing tap: {dropped} records dropped by a full subscriber queue");
                }
            })
            .map_err(Error::Io)?;
        log::info!(
            "sensing tap: illuminator {} receiver {}{}{}",
            params.illuminator,
            params.receiver,
            params
                .zmq_bind
                .as_ref()
                .map_or(String::new(), |e| format!(", publishing on {e}")),
            params
                .record_path
                .as_ref()
                .map_or(String::new(), |p| format!(", recording to {}", p.display()))
        );
        Ok(Self { params, queue })
    }

    /// Tap the TRS symbols of `slot` from its demodulated grids
    /// (`grids_all[antenna][symbol][bin]`). A full queue drops the records.
    pub(crate) fn on_slot(
        &self,
        cfg: &WorkerConfig,
        slot: SlotPoint,
        grids_all: &[Vec<Vec<Iq>>],
        state: &TapLoopState,
    ) {
        for rec in trs_records(&self.params, cfg, slot, grids_all, state) {
            if self.queue.try_send(rec).is_err() {
                log::debug!("sensing tap: queue full, record of slot {slot} dropped");
            }
        }
    }
}

#[cfg(feature = "zmq")]
type Publisher = ferrite_radio::zmq::ZmqPublisher;
#[cfg(not(feature = "zmq"))]
type Publisher = ();

#[cfg(feature = "zmq")]
fn publisher(endpoint: &str) -> Result<Publisher> {
    ferrite_radio::zmq::ZmqPublisher::bind(endpoint)
}

#[cfg(not(feature = "zmq"))]
fn publisher(_endpoint: &str) -> Result<Publisher> {
    Err(Error::Radio(
        "the sensing tap's ZMQ output needs the `zmq` feature".into(),
    ))
}

#[cfg(feature = "zmq")]
fn send(p: &Publisher, rec: &[u8]) -> Result<bool> {
    p.send(rec)
}

#[cfg(not(feature = "zmq"))]
fn send(_p: &Publisher, _rec: &[u8]) -> Result<bool> {
    Ok(false)
}

/// The records of the TRS symbols of `slot`, one per configured TRS resource
/// on it.
pub(crate) fn trs_records(
    params: &SenseTapParams,
    cfg: &WorkerConfig,
    slot: SlotPoint,
    grids_all: &[Vec<Vec<Iq>>],
    state: &TapLoopState,
) -> Vec<Vec<u8>> {
    let sc_to_bin = cfg.geom.dl_sc_to_bin();
    cfg.csi_meas
        .iter()
        .filter(|(m, period, offset, _)| {
            m.row == CsiRsRow::Row1 && ferrite_phy::csi::csi_rs_slots(*period, *offset, slot)
        })
        .filter_map(|(m, period, _, _)| {
            if m.start_rb != 0 {
                log::debug!(
                    "sensing tap: TRS from CRB {} skipped (the sensor counts from CRB 0)",
                    m.start_rb
                );
                return None;
            }
            let n = 3 * m.n_rb;
            let mut samples = Vec::with_capacity(grids_all.len() * n);
            for grids in grids_all {
                let grid = grids.get(m.symbol)?;
                for rb in m.start_rb..m.start_rb + m.n_rb {
                    for i in 0..3 {
                        samples.push(*grid.get(sc_to_bin(12 * rb + m.k0 + 4 * i))?);
                    }
                }
            }
            let occasion = (slot.index() / u64::from((*period).max(1))) as u32;
            let header = Header {
                sfn: slot.sfn,
                slot: slot.slot,
                symbol: m.symbol as u8,
                illuminator: params.illuminator,
                receiver: params.receiver,
                nof_ant: grids_all.len() as u8,
                nof_re: n as u16,
                comb_offset: m.k0 as u16,
                numerology: u16::from(slot.numerology.mu),
                occasion_index: occasion,
                cpi_index: occasion / params.cpi_occasions.max(1),
                timestamp_ns: slot_start_ns(slot),
                seed: u32::from(m.n_id),
                timing_offset_s: state.applied_samples as f64 / cfg.geom.fs,
                cfo_hz: state.cfo_removed_hz,
                gain_db: state.gain_db,
                position_m: params.position_m,
            };
            Some(encode(&header, &samples))
        })
        .collect()
}

/// Start of `slot` in the slot clock of the records, nanoseconds: it wraps
/// with the SFN every 10.24 s, as the DU's tap timestamps do.
fn slot_start_ns(slot: SlotPoint) -> u64 {
    slot.index() * (1_000_000 >> slot.numerology.mu)
}

/// The fields of one record that vary.
struct Header {
    sfn: u16,
    slot: u16,
    symbol: u8,
    illuminator: u8,
    receiver: u8,
    nof_ant: u8,
    nof_re: u16,
    comb_offset: u16,
    numerology: u16,
    occasion_index: u32,
    cpi_index: u32,
    timestamp_ns: u64,
    seed: u32,
    timing_offset_s: f64,
    cfo_hz: f64,
    gain_db: Option<f32>,
    position_m: Option<[f64; 3]>,
}

/// One version 4 record: the header, then the samples.
fn encode(h: &Header, samples: &[Iq]) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN + 8 * samples.len());
    b.extend_from_slice(&MAGIC);
    b.extend_from_slice(&VERSION.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // rs_id: the TRS
    b.extend_from_slice(&h.sfn.to_le_bytes());
    b.extend_from_slice(&h.slot.to_le_bytes());
    b.extend_from_slice(&[h.symbol, h.illuminator, h.receiver, h.nof_ant]);
    b.extend_from_slice(&h.nof_re.to_le_bytes());
    b.extend_from_slice(&COMB.to_le_bytes());
    b.extend_from_slice(&h.comb_offset.to_le_bytes());
    b.extend_from_slice(&h.numerology.to_le_bytes());
    b.extend_from_slice(&h.occasion_index.to_le_bytes());
    b.extend_from_slice(&h.cpi_index.to_le_bytes());
    b.extend_from_slice(&h.timestamp_ns.to_le_bytes());
    b.extend_from_slice(&h.seed.to_le_bytes());
    b.extend_from_slice(&SEQUENCE_CSI_RS.to_le_bytes());
    // Version 3: transmit beam, transmit ports (unknown), reserved.
    b.extend_from_slice(&DEFAULT_BEAM.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    // Version 4: the UE block.
    let mut flags = FLAG_TIMING | FLAG_CFO | FLAG_CORRECTED;
    if h.gain_db.is_some() {
        flags |= FLAG_GAIN;
    }
    if h.position_m.is_some() {
        flags |= FLAG_POSITION;
    }
    b.extend_from_slice(&flags.to_le_bytes());
    b.extend_from_slice(&0f32.to_le_bytes()); // phase: no common phase correction
    b.extend_from_slice(&h.timing_offset_s.to_le_bytes());
    b.extend_from_slice(&h.cfo_hz.to_le_bytes());
    b.extend_from_slice(&h.gain_db.unwrap_or(0.0).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    for p in h.position_m.unwrap_or_default() {
        b.extend_from_slice(&p.to_le_bytes());
    }
    b.extend_from_slice(&[0u8; 12]); // velocity: unknown
    b.extend_from_slice(&0u32.to_le_bytes());
    for s in samples {
        b.extend_from_slice(&s.re.to_le_bytes());
        b.extend_from_slice(&s.im.to_le_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::Numerology;

    fn header() -> Header {
        Header {
            sfn: 1023,
            slot: 3,
            symbol: 8,
            illuminator: 0,
            receiver: 16,
            nof_ant: 2,
            nof_re: 3,
            comb_offset: 1,
            numerology: 1,
            occasion_index: 102_300,
            cpi_index: 6393,
            timestamp_ns: 10_231_500_000,
            seed: 500,
            timing_offset_s: -2.5e-7,
            cfo_hz: 12.5,
            gain_db: None,
            position_m: Some([30.0, -40.0, 1.5]),
        }
    }

    fn u16_at(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }

    fn f64_at(b: &[u8], o: usize) -> f64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[o..o + 8]);
        f64::from_le_bytes(a)
    }

    /// The offsets of morty's tap record, version 4.
    #[test]
    fn record_layout_is_the_tap_records_version_4() {
        let samples: Vec<Iq> = (0..6).map(|i| Iq::new(i as f32, -(i as f32))).collect();
        let b = encode(&header(), &samples);
        assert_eq!(b.len(), 128 + 6 * 8);
        assert_eq!(&b[0..4], b"ISAC");
        assert_eq!(u16_at(&b, 4), 4);
        assert_eq!((u16_at(&b, 8), u16_at(&b, 10)), (1023, 3));
        assert_eq!(&b[12..16], &[8, 0, 16, 2]);
        assert_eq!(
            (
                u16_at(&b, 16),
                u16_at(&b, 18),
                u16_at(&b, 20),
                u16_at(&b, 22)
            ),
            (3, 4, 1, 1)
        );
        assert_eq!((u32_at(&b, 24), u32_at(&b, 28)), (102_300, 6393));
        assert_eq!(
            u64::from_le_bytes(b[32..40].try_into().unwrap()),
            10_231_500_000
        );
        assert_eq!((u32_at(&b, 40), u32_at(&b, 44)), (500, 2));
        assert_eq!((u16_at(&b, 48), u16_at(&b, 50)), (0xFFFF, 0));
        // Timing, CFO, position, corrected; no gain.
        assert_eq!(u32_at(&b, 56), (1 << 0) | (1 << 1) | (1 << 4) | (1 << 8));
        assert_eq!((f64_at(&b, 64), f64_at(&b, 72)), (-2.5e-7, 12.5));
        assert_eq!(
            (f64_at(&b, 88), f64_at(&b, 96), f64_at(&b, 104)),
            (30.0, -40.0, 1.5)
        );
        assert_eq!(
            f32::from_le_bytes(b[128 + 8..128 + 12].try_into().unwrap()),
            1.0
        );
    }

    #[test]
    fn slot_clock_wraps_with_the_sfn() {
        let mu1 = Numerology { mu: 1 };
        assert_eq!(slot_start_ns(SlotPoint::new(mu1, 0, 0)), 0);
        assert_eq!(slot_start_ns(SlotPoint::new(mu1, 1, 3)), 23 * 500_000);
        assert_eq!(slot_start_ns(SlotPoint::new(mu1, 1023, 19)), 10_239_500_000);
    }
}
