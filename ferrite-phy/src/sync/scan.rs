//! Cell acquisition over the synchronization raster and continuous frame
//! tracking.
//!
//! * [`gscn_scan`]: shift a wideband capture to every GSCN (TS 38.104 §5.4.3.1)
//!   whose SSB fits in the captured band, run the cell search on each, and keep
//!   the strongest cell whose MIB decodes.
//! * [`freq_shift`] / [`FreqShifter`]: the complex mixers used for that shift
//!   and for the real-time downlink path.
//! * [`FrameTracker`]: once acquired, re-correlate the PSS in a narrow window at
//!   the expected SSB position every SSB period, tracking timing error and CFO
//!   and verifying the SFN through the MIB.
//!
//! Generic over the SSB case (TS 38.213 §4.1) and numerology.

use ferrite_common::band::{gscn_range, gscn_to_hz};
use num_complex::Complex32;
use std::f64::consts::TAU;

use crate::coding::bch::Mib;
use crate::sync::cfo::{correct_cfo, estimate_cfo_hz_multi};
use crate::sync::search::{CellSearchResult, CellSearcher, PbchDecode};
use crate::sync::ssb::{pss_useful_offset_in_frame, SsbCase, SSB_SUBCARRIERS, SSB_SYMBOLS};

/// The strongest decodable SSB found by [`gscn_scan`].
#[derive(Clone, Debug)]
pub struct ScanHit {
    /// GSCN of the SSB.
    pub gscn: u32,
    /// Frequency shift `SSB centre − capture centre` (Hz).
    pub df_hz: f64,
    /// Cell search result on the shifted capture.
    pub result: CellSearchResult,
    /// PBCH decode (`None` only when no candidate's MIB decoded and the
    /// strongest PSS peak was returned instead).
    pub pbch: Option<PbchDecode>,
    /// The capture shifted by `−df_hz` (SSB centred at DC).
    pub shifted: Vec<Complex32>,
}

/// Scan the GSCN sync raster within the captured band for the strongest SSB.
///
/// `capture` is a baseband capture at `fs` centred on `center_hz`;
/// `ssb_scs_khz` (15 or 30) selects the SSB numerology and `l_max` (4 or 8)
/// the PBCH decode. Every GSCN whose SSB (20 RB) fits inside the captured band
/// is tried, using the correct raster in both FR1 ranges (`N·1.2 MHz + M·50
/// kHz` below 3 GHz, `3 GHz + N·1.44 MHz` above). With `hint`, that GSCN is
/// tried first and the full scan runs only if its MIB does not decode. The
/// candidates are processed in parallel; the strongest PSS peak whose MIB
/// decodes wins, falling back to the strongest peak overall (a weak but real
/// SSB whose PBCH is marginal — the caller retries on a fresh capture).
/// Returns `None` if `fs / SCS` is not a valid FFT size or nothing correlates.
pub fn gscn_scan(
    capture: &[Complex32],
    fs: f64,
    center_hz: f64,
    ssb_scs_khz: u32,
    l_max: u8,
    hint: Option<u32>,
) -> Option<ScanHit> {
    let mu = ferrite_common::Numerology::from_scs_khz(ssb_scs_khz)?.mu;
    let scs_hz = f64::from(ssb_scs_khz) * 1e3;
    let fft = (fs / scs_hz).round();
    if (fft * scs_hz - fs).abs() > 1e-3 || !(fft as usize).is_multiple_of(128) {
        return None;
    }
    let searcher = CellSearcher::new(fft as usize, mu, l_max);

    if let Some(g) = hint {
        let df = gscn_to_hz(g) - center_hz;
        if let Some(hit) = try_gscn(capture, fs, &searcher, g, df) {
            if hit.pbch.is_some() {
                return Some(hit);
            }
        }
    }

    // The SSB can sit anywhere its 240 subcarriers still fit inside ±fs/2 of
    // the carrier centre. On a narrow capture that is barely the SSB bandwidth,
    // so allow a little beyond: the 127-subcarrier PSS/SSS core still
    // correlates when the SSB edges are clipped.
    let ssb_half_bw = SSB_SUBCARRIERS as f64 * scs_hz / 2.0;
    let half_search = (fs / 2.0 - ssb_half_bw).max(ssb_half_bw * 1.2);
    let gscns = gscn_range(center_hz - half_search, center_hz + half_search);
    if gscns.is_empty() {
        return None;
    }

    let n_threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(gscns.len());
    let chunk = gscns.len().div_ceil(n_threads);
    let mut hits: Vec<ScanHit> = std::thread::scope(|scope| {
        let handles: Vec<_> = gscns
            .chunks(chunk)
            .map(|group| {
                let searcher = &searcher;
                scope.spawn(move || {
                    group
                        .iter()
                        .filter_map(|&g| {
                            try_gscn(capture, fs, searcher, g, gscn_to_hz(g) - center_hz)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            // A scan thread that panicked contributes no hits (its GSCNs are
            // simply not found) instead of taking the UE down.
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    // Strongest PSS peak first; a decodable MIB beats any metric.
    hits.sort_by(|a, b| {
        b.pbch.is_some().cmp(&a.pbch.is_some()).then(
            b.result
                .pss_metric
                .partial_cmp(&a.result.pss_metric)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    hits.into_iter().next()
}

/// Shift the capture onto one GSCN, search it and attempt the MIB decode.
fn try_gscn(
    capture: &[Complex32],
    fs: f64,
    searcher: &CellSearcher,
    gscn: u32,
    df: f64,
) -> Option<ScanHit> {
    let shifted = freq_shift(capture, -df, fs, 0);
    let result = searcher.search(&shifted)?;
    let mut corrected = shifted.clone();
    correct_cfo(&mut corrected, result.cfo_hz, fs);
    let pbch = searcher.decode_mib(&corrected, &result);
    Some(ScanHit {
        gscn,
        df_hz: df,
        result,
        pbch,
        shifted,
    })
}

/// Mix `samples` by `shift_hz` (positive = shift spectrum up), with the phase
/// reference at absolute sample index `start_index` so successive buffers of a
/// stream stay phase-continuous.
pub fn freq_shift(
    samples: &[Complex32],
    shift_hz: f64,
    fs: f64,
    start_index: usize,
) -> Vec<Complex32> {
    // The mixing phase advances by a constant `dph` per sample, so rotate
    // incrementally (one complex multiply per sample) instead of a sin/cos per
    // sample. `dph` is reduced mod 2π and the start phase computed once at full
    // f64 precision; the running phasor's magnitude drift over a slot (~1e-13)
    // is negligible.
    let dph = (TAU * shift_hz / fs).rem_euclid(TAU);
    let ph0 = (TAU * shift_hz * start_index as f64 / fs).rem_euclid(TAU);
    let (mut rr, mut ri) = (ph0.cos(), ph0.sin()); // running phasor e^{j·ph}
    let (sr, si) = (dph.cos(), dph.sin()); // per-sample step e^{j·dph}
    let mut out = Vec::with_capacity(samples.len());
    for s in samples {
        let (x, y) = (f64::from(s.re), f64::from(s.im));
        out.push(Complex32::new(
            (x * rr - y * ri) as f32,
            (x * ri + y * rr) as f32,
        ));
        let nr = rr * sr - ri * si;
        ri = rr * si + ri * sr;
        rr = nr;
    }
    out
}

/// Fixed-`shift_hz` mixer with a precomputed per-sample phasor table, for the
/// real-time path. [`freq_shift`]'s serial phasor recurrence cannot vectorise
/// (each sample depends on the previous phasor). Here the table `e^{j·dph·n}`
/// (`n = 0..len`) is built once, so each buffer is
/// `out[n] = in[n] · table[n] · e^{j·dph·start}` — element-wise multiplies with
/// no cross-iteration dependency. `start` is the buffer's absolute sample index
/// (phase-continuous across buffers via the scalar `e^{j·dph·start}`).
pub struct FreqShifter {
    table: Vec<Complex32>,
    fs: f64,
    shift_hz: f64,
}

impl FreqShifter {
    /// Prepare a mixer for buffers of up to `len` samples.
    pub fn new(shift_hz: f64, fs: f64, len: usize) -> Self {
        let dph = (TAU * shift_hz / fs).rem_euclid(TAU);
        let (sr, si) = (dph.cos(), dph.sin());
        let (mut rr, mut ri) = (1.0f64, 0.0f64);
        let mut table = Vec::with_capacity(len);
        for _ in 0..len {
            table.push(Complex32::new(rr as f32, ri as f32));
            let nr = rr * sr - ri * si;
            ri = rr * si + ri * sr;
            rr = nr;
        }
        Self {
            table,
            fs,
            shift_hz,
        }
    }

    /// The shift this mixer applies (Hz).
    pub fn shift_hz(&self) -> f64 {
        self.shift_hz
    }

    /// Shift `samples` (`len ≤` table length) starting at absolute sample index
    /// `start`, into `out` (cleared and refilled, so the buffer can be reused
    /// without reallocating).
    pub fn shift_into(&self, samples: &[Complex32], start: usize, out: &mut Vec<Complex32>) {
        assert!(
            samples.len() <= self.table.len(),
            "buffer longer than the phasor table"
        );
        let ph0 = (TAU * self.shift_hz * start as f64 / self.fs).rem_euclid(TAU);
        let ps = Complex32::new(ph0.cos() as f32, ph0.sin() as f32);
        out.clear();
        out.reserve(samples.len());
        out.extend(samples.iter().zip(&self.table).map(|(s, t)| s * t * ps));
    }
}

/// Result of [`FrameTracker::acquire`].
#[derive(Clone, Copy, Debug)]
pub struct Acquired {
    pub cell_id: u16,
    /// Candidate SSB index (within the half frame) of the acquired SSB.
    pub i_ssb: u8,
    /// Half frame carrying it.
    pub half_frame: u8,
    pub mib: Mib,
    pub cfo_hz: f64,
    /// Sample index (within the acquisition buffer; negative if the frame began
    /// before it) of the start of the frame carrying the acquired SSB.
    pub frame_start: i64,
    /// Samples to discard from the stream after the acquisition buffer so the
    /// next read starts exactly on a frame boundary.
    pub skip_to_frame: usize,
    /// SFN the first tracked frame (after that skip) will carry.
    pub next_sfn: u16,
}

/// One tracked frame's report.
#[derive(Clone, Copy, Debug)]
pub struct FrameReport {
    /// SFN this frame carries (by continuity from acquisition).
    pub sfn: u16,
    /// Whether an SSB was expected (and measured) in this frame.
    pub ssb_frame: bool,
    /// PSS timing error vs. the expected in-frame position, in samples (0 when
    /// no SSB was expected).
    pub timing_err: i64,
    /// Smoothed CFO estimate, Hz.
    pub cfo_hz: f64,
    /// PSS correlation metric for this frame (0 when no SSB was expected).
    pub pss_metric: f32,
    /// MIB verification outcome: `Some(true)` if it decoded with the expected
    /// SFN and SSB index, `Some(false)` if it did not, `None` if not attempted.
    pub mib_ok: Option<bool>,
}

/// Frame-by-frame synchronization tracker for one SSB case / numerology.
pub struct FrameTracker {
    searcher: CellSearcher,
    mu: u8,
    fs: f64,
    frame_len: usize,
    /// Candidate SSB first symbols for this case and carrier.
    candidates: Vec<usize>,
    /// SSB burst period in frames (1 = every frame).
    ssb_period_frames: u32,
    /// Verify the MIB on every n-th SSB occasion.
    verify_every: u32,
    /// Tracking search half-window (samples).
    window: usize,
    // --- state after acquisition ---
    cell_id: u16,
    n_id_2: u8,
    i_ssb: u8,
    /// PSS useful-part offset from the frame start for the acquired SSB.
    pss_off: usize,
    cfo_hz: f64,
    next_sfn: u16,
    ssb_occasions: u32,
}

impl FrameTracker {
    /// Default SSB burst periodicity assumed before SIB1 is read (TS 38.213
    /// §4.1: 20 ms for initial cell selection).
    pub const DEFAULT_SSB_PERIOD_MS: u32 = 20;

    /// Build a tracker for an SSB FFT size (`fs = fft · SCS`), SSB case and
    /// carrier frequency (which fix the candidate positions and `L_max`).
    pub fn new(fft_size: usize, ssb_case: SsbCase, carrier_hz: f64) -> Self {
        let mu = ssb_case.mu();
        let candidates = ssb_case.candidate_symbols(carrier_hz);
        let searcher = CellSearcher::new(fft_size, mu, candidates.len() as u8);
        let frame_len = searcher.ofdm().samples_per_subframe(mu) * 10;
        let fs = fft_size as f64 * f64::from(15_000u32 << mu);
        Self {
            searcher,
            mu,
            fs,
            frame_len,
            candidates,
            ssb_period_frames: (Self::DEFAULT_SSB_PERIOD_MS / 10).max(1),
            verify_every: 1,
            window: 64,
            cell_id: 0,
            n_id_2: 0,
            i_ssb: 0,
            pss_off: 0,
            cfo_hz: 0.0,
            next_sfn: 0,
            ssb_occasions: 0,
        }
    }

    /// Set the SSB burst periodicity (`ssb-PeriodicityServingCell`, ms); values
    /// of 5/10 ms mean every frame.
    pub fn set_ssb_period_ms(&mut self, period_ms: u32) {
        self.ssb_period_frames = (period_ms / 10).max(1);
    }

    /// Verify the MIB on every `n`-th SSB occasion (default 1 = every one).
    pub fn set_verify_every(&mut self, n: u32) {
        self.verify_every = n.max(1);
    }

    /// Tracking half-window around the expected PSS position (samples).
    pub fn set_window(&mut self, samples: usize) {
        self.window = samples;
    }

    /// Samples per 10 ms frame at this sample rate.
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// Sample rate.
    pub fn fs(&self) -> f64 {
        self.fs
    }

    /// Offset (samples) from a frame boundary to the acquired SSB's PSS useful
    /// part. Valid after [`FrameTracker::acquire`].
    pub fn pss_off(&self) -> usize {
        self.pss_off
    }

    /// Current smoothed CFO estimate (Hz).
    pub fn cfo_hz(&self) -> f64 {
        self.cfo_hz
    }

    /// Acquire from a buffer holding at least one full SSB (with headroom for
    /// the PBCH symbols), already centred on the SSB frequency (post GSCN
    /// shift). Pins the frame timing from the decoded candidate index and half
    /// frame.
    pub fn acquire(&mut self, buf: &[Complex32]) -> Option<Acquired> {
        let found = self.searcher.search(buf)?;
        let mut corrected = buf.to_vec();
        correct_cfo(&mut corrected, found.cfo_hz, self.fs);
        let pbch = self.searcher.decode_mib(&corrected, &found)?;
        self.arm(&found, &pbch, buf.len())
    }

    /// Acquire from a [`ScanHit`] (shifted capture + its search/PBCH results).
    pub fn acquire_from_hit(&mut self, hit: &ScanHit) -> Option<Acquired> {
        let pbch = hit.pbch?;
        self.arm(&hit.result, &pbch, hit.shifted.len())
    }

    fn arm(
        &mut self,
        found: &CellSearchResult,
        pbch: &PbchDecode,
        buf_len: usize,
    ) -> Option<Acquired> {
        let first_symbol = *self.candidates.get(usize::from(pbch.i_ssb))?;
        let pss_off = pss_useful_offset_in_frame(
            first_symbol,
            pbch.half_frame,
            self.mu,
            self.searcher.ofdm(),
        );
        let frame_start = found.timing_index as i64 - pss_off as i64;
        // First frame boundary at or after the end of this buffer.
        let frame_len = self.frame_len as i64;
        let frames_consumed = (buf_len as i64 - frame_start).div_euclid(frame_len)
            + i64::from((buf_len as i64 - frame_start).rem_euclid(frame_len) != 0);
        let skip_to_frame = (frame_start + frames_consumed * frame_len - buf_len as i64) as usize;
        let next_sfn = (pbch.mib.sfn + frames_consumed as u16) & 0x3FF;

        self.cell_id = found.cell_id;
        self.n_id_2 = found.n_id_2;
        self.i_ssb = pbch.i_ssb;
        self.pss_off = pss_off;
        self.cfo_hz = found.cfo_hz;
        self.next_sfn = next_sfn;
        self.ssb_occasions = 0;

        Some(Acquired {
            cell_id: found.cell_id,
            i_ssb: pbch.i_ssb,
            half_frame: pbch.half_frame,
            mib: pbch.mib,
            cfo_hz: found.cfo_hz,
            frame_start,
            skip_to_frame,
            next_sfn,
        })
    }

    /// Track one frame-aligned 10 ms buffer (`frame_len` samples). Returns the
    /// report, or `None` if an SSB was expected and the PSS was not found in
    /// the tracking window (loss of lock; the caller should re-acquire).
    pub fn track(&mut self, frame: &[Complex32]) -> Option<FrameReport> {
        assert_eq!(frame.len(), self.frame_len);
        let sfn = self.next_sfn;
        self.next_sfn = (self.next_sfn + 1) & 0x3FF;

        // SSB bursts sit in the frames with SFN ≡ 0 (mod period), TS 38.213 §4.1.
        if u32::from(sfn) % self.ssb_period_frames != 0 {
            return Some(FrameReport {
                sfn,
                ssb_frame: false,
                timing_err: 0,
                cfo_hz: self.cfo_hz,
                pss_metric: 0.0,
                mib_ok: None,
            });
        }
        self.ssb_occasions += 1;

        // Narrow PSS re-correlation around the expected position.
        let lo = self.pss_off.saturating_sub(self.window);
        let hi = self.pss_off + self.window;
        let det = self
            .searcher
            .pss_detector()
            .track(frame, self.n_id_2, lo..hi)?;
        if det.metric < 0.2 {
            return None;
        }
        let timing_err = det.sample_index as i64 - self.pss_off as i64;

        // CFO from this SSB's cyclic prefixes, smoothed (EMA) into the running
        // estimate.
        let ofdm = self.searcher.ofdm();
        let (n, cp) = (ofdm.fft_size(), ofdm.cp_len(1, self.mu));
        if det.sample_index >= cp {
            let scs_hz = f64::from(15_000u32 << self.mu);
            let cfo_now =
                estimate_cfo_hz_multi(&frame[det.sample_index - cp..], cp, n, SSB_SYMBOLS, scs_hz);
            self.cfo_hz = 0.8 * self.cfo_hz + 0.2 * cfo_now;
        }

        let mib_ok = self
            .ssb_occasions
            .is_multiple_of(self.verify_every)
            .then(|| {
                let region_start = det.sample_index.saturating_sub(cp);
                let mut region = frame[region_start..].to_vec();
                correct_cfo(&mut region, self.cfo_hz, self.fs);
                let found = CellSearchResult {
                    cell_id: self.cell_id,
                    n_id_1: self.cell_id / 3,
                    n_id_2: self.n_id_2,
                    timing_index: det.sample_index - region_start,
                    cfo_hz: self.cfo_hz,
                    pss_metric: det.metric,
                    sss_metric: 0.0,
                };
                self.searcher
                    .decode_mib(&region, &found)
                    .is_some_and(|p| p.mib.sfn == sfn && p.i_ssb == self.i_ssb)
            });

        Some(FrameReport {
            sfn,
            ssb_frame: true,
            timing_err,
            cfo_hz: self.cfo_hz,
            pss_metric: det.metric,
            mib_ok,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ofdm::Ofdm;
    use crate::sync::pbch::pbch_dmrs_index;
    use crate::sync::ssb::{build_ssb_waveform, ssb_sample_offset_in_frame};

    /// The incremental `freq_shift` must match the per-sample sin/cos reference,
    /// including at the large `start_index` a long run reaches (no phase drift).
    #[test]
    fn freq_shift_matches_reference() {
        let reference =
            |samples: &[Complex32], shift_hz: f64, fs: f64, start: usize| -> Vec<Complex32> {
                samples
                    .iter()
                    .enumerate()
                    .map(|(m, s)| {
                        let ph = TAU * shift_hz * (start + m) as f64 / fs;
                        s * Complex32::new(ph.cos() as f32, ph.sin() as f32)
                    })
                    .collect()
            };
        let fs = 11_520_000.0;
        let samples: Vec<Complex32> = (0..6144)
            .map(|i| Complex32::new((i as f32 * 0.31).sin(), (i as f32 * 0.17).cos()))
            .collect();
        for &shift in &[-540_000.0f64, 30_000.0, 3_500_000.0] {
            for &start in &[0usize, 5760, 400_000_000, 4_000_000_000] {
                let got = freq_shift(&samples, shift, fs, start);
                let want = reference(&samples, shift, fs, start);
                let max_err = got
                    .iter()
                    .zip(&want)
                    .map(|(a, b)| (a - b).norm())
                    .fold(0.0f32, f32::max);
                assert!(
                    max_err < 1e-3,
                    "shift={shift} start={start}: max_err={max_err}"
                );
                let shifter = FreqShifter::new(shift, fs, samples.len());
                let mut out = Vec::new();
                shifter.shift_into(&samples, start, &mut out);
                let max_err = out
                    .iter()
                    .zip(&want)
                    .map(|(a, b)| (a - b).norm())
                    .fold(0.0f32, f32::max);
                assert!(
                    max_err < 1e-3,
                    "table shift={shift} start={start}: max_err={max_err}"
                );
            }
        }
    }

    fn mib_for(sfn: u16, half_frame: u8, mu: u8) -> Mib {
        Mib {
            sfn,
            scs_common_is_30_or_120: mu == 1,
            ssb_subcarrier_offset: 0,
            dmrs_typea_pos3: false,
            pdcch_config_sib1: 0x20,
            cell_barred: false,
            intra_freq_reselection_allowed: true,
            half_frame,
            k_ssb_msb: 0,
        }
    }

    /// Synthesize back-to-back 10 ms frames carrying an SSB (candidate `i_ssb`
    /// in half frame `hf`, every `period_ms`) with per-frame SFN, then acquire
    /// from an unaligned start and track the rest.
    fn acquire_and_track(
        fft: usize,
        case: SsbCase,
        carrier_hz: f64,
        i_ssb: u8,
        hf: u8,
        period_ms: u32,
        sfn0: u16,
    ) {
        let mu = case.mu();
        let ofdm = Ofdm::new(fft);
        let cell_id = 623u16;
        let l_max = case.l_max(carrier_hz);
        let first_symbol = case.candidate_symbols(carrier_hz)[usize::from(i_ssb)];
        let ssb_start = ssb_sample_offset_in_frame(first_symbol, hf, mu, &ofdm);

        let mut sync = FrameTracker::new(fft, case, carrier_hz);
        sync.set_ssb_period_ms(period_ms);
        let frame_len = sync.frame_len();
        let period_frames = (period_ms / 10).max(1) as u16;

        let make_frame = |sfn: u16| -> Vec<Complex32> {
            let mut frame = vec![Complex32::default(); frame_len];
            if sfn.is_multiple_of(period_frames) {
                let mib = mib_for(sfn & 0x3FF, hf, mu);
                let ssb = build_ssb_waveform(
                    &mib,
                    cell_id,
                    pbch_dmrs_index(i_ssb, hf, l_max),
                    l_max,
                    &ofdm,
                    mu,
                );
                frame[ssb_start..ssb_start + ssb.len()].copy_from_slice(&ssb);
            }
            frame
        };

        // Stream: 0.3 frame of silence (unaligned start), then 8 frames.
        let mut stream = vec![Complex32::default(); frame_len * 3 / 10];
        for k in 0..8 {
            stream.extend(make_frame(sfn0 + k));
        }

        // Acquire on the first 2.5 frames (holds at least one SSB at any period ≤ 20 ms).
        let acq_len = frame_len * 5 / 2;
        let acq = sync.acquire(&stream[..acq_len]).expect("acquire failed");
        assert_eq!(acq.cell_id, cell_id);
        assert_eq!(acq.i_ssb, i_ssb);
        assert_eq!(acq.half_frame, hf);
        let first_ssb_sfn = (sfn0..).find(|s| s % period_frames == 0).unwrap();
        assert_eq!(acq.mib.sfn, first_ssb_sfn, "first SSB in the buffer");
        // The frame start must land on the synthetic frame grid.
        let expected_start =
            (frame_len * 3 / 10 + usize::from(first_ssb_sfn - sfn0) * frame_len) as i64;
        assert_eq!(acq.frame_start, expected_start);
        assert_eq!(
            (acq_len + acq.skip_to_frame - frame_len * 3 / 10) % frame_len,
            0
        );

        // Skip to the frame boundary, then track the remaining frames.
        let mut pos = acq_len + acq.skip_to_frame;
        let mut expect_sfn = acq.next_sfn;
        let (mut tracked, mut ssb_frames) = (0, 0);
        while pos + frame_len <= stream.len() {
            let rep = sync
                .track(&stream[pos..pos + frame_len])
                .expect("lost lock");
            assert_eq!(rep.sfn, expect_sfn, "SFN continuity");
            if rep.ssb_frame {
                assert_eq!(
                    rep.mib_ok,
                    Some(true),
                    "MIB should verify at SFN {}",
                    rep.sfn
                );
                assert_eq!(rep.timing_err, 0, "no drift in a synthetic stream");
                assert!(rep.pss_metric > 0.9);
                ssb_frames += 1;
            } else {
                assert_eq!(rep.mib_ok, None);
            }
            expect_sfn = (expect_sfn + 1) & 0x3FF;
            pos += frame_len;
            tracked += 1;
        }
        assert!(
            tracked >= 4,
            "should have tracked several frames, got {tracked}"
        );
        assert!(
            ssb_frames >= 2,
            "should have seen several SSBs, got {ssb_frames}"
        );
    }

    /// Place an SSB on a GSCN away from the capture centre, on either raster,
    /// and check the scan finds that GSCN, decodes the MIB, and returns the
    /// shifted buffer with the SSB at DC.
    fn scan_finds_ssb(fft: usize, case: SsbCase, center_gscn: u32, ssb_gscn: u32) {
        use ferrite_common::band::gscn_to_hz;
        let mu = case.mu();
        let scs_khz = 15u32 << mu;
        let fs = fft as f64 * f64::from(scs_khz) * 1e3;
        let ofdm = Ofdm::new(fft);
        let (center_hz, ssb_hz) = (gscn_to_hz(center_gscn), gscn_to_hz(ssb_gscn));
        let l_max = case.l_max(ssb_hz);
        let (cell_id, i_ssb, sfn) = (301u16, 1u8, 77u16);
        let ssb = build_ssb_waveform(
            &mib_for(sfn, 0, mu),
            cell_id,
            pbch_dmrs_index(i_ssb, 0, l_max),
            l_max,
            &ofdm,
            mu,
        );
        let mut base = vec![Complex32::default(); 700];
        base.extend_from_slice(&ssb);
        base.extend(std::iter::repeat_n(Complex32::default(), 900));
        let capture = freq_shift(&base, ssb_hz - center_hz, fs, 0);

        let hit = gscn_scan(&capture, fs, center_hz, scs_khz, l_max, None).expect("no SSB found");
        assert_eq!(hit.gscn, ssb_gscn);
        assert!((hit.df_hz - (ssb_hz - center_hz)).abs() < 1.0);
        assert_eq!(hit.result.cell_id, cell_id);
        let pbch = hit.pbch.expect("MIB should decode on the right GSCN");
        assert_eq!((pbch.mib.sfn, pbch.i_ssb), (sfn, i_ssb));
        // The hint fast path returns the same hit.
        let hinted = gscn_scan(&capture, fs, center_hz, scs_khz, l_max, Some(ssb_gscn)).unwrap();
        assert_eq!(hinted.gscn, ssb_gscn);
        assert_eq!(hinted.result, hit.result);
    }

    #[test]
    fn gscn_scan_above_3ghz() {
        // GSCN 7846 = 3 GHz + 347·1.44 MHz; the SSB one raster step up.
        scan_finds_ssb(256, SsbCase::C, 7846, 7847);
    }

    #[test]
    fn gscn_scan_below_3ghz() {
        // Band n3 region: GSCN 4517 = 1807.25 MHz (N = 1506, M = 1); the SSB
        // two raster points up (M = 5 → +200 kHz).
        scan_finds_ssb(256, SsbCase::A, 4517, 4519);
    }

    /// The n78 lab configuration: Case C, candidate 0, first half frame, SSB in
    /// every frame.
    #[test]
    fn acquires_and_tracks_sfn_across_frames() {
        acquire_and_track(256, SsbCase::C, 3.5e9, 0, 0, 10, 100);
    }

    /// Case C with a non-zero candidate (symbol 36 → subframe 1) in the second
    /// half frame, 20 ms SSB period: the frame start must account for the
    /// candidate position and the 5 ms half-frame offset.
    #[test]
    fn tracks_case_c_later_candidate_second_half_frame() {
        acquire_and_track(256, SsbCase::C, 3.5e9, 5, 1, 20, 1021);
    }

    /// 15 kHz Case A below 3 GHz (L_max = 4): the DMRS index carries the half
    /// frame and the candidate index (2 → symbol 16, subframe 1).
    #[test]
    fn tracks_case_a_mu0() {
        acquire_and_track(256, SsbCase::A, 1.8e9, 2, 1, 20, 7);
    }
}
