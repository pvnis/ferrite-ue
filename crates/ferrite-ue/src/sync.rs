//! Continuous downlink synchronization: acquire a cell once, then track it
//! frame-by-frame — timing drift via narrow PSS re-correlation, CFO via the
//! SSB cyclic prefix, and SFN continuity via per-frame MIB decode.
//!
//! Assumes the SA lab configuration: SSB every 10 ms frame, `i_SSB = 0`,
//! first half-frame (Case C, 30 kHz). Timing constants generalize later.

use ferrite_phy::coding::bch::Mib;
use ferrite_phy::sync::cfo::correct_cfo;
use ferrite_phy::sync::{CellSearchResult, CellSearcher, PssDetector};
use ferrite_phy::Ofdm;
use num_complex::Complex32;

/// One tracked frame's report.
#[derive(Clone, Copy, Debug)]
pub struct FrameReport {
    /// SFN this frame was expected (and verified) to carry.
    pub sfn: u16,
    /// PSS timing error vs. the expected in-frame position, in samples.
    pub timing_err: i64,
    /// Smoothed CFO estimate, Hz.
    pub cfo_hz: f64,
    /// PSS correlation metric for this frame.
    pub pss_metric: f32,
    /// Whether the MIB decoded (CRC pass) and matched the expected SFN.
    pub mib_ok: bool,
}

/// Result of the acquisition stage.
#[derive(Clone, Copy, Debug)]
pub struct Acquired {
    pub cell_id: u16,
    pub i_ssb: u8,
    pub mib: Mib,
    pub cfo_hz: f64,
    /// Samples to discard from the stream (after the acquisition buffer) so the
    /// next read starts exactly on a frame boundary.
    pub skip_to_frame: usize,
    /// SFN the first tracked frame will carry.
    pub next_sfn: u16,
}

/// Frame-by-frame synchronization tracker.
pub struct FrameSync {
    searcher: CellSearcher,
    pss: PssDetector,
    fs: f64,
    frame_len: usize,
    /// PSS useful-part offset from the frame start (i_SSB 0, first half-frame).
    pss_off: usize,
    /// Tracking search half-window (samples).
    window: usize,
    // --- state after acquisition ---
    cell_id: u16,
    n_id_2: u8,
    i_ssb: u8,
    cfo_hz: f64,
    next_sfn: u16,
}

impl FrameSync {
    /// `fft` must equal `fs / 30 kHz` (SSB numerology `mu = 1`).
    pub fn new(fft: usize, fs: f64) -> Self {
        let ofdm = Ofdm::new(fft);
        let mu = 1;
        // Case C, i_SSB = 0: SSB occupies symbols 2..=5 of the first slot, so
        // the PSS useful part starts after symbols 0 (long CP) and 1, plus its
        // own CP.
        let cp_long = ofdm.cp_len(0, mu);
        let cp = ofdm.cp_len(1, mu);
        let pss_off = (cp_long + fft) + (cp + fft) + cp;
        Self {
            searcher: CellSearcher::new(fft, mu),
            pss: PssDetector::new(&ofdm),
            fs,
            frame_len: (fs * 0.010).round() as usize,
            pss_off,
            window: 64,
            cell_id: 0,
            n_id_2: 0,
            i_ssb: 0,
            cfo_hz: 0.0,
            next_sfn: 0,
        }
    }

    /// Samples per 10 ms frame at this sample rate.
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// Acquire from a buffer holding at least one full SSB (with headroom for
    /// the PBCH symbols). The buffer should already be centred on the SSB
    /// frequency (post GSCN shift) — see [`gscn_scan`].
    pub fn acquire(&mut self, buf: &[Complex32]) -> Option<Acquired> {
        let found = self.searcher.search(buf)?;
        let mut corrected = buf.to_vec();
        correct_cfo(&mut corrected, found.cfo_hz, self.fs);
        let (mib, i_ssb) = self.searcher.decode_mib(&corrected, &found)?;

        // Anchor frame timing: PSS position → start of its frame (assumes the
        // detected SSB is candidate 0 in the first half-frame, our lab config).
        let pss_pos = found.timing_index;
        if pss_pos < self.pss_off {
            return None; // SSB clipped at buffer start; caller retries
        }
        let frame_start = pss_pos - self.pss_off;
        // First frame boundary at or after the end of this buffer.
        let frames_consumed = (buf.len() - frame_start).div_ceil(self.frame_len);
        let skip_to_frame = frame_start + frames_consumed * self.frame_len - buf.len();
        let next_sfn = (mib.sfn + frames_consumed as u16) & 0x3FF;

        self.cell_id = found.cell_id;
        self.n_id_2 = found.n_id_2;
        self.i_ssb = i_ssb;
        self.cfo_hz = found.cfo_hz;
        self.next_sfn = next_sfn;

        Some(Acquired {
            cell_id: found.cell_id,
            i_ssb,
            mib,
            cfo_hz: found.cfo_hz,
            skip_to_frame,
            next_sfn,
        })
    }

    /// Track one frame-aligned 10 ms buffer (`frame_len` samples). Returns the
    /// report, or `None` if the PSS was not found in the tracking window
    /// (loss of lock; caller should re-acquire).
    pub fn track(&mut self, frame: &[Complex32]) -> Option<FrameReport> {
        assert_eq!(frame.len(), self.frame_len);
        let expected_sfn = self.next_sfn;
        self.next_sfn = (self.next_sfn + 1) & 0x3FF;

        // Narrow PSS re-correlation around the expected position.
        let lo = self.pss_off.saturating_sub(self.window);
        let hi = self.pss_off + self.window;
        let det = self.pss.track(frame, self.n_id_2, lo..hi)?;
        if det.metric < 0.2 {
            return None;
        }
        let timing_err = det.sample_index as i64 - self.pss_off as i64;

        // CFO from this SSB, smoothed (EMA) into the running estimate; then
        // decode the MIB on a CFO-corrected copy of the SSB region.
        let ssb_region_start = det.sample_index.saturating_sub(self.pss_off.min(64));
        let mut region = frame[ssb_region_start..].to_vec();
        let found = CellSearchResult {
            cell_id: self.cell_id,
            n_id_1: self.cell_id / 3,
            n_id_2: self.n_id_2,
            timing_index: det.sample_index - ssb_region_start,
            cfo_hz: 0.0,
            pss_metric: det.metric,
            sss_metric: 0.0,
        };
        // Estimate CFO over the SSB symbols at the tracked position.
        let cfo_now = {
            use ferrite_phy::sync::cfo::estimate_cfo_hz_multi;
            let ofdm = Ofdm::new((self.fs / 30_000.0).round() as usize);
            let cp = ofdm.cp_len(3, 1);
            let n = ofdm.fft_size();
            let pss_cp_start = found.timing_index.saturating_sub(cp);
            estimate_cfo_hz_multi(&region[pss_cp_start..], cp, n, 4, 30_000.0)
        };
        self.cfo_hz = 0.8 * self.cfo_hz + 0.2 * cfo_now;
        correct_cfo(&mut region, self.cfo_hz, self.fs);

        let mib_ok = match self.searcher.decode_mib(&region, &found) {
            Some((mib, _)) => mib.sfn == expected_sfn,
            None => false,
        };

        Some(FrameReport {
            sfn: expected_sfn,
            timing_err,
            cfo_hz: self.cfo_hz,
            pss_metric: det.metric,
            mib_ok,
        })
    }
}

/// Scan the GSCN sync raster (3–24.25 GHz: `F = 3000 MHz + N · 1.44 MHz`)
/// within the carrier bandwidth for the strongest SSB, one thread per
/// candidate. Returns the frequency shift `df` (Hz, SSB centre minus carrier
/// centre), the search result, and the shifted buffer.
pub fn gscn_scan(
    capture: &[Complex32],
    fs: f64,
    center_hz: f64,
    searcher: &CellSearcher,
) -> Option<(f64, CellSearchResult, Vec<Complex32>)> {
    const GSCN_STEP_HZ: f64 = 1.44e6;
    const SSB_HALF_BW_HZ: f64 = 3.6e6;

    // Search the whole sampled band: the SSB can sit anywhere its 20 RB still fit inside
    // ±fs/2 of the carrier centre. On a narrow carrier that's ~the SSB bandwidth, but on
    // a wide one (e.g. 20 MHz) the SSB is several MHz off centre — well outside its own
    // bandwidth — so a fixed ±SSB_BW window misses it and locks a spurious PSS peak.
    let half_search = (fs / 2.0 - SSB_HALF_BW_HZ).max(SSB_HALF_BW_HZ * 1.2);
    let n_lo = ((center_hz - half_search - 3.0e9) / GSCN_STEP_HZ).ceil() as i64;
    let n_hi = ((center_hz + half_search - 3.0e9) / GSCN_STEP_HZ).floor() as i64;

    std::thread::scope(|scope| {
        let handles: Vec<_> = (n_lo..=n_hi)
            .map(|n| {
                let df = 3.0e9 + n as f64 * GSCN_STEP_HZ - center_hz;
                scope.spawn(move || {
                    let shifted = freq_shift(capture, -df, fs, 0);
                    searcher.search(&shifted).map(|r| (df, r, shifted))
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .max_by(|(_, a, _), (_, b, _)| a.pss_metric.partial_cmp(&b.pss_metric).unwrap())
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
    use std::f64::consts::TAU;
    // The mixing phase advances by a constant `dph` per sample, so rotate incrementally
    // (one complex multiply/sample) instead of a sin/cos per sample — the phasor is the
    // hot part of the timeline thread. `dph` is reduced mod 2π and the per-slot start
    // phase is computed once at full f64 precision; the running phasor's magnitude drift
    // over a slot (~1e-13) is negligible.
    let dph = (TAU * shift_hz / fs).rem_euclid(TAU);
    let ph0 = (TAU * shift_hz * start_index as f64 / fs).rem_euclid(TAU);
    let (mut rr, mut ri) = (ph0.cos(), ph0.sin()); // running phasor e^{j·ph}
    let (sr, si) = (dph.cos(), dph.sin()); // per-sample step e^{j·dph}
    let mut out = Vec::with_capacity(samples.len());
    for s in samples {
        let (x, y) = (s.re as f64, s.im as f64);
        out.push(Complex32::new((x * rr - y * ri) as f32, (x * ri + y * rr) as f32));
        let nr = rr * sr - ri * si;
        ri = rr * si + ri * sr;
        rr = nr;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_phy::sync::ssb::build_ssb_waveform;

    /// The incremental `freq_shift` must match the per-sample sin/cos reference, including
    /// at the large `start_index` a long steady-state run reaches (the mixing phase must not
    /// drift). Checks a realistic slot at several offsets and start indices.
    #[test]
    fn freq_shift_matches_reference() {
        use std::f64::consts::TAU;
        let reference = |samples: &[Complex32], shift_hz: f64, fs: f64, start: usize| -> Vec<Complex32> {
            samples.iter().enumerate().map(|(m, s)| {
                let ph = TAU * shift_hz * (start + m) as f64 / fs;
                s * Complex32::new(ph.cos() as f32, ph.sin() as f32)
            }).collect()
        };
        let fs = 11_520_000.0;
        let samples: Vec<Complex32> = (0..6144)
            .map(|i| Complex32::new((i as f32 * 0.31).sin(), (i as f32 * 0.17).cos()))
            .collect();
        for &shift in &[-540_000.0f64, 30_000.0, 3_500_000.0] {
            for &start in &[0usize, 5760, 400_000_000, 4_000_000_000] {
                let got = freq_shift(&samples, shift, fs, start);
                let want = reference(&samples, shift, fs, start);
                let max_err = got.iter().zip(&want).map(|(a, b)| (a - b).norm()).fold(0.0f32, f32::max);
                assert!(max_err < 1e-3, "shift={shift} start={start}: max_err={max_err}");
            }
        }
    }

    /// Synthesize `n_frames` back-to-back 10 ms frames, each carrying an SSB
    /// (i_SSB 0, first half-frame) with per-frame SFN, then acquire + track.
    #[test]
    fn acquires_and_tracks_sfn_across_frames() {
        const FFT: usize = 256; // 7.68 MHz keeps the test fast
        let fs = FFT as f64 * 30_000.0;
        let ofdm = Ofdm::new(FFT);
        let (cell_id, i_ssb, sfn0) = (623u16, 0u8, 100u16);

        let mut sync = FrameSync::new(FFT, fs);
        let frame_len = sync.frame_len();
        let cp_long = ofdm.cp_len(0, 1);
        let cp = ofdm.cp_len(1, 1);
        let ssb_start = (cp_long + FFT) + (cp + FFT);

        let make_frame = |sfn: u16| -> Vec<Complex32> {
            let mib = Mib {
                sfn,
                scs_common_is_30_or_120: true,
                ssb_subcarrier_offset: 0,
                dmrs_typea_pos3: false,
                pdcch_config_sib1: 0x20,
                cell_barred: false,
                intra_freq_reselection_allowed: true,
                half_frame: 0,
                k_ssb_msb: 0,
            };
            let ssb = build_ssb_waveform(&mib, cell_id, i_ssb, &ofdm, 1);
            let mut frame = vec![Complex32::default(); frame_len];
            frame[ssb_start..ssb_start + ssb.len()].copy_from_slice(&ssb);
            frame
        };

        // Stream: half a frame of silence (unaligned start), then 6 SSB frames.
        let mut stream = vec![Complex32::default(); frame_len / 2];
        for k in 0..6 {
            stream.extend(make_frame(sfn0 + k));
        }

        // Acquire on the first 2.5 frames.
        let acq_len = frame_len * 5 / 2;
        let acq = sync.acquire(&stream[..acq_len]).expect("acquire failed");
        assert_eq!(acq.cell_id, cell_id);
        assert_eq!(acq.i_ssb, i_ssb);
        assert_eq!(acq.mib.sfn, sfn0); // first SSB in the buffer

        // Skip to the frame boundary, then track the remaining frames.
        let mut pos = acq_len + acq.skip_to_frame;
        let mut expect_sfn = acq.next_sfn;
        let mut tracked = 0;
        while pos + frame_len <= stream.len() {
            let rep = sync.track(&stream[pos..pos + frame_len]).expect("lost lock");
            assert_eq!(rep.sfn, expect_sfn, "SFN continuity");
            assert!(rep.mib_ok, "MIB should verify at SFN {}", rep.sfn);
            assert_eq!(rep.timing_err, 0, "no drift in a synthetic stream");
            assert!(rep.pss_metric > 0.9);
            expect_sfn = (expect_sfn + 1) & 0x3FF;
            pos += frame_len;
            tracked += 1;
        }
        assert!(tracked >= 3, "should have tracked several frames, got {tracked}");
    }
}
