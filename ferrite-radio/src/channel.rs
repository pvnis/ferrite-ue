//! Baseband channel emulation (test aid), for one direction of a link:
//!
//! ```text
//!   x_i ─▶ resample (clock offset, propagation delay) ─▶ z_i
//!   z_i ─▶ time-varying multipath FIR h_{o,i}(t) ─Σ_i─▶ ─▶ CFO ─▶ + AWGN ─▶ y_o
//! ```
//!
//! * **Multipath**: a tapped-delay-line profile, TS 38.901 §7.7.2 TDL-A/B/C
//!   (normalised delays scaled by a delay spread) or the TS 36.101 Annex B.2
//!   EPA/EVA/ETU profiles. Every tap of every (output, input) antenna pair
//!   fades independently (Rayleigh, sum of sinusoids with the classical
//!   Doppler spectrum). Taps sit at fractional delays (windowed-sinc
//!   interpolation into the FIR), the FIR is rebuilt every [`UPDATE`] samples.
//! * **Clock and delay**: output sample `m` reads the input at position
//!   `m·rate − delay`; `rate ≠ 1` emulates a sampling-rate offset between the
//!   two ends (a UE clock fast by ε: `rate = 1/(1+ε)` on the downlink,
//!   `1+ε` on the uplink), so the two streams drift apart exactly as two
//!   free-running radios do.
//! * **CFO**: a fixed frequency mixed onto the output.
//! * **Noise**: complex white Gaussian at `snr_db` below the mean power of
//!   the non-zero output samples (TDD gaps and empty uplink slots are not
//!   counted). The SNR is over the full sample bandwidth; the in-band SNR of
//!   an NR carrier is higher by `f_s / (N_RB · 12 · SCS)` (≈ 1.8 dB for
//!   52 RB at 15.36 MHz).
//!
//! Everything is deterministic for a given seed.

use num_complex::Complex32;
use std::f64::consts::{PI, TAU};

/// Fading and FIR update interval (output samples).
pub const UPDATE: usize = 64;
/// Half length of the interpolation kernel (samples).
const HALF: usize = 4;
/// Phases of the tabulated interpolation kernel.
const PHASES: usize = 1024;
/// Sinusoids per fading process.
const SINUSOIDS: usize = 16;

/// A tapped-delay-line power-delay profile.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Profile {
    pub name: &'static str,
    /// `(delay, power dB)`; the delay is normalised (× delay spread) when
    /// `normalised`, else in nanoseconds.
    pub taps: &'static [(f64, f64)],
    pub normalised: bool,
}

/// TS 38.901 Table 7.7.2-1 (TDL-A, NLOS).
pub const TDL_A: Profile = Profile {
    name: "tdla",
    normalised: true,
    taps: &[
        (0.0000, -13.4),
        (0.3819, 0.0),
        (0.4025, -2.2),
        (0.5868, -4.0),
        (0.4610, -6.0),
        (0.5375, -8.2),
        (0.6708, -9.9),
        (0.5750, -10.5),
        (0.7618, -7.5),
        (1.5375, -15.9),
        (1.8978, -6.6),
        (2.2242, -16.7),
        (2.1718, -12.4),
        (2.4942, -15.2),
        (2.5119, -10.8),
        (3.0582, -11.3),
        (4.0810, -12.7),
        (4.4579, -16.2),
        (4.5695, -18.3),
        (4.7966, -18.9),
        (5.0066, -16.6),
        (5.3043, -19.9),
        (9.6586, -29.7),
    ],
};

/// TS 38.901 Table 7.7.2-2 (TDL-B, NLOS).
pub const TDL_B: Profile = Profile {
    name: "tdlb",
    normalised: true,
    taps: &[
        (0.0000, 0.0),
        (0.1072, -2.2),
        (0.2155, -4.0),
        (0.2095, -3.2),
        (0.2870, -9.8),
        (0.2986, -1.2),
        (0.3752, -3.4),
        (0.5055, -5.2),
        (0.3681, -7.6),
        (0.3697, -3.0),
        (0.5700, -8.9),
        (0.5283, -9.0),
        (1.1021, -4.8),
        (1.2756, -5.7),
        (1.5474, -7.5),
        (1.7842, -1.9),
        (2.0169, -7.6),
        (2.8294, -12.2),
        (3.0219, -9.8),
        (3.6187, -11.4),
        (4.1067, -14.9),
        (4.2790, -9.2),
        (4.7834, -11.3),
    ],
};

/// TS 38.901 Table 7.7.2-3 (TDL-C, NLOS). (0.6366 is the table's value, not 2/π.)
#[allow(clippy::approx_constant)]
pub const TDL_C: Profile = Profile {
    name: "tdlc",
    normalised: true,
    taps: &[
        (0.0000, -4.4),
        (0.2099, -1.2),
        (0.2219, -3.5),
        (0.2329, -5.2),
        (0.2176, -2.5),
        (0.6366, 0.0),
        (0.6448, -2.2),
        (0.6560, -3.9),
        (0.6584, -7.4),
        (0.7935, -7.1),
        (0.8213, -10.7),
        (0.9336, -11.1),
        (1.2285, -5.1),
        (1.3083, -6.8),
        (2.1704, -8.7),
        (2.7105, -13.2),
        (4.2589, -13.9),
        (4.6003, -13.9),
        (5.4902, -15.8),
        (5.6077, -17.1),
        (6.3065, -16.0),
        (6.6374, -15.7),
        (7.0427, -21.6),
        (8.6523, -22.8),
    ],
};

/// TS 36.101 Table B.2.1-2 (Extended Pedestrian A).
pub const EPA: Profile = Profile {
    name: "epa",
    normalised: false,
    taps: &[
        (0.0, 0.0),
        (30.0, -1.0),
        (70.0, -2.0),
        (90.0, -3.0),
        (110.0, -8.0),
        (190.0, -17.2),
        (410.0, -20.8),
    ],
};

/// TS 36.101 Table B.2.1-3 (Extended Vehicular A).
pub const EVA: Profile = Profile {
    name: "eva",
    normalised: false,
    taps: &[
        (0.0, 0.0),
        (30.0, -1.5),
        (150.0, -1.4),
        (310.0, -3.6),
        (370.0, -0.6),
        (710.0, -9.1),
        (1090.0, -7.0),
        (1730.0, -12.0),
        (2510.0, -16.9),
    ],
};

/// TS 36.101 Table B.2.1-4 (Extended Typical Urban).
pub const ETU: Profile = Profile {
    name: "etu",
    normalised: false,
    taps: &[
        (0.0, -1.0),
        (50.0, -1.0),
        (120.0, -1.0),
        (200.0, 0.0),
        (230.0, 0.0),
        (500.0, 0.0),
        (1600.0, -3.0),
        (2300.0, -5.0),
        (5000.0, -7.0),
    ],
};

/// The profiles by name (`tdla`, `tdlb`, `tdlc`, `epa`, `eva`, `etu`).
pub fn profile(name: &str) -> Option<Profile> {
    [TDL_A, TDL_B, TDL_C, EPA, EVA, ETU]
        .into_iter()
        .find(|p| p.name == name)
}

impl Profile {
    /// Taps as `(delay s, linear power)`, powers normalised to a sum of 1.
    /// `delay_spread_s` scales the normalised TDL delays (ignored otherwise).
    pub fn taps_s(&self, delay_spread_s: f64) -> Vec<(f64, f64)> {
        let scale = if self.normalised {
            delay_spread_s
        } else {
            1e-9
        };
        let total: f64 = self.taps.iter().map(|&(_, p)| 10f64.powf(p / 10.0)).sum();
        self.taps
            .iter()
            .map(|&(d, p)| (d * scale, 10f64.powf(p / 10.0) / total))
            .collect()
    }
}

/// RMS delay spread of `(delay, linear power)` taps.
pub fn rms_delay_spread(taps: &[(f64, f64)]) -> f64 {
    let p: f64 = taps.iter().map(|t| t.1).sum();
    let mean = taps.iter().map(|t| t.0 * t.1).sum::<f64>() / p;
    (taps.iter().map(|t| (t.0 - mean).powi(2) * t.1).sum::<f64>() / p).sqrt()
}

/// xorshift64* with Box–Muller Gaussians.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1) ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in (0, 1).
    pub fn uniform(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }
    /// A complex Gaussian of unit variance (E|g|² = 1).
    pub fn cgauss(&mut self) -> Complex32 {
        let r = (-self.uniform().ln()).sqrt();
        let th = TAU * self.uniform();
        Complex32::new((r * th.cos()) as f32, (r * th.sin()) as f32)
    }
}

/// One Rayleigh fading process of unit mean power: a sum of sinusoids with
/// random arrival angles (Doppler `f_d·cos α`) and phases, the classical
/// (Jakes) spectrum for large counts. A zero Doppler gives a static, still
/// Rayleigh-distributed, gain. Sampled every [`UPDATE`] outputs: each
/// sinusoid is a phasor rotated by its step per update.
#[derive(Clone, Debug)]
struct Fader {
    /// `(phasor, step)` per sinusoid.
    comps: Vec<(num_complex::Complex64, num_complex::Complex64)>,
}

impl Fader {
    fn new(doppler_hz: f64, fs: f64, rng: &mut Rng) -> Self {
        let dt = UPDATE as f64 / fs;
        let comps = (0..SINUSOIDS)
            .map(|_| {
                let alpha = TAU * rng.uniform();
                let w = TAU * doppler_hz * alpha.cos();
                (
                    num_complex::Complex64::from_polar(1.0, TAU * rng.uniform()),
                    num_complex::Complex64::from_polar(1.0, w * dt),
                )
            })
            .collect();
        Self { comps }
    }

    /// The gain now, then advance by one update interval.
    fn next(&mut self) -> Complex32 {
        let mut g = num_complex::Complex64::new(0.0, 0.0);
        for (ph, step) in self.comps.iter_mut() {
            g += *ph;
            *ph *= *step;
        }
        let g = g / (SINUSOIDS as f64).sqrt();
        Complex32::new(g.re as f32, g.im as f32)
    }
}

/// Windowed-sinc interpolation kernel tabulated over [`PHASES`] fractional
/// offsets: `table[p][j]` weights input `floor(x) − HALF + 1 + j` for a
/// position `x` with fraction `p / PHASES`.
#[derive(Clone, Debug)]
struct Kernel {
    table: Vec<[f32; 2 * HALF]>,
}

impl Kernel {
    fn new() -> Self {
        let table = (0..=PHASES)
            .map(|p| {
                let frac = p as f64 / PHASES as f64;
                std::array::from_fn(|j| weight(j as f64 - (HALF as f64 - 1.0) - frac) as f32)
            })
            .collect();
        Self { table }
    }

    /// `(first input index, weights)` for position `x`.
    fn at(&self, x: f64) -> (i64, &[f32; 2 * HALF]) {
        let base = x.floor();
        let p = ((x - base) * PHASES as f64).round() as usize;
        (base as i64 - HALF as i64 + 1, &self.table[p.min(PHASES)])
    }
}

/// sinc(d) under a Blackman window of half width `HALF`.
fn weight(d: f64) -> f64 {
    let h = HALF as f64;
    if d.abs() >= h {
        return 0.0;
    }
    let sinc = if d.abs() < 1e-12 {
        1.0
    } else {
        (PI * d).sin() / (PI * d)
    };
    let u = (d + h) / (2.0 * h);
    let w = 0.42 - 0.5 * (TAU * u).cos() + 0.08 * (2.0 * TAU * u).cos();
    sinc * w
}

/// One direction's channel parameters.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    pub fs: f64,
    /// Transmit antennas (input streams) and receive antennas (outputs).
    pub n_in: usize,
    pub n_out: usize,
    /// Multipath taps `(delay s, linear power)`; empty = one unit tap, no
    /// fading (delay, clock, CFO and noise only).
    pub taps: Vec<(f64, f64)>,
    pub doppler_hz: f64,
    /// Propagation delay (s).
    pub delay_s: f64,
    /// Input samples per output sample (see the module doc).
    pub rate: f64,
    pub cfo_hz: f64,
    pub snr_db: Option<f64>,
    pub seed: u64,
}

impl LinkConfig {
    /// An ideal 1×1 link.
    pub fn ideal(fs: f64) -> Self {
        Self {
            fs,
            n_in: 1,
            n_out: 1,
            taps: Vec::new(),
            doppler_hz: 0.0,
            delay_s: 0.0,
            rate: 1.0,
            cfo_hz: 0.0,
            snr_db: None,
            seed: 1,
        }
    }
}

/// Complex samples as split real / imaginary arrays (vectorisable loops).
#[derive(Clone, Debug, Default)]
struct Split {
    re: Vec<f32>,
    im: Vec<f32>,
}

impl Split {
    fn zeros(n: usize) -> Self {
        Self {
            re: vec![0.0; n],
            im: vec![0.0; n],
        }
    }
    fn len(&self) -> usize {
        self.re.len()
    }
    fn push(&mut self, s: Complex32) {
        self.re.push(s.re);
        self.im.push(s.im);
    }
    fn drain_front(&mut self, n: usize) {
        let n = n.min(self.len());
        self.re.drain(..n);
        self.im.drain(..n);
    }
}

/// Size of the precomputed Gaussian table the noise is drawn from.
const NOISE_TABLE: usize = 1 << 17;

/// One direction of an emulated link. See the module documentation.
pub struct Link {
    cfg: LinkConfig,
    kernel: Kernel,
    /// Input history per stream; `hist_base` is the input index of element 0.
    hist: Vec<Split>,
    hist_base: i64,
    /// Inputs received so far (per stream).
    n_in_total: i64,
    /// Outputs produced so far.
    n_out_total: u64,
    /// The last `fir_len − 1` resampled samples per input stream (the FIR's
    /// delay line).
    z_tail: Vec<Split>,
    /// `(delay in samples incl. the FIR's causal offset, amplitude)` per tap.
    taps: Vec<(f64, f32)>,
    /// `faders[(o · n_in + i) · n_taps + k]`.
    faders: Vec<Fader>,
    fir_len: usize,
    /// `fir[o · n_in + i]` (coefficient `j` weights `z[m − j]`).
    fir: Vec<Split>,
    /// Resampler delay (input samples): the propagation delay minus the
    /// FIR's causal offset.
    resample_delay: f64,
    signal_power: Option<f64>,
    noise: Vec<Complex32>,
    rng: Rng,
}

impl Link {
    pub fn new(cfg: LinkConfig) -> Self {
        let mut rng = Rng::new(cfg.seed);
        let unit = [(0.0, 1.0)];
        let raw: &[(f64, f64)] = if cfg.taps.is_empty() {
            &unit
        } else {
            &cfg.taps
        };
        let taps: Vec<(f64, f32)> = raw
            .iter()
            .map(|&(d, p)| (d * cfg.fs + HALF as f64 - 1.0, p.sqrt() as f32))
            .collect();
        let max_delay = taps.iter().map(|t| t.0).fold(0.0, f64::max);
        let fir_len = max_delay.ceil() as usize + HALF + 1;
        let pairs = cfg.n_in * cfg.n_out;
        let fade = !cfg.taps.is_empty();
        let faders = (0..pairs * taps.len())
            .map(|_| Fader::new(if fade { cfg.doppler_hz } else { 0.0 }, cfg.fs, &mut rng))
            .collect();
        let resample_delay = cfg.delay_s * cfg.fs - (HALF as f64 - 1.0);
        let noise = if cfg.snr_db.is_some() {
            (0..NOISE_TABLE).map(|_| rng.cgauss()).collect()
        } else {
            Vec::new()
        };
        let mut link = Self {
            kernel: Kernel::new(),
            hist: vec![Split::default(); cfg.n_in],
            hist_base: 0,
            n_in_total: 0,
            n_out_total: 0,
            z_tail: vec![Split::zeros(fir_len - 1); cfg.n_in],
            taps,
            faders,
            fir_len,
            fir: vec![Split::zeros(fir_len); pairs],
            resample_delay,
            signal_power: None,
            noise,
            rng,
            cfg,
        };
        link.build_fir();
        link
    }

    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    /// Mean power of the non-zero output samples (before noise).
    pub fn signal_power(&self) -> Option<f64> {
        self.signal_power
    }

    pub fn samples_in(&self) -> i64 {
        self.n_in_total
    }

    pub fn samples_out(&self) -> u64 {
        self.n_out_total
    }

    /// Rebuild the FIRs from the faders' next gains (called every [`UPDATE`]
    /// outputs).
    fn build_fir(&mut self) {
        let n_taps = self.taps.len();
        let n_in = self.cfg.n_in;
        let fade = !self.cfg.taps.is_empty();
        for (pair, fir) in self.fir.iter_mut().enumerate() {
            fir.re.fill(0.0);
            fir.im.fill(0.0);
            // Without fading the antennas are wired straight through (output
            // `o` carries input `o`), not summed into a rank-1 channel; with
            // more inputs than outputs (4 gNB ports, 2 UE antennas) output `o`
            // carries every input `i ≡ o (mod n_out)` at a total of unit power.
            let n_out = self.cfg.n_out.max(1);
            let wired = pair % n_in % n_out == pair / n_in;
            let share = (n_out as f32 / n_in.max(n_out) as f32).sqrt();
            for (k, &(d, amp)) in self.taps.iter().enumerate() {
                let g = if fade {
                    self.faders[pair * n_taps + k].next() * amp
                } else if wired {
                    Complex32::new(amp * share, 0.0)
                } else {
                    Complex32::new(0.0, 0.0)
                };
                let (first, w) = self.kernel.at(d);
                for (j, &wj) in w.iter().enumerate() {
                    let idx = first + j as i64;
                    if (0..self.fir_len as i64).contains(&idx) {
                        fir.re[idx as usize] += g.re * wj;
                        fir.im[idx as usize] += g.im * wj;
                    }
                }
            }
        }
    }

    /// Input position read by output sample `m`.
    fn position(&self, m: u64) -> f64 {
        m as f64 * self.cfg.rate - self.resample_delay
    }

    /// Outputs whose interpolation window lies within the inputs received.
    fn ready(&self) -> usize {
        // floor(pos) + HALF ≤ N − 1  ⇔  pos < N − HALF.
        let limit = (self.n_in_total as f64 - HALF as f64 + self.resample_delay) / self.cfg.rate;
        let mut count = (limit.ceil() - self.n_out_total as f64).max(0.0) as usize;
        while count > 0 {
            let (first, _) = self
                .kernel
                .at(self.position(self.n_out_total + count as u64 - 1));
            if first + 2 * HALF as i64 <= self.n_in_total {
                break;
            }
            count -= 1;
        }
        count
    }

    /// Resample input stream `i` for outputs `m0 .. m0 + run` into `z`
    /// (appended). Within a run the interpolation phase is normally constant
    /// (|rate − 1| ≪ 1/run): then it is one fixed 2·HALF-tap filter.
    fn resample(&self, i: usize, m0: u64, run: usize, z: &mut Split) {
        let h = &self.hist[i];
        let p0 = self.position(m0);
        let p1 = self.position(m0 + run as u64 - 1);
        let (f0, w0) = self.kernel.at(p0);
        let (f1, w1) = self.kernel.at(p1);
        let start = z.len();
        z.re.resize(start + run, 0.0);
        z.im.resize(start + run, 0.0);
        let (zr, zi) = (&mut z.re[start..], &mut z.im[start..]);
        if std::ptr::eq(w0, w1) && f1 - f0 == run as i64 - 1 && f0 >= self.hist_base {
            let b = (f0 - self.hist_base) as usize;
            for (j, &wj) in w0.iter().enumerate() {
                let (xr, xi) = (&h.re[b + j..b + j + run], &h.im[b + j..b + j + run]);
                for (((zr, zi), &a), &c) in zr.iter_mut().zip(zi.iter_mut()).zip(xr).zip(xi) {
                    *zr += wj * a;
                    *zi += wj * c;
                }
            }
            return;
        }
        for (c, (zr, zi)) in zr.iter_mut().zip(zi.iter_mut()).enumerate() {
            let (first, w) = self.kernel.at(self.position(m0 + c as u64));
            for (j, &wj) in w.iter().enumerate() {
                let idx = first + j as i64 - self.hist_base;
                if idx >= 0 && (idx as usize) < h.len() {
                    *zr += wj * h.re[idx as usize];
                    *zi += wj * h.im[idx as usize];
                }
            }
        }
    }

    /// Push one block per input stream (equal lengths) and return the
    /// outputs it completes, one vector per output stream (all equal length;
    /// the count follows the input by the clock ratio and lags it by the
    /// interpolator's look-ahead).
    pub fn process(&mut self, input: &[&[Complex32]]) -> Vec<Vec<Complex32>> {
        let n = input.iter().map(|b| b.len()).min().unwrap_or(0);
        for (h, x) in self.hist.iter_mut().zip(input) {
            for &s in &x[..n] {
                h.push(s);
            }
        }
        self.n_in_total += n as i64;
        let count = self.ready();
        let tail = self.fir_len - 1;
        let mut out: Vec<Split> = (0..self.cfg.n_out).map(|_| Split::zeros(count)).collect();
        // Delay line per input: the FIR history, then this call's resampled samples.
        let mut z: Vec<Split> = self.z_tail.clone();
        let mut c = 0usize;
        while c < count {
            let m = self.n_out_total + c as u64;
            if m > 0 && m.is_multiple_of(UPDATE as u64) {
                self.build_fir();
            }
            let run = (UPDATE - (m % UPDATE as u64) as usize).min(count - c);
            for (i, zi) in z.iter_mut().enumerate() {
                self.resample(i, m, run, zi);
            }
            // y[c + s] = Σ_j h[j] · z[tail + c + s − j], one coefficient at a time.
            for (o, y) in out.iter_mut().enumerate() {
                let (yr, yi) = (&mut y.re[c..c + run], &mut y.im[c..c + run]);
                for (i, zi) in z.iter().enumerate() {
                    let fir = &self.fir[o * self.cfg.n_in + i];
                    for (j, (&hr, &hi)) in fir.re.iter().zip(&fir.im).enumerate() {
                        let from = tail + c - j;
                        let (xr, xi) = (&zi.re[from..from + run], &zi.im[from..from + run]);
                        for (((yr, yi), &a), &b) in yr.iter_mut().zip(yi.iter_mut()).zip(xr).zip(xi)
                        {
                            *yr += hr * a - hi * b;
                            *yi += hr * b + hi * a;
                        }
                    }
                }
            }
            c += run;
        }
        let mut out: Vec<Vec<Complex32>> = out
            .iter()
            .map(|y| {
                y.re.iter()
                    .zip(&y.im)
                    .map(|(&a, &b)| Complex32::new(a, b))
                    .collect()
            })
            .collect();
        // CFO, measured signal power, noise.
        let start = self.n_out_total;
        for y in out.iter_mut() {
            crate::impair::mix(y, self.cfg.cfo_hz, self.cfg.fs, start);
        }
        let (p, k) = out
            .iter()
            .flatten()
            .map(|s| s.norm_sqr() as f64)
            .filter(|&p| p > 1e-12)
            .fold((0.0, 0usize), |a, p| (a.0 + p, a.1 + 1));
        if k > 0 {
            let mean = p / k as f64;
            self.signal_power = Some(self.signal_power.map_or(mean, |s| 0.95 * s + 0.05 * mean));
        }
        if let (Some(snr), Some(ps)) = (self.cfg.snr_db, self.signal_power) {
            let sigma = (ps / 10f64.powf(snr / 10.0)).sqrt() as f32;
            for y in out.iter_mut() {
                let mut idx = (self.rng.next_u64() as usize) % NOISE_TABLE;
                for s in y.iter_mut() {
                    *s += self.noise[idx] * sigma;
                    idx = (idx + 1) % NOISE_TABLE;
                }
            }
        }
        // Keep the FIR history and trim the input history to what the next
        // output still reads.
        for (t, zi) in self.z_tail.iter_mut().zip(&z) {
            let l = zi.len();
            t.re.copy_from_slice(&zi.re[l - tail..]);
            t.im.copy_from_slice(&zi.im[l - tail..]);
        }
        self.n_out_total += count as u64;
        let (next_first, _) = self.kernel.at(self.position(self.n_out_total));
        let drop = (next_first - self.hist_base).max(0) as usize;
        for h in self.hist.iter_mut() {
            h.drain_front(drop);
        }
        self.hist_base += drop as i64;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The normalised TDL tables have an RMS delay spread of 1; the 36.101
    /// profiles have their published values (catches transcription errors).
    #[test]
    fn profiles_have_their_delay_spreads() {
        for p in [TDL_A, TDL_B, TDL_C] {
            let ds = rms_delay_spread(&p.taps_s(1.0));
            assert!((ds - 1.0).abs() < 1e-3, "{}: {ds}", p.name);
        }
        for (p, want) in [(EPA, 43e-9), (EVA, 357e-9), (ETU, 991e-9)] {
            let ds = rms_delay_spread(&p.taps_s(0.0));
            assert!((ds / want - 1.0).abs() < 0.01, "{}: {ds}", p.name);
        }
        let s: f64 = TDL_C.taps_s(300e-9).iter().map(|t| t.1).sum();
        assert!((s - 1.0).abs() < 1e-12);
    }

    fn tone(f: f64, fs: f64, n: usize, start: usize) -> Vec<Complex32> {
        (start..start + n)
            .map(|k| {
                let a = TAU * f * k as f64 / fs;
                Complex32::new(a.cos() as f32, a.sin() as f32)
            })
            .collect()
    }

    fn run(link: &mut Link, input: &[Complex32], block: usize) -> Vec<Complex32> {
        let mut y = Vec::new();
        for b in input.chunks(block) {
            y.extend(link.process(&[b]).swap_remove(0));
        }
        y
    }

    /// An ideal link passes the signal through unchanged, whatever the block
    /// boundaries.
    #[test]
    fn an_ideal_link_is_transparent() {
        let fs = 1e6;
        let x = tone(12_345.0, fs, 5000, 0);
        let mut link = Link::new(LinkConfig::ideal(fs));
        let y = run(&mut link, &x, 333);
        assert!(y.len() > 4990, "{} outputs", y.len());
        // The first HALF − 1 outputs read before the stream start.
        for (k, (a, b)) in x.iter().zip(&y).enumerate().skip(HALF) {
            assert!((a - b).norm() < 1e-3, "sample {k}: {a} vs {b}");
        }
    }

    /// A fractional propagation delay delays a band-limited tone by exactly
    /// that much (its phase).
    #[test]
    fn delays_by_a_fraction_of_a_sample() {
        let (fs, f, d) = (1e6, 50_000.0, 3.3e-6);
        let x = tone(f, fs, 4000, 0);
        let mut link = Link::new(LinkConfig {
            delay_s: d,
            ..LinkConfig::ideal(fs)
        });
        let y = run(&mut link, &x, 500);
        for (k, &yk) in y.iter().enumerate().take(3000).skip(100) {
            let want = tone(f, fs, 1, 0)[0]
                * Complex32::from_polar(1.0, (TAU * f * (k as f64 / fs - d)) as f32);
            assert!((yk - want).norm() < 2e-3, "sample {k}");
        }
    }

    /// A clock offset ε stretches the stream: after N outputs the input has
    /// advanced N·rate, visible as a frequency scaled by the rate.
    #[test]
    fn a_clock_offset_drifts_the_timing() {
        let (fs, f) = (1e6, 10_000.0);
        let eps = 200e-6;
        let x = tone(f, fs, 20_000, 0);
        let mut link = Link::new(LinkConfig {
            rate: 1.0 / (1.0 + eps),
            ..LinkConfig::ideal(fs)
        });
        let y = run(&mut link, &x, 1920);
        // More outputs than inputs (the receiver's clock is fast).
        assert!(
            y.len() as f64 > 20_000.0 * (1.0 + eps) - 10.0,
            "{}",
            y.len()
        );
        // Output m reads input m/(1+ε): phase 2π f m /((1+ε) fs).
        for m in [1000usize, 10_000, 19_000] {
            let want = Complex32::from_polar(1.0, (TAU * f * m as f64 / ((1.0 + eps) * fs)) as f32);
            assert!(
                (y[m] - want).norm() < 2e-3,
                "sample {m}: {} vs {want}",
                y[m]
            );
        }
    }

    /// The CFO shows up as a frequency shift and the noise at the set SNR.
    #[test]
    fn cfo_and_noise() {
        let fs = 1e6;
        let x = vec![Complex32::new(1.0, 0.0); 50_000];
        let mut link = Link::new(LinkConfig {
            cfo_hz: 1000.0,
            ..LinkConfig::ideal(fs)
        });
        let y = run(&mut link, &x, 1000);
        let rot: Complex32 = y.windows(2).skip(100).map(|w| w[1] * w[0].conj()).sum();
        let f = f64::from(rot.arg()) * fs / TAU;
        assert!((f - 1000.0).abs() < 1.0, "cfo {f}");

        let mut link = Link::new(LinkConfig {
            snr_db: Some(10.0),
            ..LinkConfig::ideal(fs)
        });
        let y = run(&mut link, &x, 1000);
        let noise: f64 = y[1000..]
            .iter()
            .map(|s| f64::from((s - 1.0).norm_sqr()))
            .sum::<f64>()
            / (y.len() - 1000) as f64;
        let snr = -10.0 * noise.log10();
        assert!((snr - 10.0).abs() < 0.5, "snr {snr} dB");
    }

    /// Fading taps keep the average power (unit-power profile) and
    /// decorrelate over a few coherence times; antenna pairs are independent.
    #[test]
    fn fading_preserves_power_and_is_independent_per_pair() {
        let fs = 1e6;
        let x = vec![Complex32::new(1.0, 0.0); 400_000];
        let mut link = Link::new(LinkConfig {
            n_out: 2,
            taps: TDL_C.taps_s(300e-9),
            doppler_hz: 100.0,
            seed: 7,
            ..LinkConfig::ideal(fs)
        });
        let mut y = [Vec::new(), Vec::new()];
        for b in x.chunks(2000) {
            for (acc, o) in y.iter_mut().zip(link.process(&[b])) {
                acc.extend(o);
            }
        }
        let power = |v: &[Complex32]| {
            v.iter().map(|s| f64::from(s.norm_sqr())).sum::<f64>() / v.len() as f64
        };
        for v in &y {
            let p = power(&v[1000..]);
            assert!((0.5..2.0).contains(&p), "mean power {p}");
        }
        let corr: Complex32 = y[0][1000..]
            .iter()
            .zip(&y[1][1000..])
            .map(|(a, b)| a * b.conj())
            .sum();
        let rho = f64::from(corr.norm())
            / (power(&y[0][1000..]) * power(&y[1][1000..])).sqrt()
            / (y[0].len() - 1000) as f64;
        assert!(rho < 0.5, "antenna correlation {rho}");
    }

    /// Without a fading model a multi-antenna link wires each input straight
    /// to its own output (an identity channel, as when the ports are cabled
    /// directly), keeping both streams separable.
    #[test]
    fn unfaded_mimo_link_is_identity() {
        let fs = 1e6;
        let a = vec![Complex32::new(1.0, 0.0); 4000];
        let b = vec![Complex32::new(0.0, -0.5); 4000];
        let mut link = Link::new(LinkConfig {
            n_in: 2,
            n_out: 2,
            ..LinkConfig::ideal(fs)
        });
        let mut y = [Vec::new(), Vec::new()];
        for (ca, cb) in a.chunks(500).zip(b.chunks(500)) {
            for (acc, o) in y.iter_mut().zip(link.process(&[ca, cb])) {
                acc.extend(o);
            }
        }
        for (v, want) in y.iter().zip([a[0], b[0]]) {
            assert!(v.len() > 3000);
            for s in &v[100..] {
                assert!((s - want).norm() < 1e-3, "{s} vs {want}");
            }
        }
    }

    /// Four inputs into two outputs without fading: output `o` carries
    /// inputs `o` and `o + 2`, each at half power (unit total), so every
    /// transmit port reaches the UE (a 4-port CSI-RS stays measurable).
    #[test]
    fn unfaded_four_to_two_link_combines_port_pairs() {
        let fs = 1e6;
        let x: Vec<Vec<Complex32>> = (0..4)
            .map(|p| vec![Complex32::new(p as f32 + 1.0, 0.0); 4000])
            .collect();
        let mut link = Link::new(LinkConfig {
            n_in: 4,
            n_out: 2,
            ..LinkConfig::ideal(fs)
        });
        let mut y = [Vec::new(), Vec::new()];
        for c in 0..8 {
            let refs: Vec<&[Complex32]> = x.iter().map(|v| &v[c * 500..(c + 1) * 500]).collect();
            for (acc, o) in y.iter_mut().zip(link.process(&refs)) {
                acc.extend(o);
            }
        }
        let h = std::f32::consts::FRAC_1_SQRT_2;
        for (v, want) in y.iter().zip([(1.0 + 3.0) * h, (2.0 + 4.0) * h]) {
            assert!(v.len() > 3000);
            for s in &v[100..] {
                assert!(
                    (s.re - want).abs() < 1e-3 && s.im.abs() < 1e-3,
                    "{s} vs {want}"
                );
            }
        }
    }
}
