//! PRACH configuration: preamble formats, configuration tables, occasion
//! enumeration and frequency mapping (3GPP TS 38.211 §5.3.2, §6.3.3; TS 38.213
//! §8.1; TS 38.321 §5.1.3).
//!
//! * [`PreambleFormat`] / [`format_params`]: Tables 6.3.3.1-1 (long formats
//!   0–3, `L_RA = 839`) and 6.3.3.1-2 (short formats A1–C2, `L_RA = 139`),
//!   with the `2^-µ` scaling of the short-format durations.
//! * [`PRACH_CONFIG_FR1_PAIRED`] / [`PRACH_CONFIG_FR1_UNPAIRED`]: Tables
//!   6.3.3.2-2 (FR1 paired spectrum / supplementary uplink) and 6.3.3.2-3
//!   (FR1 unpaired spectrum), indexed by `prach-ConfigurationIndex`.
//! * [`prach_occasions_in_slot`], [`next_prach_occasion`]: the time-domain
//!   occasions of a cell (§6.3.3.2, §5.3.2) and the RA-RNTI inputs
//!   `s_id / t_id / f_id` (TS 38.321 §5.1.3).
//! * [`prach_frequency_mapping`], [`prach_subcarrier_offset`]: Table
//!   6.3.3.2-1 (`N_RB^RA`, `k̄`) and the subcarrier position of an occasion.
//! * [`occasion_ssb_ordinals`], [`association_period_frames`]: SS/PBCH block to
//!   PRACH occasion association (TS 38.213 §8.1, Table 8.1-1).
//!
//! The configuration tables are normative constant data (cross-checked against
//! two independent transcriptions); everything else is derived from the spec
//! text.
#![forbid(unsafe_code)]

use core::fmt;
use ferrite_common::slot::{KAPPA, TC_SECONDS};
use ferrite_common::{DuplexMode, Numerology, SlotPoint};

/// Errors of the PRACH configuration / generation path.
#[derive(Clone, Debug, PartialEq)]
pub enum PrachError {
    /// `prach-ConfigurationIndex` out of range for the table.
    InvalidConfigIndex { duplex: DuplexMode, index: u16 },
    /// PRACH subcarrier spacing not allowed for FR1 short formats (15/30 kHz
    /// only) or numerology too large.
    UnsupportedScs { mu: u8 },
    /// A mixed format (A1/B1, …) must be resolved per occasion with
    /// [`PreambleFormat::for_occasion`] before asking for its parameters.
    MixedFormat(PreambleFormat),
    /// `fs / Δf_RA` is not an integer at this sample rate.
    NonIntegerSymbolLength { fs: f64, delta_f_ra_hz: f64 },
    /// Table 6.3.3.2-1 has no entry for this (Δf_RA, Δf_PUSCH) pair.
    NoFrequencyMapping { delta_f_ra_hz: f64, mu_pusch: u8 },
    /// Restricted sets type A/B are not implemented (unrestricted only).
    RestrictedSetUnsupported,
    /// `zeroCorrelationZoneConfig` outside 0..=15.
    InvalidZeroCorrelationZone(u8),
    /// Preamble index outside 0..=63.
    InvalidPreambleIndex(u8),
    /// `msg1-FDM` must be 1, 2, 4 or 8.
    InvalidMsg1Fdm(u8),
    /// The SS/PBCH blocks cannot all be mapped within the largest association
    /// period allowed by Table 8.1-1.
    InvalidSsbMapping,
}

impl fmt::Display for PrachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfigIndex { duplex, index } => {
                write!(
                    f,
                    "prach-ConfigurationIndex {index} is out of range for {duplex:?}"
                )
            }
            Self::UnsupportedScs { mu } => write!(f, "unsupported PRACH numerology mu={mu}"),
            Self::MixedFormat(fmt) => {
                write!(
                    f,
                    "mixed preamble format {} must be resolved per occasion",
                    fmt.label()
                )
            }
            Self::NonIntegerSymbolLength { fs, delta_f_ra_hz } => {
                write!(f, "fs={fs} / delta_f_RA={delta_f_ra_hz} is not an integer")
            }
            Self::NoFrequencyMapping {
                delta_f_ra_hz,
                mu_pusch,
            } => {
                write!(f, "no Table 6.3.3.2-1 entry for delta_f_RA={delta_f_ra_hz} Hz, PUSCH mu={mu_pusch}")
            }
            Self::RestrictedSetUnsupported => write!(f, "restricted set type A/B not supported"),
            Self::InvalidZeroCorrelationZone(z) => {
                write!(f, "zeroCorrelationZoneConfig {z} out of range")
            }
            Self::InvalidPreambleIndex(p) => write!(f, "preamble index {p} out of range"),
            Self::InvalidMsg1Fdm(m) => write!(f, "msg1-FDM {m} must be 1, 2, 4 or 8"),
            Self::InvalidSsbMapping => write!(
                f,
                "SS/PBCH blocks cannot be mapped within an association period"
            ),
        }
    }
}

impl std::error::Error for PrachError {}

// ---------------------------------------------------------------------------
// Preamble formats (Tables 6.3.3.1-1 / 6.3.3.1-2)
// ---------------------------------------------------------------------------

/// Random-access preamble format (TS 38.211 Tables 6.3.3.1-1 and 6.3.3.1-2,
/// first column of Tables 6.3.3.2-2/-3). `A1B1`, `A2B2`, `A3B3` are the mixed
/// entries "A1/B1" etc. of the configuration tables: the B format is used for
/// the last time-domain occasion of a PRACH slot, the A format for the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PreambleFormat {
    F0,
    F1,
    F2,
    F3,
    A1,
    A2,
    A3,
    B1,
    B2,
    B3,
    B4,
    C0,
    C2,
    A1B1,
    A2B2,
    A3B3,
}

impl PreambleFormat {
    /// Long formats 0–3 (`L_RA = 839`, Δf_RA 1.25 / 5 kHz).
    pub const fn is_long(self) -> bool {
        matches!(self, Self::F0 | Self::F1 | Self::F2 | Self::F3)
    }

    /// Mixed table entry (A1/B1, A2/B2, A3/B3).
    pub const fn is_mixed(self) -> bool {
        matches!(self, Self::A1B1 | Self::A2B2 | Self::A3B3)
    }

    /// Sequence length `L_RA`: 839 (long) or 139 (short).
    pub const fn l_ra(self) -> usize {
        if self.is_long() {
            839
        } else {
            139
        }
    }

    /// Format used by time-domain occasion `n_t` out of `n_t_total` in a PRACH
    /// slot: for the mixed entries the B format is used for the last occasion
    /// (`n_t == n_t_total - 1`) and the A format otherwise (§6.3.3.2); plain
    /// formats map to themselves.
    pub const fn for_occasion(self, n_t: u8, n_t_total: u8) -> PreambleFormat {
        let last = n_t + 1 == n_t_total;
        match self {
            Self::A1B1 => {
                if last {
                    Self::B1
                } else {
                    Self::A1
                }
            }
            Self::A2B2 => {
                if last {
                    Self::B2
                } else {
                    Self::A2
                }
            }
            Self::A3B3 => {
                if last {
                    Self::B3
                } else {
                    Self::A3
                }
            }
            other => other,
        }
    }

    /// Spec spelling ("0", "A1", "A1/B1", …).
    pub const fn label(self) -> &'static str {
        match self {
            Self::F0 => "0",
            Self::F1 => "1",
            Self::F2 => "2",
            Self::F3 => "3",
            Self::A1 => "A1",
            Self::A2 => "A2",
            Self::A3 => "A3",
            Self::B1 => "B1",
            Self::B2 => "B2",
            Self::B3 => "B3",
            Self::B4 => "B4",
            Self::C0 => "C0",
            Self::C2 => "C2",
            Self::A1B1 => "A1/B1",
            Self::A2B2 => "A2/B2",
            Self::A3B3 => "A3/B3",
        }
    }
}

/// Which `N_CS` table applies (Tables 6.3.3.1-5/-6/-7), i.e. the PRACH
/// subcarrier-spacing class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrachScs {
    /// 1.25 kHz — long formats 0/1/2 (Table 6.3.3.1-5).
    Khz1_25,
    /// 5 kHz — long format 3 (Table 6.3.3.1-6).
    Khz5,
    /// `15·2^µ` kHz — short formats (Table 6.3.3.1-7).
    Short,
}

/// `T_c` per `κ` unit: `κ = 64`.
const KAPPA_TC: u64 = KAPPA as u64;

/// 1 ms in `T_c` units (`30720·κ`).
pub const SUBFRAME_TC: u64 = 30720 * KAPPA_TC;

/// Parameters of one preamble format at the PRACH numerology (TS 38.211
/// Tables 6.3.3.1-1 and 6.3.3.1-2). Durations are in `T_c` units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PreambleFormatParams {
    pub format: PreambleFormat,
    /// Sequence length `L_RA`.
    pub l_ra: usize,
    /// PRACH subcarrier spacing `Δf_RA` in Hz (1250, 5000, or `15000·2^µ`).
    pub delta_f_ra_hz: f64,
    /// Numerology of the PRACH slot: `0` for long formats (the 15 kHz
    /// reference of §5.3.2), `µ` of `msg1-SubcarrierSpacing` for short ones.
    pub ra_mu: u8,
    /// OFDM symbols of the sequence part: `N_u / (1/Δf_RA)` (1, 2, 4, 6 or 12).
    pub n_repeat: usize,
    /// Cyclic-prefix length `N_CP^RA` in `T_c`.
    pub cp_tc: u64,
    /// Sequence duration `N_u` in `T_c` (all repetitions).
    pub seq_tc: u64,
    /// Nominal occasion duration in `T_c`: 1 / 3 / 3.5 / 1 ms for the long
    /// formats, `N_dur^RA` PUSCH-numerology symbols (`2192κ·2^-µ` each) for
    /// the short ones.
    pub nominal_tc: u64,
    /// Guard time `nominal_tc - cp_tc - seq_tc` (0 for the A formats).
    pub guard_tc: u64,
}

/// Sample counts of a preamble at sample rate `fs` (see
/// [`PreambleFormatParams::sample_layout`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachSampleLayout {
    /// `round(N_CP^RA · T_c · fs)`.
    pub cp_samples: usize,
    /// One sequence symbol: `fs / Δf_RA` (= the IFFT size at `fs`).
    pub symbol_samples: usize,
    /// Repetitions of the symbol.
    pub n_repeat: usize,
    /// Guard samples after the sequence up to the nominal occasion end.
    pub guard_samples: usize,
}

impl PrachSampleLayout {
    /// `cp_samples + n_repeat · symbol_samples` (the transmitted part).
    pub fn waveform_samples(&self) -> usize {
        self.cp_samples + self.n_repeat * self.symbol_samples
    }

    /// Transmitted part plus guard: the nominal occasion duration.
    pub fn nominal_samples(&self) -> usize {
        self.waveform_samples() + self.guard_samples
    }
}

impl PreambleFormatParams {
    /// `N_CS` table class of this format.
    pub fn ncs_scs(&self) -> PrachScs {
        match self.format {
            PreambleFormat::F0 | PreambleFormat::F1 | PreambleFormat::F2 => PrachScs::Khz1_25,
            PreambleFormat::F3 => PrachScs::Khz5,
            _ => PrachScs::Short,
        }
    }

    /// Sample counts at `fs`. `fs / Δf_RA` must be an integer (true for every
    /// standard NR rate: 15.36e6/1.25e3 = 12288, 11.52e6/1.25e3 = 9216,
    /// 23.04e6/1.25e3 = 18432, 30.72e6/30e3 = 1024, …).
    pub fn sample_layout(&self, fs: f64) -> Result<PrachSampleLayout, PrachError> {
        let sym = fs / self.delta_f_ra_hz;
        if (sym - sym.round()).abs() > 1e-6 * sym.max(1.0) {
            return Err(PrachError::NonIntegerSymbolLength {
                fs,
                delta_f_ra_hz: self.delta_f_ra_hz,
            });
        }
        let to_samples = |tc: u64| (tc as f64 * TC_SECONDS * fs).round() as usize;
        Ok(PrachSampleLayout {
            cp_samples: to_samples(self.cp_tc),
            symbol_samples: sym.round() as usize,
            n_repeat: self.n_repeat,
            guard_samples: to_samples(self.guard_tc),
        })
    }
}

/// Table 6.3.3.1-1 / 6.3.3.1-2 for `format`. `mu` is the PRACH numerology for
/// short formats (`msg1-SubcarrierSpacing`: Δf_RA = 15·2^µ kHz, 0..=3) and is
/// ignored for the long formats. Mixed formats are rejected: resolve them with
/// [`PreambleFormat::for_occasion`] first.
pub fn format_params(format: PreambleFormat, mu: u8) -> Result<PreambleFormatParams, PrachError> {
    use PreambleFormat::*;
    if format.is_mixed() {
        return Err(PrachError::MixedFormat(format));
    }
    // Table 6.3.3.1-1 (κ units): (Δf_RA, N_u, N_CP^RA, nominal duration).
    let long = |delta_f: f64, n_repeat: u64, sym_kappa: u64, cp_kappa: u64, nominal_kappa: u64| {
        let seq_tc = n_repeat * sym_kappa * KAPPA_TC;
        let cp_tc = cp_kappa * KAPPA_TC;
        let nominal_tc = nominal_kappa * KAPPA_TC;
        PreambleFormatParams {
            format,
            l_ra: 839,
            delta_f_ra_hz: delta_f,
            ra_mu: 0,
            n_repeat: n_repeat as usize,
            cp_tc,
            seq_tc,
            nominal_tc,
            guard_tc: nominal_tc - cp_tc - seq_tc,
        }
    };
    // Table 6.3.3.1-2 (κ·2^-µ units): N_u = n_repeat·2048, N_CP as listed,
    // nominal duration N_dur symbols of (2048 + 144)κ·2^-µ.
    let short =
        |n_repeat: u64, cp_kappa: u64, n_dur: u64| -> Result<PreambleFormatParams, PrachError> {
            if mu > 3 {
                return Err(PrachError::UnsupportedScs { mu });
            }
            let scale = |k: u64| (k * KAPPA_TC) >> mu;
            let seq_tc = scale(n_repeat * 2048);
            let cp_tc = scale(cp_kappa);
            let nominal_tc = scale(n_dur * 2192);
            Ok(PreambleFormatParams {
                format,
                l_ra: 139,
                delta_f_ra_hz: 15_000.0 * f64::from(1u32 << mu),
                ra_mu: mu,
                n_repeat: n_repeat as usize,
                cp_tc,
                seq_tc,
                nominal_tc,
                guard_tc: nominal_tc - cp_tc - seq_tc,
            })
        };
    match format {
        F0 => Ok(long(1250.0, 1, 24576, 3168, 30720)),
        F1 => Ok(long(1250.0, 2, 24576, 21024, 3 * 30720)),
        F2 => Ok(long(1250.0, 4, 24576, 4688, 7 * 30720 / 2)),
        F3 => Ok(long(5000.0, 4, 6144, 3168, 30720)),
        A1 => short(2, 288, 2),
        A2 => short(4, 576, 4),
        A3 => short(6, 864, 6),
        B1 => short(2, 216, 2),
        B2 => short(4, 360, 4),
        B3 => short(6, 504, 6),
        B4 => short(12, 936, 12),
        C0 => short(1, 1240, 2),
        C2 => short(4, 2048, 6),
        A1B1 | A2B2 | A3B3 => Err(PrachError::MixedFormat(format)),
    }
}

// ---------------------------------------------------------------------------
// Configuration tables (Tables 6.3.3.2-2 / 6.3.3.2-3)
// ---------------------------------------------------------------------------

/// One row of TS 38.211 Table 6.3.3.2-2 / 6.3.3.2-3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachConfigEntry {
    /// Preamble format (possibly mixed, see [`PreambleFormat::for_occasion`]).
    pub format: PreambleFormat,
    /// SFN period `x`: PRACH occasions are in frames with `n_SFN mod x = y`.
    pub x: u8,
    /// SFN offsets `y`.
    pub y: &'static [u8],
    /// Subframe numbers (15 kHz reference slots for FR1).
    pub subframes: &'static [u8],
    /// Starting symbol `l_0` (15 kHz symbols for long formats, Δf_RA symbols
    /// within the PRACH slot for short ones).
    pub start_symbol: u8,
    /// Number of PRACH slots within a subframe (short formats; 0 = "–").
    pub prach_slots_per_subframe: u8,
    /// Number of time-domain PRACH occasions within a PRACH slot `N_t^RA,slot`
    /// (short formats; 0 = "–").
    pub occasions_per_slot: u8,
    /// PRACH duration `N_dur^RA` in symbols (short formats; 0 = "–").
    pub duration: u8,
}

impl PrachConfigEntry {
    /// Time-domain occasions per PRACH slot (1 for the long formats).
    pub fn nof_time_occasions(&self) -> u8 {
        if self.format.is_long() {
            1
        } else {
            self.occasions_per_slot
        }
    }

    /// `n_SFN mod x = y` for some listed `y`.
    pub fn sfn_matches(&self, sfn: u16) -> bool {
        self.y.contains(&((sfn % u16::from(self.x)) as u8))
    }

    /// PRACH slot indices `n_slot^RA` within a subframe for PRACH numerology
    /// `ra_mu` (§5.3.2): `{0}` at 15 kHz (and for the long formats); at 30 kHz
    /// `{0, 1}` when the table lists two PRACH slots per subframe, else `{1}`.
    pub fn prach_slots(&self, ra_mu: u8) -> &'static [u8] {
        if self.format.is_long() || ra_mu == 0 {
            &[0]
        } else if self.prach_slots_per_subframe == 2 {
            &[0, 1]
        } else {
            &[1]
        }
    }
}

use PreambleFormat::{A1, A1B1, A2, A2B2, A3, A3B3, B1, B4, C0, C2, F0, F1, F2, F3};

#[allow(clippy::too_many_arguments)]
const fn e(
    format: PreambleFormat,
    x: u8,
    y: &'static [u8],
    subframes: &'static [u8],
    start_symbol: u8,
    prach_slots_per_subframe: u8,
    occasions_per_slot: u8,
    duration: u8,
) -> PrachConfigEntry {
    PrachConfigEntry {
        format,
        x,
        y,
        subframes,
        start_symbol,
        prach_slots_per_subframe,
        occasions_per_slot,
        duration,
    }
}

/// TS 38.211 Table 6.3.3.2-2: random access configurations for FR1 and paired
/// spectrum / supplementary uplink, indexed by `prach-ConfigurationIndex`.
#[rustfmt::skip]
pub static PRACH_CONFIG_FR1_PAIRED: [PrachConfigEntry; 256] = [
    /*   0 */ e(F0, 16, &[1], &[1], 0, 0, 0, 0),
    /*   1 */ e(F0, 16, &[1], &[4], 0, 0, 0, 0),
    /*   2 */ e(F0, 16, &[1], &[7], 0, 0, 0, 0),
    /*   3 */ e(F0, 16, &[1], &[9], 0, 0, 0, 0),
    /*   4 */ e(F0, 8, &[1], &[1], 0, 0, 0, 0),
    /*   5 */ e(F0, 8, &[1], &[4], 0, 0, 0, 0),
    /*   6 */ e(F0, 8, &[1], &[7], 0, 0, 0, 0),
    /*   7 */ e(F0, 8, &[1], &[9], 0, 0, 0, 0),
    /*   8 */ e(F0, 4, &[1], &[1], 0, 0, 0, 0),
    /*   9 */ e(F0, 4, &[1], &[4], 0, 0, 0, 0),
    /*  10 */ e(F0, 4, &[1], &[7], 0, 0, 0, 0),
    /*  11 */ e(F0, 4, &[1], &[9], 0, 0, 0, 0),
    /*  12 */ e(F0, 2, &[1], &[1], 0, 0, 0, 0),
    /*  13 */ e(F0, 2, &[1], &[4], 0, 0, 0, 0),
    /*  14 */ e(F0, 2, &[1], &[7], 0, 0, 0, 0),
    /*  15 */ e(F0, 2, &[1], &[9], 0, 0, 0, 0),
    /*  16 */ e(F0, 1, &[0], &[1], 0, 0, 0, 0),
    /*  17 */ e(F0, 1, &[0], &[4], 0, 0, 0, 0),
    /*  18 */ e(F0, 1, &[0], &[7], 0, 0, 0, 0),
    /*  19 */ e(F0, 1, &[0], &[1, 6], 0, 0, 0, 0),
    /*  20 */ e(F0, 1, &[0], &[2, 7], 0, 0, 0, 0),
    /*  21 */ e(F0, 1, &[0], &[3, 8], 0, 0, 0, 0),
    /*  22 */ e(F0, 1, &[0], &[1, 4, 7], 0, 0, 0, 0),
    /*  23 */ e(F0, 1, &[0], &[2, 5, 8], 0, 0, 0, 0),
    /*  24 */ e(F0, 1, &[0], &[3, 6, 9], 0, 0, 0, 0),
    /*  25 */ e(F0, 1, &[0], &[0, 2, 4, 6, 8], 0, 0, 0, 0),
    /*  26 */ e(F0, 1, &[0], &[1, 3, 5, 7, 9], 0, 0, 0, 0),
    /*  27 */ e(F0, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 0, 0, 0),
    /*  28 */ e(F1, 16, &[1], &[1], 0, 0, 0, 0),
    /*  29 */ e(F1, 16, &[1], &[4], 0, 0, 0, 0),
    /*  30 */ e(F1, 16, &[1], &[7], 0, 0, 0, 0),
    /*  31 */ e(F1, 16, &[1], &[9], 0, 0, 0, 0),
    /*  32 */ e(F1, 8, &[1], &[1], 0, 0, 0, 0),
    /*  33 */ e(F1, 8, &[1], &[4], 0, 0, 0, 0),
    /*  34 */ e(F1, 8, &[1], &[7], 0, 0, 0, 0),
    /*  35 */ e(F1, 8, &[1], &[9], 0, 0, 0, 0),
    /*  36 */ e(F1, 4, &[1], &[1], 0, 0, 0, 0),
    /*  37 */ e(F1, 4, &[1], &[4], 0, 0, 0, 0),
    /*  38 */ e(F1, 4, &[1], &[7], 0, 0, 0, 0),
    /*  39 */ e(F1, 4, &[1], &[9], 0, 0, 0, 0),
    /*  40 */ e(F1, 2, &[1], &[1], 0, 0, 0, 0),
    /*  41 */ e(F1, 2, &[1], &[4], 0, 0, 0, 0),
    /*  42 */ e(F1, 2, &[1], &[7], 0, 0, 0, 0),
    /*  43 */ e(F1, 2, &[1], &[9], 0, 0, 0, 0),
    /*  44 */ e(F1, 1, &[0], &[1], 0, 0, 0, 0),
    /*  45 */ e(F1, 1, &[0], &[4], 0, 0, 0, 0),
    /*  46 */ e(F1, 1, &[0], &[7], 0, 0, 0, 0),
    /*  47 */ e(F1, 1, &[0], &[1, 6], 0, 0, 0, 0),
    /*  48 */ e(F1, 1, &[0], &[2, 7], 0, 0, 0, 0),
    /*  49 */ e(F1, 1, &[0], &[3, 8], 0, 0, 0, 0),
    /*  50 */ e(F1, 1, &[0], &[1, 4, 7], 0, 0, 0, 0),
    /*  51 */ e(F1, 1, &[0], &[2, 5, 8], 0, 0, 0, 0),
    /*  52 */ e(F1, 1, &[0], &[3, 6, 9], 0, 0, 0, 0),
    /*  53 */ e(F2, 16, &[1], &[1], 0, 0, 0, 0),
    /*  54 */ e(F2, 8, &[1], &[1], 0, 0, 0, 0),
    /*  55 */ e(F2, 4, &[0], &[1], 0, 0, 0, 0),
    /*  56 */ e(F2, 2, &[0], &[1], 0, 0, 0, 0),
    /*  57 */ e(F2, 2, &[0], &[5], 0, 0, 0, 0),
    /*  58 */ e(F2, 1, &[0], &[1], 0, 0, 0, 0),
    /*  59 */ e(F2, 1, &[0], &[5], 0, 0, 0, 0),
    /*  60 */ e(F3, 16, &[1], &[1], 0, 0, 0, 0),
    /*  61 */ e(F3, 16, &[1], &[4], 0, 0, 0, 0),
    /*  62 */ e(F3, 16, &[1], &[7], 0, 0, 0, 0),
    /*  63 */ e(F3, 16, &[1], &[9], 0, 0, 0, 0),
    /*  64 */ e(F3, 8, &[1], &[1], 0, 0, 0, 0),
    /*  65 */ e(F3, 8, &[1], &[4], 0, 0, 0, 0),
    /*  66 */ e(F3, 8, &[1], &[7], 0, 0, 0, 0),
    /*  67 */ e(F3, 4, &[1], &[1], 0, 0, 0, 0),
    /*  68 */ e(F3, 4, &[1], &[4], 0, 0, 0, 0),
    /*  69 */ e(F3, 4, &[1], &[7], 0, 0, 0, 0),
    /*  70 */ e(F3, 4, &[1], &[9], 0, 0, 0, 0),
    /*  71 */ e(F3, 2, &[1], &[1], 0, 0, 0, 0),
    /*  72 */ e(F3, 2, &[1], &[4], 0, 0, 0, 0),
    /*  73 */ e(F3, 2, &[1], &[7], 0, 0, 0, 0),
    /*  74 */ e(F3, 2, &[1], &[9], 0, 0, 0, 0),
    /*  75 */ e(F3, 1, &[0], &[1], 0, 0, 0, 0),
    /*  76 */ e(F3, 1, &[0], &[4], 0, 0, 0, 0),
    /*  77 */ e(F3, 1, &[0], &[7], 0, 0, 0, 0),
    /*  78 */ e(F3, 1, &[0], &[1, 6], 0, 0, 0, 0),
    /*  79 */ e(F3, 1, &[0], &[2, 7], 0, 0, 0, 0),
    /*  80 */ e(F3, 1, &[0], &[3, 8], 0, 0, 0, 0),
    /*  81 */ e(F3, 1, &[0], &[1, 4, 7], 0, 0, 0, 0),
    /*  82 */ e(F3, 1, &[0], &[2, 5, 8], 0, 0, 0, 0),
    /*  83 */ e(F3, 1, &[0], &[3, 6, 9], 0, 0, 0, 0),
    /*  84 */ e(F3, 1, &[0], &[0, 2, 4, 6, 8], 0, 0, 0, 0),
    /*  85 */ e(F3, 1, &[0], &[1, 3, 5, 7, 9], 0, 0, 0, 0),
    /*  86 */ e(F3, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 0, 0, 0),
    /*  87 */ e(A1, 16, &[0], &[4, 9], 0, 1, 6, 2),
    /*  88 */ e(A1, 16, &[1], &[4], 0, 2, 6, 2),
    /*  89 */ e(A1, 8, &[0], &[4, 9], 0, 1, 6, 2),
    /*  90 */ e(A1, 8, &[1], &[4], 0, 2, 6, 2),
    /*  91 */ e(A1, 4, &[0], &[4, 9], 0, 1, 6, 2),
    /*  92 */ e(A1, 4, &[1], &[4, 9], 0, 1, 6, 2),
    /*  93 */ e(A1, 4, &[0], &[4], 0, 2, 6, 2),
    /*  94 */ e(A1, 2, &[0], &[4, 9], 0, 1, 6, 2),
    /*  95 */ e(A1, 2, &[0], &[1], 0, 2, 6, 2),
    /*  96 */ e(A1, 2, &[0], &[4], 0, 2, 6, 2),
    /*  97 */ e(A1, 2, &[0], &[7], 0, 2, 6, 2),
    /*  98 */ e(A1, 1, &[0], &[4], 0, 1, 6, 2),
    /*  99 */ e(A1, 1, &[0], &[1, 6], 0, 1, 6, 2),
    /* 100 */ e(A1, 1, &[0], &[4, 9], 0, 1, 6, 2),
    /* 101 */ e(A1, 1, &[0], &[1], 0, 2, 6, 2),
    /* 102 */ e(A1, 1, &[0], &[7], 0, 2, 6, 2),
    /* 103 */ e(A1, 1, &[0], &[2, 7], 0, 2, 6, 2),
    /* 104 */ e(A1, 1, &[0], &[1, 4, 7], 0, 2, 6, 2),
    /* 105 */ e(A1, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 6, 2),
    /* 106 */ e(A1, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 6, 2),
    /* 107 */ e(A1, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 6, 2),
    /* 108 */ e(A1B1, 2, &[0], &[4, 9], 0, 1, 7, 2),
    /* 109 */ e(A1B1, 2, &[0], &[4], 0, 2, 7, 2),
    /* 110 */ e(A1B1, 1, &[0], &[4], 0, 1, 7, 2),
    /* 111 */ e(A1B1, 1, &[0], &[1, 6], 0, 1, 7, 2),
    /* 112 */ e(A1B1, 1, &[0], &[4, 9], 0, 1, 7, 2),
    /* 113 */ e(A1B1, 1, &[0], &[1], 0, 2, 7, 2),
    /* 114 */ e(A1B1, 1, &[0], &[7], 0, 2, 7, 2),
    /* 115 */ e(A1B1, 1, &[0], &[1, 4, 7], 0, 2, 7, 2),
    /* 116 */ e(A1B1, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 7, 2),
    /* 117 */ e(A2, 16, &[1], &[2, 6, 9], 0, 1, 3, 4),
    /* 118 */ e(A2, 16, &[1], &[4], 0, 2, 3, 4),
    /* 119 */ e(A2, 8, &[1], &[2, 6, 9], 0, 1, 3, 4),
    /* 120 */ e(A2, 8, &[1], &[4], 0, 2, 3, 4),
    /* 121 */ e(A2, 4, &[0], &[2, 6, 9], 0, 1, 3, 4),
    /* 122 */ e(A2, 4, &[0], &[4], 0, 2, 3, 4),
    /* 123 */ e(A2, 2, &[1], &[2, 6, 9], 0, 1, 3, 4),
    /* 124 */ e(A2, 2, &[0], &[1], 0, 2, 3, 4),
    /* 125 */ e(A2, 2, &[0], &[4], 0, 2, 3, 4),
    /* 126 */ e(A2, 2, &[0], &[7], 0, 2, 3, 4),
    /* 127 */ e(A2, 1, &[0], &[4], 0, 1, 3, 4),
    /* 128 */ e(A2, 1, &[0], &[1, 6], 0, 1, 3, 4),
    /* 129 */ e(A2, 1, &[0], &[4, 9], 0, 1, 3, 4),
    /* 130 */ e(A2, 1, &[0], &[1], 0, 2, 3, 4),
    /* 131 */ e(A2, 1, &[0], &[7], 0, 2, 3, 4),
    /* 132 */ e(A2, 1, &[0], &[2, 7], 0, 2, 3, 4),
    /* 133 */ e(A2, 1, &[0], &[1, 4, 7], 0, 2, 3, 4),
    /* 134 */ e(A2, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 3, 4),
    /* 135 */ e(A2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 3, 4),
    /* 136 */ e(A2, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 3, 4),
    /* 137 */ e(A2B2, 2, &[1], &[2, 6, 9], 0, 1, 3, 4),
    /* 138 */ e(A2B2, 2, &[0], &[4], 0, 2, 3, 4),
    /* 139 */ e(A2B2, 1, &[0], &[4], 0, 1, 3, 4),
    /* 140 */ e(A2B2, 1, &[0], &[1, 6], 0, 1, 3, 4),
    /* 141 */ e(A2B2, 1, &[0], &[4, 9], 0, 1, 3, 4),
    /* 142 */ e(A2B2, 1, &[0], &[1], 0, 2, 3, 4),
    /* 143 */ e(A2B2, 1, &[0], &[7], 0, 2, 3, 4),
    /* 144 */ e(A2B2, 1, &[0], &[1, 4, 7], 0, 2, 3, 4),
    /* 145 */ e(A2B2, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 3, 4),
    /* 146 */ e(A2B2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 3, 4),
    /* 147 */ e(A3, 16, &[1], &[4, 9], 0, 1, 2, 6),
    /* 148 */ e(A3, 16, &[1], &[4], 0, 2, 2, 6),
    /* 149 */ e(A3, 8, &[1], &[4, 9], 0, 1, 2, 6),
    /* 150 */ e(A3, 8, &[1], &[4], 0, 2, 2, 6),
    /* 151 */ e(A3, 4, &[0], &[4, 9], 0, 1, 2, 6),
    /* 152 */ e(A3, 4, &[0], &[4], 0, 2, 2, 6),
    /* 153 */ e(A3, 2, &[1], &[2, 6, 9], 0, 2, 2, 6),
    /* 154 */ e(A3, 2, &[0], &[1], 0, 2, 2, 6),
    /* 155 */ e(A3, 2, &[0], &[4], 0, 2, 2, 6),
    /* 156 */ e(A3, 2, &[0], &[7], 0, 2, 2, 6),
    /* 157 */ e(A3, 1, &[0], &[4], 0, 1, 2, 6),
    /* 158 */ e(A3, 1, &[0], &[1, 6], 0, 1, 2, 6),
    /* 159 */ e(A3, 1, &[0], &[4, 9], 0, 1, 2, 6),
    /* 160 */ e(A3, 1, &[0], &[1], 0, 2, 2, 6),
    /* 161 */ e(A3, 1, &[0], &[7], 0, 2, 2, 6),
    /* 162 */ e(A3, 1, &[0], &[2, 7], 0, 2, 2, 6),
    /* 163 */ e(A3, 1, &[0], &[1, 4, 7], 0, 2, 2, 6),
    /* 164 */ e(A3, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 2, 6),
    /* 165 */ e(A3, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 2, 6),
    /* 166 */ e(A3, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 2, 6),
    /* 167 */ e(A3B3, 2, &[1], &[2, 6, 9], 0, 2, 2, 6),
    /* 168 */ e(A3B3, 2, &[0], &[4], 0, 2, 2, 6),
    /* 169 */ e(A3B3, 1, &[0], &[4], 0, 1, 2, 6),
    /* 170 */ e(A3B3, 1, &[0], &[1, 6], 0, 1, 2, 6),
    /* 171 */ e(A3B3, 1, &[0], &[4, 9], 0, 1, 2, 6),
    /* 172 */ e(A3B3, 1, &[0], &[1], 0, 2, 2, 6),
    /* 173 */ e(A3B3, 1, &[0], &[7], 0, 2, 2, 6),
    /* 174 */ e(A3B3, 1, &[0], &[1, 4, 7], 0, 2, 2, 6),
    /* 175 */ e(A3B3, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 2, 6),
    /* 176 */ e(A3B3, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 2, 6),
    /* 177 */ e(B1, 16, &[0], &[4, 9], 0, 1, 7, 2),
    /* 178 */ e(B1, 16, &[1], &[4], 0, 2, 7, 2),
    /* 179 */ e(B1, 8, &[0], &[4, 9], 0, 1, 7, 2),
    /* 180 */ e(B1, 8, &[1], &[4], 0, 2, 7, 2),
    /* 181 */ e(B1, 4, &[0], &[4, 9], 0, 1, 7, 2),
    /* 182 */ e(B1, 4, &[1], &[4, 9], 0, 1, 7, 2),
    /* 183 */ e(B1, 4, &[0], &[4], 0, 2, 7, 2),
    /* 184 */ e(B1, 2, &[0], &[4, 9], 0, 1, 7, 2),
    /* 185 */ e(B1, 2, &[0], &[1], 0, 2, 7, 2),
    /* 186 */ e(B1, 2, &[0], &[4], 0, 2, 7, 2),
    /* 187 */ e(B1, 2, &[0], &[7], 0, 2, 7, 2),
    /* 188 */ e(B1, 1, &[0], &[4], 0, 1, 7, 2),
    /* 189 */ e(B1, 1, &[0], &[1, 6], 0, 1, 7, 2),
    /* 190 */ e(B1, 1, &[0], &[4, 9], 0, 1, 7, 2),
    /* 191 */ e(B1, 1, &[0], &[1], 0, 2, 7, 2),
    /* 192 */ e(B1, 1, &[0], &[7], 0, 2, 7, 2),
    /* 193 */ e(B1, 1, &[0], &[2, 7], 0, 2, 7, 2),
    /* 194 */ e(B1, 1, &[0], &[1, 4, 7], 0, 2, 7, 2),
    /* 195 */ e(B1, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 7, 2),
    /* 196 */ e(B1, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 7, 2),
    /* 197 */ e(B1, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 7, 2),
    /* 198 */ e(B4, 16, &[0], &[4, 9], 0, 2, 1, 12),
    /* 199 */ e(B4, 16, &[1], &[4], 0, 2, 1, 12),
    /* 200 */ e(B4, 8, &[0], &[4, 9], 0, 2, 1, 12),
    /* 201 */ e(B4, 8, &[1], &[4], 0, 2, 1, 12),
    /* 202 */ e(B4, 4, &[0], &[4, 9], 0, 2, 1, 12),
    /* 203 */ e(B4, 4, &[0], &[4], 0, 2, 1, 12),
    /* 204 */ e(B4, 4, &[1], &[4, 9], 0, 2, 1, 12),
    /* 205 */ e(B4, 2, &[0], &[4, 9], 0, 2, 1, 12),
    /* 206 */ e(B4, 2, &[0], &[1], 0, 2, 1, 12),
    /* 207 */ e(B4, 2, &[0], &[4], 0, 2, 1, 12),
    /* 208 */ e(B4, 2, &[0], &[7], 0, 2, 1, 12),
    /* 209 */ e(B4, 1, &[0], &[1], 0, 2, 1, 12),
    /* 210 */ e(B4, 1, &[0], &[4], 0, 2, 1, 12),
    /* 211 */ e(B4, 1, &[0], &[7], 0, 2, 1, 12),
    /* 212 */ e(B4, 1, &[0], &[1, 6], 0, 2, 1, 12),
    /* 213 */ e(B4, 1, &[0], &[2, 7], 0, 2, 1, 12),
    /* 214 */ e(B4, 1, &[0], &[4, 9], 0, 2, 1, 12),
    /* 215 */ e(B4, 1, &[0], &[1, 4, 7], 0, 2, 1, 12),
    /* 216 */ e(B4, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 1, 12),
    /* 217 */ e(B4, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 1, 12),
    /* 218 */ e(B4, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 1, 12),
    /* 219 */ e(C0, 8, &[1], &[4], 0, 2, 7, 2),
    /* 220 */ e(C0, 4, &[1], &[4, 9], 0, 1, 7, 2),
    /* 221 */ e(C0, 4, &[0], &[4], 0, 2, 7, 2),
    /* 222 */ e(C0, 2, &[0], &[4, 9], 0, 1, 7, 2),
    /* 223 */ e(C0, 2, &[0], &[1], 0, 2, 7, 2),
    /* 224 */ e(C0, 2, &[0], &[4], 0, 2, 7, 2),
    /* 225 */ e(C0, 2, &[0], &[7], 0, 2, 7, 2),
    /* 226 */ e(C0, 1, &[0], &[4], 0, 1, 7, 2),
    /* 227 */ e(C0, 1, &[0], &[1, 6], 0, 1, 7, 2),
    /* 228 */ e(C0, 1, &[0], &[4, 9], 0, 1, 7, 2),
    /* 229 */ e(C0, 1, &[0], &[1], 0, 2, 7, 2),
    /* 230 */ e(C0, 1, &[0], &[7], 0, 2, 7, 2),
    /* 231 */ e(C0, 1, &[0], &[2, 7], 0, 2, 7, 2),
    /* 232 */ e(C0, 1, &[0], &[1, 4, 7], 0, 2, 7, 2),
    /* 233 */ e(C0, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 7, 2),
    /* 234 */ e(C0, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 7, 2),
    /* 235 */ e(C0, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 7, 2),
    /* 236 */ e(C2, 16, &[1], &[4, 9], 0, 1, 2, 6),
    /* 237 */ e(C2, 16, &[1], &[4], 0, 2, 2, 6),
    /* 238 */ e(C2, 8, &[1], &[4, 9], 0, 1, 2, 6),
    /* 239 */ e(C2, 8, &[1], &[4], 0, 2, 2, 6),
    /* 240 */ e(C2, 4, &[0], &[4, 9], 0, 1, 2, 6),
    /* 241 */ e(C2, 4, &[0], &[4], 0, 2, 2, 6),
    /* 242 */ e(C2, 2, &[1], &[2, 6, 9], 0, 2, 2, 6),
    /* 243 */ e(C2, 2, &[0], &[1], 0, 2, 2, 6),
    /* 244 */ e(C2, 2, &[0], &[4], 0, 2, 2, 6),
    /* 245 */ e(C2, 2, &[0], &[7], 0, 2, 2, 6),
    /* 246 */ e(C2, 1, &[0], &[4], 0, 1, 2, 6),
    /* 247 */ e(C2, 1, &[0], &[1, 6], 0, 1, 2, 6),
    /* 248 */ e(C2, 1, &[0], &[4, 9], 0, 1, 2, 6),
    /* 249 */ e(C2, 1, &[0], &[1], 0, 2, 2, 6),
    /* 250 */ e(C2, 1, &[0], &[7], 0, 2, 2, 6),
    /* 251 */ e(C2, 1, &[0], &[2, 7], 0, 2, 2, 6),
    /* 252 */ e(C2, 1, &[0], &[1, 4, 7], 0, 2, 2, 6),
    /* 253 */ e(C2, 1, &[0], &[0, 2, 4, 6, 8], 0, 2, 2, 6),
    /* 254 */ e(C2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 2, 6),
    /* 255 */ e(C2, 1, &[0], &[1, 3, 5, 7, 9], 0, 2, 2, 6),
];

/// TS 38.211 Table 6.3.3.2-3: random access configurations for FR1 and
/// unpaired spectrum, indexed by `prach-ConfigurationIndex`. Indices 256..=262
/// are the Rel-16 extension (`prach-ConfigurationIndex-v1610`).
#[rustfmt::skip]
pub static PRACH_CONFIG_FR1_UNPAIRED: [PrachConfigEntry; 263] = [
    /*   0 */ e(F0, 16, &[1], &[9], 0, 0, 0, 0),
    /*   1 */ e(F0, 8, &[1], &[9], 0, 0, 0, 0),
    /*   2 */ e(F0, 4, &[1], &[9], 0, 0, 0, 0),
    /*   3 */ e(F0, 2, &[0], &[9], 0, 0, 0, 0),
    /*   4 */ e(F0, 2, &[1], &[9], 0, 0, 0, 0),
    /*   5 */ e(F0, 2, &[0], &[4], 0, 0, 0, 0),
    /*   6 */ e(F0, 2, &[1], &[4], 0, 0, 0, 0),
    /*   7 */ e(F0, 1, &[0], &[9], 0, 0, 0, 0),
    /*   8 */ e(F0, 1, &[0], &[8], 0, 0, 0, 0),
    /*   9 */ e(F0, 1, &[0], &[7], 0, 0, 0, 0),
    /*  10 */ e(F0, 1, &[0], &[6], 0, 0, 0, 0),
    /*  11 */ e(F0, 1, &[0], &[5], 0, 0, 0, 0),
    /*  12 */ e(F0, 1, &[0], &[4], 0, 0, 0, 0),
    /*  13 */ e(F0, 1, &[0], &[3], 0, 0, 0, 0),
    /*  14 */ e(F0, 1, &[0], &[2], 0, 0, 0, 0),
    /*  15 */ e(F0, 1, &[0], &[1, 6], 0, 0, 0, 0),
    /*  16 */ e(F0, 1, &[0], &[1, 6], 7, 0, 0, 0),
    /*  17 */ e(F0, 1, &[0], &[4, 9], 0, 0, 0, 0),
    /*  18 */ e(F0, 1, &[0], &[3, 8], 0, 0, 0, 0),
    /*  19 */ e(F0, 1, &[0], &[2, 7], 0, 0, 0, 0),
    /*  20 */ e(F0, 1, &[0], &[8, 9], 0, 0, 0, 0),
    /*  21 */ e(F0, 1, &[0], &[4, 8, 9], 0, 0, 0, 0),
    /*  22 */ e(F0, 1, &[0], &[3, 4, 9], 0, 0, 0, 0),
    /*  23 */ e(F0, 1, &[0], &[7, 8, 9], 0, 0, 0, 0),
    /*  24 */ e(F0, 1, &[0], &[3, 4, 8, 9], 0, 0, 0, 0),
    /*  25 */ e(F0, 1, &[0], &[6, 7, 8, 9], 0, 0, 0, 0),
    /*  26 */ e(F0, 1, &[0], &[1, 4, 6, 9], 0, 0, 0, 0),
    /*  27 */ e(F0, 1, &[0], &[1, 3, 5, 7, 9], 0, 0, 0, 0),
    /*  28 */ e(F1, 16, &[1], &[7], 0, 0, 0, 0),
    /*  29 */ e(F1, 8, &[1], &[7], 0, 0, 0, 0),
    /*  30 */ e(F1, 4, &[1], &[7], 0, 0, 0, 0),
    /*  31 */ e(F1, 2, &[0], &[7], 0, 0, 0, 0),
    /*  32 */ e(F1, 2, &[1], &[7], 0, 0, 0, 0),
    /*  33 */ e(F1, 1, &[0], &[7], 0, 0, 0, 0),
    /*  34 */ e(F2, 16, &[1], &[6], 0, 0, 0, 0),
    /*  35 */ e(F2, 8, &[1], &[6], 0, 0, 0, 0),
    /*  36 */ e(F2, 4, &[1], &[6], 0, 0, 0, 0),
    /*  37 */ e(F2, 2, &[0], &[6], 7, 0, 0, 0),
    /*  38 */ e(F2, 2, &[1], &[6], 7, 0, 0, 0),
    /*  39 */ e(F2, 1, &[0], &[6], 7, 0, 0, 0),
    /*  40 */ e(F3, 16, &[1], &[9], 0, 0, 0, 0),
    /*  41 */ e(F3, 8, &[1], &[9], 0, 0, 0, 0),
    /*  42 */ e(F3, 4, &[1], &[9], 0, 0, 0, 0),
    /*  43 */ e(F3, 2, &[0], &[9], 0, 0, 0, 0),
    /*  44 */ e(F3, 2, &[1], &[9], 0, 0, 0, 0),
    /*  45 */ e(F3, 2, &[0], &[4], 0, 0, 0, 0),
    /*  46 */ e(F3, 2, &[1], &[4], 0, 0, 0, 0),
    /*  47 */ e(F3, 1, &[0], &[9], 0, 0, 0, 0),
    /*  48 */ e(F3, 1, &[0], &[8], 0, 0, 0, 0),
    /*  49 */ e(F3, 1, &[0], &[7], 0, 0, 0, 0),
    /*  50 */ e(F3, 1, &[0], &[6], 0, 0, 0, 0),
    /*  51 */ e(F3, 1, &[0], &[5], 0, 0, 0, 0),
    /*  52 */ e(F3, 1, &[0], &[4], 0, 0, 0, 0),
    /*  53 */ e(F3, 1, &[0], &[3], 0, 0, 0, 0),
    /*  54 */ e(F3, 1, &[0], &[2], 0, 0, 0, 0),
    /*  55 */ e(F3, 1, &[0], &[1, 6], 0, 0, 0, 0),
    /*  56 */ e(F3, 1, &[0], &[1, 6], 7, 0, 0, 0),
    /*  57 */ e(F3, 1, &[0], &[4, 9], 0, 0, 0, 0),
    /*  58 */ e(F3, 1, &[0], &[3, 8], 0, 0, 0, 0),
    /*  59 */ e(F3, 1, &[0], &[2, 7], 0, 0, 0, 0),
    /*  60 */ e(F3, 1, &[0], &[8, 9], 0, 0, 0, 0),
    /*  61 */ e(F3, 1, &[0], &[4, 8, 9], 0, 0, 0, 0),
    /*  62 */ e(F3, 1, &[0], &[3, 4, 9], 0, 0, 0, 0),
    /*  63 */ e(F3, 1, &[0], &[7, 8, 9], 0, 0, 0, 0),
    /*  64 */ e(F3, 1, &[0], &[3, 4, 8, 9], 0, 0, 0, 0),
    /*  65 */ e(F3, 1, &[0], &[1, 4, 6, 9], 0, 0, 0, 0),
    /*  66 */ e(F3, 1, &[0], &[1, 3, 5, 7, 9], 0, 0, 0, 0),
    /*  67 */ e(A1, 16, &[1], &[9], 0, 2, 6, 2),
    /*  68 */ e(A1, 8, &[1], &[9], 0, 2, 6, 2),
    /*  69 */ e(A1, 4, &[1], &[9], 0, 1, 6, 2),
    /*  70 */ e(A1, 2, &[1], &[9], 0, 1, 6, 2),
    /*  71 */ e(A1, 2, &[1], &[4, 9], 7, 1, 3, 2),
    /*  72 */ e(A1, 2, &[1], &[7, 9], 7, 1, 3, 2),
    /*  73 */ e(A1, 2, &[1], &[7, 9], 0, 1, 6, 2),
    /*  74 */ e(A1, 2, &[1], &[8, 9], 0, 2, 6, 2),
    /*  75 */ e(A1, 2, &[1], &[4, 9], 0, 2, 6, 2),
    /*  76 */ e(A1, 2, &[1], &[2, 3, 4, 7, 8, 9], 0, 1, 6, 2),
    /*  77 */ e(A1, 1, &[0], &[9], 0, 2, 6, 2),
    /*  78 */ e(A1, 1, &[0], &[9], 7, 1, 3, 2),
    /*  79 */ e(A1, 1, &[0], &[9], 0, 1, 6, 2),
    /*  80 */ e(A1, 1, &[0], &[8, 9], 0, 2, 6, 2),
    /*  81 */ e(A1, 1, &[0], &[4, 9], 0, 1, 6, 2),
    /*  82 */ e(A1, 1, &[0], &[7, 9], 7, 1, 3, 2),
    /*  83 */ e(A1, 1, &[0], &[3, 4, 8, 9], 0, 1, 6, 2),
    /*  84 */ e(A1, 1, &[0], &[3, 4, 8, 9], 0, 2, 6, 2),
    /*  85 */ e(A1, 1, &[0], &[1, 3, 5, 7, 9], 0, 1, 6, 2),
    /*  86 */ e(A1, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 7, 1, 3, 2),
    /*  87 */ e(A2, 16, &[1], &[9], 0, 2, 3, 4),
    /*  88 */ e(A2, 8, &[1], &[9], 0, 2, 3, 4),
    /*  89 */ e(A2, 4, &[1], &[9], 0, 1, 3, 4),
    /*  90 */ e(A2, 2, &[1], &[7, 9], 0, 1, 3, 4),
    /*  91 */ e(A2, 2, &[1], &[8, 9], 0, 2, 3, 4),
    /*  92 */ e(A2, 2, &[1], &[7, 9], 9, 1, 1, 4),
    /*  93 */ e(A2, 2, &[1], &[4, 9], 9, 1, 1, 4),
    /*  94 */ e(A2, 2, &[1], &[4, 9], 0, 2, 3, 4),
    /*  95 */ e(A2, 2, &[1], &[2, 3, 4, 7, 8, 9], 0, 1, 3, 4),
    /*  96 */ e(A2, 1, &[0], &[2], 0, 1, 3, 4),
    /*  97 */ e(A2, 1, &[0], &[7], 0, 1, 3, 4),
    /*  98 */ e(A2, 2, &[1], &[9], 0, 1, 3, 4),
    /*  99 */ e(A2, 1, &[0], &[9], 0, 2, 3, 4),
    /* 100 */ e(A2, 1, &[0], &[9], 9, 1, 1, 4),
    /* 101 */ e(A2, 1, &[0], &[9], 0, 1, 3, 4),
    /* 102 */ e(A2, 1, &[0], &[2, 7], 0, 1, 3, 4),
    /* 103 */ e(A2, 1, &[0], &[8, 9], 0, 2, 3, 4),
    /* 104 */ e(A2, 1, &[0], &[4, 9], 0, 1, 3, 4),
    /* 105 */ e(A2, 1, &[0], &[7, 9], 9, 1, 1, 4),
    /* 106 */ e(A2, 1, &[0], &[3, 4, 8, 9], 0, 1, 3, 4),
    /* 107 */ e(A2, 1, &[0], &[3, 4, 8, 9], 0, 2, 3, 4),
    /* 108 */ e(A2, 1, &[0], &[1, 3, 5, 7, 9], 0, 1, 3, 4),
    /* 109 */ e(A2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 9, 1, 1, 4),
    /* 110 */ e(A3, 16, &[1], &[9], 0, 2, 2, 6),
    /* 111 */ e(A3, 8, &[1], &[9], 0, 2, 2, 6),
    /* 112 */ e(A3, 4, &[1], &[9], 0, 1, 2, 6),
    /* 113 */ e(A3, 2, &[1], &[4, 9], 7, 1, 1, 6),
    /* 114 */ e(A3, 2, &[1], &[7, 9], 7, 1, 1, 6),
    /* 115 */ e(A3, 2, &[1], &[7, 9], 0, 1, 2, 6),
    /* 116 */ e(A3, 2, &[1], &[4, 9], 0, 2, 2, 6),
    /* 117 */ e(A3, 2, &[1], &[8, 9], 0, 2, 2, 6),
    /* 118 */ e(A3, 2, &[1], &[2, 3, 4, 7, 8, 9], 0, 1, 2, 6),
    /* 119 */ e(A3, 1, &[0], &[2], 0, 1, 2, 6),
    /* 120 */ e(A3, 1, &[0], &[7], 0, 1, 2, 6),
    /* 121 */ e(A3, 2, &[1], &[9], 0, 1, 2, 6),
    /* 122 */ e(A3, 1, &[0], &[9], 0, 2, 2, 6),
    /* 123 */ e(A3, 1, &[0], &[9], 7, 1, 1, 6),
    /* 124 */ e(A3, 1, &[0], &[9], 0, 1, 2, 6),
    /* 125 */ e(A3, 1, &[0], &[2, 7], 0, 1, 2, 6),
    /* 126 */ e(A3, 1, &[0], &[8, 9], 0, 2, 2, 6),
    /* 127 */ e(A3, 1, &[0], &[4, 9], 0, 1, 2, 6),
    /* 128 */ e(A3, 1, &[0], &[7, 9], 7, 1, 1, 6),
    /* 129 */ e(A3, 1, &[0], &[3, 4, 8, 9], 0, 1, 2, 6),
    /* 130 */ e(A3, 1, &[0], &[3, 4, 8, 9], 0, 2, 2, 6),
    /* 131 */ e(A3, 1, &[0], &[1, 3, 5, 7, 9], 0, 1, 2, 6),
    /* 132 */ e(A3, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 7, 1, 1, 6),
    /* 133 */ e(B1, 4, &[1], &[9], 2, 1, 6, 2),
    /* 134 */ e(B1, 2, &[1], &[9], 2, 1, 6, 2),
    /* 135 */ e(B1, 2, &[1], &[7, 9], 2, 1, 6, 2),
    /* 136 */ e(B1, 2, &[1], &[4, 9], 8, 1, 3, 2),
    /* 137 */ e(B1, 2, &[1], &[4, 9], 2, 2, 6, 2),
    /* 138 */ e(B1, 1, &[0], &[9], 2, 2, 6, 2),
    /* 139 */ e(B1, 1, &[0], &[9], 8, 1, 3, 2),
    /* 140 */ e(B1, 1, &[0], &[9], 2, 1, 6, 2),
    /* 141 */ e(B1, 1, &[0], &[8, 9], 2, 2, 6, 2),
    /* 142 */ e(B1, 1, &[0], &[4, 9], 2, 1, 6, 2),
    /* 143 */ e(B1, 1, &[0], &[7, 9], 8, 1, 3, 2),
    /* 144 */ e(B1, 1, &[0], &[1, 3, 5, 7, 9], 2, 1, 6, 2),
    /* 145 */ e(B4, 16, &[1], &[9], 0, 2, 1, 12),
    /* 146 */ e(B4, 8, &[1], &[9], 0, 2, 1, 12),
    /* 147 */ e(B4, 4, &[1], &[9], 2, 1, 1, 12),
    /* 148 */ e(B4, 2, &[1], &[9], 0, 1, 1, 12),
    /* 149 */ e(B4, 2, &[1], &[9], 2, 1, 1, 12),
    /* 150 */ e(B4, 2, &[1], &[7, 9], 2, 1, 1, 12),
    /* 151 */ e(B4, 2, &[1], &[4, 9], 2, 1, 1, 12),
    /* 152 */ e(B4, 2, &[1], &[4, 9], 0, 2, 1, 12),
    /* 153 */ e(B4, 2, &[1], &[8, 9], 0, 2, 1, 12),
    /* 154 */ e(B4, 2, &[1], &[2, 3, 4, 7, 8, 9], 0, 1, 1, 12),
    /* 155 */ e(B4, 1, &[0], &[1], 0, 1, 1, 12),
    /* 156 */ e(B4, 1, &[0], &[2], 0, 1, 1, 12),
    /* 157 */ e(B4, 1, &[0], &[4], 0, 1, 1, 12),
    /* 158 */ e(B4, 1, &[0], &[7], 0, 1, 1, 12),
    /* 159 */ e(B4, 1, &[0], &[9], 0, 1, 1, 12),
    /* 160 */ e(B4, 1, &[0], &[9], 2, 1, 1, 12),
    /* 161 */ e(B4, 1, &[0], &[9], 0, 2, 1, 12),
    /* 162 */ e(B4, 1, &[0], &[4, 9], 2, 1, 1, 12),
    /* 163 */ e(B4, 1, &[0], &[7, 9], 2, 1, 1, 12),
    /* 164 */ e(B4, 1, &[0], &[8, 9], 0, 2, 1, 12),
    /* 165 */ e(B4, 1, &[0], &[3, 4, 8, 9], 2, 1, 1, 12),
    /* 166 */ e(B4, 1, &[0], &[1, 3, 5, 7, 9], 2, 1, 1, 12),
    /* 167 */ e(B4, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 2, 1, 12),
    /* 168 */ e(B4, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 2, 1, 1, 12),
    /* 169 */ e(C0, 16, &[1], &[9], 2, 2, 6, 2),
    /* 170 */ e(C0, 8, &[1], &[9], 2, 2, 6, 2),
    /* 171 */ e(C0, 4, &[1], &[9], 2, 1, 6, 2),
    /* 172 */ e(C0, 2, &[1], &[9], 2, 1, 6, 2),
    /* 173 */ e(C0, 2, &[1], &[8, 9], 2, 2, 6, 2),
    /* 174 */ e(C0, 2, &[1], &[7, 9], 2, 1, 6, 2),
    /* 175 */ e(C0, 2, &[1], &[7, 9], 8, 1, 3, 2),
    /* 176 */ e(C0, 2, &[1], &[4, 9], 8, 1, 3, 2),
    /* 177 */ e(C0, 2, &[1], &[4, 9], 2, 2, 6, 2),
    /* 178 */ e(C0, 2, &[1], &[2, 3, 4, 7, 8, 9], 2, 1, 6, 2),
    /* 179 */ e(C0, 1, &[0], &[9], 2, 2, 6, 2),
    /* 180 */ e(C0, 1, &[0], &[9], 8, 1, 3, 2),
    /* 181 */ e(C0, 1, &[0], &[9], 2, 1, 6, 2),
    /* 182 */ e(C0, 1, &[0], &[8, 9], 2, 2, 6, 2),
    /* 183 */ e(C0, 1, &[0], &[4, 9], 2, 1, 6, 2),
    /* 184 */ e(C0, 1, &[0], &[7, 9], 8, 1, 3, 2),
    /* 185 */ e(C0, 1, &[0], &[3, 4, 8, 9], 2, 1, 6, 2),
    /* 186 */ e(C0, 1, &[0], &[3, 4, 8, 9], 2, 2, 6, 2),
    /* 187 */ e(C0, 1, &[0], &[1, 3, 5, 7, 9], 2, 1, 6, 2),
    /* 188 */ e(C0, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 8, 1, 3, 2),
    /* 189 */ e(C2, 16, &[1], &[9], 2, 2, 2, 6),
    /* 190 */ e(C2, 8, &[1], &[9], 2, 2, 2, 6),
    /* 191 */ e(C2, 4, &[1], &[9], 2, 1, 2, 6),
    /* 192 */ e(C2, 2, &[1], &[9], 2, 1, 2, 6),
    /* 193 */ e(C2, 2, &[1], &[8, 9], 2, 2, 2, 6),
    /* 194 */ e(C2, 2, &[1], &[7, 9], 2, 1, 2, 6),
    /* 195 */ e(C2, 2, &[1], &[7, 9], 8, 1, 1, 6),
    /* 196 */ e(C2, 2, &[1], &[4, 9], 8, 1, 1, 6),
    /* 197 */ e(C2, 2, &[1], &[4, 9], 2, 2, 2, 6),
    /* 198 */ e(C2, 2, &[1], &[2, 3, 4, 7, 8, 9], 2, 1, 2, 6),
    /* 199 */ e(C2, 8, &[1], &[9], 8, 2, 1, 6),
    /* 200 */ e(C2, 4, &[1], &[9], 8, 1, 1, 6),
    /* 201 */ e(C2, 1, &[0], &[9], 2, 2, 2, 6),
    /* 202 */ e(C2, 1, &[0], &[9], 8, 1, 1, 6),
    /* 203 */ e(C2, 1, &[0], &[9], 2, 1, 2, 6),
    /* 204 */ e(C2, 1, &[0], &[8, 9], 2, 2, 2, 6),
    /* 205 */ e(C2, 1, &[0], &[4, 9], 2, 1, 2, 6),
    /* 206 */ e(C2, 1, &[0], &[7, 9], 8, 1, 1, 6),
    /* 207 */ e(C2, 1, &[0], &[3, 4, 8, 9], 2, 1, 2, 6),
    /* 208 */ e(C2, 1, &[0], &[3, 4, 8, 9], 2, 2, 2, 6),
    /* 209 */ e(C2, 1, &[0], &[1, 3, 5, 7, 9], 2, 1, 2, 6),
    /* 210 */ e(C2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 8, 1, 1, 6),
    /* 211 */ e(A1B1, 2, &[1], &[9], 2, 1, 6, 2),
    /* 212 */ e(A1B1, 2, &[1], &[4, 9], 8, 1, 3, 2),
    /* 213 */ e(A1B1, 2, &[1], &[7, 9], 8, 1, 3, 2),
    /* 214 */ e(A1B1, 2, &[1], &[7, 9], 2, 1, 6, 2),
    /* 215 */ e(A1B1, 2, &[1], &[4, 9], 2, 2, 6, 2),
    /* 216 */ e(A1B1, 2, &[1], &[8, 9], 2, 2, 6, 2),
    /* 217 */ e(A1B1, 1, &[0], &[9], 2, 2, 6, 2),
    /* 218 */ e(A1B1, 1, &[0], &[9], 8, 1, 3, 2),
    /* 219 */ e(A1B1, 1, &[0], &[9], 2, 1, 6, 2),
    /* 220 */ e(A1B1, 1, &[0], &[8, 9], 2, 2, 6, 2),
    /* 221 */ e(A1B1, 1, &[0], &[4, 9], 2, 1, 6, 2),
    /* 222 */ e(A1B1, 1, &[0], &[7, 9], 8, 1, 3, 2),
    /* 223 */ e(A1B1, 1, &[0], &[3, 4, 8, 9], 2, 2, 6, 2),
    /* 224 */ e(A1B1, 1, &[0], &[1, 3, 5, 7, 9], 2, 1, 6, 2),
    /* 225 */ e(A1B1, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 8, 1, 3, 2),
    /* 226 */ e(A2B2, 2, &[1], &[9], 0, 1, 3, 4),
    /* 227 */ e(A2B2, 2, &[1], &[4, 9], 6, 1, 2, 4),
    /* 228 */ e(A2B2, 2, &[1], &[7, 9], 6, 1, 2, 4),
    /* 229 */ e(A2B2, 2, &[1], &[4, 9], 0, 2, 3, 4),
    /* 230 */ e(A2B2, 2, &[1], &[8, 9], 0, 2, 3, 4),
    /* 231 */ e(A2B2, 1, &[0], &[9], 0, 2, 3, 4),
    /* 232 */ e(A2B2, 1, &[0], &[9], 6, 1, 2, 4),
    /* 233 */ e(A2B2, 1, &[0], &[9], 0, 1, 3, 4),
    /* 234 */ e(A2B2, 1, &[0], &[8, 9], 0, 2, 3, 4),
    /* 235 */ e(A2B2, 1, &[0], &[4, 9], 0, 1, 3, 4),
    /* 236 */ e(A2B2, 1, &[0], &[7, 9], 6, 1, 2, 4),
    /* 237 */ e(A2B2, 1, &[0], &[3, 4, 8, 9], 0, 1, 3, 4),
    /* 238 */ e(A2B2, 1, &[0], &[3, 4, 8, 9], 0, 2, 3, 4),
    /* 239 */ e(A2B2, 1, &[0], &[1, 3, 5, 7, 9], 0, 1, 3, 4),
    /* 240 */ e(A2B2, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 6, 1, 2, 4),
    /* 241 */ e(A3B3, 2, &[1], &[9], 0, 1, 2, 6),
    /* 242 */ e(A3B3, 2, &[1], &[4, 9], 2, 1, 2, 6),
    /* 243 */ e(A3B3, 2, &[1], &[7, 9], 0, 1, 2, 6),
    /* 244 */ e(A3B3, 2, &[1], &[7, 9], 2, 1, 2, 6),
    /* 245 */ e(A3B3, 2, &[1], &[4, 9], 0, 2, 2, 6),
    /* 246 */ e(A3B3, 2, &[1], &[8, 9], 0, 2, 2, 6),
    /* 247 */ e(A3B3, 1, &[0], &[9], 0, 2, 2, 6),
    /* 248 */ e(A3B3, 1, &[0], &[9], 2, 1, 2, 6),
    /* 249 */ e(A3B3, 1, &[0], &[9], 0, 1, 2, 6),
    /* 250 */ e(A3B3, 1, &[0], &[8, 9], 0, 2, 2, 6),
    /* 251 */ e(A3B3, 1, &[0], &[4, 9], 0, 1, 2, 6),
    /* 252 */ e(A3B3, 1, &[0], &[7, 9], 2, 1, 2, 6),
    /* 253 */ e(A3B3, 1, &[0], &[3, 4, 8, 9], 0, 2, 2, 6),
    /* 254 */ e(A3B3, 1, &[0], &[1, 3, 5, 7, 9], 0, 1, 2, 6),
    /* 255 */ e(A3B3, 1, &[0], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 2, 1, 2, 6),
    /* 256 */ e(F0, 16, &[1], &[7], 0, 0, 0, 0),
    /* 257 */ e(F0, 8, &[1], &[7], 0, 0, 0, 0),
    /* 258 */ e(F0, 4, &[1], &[7], 0, 0, 0, 0),
    /* 259 */ e(F0, 2, &[0], &[7], 0, 0, 0, 0),
    /* 260 */ e(F0, 2, &[1], &[7], 0, 0, 0, 0),
    /* 261 */ e(F0, 2, &[0], &[2], 0, 0, 0, 0),
    /* 262 */ e(F0, 2, &[1], &[2], 0, 0, 0, 0),
];

/// Row `index` of Table 6.3.3.2-2 (`Fdd`) or 6.3.3.2-3 (`Tdd`).
pub fn prach_config(duplex: DuplexMode, index: u16) -> Option<&'static PrachConfigEntry> {
    match duplex {
        DuplexMode::Fdd => PRACH_CONFIG_FR1_PAIRED.get(usize::from(index)),
        DuplexMode::Tdd => PRACH_CONFIG_FR1_UNPAIRED.get(usize::from(index)),
    }
}

// ---------------------------------------------------------------------------
// Cell PRACH configuration and occasion enumeration
// ---------------------------------------------------------------------------

/// The PRACH configuration of a cell (`RACH-ConfigGeneric` and the initial UL
/// BWP numerology).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachConfig {
    /// `prach-ConfigurationIndex`.
    pub index: u16,
    pub duplex: DuplexMode,
    /// `µ` of the initial UL BWP / PUSCH subcarrier spacing (`Δf`).
    pub mu: u8,
    /// `µ` of `msg1-SubcarrierSpacing` (`Δf_RA = 15·2^µ` kHz). Used for the
    /// short formats only; the long formats fix Δf_RA at 1.25 / 5 kHz.
    pub msg1_scs_mu: u8,
    /// `msg1-FDM`: number of frequency-multiplexed occasions `M` (1, 2, 4, 8).
    pub msg1_fdm: u8,
    /// `msg1-FrequencyStart`: `n_RA^start`, offset of the lowest PRACH occasion
    /// from PRB 0 of the initial UL BWP, in PUSCH-numerology RBs.
    pub msg1_frequency_start: u16,
}

impl PrachConfig {
    /// The configuration table row.
    pub fn entry(&self) -> Result<&'static PrachConfigEntry, PrachError> {
        prach_config(self.duplex, self.index).ok_or(PrachError::InvalidConfigIndex {
            duplex: self.duplex,
            index: self.index,
        })
    }

    /// Table preamble format (possibly mixed).
    pub fn format(&self) -> Result<PreambleFormat, PrachError> {
        Ok(self.entry()?.format)
    }

    /// Numerology of the PRACH slot (§5.3.2): 0 for long formats, else
    /// `msg1-SubcarrierSpacing` (FR1: 15 or 30 kHz).
    pub fn ra_mu(&self) -> Result<u8, PrachError> {
        if self.format()?.is_long() {
            Ok(0)
        } else if self.msg1_scs_mu <= 1 {
            Ok(self.msg1_scs_mu)
        } else {
            Err(PrachError::UnsupportedScs {
                mu: self.msg1_scs_mu,
            })
        }
    }

    /// Format parameters of time-domain occasion `n_t` (resolves mixed formats).
    pub fn format_params(&self, n_t: u8) -> Result<PreambleFormatParams, PrachError> {
        let entry = self.entry()?;
        let format = entry.format.for_occasion(n_t, entry.nof_time_occasions());
        format_params(format, self.ra_mu()?)
    }

    fn check_fdm(&self) -> Result<(), PrachError> {
        if matches!(self.msg1_fdm, 1 | 2 | 4 | 8) {
            Ok(())
        } else {
            Err(PrachError::InvalidMsg1Fdm(self.msg1_fdm))
        }
    }

    /// Occasions (all `n_slot^RA`, `n_t`, `n_RA`) per configured subframe:
    /// `|prach_slots| · N_t · M`.
    pub fn occasions_per_subframe(&self) -> Result<u32, PrachError> {
        let entry = self.entry()?;
        let slots = entry.prach_slots(self.ra_mu()?).len() as u32;
        Ok(slots * u32::from(entry.nof_time_occasions()) * u32::from(self.msg1_fdm))
    }

    /// Occasions per frame that satisfies the `n_SFN mod x = y` condition.
    pub fn occasions_per_prach_frame(&self) -> Result<u32, PrachError> {
        Ok(self.occasions_per_subframe()? * self.entry()?.subframes.len() as u32)
    }
}

/// Start of OFDM symbol `l` (counted from the start of the subframe, normal
/// CP) at numerology `mu`, in `T_c` (§5.3.1): `Σ_{l'<l} (N_u + N_CP,l')` with
/// `N_u = 2048κ·2^-µ`, `N_CP,l' = 144κ·2^-µ + 16κ` for `l' ∈ {0, 7·2^µ}` and
/// `144κ·2^-µ` otherwise. For the PRACH this is `t_start^RA` of §5.3.2 with
/// `l = l_0 + n_t·N_dur^RA + 14·n_slot^RA` (short formats, `µ` of Δf_RA) or
/// `l = l_0` at `µ = 0` (long formats).
pub fn symbol_start_tc(mu: u8, l: u32) -> u64 {
    let sym = (2048 * KAPPA_TC) >> mu;
    let cp = (144 * KAPPA_TC) >> mu;
    let long_cp_period = 7u32 << mu;
    let extra = (0..l).filter(|&l2| l2 % long_cp_period == 0).count() as u64 * 16 * KAPPA_TC;
    u64::from(l) * (sym + cp) + extra
}

/// One PRACH occasion of a cell (TS 38.211 §6.3.3.2; TS 38.321 §5.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachOccasionRef {
    /// Preamble format of this occasion (mixed entries resolved).
    pub format: PreambleFormat,
    pub sfn: u16,
    /// Subframe 0..10.
    pub subframe: u8,
    /// PRACH slot within the subframe `n_slot^RA` (0 at 15 kHz / long formats,
    /// 0 or 1 at 30 kHz).
    pub prach_slot_in_subframe: u8,
    /// The PRACH slot, at the PRACH-slot numerology (`ra_mu`).
    pub slot: SlotPoint,
    /// First symbol of the occasion within the PRACH slot
    /// (`l_0 + n_t·N_dur^RA`, 0..14; `l_0` for long formats).
    pub start_symbol: u8,
    /// Time-domain occasion index `n_t` within the PRACH slot.
    pub time_index: u8,
    /// Frequency-domain occasion index `n_RA` (0..msg1-FDM).
    pub freq_index: u8,
    /// `t_start^RA`: start of the occasion from the start of its subframe, in
    /// `T_c` (see [`symbol_start_tc`]).
    pub start_tc: u64,
}

impl PrachOccasionRef {
    /// RA-RNTI `s_id`: first OFDM symbol of the occasion (0..14).
    pub fn s_id(&self) -> u16 {
        u16::from(self.start_symbol)
    }

    /// RA-RNTI `t_id`: index of the first slot of the occasion in the frame,
    /// counted in slots of the PRACH-slot numerology (15 kHz for long formats,
    /// `msg1-SubcarrierSpacing` for short ones; TS 38.321 §5.1.3 with
    /// TS 38.211 §5.3.2). 0..80.
    pub fn t_id(&self) -> u16 {
        self.slot.slot
    }

    /// RA-RNTI `f_id`: frequency-domain occasion index (0..8).
    pub fn f_id(&self) -> u16 {
        u16::from(self.freq_index)
    }

    /// `RA-RNTI = 1 + s_id + 14·t_id + 14·80·f_id + 14·80·8·ul_carrier_id`
    /// (TS 38.321 §5.1.3); `ul_carrier_id` = 1 for a SUL carrier.
    pub fn ra_rnti(&self, sul: bool) -> u16 {
        1 + self.s_id() + 14 * self.t_id() + 14 * 80 * self.f_id() + 14 * 80 * 8 * u16::from(sul)
    }

    /// Start of the occasion in samples from the start of its subframe at `fs`.
    pub fn start_sample_in_subframe(&self, fs: f64) -> usize {
        (self.start_tc as f64 * TC_SECONDS * fs).round() as usize
    }
}

/// All occasions in subframe `subframe` of frame `sfn` (empty when the frame
/// or subframe is not a PRACH one), ordered by PRACH slot, then `n_t`, then
/// `n_RA` — the ordering TS 38.213 §8.1 uses for the SS/PBCH block association
/// (frequency first, then time within the slot, then slots).
pub fn prach_occasions_in_subframe(
    cfg: &PrachConfig,
    sfn: u16,
    subframe: u8,
) -> Result<Vec<PrachOccasionRef>, PrachError> {
    cfg.check_fdm()?;
    let entry = cfg.entry()?;
    let ra_mu = cfg.ra_mu()?;
    let mut out = Vec::new();
    if !entry.sfn_matches(sfn) || !entry.subframes.contains(&subframe) {
        return Ok(out);
    }
    let n_t_total = entry.nof_time_occasions();
    let dur = u32::from(entry.duration);
    let ra_num = Numerology::new(ra_mu);
    for &n_slot in entry.prach_slots(ra_mu) {
        let slot = SlotPoint::new(
            ra_num,
            sfn,
            u16::from(subframe) * ra_num.slots_per_subframe() as u16 + u16::from(n_slot),
        );
        for n_t in 0..n_t_total {
            let start_symbol = if entry.format.is_long() {
                u32::from(entry.start_symbol)
            } else {
                u32::from(entry.start_symbol) + u32::from(n_t) * dur
            };
            let l = start_symbol + 14 * u32::from(n_slot);
            let start_tc = symbol_start_tc(ra_mu, l);
            for n_ra in 0..cfg.msg1_fdm {
                out.push(PrachOccasionRef {
                    format: entry.format.for_occasion(n_t, n_t_total),
                    sfn,
                    subframe,
                    prach_slot_in_subframe: n_slot,
                    slot,
                    start_symbol: start_symbol as u8,
                    time_index: n_t,
                    freq_index: n_ra,
                    start_tc,
                });
            }
        }
    }
    Ok(out)
}

/// The occasions that *start* within `slot` (at whatever numerology the
/// caller's `SlotPoint` uses): a 30 kHz query slot sees only the PRACH slot it
/// overlaps; a 15 kHz query slot sees the whole subframe. For the long formats
/// the occasion belongs to the query slot containing `t_start^RA` (e.g. a
/// format-0 occasion with `l_0 = 7` starts in the second 30 kHz slot).
pub fn prach_occasions_in_slot(
    cfg: &PrachConfig,
    slot: SlotPoint,
) -> Result<Vec<PrachOccasionRef>, PrachError> {
    let sps = u64::from(slot.numerology.slots_per_subframe());
    let sis = u64::from(slot.slot_in_subframe());
    let lo = sis * SUBFRAME_TC / sps;
    let hi = (sis + 1) * SUBFRAME_TC / sps;
    let mut occ = prach_occasions_in_subframe(cfg, slot.sfn, slot.subframe() as u8)?;
    occ.retain(|o| (lo..hi).contains(&o.start_tc));
    Ok(occ)
}

/// Whether at least one PRACH occasion starts in `slot`.
pub fn is_prach_slot(cfg: &PrachConfig, slot: SlotPoint) -> Result<bool, PrachError> {
    Ok(!prach_occasions_in_slot(cfg, slot)?.is_empty())
}

/// The earliest occasion starting in slot `from + lead_slots` or later that
/// passes `accept` (e.g. an SS/PBCH block association check via
/// [`occasion_ssb_ordinals`], or a TDD UL-slot check). Searches 17 frames
/// ahead, which covers the longest SFN period (`x = 16`).
pub fn next_prach_occasion(
    cfg: &PrachConfig,
    from: SlotPoint,
    lead_slots: u32,
    mut accept: impl FnMut(&PrachOccasionRef) -> bool,
) -> Result<Option<PrachOccasionRef>, PrachError> {
    let start = from.add(u64::from(lead_slots));
    let horizon = 17 * u64::from(from.slots_per_frame());
    for n in 0..horizon {
        let slot = start.add(n);
        if let Some(o) = prach_occasions_in_slot(cfg, slot)?
            .into_iter()
            .find(&mut accept)
        {
            return Ok(Some(o));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Frequency mapping (§5.3.2, Table 6.3.3.2-1)
// ---------------------------------------------------------------------------

/// Table 6.3.3.2-1 row: PRACH bandwidth in PUSCH-numerology RBs and the
/// subcarrier offset `k̄` of the sequence within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrachFreqMapping {
    /// `N_RB^RA`: RBs (at Δf) occupied by one frequency-domain occasion.
    pub n_rb_ra: u16,
    /// `k̄`: offset of subcarrier `k = 0` from the start of the occasion's RBs,
    /// in units of Δf_RA.
    pub k_bar: u16,
    /// `K = Δf / Δf_RA` (PRACH subcarriers per PUSCH subcarrier).
    pub k: u16,
}

impl PrachFreqMapping {
    /// Width of one frequency-domain occasion in Δf_RA subcarriers:
    /// `N_RB^RA · 12 · K`.
    pub fn width_ra_sc(&self) -> usize {
        usize::from(self.n_rb_ra) * 12 * usize::from(self.k)
    }
}

/// Table 6.3.3.2-1 for PRACH subcarrier spacing `delta_f_ra_hz` and PUSCH
/// numerology `mu_pusch`.
pub fn prach_frequency_mapping(
    delta_f_ra_hz: f64,
    mu_pusch: u8,
) -> Result<PrachFreqMapping, PrachError> {
    let ra_khz = (delta_f_ra_hz / 1000.0 * 100.0).round() as u32; // ×100 to keep 1.25
    let (n_rb_ra, k_bar) = match (ra_khz, mu_pusch) {
        (125, 0) => (6, 7),
        (125, 1) => (3, 1),
        (125, 2) => (2, 133),
        (500, 0) => (24, 12),
        (500, 1) => (12, 10),
        (500, 2) => (6, 7),
        (1500, 0) => (12, 2),
        (1500, 1) => (6, 2),
        (1500, 2) => (3, 2),
        (3000, 0) => (24, 2),
        (3000, 1) => (12, 2),
        (3000, 2) => (6, 2),
        (6000, 2) => (12, 2),
        (6000, 3) => (6, 2),
        (12000, 2) => (24, 2),
        (12000, 3) => (12, 2),
        _ => {
            return Err(PrachError::NoFrequencyMapping {
                delta_f_ra_hz,
                mu_pusch,
            })
        }
    };
    let delta_f = 15_000.0 * f64::from(1u32 << mu_pusch);
    let k = (delta_f / delta_f_ra_hz).round() as u16;
    Ok(PrachFreqMapping { n_rb_ra, k_bar, k })
}

/// Index of PRACH subcarrier `k = 0` of frequency-domain occasion `n_ra`, in
/// units of Δf_RA, relative to the reference the caller expresses
/// `bwp_start_rb` in (§5.3.2):
/// ```text
///   K·12·(bwp_start_rb + n_RA^start + n_RA·N_RB^RA) + k̄
/// ```
/// With `bwp_start_rb` = offset of the initial UL BWP's first CRB from the
/// carrier centre (`N_BWP^start − N_grid^start − N_grid^size/2`, in RBs at Δf,
/// usually negative) the result is the offset from DC, i.e. `K·k_1 + k̄` of
/// §5.3.2, directly usable as an IFFT bin (mod the IFFT size). With
/// `bwp_start_rb = 0` it is relative to the BWP start.
pub fn prach_subcarrier_offset(
    fm: &PrachFreqMapping,
    msg1_frequency_start: u16,
    n_ra: u8,
    bwp_start_rb: i32,
) -> i64 {
    let rb = i64::from(bwp_start_rb)
        + i64::from(msg1_frequency_start)
        + i64::from(n_ra) * i64::from(fm.n_rb_ra);
    i64::from(fm.k) * 12 * rb + i64::from(fm.k_bar)
}

// ---------------------------------------------------------------------------
// SS/PBCH block ↔ PRACH occasion association (TS 38.213 §8.1)
// ---------------------------------------------------------------------------

/// `ssb-perRACH-Occasion` (TS 38.331 `ssb-perRACH-OccasionAndCB-PreamblesPerSSB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsbPerRo {
    OneEighth,
    OneFourth,
    OneHalf,
    One,
    Two,
    Four,
    Eight,
    Sixteen,
}

impl SsbPerRo {
    /// `N ≥ 1`: SS/PBCH blocks per occasion.
    pub const fn ssbs_per_ro(self) -> u8 {
        match self {
            Self::OneEighth | Self::OneFourth | Self::OneHalf | Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
            Self::Sixteen => 16,
        }
    }

    /// `N < 1`: consecutive occasions per SS/PBCH block (`1/N`).
    pub const fn ros_per_ssb(self) -> u8 {
        match self {
            Self::OneEighth => 8,
            Self::OneFourth => 4,
            Self::OneHalf => 2,
            _ => 1,
        }
    }
}

/// Occasions of one SSB→RO mapping cycle: `ceil(n_ssb_tx / N)` for `N ≥ 1`,
/// `n_ssb_tx · (1/N)` otherwise.
fn mapping_cycle_ros(ssb_per_ro: SsbPerRo, n_ssb_tx: u8) -> u32 {
    let n = u32::from(ssb_per_ro.ssbs_per_ro());
    u32::from(n_ssb_tx).div_ceil(n) * u32::from(ssb_per_ro.ros_per_ssb())
}

/// Association period in frames (Table 8.1-1): the smallest allowed number of
/// PRACH configuration periods (`x` frames each) in which every one of the
/// `n_ssb_tx` transmitted SS/PBCH blocks is mapped at least once. Assumes all
/// configured occasions are valid (always true for paired spectrum; for TDD
/// the caller must have chosen a configuration whose occasions are in UL
/// symbols).
pub fn association_period_frames(
    cfg: &PrachConfig,
    ssb_per_ro: SsbPerRo,
    n_ssb_tx: u8,
) -> Result<u16, PrachError> {
    let x = cfg.entry()?.x;
    let candidates: &[u16] = match x {
        1 => &[1, 2, 4, 8, 16],
        2 => &[1, 2, 4, 8],
        4 => &[1, 2, 4],
        8 => &[1, 2],
        _ => &[1],
    };
    let per_frame = cfg.occasions_per_prach_frame()?;
    let needed = mapping_cycle_ros(ssb_per_ro, n_ssb_tx);
    candidates
        .iter()
        .map(|&n| n * u16::from(x))
        .find(|&frames| u32::from(frames / u16::from(x)) * per_frame >= needed)
        .ok_or(PrachError::InvalidSsbMapping)
}

/// Ordinal of `occ` among the occasions of its association period (periods
/// start at `SFN mod period = 0`), frequency first, then time, then slots,
/// then frames.
fn occasion_ordinal(
    cfg: &PrachConfig,
    occ: &PrachOccasionRef,
    period_frames: u16,
) -> Result<u32, PrachError> {
    let entry = cfg.entry()?;
    let per_frame = cfg.occasions_per_prach_frame()?;
    let per_subframe = cfg.occasions_per_subframe()?;
    let first_sfn = occ.sfn - occ.sfn % period_frames;
    let frames_before = (first_sfn..occ.sfn)
        .filter(|&s| entry.sfn_matches(s))
        .count() as u32;
    let subframes_before = entry
        .subframes
        .iter()
        .filter(|&&s| s < occ.subframe)
        .count() as u32;
    let n_t = u32::from(entry.nof_time_occasions());
    let m = u32::from(cfg.msg1_fdm);
    let slot_pos = entry
        .prach_slots(cfg.ra_mu()?)
        .iter()
        .position(|&s| s == occ.prach_slot_in_subframe)
        .unwrap_or(0) as u32;
    let in_subframe = (slot_pos * n_t + u32::from(occ.time_index)) * m + u32::from(occ.freq_index);
    Ok(frames_before * per_frame + subframes_before * per_subframe + in_subframe)
}

/// SS/PBCH blocks mapped to occasion `occ` (TS 38.213 §8.1): `Some((first,
/// count))` are ordinals among the `n_ssb_tx` transmitted SS/PBCH blocks in
/// increasing SSB-index order (map them back through `ssb-PositionsInBurst`);
/// `None` when the occasion is in the tail of the association period after the
/// last complete mapping cycle (not mapped to any SS/PBCH block).
pub fn occasion_ssb_ordinals(
    cfg: &PrachConfig,
    ssb_per_ro: SsbPerRo,
    n_ssb_tx: u8,
    occ: &PrachOccasionRef,
) -> Result<Option<(u8, u8)>, PrachError> {
    let period = association_period_frames(cfg, ssb_per_ro, n_ssb_tx)?;
    let total = u32::from(period / u16::from(cfg.entry()?.x)) * cfg.occasions_per_prach_frame()?;
    let cycle = mapping_cycle_ros(ssb_per_ro, n_ssb_tx);
    let k = occasion_ordinal(cfg, occ, period)?;
    if k >= total - total % cycle {
        return Ok(None);
    }
    let kc = k % cycle;
    let n = ssb_per_ro.ssbs_per_ro();
    if n > 1 {
        let first = (kc as u8) * n;
        Ok(Some((first, n.min(n_ssb_tx - first))))
    } else {
        Ok(Some(((kc / u32::from(ssb_per_ro.ros_per_ssb())) as u8, 1)))
    }
}

/// Contention-based preamble indices for the SS/PBCH block in position
/// `ssb_in_ro` (0..N) of an occasion (TS 38.321 §5.1.2 / TS 38.213 §8.1): for
/// `N ≥ 1` SSB `n` owns preambles `n·⌊totalNumberOfRA-Preambles/N⌋ ..` and the
/// first `cb_preambles_per_ssb` of them are contention based; for `N < 1`
/// they start at 0.
pub fn cb_preamble_range(
    ssb_per_ro: SsbPerRo,
    ssb_in_ro: u8,
    total_preambles: u8,
    cb_preambles_per_ssb: u8,
) -> core::ops::Range<u8> {
    let n = ssb_per_ro.ssbs_per_ro();
    let start = ssb_in_ro * (total_preambles / n);
    start..start + cb_preambles_per_ssb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn row(
        duplex: DuplexMode,
        index: u16,
        format: PreambleFormat,
        x: u8,
        y: u8,
        subframes: &[u8],
        start: u8,
        slots: u8,
        n_t: u8,
        dur: u8,
    ) {
        let e = prach_config(duplex, index).unwrap();
        assert_eq!(
            (
                e.format,
                e.x,
                e.y,
                e.subframes,
                e.start_symbol,
                e.prach_slots_per_subframe,
                e.occasions_per_slot,
                e.duration
            ),
            (format, x, &[y][..], subframes, start, slots, n_t, dur),
            "{duplex:?} index {index}"
        );
    }

    /// Hand-verified rows of Table 6.3.3.2-2 (FR1 paired / SUL).
    #[test]
    fn table_fdd_spot_checks() {
        use DuplexMode::Fdd as D;
        assert_eq!(PRACH_CONFIG_FR1_PAIRED.len(), 256);
        row(D, 0, F0, 16, 1, &[1], 0, 0, 0, 0);
        row(D, 1, F0, 16, 1, &[4], 0, 0, 0, 0);
        row(D, 3, F0, 16, 1, &[9], 0, 0, 0, 0);
        row(D, 16, F0, 1, 0, &[1], 0, 0, 0, 0);
        row(D, 19, F0, 1, 0, &[1, 6], 0, 0, 0, 0);
        row(D, 25, F0, 1, 0, &[0, 2, 4, 6, 8], 0, 0, 0, 0);
        row(D, 27, F0, 1, 0, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 0, 0, 0);
        row(D, 28, F1, 16, 1, &[1], 0, 0, 0, 0);
        row(D, 52, F1, 1, 0, &[3, 6, 9], 0, 0, 0, 0);
        row(D, 53, F2, 16, 1, &[1], 0, 0, 0, 0);
        row(D, 55, F2, 4, 0, &[1], 0, 0, 0, 0);
        row(D, 59, F2, 1, 0, &[5], 0, 0, 0, 0);
        row(D, 60, F3, 16, 1, &[1], 0, 0, 0, 0);
        row(D, 86, F3, 1, 0, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 0, 0, 0);
        row(D, 87, A1, 16, 0, &[4, 9], 0, 1, 6, 2);
        row(D, 88, A1, 16, 1, &[4], 0, 2, 6, 2);
        row(D, 95, A1, 2, 0, &[1], 0, 2, 6, 2);
        row(
            D,
            106,
            A1,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            0,
            2,
            6,
            2,
        );
        row(D, 108, A1B1, 2, 0, &[4, 9], 0, 1, 7, 2);
        row(D, 116, A1B1, 1, 0, &[0, 2, 4, 6, 8], 0, 2, 7, 2);
        row(D, 117, A2, 16, 1, &[2, 6, 9], 0, 1, 3, 4);
        row(D, 136, A2, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 3, 4);
        row(D, 137, A2B2, 2, 1, &[2, 6, 9], 0, 1, 3, 4);
        row(
            D,
            146,
            A2B2,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            0,
            2,
            3,
            4,
        );
        row(D, 147, A3, 16, 1, &[4, 9], 0, 1, 2, 6);
        row(D, 166, A3, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 2, 6);
        row(D, 167, A3B3, 2, 1, &[2, 6, 9], 0, 2, 2, 6);
        row(
            D,
            176,
            A3B3,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            0,
            2,
            2,
            6,
        );
        row(D, 177, B1, 16, 0, &[4, 9], 0, 1, 7, 2);
        row(D, 197, B1, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 7, 2);
        row(D, 198, B4, 16, 0, &[4, 9], 0, 2, 1, 12);
        row(D, 204, B4, 4, 1, &[4, 9], 0, 2, 1, 12);
        row(D, 218, B4, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 1, 12);
        row(D, 219, C0, 8, 1, &[4], 0, 2, 7, 2);
        row(D, 220, C0, 4, 1, &[4, 9], 0, 1, 7, 2);
        row(D, 235, C0, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 7, 2);
        row(D, 236, C2, 16, 1, &[4, 9], 0, 1, 2, 6);
        row(D, 242, C2, 2, 1, &[2, 6, 9], 0, 2, 2, 6);
        row(D, 255, C2, 1, 0, &[1, 3, 5, 7, 9], 0, 2, 2, 6);
        assert!(prach_config(DuplexMode::Fdd, 256).is_none());
    }

    /// Hand-verified rows of Table 6.3.3.2-3 (FR1 unpaired).
    #[test]
    fn table_tdd_spot_checks() {
        use DuplexMode::Tdd as D;
        assert_eq!(PRACH_CONFIG_FR1_UNPAIRED.len(), 263);
        row(D, 0, F0, 16, 1, &[9], 0, 0, 0, 0);
        row(D, 3, F0, 2, 0, &[9], 0, 0, 0, 0);
        row(D, 7, F0, 1, 0, &[9], 0, 0, 0, 0);
        row(D, 14, F0, 1, 0, &[2], 0, 0, 0, 0);
        row(D, 16, F0, 1, 0, &[1, 6], 7, 0, 0, 0);
        row(D, 21, F0, 1, 0, &[4, 8, 9], 0, 0, 0, 0);
        row(D, 27, F0, 1, 0, &[1, 3, 5, 7, 9], 0, 0, 0, 0);
        row(D, 28, F1, 16, 1, &[7], 0, 0, 0, 0);
        row(D, 33, F1, 1, 0, &[7], 0, 0, 0, 0);
        row(D, 34, F2, 16, 1, &[6], 0, 0, 0, 0);
        row(D, 37, F2, 2, 0, &[6], 7, 0, 0, 0);
        row(D, 39, F2, 1, 0, &[6], 7, 0, 0, 0);
        row(D, 40, F3, 16, 1, &[9], 0, 0, 0, 0);
        row(D, 66, F3, 1, 0, &[1, 3, 5, 7, 9], 0, 0, 0, 0);
        row(D, 67, A1, 16, 1, &[9], 0, 2, 6, 2);
        row(D, 71, A1, 2, 1, &[4, 9], 7, 1, 3, 2);
        row(D, 76, A1, 2, 1, &[2, 3, 4, 7, 8, 9], 0, 1, 6, 2);
        row(D, 86, A1, 1, 0, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 7, 1, 3, 2);
        row(D, 87, A2, 16, 1, &[9], 0, 2, 3, 4);
        row(D, 92, A2, 2, 1, &[7, 9], 9, 1, 1, 4);
        row(D, 95, A2, 2, 1, &[2, 3, 4, 7, 8, 9], 0, 1, 3, 4);
        row(
            D,
            109,
            A2,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            9,
            1,
            1,
            4,
        );
        row(D, 110, A3, 16, 1, &[9], 0, 2, 2, 6);
        row(D, 113, A3, 2, 1, &[4, 9], 7, 1, 1, 6);
        row(
            D,
            132,
            A3,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            7,
            1,
            1,
            6,
        );
        row(D, 133, B1, 4, 1, &[9], 2, 1, 6, 2);
        row(D, 136, B1, 2, 1, &[4, 9], 8, 1, 3, 2);
        row(D, 140, B1, 1, 0, &[9], 2, 1, 6, 2);
        row(D, 144, B1, 1, 0, &[1, 3, 5, 7, 9], 2, 1, 6, 2);
        row(D, 145, B4, 16, 1, &[9], 0, 2, 1, 12);
        row(D, 147, B4, 4, 1, &[9], 2, 1, 1, 12);
        row(D, 158, B4, 1, 0, &[7], 0, 1, 1, 12);
        row(D, 159, B4, 1, 0, &[9], 0, 1, 1, 12);
        row(
            D,
            168,
            B4,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            2,
            1,
            1,
            12,
        );
        row(D, 169, C0, 16, 1, &[9], 2, 2, 6, 2);
        row(D, 175, C0, 2, 1, &[7, 9], 8, 1, 3, 2);
        row(D, 183, C0, 1, 0, &[4, 9], 2, 1, 6, 2);
        row(
            D,
            188,
            C0,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            8,
            1,
            3,
            2,
        );
        row(D, 189, C2, 16, 1, &[9], 2, 2, 2, 6);
        row(D, 199, C2, 8, 1, &[9], 8, 2, 1, 6);
        row(
            D,
            210,
            C2,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            8,
            1,
            1,
            6,
        );
        row(D, 211, A1B1, 2, 1, &[9], 2, 1, 6, 2);
        row(
            D,
            225,
            A1B1,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            8,
            1,
            3,
            2,
        );
        row(D, 226, A2B2, 2, 1, &[9], 0, 1, 3, 4);
        row(D, 227, A2B2, 2, 1, &[4, 9], 6, 1, 2, 4);
        row(
            D,
            240,
            A2B2,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            6,
            1,
            2,
            4,
        );
        row(D, 241, A3B3, 2, 1, &[9], 0, 1, 2, 6);
        row(
            D,
            255,
            A3B3,
            1,
            0,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            2,
            1,
            2,
            6,
        );
        row(D, 256, F0, 16, 1, &[7], 0, 0, 0, 0);
        row(D, 262, F0, 2, 1, &[2], 0, 0, 0, 0);
        assert!(prach_config(DuplexMode::Tdd, 263).is_none());
    }

    /// Structural invariants of both tables.
    #[test]
    fn tables_consistent() {
        for (duplex, table) in [
            (DuplexMode::Fdd, &PRACH_CONFIG_FR1_PAIRED[..]),
            (DuplexMode::Tdd, &PRACH_CONFIG_FR1_UNPAIRED[..]),
        ] {
            for (i, e) in table.iter().enumerate() {
                assert!(matches!(e.x, 1 | 2 | 4 | 8 | 16), "{duplex:?} {i}");
                assert!(e.y.iter().all(|&y| y < e.x), "{duplex:?} {i}");
                assert!(
                    !e.subframes.is_empty() && e.subframes.windows(2).all(|w| w[0] < w[1]),
                    "{duplex:?} {i}"
                );
                assert!(e.subframes.iter().all(|&s| s < 10), "{duplex:?} {i}");
                if e.format.is_long() {
                    assert_eq!(
                        (e.prach_slots_per_subframe, e.occasions_per_slot, e.duration),
                        (0, 0, 0)
                    );
                    assert!(e.start_symbol == 0 || e.start_symbol == 7, "{duplex:?} {i}");
                } else {
                    assert!(
                        matches!(e.prach_slots_per_subframe, 1 | 2),
                        "{duplex:?} {i}"
                    );
                    let dur = format_params(e.format.for_occasion(0, 1), 0).unwrap();
                    assert_eq!(
                        u64::from(e.duration) * 2192 * KAPPA_TC,
                        dur.nominal_tc,
                        "{duplex:?} {i}"
                    );
                    // The occasions fit in the slot.
                    assert!(
                        e.start_symbol + e.occasions_per_slot * e.duration <= 14,
                        "{duplex:?} {i}"
                    );
                }
            }
        }
    }

    #[test]
    fn format_parameters() {
        let f0 = format_params(F0, 1).unwrap();
        assert_eq!(
            (f0.l_ra, f0.n_repeat, f0.cp_tc, f0.seq_tc),
            (839, 1, 3168 * 64, 24576 * 64)
        );
        assert_eq!(f0.delta_f_ra_hz, 1250.0);
        assert_eq!(f0.guard_tc, (30720 - 3168 - 24576) * 64);
        let f1 = format_params(F1, 0).unwrap();
        assert_eq!(
            (f1.n_repeat, f1.cp_tc, f1.seq_tc),
            (2, 21024 * 64, 2 * 24576 * 64)
        );
        let f2 = format_params(F2, 0).unwrap();
        assert_eq!(
            (f2.n_repeat, f2.cp_tc, f2.nominal_tc),
            (4, 4688 * 64, 107520 * 64)
        );
        let f3 = format_params(F3, 0).unwrap();
        assert_eq!(
            (f3.delta_f_ra_hz, f3.n_repeat, f3.seq_tc),
            (5000.0, 4, 4 * 6144 * 64)
        );
        // Short formats scale with 2^-µ.
        let c0 = format_params(C0, 1).unwrap();
        assert_eq!(
            (c0.l_ra, c0.n_repeat, c0.cp_tc, c0.seq_tc, c0.delta_f_ra_hz),
            (139, 1, 1240 * 32, 2048 * 32, 30_000.0)
        );
        assert_eq!(c0.guard_tc, (2 * 2192 - 1240 - 2048) * 32);
        let b4 = format_params(B4, 0).unwrap();
        assert_eq!(
            (b4.n_repeat, b4.cp_tc, b4.guard_tc),
            (12, 936 * 64, (12 * 2192 - 936 - 12 * 2048) * 64)
        );
        for f in [A1, A2, A3] {
            assert_eq!(format_params(f, 1).unwrap().guard_tc, 0);
        }
        assert_eq!(format_params(A1B1, 1), Err(PrachError::MixedFormat(A1B1)));
        assert_eq!(A1B1.for_occasion(6, 7), B1);
        assert_eq!(A1B1.for_occasion(0, 7), A1);
        assert_eq!(
            format_params(A1, 4),
            Err(PrachError::UnsupportedScs { mu: 4 })
        );
    }

    #[test]
    fn sample_layouts() {
        let f0 = format_params(F0, 0).unwrap();
        let l = f0.sample_layout(15.36e6).unwrap();
        assert_eq!(
            (l.cp_samples, l.symbol_samples, l.n_repeat),
            (1584, 12288, 1)
        );
        assert_eq!(l.nominal_samples(), 15360);
        let l = f0.sample_layout(11.52e6).unwrap();
        assert_eq!((l.cp_samples, l.symbol_samples), (1188, 9216));
        let l = f0.sample_layout(23.04e6).unwrap();
        assert_eq!((l.cp_samples, l.symbol_samples), (2376, 18432));
        let l = f0.sample_layout(30.72e6).unwrap();
        assert_eq!((l.cp_samples, l.symbol_samples), (3168, 24576));
        let f3 = format_params(F3, 0)
            .unwrap()
            .sample_layout(15.36e6)
            .unwrap();
        assert_eq!(
            (f3.cp_samples, f3.symbol_samples, f3.n_repeat),
            (1584, 3072, 4)
        );
        let c0 = format_params(C0, 1)
            .unwrap()
            .sample_layout(15.36e6)
            .unwrap();
        assert_eq!(
            (
                c0.cp_samples,
                c0.symbol_samples,
                c0.n_repeat,
                c0.guard_samples
            ),
            (310, 512, 1, 274)
        );
        assert_eq!(c0.nominal_samples(), 2 * (512 + 36));
        assert!(matches!(
            format_params(F0, 0).unwrap().sample_layout(10.0005e6),
            Err(PrachError::NonIntegerSymbolLength { .. })
        ));
    }

    #[test]
    fn symbol_starts() {
        // 15 kHz: symbol 0 at 0, symbol 1 at (2048+160)κ, symbol 7 at 0.5 ms.
        assert_eq!(symbol_start_tc(0, 0), 0);
        assert_eq!(symbol_start_tc(0, 1), 2208 * 64);
        assert_eq!(symbol_start_tc(0, 7), SUBFRAME_TC / 2);
        assert_eq!(symbol_start_tc(0, 14), SUBFRAME_TC);
        // 30 kHz: symbol 14 (start of the second slot) at 0.5 ms, 28 at 1 ms.
        assert_eq!(symbol_start_tc(1, 14), SUBFRAME_TC / 2);
        assert_eq!(symbol_start_tc(1, 28), SUBFRAME_TC);
        assert_eq!(symbol_start_tc(1, 2), 2 * 2192 * 32 + 16 * 64);
    }

    fn tdd_183() -> PrachConfig {
        PrachConfig {
            index: 183,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 1,
            msg1_frequency_start: 0,
        }
    }

    /// TDD index 183 (C0, x=1, subframes {4, 9}, l_0 = 2, one PRACH slot per
    /// subframe → n_slot = 1, six occasions of two symbols) at 30 kHz.
    #[test]
    fn occasions_tdd_183_c0() {
        let cfg = tdd_183();
        let n = Numerology::KHZ30;
        assert!(!is_prach_slot(&cfg, SlotPoint::new(n, 3, 8)).unwrap()); // first slot of subframe 4
        assert!(is_prach_slot(&cfg, SlotPoint::new(n, 3, 9)).unwrap());
        assert!(is_prach_slot(&cfg, SlotPoint::new(n, 3, 19)).unwrap());
        assert!(!is_prach_slot(&cfg, SlotPoint::new(n, 3, 10)).unwrap());
        let occ = prach_occasions_in_slot(&cfg, SlotPoint::new(n, 3, 9)).unwrap();
        assert_eq!(occ.len(), 6);
        for (i, o) in occ.iter().enumerate() {
            assert_eq!(o.format, C0);
            assert_eq!(o.start_symbol, 2 + 2 * i as u8);
            assert_eq!(
                (
                    o.sfn,
                    o.subframe,
                    o.prach_slot_in_subframe,
                    o.time_index,
                    o.freq_index
                ),
                (3, 4, 1, i as u8, 0)
            );
            assert_eq!(o.slot, SlotPoint::new(n, 3, 9));
            assert_eq!(o.start_tc, symbol_start_tc(1, 14 + 2 + 2 * i as u32));
            assert_eq!(o.t_id(), 9);
            assert_eq!(o.ra_rnti(false), 1 + o.s_id() + 14 * 9);
        }
        // First occasion: 0.5 ms + two 30 kHz symbols (incl. the 16κ of symbol 14).
        assert_eq!(occ[0].start_sample_in_subframe(15.36e6), 7680 + 2 * 548 + 8);
        // Queried at 15 kHz the whole subframe is seen.
        let occ15 = prach_occasions_in_slot(&cfg, SlotPoint::new(Numerology::KHZ15, 3, 4)).unwrap();
        assert_eq!(occ15.len(), 6);
        // next: from slot 10 of frame 3 the next is slot 19.
        let nxt = next_prach_occasion(&cfg, SlotPoint::new(n, 3, 10), 0, |_| true)
            .unwrap()
            .unwrap();
        assert_eq!((nxt.sfn, nxt.slot.slot, nxt.time_index), (3, 19, 0));
        // with lead 10 → frame 4 slot 9.
        let nxt = next_prach_occasion(&cfg, SlotPoint::new(n, 3, 10), 10, |_| true)
            .unwrap()
            .unwrap();
        assert_eq!((nxt.sfn, nxt.slot.slot), (4, 9));
        // Filter: only the last time-domain occasion.
        let nxt = next_prach_occasion(&cfg, SlotPoint::new(n, 3, 10), 0, |o| o.time_index == 5)
            .unwrap()
            .unwrap();
        assert_eq!((nxt.slot.slot, nxt.start_symbol), (19, 12));
    }

    /// TDD index 159 (B4, x=1, subframe 9, l_0 = 0, one PRACH slot per subframe
    /// → the second 30 kHz slot, a single 12-symbol occasion).
    #[test]
    fn occasions_tdd_159_b4() {
        let cfg = PrachConfig {
            index: 159,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 1,
            msg1_frequency_start: 0,
        };
        let n = Numerology::KHZ30;
        assert!(!is_prach_slot(&cfg, SlotPoint::new(n, 7, 18)).unwrap());
        let occ = prach_occasions_in_slot(&cfg, SlotPoint::new(n, 7, 19)).unwrap();
        assert_eq!(occ.len(), 1);
        let o = occ[0];
        assert_eq!(
            (
                o.format,
                o.start_symbol,
                o.prach_slot_in_subframe,
                o.t_id(),
                o.start_tc
            ),
            (B4, 0, 1, 19, SUBFRAME_TC / 2)
        );
        assert_eq!(o.ra_rnti(false), 1 + 14 * 19);
        assert_eq!(cfg.occasions_per_prach_frame().unwrap(), 1);
        let p = cfg
            .format_params(0)
            .unwrap()
            .sample_layout(15.36e6)
            .unwrap();
        assert_eq!(
            (p.cp_samples, p.n_repeat, p.symbol_samples, p.guard_samples),
            (234, 12, 512, 198)
        );
        assert_eq!(p.nominal_samples(), 12 * 548);
    }

    /// FDD index 16: format 0, every frame, subframe 1, l_0 = 0.
    #[test]
    fn occasions_fdd_16_format0() {
        let cfg = PrachConfig {
            index: 16,
            duplex: DuplexMode::Fdd,
            mu: 0,
            msg1_scs_mu: 0,
            msg1_fdm: 2,
            msg1_frequency_start: 4,
        };
        let n = Numerology::KHZ15;
        let occ = prach_occasions_in_slot(&cfg, SlotPoint::new(n, 100, 1)).unwrap();
        assert_eq!(occ.len(), 2);
        assert_eq!(
            (
                occ[0].format,
                occ[0].start_symbol,
                occ[0].start_tc,
                occ[0].t_id()
            ),
            (F0, 0, 0, 1)
        );
        assert_eq!(
            (occ[1].freq_index, occ[1].ra_rnti(false)),
            (1, 1 + 14 + 14 * 80)
        );
        assert!(prach_occasions_in_slot(&cfg, SlotPoint::new(n, 100, 2))
            .unwrap()
            .is_empty());
        // At 30 kHz only the first slot of subframe 1 holds the start.
        assert_eq!(
            prach_occasions_in_slot(&cfg, SlotPoint::new(Numerology::KHZ30, 100, 2))
                .unwrap()
                .len(),
            2
        );
        assert!(
            prach_occasions_in_slot(&cfg, SlotPoint::new(Numerology::KHZ30, 100, 3))
                .unwrap()
                .is_empty()
        );
    }

    /// TDD index 16: format 0 with l_0 = 7 (starts at 0.5 ms), x = 1,
    /// subframes {1, 6}; TDD index 0: x = 16, y = 1.
    #[test]
    fn occasions_long_start_symbol_and_sfn_period() {
        let cfg = PrachConfig {
            index: 16,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 1,
            msg1_frequency_start: 0,
        };
        let n30 = Numerology::KHZ30;
        assert!(prach_occasions_in_slot(&cfg, SlotPoint::new(n30, 0, 2))
            .unwrap()
            .is_empty());
        let occ = prach_occasions_in_slot(&cfg, SlotPoint::new(n30, 0, 3)).unwrap();
        assert_eq!(occ.len(), 1);
        assert_eq!(
            (
                occ[0].start_symbol,
                occ[0].start_tc,
                occ[0].t_id(),
                occ[0].slot.numerology.mu
            ),
            (7, SUBFRAME_TC / 2, 1, 0)
        );
        assert_eq!(occ[0].ra_rnti(false), 1 + 7 + 14);
        assert!(is_prach_slot(&cfg, SlotPoint::new(n30, 0, 13)).unwrap());

        let cfg = PrachConfig {
            index: 0,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 1,
            msg1_frequency_start: 0,
        };
        let n15 = Numerology::KHZ15;
        assert!(!is_prach_slot(&cfg, SlotPoint::new(n15, 0, 9)).unwrap());
        assert!(is_prach_slot(&cfg, SlotPoint::new(n15, 1, 9)).unwrap());
        assert!(is_prach_slot(&cfg, SlotPoint::new(n15, 17, 9)).unwrap());
        assert!(!is_prach_slot(&cfg, SlotPoint::new(n15, 16, 9)).unwrap());
        let nxt = next_prach_occasion(&cfg, SlotPoint::new(n15, 2, 0), 0, |_| true)
            .unwrap()
            .unwrap();
        assert_eq!((nxt.sfn, nxt.subframe), (17, 9));
        // Wrap at SFN 1024: 1023 % 16 = 15, next match is SFN 1 (1 % 16 = 1).
        let nxt = next_prach_occasion(&cfg, SlotPoint::new(n15, 1023, 0), 0, |_| true)
            .unwrap()
            .unwrap();
        assert_eq!((nxt.sfn, nxt.subframe), (1, 9));
    }

    /// Two PRACH slots per subframe at 30 kHz (TDD index 67: A1, x=16, y=1,
    /// subframe 9, 2 slots, 6 occasions) and the mixed A1/B1 (TDD 211).
    #[test]
    fn occasions_two_prach_slots_and_mixed() {
        let cfg = PrachConfig {
            index: 67,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 4,
            msg1_frequency_start: 0,
        };
        let n30 = Numerology::KHZ30;
        let a = prach_occasions_in_slot(&cfg, SlotPoint::new(n30, 1, 18)).unwrap();
        let b = prach_occasions_in_slot(&cfg, SlotPoint::new(n30, 1, 19)).unwrap();
        assert_eq!((a.len(), b.len()), (24, 24));
        assert_eq!(
            (
                a[0].prach_slot_in_subframe,
                a[0].t_id(),
                b[0].prach_slot_in_subframe,
                b[0].t_id()
            ),
            (0, 18, 1, 19)
        );
        assert_eq!(a[5].freq_index, 1);
        assert_eq!(a[23].ra_rnti(false), 1 + 10 + 14 * 18 + 14 * 80 * 3);
        assert_eq!(cfg.occasions_per_subframe().unwrap(), 48);

        let cfg = PrachConfig {
            index: 211,
            duplex: DuplexMode::Tdd,
            mu: 1,
            msg1_scs_mu: 1,
            msg1_fdm: 1,
            msg1_frequency_start: 0,
        };
        let o = prach_occasions_in_slot(&cfg, SlotPoint::new(n30, 1, 19)).unwrap();
        assert_eq!(o.len(), 6);
        assert!(o[..5].iter().all(|x| x.format == A1));
        assert_eq!(o[5].format, B1);
        assert_eq!(cfg.format_params(5).unwrap().cp_tc, 216 * 32);
        assert_eq!(cfg.format_params(0).unwrap().cp_tc, 288 * 32);
    }

    #[test]
    fn config_errors() {
        let mut cfg = tdd_183();
        cfg.msg1_fdm = 3;
        assert_eq!(
            prach_occasions_in_subframe(&cfg, 0, 4),
            Err(PrachError::InvalidMsg1Fdm(3))
        );
        cfg.msg1_fdm = 1;
        cfg.msg1_scs_mu = 2;
        assert_eq!(cfg.ra_mu(), Err(PrachError::UnsupportedScs { mu: 2 }));
        cfg.index = 300;
        assert!(matches!(
            cfg.entry(),
            Err(PrachError::InvalidConfigIndex { .. })
        ));
    }

    #[test]
    fn frequency_mapping_table() {
        let m = prach_frequency_mapping(1250.0, 0).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (6, 7, 12));
        let m = prach_frequency_mapping(1250.0, 1).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (3, 1, 24));
        let m = prach_frequency_mapping(1250.0, 2).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (2, 133, 48));
        let m = prach_frequency_mapping(5000.0, 1).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (12, 10, 6));
        let m = prach_frequency_mapping(15_000.0, 1).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (6, 2, 2));
        let m = prach_frequency_mapping(30_000.0, 1).unwrap();
        assert_eq!((m.n_rb_ra, m.k_bar, m.k), (12, 2, 1));
        assert!(prach_frequency_mapping(60_000.0, 1).is_err());
        // The sequence fits inside the occasion's RBs for every row.
        for (ra, mu, l) in [
            (1250.0, 0, 839),
            (1250.0, 1, 839),
            (1250.0, 2, 839),
            (5000.0, 0, 839),
            (5000.0, 1, 839),
            (5000.0, 2, 839),
            (15_000.0, 0, 139),
            (15_000.0, 1, 139),
            (30_000.0, 1, 139),
            (30_000.0, 0, 139),
        ] {
            let m = prach_frequency_mapping(ra, mu).unwrap();
            assert!(usize::from(m.k_bar) + l <= m.width_ra_sc(), "{ra} {mu}");
        }
    }

    #[test]
    fn subcarrier_offsets() {
        // Cell: 30 kHz, 51-RB UL grid, BWP = whole carrier, msg1-FrequencyStart 0.
        let c0 = format_params(C0, 1).unwrap();
        let m = prach_frequency_mapping(c0.delta_f_ra_hz, 1).unwrap();
        // relative to the BWP start (as the legacy k_start of the C0 occasion).
        assert_eq!(prach_subcarrier_offset(&m, 0, 0, 0), 2);
        assert_eq!(prach_subcarrier_offset(&m, 0, 1, 0), 12 * 12 + 2);
        assert_eq!(prach_subcarrier_offset(&m, 5, 0, 0), 5 * 12 + 2);
        // relative to DC with a 24-RB grid: −12 RB.
        assert_eq!(prach_subcarrier_offset(&m, 0, 0, -12), -144 + 2);
        // Long format at 30 kHz PUSCH: K = 24.
        let f0 = format_params(F0, 0).unwrap();
        let m = prach_frequency_mapping(f0.delta_f_ra_hz, 1).unwrap();
        assert_eq!(
            prach_subcarrier_offset(&m, 1, 2, 0),
            24 * 12 * (1 + 2 * 3) + 1
        );
    }

    #[test]
    fn ssb_ro_association() {
        // TDD 183 (C0, x=1, subframes {4,9}, 6 occasions, FDM 1): 12 ROs per frame.
        let cfg = tdd_183();
        // 8 SSBs, one SSB per RO → 8 ROs needed → 1 frame.
        assert_eq!(
            association_period_frames(&cfg, SsbPerRo::One, 8).unwrap(),
            1
        );
        // 1/2 SSB per RO (2 ROs per SSB), 8 SSBs → 16 ROs → 2 frames.
        assert_eq!(
            association_period_frames(&cfg, SsbPerRo::OneHalf, 8).unwrap(),
            2
        );
        // 1/8 with 8 SSB → 64 ROs → 8 frames (96 ROs).
        assert_eq!(
            association_period_frames(&cfg, SsbPerRo::OneEighth, 8).unwrap(),
            8
        );
        let occ: Vec<_> = (0..2)
            .flat_map(|sfn| {
                [4u8, 9]
                    .into_iter()
                    .flat_map(move |sf| prach_occasions_in_subframe(&cfg, sfn, sf).unwrap())
            })
            .collect();
        assert_eq!(occ.len(), 24);
        // One SSB per RO, 8 SSBs: ROs 0..8 → SSB 0..8, ROs 8..12 unmapped (tail).
        let map: Vec<_> = occ
            .iter()
            .map(|o| occasion_ssb_ordinals(&cfg, SsbPerRo::One, 8, o).unwrap())
            .collect();
        for (k, m) in map.iter().enumerate().take(8) {
            assert_eq!(*m, Some((k as u8, 1)));
        }
        assert!(map[8..12].iter().all(Option::is_none));
        assert_eq!(map[12], Some((0, 1))); // next frame = next association period
                                           // 1/2: period 2 frames = 24 ROs, cycle 16: RO k → SSB k/2; 16..24 unmapped.
        let map: Vec<_> = occ
            .iter()
            .map(|o| occasion_ssb_ordinals(&cfg, SsbPerRo::OneHalf, 8, o).unwrap())
            .collect();
        assert_eq!(map[3], Some((1, 1)));
        assert_eq!(map[15], Some((7, 1)));
        assert!(map[16..24].iter().all(Option::is_none));
        // Two SSBs per RO, 8 SSBs: cycle 4 ROs; RO 1 → SSB 2,3; ROs 12 per frame → 3 cycles, none unmapped.
        let map: Vec<_> = occ
            .iter()
            .map(|o| occasion_ssb_ordinals(&cfg, SsbPerRo::Two, 8, o).unwrap())
            .collect();
        assert_eq!(map[1], Some((2, 2)));
        assert_eq!(map[11], Some((6, 2)));
        // Four SSBs per RO with 6 SSBs: RO 1 gets SSBs 4,5 (count 2).
        assert_eq!(
            occasion_ssb_ordinals(&cfg, SsbPerRo::Four, 6, &occ[1]).unwrap(),
            Some((4, 2))
        );
        // 64 SSBs at 1/8 would need 512 ROs > 16 frames × 12.
        assert_eq!(
            association_period_frames(&cfg, SsbPerRo::OneEighth, 64),
            Err(PrachError::InvalidSsbMapping)
        );
        // Preamble ranges.
        assert_eq!(cb_preamble_range(SsbPerRo::Two, 1, 64, 8), 32..40);
        assert_eq!(cb_preamble_range(SsbPerRo::OneHalf, 0, 64, 16), 0..16);
    }
}
