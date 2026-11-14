//! The slot clock (TS 38.211 §4.3): numerology, frames, subframes and slots.
//!
//! `SlotPoint` is the single time reference shared by every layer: L1 tags each
//! indication with it, MAC/RRC express timers and offsets in it, and all
//! "n + k" arithmetic (k0/k1/k2, RAR windows, PRACH occasions, periodicities)
//! goes through it so the frame wrap (SFN mod 1024) is handled once.

/// Subcarrier-spacing configuration `mu` (TS 38.211 §4.2): SCS = 15·2^mu kHz.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Numerology {
    pub mu: u8,
}

impl Numerology {
    pub const KHZ15: Numerology = Numerology { mu: 0 };
    pub const KHZ30: Numerology = Numerology { mu: 1 };
    pub const KHZ60: Numerology = Numerology { mu: 2 };
    pub const KHZ120: Numerology = Numerology { mu: 3 };

    pub const fn new(mu: u8) -> Self {
        Self { mu }
    }

    /// From a subcarrier spacing in kHz (15/30/60/120/240).
    pub fn from_scs_khz(khz: u32) -> Option<Self> {
        match khz {
            15 => Some(Self::new(0)),
            30 => Some(Self::new(1)),
            60 => Some(Self::new(2)),
            120 => Some(Self::new(3)),
            240 => Some(Self::new(4)),
            _ => None,
        }
    }

    /// Subcarrier spacing in Hz.
    pub const fn scs_hz(self) -> u32 {
        15_000u32 << self.mu
    }

    pub const fn scs_khz(self) -> u32 {
        15u32 << self.mu
    }

    /// Slots per 1 ms subframe: `2^mu`.
    pub const fn slots_per_subframe(self) -> u32 {
        1u32 << self.mu
    }

    /// Slots per 10 ms frame: `10·2^mu`.
    pub const fn slots_per_frame(self) -> u32 {
        10u32 << self.mu
    }

    /// Slot duration in microseconds (1000 / 2^mu).
    pub fn slot_duration_us(self) -> f64 {
        1000.0 / self.slots_per_subframe() as f64
    }

    /// Samples per slot at sample rate `fs` (Hz). `fs · 1e-3 / 2^mu`; exact for
    /// every standard NR sample rate.
    pub fn samples_per_slot(self, fs: f64) -> usize {
        ((fs * 1e-3) / self.slots_per_subframe() as f64).round() as usize
    }

    /// Samples per 10 ms frame at `fs`.
    pub fn samples_per_frame(self, fs: f64) -> usize {
        (fs * 10e-3).round() as usize
    }
}

/// Basic time unit `T_c = 1 / (480 kHz · 4096)` seconds (TS 38.211 §4.1).
pub const TC_SECONDS: f64 = 1.0 / (480_000.0 * 4096.0);

/// `kappa = T_s / T_c = 64`.
pub const KAPPA: u32 = 64;

/// A slot in the 1024-frame system-frame cycle, at a given numerology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotPoint {
    pub numerology: Numerology,
    /// System frame number, 0..1024.
    pub sfn: u16,
    /// Slot within the frame, 0..slots_per_frame().
    pub slot: u16,
}

impl SlotPoint {
    pub fn new(numerology: Numerology, sfn: u16, slot: u16) -> Self {
        debug_assert!(sfn < 1024);
        debug_assert!((slot as u32) < numerology.slots_per_frame());
        Self {
            numerology,
            sfn,
            slot,
        }
    }

    /// Build from an absolute slot count (wraps at 1024 frames).
    pub fn from_index(numerology: Numerology, index: u64) -> Self {
        let spf = numerology.slots_per_frame() as u64;
        let total = spf * 1024;
        let i = index % total;
        Self {
            numerology,
            sfn: (i / spf) as u16,
            slot: (i % spf) as u16,
        }
    }

    pub const fn mu(&self) -> u8 {
        self.numerology.mu
    }

    pub const fn slots_per_frame(&self) -> u32 {
        self.numerology.slots_per_frame()
    }

    /// Absolute slot index within the 1024-frame cycle.
    pub fn index(&self) -> u64 {
        self.sfn as u64 * self.slots_per_frame() as u64 + self.slot as u64
    }

    /// Subframe (0..10) and slot within the subframe.
    pub fn subframe(&self) -> u16 {
        self.slot / self.numerology.slots_per_subframe() as u16
    }

    pub fn slot_in_subframe(&self) -> u16 {
        self.slot % self.numerology.slots_per_subframe() as u16
    }

    /// Half-frame (0 = first 5 ms, 1 = second).
    pub fn half_frame(&self) -> u8 {
        (self.subframe() >= 5) as u8
    }

    /// `self + n` slots (wrapping at 1024 frames).
    pub fn add(&self, n: u64) -> Self {
        Self::from_index(self.numerology, self.index() + n)
    }

    /// `self - n` slots (wrapping).
    pub fn sub(&self, n: u64) -> Self {
        let total = self.slots_per_frame() as u64 * 1024;
        Self::from_index(
            self.numerology,
            (self.index() + total - (n % total)) % total,
        )
    }

    /// Signed slot difference `self - other`, shortest way around the 1024-frame
    /// cycle (so a wrap near SFN 1023/0 still gives a small number).
    pub fn diff(&self, other: &SlotPoint) -> i64 {
        let total = self.slots_per_frame() as i64 * 1024;
        let d = (self.index() as i64 - other.index() as i64).rem_euclid(total);
        if d > total / 2 {
            d - total
        } else {
            d
        }
    }

    /// `(sfn·slots_per_frame + slot) mod period == offset` — the generic
    /// periodicity test used by SR/CSI/PRACH/SSB occasions.
    pub fn is_occasion(&self, period_slots: u32, offset_slots: u32) -> bool {
        period_slots > 0
            && (self.index() % period_slots as u64) == offset_slots as u64 % period_slots as u64
    }

    /// The same instant expressed at another numerology (slot index scaled).
    /// Going to a coarser numerology truncates to the containing slot.
    pub fn at_numerology(&self, numerology: Numerology) -> SlotPoint {
        let from = self.numerology.slots_per_subframe() as u64;
        let to = numerology.slots_per_subframe() as u64;
        let sub_index = self.sfn as u64 * 10 + self.subframe() as u64;
        let in_sub = self.slot_in_subframe() as u64;
        let new_in_sub = in_sub * to / from;
        SlotPoint::from_index(numerology, sub_index * to + new_in_sub)
    }
}

impl std::fmt::Display for SlotPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.sfn, self.slot)
    }
}

/// Timing-advance arithmetic (TS 38.211 §4.3.1, TS 38.213 §4.2).
pub mod ta {
    use super::{Numerology, KAPPA, TC_SECONDS};

    /// `N_TA` (in T_c units) from a RAR 12-bit TA command: `T_A · 16 · 64 / 2^mu`.
    pub fn n_ta_from_rar(ta_cmd: u32, numerology: Numerology) -> i64 {
        (ta_cmd as i64 * 16 * KAPPA as i64) >> numerology.mu
    }

    /// Updated `N_TA` from a 6-bit TA command MAC CE: `N_TA + (T_A − 31) · 16 · 64 / 2^mu`.
    pub fn n_ta_apply_ce(n_ta: i64, ta_cmd: u8, numerology: Numerology) -> i64 {
        n_ta + ((((ta_cmd as i64) - 31) * 16 * KAPPA as i64) >> numerology.mu)
    }

    /// Convert a count of `T_c` units into samples at `fs` (rounded).
    pub fn tc_to_samples(n_tc: i64, fs: f64) -> i64 {
        (n_tc as f64 * TC_SECONDS * fs).round() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_arithmetic_wraps() {
        let n = Numerology::KHZ30;
        let s = SlotPoint::new(n, 1023, 19);
        let t = s.add(1);
        assert_eq!((t.sfn, t.slot), (0, 0));
        assert_eq!(t.diff(&s), 1);
        assert_eq!(s.diff(&t), -1);
        assert_eq!(s.sub(20).sfn, 1022);
        assert_eq!(SlotPoint::new(n, 5, 7).subframe(), 3);
        assert_eq!(SlotPoint::new(n, 5, 7).slot_in_subframe(), 1);
    }

    #[test]
    fn samples_per_slot() {
        assert_eq!(Numerology::KHZ30.samples_per_slot(15.36e6), 7680);
        assert_eq!(Numerology::KHZ15.samples_per_slot(15.36e6), 15360);
        assert_eq!(Numerology::KHZ15.samples_per_slot(11.52e6), 11520);
        assert_eq!(Numerology::KHZ30.samples_per_frame(30.72e6), 307200);
    }

    #[test]
    fn ta_units() {
        // mu=1: one TA unit = 16·64/2 = 512 Tc = 512/(480e3·4096) s → 4 samples at 15.36 MHz.
        let n_ta = ta::n_ta_from_rar(1, Numerology::KHZ30);
        assert_eq!(n_ta, 512);
        assert_eq!(ta::tc_to_samples(n_ta, 15.36e6), 4);
        // N_TA_offset 25600 Tc → 200 samples at 15.36 MHz, 400 at 30.72 MHz.
        assert_eq!(ta::tc_to_samples(25600, 15.36e6), 200);
        assert_eq!(ta::tc_to_samples(25600, 30.72e6), 400);
        assert_eq!(ta::n_ta_apply_ce(1000, 31, Numerology::KHZ30), 1000);
        assert_eq!(ta::n_ta_apply_ce(1000, 32, Numerology::KHZ30), 1512);
    }

    #[test]
    fn numerology_conversion() {
        let s = SlotPoint::new(Numerology::KHZ30, 3, 7); // subframe 3, second slot
        let c = s.at_numerology(Numerology::KHZ15);
        assert_eq!((c.sfn, c.slot), (3, 3));
        let f = c.at_numerology(Numerology::KHZ30);
        assert_eq!((f.sfn, f.slot), (3, 6));
    }
}
