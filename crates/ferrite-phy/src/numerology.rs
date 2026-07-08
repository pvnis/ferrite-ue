//! NR numerology / frame structure (3GPP TS 38.211 §4).
//!
//! A subcarrier spacing (SCS) of `15 * 2^mu` kHz defines the OFDM grid. For our
//! target — band n78, FR1 TDD — the SSB and data use `mu = 1` (30 kHz).

/// Number of OFDM symbols per slot with the normal cyclic prefix (§4.3.2).
pub const SYMBOLS_PER_SLOT_NORMAL_CP: u32 = 14;

/// Subcarriers per resource block (§4.4.4.1).
pub const SUBCARRIERS_PER_RB: u32 = 12;

/// A concrete numerology, identified by the subcarrier-spacing index `mu`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Numerology {
    /// Subcarrier-spacing configuration `mu` in `{0, 1, 2, 3, 4}` (§4.2).
    pub mu: u8,
}

impl Numerology {
    /// `mu = 1` → 30 kHz SCS, the FR1 default used by band n78.
    pub const FR1_30KHZ: Numerology = Numerology { mu: 1 };

    /// Construct a numerology from its SCS-configuration index.
    pub const fn new(mu: u8) -> Self {
        Self { mu }
    }

    /// Subcarrier spacing in Hz: `15_000 * 2^mu`.
    pub const fn scs_hz(self) -> u32 {
        15_000u32 << self.mu
    }

    /// Number of slots per subframe (§4.3.2): `2^mu`.
    pub const fn slots_per_subframe(self) -> u32 {
        1u32 << self.mu
    }

    /// Number of slots per 10 ms frame: `10 * 2^mu`.
    pub const fn slots_per_frame(self) -> u32 {
        10u32 << self.mu
    }

    /// OFDM symbol duration (excluding CP), in seconds: `1 / scs`.
    pub fn symbol_duration_s(self) -> f64 {
        1.0 / self.scs_hz() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scs_and_slots() {
        assert_eq!(Numerology::new(0).scs_hz(), 15_000);
        assert_eq!(Numerology::new(1).scs_hz(), 30_000);
        assert_eq!(Numerology::new(2).scs_hz(), 60_000);

        assert_eq!(Numerology::new(0).slots_per_frame(), 10);
        assert_eq!(Numerology::new(1).slots_per_frame(), 20);
        assert_eq!(Numerology::FR1_30KHZ.slots_per_subframe(), 2);
    }
}
