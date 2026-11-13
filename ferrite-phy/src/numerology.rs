//! NR numerology / frame structure (3GPP TS 38.211 §4).
//!
//! The numerology type itself ([`Numerology`]) is the workspace-wide one from
//! `ferrite_common` (so every layer shares one slot clock); this module keeps
//! the resource-grid constants the PHY needs alongside it.

pub use ferrite_common::Numerology;

/// Number of OFDM symbols per slot with the normal cyclic prefix (§4.3.2).
pub const SYMBOLS_PER_SLOT_NORMAL_CP: u32 = 14;

/// Subcarriers per resource block (§4.4.4.1).
pub const SUBCARRIERS_PER_RB: u32 = 12;

/// Number of OFDM symbols per 1 ms subframe at numerology `mu` (normal CP):
/// `14 · 2^mu`.
pub const fn symbols_per_subframe(mu: u8) -> usize {
    (SYMBOLS_PER_SLOT_NORMAL_CP as usize) << mu
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
        assert_eq!(Numerology::KHZ30.slots_per_subframe(), 2);
        assert_eq!(symbols_per_subframe(0), 14);
        assert_eq!(symbols_per_subframe(1), 28);
    }
}
