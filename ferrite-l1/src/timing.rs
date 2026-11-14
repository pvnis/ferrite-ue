//! The sample clock: the mapping between the radio's absolute sample index and
//! the NR slot structure (TS 38.211 §4.3), plus the uplink timing relation
//! (TS 38.211 §4.3.1, TS 38.213 §4.2).
//!
//! The DL stream index `d` of the start of a slot follows from one anchor
//! (`(sfn0, slot0) ↔ d0`) by slot arithmetic. The UL stream index at which a
//! slot's uplink must *start* is
//!
//! ```text
//!   u(slot) = d(slot) − (N_TA + N_TA_offset)·T_c·f_s − tx_rx_offset + ul_guard
//! ```
//!
//! where `tx_rx_offset` is a fixed, radio-backend-specific calibration (0 for
//! the ZMQ lockstep transport, the RX→TX loopback latency for a real SDR).
//! Nothing else about the transport leaks into the slot engine.

use ferrite_common::{slot::ta, Numerology, SlotPoint};

/// Slot ↔ sample index mapping for one carrier.
#[derive(Clone, Debug)]
pub struct SampleClock {
    pub fs: f64,
    pub numerology: Numerology,
    /// DL stream index of the start of `anchor_slot`.
    anchor_index: i64,
    anchor_slot: SlotPoint,
    /// `N_TA_offset` in T_c (SIB1 `n-TimingAdvanceOffset`, default 25600).
    pub n_ta_offset_tc: i64,
    /// `N_TA` in T_c (from the RAR / TA MAC CEs).
    pub n_ta_tc: i64,
    /// Backend calibration offset in samples (see module doc).
    pub tx_rx_offset: i64,
    /// Uplink timing guard in samples (positive = transmit later), applied
    /// to *every* uplink transmission including the PRACH. Over a zero-delay
    /// transport it keeps the preamble inside detector windows that start
    /// after the slot and reject negative delays; because the network's
    /// timing-advance command then measures and removes the same guard, the
    /// PUSCH/PUCCH end up on time. A PRACH-only delay would leave the later
    /// uplink early by the guard. Over the air the propagation delay plays
    /// this role and the guard can be 0.
    pub ul_guard: i64,
    /// Per-symbol sample offsets within a slot, for each slot-in-subframe
    /// position (index = slot_in_subframe), including the long CP of symbol 0
    /// and symbol 7·2^µ of the subframe.
    #[cfg(test)]
    symbol_offsets: Vec<[usize; 15]>,
}

impl SampleClock {
    /// The same clock with another N_TA (the PRACH is sent with N_TA = 0,
    /// TS 38.211 §4.3.1).
    pub fn with_n_ta(&self, n_ta_tc: i64) -> Self {
        let mut c = self.clone();
        c.n_ta_tc = n_ta_tc;
        c
    }

    /// `fft` is `fs / SCS`; the FFT size must be a multiple of 128.
    pub fn new(fs: f64, numerology: Numerology, anchor_slot: SlotPoint, anchor_index: i64) -> Self {
        #[cfg(test)]
        let symbol_offsets = {
            let fft = (fs / numerology.scs_hz() as f64).round() as usize;
            let spsf = numerology.slots_per_subframe() as usize;
            let mut symbol_offsets = Vec::with_capacity(spsf);
            for sis in 0..spsf {
                let mut offs = [0usize; 15];
                let mut acc = 0usize;
                for l in 0..14 {
                    offs[l] = acc;
                    acc += cp_len(fft, sis * 14 + l, numerology.mu) + fft;
                }
                offs[14] = acc;
                symbol_offsets.push(offs);
            }
            symbol_offsets
        };
        Self {
            fs,
            numerology,
            anchor_index,
            anchor_slot,
            n_ta_offset_tc: 25600,
            n_ta_tc: 0,
            tx_rx_offset: 0,
            ul_guard: 0,
            #[cfg(test)]
            symbol_offsets,
        }
    }

    pub fn samples_per_slot(&self) -> i64 {
        self.numerology.samples_per_slot(self.fs) as i64
    }


    /// DL stream index of the start of `slot`.
    pub fn dl_index(&self, slot: SlotPoint) -> i64 {
        self.anchor_index + slot.diff(&self.anchor_slot) * self.samples_per_slot()
    }

    /// The slot containing DL stream index `index`, and the offset within it.
    pub fn slot_at(&self, index: i64) -> (SlotPoint, i64) {
        let d = index - self.anchor_index;
        let sps = self.samples_per_slot();
        let n = d.div_euclid(sps);
        let off = d.rem_euclid(sps);
        let slot = if n >= 0 { self.anchor_slot.add(n as u64) } else { self.anchor_slot.sub((-n) as u64) };
        (slot, off)
    }

    /// Sample offset of symbol `l` (0..=14) from the start of a slot at
    /// slot-in-subframe position `sis`. `l = 14` is the slot end.
    #[cfg(test)]
    pub fn symbol_offset(&self, slot: SlotPoint, l: usize) -> usize {
        self.symbol_offsets[slot.slot_in_subframe() as usize][l]
    }

    /// Total timing advance in samples: `(N_TA + N_TA_offset)·T_c·f_s`.
    pub fn ta_samples(&self) -> i64 {
        ta::tc_to_samples(self.n_ta_tc + self.n_ta_offset_tc, self.fs)
    }

    /// UL stream index at which the uplink of `slot` starts.
    pub fn ul_index(&self, slot: SlotPoint) -> i64 {
        self.dl_index(slot) - self.ta_samples() - self.tx_rx_offset + self.ul_guard
    }


    /// Re-anchor after a measured timing error: the SSB at `slot` was found
    /// `err` samples later than predicted → shift the anchor by `err`.
    pub fn slew(&mut self, err: i64) {
        self.anchor_index += err;
    }

    /// Re-anchor absolutely.
    pub fn set_anchor(&mut self, slot: SlotPoint, index: i64) {
        self.anchor_slot = slot;
        self.anchor_index = index;
    }
}

/// Normal-CP length in samples for `symbol_in_subframe` at numerology `mu`
/// (TS 38.211 §5.3.1), FFT size `fft`. Test reference for the symbol offsets;
/// the engine uses `Ofdm::cp_len`.
#[cfg(test)]
pub fn cp_len(fft: usize, symbol_in_subframe: usize, mu: u8) -> usize {
    let normal = 144 * fft / 2048;
    if symbol_in_subframe == 0 || symbol_in_subframe == 7 * (1usize << mu) {
        normal + (16 << mu) * fft / 2048
    } else {
        normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_mapping_and_ul_offset() {
        let n = Numerology::KHZ30;
        let anchor = SlotPoint::new(n, 10, 0);
        let c = SampleClock::new(15.36e6, n, anchor, 1_000_000);
        assert_eq!(c.samples_per_slot(), 7680);
        assert_eq!(c.dl_index(SlotPoint::new(n, 10, 3)), 1_000_000 + 3 * 7680);
        assert_eq!(c.dl_index(SlotPoint::new(n, 9, 19)), 1_000_000 - 7680);
        let (s, off) = c.slot_at(1_000_000 + 2 * 7680 + 100);
        assert_eq!((s.sfn, s.slot, off), (10, 2, 100));
        // UL = DL − N_TA_offset (200 samples at 15.36 MHz) − N_TA.
        assert_eq!(c.ul_index(anchor), 1_000_000 - 200);
        let mut c2 = c.clone();
        c2.n_ta_tc = 512 * 3; // TA command 3 at µ=1 → 12 samples
        assert_eq!(c2.ul_index(anchor), 1_000_000 - 212);
        // Symbol offsets: slot 0 of a subframe has the long CP on symbol 0.
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 0), 1), 44 + 512);
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 1), 1), 44 + 512); // symbol 14 = 7·2^µ also has the long CP
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 1), 2) - c.symbol_offset(SlotPoint::new(n, 0, 1), 1), 36 + 512);
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 0), 14), 7680);
    }

    #[test]
    fn mu0_symbols() {
        let n = Numerology::KHZ15;
        let c = SampleClock::new(11.52e6, n, SlotPoint::new(n, 0, 0), 0);
        assert_eq!(c.samples_per_slot(), 11520);
        // fft 768: CP 54 normal, 60 long (symbols 0 and 7).
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 0), 1), 60 + 768);
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 0), 8) - c.symbol_offset(SlotPoint::new(n, 0, 0), 7), 60 + 768);
        assert_eq!(c.symbol_offset(SlotPoint::new(n, 0, 0), 14), 11520);
        assert_eq!(c.ta_samples(), 150);
    }
}
