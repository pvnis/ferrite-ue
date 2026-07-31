//! Dump the time-domain Msg3 PUSCH slot waveform (one slot, 7680 samples at
//! 15.36 Msps) so an OCUDU OFDM-demodulator harness can demodulate it exactly as
//! the gNB's lower PHY would — isolating the OFDM/phase-compensation convention
//! from the ZMQ transport. Output: one "<re> <im>" line per complex sample.

use ferrite_phy::coding::dlsch::dlsch_encode_single;
use ferrite_phy::pusch::{pusch_e_len, pusch_modulate_slot, PuschAlloc};
use ferrite_phy::Ofdm;

fn main() {
    let ofdm = Ofdm::new(512);
    let alloc = PuschAlloc { rb_start: 4, n_rb: 3, dmrs_symbols: vec![2, 7, 11], qm: 2, carrier_rb: 24, crb_offset: 2 };
    let (cell, tc, slot) = (1u16, 0x4601u16, 17u32);

    let tb_bytes = [0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00];
    let tb: Vec<u8> = tb_bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
    let ulsch = dlsch_encode_single(&tb, pusch_e_len(&alloc), 0.117, 2, 0);

    // slot 17 → slot_in_subframe = 1. Phase comp at the carrier centre (3390 MHz).
    let fc: f64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3390e6);
    let wave = pusch_modulate_slot(&ofdm, &ulsch, &alloc, cell, slot, (slot % 2) as usize, tc, fc, 15.36e6);
    for s in &wave {
        println!("{:.6} {:.6}", s.re, s.im);
    }
}
