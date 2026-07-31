//! Dump the time-domain PUCCH Format 1 slot waveform (7680 samples @ 15.36 Msps)
//! so an OCUDU pucch_processor harness can detect the HARQ-ACK — validates the
//! F1 sequence/DMRS/OCC/hopping/phase-comp against the gNB's own receiver.
//! Output: one "<re> <im>" line per complex sample. arg1 = ACK bit (default 1).

use ferrite_phy::pucch::{pucch_f1_modulate_slot, PucchF1};
use ferrite_phy::Ofdm;

fn main() {
    let ofdm = Ofdm::new(512);
    let cfg = PucchF1 {
        prb1: 0,
        prb2: 23,
        start_symbol: 0,
        nof_symbols: 14,
        init_cyclic_shift: 0,
        occ_index: 0,
        n_id: 1,
        carrier_rb: 24,
    };
    let ack: u8 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let fc: f64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3390e6);
    // slot 17 (an UL slot), phase comp at the carrier centre.
    let wave = pucch_f1_modulate_slot(&ofdm, &cfg, &[ack], 17, fc, 15.36e6);
    for s in &wave {
        println!("{:.6} {:.6}", s.re, s.im);
    }
}
