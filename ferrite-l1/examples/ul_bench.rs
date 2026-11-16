//! Micro-benchmark of the UL waveform builders (PUCCH F1 / PUSCH) at 15.36 MHz.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use ferrite_phy::{pucch, pusch, Ofdm};
fn main() {
    let ofdm = Ofdm::new(512);
    let f1 = pucch::PucchF1 {
        prb1: 1,
        prb2: 22,
        start_symbol: 0,
        nof_symbols: 14,
        init_cyclic_shift: 0,
        occ_index: 0,
        n_id: 1,
        carrier_rb: 24,
    };
    let t = std::time::Instant::now();
    for _ in 0..10 {
        let w = pucch::pucch_f1_modulate_slot(&ofdm, &f1, &[1], 7, 1, 3390e6, 15.36e6);
        assert!(!w.is_empty());
    }
    println!(
        "pucch f1: {:.2} ms per call",
        t.elapsed().as_secs_f64() * 100.0
    );
    let alloc = pusch::PuschAlloc {
        rb_start: 4,
        n_rb: 3,
        sym_start: 0,
        n_sym: 14,
        dmrs_symbols: vec![2, 7, 11],
        qm: 2,
        carrier_rb: 24,
        crb_offset: 0,
        transform_precoding: None,
    };
    let tb = vec![0u8; 11];
    let t = std::time::Instant::now();
    for _ in 0..10 {
        let w = pusch::pusch_modulate_slot(&ofdm, &tb, &alloc, 1, 9, 1, 1, 0x4601, 3390e6, 15.36e6);
        assert!(!w.is_empty());
    }
    println!(
        "pusch: {:.2} ms per call",
        t.elapsed().as_secs_f64() * 100.0
    );
    for (n_rb, tbs_bytes) in [(5usize, 80usize), (10, 200), (20, 500), (24, 1000)] {
        let alloc = pusch::PuschAlloc {
            rb_start: 0,
            n_rb,
            sym_start: 0,
            n_sym: 14,
            dmrs_symbols: vec![2, 7, 11],
            qm: 2,
            carrier_rb: 24,
            crb_offset: 0,
            transform_precoding: None,
        };
        let tb = vec![0x5au8; tbs_bytes];
        let t = std::time::Instant::now();
        let w = pusch::pusch_modulate_slot(&ofdm, &tb, &alloc, 1, 9, 1, 1, 0x4601, 3390e6, 15.36e6);
        assert!(!w.is_empty());
        println!(
            "pusch {n_rb} RB, {tbs_bytes} B: {:.2} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
    }
    for tbs_bits in [88usize, 320, 640, 1032, 2088, 4104, 8200] {
        let bits = vec![1u8; tbs_bits];
        let e = (tbs_bits as f64 / 0.3) as usize;
        let t = std::time::Instant::now();
        let c = ferrite_phy::coding::dlsch::dlsch_encode(&bits, e, 0.3, 2, 0);
        println!(
            "dlsch_encode {tbs_bits} bits (E {e}): {:.2} ms, {} coded bits",
            t.elapsed().as_secs_f64() * 1e3,
            c.len()
        );
    }
}

#[allow(dead_code)]
fn unused() {}
