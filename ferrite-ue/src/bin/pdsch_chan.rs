//! Diagnose the PDSCH receive front-end using OCUDU's exact codeword. Generate
//! the true transmitted QPSK symbols (scramble + map), pair them with the
//! captured (equalized) symbols under a candidate RE order, and report the
//! per-OFDM-symbol channel h = captured·conj(ideal). If h is phase-consistent
//! within each symbol, the RE order is correct and only a residual per-symbol
//! rotation remains; if h is random, the order is wrong.
//!
//! Usage: pdsch-chan <capture.bin> <ocudu_codeword.txt>

use ferrite_phy::pdsch::pdsch_scramble_c_init;
use ferrite_phy::sequence::gold_sequence;
use num_complex::Complex32;

const SI_RNTI: u16 = 0xFFFF;

fn main() {
    let cap_path = std::env::args().nth(1).unwrap();
    let cw_path = std::env::args().nth(2).unwrap();
    let cap = std::fs::read(&cap_path).unwrap();
    let cell_id = u32::from_le_bytes(cap[0..4].try_into().unwrap()) as u16;
    let mut recs: Vec<(u8, u8, u8, f32, f32)> = Vec::new();
    for r in cap[8..].chunks_exact(11) {
        recs.push((r[0], r[1], r[2], f32::from_le_bytes(r[3..7].try_into().unwrap()), f32::from_le_bytes(r[7..11].try_into().unwrap())));
    }
    let cw: Vec<u8> = std::fs::read_to_string(&cw_path).unwrap().trim().bytes().map(|c| c - b'0').collect();
    let inv = 1.0 / 2.0f32.sqrt();
    let mk_ideal = |g: &[u8]| -> Vec<Complex32> {
        g.chunks_exact(2)
            .map(|p| Complex32::new((1 - 2 * p[0] as i32) as f32 * inv, (1 - 2 * p[1] as i32) as f32 * inv))
            .collect()
    };
    // Quick scramble-variant scan: mean per-(rb,symbol) block coherence, spec order.
    let mut sspec = recs.clone();
    sspec.sort_by_key(|x: &(u8, u8, u8, f32, f32)| (x.0, x.1, x.2));
    let block_coh = |ideal: &[Complex32]| -> f32 {
        let mut blk: std::collections::BTreeMap<(u8, u8), (Complex32, f32)> = Default::default();
        for (k, &(rb, _, l, re, im)) in sspec.iter().enumerate() {
            let h = Complex32::new(re, im) * ideal[k].conj();
            let e = blk.entry((l, rb)).or_insert((Complex32::new(0.0, 0.0), 0.0));
            e.0 += h;
            e.1 += h.norm();
        }
        blk.values().map(|(s, a)| s.norm() / a.max(1e-9)).sum::<f32>() / blk.len() as f32
    };
    for (name, ci) in [
        ("si-rnti", Some(pdsch_scramble_c_init(SI_RNTI, cell_id))),
        ("none", None),
        ("nid-only", Some(cell_id as u32)),
        ("rnti<<15", Some((SI_RNTI as u32) << 15)),
    ] {
        let g: Vec<u8> = match ci {
            Some(ci) => { let c = gold_sequence(ci, cw.len()); cw.iter().zip(&c).map(|(a, b)| a ^ b).collect() }
            None => cw.clone(),
        };
        println!("scramble {name:<10}: block coherence {:.3}", block_coh(&mk_ideal(&g)));
    }
    // EVM of the captured symbols + a few raw values.
    let inv2 = 1.0 / 2.0f32.sqrt();
    let (mut evm, mut n) = (0f32, 0usize);
    for &(_, _, _, re, im) in &recs {
        let z = Complex32::new(re, im);
        let mag = z.norm().max(1e-12);
        let near = Complex32::new(re.signum(), im.signum()) * inv2;
        evm += (z / mag - near).norm_sqr();
        n += 1;
    }
    println!("capture EVM (rms): {:.4}  ({n} REs)", (evm / n as f32).sqrt());
    print!("first raw symbols: ");
    for r in recs.iter().take(4) {
        print!("({:+.3},{:+.3}) ", r.3, r.4);
    }
    println!();

    let c = gold_sequence(pdsch_scramble_c_init(SI_RNTI, cell_id), cw.len());
    let g: Vec<u8> = cw.iter().zip(&c).map(|(a, b)| a ^ b).collect();
    let ideal = mk_ideal(&g);

    type Key = fn(&(u8, u8, u8, f32, f32)) -> (u8, u8, u8);
    let orders: [(&str, Key); 6] = [
        ("rb,sc,l (spec k')", |x| (x.0, x.1, x.2)),
        ("l,rb,sc", |x| (x.2, x.0, x.1)),
        ("sc,rb,l", |x| (x.1, x.0, x.2)),
        ("rb,l,sc", |x| (x.0, x.2, x.1)),
        ("l,sc,rb", |x| (x.2, x.1, x.0)),
        ("sc,l,rb", |x| (x.1, x.2, x.0)),
    ];
    for (name, key) in orders {
        let mut s = recs.clone();
        s.sort_by_key(key);
        // per-symbol accumulate h = captured·conj(ideal)
        let mut by: std::collections::BTreeMap<u8, (Complex32, f32, usize)> = Default::default();
        for (k, &(_, _, l, re, im)) in s.iter().enumerate() {
            let h = Complex32::new(re, im) * ideal[k].conj();
            let e = by.entry(l).or_insert((Complex32::new(0.0, 0.0), 0.0, 0));
            e.0 += h;
            e.1 += h.norm();
            e.2 += 1;
        }
        // coherence = |sum h| / sum|h|; ~1 ⇒ phase-consistent (order correct).
        let mut tot_coh = 0.0;
        let mut nsym = 0;
        print!("order {name:<20}: ");
        for (_sym, (sum, absum, _n)) in &by {
            tot_coh += sum.norm() / absum.max(1e-9);
            nsym += 1;
        }
        println!("mean per-symbol coherence {:.3}", tot_coh / nsym as f32);
    }
    // Coherence WITHIN each (rb, symbol) block (12 subcarriers), for the spec
    // order. High ⇒ subcarrier order + channel within an RB is correct, and any
    // remaining scramble is an RB-level (VRB-to-PRB) permutation.
    let mut s = recs.clone();
    s.sort_by_key(|x: &(u8, u8, u8, f32, f32)| (x.0, x.1, x.2));
    let mut blk: std::collections::BTreeMap<(u8, u8), (Complex32, f32)> = Default::default();
    for (k, &(rb, _, l, re, im)) in s.iter().enumerate() {
        let h = Complex32::new(re, im) * ideal[k].conj();
        let e = blk.entry((l, rb)).or_insert((Complex32::new(0.0, 0.0), 0.0));
        e.0 += h;
        e.1 += h.norm();
    }
    let mean_blk: f32 = blk.values().map(|(s, a)| s.norm() / a.max(1e-9)).sum::<f32>() / blk.len() as f32;
    println!("\nmean per-(rb,symbol) block coherence (spec order): {mean_blk:.3}");
    println!("  (~1 ⇒ subcarrier order & channel within RB correct; RB permutation remains)");
    // Show a few blocks' phases for symbol 3.
    println!("  symbol 3 per-RB phase:");
    for (&(l, rb), (sum, absum)) in blk.iter().filter(|(k, _)| k.0 == 3) {
        println!("    rb {rb:>2}: coh {:.2} phase {:>6.1}°", sum.norm() / absum.max(1e-9), sum.arg().to_degrees());
        let _ = l;
    }
}
