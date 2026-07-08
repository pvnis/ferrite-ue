//! Ultra-direct front-end check: de-rate-match the received soft bits to the
//! LDPC systematic bits (= transport block bits), and compare to the KNOWN TB
//! = SIB1(92 bytes) + zero padding. Checks both the SIB1 region and the
//! zero-padding region (a strong independent signal). Isolates RE order /
//! rotation / scramble from the LDPC path.
//!
//! Usage: pdsch-sys <capture.bin>

use ferrite_phy::coding::dlsch::de_rate_match_full;
use ferrite_phy::pdsch::{descramble_llrs, pdsch_scramble_c_init};

const SI_RNTI: u16 = 0xFFFF;
const SIB1: [u8; 92] = [
    0xd2, 0x04, 0x05, 0xc0, 0x41, 0x00, 0x10, 0x08, 0x00, 0x00, 0x38, 0x00, 0x29, 0xa0, 0x00, 0x60,
    0x15, 0x84, 0x26, 0x80, 0x20, 0x80, 0x01, 0x0b, 0x80, 0x81, 0x42, 0x40, 0x30, 0xc5, 0xa9, 0x86,
    0xcd, 0xc1, 0x00, 0x80, 0x00, 0x02, 0x02, 0x00, 0x01, 0x06, 0x88, 0xd4, 0x90, 0x48, 0x4c, 0x10,
    0x9a, 0x4c, 0x61, 0x80, 0x00, 0x01, 0x0b, 0xb8, 0x62, 0xd4, 0xc8, 0x93, 0xe0, 0x14, 0x19, 0x92,
    0xaf, 0xfc, 0x04, 0x93, 0xa4, 0x41, 0xb8, 0xa3, 0x71, 0x86, 0xe3, 0x8d, 0xcb, 0x1b, 0xef, 0xd5,
    0xb1, 0xc3, 0xa8, 0x02, 0x16, 0x03, 0x40, 0x0c, 0x16, 0x2d, 0xa0, 0x8a,
];

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let cap = std::fs::read(&path).unwrap();
    let cell_id = u32::from_le_bytes(cap[0..4].try_into().unwrap()) as u16;
    let tbs = u32::from_le_bytes(cap[4..8].try_into().unwrap()) as usize;
    let mut recs: Vec<(u8, u8, u8, f32, f32)> = Vec::new();
    for r in cap[8..].chunks_exact(11) {
        recs.push((r[0], r[1], r[2], f32::from_le_bytes(r[3..7].try_into().unwrap()), f32::from_le_bytes(r[7..11].try_into().unwrap())));
    }
    let (qm, r) = (2usize, 379.0 / 1024.0);
    // Known TB = SIB1 + zeros → info bits (TB || CRC || filler). We only need TB.
    let mut tb_bits = vec![0u8; tbs];
    for (bi, chunk) in tb_bits.chunks_mut(8).enumerate().take(SIB1.len()) {
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (SIB1[bi] >> (7 - i)) & 1;
        }
    }

    type Key = fn(&(u8, u8, u8, f32, f32)) -> (u8, u8, u8);
    let orders: [(&str, Key); 6] = [
        ("rb,sc,l", |x| (x.0, x.1, x.2)), ("l,rb,sc", |x| (x.2, x.0, x.1)),
        ("rb,l,sc", |x| (x.0, x.2, x.1)), ("l,sc,rb", |x| (x.2, x.1, x.0)),
        ("sc,rb,l", |x| (x.1, x.0, x.2)), ("sc,l,rb", |x| (x.1, x.2, x.0)),
    ];
    let rots: [(&str, fn(f32, f32) -> (f32, f32)); 8] = [
        ("rot0", |a, b| (a, b)), ("rot90", |a, b| (-b, a)), ("rot180", |a, b| (-a, -b)),
        ("rot270", |a, b| (b, -a)), ("conj", |a, b| (a, -b)), ("negre", |a, b| (-a, b)),
        ("swap", |a, b| (b, a)), ("swapneg", |a, b| (-b, -a)),
    ];
    let scrs: [(&str, Option<u32>); 2] = [("si", Some(pdsch_scramble_c_init(SI_RNTI, cell_id))), ("none", None)];

    let mut results: Vec<(f32, String)> = Vec::new();
    for (oname, key) in orders {
        let mut s = recs.clone();
        s.sort_by_key(key);
        for (rname, rot) in rots {
            for (sname, ci) in scrs {
                let mut llr: Vec<f32> = s.iter().flat_map(|&(_, _, _, re, im)| { let (a, b) = rot(re, im); [a, b] }).collect();
                if let Some(ci) = ci { descramble_llrs(&mut llr, ci); }
                let (full, zc) = de_rate_match_full(&llr, tbs, r, qm, 0);
                // Transmitted systematic bits = full[2Zc..]; info bit index = 2Zc + i.
                // Compare to the known TB bits over the transmitted, non-erased range.
                let sys: Vec<u8> = full[2 * zc..].iter().map(|&l| (l < 0.0) as u8).collect();
                let mut m = 0usize;
                let mut n = 0usize;
                for i in 0..sys.len() {
                    let info = 2 * zc + i;
                    if info < tbs {
                        // sys should equal TB bit `info`; skip erased (llr ~ 0).
                        if full[2 * zc + i].abs() > 1e-3 {
                            n += 1;
                            if sys[i] == tb_bits[info] { m += 1; }
                        }
                    }
                }
                let frac = if n > 0 { m as f32 / n as f32 } else { 0.0 };
                results.push((frac, format!("order={oname} rot={rname} scr={sname}: {m}/{n} TB-bit match")));
            }
        }
    }
    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    println!("Top front-end candidates (TB-bit match, known TB = SIB1+zeros):");
    for (frac, desc) in results.iter().take(6) {
        println!("  {:.1}%  {desc}", 100.0 * frac);
    }

    // Per-symbol match pattern for order=l,rb,sc, rot0, si (the best): the
    // systematic real bits come from symbols in extraction order. A channel bug
    // shows some symbols good/bad; a wrong order shows uniform ~50%.
    let mut s = recs.clone();
    s.sort_by_key(|x: &(u8, u8, u8, f32, f32)| (x.2, x.0, x.1));
    let mut llr: Vec<f32> = s.iter().flat_map(|&(_, _, _, re, im)| [re, im]).collect();
    descramble_llrs(&mut llr, pdsch_scramble_c_init(SI_RNTI, cell_id));
    let (full, zc) = de_rate_match_full(&llr, tbs, r, qm, 0);
    // Map systematic index i → the symbol it came from (real bit of symbol i in
    // l,rb,sc order).
    let syms_in_order: Vec<u8> = s.iter().map(|x| x.2).collect();
    let mut per_sym: std::collections::BTreeMap<u8, (usize, usize)> = Default::default();
    for i in 0..(full.len() - 2 * zc) {
        let info = 2 * zc + i;
        if info < tbs && full[2 * zc + i].abs() > 1e-3 && i < syms_in_order.len() {
            let bit = (full[2 * zc + i] < 0.0) as u8;
            let e = per_sym.entry(syms_in_order[i]).or_default();
            e.1 += 1;
            if bit == tb_bits[info] { e.0 += 1; }
        }
    }
    println!("\nper-symbol TB-bit match (order l,rb,sc):");
    for (sym, (m, n)) in per_sym {
        println!("  symbol {sym:>2}: {m}/{n} ({:.0}%)", 100.0 * m as f32 / n.max(1) as f32);
    }

    // Oracle search: the captured symbols already went through a CFO phase-slope
    // model; if its slope alias is wrong, an extra per-symbol de-rotation
    // exp(-j·dphi·l) fixes it. Search dphi to maximize the known-TB match.
    println!("\nper-symbol phase-slope (dphi) oracle search:");
    let mut best = (0f64, 0f32);
    let mut sd = recs.clone();
    sd.sort_by_key(|x: &(u8, u8, u8, f32, f32)| (x.2, x.0, x.1));
    for step in -200..=200 {
        let dphi = step as f64 * std::f64::consts::PI / 200.0;
        let mut llr: Vec<f32> = sd.iter().flat_map(|&(_, _, l, re, im)| {
            let ang = dphi * l as f64;
            let (c, s) = (ang.cos() as f32, ang.sin() as f32);
            [re * c + im * s, -re * s + im * c] // rotate by -dphi*l
        }).collect();
        descramble_llrs(&mut llr, pdsch_scramble_c_init(SI_RNTI, cell_id));
        let (full, zc) = de_rate_match_full(&llr, tbs, r, qm, 0);
        let (mut m, mut n) = (0usize, 0usize);
        for i in 0..(full.len() - 2 * zc) {
            let info = 2 * zc + i;
            if info < tbs && full[2 * zc + i].abs() > 1e-3 {
                n += 1;
                if (full[2 * zc + i] < 0.0) as u8 == tb_bits[info] { m += 1; }
            }
        }
        let frac = m as f32 / n.max(1) as f32;
        if frac > best.1 { best = (dphi, frac); }
    }
    println!("  best dphi = {:.4} rad/symbol → {:.1}% TB match", best.0, 100.0 * best.1);

    // Per-OFDM-symbol rotation oracle: systematic bit i = real bit of record i
    // (l,rb,sc order), descrambled by c[2i]. Group by OFDM symbol; per symbol,
    // pick the rotation (0/90/180/270) maximizing the known-TB match. If total
    // jumps to ~100% with non-trivial per-symbol rotations, the bug is purely
    // the per-symbol channel phase (EVM=0 but wrong QPSK point).
    let c = ferrite_phy::sequence::gold_sequence(pdsch_scramble_c_init(SI_RNTI, cell_id), 2 * recs.len());
    // real-bit under rotation ρ ∈ {0,90,180,270}: sign of {re, -im, -re, im}.
    let realbit = |re: f32, im: f32, rho: usize| -> u8 {
        let v = match rho { 0 => re, 1 => -im, 2 => -re, _ => im };
        (v < 0.0) as u8
    };
    let mut by_sym: std::collections::BTreeMap<u8, [ (usize, usize); 4 ]> = Default::default();
    for (i, &(_, _, l, re, im)) in sd.iter().enumerate() {
        if i >= 632 { break; } // systematic range
        let e = by_sym.entry(l).or_default();
        for rho in 0..4 {
            let bit = realbit(re, im, rho) ^ c[2 * i];
            e[rho].1 += 1;
            if bit == tb_bits[176 + i] { e[rho].0 += 1; }
        }
    }
    println!("\nper-symbol rotation oracle:");
    let (mut tm, mut tn) = (0usize, 0usize);
    for (sym, counts) in &by_sym {
        let (rho, best) = (0..4).map(|r| (r, counts[r].0)).max_by_key(|x| x.1).unwrap();
        let deg = [0, 90, 180, 270][rho];
        println!("  symbol {sym:>2}: best rot {deg:>3}° → {}/{}", best, counts[rho].1);
        tm += best;
        tn += counts[rho].1;
    }
    println!("  TOTAL with per-symbol rotations: {tm}/{tn} ({:.1}%)", 100.0 * tm as f32 / tn.max(1) as f32);
}
