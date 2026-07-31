//! Offline PDSCH decode sweep: read a capture of equalized data symbols
//! `(rb, sc, l, re, im)` and brute-force RE ordering × QPSK symmetry ×
//! scrambling, reporting LDPC convergence + CRC for each combination.
//!
//! Usage: pdsch-dbg <capture.bin>

use ferrite_phy::coding::dlsch::dlsch_decode_single_dbg;
use ferrite_phy::pdsch::{descramble_llrs, pdsch_scramble_c_init};

const SI_RNTI: u16 = 0xFFFF;

fn main() {
    let path = std::env::args().nth(1).expect("usage: pdsch-dbg <capture.bin>");
    let b = std::fs::read(&path).unwrap();
    let cell_id = u32::from_le_bytes(b[0..4].try_into().unwrap()) as u16;
    let tbs = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let mut recs: Vec<(u8, u8, u8, f32, f32)> = Vec::new();
    for r in b[8..].chunks_exact(11) {
        recs.push((
            r[0],
            r[1],
            r[2],
            f32::from_le_bytes(r[3..7].try_into().unwrap()),
            f32::from_le_bytes(r[7..11].try_into().unwrap()),
        ));
    }
    let (qm, r) = (2usize, 379.0 / 1024.0);
    let e_len = recs.len() * qm;
    println!("cell {cell_id}, tbs {tbs}, {} REs, E={e_len}", recs.len());

    // Constellation sanity.
    let evm: f32 = recs
        .iter()
        .map(|&(_, _, _, re, im)| {
            let m = (re * re + im * im).sqrt().max(1e-9);
            let (nr, ni) = (re.signum() / 2f32.sqrt(), im.signum() / 2f32.sqrt());
            (re / m - nr).powi(2) + (im / m - ni).powi(2)
        })
        .sum::<f32>()
        / recs.len() as f32;
    println!("mean EVM^2 {evm:.4}");

    // Orderings: sort key over (rb, sc, l).
    type Key = fn(&(u8, u8, u8, f32, f32)) -> (u8, u8, u8);
    let orders: [(&str, Key); 6] = [
        ("k'l  (rb,sc,l)", |x| (x.0, x.1, x.2)),
        ("lk'  (l,rb,sc)", |x| (x.2, x.0, x.1)),
        ("(rb,l,sc)", |x| (x.0, x.2, x.1)),
        ("(l,sc,rb)", |x| (x.2, x.1, x.0)),
        ("(sc,rb,l)", |x| (x.1, x.0, x.2)),
        ("(sc,l,rb)", |x| (x.1, x.2, x.0)),
    ];
    let rots: [(&str, fn(f32, f32) -> (f32, f32)); 8] = [
        ("rot0", |re, im| (re, im)),
        ("rot90", |re, im| (-im, re)),
        ("rot180", |re, im| (-re, -im)),
        ("rot270", |re, im| (im, -re)),
        ("conj", |re, im| (re, -im)),
        ("negre", |re, im| (-re, im)),
        ("swap", |re, im| (im, re)),
        ("swapneg", |re, im| (-im, -re)),
    ];

    let scrambles: [(&str, Option<u32>); 3] = [
        ("si-rnti", Some(pdsch_scramble_c_init(SI_RNTI, cell_id))),
        ("none", None),
        ("rnti0", Some(pdsch_scramble_c_init(0, cell_id))),
    ];
    for (oname, key) in orders {
        let mut sorted = recs.clone();
        sorted.sort_by_key(key);
        for (rname, rot) in rots {
            let base: Vec<f32> = sorted
                .iter()
                .flat_map(|&(_, _, _, re, im)| {
                    let (a, b) = rot(re, im);
                    [a, b]
                })
                .collect();
            for (sname, ci) in scrambles {
                let mut llrs = base.clone();
                if let Some(ci) = ci {
                    descramble_llrs(&mut llrs, ci);
                }
                let (tb, conv) = dlsch_decode_single_dbg(&llrs, tbs, r, qm, 0, 100);
                if conv || tb.is_some() {
                    println!("  order={oname} rot={rname} scr={sname}: converged={conv} crc={}", tb.is_some());
                    if tb.is_some() {
                        println!("  *** SUCCESS ***");
                    }
                }
            }
        }
    }
    println!("(sweep done)");
}
