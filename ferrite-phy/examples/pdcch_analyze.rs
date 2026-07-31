//! Offline PDCCH data-RE analysis: read `(l:u8, k:u16, re:f32, im:f32)` records,
//! then brute-force the coded-bit ordering, scrambling init, payload size, and
//! polarity to find a CRC-valid DCI decode.
//!
//! Usage: cargo run -p ferrite-phy --example pdcch_analyze -- <file.rec> [n_rb] [n_cell]

use ferrite_phy::coding::dci::dci_decode;
use ferrite_phy::sequence::gold_sequence;

fn main() {
    let path = std::env::args().nth(1).expect("usage: pdcch_analyze <file.rec> [n_rb] [n_cell]");
    let n_rb: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(24);
    let n_cell: u32 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let bytes = std::fs::read(&path).unwrap();

    // Parse records: 1 + 2 + 4 + 4 = 11 bytes each.
    let mut res: Vec<(u8, u16, f32, f32)> = Vec::new();
    for r in bytes.chunks_exact(11) {
        let l = r[0];
        let k = u16::from_le_bytes([r[1], r[2]]);
        let re = f32::from_le_bytes([r[3], r[4], r[5], r[6]]);
        let im = f32::from_le_bytes([r[7], r[8], r[9], r[10]]);
        res.push((l, k, re, im));
    }
    println!("{} data REs, n_rb={n_rb}, n_cell={n_cell}", res.len());

    // Candidate orderings of the REs → LLR stream.
    let orderings: Vec<(&str, Box<dyn Fn(&mut Vec<(u8, u16, f32, f32)>)>)> = vec![
        ("k,l", Box::new(|v: &mut Vec<_>| v.sort_by_key(|&(l, k, ..)| (k, l)))),
        ("l,k", Box::new(|v: &mut Vec<_>| v.sort_by_key(|&(l, k, ..)| (l, k)))),
    ];
    let c_inits: Vec<(String, Option<u32>)> = vec![
        ("none".into(), None),
        ("N_cell".into(), Some(n_cell)),
        ("0".into(), Some(0)),
        ("N_cell<<1".into(), Some(n_cell << 1)),
    ];

    for (oname, sorter) in &orderings {
        let mut ordered = res.clone();
        sorter(&mut ordered);
        // Two ways to serialize a QPSK symbol into 2 LLRs.
        for (sname, swap) in [("re,im", false), ("im,re", true)] {
            let mut base = Vec::with_capacity(ordered.len() * 2);
            for &(_, _, re, im) in &ordered {
                if swap {
                    base.push(im);
                    base.push(re);
                } else {
                    base.push(re);
                    base.push(im);
                }
            }
            for (cname, c_init) in &c_inits {
                let mut buf = base.clone();
                if let Some(ci) = c_init {
                    let c = gold_sequence(*ci, buf.len());
                    for (x, &b) in buf.iter_mut().zip(&c) {
                        if b == 1 {
                            *x = -*x;
                        }
                    }
                }
                for conj in [false, true] {
                    let mut b2 = buf.clone();
                    if conj {
                        // conjugate: negate every imag LLR (odd indices)
                        for x in b2.iter_mut().skip(1).step_by(2) {
                            *x = -*x;
                        }
                    }
                    for a_len in 20..=50 {
                        if let Some(bits) = dci_decode(&b2, 0xFFFF, a_len) {
                            println!(
                                "  DECODED order={oname} ser={sname} c_init={cname} conj={conj} a_len={a_len}:"
                            );
                            println!("    {}", bits.iter().map(|x| x.to_string()).collect::<String>());
                        }
                    }
                }
            }
        }
    }
    println!("(done)");
}
