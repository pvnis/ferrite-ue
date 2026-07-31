//! Forward check: encode the *known* SIB1 transport block (from the gNB log)
//! through our DL-SCH + scrambling chain and compare bit-exactly to a capture
//! of the received symbols. Mismatches localize the interface bug.
//!
//! Usage: pdsch-fwd <capture.bin>

use ferrite_phy::coding::dlsch::dlsch_encode_single;
use ferrite_phy::pdsch::{descramble_llrs, pdsch_scramble_c_init};

const SI_RNTI: u16 = 0xFFFF;

// The 92-byte BCCH-DL-SCH (SIB1) PDU logged by the gNB.
const SIB1: [u8; 92] = [
    0xd2, 0x04, 0x05, 0xc0, 0x41, 0x00, 0x10, 0x08, 0x00, 0x00, 0x38, 0x00, 0x29, 0xa0, 0x00, 0x60,
    0x15, 0x84, 0x26, 0x80, 0x20, 0x80, 0x01, 0x0b, 0x80, 0x81, 0x42, 0x40, 0x30, 0xc5, 0xa9, 0x86,
    0xcd, 0xc1, 0x00, 0x80, 0x00, 0x02, 0x02, 0x00, 0x01, 0x06, 0x88, 0xd4, 0x90, 0x48, 0x4c, 0x10,
    0x9a, 0x4c, 0x61, 0x80, 0x00, 0x01, 0x0b, 0xb8, 0x62, 0xd4, 0xc8, 0x93, 0xe0, 0x14, 0x19, 0x92,
    0xaf, 0xfc, 0x04, 0x93, 0xa4, 0x41, 0xb8, 0xa3, 0x71, 0x86, 0xe3, 0x8d, 0xcb, 0x1b, 0xef, 0xd5,
    0xb1, 0xc3, 0xa8, 0x02, 0x16, 0x03, 0x40, 0x0c, 0x16, 0x2d, 0xa0, 0x8a,
];

fn bytes_to_bits(b: &[u8]) -> Vec<u8> {
    b.iter().flat_map(|&x| (0..8).map(move |i| (x >> (7 - i)) & 1)).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: pdsch-fwd <capture.bin>");
    let cap = std::fs::read(&path).unwrap();
    let cell_id = u32::from_le_bytes(cap[0..4].try_into().unwrap()) as u16;
    let tbs = u32::from_le_bytes(cap[4..8].try_into().unwrap()) as usize;
    let mut recs: Vec<(u8, u8, u8, f32, f32)> = Vec::new();
    for r in cap[8..].chunks_exact(11) {
        recs.push((r[0], r[1], r[2], f32::from_le_bytes(r[3..7].try_into().unwrap()), f32::from_le_bytes(r[7..11].try_into().unwrap())));
    }
    let (qm, r) = (2usize, 379.0 / 1024.0);
    let e_len = recs.len() * qm;
    println!("cell {cell_id} tbs {tbs} ({} bytes), {} REs, E={e_len}", tbs / 8, recs.len());

    // Joint search: for each MAC framing, encode the known TB, then compare to
    // the capture under every RE ordering × QPSK symmetry × scramble.
    type Key = fn(&(u8, u8, u8, f32, f32)) -> (u8, u8, u8);
    let orders: [(&str, Key); 6] = [
        ("rb,sc,l", |x| (x.0, x.1, x.2)),
        ("l,rb,sc", |x| (x.2, x.0, x.1)),
        ("rb,l,sc", |x| (x.0, x.2, x.1)),
        ("l,sc,rb", |x| (x.2, x.1, x.0)),
        ("sc,rb,l", |x| (x.1, x.0, x.2)),
        ("sc,l,rb", |x| (x.1, x.2, x.0)),
    ];
    let rots: [(&str, fn(f32, f32) -> (f32, f32)); 8] = [
        ("rot0", |a, b| (a, b)), ("rot90", |a, b| (-b, a)), ("rot180", |a, b| (-a, -b)),
        ("rot270", |a, b| (b, -a)), ("conj", |a, b| (a, -b)), ("negre", |a, b| (-a, b)),
        ("swap", |a, b| (b, a)), ("swapneg", |a, b| (-b, -a)),
    ];
    let scrs: [(&str, Option<u32>); 2] = [
        ("si", Some(pdsch_scramble_c_init(SI_RNTI, cell_id))),
        ("none", None),
    ];
    let tb_bytes = tbs / 8;
    let mut best = (String::new(), 0usize);
    for off in 0..=(tb_bytes - SIB1.len()) {
        let mut tb = vec![0u8; tb_bytes];
        tb[off..off + SIB1.len()].copy_from_slice(&SIB1);
        let f = dlsch_encode_single(&bytes_to_bits(&tb), e_len, r, qm, 0);
        for (oname, key) in orders {
            let mut s = recs.clone();
            s.sort_by_key(key);
            for (rname, rot) in rots {
                for (sname, ci) in scrs {
                    let mut llr: Vec<f32> = s.iter().flat_map(|&(_, _, _, re, im)| { let (a, b) = rot(re, im); [a, b] }).collect();
                    if let Some(ci) = ci { descramble_llrs(&mut llr, ci); }
                    let m = f.iter().zip(&llr).filter(|(a, l)| (**a == 1) == (**l < 0.0)).count();
                    if m > best.1 {
                        best = (format!("off={off} order={oname} rot={rname} scr={sname}"), m);
                    }
                }
            }
        }
    }
    println!("best match: {} → {}/{e_len} ({:.1}%)", best.0, best.1, 100.0 * best.1 as f32 / e_len as f32);
    println!("(~100% ⇒ all identified; still ~55% ⇒ encode-chain/rate-matching bug)");
}
