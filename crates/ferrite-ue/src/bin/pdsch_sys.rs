//! Decouple the PDSCH front-end from LDPC: de-rate-match the received soft bits
//! to the LDPC codeword's *systematic* part (= the transport block bits
//! directly), and compare to the known SIB1 bytes. High match ⇒ the RE order /
//! scramble / rate-recovery is correct and the bug is in the LDPC/parity path.
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

    // SIB1 as bits; the transport block may carry it at some byte offset.
    let sib1_bits: Vec<u8> = SIB1.iter().flat_map(|&x| (0..8).map(move |i| (x >> (7 - i)) & 1)).collect();

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

    let mut best = (String::new(), 0f32);
    for (oname, key) in orders {
        let mut s = recs.clone();
        s.sort_by_key(key);
        for (rname, rot) in rots {
            for (sname, ci) in scrs {
                let mut llr: Vec<f32> = s.iter().flat_map(|&(_, _, _, re, im)| { let (a, b) = rot(re, im); [a, b] }).collect();
                if let Some(ci) = ci { descramble_llrs(&mut llr, ci); }
                let (full, zc) = de_rate_match_full(&llr, tbs, r, qm, 0);
                // Systematic (info) bits = full[0..K]; the transmitted ones are
                // cols 2..9 = full[2Zc..]. Compare TB region to SIB1 at each byte offset.
                let sys: Vec<u8> = full[2 * zc..].iter().map(|&l| (l < 0.0) as u8).collect();
                // sys[i] corresponds to info bit (2Zc + i). SIB1 sits at info bit
                // (off*8); overlap with the transmitted systematic (>=2Zc).
                for off in 0..=(tbs / 8 - SIB1.len()) {
                    let tb_start = off * 8;
                    let lo = (2 * zc).max(tb_start);
                    let hi = (tb_start + sib1_bits.len()).min(2 * zc + sys.len());
                    if hi <= lo { continue; }
                    let m = (lo..hi).filter(|&i| sys[i - 2 * zc] == sib1_bits[i - tb_start]).count();
                    let frac = m as f32 / (hi - lo) as f32;
                    if frac > best.1 {
                        best = (format!("order={oname} rot={rname} scr={sname} off={off} ({}/{})", m, hi - lo), frac);
                    }
                }
            }
        }
    }
    println!("best systematic match: {} = {:.1}%", best.0, 100.0 * best.1);
    println!("(~100% ⇒ front-end correct, LDPC/parity is the remaining bug)");
}
