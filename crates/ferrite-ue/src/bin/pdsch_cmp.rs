//! Compare Ferrite's DL-SCH encode of the known SIB1 TB against OCUDU's
//! reference codeword bits (pdsch_ref output). Pinpoints the encode-chain
//! divergence (LDPC vs rate-matching vs interleaving).
//!
//! Usage: pdsch-cmp <ocudu_codeword.txt>

use ferrite_phy::coding::dlsch::dlsch_encode_single;

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
    let ref_bits: Vec<u8> = std::fs::read_to_string(&path)
        .unwrap()
        .trim()
        .bytes()
        .map(|c| c - b'0')
        .collect();

    let mut tb = vec![0u8; 101 * 8];
    for (bi, chunk) in tb.chunks_mut(8).enumerate().take(92) {
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (SIB1[bi] >> (7 - i)) & 1;
        }
    }
    let (qm, r, e_len) = (2usize, 379.0 / 1024.0, 2160usize);
    let mine = dlsch_encode_single(&tb, e_len, r, qm, 0);

    println!("ref {} bits, mine {} bits", ref_bits.len(), mine.len());
    let m = mine.iter().zip(&ref_bits).filter(|(a, b)| a == b).count();
    println!("codeword match: {m}/{} ({:.1}%)", ref_bits.len(), 100.0 * m as f32 / ref_bits.len() as f32);

    // Deinterleave both (undo §5.4.2.2) to isolate: if the deinterleaved
    // (pre-interleave e) sequences match, only the bit-interleaving differs.
    let deint = |f: &[u8]| -> Vec<u8> {
        let (e_len, rows) = (f.len(), f.len() / qm);
        let mut e = vec![0u8; e_len];
        for i in 0..qm {
            for j in 0..rows {
                e[i * rows + j] = f[i + j * qm];
            }
        }
        e
    };
    let (er, em) = (deint(&ref_bits), deint(&mine));
    let md = er.iter().zip(&em).filter(|(a, b)| a == b).count();
    println!("deinterleaved (e) match: {md}/{} ({:.1}%)", er.len(), 100.0 * md as f32 / er.len() as f32);

    // Systematic e[0..656] = info[176..832] = TB[176..808] then CRC[808..832].
    let tbm = em[..632].iter().zip(&er[..632]).filter(|(a, b)| a == b).count();
    let crcm = em[632..656].iter().zip(&er[632..656]).filter(|(a, b)| a == b).count();
    println!("  TB part e[0..632]:   {tbm}/632 match");
    println!("  CRC part e[632..656]: {crcm}/24 match");
    println!("  ref CRC bits:  {}", er[632..656].iter().map(|b| b.to_string()).collect::<String>());
    println!("  mine CRC bits: {}", em[632..656].iter().map(|b| b.to_string()).collect::<String>());

    if let Some(pos) = mine.iter().zip(&ref_bits).position(|(a, b)| a != b) {
        println!("first raw divergence at bit {pos}");
    } else {
        println!("IDENTICAL — Ferrite DL-SCH encode matches OCUDU exactly.");
    }
}
