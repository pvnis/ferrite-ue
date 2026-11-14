// Round-trip the exact NAS-phase mcs=2 rb[0,2) size that fails live:
// tbs=88 bits (11 B) → B=104 → BG2 Kb=6 Zc=18 (lifting set 4), 76 filler bits.
fn main() {
    use ferrite_phy::coding::dlsch::{dlsch_decode_single, dlsch_encode_single};
    for (a, e, r, label) in [
        (
            88usize,
            504usize,
            193.0 / 1024.0,
            "mcs2 rb[0,2) cdm1 (FAILING LIVE)",
        ),
        (88, 432, 193.0 / 1024.0, "mcs2 rb[0,2) cdm2"),
        (
            336,
            504,
            679.0 / 1024.0,
            "mcs9 rb[0,2) cdm1 (tbs=42, works live)",
        ),
        (432, 2268, 193.0 / 1024.0, "mcs2 rb[0,9) cdm1 (tbs=54)"),
        (72, 216, 0.117, "RAR-like (works live)"),
    ] {
        let tb: Vec<u8> = (0..a).map(|i| ((i * 37 + i / 3) % 2) as u8).collect();
        let coded = dlsch_encode_single(&tb, e, r, 2, 0);
        let llr: Vec<f32> = coded
            .iter()
            .map(|&b| if b == 1 { -8.0 } else { 8.0 })
            .collect();
        match dlsch_decode_single(&llr, a, r, 2, 0, 10) {
            Some(out) if out == tb => println!("OK   a={a} e={e} {label}"),
            Some(_) => println!("MISMATCH a={a} e={e} {label}"),
            None => println!("CRC-FAIL a={a} e={e} {label}"),
        }
    }
}
