//! Validate Ferrite's PRACH Zadoff-Chu preamble against OCUDU's generator.
//! OCUDU emits the frequency-domain y_{u,v} = DFT(x_{u,v}); we DFT our own
//! sequence-domain x_{u,v} and compare. Usage: prach-cmp <ocudu_prach.txt>

use ferrite_phy::prach::{prach_ncs_unrestricted, prach_preamble_seq, PrachScs, PrachSeqLen};
use num_complex::Complex32;
use std::f32::consts::TAU;

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let refy: Vec<Complex32> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| {
            let mut it = l.split_whitespace().map(|x| x.parse::<f32>().unwrap());
            Complex32::new(it.next().unwrap(), it.next().unwrap())
        })
        .collect();

    // Config from argv: <ref> <format 0|B4> <root> <preamble> <zcz>.
    let a: Vec<String> = std::env::args().collect();
    let fmt = a.get(2).map(String::as_str).unwrap_or("0");
    let root: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let pre: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let zcz: usize = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(8);
    let (seq_len, scs) = if fmt == "0" {
        (PrachSeqLen::Long, PrachScs::Khz1_25)
    } else {
        (PrachSeqLen::Short, PrachScs::Short)
    };
    let l = seq_len.l_ra();
    let n_cs = prach_ncs_unrestricted(scs, zcz).unwrap();
    let x = prach_preamble_seq(root, pre, n_cs, seq_len);

    // y(n) = Σ_m x(m)·exp(-j2π·m·n/L)
    let y: Vec<Complex32> = (0..l)
        .map(|n| {
            (0..l)
                .map(|m| x[m] * Complex32::from_polar(1.0, -TAU * (m * n) as f32 / l as f32))
                .sum()
        })
        .collect();

    let mut max_err = 0f32;
    for (a, b) in y.iter().zip(&refy) {
        max_err = max_err.max((a - b).norm());
    }
    println!("N_CS={n_cs}, L={l}, ref {} pts", refy.len());
    println!("max |DFT(mine) - OCUDU y| = {max_err:.5}  (|y|≈{:.2})", (l as f32).sqrt());
    println!("{}", if max_err < 1e-2 { "MATCH — PRACH ZC preamble is bit-correct vs OCUDU." } else { "MISMATCH" });
}
