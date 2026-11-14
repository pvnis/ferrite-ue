//! LDPC decoder throughput benchmark.
//!
//! Methodology mirrors OCUDU's `ldpc_decoder_benchmark` so the numbers are
//! directly comparable (behavioural reference only — no code shared):
//!   * sweep base graph BG1/BG2 over every NR lifting size Zc,
//!   * a fixed number of normalised min-sum iterations (default 6, OCUDU's default),
//!   * feed a random ±L codeblock so the syndrome check never trips early-exit and
//!     the decoder runs the *full* iteration budget every rep (OCUDU's `use_crc=false`
//!     path generates random `(rgen()&1)*20-10` LLRs for exactly this reason),
//!   * throughput denominator = message length k (info bits), same as OCUDU's
//!     `new_measure(descr, msg_length, ...)`.
//!
//! Run: `cargo bench -p ferrite-phy --bench ldpc_decode -- [reps] [iters]`
//! e.g. `cargo bench -p ferrite-phy --bench ldpc_decode -- 1000 6`
//!
//! Compare against OCUDU:
//!   /home/dmd/ocudu-pavo/build2/tests/benchmarks/phy/upper/channel_coding/ldpc/\
//!   ldpc_decoder_benchmark -R 1000 -I 6

use ferrite_phy::coding::ldpc::{BaseGraph, LdpcGraph};
use ferrite_phy::coding::ldpc_tables::LIFTING_SETS;
use std::time::Instant;

/// xorshift64 — deterministic, dependency-free (same generator as the ldpc unit tests).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bit(&mut self) -> u8 {
        (self.next() >> 40) as u8 & 1
    }
}

/// Every distinct NR lifting size, ascending.
fn all_lifting_sizes() -> Vec<u16> {
    let mut v: Vec<u16> = LIFTING_SETS
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn percentile(sorted_ns: &[u64], p: f64) -> u64 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let idx = ((sorted_ns.len() as f64 - 1.0) * p).round() as usize;
    sorted_ns[idx]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reps: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(6);
    let alpha = 0.75f32; // normalised min-sum scaling used throughout ferrite

    println!(
        "LDPC decoder — {iters} min-sum iterations, {reps} reps/config, alpha={alpha}\n\
         random ±L codeblock (full iteration budget every rep), first 2·Zc punctured\n"
    );
    println!(
        "{:<4} {:>4} {:>7} {:>7} {:>6}  {:>9} {:>9} {:>9} {:>9}  {:>10}",
        "BG", "Zc", "k", "N_tx", "R", "med(us)", "p90(us)", "p99(us)", "max(us)", "Mbps(med)"
    );

    let lifting = all_lifting_sizes();
    let mut rng = Rng(0x000F_3441_1CDC_0001);

    for bg in [BaseGraph::Bg2, BaseGraph::Bg1] {
        for &zc in &lifting {
            let Some(g) = LdpcGraph::new(bg, zc) else {
                continue;
            };
            let k = g.k();
            let n = g.n();
            let n_tx = n - 2 * g.zc(); // transmitted length excl. 2·Zc puncture (OCUDU convention)
            let rate = k as f64 / n_tx as f64;

            // Random ±L LLRs over the full codeword; first 2·Zc punctured (0 LLR) as in NR.
            // Random input never forms a valid codeword, so decode() runs all `iters`.
            let mut llr = vec![0f32; n];
            for l in llr.iter_mut().skip(2 * g.zc()) {
                *l = if rng.bit() == 0 { 10.0 } else { -10.0 };
            }

            // Warm-up (page/cache the msg store; not timed).
            for _ in 0..8 {
                let _ = g.decode(&llr, iters, alpha);
            }

            let mut samples = Vec::with_capacity(reps);
            for _ in 0..reps {
                let t = Instant::now();
                let out = g.decode(&llr, iters, alpha);
                let dt = t.elapsed().as_nanos() as u64;
                std::hint::black_box(&out);
                samples.push(dt);
            }
            samples.sort_unstable();

            let med = percentile(&samples, 0.50);
            let p90 = percentile(&samples, 0.90);
            let p99 = percentile(&samples, 0.99);
            let max = *samples.last().unwrap();
            let mbps = (k as f64) / (med as f64 / 1e9) / 1e6; // info bits / median time

            println!(
                "{:<4} {:>4} {:>7} {:>7} {:>6.3}  {:>9.2} {:>9.2} {:>9.2} {:>9.2}  {:>10.1}",
                format!("{bg:?}"),
                zc,
                k,
                n_tx,
                rate,
                med as f64 / 1e3,
                p90 as f64 / 1e3,
                p99 as f64 / 1e3,
                max as f64 / 1e3,
                mbps,
            );
        }
    }
}
