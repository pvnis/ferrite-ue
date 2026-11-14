//! Offline sync analysis of a captured IQ file (interleaved f32 LE):
//!   offline_scan <file.iq> <srate-MHz> <center-MHz> <ssb-scs-kHz> [df-Hz]
//! Runs the GSCN scan and, with an explicit df, the searcher at that shift,
//! printing PSS/SSS metrics and the MIB; also measures the MIB false-pass rate
//! on noise.

use ferrite_common::Iq;
use ferrite_phy::sync::scan::{freq_shift, gscn_scan};
use ferrite_phy::sync::search::CellSearcher;
use ferrite_phy::sync::ssb::l_max_fr1;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let path = &a[1];
    let fs: f64 = a[2].parse::<f64>().unwrap() * 1e6;
    let center: f64 = a[3].parse::<f64>().unwrap() * 1e6;
    let scs: u32 = a[4].parse().unwrap();
    let df: Option<f64> = a.get(5).and_then(|x| x.parse().ok());
    let bytes = std::fs::read(path).unwrap();
    let samples: Vec<Iq> = bytes
        .chunks_exact(8)
        .map(|c| {
            Iq::new(
                f32::from_le_bytes(c[0..4].try_into().unwrap()),
                f32::from_le_bytes(c[4..8].try_into().unwrap()),
            )
        })
        .collect();
    println!(
        "{} samples ({:.1} ms)",
        samples.len(),
        samples.len() as f64 / fs * 1e3
    );
    let mu = ferrite_common::Numerology::from_scs_khz(scs).unwrap().mu;
    let fft = (fs / (scs as f64 * 1e3)).round() as usize;
    let l_max = l_max_fr1(center);
    let searcher = CellSearcher::new(fft, mu, l_max);
    let pw: f32 = samples.iter().map(|s| s.norm_sqr()).sum::<f32>() / samples.len() as f32;
    println!("mean power {pw:.3e}, fft {fft}, mu {mu}, l_max {l_max}");
    if let Some(df) = df {
        let shifted = freq_shift(&samples, -df, fs, 0);
        match searcher.search(&shifted) {
            Some(r) => {
                println!(
                    "search @df {df}: PCI {} pss {:.3} sss {:.3} t {} cfo {:.0}",
                    r.cell_id, r.pss_metric, r.sss_metric, r.timing_index, r.cfo_hz
                );
                let mut corr = shifted.clone();
                ferrite_phy::sync::cfo::correct_cfo(&mut corr, r.cfo_hz, fs);
                println!("mib: {:?}", searcher.decode_mib(&corr, &r));
                // PBCH hypotheses in detail.
                use ferrite_phy::sync::pbch::{equalize_pbch, extract_pbch, pbch_dmrs};
                if let Some((rx_dmrs, rx_data, layout)) =
                    extract_pbch(searcher.ofdm(), &corr, r.timing_index, mu, r.cell_id)
                {
                    let rx_norm: f32 = rx_dmrs.iter().map(|s| s.norm_sqr()).sum::<f32>().sqrt();
                    for h in 0..8u8 {
                        let refs = pbch_dmrs(r.cell_id, h);
                        let acc: Iq = rx_dmrs.iter().zip(&refs).map(|(a, b)| a * b.conj()).sum();
                        let m = acc.norm() / (rx_norm * (rx_dmrs.len() as f32).sqrt());
                        let llrs = equalize_pbch(&rx_dmrs, &rx_data, &layout, r.cell_id, h);
                        let mut ok = Vec::new();
                        for v in 0..8u8 {
                            if let Some(mib) =
                                ferrite_phy::coding::bch::bch_decode(&llrs, r.cell_id, v)
                            {
                                ok.push((v, mib.sfn));
                            }
                        }
                        println!("  dmrs hyp {h}: metric {m:.3} decodes {ok:?}");
                    }
                    let pw: f32 =
                        rx_data.iter().map(|s| s.norm_sqr()).sum::<f32>() / rx_data.len() as f32;
                    println!(
                        "  pbch data power {pw:.3e}, dmrs power {:.3e}",
                        rx_norm * rx_norm / rx_dmrs.len() as f32
                    );
                }
            }
            None => println!("search @df {df}: nothing"),
        }
    }
    match gscn_scan(&samples, fs, center, scs, l_max, None) {
        Some(h) => println!(
            "gscn_scan: gscn {} df {:.0} PCI {} pss {:.3} sss {:.3} mib {:?}",
            h.gscn,
            h.df_hz,
            h.result.cell_id,
            h.result.pss_metric,
            h.result.sss_metric,
            h.pbch.map(|p| p.mib)
        ),
        None => println!("gscn_scan: nothing"),
    }
    // MIB false-pass rate on random LLRs.
    let mut seed = 0x1234_5678u64;
    let mut passes = 0;
    for _ in 0..2000 {
        let llr: Vec<f32> = (0..864)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                ((seed >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 8.0
            })
            .collect();
        if ferrite_phy::coding::bch::bch_decode(&llr, 1, 0).is_some() {
            passes += 1;
        }
    }
    println!("bch_decode false passes on noise: {passes}/2000");
}
