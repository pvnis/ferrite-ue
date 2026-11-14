//! Offline PRACH sanity check for the n78 TDD cell (idx 159 = B4, 30 kHz):
//! occasion timing within the subframe, the frequency placement, and the
//! new generator against the legacy single-symbol path that OCUDU detected.
use ferrite_common::{DuplexMode, Numerology, SlotPoint};
use ferrite_phy::prach::{self, PrachScs, PrachSeqLen, RestrictedSet};
use ferrite_phy::prach_config as pc;

fn main() {
    let fs = 15.36e6;
    let cfg = pc::PrachConfig {
        index: 159,
        duplex: DuplexMode::Tdd,
        mu: 1,
        msg1_scs_mu: 1,
        msg1_fdm: 1,
        msg1_frequency_start: 0,
    };
    for s in 0..20u16 {
        let slot = SlotPoint::new(Numerology::KHZ30, 48, s);
        if let Ok(v) = pc::prach_occasions_in_slot(&cfg, slot) {
            for o in v {
                println!("slot {slot}: occasion fmt {:?} start_symbol {} t {} f {} start_tc {} (= {:.1} samples @15.36M) ra_rnti {}", o.format, o.start_symbol, o.time_index, o.freq_index, o.start_tc, o.start_tc as f64 * fs / (480_000.0 * 4096.0), o.ra_rnti(false));
            }
        }
    }
    let params = cfg.format_params(0).unwrap();
    println!("params: {params:?}");
    let fm = pc::prach_frequency_mapping(params.delta_f_ra_hz, 1).unwrap();
    let first_sc = pc::prach_subcarrier_offset(&fm, 0, 0, -12);
    println!("freq mapping {fm:?}; first_sc from dc {first_sc}");
    let new = prach::prach_preamble_waveform(
        params.format,
        1,
        1,
        0,
        0,
        RestrictedSet::Unrestricted,
        fs,
        first_sc,
    )
    .unwrap();
    println!("new waveform len {}", new.len());
    // Legacy path: same sequence, 12 symbols, CP 234, grid of 24 RB, k_start 2.
    let x_uv = prach::prach_preamble_seq(
        1,
        0,
        prach::prach_ncs_unrestricted(PrachScs::Short, 0).unwrap(),
        PrachSeqLen::Short,
    );
    let occ = prach::PrachOccasion {
        fft_size: 512,
        grid_size: 288,
        k_start: 2,
        cp_samples: 234,
        nof_symbols: 12,
    };
    let old = prach::prach_occasion_waveform(&x_uv, &occ);
    println!("old waveform len {}", old.len());
    let n = new.len().min(old.len());
    let num: f32 = (0..n).map(|i| (new[i] * old[i].conj()).re).sum();
    let d1: f32 = new.iter().map(|c| c.norm_sqr()).sum();
    let d2: f32 = old.iter().map(|c| c.norm_sqr()).sum();
    println!("correlation new·old = {:.4}", num / (d1 * d2).sqrt());
    // Spectrum of symbol 1: which bins carry energy?
    let ofdm = ferrite_phy::Ofdm::new(512);
    let g = ofdm.demodulate_symbol(&new[234..], 0);
    let mut bins: Vec<(usize, f32)> = g
        .iter()
        .enumerate()
        .map(|(i, c)| (i, c.norm_sqr()))
        .filter(|(_, p)| *p > 1e-6)
        .collect();
    bins.sort_by_key(|b| b.0);
    let lo = bins.first().map(|b| b.0 as i64).unwrap_or(0);
    let hi = bins.last().map(|b| b.0 as i64).unwrap_or(0);
    println!(
        "occupied bins: {} bins, from {} to {} (as signed: {} .. {})",
        bins.len(),
        lo,
        hi,
        if lo >= 256 { lo - 512 } else { lo },
        if hi >= 256 { hi - 512 } else { hi }
    );
    // Preamble 1 should be a different root (N_CS = 0).
    let p1 = prach::prach_preamble_waveform(
        params.format,
        1,
        1,
        1,
        0,
        RestrictedSet::Unrestricted,
        fs,
        first_sc,
    )
    .unwrap();
    let c01: f32 = (0..n).map(|i| (new[i] * p1[i].conj()).re).sum::<f32>() / d1;
    println!("correlation preamble0·preamble1 = {c01:.4}");
}
