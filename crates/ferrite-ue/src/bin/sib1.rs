//! Live SIB1 decode: sync → SI-RNTI DCI → PDSCH → DL-SCH → transport block.
//!
//! Usage: sib1 [--tx tcp://127.0.0.1:2100] [--rx tcp://127.0.0.1:2101]
//!             [--srate 15.36e6] [--center-mhz 3390.0] [--frames 80]

use ferrite_phy::coding::dci::{dci_1_0_si_size, dci_decode, pdcch_descramble_llr};
use ferrite_phy::pdcch::{equalize_candidate, type0_candidates, Coreset0};
use ferrite_phy::pdsch::{demod_slot, extract_pdsch, PdschAlloc};
use ferrite_phy::pdsch_params::{mcs_params, ndmrs_per_prb, transport_block_size};
use ferrite_phy::sync::CellSearcher;
use ferrite_phy::Ofdm;
use ferrite_radio::zmq::{ZmqSink, ZmqSource};
use ferrite_ue::stream::BufferedStream;
use ferrite_ue::sync::{freq_shift, gscn_scan, FrameSync};
use num_complex::Complex32;

const SI_RNTI: u16 = 0xFFFF;

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

/// RIV → (start RB, length) for a bandwidth of `n` RBs (38.214 §5.1.2.2.2).
fn riv_decode(riv: usize, n: usize) -> (usize, usize) {
    let l0 = riv / n + 1;
    let s0 = riv % n;
    if l0 <= n - s0 {
        (s0, l0)
    } else {
        (n - 1 - s0, n - l0 + 2)
    }
}

fn main() {
    let tx = arg("--tx", "tcp://127.0.0.1:2100");
    let rx = arg("--rx", "tcp://127.0.0.1:2101");
    let fs: f64 = arg("--srate", "15.36e6").parse().unwrap();
    let center_hz: f64 = arg("--center-mhz", "3390.0").parse::<f64>().unwrap() * 1e6;
    let n_frames: usize = arg("--frames", "80").parse().unwrap();

    let fft = (fs / 30_000.0).round() as usize;
    let searcher = CellSearcher::new(fft, 1);
    let mut sync = FrameSync::new(fft, fs);
    let frame_len = sync.frame_len();
    let ofdm = Ofdm::new(fft);

    let mut ul = ZmqSink::bind(&rx, fs, 1024).expect("bind UL");
    std::thread::spawn(move || loop {
        if ul.serve_zeros().is_err() {
            break;
        }
    });
    let dl = ZmqSource::connect(&tx, fs, 5_000).expect("connect DL");
    let mut stream = BufferedStream::spawn(dl, 32 * 1024);

    // Acquire.
    let mut cap = vec![Complex32::default(); frame_len * 6 / 5];
    stream.read_exact(&mut cap).expect("capture");
    let (df, _r, shifted) = gscn_scan(&cap, fs, center_hz, &searcher).expect("no SSB");
    let acq = sync.acquire(&shifted).expect("acquire");
    let mib = acq.mib;
    let k_ssb = (mib.k_ssb_msb << 4) | mib.ssb_subcarrier_offset;
    let coreset = Coreset0::from_index_30_30_minbw5_10(mib.pdcch_config_sib1 >> 4).expect("coreset0");
    let first_sc = coreset.first_subcarrier_rel_ssb_centre(k_ssb);
    let sc_to_bin = move |sc: i32| (first_sc + sc).rem_euclid(fft as i32) as usize;
    let a_len = dci_1_0_si_size(coreset.n_rb);
    let candidates = type0_candidates(coreset.n_cce());
    println!(
        "acquired PCI {} SFN {}  coreset0 {}RB x {}sym  (DCI size {a_len})",
        acq.cell_id, mib.sfn, coreset.n_rb, coreset.n_symb
    );
    stream.skip(acq.skip_to_frame).expect("skip");

    let slot_len = frame_len / 20;
    let mut frame = vec![Complex32::default(); frame_len];
    for _ in 0..n_frames {
        let start_idx = stream.position();
        stream.read_exact(&mut frame).expect("stream ended");
        let fsh = freq_shift(&frame, -df, fs, start_idx);
        let Some(rep) = sync.track(&fsh) else {
            println!("lost lock");
            break;
        };
        if rep.sfn % 2 != 0 {
            continue;
        }
        for slot in 0..2u32 {
            let base = slot as usize * slot_len;
            // PDCCH: CORESET symbols 0..n_symb of this slot.
            let mut cgrids = Vec::new();
            let mut off = base;
            for l in 0..coreset.n_symb {
                let cp = ofdm.cp_len((slot as usize) * 14 + l, 1);
                cgrids.push(ofdm.demodulate_symbol(&fsh[off..], cp));
                off += cp + fft;
            }
            let mut dci = None;
            for cand in &candidates {
                let mut llrs = equalize_candidate(&cgrids, |sc: usize| sc_to_bin(sc as i32), &coreset, acq.cell_id, slot, cand);
                pdcch_descramble_llr(&mut llrs, u32::from(acq.cell_id));
                if let Some(bits) = dci_decode(&llrs, SI_RNTI, a_len) {
                    dci = Some(bits);
                    break;
                }
            }
            let Some(bits) = dci else { continue };

            // Parse DCI 1_0 (SI-RNTI) freq/time fields.
            let riv_bits = usize::BITS as usize - ((coreset.n_rb * (coreset.n_rb + 1) / 2) - 1).leading_zeros() as usize;
            let riv = bits[..riv_bits].iter().fold(0usize, |a, &b| a << 1 | b as usize);
            let tdra = bits[riv_bits..riv_bits + 4].iter().fold(0u8, |a, &b| a << 1 | b);
            let mcs = bits[riv_bits + 5..riv_bits + 10].iter().fold(0u8, |a, &b| a << 1 | b);
            let (rb_start, n_rb) = riv_decode(riv, coreset.n_rb);
            // TDRA row 1 (field 0), dmrs-TypeA-Position=2 → S=2, L=12.
            let (s_sym, l_sym) = ([2usize, 2, 2, 2, 2][tdra.min(4) as usize], [12usize, 10, 9, 7, 5][tdra.min(4) as usize]);
            let (qm, r) = mcs_params(mcs);
            // DM-RS symbols (Type A, single-symbol, additionalPosition pos2,
            // ld = S+L): {l0, 7, 11} with l0 = dmrs-TypeA-Position = 2.
            let dmrs_symbols = vec![2usize, 7, 11];
            let alloc = PdschAlloc {
                rb_start,
                n_rb,
                sym_start: s_sym,
                n_sym: l_sym,
                dmrs_symbols: dmrs_symbols.clone(),
                qm: qm as usize,
            };
            println!(
                "SFN {} slot {slot}: SIB1 DCI  RB {rb_start}+{n_rb}  sym {s_sym}+{l_sym}  MCS {mcs} (Qm {qm}, R {:.3})",
                rep.sfn, r
            );

            let grids = demod_slot(&ofdm, &fsh, base, slot as usize % 2, 1).expect("demod slot");

            // Probe: for each candidate symbol, the best DM-RS correlation over
            // even subcarriers across base offsets → reveals the real DM-RS symbols.
            if std::env::args().any(|a| a == "--probe") {
                use ferrite_phy::pdsch::pdsch_dmrs;
                for l in s_sym..s_sym + l_sym {
                    let mut best = 0f32;
                    let mut best_b = 0usize;
                    let mut phase = 0f32;
                    for b in 0..coreset.n_rb + 40 {
                        let refs = pdsch_dmrs(acq.cell_id, slot, l as u32, 6 * (b + rb_start + n_rb));
                        let mut acc = Complex32::new(0.0, 0.0);
                        let mut pow = 0f32;
                        for rb in 0..n_rb {
                            for j in 0..6 {
                                let k = 12 * (rb_start + rb) as i32 + 2 * j as i32;
                                let rx = grids[l][sc_to_bin(k)];
                                acc += rx * refs[6 * (b + rb_start + rb) + j].conj();
                                pow += rx.norm_sqr();
                            }
                        }
                        let m = acc.norm() / (pow.sqrt() * (n_rb as f32 * 6.0).sqrt());
                        if m > best {
                            best = m;
                            best_b = b;
                            phase = acc.arg();
                        }
                    }
                    if best > 0.5 {
                        println!("    symbol {l:>2}: corr {best:.3} @ base {best_b}  phase {:.2} rad", phase);
                    }
                }
            }

            // Scan the DM-RS sequence base (unknown CRB offset) by correlation.
            let best_base = (0..coreset.n_rb + 40)
                .map(|b| (b, extract_pdsch(&grids, sc_to_bin, &alloc, acq.cell_id, slot, 6 * b, SI_RNTI, acq.cell_id, false).dmrs_metric))
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .unwrap()
                .0;
            let n_re_prb = 12 * l_sym - ndmrs_per_prb(dmrs_symbols.len());
            let tbs = transport_block_size(n_re_prb, n_rb, qm, r, 1);

            if let Some(path) = std::env::args().position(|a| a == "--capture").and_then(|i| std::env::args().nth(i + 1)) {
                use ferrite_phy::pdsch::capture_data_res;
                let recs = capture_data_res(&grids, sc_to_bin, &alloc, acq.cell_id, slot, 6 * best_base);
                let mut bytes = Vec::new();
                bytes.extend((acq.cell_id as u32).to_le_bytes());
                bytes.extend((tbs as u32).to_le_bytes());
                for (rb, sc, l, re, im) in recs {
                    bytes.extend([rb as u8, sc as u8, l as u8]);
                    bytes.extend(re.to_le_bytes());
                    bytes.extend(im.to_le_bytes());
                }
                std::fs::write(&path, bytes).ok();
                println!("  captured -> {path}");
                return;
            }

            use ferrite_phy::pdsch::{descramble_llrs, pdsch_scramble_c_init};
            let mut decoded = None;
            'outer: for time_first in [false, true] {
                let p = extract_pdsch(&grids, sc_to_bin, &alloc, acq.cell_id, slot, 6 * best_base, SI_RNTI, acq.cell_id, time_first);
                let order = if time_first { "l,k'" } else { "k',l" };
                println!(
                    "  PDSCH [{order}]: {} data REs, G={} bits, TBS={tbs}, dmrs {:.3}, EVM {:.3}",
                    p.n_data_re, p.n_data_re * qm as usize, p.dmrs_metric, p.evm
                );
                // Descramble with SI-RNTI, then brute-force the QPSK symmetries
                // (rotation/reflection) — the oracle disambiguates convention.
                let mut base = p.llrs.clone();
                descramble_llrs(&mut base, pdsch_scramble_c_init(SI_RNTI, acq.cell_id));
                // All 8 QPSK dihedral symmetries (4 rotations + 4 reflections):
                // EVM=0 only pins the symbol to *a* QPSK point, so a channel
                // phase ambiguity of 90°/180°/270° still passes EVM.
                let transforms: [(&str, fn(f32, f32) -> (f32, f32)); 8] = [
                    ("rot0", |re, im| (re, im)),
                    ("rot90", |re, im| (-im, re)),
                    ("rot180", |re, im| (-re, -im)),
                    ("rot270", |re, im| (im, -re)),
                    ("conj", |re, im| (re, -im)),
                    ("negre", |re, im| (-re, im)),
                    ("swap", |re, im| (im, re)),
                    ("swapneg", |re, im| (-im, -re)),
                ];
                for (name, t) in transforms {
                    let llrs: Vec<f32> = base
                        .chunks_exact(2)
                        .flat_map(|c| {
                            let (a, b) = t(c[0], c[1]);
                            [a, b]
                        })
                        .collect();
                    let (tb, conv) = ferrite_phy::coding::dlsch::dlsch_decode_single_dbg(&llrs, tbs, r, qm as usize, 0, 60);
                    if conv {
                        println!("  order={order} transform={name}: LDPC CONVERGED, crc={}", tb.is_some());
                    }
                    if let Some(tb) = tb {
                        println!("  -> decoded with order={order} transform={name}");
                        decoded = Some(tb);
                        break 'outer;
                    }
                }
            }
            match decoded {
                Some(tb) => {
                    println!("  *** SIB1 DECODED: {tbs}-bit TB, CRC OK ***");
                    let hex: String = tb.chunks(8).map(|c| format!("{:02x}", c.iter().fold(0u8, |a, &b| a << 1 | b))).collect();
                    println!("  TB (hex): {hex}");
                    return;
                }
                None => println!("  DL-SCH CRC failed on both orderings"),
            }
        }
    }
    println!("no SIB1 decoded");
    std::process::exit(1);
}
