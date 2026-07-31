//! Offline reproduction of the live 2-RB MCS-9 DRB decode failure. Loads OCUDU's
//! transmitted PDSCH grid (pdsch_grid_drb dump: "rb sc l re im") for a KNOWN 42-byte
//! TB, runs Ferrite's extract_pdsch + descramble + dlsch decode exactly as the live
//! UE does, and checks whether it recovers the TB. Since the ZMQ channel is lossless,
//! this grid IS what the UE receives — so a failure here reproduces the bug offline.
//!
//! Usage: pdsch-grid-drb <drb_grid.txt>

use ferrite_phy::coding::dlsch::dlsch_decode_single_bits;
use ferrite_phy::pdsch::{descramble_llrs, extract_pdsch, pdsch_scramble_c_init, PdschAlloc};
use ferrite_phy::pdsch_params::mcs_params;
use num_complex::Complex32;

fn pack_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &b)| a | (b << (7 - i)))).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: pdsch-grid-drb <drb_grid.txt>");
    let cell_id = 1u16;
    let crnti: u16 = std::env::var("CRNTI").ok().and_then(|v| u16::from_str_radix(v.trim_start_matches("0x"), 16).ok()).unwrap_or(0x4626);
    let slot_idx: u32 = std::env::var("SLOT").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let (rb_start, n_rb, mcs, rv) = (0usize, 2usize, 9u8, 0u8);
    let check_tb = std::env::var("NOCHECK").is_err(); // live grid has an unknown TB

    // Known TB: tb[i] = (i*37 + 13) & 0xff. MUST match pdsch_grid_drb.cpp.
    let tb_true: Vec<u8> = (0..42).map(|i| ((i * 37 + 13) & 0xff) as u8).collect();

    // Load grid into grids[l][bin], 14 symbols × 288 bins (24 RB BWP). PDSCH at bins 0..23.
    let mut grids: Vec<Vec<Complex32>> = vec![vec![Complex32::new(0.0, 0.0); 24 * 12]; 14];
    for line in std::fs::read_to_string(&path).unwrap().lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 5 { continue; }
        let (rb, sc, l): (usize, usize, usize) = (f[0].parse().unwrap(), f[1].parse().unwrap(), f[2].parse().unwrap());
        let (re, im): (f32, f32) = (f[3].parse().unwrap(), f[4].parse().unwrap());
        grids[l][rb * 12 + sc] = Complex32::new(re, im);
    }
    // Optionally inject a per-symbol CFO phase e^{j·cfo·l} (FERRITE_CFO rad/symbol)
    // and/or a per-subcarrier timing phase e^{j·freq·k} (FERRITE_FREQ rad/subcarrier,
    // k = absolute subcarrier). Reproduces demod artifacts on the clean grid.
    let cfo: f32 = std::env::var("FERRITE_CFO").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let freq: f32 = std::env::var("FERRITE_FREQ").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    if cfo != 0.0 || freq != 0.0 {
        for (l, g) in grids.iter_mut().enumerate() {
            for (k, z) in g.iter_mut().enumerate() {
                *z *= Complex32::from_polar(1.0, cfo * l as f32 + freq * k as f32);
            }
        }
        eprintln!("[injected CFO={cfo} rad/symbol, FREQ={freq} rad/subcarrier]");
    }
    let sc_to_bin = |k: i32| k as usize; // PDSCH at BWP start → identity

    let (qm, r) = mcs_params(mcs);
    let (qm, r) = (qm as usize, r);
    println!("TB(true) = {}", tb_true.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("qm={qm} r={r:.4}");

    for (cdm, time_first) in [(1usize, true), (1, false), (2, true), (2, false)] {
        let n_re = n_rb * ((12 - 3) * 12 + if cdm == 1 { 3 * 6 } else { 0 });
        // tbs_from_nre inline (from main.rs)
        let n_info = (n_re as f64 * r * qm as f64).floor() as usize;
        let tbs = {
            const TBL: &[usize] = &[24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,208,224,240,256,272,288,304,320,336,352,368,384,408,432,456,480,504,528,552,576,608,640,672,704,736,768,808,848,888,928,984,1032,1064,1128,1160,1192,1224,1256,1288,1320,1352,1416,1480,1544,1608,1672,1736,1800,1864,1928,2024,2088,2152,2216,2280,2408,2472,2536,2600,2664,2728,2792,2856,2976,3104,3240,3368,3496,3624,3752,3824];
            let n = (((n_info as f64).log2().floor() as i64) - 6).max(3) as u32;
            let n_info_p = 24.max((1 << n) * (n_info / (1 << n)));
            *TBL.iter().find(|&&t| t >= n_info_p).unwrap_or(&3824)
        };
        let alloc = PdschAlloc { rb_start, n_rb, sym_start: 2, n_sym: 12, dmrs_symbols: vec![2, 7, 11], qm, n_bwp: 0, nof_cdm_groups: cdm };
        let px = extract_pdsch(&grids, sc_to_bin, &alloc, cell_id, slot_idx, 0, crnti, cell_id, time_first);
        let mut llr = px.llrs.clone();
        descramble_llrs(&mut llr, pdsch_scramble_c_init(crnti, cell_id));
        let (bits, conv, crc) = dlsch_decode_single_bits(&llr, tbs, r, qm, rv, 40);
        let tb = pack_bits(&bits);
        let matches = check_tb && tb.len() >= tb_true.len() && tb[..tb_true.len()] == tb_true[..];
        println!(
            "cdm={cdm} tf={time_first} tbs={tbs} n_re={} evm={:.4} slope={:.3} conv={conv} crc={crc} MATCH={matches}",
            px.n_data_re, px.evm, px.dbg_slope,
        );
        if crc {
            println!("   decoded tb = {}", tb.iter().take(tb_true.len()).map(|b| format!("{b:02x}")).collect::<String>());
            // Re-encode the decoded TB and count how many DESCRAMBLED-LLR signs disagree
            // with the re-encoded codeword. 0 ⇒ the grid faithfully carries this TB (so a
            // plausible-check bug); N>0 ⇒ the LDPC moved N bits to reach a nearby codeword
            // (so the true TB differs and the LLRs are subtly corrupt).
            let tb_bits: Vec<u8> = tb.iter().flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1)).take(336).collect();
            let cw = ferrite_phy::coding::dlsch::dlsch_encode_single(&tb_bits, 504, r, qm, rv);
            let mut ll = px.llrs.clone();
            descramble_llrs(&mut ll, pdsch_scramble_c_init(crnti, cell_id));
            let mism = cw.iter().zip(&ll).filter(|(&b, &l)| (l < 0.0) as u8 != b).count();
            println!("   re-encode vs descrambled-LLR signs: {mism}/{} disagree (0 ⇒ faithful)", cw.len());
        }
    }
}
