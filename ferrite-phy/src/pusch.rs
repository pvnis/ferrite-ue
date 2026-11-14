//! PUSCH (uplink shared channel) modulation — CP-OFDM or DFT-s-OFDM (transform
//! precoding). Scramble the UL-SCH bits (TS 38.211 §6.3.1.1), map them to
//! π/2-BPSK/QPSK/16/64/256-QAM (§5.1), place data and DM-RS on the allocated
//! RBs/symbols, optionally DFT every data symbol (§6.3.1.4), and IFFT each
//! OFDM symbol.
//!
//! UL-SCH channel coding is identical to DL-SCH (reuse `coding::dlsch`). Without
//! transform precoding the PUSCH DM-RS sequence uses the same `c_init` as PDSCH
//! (reuse `pdsch_dmrs`); with it the DM-RS is the low-PAPR sequence of
//! §6.4.1.1.1.2 (group / sequence hopping per §6.4.1.1.1.2).

use crate::pdsch::{pdsch_dmrs, pdsch_scramble_c_init};
use crate::sequence::gold_sequence;
use crate::Ofdm;
use num_complex::Complex32;

/// Msg3 PUSCH resource allocation on the initial UL BWP (relative to the UL
/// carrier, which is centred at DC in the IFFT).
#[derive(Clone, Debug)]
pub struct PuschAlloc {
    /// First RB, relative to the UL carrier.
    pub rb_start: usize,
    /// Number of RBs.
    pub n_rb: usize,
    /// First OFDM symbol and number of symbols of the allocation (TS 38.214
    /// §6.1.2.1): data goes on `[sym_start, sym_start + n_sym)` minus the DM-RS.
    pub sym_start: usize,
    pub n_sym: usize,
    /// Slot symbols carrying single-symbol DM-RS (config type 1, CDM group 0).
    pub dmrs_symbols: Vec<usize>,
    /// Modulation order (2 = QPSK).
    pub qm: usize,
    /// UL carrier size in RBs (for DC-centred subcarrier→bin mapping).
    pub carrier_rb: usize,
    /// CRB of the carrier's RB 0 (= offsetToPointA in this SCS). The PUSCH DM-RS
    /// sequence is referenced to CRB 0 / point A (§6.4.1.1.1.2), so the sequence
    /// index is `6·(crb_offset + PRB) + j`, not `6·PRB + j`.
    pub crb_offset: usize,
    /// Transform precoding (DFT-s-OFDM, TS 38.211 §6.3.1.4): `Some` enables
    /// the DFT over the `12·n_rb` subcarriers of every data symbol and replaces
    /// the gold-sequence DM-RS by the low-PAPR DM-RS of §6.4.1.1.1.2.
    pub transform_precoding: Option<TransformPrecoding>,
}

/// Transform-precoded PUSCH DM-RS parameters (TS 38.211 §6.4.1.1.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformPrecoding {
    /// `n_ID^RS`: `nPUSCH-Identity` when configured, else the cell id.
    pub n_id_rs: u16,
    /// Group hopping (`groupHoppingEnabledTransformPrecoding` and not
    /// disabled by `sequenceGroupHopping`).
    pub group_hopping: bool,
    /// Sequence hopping (`sequenceHopping`), only effective for ≥ 6 PRBs... per
    /// the spec, for `M_ZC ≥ 6·N_RB^sc` i.e. 12 PRBs and more.
    pub sequence_hopping: bool,
}

/// Low-PAPR DM-RS sequence `r(n)`, `n = 0..6·n_rb`, of one transform-precoded
/// PUSCH DM-RS symbol `l` in slot `n_slot` (TS 38.211 §6.4.1.1.1.2 with §6.3.1.4
/// group `u = (f_gh + n_ID^RS) mod 30` and sequence number `v`). `None` when
/// `6·n_rb` is not a supported low-PAPR length (`n_rb` not of the form 2^a·3^b·5^c).
pub fn tp_dmrs_sequence(
    tp: &TransformPrecoding,
    n_rb: usize,
    n_slot: u32,
    l: usize,
) -> Option<Vec<Complex32>> {
    let n_id = tp.n_id_rs as u32;
    let f_gh = if tp.group_hopping {
        let c = gold_sequence(n_id / 30, 8 * (14 * n_slot as usize + l) + 8);
        (0..8)
            .map(|m| (c[8 * (14 * n_slot as usize + l) + m] as u32) << m)
            .sum::<u32>()
            % 30
    } else {
        0
    };
    let u = ((f_gh + n_id) % 30) as u8;
    let m_zc = 6 * n_rb;
    let v = if tp.sequence_hopping && !tp.group_hopping && m_zc >= 72 {
        let c = gold_sequence((n_id / 30) * 32 + n_id % 30, 14 * n_slot as usize + l + 1);
        c[14 * n_slot as usize + l]
    } else {
        0
    };
    crate::srs::low_papr_base_sequence(u, v, m_zc)
}

/// Whether `n_rb` PRBs can carry a transform-precoded PUSCH (TS 38.211
/// §6.3.1.4: `2^a·3^b·5^c`).
pub fn tp_prb_valid(n_rb: usize) -> bool {
    if n_rb == 0 {
        return false;
    }
    let mut n = n_rb;
    for p in [2, 3, 5] {
        while n.is_multiple_of(p) {
            n /= p;
        }
    }
    n_rb > 0 && n == 1
}

/// π/2-BPSK (TS 38.211 §5.1.1): bit `b` at modulation-symbol index `i`.
fn pi2_bpsk(b: u8, i: usize) -> Complex32 {
    let v = (1 - 2 * b as i32) as f32 * std::f32::consts::FRAC_1_SQRT_2;
    let d = Complex32::new(v, v);
    if i % 2 == 1 {
        Complex32::new(-d.im, d.re)
    } else {
        d
    }
}

/// Modulate one RE's bits: π/2-BPSK (`Q_m = 1`, needs the symbol index) or QAM.
fn modulate_re(bits: &[u8], i: usize) -> Complex32 {
    if bits.len() == 1 {
        pi2_bpsk(bits[0], i)
    } else {
        qam_modulate(bits)
    }
}

/// Map `Q_m = bits.len()` bits (2, 4, 6 or 8) to one QPSK / 16-QAM / 64-QAM /
/// 256-QAM symbol (TS 38.211 §5.1.3–5.1.6): even-indexed bits form the I
/// level, odd-indexed bits the Q level, the first bit of each axis is the
/// sign and every further bit folds the magnitude.
pub fn qam_modulate(bits: &[u8]) -> Complex32 {
    let qm = bits.len();
    debug_assert!(
        matches!(qm, 2 | 4 | 6 | 8),
        "unsupported modulation order {qm}"
    );
    let m = qm / 2;
    let axis = |first: usize| {
        let b = |i: usize| 1.0 - 2.0 * f32::from(bits[first + 2 * i]);
        // 38.211: x = s0·(2^(m−1) − s1·(2^(m−2) − … (2 − s_{m−1})))
        let mut v = 1.0f32;
        for i in (1..m).rev() {
            v = (1 << (m - i)) as f32 - b(i) * v;
        }
        b(0) * v
    };
    let scale = 1.0 / [2.0f32, 10.0, 42.0, 170.0][m - 1].sqrt();
    Complex32::new(axis(0) * scale, axis(1) * scale)
}

/// Modulate one PUSCH slot (14 OFDM symbols) carrying `ulsch` rate-matched bits.
/// Returns the CP-OFDM time-domain samples for the slot. `slot_in_frame` drives
/// the DM-RS sequence, `slot_in_subframe` (0/1 at μ=1) the cyclic-prefix pattern.
///
/// `center_freq_hz` applies the TS 38.211 §5.4 per-symbol phase compensation
/// (multiply symbol l by `exp(-j2π·f_c·t_start,l)`, `t_start` from the subframe
/// start): the gNB's OFDM demodulator removes this using the carrier centre
/// frequency, so an uncompensated uplink decodes at a garbage SINR. Pass 0.0 to
/// disable (e.g. for the self-consistent round-trip test). `fs` is the sample rate.
#[allow(clippy::too_many_arguments)]
pub fn pusch_modulate_slot(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    mu: u8,
    tc_rnti: u16,
    center_freq_hz: f64,
    fs: f64,
) -> Vec<Complex32> {
    pusch_modulate_slot_uci(
        ofdm,
        ulsch,
        alloc,
        cell_id,
        slot_in_frame,
        slot_in_subframe,
        mu,
        tc_rnti,
        center_freq_hz,
        fs,
        &[],
        0.0,
        0,
    )
}

/// As `pusch_modulate_slot`, but multiplex up to 2 HARQ-ACK bits onto the PUSCH
/// (UCI-on-PUSCH, TS 38.212 §6.2.7 / 38.213 §9.3): the gNB moves the DL HARQ-ACK
/// onto a scheduled PUSCH instead of the PUCCH. For ≤2 bits the ACK PUNCTURES the
/// UL-SCH (the UL-SCH rate-match is unchanged; the ACK REs overwrite data REs), so
/// only the ACK RE placement + encoding differ. `beta_harq` = beta_offset_harq_ack
/// value, `tb_bits` = UL-SCH transport-block size (bits) for Q'_ACK. `harq_ack`
/// empty ⇒ identical to `pusch_modulate_slot`.
#[allow(clippy::too_many_arguments)]
pub fn pusch_modulate_slot_uci(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    mu: u8,
    tc_rnti: u16,
    center_freq_hz: f64,
    fs: f64,
    harq_ack: &[u8],
    beta_harq: f32,
    tb_bits: usize,
) -> Vec<Complex32> {
    pusch_modulate_slot_uci_csi(
        ofdm,
        ulsch,
        alloc,
        cell_id,
        slot_in_frame,
        slot_in_subframe,
        mu,
        tc_rnti,
        center_freq_hz,
        fs,
        harq_ack,
        beta_harq,
        tb_bits,
        &[],
        &[],
    )
}

/// As `pusch_modulate_slot_uci`, additionally multiplexing a CSI part 1 report
/// (TS 38.212 §6.2.7): the CSI REs (see `csi1_pusch_res`, β = `beta_csi`, α = 1) carry
/// the RM(32,O)-coded report, and the UL-SCH data is RATE-MATCHED around them — the
/// caller must have encoded `ulsch` to `E − 2·Q'_CSI` bits. Scrambling is indexed by
/// RE position (the gNB descrambles the multiplexed stream in mapping order), which
/// reduces to the plain stream scrambling when no CSI is present.
#[allow(clippy::too_many_arguments)]
pub fn pusch_modulate_slot_uci_csi(
    ofdm: &Ofdm,
    ulsch: &[u8],
    alloc: &PuschAlloc,
    cell_id: u16,
    slot_in_frame: u32,
    slot_in_subframe: usize,
    mu: u8,
    tc_rnti: u16,
    center_freq_hz: f64,
    fs: f64,
    harq_ack: &[u8],
    beta_harq: f32,
    tb_bits: usize,
    csi1: &[u8],
    csi_res: &[(usize, usize)],
) -> Vec<Complex32> {
    let n = ofdm.fft_size();
    let center = alloc.carrier_rb * 6; // DC subcarrier index of the UL carrier
    let bin = |sc: usize| (sc as i32 - center as i32).rem_euclid(n as i32) as usize;

    let dmrs_set: std::collections::HashSet<usize> = alloc.dmrs_symbols.iter().copied().collect();
    let data_syms: Vec<usize> = (alloc.sym_start..alloc.sym_start + alloc.n_sym)
        .filter(|l| !dmrs_set.contains(l))
        .collect();
    let n_sc = 12 * alloc.n_rb;
    let n_re = data_syms.len() * n_sc;
    let qm = alloc.qm;

    // CSI part 1 REs by map index (k'-first-then-l order) → coded-bit-pair index.
    let mut csi_at: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let rm_csi = if !csi1.is_empty() {
        for (ci, &(l, sc_a)) in csi_res.iter().enumerate() {
            let sym_pos = data_syms.iter().position(|&x| x == l).unwrap();
            csi_at.insert(sym_pos * n_sc + sc_a, ci);
        }
        rm_encode(csi1, csi_res.len() * qm)
    } else {
        Vec::new()
    };

    // Scramble (§6.3.1.1): c_init = n_RNTI·2^15 + n_ID (n_RNTI = TC-RNTI, n_ID = PCI).
    // Indexed by RE position over the whole mapping (identical to the plain stream
    // scrambling when the data occupies every RE).
    let c = gold_sequence(pdsch_scramble_c_init(tc_rnti, cell_id), qm * n_re);

    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 14];
    // Data in §6.3.1.6 order: increasing k' (subcarrier over RBs) first, then l,
    // skipping the CSI REs (the UL-SCH is rate-matched around them).
    let mut src = 0usize; // next UL-SCH bit
    let mut re_bits = vec![0u8; qm];
    for (di, (&l, kp)) in data_syms
        .iter()
        .flat_map(|l| (0..n_sc).map(move |kp| (l, kp)))
        .enumerate()
    {
        let sc = 12 * alloc.rb_start + kp;
        if let Some(&ci) = csi_at.get(&di) {
            for i in 0..qm {
                re_bits[i] = rm_csi[qm * ci + i] ^ c[qm * di + i];
            }
            grids[l][bin(sc)] = modulate_re(&re_bits, di);
        } else if src + qm <= ulsch.len() {
            for i in 0..qm {
                re_bits[i] = ulsch[src + i] ^ c[qm * di + i];
            }
            grids[l][bin(sc)] = modulate_re(&re_bits, di);
            src += qm;
        }
    }
    // DM-RS (config type 1, CDM group 0: even subcarriers). The DM-RS symbols
    // carry no data (two CDM groups without data, TS 38.214 §6.2.2), so the
    // DM-RS EPRE is 3 dB above the data EPRE (Table 6.2.2-1).
    let dmrs_boost = std::f32::consts::SQRT_2;
    for &l in &alloc.dmrs_symbols {
        if let Some(tp) = &alloc.transform_precoding {
            // Low-PAPR sequence over the allocation (§6.4.1.1.1.2): r(n) on the
            // n-th even subcarrier of the allocated PRBs.
            if let Some(seq) = tp_dmrs_sequence(tp, alloc.n_rb, slot_in_frame, l) {
                for (i, r) in seq.iter().enumerate() {
                    grids[l][bin(12 * alloc.rb_start + 2 * i)] = r * dmrs_boost;
                }
            }
            continue;
        }
        // Gold sequence referenced to CRB 0 (point A): index by
        // 6·(crb_offset + PRB) + j.
        let refs = pdsch_dmrs(
            cell_id,
            slot_in_frame,
            l as u32,
            6 * (alloc.crb_offset + alloc.carrier_rb),
        );
        for rb in 0..alloc.n_rb {
            for j in 0..6 {
                let sc = 12 * (alloc.rb_start + rb) + 2 * j;
                grids[l][bin(sc)] =
                    refs[6 * (alloc.crb_offset + alloc.rb_start + rb) + j] * dmrs_boost;
            }
        }
    }

    // UCI-on-PUSCH: overwrite (puncture) the selected data REs with the HARQ-ACK
    // symbols. Each ACK RE is at data index `di` in the k'-first, then-l map; the
    // scrambling bits are c[Qm·di ..] (same sequence as the data).
    //   1-2 bits: small-block "placeholder" code (TS 38.212 Table 5.3.3.1-1/2):
    //     1 bit → [c0, y, x, …], 2 bits → [c0, c1, x, …], [c2, c0, x, …], [c1, c2, x, …];
    //     scrambling (§6.3.1.1) maps x → 1 and y → the previous scrambled bit.
    //   3-11 bits: Reed-Muller (32,O) coded, rate-matched to Q'_ACK·Qm bits, scrambled.
    // (For ≥3 bits the gNB actually rate-matches the UL-SCH around the ACK REs; we
    // still puncture, so that PUSCH's own UL data fails CRC and retransmits — but the
    // gNB reads the ACK from these REs regardless, which frees the DL HARQ.)
    if !harq_ack.is_empty() && harq_ack.len() <= 11 {
        let o_ack = harq_ack.len();
        let n_sc = 12 * alloc.n_rb;
        let res = harq_ack_pusch_res(
            &alloc.dmrs_symbols,
            (alloc.sym_start, alloc.n_sym),
            alloc.n_rb,
            o_ack,
            beta_harq,
            tb_bits,
        );
        // Coded bit `k` of the UCI (per RE-pair): ≤2 use the small-block form, ≥3 RM.
        let rm = if o_ack >= 3 {
            rm_encode(harq_ack, res.len() * qm)
        } else {
            Vec::new()
        };
        for (i, &(l, sc_a)) in res.iter().enumerate() {
            let di = data_syms.iter().position(|&x| x == l).unwrap() * n_sc + sc_a;
            let m = &c[qm * di..qm * di + qm];
            // Placeholders (`x`) scramble to 1 whatever the sequence.
            re_bits.iter_mut().for_each(|b| *b = 1);
            match o_ack {
                1 => {
                    let b = harq_ack[0] ^ m[0];
                    re_bits[0] = b;
                    if qm > 1 {
                        re_bits[1] = b; // y: repeat the previous scrambled bit
                    }
                }
                2 => {
                    let seq = [harq_ack[0], harq_ack[1], harq_ack[0] ^ harq_ack[1]];
                    if qm == 1 {
                        re_bits[0] = seq[i % 3] ^ m[0];
                    } else {
                        re_bits[0] = seq[(2 * i) % 3] ^ m[0];
                        re_bits[1] = seq[(2 * i + 1) % 3] ^ m[1];
                    }
                }
                _ => {
                    for k in 0..qm {
                        re_bits[k] = rm[qm * i + k] ^ m[k];
                    }
                }
            }
            grids[l][bin(12 * alloc.rb_start + sc_a)] = modulate_re(&re_bits, di);
        }
    }

    // Transform precoding (§6.3.1.4): y(k) = Σ_i x(i)·e^{−j2πik/M_sc} / √M_sc
    // over the allocated subcarriers of each data symbol (DM-RS symbols are
    // not precoded).
    if alloc.transform_precoding.is_some() {
        let dft = rustfft::FftPlanner::<f32>::new().plan_fft_forward(n_sc);
        let scale = 1.0 / (n_sc as f32).sqrt();
        let mut block = vec![Complex32::new(0.0, 0.0); n_sc];
        for &l in &data_syms {
            for (k, b) in block.iter_mut().enumerate() {
                *b = grids[l][bin(12 * alloc.rb_start + k)];
            }
            dft.process(&mut block);
            for (k, y) in block.iter().enumerate() {
                grids[l][bin(12 * alloc.rb_start + k)] = y * scale;
            }
        }
    }

    let mut out = Vec::with_capacity(14 * (n + 40));
    // Sample offset from the subframe start to this slot's first symbol.
    let mut sub_off: usize = (0..slot_in_subframe * 14)
        .map(|k| ofdm.cp_len(k, mu) + n)
        .sum();
    for (l, grid) in grids.iter().enumerate() {
        let cp = ofdm.cp_len(slot_in_subframe * 14 + l, mu);
        let sym = ofdm.modulate_symbol(grid, cp);
        if center_freq_hz != 0.0 {
            // §5.4 phase compensation: t_start = start of the useful part.
            let t_start = (sub_off + cp) as f64 / fs;
            let phase = -2.0 * std::f64::consts::PI * center_freq_hz * t_start;
            let coeff = Complex32::new(phase.cos() as f32, phase.sin() as f32);
            out.extend(sym.iter().map(|s| s * coeff));
        } else {
            out.extend(sym);
        }
        sub_off += cp + n;
    }
    out
}

/// Reed-Muller (32, O) basis sequences (TS 38.212 Table 5.3.3.2-1), for encoding
/// 3-11 UCI bits.
const RM_BASIS: [[u8; 32]; 11] = [
    [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1,
    ],
    [
        1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0,
        1, 0,
    ],
    [
        0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
        1, 0,
    ],
    [
        0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1,
        1, 0,
    ],
    [
        0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1,
        1, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
        1, 0,
    ],
    [
        0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1,
        1, 0,
    ],
    [
        0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1,
        1, 0,
    ],
    [
        0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1,
        1, 0,
    ],
    [
        0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0,
        1, 0,
    ],
    [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
        1, 0,
    ],
];

/// Encode 3-11 UCI bits with the (32, O) Reed-Muller code (TS 38.212 §5.3.3.2),
/// rate-matched (repeated) to `e` bits.
pub(crate) fn rm_encode(bits: &[u8], e: usize) -> Vec<u8> {
    let mut d = [0u8; 32];
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 {
            for (j, dj) in d.iter_mut().enumerate() {
                *dj ^= RM_BASIS[i][j];
            }
        }
    }
    (0..e).map(|k| d[k % 32]).collect()
}

/// HARQ-ACK-on-PUSCH RE placement for 1-2 ACK bits (QPSK), matching OCUDU's
/// `ulsch_demultiplex` (TS 38.212 §6.2.7): reserve Q'_rvd REs across the non-DM-RS
/// symbols starting after the first DM-RS symbol (strided so each symbol carries a
/// fair share), then place the actual Q'_ACK REs on a strided subset of the reserved
/// ones. Returns each ACK RE as `(symbol, subcarrier-within-alloc)`, in gNB order.
fn harq_ack_pusch_res(
    dmrs_symbols: &[usize],
    sym_range: (usize, usize),
    n_rb: usize,
    o_ack: usize,
    beta: f32,
    tb_bits: usize,
) -> Vec<(usize, usize)> {
    let n_sc = 12 * n_rb;
    let dmrs: std::collections::HashSet<usize> = dmrs_symbols.iter().copied().collect();
    let data_syms: Vec<usize> = (sym_range.0..sym_range.0 + sym_range.1)
        .filter(|l| !dmrs.contains(l))
        .collect();
    let first_dmrs = *dmrs_symbols.iter().min().unwrap();
    let l1 = match data_syms.iter().find(|&&l| l > first_dmrs) {
        Some(&l) => l,
        None => return Vec::new(),
    };
    let nof_re_uci = data_syms.len() * n_sc;
    let nof_re_uci_l0 = data_syms.iter().filter(|&&l| l > first_dmrs).count() * n_sc;
    let crc = if tb_bits <= 3824 { 16 } else { 24 };
    let sum_cb = (tb_bits + crc) as f32;
    // Q'_ACK = min(ceil(O_ACK·β·M_uci / ΣK), ceil(α·M_uci_l0)), α = 1.
    let q_of = |oa: usize| -> usize {
        let left = ((oa as f32) * beta * nof_re_uci as f32 / sum_cb).ceil() as usize;
        left.min(nof_re_uci_l0)
    };
    let q_ack = q_of(o_ack).max(1);
    // >2 ACK bits: select Q'_ACK REs DIRECTLY (Step 2, no reserved set), strided per
    // symbol across the non-DM-RS symbols from l1 (the UL-SCH is rate-matched around
    // them — here punctured, since we don't reduce the UL-SCH E).
    if o_ack >= 3 {
        let mut res = Vec::new();
        let mut placed = 0usize;
        for &l in data_syms.iter().filter(|&&l| l >= l1) {
            let rem = q_ack - placed;
            if rem > 0 {
                let (d, cnt) = if rem < n_sc {
                    (n_sc / rem, rem)
                } else {
                    (1, n_sc)
                };
                for i in 0..cnt {
                    res.push((l, i * d));
                }
                placed += cnt;
            }
            if placed >= q_ack {
                break;
            }
        }
        return res;
    }
    // For <2 ACK bits the reserved count is computed as if there were 2.
    let q_rvd = if o_ack < 2 { q_of(2).max(q_ack) } else { q_ack };

    let mut res = Vec::new();
    let (mut rvd_placed, mut ack_placed) = (0usize, 0usize);
    for &l in data_syms.iter().filter(|&&l| l >= l1) {
        let m_uci = n_sc;
        // Step 1: reserve REs in this symbol (strided across all subcarriers).
        let rem_rvd = q_rvd - rvd_placed;
        let reserved: Vec<usize> = if rem_rvd > 0 {
            let (d, cnt) = if rem_rvd < m_uci {
                (m_uci / rem_rvd, rem_rvd)
            } else {
                (1, m_uci)
            };
            rvd_placed += cnt;
            (0..cnt).map(|i| i * d).collect()
        } else {
            Vec::new()
        };
        // Step 5: place the actual HARQ-ACK on a strided subset of the reserved REs.
        let rem_ack = q_ack - ack_placed;
        if !reserved.is_empty() && rem_ack > 0 {
            let m_rvd = reserved.len();
            let (d2, cnt2) = if rem_ack < m_rvd {
                (m_rvd / rem_ack, rem_ack)
            } else {
                (1, m_rvd)
            };
            for i in 0..cnt2 {
                res.push((l, reserved[i * d2]));
            }
            ack_placed += cnt2;
        }
        if ack_placed >= q_ack {
            break;
        }
    }
    res
}

/// β_offset for CSI part 1/2 on PUSCH by betaOffsetCSI-Part-Index (TS 38.213
/// Table 9.3-2; normative constants).
pub fn beta_offset_csi(index: u8) -> f32 {
    const T: [f32; 19] = [
        1.125, 1.25, 1.375, 1.625, 1.75, 2.0, 2.25, 2.5, 2.875, 3.125, 3.5, 4.0, 5.0, 6.25, 8.0,
        10.0, 12.625, 15.875, 20.0,
    ];
    *T.get(index as usize).unwrap_or(&6.25)
}

/// CSI-part-1-on-PUSCH RE placement (TS 38.212 §6.3.2.4.1.2 count, §6.2.7 mapping,
/// matching OCUDU's `ulsch_demultiplex`): Q'_CSI = min(⌈O·β·M_uci/ΣK_r⌉, ⌈α·M_uci⌉),
/// placed strided per symbol over ALL non-DM-RS symbols from the slot start (unlike
/// HARQ-ACK, which starts after the first DM-RS). `sum_kr` is the UL-SCH's ΣK_r —
/// the LDPC code-block sizes INCLUDING filler (C·K from `seg_params`), NOT TBS+CRC
/// (one RE of difference shifts the whole data map). The UL-SCH is RATE-MATCHED
/// around these REs — the caller must shrink its data E by 2·len() and the mapper
/// must skip them. Returns each CSI RE as `(symbol, subcarrier-within-alloc)`.
pub fn csi1_pusch_res(
    dmrs_symbols: &[usize],
    sym_range: (usize, usize),
    n_rb: usize,
    o_csi: usize,
    beta: f32,
    alpha: f32,
    sum_kr: usize,
) -> Vec<(usize, usize)> {
    let n_sc = 12 * n_rb;
    let dmrs: std::collections::HashSet<usize> = dmrs_symbols.iter().copied().collect();
    let data_syms: Vec<usize> = (sym_range.0..sym_range.0 + sym_range.1)
        .filter(|l| !dmrs.contains(l))
        .collect();
    let nof_re_uci = data_syms.len() * n_sc;
    let sum_cb = sum_kr as f32;
    let q_csi = (((o_csi as f32) * beta * nof_re_uci as f32 / sum_cb).ceil() as usize)
        .min((alpha * nof_re_uci as f32).ceil() as usize)
        .max(1);
    let mut res = Vec::new();
    let mut placed = 0usize;
    for &l in &data_syms {
        let rem = q_csi - placed;
        if rem > 0 {
            let (d, cnt) = if rem < n_sc {
                (n_sc / rem, rem)
            } else {
                (1, n_sc)
            };
            for i in 0..cnt {
                res.push((l, i * d));
            }
            placed += cnt;
        }
        if placed >= q_csi {
            break;
        }
    }
    res
}

/// Number of PUSCH data REs and rate-match length `E = N_RE·Qm` for an
/// allocation (2 DM-RS CDM groups without data → no data on DM-RS symbols).
pub fn pusch_e_len(alloc: &PuschAlloc) -> usize {
    let data_syms = alloc.n_sym - alloc.dmrs_symbols.len();
    data_syms * alloc.n_rb * 12 * alloc.qm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::dlsch::{dlsch_decode_single, dlsch_encode_single};
    use crate::pdsch::descramble_llrs;

    /// HARQ-ACK-on-PUSCH RE placement for 1 bit: dmrs [2,7,11], β=20, TB 1600 bits,
    /// 20 RB → Q'_ACK = ceil(20·2640/1616) = 33 REs, all in symbol 3 (the first
    /// symbol after the first DM-RS), strided at subcarriers 0,6,12,…
    #[test]
    fn harq_ack_pusch_re_placement() {
        let res = harq_ack_pusch_res(&[2, 7, 11], (0, 14), 20, 1, 20.0, 1600);
        assert_eq!(res.len(), 33);
        assert!(res.iter().all(|&(l, sc)| l == 3 && sc < 240));
        assert_eq!(&res[..3], &[(3, 0), (3, 6), (3, 12)]);
    }

    /// Reed-Muller (32,O): input bit i selects basis row i; all-zero → all-zero.
    #[test]
    fn reed_muller_basis() {
        assert!(rm_encode(&[0, 0, 0], 32).iter().all(|&b| b == 0));
        assert_eq!(rm_encode(&[1, 0, 0], 32), RM_BASIS[0]); // row 0 = all ones
        assert_eq!(rm_encode(&[0, 1, 0], 32), RM_BASIS[1]);
        // input [1,1,0] = row0 XOR row1.
        let expect: Vec<u8> = (0..32).map(|j| RM_BASIS[0][j] ^ RM_BASIS[1][j]).collect();
        assert_eq!(rm_encode(&[1, 1, 0], 32), expect);
    }

    /// 3-bit HARQ-ACK RE placement (direct, not reserved): Q'_ACK=ceil(3·20·2640/1616)
    /// = 99 REs in symbol 3, strided at subcarriers 0,2,4,…
    #[test]
    fn harq_ack_pusch_re_placement_3bit() {
        let res = harq_ack_pusch_res(&[2, 7, 11], (0, 14), 20, 3, 20.0, 1600);
        assert_eq!(res.len(), 99);
        assert!(res.iter().all(|&(l, sc)| l == 3 && sc < 240));
        assert_eq!(&res[..3], &[(3, 0), (3, 2), (3, 4)]);
    }

    /// Modulate a Msg3-sized PUSCH, demodulate it, equalise trivially (no
    /// channel), descramble, and recover the transport block.
    #[test]
    fn qam_modulate_matches_38_211() {
        // 16-QAM: bits 0000 → (1+j)/√10 ... Table 5.1.4-1 spot checks.
        let s = 1.0 / 10f32.sqrt();
        let p = qam_modulate(&[0, 0, 0, 0]);
        assert!((p.re - s).abs() < 1e-6 && (p.im - s).abs() < 1e-6);
        let p = qam_modulate(&[0, 0, 1, 1]);
        assert!((p.re - 3.0 * s).abs() < 1e-6 && (p.im - 3.0 * s).abs() < 1e-6);
        let p = qam_modulate(&[1, 0, 1, 0]);
        assert!((p.re + 3.0 * s).abs() < 1e-6 && (p.im - s).abs() < 1e-6);
        // 64-QAM 000000 → (3+3j)/√42, 256-QAM 00000000 → (5+5j)/√170.
        let p = qam_modulate(&[0; 6]);
        assert!((p.re - 3.0 / 42f32.sqrt()).abs() < 1e-6);
        let p = qam_modulate(&[0; 8]);
        assert!((p.re - 5.0 / 170f32.sqrt()).abs() < 1e-6);
        // Every constellation has unit mean power.
        for qm in [2usize, 4, 6, 8] {
            let n = 1usize << qm;
            let pw: f32 = (0..n)
                .map(|v| {
                    qam_modulate(
                        &(0..qm)
                            .map(|i| ((v >> (qm - 1 - i)) & 1) as u8)
                            .collect::<Vec<_>>(),
                    )
                    .norm_sqr()
                })
                .sum::<f32>()
                / n as f32;
            assert!((pw - 1.0).abs() < 1e-5, "qm {qm}: mean power {pw}");
        }
    }

    /// Transform-precoded PUSCH: inverse-DFT each data symbol at the receiver,
    /// demap, descramble, decode; the DM-RS symbols carry the low-PAPR sequence
    /// on the even subcarriers (and nothing on the odd ones).
    #[test]
    fn pusch_transform_precoding_round_trip() {
        let ofdm = Ofdm::new(512);
        let (cell_id, rnti) = (1u16, 0x4601u16);
        let tb_bytes = [
            0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00,
        ];
        let tb: Vec<u8> = tb_bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1))
            .collect();
        let tp = TransformPrecoding {
            n_id_rs: 1,
            group_hopping: false,
            sequence_hopping: false,
        };
        for (qm, n_rb) in [(1usize, 5usize), (2, 5), (4, 6), (6, 8)] {
            let alloc = PuschAlloc {
                rb_start: 2,
                n_rb,
                sym_start: 0,
                n_sym: 14,
                dmrs_symbols: vec![2, 7, 11],
                qm,
                carrier_rb: 24,
                crb_offset: 0,
                transform_precoding: Some(tp),
            };
            let e = pusch_e_len(&alloc);
            let r = 0.05 * qm as f64;
            let ulsch = dlsch_encode_single(&tb, e, r, qm.max(2), 0);
            let slot =
                pusch_modulate_slot(&ofdm, &ulsch, &alloc, cell_id, 5, 1, 1, rnti, 0.0, 15.36e6);
            let center = alloc.carrier_rb as i32 * 6;
            let bin = |sc: usize| (sc as i32 - center).rem_euclid(512) as usize;
            let n_sc = 12 * n_rb;
            let idft = rustfft::FftPlanner::<f32>::new().plan_fft_inverse(n_sc);
            let mut off = 0;
            let mut llr: Vec<f32> = Vec::new();
            let demapper = crate::pdsch::Demapper::new(qm.max(2));
            let mut i = 0usize;
            for l in 0..14 {
                let cp = ofdm.cp_len(14 + l, 1);
                let g = ofdm.demodulate_symbol(&slot[off..], cp);
                off += cp + 512;
                if alloc.dmrs_symbols.contains(&l) {
                    let seq = tp_dmrs_sequence(&tp, n_rb, 5, l).unwrap();
                    for (k, r) in seq.iter().enumerate() {
                        assert!(
                            (g[bin(12 * 2 + 2 * k)] - r * 2f32.sqrt()).norm() < 1e-3,
                            "dmrs l={l} k={k}"
                        );
                        assert!(g[bin(12 * 2 + 2 * k + 1)].norm() < 1e-4);
                    }
                    continue;
                }
                let mut block: Vec<Complex32> = (0..n_sc).map(|k| g[bin(24 + k)]).collect();
                idft.process(&mut block);
                let scale = 1.0 / (n_sc as f32).sqrt();
                for x in &block {
                    let x = x * scale;
                    if qm == 1 {
                        // Undo the π/2 rotation, then read the BPSK sign.
                        let d = if i % 2 == 1 {
                            Complex32::new(x.im, -x.re)
                        } else {
                            x
                        };
                        llr.push(d.re + d.im);
                        i += 1;
                    } else {
                        demapper.demap(x, 1.0, &mut llr);
                    }
                }
            }
            descramble_llrs(&mut llr, pdsch_scramble_c_init(rnti, cell_id));
            if qm == 1 {
                // π/2-BPSK codeword: hard bits must equal the scrambled-then-descrambled UL-SCH.
                let hard: Vec<u8> = llr.iter().map(|&v| u8::from(v < 0.0)).collect();
                assert_eq!(&hard[..ulsch.len()], &ulsch[..], "pi/2-BPSK bits");
            } else {
                let out = dlsch_decode_single(&llr, 88, r, qm, 0, 40)
                    .unwrap_or_else(|| panic!("decode failed at qm {qm}"));
                let out_bytes: Vec<u8> = out
                    .chunks(8)
                    .map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b))
                    .collect();
                assert_eq!(out_bytes, tb_bytes, "qm {qm}");
            }
        }
        assert!(tp_prb_valid(1) && tp_prb_valid(6) && tp_prb_valid(45) && tp_prb_valid(160));
        assert!(!tp_prb_valid(7) && !tp_prb_valid(14) && !tp_prb_valid(0));
    }

    /// Modulate a TB at every modulation order and decode it with the PDSCH
    /// demapper (the gNB side): the mapper and the demapper must agree on the
    /// constellation and on the bit order.
    #[test]
    fn pusch_round_trip_all_orders() {
        let ofdm = Ofdm::new(512);
        let (cell_id, tc_rnti) = (1u16, 0x4601u16);
        let tb_bytes = [
            0x00u8, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x3f, 0x00, 0x00, 0x00,
        ];
        let tb: Vec<u8> = tb_bytes
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1))
            .collect();
        for qm in [2usize, 4, 6, 8] {
            let alloc = PuschAlloc {
                rb_start: 4,
                n_rb: 3,
                sym_start: 0,
                n_sym: 14,
                dmrs_symbols: vec![2, 7, 11],
                qm,
                carrier_rb: 24,
                crb_offset: 0,
                transform_precoding: None,
            };
            let e = pusch_e_len(&alloc);
            assert_eq!(e, 396 * qm);
            let r = 0.117 * qm as f64 / 2.0;
            let ulsch = dlsch_encode_single(&tb, e, r, qm, 0);
            let slot = pusch_modulate_slot(
                &ofdm, &ulsch, &alloc, cell_id, 5, 1, 1, tc_rnti, 0.0, 15.36e6,
            );

            // Demodulate: extract the data REs (skip DM-RS symbols), soft-demap.
            let center = alloc.carrier_rb as i32 * 6;
            let bin = |sc: usize| (sc as i32 - center).rem_euclid(512) as usize;
            let dmrs: std::collections::HashSet<usize> =
                alloc.dmrs_symbols.iter().copied().collect();
            let mut grids = Vec::new();
            let mut off = 0;
            for l in 0..14 {
                let cp = ofdm.cp_len(14 + l, 1);
                grids.push(ofdm.demodulate_symbol(&slot[off..], cp));
                off += cp + 512;
            }
            let demapper = crate::pdsch::Demapper::new(qm);
            let mut llr: Vec<f32> = Vec::new();
            for l in 0..14 {
                if dmrs.contains(&l) {
                    continue;
                }
                for kp in 0..(12 * alloc.n_rb) {
                    let sc = 12 * alloc.rb_start + kp;
                    demapper.demap(grids[l][bin(sc)], 1.0, &mut llr);
                }
            }
            descramble_llrs(&mut llr, pdsch_scramble_c_init(tc_rnti, cell_id));
            let out = dlsch_decode_single(&llr, 88, r, qm, 0, 40)
                .unwrap_or_else(|| panic!("decode failed at qm {qm}"));
            let out_bytes: Vec<u8> = out
                .chunks(8)
                .map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b))
                .collect();
            assert_eq!(out_bytes, tb_bytes, "qm {qm}");
        }
    }
}
