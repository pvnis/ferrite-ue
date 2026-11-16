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
        &[],
        &[],
        &UciLayout::default(),
    )
}

/// As `pusch_modulate_slot`, multiplexing UCI (TS 38.212 §6.2.7): HARQ-ACK
/// bits `harq_ack` and a CSI part 1 report `csi1` on the REs `layout` gives
/// (from [`uci_pusch_layout`] with the same payload sizes). The UL-SCH `ulsch`
/// must be rate-matched to [`UciLayout::ulsch_e`] bits: it is mapped around the
/// CSI REs and, with more than two ACK bits, around the ACK REs; one or two ACK
/// bits puncture it instead. Scrambling is indexed by RE position (the gNB
/// descrambles the multiplexed stream in mapping order), which reduces to the
/// plain stream scrambling without UCI.
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
    csi1: &[u8],
    layout: &UciLayout,
) -> Vec<Complex32> {
    let n = ofdm.fft_size();
    let center = alloc.carrier_rb * 6; // DC subcarrier index of the UL carrier
    let bin = |sc: usize| (sc as i32 - center as i32).rem_euclid(n as i32) as usize;

    let data_syms = data_symbols(alloc);
    let n_sc = 12 * alloc.n_rb;
    let n_re = data_syms.len() * n_sc;
    let qm = alloc.qm;
    // Map index (k'-first, then l) of an RE given as (symbol, subcarrier).
    let map_index = |&(l, sc): &(usize, usize)| {
        data_syms
            .iter()
            .position(|&x| x == l)
            .map(|p| p * n_sc + sc)
    };
    let csi_at: std::collections::HashMap<usize, usize> = layout
        .csi1
        .iter()
        .enumerate()
        .filter_map(|(i, re)| map_index(re).map(|di| (di, i)))
        .collect();
    let ack_at: std::collections::HashMap<usize, usize> = layout
        .ack
        .iter()
        .enumerate()
        .filter_map(|(i, re)| map_index(re).map(|di| (di, i)))
        .collect();
    let rm_csi = if csi1.is_empty() {
        Vec::new()
    } else {
        rm_encode(csi1, layout.csi1.len() * qm)
    };
    let rm_ack = if harq_ack.len() >= 3 {
        rm_encode(harq_ack, layout.ack.len() * qm)
    } else {
        Vec::new()
    };

    // Scramble (§6.3.1.1): c_init = n_RNTI·2^15 + n_ID (n_RNTI = TC-RNTI, n_ID = PCI).
    let c = gold_sequence(pdsch_scramble_c_init(tc_rnti, cell_id), qm * n_re);

    // The scrambled bits of HARQ-ACK RE `i` at map index `di`. One or two bits
    // use the small-block code with placeholders (TS 38.212 §5.3.3.1, scrambled
    // per TS 38.211 §6.3.1.1: `x` → 1, `y` → the previous scrambled bit):
    // 1 bit → [c0, y, x, …]; 2 bits → [c0, c1, x, …], [c2, c0, x, …], [c1, c2, x, …]
    // with c2 = c0 ⊕ c1. Three to eleven bits are Reed-Muller (32, O) coded.
    let ack_bits = |i: usize, di: usize, out: &mut [u8]| {
        let m = &c[qm * di..qm * di + qm];
        out.iter_mut().for_each(|b| *b = 1);
        match harq_ack {
            [b0] => {
                out[0] = b0 ^ m[0];
                if qm > 1 {
                    out[1] = out[0];
                }
            }
            [b0, b1] => {
                let seq = [*b0, *b1, b0 ^ b1];
                if qm == 1 {
                    out[0] = seq[i % 3] ^ m[0];
                } else {
                    out[0] = seq[(2 * i) % 3] ^ m[0];
                    out[1] = seq[(2 * i + 1) % 3] ^ m[1];
                }
            }
            _ => {
                for (k, o) in out.iter_mut().enumerate() {
                    *o = rm_ack.get(qm * i + k).copied().unwrap_or(0) ^ m[k];
                }
            }
        }
    };

    let mut grids = vec![vec![Complex32::new(0.0, 0.0); n]; 14];
    // Map in §6.3.1.6 order: increasing k' (subcarrier over RBs) first, then l.
    let mut src = 0usize; // next UL-SCH bit
    let mut re_bits = vec![0u8; qm];
    for (di, (&l, kp)) in data_syms
        .iter()
        .flat_map(|l| (0..n_sc).map(move |kp| (l, kp)))
        .enumerate()
    {
        let sc = 12 * alloc.rb_start + kp;
        let ack = ack_at.get(&di).copied();
        let filled = if let Some(&ci) = csi_at.get(&di) {
            for (i, b) in re_bits.iter_mut().enumerate() {
                *b = rm_csi.get(qm * ci + i).copied().unwrap_or(0) ^ c[qm * di + i];
            }
            true
        } else if let (Some(i), true) = (ack, layout.ack_rate_matched) {
            ack_bits(i, di, &mut re_bits);
            true
        } else {
            let data = src + qm <= ulsch.len();
            if data {
                for (i, b) in re_bits.iter_mut().enumerate() {
                    *b = ulsch[src + i] ^ c[qm * di + i];
                }
                src += qm;
            }
            // One or two ACK bits puncture the UL-SCH.
            if let Some(i) = ack {
                ack_bits(i, di, &mut re_bits);
            }
            data || ack.is_some()
        };
        if filled {
            grids[l][bin(sc)] = modulate_re(&re_bits, di);
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

/// β_offset for CSI part 1/2 on PUSCH by betaOffsetCSI-Part-Index (TS 38.213
/// Table 9.3-2; normative constants).
pub fn beta_offset_csi(index: u8) -> f32 {
    const T: [f32; 19] = [
        1.125, 1.25, 1.375, 1.625, 1.75, 2.0, 2.25, 2.5, 2.875, 3.125, 3.5, 4.0, 5.0, 6.25, 8.0,
        10.0, 12.625, 15.875, 20.0,
    ];
    *T.get(index as usize).unwrap_or(&6.25)
}

/// The non-DM-RS symbols of an allocation (two DM-RS CDM groups without data:
/// the DM-RS symbols carry no data or UCI).
fn data_symbols(alloc: &PuschAlloc) -> Vec<usize> {
    (alloc.sym_start..alloc.sym_start + alloc.n_sym)
        .filter(|l| !alloc.dmrs_symbols.contains(l))
        .collect()
}

/// UCI payload sizes and coding parameters for [`uci_pusch_layout`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UciSizes {
    /// HARQ-ACK bits (0-11).
    pub o_ack: usize,
    /// CSI part 1 bits (0-11).
    pub o_csi1: usize,
    /// β_offset for the HARQ-ACK (the index matching `o_ack`, TS 38.213 §9.3).
    pub beta_ack: f32,
    /// β_offset for CSI part 1.
    pub beta_csi1: f32,
    /// `uci-OnPUSCH.scaling` α.
    pub alpha: f32,
    /// ΣK_r: the UL-SCH LDPC code-block sizes INCLUDING filler bits (C·K), not
    /// TBS + CRC: one RE of difference shifts the whole map.
    pub sum_kr: usize,
}

/// Where UCI goes on a PUSCH: each HARQ-ACK and CSI part 1 RE as `(symbol,
/// subcarrier within the allocation)`, in coded-bit order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UciLayout {
    pub ack: Vec<(usize, usize)>,
    pub csi1: Vec<(usize, usize)>,
    /// More than two ACK bits: the UL-SCH is rate-matched around the ACK REs
    /// (one or two puncture it).
    pub ack_rate_matched: bool,
}

impl UciLayout {
    /// The UL-SCH rate-matching length E for `alloc` with this UCI, or `None`
    /// if the UCI leaves no room.
    pub fn ulsch_e(&self, alloc: &PuschAlloc) -> Option<usize> {
        let uci_re = self.csi1.len()
            + if self.ack_rate_matched {
                self.ack.len()
            } else {
                0
            };
        pusch_e_len(alloc).checked_sub(alloc.qm * uci_re)
    }
}

/// UCI-on-PUSCH resource counts (TS 38.212 §6.3.2.4.1.1-2) and RE mapping
/// (§6.2.7), with UL-SCH, exactly as OCUDU's `get_ulsch_information` and
/// `ulsch_demultiplex` compute them:
///
/// * Q'_ACK = min(⌈O_ACK·β·M_UCI / ΣK_r⌉, ⌈α·M_UCI(l₀)⌉), M_UCI(l₀) counting
///   the symbols from the first DM-RS on;
/// * with fewer than two ACK bits (none included) Q'_rvd is Q'_ACK for two
///   bits, with two it is Q'_ACK, with more there is no reserved set;
/// * Q'_CSI1 = min(⌈O_CSI·β·M_UCI / ΣK_r⌉, ⌈α·M_UCI⌉ − Q'_ACK,rvd), where the
///   subtrahend is Q'_rvd for up to two ACK bits and Q'_ACK above;
/// * per symbol: reserved REs (from the first symbol after the first DM-RS,
///   strided), then more-than-two ACK REs (same rule), then CSI REs (from the
///   first symbol, strided over the REs not reserved and not ACK), then one or
///   two ACK bits on a strided subset of the reserved REs.
///
/// Payloads above 11 bits need a CRC and polar coding, not implemented: `Err`.
pub fn uci_pusch_layout(alloc: &PuschAlloc, u: &UciSizes) -> Result<UciLayout, String> {
    if u.o_ack > 11 || u.o_csi1 > 11 {
        return Err(format!(
            "UCI on PUSCH with {} HARQ-ACK / {} CSI bits (more than 11 needs polar coding)",
            u.o_ack, u.o_csi1
        ));
    }
    let n_sc = 12 * alloc.n_rb;
    let data_syms = data_symbols(alloc);
    let Some(&first_dmrs) = alloc.dmrs_symbols.iter().min() else {
        return Ok(UciLayout::default());
    };
    let m_uci = data_syms.len() * n_sc;
    let m_uci_l0 = data_syms.iter().filter(|&&l| l > first_dmrs).count() * n_sc;
    let q = |o: usize, beta: f32| -> usize {
        (o as f32 * beta * m_uci as f32 / u.sum_kr.max(1) as f32).ceil() as usize
    };
    let q_ack_of = |o: usize| -> usize {
        if o == 0 {
            0
        } else {
            q(o, u.beta_ack).min((u.alpha * m_uci_l0 as f32).ceil() as usize)
        }
    };
    let q_ack = q_ack_of(u.o_ack);
    let q_rvd = match u.o_ack {
        0 | 1 => q_ack_of(2),
        2 => q_ack,
        _ => 0,
    };
    let q_csi = if u.o_csi1 == 0 {
        0
    } else {
        let ack_for_csi = if u.o_ack <= 2 { q_rvd } else { q_ack };
        q(u.o_csi1, u.beta_csi1)
            .min(((u.alpha * m_uci as f32).ceil() as usize).saturating_sub(ack_for_csi))
    };
    // Every `d`-th of the first `d·count` entries of `set`, where (d, count) =
    // (M / remaining, remaining) if remaining < M, else (1, M).
    let select = |set: &[usize], remaining: usize| -> Vec<usize> {
        let m = set.len();
        let (d, count) = if remaining < m {
            (m / remaining, remaining)
        } else {
            (1, m)
        };
        set.iter().step_by(d).take(count).copied().collect()
    };
    let mut out = UciLayout {
        ack_rate_matched: u.o_ack > 2,
        ..UciLayout::default()
    };
    let (mut rvd_done, mut ack_done, mut csi_done) = (0usize, 0usize, 0usize);
    for &l in &data_syms {
        let after_dmrs = l > first_dmrs;
        let mut uci: Vec<usize> = (0..n_sc).collect();
        let rvd = if after_dmrs && rvd_done < q_rvd {
            let r = select(&uci, q_rvd - rvd_done);
            rvd_done += r.len();
            r
        } else {
            Vec::new()
        };
        let ack_left = q_ack - ack_done;
        if after_dmrs && u.o_ack > 2 && ack_left > 0 {
            let a = select(&uci, ack_left);
            ack_done += a.len();
            uci.retain(|k| !a.contains(k));
            out.ack.extend(a.iter().map(|&k| (l, k)));
        }
        if uci.len() > rvd.len() && csi_done < q_csi {
            let free: Vec<usize> = uci.iter().copied().filter(|k| !rvd.contains(k)).collect();
            let c = select(&free, q_csi - csi_done);
            csi_done += c.len();
            out.csi1.extend(c.iter().map(|&k| (l, k)));
        }
        if !rvd.is_empty() && u.o_ack <= 2 && ack_left > 0 {
            let a = select(&rvd, ack_left);
            ack_done += a.len();
            out.ack.extend(a.iter().map(|&k| (l, k)));
        }
    }
    Ok(out)
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

    fn uci_alloc(n_rb: usize, qm: usize) -> PuschAlloc {
        PuschAlloc {
            rb_start: 0,
            n_rb,
            sym_start: 0,
            n_sym: 14,
            dmrs_symbols: vec![2, 7, 11],
            qm,
            carrier_rb: 24,
            crb_offset: 0,
            transform_precoding: None,
        }
    }

    fn sizes(o_ack: usize, o_csi1: usize, sum_kr: usize) -> UciSizes {
        UciSizes {
            o_ack,
            o_csi1,
            beta_ack: 20.0,
            beta_csi1: 6.25,
            alpha: 1.0,
            sum_kr,
        }
    }

    /// One ACK bit, 20 RB, ΣK 1616: Q'_rvd (two bits) = ⌈2·20·2640/1616⌉ = 66
    /// REs reserved in symbol 3 (stride 3), Q'_ACK = 33 on every other one —
    /// subcarriers 0, 6, 12, …; the UL-SCH keeps its full length (punctured).
    #[test]
    fn uci_layout_one_ack_bit() {
        let alloc = uci_alloc(20, 2);
        let l = uci_pusch_layout(&alloc, &sizes(1, 0, 1616)).unwrap();
        assert_eq!(l.ack.len(), 33);
        assert!(l.ack.iter().all(|&(s, _)| s == 3));
        assert_eq!(&l.ack[..3], &[(3, 0), (3, 6), (3, 12)]);
        assert!(!l.ack_rate_matched);
        assert_eq!(l.ulsch_e(&alloc), Some(pusch_e_len(&alloc)));
    }

    /// Two ACK bits use the whole reserved set (66 REs, stride 3).
    #[test]
    fn uci_layout_two_ack_bits() {
        let l = uci_pusch_layout(&uci_alloc(20, 2), &sizes(2, 0, 1616)).unwrap();
        assert_eq!(l.ack.len(), 66);
        assert_eq!(&l.ack[..3], &[(3, 0), (3, 3), (3, 6)]);
    }

    /// Three ACK bits: Q'_ACK = 99 REs placed directly (stride 2) and the
    /// UL-SCH rate-matched around them.
    #[test]
    fn uci_layout_three_ack_bits_rate_match() {
        let alloc = uci_alloc(20, 2);
        let l = uci_pusch_layout(&alloc, &sizes(3, 0, 1616)).unwrap();
        assert_eq!(l.ack.len(), 99);
        assert_eq!(&l.ack[..3], &[(3, 0), (3, 2), (3, 4)]);
        assert!(l.ack_rate_matched);
        assert_eq!(l.ulsch_e(&alloc), Some(pusch_e_len(&alloc) - 2 * 99));
    }

    /// CSI without HARQ-ACK still avoids the REs reserved for two ACK bits
    /// (as OCUDU's demultiplexer does). 1 RB, ΣK 100: Q'_CSI = ⌈4·6.25·132/100⌉
    /// = 33, Q'_rvd = ⌈2·20·132/100⌉ = 53 (symbols 3-6 whole, 5 REs of symbol 8).
    /// CSI fills symbols 0-1 (24), skips 3-6, takes the 7 free REs of symbol 8
    /// and two more (stride 6) in symbol 9.
    #[test]
    fn uci_layout_csi_avoids_reserved_ack_res() {
        let l = uci_pusch_layout(&uci_alloc(1, 2), &sizes(0, 4, 100)).unwrap();
        assert!(l.ack.is_empty());
        assert_eq!(l.csi1.len(), 33);
        let on = |sym: usize| -> Vec<usize> {
            l.csi1.iter().filter(|r| r.0 == sym).map(|r| r.1).collect()
        };
        assert_eq!(on(0).len() + on(1).len(), 24);
        assert!((3..=6).all(|s| on(s).is_empty()));
        assert_eq!(on(8), vec![1, 3, 5, 7, 9, 10, 11]);
        assert_eq!(on(9), vec![0, 6]);
    }

    /// Payloads above 11 bits are refused rather than silently dropped.
    #[test]
    fn uci_layout_refuses_polar_sized_payloads() {
        assert!(uci_pusch_layout(&uci_alloc(20, 2), &sizes(12, 0, 1616)).is_err());
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
