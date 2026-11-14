//! SRS resource parameters and frequency-domain layout (TS 38.211 §6.4.1.4.3,
//! Table 6.4.1.4.3-1); the sequence and waveform generation is in `ferrite_phy::srs`.

/// One SRS resource as the PHY needs it (one antenna port).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrsResourceParams {
    /// `transmissionComb` K_TC: 2 or 4.
    pub k_tc: u8,
    /// `combOffset` k̄_TC (0..K_TC).
    pub comb_offset: u8,
    /// `cyclicShift` n_SRS^cs (0..8 for K_TC = 2, 0..12 for K_TC = 4).
    pub cyclic_shift: u8,
    /// `startPosition` l_offset (0..5): first symbol is 14 − 1 − l_offset.
    pub start_position: u8,
    /// `nrofSymbols` N_symb^SRS (1, 2, 4).
    pub nrof_symbols: u8,
    /// `repetitionFactor` R (1, 2, 4).
    pub repetition_factor: u8,
    /// `freqDomainPosition` n_RRC (0..23).
    pub freq_domain_position: u8,
    /// `freqDomainShift` n_shift (0..268).
    pub freq_domain_shift: u16,
    /// `c-SRS` (0..63) and `b-SRS` (0..3).
    pub c_srs: u8,
    pub b_srs: u8,
    /// `b-hop` (0..3); hopping is disabled when b_hop ≥ b_SRS.
    pub b_hop: u8,
    /// `sequenceId` n_ID^SRS (0..1023).
    pub sequence_id: u16,
}

/// TS 38.211 Table 6.4.1.4.3-1: `(m_SRS,b, N_b)` for b = 0..3 by `C_SRS`.
const BW_TABLE: [[(u16, u8); 4]; 64] = [
    [(4, 1), (4, 1), (4, 1), (4, 1)],
    [(8, 1), (4, 2), (4, 1), (4, 1)],
    [(12, 1), (4, 3), (4, 1), (4, 1)],
    [(16, 1), (4, 4), (4, 1), (4, 1)],
    [(16, 1), (8, 2), (4, 2), (4, 1)],
    [(20, 1), (4, 5), (4, 1), (4, 1)],
    [(24, 1), (4, 6), (4, 1), (4, 1)],
    [(24, 1), (12, 2), (4, 3), (4, 1)],
    [(28, 1), (4, 7), (4, 1), (4, 1)],
    [(32, 1), (16, 2), (8, 2), (4, 2)],
    [(36, 1), (12, 3), (4, 3), (4, 1)],
    [(40, 1), (20, 2), (4, 5), (4, 1)],
    [(48, 1), (16, 3), (8, 2), (4, 2)],
    [(48, 1), (24, 2), (12, 2), (4, 3)],
    [(52, 1), (4, 13), (4, 1), (4, 1)],
    [(56, 1), (28, 2), (4, 7), (4, 1)],
    [(60, 1), (20, 3), (4, 5), (4, 1)],
    [(64, 1), (32, 2), (16, 2), (4, 4)],
    [(72, 1), (24, 3), (12, 2), (4, 3)],
    [(72, 1), (36, 2), (12, 3), (4, 3)],
    [(76, 1), (4, 19), (4, 1), (4, 1)],
    [(80, 1), (40, 2), (20, 2), (4, 5)],
    [(88, 1), (44, 2), (4, 11), (4, 1)],
    [(96, 1), (32, 3), (16, 2), (4, 4)],
    [(96, 1), (48, 2), (24, 2), (4, 6)],
    [(104, 1), (52, 2), (4, 13), (4, 1)],
    [(112, 1), (56, 2), (28, 2), (4, 7)],
    [(120, 1), (60, 2), (20, 3), (4, 5)],
    [(120, 1), (40, 3), (8, 5), (4, 2)],
    [(120, 1), (24, 5), (12, 2), (4, 3)],
    [(128, 1), (64, 2), (32, 2), (4, 8)],
    [(128, 1), (64, 2), (16, 4), (4, 4)],
    [(128, 1), (16, 8), (8, 2), (4, 2)],
    [(132, 1), (44, 3), (4, 11), (4, 1)],
    [(136, 1), (68, 2), (4, 17), (4, 1)],
    [(144, 1), (72, 2), (36, 2), (4, 9)],
    [(144, 1), (48, 3), (24, 2), (12, 2)],
    [(144, 1), (48, 3), (16, 3), (4, 4)],
    [(144, 1), (16, 9), (8, 2), (4, 2)],
    [(152, 1), (76, 2), (4, 19), (4, 1)],
    [(160, 1), (80, 2), (40, 2), (4, 10)],
    [(160, 1), (80, 2), (20, 4), (4, 5)],
    [(160, 1), (32, 5), (16, 2), (4, 4)],
    [(168, 1), (84, 2), (28, 3), (4, 7)],
    [(176, 1), (88, 2), (44, 2), (4, 11)],
    [(184, 1), (92, 2), (4, 23), (4, 1)],
    [(192, 1), (96, 2), (48, 2), (4, 12)],
    [(192, 1), (96, 2), (24, 4), (4, 6)],
    [(192, 1), (64, 3), (16, 4), (4, 4)],
    [(192, 1), (24, 8), (8, 3), (4, 2)],
    [(208, 1), (104, 2), (52, 2), (4, 13)],
    [(216, 1), (108, 2), (36, 3), (4, 9)],
    [(224, 1), (112, 2), (56, 2), (4, 14)],
    [(240, 1), (120, 2), (60, 2), (4, 15)],
    [(240, 1), (80, 3), (20, 4), (4, 5)],
    [(240, 1), (48, 5), (16, 3), (8, 2)],
    [(240, 1), (24, 10), (12, 2), (4, 3)],
    [(256, 1), (128, 2), (64, 2), (4, 16)],
    [(256, 1), (128, 2), (32, 4), (4, 8)],
    [(256, 1), (16, 16), (8, 2), (4, 2)],
    [(264, 1), (132, 2), (44, 3), (4, 11)],
    [(272, 1), (136, 2), (68, 2), (4, 17)],
    [(272, 1), (68, 4), (4, 17), (4, 1)],
    [(272, 1), (16, 17), (8, 2), (4, 2)],
];

/// `(m_SRS,b, N_b)` for `C_SRS` and `b`.
pub fn srs_bandwidth(c_srs: u8, b: u8) -> (u16, u8) {
    BW_TABLE[(c_srs & 63) as usize][(b & 3) as usize]
}

/// Frequency-domain layout of an SRS resource (no frequency hopping):
/// the sequence length `m_sc` and the first subcarrier `k0` (relative to
/// CRB 0 of the UL carrier, with the SRS occupying `k0 + K_TC·k`).
pub fn srs_layout(p: &SrsResourceParams) -> Option<(usize, usize)> {
    let b = p.b_srs;
    let (m_srs_b, _) = srs_bandwidth(p.c_srs, b);
    let m_sc = (m_srs_b as usize * 12) / p.k_tc as usize;
    // k0 = n_shift·12 + k̄_TC + Σ_{b'} K_TC·M_sc,b'·n_b' (§6.4.1.4.3).
    let mut k0 = p.freq_domain_shift as usize * 12 + p.comb_offset as usize;
    for bp in 0..=b {
        let (m_b, n_b) = srs_bandwidth(p.c_srs, bp);
        let m_sc_b = (m_b as usize * 12) / p.k_tc as usize;
        // No hopping (b_hop ≥ b_SRS): n_b = ⌊4·n_RRC / m_SRS,b⌋ mod N_b.
        let n_bp = ((4 * p.freq_domain_position as usize) / m_b as usize) % n_b.max(1) as usize;
        k0 += p.k_tc as usize * m_sc_b * n_bp;
    }
    (m_sc > 0).then_some((m_sc, k0))
}

/// Symbols of the resource in the slot: `l0 + l'`, l0 = 14 − 1 − l_offset.
pub fn srs_symbols(p: &SrsResourceParams) -> Vec<usize> {
    let l0 = 14usize.saturating_sub(1 + p.start_position as usize);
    (0..p.nrof_symbols as usize).map(|l| l0 + l).filter(|&l| l < 14).collect()
}

