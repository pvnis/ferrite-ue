//! MAC PDU multiplexing / demultiplexing (TS 38.321 §6.1) and the MAC control
//! elements the UE builds and consumes (§6.1.3).

use crate::*;

/// One subPDU of a DL-SCH MAC PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DlSubPdu {
    /// A logical-channel SDU (CCCH = LCID 0, DCCH/DTCH 1..32).
    Sdu { lcid: u8, sdu: Vec<u8> },
    /// Timing Advance Command: (TAG id, T_A 0..63).
    TaCommand { tag: u8, ta: u8 },
    /// UE Contention Resolution Identity (the first 48 bits of the Msg3 CCCH SDU).
    ContentionResolution([u8; 6]),
    DrxCommand,
    LongDrxCommand,
    /// Any other CE, kept for diagnostics.
    Other { lcid: u8, payload: Vec<u8> },
}

/// Parse a DL-SCH MAC PDU (§6.1.2) into subPDUs. Stops at padding; tolerates a
/// truncated tail (returns what parsed so far).
pub fn parse_dl_pdu(pdu: &[u8]) -> Vec<DlSubPdu> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < pdu.len() {
        let hdr = pdu[i];
        let lcid = hdr & 0x3f;
        let f = (hdr >> 6) & 1;
        i += 1;
        match lcid {
            LCID_PADDING => break,
            LCID_TA_COMMAND => {
                let Some(&v) = pdu.get(i) else { break };
                out.push(DlSubPdu::TaCommand { tag: v >> 6, ta: v & 0x3f });
                i += 1;
            }
            LCID_DL_CON_RES => {
                let Some(p) = pdu.get(i..i + 6) else { break };
                out.push(DlSubPdu::ContentionResolution(p.try_into().unwrap()));
                i += 6;
            }
            LCID_DRX => out.push(DlSubPdu::DrxCommand),
            LCID_LONG_DRX => out.push(DlSubPdu::LongDrxCommand),
            LCID_SCELL_ACT_1 => {
                let Some(&v) = pdu.get(i) else { break };
                out.push(DlSubPdu::Other { lcid, payload: vec![v] });
                i += 1;
            }
            LCID_SCELL_ACT_4 => {
                let Some(p) = pdu.get(i..i + 4) else { break };
                out.push(DlSubPdu::Other { lcid, payload: p.to_vec() });
                i += 4;
            }
            LCID_DUP_ACT => {
                let Some(&v) = pdu.get(i) else { break };
                out.push(DlSubPdu::Other { lcid, payload: vec![v] });
                i += 1;
            }
            // Fixed-size CEs without an L field (TS 38.321 Table 6.2.1-1):
            // 47 Recommended bit rate (2), 48 SP ZP CSI-RS Resource Set
            // Activation (2), 49 PUCCH spatial relation Activation (3),
            // 51 SP CSI reporting on PUCCH Activation (2), 52 TCI State
            // Indication for UE-specific PDCCH (2).
            47 | 48 | 51 | 52 | 49 => {
                let n = if lcid == 49 { 3 } else { 2 };
                let Some(p) = pdu.get(i..i + n) else { break };
                out.push(DlSubPdu::Other { lcid, payload: p.to_vec() });
                i += n;
            }
            // eLCID subheaders (33: 1-octet eLCID, 34: 2-octet eLCID) and the
            // reserved range 35..=46: unknown layout, stop parsing here.
            33..=46 => {
                log::debug!("DL MAC subPDU with LCID {lcid} (eLCID / reserved) not supported; rest of the PDU dropped");
                break;
            }
            _ => {
                // Variable-length: an L field (8 or 16 bits) follows.
                let len = if f == 1 {
                    let (Some(&h), Some(&l)) = (pdu.get(i), pdu.get(i + 1)) else { break };
                    i += 2;
                    ((h as usize) << 8) | l as usize
                } else {
                    let Some(&l) = pdu.get(i) else { break };
                    i += 1;
                    l as usize
                };
                let Some(p) = pdu.get(i..i + len) else { break };
                if lcid <= LCID_MAX_LCH {
                    out.push(DlSubPdu::Sdu { lcid, sdu: p.to_vec() });
                } else {
                    out.push(DlSubPdu::Other { lcid, payload: p.to_vec() });
                }
                i += len;
            }
        }
    }
    out
}

/// Append an `R/F/LCID[/L]` subheader + SDU to `out` (§6.1.2).
pub fn push_sdu_subpdu(out: &mut Vec<u8>, lcid: u8, sdu: &[u8]) {
    if sdu.len() < 256 {
        out.push(lcid & 0x3f);
        out.push(sdu.len() as u8);
    } else {
        out.push(0x40 | (lcid & 0x3f));
        out.push((sdu.len() >> 8) as u8);
        out.push((sdu.len() & 0xff) as u8);
    }
    out.extend_from_slice(sdu);
}

/// Bytes a subPDU for an SDU of `len` costs including its subheader.
pub fn sdu_subpdu_len(len: usize) -> usize {
    len + if len < 256 { 2 } else { 3 }
}

/// Pad `mac` with a padding subPDU out to `tbs` octets (§6.1.2: padding is the last subPDU).
pub fn pad_to(mac: &mut Vec<u8>, tbs: usize) {
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
}

/// TS 38.321 Table 6.1.3.1-1: 5-bit buffer-size index for the Short BSR.
pub fn bsr_index_5bit(bytes: usize) -> u8 {
    const LEVELS: [usize; 31] = [
        0, 10, 14, 20, 28, 38, 53, 74, 102, 142, 198, 276, 384, 528, 726, 1010, 1420, 1983, 2765,
        3839, 5446, 7594, 10570, 14099, 19468, 26971, 38326, 49759, 65726, 86677, 114069,
    ];
    LEVELS.iter().position(|&l| l >= bytes).unwrap_or(31) as u8
}

/// TS 38.321 Table 6.1.3.1-2: 8-bit buffer-size index for the Long BSR
/// (index k ⇔ bytes ≤ B_k; 254 ⇔ > 81338368; 255 reserved). Normative
/// constant table (cross-checked against the OCUDU reference implementation).
pub fn bsr_index_8bit(bytes: usize) -> u8 {
    LONG_BSR_LEVELS.iter().position(|&l| l as usize >= bytes).map_or(254, |p| p as u8)
}

#[rustfmt::skip]
const LONG_BSR_LEVELS: [u32; 254] = [
        0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        22, 23, 25, 26, 28, 30, 32, 34, 36, 38, 40, 43,
        46, 49, 52, 55, 59, 62, 66, 71, 75, 80, 85, 91,
        97, 103, 110, 117, 124, 132, 141, 150, 160, 170, 181, 193,
        205, 218, 233, 248, 264, 281, 299, 318, 339, 361, 384, 409,
        436, 464, 494, 526, 560, 597, 635, 677, 720, 767, 817, 870,
        926, 987, 1051, 1119, 1191, 1269, 1351, 1439, 1532, 1631, 1737, 1850,
        1970, 2098, 2234, 2379, 2533, 2698, 2873, 3059, 3258, 3469, 3694, 3934,
        4189, 4461, 4751, 5059, 5387, 5737, 6109, 6506, 6928, 7378, 7857, 8367,
        8910, 9488, 10104, 10760, 11458, 12202, 12994, 13838, 14736, 15692, 16711, 17795,
        18951, 20181, 21491, 22885, 24371, 25953, 27638, 29431, 31342, 33376, 35543, 37850,
        40307, 42923, 45709, 48676, 51836, 55200, 58784, 62599, 66663, 70990, 75598, 80505,
        85730, 91295, 97221, 103532, 110252, 117409, 125030, 133146, 141789, 150992, 160793, 171231,
        182345, 194182, 206786, 220209, 234503, 249725, 265935, 283197, 301579, 321155, 342002, 364202,
        387842, 413018, 439827, 468377, 498780, 531156, 565634, 602350, 641449, 683087, 727427, 774645,
        824928, 878475, 935498, 996222, 1060888, 1129752, 1203085, 1281179, 1364342, 1452903, 1547213, 1647644,
        1754595, 1868488, 1989774, 2118933, 2256475, 2402946, 2558924, 2725027, 2901912, 3090279, 3290873, 3504487,
        3731968, 3974215, 4232186, 4506902, 4799451, 5110989, 5442750, 5796046, 6172275, 6572925, 6999582, 7453933,
        7937777, 8453028, 9001725, 9586039, 10208280, 10870913, 11576557, 12328006, 13128233, 13980403, 14887889, 15854280,
        16883401, 17979324, 19146385, 20389201, 21712690, 23122088, 24622972, 26221280, 27923336, 29735875, 31666069, 33721553,
        35910462, 38241455, 40723756, 43367187, 46182206, 49179951, 52372284, 55771835, 59392055, 63247269, 67352729, 71724679,
        76380419, 81338368,
];

/// Build a Single Entry PHR MAC CE subPDU (§6.1.3.8): `P` = 0 (no power
/// backoff), `V` = 0 (real PUSCH reference), 6-bit PH, 6-bit P_CMAX,c.
pub fn push_single_phr(out: &mut Vec<u8>, ph_db: f32, pcmax_dbm: f32) {
    out.push(LCID_SINGLE_PHR);
    out.push(crate::phr::ph_index(ph_db) & 0x3f);
    out.push(crate::phr::pcmax_index(pcmax_dbm) & 0x3f);
}

/// Build a Short BSR MAC CE subPDU (LCG id + 5-bit index) into `out`.
pub fn push_short_bsr(out: &mut Vec<u8>, lcg: u8, bytes: usize, truncated: bool) {
    out.push(if truncated { LCID_SHORT_TRUNC_BSR } else { LCID_SHORT_BSR });
    out.push(((lcg & 7) << 5) | bsr_index_5bit(bytes));
}

/// Build a Long BSR MAC CE subPDU (bitmap + one 8-bit index per reported LCG, ascending).
pub fn push_long_bsr(out: &mut Vec<u8>, lcg_bytes: &[(u8, usize)], truncated: bool) {
    let mut bitmap = 0u8;
    let mut entries: Vec<(u8, usize)> = lcg_bytes.to_vec();
    entries.sort_by_key(|e| e.0);
    for &(lcg, _) in &entries {
        bitmap |= 1 << (lcg & 7);
    }
    let payload_len = 1 + entries.len();
    out.push(if truncated { LCID_LONG_TRUNC_BSR } else { LCID_LONG_BSR });
    out.push(payload_len as u8);
    out.push(bitmap);
    for &(_, b) in &entries {
        out.push(bsr_index_8bit(b));
    }
}

/// Build a C-RNTI MAC CE subPDU.
pub fn push_crnti_ce(out: &mut Vec<u8>, crnti: u16) {
    out.push(LCID_CRNTI);
    out.extend_from_slice(&crnti.to_be_bytes());
}

/// Build the Msg3 CCCH subPDU: 48- or 64-bit CCCH SDU, no length field.
pub fn push_ccch(out: &mut Vec<u8>, ccch: &[u8]) {
    match ccch.len() {
        6 => out.push(LCID_UL_CCCH48),
        8 => out.push(LCID_UL_CCCH64),
        n => panic!("CCCH SDU must be 6 or 8 octets, got {n}"),
    }
    out.extend_from_slice(ccch);
}

/// A decoded TB is a plausible DL-SCH MAC PDU (every subheader understood and
/// in-bounds). Used only for diagnostics.
pub fn plausible_dl_pdu(tb: &[u8]) -> bool {
    !parse_dl_pdu(tb).is_empty() || tb.first().is_some_and(|&b| b & 0x3f == LCID_PADDING)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_con_res_ccch_ta_padding() {
        let pdu = [62, 9, 8, 7, 6, 5, 4, 0, 3, 0xaa, 0xbb, 0xcc, 61, 0x1a, 63, 0, 0];
        let subs = parse_dl_pdu(&pdu);
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[0], DlSubPdu::ContentionResolution([9, 8, 7, 6, 5, 4]));
        assert_eq!(subs[1], DlSubPdu::Sdu { lcid: 0, sdu: vec![0xaa, 0xbb, 0xcc] });
        assert_eq!(subs[2], DlSubPdu::TaCommand { tag: 0, ta: 26 });
    }

    #[test]
    fn sdu_subpdu_sizes() {
        let mut v = Vec::new();
        push_sdu_subpdu(&mut v, 4, &[1, 2]);
        assert_eq!(v, vec![4, 2, 1, 2]);
        let big = vec![7u8; 300];
        let mut v = Vec::new();
        push_sdu_subpdu(&mut v, 1, &big);
        assert_eq!(&v[..3], &[0x41, 1, 44]);
        assert_eq!(sdu_subpdu_len(300), 303);
        let parsed = parse_dl_pdu(&v);
        assert_eq!(parsed, vec![DlSubPdu::Sdu { lcid: 1, sdu: big }]);
    }

    #[test]
    fn bsr_indices() {
        assert_eq!(bsr_index_5bit(0), 0);
        assert_eq!(bsr_index_5bit(10), 1);
        assert_eq!(bsr_index_5bit(11), 2);
        assert_eq!(bsr_index_5bit(1_000_000), 31);
        assert_eq!(bsr_index_8bit(0), 0);
        assert_eq!(bsr_index_8bit(10), 1);
        assert_eq!(bsr_index_8bit(11), 2);
        assert_eq!(bsr_index_8bit(200_000_000), 254);
    }

    #[test]
    fn long_bsr_layout() {
        let mut v = Vec::new();
        push_long_bsr(&mut v, &[(2, 100), (0, 10)], false);
        assert_eq!(v, vec![LCID_LONG_BSR, 3, 0b101, bsr_index_8bit(10), bsr_index_8bit(100)]);
    }
}
