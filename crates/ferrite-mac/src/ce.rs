//! MAC control elements (TS 38.321 §6.1.3): the CEs the UE builds (Short BSR)
//! and consumes (Timing Advance Command), plus MAC-PDU plausibility.

use crate::pdu::pad_to;
use crate::LCID_SHORT_BSR;

/// TS 38.321 Table 6.1.3.1-1: map a buffer occupancy (bytes) to the 5-bit Short
/// BSR buffer-size index (LCG 0) — the smallest level whose upper bound ≥
/// `buf_bytes`.
pub fn bsr_index(buf_bytes: usize) -> u8 {
    const LEVELS: [usize; 32] = [
        0, 10, 14, 20, 28, 38, 53, 74, 102, 142, 198, 276, 384, 528, 726, 1010,
        1420, 1983, 2765, 3839, 5446, 7594, 10570, 14099, 19468, 26971, 38326,
        49759, 65726, 86677, 114069, usize::MAX,
    ];
    LEVELS.iter().position(|&l| l >= buf_bytes).unwrap_or(31) as u8 & 0x1f
}

/// Build a UL-SCH MAC PDU carrying a Short BSR MAC CE (TS 38.321 §6.1.3.1) that
/// reports `buf_bytes` pending on logical-channel group 0, padded to `tbs`
/// bytes. Sent in a minimal grant to solicit a larger one when a queued PDU
/// doesn't fit.
pub fn mac_short_bsr(buf_bytes: usize, tbs: usize) -> Vec<u8> {
    let mut mac = Vec::with_capacity(tbs);
    mac.push(LCID_SHORT_BSR); // R/R/LCID (fixed-size CE, no L field)
    mac.push(bsr_index(buf_bytes)); // LCG-ID (bits 7..5) = 0 | buffer-size index (bits 4..0)
    pad_to(&mut mac, tbs);
    mac
}

/// Extract the 6-bit Timing Advance Command from a DL-SCH MAC PDU's TA Command
/// MAC CE (TS 38.321: LCID 61, one payload octet = 2-bit TAG id + 6-bit T_A), if
/// present. Walks the subPDU subheaders in order and stops at padding; returns
/// `None` if there is no TA command or the layout isn't understood.
pub fn parse_ta_command_ce(tb: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < tb.len() {
        let (lcid, f) = (tb[i] & 0x3f, (tb[i] >> 6) & 1);
        match lcid {
            63 => return None,                             // padding: rest is padding
            61 => return tb.get(i + 1).map(|&v| v & 0x3f), // TA Command CE: 1-octet payload
            60 | 59 => i += 1,                             // (Long) DRX Command: 0-octet payload
            62 => i += 1 + 6,                              // Contention Resolution Identity: 6 octets
            1..=32 => {
                // logical-channel SDU: R/F/LCID + L(+SDU)
                let (len, hdr) = if f == 1 {
                    (((*tb.get(i + 1)? as usize) << 8) | *tb.get(i + 2)? as usize, 3)
                } else {
                    (*tb.get(i + 1)? as usize, 2)
                };
                i += hdr + len;
            }
            _ => return None,
        }
    }
    None
}

/// A decoded transport block parses as a well-formed DL-SCH MAC PDU (every
/// subheader understood, lengths in-bounds, ≥1 subPDU, terminated by padding or
/// the exact end). Used only to allow an ACK on a CRC16-collision retransmission
/// — never to deliver content — so a residual false accept costs one RLC retx at
/// most.
pub fn plausible_mac_pdu(tb: &[u8]) -> bool {
    let mut i = 0;
    let mut subpdus = 0usize;
    while i < tb.len() {
        let (lcid, f) = (tb[i] & 0x3f, (tb[i] >> 6) & 1);
        match lcid {
            63 => return subpdus > 0, // padding: rest of the TB
            61 => i += 2,             // TA Command CE
            60 | 59 => i += 1,        // (Long) DRX Command
            62 => i += 1 + 6,         // Contention Resolution Identity
            1..=32 => {
                let (len, hdr) = if f == 1 {
                    let (Some(&h), Some(&l)) = (tb.get(i + 1), tb.get(i + 2)) else { return false };
                    (((h as usize) << 8) | l as usize, 3)
                } else {
                    let Some(&l) = tb.get(i + 1) else { return false };
                    (l as usize, 2)
                };
                i += hdr + len;
            }
            _ => return false,
        }
        if i > tb.len() {
            return false;
        }
        subpdus += 1;
    }
    subpdus > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsr_index_levels() {
        assert_eq!(bsr_index(0), 0);
        assert_eq!(bsr_index(10), 1);
        assert_eq!(bsr_index(11), 2);
        assert_eq!(bsr_index(1_000_000) & 0x1f, 31);
    }

    #[test]
    fn ta_command_extracted() {
        // subheader LCID 61 + one octet (TAG 0, T_A = 0x25).
        let tb = [61u8, 0x25, 63, 0, 0];
        assert_eq!(parse_ta_command_ce(&tb), Some(0x25));
        // No TA command present.
        assert_eq!(parse_ta_command_ce(&[63, 0, 0]), None);
    }
}
