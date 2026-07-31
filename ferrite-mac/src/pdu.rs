//! MAC PDU multiplexing and demultiplexing (TS 38.321 §6.1).

use crate::ce::bsr_index;
use crate::{LCID_DRB1, LCID_PADDING, LCID_SHORT_BSR, LCID_UL_CCCH48};

/// Build one variable-length MAC subPDU: an `R/F/LCID` subheader with an 8- or
/// 16-bit `L` field (chosen by `sdu.len()`) followed by the SDU. This is the
/// framing shared by every DCCH/DTCH logical channel (SRB1, DRB, …).
pub fn sdu_subpdu(lcid: u8, sdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sdu.len() + 3);
    if sdu.len() < 256 {
        out.push(lcid); // R=0, F=0 (8-bit L)
        out.push(sdu.len() as u8);
    } else {
        out.push(0x40 | lcid); // F=1 (16-bit L)
        out.push((sdu.len() >> 8) as u8);
        out.push((sdu.len() & 0xff) as u8);
    }
    out.extend_from_slice(sdu);
    out
}

/// Append a padding subheader and zero-fill `mac` out to `tbs` octets, if there
/// is room left (TS 38.321 §6.1.2: padding is the last subPDU).
pub fn pad_to(mac: &mut Vec<u8>, tbs: usize) {
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
}

/// Wrap one RLC PDU in a UL-SCH MAC subPDU for DRB 1 (LCID 4) and pad to `tbs`.
pub fn drb_mac_wrap(rlc: &[u8], tbs: usize) -> Vec<u8> {
    let mut mac = sdu_subpdu(LCID_DRB1, rlc);
    mac.reserve(tbs.saturating_sub(mac.len()));
    pad_to(&mut mac, tbs);
    mac
}

/// Wrap one RLC PDU in a UL-SCH MAC subPDU for DRB 1 (LCID 4), and — when
/// `bsr_bytes > 0` (more DRB data is still buffered) — piggyback a Short BSR CE
/// reporting the total remaining buffer, then pad to `tbs`. The BSR keeps the
/// gNB granting continuously to drain the whole queue instead of the UE having
/// to SR/BSR once per packet (which serialises the queue behind the ~1-frame SR
/// period and caps DRB throughput). Order per TS 38.321 §6.1.2: SDU subPDU, then
/// the CE subPDU, then padding.
pub fn drb_mac_wrap_bsr(rlc: &[u8], bsr_bytes: usize, tbs: usize) -> Vec<u8> {
    let mut mac = sdu_subpdu(LCID_DRB1, rlc);
    if bsr_bytes > 0 && mac.len() + 2 <= tbs {
        mac.push(LCID_SHORT_BSR);
        mac.push(bsr_index(bsr_bytes));
    }
    pad_to(&mut mac, tbs);
    mac
}

/// Build the Msg3 MAC PDU: one CCCH48 subPDU carrying `ccch_sdu` (the 6-byte
/// RRCSetupRequest) followed by padding, sized to `tbs` bytes.
pub fn msg3_mac_pdu(ccch_sdu: &[u8; 6], tbs: usize) -> Vec<u8> {
    assert!(tbs >= 7, "TBS too small for CCCH48 subPDU");
    let mut pdu = Vec::with_capacity(tbs);
    pdu.push(LCID_UL_CCCH48); // R|R|LCID; CCCH has no length field
    pdu.extend_from_slice(ccch_sdu);
    pad_to(&mut pdu, tbs);
    pdu
}

/// One subPDU of a DL-SCH MAC PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlSubPdu {
    pub lcid: u8,
    pub payload: Vec<u8>,
}

/// Parse a DL-SCH MAC PDU (TS 38.321 §6.1.2) into subPDUs. Handles the
/// fixed-size CEs the UE cares about (contention resolution, TA command), SDUs
/// with 8/16-bit L fields, and stops at padding.
pub fn parse_dl_mac_pdu(pdu: &[u8]) -> Vec<DlSubPdu> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < pdu.len() {
        let hdr = pdu[i];
        let lcid = hdr & 0x3f;
        let f = (hdr >> 6) & 1; // 16-bit L field flag
        i += 1;
        if lcid == LCID_PADDING {
            break;
        }
        // Fixed-size MAC CEs (no L field).
        let fixed: Option<usize> = match lcid {
            crate::LCID_DL_CON_RES => Some(6), // UE Contention Resolution Identity
            61 => Some(1),                      // Timing Advance Command
            _ => None,
        };
        let len = if let Some(n) = fixed {
            n
        } else {
            // SDU (or variable CE): L field, 8 or 16 bits.
            if i >= pdu.len() {
                break;
            }
            if f == 1 {
                if i + 1 >= pdu.len() {
                    break;
                }
                let l = ((pdu[i] as usize) << 8) | pdu[i + 1] as usize;
                i += 2;
                l
            } else {
                let l = pdu[i] as usize;
                i += 1;
                l
            }
        };
        if i + len > pdu.len() {
            break;
        }
        out.push(DlSubPdu { lcid, payload: pdu[i..i + len].to_vec() });
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdu_subpdu_8bit_and_16bit_l() {
        assert_eq!(sdu_subpdu(4, &[0xaa, 0xbb]), vec![4, 2, 0xaa, 0xbb]);
        let big = vec![0x11u8; 300];
        let s = sdu_subpdu(1, &big);
        assert_eq!(&s[..3], &[0x41, (300 >> 8) as u8, (300 & 0xff) as u8]);
        assert_eq!(s.len(), 3 + 300);
    }

    #[test]
    fn drb_wrap_roundtrips_through_parse() {
        let rlc = [0x00u8, 0x45, 0x00, 0x1c];
        let mac = drb_mac_wrap(&rlc, 16);
        assert_eq!(mac.len(), 16);
        // The DL parser understands the same subheader layout.
        let subs = parse_dl_mac_pdu(&mac);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].lcid, LCID_DRB1);
        assert_eq!(subs[0].payload, rlc);
    }

    #[test]
    fn msg3_layout() {
        let m = msg3_mac_pdu(&[1, 2, 3, 4, 5, 6], 12);
        assert_eq!(m[0], LCID_UL_CCCH48);
        assert_eq!(&m[1..7], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(m[7], LCID_PADDING);
        assert_eq!(m.len(), 12);
    }
}
