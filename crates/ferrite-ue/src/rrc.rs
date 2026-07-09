//! Minimal RRC message encode/decode (TS 38.331, UPER per X.691) and the MAC
//! PDU framing (TS 38.321) needed for the RA/attach procedure. Hand-rolled for
//! exactly the messages the UE sends/receives — not a general ASN.1 stack.

/// Big-endian bit writer for UPER encoding.
pub struct BitWriter {
    bytes: Vec<u8>,
    nbits: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new(), nbits: 0 }
    }

    /// Append the `width` low bits of `v`, MSB first.
    pub fn put(&mut self, v: u64, width: usize) {
        for i in (0..width).rev() {
            let bit = ((v >> i) & 1) as u8;
            if self.nbits % 8 == 0 {
                self.bytes.push(0);
            }
            let last = self.bytes.len() - 1;
            self.bytes[last] |= bit << (7 - self.nbits % 8);
            self.nbits += 1;
        }
    }

    /// Pad with zeros to a byte boundary and return the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        while self.nbits % 8 != 0 {
            self.put(0, 1);
        }
        self.bytes
    }

    pub fn len_bits(&self) -> usize {
        self.nbits
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Big-endian bit reader for UPER decoding.
pub struct BitReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Read `width` bits MSB-first; None if out of data.
    pub fn get(&mut self, width: usize) -> Option<u64> {
        if self.pos + width > self.bytes.len() * 8 {
            return None;
        }
        let mut v = 0u64;
        for _ in 0..width {
            let byte = self.bytes[self.pos / 8];
            let bit = (byte >> (7 - self.pos % 8)) & 1;
            v = v << 1 | bit as u64;
            self.pos += 1;
        }
        Some(v)
    }

    pub fn pos_bits(&self) -> usize {
        self.pos
    }
}

/// Encode `UL-CCCH-Message { c1: rrcSetupRequest }` (TS 38.331 §6.2.2): a fixed
/// 48-bit (6-byte) message.
///
/// Bit layout: [1: message CHOICE c1=0][2: c1 CHOICE rrcSetupRequest=0]
/// [1: InitialUE-Identity CHOICE randomValue=1][39: randomValue]
/// [4: establishmentCause][1: spare=0].
pub fn rrc_setup_request(random_value_39: u64, establishment_cause: u8) -> [u8; 6] {
    let mut w = BitWriter::new();
    w.put(0, 1); // UL-CCCH-MessageType ::= CHOICE {c1, ext}: c1
    w.put(0, 2); // c1 ::= CHOICE {rrcSetupRequest, resume, reest, sysInfoReq}
    w.put(1, 1); // ue-Identity ::= CHOICE {ng-5G-S-TMSI-Part1, randomValue}: randomValue
    w.put(random_value_39 & ((1 << 39) - 1), 39);
    w.put(establishment_cause as u64, 4); // EstablishmentCause (16 values)
    w.put(0, 1); // spare
    let v = w.finish();
    let mut out = [0u8; 6];
    out.copy_from_slice(&v);
    out
}

/// EstablishmentCause mo-Signalling (TS 38.331).
pub const CAUSE_MO_SIGNALLING: u8 = 3;

// ---------------------------------------------------------------------------
// MAC (TS 38.321)
// ---------------------------------------------------------------------------

/// UL-SCH LCID values (TS 38.321 Table 6.2.1-2).
pub const LCID_UL_CCCH48: u8 = 52; // 48-bit CCCH SDU, no length field
pub const LCID_PADDING: u8 = 63;

/// DL-SCH LCID values (TS 38.321 Table 6.2.1-1).
pub const LCID_DL_CCCH: u8 = 0; // DL CCCH SDU (has length field)
pub const LCID_DL_CON_RES: u8 = 62; // UE Contention Resolution Identity CE (6 bytes)

/// Build the Msg3 MAC PDU: one CCCH48 subPDU carrying `ccch_sdu` (the 6-byte
/// RRCSetupRequest) followed by padding, sized to `tbs` bytes.
pub fn msg3_mac_pdu(ccch_sdu: &[u8; 6], tbs: usize) -> Vec<u8> {
    assert!(tbs >= 7, "TBS too small for CCCH48 subPDU");
    let mut pdu = Vec::with_capacity(tbs);
    pdu.push(LCID_UL_CCCH48); // R|R|LCID; CCCH has no length field
    pdu.extend_from_slice(ccch_sdu);
    if pdu.len() < tbs {
        pdu.push(LCID_PADDING); // padding subheader; zeros follow
        pdu.resize(tbs, 0);
    }
    pdu
}

/// One subPDU of a DL-SCH MAC PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlSubPdu {
    pub lcid: u8,
    pub payload: Vec<u8>,
}

/// Parse a DL-SCH MAC PDU (TS 38.321 §6.1.2) into subPDUs. Handles the
/// fixed-size CEs the UE cares about (contention resolution), SDUs with 8/16-bit
/// L fields, and stops at padding.
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
            LCID_DL_CON_RES => Some(6), // UE Contention Resolution Identity
            61 => Some(1),              // Timing Advance Command
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
    fn setup_request_layout() {
        // randomValue = all ones, cause mo-Signalling (3), spare 0:
        // bits: 0 00 1 [39×1] 0011 0
        let m = rrc_setup_request((1 << 39) - 1, CAUSE_MO_SIGNALLING);
        // 0001 1111 ... first byte = 0b0001_1111 = 0x1f
        assert_eq!(m[0], 0x1f);
        assert_eq!(&m[1..5], &[0xff, 0xff, 0xff, 0xff]);
        // last byte: 4 remaining randomValue bits (1111) + cause 0011 → 0b1111_0011
        // wait: 39 bits: 1 (choice) + 39 = 40 bits after the 3 header bits → ends
        // at bit 43; cause bits 43..47; spare bit 47.
        assert_eq!(m[5] & 1, 0); // spare
        // cause = bits 43..46: byte5 bits: [rv][rv][rv][cause3][cause2][cause1][cause0][spare]
        assert_eq!((m[5] >> 1) & 0xf, 3);
    }

    #[test]
    fn msg3_pdu_framing() {
        let sdu = [1, 2, 3, 4, 5, 6];
        let pdu = msg3_mac_pdu(&sdu, 11);
        assert_eq!(pdu.len(), 11);
        assert_eq!(pdu[0], 52);
        assert_eq!(&pdu[1..7], &sdu);
        assert_eq!(pdu[7], 63);
        assert_eq!(&pdu[8..], &[0, 0, 0]);
    }

    #[test]
    fn dl_pdu_parse_con_res_plus_ccch() {
        // ConRes CE (62, 6B) + DL-CCCH SDU (0, L=3) + padding
        let pdu = [62, 9, 8, 7, 6, 5, 4, 0, 3, 0xaa, 0xbb, 0xcc, 63, 0, 0];
        let subs = parse_dl_mac_pdu(&pdu);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].lcid, 62);
        assert_eq!(subs[0].payload, vec![9, 8, 7, 6, 5, 4]);
        assert_eq!(subs[1].lcid, 0);
        assert_eq!(subs[1].payload, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn bit_roundtrip() {
        let mut w = BitWriter::new();
        w.put(0b101, 3);
        w.put(0x1234, 16);
        w.put(1, 1);
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.get(3), Some(0b101));
        assert_eq!(r.get(16), Some(0x1234));
        assert_eq!(r.get(1), Some(1));
    }
}
