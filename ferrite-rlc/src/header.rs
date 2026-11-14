//! RLC PDU formats (TS 38.322 §6.2): UMD / AMD data PDU headers and the STATUS
//! PDU. Pure byte codecs; every decoder returns `None` on a malformed or
//! truncated input and never panics.
//!
//! Bit layouts (MSB first, one row per octet), from the figures in §6.2.2:
//!
//! ```text
//! UMD, SI=00, 6/12-bit SN (Fig 6.2.2.3-1/3):   | SI | R R R R R R |
//! UMD, SI≠00, 6-bit SN     (Fig 6.2.2.3-2):    | SI | SN(6)       |  [ SO(16) if SI=10/11 ]
//! UMD, SI≠00, 12-bit SN    (Fig 6.2.2.3-4):    | SI | R R | SN(4) | SN(8) |  [ SO(16) ]
//! AMD, 12-bit SN           (Fig 6.2.2.4-1/2):  | D/C | P | SI | SN(4) | SN(8) |  [ SO(16) ]
//! AMD, 18-bit SN           (Fig 6.2.2.4-3/4):  | D/C | P | SI | R R | SN(2) | SN(8) | SN(8) |  [ SO(16) ]
//! STATUS, 12-bit SN        (Fig 6.2.2.5-1):    | D/C | CPT(3) | ACK_SN(4) | ACK_SN(8) | E1 | R(7) |
//!      NACK entry:                              | NACK_SN(8) | NACK_SN(4) | E1 | E2 | E3 | R |
//! STATUS, 18-bit SN        (Fig 6.2.2.5-2):    | D/C | CPT(3) | ACK_SN(4) | ACK_SN(8) | ACK_SN(6) | E1 | R |
//!      NACK entry:                              | NACK_SN(8) | NACK_SN(8) | NACK_SN(2) | E1 | E2 | E3 | R R R |
//!      each NACK entry is followed by SOstart(16) SOend(16) when E2=1 and NACK range(8) when E3=1.
//! ```

use crate::SnLen;

/// Segmentation Info field (TS 38.322 §6.2.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Si {
    /// Data field contains all bytes of an RLC SDU.
    Full = 0b00,
    /// First segment of an RLC SDU (no SO field).
    First = 0b01,
    /// Last segment of an RLC SDU (SO present).
    Last = 0b10,
    /// Neither first nor last segment (SO present).
    Middle = 0b11,
}

impl Si {
    /// The 2-bit field value.
    pub const fn bits(self) -> u8 {
        self as u8
    }

    /// Decode the 2-bit field value (only the two LSBs of `b` are used).
    pub const fn from_bits(b: u8) -> Si {
        match b & 0b11 {
            0b00 => Si::Full,
            0b01 => Si::First,
            0b10 => Si::Last,
            _ => Si::Middle,
        }
    }

    /// Whether this SI value carries a Segment Offset field (§6.2.3.5: SO is
    /// present for the last and middle segments only).
    pub const fn has_so(self) -> bool {
        matches!(self, Si::Last | Si::Middle)
    }

    /// SI for the byte range `[start, end)` of an SDU of `len` bytes.
    pub const fn of_range(start: usize, end: usize, len: usize) -> Si {
        match (start == 0, end >= len) {
            (true, true) => Si::Full,
            (true, false) => Si::First,
            (false, true) => Si::Last,
            (false, false) => Si::Middle,
        }
    }
}

/// Special `SOend` value: the missing portion extends to the last byte of the
/// RLC SDU (TS 38.322 §6.2.3.14).
pub const SO_END_ALL: u16 = 0xFFFF;

/// UMD PDU header (TS 38.322 §6.2.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmdHeader {
    pub si: Si,
    /// Sequence number; ignored (and encoded as absent) when `si == Si::Full`.
    pub sn: u32,
    /// Segment offset; only encoded when `si.has_so()`.
    pub so: u16,
}

impl UmdHeader {
    /// Header length in octets for a given SI and SN length.
    pub const fn size(si: Si, sn_len: SnLen) -> usize {
        if matches!(si, Si::Full) {
            return 1;
        }
        let base = match sn_len {
            SnLen::Bits6 => 1,
            _ => 2,
        };
        base + if si.has_so() { 2 } else { 0 }
    }

    /// Append the encoded header to `out`.
    pub fn encode(&self, sn_len: SnLen, out: &mut Vec<u8>) {
        let si = self.si.bits();
        if self.si == Si::Full {
            out.push(0x00);
            return;
        }
        match sn_len {
            SnLen::Bits6 => out.push((si << 6) | (self.sn & 0x3F) as u8),
            _ => {
                out.push((si << 6) | ((self.sn >> 8) & 0x0F) as u8);
                out.push((self.sn & 0xFF) as u8);
            }
        }
        if self.si.has_so() {
            out.extend_from_slice(&self.so.to_be_bytes());
        }
    }

    /// Decode the header at the start of `pdu`; returns the header and its
    /// length in octets.
    pub fn decode(sn_len: SnLen, pdu: &[u8]) -> Option<(UmdHeader, usize)> {
        let b0 = *pdu.first()?;
        let si = Si::from_bits(b0 >> 6);
        if si == Si::Full {
            return Some((UmdHeader { si, sn: 0, so: 0 }, 1));
        }
        let (sn, mut len) = match sn_len {
            SnLen::Bits6 => ((b0 & 0x3F) as u32, 1usize),
            _ => ((((b0 & 0x0F) as u32) << 8) | *pdu.get(1)? as u32, 2usize),
        };
        let so = if si.has_so() {
            let so = u16::from_be_bytes([*pdu.get(len)?, *pdu.get(len + 1)?]);
            len += 2;
            so
        } else {
            0
        };
        Some((UmdHeader { si, sn, so }, len))
    }
}

/// AMD PDU header (TS 38.322 §6.2.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdHeader {
    /// The P field (§6.2.3.7): a poll request.
    pub poll: bool,
    pub si: Si,
    pub sn: u32,
    /// Segment offset; only encoded when `si.has_so()`.
    pub so: u16,
}

impl AmdHeader {
    /// Header length in octets without the SO field.
    pub const fn base_size(sn_len: SnLen) -> usize {
        match sn_len {
            SnLen::Bits18 => 3,
            _ => 2,
        }
    }

    /// Header length in octets.
    pub const fn size(si: Si, sn_len: SnLen) -> usize {
        Self::base_size(sn_len) + if si.has_so() { 2 } else { 0 }
    }

    /// Append the encoded header to `out`.
    pub fn encode(&self, sn_len: SnLen, out: &mut Vec<u8>) {
        let top = 0x80 | ((self.poll as u8) << 6) | (self.si.bits() << 4);
        match sn_len {
            SnLen::Bits18 => {
                out.push(top | ((self.sn >> 16) & 0x03) as u8);
                out.push(((self.sn >> 8) & 0xFF) as u8);
                out.push((self.sn & 0xFF) as u8);
            }
            _ => {
                out.push(top | ((self.sn >> 8) & 0x0F) as u8);
                out.push((self.sn & 0xFF) as u8);
            }
        }
        if self.si.has_so() {
            out.extend_from_slice(&self.so.to_be_bytes());
        }
    }

    /// Decode the header at the start of `pdu`. Returns `None` for a STATUS
    /// PDU (D/C = 0) or a truncated buffer.
    pub fn decode(sn_len: SnLen, pdu: &[u8]) -> Option<(AmdHeader, usize)> {
        let b0 = *pdu.first()?;
        if b0 & 0x80 == 0 {
            return None;
        }
        let poll = b0 & 0x40 != 0;
        let si = Si::from_bits(b0 >> 4);
        let (sn, mut len) = match sn_len {
            SnLen::Bits18 => (
                (((b0 & 0x03) as u32) << 16) | ((*pdu.get(1)? as u32) << 8) | *pdu.get(2)? as u32,
                3usize,
            ),
            _ => ((((b0 & 0x0F) as u32) << 8) | *pdu.get(1)? as u32, 2usize),
        };
        let so = if si.has_so() {
            let so = u16::from_be_bytes([*pdu.get(len)?, *pdu.get(len + 1)?]);
            len += 2;
            so
        } else {
            0
        };
        Some((AmdHeader { poll, si, sn, so }, len))
    }
}

/// Whether an AM PDU is a STATUS PDU (D/C = 0, §6.2.3.1).
pub fn is_status_pdu(pdu: &[u8]) -> bool {
    pdu.first().is_some_and(|b| b & 0x80 == 0)
}

/// One negative acknowledgement of a STATUS PDU (§6.2.3.11–§6.2.3.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nack {
    /// NACK_SN: the first (or only) missing RLC SDU.
    pub sn: u32,
    /// `(SOstart, SOend)` when E2 = 1: the missing byte range (inclusive;
    /// `SOend == SO_END_ALL` means "to the end of the SDU"). With a range, SOstart
    /// applies to the first SDU of the range and SOend to the last (§6.2.3.14).
    pub so: Option<(u16, u16)>,
    /// NACK range when E3 = 1: number of consecutively missing SDUs starting
    /// at `sn`.
    pub range: Option<u8>,
}

impl Nack {
    /// Encoded size of this entry in octets.
    pub const fn size(&self, sn_len: SnLen) -> usize {
        let base = match sn_len {
            SnLen::Bits18 => 3,
            _ => 2,
        };
        base + if self.so.is_some() { 4 } else { 0 } + if self.range.is_some() { 1 } else { 0 }
    }
}

/// STATUS PDU (TS 38.322 §6.2.2.5), CPT = 000.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StatusPdu {
    /// ACK_SN: the SN of the next not-received SDU not reported as missing.
    pub ack_sn: u32,
    pub nacks: Vec<Nack>,
}

impl StatusPdu {
    /// Fixed part size in octets (identical for 12- and 18-bit SN).
    pub const HEADER_SIZE: usize = 3;

    /// Encoded size in octets.
    pub fn size(&self, sn_len: SnLen) -> usize {
        Self::HEADER_SIZE + self.nacks.iter().map(|n| n.size(sn_len)).sum::<usize>()
    }

    /// Encode to bytes.
    pub fn encode(&self, sn_len: SnLen) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size(sn_len));
        let e1 = !self.nacks.is_empty();
        match sn_len {
            SnLen::Bits18 => {
                out.push(((self.ack_sn >> 14) & 0x0F) as u8);
                out.push(((self.ack_sn >> 6) & 0xFF) as u8);
                out.push((((self.ack_sn & 0x3F) as u8) << 2) | ((e1 as u8) << 1));
            }
            _ => {
                out.push(((self.ack_sn >> 8) & 0x0F) as u8);
                out.push((self.ack_sn & 0xFF) as u8);
                out.push((e1 as u8) << 7);
            }
        }
        for (i, n) in self.nacks.iter().enumerate() {
            let more = (i + 1 < self.nacks.len()) as u8;
            let e2 = n.so.is_some() as u8;
            let e3 = n.range.is_some() as u8;
            match sn_len {
                SnLen::Bits18 => {
                    out.push(((n.sn >> 10) & 0xFF) as u8);
                    out.push(((n.sn >> 2) & 0xFF) as u8);
                    out.push((((n.sn & 0x03) as u8) << 6) | (more << 5) | (e2 << 4) | (e3 << 3));
                }
                _ => {
                    out.push(((n.sn >> 4) & 0xFF) as u8);
                    out.push((((n.sn & 0x0F) as u8) << 4) | (more << 3) | (e2 << 2) | (e3 << 1));
                }
            }
            if let Some((s, e)) = n.so {
                out.extend_from_slice(&s.to_be_bytes());
                out.extend_from_slice(&e.to_be_bytes());
            }
            if let Some(r) = n.range {
                out.push(r);
            }
        }
        out
    }

    /// Decode a STATUS PDU. Returns `None` for a data PDU, a reserved CPT, or a
    /// truncated buffer.
    pub fn decode(sn_len: SnLen, pdu: &[u8]) -> Option<StatusPdu> {
        let b0 = *pdu.first()?;
        if b0 & 0x80 != 0 || (b0 >> 4) & 0x07 != 0 {
            return None;
        }
        let b1 = *pdu.get(1)?;
        let b2 = *pdu.get(2)?;
        let (ack_sn, mut e1) = match sn_len {
            SnLen::Bits18 => (
                (((b0 & 0x0F) as u32) << 14) | ((b1 as u32) << 6) | ((b2 >> 2) as u32),
                b2 & 0x02 != 0,
            ),
            _ => ((((b0 & 0x0F) as u32) << 8) | b1 as u32, b2 & 0x80 != 0),
        };
        let mut i = 3usize;
        let mut nacks = Vec::new();
        while e1 {
            let (sn, e2, e3) = match sn_len {
                SnLen::Bits18 => {
                    let n0 = *pdu.get(i)?;
                    let n1 = *pdu.get(i + 1)?;
                    let n2 = *pdu.get(i + 2)?;
                    i += 3;
                    e1 = n2 & 0x20 != 0;
                    (
                        ((n0 as u32) << 10) | ((n1 as u32) << 2) | ((n2 >> 6) as u32),
                        n2 & 0x10 != 0,
                        n2 & 0x08 != 0,
                    )
                }
                _ => {
                    let n0 = *pdu.get(i)?;
                    let n1 = *pdu.get(i + 1)?;
                    i += 2;
                    e1 = n1 & 0x08 != 0;
                    (
                        ((n0 as u32) << 4) | ((n1 >> 4) as u32),
                        n1 & 0x04 != 0,
                        n1 & 0x02 != 0,
                    )
                }
            };
            let so = if e2 {
                let s = u16::from_be_bytes([*pdu.get(i)?, *pdu.get(i + 1)?]);
                let e = u16::from_be_bytes([*pdu.get(i + 2)?, *pdu.get(i + 3)?]);
                i += 4;
                Some((s, e))
            } else {
                None
            };
            let range = if e3 {
                let r = *pdu.get(i)?;
                i += 1;
                Some(r)
            } else {
                None
            };
            nacks.push(Nack { sn, so, range });
        }
        Some(StatusPdu { ack_sn, nacks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umd_full_sdu_is_one_zero_octet() {
        for sn_len in [SnLen::Bits6, SnLen::Bits12] {
            let mut out = Vec::new();
            UmdHeader {
                si: Si::Full,
                sn: 17,
                so: 0,
            }
            .encode(sn_len, &mut out);
            assert_eq!(out, [0x00]);
            let (h, len) = UmdHeader::decode(sn_len, &[0x00, 0xAA]).unwrap();
            assert_eq!((h.si, len), (Si::Full, 1));
        }
    }

    #[test]
    fn umd_6bit_layouts() {
        let mut out = Vec::new();
        UmdHeader {
            si: Si::First,
            sn: 0x2A,
            so: 0,
        }
        .encode(SnLen::Bits6, &mut out);
        assert_eq!(out, [0x40 | 0x2A]);
        out.clear();
        UmdHeader {
            si: Si::Middle,
            sn: 0x3F,
            so: 0x1234,
        }
        .encode(SnLen::Bits6, &mut out);
        assert_eq!(out, [0xC0 | 0x3F, 0x12, 0x34]);
        let (h, len) = UmdHeader::decode(SnLen::Bits6, &out).unwrap();
        assert_eq!(
            (h, len),
            (
                UmdHeader {
                    si: Si::Middle,
                    sn: 0x3F,
                    so: 0x1234
                },
                3
            )
        );
        out.clear();
        UmdHeader {
            si: Si::Last,
            sn: 1,
            so: 7,
        }
        .encode(SnLen::Bits6, &mut out);
        assert_eq!(out, [0x81, 0x00, 0x07]);
        assert_eq!(UmdHeader::size(Si::Last, SnLen::Bits6), 3);
        assert_eq!(UmdHeader::size(Si::First, SnLen::Bits6), 1);
    }

    #[test]
    fn umd_12bit_layouts() {
        let mut out = Vec::new();
        UmdHeader {
            si: Si::First,
            sn: 0xABC,
            so: 0,
        }
        .encode(SnLen::Bits12, &mut out);
        assert_eq!(out, [0x40 | 0x0A, 0xBC]);
        out.clear();
        UmdHeader {
            si: Si::Last,
            sn: 0xFFF,
            so: 0xBEEF,
        }
        .encode(SnLen::Bits12, &mut out);
        assert_eq!(out, [0x80 | 0x0F, 0xFF, 0xBE, 0xEF]);
        let (h, len) = UmdHeader::decode(SnLen::Bits12, &out).unwrap();
        assert_eq!(
            (h, len),
            (
                UmdHeader {
                    si: Si::Last,
                    sn: 0xFFF,
                    so: 0xBEEF
                },
                4
            )
        );
        // Truncated SO field.
        assert!(UmdHeader::decode(SnLen::Bits12, &[0x8F, 0xFF, 0xBE]).is_none());
        assert!(UmdHeader::decode(SnLen::Bits12, &[]).is_none());
        assert_eq!(UmdHeader::size(Si::Middle, SnLen::Bits12), 4);
        assert_eq!(UmdHeader::size(Si::First, SnLen::Bits12), 2);
    }

    #[test]
    fn amd_12bit_layouts() {
        // D/C=1, P=1, SI=00, SN=0x123 → 0xC1 0x23 (matches the Msg5 framing proven on a live gNB).
        let mut out = Vec::new();
        AmdHeader {
            poll: true,
            si: Si::Full,
            sn: 0x123,
            so: 0,
        }
        .encode(SnLen::Bits12, &mut out);
        assert_eq!(out, [0xC1, 0x23]);
        out.clear();
        AmdHeader {
            poll: false,
            si: Si::Middle,
            sn: 0xFFF,
            so: 0x0102,
        }
        .encode(SnLen::Bits12, &mut out);
        assert_eq!(out, [0x80 | 0x30 | 0x0F, 0xFF, 0x01, 0x02]);
        let (h, len) = AmdHeader::decode(SnLen::Bits12, &out).unwrap();
        assert_eq!(
            (h, len),
            (
                AmdHeader {
                    poll: false,
                    si: Si::Middle,
                    sn: 0xFFF,
                    so: 0x0102
                },
                4
            )
        );
        assert!(
            AmdHeader::decode(SnLen::Bits12, &[0x00, 0x00]).is_none(),
            "status pdu"
        );
        assert!(
            AmdHeader::decode(SnLen::Bits12, &[0xB0, 0x01, 0x00]).is_none(),
            "truncated SO"
        );
    }

    #[test]
    fn amd_18bit_layouts() {
        let mut out = Vec::new();
        AmdHeader {
            poll: true,
            si: Si::Last,
            sn: 0x3FFFF,
            so: 0xFFFF,
        }
        .encode(SnLen::Bits18, &mut out);
        assert_eq!(out, [0x80 | 0x40 | 0x20 | 0x03, 0xFF, 0xFF, 0xFF, 0xFF]);
        out.clear();
        AmdHeader {
            poll: false,
            si: Si::First,
            sn: 0x12345,
            so: 0,
        }
        .encode(SnLen::Bits18, &mut out);
        assert_eq!(out, [0x80 | 0x10 | 0x01, 0x23, 0x45]);
        let (h, len) = AmdHeader::decode(SnLen::Bits18, &out).unwrap();
        assert_eq!(
            (h, len),
            (
                AmdHeader {
                    poll: false,
                    si: Si::First,
                    sn: 0x12345,
                    so: 0
                },
                3
            )
        );
        assert_eq!(AmdHeader::size(Si::Full, SnLen::Bits18), 3);
        assert_eq!(AmdHeader::size(Si::Last, SnLen::Bits18), 5);
    }

    #[test]
    fn status_12bit_ack_only_matches_legacy_vector() {
        // The legacy (gNB-proven) builder: [ACK_SN>>8 & 0xF, ACK_SN & 0xFF, 0x00].
        let s = StatusPdu {
            ack_sn: 0x5A7,
            nacks: vec![],
        };
        assert_eq!(s.encode(SnLen::Bits12), [0x05, 0xA7, 0x00]);
        assert_eq!(
            StatusPdu::decode(SnLen::Bits12, &[0x05, 0xA7, 0x00]).unwrap(),
            s
        );
        assert!(is_status_pdu(&[0x05]));
        assert!(!is_status_pdu(&[0x85]));
        // Reserved CPT.
        assert!(StatusPdu::decode(SnLen::Bits12, &[0x15, 0xA7, 0x00]).is_none());
        assert!(StatusPdu::decode(SnLen::Bits12, &[0x05, 0xA7]).is_none());
    }

    #[test]
    fn status_12bit_nack_layouts() {
        let s = StatusPdu {
            ack_sn: 10,
            nacks: vec![
                Nack {
                    sn: 3,
                    so: None,
                    range: None,
                },
                Nack {
                    sn: 5,
                    so: Some((0x0010, SO_END_ALL)),
                    range: None,
                },
                Nack {
                    sn: 7,
                    so: None,
                    range: Some(2),
                },
                Nack {
                    sn: 0xABC,
                    so: Some((1, 2)),
                    range: Some(3),
                },
            ],
        };
        let b = s.encode(SnLen::Bits12);
        let expect = [
            0x00,
            0x0A,
            0x80, // ACK_SN=10, E1=1
            0x00,
            0x30 | 0x08, // NACK_SN=3, E1=1
            0x00,
            0x50 | 0x08 | 0x04,
            0x00,
            0x10,
            0xFF,
            0xFF, // NACK_SN=5 E1 E2 SOstart SOend
            0x00,
            0x70 | 0x08 | 0x02,
            0x02, // NACK_SN=7 E1 E3 range=2
            0xAB,
            0xC0 | 0x04 | 0x02,
            0x00,
            0x01,
            0x00,
            0x02,
            0x03, // last: E1=0 E2 E3
        ];
        assert_eq!(b, expect);
        assert_eq!(s.size(SnLen::Bits12), expect.len());
        assert_eq!(StatusPdu::decode(SnLen::Bits12, &b).unwrap(), s);
        // Truncated inside the last NACK's range octet.
        assert!(StatusPdu::decode(SnLen::Bits12, &b[..b.len() - 1]).is_none());
    }

    #[test]
    fn status_18bit_nack_layouts() {
        let s = StatusPdu {
            ack_sn: 0x3FFFF,
            nacks: vec![
                Nack {
                    sn: 0x2AAAA,
                    so: Some((5, 9)),
                    range: None,
                },
                Nack {
                    sn: 0x00001,
                    so: None,
                    range: Some(200),
                },
            ],
        };
        let b = s.encode(SnLen::Bits18);
        let expect = [
            0x0F,
            0xFF,
            0xFC | 0x02, // ACK_SN all ones, E1=1
            0xAA,
            0xAA,
            0x80 | 0x20 | 0x10,
            0x00,
            0x05,
            0x00,
            0x09, // sn=0x2AAAA → 10101010 10101010 10|E1|E2
            0x00,
            0x00,
            0x40 | 0x08,
            200, // sn=1 → 00000000 00000000 01, E1=0, E3=1
        ];
        assert_eq!(b, expect);
        assert_eq!(s.size(SnLen::Bits18), expect.len());
        assert_eq!(StatusPdu::decode(SnLen::Bits18, &b).unwrap(), s);
        let ack_only = StatusPdu {
            ack_sn: 0x12345,
            nacks: vec![],
        };
        let b = ack_only.encode(SnLen::Bits18);
        assert_eq!(b, [0x04, 0x8D, 0x14]);
        assert_eq!(StatusPdu::decode(SnLen::Bits18, &b).unwrap(), ack_only);
    }

    #[test]
    fn si_of_range() {
        assert_eq!(Si::of_range(0, 10, 10), Si::Full);
        assert_eq!(Si::of_range(0, 5, 10), Si::First);
        assert_eq!(Si::of_range(5, 10, 10), Si::Last);
        assert_eq!(Si::of_range(5, 7, 10), Si::Middle);
    }
}
