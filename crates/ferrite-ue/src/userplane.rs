//! User-plane data path for the DRB: the IP/ICMP payload and the SDAP/PDCP/RLC/MAC
//! framing that carries it over the air. Hand-rolled for exactly this DRB config
//! (from the gNB's RRCReconfiguration): DRB 1 = LCID 4, SDAP headers absent,
//! PDCP 18-bit SN (NEA0, no integrity), RLC UM 12-bit SN. See TS 38.323/38.322/38.321.

use crate::rrc::{bsr_index, parse_dl_mac_pdu, LCID_PADDING, LCID_SHORT_BSR};

/// DRB logical channel identity (from the masterCellGroup RLC-BearerConfig).
pub const LCID_DRB1: u8 = 4;

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian words.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8; // odd trailing byte, padded with 0
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 packet carrying an ICMP echo request (ping) from `src` to `dst`
/// (TS-agnostic; RFC 791 + RFC 792). `id`/`seq` identify the echo; `payload` is
/// the ICMP data. Returns the full IPv4 datagram.
pub fn ipv4_icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    // ICMP echo request: type 8, code 0, checksum, id, seq, payload.
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.extend_from_slice(&[8, 0, 0, 0]); // type, code, checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    // IPv4 header (20 bytes, no options).
    let total_len = 20 + icmp.len();
    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes()); // identification
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: don't fragment
    ip.push(64); // TTL
    ip.push(1); // protocol: ICMP
    ip.extend_from_slice(&[0, 0]); // header checksum placeholder
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ip_csum = internet_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    ip.extend_from_slice(&icmp);
    ip
}

/// A parsed ICMP echo reply extracted from an IPv4 datagram.
pub struct IcmpEchoReply {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub id: u16,
    pub seq: u16,
}

/// Parse an IPv4 datagram and, if it is an ICMP echo reply (type 0), return its
/// fields. Returns None for anything else (other protocols, ICMP errors, …).
pub fn parse_ipv4_icmp_echo_reply(pkt: &[u8]) -> Option<IcmpEchoReply> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt[9] != 1 || pkt.len() < ihl + 8 {
        return None; // not ICMP
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 {
        return None; // not an echo reply
    }
    Some(IcmpEchoReply {
        src: pkt[12..16].try_into().ok()?,
        dst: pkt[16..20].try_into().ok()?,
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

/// Build a PDCP Data PDU for the DRB, 18-bit SN (TS 38.323 §6.2.2.1):
/// [D/C=1|R(5)|SN(18)] over 3 octets, then the (NEA0 = plaintext) payload; no
/// MAC-I (DRB, no integrity). The payload is an SDAP SDU = the raw IP packet
/// (SDAP headers are absent for this DRB).
pub fn pdcp_data_pdu(pdcp_sn: u32, ip_packet: &[u8]) -> Vec<u8> {
    let mut pdcp = Vec::with_capacity(3 + ip_packet.len());
    pdcp.push(0x80 | ((pdcp_sn >> 16) & 0x03) as u8);
    pdcp.push((pdcp_sn >> 8) as u8);
    pdcp.push(pdcp_sn as u8);
    pdcp.extend_from_slice(ip_packet);
    pdcp
}

/// Wrap one RLC PDU in a UL-SCH MAC subPDU for DRB 1 (LCID 4) and pad to `tbs`.
pub fn drb_mac_wrap(rlc: &[u8], tbs: usize) -> Vec<u8> {
    let mut mac = Vec::with_capacity(tbs);
    if rlc.len() < 256 {
        mac.push(LCID_DRB1); // R=0, F=0 (8-bit L), LCID=4
        mac.push(rlc.len() as u8);
    } else {
        mac.push(0x40 | LCID_DRB1); // F=1 (16-bit L)
        mac.push((rlc.len() >> 8) as u8);
        mac.push((rlc.len() & 0xff) as u8);
    }
    mac.extend_from_slice(rlc);
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
    mac
}

/// Wrap one RLC PDU in a UL-SCH MAC subPDU for DRB 1 (LCID 4), and — when `bsr_bytes > 0`
/// (more DRB data is still buffered) — piggyback a Short BSR CE reporting the total
/// remaining buffer, then pad to `tbs`. The BSR keeps the gNB granting continuously to
/// drain the whole queue instead of the UE having to SR/BSR once per packet (which serialises
/// the queue behind the ~1-frame SR period and caps DRB throughput). Order per TS 38.321
/// §6.1.2: SDU subPDU, then the CE subPDU, then padding.
pub fn drb_mac_wrap_bsr(rlc: &[u8], bsr_bytes: usize, tbs: usize) -> Vec<u8> {
    let mut mac = Vec::with_capacity(tbs);
    if rlc.len() < 256 {
        mac.push(LCID_DRB1);
        mac.push(rlc.len() as u8);
    } else {
        mac.push(0x40 | LCID_DRB1);
        mac.push((rlc.len() >> 8) as u8);
        mac.push((rlc.len() & 0xff) as u8);
    }
    mac.extend_from_slice(rlc);
    if bsr_bytes > 0 && mac.len() + 2 <= tbs {
        mac.push(LCID_SHORT_BSR);
        mac.push(bsr_index(bsr_bytes));
    }
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
    mac
}

/// Frame a complete IP packet for uplink on DRB 1: PDCP 18-bit Data PDU → RLC UM
/// complete-SDU PDU (1-octet header, SI=00) → MAC subheader (LCID 4), padded to
/// `tbs`. Used for small packets (e.g. the built-in ping) that fit one grant.
pub fn drb_ul_pdu(pdcp_sn: u32, ip_packet: &[u8], tbs: usize) -> Vec<u8> {
    let pdcp = pdcp_data_pdu(pdcp_sn, ip_packet);
    let mut rlc = Vec::with_capacity(1 + pdcp.len());
    rlc.push(0x00); // RLC UM, SI=00 (complete SDU), no SN
    rlc.extend_from_slice(&pdcp);
    drb_mac_wrap(&rlc, tbs)
}

/// Produce one RLC UM Data PDU (TS 38.322 §6.2.2.3, 12-bit SN) carrying `sdu` from
/// byte `offset`, no larger than `max_len` octets total. Returns `(pdu, new_offset)`;
/// when `new_offset == sdu.len()` the SDU is fully transmitted. Emits a complete-SDU
/// PDU (SI=00) when the whole SDU fits from the start, else first/middle/last
/// segments with a Segment Offset — for IP packets larger than a single UL grant.
pub fn rlc_um_segment(sdu: &[u8], offset: usize, sn: u16, max_len: usize) -> (Vec<u8>, usize) {
    let first = offset == 0;
    if first && 1 + sdu.len() <= max_len {
        let mut p = Vec::with_capacity(1 + sdu.len());
        p.push(0x00); // SI=00 complete SDU
        p.extend_from_slice(sdu);
        return (p, sdu.len());
    }
    let hdr = if first { 2 } else { 4 }; // first: SI+SN(2); mid/last: SI+SN+SO(4)
    if max_len <= hdr {
        return (Vec::new(), offset); // grant can't hold any data this round
    }
    let take = (max_len - hdr).min(sdu.len() - offset);
    let last = offset + take == sdu.len();
    let si: u8 = match (first, last) {
        (true, _) => 0b01,  // first segment
        (false, true) => 0b10,  // last segment
        (false, false) => 0b11, // middle segment
    };
    let mut p = Vec::with_capacity(hdr + take);
    p.push((si << 6) | ((sn >> 8) & 0x0f) as u8);
    p.push((sn & 0xff) as u8);
    if !first {
        p.push((offset >> 8) as u8);
        p.push((offset & 0xff) as u8);
    }
    p.extend_from_slice(&sdu[offset..offset + take]);
    (p, offset + take)
}

/// Reassembles RLC UM SDUs (TS 38.322 §6.2.2.3, 12-bit SN). Keeps per-SN segment
/// buffers keyed by segment offset; delivers a full SDU once contiguous to the
/// last segment. A complete-SDU PDU (SI=00) is returned directly.
#[derive(Default)]
pub struct RlcUmReassembler {
    segs: std::collections::HashMap<u16, (std::collections::BTreeMap<usize, Vec<u8>>, Option<usize>)>,
}

impl RlcUmReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one RLC UM Data PDU (12-bit SN). Returns the completed SDU, if any.
    pub fn push(&mut self, rlc: &[u8]) -> Option<Vec<u8>> {
        let si = (rlc.first()? >> 6) & 0x03;
        if si == 0b00 {
            return Some(rlc.get(1..)?.to_vec()); // complete SDU, 1-octet header
        }
        // Segmented: 12-bit SN in the low 4 bits of octet 0 + octet 1.
        let sn = (((rlc[0] & 0x0f) as u16) << 8) | *rlc.get(1)? as u16;
        let (so, hdr) = if si == 0b10 || si == 0b11 {
            (((*rlc.get(2)? as u16) << 8) | *rlc.get(3)? as u16, 4)
        } else {
            (0u16, 2)
        };
        let data = rlc.get(hdr..)?.to_vec();
        let entry = self.segs.entry(sn).or_default();
        let end = so as usize + data.len();
        entry.0.insert(so as usize, data);
        if si == 0b10 {
            entry.1 = Some(end); // last segment fixes the length
        }
        let total = entry.1?;
        let mut out: Vec<u8> = Vec::new();
        for (&off, seg) in entry.0.iter() {
            if off == out.len() {
                out.extend_from_slice(seg);
            } else if off < out.len() {
                if off + seg.len() > out.len() {
                    out.extend_from_slice(&seg[out.len() - off..]);
                }
            } else {
                return None; // gap
            }
        }
        if out.len() >= total {
            self.segs.remove(&sn);
            Some(out)
        } else {
            None
        }
    }
}

/// Plausibility check for a DL-SCH MAC PDU carrying DRB 1 (LCID 4) user data — used
/// to accept a brute-forced DRB PDSCH decode (which otherwise wouldn't unstack to a
/// known RRC message). The gNB segments DL SDUs across RLC UM PDUs, so accept the
/// complete SDU AND the first/middle/last segments: a complete SDU or first segment
/// starts a PDCP data PDU (D/C=1) + IPv4 packet; mid/last segments are mid-PDU, so
/// the 24-bit TB CRC (already passed) is the guarantee and only the RLC header is checked.
pub fn looks_like_drb_ip(mac_pdu: &[u8]) -> bool {
    parse_dl_mac_pdu(mac_pdu).iter().any(|s| {
        let p = &s.payload;
        if s.lcid != LCID_DRB1 || p.is_empty() {
            return false;
        }
        match (p[0] >> 6) & 0x03 {
            // Complete SDU (SI=00): [0x00 | PDCP(3) | IPv4…].
            0b00 => p.len() >= 5 && (p[1] & 0x80) != 0 && (p[4] >> 4) == 4,
            // First segment (SI=01, 2-byte header): [hdr(2) | PDCP(3) | IPv4…].
            0b01 => p.len() >= 6 && (p[2] & 0x80) != 0 && (p[5] >> 4) == 4,
            // Last/middle segment (SI=10/11, 4-byte SN+SO header): mid-PDU.
            _ => p.len() >= 5,
        }
    })
}

/// Unstack a DL-SCH MAC PDU for DRB 1: MAC (LCID 4) → RLC UM reassembly → PDCP
/// (strip the 3-octet 18-bit-SN header; NEA0 plaintext). Returns `(pdcp_sn, ip)`
/// once a full SDU reassembles — the SN lets the caller drop HARQ-retransmitted
/// duplicates.
pub fn parse_drb_dl_ip(reasm: &mut RlcUmReassembler, mac_pdu: &[u8]) -> Option<(u32, Vec<u8>)> {
    for s in parse_dl_mac_pdu(mac_pdu).iter().filter(|s| s.lcid == LCID_DRB1) {
        if let Some(pdcp) = reasm.push(&s.payload) {
            if pdcp.len() < 3 {
                return None;
            }
            let sn = (((pdcp[0] & 0x03) as u32) << 16) | ((pdcp[1] as u32) << 8) | pdcp[2] as u32;
            return pdcp.get(3..).map(|ip| (sn, ip.to_vec()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // A minimal IPv4 header with a known checksum (RFC example style).
        let hdr = [
            0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        // Checksum field is 0 above; computed value is 0xb1e6.
        assert_eq!(internet_checksum(&hdr), 0xb1e6);
    }

    #[test]
    fn icmp_echo_roundtrip() {
        let pkt = ipv4_icmp_echo_request([10, 255, 0, 3], [8, 8, 8, 8], 0x1234, 1, b"ferrite!");
        // A well-formed IPv4 header checksums (with its own field) to 0.
        assert_eq!(internet_checksum(&pkt[..20]), 0);
        // Turn it into a reply (type 8 → 0) and parse it back.
        let mut reply = pkt.clone();
        reply[20] = 0; // ICMP type: echo reply
        let r = parse_ipv4_icmp_echo_reply(&reply).unwrap();
        assert_eq!(r.src, [10, 255, 0, 3]);
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.seq, 1);
    }

    #[test]
    fn drb_ul_then_dl_roundtrip() {
        let ip = ipv4_icmp_echo_request([10, 255, 0, 3], [8, 8, 8, 8], 7, 2, b"x");
        let mac = drb_ul_pdu(0, &ip, 80);
        let mut reasm = RlcUmReassembler::new();
        let (sn, got) = parse_drb_dl_ip(&mut reasm, &mac).unwrap();
        assert_eq!(sn, 0);
        assert_eq!(got, ip);
    }

    #[test]
    fn rlc_um_segmentation_roundtrip() {
        // A large IP packet that must be split across several small grants, then
        // reassembled by the RLC UM receiver.
        let ip = ipv4_icmp_echo_request([10, 255, 0, 3], [8, 8, 8, 8], 9, 5, &vec![0xab; 400]);
        let pdcp = pdcp_data_pdu(3, &ip);
        let mut reasm = RlcUmReassembler::new();
        let mut off = 0;
        let mut done = None;
        while off < pdcp.len() {
            let (rlc, new_off) = rlc_um_segment(&pdcp, off, 12, 90); // 90-byte grants
            assert!(new_off > off, "segment made progress");
            off = new_off;
            if let Some(sdu) = reasm.push(&rlc) {
                done = Some(sdu);
            }
        }
        assert_eq!(done.unwrap(), pdcp);
        // And the reassembled PDCP unstacks (strip 3-byte header) back to the IP.
        // (parse_drb_dl_ip does MAC+RLC+PDCP; here we already have the PDCP SDU.)
    }
}
