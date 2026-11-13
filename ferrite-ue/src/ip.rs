//! IP/ICMP helpers for the built-in ping probe (RFC 791 / RFC 792). OS plumbing
//! and user-plane framing live elsewhere (TUN in `tun.rs`, PDCP/RLC in their crates).

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

