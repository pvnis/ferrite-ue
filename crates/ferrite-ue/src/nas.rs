//! Minimal 5GS NAS (TS 24.501) — just the RegistrationRequest the UE sends in
//! RRCSetupComplete, with a SUCI (null protection scheme) built from the IMSI.
//! Hand-rolled for exactly this message.

/// Pack two decimal digits into a BCD octet (low nibble first): (d_lo, d_hi).
fn bcd(lo: u8, hi: u8) -> u8 {
    (hi << 4) | (lo & 0x0f)
}

/// Build the SUCI (5GS mobile identity, null scheme) from a 15-digit IMSI with a
/// 2-digit MNC (TS 24.501 §9.11.3.4). Layout: identity-type octet, MCC/MNC (3),
/// routing indicator (2), protection scheme (1), home-net key id (1), then the
/// MSIN BCD (scheme output for the null scheme).
pub fn suci_from_imsi(imsi: &str) -> Vec<u8> {
    let d: Vec<u8> = imsi.bytes().map(|b| b - b'0').collect();
    assert!(d.len() == 15, "expect a 15-digit IMSI (2-digit MNC)");
    let (mcc, mnc, msin) = (&d[0..3], &d[3..5], &d[5..]);
    let mut v = Vec::new();
    // Identity type octet: SUPI format = IMSI (0), type of identity = SUCI (001).
    v.push(0x01);
    // MCC/MNC BCD (2-digit MNC → 3rd MNC digit = 0xf).
    v.push(bcd(mcc[0], mcc[1]));
    v.push(bcd(mcc[2], 0xf));
    v.push(bcd(mnc[0], mnc[1]));
    // Routing indicator: none configured → "0000" (per many cores) = 0x00 0x00.
    v.push(0x00);
    v.push(0x00);
    // Protection scheme id = null (0), home network public key id = 0.
    v.push(0x00);
    v.push(0x00);
    // Scheme output = MSIN in BCD (null scheme = cleartext).
    for pair in msin.chunks(2) {
        v.push(bcd(pair[0], *pair.get(1).unwrap_or(&0xf)));
    }
    v
}

/// Build a plain 5GS RegistrationRequest (TS 24.501 §8.2.6): initial
/// registration with the SUCI, 5GMM capability, and UE security capability.
pub fn registration_request(imsi: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.push(0x7e); // Extended protocol discriminator: 5GS mobility management
    m.push(0x00); // Security header type: plain NAS message
    m.push(0x41); // Message type: Registration request
    // 5GS registration type (½ octet) + ngKSI (½ octet): initial reg (0b001),
    // FOR=0; ngKSI = no key available (0b111). Octet = ngKSI<<4 | regtype.
    m.push(0x79); // 0111_1001: ngKSI=7, FOR=1, type=001 (initial)
    // 5GS mobile identity (SUCI), type-6 IE: 2-octet length + value.
    let suci = suci_from_imsi(imsi);
    m.push((suci.len() >> 8) as u8);
    m.push((suci.len() & 0xff) as u8);
    m.extend_from_slice(&suci);
    // 5GMM capability (IEI 0x10), length 1: S1 mode / handover bits (0x07 typical).
    m.push(0x10);
    m.push(0x01);
    m.push(0x07);
    // UE security capability (IEI 0x2e), length 2: 5G-EA0 + 128-5G-EA1/2 and
    // 5G-IA0 + 128-5G-IA1/2 (bit7..: EA0,EA1,EA2 / IA0,IA1,IA2). 0xe0 0xe0.
    m.push(0x2e);
    m.push(0x02);
    m.push(0xe0);
    m.push(0xe0);
    m
}

/// Parsed 5GS AuthenticationRequest (TS 24.501 §8.2.1): RAND (IEI 0x21) and
/// AUTN (IEI 0x20), plus ngKSI and ABBA.
pub struct AuthRequest {
    pub ngksi: u8,
    pub abba: Vec<u8>,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

/// Parse an AuthenticationRequest NAS message (header 7e 00 56).
pub fn parse_auth_request(nas: &[u8]) -> Option<AuthRequest> {
    if nas.len() < 4 || nas[0] != 0x7e || nas[2] != 0x56 {
        return None;
    }
    let ngksi = nas[3] & 0x0f;
    let abba_len = *nas.get(4)? as usize;
    let mut i = 5 + abba_len;
    let abba = nas.get(5..5 + abba_len)?.to_vec();
    let mut rand = None;
    let mut autn = None;
    while i < nas.len() {
        let iei = nas[i];
        match iei {
            0x21 => {
                // RAND: type-3 IE, fixed 16 octets, no length.
                rand = Some(nas.get(i + 1..i + 17)?.try_into().ok()?);
                i += 17;
            }
            0x20 => {
                // AUTN: type-4 IE, length + value.
                let l = *nas.get(i + 1)? as usize;
                autn = Some(nas.get(i + 2..i + 2 + l.min(16))?.try_into().ok()?);
                i += 2 + l;
            }
            _ => {
                // Other type-4 IEs (length-prefixed) — skip.
                let l = *nas.get(i + 1)? as usize;
                i += 2 + l;
            }
        }
    }
    Some(AuthRequest { ngksi, abba, rand: rand?, autn: autn? })
}

/// Build a 5GS AuthenticationResponse (TS 24.501 §8.2.2) carrying RES*
/// (Authentication response parameter, IEI 0x2d, length 16).
pub fn auth_response(res_star: &[u8; 16]) -> Vec<u8> {
    let mut m = vec![0x7e, 0x00, 0x57]; // 5GMM, plain, Authentication response
    m.push(0x2d); // IEI: Authentication response parameter
    m.push(0x10); // length 16
    m.extend_from_slice(res_star);
    m
}

/// Strip a 5GS NAS security header (TS 24.501 §9.1.1) if present. Returns
/// `(security_header_type, mac, sequence_number, inner_plain_message)`; for a
/// plain message (SHT nibble 0) returns `(0, [0;4], 0, whole message)`. A
/// protected message is [EPD 0x7e | SHT | MAC(4) | SEQ | inner].
pub fn strip_security_header(nas: &[u8]) -> (u8, [u8; 4], u8, &[u8]) {
    if nas.len() >= 7 && nas[0] == 0x7e && (nas[1] & 0x0f) != 0 {
        (nas[1] & 0x0f, nas[2..6].try_into().unwrap(), nas[6], &nas[7..])
    } else {
        (0, [0; 4], 0, nas)
    }
}

/// The 5GMM message type of a plain NAS message (3rd octet: EPD, SHT=0, type).
pub fn nas_msg_type(plain: &[u8]) -> Option<u8> {
    plain.get(2).copied()
}

/// Wrap a plain 5GS NAS message in a security header (TS 24.501 §9.1.1) with a
/// 128-NIA2 integrity MAC: [EPD 0x7e | SHT | MAC(4) | SEQ | inner]. The MAC is
/// computed over SEQ||inner with the NAS COUNT and BEARER=1 (`direction`: 0
/// uplink, 1 downlink). NEA0 ⇒ the inner message is not ciphered.
pub fn nas_protect(sht: u8, k_nasint: &[u8; 16], count: u32, direction: u8, inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0x7e, sht, 0, 0, 0, 0, (count & 0xff) as u8];
    out.extend_from_slice(inner);
    let mac = crate::milenage::nia2_mac(k_nasint, count, 1, direction, &out[6..]);
    out[2..6].copy_from_slice(&mac);
    out
}

/// Build a plain SecurityModeComplete (TS 24.501 §8.2.26), replaying the initial
/// RegistrationRequest in a NAS message container (IEI 0x71) as required when the
/// initial registration was sent without integrity protection.
pub fn security_mode_complete(imsi: &str) -> Vec<u8> {
    let mut m = vec![0x7e, 0x00, 0x5e]; // 5GMM, plain, Security mode complete
    let rr = registration_request(imsi);
    m.push(0x71); // NAS message container IEI
    m.push((rr.len() >> 8) as u8);
    m.push((rr.len() & 0xff) as u8);
    m.extend_from_slice(&rr);
    m
}

/// Build a plain RegistrationComplete (TS 24.501 §8.2.9): header only.
pub fn registration_complete() -> Vec<u8> {
    vec![0x7e, 0x00, 0x43]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suci_layout() {
        // imsi 001010167891203 → MCC 001, MNC 01, MSIN 0167891203
        let s = suci_from_imsi("001010167891203");
        assert_eq!(s[0], 0x01); // IMSI / SUCI
        assert_eq!(s[1], 0x00); // MCC digits 0,0
        assert_eq!(s[2], 0xf1); // MNC filler f, MCC digit 1
        assert_eq!(s[3], 0x10); // MNC digits 1,0
        assert_eq!(s[6], 0x00); // protection scheme = null
        assert_eq!(s[7], 0x00); // home net key id
        // MSIN 0167891203 → 10,76,98,21,30
        assert_eq!(&s[8..], &[0x10, 0x76, 0x98, 0x21, 0x30]);
    }

    #[test]
    fn reg_request_header() {
        let r = registration_request("001010167891203");
        assert_eq!(&r[0..4], &[0x7e, 0x00, 0x41, 0x79]);
    }
}
