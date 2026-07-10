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

/// Encode `UL-DCCH-Message { c1: ulInformationTransfer }` carrying `nas`
/// (TS 38.331). Used to send NAS uplink (AuthenticationResponse, etc.).
/// Layout: [1: c1=0][4: c1 idx ulInformationTransfer=7][1: critExt=0]
/// [3: optional bitmap = 100 (dedicatedNAS present)][NAS length + octets].
pub fn rrc_ul_information_transfer(nas: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.put(0, 1); // c1
    w.put(7, 4); // c1: ulInformationTransfer (index 7)
    w.put(0, 1); // criticalExtensions: ulInformationTransfer
    w.put(0b100, 3); // optional bitmap: dedicatedNAS present, lateExt/nonCrit absent
    put_length(&mut w, nas.len());
    for &b in nas {
        w.put(b as u64, 8);
    }
    w.finish()
}

/// Encode `UL-DCCH-Message { c1: securityModeComplete }` (TS 38.331). Layout:
/// [1: c1=0][4: c1 idx securityModeComplete=5][2: rrc-TransactionIdentifier]
/// [1: critExt=securityModeComplete=0][2: IEs optional bitmap = 00 (lateExt,
/// nonCrit absent)].
pub fn rrc_security_mode_complete(transaction_id: u8) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.put(0, 1);
    w.put(5, 4);
    w.put((transaction_id & 3) as u64, 2);
    w.put(0, 1);
    w.put(0, 2);
    w.finish()
}

/// Encode `UL-DCCH-Message { c1: rrcReconfigurationComplete }` (TS 38.331):
/// c1 index 1, rrc-TransactionIdentifier, critExt=0, IEs optional bitmap 00.
pub fn rrc_reconfiguration_complete(transaction_id: u8) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.put(0, 1);
    w.put(1, 4);
    w.put((transaction_id & 3) as u64, 2);
    w.put(0, 1);
    w.put(0, 2);
    w.finish()
}

/// A minimal UE-NR-Capability (TS 38.331): accessStratumRelease rel15 + a single
/// supported band n78, every optional feature set absent. UPER-encoded and
/// validated byte-exact against OCUDU's `ue_nr_cap_s` packer (`rrc_dec gen-uecap`).
/// This is the UE's claimed radio capability — the minimum the gNB accepts to
/// finish the capability transfer and proceed to RRCReconfiguration.
pub fn ue_nr_capability() -> Vec<u8> {
    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0x9a]
}

/// Encode `UL-DCCH-Message { c1: ueCapabilityInformation }` (TS 38.331): c1 index
/// 9, carrying one UE-CapabilityRAT-Container (rat-Type nr) with the minimal
/// UE-NR-Capability. Answer to a UECapabilityEnquiry. Validated byte-exact vs
/// OCUDU (`rrc_dec gen-uecapinfo` → 4882028000000000000000002680 for tid 0).
///
/// Layout: [1: c1=0][4: idx=9][2: tid][1: critExt=0][3: IEs opt bitmap=100
/// (ratContainerList present)][4: list SIZE(0..8) count=1][1: rat-Type ext=0]
/// [2: rat-Type nr=0][OCTET STRING: length + UE-NR-Capability octets].
pub fn rrc_ue_capability_information(transaction_id: u8) -> Vec<u8> {
    let cap = ue_nr_capability();
    let mut w = BitWriter::new();
    w.put(0, 1);
    w.put(9, 4);
    w.put((transaction_id & 3) as u64, 2);
    w.put(0, 1);
    w.put(0b100, 3); // ue-CapabilityRAT-ContainerList present
    w.put(1, 4); // container list count = 1
    w.put(0, 1); // rat-Type extension bit
    w.put(0, 2); // rat-Type = nr
    put_length(&mut w, cap.len());
    for &b in &cap {
        w.put(b as u64, 8);
    }
    w.finish()
}

/// The 2-bit rrc-TransactionIdentifier of a DL-DCCH c1 message (it follows the
/// 1-bit c1 CHOICE + 4-bit message index).
pub fn dl_dcch_transaction_id(rrc: &[u8]) -> u8 {
    let mut r = BitReader::new(rrc);
    let _ = r.get(5); // c1 + index
    r.get(2).unwrap_or(0) as u8
}

/// UPER length determinant for an unconstrained count `n` (TS X.691 §11.9).
fn put_length(w: &mut BitWriter, n: usize) {
    if n < 128 {
        w.put(n as u64, 8); // 0 | 7-bit
    } else {
        assert!(n < 16384, "length too large for the short form");
        w.put(0b10, 2);
        w.put(n as u64, 14);
    }
}

/// Read a UPER length determinant (inverse of `put_length`).
fn get_length(r: &mut BitReader) -> Option<usize> {
    if r.get(1)? == 0 {
        Some(r.get(7)? as usize) // short form: 0 | 7-bit
    } else {
        if r.get(1)? != 0 {
            return None; // fragmented form not supported
        }
        Some(r.get(14)? as usize) // 10 | 14-bit
    }
}

/// Decode a `DL-DCCH-Message { c1: dlInformationTransfer }` (TS 38.331) and
/// return the carried `dedicatedNAS-Message` octets. Mirror of the UL encoder,
/// but DLInformationTransfer has a 2-bit rrc-TransactionIdentifier before the
/// criticalExtensions CHOICE. The NAS octets are UPER-packed (not byte aligned),
/// so they must be bit-shifted out — a plain byte scan for 0x7e misses them.
///
/// Layout: [1: c1=0][4: c1 idx dlInformationTransfer=5][2: rrc-TransactionId]
/// [1: critExt=dlInformationTransfer=0][3: optional bitmap {dedNAS,lateExt,
/// nonCrit}][dedicatedNAS-Message: length + octets].
pub fn parse_dl_dcch_nas(rrc: &[u8]) -> Option<Vec<u8>> {
    let mut r = BitReader::new(rrc);
    if r.get(1)? != 0 {
        return None; // DL-DCCH-MessageType CHOICE: c1
    }
    if r.get(4)? != 5 {
        return None; // c1 CHOICE: dlInformationTransfer (index 5)
    }
    let _tid = r.get(2)?; // rrc-TransactionIdentifier (0..3)
    if r.get(1)? != 0 {
        return None; // criticalExtensions CHOICE: dlInformationTransfer
    }
    let opt = r.get(3)?; // {dedicatedNAS-Message, lateNonCritExt, nonCritExt}
    if opt & 0b100 == 0 {
        return None; // dedicatedNAS-Message absent
    }
    let len = get_length(&mut r)?;
    let mut nas = Vec::with_capacity(len);
    for _ in 0..len {
        nas.push(r.get(8)? as u8);
    }
    Some(nas)
}

/// Unstack a DL-SCH SRB1 MAC PDU → the carried NAS. Peels the MAC subheader
/// (DCCH = LCID 1), the RLC AM Data PDU header (2 octets, 12-bit SN, complete
/// SDU), the PDCP Data PDU header (2 octets, 12-bit SN) and trailing MAC-I
/// (4 octets), then decodes the DL-DCCH dlInformationTransfer RRC PDU.
pub fn parse_srb1_dl_nas(mac_pdu: &[u8]) -> Option<Vec<u8>> {
    parse_dl_dcch_nas(&parse_srb1_dl_rrc(mac_pdu)?)
}

/// Unstack a DL-SCH SRB1 MAC PDU → the raw RRC PDU (a DL-DCCH message). Peels the
/// MAC subheader (DCCH = LCID 1), the RLC AM Data PDU header (2 octets, 12-bit
/// SN — skipping any RLC STATUS PDU), and the PDCP header (2 octets) + trailing
/// MAC-I (4 octets). The payload is plaintext RRC (NEA0); a non-null AS cipher
/// would require deciphering the PDCP payload first. Also returns the RLC SN.
pub fn parse_srb1_dl_rrc_sn(mac_pdu: &[u8]) -> Option<(u16, Vec<u8>)> {
    for s in parse_dl_mac_pdu(mac_pdu).iter().filter(|s| s.lcid == 1) {
        let rlc = &s.payload;
        // RLC AM DATA PDU: D/C must be 1 (skip STATUS); 12-bit SN ⇒ 2-octet header.
        if rlc.len() < 2 || (rlc[0] & 0x80) == 0 {
            continue;
        }
        let rlc_sn = (((rlc[0] & 0x0f) as u16) << 8) | rlc[1] as u16;
        let pdcp = &rlc[2..];
        // PDCP Data PDU (SRB): 2-octet header (12-bit SN) + RRC + 4-octet MAC-I.
        if pdcp.len() < 2 + 4 {
            continue;
        }
        return Some((rlc_sn, pdcp[2..pdcp.len() - 4].to_vec()));
    }
    None
}

/// As `parse_srb1_dl_rrc_sn` but returning only the RRC PDU.
pub fn parse_srb1_dl_rrc(mac_pdu: &[u8]) -> Option<Vec<u8>> {
    parse_srb1_dl_rrc_sn(mac_pdu).map(|(_, rrc)| rrc)
}

/// Parsed RLC AM Data PDU header (TS 38.322 §6.2.2.4, 12-bit SN). `si`:
/// 0b00 = complete SDU, 0b01 = first segment, 0b10 = last, 0b11 = middle.
pub struct RlcAmHeader {
    pub si: u8,
    pub sn: u16,
    pub so: u16,
    pub hdr_len: usize,
}

/// Parse the header of an RLC AM Data PDU. Returns None for a STATUS PDU (D/C=0)
/// or a too-short buffer. A last/middle segment carries a 2-octet Segment Offset.
pub fn parse_rlc_am_header(rlc: &[u8]) -> Option<RlcAmHeader> {
    if rlc.len() < 2 || (rlc[0] & 0x80) == 0 {
        return None; // STATUS PDU or empty
    }
    let si = (rlc[0] >> 4) & 0x03;
    let sn = (((rlc[0] & 0x0f) as u16) << 8) | rlc[1] as u16;
    let (so, hdr_len) = if si == 0b10 || si == 0b11 {
        (((*rlc.get(2)? as u16) << 8) | *rlc.get(3)? as u16, 4)
    } else {
        (0, 2)
    };
    Some(RlcAmHeader { si, sn, so, hdr_len })
}

/// Reassembles RLC AM SDUs from (possibly segmented, possibly retransmitted) AM
/// Data PDUs (TS 38.322 §5.2.3). Keeps per-SN segment buffers keyed by segment
/// offset; delivers a full SDU once all bytes up to the last segment are present.
#[derive(Default)]
pub struct RlcReassembler {
    segs: std::collections::HashMap<u16, (std::collections::BTreeMap<usize, Vec<u8>>, Option<usize>)>,
}

impl RlcReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one RLC AM Data PDU (header + data). Returns the completed SDU if this
    /// PDU finishes one. A complete-SDU PDU (SI=00) is returned directly.
    pub fn push(&mut self, rlc: &[u8]) -> Option<Vec<u8>> {
        let h = parse_rlc_am_header(rlc)?;
        let data = rlc.get(h.hdr_len..)?.to_vec();
        if h.si == 0b00 {
            return Some(data); // whole SDU, no segmentation
        }
        let entry = self.segs.entry(h.sn).or_default();
        let end = h.so as usize + data.len();
        entry.0.insert(h.so as usize, data);
        if h.si == 0b10 {
            entry.1 = Some(end); // last segment fixes the SDU length
        }
        let total = entry.1?;
        // Walk the offset-ordered segments; require contiguity from 0.
        let mut out: Vec<u8> = Vec::new();
        for (&so, seg) in entry.0.iter() {
            if so == out.len() {
                out.extend_from_slice(seg);
            } else if so < out.len() {
                // overlap (retransmission); extend only past what we already have
                if so + seg.len() > out.len() {
                    out.extend_from_slice(&seg[out.len() - so..]);
                }
            } else {
                return None; // gap — wait for the missing segment
            }
        }
        if out.len() >= total {
            self.segs.remove(&h.sn);
            Some(out)
        } else {
            None
        }
    }
}

/// Feed the SRB1 (LCID 1) RLC AM PDU from a DL-SCH MAC PDU into `reasm`. Returns
/// `(rlc_sn, Option<rrc>)`: the RLC SN (for STATUS reporting) and, once a full SDU
/// reassembles, the RRC PDU (PDCP header + trailing MAC-I stripped; NEA0 plaintext).
pub fn srb1_dl_rrc_reasm(reasm: &mut RlcReassembler, mac_pdu: &[u8]) -> Option<(u16, Option<Vec<u8>>)> {
    for s in parse_dl_mac_pdu(mac_pdu).iter().filter(|s| s.lcid == 1) {
        let h = parse_rlc_am_header(&s.payload)?; // None = STATUS PDU, skip
        let rrc = reasm.push(&s.payload).and_then(|pdcp| {
            (pdcp.len() >= 2 + 4).then(|| pdcp[2..pdcp.len() - 4].to_vec())
        });
        return Some((h.sn, rrc));
    }
    None
}

/// Unstack a DL-SCH SRB1 MAC PDU → `(pdcp_count, pdcp_msg, mac_i)` for PDCP
/// integrity verification: `pdcp_msg` = PDCP header || RRC (the 128-NIA2 input),
/// `mac_i` the received 4-octet MAC-I. The RRC PDU is `pdcp_msg[2..]`.
pub fn parse_srb1_dl_pdcp(mac_pdu: &[u8]) -> Option<(u16, Vec<u8>, [u8; 4])> {
    for s in parse_dl_mac_pdu(mac_pdu).iter().filter(|s| s.lcid == 1) {
        let rlc = &s.payload;
        if rlc.len() < 2 || (rlc[0] & 0x80) == 0 {
            continue;
        }
        let pdcp = &rlc[2..];
        if pdcp.len() < 2 + 4 {
            continue;
        }
        let pdcp_sn = (((pdcp[0] & 0x0f) as u16) << 8) | pdcp[1] as u16;
        let cut = pdcp.len() - 4;
        return Some((pdcp_sn, pdcp[..cut].to_vec(), pdcp[cut..].try_into().unwrap()));
    }
    None
}

/// Left-shift a byte array by `shift` bits (0..8), pulling bits in from the next
/// byte — used to re-align a UPER-packed field to a byte boundary for scanning.
fn bitshift_left(data: &[u8], shift: usize) -> Vec<u8> {
    if shift == 0 {
        return data.to_vec();
    }
    (0..data.len())
        .map(|i| {
            let hi = (data[i] as usize) << shift;
            let lo = data.get(i + 1).map(|&b| (b as usize) >> (8 - shift)).unwrap_or(0);
            ((hi | lo) & 0xff) as u8
        })
        .collect()
}

/// Extract the UE's assigned IPv4 address from an RRCReconfiguration that carries
/// a PDU Session Establishment Accept in its `dedicatedNAS-MessageList`. That NAS
/// message is UPER bit-packed (not byte-aligned) inside the reconfiguration, so
/// rather than decode the whole RadioBearerConfig, try all 8 bit alignments and
/// look for the DL NAS Transport (`7e 00 68 01`) whose payload container (the 5GSM
/// Accept) contains a PDU-address IE (`29 05 01` = IPv4). Validating the full chain
/// makes a wrong alignment essentially impossible to false-match.
pub fn reconfig_pdu_session_ip(rrc: &[u8]) -> Option<[u8; 4]> {
    for shift in 0..8 {
        let buf = bitshift_left(rrc, shift);
        let mut i = 0;
        while i + 6 <= buf.len() {
            // DL NAS Transport header + N1 SM payload container type.
            if buf[i] == 0x7e && buf[i + 1] == 0x00 && buf[i + 2] == 0x68 && buf[i + 3] == 0x01 {
                let plen = ((buf[i + 4] as usize) << 8) | buf[i + 5] as usize;
                if let Some(accept) = buf.get(i + 6..i + 6 + plen) {
                    // PDU address IE: IEI 0x29, length 5, PDU type 0x01 (IPv4), 4 octets.
                    if let Some(ip) = accept.windows(7).find_map(|w| {
                        (w[0] == 0x29 && w[1] == 0x05 && w[2] == 0x01).then(|| [w[3], w[4], w[5], w[6]])
                    }) {
                        return Some(ip);
                    }
                }
            }
            i += 1;
        }
    }
    None
}

/// The DL-DCCH c1 message index (TS 38.331): 0=rrcReconfiguration, 2=rrcRelease,
/// 4=securityModeCommand, 5=dlInformationTransfer, … Returns None if not a c1.
pub fn dl_dcch_type(rrc: &[u8]) -> Option<u8> {
    let b = *rrc.first()?;
    if b & 0x80 != 0 {
        return None; // not the c1 CHOICE
    }
    Some((b >> 3) & 0x0f)
}

/// Encode `UL-DCCH-Message { c1: rrcSetupComplete }` carrying `nas` as the
/// dedicatedNAS-Message (TS 38.331). `selectedPLMN-Identity` = `plmn` (1..12).
///
/// UPER layout: [1: msg CHOICE c1=0][4: c1 index rrcSetupComplete=2]
/// [2: rrc-TransactionIdentifier][1: critExt CHOICE rrcSetupComplete=0]
/// [1: IEs ext marker=0][6: optional bitmap=0][4: selectedPLMN-1]
/// [dedicatedNAS-Message: length + octets].
pub fn rrc_setup_complete(transaction_id: u8, plmn: u8, nas: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.put(0, 1); // UL-DCCH-MessageType CHOICE: c1
    w.put(2, 4); // c1 CHOICE: rrcSetupComplete (index 2 of 16)
    w.put((transaction_id & 0x3) as u64, 2); // RRC-TransactionIdentifier (0..3)
    w.put(0, 1); // criticalExtensions CHOICE: rrcSetupComplete
    w.put(0, 6); // optional bitmap: registeredAMF/guami/s-NSSAI/ng-5G-S-TMSI/lateExt/nonCrit all absent
    w.put((plmn - 1) as u64, 4); // selectedPLMN-Identity (1..12) → constrained 4 bits
    put_length(&mut w, nas.len()); // dedicatedNAS-Message OCTET STRING length
    for &b in nas {
        w.put(b as u64, 8);
    }
    w.finish()
}

// ---------------------------------------------------------------------------
// MAC (TS 38.321)
// ---------------------------------------------------------------------------

/// UL-SCH LCID values (TS 38.321 Table 6.2.1-2).
pub const LCID_UL_CCCH48: u8 = 52; // 48-bit CCCH SDU, no length field
pub const LCID_PADDING: u8 = 63;

/// DL-SCH LCID values (TS 38.321 Table 6.2.1-1).
pub const LCID_DL_CCCH: u8 = 0; // DL CCCH SDU (has length field)
pub const LCID_DL_CON_RES: u8 = 62; // UE Contention Resolution Identity CE (6 bytes)

/// Frame an RRC message for SRB1 into a UL-SCH MAC PDU (Msg5). Stacks:
/// PDCP Data PDU (SRB, 12-bit SN + 4-octet MAC-I, TS 38.323) → RLC AM Data PDU
/// (complete SDU, 12-bit SN, poll set, TS 38.322) → MAC subPDU (LCID 1 =
/// DCCH/SRB1, 8/16-bit L) + padding to `tbs`. Before AS security the MAC-I is 0;
/// once `k_rrcint` is set it is the 128-NIA2 MAC over the PDCP PDU (count = SN,
/// bearer 0 = SRB1, uplink direction).
pub fn srb1_msg5_pdu(rrc: &[u8], rlc_sn: u16, pdcp_sn: u16, tbs: usize, k_rrcint: Option<&[u8; 16]>) -> Vec<u8> {
    // PDCP Data PDU for SRB: [RRRR|SN(4 MSB)][SN(8 LSB)] || data || MAC-I(4).
    let mut pdcp = Vec::with_capacity(rrc.len() + 6);
    pdcp.push(((pdcp_sn >> 8) & 0x0f) as u8);
    pdcp.push((pdcp_sn & 0xff) as u8);
    pdcp.extend_from_slice(rrc);
    let mac_i = match k_rrcint {
        Some(ik) => crate::milenage::nia2_mac(ik, pdcp_sn as u32, 0, 0, &pdcp),
        None => [0, 0, 0, 0],
    };
    pdcp.extend_from_slice(&mac_i);

    // RLC AM Data PDU (12-bit SN): [D/C=1|P=1|SI=00|SN(4 MSB)][SN(8 LSB)] || data.
    let mut rlc = Vec::with_capacity(pdcp.len() + 2);
    rlc.push(0xc0 | ((rlc_sn >> 8) & 0x0f) as u8); // D/C=1, P=1, SI=00
    rlc.push((rlc_sn & 0xff) as u8);
    rlc.extend_from_slice(&pdcp);

    // MAC subPDU: subheader (LCID 1, with L field) + the RLC PDU.
    let mut mac = Vec::with_capacity(tbs);
    if rlc.len() < 256 {
        mac.push(0x01); // R=0, F=0 (8-bit L), LCID=1
        mac.push(rlc.len() as u8);
    } else {
        mac.push(0x41); // R=0, F=1 (16-bit L), LCID=1
        mac.push((rlc.len() >> 8) as u8);
        mac.push((rlc.len() & 0xff) as u8);
    }
    mac.extend_from_slice(&rlc);
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
    mac
}

/// UL-SCH LCID for a Short BSR MAC CE (TS 38.321 Table 6.2.1-2).
pub const LCID_SHORT_BSR: u8 = 61;

/// Build a UL-SCH MAC PDU carrying an RLC AM STATUS PDU (TS 38.322 §6.2.3.2,
/// 12-bit SN) that acknowledges all DL RLC SDUs below `ack_sn` (D/C=0, CPT=0,
/// E1=0 — no NACKs), on SRB1 (LCID 1), padded to `tbs` bytes. Sending these lets
/// the gNB's DL RLC AM window advance so it stops retransmitting and delivers the
/// next SDU (else it loops on the first unacknowledged PDU).
pub fn rlc_status_mac_pdu(ack_sn: u16, tbs: usize) -> Vec<u8> {
    let status = [
        ((ack_sn >> 8) & 0x0f) as u8, // D/C=0, CPT=000, ACK_SN[11:8]
        (ack_sn & 0xff) as u8,        // ACK_SN[7:0]
        0x00,                         // E1=0, padding
    ];
    let mut mac = Vec::with_capacity(tbs);
    mac.push(0x01); // R/F=0, LCID=1 (DCCH), 8-bit L
    mac.push(status.len() as u8);
    mac.extend_from_slice(&status);
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
    mac
}

/// Build a UL-SCH MAC PDU carrying a Short BSR MAC CE (TS 38.321 §6.1.3.1) that
/// reports `buf_bytes` pending on logical-channel group 0, padded to `tbs`
/// bytes. Sent in a minimal grant to solicit a larger one when the queued SRB1
/// PDU doesn't fit. The 5-bit buffer-size index is the smallest level whose
/// upper bound ≥ `buf_bytes` (Table 6.1.3.1-1).
pub fn mac_short_bsr(buf_bytes: usize, tbs: usize) -> Vec<u8> {
    const LEVELS: [usize; 32] = [
        0, 10, 14, 20, 28, 38, 53, 74, 102, 142, 198, 276, 384, 528, 726, 1010,
        1420, 1983, 2765, 3839, 5446, 7594, 10570, 14099, 19468, 26971, 38326,
        49759, 65726, 86677, 114069, usize::MAX,
    ];
    let idx = LEVELS.iter().position(|&l| l >= buf_bytes).unwrap_or(31) as u8;
    let mut mac = Vec::with_capacity(tbs);
    mac.push(LCID_SHORT_BSR); // R/R/LCID (fixed-size CE, no L field)
    mac.push(idx & 0x1f); // LCG-ID (bits 7..5) = 0 | buffer-size index (bits 4..0)
    if mac.len() < tbs {
        mac.push(LCID_PADDING);
        mac.resize(tbs, 0);
    }
    mac
}

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

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// A real gNB RRCReconfiguration (reassembled) carrying a PDU Session
    /// Establishment Accept: the UE IP must be extracted despite the NAS being
    /// UPER bit-packed inside the message. This capture assigned 10.255.0.3.
    #[test]
    fn extract_ue_ip_from_reconfig() {
        let rrc = hx("068a80409a05e00205e3f05d00bac01584888bd76380832f00058e03f441a0b200811801001c5f80b6fbd20e00df801a0040188b8140708440024040018c4c40407fc041828000c28000ca414042bfc000c881004000001e4001804810404041dec009e02008440080000420418202020220c1820201010003410202020200034102020101000400815e0942421a5b9d195c9b995d048140");
        assert_eq!(reconfig_pdu_session_ip(&rrc), Some([10, 255, 0, 3]));
    }

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
