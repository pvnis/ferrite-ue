//! 5GS session management (5GSM) message codec, TS 24.501 §8.3 / §9.11.4.
//!
//! A 5GSM message is carried in the payload container of UL/DL NAS TRANSPORT.
//! Header (TS 24.501 §9.1.1): `EPD 0x2e | PDU session ID | PTI | message type`.

use crate::ie::{IeFmt, NasError, OptIes, Reader, Writer};
use crate::mm::{decode_dnn, encode_dnn, GprsTimer3, Snssai, EPD_5GSM};

/// 5GSM message types (TS 24.501 Table 9.7.2).
pub mod msg_type {
    pub const PDU_SESSION_ESTABLISHMENT_REQUEST: u8 = 0xc1;
    pub const PDU_SESSION_ESTABLISHMENT_ACCEPT: u8 = 0xc2;
    pub const PDU_SESSION_ESTABLISHMENT_REJECT: u8 = 0xc3;
    pub const PDU_SESSION_AUTHENTICATION_COMMAND: u8 = 0xc5;
    pub const PDU_SESSION_AUTHENTICATION_COMPLETE: u8 = 0xc6;
    pub const PDU_SESSION_AUTHENTICATION_RESULT: u8 = 0xc7;
    pub const PDU_SESSION_MODIFICATION_REQUEST: u8 = 0xc9;
    pub const PDU_SESSION_MODIFICATION_REJECT: u8 = 0xca;
    pub const PDU_SESSION_MODIFICATION_COMMAND: u8 = 0xcb;
    pub const PDU_SESSION_MODIFICATION_COMPLETE: u8 = 0xcc;
    pub const PDU_SESSION_MODIFICATION_COMMAND_REJECT: u8 = 0xcd;
    pub const PDU_SESSION_RELEASE_REQUEST: u8 = 0xd1;
    pub const PDU_SESSION_RELEASE_REJECT: u8 = 0xd2;
    pub const PDU_SESSION_RELEASE_COMMAND: u8 = 0xd3;
    pub const PDU_SESSION_RELEASE_COMPLETE: u8 = 0xd4;
    pub const SM_STATUS: u8 = 0xd6;
}

/// 5GSM cause values (TS 24.501 §9.11.4.2) used here.
pub mod cause {
    pub const REGULAR_DEACTIVATION: u8 = 36;
    pub const INSUFFICIENT_RESOURCES: u8 = 26;
    pub const MISSING_OR_UNKNOWN_DNN: u8 = 27;
    pub const UNKNOWN_PDU_SESSION_TYPE: u8 = 28;
    pub const PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED: u8 = 50;
    pub const PDU_SESSION_TYPE_IPV6_ONLY_ALLOWED: u8 = 51;
    pub const INVALID_PTI: u8 = 81;
    pub const MESSAGE_TYPE_NON_EXISTENT: u8 = 97;
    pub const MESSAGE_TYPE_NOT_COMPATIBLE: u8 = 98;
    pub const PROTOCOL_ERROR_UNSPECIFIED: u8 = 111;
}

/// PDU session type (TS 24.501 §9.11.4.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduSessionType {
    Ipv4 = 1,
    Ipv6 = 2,
    Ipv4v6 = 3,
    Unstructured = 4,
    Ethernet = 5,
}

impl PduSessionType {
    /// From the 3-bit value.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v & 0x7 {
            1 => Self::Ipv4,
            2 => Self::Ipv6,
            3 => Self::Ipv4v6,
            4 => Self::Unstructured,
            5 => Self::Ethernet,
            _ => return None,
        })
    }
}

/// 5GSM header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmHeader {
    pub psi: u8,
    pub pti: u8,
    pub msg_type: u8,
}

/// Read the 5GSM header; the reader is positioned on the body.
pub fn read_sm_header(pdu: &[u8]) -> Result<(SmHeader, Reader<'_>), NasError> {
    let mut rd = Reader::new(pdu);
    if rd.u8("epd")? != EPD_5GSM {
        return Err(NasError::BadHeader);
    }
    let psi = rd.u8("pdu session id")?;
    let pti = rd.u8("pti")?;
    let msg_type = rd.u8("message type")?;
    Ok((SmHeader { psi, pti, msg_type }, rd))
}

fn sm_header(psi: u8, pti: u8, msg_type: u8) -> Writer {
    Writer::from_vec(vec![EPD_5GSM, psi, pti, msg_type])
}

/// PDU address (TS 24.501 §9.11.4.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PduAddress {
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 interface identifier (the low 64 bits of the UE's address).
    pub ipv6_iid: Option<[u8; 8]>,
    /// SMF's IPv6 link-local address (SI6LLA).
    pub smf_ipv6_link_local: Option<[u8; 16]>,
}

impl PduAddress {
    /// IE value.
    pub fn encode(&self) -> Vec<u8> {
        let t = match (self.ipv4, self.ipv6_iid) {
            (Some(_), Some(_)) => 3,
            (None, Some(_)) => 2,
            _ => 1,
        };
        let mut v = vec![t | ((self.smf_ipv6_link_local.is_some() as u8) << 3)];
        if let Some(i6) = self.ipv6_iid {
            v.extend_from_slice(&i6);
        }
        if let Some(i4) = self.ipv4 {
            v.extend_from_slice(&i4);
        }
        if let Some(ll) = self.smf_ipv6_link_local {
            v.extend_from_slice(&ll);
        }
        v
    }

    /// Decode an IE value.
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        let mut rd = Reader::new(v);
        let t = rd.u8("pdu address type")?;
        let mut a = PduAddress::default();
        match t & 0x7 {
            1 => a.ipv4 = Some(rd.array::<4>("ipv4")?),
            2 => a.ipv6_iid = Some(rd.array::<8>("ipv6 iid")?),
            3 => {
                a.ipv6_iid = Some(rd.array::<8>("ipv6 iid")?);
                a.ipv4 = Some(rd.array::<4>("ipv4")?);
            }
            _ => return Err(NasError::InvalidValue("pdu address type")),
        }
        if t & 0x08 != 0 {
            a.smf_ipv6_link_local = Some(rd.array::<16>("smf link local")?);
        }
        Ok(a)
    }
}

/// Session-AMBR (TS 24.501 §9.11.4.14): unit + 16-bit value per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionAmbr {
    pub dl_unit: u8,
    pub dl: u16,
    pub ul_unit: u8,
    pub ul: u16,
}

impl SessionAmbr {
    /// IE value (6 octets).
    pub fn encode(&self) -> [u8; 6] {
        let d = self.dl.to_be_bytes();
        let u = self.ul.to_be_bytes();
        [self.dl_unit, d[0], d[1], self.ul_unit, u[0], u[1]]
    }

    /// Decode an IE value.
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        if v.len() < 6 {
            return Err(NasError::Truncated("session ambr"));
        }
        Ok(SessionAmbr {
            dl_unit: v[0],
            dl: u16::from_be_bytes([v[1], v[2]]),
            ul_unit: v[3],
            ul: u16::from_be_bytes([v[4], v[5]]),
        })
    }

    /// Convert a unit/value pair to kbit/s (unit 1 = 1 kbps, 2 = 4 kbps ...
    /// per Table 9.11.4.14.1; unit 0 = not used).
    pub fn to_kbps(unit: u8, value: u16) -> u64 {
        let v = value as u64;
        match unit {
            0x00 => 0,
            0x01..=0x05 => v * 4u64.pow((unit - 1) as u32),
            0x06..=0x0a => v * 1_000 * 4u64.pow((unit - 6) as u32),
            0x0b..=0x0f => v * 1_000_000 * 4u64.pow((unit - 11) as u32),
            0x10..=0x14 => v * 1_000_000_000 * 4u64.pow((unit - 16) as u32),
            _ => v * 1_000_000_000_000 * 4u64.pow((unit.saturating_sub(21)) as u32),
        }
    }
}

/// One packet filter of a QoS rule (TS 24.501 §9.11.4.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFilter {
    /// Direction: 1 = DL, 2 = UL, 3 = bidirectional.
    pub direction: u8,
    pub id: u8,
    /// Packet filter contents (component list), raw.
    pub contents: Vec<u8>,
}

/// A QoS rule (TS 24.501 §9.11.4.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosRule {
    pub id: u8,
    /// Rule operation code (1 = create new, 2 = delete, 3 = modify+add, ...).
    pub operation: u8,
    /// Default QoS rule.
    pub dqr: bool,
    pub packet_filters: Vec<PacketFilter>,
    /// Absent for "delete existing QoS rule".
    pub precedence: Option<u8>,
    pub qfi: Option<u8>,
    pub segregation: bool,
}

impl QosRule {
    /// The default rule used by test cores: match-all bidirectional filter,
    /// precedence 255, the given QFI.
    pub fn default_match_all(qfi: u8) -> Self {
        QosRule {
            id: 1,
            operation: 1,
            dqr: true,
            packet_filters: vec![PacketFilter {
                direction: 3,
                id: 1,
                contents: vec![0x01],
            }],
            precedence: Some(255),
            qfi: Some(qfi),
            segregation: false,
        }
    }

    fn encode_into(&self, w: &mut Writer) {
        let mut body = Writer::new();
        let n = self.packet_filters.len().min(15) as u8;
        body.u8(((self.operation & 0x7) << 5) | ((self.dqr as u8) << 4) | n);
        for pf in self.packet_filters.iter().take(15) {
            body.u8(((pf.direction & 0x3) << 4) | (pf.id & 0xf));
            if self.operation != 2 && self.operation != 5 {
                body.lv(&pf.contents);
            }
        }
        if let Some(p) = self.precedence {
            body.u8(p);
            body.u8(((self.segregation as u8) << 6) | (self.qfi.unwrap_or(0) & 0x3f));
        }
        w.u8(self.id);
        w.u16(body.as_slice().len() as u16);
        w.bytes(body.as_slice());
    }
}

/// Encode a QoS rules IE value.
pub fn encode_qos_rules(rules: &[QosRule]) -> Vec<u8> {
    let mut w = Writer::new();
    for r in rules {
        r.encode_into(&mut w);
    }
    w.into_vec()
}

/// Decode a QoS rules IE value. Each rule is length-delimited, so a rule
/// whose body is shorter than expected is kept with what was parsed.
pub fn decode_qos_rules(v: &[u8]) -> Result<Vec<QosRule>, NasError> {
    let mut rd = Reader::new(v);
    let mut out = Vec::new();
    while !rd.is_empty() {
        let id = rd.u8("qos rule id")?;
        let body = rd.lv_e("qos rule")?;
        let mut b = Reader::new(body);
        let h = b.u8("qos rule header")?;
        let operation = h >> 5;
        let dqr = h & 0x10 != 0;
        let n = (h & 0xf) as usize;
        let mut packet_filters = Vec::with_capacity(n);
        for _ in 0..n {
            let f = b.u8("packet filter")?;
            let contents = if operation == 2 || operation == 5 {
                Vec::new()
            } else {
                b.lv("packet filter contents")?.to_vec()
            };
            packet_filters.push(PacketFilter {
                direction: (f >> 4) & 0x3,
                id: f & 0xf,
                contents,
            });
        }
        let (precedence, qfi, segregation) = if b.remaining() >= 2 {
            let p = b.u8("precedence")?;
            let q = b.u8("qfi")?;
            (Some(p), Some(q & 0x3f), q & 0x40 != 0)
        } else {
            (None, None, false)
        };
        out.push(QosRule {
            id,
            operation,
            dqr,
            packet_filters,
            precedence,
            qfi,
            segregation,
        });
    }
    Ok(out)
}

/// A QoS flow description (TS 24.501 §9.11.4.12), parameters kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowDescription {
    pub qfi: u8,
    pub operation: u8,
    /// (parameter identifier, contents) pairs; 1 = 5QI, 2 = GFBR UL, ...
    pub parameters: Vec<(u8, Vec<u8>)>,
}

impl QosFlowDescription {
    /// The 5QI parameter, if present.
    pub fn five_qi(&self) -> Option<u8> {
        self.parameters
            .iter()
            .find(|(id, _)| *id == 1)
            .and_then(|(_, v)| v.first().copied())
    }
}

/// Encode a QoS flow descriptions IE value.
pub fn encode_qos_flow_descriptions(list: &[QosFlowDescription]) -> Vec<u8> {
    let mut w = Writer::new();
    for d in list {
        w.u8(d.qfi & 0x3f);
        w.u8((d.operation & 0x7) << 5);
        w.u8(0x40 | (d.parameters.len().min(63) as u8)); // E bit = 1: parameters list follows
        for (id, v) in d.parameters.iter().take(63) {
            w.u8(*id);
            w.lv(v);
        }
    }
    w.into_vec()
}

/// Decode a QoS flow descriptions IE value.
pub fn decode_qos_flow_descriptions(v: &[u8]) -> Result<Vec<QosFlowDescription>, NasError> {
    let mut rd = Reader::new(v);
    let mut out = Vec::new();
    while !rd.is_empty() {
        let qfi = rd.u8("qfi")? & 0x3f;
        let operation = rd.u8("qos flow op")? >> 5;
        let e = rd.u8("qos flow params")?;
        let n = if e & 0x40 != 0 {
            (e & 0x3f) as usize
        } else {
            0
        };
        let mut parameters = Vec::with_capacity(n);
        for _ in 0..n {
            let id = rd.u8("param id")?;
            parameters.push((id, rd.lv("param")?.to_vec()));
        }
        out.push(QosFlowDescription {
            qfi,
            operation,
            parameters,
        });
    }
    Ok(out)
}

/// PDU SESSION ESTABLISHMENT REQUEST (TS 24.501 §8.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentRequest {
    pub psi: u8,
    pub pti: u8,
    /// Integrity protection maximum data rate (UL, DL): 0xff = full rate.
    pub integrity_max_rate: (u8, u8),
    /// PDU session type (type 1, IEI 0x9-).
    pub pdu_session_type: Option<PduSessionType>,
    /// SSC mode (type 1, IEI 0xA-).
    pub ssc_mode: Option<u8>,
    /// 5GSM capability (IEI 0x28).
    pub sm_capability: Option<Vec<u8>>,
    /// Maximum number of supported packet filters (IEI 0x55, 2 octets).
    pub max_packet_filters: Option<u16>,
    /// Always-on PDU session requested (type 1, IEI 0xB-).
    pub always_on_requested: Option<bool>,
    /// Extended protocol configuration options (IEI 0x7B).
    pub epco: Option<Vec<u8>>,
}

impl PduSessionEstablishmentRequest {
    /// The proven minimal request: IPv4, SSC mode 1, full integrity rate.
    pub fn ipv4(psi: u8, pti: u8) -> Self {
        Self::new(psi, pti, PduSessionType::Ipv4, 1)
    }

    /// Minimal request for a session type and SSC mode.
    pub fn new(psi: u8, pti: u8, t: PduSessionType, ssc_mode: u8) -> Self {
        PduSessionEstablishmentRequest {
            psi,
            pti,
            integrity_max_rate: (0xff, 0xff),
            pdu_session_type: Some(t),
            ssc_mode: Some(ssc_mode),
            sm_capability: None,
            max_packet_filters: None,
            always_on_requested: None,
            epco: None,
        }
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(
            self.psi,
            self.pti,
            msg_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
        );
        w.u8(self.integrity_max_rate.0)
            .u8(self.integrity_max_rate.1);
        if let Some(t) = self.pdu_session_type {
            w.tv1(0x90, t as u8);
        }
        if let Some(s) = self.ssc_mode {
            w.tv1(0xa0, s);
        }
        if let Some(c) = &self.sm_capability {
            w.tlv(0x28, c);
        }
        if let Some(n) = self.max_packet_filters {
            w.tv(0x55, &n.to_be_bytes());
        }
        if let Some(a) = self.always_on_requested {
            w.tv1(0xb0, a as u8);
        }
        if let Some(e) = &self.epco {
            w.tlv_e(0x7b, e);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_ESTABLISHMENT_REQUEST {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let ul = rd.u8("integrity max rate")?;
        let dl = rd.u8("integrity max rate")?;
        let mut m = PduSessionEstablishmentRequest {
            psi: h.psi,
            pti: h.pti,
            integrity_max_rate: (ul, dl),
            pdu_session_type: None,
            ssc_mode: None,
            sm_capability: None,
            max_packet_filters: None,
            always_on_requested: None,
            epco: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x55, IeFmt::Tv(2))]) {
            let ie = ie?;
            match ie.iei {
                0x90 => m.pdu_session_type = PduSessionType::from_u8(ie.nibble),
                0xa0 => m.ssc_mode = Some(ie.nibble & 0x7),
                0x28 => m.sm_capability = Some(ie.value.to_vec()),
                0x55 => m.max_packet_filters = ie.value.try_into().ok().map(u16::from_be_bytes),
                0xb0 => m.always_on_requested = Some(ie.nibble & 1 != 0),
                0x7b => m.epco = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// PDU SESSION ESTABLISHMENT ACCEPT (TS 24.501 §8.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentAccept {
    pub psi: u8,
    pub pti: u8,
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: u8,
    pub qos_rules: Vec<QosRule>,
    pub session_ambr: SessionAmbr,
    /// 5GSM cause (IEI 0x59), e.g. #50/#51 when only one IP version was granted.
    pub cause: Option<u8>,
    pub pdu_address: Option<PduAddress>,
    /// RQ timer value (IEI 0x56).
    pub rq_timer: Option<u8>,
    pub snssai: Option<Snssai>,
    /// Always-on PDU session indication (type 1, IEI 0x8-).
    pub always_on: Option<bool>,
    pub qos_flow_descriptions: Vec<QosFlowDescription>,
    pub epco: Option<Vec<u8>>,
    pub dnn: Option<String>,
}

impl PduSessionEstablishmentAccept {
    /// The QFI of the default QoS rule (DQR), if any.
    pub fn default_qfi(&self) -> Option<u8> {
        self.qos_rules.iter().find(|r| r.dqr).and_then(|r| r.qfi)
    }

    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(
            self.psi,
            self.pti,
            msg_type::PDU_SESSION_ESTABLISHMENT_ACCEPT,
        );
        w.u8(((self.ssc_mode & 0x7) << 4) | (self.pdu_session_type as u8));
        w.lv_e(&encode_qos_rules(&self.qos_rules));
        w.lv(&self.session_ambr.encode());
        if let Some(c) = self.cause {
            w.tv(0x59, &[c]);
        }
        if let Some(a) = &self.pdu_address {
            w.tlv(0x29, &a.encode());
        }
        if let Some(t) = self.rq_timer {
            w.tv(0x56, &[t]);
        }
        if let Some(s) = &self.snssai {
            w.tlv(0x22, &s.encode());
        }
        if let Some(a) = self.always_on {
            w.tv1(0x80, a as u8);
        }
        if !self.qos_flow_descriptions.is_empty() {
            w.tlv_e(
                0x79,
                &encode_qos_flow_descriptions(&self.qos_flow_descriptions),
            );
        }
        if let Some(e) = &self.epco {
            w.tlv_e(0x7b, e);
        }
        if let Some(d) = &self.dnn {
            w.tlv(0x25, &encode_dnn(d));
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_ESTABLISHMENT_ACCEPT {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let b = rd.u8("selected pdu session type")?;
        let pdu_session_type =
            PduSessionType::from_u8(b & 0x7).ok_or(NasError::InvalidValue("pdu session type"))?;
        let qos_rules = decode_qos_rules(rd.lv_e("authorized qos rules")?)?;
        let session_ambr = SessionAmbr::decode(rd.lv("session ambr")?)?;
        let mut m = PduSessionEstablishmentAccept {
            psi: h.psi,
            pti: h.pti,
            pdu_session_type,
            ssc_mode: (b >> 4) & 0x7,
            qos_rules,
            session_ambr,
            cause: None,
            pdu_address: None,
            rq_timer: None,
            snssai: None,
            always_on: None,
            qos_flow_descriptions: Vec::new(),
            epco: None,
            dnn: None,
        };
        const KNOWN: &[(u8, IeFmt)] = &[(0x59, IeFmt::Tv(1)), (0x56, IeFmt::Tv(1))];
        for ie in OptIes::new(rd.rest(), KNOWN) {
            let ie = ie?;
            match ie.iei {
                0x59 => m.cause = ie.value.first().copied(),
                0x29 => m.pdu_address = Some(PduAddress::decode(ie.value)?),
                0x56 => m.rq_timer = ie.value.first().copied(),
                0x22 => m.snssai = Some(Snssai::decode(ie.value)?),
                0x80 => m.always_on = Some(ie.nibble & 1 != 0),
                0x79 => m.qos_flow_descriptions = decode_qos_flow_descriptions(ie.value)?,
                0x7b => m.epco = Some(ie.value.to_vec()),
                0x25 => m.dnn = Some(decode_dnn(ie.value)?),
                _ => log::debug!(
                    "PduSessionEstablishmentAccept: skipping IEI {:#04x}",
                    ie.iei
                ),
            }
        }
        Ok(m)
    }
}

/// PDU SESSION ESTABLISHMENT REJECT (TS 24.501 §8.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentReject {
    pub psi: u8,
    pub pti: u8,
    pub cause: u8,
    pub back_off_timer: Option<GprsTimer3>,
    /// Allowed SSC mode (type 1, IEI 0xF-).
    pub allowed_ssc_mode: Option<u8>,
    pub epco: Option<Vec<u8>>,
}

impl PduSessionEstablishmentReject {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(
            self.psi,
            self.pti,
            msg_type::PDU_SESSION_ESTABLISHMENT_REJECT,
        );
        w.u8(self.cause);
        if let Some(t) = self.back_off_timer {
            w.tlv(0x37, &[t.to_octet()]);
        }
        if let Some(s) = self.allowed_ssc_mode {
            w.tv1(0xf0, s);
        }
        if let Some(e) = &self.epco {
            w.tlv_e(0x7b, e);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_ESTABLISHMENT_REJECT {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let mut m = PduSessionEstablishmentReject {
            psi: h.psi,
            pti: h.pti,
            cause: rd.u8("5gsm cause")?,
            back_off_timer: None,
            allowed_ssc_mode: None,
            epco: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x37 => m.back_off_timer = ie.value.first().map(|&b| GprsTimer3::from_octet(b)),
                0xf0 => m.allowed_ssc_mode = Some(ie.nibble),
                0x7b => m.epco = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// PDU SESSION RELEASE REQUEST (TS 24.501 §8.3.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseRequest {
    pub psi: u8,
    pub pti: u8,
    /// 5GSM cause (IEI 0x59).
    pub cause: Option<u8>,
}

impl PduSessionReleaseRequest {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(self.psi, self.pti, msg_type::PDU_SESSION_RELEASE_REQUEST);
        if let Some(c) = self.cause {
            w.tv(0x59, &[c]);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_RELEASE_REQUEST {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let mut m = PduSessionReleaseRequest {
            psi: h.psi,
            pti: h.pti,
            cause: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x59, IeFmt::Tv(1))]) {
            let ie = ie?;
            if ie.iei == 0x59 {
                m.cause = ie.value.first().copied();
            }
        }
        Ok(m)
    }
}

/// PDU SESSION RELEASE REJECT (TS 24.501 §8.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseReject {
    pub psi: u8,
    pub pti: u8,
    pub cause: u8,
}

impl PduSessionReleaseReject {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(self.psi, self.pti, msg_type::PDU_SESSION_RELEASE_REJECT);
        w.u8(self.cause);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_RELEASE_REJECT {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        Ok(PduSessionReleaseReject {
            psi: h.psi,
            pti: h.pti,
            cause: rd.u8("5gsm cause")?,
        })
    }
}

/// PDU SESSION RELEASE COMMAND (TS 24.501 §8.3.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseCommand {
    pub psi: u8,
    pub pti: u8,
    pub cause: u8,
    pub back_off_timer: Option<GprsTimer3>,
    /// Access type (type 1, IEI 0xD-).
    pub access_type: Option<u8>,
    pub epco: Option<Vec<u8>>,
}

impl PduSessionReleaseCommand {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(self.psi, self.pti, msg_type::PDU_SESSION_RELEASE_COMMAND);
        w.u8(self.cause);
        if let Some(t) = self.back_off_timer {
            w.tlv(0x37, &[t.to_octet()]);
        }
        if let Some(a) = self.access_type {
            w.tv1(0xd0, a);
        }
        if let Some(e) = &self.epco {
            w.tlv_e(0x7b, e);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_RELEASE_COMMAND {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let mut m = PduSessionReleaseCommand {
            psi: h.psi,
            pti: h.pti,
            cause: rd.u8("5gsm cause")?,
            back_off_timer: None,
            access_type: None,
            epco: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x37 => m.back_off_timer = ie.value.first().map(|&b| GprsTimer3::from_octet(b)),
                0xd0 => m.access_type = Some(ie.nibble & 0x3),
                0x7b => m.epco = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// PDU SESSION RELEASE COMPLETE (TS 24.501 §8.3.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseComplete {
    pub psi: u8,
    pub pti: u8,
    pub cause: Option<u8>,
}

impl PduSessionReleaseComplete {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(self.psi, self.pti, msg_type::PDU_SESSION_RELEASE_COMPLETE);
        if let Some(c) = self.cause {
            w.tv(0x59, &[c]);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::PDU_SESSION_RELEASE_COMPLETE {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        let mut m = PduSessionReleaseComplete {
            psi: h.psi,
            pti: h.pti,
            cause: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x59, IeFmt::Tv(1))]) {
            let ie = ie?;
            if ie.iei == 0x59 {
                m.cause = ie.value.first().copied();
            }
        }
        Ok(m)
    }
}

/// 5GSM STATUS (TS 24.501 §8.3.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmStatus {
    pub psi: u8,
    pub pti: u8,
    pub cause: u8,
}

impl SmStatus {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = sm_header(self.psi, self.pti, msg_type::SM_STATUS);
        w.u8(self.cause);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(pdu: &[u8]) -> Result<Self, NasError> {
        let (h, mut rd) = read_sm_header(pdu)?;
        if h.msg_type != msg_type::SM_STATUS {
            return Err(NasError::UnexpectedMessage(h.msg_type));
        }
        Ok(SmStatus {
            psi: h.psi,
            pti: h.pti,
            cause: rd.u8("5gsm cause")?,
        })
    }
}

/// Any decoded 5GSM message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmMessage {
    EstablishmentRequest(PduSessionEstablishmentRequest),
    EstablishmentAccept(PduSessionEstablishmentAccept),
    EstablishmentReject(PduSessionEstablishmentReject),
    ReleaseRequest(PduSessionReleaseRequest),
    ReleaseReject(PduSessionReleaseReject),
    ReleaseCommand(PduSessionReleaseCommand),
    ReleaseComplete(PduSessionReleaseComplete),
    Status(SmStatus),
    /// PDU SESSION MODIFICATION COMMAND (TS 24.501 §8.3.9): the header only;
    /// the authorized QoS rules / flow descriptions it carries are accepted
    /// unread (the default QoS rule stays in force) and answered with a
    /// PDU SESSION MODIFICATION COMPLETE.
    ModificationCommand(SmHeader),
    /// A 5GSM message this decoder does not implement (header only).
    Unknown(SmHeader),
}

/// PDU SESSION MODIFICATION COMPLETE (TS 24.501 §8.3.10), no optional IEs.
pub fn modification_complete(psi: u8, pti: u8) -> Vec<u8> {
    sm_header(psi, pti, msg_type::PDU_SESSION_MODIFICATION_COMPLETE).into_vec()
}

/// Decode any 5GSM message by its type.
pub fn decode_sm(pdu: &[u8]) -> Result<SmMessage, NasError> {
    use msg_type::*;
    let (h, _) = read_sm_header(pdu)?;
    Ok(match h.msg_type {
        PDU_SESSION_ESTABLISHMENT_REQUEST => {
            SmMessage::EstablishmentRequest(PduSessionEstablishmentRequest::decode(pdu)?)
        }
        PDU_SESSION_ESTABLISHMENT_ACCEPT => {
            SmMessage::EstablishmentAccept(PduSessionEstablishmentAccept::decode(pdu)?)
        }
        PDU_SESSION_ESTABLISHMENT_REJECT => {
            SmMessage::EstablishmentReject(PduSessionEstablishmentReject::decode(pdu)?)
        }
        PDU_SESSION_RELEASE_REQUEST => {
            SmMessage::ReleaseRequest(PduSessionReleaseRequest::decode(pdu)?)
        }
        PDU_SESSION_RELEASE_REJECT => {
            SmMessage::ReleaseReject(PduSessionReleaseReject::decode(pdu)?)
        }
        PDU_SESSION_RELEASE_COMMAND => {
            SmMessage::ReleaseCommand(PduSessionReleaseCommand::decode(pdu)?)
        }
        PDU_SESSION_RELEASE_COMPLETE => {
            SmMessage::ReleaseComplete(PduSessionReleaseComplete::decode(pdu)?)
        }
        SM_STATUS => SmMessage::Status(SmStatus::decode(pdu)?),
        PDU_SESSION_MODIFICATION_COMMAND => SmMessage::ModificationCommand(h),
        _ => SmMessage::Unknown(h),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn establishment_request_matches_legacy_bytes() {
        let r = PduSessionEstablishmentRequest::ipv4(5, 1);
        assert_eq!(
            r.encode(),
            crate::msgs::pdu_session_establishment_request(5, 1)
        );
        assert_eq!(r.encode(), hx("2e0501c1ffff91a1"));
        assert_eq!(
            PduSessionEstablishmentRequest::decode(&r.encode()).unwrap(),
            r
        );
        let mut full = PduSessionEstablishmentRequest::new(1, 2, PduSessionType::Ipv4v6, 2);
        full.sm_capability = Some(vec![0x01]);
        full.max_packet_filters = Some(16);
        full.always_on_requested = Some(true);
        full.epco = Some(vec![0x80, 0x00, 0x0d, 0x00]);
        assert_eq!(
            PduSessionEstablishmentRequest::decode(&full.encode()).unwrap(),
            full
        );
    }

    fn accept() -> PduSessionEstablishmentAccept {
        PduSessionEstablishmentAccept {
            psi: 5,
            pti: 1,
            pdu_session_type: PduSessionType::Ipv4,
            ssc_mode: 1,
            qos_rules: vec![QosRule::default_match_all(1)],
            session_ambr: SessionAmbr {
                dl_unit: 6,
                dl: 1000,
                ul_unit: 6,
                ul: 1000,
            },
            cause: None,
            pdu_address: Some(PduAddress {
                ipv4: Some([10, 45, 0, 2]),
                ..Default::default()
            }),
            rq_timer: None,
            snssai: Some(Snssai { sst: 1, sd: None }),
            always_on: Some(false),
            qos_flow_descriptions: vec![QosFlowDescription {
                qfi: 1,
                operation: 1,
                parameters: vec![(1, vec![9])],
            }],
            epco: Some(vec![0x80, 0x00, 0x0d, 0x04, 8, 8, 8, 8]),
            dnn: Some("internet".into()),
        }
    }

    #[test]
    fn establishment_accept_roundtrip() {
        let a = accept();
        let e = a.encode();
        let d = PduSessionEstablishmentAccept::decode(&e).unwrap();
        assert_eq!(d, a);
        assert_eq!(d.default_qfi(), Some(1));
        assert_eq!(d.qos_flow_descriptions[0].five_qi(), Some(9));
        assert_eq!(SessionAmbr::to_kbps(6, 1000), 1_000_000);
        // Unknown IEs appended (TLV 0x18 serving PLMN rate control, type1 0xc1, TLV-E 0x75).
        let mut e2 = e.clone();
        e2.extend_from_slice(&[0x18, 0x02, 0x00, 0x10, 0xc1, 0x75, 0x00, 0x01, 0x00]);
        assert_eq!(PduSessionEstablishmentAccept::decode(&e2).unwrap(), a);
        // Truncated QoS rules → error, not panic.
        assert!(PduSessionEstablishmentAccept::decode(&e[..8]).is_err());
        for n in 0..e.len() {
            let _ = PduSessionEstablishmentAccept::decode(&e[..n]);
        }
    }

    #[test]
    fn pdu_address_variants() {
        let v6 = PduAddress {
            ipv4: None,
            ipv6_iid: Some([1; 8]),
            smf_ipv6_link_local: None,
        };
        assert_eq!(PduAddress::decode(&v6.encode()).unwrap(), v6);
        let both = PduAddress {
            ipv4: Some([1, 2, 3, 4]),
            ipv6_iid: Some([2; 8]),
            smf_ipv6_link_local: Some([3; 16]),
        };
        let e = both.encode();
        assert_eq!(e[0], 0x0b);
        assert_eq!(PduAddress::decode(&e).unwrap(), both);
        assert!(PduAddress::decode(&[0x01, 1, 2]).is_err());
        assert!(PduAddress::decode(&[0x07]).is_err());
    }

    #[test]
    fn qos_rules_delete_and_multi() {
        let rules = vec![
            QosRule::default_match_all(1),
            QosRule {
                id: 2,
                operation: 2,
                dqr: false,
                packet_filters: vec![],
                precedence: None,
                qfi: None,
                segregation: false,
            },
            QosRule {
                id: 3,
                operation: 1,
                dqr: false,
                packet_filters: vec![
                    PacketFilter {
                        direction: 1,
                        id: 1,
                        contents: vec![0x30, 1],
                    },
                    PacketFilter {
                        direction: 2,
                        id: 2,
                        contents: vec![0x10, 1, 2, 3, 4, 255, 255, 255, 255],
                    },
                ],
                precedence: Some(10),
                qfi: Some(5),
                segregation: true,
            },
        ];
        let e = encode_qos_rules(&rules);
        assert_eq!(decode_qos_rules(&e).unwrap(), rules);
        assert!(decode_qos_rules(&e[..e.len() - 1]).is_err());
    }

    #[test]
    fn reject_release_status_roundtrip() {
        let r = PduSessionEstablishmentReject {
            psi: 5,
            pti: 1,
            cause: cause::MISSING_OR_UNKNOWN_DNN,
            back_off_timer: Some(GprsTimer3 { unit: 3, value: 5 }),
            allowed_ssc_mode: Some(0x7),
            epco: None,
        };
        assert_eq!(
            PduSessionEstablishmentReject::decode(&r.encode()).unwrap(),
            r
        );
        let q = PduSessionReleaseRequest {
            psi: 5,
            pti: 2,
            cause: Some(cause::REGULAR_DEACTIVATION),
        };
        assert_eq!(PduSessionReleaseRequest::decode(&q.encode()).unwrap(), q);
        let c = PduSessionReleaseCommand {
            psi: 5,
            pti: 0,
            cause: cause::REGULAR_DEACTIVATION,
            back_off_timer: None,
            access_type: Some(1),
            epco: None,
        };
        assert_eq!(PduSessionReleaseCommand::decode(&c.encode()).unwrap(), c);
        let k = PduSessionReleaseComplete {
            psi: 5,
            pti: 0,
            cause: None,
        };
        assert_eq!(k.encode(), vec![0x2e, 5, 0, 0xd4]);
        assert_eq!(PduSessionReleaseComplete::decode(&k.encode()).unwrap(), k);
        let j = PduSessionReleaseReject {
            psi: 5,
            pti: 2,
            cause: 43,
        };
        assert_eq!(PduSessionReleaseReject::decode(&j.encode()).unwrap(), j);
        let s = SmStatus {
            psi: 5,
            pti: 0,
            cause: 97,
        };
        assert_eq!(SmStatus::decode(&s.encode()).unwrap(), s);
        assert!(matches!(
            decode_sm(&accept().encode()),
            Ok(SmMessage::EstablishmentAccept(_))
        ));
        assert!(matches!(
            decode_sm(&[0x2e, 1, 2, 0xcb]),
            Ok(SmMessage::ModificationCommand(SmHeader {
                psi: 1,
                pti: 2,
                ..
            }))
        ));
        assert_eq!(modification_complete(1, 2), vec![0x2e, 1, 2, 0xcc]);
        assert!(matches!(
            decode_sm(&[0x2e, 1, 2, 0xc9]),
            Ok(SmMessage::Unknown(_))
        ));
        assert!(decode_sm(&[0x2e, 1]).is_err());
    }
}
