//! 5GS mobility management (5GMM) message codec, TS 24.501 §8.2 / §9.11.3.
//!
//! Uplink messages implement `encode`, downlink messages implement `decode`;
//! most implement both so that the codecs round-trip in tests and so that a
//! test core can be scripted against the UE. Decoders store the IEs they
//! understand and skip the rest ([`crate::ie::OptIes`]); they return an error
//! only on structural truncation.

use crate::ie::{bcd, bcd_digits, bcd_to_string, IeFmt, NasError, OptIe, OptIes, Reader, Writer};

/// Extended protocol discriminator: 5GS mobility management (TS 24.007 §11.2.3.1.1).
pub const EPD_5GMM: u8 = 0x7e;
/// Extended protocol discriminator: 5GS session management.
pub const EPD_5GSM: u8 = 0x2e;

/// 5GMM message types (TS 24.501 Table 9.7.1).
pub mod msg_type {
    pub const REGISTRATION_REQUEST: u8 = 0x41;
    pub const REGISTRATION_ACCEPT: u8 = 0x42;
    pub const REGISTRATION_COMPLETE: u8 = 0x43;
    pub const REGISTRATION_REJECT: u8 = 0x44;
    pub const DEREGISTRATION_REQUEST_UE_ORIG: u8 = 0x45;
    pub const DEREGISTRATION_ACCEPT_UE_ORIG: u8 = 0x46;
    pub const DEREGISTRATION_REQUEST_UE_TERM: u8 = 0x47;
    pub const DEREGISTRATION_ACCEPT_UE_TERM: u8 = 0x48;
    pub const SERVICE_REQUEST: u8 = 0x4c;
    pub const SERVICE_REJECT: u8 = 0x4d;
    pub const SERVICE_ACCEPT: u8 = 0x4e;
    pub const CONFIGURATION_UPDATE_COMMAND: u8 = 0x54;
    pub const CONFIGURATION_UPDATE_COMPLETE: u8 = 0x55;
    pub const AUTHENTICATION_REQUEST: u8 = 0x56;
    pub const AUTHENTICATION_RESPONSE: u8 = 0x57;
    pub const AUTHENTICATION_REJECT: u8 = 0x58;
    pub const AUTHENTICATION_FAILURE: u8 = 0x59;
    pub const AUTHENTICATION_RESULT: u8 = 0x5a;
    pub const IDENTITY_REQUEST: u8 = 0x5b;
    pub const IDENTITY_RESPONSE: u8 = 0x5c;
    pub const SECURITY_MODE_COMMAND: u8 = 0x5d;
    pub const SECURITY_MODE_COMPLETE: u8 = 0x5e;
    pub const SECURITY_MODE_REJECT: u8 = 0x5f;
    pub const MM_STATUS: u8 = 0x64;
    pub const NOTIFICATION: u8 = 0x65;
    pub const NOTIFICATION_RESPONSE: u8 = 0x66;
    pub const UL_NAS_TRANSPORT: u8 = 0x67;
    pub const DL_NAS_TRANSPORT: u8 = 0x68;
}

/// 5GMM cause values (TS 24.501 §9.11.3.2) used by this implementation.
pub mod cause {
    pub const ILLEGAL_UE: u8 = 3;
    pub const PLMN_NOT_ALLOWED: u8 = 11;
    pub const MAC_FAILURE: u8 = 20;
    pub const SYNCH_FAILURE: u8 = 21;
    pub const UE_SECURITY_CAPABILITIES_MISMATCH: u8 = 23;
    pub const SECURITY_MODE_REJECTED_UNSPECIFIED: u8 = 24;
    pub const NON_5G_AUTHENTICATION_UNACCEPTABLE: u8 = 26;
    pub const SEMANTICALLY_INCORRECT: u8 = 95;
    pub const INVALID_MANDATORY_INFORMATION: u8 = 96;
    pub const MESSAGE_TYPE_NON_EXISTENT: u8 = 97;
    pub const MESSAGE_TYPE_NOT_COMPATIBLE: u8 = 98;
    pub const IE_NON_EXISTENT: u8 = 99;
    pub const PROTOCOL_ERROR_UNSPECIFIED: u8 = 111;
}

/// Security header type (TS 24.501 §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityHeaderType {
    /// Plain NAS message, not security protected.
    Plain = 0,
    /// Integrity protected.
    Integrity = 1,
    /// Integrity protected and ciphered.
    IntegrityCiphered = 2,
    /// Integrity protected with new 5G NAS security context (SMC only).
    IntegrityNewContext = 3,
    /// Integrity protected and ciphered with new 5G NAS security context (SM Complete).
    IntegrityCipheredNewContext = 4,
}

impl SecurityHeaderType {
    /// From the low nibble of octet 2.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v & 0x0f {
            0 => Self::Plain,
            1 => Self::Integrity,
            2 => Self::IntegrityCiphered,
            3 => Self::IntegrityNewContext,
            4 => Self::IntegrityCipheredNewContext,
            _ => return None,
        })
    }

    /// True when the message body is ciphered (types 2 and 4).
    pub fn is_ciphered(self) -> bool {
        matches!(
            self,
            Self::IntegrityCiphered | Self::IntegrityCipheredNewContext
        )
    }

    /// True when a new 5G NAS security context is taken into use (types 3 and 4).
    pub fn is_new_context(self) -> bool {
        matches!(
            self,
            Self::IntegrityNewContext | Self::IntegrityCipheredNewContext
        )
    }
}

/// The security protected NAS message header (TS 24.501 §9.1.1 / §9.8):
/// `EPD | SHT | MAC(4) | SEQ` followed by the plain NAS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityHeader {
    pub sht: SecurityHeaderType,
    pub mac: [u8; 4],
    pub seq: u8,
}

/// Split a 5GMM PDU into its optional security header and the plain message
/// that follows. A plain message (SHT 0) is returned with `None`.
pub fn split_security_header(pdu: &[u8]) -> Result<(Option<SecurityHeader>, &[u8]), NasError> {
    let mut rd = Reader::new(pdu);
    if rd.u8("epd")? != EPD_5GMM {
        return Err(NasError::BadHeader);
    }
    let sht = SecurityHeaderType::from_u8(rd.u8("sht")?).ok_or(NasError::BadHeader)?;
    if sht == SecurityHeaderType::Plain {
        return Ok((None, pdu));
    }
    let mac = rd.array::<4>("mac")?;
    let seq = rd.u8("seq")?;
    Ok((Some(SecurityHeader { sht, mac, seq }), rd.rest()))
}

/// Plain 5GMM header: EPD, SHT=0, message type.
pub fn mm_header(msg_type: u8) -> Writer {
    Writer::from_vec(vec![EPD_5GMM, 0x00, msg_type])
}

/// Read a plain 5GMM header and return the message type with a reader
/// positioned on the body.
pub fn read_mm_header(plain: &[u8]) -> Result<(u8, Reader<'_>), NasError> {
    let mut rd = Reader::new(plain);
    if rd.u8("epd")? != EPD_5GMM || rd.u8("sht")? & 0x0f != 0 {
        return Err(NasError::BadHeader);
    }
    let t = rd.u8("message type")?;
    Ok((t, rd))
}

/// The message type of a plain 5GMM message, if the header is well-formed.
pub fn mm_message_type(plain: &[u8]) -> Option<u8> {
    read_mm_header(plain).ok().map(|(t, _)| t)
}

// ---------------------------------------------------------------------------
// Common IEs
// ---------------------------------------------------------------------------

/// PLMN identity (TS 24.008 §10.5.1.3 / TS 24.501 §9.11.3.4): MCC + MNC in
/// three BCD octets, `0xf` filler for a two-digit MNC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plmn {
    pub mcc: u16,
    pub mnc: u16,
    /// Number of MNC digits (2 or 3).
    pub mnc_digits: u8,
}

impl Plmn {
    /// The three BCD octets.
    pub fn encode(&self) -> [u8; 3] {
        let m = self.mcc % 1000;
        let (c1, c2, c3) = ((m / 100) as u8, (m / 10 % 10) as u8, (m % 10) as u8);
        let n = self.mnc % 1000;
        let (n1, n2, n3) = if self.mnc_digits == 3 {
            ((n / 100) as u8, (n / 10 % 10) as u8, (n % 10) as u8)
        } else {
            (((n / 10) % 10) as u8, (n % 10) as u8, 0xf)
        };
        [bcd(c1, c2), bcd(c3, n3), bcd(n1, n2)]
    }

    /// Decode three BCD octets.
    pub fn decode(b: &[u8]) -> Result<Self, NasError> {
        if b.len() < 3 {
            return Err(NasError::Truncated("plmn"));
        }
        let d = |x: u8| (x.min(9)) as u16;
        let mcc = d(b[0] & 0xf) * 100 + d(b[0] >> 4) * 10 + d(b[1] & 0xf);
        let n3 = b[1] >> 4;
        let (mnc, mnc_digits) = if n3 == 0xf {
            (d(b[2] & 0xf) * 10 + d(b[2] >> 4), 2)
        } else {
            (d(b[2] & 0xf) * 100 + d(b[2] >> 4) * 10 + d(n3), 3)
        };
        Ok(Plmn {
            mcc,
            mnc,
            mnc_digits,
        })
    }

    /// Serving network name for 5G-AKA (TS 24.501 §9.12.1):
    /// `5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org` with a 3-digit zero-padded MNC.
    pub fn serving_network_name(&self) -> String {
        format!("5G:mnc{:03}.mcc{:03}.3gppnetwork.org", self.mnc, self.mcc)
    }
}

/// 5G-GUTI (TS 24.501 §9.11.3.4, type of identity 010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guti {
    pub plmn: Plmn,
    pub amf_region_id: u8,
    /// 10-bit AMF set ID.
    pub amf_set_id: u16,
    /// 6-bit AMF pointer.
    pub amf_pointer: u8,
    pub tmsi: u32,
}

impl Guti {
    /// The 5G-S-TMSI: AMF set ID (10 bits) | AMF pointer (6 bits) | 5G-TMSI.
    pub fn s_tmsi(&self) -> [u8; 6] {
        let sp = ((self.amf_set_id & 0x3ff) << 6) | (self.amf_pointer as u16 & 0x3f);
        let t = self.tmsi.to_be_bytes();
        [(sp >> 8) as u8, sp as u8, t[0], t[1], t[2], t[3]]
    }
}

/// 5GS mobile identity (TS 24.501 §9.11.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIdentity {
    /// No identity (type 000).
    NoIdentity,
    /// SUCI with SUPI format IMSI and the null protection scheme (scheme
    /// output = MSIN in clear).
    Suci {
        plmn: Plmn,
        /// Routing indicator (up to 4 digits, 0 = "0000").
        routing_indicator: u16,
        /// MSIN digits.
        msin: String,
    },
    /// 5G-GUTI.
    Guti(Guti),
    /// IMEISV digits (16).
    Imeisv(String),
    /// 5G-S-TMSI (AMF set ID / pointer / 5G-TMSI).
    STmsi {
        amf_set_id: u16,
        amf_pointer: u8,
        tmsi: u32,
    },
    /// Any other identity, kept as the raw IE value.
    Other(Vec<u8>),
}

impl MobileIdentity {
    /// Build the null-scheme SUCI for a 15-digit IMSI with a `mnc_digits`
    /// (2 or 3) MNC. Non-digit characters are ignored; a short IMSI yields a
    /// short MSIN rather than a panic.
    pub fn suci_from_imsi(imsi: &str, mnc_digits: u8, routing_indicator: u16) -> Self {
        let d: Vec<u8> = imsi
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect();
        let n = if mnc_digits == 3 { 3 } else { 2 };
        let num = |s: &[u8]| s.iter().fold(0u16, |a, &x| a * 10 + x as u16);
        let mcc = num(d.get(0..3).unwrap_or(&[]));
        let mnc = num(d.get(3..3 + n).unwrap_or(&[]));
        let msin: String = d
            .get(3 + n..)
            .unwrap_or(&[])
            .iter()
            .map(|&x| (b'0' + x) as char)
            .collect();
        MobileIdentity::Suci {
            plmn: Plmn {
                mcc,
                mnc,
                mnc_digits: n as u8,
            },
            routing_indicator,
            msin,
        }
    }

    /// The IE value octets (without any length field).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            MobileIdentity::NoIdentity => vec![0x00],
            MobileIdentity::Suci {
                plmn,
                routing_indicator,
                msin,
            } => {
                let mut v = vec![0x01]; // SUPI format IMSI (000), type SUCI (001)
                v.extend_from_slice(&plmn.encode());
                let ri = *routing_indicator % 10000;
                let rd = [
                    (ri / 1000) as u8,
                    (ri / 100 % 10) as u8,
                    (ri / 10 % 10) as u8,
                    (ri % 10) as u8,
                ];
                v.push(bcd(rd[0], rd[1]));
                v.push(bcd(rd[2], rd[3]));
                v.push(0x00); // protection scheme: null
                v.push(0x00); // home network public key identifier
                v.extend(bcd_digits(msin));
                v
            }
            MobileIdentity::Guti(g) => {
                let mut v = vec![0xf2]; // spare 1111, odd/even 0, type 5G-GUTI (010)
                v.extend_from_slice(&g.plmn.encode());
                v.push(g.amf_region_id);
                v.extend_from_slice(&g.s_tmsi());
                v
            }
            MobileIdentity::Imeisv(digits) => {
                let d: Vec<u8> = digits
                    .bytes()
                    .filter(u8::is_ascii_digit)
                    .map(|b| b - b'0')
                    .collect();
                let odd = d.len() % 2 == 1;
                let first = d.first().copied().unwrap_or(0);
                let mut v = vec![(first << 4) | ((odd as u8) << 3) | 0x05];
                v.extend(
                    d.get(1..)
                        .unwrap_or(&[])
                        .chunks(2)
                        .map(|p| bcd(p[0], *p.get(1).unwrap_or(&0xf))),
                );
                v
            }
            MobileIdentity::STmsi {
                amf_set_id,
                amf_pointer,
                tmsi,
            } => {
                let mut v = vec![0xf4];
                let sp = ((amf_set_id & 0x3ff) << 6) | (*amf_pointer as u16 & 0x3f);
                v.extend_from_slice(&sp.to_be_bytes());
                v.extend_from_slice(&tmsi.to_be_bytes());
                v
            }
            MobileIdentity::Other(raw) => raw.clone(),
        }
    }

    /// Decode an IE value.
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        let mut rd = Reader::new(v);
        let t = rd.u8("identity type")?;
        match t & 0x07 {
            0 => Ok(MobileIdentity::NoIdentity),
            1 if t >> 4 == 0 => {
                let plmn = Plmn::decode(rd.take(3, "suci plmn")?)?;
                let ri = rd.take(2, "routing indicator")?;
                let digits = bcd_to_string(ri);
                let routing_indicator = digits.parse::<u16>().unwrap_or(0);
                let _scheme = rd.u8("protection scheme")?;
                let _hnpk = rd.u8("home network key id")?;
                let msin = bcd_to_string(rd.rest());
                Ok(MobileIdentity::Suci {
                    plmn,
                    routing_indicator,
                    msin,
                })
            }
            2 => {
                let plmn = Plmn::decode(rd.take(3, "guti plmn")?)?;
                let amf_region_id = rd.u8("amf region")?;
                let sp = rd.u16("amf set/pointer")?;
                let tmsi = u32::from_be_bytes(rd.array::<4>("tmsi")?);
                Ok(MobileIdentity::Guti(Guti {
                    plmn,
                    amf_region_id,
                    amf_set_id: sp >> 6,
                    amf_pointer: (sp & 0x3f) as u8,
                    tmsi,
                }))
            }
            4 => {
                let sp = rd.u16("amf set/pointer")?;
                let tmsi = u32::from_be_bytes(rd.array::<4>("tmsi")?);
                Ok(MobileIdentity::STmsi {
                    amf_set_id: sp >> 6,
                    amf_pointer: (sp & 0x3f) as u8,
                    tmsi,
                })
            }
            5 => {
                let odd = t & 0x08 != 0;
                let mut s = String::new();
                s.push((b'0' + (t >> 4).min(9)) as char);
                let rest = bcd_to_string(rd.rest());
                s.push_str(&rest);
                if !odd && s.len() % 2 == 1 {
                    s.pop();
                }
                Ok(MobileIdentity::Imeisv(s))
            }
            _ => Ok(MobileIdentity::Other(v.to_vec())),
        }
    }
}

/// S-NSSAI (TS 24.501 §9.11.2.8): SST with optional SD (mapped HPLMN fields
/// are decoded and dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snssai {
    pub sst: u8,
    pub sd: Option<[u8; 3]>,
}

impl Snssai {
    /// IE value: 1 octet (SST) or 4 octets (SST + SD).
    pub fn encode(&self) -> Vec<u8> {
        match self.sd {
            Some(sd) => vec![self.sst, sd[0], sd[1], sd[2]],
            None => vec![self.sst],
        }
    }

    /// Decode an IE value (lengths 1, 2, 4, 5 and 8 per the spec).
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        let sst = *v.first().ok_or(NasError::Truncated("s-nssai"))?;
        let sd = if v.len() >= 4 {
            Some([v[1], v[2], v[3]])
        } else {
            None
        };
        Ok(Snssai { sst, sd })
    }
}

/// Encode an NSSAI IE value (TS 24.501 §9.11.3.37): a list of LV S-NSSAIs.
pub fn encode_nssai(list: &[Snssai]) -> Vec<u8> {
    let mut w = Writer::new();
    for s in list {
        w.lv(&s.encode());
    }
    w.into_vec()
}

/// Decode an NSSAI IE value.
pub fn decode_nssai(v: &[u8]) -> Result<Vec<Snssai>, NasError> {
    let mut rd = Reader::new(v);
    let mut out = Vec::new();
    while !rd.is_empty() {
        out.push(Snssai::decode(rd.lv("nssai entry")?)?);
    }
    Ok(out)
}

/// Tracking area identity (TS 24.501 §9.11.3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tai {
    pub plmn: Plmn,
    /// 24-bit TAC.
    pub tac: u32,
}

impl Tai {
    /// Six octets: PLMN + TAC.
    pub fn encode(&self) -> [u8; 6] {
        let p = self.plmn.encode();
        let t = self.tac.to_be_bytes();
        [p[0], p[1], p[2], t[1], t[2], t[3]]
    }

    /// Decode six octets.
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        if v.len() < 6 {
            return Err(NasError::Truncated("tai"));
        }
        Ok(Tai {
            plmn: Plmn::decode(&v[0..3])?,
            tac: u32::from_be_bytes([0, v[3], v[4], v[5]]),
        })
    }
}

/// Decode a 5GS tracking area identity list (TS 24.501 §9.11.3.9) into the
/// TAIs it enumerates (partial list types 00, 01 and 10).
pub fn decode_tai_list(v: &[u8]) -> Result<Vec<Tai>, NasError> {
    let mut rd = Reader::new(v);
    let mut out = Vec::new();
    while !rd.is_empty() {
        let h = rd.u8("tai list header")?;
        let kind = (h >> 5) & 0x3;
        let n = (h & 0x1f) as usize + 1;
        match kind {
            0 => {
                let plmn = Plmn::decode(rd.take(3, "tai plmn")?)?;
                let t = rd.take(3, "tac")?;
                let tac = u32::from_be_bytes([0, t[0], t[1], t[2]]);
                for i in 0..n as u32 {
                    out.push(Tai {
                        plmn,
                        tac: (tac + i) & 0xff_ffff,
                    });
                }
            }
            1 => {
                let plmn = Plmn::decode(rd.take(3, "tai plmn")?)?;
                for _ in 0..n {
                    let t = rd.take(3, "tac")?;
                    out.push(Tai {
                        plmn,
                        tac: u32::from_be_bytes([0, t[0], t[1], t[2]]),
                    });
                }
            }
            2 => {
                for _ in 0..n {
                    out.push(Tai::decode(rd.take(6, "tai")?)?);
                }
            }
            _ => break, // reserved: stop parsing, keep what we have
        }
    }
    Ok(out)
}

/// Encode a TAI list with one "type 10" partial list of explicit TAIs.
pub fn encode_tai_list(tais: &[Tai]) -> Vec<u8> {
    let mut w = Writer::new();
    if tais.is_empty() {
        return w.into_vec();
    }
    let n = tais.len().min(16);
    w.u8(0x40 | (n as u8 - 1));
    for t in &tais[..n] {
        w.bytes(&t.encode());
    }
    w.into_vec()
}

/// GPRS timer 3 (TS 24.501 §9.11.2.5; T3512, back-off timers): unit in bits
/// 6-8, value in bits 1-5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GprsTimer3 {
    pub unit: u8,
    pub value: u8,
}

impl GprsTimer3 {
    /// Decode the single value octet.
    pub fn from_octet(b: u8) -> Self {
        GprsTimer3 {
            unit: b >> 5,
            value: b & 0x1f,
        }
    }

    /// The value octet.
    pub fn to_octet(self) -> u8 {
        (self.unit << 5) | (self.value & 0x1f)
    }

    /// Duration in milliseconds; `None` when the timer is deactivated (unit 7).
    pub fn to_ms(self) -> Option<u64> {
        let v = self.value as u64;
        Some(match self.unit {
            0 => v * 10 * 60_000,
            1 => v * 3_600_000,
            2 => v * 10 * 3_600_000,
            3 => v * 2_000,
            4 => v * 30_000,
            5 => v * 60_000,
            6 => v * 320 * 3_600_000,
            _ => return None,
        })
    }
}

/// GPRS timer 2 (TS 24.501 §9.11.2.4; T3502, T3346): unit in bits 6-8
/// (0 = 2 s, 1 = 1 min, 2 = decihours, 7 = deactivated), value in bits 1-5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GprsTimer2 {
    pub unit: u8,
    pub value: u8,
}

impl GprsTimer2 {
    /// Decode the single value octet.
    pub fn from_octet(b: u8) -> Self {
        GprsTimer2 {
            unit: b >> 5,
            value: b & 0x1f,
        }
    }

    /// The value octet.
    pub fn to_octet(self) -> u8 {
        (self.unit << 5) | (self.value & 0x1f)
    }

    /// Duration in milliseconds; `None` when deactivated.
    pub fn to_ms(self) -> Option<u64> {
        let v = self.value as u64;
        Some(match self.unit {
            0 => v * 2_000,
            1 => v * 60_000,
            2 => v * 6 * 60_000,
            7 => return None,
            _ => v * 60_000,
        })
    }
}

/// UE security capability (TS 24.501 §9.11.3.54): bitmaps with bit 8 = EA0 /
/// IA0, bit 7 = 128-EA1 / IA1, bit 6 = 128-EA2 / IA2, bit 5 = 128-EA3 / IA3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeSecurityCapability {
    pub ea: u8,
    pub ia: u8,
    /// EPS algorithms (octets 5-6), if present.
    pub eps_ea: Option<u8>,
    pub eps_ia: Option<u8>,
}

impl Default for UeSecurityCapability {
    /// 5G-EA0 + 5G-EA2 and 5G-IA0 + 5G-IA2 (`0xa0 0xa0`): exactly the
    /// algorithms `ferrite-security` implements (no SNOW 3G / ZUC).
    fn default() -> Self {
        UeSecurityCapability {
            ea: 0xa0,
            ia: 0xa0,
            eps_ea: None,
            eps_ia: None,
        }
    }
}

impl UeSecurityCapability {
    /// IE value (2 or 4 octets).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.ea, self.ia];
        if let (Some(e), Some(i)) = (self.eps_ea, self.eps_ia) {
            v.push(e);
            v.push(i);
        }
        v
    }

    /// Decode an IE value (extra octets are ignored).
    pub fn decode(v: &[u8]) -> Result<Self, NasError> {
        if v.len() < 2 {
            return Err(NasError::Truncated("ue security capability"));
        }
        let (eps_ea, eps_ia) = if v.len() >= 4 {
            (Some(v[2]), Some(v[3]))
        } else {
            (None, None)
        };
        Ok(UeSecurityCapability {
            ea: v[0],
            ia: v[1],
            eps_ea,
            eps_ia,
        })
    }

    /// Whether the 5G ciphering algorithm `nea` (0..=7) is supported.
    pub fn supports_ea(&self, nea: u8) -> bool {
        nea < 8 && self.ea & (0x80 >> nea) != 0
    }

    /// Whether the 5G integrity algorithm `nia` (0..=7) is supported.
    pub fn supports_ia(&self, nia: u8) -> bool {
        nia < 8 && self.ia & (0x80 >> nia) != 0
    }
}

/// NAS key set identifier (TS 24.501 §9.11.3.32): TSC (bit 4) + 3-bit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NgKsi {
    /// Type of security context: false = native, true = mapped.
    pub mapped: bool,
    /// Key set identifier 0..=6, or 7 = no key is available.
    pub ksi: u8,
}

impl NgKsi {
    /// "No key is available" (ngKSI value 7).
    pub const NO_KEY: NgKsi = NgKsi {
        mapped: false,
        ksi: 7,
    };

    /// The nibble.
    pub fn nibble(self) -> u8 {
        ((self.mapped as u8) << 3) | (self.ksi & 0x7)
    }

    /// From a nibble.
    pub fn from_nibble(n: u8) -> Self {
        NgKsi {
            mapped: n & 0x8 != 0,
            ksi: n & 0x7,
        }
    }
}

/// 5GS registration type value (TS 24.501 §9.11.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegistrationType {
    Initial = 1,
    MobilityUpdating = 2,
    PeriodicUpdating = 3,
    Emergency = 4,
    SnpnOnboarding = 5,
}

impl RegistrationType {
    fn from_u8(v: u8) -> Self {
        match v & 0x7 {
            2 => Self::MobilityUpdating,
            3 => Self::PeriodicUpdating,
            4 => Self::Emergency,
            5 => Self::SnpnOnboarding,
            _ => Self::Initial,
        }
    }
}

/// Payload container type (TS 24.501 §9.11.3.40).
pub mod payload_container_type {
    pub const N1_SM_INFORMATION: u8 = 1;
    pub const SMS: u8 = 2;
    pub const LPP: u8 = 3;
    pub const SOR_TRANSPARENT_CONTAINER: u8 = 4;
    pub const UE_POLICY_CONTAINER: u8 = 5;
    pub const UE_PARAMETERS_UPDATE: u8 = 6;
    pub const LOCATION_SERVICES: u8 = 7;
    pub const CIOT_USER_DATA: u8 = 8;
    pub const MULTIPLE_PAYLOADS: u8 = 15;
}

/// Request type (TS 24.501 §9.11.3.47) in UL NAS TRANSPORT.
pub mod request_type {
    pub const INITIAL_REQUEST: u8 = 1;
    pub const EXISTING_PDU_SESSION: u8 = 2;
    pub const INITIAL_EMERGENCY_REQUEST: u8 = 3;
    pub const EXISTING_EMERGENCY_PDU_SESSION: u8 = 4;
    pub const MODIFICATION_REQUEST: u8 = 5;
    pub const MA_PDU_REQUEST: u8 = 6;
}

/// Encode a DNN IE value (TS 24.501 §9.11.2.1B): dot-separated labels, each
/// prefixed by its length.
pub fn encode_dnn(dnn: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(dnn.len() + 1);
    for label in dnn.split('.').filter(|l| !l.is_empty()) {
        let b = label.as_bytes();
        let n = b.len().min(63);
        v.push(n as u8);
        v.extend_from_slice(&b[..n]);
    }
    v
}

/// Decode a DNN IE value into its dotted form.
pub fn decode_dnn(v: &[u8]) -> Result<String, NasError> {
    let mut rd = Reader::new(v);
    let mut labels = Vec::new();
    while !rd.is_empty() {
        let l = rd.lv("dnn label")?;
        labels.push(String::from_utf8_lossy(l).into_owned());
    }
    Ok(labels.join("."))
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// REGISTRATION REQUEST (TS 24.501 §8.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRequest {
    pub reg_type: RegistrationType,
    /// Follow-on request pending (FOR bit).
    pub follow_on_request: bool,
    pub ngksi: NgKsi,
    pub mobile_identity: MobileIdentity,
    /// 5GMM capability, first octet only (IEI 0x10).
    pub mm_capability: Option<u8>,
    /// UE security capability (IEI 0x2E).
    pub ue_security_capability: Option<UeSecurityCapability>,
    /// Requested NSSAI (IEI 0x2F).
    pub requested_nssai: Option<Vec<Snssai>>,
    /// Last visited registered TAI (IEI 0x52).
    pub last_visited_tai: Option<Tai>,
    /// Uplink data status (IEI 0x40), PSI bitmap as in the IE (octet 3, 4).
    pub uplink_data_status: Option<u16>,
    /// PDU session status (IEI 0x50).
    pub pdu_session_status: Option<u16>,
    /// UE's usage setting (IEI 0x18): true = data centric.
    pub ue_usage_setting: Option<bool>,
    /// NAS message container (IEI 0x71).
    pub nas_message_container: Option<Vec<u8>>,
}

impl RegistrationRequest {
    /// The minimal initial registration the proven core flow uses: SUCI,
    /// ngKSI = no key, FOR = 1, 5GMM capability `0x07`, security capability
    /// EA0-2 / IA0-2 and nothing else.
    pub fn initial(identity: MobileIdentity) -> Self {
        RegistrationRequest {
            reg_type: RegistrationType::Initial,
            follow_on_request: true,
            ngksi: NgKsi::NO_KEY,
            mobile_identity: identity,
            mm_capability: Some(0x07),
            ue_security_capability: Some(UeSecurityCapability::default()),
            requested_nssai: None,
            last_visited_tai: None,
            uplink_data_status: None,
            pdu_session_status: None,
            ue_usage_setting: None,
            nas_message_container: None,
        }
    }

    /// Encode as a plain NAS message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::REGISTRATION_REQUEST);
        let rt = (self.reg_type as u8) | ((self.follow_on_request as u8) << 3);
        w.u8((self.ngksi.nibble() << 4) | rt);
        w.lv_e(&self.mobile_identity.encode());
        if let Some(c) = self.mm_capability {
            w.tlv(0x10, &[c]);
        }
        if let Some(s) = &self.ue_security_capability {
            w.tlv(0x2e, &s.encode());
        }
        if let Some(n) = &self.requested_nssai {
            w.tlv(0x2f, &encode_nssai(n));
        }
        if let Some(t) = &self.last_visited_tai {
            w.tv(0x52, &t.encode());
        }
        if let Some(s) = self.uplink_data_status {
            w.tlv(0x40, &s.to_le_bytes());
        }
        if let Some(s) = self.pdu_session_status {
            w.tlv(0x50, &s.to_le_bytes());
        }
        if let Some(dc) = self.ue_usage_setting {
            w.tlv(0x18, &[dc as u8]);
        }
        if let Some(c) = &self.nas_message_container {
            w.tlv_e(0x71, c);
        }
        w.into_vec()
    }

    /// Decode a plain NAS message.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::REGISTRATION_REQUEST {
            return Err(NasError::UnexpectedMessage(t));
        }
        let b = rd.u8("registration type")?;
        let mut m = RegistrationRequest {
            reg_type: RegistrationType::from_u8(b),
            follow_on_request: b & 0x08 != 0,
            ngksi: NgKsi::from_nibble(b >> 4),
            mobile_identity: MobileIdentity::decode(rd.lv_e("mobile identity")?)?,
            mm_capability: None,
            ue_security_capability: None,
            requested_nssai: None,
            last_visited_tai: None,
            uplink_data_status: None,
            pdu_session_status: None,
            ue_usage_setting: None,
            nas_message_container: None,
        };
        const KNOWN: &[(u8, IeFmt)] = &[(0x52, IeFmt::Tv(6)), (0x48, IeFmt::Tv(1))];
        for ie in OptIes::new(rd.rest(), KNOWN) {
            let ie = ie?;
            match ie.iei {
                0x10 => m.mm_capability = ie.value.first().copied(),
                0x2e => m.ue_security_capability = Some(UeSecurityCapability::decode(ie.value)?),
                0x2f => m.requested_nssai = Some(decode_nssai(ie.value)?),
                0x52 => m.last_visited_tai = Some(Tai::decode(ie.value)?),
                0x40 => m.uplink_data_status = psi_bitmap(ie.value),
                0x50 => m.pdu_session_status = psi_bitmap(ie.value),
                0x18 => m.ue_usage_setting = ie.value.first().map(|b| b & 1 != 0),
                0x71 => m.nas_message_container = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

fn psi_bitmap(v: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes([
        *v.first()?,
        v.get(1).copied().unwrap_or(0),
    ]))
}

/// 5GS network feature support (TS 24.501 §9.11.3.5), first octet decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkFeatureSupport {
    pub ims_vops_3gpp: bool,
    pub ims_vops_n3gpp: bool,
    /// Emergency services support indicator (2 bits).
    pub emc: u8,
    /// Emergency services fallback indicator (2 bits).
    pub emf: u8,
    pub iwk_n26: bool,
    pub mpsi: bool,
}

impl NetworkFeatureSupport {
    fn decode(v: &[u8]) -> Self {
        let b = v.first().copied().unwrap_or(0);
        NetworkFeatureSupport {
            ims_vops_3gpp: b & 0x01 != 0,
            ims_vops_n3gpp: b & 0x02 != 0,
            emc: (b >> 2) & 0x3,
            emf: (b >> 4) & 0x3,
            iwk_n26: b & 0x40 != 0,
            mpsi: b & 0x80 != 0,
        }
    }

    fn encode(&self) -> u8 {
        (self.ims_vops_3gpp as u8)
            | ((self.ims_vops_n3gpp as u8) << 1)
            | ((self.emc & 3) << 2)
            | ((self.emf & 3) << 4)
            | ((self.iwk_n26 as u8) << 6)
            | ((self.mpsi as u8) << 7)
    }
}

/// REGISTRATION ACCEPT (TS 24.501 §8.2.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegistrationAccept {
    /// 5GS registration result value (bits 1-3: 1 = 3GPP, 2 = non-3GPP, 3 = both).
    pub result: u8,
    pub sms_allowed: bool,
    /// NSSAA to be performed.
    pub nssaa_pending: bool,
    pub guti: Option<Guti>,
    pub equivalent_plmns: Vec<Plmn>,
    pub tai_list: Vec<Tai>,
    pub allowed_nssai: Vec<Snssai>,
    pub rejected_nssai: Option<Vec<u8>>,
    pub configured_nssai: Vec<Snssai>,
    pub network_feature_support: Option<NetworkFeatureSupport>,
    pub pdu_session_status: Option<u16>,
    pub pdu_session_reactivation_result: Option<u16>,
    pub t3512: Option<GprsTimer3>,
    pub t3502: Option<GprsTimer2>,
    /// Non-3GPP de-registration timer (IEI 0x5D).
    pub non_3gpp_dereg_timer: Option<GprsTimer2>,
    pub eap_message: Option<Vec<u8>>,
    /// NSSAI inclusion mode (type 1, IEI 0xA-).
    pub nssai_inclusion_mode: Option<u8>,
}

impl RegistrationAccept {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::REGISTRATION_ACCEPT);
        let r = (self.result & 0x7)
            | ((self.sms_allowed as u8) << 3)
            | ((self.nssaa_pending as u8) << 4);
        w.lv(&[r]);
        if let Some(g) = &self.guti {
            w.tlv_e(0x77, &MobileIdentity::Guti(*g).encode());
        }
        if !self.equivalent_plmns.is_empty() {
            let v: Vec<u8> = self
                .equivalent_plmns
                .iter()
                .flat_map(|p| p.encode())
                .collect();
            w.tlv(0x4a, &v);
        }
        if !self.tai_list.is_empty() {
            w.tlv(0x54, &encode_tai_list(&self.tai_list));
        }
        if !self.allowed_nssai.is_empty() {
            w.tlv(0x15, &encode_nssai(&self.allowed_nssai));
        }
        if let Some(r) = &self.rejected_nssai {
            w.tlv(0x11, r);
        }
        if !self.configured_nssai.is_empty() {
            w.tlv(0x31, &encode_nssai(&self.configured_nssai));
        }
        if let Some(f) = &self.network_feature_support {
            w.tlv(0x21, &[f.encode()]);
        }
        if let Some(s) = self.pdu_session_status {
            w.tlv(0x50, &s.to_le_bytes());
        }
        if let Some(s) = self.pdu_session_reactivation_result {
            w.tlv(0x26, &s.to_le_bytes());
        }
        if let Some(t) = self.t3512 {
            w.tlv(0x5e, &[t.to_octet()]);
        }
        if let Some(t) = self.non_3gpp_dereg_timer {
            w.tlv(0x5d, &[t.to_octet()]);
        }
        if let Some(t) = self.t3502 {
            w.tlv(0x16, &[t.to_octet()]);
        }
        if let Some(e) = &self.eap_message {
            w.tlv_e(0x78, e);
        }
        if let Some(m) = self.nssai_inclusion_mode {
            w.tv1(0xa0, m);
        }
        w.into_vec()
    }

    /// Decode a plain REGISTRATION ACCEPT, storing known IEs and skipping the rest.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::REGISTRATION_ACCEPT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let res = rd.lv("registration result")?;
        let r0 = *res
            .first()
            .ok_or(NasError::Truncated("registration result"))?;
        let mut m = RegistrationAccept {
            result: r0 & 0x7,
            sms_allowed: r0 & 0x08 != 0,
            nssaa_pending: r0 & 0x10 != 0,
            ..Default::default()
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x77 => {
                    if let MobileIdentity::Guti(g) = MobileIdentity::decode(ie.value)? {
                        m.guti = Some(g);
                    }
                }
                0x4a => {
                    m.equivalent_plmns = ie
                        .value
                        .chunks_exact(3)
                        .filter_map(|c| Plmn::decode(c).ok())
                        .collect();
                }
                0x54 => m.tai_list = decode_tai_list(ie.value)?,
                0x15 => m.allowed_nssai = decode_nssai(ie.value)?,
                0x11 => m.rejected_nssai = Some(ie.value.to_vec()),
                0x31 => m.configured_nssai = decode_nssai(ie.value)?,
                0x21 => m.network_feature_support = Some(NetworkFeatureSupport::decode(ie.value)),
                0x50 => m.pdu_session_status = psi_bitmap(ie.value),
                0x26 => m.pdu_session_reactivation_result = psi_bitmap(ie.value),
                0x5e => m.t3512 = ie.value.first().map(|&b| GprsTimer3::from_octet(b)),
                0x5d => {
                    m.non_3gpp_dereg_timer = ie.value.first().map(|&b| GprsTimer2::from_octet(b))
                }
                0x16 => m.t3502 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                0x78 => m.eap_message = Some(ie.value.to_vec()),
                0xa0 => m.nssai_inclusion_mode = Some(ie.nibble),
                _ => log::debug!(
                    "RegistrationAccept: skipping IEI {:#04x} ({} octets)",
                    ie.iei,
                    ie.value.len()
                ),
            }
        }
        Ok(m)
    }
}

/// REGISTRATION REJECT (TS 24.501 §8.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationReject {
    pub cause: u8,
    pub t3346: Option<GprsTimer2>,
    pub t3502: Option<GprsTimer2>,
    pub eap_message: Option<Vec<u8>>,
    pub rejected_nssai: Option<Vec<u8>>,
}

impl RegistrationReject {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::REGISTRATION_REJECT);
        w.u8(self.cause);
        if let Some(t) = self.t3346 {
            w.tlv(0x5f, &[t.to_octet()]);
        }
        if let Some(t) = self.t3502 {
            w.tlv(0x16, &[t.to_octet()]);
        }
        if let Some(e) = &self.eap_message {
            w.tlv_e(0x78, e);
        }
        if let Some(r) = &self.rejected_nssai {
            w.tlv(0x11, r);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::REGISTRATION_REJECT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = RegistrationReject {
            cause: rd.u8("5gmm cause")?,
            t3346: None,
            t3502: None,
            eap_message: None,
            rejected_nssai: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x5f => m.t3346 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                0x16 => m.t3502 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                0x78 => m.eap_message = Some(ie.value.to_vec()),
                0x11 => m.rejected_nssai = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// REGISTRATION COMPLETE (TS 24.501 §8.2.9): header only (the SOR transparent
/// container is never sent by this UE).
pub fn registration_complete() -> Vec<u8> {
    mm_header(msg_type::REGISTRATION_COMPLETE).into_vec()
}

/// De-registration type (TS 24.501 §9.11.3.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeregistrationType {
    /// Access type: 1 = 3GPP, 2 = non-3GPP, 3 = both.
    pub access_type: u8,
    pub reregistration_required: bool,
    pub switch_off: bool,
}

impl DeregistrationType {
    fn nibble(self) -> u8 {
        (self.access_type & 0x3)
            | ((self.reregistration_required as u8) << 2)
            | ((self.switch_off as u8) << 3)
    }

    fn from_nibble(n: u8) -> Self {
        DeregistrationType {
            access_type: n & 0x3,
            reregistration_required: n & 0x4 != 0,
            switch_off: n & 0x8 != 0,
        }
    }
}

/// DEREGISTRATION REQUEST, UE originating (TS 24.501 §8.2.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeregistrationRequestUeOriginating {
    pub dereg_type: DeregistrationType,
    pub ngksi: NgKsi,
    pub mobile_identity: MobileIdentity,
}

impl DeregistrationRequestUeOriginating {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::DEREGISTRATION_REQUEST_UE_ORIG);
        w.u8((self.ngksi.nibble() << 4) | self.dereg_type.nibble());
        w.lv_e(&self.mobile_identity.encode());
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::DEREGISTRATION_REQUEST_UE_ORIG {
            return Err(NasError::UnexpectedMessage(t));
        }
        let b = rd.u8("de-registration type")?;
        Ok(DeregistrationRequestUeOriginating {
            dereg_type: DeregistrationType::from_nibble(b & 0xf),
            ngksi: NgKsi::from_nibble(b >> 4),
            mobile_identity: MobileIdentity::decode(rd.lv_e("mobile identity")?)?,
        })
    }
}

/// DEREGISTRATION REQUEST, UE terminated (TS 24.501 §8.2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeregistrationRequestUeTerminated {
    pub dereg_type: DeregistrationType,
    pub cause: Option<u8>,
    pub t3346: Option<GprsTimer2>,
}

impl DeregistrationRequestUeTerminated {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::DEREGISTRATION_REQUEST_UE_TERM);
        w.u8(self.dereg_type.nibble());
        if let Some(c) = self.cause {
            w.tv(0x58, &[c]);
        }
        if let Some(t) = self.t3346 {
            w.tlv(0x5f, &[t.to_octet()]);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::DEREGISTRATION_REQUEST_UE_TERM {
            return Err(NasError::UnexpectedMessage(t));
        }
        let b = rd.u8("de-registration type")?;
        let mut m = DeregistrationRequestUeTerminated {
            dereg_type: DeregistrationType::from_nibble(b & 0xf),
            cause: None,
            t3346: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x58, IeFmt::Tv(1))]) {
            let ie = ie?;
            match ie.iei {
                0x58 => m.cause = ie.value.first().copied(),
                0x5f => m.t3346 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// DEREGISTRATION ACCEPT, UE originating (0x46) or UE terminated (0x48):
/// header only.
pub fn deregistration_accept(ue_terminated: bool) -> Vec<u8> {
    let t = if ue_terminated {
        msg_type::DEREGISTRATION_ACCEPT_UE_TERM
    } else {
        msg_type::DEREGISTRATION_ACCEPT_UE_ORIG
    };
    mm_header(t).into_vec()
}

/// AUTHENTICATION REQUEST (TS 24.501 §8.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    pub ngksi: NgKsi,
    pub abba: Vec<u8>,
    pub rand: Option<[u8; 16]>,
    pub autn: Option<[u8; 16]>,
    pub eap_message: Option<Vec<u8>>,
}

impl AuthenticationRequest {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::AUTHENTICATION_REQUEST);
        w.u8(self.ngksi.nibble());
        w.lv(&self.abba);
        if let Some(r) = &self.rand {
            w.tv(0x21, r);
        }
        if let Some(a) = &self.autn {
            w.tlv(0x20, a);
        }
        if let Some(e) = &self.eap_message {
            w.tlv_e(0x78, e);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::AUTHENTICATION_REQUEST {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = AuthenticationRequest {
            ngksi: NgKsi::from_nibble(rd.u8("ngksi")? & 0xf),
            abba: rd.lv("abba")?.to_vec(),
            rand: None,
            autn: None,
            eap_message: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x21, IeFmt::Tv(16))]) {
            let ie = ie?;
            match ie.iei {
                0x21 => m.rand = ie.value.try_into().ok(),
                0x20 => m.autn = ie.value.get(..16).and_then(|v| v.try_into().ok()),
                0x78 => m.eap_message = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// AUTHENTICATION RESPONSE (TS 24.501 §8.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    /// RES* (IEI 0x2D).
    pub res_star: Option<[u8; 16]>,
    pub eap_message: Option<Vec<u8>>,
}

impl AuthenticationResponse {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::AUTHENTICATION_RESPONSE);
        if let Some(r) = &self.res_star {
            w.tlv(0x2d, r);
        }
        if let Some(e) = &self.eap_message {
            w.tlv_e(0x78, e);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::AUTHENTICATION_RESPONSE {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = AuthenticationResponse {
            res_star: None,
            eap_message: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x2d => m.res_star = ie.value.try_into().ok(),
                0x78 => m.eap_message = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// AUTHENTICATION FAILURE (TS 24.501 §8.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationFailure {
    pub cause: u8,
    /// AUTS for cause #21 synch failure (IEI 0x30).
    pub auts: Option<[u8; 14]>,
}

impl AuthenticationFailure {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::AUTHENTICATION_FAILURE);
        w.u8(self.cause);
        if let Some(a) = &self.auts {
            w.tlv(0x30, a);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::AUTHENTICATION_FAILURE {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = AuthenticationFailure {
            cause: rd.u8("5gmm cause")?,
            auts: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            if ie.iei == 0x30 {
                m.auts = ie.value.try_into().ok();
            }
        }
        Ok(m)
    }
}

/// AUTHENTICATION REJECT (TS 24.501 §8.2.3): header, optional EAP message.
pub fn authentication_reject() -> Vec<u8> {
    mm_header(msg_type::AUTHENTICATION_REJECT).into_vec()
}

/// SECURITY MODE COMMAND (TS 24.501 §8.2.25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    /// Selected NAS ciphering algorithm (5G-EA identifier).
    pub ea: u8,
    /// Selected NAS integrity algorithm (5G-IA identifier).
    pub ia: u8,
    pub ngksi: NgKsi,
    pub replayed_ue_security_capability: UeSecurityCapability,
    pub imeisv_requested: bool,
    /// Selected EPS NAS security algorithms (IEI 0x57).
    pub eps_algorithms: Option<u8>,
    /// Additional 5G security information (IEI 0x36): horizontal derivation.
    pub hdp: bool,
    /// Additional 5G security information: retransmission of initial NAS
    /// message requested.
    pub rinmr: bool,
    pub eap_message: Option<Vec<u8>>,
    pub abba: Option<Vec<u8>>,
}

impl SecurityModeCommand {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::SECURITY_MODE_COMMAND);
        w.u8(((self.ea & 0xf) << 4) | (self.ia & 0xf));
        w.u8(self.ngksi.nibble());
        w.lv(&self.replayed_ue_security_capability.encode());
        if self.imeisv_requested {
            w.tv1(0xe0, 1);
        }
        if let Some(a) = self.eps_algorithms {
            w.tv(0x57, &[a]);
        }
        if self.hdp || self.rinmr {
            w.tlv(0x36, &[(self.hdp as u8) | ((self.rinmr as u8) << 1)]);
        }
        if let Some(e) = &self.eap_message {
            w.tlv_e(0x78, e);
        }
        if let Some(a) = &self.abba {
            w.tlv(0x38, a);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::SECURITY_MODE_COMMAND {
            return Err(NasError::UnexpectedMessage(t));
        }
        let alg = rd.u8("selected nas security algorithms")?;
        let ngksi = NgKsi::from_nibble(rd.u8("ngksi")? & 0xf);
        let cap = UeSecurityCapability::decode(rd.lv("replayed ue security capabilities")?)?;
        let mut m = SecurityModeCommand {
            ea: alg >> 4,
            ia: alg & 0xf,
            ngksi,
            replayed_ue_security_capability: cap,
            imeisv_requested: false,
            eps_algorithms: None,
            hdp: false,
            rinmr: false,
            eap_message: None,
            abba: None,
        };
        for ie in OptIes::new(rd.rest(), &[(0x57, IeFmt::Tv(1))]) {
            let ie = ie?;
            match ie.iei {
                0xe0 => m.imeisv_requested = ie.nibble & 0x7 == 1,
                0x57 => m.eps_algorithms = ie.value.first().copied(),
                0x36 => {
                    let b = ie.value.first().copied().unwrap_or(0);
                    m.hdp = b & 1 != 0;
                    m.rinmr = b & 2 != 0;
                }
                0x78 => m.eap_message = Some(ie.value.to_vec()),
                0x38 => m.abba = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// SECURITY MODE COMPLETE (TS 24.501 §8.2.26).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityModeComplete {
    /// IMEISV (IEI 0x77).
    pub imeisv: Option<String>,
    /// NAS message container (IEI 0x71): the replayed initial NAS message.
    pub nas_message_container: Option<Vec<u8>>,
}

impl SecurityModeComplete {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::SECURITY_MODE_COMPLETE);
        if let Some(i) = &self.imeisv {
            w.tlv_e(0x77, &MobileIdentity::Imeisv(i.clone()).encode());
        }
        if let Some(c) = &self.nas_message_container {
            w.tlv_e(0x71, c);
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::SECURITY_MODE_COMPLETE {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = SecurityModeComplete::default();
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x77 => {
                    if let MobileIdentity::Imeisv(s) = MobileIdentity::decode(ie.value)? {
                        m.imeisv = Some(s);
                    }
                }
                0x71 => m.nas_message_container = Some(ie.value.to_vec()),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// SECURITY MODE REJECT (TS 24.501 §8.2.27): cause only.
pub fn security_mode_reject(cause: u8) -> Vec<u8> {
    let mut w = mm_header(msg_type::SECURITY_MODE_REJECT);
    w.u8(cause);
    w.into_vec()
}

/// Identity type values (TS 24.501 §9.11.3.3).
pub mod identity_type {
    pub const SUCI: u8 = 1;
    pub const GUTI: u8 = 2;
    pub const IMEI: u8 = 3;
    pub const S_TMSI: u8 = 4;
    pub const IMEISV: u8 = 5;
}

/// IDENTITY REQUEST (TS 24.501 §8.2.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRequest {
    pub identity_type: u8,
}

impl IdentityRequest {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::IDENTITY_REQUEST);
        w.u8(self.identity_type & 0x7);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::IDENTITY_REQUEST {
            return Err(NasError::UnexpectedMessage(t));
        }
        Ok(IdentityRequest {
            identity_type: rd.u8("identity type")? & 0x7,
        })
    }
}

/// IDENTITY RESPONSE (TS 24.501 §8.2.22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityResponse {
    pub mobile_identity: MobileIdentity,
}

impl IdentityResponse {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::IDENTITY_RESPONSE);
        w.lv_e(&self.mobile_identity.encode());
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::IDENTITY_RESPONSE {
            return Err(NasError::UnexpectedMessage(t));
        }
        Ok(IdentityResponse {
            mobile_identity: MobileIdentity::decode(rd.lv_e("mobile identity")?)?,
        })
    }
}

/// CONFIGURATION UPDATE COMMAND (TS 24.501 §8.2.19).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigurationUpdateCommand {
    /// Configuration update indication (IEI 0xA-): acknowledgement requested.
    pub ack_requested: bool,
    /// Configuration update indication: registration requested.
    pub registration_requested: bool,
    pub guti: Option<Guti>,
    pub tai_list: Vec<Tai>,
    pub allowed_nssai: Option<Vec<Snssai>>,
    pub configured_nssai: Option<Vec<Snssai>>,
    pub full_network_name: Option<Vec<u8>>,
    pub short_network_name: Option<Vec<u8>>,
    pub local_time_zone: Option<u8>,
    pub universal_time_and_tz: Option<[u8; 7]>,
    pub daylight_saving_time: Option<u8>,
}

impl ConfigurationUpdateCommand {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::CONFIGURATION_UPDATE_COMMAND);
        if self.ack_requested || self.registration_requested {
            w.tv1(
                0xa0,
                (self.ack_requested as u8) | ((self.registration_requested as u8) << 1),
            );
        }
        if let Some(g) = &self.guti {
            w.tlv_e(0x77, &MobileIdentity::Guti(*g).encode());
        }
        if !self.tai_list.is_empty() {
            w.tlv(0x54, &encode_tai_list(&self.tai_list));
        }
        if let Some(n) = &self.allowed_nssai {
            w.tlv(0x15, &encode_nssai(n));
        }
        if let Some(n) = &self.configured_nssai {
            w.tlv(0x31, &encode_nssai(n));
        }
        if let Some(n) = &self.full_network_name {
            w.tlv(0x43, n);
        }
        if let Some(n) = &self.short_network_name {
            w.tlv(0x45, n);
        }
        if let Some(t) = self.local_time_zone {
            w.tv(0x46, &[t]);
        }
        if let Some(t) = &self.universal_time_and_tz {
            w.tv(0x47, t);
        }
        if let Some(d) = self.daylight_saving_time {
            w.tlv(0x49, &[d]);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::CONFIGURATION_UPDATE_COMMAND {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = ConfigurationUpdateCommand::default();
        const KNOWN: &[(u8, IeFmt)] = &[(0x46, IeFmt::Tv(1)), (0x47, IeFmt::Tv(7))];
        for ie in OptIes::new(rd.rest(), KNOWN) {
            let ie = ie?;
            match ie.iei {
                0xa0 => {
                    m.ack_requested = ie.nibble & 1 != 0;
                    m.registration_requested = ie.nibble & 2 != 0;
                }
                0x77 => {
                    if let MobileIdentity::Guti(g) = MobileIdentity::decode(ie.value)? {
                        m.guti = Some(g);
                    }
                }
                0x54 => m.tai_list = decode_tai_list(ie.value)?,
                0x15 => m.allowed_nssai = Some(decode_nssai(ie.value)?),
                0x31 => m.configured_nssai = Some(decode_nssai(ie.value)?),
                0x43 => m.full_network_name = Some(ie.value.to_vec()),
                0x45 => m.short_network_name = Some(ie.value.to_vec()),
                0x46 => m.local_time_zone = ie.value.first().copied(),
                0x47 => m.universal_time_and_tz = ie.value.try_into().ok(),
                0x49 => m.daylight_saving_time = ie.value.first().copied(),
                _ => log::debug!("ConfigurationUpdateCommand: skipping IEI {:#04x}", ie.iei),
            }
        }
        Ok(m)
    }
}

/// CONFIGURATION UPDATE COMPLETE (TS 24.501 §8.2.20): header only.
pub fn configuration_update_complete() -> Vec<u8> {
    mm_header(msg_type::CONFIGURATION_UPDATE_COMPLETE).into_vec()
}

/// Service type values (TS 24.501 §9.11.3.50).
pub mod service_type {
    pub const SIGNALLING: u8 = 0;
    pub const DATA: u8 = 1;
    pub const MOBILE_TERMINATED_SERVICES: u8 = 2;
    pub const EMERGENCY_SERVICES: u8 = 3;
    pub const HIGH_PRIORITY_ACCESS: u8 = 5;
}

/// SERVICE REQUEST (TS 24.501 §8.2.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRequest {
    pub ngksi: NgKsi,
    pub service_type: u8,
    /// 5G-S-TMSI.
    pub s_tmsi: MobileIdentity,
    pub uplink_data_status: Option<u16>,
    pub pdu_session_status: Option<u16>,
}

impl ServiceRequest {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::SERVICE_REQUEST);
        w.u8(((self.service_type & 0xf) << 4) | self.ngksi.nibble());
        w.lv_e(&self.s_tmsi.encode());
        if let Some(s) = self.uplink_data_status {
            w.tlv(0x40, &s.to_le_bytes());
        }
        if let Some(s) = self.pdu_session_status {
            w.tlv(0x50, &s.to_le_bytes());
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::SERVICE_REQUEST {
            return Err(NasError::UnexpectedMessage(t));
        }
        let b = rd.u8("service type")?;
        let mut m = ServiceRequest {
            ngksi: NgKsi::from_nibble(b & 0xf),
            service_type: b >> 4,
            s_tmsi: MobileIdentity::decode(rd.lv_e("s-tmsi")?)?,
            uplink_data_status: None,
            pdu_session_status: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x40 => m.uplink_data_status = psi_bitmap(ie.value),
                0x50 => m.pdu_session_status = psi_bitmap(ie.value),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// SERVICE ACCEPT (TS 24.501 §8.2.17).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceAccept {
    pub pdu_session_status: Option<u16>,
    pub pdu_session_reactivation_result: Option<u16>,
    pub t3448: Option<GprsTimer2>,
}

impl ServiceAccept {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::SERVICE_ACCEPT);
        if let Some(s) = self.pdu_session_status {
            w.tlv(0x50, &s.to_le_bytes());
        }
        if let Some(s) = self.pdu_session_reactivation_result {
            w.tlv(0x26, &s.to_le_bytes());
        }
        if let Some(t) = self.t3448 {
            w.tlv(0x6b, &[t.to_octet()]);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::SERVICE_ACCEPT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = ServiceAccept::default();
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x50 => m.pdu_session_status = psi_bitmap(ie.value),
                0x26 => m.pdu_session_reactivation_result = psi_bitmap(ie.value),
                0x6b => m.t3448 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// SERVICE REJECT (TS 24.501 §8.2.18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceReject {
    pub cause: u8,
    pub pdu_session_status: Option<u16>,
    pub t3346: Option<GprsTimer2>,
}

impl ServiceReject {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::SERVICE_REJECT);
        w.u8(self.cause);
        if let Some(s) = self.pdu_session_status {
            w.tlv(0x50, &s.to_le_bytes());
        }
        if let Some(t) = self.t3346 {
            w.tlv(0x5f, &[t.to_octet()]);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::SERVICE_REJECT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = ServiceReject {
            cause: rd.u8("5gmm cause")?,
            pdu_session_status: None,
            t3346: None,
        };
        for ie in OptIes::new(rd.rest(), &[]) {
            let ie = ie?;
            match ie.iei {
                0x50 => m.pdu_session_status = psi_bitmap(ie.value),
                0x5f => m.t3346 = ie.value.first().map(|&b| GprsTimer2::from_octet(b)),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// UL NAS TRANSPORT (TS 24.501 §8.2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlNasTransport {
    pub payload_container_type: u8,
    pub payload_container: Vec<u8>,
    /// PDU session ID (IEI 0x12).
    pub pdu_session_id: Option<u8>,
    /// Old PDU session ID (IEI 0x59).
    pub old_pdu_session_id: Option<u8>,
    /// Request type (type 1, IEI 0x8-).
    pub request_type: Option<u8>,
    /// S-NSSAI (IEI 0x22).
    pub snssai: Option<Snssai>,
    /// DNN (IEI 0x25).
    pub dnn: Option<String>,
}

impl UlNasTransport {
    /// Encode. The IE order (PSI, request type, S-NSSAI, DNN) is the order
    /// the reference vector uses.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::UL_NAS_TRANSPORT);
        w.u8(self.payload_container_type & 0xf);
        w.lv_e(&self.payload_container);
        if let Some(p) = self.pdu_session_id {
            w.tv(0x12, &[p]);
        }
        if let Some(p) = self.old_pdu_session_id {
            w.tv(0x59, &[p]);
        }
        if let Some(r) = self.request_type {
            w.tv1(0x80, r);
        }
        if let Some(s) = &self.snssai {
            w.tlv(0x22, &s.encode());
        }
        if let Some(d) = &self.dnn {
            w.tlv(0x25, &encode_dnn(d));
        }
        w.into_vec()
    }

    /// Decode (used by test cores).
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::UL_NAS_TRANSPORT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = UlNasTransport {
            payload_container_type: rd.u8("payload container type")? & 0xf,
            payload_container: rd.lv_e("payload container")?.to_vec(),
            pdu_session_id: None,
            old_pdu_session_id: None,
            request_type: None,
            snssai: None,
            dnn: None,
        };
        const KNOWN: &[(u8, IeFmt)] = &[(0x12, IeFmt::Tv(1)), (0x59, IeFmt::Tv(1))];
        for ie in OptIes::new(rd.rest(), KNOWN) {
            let ie = ie?;
            match ie.iei {
                0x12 => m.pdu_session_id = ie.value.first().copied(),
                0x59 => m.old_pdu_session_id = ie.value.first().copied(),
                0x80 => m.request_type = Some(ie.nibble & 0x7),
                0x22 => m.snssai = Some(Snssai::decode(ie.value)?),
                0x25 => m.dnn = Some(decode_dnn(ie.value)?),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// DL NAS TRANSPORT (TS 24.501 §8.2.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlNasTransport {
    pub payload_container_type: u8,
    pub payload_container: Vec<u8>,
    pub pdu_session_id: Option<u8>,
    pub additional_information: Option<Vec<u8>>,
    /// 5GMM cause (IEI 0x58), e.g. #91 payload was not forwarded.
    pub cause: Option<u8>,
    /// Back-off timer value (IEI 0x37).
    pub back_off_timer: Option<GprsTimer3>,
}

impl DlNasTransport {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::DL_NAS_TRANSPORT);
        w.u8(self.payload_container_type & 0xf);
        w.lv_e(&self.payload_container);
        if let Some(p) = self.pdu_session_id {
            w.tv(0x12, &[p]);
        }
        if let Some(a) = &self.additional_information {
            w.tlv(0x24, a);
        }
        if let Some(c) = self.cause {
            w.tv(0x58, &[c]);
        }
        if let Some(t) = self.back_off_timer {
            w.tlv(0x37, &[t.to_octet()]);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::DL_NAS_TRANSPORT {
            return Err(NasError::UnexpectedMessage(t));
        }
        let mut m = DlNasTransport {
            payload_container_type: rd.u8("payload container type")? & 0xf,
            payload_container: rd.lv_e("payload container")?.to_vec(),
            pdu_session_id: None,
            additional_information: None,
            cause: None,
            back_off_timer: None,
        };
        const KNOWN: &[(u8, IeFmt)] = &[(0x12, IeFmt::Tv(1)), (0x58, IeFmt::Tv(1))];
        for ie in OptIes::new(rd.rest(), KNOWN) {
            let ie = ie?;
            match ie.iei {
                0x12 => m.pdu_session_id = ie.value.first().copied(),
                0x24 => m.additional_information = Some(ie.value.to_vec()),
                0x58 => m.cause = ie.value.first().copied(),
                0x37 => m.back_off_timer = ie.value.first().map(|&b| GprsTimer3::from_octet(b)),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// 5GMM STATUS (TS 24.501 §8.2.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmStatus {
    pub cause: u8,
}

impl MmStatus {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::MM_STATUS);
        w.u8(self.cause);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::MM_STATUS {
            return Err(NasError::UnexpectedMessage(t));
        }
        Ok(MmStatus {
            cause: rd.u8("5gmm cause")?,
        })
    }
}

/// NOTIFICATION (TS 24.501 §8.2.23): access type (1 = 3GPP, 2 = non-3GPP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    pub access_type: u8,
}

impl Notification {
    /// Encode (used by test cores).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = mm_header(msg_type::NOTIFICATION);
        w.u8(self.access_type & 0x3);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(plain: &[u8]) -> Result<Self, NasError> {
        let (t, mut rd) = read_mm_header(plain)?;
        if t != msg_type::NOTIFICATION {
            return Err(NasError::UnexpectedMessage(t));
        }
        Ok(Notification {
            access_type: rd.u8("access type")? & 0x3,
        })
    }
}

/// NOTIFICATION RESPONSE (TS 24.501 §8.2.24): header, optional PDU session status.
pub fn notification_response(pdu_session_status: Option<u16>) -> Vec<u8> {
    let mut w = mm_header(msg_type::NOTIFICATION_RESPONSE);
    if let Some(s) = pdu_session_status {
        w.tlv(0x50, &s.to_le_bytes());
    }
    w.into_vec()
}

/// Any decoded 5GMM message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmMessage {
    RegistrationRequest(RegistrationRequest),
    RegistrationAccept(RegistrationAccept),
    RegistrationComplete,
    RegistrationReject(RegistrationReject),
    DeregistrationRequestUeOriginating(DeregistrationRequestUeOriginating),
    DeregistrationAcceptUeOriginating,
    DeregistrationRequestUeTerminated(DeregistrationRequestUeTerminated),
    DeregistrationAcceptUeTerminated,
    ServiceRequest(ServiceRequest),
    ServiceAccept(ServiceAccept),
    ServiceReject(ServiceReject),
    ConfigurationUpdateCommand(ConfigurationUpdateCommand),
    ConfigurationUpdateComplete,
    AuthenticationRequest(AuthenticationRequest),
    AuthenticationResponse(AuthenticationResponse),
    AuthenticationReject,
    AuthenticationFailure(AuthenticationFailure),
    /// AUTHENTICATION RESULT (EAP based): kept raw.
    AuthenticationResult(Vec<u8>),
    IdentityRequest(IdentityRequest),
    IdentityResponse(IdentityResponse),
    SecurityModeCommand(SecurityModeCommand),
    SecurityModeComplete(SecurityModeComplete),
    SecurityModeReject(u8),
    Status(MmStatus),
    Notification(Notification),
    NotificationResponse,
    UlNasTransport(UlNasTransport),
    DlNasTransport(DlNasTransport),
    /// A 5GMM message type this decoder does not implement.
    Unknown {
        msg_type: u8,
    },
}

/// Decode any plain 5GMM message by its type.
pub fn decode_mm(plain: &[u8]) -> Result<MmMessage, NasError> {
    use msg_type::*;
    let (t, mut rd) = read_mm_header(plain)?;
    Ok(match t {
        REGISTRATION_REQUEST => MmMessage::RegistrationRequest(RegistrationRequest::decode(plain)?),
        REGISTRATION_ACCEPT => MmMessage::RegistrationAccept(RegistrationAccept::decode(plain)?),
        REGISTRATION_COMPLETE => MmMessage::RegistrationComplete,
        REGISTRATION_REJECT => MmMessage::RegistrationReject(RegistrationReject::decode(plain)?),
        DEREGISTRATION_REQUEST_UE_ORIG => MmMessage::DeregistrationRequestUeOriginating(
            DeregistrationRequestUeOriginating::decode(plain)?,
        ),
        DEREGISTRATION_ACCEPT_UE_ORIG => MmMessage::DeregistrationAcceptUeOriginating,
        DEREGISTRATION_REQUEST_UE_TERM => MmMessage::DeregistrationRequestUeTerminated(
            DeregistrationRequestUeTerminated::decode(plain)?,
        ),
        DEREGISTRATION_ACCEPT_UE_TERM => MmMessage::DeregistrationAcceptUeTerminated,
        SERVICE_REQUEST => MmMessage::ServiceRequest(ServiceRequest::decode(plain)?),
        SERVICE_ACCEPT => MmMessage::ServiceAccept(ServiceAccept::decode(plain)?),
        SERVICE_REJECT => MmMessage::ServiceReject(ServiceReject::decode(plain)?),
        CONFIGURATION_UPDATE_COMMAND => {
            MmMessage::ConfigurationUpdateCommand(ConfigurationUpdateCommand::decode(plain)?)
        }
        CONFIGURATION_UPDATE_COMPLETE => MmMessage::ConfigurationUpdateComplete,
        AUTHENTICATION_REQUEST => {
            MmMessage::AuthenticationRequest(AuthenticationRequest::decode(plain)?)
        }
        AUTHENTICATION_RESPONSE => {
            MmMessage::AuthenticationResponse(AuthenticationResponse::decode(plain)?)
        }
        AUTHENTICATION_REJECT => MmMessage::AuthenticationReject,
        AUTHENTICATION_FAILURE => {
            MmMessage::AuthenticationFailure(AuthenticationFailure::decode(plain)?)
        }
        AUTHENTICATION_RESULT => MmMessage::AuthenticationResult(rd.rest().to_vec()),
        IDENTITY_REQUEST => MmMessage::IdentityRequest(IdentityRequest::decode(plain)?),
        IDENTITY_RESPONSE => MmMessage::IdentityResponse(IdentityResponse::decode(plain)?),
        SECURITY_MODE_COMMAND => {
            MmMessage::SecurityModeCommand(SecurityModeCommand::decode(plain)?)
        }
        SECURITY_MODE_COMPLETE => {
            MmMessage::SecurityModeComplete(SecurityModeComplete::decode(plain)?)
        }
        SECURITY_MODE_REJECT => MmMessage::SecurityModeReject(rd.u8("5gmm cause")?),
        MM_STATUS => MmMessage::Status(MmStatus::decode(plain)?),
        NOTIFICATION => MmMessage::Notification(Notification::decode(plain)?),
        NOTIFICATION_RESPONSE => MmMessage::NotificationResponse,
        UL_NAS_TRANSPORT => MmMessage::UlNasTransport(UlNasTransport::decode(plain)?),
        DL_NAS_TRANSPORT => MmMessage::DlNasTransport(DlNasTransport::decode(plain)?),
        other => MmMessage::Unknown { msg_type: other },
    })
}

/// Convenience: the IEI/value pairs of the optional part of a message, for
/// diagnostics (`None` on truncation).
pub fn list_optional_ies<'a>(rest: &'a [u8], known: &'a [(u8, IeFmt)]) -> Option<Vec<OptIe<'a>>> {
    OptIes::new(rest, known).collect::<Result<Vec<_>, _>>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMSI: &str = "001010167891203";

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn plmn() -> Plmn {
        Plmn {
            mcc: 1,
            mnc: 1,
            mnc_digits: 2,
        }
    }

    fn guti() -> Guti {
        Guti {
            plmn: plmn(),
            amf_region_id: 2,
            amf_set_id: 1,
            amf_pointer: 0,
            tmsi: 0xdead_beef,
        }
    }

    #[test]
    fn plmn_codec() {
        assert_eq!(plmn().encode(), [0x00, 0xf1, 0x10]);
        assert_eq!(Plmn::decode(&[0x00, 0xf1, 0x10]).unwrap(), plmn());
        let p3 = Plmn {
            mcc: 310,
            mnc: 410,
            mnc_digits: 3,
        };
        assert_eq!(Plmn::decode(&p3.encode()).unwrap(), p3);
        assert_eq!(
            plmn().serving_network_name(),
            "5G:mnc001.mcc001.3gppnetwork.org"
        );
    }

    #[test]
    fn suci_matches_legacy_layout() {
        let s = MobileIdentity::suci_from_imsi(IMSI, 2, 0);
        assert_eq!(s.encode(), crate::msgs::suci_from_imsi(IMSI));
        let d = MobileIdentity::decode(&s.encode()).unwrap();
        assert_eq!(d, s);
        if let MobileIdentity::Suci { msin, .. } = d {
            assert_eq!(msin, "0167891203");
        }
    }

    #[test]
    fn guti_and_imeisv_codec() {
        let g = MobileIdentity::Guti(guti());
        let e = g.encode();
        assert_eq!(e.len(), 11);
        assert_eq!(e[0], 0xf2);
        assert_eq!(MobileIdentity::decode(&e).unwrap(), g);
        let i = MobileIdentity::Imeisv("3534900698735912".into());
        let e = i.encode();
        assert_eq!(e.len(), 9);
        assert_eq!(MobileIdentity::decode(&e).unwrap(), i);
        let s = MobileIdentity::STmsi {
            amf_set_id: 1,
            amf_pointer: 0,
            tmsi: 7,
        };
        assert_eq!(MobileIdentity::decode(&s.encode()).unwrap(), s);
        assert_eq!(
            MobileIdentity::decode(&[0x00]).unwrap(),
            MobileIdentity::NoIdentity
        );
        assert!(MobileIdentity::decode(&[]).is_err());
    }

    #[test]
    fn registration_request_matches_legacy_bytes() {
        let rr = RegistrationRequest::initial(MobileIdentity::suci_from_imsi(IMSI, 2, 0));
        assert_eq!(rr.encode(), crate::msgs::registration_request(IMSI));
        let d = RegistrationRequest::decode(&rr.encode()).unwrap();
        assert_eq!(d, rr);
    }

    #[test]
    fn registration_request_full_roundtrip() {
        let mut rr = RegistrationRequest::initial(MobileIdentity::Guti(guti()));
        rr.ngksi = NgKsi {
            mapped: false,
            ksi: 2,
        };
        rr.reg_type = RegistrationType::MobilityUpdating;
        rr.requested_nssai = Some(vec![
            Snssai { sst: 1, sd: None },
            Snssai {
                sst: 2,
                sd: Some([1, 2, 3]),
            },
        ]);
        rr.last_visited_tai = Some(Tai {
            plmn: plmn(),
            tac: 0x000001,
        });
        rr.uplink_data_status = Some(0x0020);
        rr.pdu_session_status = Some(0x0020);
        rr.ue_usage_setting = Some(true);
        rr.nas_message_container = Some(vec![1, 2, 3]);
        let e = rr.encode();
        assert_eq!(RegistrationRequest::decode(&e).unwrap(), rr);
        // Unknown IEs are skipped: append a TLV (0x33), a type-1 (0x9f), a TLV-E (0x7c).
        let mut e2 = e.clone();
        e2.extend_from_slice(&[0x33, 0x02, 0xaa, 0xbb, 0x9f, 0x7c, 0x00, 0x01, 0xcc]);
        assert_eq!(RegistrationRequest::decode(&e2).unwrap(), rr);
        // Truncated inside a TLV → error, never panic.
        let mut e3 = e;
        e3.extend_from_slice(&[0x33, 0x09, 0xaa]);
        assert_eq!(
            RegistrationRequest::decode(&e3),
            Err(NasError::Truncated("tlv"))
        );
    }

    #[test]
    fn registration_accept_roundtrip_and_skip() {
        let ra = RegistrationAccept {
            result: 1,
            sms_allowed: true,
            nssaa_pending: false,
            guti: Some(guti()),
            equivalent_plmns: vec![plmn()],
            tai_list: vec![
                Tai {
                    plmn: plmn(),
                    tac: 1,
                },
                Tai {
                    plmn: plmn(),
                    tac: 2,
                },
            ],
            allowed_nssai: vec![Snssai { sst: 1, sd: None }],
            rejected_nssai: None,
            configured_nssai: vec![Snssai {
                sst: 1,
                sd: Some([0, 0, 1]),
            }],
            network_feature_support: Some(NetworkFeatureSupport {
                ims_vops_3gpp: true,
                ..Default::default()
            }),
            pdu_session_status: None,
            pdu_session_reactivation_result: None,
            t3512: Some(GprsTimer3 { unit: 1, value: 1 }),
            t3502: Some(GprsTimer2 { unit: 1, value: 12 }),
            non_3gpp_dereg_timer: None,
            eap_message: None,
            nssai_inclusion_mode: Some(0),
        };
        let e = ra.encode();
        assert_eq!(RegistrationAccept::decode(&e).unwrap(), ra);
        assert_eq!(ra.t3512.unwrap().to_ms(), Some(3_600_000));
        assert_eq!(ra.t3502.unwrap().to_ms(), Some(12 * 60_000));
        // A bare accept with an unknown TLV-E (0x7d) and unknown TLV (0x1b).
        let bare = hx("7e004201017d000211221b0100");
        let d = RegistrationAccept::decode(&bare).unwrap();
        assert_eq!(d.result, 1);
        assert!(d.guti.is_none());
    }

    #[test]
    fn tai_list_types() {
        // type 00: one PLMN, consecutive TACs starting at 5 (3 entries).
        let v = [0x02, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x05];
        let l = decode_tai_list(&v).unwrap();
        assert_eq!(l.iter().map(|t| t.tac).collect::<Vec<_>>(), vec![5, 6, 7]);
        // type 01: one PLMN, explicit TACs.
        let v = [0x21, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x09, 0x00, 0x00, 0x0a];
        let l = decode_tai_list(&v).unwrap();
        assert_eq!(l.iter().map(|t| t.tac).collect::<Vec<_>>(), vec![9, 10]);
        assert!(decode_tai_list(&[0x21, 0x00, 0xf1]).is_err());
    }

    #[test]
    fn auth_request_matches_legacy_parser() {
        let ar = AuthenticationRequest {
            ngksi: NgKsi {
                mapped: false,
                ksi: 0,
            },
            abba: vec![0, 0],
            rand: Some([0x11; 16]),
            autn: Some([0x22; 16]),
            eap_message: None,
        };
        let e = ar.encode();
        let legacy = crate::msgs::parse_auth_request(&e).unwrap();
        assert_eq!(legacy.rand, [0x11; 16]);
        assert_eq!(legacy.autn, [0x22; 16]);
        assert_eq!(legacy.abba, vec![0, 0]);
        assert_eq!(AuthenticationRequest::decode(&e).unwrap(), ar);
        // With a trailing EAP TLV-E, still fine.
        let mut e2 = e;
        e2.extend_from_slice(&[0x78, 0x00, 0x02, 0x01, 0x02]);
        let d = AuthenticationRequest::decode(&e2).unwrap();
        assert_eq!(d.eap_message, Some(vec![1, 2]));
    }

    #[test]
    fn auth_response_matches_legacy_bytes() {
        let rs = [0x5a; 16];
        let m = AuthenticationResponse {
            res_star: Some(rs),
            eap_message: None,
        };
        assert_eq!(m.encode(), crate::msgs::auth_response(&rs));
        assert_eq!(AuthenticationResponse::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn auth_failure_roundtrip() {
        let m = AuthenticationFailure {
            cause: cause::SYNCH_FAILURE,
            auts: Some([7; 14]),
        };
        assert_eq!(AuthenticationFailure::decode(&m.encode()).unwrap(), m);
        let m = AuthenticationFailure {
            cause: cause::MAC_FAILURE,
            auts: None,
        };
        assert_eq!(m.encode(), vec![0x7e, 0x00, 0x59, 20]);
    }

    #[test]
    fn security_mode_command_roundtrip() {
        let smc = SecurityModeCommand {
            ea: 0,
            ia: 2,
            ngksi: NgKsi {
                mapped: false,
                ksi: 0,
            },
            replayed_ue_security_capability: UeSecurityCapability::default(),
            imeisv_requested: true,
            eps_algorithms: Some(0x11),
            hdp: false,
            rinmr: true,
            eap_message: None,
            abba: Some(vec![0, 0]),
        };
        let e = smc.encode();
        assert_eq!(&e[..7], &[0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xa0]);
        assert_eq!(SecurityModeCommand::decode(&e).unwrap(), smc);
        assert!(SecurityModeCommand::decode(&e[..5]).is_err());
    }

    #[test]
    fn security_mode_complete_matches_legacy_bytes() {
        let m = SecurityModeComplete {
            imeisv: None,
            nas_message_container: Some(crate::msgs::registration_request(IMSI)),
        };
        assert_eq!(m.encode(), crate::msgs::security_mode_complete(IMSI));
        assert_eq!(SecurityModeComplete::decode(&m.encode()).unwrap(), m);
        let m2 = SecurityModeComplete {
            imeisv: Some("3534900698735912".into()),
            nas_message_container: None,
        };
        assert_eq!(SecurityModeComplete::decode(&m2.encode()).unwrap(), m2);
    }

    #[test]
    fn identity_and_config_update_roundtrip() {
        let r = IdentityRequest {
            identity_type: identity_type::SUCI,
        };
        assert_eq!(IdentityRequest::decode(&r.encode()).unwrap(), r);
        let s = IdentityResponse {
            mobile_identity: MobileIdentity::suci_from_imsi(IMSI, 2, 0),
        };
        assert_eq!(IdentityResponse::decode(&s.encode()).unwrap(), s);
        let c = ConfigurationUpdateCommand {
            ack_requested: true,
            registration_requested: false,
            guti: Some(guti()),
            tai_list: vec![Tai {
                plmn: plmn(),
                tac: 1,
            }],
            allowed_nssai: Some(vec![Snssai { sst: 1, sd: None }]),
            configured_nssai: None,
            full_network_name: Some(vec![0x80, 0x41]),
            short_network_name: None,
            local_time_zone: Some(0x40),
            universal_time_and_tz: Some([0x22, 0x01, 0x01, 0x00, 0x00, 0x00, 0x40]),
            daylight_saving_time: Some(0),
        };
        assert_eq!(ConfigurationUpdateCommand::decode(&c.encode()).unwrap(), c);
        assert_eq!(configuration_update_complete(), vec![0x7e, 0x00, 0x55]);
    }

    #[test]
    fn deregistration_roundtrip() {
        let d = DeregistrationRequestUeOriginating {
            dereg_type: DeregistrationType {
                access_type: 1,
                reregistration_required: false,
                switch_off: true,
            },
            ngksi: NgKsi {
                mapped: false,
                ksi: 1,
            },
            mobile_identity: MobileIdentity::Guti(guti()),
        };
        assert_eq!(
            DeregistrationRequestUeOriginating::decode(&d.encode()).unwrap(),
            d
        );
        let n = DeregistrationRequestUeTerminated {
            dereg_type: DeregistrationType {
                access_type: 1,
                reregistration_required: true,
                switch_off: false,
            },
            cause: Some(cause::ILLEGAL_UE),
            t3346: Some(GprsTimer2 { unit: 0, value: 5 }),
        };
        assert_eq!(
            DeregistrationRequestUeTerminated::decode(&n.encode()).unwrap(),
            n
        );
        assert_eq!(deregistration_accept(true), vec![0x7e, 0x00, 0x48]);
        assert_eq!(deregistration_accept(false), vec![0x7e, 0x00, 0x46]);
    }

    #[test]
    fn service_messages_roundtrip() {
        let sr = ServiceRequest {
            ngksi: NgKsi {
                mapped: false,
                ksi: 0,
            },
            service_type: service_type::DATA,
            s_tmsi: MobileIdentity::STmsi {
                amf_set_id: 1,
                amf_pointer: 0,
                tmsi: 0xdead_beef,
            },
            uplink_data_status: Some(0x0020),
            pdu_session_status: None,
        };
        assert_eq!(ServiceRequest::decode(&sr.encode()).unwrap(), sr);
        let sa = ServiceAccept {
            pdu_session_status: Some(0x20),
            pdu_session_reactivation_result: None,
            t3448: None,
        };
        assert_eq!(ServiceAccept::decode(&sa.encode()).unwrap(), sa);
        let sj = ServiceReject {
            cause: 9,
            pdu_session_status: None,
            t3346: Some(GprsTimer2 { unit: 1, value: 2 }),
        };
        assert_eq!(ServiceReject::decode(&sj.encode()).unwrap(), sj);
    }

    #[test]
    fn ul_nas_transport_matches_reference_vector() {
        let sm = crate::sm::PduSessionEstablishmentRequest::ipv4(5, 1).encode();
        let m = UlNasTransport {
            payload_container_type: payload_container_type::N1_SM_INFORMATION,
            payload_container: sm,
            pdu_session_id: Some(5),
            old_pdu_session_id: None,
            request_type: Some(request_type::INITIAL_REQUEST),
            snssai: Some(Snssai { sst: 1, sd: None }),
            dnn: Some("internet".into()),
        };
        let expect = hx("7e00670100082e0501c1ffff91a1120581220101250908696e7465726e6574");
        assert_eq!(m.encode(), expect);
        assert_eq!(
            m.encode(),
            crate::msgs::ul_nas_transport_pdu_session(5, 1, "internet")
        );
        assert_eq!(UlNasTransport::decode(&expect).unwrap(), m);
    }

    #[test]
    fn dl_nas_transport_roundtrip() {
        let m = DlNasTransport {
            payload_container_type: 1,
            payload_container: vec![0x2e, 0x05, 0x01, 0xc3, 0x1a],
            pdu_session_id: Some(5),
            additional_information: None,
            cause: Some(91),
            back_off_timer: Some(GprsTimer3 { unit: 3, value: 10 }),
        };
        assert_eq!(DlNasTransport::decode(&m.encode()).unwrap(), m);
        assert_eq!(
            crate::msgs::nas_transport_payload(&m.encode()).unwrap(),
            &[0x2e, 0x05, 0x01, 0xc3, 0x1a]
        );
    }

    #[test]
    fn status_notification_and_dispatch() {
        assert_eq!(
            MmStatus::decode(&MmStatus { cause: 97 }.encode())
                .unwrap()
                .cause,
            97
        );
        assert_eq!(
            Notification::decode(&Notification { access_type: 1 }.encode())
                .unwrap()
                .access_type,
            1
        );
        assert!(matches!(
            decode_mm(&[0x7e, 0x00, 0x43]),
            Ok(MmMessage::RegistrationComplete)
        ));
        assert!(matches!(
            decode_mm(&[0x7e, 0x00, 0x99]),
            Ok(MmMessage::Unknown { msg_type: 0x99 })
        ));
        assert!(matches!(
            decode_mm(&[0x7e, 0x00]),
            Err(NasError::Truncated(_))
        ));
        assert!(matches!(
            decode_mm(&[0x2e, 0x00, 0x41]),
            Err(NasError::BadHeader)
        ));
        assert!(matches!(
            decode_mm(&[0x7e, 0x00, 0x56, 0x00]),
            Err(NasError::Truncated(_))
        ));
    }

    #[test]
    fn security_header_split() {
        let plain = [0x7e, 0x00, 0x43];
        let (h, p) = split_security_header(&plain).unwrap();
        assert!(h.is_none());
        assert_eq!(p, &plain);
        let prot = [0x7e, 0x02, 1, 2, 3, 4, 0x05, 0x7e, 0x00, 0x43];
        let (h, p) = split_security_header(&prot).unwrap();
        let h = h.unwrap();
        assert_eq!(h.sht, SecurityHeaderType::IntegrityCiphered);
        assert_eq!(h.mac, [1, 2, 3, 4]);
        assert_eq!(h.seq, 5);
        assert_eq!(p, &[0x7e, 0x00, 0x43]);
        assert_eq!(
            split_security_header(&[0x7e, 0x02, 1, 2]),
            Err(NasError::Truncated("mac"))
        );
        assert_eq!(
            split_security_header(&[0x7e, 0x07, 1, 2, 3, 4, 5]),
            Err(NasError::BadHeader)
        );
    }

    #[test]
    fn dnn_codec() {
        assert_eq!(encode_dnn("internet"), hx("08696e7465726e6574"));
        assert_eq!(
            decode_dnn(&encode_dnn("ims.mnc001.mcc001")).unwrap(),
            "ims.mnc001.mcc001"
        );
        assert!(decode_dnn(&[0x05, 0x61]).is_err());
    }
}
