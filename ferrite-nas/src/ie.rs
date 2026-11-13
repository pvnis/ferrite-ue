//! TS 24.007 §11.2 information-element toolkit: a bounds-checked byte
//! [`Reader`], a [`Writer`] for the standard IE formats (T, V, TV, LV, TLV,
//! LV-E, TLV-E), and an [`OptIes`] iterator that walks the optional part of a
//! NAS message skipping any IE it does not know about.
//!
//! The skipping rule follows TS 24.007 §11.2.4 (and the 5GS IEI allocation in
//! TS 24.501 §9.11): an IEI octet with bit 8 set is a type 1 or type 2 IE (one
//! octet in total); IEIs `0x70..=0x7F` are type 6 (TLV-E, two length octets);
//! every other IEI is type 4 (TLV, one length octet) unless the message
//! declares it as type 3 (TV with a fixed value length).

use core::fmt;

/// NAS layer error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasError {
    /// The PDU ended before a mandatory field or a declared length.
    Truncated(&'static str),
    /// The extended protocol discriminator / security header is malformed.
    BadHeader,
    /// A message of this type was not expected in the current state.
    UnexpectedMessage(u8),
    /// The message type is not implemented by this decoder.
    UnknownMessageType(u8),
    /// A mandatory IE carries a value outside its defined range.
    InvalidValue(&'static str),
    /// The NAS MAC did not verify (TS 24.501 §4.4.3.3).
    MacFailure,
    /// A protected message arrived but no security context is in use.
    NoSecurityContext,
    /// The selected NAS algorithm is not implemented or not allowed.
    UnsupportedAlgorithm { ea: u8, ia: u8 },
    /// A downlink NAS COUNT was not fresh (replay).
    Replay,
    /// A message that must be integrity protected arrived in plain text.
    Unprotected(u8),
    /// The UE is not in a state where this procedure can be started.
    InvalidState,
}

impl fmt::Display for NasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NasError::Truncated(what) => write!(f, "nas: truncated at {what}"),
            NasError::BadHeader => write!(f, "nas: malformed header"),
            NasError::UnexpectedMessage(t) => write!(f, "nas: unexpected message type {t:#04x}"),
            NasError::UnknownMessageType(t) => write!(f, "nas: unknown message type {t:#04x}"),
            NasError::InvalidValue(what) => write!(f, "nas: invalid value in {what}"),
            NasError::MacFailure => write!(f, "nas: integrity check failed"),
            NasError::NoSecurityContext => write!(f, "nas: no security context"),
            NasError::UnsupportedAlgorithm { ea, ia } => {
                write!(f, "nas: unsupported algorithms NEA{ea}/NIA{ia}")
            }
            NasError::Replay => write!(f, "nas: replayed downlink NAS COUNT"),
            NasError::Unprotected(t) => {
                write!(f, "nas: message {t:#04x} must be integrity protected")
            }
            NasError::InvalidState => write!(f, "nas: procedure not allowed in this state"),
        }
    }
}

impl std::error::Error for NasError {}

/// Bounds-checked cursor over a NAS PDU. Every accessor returns
/// [`NasError::Truncated`] instead of panicking when the data runs out.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Octets not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True when every octet has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Peek at the next octet without consuming it.
    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume one octet.
    pub fn u8(&mut self, what: &'static str) -> Result<u8, NasError> {
        let b = *self.buf.get(self.pos).ok_or(NasError::Truncated(what))?;
        self.pos += 1;
        Ok(b)
    }

    /// Consume a big-endian 16-bit value.
    pub fn u16(&mut self, what: &'static str) -> Result<u16, NasError> {
        let hi = self.u8(what)?;
        let lo = self.u8(what)?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    /// Consume `n` octets.
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], NasError> {
        let end = self.pos.checked_add(n).ok_or(NasError::Truncated(what))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(NasError::Truncated(what))?;
        self.pos = end;
        Ok(s)
    }

    /// Consume a fixed-size array.
    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], NasError> {
        let s = self.take(N, what)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Consume an LV field (one length octet followed by the value).
    pub fn lv(&mut self, what: &'static str) -> Result<&'a [u8], NasError> {
        let n = self.u8(what)? as usize;
        self.take(n, what)
    }

    /// Consume an LV-E field (two length octets followed by the value).
    pub fn lv_e(&mut self, what: &'static str) -> Result<&'a [u8], NasError> {
        let n = self.u16(what)? as usize;
        self.take(n, what)
    }

    /// Everything that is left, consuming it.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        s
    }
}

/// Encoder for the TS 24.007 IE formats. Length fields are clamped to their
/// maximum (with an error log) rather than panicking; callers that produce
/// over-long values have a configuration bug, not a protocol one.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Writer {
            buf: Vec::with_capacity(64),
        }
    }

    /// Start from an existing prefix (e.g. a message header).
    pub fn from_vec(buf: Vec<u8>) -> Self {
        Writer { buf }
    }

    /// One octet (V format, or a T/type-2 IEI).
    pub fn u8(&mut self, b: u8) -> &mut Self {
        self.buf.push(b);
        self
    }

    /// Big-endian 16-bit value.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Raw octets (V format with a known length).
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Type 2 IE: the IEI alone.
    pub fn t(&mut self, iei: u8) -> &mut Self {
        self.u8(iei)
    }

    /// Type 1 IE: IEI in the high nibble, value in the low nibble.
    pub fn tv1(&mut self, iei_hi: u8, nibble: u8) -> &mut Self {
        self.u8((iei_hi & 0xf0) | (nibble & 0x0f))
    }

    /// Type 3 IE: IEI followed by a fixed-length value.
    pub fn tv(&mut self, iei: u8, v: &[u8]) -> &mut Self {
        self.u8(iei).bytes(v)
    }

    /// LV: one length octet followed by the value.
    pub fn lv(&mut self, v: &[u8]) -> &mut Self {
        let n = clamp_len(v.len(), 0xff);
        self.u8(n as u8).bytes(&v[..n])
    }

    /// LV-E: two length octets followed by the value.
    pub fn lv_e(&mut self, v: &[u8]) -> &mut Self {
        let n = clamp_len(v.len(), 0xffff);
        self.u16(n as u16).bytes(&v[..n])
    }

    /// Type 4 IE: IEI, one length octet, value.
    pub fn tlv(&mut self, iei: u8, v: &[u8]) -> &mut Self {
        self.u8(iei).lv(v)
    }

    /// Type 6 IE: IEI, two length octets, value.
    pub fn tlv_e(&mut self, iei: u8, v: &[u8]) -> &mut Self {
        self.u8(iei).lv_e(v)
    }

    /// Finish and return the encoded octets.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Octets written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

fn clamp_len(n: usize, max: usize) -> usize {
    if n > max {
        log::error!("nas: IE value of {n} octets exceeds the {max}-octet length field; truncating");
        max
    } else {
        n
    }
}

/// Declared format of a known optional IE (only needed for formats the
/// generic TS 24.007 rule cannot infer from the IEI alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeFmt {
    /// Type 3: IEI followed by exactly `n` value octets.
    Tv(usize),
    /// Type 4: IEI, one length octet.
    Tlv,
    /// Type 6: IEI, two length octets.
    TlvE,
}

/// One optional IE as located by [`OptIes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptIe<'a> {
    /// The IEI. For type 1/2 IEs (bit 8 set) this is the *high nibble only*
    /// (e.g. `0x80` for IEI "8-"); the low nibble is in [`OptIe::nibble`].
    pub iei: u8,
    /// Low nibble of a type 1 IE (0 for every other format).
    pub nibble: u8,
    /// Value octets (empty for type 1/2 IEs).
    pub value: &'a [u8],
}

/// Iterator over the optional IEs of a message body, skipping unknown ones.
/// Yields `Err(Truncated)` only when a declared length overruns the buffer.
pub struct OptIes<'a> {
    rd: Reader<'a>,
    known: &'a [(u8, IeFmt)],
    failed: bool,
}

impl<'a> OptIes<'a> {
    /// Walk `rest` using `known` for the IEIs whose format is not inferable.
    pub fn new(rest: &'a [u8], known: &'a [(u8, IeFmt)]) -> Self {
        OptIes {
            rd: Reader::new(rest),
            known,
            failed: false,
        }
    }

    fn fmt_of(&self, iei: u8) -> IeFmt {
        for (k, f) in self.known {
            if *k == iei {
                return *f;
            }
        }
        if (0x70..=0x7f).contains(&iei) {
            IeFmt::TlvE
        } else {
            IeFmt::Tlv
        }
    }
}

impl<'a> Iterator for OptIes<'a> {
    type Item = Result<OptIe<'a>, NasError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rd.is_empty() {
            return None;
        }
        let b = match self.rd.u8("iei") {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };
        if b & 0x80 != 0 {
            return Some(Ok(OptIe {
                iei: b & 0xf0,
                nibble: b & 0x0f,
                value: &[],
            }));
        }
        let r = match self.fmt_of(b) {
            IeFmt::Tv(n) => self.rd.take(n, "tv"),
            IeFmt::Tlv => self.rd.lv("tlv"),
            IeFmt::TlvE => self.rd.lv_e("tlv-e"),
        };
        match r {
            Ok(value) => Some(Ok(OptIe {
                iei: b,
                nibble: 0,
                value,
            })),
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

/// Pack two decimal digits into one BCD octet, `lo` in bits 1-4 and `hi` in
/// bits 5-8 (TS 24.008 §10.5.1.4 digit order).
pub fn bcd(lo: u8, hi: u8) -> u8 {
    (hi << 4) | (lo & 0x0f)
}

/// Encode a digit string in BCD, low nibble first, padding an odd final
/// nibble with `0xf`. Non-digit characters are ignored.
pub fn bcd_digits(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    d.chunks(2)
        .map(|p| bcd(p[0], *p.get(1).unwrap_or(&0xf)))
        .collect()
}

/// Decode BCD octets (low nibble first) into a digit string, stopping at the
/// first `0xf` filler nibble.
pub fn bcd_to_string(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    for &b in v {
        for n in [b & 0x0f, b >> 4] {
            if n == 0xf {
                return s;
            }
            s.push((b'0' + n.min(9)) as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u8("a"), Ok(1));
        assert_eq!(r.u16("b"), Ok(0x0203));
        assert_eq!(r.u8("c"), Err(NasError::Truncated("c")));
        let mut r = Reader::new(&[2, 9]);
        assert_eq!(r.lv("lv"), Err(NasError::Truncated("lv")));
        let mut r = Reader::new(&[0, 2, 9, 8, 7]);
        assert_eq!(r.lv_e("lve"), Ok(&[9, 8][..]));
        assert_eq!(r.rest(), &[7]);
        assert!(r.is_empty());
    }

    #[test]
    fn writer_formats() {
        let mut w = Writer::new();
        w.t(0x9a)
            .tv1(0x80, 0x1)
            .tv(0x12, &[5])
            .lv(&[1, 2])
            .tlv(0x25, &[9])
            .tlv_e(0x71, &[7, 7, 7])
            .lv_e(&[]);
        assert_eq!(
            w.into_vec(),
            vec![0x9a, 0x81, 0x12, 5, 2, 1, 2, 0x25, 1, 9, 0x71, 0, 3, 7, 7, 7, 0, 0]
        );
    }

    #[test]
    fn optional_ies_skip_unknown() {
        // type1 (0x8-), unknown TLV (0x33), known TV(2) (0x12), unknown TLV-E (0x7c), type2 (0xa0)
        let body = [
            0x81, 0x33, 0x02, 0xaa, 0xbb, 0x12, 0x05, 0x7c, 0x00, 0x01, 0xcc, 0xa0,
        ];
        let ies: Vec<_> = OptIes::new(&body, &[(0x12, IeFmt::Tv(1))])
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ies.len(), 5);
        assert_eq!((ies[0].iei, ies[0].nibble), (0x80, 1));
        assert_eq!((ies[1].iei, ies[1].value), (0x33, &[0xaa, 0xbb][..]));
        assert_eq!((ies[2].iei, ies[2].value), (0x12, &[0x05][..]));
        assert_eq!((ies[3].iei, ies[3].value), (0x7c, &[0xcc][..]));
        assert_eq!((ies[4].iei, ies[4].nibble), (0xa0, 0));
    }

    #[test]
    fn optional_ies_truncated() {
        let body = [0x33, 0x05, 0xaa];
        let mut it = OptIes::new(&body, &[]);
        assert!(matches!(it.next(), Some(Err(NasError::Truncated(_)))));
        assert!(it.next().is_none());
    }

    #[test]
    fn bcd_roundtrip() {
        assert_eq!(bcd_digits("12345"), vec![0x21, 0x43, 0xf5]);
        assert_eq!(bcd_to_string(&[0x21, 0x43, 0xf5]), "12345");
        assert_eq!(bcd_to_string(&[0x21, 0x43]), "1234");
    }
}
