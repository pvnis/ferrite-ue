//! X.691 UNALIGNED PER (UPER) primitives shared by every TS 38.331 codec in this
//! crate. Hand-rolled, clean-room from the X.691 rules:
//!
//! * constrained whole numbers in ⌈log2(range)⌉ bits (§10.5),
//! * normally-small non-negative whole numbers (§10.6),
//! * general length determinants (§10.9) — the fragmented `'11'` form is
//!   rejected with [`DecodeErrorKind::FragmentedLength`],
//! * extensible types with a leading extension bit; extension additions are
//!   length-prefixed open types and therefore the only skippable thing in UPER
//!   (§18.7 … §18.9) — the parsers lean on this for release-16+ additions,
//! * OCTET STRING / BIT STRING, and open types (a contained message inside an
//!   OCTET STRING).
//!
//! [`BitReader`] and [`BitWriter`] share one vocabulary (`bit`, `bits`, `int`,
//! `enu`, `enu_ext`, `len_det`, `octet_string`, `bitstring`, …) so that an
//! encoder reads as the mirror image of its decoder.

use std::fmt;

/// Why a decode failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The PDU ended before the IE was complete.
    EndOfData,
    /// A legal ASN.1 branch this crate deliberately does not implement.
    Unsupported(&'static str),
    /// A value outside its TS 38.331 range / an impossible combination.
    Invalid(&'static str),
    /// A fragmented length determinant (`'11'` form, ≥ 16384 items).
    FragmentedLength,
}

/// A decode failure, with the IE path (`RRCSetup/masterCellGroup/…`) and the
/// bit offset at which it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub kind: DecodeErrorKind,
    /// Slash-separated IE names from the message down to the failing field.
    pub path: String,
    /// Bit position in the PDU being decoded when the failure was detected.
    pub bit_pos: usize,
}

impl DecodeError {
    pub fn new(kind: DecodeErrorKind, bit_pos: usize) -> Self {
        Self {
            kind,
            path: String::new(),
            bit_pos,
        }
    }

    pub fn unsupported(what: &'static str, bit_pos: usize) -> Self {
        Self::new(DecodeErrorKind::Unsupported(what), bit_pos)
    }

    pub fn invalid(what: &'static str, bit_pos: usize) -> Self {
        Self::new(DecodeErrorKind::Invalid(what), bit_pos)
    }

    /// Prepend an IE name to the path.
    pub fn in_ie(mut self, name: &str) -> Self {
        if self.path.is_empty() {
            self.path = name.to_owned();
        } else {
            self.path = format!("{name}/{}", self.path);
        }
        self
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match &self.kind {
            DecodeErrorKind::EndOfData => "unexpected end of data".to_owned(),
            DecodeErrorKind::Unsupported(s) => format!("unsupported: {s}"),
            DecodeErrorKind::Invalid(s) => format!("invalid: {s}"),
            DecodeErrorKind::FragmentedLength => "fragmented length determinant".to_owned(),
        };
        write!(f, "{what} at bit {} in {}", self.bit_pos, self.path)
    }
}

impl std::error::Error for DecodeError {}

/// Result alias for every decoder in this crate.
pub type DecodeResult<T> = Result<T, DecodeError>;

/// Adds an IE name to the error path of a decode result: `parse_x(r).ctx("x")`.
pub trait Ctx {
    fn ctx(self, name: &str) -> Self;
}

impl<T> Ctx for DecodeResult<T> {
    fn ctx(self, name: &str) -> Self {
        self.map_err(|e| e.in_ie(name))
    }
}

/// `SetupRelease { T } ::= CHOICE { release NULL, setup T }` (TS 38.331 §6.3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupRelease<T> {
    Release,
    Setup(T),
}

impl<T> SetupRelease<T> {
    /// The configured value when this is `setup`.
    pub fn setup(&self) -> Option<&T> {
        match self {
            SetupRelease::Setup(v) => Some(v),
            SetupRelease::Release => None,
        }
    }
}

/// X.691 unaligned-PER bit reader. Every read past the end fails with
/// [`DecodeErrorKind::EndOfData`]; nothing panics on malformed input.
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current bit offset from the start of the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bits left in the buffer.
    pub fn remaining(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.pos)
    }

    fn eof(&self) -> DecodeError {
        DecodeError::new(DecodeErrorKind::EndOfData, self.pos)
    }

    /// One bit (also a BOOLEAN, an extension marker, an OPTIONAL presence flag).
    pub fn bit(&mut self) -> DecodeResult<bool> {
        let byte = *self.data.get(self.pos / 8).ok_or_else(|| self.eof())?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Ok(v == 1)
    }

    /// `n ≤ 64` bits, MSB first.
    pub fn bits(&mut self, n: u32) -> DecodeResult<u64> {
        if n > 64 {
            return Err(DecodeError::invalid("bit field wider than 64", self.pos));
        }
        if self.remaining() < n as usize {
            return Err(self.eof());
        }
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Ok(v)
    }

    /// Fixed-size BIT STRING of `n ≤ 64` bits, returned MSB-first in the low
    /// `n` bits (bit 0 of the string is the most significant).
    pub fn bitstring(&mut self, n: u32) -> DecodeResult<u64> {
        self.bits(n)
    }

    /// Fixed-size BIT STRING of any length, as bytes (bit 0 of the string is the
    /// MSB of byte 0; the last byte is zero-padded).
    pub fn bitstring_bytes(&mut self, n: usize) -> DecodeResult<Vec<u8>> {
        if self.remaining() < n {
            return Err(self.eof());
        }
        let mut out = vec![0u8; n.div_ceil(8)];
        for (i, slot) in (0..n).zip(0..) {
            if self.bit()? {
                out[slot / 8] |= 0x80 >> (i % 8);
            }
        }
        Ok(out)
    }

    /// Constrained whole number in `lo..=hi` (§10.5): ⌈log2(range)⌉ bits, offset `lo`.
    pub fn int(&mut self, lo: i64, hi: i64) -> DecodeResult<i64> {
        if hi < lo {
            return Err(DecodeError::invalid("empty integer range", self.pos));
        }
        let range = (hi - lo) as u64 + 1;
        if range <= 1 {
            return Ok(lo);
        }
        let n = 64 - (range - 1).leading_zeros();
        let v = lo + self.bits(n)? as i64;
        if v > hi {
            return Err(DecodeError::invalid(
                "integer above its upper bound",
                self.pos,
            ));
        }
        Ok(v)
    }

    /// Constrained non-negative whole number in `lo..=hi`, as `u32`.
    pub fn uint(&mut self, lo: u32, hi: u32) -> DecodeResult<u32> {
        Ok(self.int(lo as i64, hi as i64)? as u32)
    }

    /// Constrained non-negative whole number in `lo..=hi`, as `u8`.
    pub fn u8(&mut self, lo: u8, hi: u8) -> DecodeResult<u8> {
        Ok(self.int(lo as i64, hi as i64)? as u8)
    }

    /// Constrained non-negative whole number in `lo..=hi`, as `u16`.
    pub fn u16(&mut self, lo: u16, hi: u16) -> DecodeResult<u16> {
        Ok(self.int(lo as i64, hi as i64)? as u16)
    }

    /// BOOLEAN.
    pub fn boolean(&mut self) -> DecodeResult<bool> {
        self.bit()
    }

    /// Non-extensible ENUMERATED with `n` root values (index).
    pub fn enu(&mut self, n: u32) -> DecodeResult<u32> {
        if n == 0 {
            return Err(DecodeError::invalid("empty enumeration", self.pos));
        }
        self.uint(0, n - 1)
    }

    /// Extensible ENUMERATED: `Some(root index)` or `None` for an extension
    /// value (whose identity is unknown to this crate; its normally-small index
    /// is consumed).
    pub fn enu_ext(&mut self, n_root: u32) -> DecodeResult<Option<u32>> {
        if self.bit()? {
            let _ = self.normally_small()?;
            return Ok(None);
        }
        Ok(Some(self.enu(n_root)?))
    }

    /// Normally-small non-negative whole number (§10.6): `'0'` + 6 bits, else a
    /// length-prefixed semi-constrained number.
    pub fn normally_small(&mut self) -> DecodeResult<u64> {
        if !self.bit()? {
            self.bits(6)
        } else {
            let len = self.len_det()?;
            if len == 0 || len > 8 {
                return Err(DecodeError::invalid(
                    "normally-small number length",
                    self.pos,
                ));
            }
            self.bits(len as u32 * 8)
        }
    }

    /// General (unconstrained) length determinant (§10.9, unaligned):
    /// `'0'`+7 bits (<128) or `'10'`+14 bits (<16384). The fragmented `'11'`
    /// form is an error.
    pub fn len_det(&mut self) -> DecodeResult<usize> {
        if !self.bit()? {
            Ok(self.bits(7)? as usize)
        } else if !self.bit()? {
            Ok(self.bits(14)? as usize)
        } else {
            Err(DecodeError::new(
                DecodeErrorKind::FragmentedLength,
                self.pos,
            ))
        }
    }

    /// Length of a `SIZE (lo..hi)` constrained SEQUENCE OF / string with
    /// `hi < 65536`: a constrained whole number (no bits when `lo == hi`).
    pub fn len_constrained(&mut self, lo: usize, hi: usize) -> DecodeResult<usize> {
        Ok(self.int(lo as i64, hi as i64)? as usize)
    }

    /// `n` raw octets at the current (unaligned) position.
    pub fn octets(&mut self, n: usize) -> DecodeResult<Vec<u8>> {
        if self.remaining() < n * 8 {
            return Err(self.eof());
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.bits(8)? as u8);
        }
        Ok(out)
    }

    /// Unconstrained OCTET STRING: general length determinant + octets. Also
    /// the encoding of an open type (`OCTET STRING (CONTAINING …)`).
    pub fn octet_string(&mut self) -> DecodeResult<Vec<u8>> {
        let n = self.len_det()?;
        self.octets(n)
    }

    /// `OCTET STRING (SIZE (lo..hi))`.
    pub fn octet_string_sized(&mut self, lo: usize, hi: usize) -> DecodeResult<Vec<u8>> {
        let n = self.len_constrained(lo, hi)?;
        self.octets(n)
    }

    /// Skip one open-type value (length determinant counts octets).
    pub fn skip_open(&mut self) -> DecodeResult<()> {
        let len = self.len_det()?;
        if self.remaining() < len * 8 {
            return Err(self.eof());
        }
        self.pos += len * 8;
        Ok(())
    }

    /// Skip a SEQUENCE's extension additions (call when its extension bit was
    /// 1): a normally-small count−1, that many presence bits, then each present
    /// addition as an open type.
    pub fn skip_ext_additions(&mut self) -> DecodeResult<()> {
        self.ext_additions(|_, _| Ok(()))
    }

    /// Walk a SEQUENCE's extension additions, handing each *present* addition
    /// group `i` (0-based, in definition order) to `f` as a sub-reader over the
    /// open type's octets. Groups `f` does not consume are simply skipped.
    pub fn ext_additions<F>(&mut self, mut f: F) -> DecodeResult<()>
    where
        F: FnMut(usize, &mut BitReader<'_>) -> DecodeResult<()>,
    {
        let n = self.normally_small()? + 1;
        if n > 4096 {
            return Err(DecodeError::invalid("extension addition count", self.pos));
        }
        let mut present = Vec::with_capacity(n as usize);
        for _ in 0..n {
            present.push(self.bit()?);
        }
        for (i, p) in present.into_iter().enumerate() {
            if p {
                let octets = self.octet_string()?;
                let mut sub = BitReader::new(&octets);
                f(i, &mut sub)?;
            }
        }
        Ok(())
    }

    /// The OPTIONAL/DEFAULT presence bitmap of a SEQUENCE (read *after* its
    /// extension bit, *before* any component value).
    pub fn opt_bits<const N: usize>(&mut self) -> DecodeResult<[bool; N]> {
        let mut out = [false; N];
        for o in out.iter_mut() {
            *o = self.bit()?;
        }
        Ok(out)
    }

    /// `SEQUENCE (SIZE (lo..hi)) OF`: constrained count then `f` per element.
    pub fn seq_of<T, F>(&mut self, lo: usize, hi: usize, mut f: F) -> DecodeResult<Vec<T>>
    where
        F: FnMut(&mut BitReader<'a>) -> DecodeResult<T>,
    {
        let n = self.len_constrained(lo, hi)?;
        let mut out = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    /// `SetupRelease { T }`: `'0'` = release, `'1'` = setup followed by `f`.
    pub fn setup_release<T, F>(&mut self, f: F) -> DecodeResult<SetupRelease<T>>
    where
        F: FnOnce(&mut BitReader<'a>) -> DecodeResult<T>,
    {
        if self.bit()? {
            Ok(SetupRelease::Setup(f(self)?))
        } else {
            Ok(SetupRelease::Release)
        }
    }

    /// `Some(f(self))` when `present`, else `None`.
    pub fn opt<T, F>(&mut self, present: bool, f: F) -> DecodeResult<Option<T>>
    where
        F: FnOnce(&mut BitReader<'a>) -> DecodeResult<T>,
    {
        if present {
            Ok(Some(f(self)?))
        } else {
            Ok(None)
        }
    }

    /// Fail with [`DecodeErrorKind::Unsupported`] at the current position.
    pub fn unsupported<T>(&self, what: &'static str) -> DecodeResult<T> {
        Err(DecodeError::unsupported(what, self.pos))
    }

    /// Fail with [`DecodeErrorKind::Invalid`] at the current position.
    pub fn invalid<T>(&self, what: &'static str) -> DecodeResult<T> {
        Err(DecodeError::invalid(what, self.pos))
    }
}

/// X.691 unaligned-PER bit writer: the mirror image of [`BitReader`].
///
/// The primitives are infallible; a value outside its declared range is an
/// encoder bug and is masked to the field width (checked in debug builds).
#[derive(Clone, Debug, Default)]
pub struct BitWriter {
    buf: Vec<u8>,
    nbits: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bits written so far.
    pub fn len_bits(&self) -> usize {
        self.nbits
    }

    /// One bit (BOOLEAN / extension marker / OPTIONAL presence flag).
    pub fn bit(&mut self, b: bool) {
        if self.nbits.is_multiple_of(8) {
            self.buf.push(0);
        }
        if b {
            let last = self.buf.len() - 1;
            self.buf[last] |= 0x80 >> (self.nbits % 8);
        }
        self.nbits += 1;
    }

    /// The low `n ≤ 64` bits of `v`, MSB first.
    pub fn bits(&mut self, v: u64, n: u32) {
        debug_assert!(n <= 64);
        for i in (0..n).rev() {
            self.bit((v >> i) & 1 == 1);
        }
    }

    /// Fixed-size BIT STRING of `n ≤ 64` bits (bit 0 of the string = MSB of `v`'s low `n` bits).
    pub fn bitstring(&mut self, v: u64, n: u32) {
        self.bits(v, n)
    }

    /// Fixed-size BIT STRING of `n` bits from MSB-first bytes.
    pub fn bitstring_bytes(&mut self, bytes: &[u8], n: usize) {
        for i in 0..n {
            let b = bytes.get(i / 8).is_some_and(|x| x & (0x80 >> (i % 8)) != 0);
            self.bit(b);
        }
    }

    /// Constrained whole number in `lo..=hi` (§10.5).
    pub fn int(&mut self, v: i64, lo: i64, hi: i64) {
        debug_assert!(lo <= v && v <= hi, "value {v} outside {lo}..={hi}");
        let range = (hi - lo) as u64 + 1;
        if range <= 1 {
            return;
        }
        let n = 64 - (range - 1).leading_zeros();
        self.bits((v.clamp(lo, hi) - lo) as u64, n);
    }

    /// Constrained non-negative whole number in `lo..=hi`.
    pub fn uint(&mut self, v: u32, lo: u32, hi: u32) {
        self.int(v as i64, lo as i64, hi as i64)
    }

    /// BOOLEAN.
    pub fn boolean(&mut self, b: bool) {
        self.bit(b)
    }

    /// Non-extensible ENUMERATED with `n` root values.
    pub fn enu(&mut self, idx: u32, n: u32) {
        self.uint(idx, 0, n.saturating_sub(1))
    }

    /// Extensible ENUMERATED, a root value (`'0'` + index).
    pub fn enu_ext(&mut self, idx: u32, n_root: u32) {
        self.bit(false);
        self.enu(idx, n_root)
    }

    /// Normally-small non-negative whole number (§10.6).
    pub fn normally_small(&mut self, v: u64) {
        if v < 64 {
            self.bit(false);
            self.bits(v, 6);
        } else {
            self.bit(true);
            let nbytes = (8 - (v.leading_zeros() / 8)).max(1) as usize;
            self.len_det(nbytes);
            self.bits(v, nbytes as u32 * 8);
        }
    }

    /// General length determinant (§10.9, unaligned). Lengths ≥ 16384 would
    /// need fragmentation, which no TS 38.331 PDU this crate produces reaches.
    pub fn len_det(&mut self, n: usize) {
        debug_assert!(n < 16384, "length {n} needs fragmentation");
        if n < 128 {
            self.bit(false);
            self.bits(n as u64, 7);
        } else {
            self.bits(0b10, 2);
            self.bits((n & 0x3fff) as u64, 14);
        }
    }

    /// Length of a `SIZE (lo..hi)` constrained SEQUENCE OF / string.
    pub fn len_constrained(&mut self, n: usize, lo: usize, hi: usize) {
        self.int(n as i64, lo as i64, hi as i64)
    }

    /// Raw octets (no length).
    pub fn octets(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.bits(b as u64, 8);
        }
    }

    /// Unconstrained OCTET STRING (also an open type): length determinant + octets.
    pub fn octet_string(&mut self, bytes: &[u8]) {
        self.len_det(bytes.len());
        self.octets(bytes);
    }

    /// `OCTET STRING (SIZE (lo..hi))`.
    pub fn octet_string_sized(&mut self, bytes: &[u8], lo: usize, hi: usize) {
        self.len_constrained(bytes.len(), lo, hi);
        self.octets(bytes);
    }

    /// The OPTIONAL presence bitmap of a SEQUENCE.
    pub fn opt_bits(&mut self, flags: &[bool]) {
        for &f in flags {
            self.bit(f);
        }
    }

    /// `SEQUENCE (SIZE (lo..hi)) OF`: count then `f` per element.
    pub fn seq_of<T, F>(&mut self, items: &[T], lo: usize, hi: usize, mut f: F)
    where
        F: FnMut(&mut BitWriter, &T),
    {
        self.len_constrained(items.len(), lo, hi);
        for it in items {
            f(self, it);
        }
    }

    /// `SetupRelease { T }`.
    pub fn setup_release<T, F>(&mut self, v: &SetupRelease<T>, f: F)
    where
        F: FnOnce(&mut BitWriter, &T),
    {
        match v {
            SetupRelease::Release => self.bit(false),
            SetupRelease::Setup(t) => {
                self.bit(true);
                f(self, t);
            }
        }
    }

    /// Pad to an octet boundary and return the encoding. An empty encoding
    /// becomes a single zero octet (X.691 §10.1.3).
    pub fn finish(mut self) -> Vec<u8> {
        while !self.nbits.is_multiple_of(8) {
            self.bit(false);
        }
        if self.buf.is_empty() {
            self.buf.push(0);
        }
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip() {
        let mut w = BitWriter::new();
        w.bit(true);
        w.bits(0b1011, 4);
        w.int(-5, -10, 10);
        w.uint(37949, 0, 37949);
        w.enu(3, 8);
        w.enu_ext(2, 4);
        w.normally_small(17);
        w.normally_small(300);
        w.len_det(5);
        w.len_det(1000);
        w.octet_string(&[1, 2, 3]);
        w.bitstring(0b101, 3);
        w.bitstring_bytes(&[0xa5, 0x80], 9);
        w.opt_bits(&[true, false, true]);
        w.seq_of(&[7u8, 9], 1, 4, |w, v| w.uint(*v as u32, 0, 15));
        w.setup_release(&SetupRelease::Setup(5u32), |w, v| w.uint(*v, 0, 7));
        let bytes = w.finish();

        let mut r = BitReader::new(&bytes);
        assert!(r.bit().unwrap());
        assert_eq!(r.bits(4).unwrap(), 0b1011);
        assert_eq!(r.int(-10, 10).unwrap(), -5);
        assert_eq!(r.uint(0, 37949).unwrap(), 37949);
        assert_eq!(r.enu(8).unwrap(), 3);
        assert_eq!(r.enu_ext(4).unwrap(), Some(2));
        assert_eq!(r.normally_small().unwrap(), 17);
        assert_eq!(r.normally_small().unwrap(), 300);
        assert_eq!(r.len_det().unwrap(), 5);
        assert_eq!(r.len_det().unwrap(), 1000);
        assert_eq!(r.octet_string().unwrap(), vec![1, 2, 3]);
        assert_eq!(r.bitstring(3).unwrap(), 0b101);
        assert_eq!(r.bitstring_bytes(9).unwrap(), vec![0xa5, 0x80]);
        assert_eq!(r.opt_bits::<3>().unwrap(), [true, false, true]);
        assert_eq!(r.seq_of(1, 4, |r| r.u8(0, 15)).unwrap(), vec![7, 9]);
        assert_eq!(
            r.setup_release(|r| r.uint(0, 7)).unwrap(),
            SetupRelease::Setup(5)
        );
    }

    #[test]
    fn errors_carry_path_and_kind() {
        let mut r = BitReader::new(&[0xff]);
        // '11' length determinant = fragmented.
        let e = r.len_det().unwrap_err().in_ie("inner").in_ie("outer");
        assert_eq!(e.kind, DecodeErrorKind::FragmentedLength);
        assert_eq!(e.path, "outer/inner");
        let mut r = BitReader::new(&[0x00]);
        assert!(r.bits(9).is_err());
        let e: DecodeResult<()> = Err(r.eof());
        assert_eq!(e.ctx("x").unwrap_err().path, "x");
    }

    #[test]
    fn ext_additions_are_skipped_or_visited() {
        // Build: normally-small (2-1=1) → 2 groups, presence 1,1; group0 = open type
        // of one octet 0xAB; group1 = open type of two octets.
        let mut w = BitWriter::new();
        w.normally_small(1);
        w.bit(true);
        w.bit(true);
        w.octet_string(&[0xab]);
        w.octet_string(&[1, 2]);
        w.bits(0b101, 3); // trailing data must stay aligned
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        let mut seen = Vec::new();
        r.ext_additions(|i, sub| {
            seen.push((i, sub.bits(8).unwrap()));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![(0, 0xab), (1, 0x01)]);
        assert_eq!(r.bits(3).unwrap(), 0b101);
        let mut r = BitReader::new(&bytes);
        r.skip_ext_additions().unwrap();
        assert_eq!(r.bits(3).unwrap(), 0b101);
    }

    #[test]
    fn empty_encoding_is_one_zero_octet() {
        assert_eq!(BitWriter::new().finish(), vec![0]);
    }
}
