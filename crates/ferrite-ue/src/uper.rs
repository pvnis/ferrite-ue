//! X.691 UNALIGNED PER (UPER) primitives shared by the TS 38.331 parsers
//! (`sib1`, `cellgroup`). Hand-rolled, clean-room from the X.691 rules:
//! constrained whole numbers in ⌈log2(range)⌉ bits, extensible types with a
//! leading extension bit, extension additions as skippable length-prefixed
//! open types.

/// X.691 unaligned-PER bit reader. Every read returns `None` past the end, which
/// propagates as a parse failure (`?`).
pub struct Bits<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}

impl<'a> Bits<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    pub fn bit(&mut self) -> Option<bool> {
        let byte = *self.b.get(self.pos / 8)?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(v == 1)
    }

    pub fn bits(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Some(v)
    }

    /// Constrained whole number in `lo..=hi` (§10.5): ⌈log2(range)⌉ bits, offset `lo`.
    pub fn int(&mut self, lo: i64, hi: i64) -> Option<i64> {
        let range = (hi - lo + 1) as u64;
        if range <= 1 {
            return Some(lo);
        }
        let n = 64 - (range - 1).leading_zeros();
        Some(lo + self.bits(n)? as i64)
    }

    /// Non-extensible ENUMERATED with `n` root values.
    pub fn enu(&mut self, n: u32) -> Option<u32> {
        Some(self.int(0, n as i64 - 1)? as u32)
    }

    /// Extensible ENUMERATED: extension bit then the root index (extension values
    /// are read as a normally-small number).
    pub fn enu_ext(&mut self, n_root: u32) -> Option<u32> {
        if self.bit()? {
            // Extended value: normally-small number; the actual identity is unknown
            // to us, return a sentinel beyond the root range.
            let _ = self.normally_small()?;
            return Some(n_root);
        }
        self.enu(n_root)
    }

    /// Normally-small non-negative whole number (§10.6): '0' + 6 bits, else a
    /// length-prefixed unconstrained number (not needed beyond 63 here).
    pub fn normally_small(&mut self) -> Option<u64> {
        if !self.bit()? {
            self.bits(6)
        } else {
            let len = self.len_det()?;
            self.bits((len * 8).min(64) as u32)
        }
    }

    /// General length determinant (§10.9, unaligned): '0'+7 bits (<128) or
    /// '10'+14 bits (<16384). Fragmentation ('11') unsupported (never hit in SIB1).
    pub fn len_det(&mut self) -> Option<usize> {
        if !self.bit()? {
            Some(self.bits(7)? as usize)
        } else if !self.bit()? {
            Some(self.bits(14)? as usize)
        } else {
            None
        }
    }

    /// Skip one open-type value (length determinant counts OCTETS).
    pub fn skip_open(&mut self) -> Option<()> {
        let len = self.len_det()?;
        self.pos += len * 8;
        (self.pos <= self.b.len() * 8).then_some(())
    }

    /// Skip a SEQUENCE's extension additions (call when its extension bit was 1):
    /// a normally-small count-1, that many presence bits, then each present
    /// addition as an open type.
    pub fn skip_ext_additions(&mut self) -> Option<()> {
        let n = self.normally_small()? + 1;
        let mut present = Vec::with_capacity(n as usize);
        for _ in 0..n {
            present.push(self.bit()?);
        }
        for p in present {
            if p {
                self.skip_open()?;
            }
        }
        Some(())
    }
}

