//! Cyclic redundancy check (3GPP TS 38.212 §5.1).
//!
//! NR CRCs are ordinary polynomial-division CRCs: zero initial value, no final
//! inversion, computed MSB-first. Bits are represented one-per-`u8` (0 or 1).

/// A CRC generator: the polynomial (low `width` bits, excluding the `D^width`
/// term) and its width.
#[derive(Clone, Copy, Debug)]
pub struct Crc {
    poly: u32,
    width: u32,
}

/// CRC24C (§5.1): `D^24+D^23+D^21+D^20+D^17+D^15+D^13+D^12+D^8+D^4+D^2+D+1`.
pub const CRC24C: Crc = Crc {
    poly: 0x00B2_B117,
    width: 24,
};

/// CRC24A (§5.1), used by DL-SCH/UL-SCH transport blocks.
pub const CRC24A: Crc = Crc {
    poly: 0x0086_4CFB,
    width: 24,
};

/// CRC16 (§5.1).
pub const CRC16: Crc = Crc {
    poly: 0x0000_1021,
    width: 16,
};

impl Crc {
    /// CRC width in bits.
    pub fn width(&self) -> usize {
        self.width as usize
    }

    /// Compute the CRC over `bits` (each 0/1), returning `width` bits MSB-first.
    pub fn compute(&self, bits: &[u8]) -> Vec<u8> {
        let l = self.width;
        let mask = if l >= 32 { u32::MAX } else { (1u32 << l) - 1 };
        let mut reg = 0u32;
        for &m in bits {
            let feedback = (((reg >> (l - 1)) & 1) ^ (u32::from(m) & 1)) != 0;
            reg = (reg << 1) & mask;
            if feedback {
                reg ^= self.poly;
            }
        }
        (0..l).rev().map(|i| ((reg >> i) & 1) as u8).collect()
    }

    /// Append the CRC to `bits`, returning `bits || crc`.
    pub fn attach(&self, bits: &[u8]) -> Vec<u8> {
        let mut out = bits.to_vec();
        out.extend(self.compute(bits));
        out
    }

    /// Check a `message || crc` block: recomputing the CRC over the whole block
    /// yields all-zero iff the CRC is consistent.
    pub fn check(&self, bits_with_crc: &[u8]) -> bool {
        self.compute(bits_with_crc).iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_length() {
        assert_eq!(CRC24C.compute(&[1, 0, 1, 1, 0, 0, 1]).len(), 24);
        assert_eq!(CRC16.compute(&[1, 1, 0, 0]).len(), 16);
    }

    /// A correctly attached CRC must verify, and any single-bit flip must fail.
    #[test]
    fn attach_then_check_and_detect_errors() {
        for crc in [CRC24C, CRC24A, CRC16] {
            let msg: Vec<u8> = (0..40).map(|i| ((i * 7 + 3) % 2) as u8).collect();
            let block = crc.attach(&msg);
            assert!(crc.check(&block), "valid CRC should pass");

            for flip in 0..block.len() {
                let mut bad = block.clone();
                bad[flip] ^= 1;
                assert!(!crc.check(&bad), "flip at {flip} should be detected");
            }
        }
    }

    #[test]
    fn deterministic() {
        let msg = [1u8, 0, 1, 0, 1, 1, 1, 0];
        assert_eq!(CRC24C.compute(&msg), CRC24C.compute(&msg));
    }
}
