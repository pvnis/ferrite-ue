//! Security primitives shared by PDCP, RRC and NAS: the NR integrity (NIA) and
//! ciphering (NEA) algorithms of TS 33.501 Annex D, the key hierarchy of
//! TS 33.501 Annex A and the MILENAGE USIM functions of TS 35.206. One
//! implementation for every layer; the algorithm identifiers are typed so an
//! unsupported algorithm is a value the caller must handle, never a silent
//! pass-through.
//!
//! Implemented: NIA0 / NIA2, NEA0 / NEA2. Not implemented: NIA1 / NEA1
//! (SNOW 3G) and NIA3 / NEA3 (ZUC); [`IntegrityAlg::is_supported`] /
//! [`CipherAlg::is_supported`] tell, and the UE must not advertise them.

#![forbid(unsafe_code)]

pub mod kdf;
pub mod milenage;
pub mod nea;
pub mod nia;

/// DIRECTION bit: uplink (TS 33.501 D.2.1.1).
pub const DIR_UL: u8 = 0;
/// DIRECTION bit: downlink.
pub const DIR_DL: u8 = 1;

/// Why a security operation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecurityError {
    #[error("{0} is not implemented")]
    Unsupported(&'static str),
    #[error("unknown security algorithm identifier {0}")]
    UnknownAlgorithm(u8),
}

/// NR integrity algorithm identifiers (TS 33.501 §5.11.1.2 / Annex D.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IntegrityAlg {
    Nia0 = 0,
    Nia1 = 1,
    Nia2 = 2,
    Nia3 = 3,
}

/// NR ciphering algorithm identifiers (TS 33.501 §5.11.1.1 / Annex D.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CipherAlg {
    Nea0 = 0,
    Nea1 = 1,
    Nea2 = 2,
    Nea3 = 3,
}

impl IntegrityAlg {
    /// The 4-bit identifier used in NAS / RRC signalling.
    pub const fn id(self) -> u8 {
        self as u8
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nia0 => "NIA0",
            Self::Nia1 => "NIA1 (SNOW 3G)",
            Self::Nia2 => "NIA2 (AES-CMAC)",
            Self::Nia3 => "NIA3 (ZUC)",
        }
    }
    /// Whether this crate implements the algorithm.
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Nia0 | Self::Nia2)
    }
    pub fn check_supported(self) -> Result<Self, SecurityError> {
        if self.is_supported() {
            Ok(self)
        } else {
            Err(SecurityError::Unsupported(self.name()))
        }
    }
}

impl CipherAlg {
    pub const fn id(self) -> u8 {
        self as u8
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nea0 => "NEA0",
            Self::Nea1 => "NEA1 (SNOW 3G)",
            Self::Nea2 => "NEA2 (AES-CTR)",
            Self::Nea3 => "NEA3 (ZUC)",
        }
    }
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Nea0 | Self::Nea2)
    }
    pub fn check_supported(self) -> Result<Self, SecurityError> {
        if self.is_supported() {
            Ok(self)
        } else {
            Err(SecurityError::Unsupported(self.name()))
        }
    }
}

impl TryFrom<u8> for IntegrityAlg {
    type Error = SecurityError;
    fn try_from(v: u8) -> Result<Self, SecurityError> {
        match v {
            0 => Ok(Self::Nia0),
            1 => Ok(Self::Nia1),
            2 => Ok(Self::Nia2),
            3 => Ok(Self::Nia3),
            other => Err(SecurityError::UnknownAlgorithm(other)),
        }
    }
}

impl TryFrom<u8> for CipherAlg {
    type Error = SecurityError;
    fn try_from(v: u8) -> Result<Self, SecurityError> {
        match v {
            0 => Ok(Self::Nea0),
            1 => Ok(Self::Nea1),
            2 => Ok(Self::Nea2),
            3 => Ok(Self::Nea3),
            other => Err(SecurityError::UnknownAlgorithm(other)),
        }
    }
}

/// 32-bit MAC-I with `alg` over `msg` (TS 33.501 D.3.1.1 inputs). NIA0 yields
/// all zeros; NIA1 / NIA3 fail with [`SecurityError::Unsupported`].
pub fn integrity_mac(alg: IntegrityAlg, key: &[u8; 16], count: u32, bearer: u8, direction: u8, msg: &[u8]) -> Result<[u8; 4], SecurityError> {
    match alg {
        IntegrityAlg::Nia0 => Ok([0; 4]),
        IntegrityAlg::Nia2 => Ok(nia::nia2_mac(key, count, bearer, direction, msg)),
        other => Err(SecurityError::Unsupported(other.name())),
    }
}

/// Cipher / decipher `data` in place with `alg` (the two are the same
/// operation). NEA0 leaves the data untouched; NEA1 / NEA3 fail.
pub fn cipher_in_place(alg: CipherAlg, key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &mut [u8]) -> Result<(), SecurityError> {
    match alg {
        CipherAlg::Nea0 => Ok(()),
        CipherAlg::Nea2 => {
            nea::nea2_crypt(key, count, bearer, direction, data);
            Ok(())
        }
        other => Err(SecurityError::Unsupported(other.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_and_support() {
        for id in 0..4u8 {
            assert_eq!(IntegrityAlg::try_from(id).unwrap().id(), id);
            assert_eq!(CipherAlg::try_from(id).unwrap().id(), id);
        }
        assert_eq!(IntegrityAlg::try_from(7), Err(SecurityError::UnknownAlgorithm(7)));
        assert!(IntegrityAlg::Nia2.is_supported() && !IntegrityAlg::Nia1.is_supported());
        assert!(CipherAlg::Nea0.is_supported() && !CipherAlg::Nea3.is_supported());
        assert_eq!(integrity_mac(IntegrityAlg::Nia3, &[0; 16], 0, 0, 0, b"x"), Err(SecurityError::Unsupported("NIA3 (ZUC)")));
        assert_eq!(integrity_mac(IntegrityAlg::Nia0, &[0; 16], 0, 0, 0, b"x"), Ok([0; 4]));
        let mut d = *b"hello";
        cipher_in_place(CipherAlg::Nea0, &[0; 16], 0, 0, 0, &mut d).unwrap();
        assert_eq!(&d, b"hello");
    }
}
