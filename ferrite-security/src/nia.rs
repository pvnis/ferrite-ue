//! 128-NIA2 integrity (TS 33.501 Annex D.3.1.3 = TS 33.401 Annex B.2.3): AES-128
//! in CMAC mode over `COUNT || BEARER || DIRECTION || 0^26 || MESSAGE`. NIA0 is
//! the all-zero MAC-I and needs no code; NIA1 (SNOW 3G) and NIA3 (ZUC) are not
//! implemented (see [`crate::IntegrityAlg::is_supported`]).

use aes::Aes128;
use cmac::{Cmac, Mac};

/// The first 64 bits that prefix every integrity message / counter block:
/// `COUNT[0]..COUNT[31] || BEARER[0]..BEARER[4] || DIRECTION || 0^26`
/// (TS 33.401 B.2.3 for the MAC input, B.1.3 for the counter block `T1`).
pub(crate) fn count_bearer_direction_block(count: u32, bearer: u8, direction: u8) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&count.to_be_bytes());
    b[4] = ((bearer & 0x1f) << 3) | ((direction & 1) << 2);
    b
}

/// 128-NIA2: 32-bit MAC-I over `COUNT || BEARER || DIRECTION || 0^26 || MESSAGE`
/// (TS 33.401 B.2.3). `direction` is 0 for uplink, 1 for downlink. `bearer`
/// is the 5-bit bearer identity (RB identity minus one, TS 38.323 §5.9).
///
/// Returns the first 32 bits of the AES-CMAC output.
pub fn nia2_mac(key: &[u8; 16], count: u32, bearer: u8, direction: u8, msg: &[u8]) -> [u8; 4] {
    let mut mac = <Cmac<Aes128> as Mac>::new(key.into());
    mac.update(&count_bearer_direction_block(count, bearer, direction));
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    [out[0], out[1], out[2], out[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::from_hex;

    fn key(s: &str) -> [u8; 16] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    /// TS 33.401 C.2.2 (128-EIA2 Test Set 2): LENGTH = 64 bits.
    #[test]
    fn nia2_test_set_2() {
        let k = key("d3c5d592327fb11c4035c6680af8c6d1");
        let msg = from_hex("484583d5afe082ae").unwrap();
        assert_eq!(
            nia2_mac(&k, 0x398a_59b4, 0x1a, 1, &msg),
            [0xb9, 0x37, 0x87, 0xe6]
        );
    }

    /// TS 33.401 C.2.5 (128-EIA2 Test Set 5): LENGTH = 768 bits.
    #[test]
    fn nia2_test_set_5() {
        let k = key("83fd23a244a74cf358da3019f1722635");
        let msg = from_hex(
            "35c68716633c66fb750c266865d53c11ea05b1e9fa49c8398d48e1efa5909d39\
             47902837f5ae96d5a05bc8d61ca8dbef1b13a4b4abfe4fb1006045b674bb5472\
             9304c382be53a5af05556176f6eaa2ef1d05e4b083181ee674cda5a485f74d7a",
        )
        .unwrap();
        assert_eq!(msg.len(), 96);
        assert_eq!(
            nia2_mac(&k, 0x36af_6144, 0x0f, 1, &msg),
            [0xe6, 0x57, 0xe1, 0x82]
        );
    }

    /// Different COUNT / BEARER / DIRECTION must all change the MAC.
    #[test]
    fn nia2_inputs_matter() {
        let k = key("d3c5d592327fb11c4035c6680af8c6d1");
        let msg = from_hex("484583d5afe082ae").unwrap();
        let base = nia2_mac(&k, 0x398a_59b4, 0x1a, 1, &msg);
        assert_ne!(base, nia2_mac(&k, 0x398a_59b5, 0x1a, 1, &msg));
        assert_ne!(base, nia2_mac(&k, 0x398a_59b4, 0x1b, 1, &msg));
        assert_ne!(base, nia2_mac(&k, 0x398a_59b4, 0x1a, 0, &msg));
    }
}
