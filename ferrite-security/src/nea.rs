//! 128-NEA2 ciphering (TS 33.501 Annex D.2.1.3 = TS 33.401 Annex B.1.3): AES-128
//! in big-endian 128-bit counter mode. NEA0 is plaintext; NEA1 (SNOW 3G) and
//! NEA3 (ZUC) are not implemented (see [`crate::CipherAlg::is_supported`]).

use crate::nia::count_bearer_direction_block;
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-128 in big-endian 128-bit counter mode, as required by TS 33.401 B.1.3
/// ("the counter is incremented as a 128-bit big-endian integer").
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// 128-NEA2: AES-128-CTR keystream XORed into `data` in place (TS 33.401
/// B.1.3). The initial counter block is
/// `T1 = COUNT || BEARER || DIRECTION || 0^26 || 0^64` and increments as a
/// 128-bit big-endian integer per block. Encryption and decryption are the
/// same operation.
pub fn nea2_crypt(key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&count_bearer_direction_block(count, bearer, direction));
    let mut cipher = Aes128Ctr::new(key.into(), (&iv).into());
    cipher.apply_keystream(data);
}

/// [`nea2_crypt`] on a copy of `data`.
pub fn nea2(key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    nea2_crypt(key, count, bearer, direction, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::from_hex;

    fn key(s: &str) -> [u8; 16] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    /// TS 33.401 C.1.1 (128-EEA2 Test Set 1): LENGTH = 253 bits; the last 3
    /// keystream bits are discarded by the spec, so the final octet is compared
    /// masked.
    #[test]
    fn nea2_test_set_1() {
        let k = key("d3c5d592327fb11c4035c6680af8c6d1");
        let mut data =
            from_hex("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0").unwrap();
        let expect =
            from_hex("e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78").unwrap();
        nea2_crypt(&k, 0x398a_59b4, 0x15, 1, &mut data);
        assert_eq!(data[..31], expect[..31]);
        assert_eq!(data[31] & 0xf8, expect[31] & 0xf8);
    }

    /// TS 33.401 C.1.2 (128-EEA2 Test Set 2): LENGTH = 798 bits (last 2 bits
    /// of the final octet discarded); spans several counter blocks.
    #[test]
    fn nea2_test_set_2() {
        let k = key("2bd6459f82c440e0952c49104805ff48");
        let mut data = from_hex(
            "7ec61272743bf1614726446a6c38ced166f6ca76eb5430044286346cef130f92\
             922b03450d3a9975e5bd2ea0eb55ad8e1b199e3ec4316020e9a1b285e7627953\
             59b7bdfd39bef4b2484583d5afe082aee638bf5fd5a606193901a08f4ab41aab\
             9b134880",
        )
        .unwrap();
        let expect = from_hex(
            "5961605353c64bdca15b195e288553a910632506d6200aa790c4c806c99904cf\
             2445cc50bb1cf168a49673734e081b57e324ce5259c0e78d4cd97b870976503c\
             0943f2cb5ae8f052c7b7d392239587b8956086bcab18836042e2e6ce42432a17\
             105c53d0",
        )
        .unwrap();
        assert_eq!(data.len(), 100);
        let plain = data.clone();
        nea2_crypt(&k, 0xc675_a64b, 0x0c, 1, &mut data);
        assert_eq!(data[..99], expect[..99]);
        assert_eq!(data[99] & 0xfc, expect[99] & 0xfc);
        // Decryption is the same operation.
        nea2_crypt(&k, 0xc675_a64b, 0x0c, 1, &mut data);
        assert_eq!(data, plain);
    }
}
