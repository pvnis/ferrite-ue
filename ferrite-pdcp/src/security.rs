//! NR access-stratum security algorithms (TS 33.501 Annex D).
//!
//! * `NIA2` (D.3.1.3) — integrity, 128-bit AES in CMAC mode. Identical to the
//!   LTE `128-EIA2` of TS 33.401 Annex B.2.3, whose Annex C.2 test sets we use.
//! * `NEA2` (D.2.1.3) — ciphering, 128-bit AES in CTR mode. Identical to the
//!   LTE `128-EEA2` of TS 33.401 Annex B.1.3 (test sets in Annex C.1).
//! * `NIA0` / `NEA0` are the null algorithms (D.3.1.1 / D.2.1.1): all-zero
//!   MAC-I, plaintext ciphering. They need no code of their own; the entity
//!   handles them.
//!
//! Both algorithms take the same five inputs (TS 33.501 D.2.1.1 / D.3.1.1):
//! `COUNT` (32 bits), `BEARER` (5 bits), `DIRECTION` (1 bit: 0 uplink,
//! 1 downlink) and the key; the integrity algorithm additionally takes the
//! message, the ciphering algorithm the keystream length.
//!
//! The functions here are byte-oriented: NR PDCP PDUs are always a whole number
//! of octets, so the bit-level padding cases of the LTE test vectors with a
//! `LENGTH` that is not a multiple of 8 do not arise.

use aes::Aes128;
use cmac::{Cmac, Mac};
use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-128 in big-endian 128-bit counter mode, as required by TS 33.401 B.1.3
/// ("the counter is incremented as a 128-bit big-endian integer").
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// The first 64 bits that prefix every integrity message / counter block:
/// `COUNT[0]..COUNT[31] || BEARER[0]..BEARER[4] || DIRECTION || 0^26`
/// (TS 33.401 B.2.3 for the MAC input, B.1.3 for the counter block `T1`).
fn count_bearer_direction_block(count: u32, bearer: u8, direction: u8) -> [u8; 8] {
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
