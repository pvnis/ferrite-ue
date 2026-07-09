//! MILENAGE (TS 35.206) authentication functions and the 5G key derivations
//! (TS 33.501 Annex A) the UE needs for 5G-AKA. Built on AES-128 + HMAC-SHA256.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn aes128(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Cyclic left-rotate a 128-bit value by `r` bits (`r` is a multiple of 8 for
/// all MILENAGE uses, so byte rotation suffices).
fn rotl(x: &[u8; 16], r: usize) -> [u8; 16] {
    let rb = (r / 8) % 16;
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = x[(i + rb) % 16];
    }
    o
}

/// MILENAGE outputs for one RAND (with OPc given directly, as in most SIMs).
pub struct Milenage {
    pub res: [u8; 8],  // f2
    pub ck: [u8; 16],  // f3
    pub ik: [u8; 16],  // f4
    pub ak: [u8; 6],   // f5
    pub mac_a: [u8; 8], // f1
}

/// Compute f1..f5 (TS 35.206 §4.1). Constants: c1=0, c2..c5 = 1,2,4,8 (LSB);
/// r1=64, r2=0, r3=32, r4=64.
pub fn milenage(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> Milenage {
    let temp = aes128(k, &xor16(rand, opc));

    // f1 / MAC-A: IN1 = SQN||AMF||SQN||AMF.
    let mut in1 = [0u8; 16];
    in1[0..6].copy_from_slice(sqn);
    in1[6..8].copy_from_slice(amf);
    in1[8..14].copy_from_slice(sqn);
    in1[14..16].copy_from_slice(amf);
    let a1 = xor16(&temp, &rotl(&xor16(&in1, opc), 64)); // XOR c1 = 0
    let out1 = xor16(&aes128(k, &a1), opc);
    let mac_a: [u8; 8] = out1[0..8].try_into().unwrap();

    // f2 / RES and f5 / AK.
    let mut c2 = [0u8; 16];
    c2[15] = 1;
    let a2 = xor16(&rotl(&xor16(&temp, opc), 0), &c2);
    let out2 = xor16(&aes128(k, &a2), opc);
    let ak: [u8; 6] = out2[0..6].try_into().unwrap();
    let res: [u8; 8] = out2[8..16].try_into().unwrap();

    // f3 / CK.
    let mut c3 = [0u8; 16];
    c3[15] = 2;
    let a3 = xor16(&rotl(&xor16(&temp, opc), 32), &c3);
    let ck = xor16(&aes128(k, &a3), opc);

    // f4 / IK.
    let mut c4 = [0u8; 16];
    c4[15] = 4;
    let a4 = xor16(&rotl(&xor16(&temp, opc), 64), &c4);
    let ik = xor16(&aes128(k, &a4), opc);

    Milenage { res, ck, ik, ak, mac_a }
}

/// KDF as HMAC-SHA256(key, S) (TS 33.220 §B.2). Returns the 32-byte output.
pub fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(s);
    mac.finalize().into_bytes().into()
}

/// RES* for 5G-AKA (TS 33.501 §A.4): KDF(CK||IK, FC=0x6B || SNN || RAND || RES),
/// take the low 128 bits. `snn` is the serving-network name string.
pub fn res_star(ck: &[u8; 16], ik: &[u8; 16], snn: &str, rand: &[u8; 16], res: &[u8; 8]) -> [u8; 16] {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(ck);
    key[16..32].copy_from_slice(ik);
    let mut s = Vec::new();
    s.push(0x6b); // FC
    s.extend_from_slice(snn.as_bytes());
    s.extend_from_slice(&(snn.len() as u16).to_be_bytes());
    s.extend_from_slice(rand);
    s.extend_from_slice(&(rand.len() as u16).to_be_bytes());
    s.extend_from_slice(res);
    s.extend_from_slice(&(res.len() as u16).to_be_bytes());
    let out = kdf(&key, &s);
    out[16..32].try_into().unwrap()
}

/// K_AUSF (TS 33.501 §A.2): KDF(CK||IK, FC=0x6A || SNN || (SQN xor AK)).
pub fn k_ausf(ck: &[u8; 16], ik: &[u8; 16], snn: &str, sqn_xor_ak: &[u8; 6]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(ck);
    key[16..32].copy_from_slice(ik);
    let mut s = Vec::new();
    s.push(0x6a);
    s.extend_from_slice(snn.as_bytes());
    s.extend_from_slice(&(snn.len() as u16).to_be_bytes());
    s.extend_from_slice(sqn_xor_ak);
    s.extend_from_slice(&(sqn_xor_ak.len() as u16).to_be_bytes());
    kdf(&key, &s)
}

/// K_SEAF (TS 33.501 §A.6): KDF(K_AUSF, FC=0x6C || SNN).
pub fn k_seaf(k_ausf: &[u8; 32], snn: &str) -> [u8; 32] {
    let mut s = Vec::new();
    s.push(0x6c);
    s.extend_from_slice(snn.as_bytes());
    s.extend_from_slice(&(snn.len() as u16).to_be_bytes());
    kdf(k_ausf, &s)
}

/// K_AMF (TS 33.501 §A.7): KDF(K_SEAF, FC=0x6D || SUPI || ABBA).
pub fn k_amf(k_seaf: &[u8; 32], supi: &str, abba: &[u8]) -> [u8; 32] {
    let mut s = Vec::new();
    s.push(0x6d);
    s.extend_from_slice(supi.as_bytes());
    s.extend_from_slice(&(supi.len() as u16).to_be_bytes());
    s.extend_from_slice(abba);
    s.extend_from_slice(&(abba.len() as u16).to_be_bytes());
    kdf(k_seaf, &s)
}

/// K_gNB (TS 33.501 §A.9): KDF(K_AMF, FC=0x6E || uplink-NAS-COUNT(4) || 0x0004 ||
/// access-type-distinguisher 0x01 (3GPP) || 0x0001).
pub fn k_gnb(k_amf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    let mut s = Vec::new();
    s.push(0x6e);
    s.extend_from_slice(&ul_nas_count.to_be_bytes());
    s.extend_from_slice(&[0x00, 0x04]);
    s.push(0x01);
    s.extend_from_slice(&[0x00, 0x01]);
    kdf(k_amf, &s)
}

/// NAS/RRC algorithm key (TS 33.501 §A.8): KDF(K_AMF or K_gNB, FC=0x69 ||
/// algo-type-dist || algo-id), low 128 bits. `algo_type`: 1=NAS-enc, 2=NAS-int,
/// 3=RRC-enc, 4=RRC-int. `algo_id`: the NEA/NIA identifier (0..3).
pub fn algo_key(k_amf: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 16] {
    let s = [0x69, algo_type, 0x00, 0x01, algo_id, 0x00, 0x01];
    let out = kdf(k_amf, &s);
    out[16..32].try_into().unwrap()
}

/// 128-NIA2 integrity MAC (TS 33.501 Annex D.3.1.2 = TS 33.401 B.2.3): AES-CMAC
/// over the bit string COUNT(32) || BEARER(5) || DIRECTION(1) || 0^26 || MESSAGE,
/// i.e. octets COUNT(4) || (BEARER<<3 | DIR<<2) || 0x00 0x00 0x00 || MESSAGE.
/// Returns the leading 32 bits (4 octets). `direction`: 0 uplink, 1 downlink.
pub fn nia2_mac(k: &[u8; 16], count: u32, bearer: u8, direction: u8, message: &[u8]) -> [u8; 4] {
    use cmac::Cmac;
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(k).unwrap();
    mac.update(&count.to_be_bytes());
    mac.update(&[(bearer << 3) | (direction << 2)]);
    mac.update(&[0u8; 3]);
    mac.update(message);
    mac.finalize().into_bytes()[..4].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// 128-EIA2/NIA2 Test Set 2 (TS 33.401 C.2 / 35.208).
    #[test]
    fn nia2_test_set_2() {
        let ik: [u8; 16] = hx("d3c5d592327fb11c4035c6680af8c6d1").try_into().unwrap();
        let msg = hx("484583d5afe082ae");
        let mac = nia2_mac(&ik, 0x398a59b4, 0b11010, 1, &msg);
        assert_eq!(mac, hx("b93787e6").as_slice());
    }

    /// TS 35.208 Test Set 1.
    #[test]
    fn milenage_test_set_1() {
        let k: [u8; 16] = hx("465b5ce8b199b49faa5f0a2ee238a6bc").try_into().unwrap();
        let opc: [u8; 16] = hx("cd63cb71954a9f4e48a5994e37a02baf").try_into().unwrap();
        let rand: [u8; 16] = hx("23553cbe9637a89d218ae64dae47bf35").try_into().unwrap();
        let sqn: [u8; 6] = hx("ff9bb4d0b607").try_into().unwrap();
        let amf: [u8; 2] = hx("b9b9").try_into().unwrap();
        let m = milenage(&k, &opc, &rand, &sqn, &amf);
        assert_eq!(m.mac_a, hx("4a9ffac354dfafb3").as_slice());
        assert_eq!(m.res, hx("a54211d5e3ba50bf").as_slice());
        assert_eq!(m.ck, hx("b40ba9a3c58b2a05bbf0d987b21bf8cb").as_slice());
        assert_eq!(m.ik, hx("f769bcd751044604127672711c6d3441").as_slice());
        assert_eq!(m.ak, hx("aa689c648370").as_slice());
    }
}
