//! MILENAGE (TS 35.206) USIM authentication functions f1, f1*, f2–f5, f5* on
//! AES-128. The 5G key hierarchy built on their outputs is in [`crate::kdf`].

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Milenage {
    /// f2: RES.
    pub res: [u8; 8],
    /// f3: CK.
    pub ck: [u8; 16],
    /// f4: IK.
    pub ik: [u8; 16],
    /// f5: AK.
    pub ak: [u8; 6],
    /// f1: MAC-A.
    pub mac_a: [u8; 8],
    /// f1*: MAC-S (resynchronisation), computed with the same SQN/AMF inputs.
    pub mac_s: [u8; 8],
    /// f5*: AK* (resynchronisation anonymity key).
    pub ak_star: [u8; 6],
}

/// Derive OPc from OP (TS 35.206 §4.1 / §5.1): OPc = E_K(OP) xor OP.
pub fn opc_from_op(k: &[u8; 16], op: &[u8; 16]) -> [u8; 16] {
    xor16(&aes128(k, op), op)
}

/// Compute f1, f1*, f2..f5 and f5* (TS 35.206 §4.1). Constants: c1=0,
/// c2..c5 = 1,2,4,8 (LSB); r1=64, r2=0, r3=32, r4=64, r5=96.
/// f1 and f1* share OUT1: MAC-A = OUT1[0..64], MAC-S = OUT1[64..128].
pub fn milenage(
    k: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> Milenage {
    let temp = aes128(k, &xor16(rand, opc));

    // f1 / MAC-A: IN1 = SQN||AMF||SQN||AMF.
    let mut in1 = [0u8; 16];
    in1[0..6].copy_from_slice(sqn);
    in1[6..8].copy_from_slice(amf);
    in1[8..14].copy_from_slice(sqn);
    in1[14..16].copy_from_slice(amf);
    let a1 = xor16(&temp, &rotl(&xor16(&in1, opc), 64)); // XOR c1 = 0
    let out1 = xor16(&aes128(k, &a1), opc);
    let mut mac_a = [0u8; 8];
    mac_a.copy_from_slice(&out1[0..8]);
    let mut mac_s = [0u8; 8];
    mac_s.copy_from_slice(&out1[8..16]);

    // f2 / RES and f5 / AK.
    let mut c2 = [0u8; 16];
    c2[15] = 1;
    let a2 = xor16(&rotl(&xor16(&temp, opc), 0), &c2);
    let out2 = xor16(&aes128(k, &a2), opc);
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&out2[0..6]);
    let mut res = [0u8; 8];
    res.copy_from_slice(&out2[8..16]);

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

    // f5* / AK*: r5 = 96, c5 = 8.
    let mut c5 = [0u8; 16];
    c5[15] = 8;
    let a5 = xor16(&rotl(&xor16(&temp, opc), 96), &c5);
    let out5 = xor16(&aes128(k, &a5), opc);
    let mut ak_star = [0u8; 6];
    ak_star.copy_from_slice(&out5[0..6]);

    Milenage {
        res,
        ck,
        ik,
        ak,
        mac_a,
        mac_s,
        ak_star,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
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
        assert_eq!(m.mac_s, hx("01cfaf9ec4e871e9").as_slice());
        assert_eq!(m.ak_star, hx("451e8beca43b").as_slice());
        let op: [u8; 16] = hx("cdc202d5123e20f62b6d676ac72cb318").try_into().unwrap();
        assert_eq!(opc_from_op(&k, &op), opc);
    }
}
