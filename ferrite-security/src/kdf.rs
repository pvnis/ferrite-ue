//! 5G key hierarchy (TS 33.501 Annex A, KDF of TS 33.220 §B.2 = HMAC-SHA256):
//! RES* (A.4), K_AUSF (A.2), K_SEAF (A.6), K_AMF (A.7), the NAS / RRC / UP
//! algorithm keys (A.8), K_gNB (A.9) and the horizontal K_NG-RAN* (A.11).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Algorithm type distinguishers of TS 33.501 Table A.8-1 for [`algo_key`].
pub mod algo_type {
    pub const NAS_ENC: u8 = 0x01;
    pub const NAS_INT: u8 = 0x02;
    pub const RRC_ENC: u8 = 0x03;
    pub const RRC_INT: u8 = 0x04;
    pub const UP_ENC: u8 = 0x05;
    pub const UP_INT: u8 = 0x06;
}

/// KDF as HMAC-SHA256(key, S) (TS 33.220 §B.2). Returns the 32-byte output.
pub fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    // HMAC accepts any key length, so `new_from_slice` cannot fail here.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(s);
    mac.finalize().into_bytes().into()
}

/// RES* for 5G-AKA (TS 33.501 §A.4): KDF(CK||IK, FC=0x6B || SNN || RAND || RES),
/// take the low 128 bits. `snn` is the serving-network name string.
pub fn res_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    snn: &str,
    rand: &[u8; 16],
    res: &[u8; 8],
) -> [u8; 16] {
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
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[16..32]);
    r
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

/// NAS / RRC / UP algorithm key (TS 33.501 §A.8): KDF(K_AMF or K_gNB, FC=0x69 ||
/// algo-type-dist || algo-id), low 128 bits. `algo_type` is one of
/// [`algo_type`] (NAS-enc 1, NAS-int 2, RRC-enc 3, RRC-int 4, UP-enc 5,
/// UP-int 6); `algo_id` the NEA/NIA identifier (0..3).
pub fn algo_key(k_amf: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 16] {
    let s = [0x69, algo_type, 0x00, 0x01, algo_id, 0x00, 0x01];
    let out = kdf(k_amf, &s);
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[16..32]);
    r
}

/// K_NG-RAN* for the cell `pci` / SSB `arfcn` by horizontal derivation from
/// the current K_gNB (TS 33.501 §A.11, FC = 0x70: PCI(2) || ARFCN-DL(3)).
pub fn k_ng_ran_star(k_gnb: &[u8; 32], pci: u16, arfcn: u32) -> [u8; 32] {
    let mut s = vec![0x70u8];
    s.extend_from_slice(&pci.to_be_bytes());
    s.extend_from_slice(&[0x00, 0x02]);
    s.extend_from_slice(&arfcn.to_be_bytes()[1..]);
    s.extend_from_slice(&[0x00, 0x03]);
    kdf(k_gnb, &s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A.8 keys differ per type distinguisher and algorithm id; UP keys use
    /// the UP distinguishers (0x05 / 0x06), not the NAS ones.
    #[test]
    fn algo_keys_distinct() {
        let k = [0x11u8; 32];
        let rrc_int = algo_key(&k, algo_type::RRC_INT, 2);
        assert_ne!(rrc_int, algo_key(&k, algo_type::UP_INT, 2));
        assert_ne!(rrc_int, algo_key(&k, algo_type::RRC_INT, 1));
        assert_ne!(algo_key(&k, algo_type::NAS_ENC, 2), algo_key(&k, algo_type::UP_ENC, 2));
    }

    #[test]
    fn k_ng_ran_star_depends_on_cell() {
        let k = [0x22u8; 32];
        assert_ne!(k_ng_ran_star(&k, 1, 368500), k_ng_ran_star(&k, 2, 368500));
        assert_ne!(k_ng_ran_star(&k, 1, 368500), k_ng_ran_star(&k, 1, 626000));
    }
}
