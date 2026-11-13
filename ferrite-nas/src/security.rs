//! NAS security (TS 24.501 §4.4, TS 33.501 §6.4) and 5G-AKA (TS 33.501
//! §6.1.3.2, TS 33.102 §6.3.3 resynchronisation).
//!
//! * [`NasSecurityContext`]: K_AMF, ngKSI, the selected algorithms, the
//!   derived K_NASint / K_NASenc and the uplink / downlink NAS COUNTs.
//! * [`protect`] / [`unprotect`]: security-protected NAS message framing
//!   (TS 24.501 §9.1.1): `EPD | SHT | MAC(4) | SEQ | plain message`.
//! * [`nea2`]: 128-NEA2 (AES-128 CTR, TS 33.501 D.3.1.3 = TS 33.401 B.1.3).
//! * [`run_5g_aka`]: USIM side of 5G-AKA with MILENAGE, SQN freshness and
//!   AUTS generation.

use crate::ie::NasError;
use crate::milenage::{algo_key, k_amf, k_ausf, k_gnb, k_seaf, milenage, nia2_mac, res_star};
use crate::mm::{SecurityHeader, SecurityHeaderType, EPD_5GMM};
use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use aes::Aes128;

/// NAS connection identifier / BEARER for 3GPP access (TS 33.501 §6.4.2.2).
pub const BEARER_3GPP: u8 = 1;
/// DIRECTION bit: uplink.
pub const DIR_UL: u8 = 0;
/// DIRECTION bit: downlink.
pub const DIR_DL: u8 = 1;

/// 5G NAS ciphering algorithm identifiers (TS 33.501 §5.11.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherAlg {
    Nea0 = 0,
    Nea1 = 1,
    Nea2 = 2,
    Nea3 = 3,
}

/// 5G NAS integrity algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntegrityAlg {
    Nia0 = 0,
    Nia1 = 1,
    Nia2 = 2,
    Nia3 = 3,
}

impl CipherAlg {
    /// Only NEA0 and NEA2 are implemented.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Nea0),
            2 => Some(Self::Nea2),
            _ => None,
        }
    }
}

impl IntegrityAlg {
    /// Only NIA0 and NIA2 are implemented.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Nia0),
            2 => Some(Self::Nia2),
            _ => None,
        }
    }
}

/// 128-NEA2: AES-128 in CTR mode. The initial counter block (TS 33.401 B.1.3)
/// is `COUNT(32) | BEARER(5) | DIRECTION(1) | 0(26) | 0(64)` and is
/// incremented as a 128-bit big-endian integer. Encryption and decryption are
/// the same operation.
pub fn nea2(key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &[u8]) -> Vec<u8> {
    type Ctr = ctr::Ctr128BE<Aes128>;
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = ((bearer & 0x1f) << 3) | ((direction & 1) << 2);
    let mut c = Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    let mut out = data.to_vec();
    c.apply_keystream(&mut out);
    out
}

/// Apply the selected ciphering algorithm (both directions are symmetric).
pub fn cipher(
    alg: CipherAlg,
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    data: &[u8],
) -> Vec<u8> {
    match alg {
        CipherAlg::Nea0 => data.to_vec(),
        CipherAlg::Nea2 => nea2(key, count, bearer, direction, data),
        // Not implemented; never selected because `from_id` rejects them.
        CipherAlg::Nea1 | CipherAlg::Nea3 => data.to_vec(),
    }
}

/// Compute the NAS-MAC with the selected integrity algorithm over
/// `SEQ || plain message` (TS 24.501 §4.4.3.3). NIA0 yields all zeros.
pub fn integrity_mac(
    alg: IntegrityAlg,
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    msg: &[u8],
) -> [u8; 4] {
    match alg {
        IntegrityAlg::Nia0 => [0; 4],
        IntegrityAlg::Nia2 => nia2_mac(key, count, bearer, direction, msg),
        IntegrityAlg::Nia1 | IntegrityAlg::Nia3 => [0; 4],
    }
}

/// The selected NAS algorithms with their keys (TS 33.501 A.8).
#[derive(Debug, Clone, Copy)]
pub struct NasKeys {
    pub ea: CipherAlg,
    pub ia: IntegrityAlg,
    pub k_enc: [u8; 16],
    pub k_int: [u8; 16],
}

/// Build a security protected NAS message (TS 24.501 §9.1.1) from a plain
/// one. The sequence number is `count & 0xff`; ciphering (for SHT 2/4) uses
/// the same COUNT. `direction` selects UL (UE) or DL (test core).
pub fn protect(
    sht: SecurityHeaderType,
    keys: &NasKeys,
    count: u32,
    direction: u8,
    plain: &[u8],
) -> Vec<u8> {
    let body = if sht.is_ciphered() {
        cipher(keys.ea, &keys.k_enc, count, BEARER_3GPP, direction, plain)
    } else {
        plain.to_vec()
    };
    let mut out = vec![EPD_5GMM, sht as u8, 0, 0, 0, 0, (count & 0xff) as u8];
    out.extend_from_slice(&body);
    let mac = integrity_mac(
        keys.ia,
        &keys.k_int,
        count,
        BEARER_3GPP,
        direction,
        &out[6..],
    );
    out[2..6].copy_from_slice(&mac);
    out
}

/// Verify and strip the security header of a protected NAS message whose
/// COUNT has already been estimated. Returns the plain inner message.
pub fn unprotect(
    pdu: &[u8],
    hdr: &SecurityHeader,
    keys: &NasKeys,
    count: u32,
    direction: u8,
) -> Result<Vec<u8>, NasError> {
    let seq_and_body = pdu.get(6..).ok_or(NasError::Truncated("security header"))?;
    let expect = integrity_mac(
        keys.ia,
        &keys.k_int,
        count,
        BEARER_3GPP,
        direction,
        seq_and_body,
    );
    if expect != hdr.mac {
        return Err(NasError::MacFailure);
    }
    let body = seq_and_body
        .get(1..)
        .ok_or(NasError::Truncated("sequence number"))?;
    Ok(if hdr.sht.is_ciphered() {
        cipher(keys.ea, &keys.k_enc, count, BEARER_3GPP, direction, body)
    } else {
        body.to_vec()
    })
}

/// The 5G NAS security context (TS 24.501 §4.4.2 / TS 33.501 §6.4).
#[derive(Debug, Clone)]
pub struct NasSecurityContext {
    pub k_amf: [u8; 32],
    pub ngksi: u8,
    pub ea: CipherAlg,
    pub ia: IntegrityAlg,
    pub k_nas_enc: [u8; 16],
    pub k_nas_int: [u8; 16],
    /// Uplink NAS COUNT (24 bits: overflow(16) | SQN(8)) for the next UL message.
    pub ul_count: u32,
    /// Highest downlink NAS COUNT accepted so far (`None` before the first).
    pub dl_count: Option<u32>,
    /// Direction this context sends in (UL for the UE; a test core flips it).
    pub tx_direction: u8,
}

impl NasSecurityContext {
    /// Derive a context from K_AMF and the algorithms selected by the SMC
    /// (TS 33.501 A.8: K_NASenc = KDF(K_AMF, 0x69, 0x01, NEA), K_NASint = (.., 0x02, NIA)).
    pub fn new(k_amf: [u8; 32], ngksi: u8, ea: u8, ia: u8) -> Result<Self, NasError> {
        let ea_alg = CipherAlg::from_id(ea).ok_or(NasError::UnsupportedAlgorithm { ea, ia })?;
        let ia_alg = IntegrityAlg::from_id(ia).ok_or(NasError::UnsupportedAlgorithm { ea, ia })?;
        Ok(NasSecurityContext {
            k_amf,
            ngksi,
            ea: ea_alg,
            ia: ia_alg,
            k_nas_enc: algo_key(&k_amf, 1, ea),
            k_nas_int: algo_key(&k_amf, 2, ia),
            ul_count: 0,
            dl_count: None,
            tx_direction: DIR_UL,
        })
    }

    /// Flip the context to the network side (used by test cores).
    pub fn as_network(mut self) -> Self {
        self.tx_direction = DIR_DL;
        self
    }

    fn rx_direction(&self) -> u8 {
        self.tx_direction ^ 1
    }

    /// The algorithms and keys of this context.
    pub fn keys(&self) -> NasKeys {
        NasKeys {
            ea: self.ea,
            ia: self.ia,
            k_enc: self.k_nas_enc,
            k_int: self.k_nas_int,
        }
    }

    /// The uplink NAS COUNT the next [`Self::protect`] call will use.
    pub fn next_ul_count(&self) -> u32 {
        self.ul_count
    }

    /// Protect `plain` with the next UL COUNT, then advance the COUNT.
    /// Returns the PDU and the COUNT that was used (needed for K_gNB).
    pub fn protect(&mut self, sht: SecurityHeaderType, plain: &[u8]) -> (Vec<u8>, u32) {
        let count = self.ul_count;
        let pdu = protect(sht, &self.keys(), count, self.tx_direction, plain);
        self.ul_count = (self.ul_count + 1) & 0x00ff_ffff;
        (pdu, count)
    }

    /// Estimate the downlink NAS COUNT from the 8-bit SQN in a received
    /// message (TS 24.501 §4.4.3.1): the overflow counter is incremented when
    /// the SQN wraps relative to the last accepted COUNT.
    pub fn estimate_dl_count(&self, seq: u8) -> u32 {
        match self.dl_count {
            None => seq as u32,
            Some(last) => {
                let overflow = last >> 8;
                let last_seq = (last & 0xff) as u8;
                let ovf = if seq <= last_seq {
                    (overflow + 1) & 0xffff
                } else {
                    overflow
                };
                (ovf << 8) | seq as u32
            }
        }
    }

    /// Verify, decipher and strip the header of a received protected
    /// message, advancing the DL COUNT. A message whose SQN equals that of
    /// the last accepted one is discarded as a replay (TS 24.501 §4.4.3.2)
    /// before the MAC is checked.
    pub fn unprotect(&mut self, pdu: &[u8], hdr: &SecurityHeader) -> Result<Vec<u8>, NasError> {
        if let Some(last) = self.dl_count {
            if (last & 0xff) as u8 == hdr.seq {
                return Err(NasError::Replay);
            }
        }
        let count = self.estimate_dl_count(hdr.seq);
        let dir = self.rx_direction();
        let plain = unprotect(pdu, hdr, &self.keys(), count, dir)?;
        self.dl_count = Some(count);
        Ok(plain)
    }

    /// K_gNB for the given uplink NAS COUNT (TS 33.501 A.9).
    pub fn k_gnb(&self, ul_nas_count: u32) -> [u8; 32] {
        k_gnb(&self.k_amf, ul_nas_count)
    }
}

/// Subscriber credentials on the USIM side.
#[derive(Debug, Clone, Copy)]
pub struct UsimKeys {
    pub k: [u8; 16],
    pub opc: [u8; 16],
}

/// The result of running 5G-AKA on an AUTHENTICATION REQUEST.
#[derive(Debug, Clone)]
pub enum AkaOutcome {
    /// AUTN verified and SQN fresh: RES* and the key hierarchy.
    Success(AkaKeys),
    /// MAC in AUTN did not verify (TS 24.501 §5.4.1.3.6, cause #20).
    MacFailure,
    /// SQN not in range: resynchronise with AUTS (cause #21).
    SyncFailure { auts: [u8; 14] },
}

/// Keys and RES* from a successful 5G-AKA run.
#[derive(Debug, Clone)]
pub struct AkaKeys {
    pub res_star: [u8; 16],
    pub ck: [u8; 16],
    pub ik: [u8; 16],
    pub k_ausf: [u8; 32],
    pub k_seaf: [u8; 32],
    pub k_amf: [u8; 32],
    /// The SQN carried in AUTN (48 bits).
    pub sqn: u64,
}

/// Decode a 48-bit SQN.
pub fn sqn_to_u64(s: &[u8; 6]) -> u64 {
    s.iter().fold(0u64, |a, &b| (a << 8) | b as u64)
}

/// Encode a 48-bit SQN.
pub fn sqn_from_u64(v: u64) -> [u8; 6] {
    let b = v.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Accept the network's SQN when it is greater than the highest SQN seen
/// (a simplified TS 33.102 Annex C.2 check without the IND array; also
/// bounds the jump by `delta` = 2^28 as in the spec).
pub fn sqn_is_fresh(sqn: u64, sqn_ms: Option<u64>) -> bool {
    match sqn_ms {
        None => true,
        Some(ms) => sqn > ms && sqn - ms <= (1 << 28),
    }
}

/// Run the USIM side of 5G-AKA (TS 33.501 §6.1.3.2 / TS 33.102 §6.3.3):
/// recover SQN from AUTN with AK, verify MAC-A, check SQN freshness
/// against `sqn_ms`, then derive RES*, K_AUSF, K_SEAF and K_AMF.
///
/// `supi` is the IMSI digit string (TS 33.501 A.7.0: P0 = SUPI as in
/// TS 23.003 without the "imsi-" prefix), `snn` the serving network name.
pub fn run_5g_aka(
    keys: &UsimKeys,
    rand: &[u8; 16],
    autn: &[u8; 16],
    snn: &str,
    supi: &str,
    abba: &[u8],
    sqn_ms: Option<u64>,
) -> AkaOutcome {
    let mut sqn_xor_ak = [0u8; 6];
    sqn_xor_ak.copy_from_slice(&autn[0..6]);
    let amf = [autn[6], autn[7]];
    // AK does not depend on SQN: run once with a dummy SQN to recover it.
    let z = milenage(&keys.k, &keys.opc, rand, &[0; 6], &amf);
    let mut sqn = [0u8; 6];
    for i in 0..6 {
        sqn[i] = sqn_xor_ak[i] ^ z.ak[i];
    }
    let m = milenage(&keys.k, &keys.opc, rand, &sqn, &amf);
    if m.mac_a != autn[8..16] {
        return AkaOutcome::MacFailure;
    }
    let sqn_v = sqn_to_u64(&sqn);
    if !sqn_is_fresh(sqn_v, sqn_ms) {
        // AUTS = (SQN_MS xor AK*) || MAC-S, MAC-S = f1*(SQN_MS || RAND || AMF*)
        // with AMF* = 0x0000 (TS 33.102 §6.3.3).
        let sqn_ms_b = sqn_from_u64(sqn_ms.unwrap_or(0));
        let r = milenage(&keys.k, &keys.opc, rand, &sqn_ms_b, &[0, 0]);
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = sqn_ms_b[i] ^ r.ak_star[i];
        }
        auts[6..14].copy_from_slice(&r.mac_s);
        return AkaOutcome::SyncFailure { auts };
    }
    let res_star = res_star(&m.ck, &m.ik, snn, rand, &m.res);
    let k_ausf = k_ausf(&m.ck, &m.ik, snn, &sqn_xor_ak);
    let k_seaf = k_seaf(&k_ausf, snn);
    let k_amf = k_amf(&k_seaf, supi, abba);
    AkaOutcome::Success(AkaKeys {
        res_star,
        ck: m.ck,
        ik: m.ik,
        k_ausf,
        k_seaf,
        k_amf,
        sqn: sqn_v,
    })
}

/// Network side helper (test cores / HSS emulation): build RAND-dependent
/// AUTN and XRES* and the same key hierarchy from the subscriber keys.
#[derive(Debug, Clone)]
pub struct AuthVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: [u8; 16],
    pub k_ausf: [u8; 32],
    pub k_seaf: [u8; 32],
    pub k_amf: [u8; 32],
}

/// Generate a 5G authentication vector (TS 33.501 §6.1.3.2, home network
/// side) for `sqn` / `amf`.
pub fn generate_auth_vector(
    keys: &UsimKeys,
    rand: [u8; 16],
    sqn: u64,
    amf: [u8; 2],
    snn: &str,
    supi: &str,
    abba: &[u8],
) -> AuthVector {
    let sqn_b = sqn_from_u64(sqn);
    let m = milenage(&keys.k, &keys.opc, &rand, &sqn_b, &amf);
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn_b[i] ^ m.ak[i];
    }
    autn[6..8].copy_from_slice(&amf);
    autn[8..16].copy_from_slice(&m.mac_a);
    let mut sqn_xor_ak = [0u8; 6];
    sqn_xor_ak.copy_from_slice(&autn[0..6]);
    let xres_star = res_star(&m.ck, &m.ik, snn, &rand, &m.res);
    let k_ausf = k_ausf(&m.ck, &m.ik, snn, &sqn_xor_ak);
    let k_seaf = k_seaf(&k_ausf, snn);
    let k_amf = k_amf(&k_seaf, supi, abba);
    AuthVector {
        rand,
        autn,
        xres_star,
        k_ausf,
        k_seaf,
        k_amf,
    }
}

/// Network side resynchronisation (TS 33.102 §6.3.5): recover SQN_MS from
/// AUTS and verify MAC-S. Returns `Some(sqn_ms)` when MAC-S verifies.
pub fn verify_auts(keys: &UsimKeys, rand: &[u8; 16], auts: &[u8; 14]) -> Option<u64> {
    let z = milenage(&keys.k, &keys.opc, rand, &[0; 6], &[0, 0]);
    let mut sqn_ms = [0u8; 6];
    for i in 0..6 {
        sqn_ms[i] = auts[i] ^ z.ak_star[i];
    }
    let r = milenage(&keys.k, &keys.opc, rand, &sqn_ms, &[0, 0]);
    (r.mac_s == auts[6..14]).then(|| sqn_to_u64(&sqn_ms))
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

    fn a16(s: &str) -> [u8; 16] {
        hx(s).try_into().unwrap()
    }

    /// 128-EEA2/NEA2 Test Set 1 (TS 33.401 C.1.1); 253 bits, so the last
    /// three bits of the final octet are don't-care.
    #[test]
    fn nea2_test_set_1() {
        let key = a16("d3c5d592327fb11c4035c6680af8c6d1");
        let pt = hx("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0");
        let ct = hx("e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78");
        let out = nea2(&key, 0x398a59b4, 0x15, 1, &pt);
        assert_eq!(&out[..31], &ct[..31]);
        assert_eq!(out[31] & 0xf8, ct[31] & 0xf8);
        // Decrypt is the same operation.
        let back = nea2(&key, 0x398a59b4, 0x15, 1, &out);
        assert_eq!(back, pt);
    }

    /// 128-EEA2/NEA2 Test Set 2 (TS 33.401 C.1.2); 798 bits.
    #[test]
    fn nea2_test_set_2() {
        let key = a16("2bd6459f82c440e0952c49104805ff48");
        let pt = hx(concat!(
            "7ec61272743bf1614726446a6c38ced166f6ca76eb5430044286346cef130f92",
            "922b03450d3a9975e5bd2ea0eb55ad8e1b199e3ec4316020e9a1b285e7627953",
            "59b7bdfd39bef4b2484583d5afe082aee638bf5fd5a606193901a08f4ab41aab",
            "9b134880"
        ));
        let ct = hx(concat!(
            "5961605353c64bdca15b195e288553a910632506d6200aa790c4c806c99904cf",
            "2445cc50bb1cf168a49673734e081b57e324ce5259c0e78d4cd97b870976503c",
            "0943f2cb5ae8f052c7b7d392239587b8956086bcab18836042e2e6ce42432a17",
            "105c53d0"
        ));
        let out = nea2(&key, 0xc675a64b, 0x0c, 1, &pt);
        let n = ct.len() - 1;
        assert_eq!(&out[..n], &ct[..n]);
        assert_eq!(out[n] & 0xfc, ct[n] & 0xfc);
    }

    fn ctx_pair() -> (NasSecurityContext, NasSecurityContext) {
        let k_amf = [0x42u8; 32];
        let ue = NasSecurityContext::new(k_amf, 1, 2, 2).unwrap();
        let nw = NasSecurityContext::new(k_amf, 1, 2, 2)
            .unwrap()
            .as_network();
        (ue, nw)
    }

    #[test]
    fn protect_verify_roundtrip_nea2_nia2() {
        let (mut ue, mut nw) = ctx_pair();
        let plain = vec![0x7e, 0x00, 0x43];
        let (pdu, c0) = ue.protect(SecurityHeaderType::IntegrityCiphered, &plain);
        assert_eq!(c0, 0);
        assert_eq!(pdu[1], 2);
        assert_ne!(&pdu[7..], &plain[..]); // ciphered
        let (hdr, _) = crate::mm::split_security_header(&pdu).unwrap();
        let got = nw.unprotect(&pdu, &hdr.unwrap()).unwrap();
        assert_eq!(got, plain);
        // Replay of the same PDU is rejected.
        let (hdr, _) = crate::mm::split_security_header(&pdu).unwrap();
        assert_eq!(nw.unprotect(&pdu, &hdr.unwrap()), Err(NasError::Replay));
        // Second message: count 1.
        let (pdu2, c1) = ue.protect(SecurityHeaderType::Integrity, &plain);
        assert_eq!(c1, 1);
        let (hdr, _) = crate::mm::split_security_header(&pdu2).unwrap();
        assert_eq!(nw.unprotect(&pdu2, &hdr.unwrap()).unwrap(), plain);
        // Tampered MAC on a fresh message.
        let (mut bad, _) = ue.protect(SecurityHeaderType::Integrity, &plain);
        bad[3] ^= 1;
        let (hdr, _) = crate::mm::split_security_header(&bad).unwrap();
        assert_eq!(nw.unprotect(&bad, &hdr.unwrap()), Err(NasError::MacFailure));
    }

    #[test]
    fn dl_count_estimation_wraps() {
        let (mut ue, mut nw) = ctx_pair();
        let plain = [0x7e, 0x00, 0x64, 0x5f];
        // Network sends 300 messages; the UE must follow the overflow counter.
        for i in 0..300u32 {
            let (pdu, c) = nw.protect(SecurityHeaderType::IntegrityCiphered, &plain);
            assert_eq!(c, i);
            let (hdr, _) = crate::mm::split_security_header(&pdu).unwrap();
            assert_eq!(ue.unprotect(&pdu, &hdr.unwrap()).unwrap(), plain);
            assert_eq!(ue.dl_count, Some(i));
        }
        assert_eq!(ue.estimate_dl_count(44), 300);
        assert_eq!(ue.estimate_dl_count(43), 0x100 + 43 + 0x100);
    }

    #[test]
    fn legacy_protect_is_compatible() {
        let k_amf = [0x11u8; 32];
        let mut ue = NasSecurityContext::new(k_amf, 0, 0, 2).unwrap();
        let plain = crate::msgs::registration_complete();
        let (pdu, _) = ue.protect(SecurityHeaderType::IntegrityCiphered, &plain);
        let k_int = algo_key(&k_amf, 2, 2);
        assert_eq!(pdu, crate::msgs::nas_protect(2, &k_int, 0, 0, &plain));
    }

    #[test]
    fn unsupported_algorithms_rejected() {
        assert!(matches!(
            NasSecurityContext::new([0; 32], 0, 1, 2),
            Err(NasError::UnsupportedAlgorithm { ea: 1, ia: 2 })
        ));
        assert!(matches!(
            NasSecurityContext::new([0; 32], 0, 0, 3),
            Err(NasError::UnsupportedAlgorithm { .. })
        ));
    }

    fn keys() -> UsimKeys {
        UsimKeys {
            k: a16("465b5ce8b199b49faa5f0a2ee238a6bc"),
            opc: a16("cd63cb71954a9f4e48a5994e37a02baf"),
        }
    }

    #[test]
    fn aka_success_and_mac_failure() {
        let snn = "5G:mnc001.mcc001.3gppnetwork.org";
        let supi = "001010000000001";
        let av = generate_auth_vector(
            &keys(),
            a16("23553cbe9637a89d218ae64dae47bf35"),
            0x20,
            [0x80, 0x00],
            snn,
            supi,
            &[0, 0],
        );
        match run_5g_aka(&keys(), &av.rand, &av.autn, snn, supi, &[0, 0], Some(0x1f)) {
            AkaOutcome::Success(k) => {
                assert_eq!(k.res_star, av.xres_star);
                assert_eq!(k.k_amf, av.k_amf);
                assert_eq!(k.sqn, 0x20);
            }
            other => panic!("expected success, got {other:?}"),
        }
        let mut bad = av.autn;
        bad[15] ^= 1;
        assert!(matches!(
            run_5g_aka(&keys(), &av.rand, &bad, snn, supi, &[0, 0], None),
            AkaOutcome::MacFailure
        ));
    }

    #[test]
    fn aka_sync_failure_and_auts_verification() {
        let snn = "5G:mnc001.mcc001.3gppnetwork.org";
        let supi = "001010000000001";
        let av = generate_auth_vector(&keys(), [0x5a; 16], 0x10, [0x80, 0x00], snn, supi, &[0, 0]);
        // UE has already seen SQN 0x40 → the network's 0x10 is stale.
        match run_5g_aka(&keys(), &av.rand, &av.autn, snn, supi, &[0, 0], Some(0x40)) {
            AkaOutcome::SyncFailure { auts } => {
                assert_eq!(verify_auts(&keys(), &av.rand, &auts), Some(0x40));
                let mut tampered = auts;
                tampered[13] ^= 1;
                assert_eq!(verify_auts(&keys(), &av.rand, &tampered), None);
            }
            other => panic!("expected sync failure, got {other:?}"),
        }
    }

    #[test]
    fn sqn_helpers() {
        assert_eq!(
            sqn_to_u64(&sqn_from_u64(0x1234_5678_9abc)),
            0x1234_5678_9abc
        );
        assert!(sqn_is_fresh(1, None));
        assert!(sqn_is_fresh(5, Some(4)));
        assert!(!sqn_is_fresh(4, Some(4)));
        assert!(!sqn_is_fresh(4 + (1 << 29), Some(4)));
    }
}
