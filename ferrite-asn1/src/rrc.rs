//! RRC message codecs (TS 38.331 §6.2.2): `DL-CCCH-Message`, `DL-DCCH-Message`,
//! `UL-CCCH-Message`, `UL-DCCH-Message`, the `RadioBearerConfig` family and a
//! minimal `UE-NR-Capability` encoder. Downlink messages decode (and, where
//! the content does not contain a `CellGroupConfig`, also encode, for
//! round-trip tests); uplink messages encode and decode.

use crate::cellgroup::CellGroupConfig;
use crate::common::{PlmnIdentity, SubcarrierSpacing};
use crate::meas::{MeasConfig, MeasResults};
use crate::uper::{BitReader, BitWriter, Ctx, DecodeError, DecodeResult, SetupRelease};

/// Why an encode was refused (only for downlink messages built for tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The message contains an IE this crate has no encoder for.
    Unsupported(&'static str),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::Unsupported(s) => write!(f, "cannot encode {s}"),
        }
    }
}

impl std::error::Error for EncodeError {}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// `CipheringAlgorithm ::= ENUMERATED { nea0, nea1, nea2, nea3, spare4, spare3, spare2, spare1, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipheringAlgorithm {
    Nea0,
    Nea1,
    Nea2,
    Nea3,
}

/// `IntegrityProtAlgorithm ::= ENUMERATED { nia0, nia1, nia2, nia3, spare4, spare3, spare2, spare1, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityProtAlgorithm {
    Nia0,
    Nia1,
    Nia2,
    Nia3,
}

/// `SecurityAlgorithmConfig ::= SEQUENCE { cipheringAlgorithm CipheringAlgorithm,
/// integrityProtAlgorithm IntegrityProtAlgorithm OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityAlgorithmConfig {
    pub ciphering_algorithm: CipheringAlgorithm,
    pub integrity_prot_algorithm: Option<IntegrityProtAlgorithm>,
}

impl SecurityAlgorithmConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_int] = r.opt_bits::<1>()?;
        let ciphering_algorithm = match r.enu_ext(8)? {
            Some(0) => CipheringAlgorithm::Nea0,
            Some(1) => CipheringAlgorithm::Nea1,
            Some(2) => CipheringAlgorithm::Nea2,
            Some(3) => CipheringAlgorithm::Nea3,
            _ => return r.unsupported("cipheringAlgorithm spare/extension value"),
        };
        let integrity_prot_algorithm = r.opt(has_int, |r| {
            Ok(match r.enu_ext(8)? {
                Some(0) => IntegrityProtAlgorithm::Nia0,
                Some(1) => IntegrityProtAlgorithm::Nia1,
                Some(2) => IntegrityProtAlgorithm::Nia2,
                Some(3) => IntegrityProtAlgorithm::Nia3,
                _ => return r.unsupported("integrityProtAlgorithm spare/extension value"),
            })
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            ciphering_algorithm,
            integrity_prot_algorithm,
        })
    }

    fn encode(&self, w: &mut BitWriter) {
        w.bit(false);
        w.bit(self.integrity_prot_algorithm.is_some());
        w.enu_ext(self.ciphering_algorithm as u32, 8);
        if let Some(i) = self.integrity_prot_algorithm {
            w.enu_ext(i as u32, 8);
        }
    }
}

/// `keyToUse ENUMERATED { master, secondary }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyToUse {
    Master,
    Secondary,
}

/// `SecurityConfig ::= SEQUENCE { securityAlgorithmConfig SecurityAlgorithmConfig OPTIONAL,
/// keyToUse ENUMERATED { master, secondary } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SecurityConfig {
    pub security_algorithm_config: Option<SecurityAlgorithmConfig>,
    pub key_to_use: Option<KeyToUse>,
}

// ---------------------------------------------------------------------------
// RadioBearerConfig
// ---------------------------------------------------------------------------

/// `discardTimer ENUMERATED { ms10, ms20, ms30, ms40, ms50, ms60, ms75, ms100, ms150, ms200, ms250,
/// ms300, ms500, ms750, ms1500, infinity }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdcpDiscardTimer {
    Ms(u16),
    Infinity,
}

const DISCARD_MS: [u16; 15] = [
    10, 20, 30, 40, 50, 60, 75, 100, 150, 200, 250, 300, 500, 750, 1500,
];

impl PdcpDiscardTimer {
    fn index(self) -> u32 {
        match self {
            Self::Infinity => 15,
            Self::Ms(ms) => DISCARD_MS.iter().position(|&v| v == ms).unwrap_or(15) as u32,
        }
    }
}

/// `headerCompression CHOICE { notUsed NULL, rohc SEQUENCE { maxCID INTEGER (1..16383) DEFAULT 15,
/// profiles SEQUENCE { profile0x0001 BOOLEAN, …, profile0x0104 BOOLEAN }, drb-ContinueROHC
/// ENUMERATED { true } OPTIONAL }, uplinkOnlyROHC SEQUENCE { maxCID INTEGER (1..16383) DEFAULT 15,
/// profiles SEQUENCE { profile0x0006 BOOLEAN }, drb-ContinueROHC ENUMERATED { true } OPTIONAL }, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderCompression {
    NotUsed,
    Rohc {
        max_cid: Option<u16>,
        /// Profiles 0x0001, 0x0002, 0x0003, 0x0004, 0x0006, 0x0101, 0x0102, 0x0103, 0x0104 (bit 8 = first).
        profiles: u16,
        drb_continue_rohc: bool,
    },
    UplinkOnlyRohc {
        max_cid: Option<u16>,
        profile0x0006: bool,
        drb_continue_rohc: bool,
    },
}

/// `drb SEQUENCE { discardTimer ENUMERATED {…} OPTIONAL, pdcp-SN-SizeUL ENUMERATED { len12bits,
/// len18bits } OPTIONAL, pdcp-SN-SizeDL ENUMERATED {…} OPTIONAL, headerCompression CHOICE {…},
/// integrityProtection ENUMERATED { enabled } OPTIONAL, statusReportRequired ENUMERATED { true }
/// OPTIONAL, outOfOrderDelivery ENUMERATED { true } OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdcpDrbConfig {
    pub discard_timer: Option<PdcpDiscardTimer>,
    /// 12 or 18.
    pub pdcp_sn_size_ul: Option<u8>,
    pub pdcp_sn_size_dl: Option<u8>,
    pub header_compression: HeaderCompression,
    pub integrity_protection: bool,
    pub status_report_required: bool,
    pub out_of_order_delivery: bool,
}

/// `moreThanOneRLC SEQUENCE { primaryPath SEQUENCE { cellGroup CellGroupId OPTIONAL, logicalChannel
/// LogicalChannelIdentity OPTIONAL }, ul-DataSplitThreshold UL-DataSplitThreshold OPTIONAL,
/// pdcp-Duplication BOOLEAN OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MoreThanOneRlc {
    pub primary_path_cell_group: Option<u8>,
    pub primary_path_logical_channel: Option<u8>,
    /// Raw `UL-DataSplitThreshold` index.
    pub ul_data_split_threshold: Option<u8>,
    pub pdcp_duplication: Option<bool>,
}

/// `PDCP-Config ::= SEQUENCE { drb SEQUENCE {…} OPTIONAL, moreThanOneRLC SEQUENCE {…} OPTIONAL,
/// t-Reordering ENUMERATED { ms0, ms1, ms2, ms4, ms5, ms8, ms10, ms15, ms20, ms30, ms40, ms50, ms60,
/// ms80, ms100, ms120, ms140, ms160, ms180, ms200, ms220, ms240, ms260, ms280, ms300, ms500, ms750,
/// ms1000, ms1250, ms1500, ms1750, ms2000, ms2250, ms2500, ms2750, ms3000, spare28..spare01 } OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PdcpConfig {
    pub drb: Option<PdcpDrbConfig>,
    pub more_than_one_rlc: Option<MoreThanOneRlc>,
    pub t_reordering_ms: Option<u16>,
}

const T_REORDERING_MS: [u16; 36] = [
    0, 1, 2, 4, 5, 8, 10, 15, 20, 30, 40, 50, 60, 80, 100, 120, 140, 160, 180, 200, 220, 240, 260,
    280, 300, 500, 750, 1000, 1250, 1500, 1750, 2000, 2250, 2500, 2750, 3000,
];

impl PdcpConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [has_drb, has_more, has_treo] = r.opt_bits::<3>()?;
        let drb = r.opt(has_drb, |r| {
            let [dt, snul, sndl, ip, srr, ooo] = r.opt_bits::<6>()?;
            let discard_timer = r.opt(dt, |r| {
                let i = r.enu(16)?;
                Ok(if i == 15 {
                    PdcpDiscardTimer::Infinity
                } else {
                    PdcpDiscardTimer::Ms(DISCARD_MS[i as usize])
                })
            })?;
            let pdcp_sn_size_ul = r.opt(snul, |r| Ok([12u8, 18][r.enu(2)? as usize]))?;
            let pdcp_sn_size_dl = r.opt(sndl, |r| Ok([12u8, 18][r.enu(2)? as usize]))?;
            if r.bit()? {
                return r.unsupported("headerCompression extension alternative");
            }
            let header_compression = match r.uint(0, 2)? {
                0 => HeaderCompression::NotUsed,
                1 => {
                    let [has_cid, cont] = r.opt_bits::<2>()?;
                    let max_cid = r.opt(has_cid, |r| r.u16(1, 16383))?;
                    let profiles = r.bits(9)? as u16;
                    HeaderCompression::Rohc {
                        max_cid,
                        profiles,
                        drb_continue_rohc: cont,
                    }
                }
                _ => {
                    let [has_cid, cont] = r.opt_bits::<2>()?;
                    let max_cid = r.opt(has_cid, |r| r.u16(1, 16383))?;
                    let profile0x0006 = r.boolean()?;
                    HeaderCompression::UplinkOnlyRohc {
                        max_cid,
                        profile0x0006,
                        drb_continue_rohc: cont,
                    }
                }
            };
            Ok(PdcpDrbConfig {
                discard_timer,
                pdcp_sn_size_ul,
                pdcp_sn_size_dl,
                header_compression,
                integrity_protection: ip,
                status_report_required: srr,
                out_of_order_delivery: ooo,
            })
        })?;
        let more_than_one_rlc = r.opt(has_more, |r| {
            let [thr, dup, cg, lc] = r.opt_bits::<4>()?;
            let primary_path_cell_group = r.opt(cg, |r| r.u8(0, 3))?;
            let primary_path_logical_channel = r.opt(lc, |r| r.u8(1, 32))?;
            let ul_data_split_threshold = r.opt(thr, |r| Ok(r.enu(32)? as u8))?;
            let pdcp_duplication = r.opt(dup, |r| r.boolean())?;
            Ok(MoreThanOneRlc {
                primary_path_cell_group,
                primary_path_logical_channel,
                ul_data_split_threshold,
                pdcp_duplication,
            })
        })?;
        let t_reordering_ms = r.opt(has_treo, |r| {
            let i = r.enu(64)?;
            T_REORDERING_MS
                .get(i as usize)
                .copied()
                .ok_or_else(|| DecodeError::invalid("t-Reordering spare value", r.pos()))
        })?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            drb,
            more_than_one_rlc,
            t_reordering_ms,
        })
    }

    fn encode(&self, w: &mut BitWriter) {
        w.bit(false);
        w.opt_bits(&[
            self.drb.is_some(),
            self.more_than_one_rlc.is_some(),
            self.t_reordering_ms.is_some(),
        ]);
        if let Some(d) = &self.drb {
            w.opt_bits(&[
                d.discard_timer.is_some(),
                d.pdcp_sn_size_ul.is_some(),
                d.pdcp_sn_size_dl.is_some(),
                d.integrity_protection,
                d.status_report_required,
                d.out_of_order_delivery,
            ]);
            if let Some(t) = d.discard_timer {
                w.enu(t.index(), 16);
            }
            for sn in [d.pdcp_sn_size_ul, d.pdcp_sn_size_dl].into_iter().flatten() {
                w.enu(if sn == 18 { 1 } else { 0 }, 2);
            }
            w.bit(false);
            match d.header_compression {
                HeaderCompression::NotUsed => w.uint(0, 0, 2),
                HeaderCompression::Rohc {
                    max_cid,
                    profiles,
                    drb_continue_rohc,
                } => {
                    w.uint(1, 0, 2);
                    w.opt_bits(&[max_cid.is_some(), drb_continue_rohc]);
                    if let Some(c) = max_cid {
                        w.uint(c as u32, 1, 16383);
                    }
                    w.bits(profiles as u64, 9);
                }
                HeaderCompression::UplinkOnlyRohc {
                    max_cid,
                    profile0x0006,
                    drb_continue_rohc,
                } => {
                    w.uint(2, 0, 2);
                    w.opt_bits(&[max_cid.is_some(), drb_continue_rohc]);
                    if let Some(c) = max_cid {
                        w.uint(c as u32, 1, 16383);
                    }
                    w.bit(profile0x0006);
                }
            }
        }
        if let Some(m) = &self.more_than_one_rlc {
            w.opt_bits(&[
                m.ul_data_split_threshold.is_some(),
                m.pdcp_duplication.is_some(),
                m.primary_path_cell_group.is_some(),
                m.primary_path_logical_channel.is_some(),
            ]);
            if let Some(c) = m.primary_path_cell_group {
                w.uint(c as u32, 0, 3);
            }
            if let Some(l) = m.primary_path_logical_channel {
                w.uint(l as u32, 1, 32);
            }
            if let Some(t) = m.ul_data_split_threshold {
                w.enu(t as u32, 32);
            }
            if let Some(d) = m.pdcp_duplication {
                w.bit(d);
            }
        }
        if let Some(t) = self.t_reordering_ms {
            w.enu(
                T_REORDERING_MS.iter().position(|&v| v == t).unwrap_or(0) as u32,
                64,
            );
        }
    }
}

/// `SRB-ToAddMod ::= SEQUENCE { srb-Identity SRB-Identity, reestablishPDCP ENUMERATED { true }
/// OPTIONAL, discardOnPDCP ENUMERATED { true } OPTIONAL, pdcp-Config PDCP-Config OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrbToAddMod {
    pub srb_identity: u8,
    pub reestablish_pdcp: bool,
    pub discard_on_pdcp: bool,
    pub pdcp_config: Option<PdcpConfig>,
}

/// `SDAP-Config ::= SEQUENCE { pdu-Session PDU-SessionID, sdap-HeaderDL ENUMERATED { present, absent },
/// sdap-HeaderUL ENUMERATED { present, absent }, defaultDRB BOOLEAN, mappedQoS-FlowsToAdd SEQUENCE
/// (SIZE (1..maxNrofQFIs)) OF QFI OPTIONAL, mappedQoS-FlowsToRelease … OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdapConfig {
    pub pdu_session: u8,
    pub sdap_header_dl_present: bool,
    pub sdap_header_ul_present: bool,
    pub default_drb: bool,
    pub mapped_qos_flows_to_add: Vec<u8>,
    pub mapped_qos_flows_to_release: Vec<u8>,
}

/// `cnAssociation CHOICE { eps-BearerIdentity INTEGER (0..15), sdap-Config SDAP-Config }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CnAssociation {
    EpsBearerIdentity(u8),
    SdapConfig(SdapConfig),
}

/// `DRB-ToAddMod ::= SEQUENCE { cnAssociation CHOICE {…} OPTIONAL, drb-Identity DRB-Identity,
/// reestablishPDCP ENUMERATED { true } OPTIONAL, recoverPDCP ENUMERATED { true } OPTIONAL,
/// pdcp-Config PDCP-Config OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrbToAddMod {
    pub cn_association: Option<CnAssociation>,
    pub drb_identity: u8,
    pub reestablish_pdcp: bool,
    pub recover_pdcp: bool,
    pub pdcp_config: Option<PdcpConfig>,
}

/// `RadioBearerConfig ::= SEQUENCE { srb-ToAddModList SRB-ToAddModList OPTIONAL, srb3-ToRelease
/// ENUMERATED { true } OPTIONAL, drb-ToAddModList DRB-ToAddModList OPTIONAL, drb-ToReleaseList
/// DRB-ToReleaseList OPTIONAL, securityConfig SecurityConfig OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RadioBearerConfig {
    pub srb_to_add_mod_list: Vec<SrbToAddMod>,
    pub srb3_to_release: bool,
    pub drb_to_add_mod_list: Vec<DrbToAddMod>,
    pub drb_to_release_list: Vec<u8>,
    pub security_config: Option<SecurityConfig>,
}

impl RadioBearerConfig {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let ext = r.bit()?;
        let [srb, srb3rel, drb, drbrel, sec] = r.opt_bits::<5>()?;
        let srb_to_add_mod_list = if srb {
            r.seq_of(1, 2, |r| {
                let e = r.bit()?;
                let [re, disc, pdcp] = r.opt_bits::<3>()?;
                let srb_identity = r.u8(1, 3)?;
                let pdcp_config = r.opt(pdcp, PdcpConfig::decode).ctx("pdcp-Config")?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(SrbToAddMod {
                    srb_identity,
                    reestablish_pdcp: re,
                    discard_on_pdcp: disc,
                    pdcp_config,
                })
            })
            .ctx("srb-ToAddModList")?
        } else {
            vec![]
        };
        let drb_to_add_mod_list = if drb {
            r.seq_of(1, 29, |r| {
                let e = r.bit()?;
                let [cn, re, rec, pdcp] = r.opt_bits::<4>()?;
                let cn_association = r
                    .opt(cn, |r| {
                        Ok(if !r.bit()? {
                            CnAssociation::EpsBearerIdentity(r.u8(0, 15)?)
                        } else {
                            let se = r.bit()?;
                            let [add, rel] = r.opt_bits::<2>()?;
                            let pdu_session = r.u8(0, 255)?;
                            let sdap_header_dl_present = r.enu(2)? == 0;
                            let sdap_header_ul_present = r.enu(2)? == 0;
                            let default_drb = r.boolean()?;
                            let mapped_qos_flows_to_add = if add {
                                r.seq_of(1, 64, |r| r.u8(0, 63))?
                            } else {
                                vec![]
                            };
                            let mapped_qos_flows_to_release = if rel {
                                r.seq_of(1, 64, |r| r.u8(0, 63))?
                            } else {
                                vec![]
                            };
                            if se {
                                r.skip_ext_additions()?;
                            }
                            CnAssociation::SdapConfig(SdapConfig {
                                pdu_session,
                                sdap_header_dl_present,
                                sdap_header_ul_present,
                                default_drb,
                                mapped_qos_flows_to_add,
                                mapped_qos_flows_to_release,
                            })
                        })
                    })
                    .ctx("cnAssociation")?;
                let drb_identity = r.u8(1, 32)?;
                let pdcp_config = r.opt(pdcp, PdcpConfig::decode).ctx("pdcp-Config")?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(DrbToAddMod {
                    cn_association,
                    drb_identity,
                    reestablish_pdcp: re,
                    recover_pdcp: rec,
                    pdcp_config,
                })
            })
            .ctx("drb-ToAddModList")?
        } else {
            vec![]
        };
        let drb_to_release_list = if drbrel {
            r.seq_of(1, 29, |r| r.u8(1, 32))?
        } else {
            vec![]
        };
        let security_config = r
            .opt(sec, |r| {
                let e = r.bit()?;
                let [alg, key] = r.opt_bits::<2>()?;
                let security_algorithm_config = r.opt(alg, SecurityAlgorithmConfig::decode)?;
                let key_to_use = r.opt(key, |r| {
                    Ok(if r.enu(2)? == 0 {
                        KeyToUse::Master
                    } else {
                        KeyToUse::Secondary
                    })
                })?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(SecurityConfig {
                    security_algorithm_config,
                    key_to_use,
                })
            })
            .ctx("securityConfig")?;
        if ext {
            r.skip_ext_additions()?;
        }
        Ok(Self {
            srb_to_add_mod_list,
            srb3_to_release: srb3rel,
            drb_to_add_mod_list,
            drb_to_release_list,
            security_config,
        })
    }

    fn encode(&self, w: &mut BitWriter) {
        w.bit(false);
        w.opt_bits(&[
            !self.srb_to_add_mod_list.is_empty(),
            self.srb3_to_release,
            !self.drb_to_add_mod_list.is_empty(),
            !self.drb_to_release_list.is_empty(),
            self.security_config.is_some(),
        ]);
        if !self.srb_to_add_mod_list.is_empty() {
            w.seq_of(&self.srb_to_add_mod_list, 1, 2, |w, s| {
                w.bit(false);
                w.opt_bits(&[
                    s.reestablish_pdcp,
                    s.discard_on_pdcp,
                    s.pdcp_config.is_some(),
                ]);
                w.uint(s.srb_identity as u32, 1, 3);
                if let Some(p) = &s.pdcp_config {
                    p.encode(w);
                }
            });
        }
        if !self.drb_to_add_mod_list.is_empty() {
            w.seq_of(&self.drb_to_add_mod_list, 1, 29, |w, d| {
                w.bit(false);
                w.opt_bits(&[
                    d.cn_association.is_some(),
                    d.reestablish_pdcp,
                    d.recover_pdcp,
                    d.pdcp_config.is_some(),
                ]);
                match &d.cn_association {
                    None => {}
                    Some(CnAssociation::EpsBearerIdentity(id)) => {
                        w.bit(false);
                        w.uint(*id as u32, 0, 15);
                    }
                    Some(CnAssociation::SdapConfig(s)) => {
                        w.bit(true);
                        w.bit(false);
                        w.opt_bits(&[
                            !s.mapped_qos_flows_to_add.is_empty(),
                            !s.mapped_qos_flows_to_release.is_empty(),
                        ]);
                        w.uint(s.pdu_session as u32, 0, 255);
                        w.enu(if s.sdap_header_dl_present { 0 } else { 1 }, 2);
                        w.enu(if s.sdap_header_ul_present { 0 } else { 1 }, 2);
                        w.bit(s.default_drb);
                        if !s.mapped_qos_flows_to_add.is_empty() {
                            w.seq_of(&s.mapped_qos_flows_to_add, 1, 64, |w, q| {
                                w.uint(*q as u32, 0, 63)
                            });
                        }
                        if !s.mapped_qos_flows_to_release.is_empty() {
                            w.seq_of(&s.mapped_qos_flows_to_release, 1, 64, |w, q| {
                                w.uint(*q as u32, 0, 63)
                            });
                        }
                    }
                }
                w.uint(d.drb_identity as u32, 1, 32);
                if let Some(p) = &d.pdcp_config {
                    p.encode(w);
                }
            });
        }
        if !self.drb_to_release_list.is_empty() {
            w.seq_of(&self.drb_to_release_list, 1, 29, |w, d| {
                w.uint(*d as u32, 1, 32)
            });
        }
        if let Some(s) = &self.security_config {
            w.bit(false);
            w.opt_bits(&[
                s.security_algorithm_config.is_some(),
                s.key_to_use.is_some(),
            ]);
            if let Some(a) = &s.security_algorithm_config {
                a.encode(w);
            }
            if let Some(k) = s.key_to_use {
                w.enu(k as u32, 2);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DL-CCCH
// ---------------------------------------------------------------------------

/// `RRCReject ::= SEQUENCE { criticalExtensions CHOICE { rrcReject RRCReject-IEs, criticalExtensionsFuture
/// SEQUENCE {} } }` with `RRCReject-IEs ::= SEQUENCE { waitTime RejectWaitTime OPTIONAL,
/// lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RrcReject {
    /// `RejectWaitTime ::= INTEGER (1..16)` seconds.
    pub wait_time: Option<u8>,
}

/// `RRCSetup ::= SEQUENCE { rrc-TransactionIdentifier RRC-TransactionIdentifier, criticalExtensions
/// CHOICE { rrcSetup RRCSetup-IEs, criticalExtensionsFuture SEQUENCE {} } }` with `RRCSetup-IEs ::=
/// SEQUENCE { radioBearerConfig RadioBearerConfig, masterCellGroup OCTET STRING (CONTAINING
/// CellGroupConfig), lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension
/// RRCSetup-v1690-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrcSetup {
    pub rrc_transaction_identifier: u8,
    pub radio_bearer_config: RadioBearerConfig,
    pub master_cell_group: CellGroupConfig,
}

/// `DL-CCCH-MessageType ::= CHOICE { c1 CHOICE { rrcReject RRCReject, rrcSetup RRCSetup, spare2 NULL,
/// spare1 NULL }, messageClassExtension SEQUENCE {} }`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // RRCSetup carries the whole CellGroupConfig by design
pub enum DlCcchMessage {
    RrcReject(RrcReject),
    RrcSetup(RrcSetup),
}

impl DlCcchMessage {
    /// Decode a `DL-CCCH-Message` PDU (the CCCH SDU of Msg4).
    pub fn decode(pdu: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(pdu)).ctx("DL-CCCH-Message")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        match r.uint(0, 3)? {
            0 => {
                if r.bit()? {
                    return r.unsupported("criticalExtensionsFuture");
                }
                let [has_wait, _late, _non_crit] = r.opt_bits::<3>()?;
                let wait_time = r.opt(has_wait, |r| r.u8(1, 16))?;
                Ok(Self::RrcReject(RrcReject { wait_time })).ctx("RRCReject")
            }
            1 => {
                let rrc_transaction_identifier = r.u8(0, 3)?;
                if r.bit()? {
                    return r.unsupported("criticalExtensionsFuture");
                }
                let [_late, _non_crit] = r.opt_bits::<2>()?;
                let radio_bearer_config =
                    RadioBearerConfig::decode(r).ctx("RRCSetup/radioBearerConfig")?;
                let mcg = r.octet_string().ctx("RRCSetup/masterCellGroup")?;
                log::trace!("masterCellGroup: {} octets", mcg.len());
                let master_cell_group =
                    CellGroupConfig::decode(&mcg).ctx("RRCSetup/masterCellGroup")?;
                Ok(Self::RrcSetup(RrcSetup {
                    rrc_transaction_identifier,
                    radio_bearer_config,
                    master_cell_group,
                }))
            }
            _ => r.unsupported("DL-CCCH spare message"),
        }
    }

    /// Encode (test/tooling aid): `RRCSetup` is refused because this crate has no
    /// `CellGroupConfig` encoder.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = BitWriter::new();
        w.bit(false);
        match self {
            Self::RrcReject(m) => {
                w.uint(0, 0, 3);
                w.bit(false);
                w.opt_bits(&[m.wait_time.is_some(), false, false]);
                if let Some(t) = m.wait_time {
                    w.uint(t as u32, 1, 16);
                }
            }
            Self::RrcSetup(_) => {
                return Err(EncodeError::Unsupported(
                    "RRCSetup/masterCellGroup (CellGroupConfig)",
                ))
            }
        }
        Ok(w.finish())
    }
}

// ---------------------------------------------------------------------------
// DL-DCCH
// ---------------------------------------------------------------------------

/// `MasterKeyUpdate ::= SEQUENCE { keySetChangeIndicator BOOLEAN, nextHopChainingCount
/// NextHopChainingCount, nas-Container OCTET STRING OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterKeyUpdate {
    pub key_set_change_indicator: bool,
    pub next_hop_chaining_count: u8,
    pub nas_container: Option<Vec<u8>>,
}

/// `OtherConfig ::= SEQUENCE { delayBudgetReportingConfig CHOICE { release NULL, setup SEQUENCE {
/// delayBudgetReportingProhibitTimer ENUMERATED { s0, s0dot4, s0dot8, s1dot6, s3, s6, s12, s30 } } }
/// OPTIONAL }` — the timer as its raw index.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OtherConfig {
    pub delay_budget_reporting_config: Option<SetupRelease<u8>>,
}

/// `MRDC-SecondaryCellGroupConfig ::= SEQUENCE { mrdc-ReleaseAndAdd ENUMERATED { true } OPTIONAL,
/// mrdc-SecondaryCellGroup CHOICE { nr-SCG OCTET STRING, eutra-SCG OCTET STRING } }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MrdcSecondaryCellGroupConfig {
    pub mrdc_release_and_add: bool,
    /// `true` for `nr-SCG`, `false` for `eutra-SCG`.
    pub nr_scg: bool,
    pub secondary_cell_group: Vec<u8>,
}

/// `RRCReconfiguration-v1560-IEs ::= SEQUENCE { mrdc-SecondaryCellGroupConfig SetupRelease {…}
/// OPTIONAL, radioBearerConfig2 OCTET STRING (CONTAINING RadioBearerConfig) OPTIONAL, sk-Counter
/// SK-Counter OPTIONAL, nonCriticalExtension RRCReconfiguration-v1610-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcReconfigurationV1560 {
    pub mrdc_secondary_cell_group_config: Option<SetupRelease<MrdcSecondaryCellGroupConfig>>,
    pub radio_bearer_config2: Option<Vec<u8>>,
    pub sk_counter: Option<u16>,
    /// `RRCReconfiguration-v1610-IEs` present (not interpreted; nothing follows it).
    pub v1610_present: bool,
}

/// `RRCReconfiguration-v1540-IEs ::= SEQUENCE { otherConfig-v1540 OtherConfig-v1540 OPTIONAL,
/// nonCriticalExtension RRCReconfiguration-v1560-IEs OPTIONAL }` with `OtherConfig-v1540 ::= SEQUENCE
/// { overheatingAssistanceConfig SetupRelease { OverheatingAssistanceConfig } OPTIONAL, ... }` and
/// `OverheatingAssistanceConfig ::= SEQUENCE { overheatingIndicationProhibitTimer ENUMERATED { s0,
/// s0dot5, s1, s2, s5, s10, s20, s30, s60, s90, s120, s300, s600, spare3, spare2, spare1 } }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcReconfigurationV1540 {
    /// `overheatingIndicationProhibitTimer` raw index when `otherConfig-v1540` sets it up.
    pub overheating_assistance_config: Option<Option<SetupRelease<u8>>>,
    pub v1560: Option<RrcReconfigurationV1560>,
}

/// `RRCReconfiguration-v1530-IEs ::= SEQUENCE { masterCellGroup OCTET STRING (CONTAINING CellGroupConfig)
/// OPTIONAL, fullConfig ENUMERATED { true } OPTIONAL, dedicatedNAS-MessageList SEQUENCE (SIZE(1..maxDRB))
/// OF DedicatedNAS-Message OPTIONAL, masterKeyUpdate MasterKeyUpdate OPTIONAL, dedicatedSIB1-Delivery
/// OCTET STRING OPTIONAL, dedicatedSystemInformationDelivery OCTET STRING OPTIONAL, otherConfig
/// OtherConfig OPTIONAL, nonCriticalExtension RRCReconfiguration-v1540-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcReconfigurationV1530 {
    pub master_cell_group: Option<CellGroupConfig>,
    pub full_config: bool,
    pub dedicated_nas_message_list: Vec<Vec<u8>>,
    pub master_key_update: Option<MasterKeyUpdate>,
    pub dedicated_sib1_delivery: Option<Vec<u8>>,
    pub dedicated_system_information_delivery: Option<Vec<u8>>,
    pub other_config: Option<OtherConfig>,
    pub v1540: Option<RrcReconfigurationV1540>,
}

/// `RRCReconfiguration ::= SEQUENCE { rrc-TransactionIdentifier RRC-TransactionIdentifier,
/// criticalExtensions CHOICE { rrcReconfiguration RRCReconfiguration-IEs, criticalExtensionsFuture
/// SEQUENCE {} } }` with `RRCReconfiguration-IEs ::= SEQUENCE { radioBearerConfig RadioBearerConfig
/// OPTIONAL, secondaryCellGroup OCTET STRING (CONTAINING CellGroupConfig) OPTIONAL, measConfig
/// MeasConfig OPTIONAL, lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension
/// RRCReconfiguration-v1530-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcReconfiguration {
    pub rrc_transaction_identifier: u8,
    pub radio_bearer_config: Option<RadioBearerConfig>,
    /// Raw `secondaryCellGroup` container octets (not decoded).
    pub secondary_cell_group: Option<Vec<u8>>,
    pub meas_config: Option<MeasConfig>,
    pub late_non_critical_extension: Option<Vec<u8>>,
    pub v1530: Option<RrcReconfigurationV1530>,
}

impl RrcReconfiguration {
    /// The `masterCellGroup` carried in the v1530 extension, if any.
    pub fn master_cell_group(&self) -> Option<&CellGroupConfig> {
        self.v1530.as_ref()?.master_cell_group.as_ref()
    }

    /// The `dedicatedNAS-MessageList` PDUs (empty when absent).
    pub fn dedicated_nas_messages(&self) -> &[Vec<u8>] {
        self.v1530
            .as_ref()
            .map_or(&[], |v| v.dedicated_nas_message_list.as_slice())
    }

    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let rrc_transaction_identifier = r.u8(0, 3)?;
        if r.bit()? {
            return r.unsupported("criticalExtensionsFuture");
        }
        let [rbc, scg, meas, late, non_crit] = r.opt_bits::<5>()?;
        let radio_bearer_config = r
            .opt(rbc, RadioBearerConfig::decode)
            .ctx("radioBearerConfig")?;
        let secondary_cell_group = r.opt(scg, |r| r.octet_string())?;
        let meas_config = r.opt(meas, MeasConfig::decode).ctx("measConfig")?;
        let late_non_critical_extension = r.opt(late, |r| r.octet_string())?;
        let v1530 = r
            .opt(non_crit, Self::decode_v1530)
            .ctx("RRCReconfiguration-v1530-IEs")?;
        Ok(Self {
            rrc_transaction_identifier,
            radio_bearer_config,
            secondary_cell_group,
            meas_config,
            late_non_critical_extension,
            v1530,
        })
    }

    fn decode_v1530(r: &mut BitReader) -> DecodeResult<RrcReconfigurationV1530> {
        let o = r.opt_bits::<8>()?;
        let master_cell_group = r
            .opt(o[0], |r| {
                let octets = r.octet_string()?;
                CellGroupConfig::decode(&octets)
            })
            .ctx("masterCellGroup")?;
        let dedicated_nas_message_list = if o[2] {
            r.seq_of(1, 29, |r| r.octet_string())
                .ctx("dedicatedNAS-MessageList")?
        } else {
            vec![]
        };
        let master_key_update = r
            .opt(o[3], |r| {
                let e = r.bit()?;
                let [has_nas] = r.opt_bits::<1>()?;
                let key_set_change_indicator = r.boolean()?;
                let next_hop_chaining_count = r.u8(0, 7)?;
                let nas_container = r.opt(has_nas, |r| r.octet_string())?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(MasterKeyUpdate {
                    key_set_change_indicator,
                    next_hop_chaining_count,
                    nas_container,
                })
            })
            .ctx("masterKeyUpdate")?;
        let dedicated_sib1_delivery = r.opt(o[4], |r| r.octet_string())?;
        let dedicated_system_information_delivery = r.opt(o[5], |r| r.octet_string())?;
        let other_config = r.opt(o[6], |r| {
            let [has_dbr] = r.opt_bits::<1>()?;
            let delay_budget_reporting_config =
                r.opt(has_dbr, |r| r.setup_release(|r| Ok(r.enu(8)? as u8)))?;
            Ok(OtherConfig {
                delay_budget_reporting_config,
            })
        })?;
        let v1540 = r
            .opt(o[7], |r| {
                let [has_oc, has_next] = r.opt_bits::<2>()?;
                let overheating_assistance_config = r.opt(has_oc, |r| {
                    let e = r.bit()?;
                    let [has] = r.opt_bits::<1>()?;
                    let v = r.opt(has, |r| r.setup_release(|r| Ok(r.enu(16)? as u8)))?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    Ok(v)
                })?;
                let v1560 = r.opt(has_next, |r| {
                    let [mrdc, rbc2, sk, next] = r.opt_bits::<4>()?;
                    let mrdc_secondary_cell_group_config = r.opt(mrdc, |r| {
                        r.setup_release(|r| {
                            let [rel_add] = r.opt_bits::<1>()?;
                            let nr_scg = !r.bit()?;
                            let secondary_cell_group = r.octet_string()?;
                            Ok(MrdcSecondaryCellGroupConfig {
                                mrdc_release_and_add: rel_add,
                                nr_scg,
                                secondary_cell_group,
                            })
                        })
                    })?;
                    let radio_bearer_config2 = r.opt(rbc2, |r| r.octet_string())?;
                    let sk_counter = r.opt(sk, |r| r.u16(0, 65535))?;
                    Ok(RrcReconfigurationV1560 {
                        mrdc_secondary_cell_group_config,
                        radio_bearer_config2,
                        sk_counter,
                        v1610_present: next,
                    })
                })?;
                Ok(RrcReconfigurationV1540 {
                    overheating_assistance_config,
                    v1560,
                })
            })
            .ctx("RRCReconfiguration-v1540-IEs")?;
        Ok(RrcReconfigurationV1530 {
            master_cell_group,
            full_config: o[1],
            dedicated_nas_message_list,
            master_key_update,
            dedicated_sib1_delivery,
            dedicated_system_information_delivery,
            other_config,
            v1540,
        })
    }

    fn encode(&self, w: &mut BitWriter) -> Result<(), EncodeError> {
        w.uint(self.rrc_transaction_identifier as u32, 0, 3);
        w.bit(false);
        w.opt_bits(&[
            self.radio_bearer_config.is_some(),
            self.secondary_cell_group.is_some(),
            false,
            self.late_non_critical_extension.is_some(),
            self.v1530.is_some(),
        ]);
        if let Some(rbc) = &self.radio_bearer_config {
            rbc.encode(w);
        }
        if let Some(s) = &self.secondary_cell_group {
            w.octet_string(s);
        }
        if let Some(l) = &self.late_non_critical_extension {
            w.octet_string(l);
        }
        if let Some(v) = &self.v1530 {
            if v.master_cell_group.is_some() {
                return Err(EncodeError::Unsupported(
                    "RRCReconfiguration/masterCellGroup (CellGroupConfig)",
                ));
            }
            w.opt_bits(&[
                false,
                v.full_config,
                !v.dedicated_nas_message_list.is_empty(),
                v.master_key_update.is_some(),
                v.dedicated_sib1_delivery.is_some(),
                v.dedicated_system_information_delivery.is_some(),
                v.other_config.is_some(),
                v.v1540.is_some(),
            ]);
            if !v.dedicated_nas_message_list.is_empty() {
                w.seq_of(&v.dedicated_nas_message_list, 1, 29, |w, m| {
                    w.octet_string(m)
                });
            }
            if let Some(k) = &v.master_key_update {
                w.bit(false);
                w.bit(k.nas_container.is_some());
                w.bit(k.key_set_change_indicator);
                w.uint(k.next_hop_chaining_count as u32, 0, 7);
                if let Some(n) = &k.nas_container {
                    w.octet_string(n);
                }
            }
            if let Some(s) = &v.dedicated_sib1_delivery {
                w.octet_string(s);
            }
            if let Some(s) = &v.dedicated_system_information_delivery {
                w.octet_string(s);
            }
            if let Some(oc) = &v.other_config {
                w.bit(oc.delay_budget_reporting_config.is_some());
                if let Some(d) = &oc.delay_budget_reporting_config {
                    w.setup_release(d, |w, t| w.enu(*t as u32, 8));
                }
            }
            if let Some(v4) = &v.v1540 {
                w.opt_bits(&[
                    v4.overheating_assistance_config.is_some(),
                    v4.v1560.is_some(),
                ]);
                if let Some(oc) = &v4.overheating_assistance_config {
                    w.bit(false);
                    w.bit(oc.is_some());
                    if let Some(sr) = oc {
                        w.setup_release(sr, |w, t| w.enu(*t as u32, 16));
                    }
                }
                if let Some(v6) = &v4.v1560 {
                    if v6.v1610_present {
                        return Err(EncodeError::Unsupported("RRCReconfiguration-v1610-IEs"));
                    }
                    w.opt_bits(&[
                        v6.mrdc_secondary_cell_group_config.is_some(),
                        v6.radio_bearer_config2.is_some(),
                        v6.sk_counter.is_some(),
                        false,
                    ]);
                    if let Some(m) = &v6.mrdc_secondary_cell_group_config {
                        w.setup_release(m, |w, c| {
                            w.bit(c.mrdc_release_and_add);
                            w.bit(!c.nr_scg);
                            w.octet_string(&c.secondary_cell_group);
                        });
                    }
                    if let Some(r2) = &v6.radio_bearer_config2 {
                        w.octet_string(r2);
                    }
                    if let Some(sk) = v6.sk_counter {
                        w.uint(sk as u32, 0, 65535);
                    }
                }
            }
        }
        Ok(())
    }
}

/// `SSB-MTC ::= SEQUENCE { periodicityAndOffset CHOICE { sf5 INTEGER (0..4), sf10, sf20, sf40, sf80,
/// sf160 INTEGER (0..159) }, duration ENUMERATED { sf1, sf2, sf3, sf4, sf5 } }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsbMtc {
    pub periodicity_sf: u8,
    pub offset_sf: u8,
    pub duration_sf: u8,
}

/// `CarrierInfoNR ::= SEQUENCE { carrierFreq ARFCN-ValueNR, ssbSubcarrierSpacing SubcarrierSpacing,
/// smtc SSB-MTC OPTIONAL, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierInfoNr {
    pub carrier_freq: u32,
    pub ssb_subcarrier_spacing: SubcarrierSpacing,
    pub smtc: Option<SsbMtc>,
}

/// `RedirectedCarrierInfo ::= CHOICE { nr CarrierInfoNR, eutra RedirectedCarrierInfo-EUTRA, ... }` with
/// `RedirectedCarrierInfo-EUTRA ::= SEQUENCE { eutraFrequency ARFCN-ValueEUTRA, cnType ENUMERATED
/// { epc, fiveGC } OPTIONAL }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectedCarrierInfo {
    Nr(CarrierInfoNr),
    Eutra {
        eutra_frequency: u32,
        cn_type_5gc: Option<bool>,
    },
}

/// `FreqPriorityNR ::= SEQUENCE { carrierFreq ARFCN-ValueNR, cellReselectionPriority
/// CellReselectionPriority, cellReselectionSubPriority CellReselectionSubPriority OPTIONAL }` (and the
/// EUTRA variant with `ARFCN-ValueEUTRA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreqPriority {
    pub carrier_freq: u32,
    pub cell_reselection_priority: u8,
    /// `ENUMERATED { oDot2, oDot4, oDot6, oDot8 }` as the raw index.
    pub cell_reselection_sub_priority: Option<u8>,
}

/// `CellReselectionPriorities ::= SEQUENCE { freqPriorityListEUTRA FreqPriorityListEUTRA OPTIONAL,
/// freqPriorityListNR FreqPriorityListNR OPTIONAL, t320 ENUMERATED { min5, min10, min20, min30, min60,
/// min120, min180, spare1 } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CellReselectionPriorities {
    pub freq_priority_list_eutra: Vec<FreqPriority>,
    pub freq_priority_list_nr: Vec<FreqPriority>,
    pub t320_min: Option<u8>,
}

/// `RAN-NotificationAreaInfo ::= CHOICE { cellList PLMN-RAN-AreaCellList, ran-AreaConfigList
/// PLMN-RAN-AreaConfigList, ... }` with `PLMN-RAN-AreaCell ::= SEQUENCE { plmn-Identity PLMN-Identity
/// OPTIONAL, ran-AreaCells SEQUENCE (SIZE (1..32)) OF CellIdentity }` and `PLMN-RAN-AreaConfig ::=
/// SEQUENCE { plmn-Identity PLMN-Identity OPTIONAL, ran-Area SEQUENCE (SIZE (1..16)) OF RAN-AreaConfig }`,
/// `RAN-AreaConfig ::= SEQUENCE { trackingAreaCode TrackingAreaCode, ran-AreaCodeList SEQUENCE (SIZE
/// (1..32)) OF RAN-AreaCode OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RanNotificationAreaInfo {
    CellList(Vec<PlmnRanAreaCell>),
    RanAreaConfigList(Vec<PlmnRanAreaConfig>),
}

/// `PLMN-RAN-AreaCell ::= SEQUENCE { plmn-Identity PLMN-Identity OPTIONAL, ran-AreaCells SEQUENCE
/// (SIZE (1..32)) OF CellIdentity }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlmnRanAreaCell {
    pub plmn_identity: Option<PlmnIdentity>,
    /// 36-bit cell identities.
    pub ran_area_cells: Vec<u64>,
}

/// `RAN-AreaConfig ::= SEQUENCE { trackingAreaCode TrackingAreaCode, ran-AreaCodeList SEQUENCE (SIZE
/// (1..32)) OF RAN-AreaCode OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RanAreaConfig {
    pub tracking_area_code: u32,
    pub ran_area_code_list: Vec<u8>,
}

/// `PLMN-RAN-AreaConfig ::= SEQUENCE { plmn-Identity PLMN-Identity OPTIONAL, ran-Area SEQUENCE (SIZE
/// (1..16)) OF RAN-AreaConfig }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlmnRanAreaConfig {
    pub plmn_identity: Option<PlmnIdentity>,
    pub ran_area: Vec<RanAreaConfig>,
}

/// `SuspendConfig ::= SEQUENCE { fullI-RNTI I-RNTI-Value, shortI-RNTI ShortI-RNTI-Value, ran-PagingCycle
/// PagingCycle, ran-NotificationAreaInfo RAN-NotificationAreaInfo OPTIONAL, t380 PeriodicRNAU-TimerValue
/// OPTIONAL, nextHopChainingCount NextHopChainingCount, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuspendConfig {
    /// 40-bit I-RNTI.
    pub full_i_rnti: u64,
    /// 24-bit short I-RNTI.
    pub short_i_rnti: u32,
    pub ran_paging_cycle_rf: u16,
    pub ran_notification_area_info: Option<RanNotificationAreaInfo>,
    /// `PeriodicRNAU-TimerValue ::= ENUMERATED { min5, min10, min20, min30, min60, min120, min360, min720 }`.
    pub t380_min: Option<u16>,
    pub next_hop_chaining_count: u8,
}

/// `RRCRelease ::= SEQUENCE { rrc-TransactionIdentifier RRC-TransactionIdentifier, criticalExtensions
/// CHOICE { rrcRelease RRCRelease-IEs, criticalExtensionsFuture SEQUENCE {} } }` with `RRCRelease-IEs ::=
/// SEQUENCE { redirectedCarrierInfo RedirectedCarrierInfo OPTIONAL, cellReselectionPriorities
/// CellReselectionPriorities OPTIONAL, suspendConfig SuspendConfig OPTIONAL, deprioritisationReq SEQUENCE
/// { deprioritisationType ENUMERATED { frequency, nr }, deprioritisationTimer ENUMERATED { min5, min10,
/// min15, min30 } } OPTIONAL, lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension
/// RRCRelease-v1540-IEs OPTIONAL }` and `RRCRelease-v1540-IEs ::= SEQUENCE { waitTime RejectWaitTime
/// OPTIONAL, nonCriticalExtension RRCRelease-v1610-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcRelease {
    pub rrc_transaction_identifier: u8,
    pub redirected_carrier_info: Option<RedirectedCarrierInfo>,
    pub cell_reselection_priorities: Option<CellReselectionPriorities>,
    pub suspend_config: Option<SuspendConfig>,
    /// `(deprioritisationType is nr, deprioritisationTimer minutes)`.
    pub deprioritisation_req: Option<(bool, u8)>,
    pub late_non_critical_extension: Option<Vec<u8>>,
    pub wait_time: Option<u8>,
}

impl RrcRelease {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        let rrc_transaction_identifier = r.u8(0, 3)?;
        if r.bit()? {
            return r.unsupported("criticalExtensionsFuture");
        }
        let [redir, prio, susp, depri, late, non_crit] = r.opt_bits::<6>()?;
        let redirected_carrier_info = r
            .opt(redir, |r| {
                if r.bit()? {
                    return r.unsupported("redirectedCarrierInfo extension alternative");
                }
                Ok(if !r.bit()? {
                    let e = r.bit()?;
                    let [has_smtc] = r.opt_bits::<1>()?;
                    let carrier_freq = r.uint(0, 3279165)?;
                    let ssb_subcarrier_spacing = SubcarrierSpacing::decode(r)?;
                    let smtc = r.opt(has_smtc, |r| {
                        let periodicity_sf = 5u8 << r.uint(0, 5)?;
                        let offset_sf = r.u8(0, periodicity_sf - 1)?;
                        let duration_sf = r.enu(5)? as u8 + 1;
                        Ok(SsbMtc {
                            periodicity_sf,
                            offset_sf,
                            duration_sf,
                        })
                    })?;
                    if e {
                        r.skip_ext_additions()?;
                    }
                    RedirectedCarrierInfo::Nr(CarrierInfoNr {
                        carrier_freq,
                        ssb_subcarrier_spacing,
                        smtc,
                    })
                } else {
                    let [has_cn] = r.opt_bits::<1>()?;
                    let eutra_frequency = r.uint(0, 262143)?;
                    let cn_type_5gc = r.opt(has_cn, |r| Ok(r.enu(2)? == 1))?;
                    RedirectedCarrierInfo::Eutra {
                        eutra_frequency,
                        cn_type_5gc,
                    }
                })
            })
            .ctx("redirectedCarrierInfo")?;
        let cell_reselection_priorities = r
            .opt(prio, |r| {
                let e = r.bit()?;
                let [eutra, nr, t320] = r.opt_bits::<3>()?;
                let fp = |hi: u32| {
                    move |r: &mut BitReader| {
                        let [has_sub] = r.opt_bits::<1>()?;
                        let carrier_freq = r.uint(0, hi)?;
                        let cell_reselection_priority = r.u8(0, 7)?;
                        let cell_reselection_sub_priority =
                            r.opt(has_sub, |r| Ok(r.enu(4)? as u8))?;
                        Ok(FreqPriority {
                            carrier_freq,
                            cell_reselection_priority,
                            cell_reselection_sub_priority,
                        })
                    }
                };
                let freq_priority_list_eutra = if eutra {
                    r.seq_of(1, 8, fp(262143))?
                } else {
                    vec![]
                };
                let freq_priority_list_nr = if nr {
                    r.seq_of(1, 8, fp(3279165))?
                } else {
                    vec![]
                };
                let t320_min = r.opt(t320, |r| {
                    Ok([5u8, 10, 20, 30, 60, 120, 180, 0][r.enu(8)? as usize])
                })?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(CellReselectionPriorities {
                    freq_priority_list_eutra,
                    freq_priority_list_nr,
                    t320_min,
                })
            })
            .ctx("cellReselectionPriorities")?;
        let suspend_config = r
            .opt(susp, |r| {
                let e = r.bit()?;
                let [has_rna, has_t380] = r.opt_bits::<2>()?;
                let full_i_rnti = r.bitstring(40)?;
                let short_i_rnti = r.bitstring(24)? as u32;
                let ran_paging_cycle_rf = 32u16 << r.enu(4)?;
                let ran_notification_area_info = r.opt(has_rna, |r| {
                    if r.bit()? {
                        return r.unsupported("ran-NotificationAreaInfo extension alternative");
                    }
                    let plmn = |r: &mut BitReader, has: bool| r.opt(has, PlmnIdentity::decode);
                    Ok(if !r.bit()? {
                        RanNotificationAreaInfo::CellList(r.seq_of(1, 8, |r| {
                            let [has_plmn] = r.opt_bits::<1>()?;
                            let plmn_identity = plmn(r, has_plmn)?;
                            let ran_area_cells = r.seq_of(1, 32, |r| r.bitstring(36))?;
                            Ok(PlmnRanAreaCell {
                                plmn_identity,
                                ran_area_cells,
                            })
                        })?)
                    } else {
                        RanNotificationAreaInfo::RanAreaConfigList(r.seq_of(1, 8, |r| {
                            let [has_plmn] = r.opt_bits::<1>()?;
                            let plmn_identity = plmn(r, has_plmn)?;
                            let ran_area = r.seq_of(1, 16, |r| {
                                let [has_codes] = r.opt_bits::<1>()?;
                                let tracking_area_code = r.bitstring(24)? as u32;
                                let ran_area_code_list = if has_codes {
                                    r.seq_of(1, 32, |r| r.u8(0, 255))?
                                } else {
                                    vec![]
                                };
                                Ok(RanAreaConfig {
                                    tracking_area_code,
                                    ran_area_code_list,
                                })
                            })?;
                            Ok(PlmnRanAreaConfig {
                                plmn_identity,
                                ran_area,
                            })
                        })?)
                    })
                })?;
                let t380_min = r.opt(has_t380, |r| {
                    Ok([5u16, 10, 20, 30, 60, 120, 360, 720][r.enu(8)? as usize])
                })?;
                let next_hop_chaining_count = r.u8(0, 7)?;
                if e {
                    r.skip_ext_additions()?;
                }
                Ok(SuspendConfig {
                    full_i_rnti,
                    short_i_rnti,
                    ran_paging_cycle_rf,
                    ran_notification_area_info,
                    t380_min,
                    next_hop_chaining_count,
                })
            })
            .ctx("suspendConfig")?;
        let deprioritisation_req = r.opt(depri, |r| {
            Ok((r.enu(2)? == 1, [5u8, 10, 15, 30][r.enu(4)? as usize]))
        })?;
        let late_non_critical_extension = r.opt(late, |r| r.octet_string())?;
        let wait_time = if non_crit {
            let [has_wait, _next] = r.opt_bits::<2>()?;
            r.opt(has_wait, |r| r.u8(1, 16))?
        } else {
            None
        };
        Ok(Self {
            rrc_transaction_identifier,
            redirected_carrier_info,
            cell_reselection_priorities,
            suspend_config,
            deprioritisation_req,
            late_non_critical_extension,
            wait_time,
        })
    }

    /// Encoder for the fields a test needs (no carrier/priority/suspend IEs).
    fn encode(&self, w: &mut BitWriter) -> Result<(), EncodeError> {
        if self.redirected_carrier_info.is_some()
            || self.cell_reselection_priorities.is_some()
            || self.suspend_config.is_some()
        {
            return Err(EncodeError::Unsupported(
                "RRCRelease redirect/priorities/suspend",
            ));
        }
        w.uint(self.rrc_transaction_identifier as u32, 0, 3);
        w.bit(false);
        w.opt_bits(&[
            false,
            false,
            false,
            self.deprioritisation_req.is_some(),
            self.late_non_critical_extension.is_some(),
            self.wait_time.is_some(),
        ]);
        if let Some((nr, min)) = self.deprioritisation_req {
            w.enu(nr as u32, 2);
            w.enu(
                [5u8, 10, 15, 30]
                    .iter()
                    .position(|&m| m == min)
                    .unwrap_or(0) as u32,
                4,
            );
        }
        if let Some(l) = &self.late_non_critical_extension {
            w.octet_string(l);
        }
        if let Some(t) = self.wait_time {
            w.opt_bits(&[true, false]);
            w.uint(t as u32, 1, 16);
        }
        Ok(())
    }
}

/// `RRCReestablishment-IEs ::= SEQUENCE { nextHopChainingCount NextHopChainingCount,
/// lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RrcReestablishment {
    pub rrc_transaction_identifier: u8,
    pub next_hop_chaining_count: u8,
}

/// `SecurityModeCommand-IEs ::= SEQUENCE { securityConfigSMC SecurityConfigSMC, lateNonCriticalExtension
/// OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }` with `SecurityConfigSMC ::=
/// SEQUENCE { securityAlgorithmConfig SecurityAlgorithmConfig, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityModeCommand {
    pub rrc_transaction_identifier: u8,
    pub security_algorithm_config: SecurityAlgorithmConfig,
}

/// `DLInformationTransfer-IEs ::= SEQUENCE { dedicatedNAS-Message DedicatedNAS-Message OPTIONAL,
/// lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension DLInformationTransfer-v1610-IEs
/// OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DlInformationTransfer {
    pub rrc_transaction_identifier: u8,
    pub dedicated_nas_message: Option<Vec<u8>>,
}

/// `RAT-Type ::= ENUMERATED { nr, eutra-nr, eutra, utra-fdd-v1610, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatType {
    Nr,
    EutraNr,
    Eutra,
    UtraFdd,
}

impl RatType {
    fn decode(r: &mut BitReader) -> DecodeResult<Self> {
        Ok(match r.enu_ext(4)? {
            Some(0) => Self::Nr,
            Some(1) => Self::EutraNr,
            Some(2) => Self::Eutra,
            Some(3) => Self::UtraFdd,
            _ => return r.unsupported("RAT-Type extension value"),
        })
    }
}

/// `UE-CapabilityRAT-Request ::= SEQUENCE { rat-Type RAT-Type, capabilityRequestFilter OCTET STRING
/// OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeCapabilityRatRequest {
    pub rat_type: RatType,
    pub capability_request_filter: Option<Vec<u8>>,
}

/// `UECapabilityEnquiry-IEs ::= SEQUENCE { ue-CapabilityRAT-RequestList UE-CapabilityRAT-RequestList,
/// lateNonCriticalExtension OCTET STRING OPTIONAL, ue-CapabilityEnquiryExt OCTET STRING (CONTAINING
/// UECapabilityEnquiry-v1560-IEs) OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeCapabilityEnquiry {
    pub rrc_transaction_identifier: u8,
    pub ue_capability_rat_request_list: Vec<UeCapabilityRatRequest>,
    pub ue_capability_enquiry_ext: Option<Vec<u8>>,
}

/// `DRB-CountMSB-Info ::= SEQUENCE { drb-Identity DRB-Identity, countMSB-Uplink INTEGER (0..33554431),
/// countMSB-Downlink INTEGER (0..33554431) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrbCountMsbInfo {
    pub drb_identity: u8,
    pub count_msb_uplink: u32,
    pub count_msb_downlink: u32,
}

/// `CounterCheck-IEs ::= SEQUENCE { drb-CountMSB-InfoList DRB-CountMSB-InfoList, lateNonCriticalExtension
/// OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterCheck {
    pub rrc_transaction_identifier: u8,
    pub drb_count_msb_info_list: Vec<DrbCountMsbInfo>,
}

/// Message kind of a `DL-DCCH-Message` c1 alternative (the 4-bit index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlDcchKind {
    RrcReconfiguration,
    RrcResume,
    RrcRelease,
    RrcReestablishment,
    SecurityModeCommand,
    DlInformationTransfer,
    UeCapabilityEnquiry,
    CounterCheck,
    MobilityFromNrCommand,
    DlDedicatedMessageSegment,
    UeInformationRequest,
    DlInformationTransferMrdc,
    LoggedMeasurementConfiguration,
    Spare,
}

/// `DL-DCCH-MessageType ::= CHOICE { c1 CHOICE { rrcReconfiguration, rrcResume, rrcRelease,
/// rrcReestablishment, securityModeCommand, dlInformationTransfer, ueCapabilityEnquiry, counterCheck,
/// mobilityFromNRCommand, dlDedicatedMessageSegment-r16, ueInformationRequest-r16,
/// dlInformationTransferMRDC-r16, loggedMeasurementConfiguration-r16, spare3, spare2, spare1 },
/// messageClassExtension SEQUENCE {} }`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // RRCReconfiguration carries the whole CellGroupConfig by design
pub enum DlDcchMessage {
    RrcReconfiguration(RrcReconfiguration),
    RrcRelease(RrcRelease),
    RrcReestablishment(RrcReestablishment),
    SecurityModeCommand(SecurityModeCommand),
    DlInformationTransfer(DlInformationTransfer),
    UeCapabilityEnquiry(UeCapabilityEnquiry),
    CounterCheck(CounterCheck),
}

impl DlDcchMessage {
    /// Peek at the c1 message kind and `rrc-TransactionIdentifier` (when the
    /// message has one) without decoding the body.
    pub fn kind(pdu: &[u8]) -> DecodeResult<(DlDcchKind, Option<u8>)> {
        let mut r = BitReader::new(pdu);
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        let kind = match r.uint(0, 15)? {
            0 => DlDcchKind::RrcReconfiguration,
            1 => DlDcchKind::RrcResume,
            2 => DlDcchKind::RrcRelease,
            3 => DlDcchKind::RrcReestablishment,
            4 => DlDcchKind::SecurityModeCommand,
            5 => DlDcchKind::DlInformationTransfer,
            6 => DlDcchKind::UeCapabilityEnquiry,
            7 => DlDcchKind::CounterCheck,
            8 => DlDcchKind::MobilityFromNrCommand,
            9 => DlDcchKind::DlDedicatedMessageSegment,
            10 => DlDcchKind::UeInformationRequest,
            11 => DlDcchKind::DlInformationTransferMrdc,
            12 => DlDcchKind::LoggedMeasurementConfiguration,
            _ => DlDcchKind::Spare,
        };
        let tid = match kind {
            DlDcchKind::Spare | DlDcchKind::DlDedicatedMessageSegment => None,
            _ => Some(r.u8(0, 3)?),
        };
        Ok((kind, tid))
    }

    /// Decode a `DL-DCCH-Message` PDU (an SRB1/SRB2 RRC PDU after PDCP).
    pub fn decode(pdu: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(pdu)).ctx("DL-DCCH-Message")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        let idx = r.uint(0, 15)?;
        let crit = |r: &mut BitReader| -> DecodeResult<u8> {
            let tid = r.u8(0, 3)?;
            if r.bit()? {
                return r.unsupported("criticalExtensionsFuture");
            }
            Ok(tid)
        };
        match idx {
            0 => Ok(Self::RrcReconfiguration(
                RrcReconfiguration::decode(r).ctx("RRCReconfiguration")?,
            )),
            2 => Ok(Self::RrcRelease(RrcRelease::decode(r).ctx("RRCRelease")?)),
            3 => {
                let tid = crit(r)?;
                let [_late, _nc] = r.opt_bits::<2>()?;
                let next_hop_chaining_count = r.u8(0, 7)?;
                Ok(Self::RrcReestablishment(RrcReestablishment {
                    rrc_transaction_identifier: tid,
                    next_hop_chaining_count,
                }))
            }
            4 => {
                let tid = crit(r)?;
                let [_late, _nc] = r.opt_bits::<2>()?;
                let ext = r.bit()?;
                let security_algorithm_config = SecurityAlgorithmConfig::decode(r)
                    .ctx("SecurityModeCommand/securityAlgorithmConfig")?;
                if ext {
                    r.skip_ext_additions()?;
                }
                Ok(Self::SecurityModeCommand(SecurityModeCommand {
                    rrc_transaction_identifier: tid,
                    security_algorithm_config,
                }))
            }
            5 => {
                let tid = crit(r)?;
                let [has_nas, _late, _nc] = r.opt_bits::<3>()?;
                let dedicated_nas_message = r
                    .opt(has_nas, |r| r.octet_string())
                    .ctx("DLInformationTransfer/dedicatedNAS-Message")?;
                Ok(Self::DlInformationTransfer(DlInformationTransfer {
                    rrc_transaction_identifier: tid,
                    dedicated_nas_message,
                }))
            }
            6 => {
                let tid = crit(r)?;
                let [late, ext] = r.opt_bits::<2>()?;
                let list = r
                    .seq_of(1, 8, |r| {
                        let e = r.bit()?;
                        let [has_filter] = r.opt_bits::<1>()?;
                        let rat_type = RatType::decode(r)?;
                        let capability_request_filter = r.opt(has_filter, |r| r.octet_string())?;
                        if e {
                            r.skip_ext_additions()?;
                        }
                        Ok(UeCapabilityRatRequest {
                            rat_type,
                            capability_request_filter,
                        })
                    })
                    .ctx("UECapabilityEnquiry/ue-CapabilityRAT-RequestList")?;
                if late {
                    r.octet_string()?;
                }
                let ue_capability_enquiry_ext = r.opt(ext, |r| r.octet_string())?;
                Ok(Self::UeCapabilityEnquiry(UeCapabilityEnquiry {
                    rrc_transaction_identifier: tid,
                    ue_capability_rat_request_list: list,
                    ue_capability_enquiry_ext,
                }))
            }
            7 => {
                let tid = crit(r)?;
                let [_late, _nc] = r.opt_bits::<2>()?;
                let drb_count_msb_info_list = r
                    .seq_of(1, 29, |r| {
                        Ok(DrbCountMsbInfo {
                            drb_identity: r.u8(1, 32)?,
                            count_msb_uplink: r.uint(0, 33554431)?,
                            count_msb_downlink: r.uint(0, 33554431)?,
                        })
                    })
                    .ctx("CounterCheck/drb-CountMSB-InfoList")?;
                Ok(Self::CounterCheck(CounterCheck {
                    rrc_transaction_identifier: tid,
                    drb_count_msb_info_list,
                }))
            }
            1 => r.unsupported("RRCResume"),
            8 => r.unsupported("MobilityFromNRCommand"),
            9..=12 => r.unsupported("Rel-16 DL-DCCH message"),
            _ => r.unsupported("DL-DCCH spare message"),
        }
    }

    /// Encode (test/tooling aid). Messages carrying a `CellGroupConfig` or the
    /// RRCRelease redirect/priority/suspend IEs are refused.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = BitWriter::new();
        w.bit(false);
        match self {
            Self::RrcReconfiguration(m) => {
                w.uint(0, 0, 15);
                m.encode(&mut w)?;
            }
            Self::RrcRelease(m) => {
                w.uint(2, 0, 15);
                m.encode(&mut w)?;
            }
            Self::RrcReestablishment(m) => {
                w.uint(3, 0, 15);
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[false, false]);
                w.uint(m.next_hop_chaining_count as u32, 0, 7);
            }
            Self::SecurityModeCommand(m) => {
                w.uint(4, 0, 15);
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[false, false]);
                w.bit(false);
                m.security_algorithm_config.encode(&mut w);
            }
            Self::DlInformationTransfer(m) => {
                w.uint(5, 0, 15);
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[m.dedicated_nas_message.is_some(), false, false]);
                if let Some(n) = &m.dedicated_nas_message {
                    w.octet_string(n);
                }
            }
            Self::UeCapabilityEnquiry(m) => {
                w.uint(6, 0, 15);
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[false, m.ue_capability_enquiry_ext.is_some()]);
                w.seq_of(&m.ue_capability_rat_request_list, 1, 8, |w, q| {
                    w.bit(false);
                    w.bit(q.capability_request_filter.is_some());
                    w.enu_ext(q.rat_type as u32, 4);
                    if let Some(f) = &q.capability_request_filter {
                        w.octet_string(f);
                    }
                });
                if let Some(e) = &m.ue_capability_enquiry_ext {
                    w.octet_string(e);
                }
            }
            Self::CounterCheck(m) => {
                w.uint(7, 0, 15);
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[false, false]);
                w.seq_of(&m.drb_count_msb_info_list, 1, 29, |w, d| {
                    w.uint(d.drb_identity as u32, 1, 32);
                    w.uint(d.count_msb_uplink, 0, 33554431);
                    w.uint(d.count_msb_downlink, 0, 33554431);
                });
            }
        }
        Ok(w.finish())
    }
}

// ---------------------------------------------------------------------------
// UL-CCCH
// ---------------------------------------------------------------------------

/// `InitialUE-Identity ::= CHOICE { ng-5G-S-TMSI-Part1 BIT STRING (SIZE (39)), randomValue BIT STRING
/// (SIZE (39)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialUeIdentity {
    Ng5gSTmsiPart1(u64),
    RandomValue(u64),
}

/// `EstablishmentCause ::= ENUMERATED { emergency, highPriorityAccess, mt-Access, mo-Signalling,
/// mo-Data, mo-VoiceCall, mo-VideoCall, mo-SMS, mps-PriorityAccess, mcs-PriorityAccess, spare6, spare5,
/// spare4, spare3, spare2, spare1 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    MoVideoCall = 6,
    MoSms = 7,
    MpsPriorityAccess = 8,
    McsPriorityAccess = 9,
}

impl EstablishmentCause {
    fn from_index(i: u32) -> Option<Self> {
        use EstablishmentCause::*;
        [
            Emergency,
            HighPriorityAccess,
            MtAccess,
            MoSignalling,
            MoData,
            MoVoiceCall,
            MoVideoCall,
            MoSms,
            MpsPriorityAccess,
            McsPriorityAccess,
        ]
        .get(i as usize)
        .copied()
    }
}

/// `RRCSetupRequest-IEs ::= SEQUENCE { ue-Identity InitialUE-Identity, establishmentCause
/// EstablishmentCause, spare BIT STRING (SIZE (1)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RrcSetupRequest {
    pub ue_identity: InitialUeIdentity,
    pub establishment_cause: EstablishmentCause,
}

/// `ReestablishmentCause ::= ENUMERATED { reconfigurationFailure, handoverFailure, otherFailure, spare1 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReestablishmentCause {
    ReconfigurationFailure = 0,
    HandoverFailure = 1,
    OtherFailure = 2,
}

/// `RRCReestablishmentRequest-IEs ::= SEQUENCE { ue-Identity ReestabUE-Identity, reestablishmentCause
/// ReestablishmentCause, spare BIT STRING (SIZE (1)) }` with `ReestabUE-Identity ::= SEQUENCE { c-RNTI
/// RNTI-Value, physCellId PhysCellId, shortMAC-I ShortMAC-I }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RrcReestablishmentRequest {
    pub c_rnti: u16,
    pub phys_cell_id: u16,
    pub short_mac_i: u16,
    pub reestablishment_cause: ReestablishmentCause,
}

/// `RRCSystemInfoRequest-IEs ::= SEQUENCE { requested-SI-List BIT STRING (SIZE (maxSI-Message)),
/// spare BIT STRING (SIZE (12)) }` (MSB = first SI message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RrcSystemInfoRequest {
    pub requested_si_list: u32,
}

/// `UL-CCCH-MessageType ::= CHOICE { c1 CHOICE { rrcSetupRequest, rrcResumeRequest,
/// rrcReestablishmentRequest, rrcSystemInfoRequest }, messageClassExtension SEQUENCE {} }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UlCcchMessage {
    RrcSetupRequest(RrcSetupRequest),
    RrcReestablishmentRequest(RrcReestablishmentRequest),
    RrcSystemInfoRequest(RrcSystemInfoRequest),
}

impl UlCcchMessage {
    /// Encode to the fixed 6-octet CCCH SDU (Msg3).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bit(false);
        match self {
            Self::RrcSetupRequest(m) => {
                w.uint(0, 0, 3);
                match m.ue_identity {
                    InitialUeIdentity::Ng5gSTmsiPart1(v) => {
                        w.bit(false);
                        w.bitstring(v, 39);
                    }
                    InitialUeIdentity::RandomValue(v) => {
                        w.bit(true);
                        w.bitstring(v, 39);
                    }
                }
                w.enu(m.establishment_cause as u32, 16);
                w.bitstring(0, 1);
            }
            Self::RrcReestablishmentRequest(m) => {
                w.uint(2, 0, 3);
                w.uint(m.c_rnti as u32, 0, 65535);
                w.uint(m.phys_cell_id as u32, 0, 1007);
                w.bitstring(m.short_mac_i as u64, 16);
                w.enu(m.reestablishment_cause as u32, 4);
                w.bitstring(0, 1);
            }
            Self::RrcSystemInfoRequest(m) => {
                w.uint(3, 0, 3);
                w.bit(false);
                w.bitstring(m.requested_si_list as u64, 32);
                w.bitstring(0, 12);
            }
        }
        w.finish()
    }

    pub fn decode(pdu: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(pdu)).ctx("UL-CCCH-Message")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        match r.uint(0, 3)? {
            0 => {
                let part1 = !r.bit()?;
                let v = r.bitstring(39)?;
                let ue_identity = if part1 {
                    InitialUeIdentity::Ng5gSTmsiPart1(v)
                } else {
                    InitialUeIdentity::RandomValue(v)
                };
                let establishment_cause = EstablishmentCause::from_index(r.enu(16)?)
                    .ok_or_else(|| DecodeError::invalid("establishmentCause spare", r.pos()))?;
                r.bitstring(1)?;
                Ok(Self::RrcSetupRequest(RrcSetupRequest {
                    ue_identity,
                    establishment_cause,
                }))
            }
            2 => {
                let c_rnti = r.u16(0, 65535)?;
                let phys_cell_id = r.u16(0, 1007)?;
                let short_mac_i = r.bitstring(16)? as u16;
                let reestablishment_cause = match r.enu(4)? {
                    0 => ReestablishmentCause::ReconfigurationFailure,
                    1 => ReestablishmentCause::HandoverFailure,
                    2 => ReestablishmentCause::OtherFailure,
                    _ => return r.invalid("reestablishmentCause spare"),
                };
                r.bitstring(1)?;
                Ok(Self::RrcReestablishmentRequest(RrcReestablishmentRequest {
                    c_rnti,
                    phys_cell_id,
                    short_mac_i,
                    reestablishment_cause,
                }))
            }
            3 => {
                if r.bit()? {
                    return r.unsupported("criticalExtensionsFuture-r16");
                }
                let requested_si_list = r.bitstring(32)? as u32;
                r.bitstring(12)?;
                Ok(Self::RrcSystemInfoRequest(RrcSystemInfoRequest {
                    requested_si_list,
                }))
            }
            _ => r.unsupported("RRCResumeRequest"),
        }
    }
}

// ---------------------------------------------------------------------------
// UL-DCCH
// ---------------------------------------------------------------------------

/// `registeredAMF RegisteredAMF ::= SEQUENCE { plmn-Identity PLMN-Identity OPTIONAL, amf-Identifier
/// AMF-Identifier }` with `AMF-Identifier ::= BIT STRING (SIZE (24))`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredAmf {
    pub plmn_identity: Option<PlmnIdentity>,
    pub amf_identifier: u32,
}

/// `GuamiType ENUMERATED { native, mapped }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuamiType {
    Native,
    Mapped,
}

/// `S-NSSAI ::= CHOICE { sst BIT STRING (SIZE (8)), sst-SD BIT STRING (SIZE (32)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SNssai {
    Sst(u8),
    SstSd(u32),
}

/// `ng-5G-S-TMSI-Value CHOICE { ng-5G-S-TMSI NG-5G-S-TMSI, ng-5G-S-TMSI-Part2 BIT STRING (SIZE (9)) }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ng5gSTmsiValue {
    /// 48-bit 5G-S-TMSI.
    Full(u64),
    /// The 9 MSBs not sent in `RRCSetupRequest`.
    Part2(u16),
}

/// `RRCSetupComplete-IEs ::= SEQUENCE { selectedPLMN-Identity INTEGER (1..maxPLMN), registeredAMF
/// RegisteredAMF OPTIONAL, guami-Type ENUMERATED { native, mapped } OPTIONAL, s-NSSAI-List SEQUENCE
/// (SIZE (1..maxNrofS-NSSAI)) OF S-NSSAI OPTIONAL, dedicatedNAS-Message DedicatedNAS-Message,
/// ng-5G-S-TMSI-Value CHOICE {…} OPTIONAL, lateNonCriticalExtension OCTET STRING OPTIONAL,
/// nonCriticalExtension RRCSetupComplete-v1610-IEs OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrcSetupComplete {
    pub rrc_transaction_identifier: u8,
    pub selected_plmn_identity: u8,
    pub registered_amf: Option<RegisteredAmf>,
    pub guami_type: Option<GuamiType>,
    pub s_nssai_list: Vec<SNssai>,
    pub dedicated_nas_message: Vec<u8>,
    pub ng_5g_s_tmsi_value: Option<Ng5gSTmsiValue>,
}

/// `ULInformationTransfer-IEs ::= SEQUENCE { dedicatedNAS-Message DedicatedNAS-Message OPTIONAL,
/// lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UlInformationTransfer {
    pub dedicated_nas_message: Option<Vec<u8>>,
}

/// `UE-CapabilityRAT-Container ::= SEQUENCE { rat-Type RAT-Type, ue-CapabilityRAT-Container OCTET STRING }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeCapabilityRatContainer {
    pub rat_type: RatType,
    /// For `nr`: a UPER-encoded `UE-NR-Capability` (see [`UeNrCapability::encode`]).
    pub container: Vec<u8>,
}

/// `UECapabilityInformation-IEs ::= SEQUENCE { ue-CapabilityRAT-ContainerList UE-CapabilityRAT-ContainerList
/// OPTIONAL, lateNonCriticalExtension OCTET STRING OPTIONAL, nonCriticalExtension SEQUENCE {} OPTIONAL }`
/// with `UE-CapabilityRAT-ContainerList ::= SEQUENCE (SIZE (0..maxRAT-CapabilityContainers)) OF …`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeCapabilityInformation {
    pub rrc_transaction_identifier: u8,
    pub ue_capability_rat_container_list: Vec<UeCapabilityRatContainer>,
}

/// `UL-DCCH-MessageType ::= CHOICE { c1 CHOICE { measurementReport, rrcReconfigurationComplete,
/// rrcSetupComplete, rrcReestablishmentComplete, rrcResumeComplete, securityModeComplete,
/// securityModeFailure, ulInformationTransfer, locationMeasurementIndication, ueCapabilityInformation,
/// counterCheckResponse, ueAssistanceInformation, failureInformation, ulInformationTransferMRDC,
/// scgFailureInformation, scgFailureInformationEUTRA }, messageClassExtension … }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UlDcchMessage {
    MeasurementReport(MeasResults),
    RrcReconfigurationComplete { rrc_transaction_identifier: u8 },
    RrcReestablishmentComplete { rrc_transaction_identifier: u8 },
    RrcSetupComplete(RrcSetupComplete),
    SecurityModeComplete { rrc_transaction_identifier: u8 },
    SecurityModeFailure { rrc_transaction_identifier: u8 },
    UlInformationTransfer(UlInformationTransfer),
    UeCapabilityInformation(UeCapabilityInformation),
}

impl UlDcchMessage {
    fn c1_index(&self) -> u32 {
        match self {
            Self::MeasurementReport(_) => 0,
            Self::RrcReconfigurationComplete { .. } => 1,
            Self::RrcReestablishmentComplete { .. } => 3,
            Self::RrcSetupComplete(_) => 2,
            Self::SecurityModeComplete { .. } => 5,
            Self::SecurityModeFailure { .. } => 6,
            Self::UlInformationTransfer(_) => 7,
            Self::UeCapabilityInformation(_) => 9,
        }
    }

    /// UPER-encode the `UL-DCCH-Message`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bit(false);
        w.uint(self.c1_index(), 0, 15);
        match self {
            Self::MeasurementReport(m) => {
                // criticalExtensions CHOICE: measurementReport; MeasurementReport-IEs
                // with neither lateNonCriticalExtension nor nonCriticalExtension.
                w.bit(false);
                w.opt_bits(&[false, false]);
                m.encode(&mut w);
            }
            Self::RrcReconfigurationComplete {
                rrc_transaction_identifier,
            }
            | Self::RrcReestablishmentComplete {
                rrc_transaction_identifier,
            }
            | Self::SecurityModeComplete {
                rrc_transaction_identifier,
            }
            | Self::SecurityModeFailure {
                rrc_transaction_identifier,
            } => {
                w.uint(*rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[false, false]);
            }
            Self::RrcSetupComplete(m) => {
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[
                    m.registered_amf.is_some(),
                    m.guami_type.is_some(),
                    !m.s_nssai_list.is_empty(),
                    m.ng_5g_s_tmsi_value.is_some(),
                    false,
                    false,
                ]);
                w.uint(m.selected_plmn_identity as u32, 1, 12);
                if let Some(amf) = &m.registered_amf {
                    w.bit(amf.plmn_identity.is_some());
                    if let Some(p) = &amf.plmn_identity {
                        p.encode(&mut w);
                    }
                    w.bitstring(amf.amf_identifier as u64, 24);
                }
                if let Some(g) = m.guami_type {
                    w.enu(g as u32, 2);
                }
                if !m.s_nssai_list.is_empty() {
                    w.seq_of(&m.s_nssai_list, 1, 8, |w, s| match *s {
                        SNssai::Sst(v) => {
                            w.bit(false);
                            w.bitstring(v as u64, 8);
                        }
                        SNssai::SstSd(v) => {
                            w.bit(true);
                            w.bitstring(v as u64, 32);
                        }
                    });
                }
                w.octet_string(&m.dedicated_nas_message);
                match m.ng_5g_s_tmsi_value {
                    None => {}
                    Some(Ng5gSTmsiValue::Full(v)) => {
                        w.bit(false);
                        w.bitstring(v, 48);
                    }
                    Some(Ng5gSTmsiValue::Part2(v)) => {
                        w.bit(true);
                        w.bitstring(v as u64, 9);
                    }
                }
            }
            Self::UlInformationTransfer(m) => {
                w.bit(false);
                w.opt_bits(&[m.dedicated_nas_message.is_some(), false, false]);
                if let Some(n) = &m.dedicated_nas_message {
                    w.octet_string(n);
                }
            }
            Self::UeCapabilityInformation(m) => {
                w.uint(m.rrc_transaction_identifier as u32, 0, 3);
                w.bit(false);
                w.opt_bits(&[true, false, false]);
                w.seq_of(&m.ue_capability_rat_container_list, 0, 8, |w, c| {
                    w.enu_ext(c.rat_type as u32, 4);
                    w.octet_string(&c.container);
                });
            }
        }
        w.finish()
    }

    pub fn decode(pdu: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(pdu)).ctx("UL-DCCH-Message")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        let idx = r.uint(0, 15)?;
        let crit = |r: &mut BitReader| -> DecodeResult<u8> {
            let tid = r.u8(0, 3)?;
            if r.bit()? {
                return r.unsupported("criticalExtensionsFuture");
            }
            Ok(tid)
        };
        match idx {
            1 | 5 | 6 => {
                let tid = crit(r)?;
                let [_late, _nc] = r.opt_bits::<2>()?;
                Ok(match idx {
                    1 => Self::RrcReconfigurationComplete {
                        rrc_transaction_identifier: tid,
                    },
                    5 => Self::SecurityModeComplete {
                        rrc_transaction_identifier: tid,
                    },
                    _ => Self::SecurityModeFailure {
                        rrc_transaction_identifier: tid,
                    },
                })
            }
            2 => {
                let tid = crit(r)?;
                let [amf, guami, nssai, tmsi, _late, _nc] = r.opt_bits::<6>()?;
                let selected_plmn_identity = r.u8(1, 12)?;
                let registered_amf = r.opt(amf, |r| {
                    let [has_plmn] = r.opt_bits::<1>()?;
                    let plmn_identity = r.opt(has_plmn, PlmnIdentity::decode)?;
                    let amf_identifier = r.bitstring(24)? as u32;
                    Ok(RegisteredAmf {
                        plmn_identity,
                        amf_identifier,
                    })
                })?;
                let guami_type = r.opt(guami, |r| {
                    Ok(if r.enu(2)? == 0 {
                        GuamiType::Native
                    } else {
                        GuamiType::Mapped
                    })
                })?;
                let s_nssai_list = if nssai {
                    r.seq_of(1, 8, |r| {
                        Ok(if !r.bit()? {
                            SNssai::Sst(r.bitstring(8)? as u8)
                        } else {
                            SNssai::SstSd(r.bitstring(32)? as u32)
                        })
                    })?
                } else {
                    vec![]
                };
                let dedicated_nas_message = r.octet_string()?;
                let ng_5g_s_tmsi_value = r.opt(tmsi, |r| {
                    Ok(if !r.bit()? {
                        Ng5gSTmsiValue::Full(r.bitstring(48)?)
                    } else {
                        Ng5gSTmsiValue::Part2(r.bitstring(9)? as u16)
                    })
                })?;
                Ok(Self::RrcSetupComplete(RrcSetupComplete {
                    rrc_transaction_identifier: tid,
                    selected_plmn_identity,
                    registered_amf,
                    guami_type,
                    s_nssai_list,
                    dedicated_nas_message,
                    ng_5g_s_tmsi_value,
                }))
                .ctx("RRCSetupComplete")
            }
            7 => {
                if r.bit()? {
                    return r.unsupported("criticalExtensionsFuture");
                }
                let [has_nas, _late, _nc] = r.opt_bits::<3>()?;
                let dedicated_nas_message = r.opt(has_nas, |r| r.octet_string())?;
                Ok(Self::UlInformationTransfer(UlInformationTransfer {
                    dedicated_nas_message,
                }))
            }
            9 => {
                let tid = crit(r)?;
                let [has_list, _late, _nc] = r.opt_bits::<3>()?;
                let list = if has_list {
                    r.seq_of(0, 8, |r| {
                        Ok(UeCapabilityRatContainer {
                            rat_type: RatType::decode(r)?,
                            container: r.octet_string()?,
                        })
                    })?
                } else {
                    vec![]
                };
                Ok(Self::UeCapabilityInformation(UeCapabilityInformation {
                    rrc_transaction_identifier: tid,
                    ue_capability_rat_container_list: list,
                }))
            }
            _ => r.unsupported("UL-DCCH message not implemented"),
        }
    }
}

// ---------------------------------------------------------------------------
// UE-NR-Capability (minimal encoder)
// ---------------------------------------------------------------------------

/// `AccessStratumRelease ::= ENUMERATED { rel15, rel16, rel17, rel18, spare4, spare3, spare2, spare1, ... }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessStratumRelease {
    Rel15 = 0,
    Rel16 = 1,
    Rel17 = 2,
    Rel18 = 3,
}

/// A minimal `UE-NR-Capability` (TS 38.331 §6.3.3): the access stratum release, an empty
/// `PDCP-Parameters` (no ROHC profiles, `maxNumberROHC-ContextSessions = cs2`), an empty
/// `PHY-Parameters`, and `RF-Parameters { supportedBandListNR }` listing `supported_band_list_nr`
/// with no per-band features. Every OPTIONAL feature container is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeNrCapability {
    pub access_stratum_release: AccessStratumRelease,
    /// `FreqBandIndicatorNR` values (1..1024), at least one.
    pub supported_band_list_nr: Vec<u16>,
    /// `phy-ParametersFR1.pdsch-256QAM-FR1`.
    pub pdsch_256qam_fr1: bool,
    /// `BandNR.pusch-256QAM` on every listed band.
    pub pusch_256qam: bool,
    /// `mac-Parameters.mac-ParametersXDD-Diff { longDRX-Cycle, shortDRX-Cycle }`:
    /// connected-mode DRX supported (the gNB configures DRX only then).
    pub drx: bool,
}

impl UeNrCapability {
    /// UPER-encode. With `Rel15` and `[78]` this reproduces the OCUDU-validated vector
    /// `00 00 00 00 00 00 00 00 00 9a`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        // UE-NR-Capability: 11 OPTIONALs (rlc-Parameters, mac-Parameters, measAndMobParameters,
        // fdd-Add-UE-NR-Capabilities, tdd-Add-UE-NR-Capabilities, fr1-Add-UE-NR-Capabilities,
        // fr2-Add-UE-NR-Capabilities, featureSets, featureSetCombinations,
        // lateNonCriticalExtension, nonCriticalExtension), no extension marker.
        let mut opts = [false; 11];
        opts[1] = self.drx; // mac-Parameters
        w.opt_bits(&opts);
        w.enu_ext(self.access_stratum_release as u32, 8);
        // PDCP-Parameters ::= SEQUENCE { supportedROHC-Profiles SEQUENCE { 10 × BOOLEAN },
        // maxNumberROHC-ContextSessions ENUMERATED (16), 6 OPTIONALs, ... }
        w.bit(false);
        w.opt_bits(&[false; 6]);
        w.bits(0, 10);
        w.enu(0, 16);
        if self.drx {
            // MAC-Parameters ::= SEQUENCE { mac-ParametersCommon OPTIONAL,
            // mac-ParametersXDD-Diff OPTIONAL } (no extension marker);
            // MAC-ParametersXDD-Diff ::= SEQUENCE { skipUplinkTxDynamic,
            // logicalChannelSR-DelayTimer, longDRX-Cycle, shortDRX-Cycle,
            // multipleSR-Configurations, multipleConfiguredGrants (all
            // ENUMERATED {supported} OPTIONAL, zero bits each), ... }
            w.opt_bits(&[false, true]);
            w.bit(false);
            w.opt_bits(&[false, false, true, true, false, false]);
        }
        // PHY-Parameters ::= SEQUENCE { 5 OPTIONAL sub-structures }: only
        // phy-ParametersFR1 when it has something to say.
        w.opt_bits(&[false, false, false, self.pdsch_256qam_fr1, false]);
        if self.pdsch_256qam_fr1 {
            // Phy-ParametersFR1 ::= SEQUENCE { pdcchMonitoringSingleOccasion OPTIONAL,
            // scs-60kHz OPTIONAL, pdsch-256QAM-FR1 ENUMERATED {supported} OPTIONAL,
            // pdsch-RE-MappingFR1-PerSymbol OPTIONAL, ... }
            w.bit(false);
            w.opt_bits(&[false, false, true, false]);
        }
        // RF-Parameters ::= SEQUENCE { supportedBandListNR SEQUENCE (SIZE (1..maxBands)) OF BandNR,
        // supportedBandCombinationList OPTIONAL, appliedFreqBandListFilter OPTIONAL, ... }
        w.bit(false);
        w.opt_bits(&[false, false]);
        w.seq_of(&self.supported_band_list_nr, 1, 1024, |w, &band| {
            // BandNR ::= SEQUENCE { bandNR FreqBandIndicatorNR, 14 OPTIONALs, ... }:
            // the 10th optional is pusch-256QAM ENUMERATED {supported}.
            w.bit(false);
            let mut opts = [false; 14];
            opts[9] = self.pusch_256qam;
            w.opt_bits(&opts);
            w.uint(band as u32, 1, 1024);
        });
        w.finish()
    }

    /// Decode the minimal form produced by [`Self::encode`]: any optional feature
    /// container present is reported as unsupported.
    pub fn decode(octets: &[u8]) -> DecodeResult<Self> {
        let r = &mut BitReader::new(octets);
        let o = r.opt_bits::<11>()?;
        if o.iter().enumerate().any(|(i, &p)| p && i != 1) {
            return r.unsupported("UE-NR-Capability optional containers");
        }
        let access_stratum_release = match r.enu_ext(8)? {
            Some(0) => AccessStratumRelease::Rel15,
            Some(1) => AccessStratumRelease::Rel16,
            Some(2) => AccessStratumRelease::Rel17,
            Some(3) => AccessStratumRelease::Rel18,
            _ => return r.unsupported("accessStratumRelease spare/extension"),
        };
        let pext = r.bit()?;
        let po = r.opt_bits::<6>()?;
        r.bits(10)?;
        r.enu(16)?;
        if pext || po.iter().any(|&p| p) {
            return r.unsupported("PDCP-Parameters optional fields");
        }
        let mut drx = false;
        if o[1] {
            let [common, xdd] = r.opt_bits::<2>()?;
            if common {
                return r.unsupported("mac-ParametersCommon");
            }
            if xdd {
                let ext = r.bit()?;
                let x = r.opt_bits::<6>()?;
                if ext || x[0] || x[1] || x[4] || x[5] {
                    return r.unsupported("MAC-ParametersXDD-Diff fields");
                }
                drx = x[2] && x[3];
            }
        }
        let ph = r.opt_bits::<5>()?;
        if ph.iter().any(|&p| p) {
            return r.unsupported("PHY-Parameters sub-structures");
        }
        let rext = r.bit()?;
        let [bc, filt] = r.opt_bits::<2>()?;
        let supported_band_list_nr = r.seq_of(1, 1024, |r| {
            let e = r.bit()?;
            let bo = r.opt_bits::<14>()?;
            let band = r.u16(1, 1024)?;
            if e || bo.iter().any(|&p| p) {
                return r.unsupported("BandNR optional fields");
            }
            Ok(band)
        })?;
        if rext || bc || filt {
            return r.unsupported("RF-Parameters optional fields");
        }
        Ok(Self {
            access_stratum_release,
            supported_band_list_nr,
            pdsch_256qam_fr1: false,
            pusch_256qam: false,
            drx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_common::from_hex;

    /// A real gNB RRCReconfiguration (reassembled) carrying a PDU Session
    /// Establishment Accept in its dedicatedNAS-MessageList (assigned 10.255.0.3).
    const RECONFIG_HEX: &str = "068a80409a05e00205e3f05d00bac01584888bd76380832f00058e03f441a0b200811801001c5f80b6fbd20e00df801a0040188b8140708440024040018c4c40407fc041828000c28000ca414042bfc000c881004000001e4001804810404041dec009e02008440080000420418202020220c1820201010003410202020200034102020101000400815e0942421a5b9d195c9b995d048140";

    fn reconfig() -> RrcReconfiguration {
        match DlDcchMessage::decode(&from_hex(RECONFIG_HEX).unwrap())
            .expect("RRCReconfiguration must parse")
        {
            DlDcchMessage::RrcReconfiguration(m) => m,
            other => panic!("not an RRCReconfiguration: {other:?}"),
        }
    }

    #[test]
    fn live_reconfiguration_carries_pdu_session_accept() {
        let m = reconfig();
        let nas = m.dedicated_nas_messages();
        assert_eq!(nas.len(), 1);
        let pdu = &nas[0];
        // DL NAS Transport (7e 00 68 01) carrying the 5GSM Accept with the PDU address IE
        // 29 05 01 0a ff 00 03 = IPv4 10.255.0.3.
        assert!(
            pdu.windows(4).any(|w| w == [0x7e, 0x00, 0x68, 0x01]),
            "{}",
            ferrite_common::hex(pdu)
        );
        assert!(pdu
            .windows(7)
            .any(|w| w == [0x29, 0x05, 0x01, 0x0a, 0xff, 0x00, 0x03]));
        // The bearer that carries it: one DRB with SDAP + PDCP config.
        let rbc = m.radio_bearer_config.as_ref().unwrap();
        assert_eq!(rbc.drb_to_add_mod_list.len(), 1);
        let drb = &rbc.drb_to_add_mod_list[0];
        assert!(matches!(
            drb.cn_association,
            Some(CnAssociation::SdapConfig(_))
        ));
        let pdcp = drb.pdcp_config.as_ref().unwrap().drb.unwrap();
        assert!(matches!(
            pdcp.header_compression,
            HeaderCompression::NotUsed
        ));
        assert!(pdcp.pdcp_sn_size_ul.is_some() && pdcp.pdcp_sn_size_dl.is_some());
        // The masterCellGroup adds the DRB's RLC bearer.
        let cg = m.master_cell_group().expect("masterCellGroup");
        assert!(cg.rlc_bearer_to_add_mod_list.iter().any(|b| matches!(
            b.served_radio_bearer,
            Some(crate::cellgroup::ServedRadioBearer::Drb(_))
        )));
        assert_eq!(
            DlDcchMessage::kind(&from_hex(RECONFIG_HEX).unwrap()).unwrap(),
            (
                DlDcchKind::RrcReconfiguration,
                Some(m.rrc_transaction_identifier)
            )
        );
    }

    #[test]
    fn ue_nr_capability_matches_ocudu_vector() {
        let cap = UeNrCapability {
            access_stratum_release: AccessStratumRelease::Rel15,
            supported_band_list_nr: vec![78],
            pdsch_256qam_fr1: false,
            pusch_256qam: false,
            drx: false,
        };
        let bytes = cap.encode();
        assert_eq!(bytes, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0x9a]);
        assert_eq!(UeNrCapability::decode(&bytes).unwrap(), cap);
        let multi = UeNrCapability {
            access_stratum_release: AccessStratumRelease::Rel16,
            supported_band_list_nr: vec![1, 3, 78],
            pdsch_256qam_fr1: false,
            pusch_256qam: false,
            drx: false,
        };
        assert_eq!(UeNrCapability::decode(&multi.encode()).unwrap(), multi);
        // mac-Parameters with long + short DRX: 2 + 1 + 6 extra bits after PDCP-Parameters.
        let drx = UeNrCapability {
            drx: true,
            ..multi.clone()
        };
        let b = drx.encode();
        assert_eq!(b[0] & 0x40, 0x40, "mac-Parameters present");
        assert_eq!(b.len() * 8, multi.encode().len() * 8 + 8);
        assert_eq!(UeNrCapability::decode(&b).unwrap(), drx);
        // UECapabilityInformation tid 0 with the minimal capability, validated against
        // OCUDU `rrc_dec gen-uecapinfo`: 4882028000000000000000002680.
        let m = UlDcchMessage::UeCapabilityInformation(UeCapabilityInformation {
            rrc_transaction_identifier: 0,
            ue_capability_rat_container_list: vec![UeCapabilityRatContainer {
                rat_type: RatType::Nr,
                container: bytes,
            }],
        });
        assert_eq!(
            ferrite_common::hex(&m.encode()),
            "4882028000000000000000002680"
        );
        assert_eq!(UlDcchMessage::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn setup_request_layout_and_round_trip() {
        let m = UlCcchMessage::RrcSetupRequest(RrcSetupRequest {
            ue_identity: InitialUeIdentity::RandomValue((1 << 39) - 1),
            establishment_cause: EstablishmentCause::MoSignalling,
        });
        let b = m.encode();
        assert_eq!(b.len(), 6);
        assert_eq!(b[0], 0x1f);
        assert_eq!(&b[1..5], &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(b[5] & 1, 0);
        assert_eq!((b[5] >> 1) & 0xf, 3);
        assert_eq!(UlCcchMessage::decode(&b).unwrap(), m);
        for m in [
            UlCcchMessage::RrcSetupRequest(RrcSetupRequest {
                ue_identity: InitialUeIdentity::Ng5gSTmsiPart1(0x12_3456_789a),
                establishment_cause: EstablishmentCause::MoData,
            }),
            UlCcchMessage::RrcReestablishmentRequest(RrcReestablishmentRequest {
                c_rnti: 0x4601,
                phys_cell_id: 500,
                short_mac_i: 0xbeef,
                reestablishment_cause: ReestablishmentCause::OtherFailure,
            }),
            UlCcchMessage::RrcSystemInfoRequest(RrcSystemInfoRequest {
                requested_si_list: 0x8000_0001,
            }),
        ] {
            assert_eq!(UlCcchMessage::decode(&m.encode()).unwrap(), m, "{m:?}");
        }
    }

    #[test]
    fn ul_dcch_round_trips_and_legacy_layouts() {
        let nas = vec![0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d];
        let setup_complete = UlDcchMessage::RrcSetupComplete(RrcSetupComplete {
            rrc_transaction_identifier: 1,
            selected_plmn_identity: 1,
            registered_amf: None,
            guami_type: None,
            s_nssai_list: vec![],
            dedicated_nas_message: nas.clone(),
            ng_5g_s_tmsi_value: None,
        });
        let b = setup_complete.encode();
        // Legacy layout: [0][0010][01][0][000000][0000] then the NAS octet string.
        assert_eq!(b[0], 0b0001_0010);
        assert_eq!(b[1], 0);
        assert_eq!(UlDcchMessage::decode(&b).unwrap(), setup_complete);
        let full = UlDcchMessage::RrcSetupComplete(RrcSetupComplete {
            rrc_transaction_identifier: 2,
            selected_plmn_identity: 3,
            registered_amf: Some(RegisteredAmf {
                plmn_identity: Some(PlmnIdentity {
                    mcc: Some([0, 0, 1]),
                    mnc: vec![0, 1],
                }),
                amf_identifier: 0x0002_0100,
            }),
            guami_type: Some(GuamiType::Native),
            s_nssai_list: vec![SNssai::Sst(1), SNssai::SstSd(0x0100_0001)],
            dedicated_nas_message: nas.clone(),
            ng_5g_s_tmsi_value: Some(Ng5gSTmsiValue::Part2(0x1ff)),
        });
        assert_eq!(UlDcchMessage::decode(&full.encode()).unwrap(), full);
        let ul = UlDcchMessage::UlInformationTransfer(UlInformationTransfer {
            dedicated_nas_message: Some(nas.clone()),
        });
        let b = ul.encode();
        assert_eq!(b[0] >> 3, 0b00111); // c1, index 7
        assert_eq!(UlDcchMessage::decode(&b).unwrap(), ul);
        for tid in 0..4u8 {
            let smc = UlDcchMessage::SecurityModeComplete {
                rrc_transaction_identifier: tid,
            };
            assert_eq!(smc.encode(), vec![0b0010_1000 | (tid << 1), 0]);
            assert_eq!(UlDcchMessage::decode(&smc.encode()).unwrap(), smc);
            let rc = UlDcchMessage::RrcReconfigurationComplete {
                rrc_transaction_identifier: tid,
            };
            assert_eq!(rc.encode(), vec![0b0000_1000 | (tid << 1), 0]);
            assert_eq!(UlDcchMessage::decode(&rc.encode()).unwrap(), rc);
            let smf = UlDcchMessage::SecurityModeFailure {
                rrc_transaction_identifier: tid,
            };
            assert_eq!(UlDcchMessage::decode(&smf.encode()).unwrap(), smf);
        }
    }

    #[test]
    fn dl_dcch_round_trips() {
        let nas = vec![0x7e, 0x00, 0x56, 0x01, 0x02];
        let msgs = vec![
            DlDcchMessage::DlInformationTransfer(DlInformationTransfer {
                rrc_transaction_identifier: 2,
                dedicated_nas_message: Some(nas.clone()),
            }),
            DlDcchMessage::SecurityModeCommand(SecurityModeCommand {
                rrc_transaction_identifier: 1,
                security_algorithm_config: SecurityAlgorithmConfig {
                    ciphering_algorithm: CipheringAlgorithm::Nea2,
                    integrity_prot_algorithm: Some(IntegrityProtAlgorithm::Nia2),
                },
            }),
            DlDcchMessage::UeCapabilityEnquiry(UeCapabilityEnquiry {
                rrc_transaction_identifier: 0,
                ue_capability_rat_request_list: vec![UeCapabilityRatRequest {
                    rat_type: RatType::Nr,
                    capability_request_filter: Some(vec![0x00, 0x1a]),
                }],
                ue_capability_enquiry_ext: None,
            }),
            DlDcchMessage::RrcRelease(RrcRelease {
                rrc_transaction_identifier: 3,
                deprioritisation_req: Some((true, 15)),
                wait_time: Some(4),
                ..Default::default()
            }),
            DlDcchMessage::RrcReestablishment(RrcReestablishment {
                rrc_transaction_identifier: 1,
                next_hop_chaining_count: 5,
            }),
            DlDcchMessage::CounterCheck(CounterCheck {
                rrc_transaction_identifier: 2,
                drb_count_msb_info_list: vec![DrbCountMsbInfo {
                    drb_identity: 1,
                    count_msb_uplink: 7,
                    count_msb_downlink: 33554431,
                }],
            }),
            DlDcchMessage::RrcReconfiguration(RrcReconfiguration {
                rrc_transaction_identifier: 0,
                radio_bearer_config: Some(RadioBearerConfig {
                    srb_to_add_mod_list: vec![SrbToAddMod {
                        srb_identity: 2,
                        reestablish_pdcp: false,
                        discard_on_pdcp: false,
                        pdcp_config: Some(PdcpConfig {
                            t_reordering_ms: Some(100),
                            ..Default::default()
                        }),
                    }],
                    drb_to_add_mod_list: vec![DrbToAddMod {
                        cn_association: Some(CnAssociation::SdapConfig(SdapConfig {
                            pdu_session: 1,
                            sdap_header_dl_present: false,
                            sdap_header_ul_present: true,
                            default_drb: true,
                            mapped_qos_flows_to_add: vec![1, 2],
                            mapped_qos_flows_to_release: vec![],
                        })),
                        drb_identity: 1,
                        reestablish_pdcp: false,
                        recover_pdcp: false,
                        pdcp_config: Some(PdcpConfig {
                            drb: Some(PdcpDrbConfig {
                                discard_timer: Some(PdcpDiscardTimer::Infinity),
                                pdcp_sn_size_ul: Some(18),
                                pdcp_sn_size_dl: Some(18),
                                header_compression: HeaderCompression::Rohc {
                                    max_cid: Some(15),
                                    profiles: 0b1_0000_0000,
                                    drb_continue_rohc: false,
                                },
                                integrity_protection: false,
                                status_report_required: true,
                                out_of_order_delivery: false,
                            }),
                            more_than_one_rlc: None,
                            t_reordering_ms: Some(0),
                        }),
                    }],
                    drb_to_release_list: vec![2],
                    security_config: Some(SecurityConfig {
                        security_algorithm_config: Some(SecurityAlgorithmConfig {
                            ciphering_algorithm: CipheringAlgorithm::Nea0,
                            integrity_prot_algorithm: None,
                        }),
                        key_to_use: Some(KeyToUse::Master),
                    }),
                    ..Default::default()
                }),
                v1530: Some(RrcReconfigurationV1530 {
                    dedicated_nas_message_list: vec![nas.clone(), vec![1, 2, 3]],
                    master_key_update: Some(MasterKeyUpdate {
                        key_set_change_indicator: true,
                        next_hop_chaining_count: 3,
                        nas_container: None,
                    }),
                    other_config: Some(OtherConfig {
                        delay_budget_reporting_config: Some(SetupRelease::Setup(2)),
                    }),
                    v1540: Some(RrcReconfigurationV1540 {
                        overheating_assistance_config: Some(Some(SetupRelease::Release)),
                        v1560: Some(RrcReconfigurationV1560 {
                            sk_counter: Some(7),
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        ];
        for m in msgs {
            let b = m.encode().unwrap();
            assert_eq!(DlDcchMessage::decode(&b).unwrap(), m, "{m:?}");
        }
        let rej = DlCcchMessage::RrcReject(RrcReject {
            wait_time: Some(16),
        });
        assert_eq!(DlCcchMessage::decode(&rej.encode().unwrap()).unwrap(), rej);
        assert!(DlDcchMessage::decode(&[0x80]).is_err());
    }
}

// ---------------------------------------------------------------------------
// PCCH
// ---------------------------------------------------------------------------

/// A `PagingRecord.ue-Identity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingUeIdentity {
    /// 48-bit 5G-S-TMSI.
    Ng5gSTmsi(u64),
    /// 40-bit fullI-RNTI.
    FullIRnti(u64),
}

/// `PCCH-Message ::= SEQUENCE { message CHOICE { c1 CHOICE { paging Paging, spare1 NULL },
/// messageClassExtension SEQUENCE {} } }` with `Paging ::= SEQUENCE { pagingRecordList
/// SEQUENCE (SIZE (1..maxNrofPageRec)) OF PagingRecord OPTIONAL, lateNonCriticalExtension
/// OCTET STRING OPTIONAL, nonCriticalExtension Paging-v1700-IEs OPTIONAL }` and
/// `PagingRecord ::= SEQUENCE { ue-Identity PagingUE-Identity, accessType ENUMERATED
/// { non3GPP } OPTIONAL, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PagingMessage {
    pub records: Vec<PagingUeIdentity>,
}

impl PagingMessage {
    pub fn decode(pdu: &[u8]) -> DecodeResult<Self> {
        Self::decode_inner(&mut BitReader::new(pdu)).ctx("PCCH-Message")
    }

    fn decode_inner(r: &mut BitReader) -> DecodeResult<Self> {
        if r.bit()? {
            return r.unsupported("messageClassExtension");
        }
        if r.bit()? {
            return r.unsupported("spare1");
        }
        let [has_list, _late, _non_crit] = r.opt_bits::<3>()?;
        let records = if has_list {
            r.seq_of(1, 32, |r| {
                let ext = r.bit()?;
                let [has_access_type] = r.opt_bits::<1>()?;
                if r.bit()? {
                    return r.unsupported("PagingUE-Identity extension alternative");
                }
                let id = if r.bit()? {
                    PagingUeIdentity::FullIRnti(r.bitstring(40)?)
                } else {
                    PagingUeIdentity::Ng5gSTmsi(r.bitstring(48)?)
                };
                if has_access_type {
                    r.enu(1)?;
                }
                if ext {
                    r.skip_ext_additions()?;
                }
                Ok(id)
            })?
        } else {
            Vec::new()
        };
        Ok(Self { records })
    }

    /// Encode (tests / tooling).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bit(false);
        w.bit(false);
        w.opt_bits(&[!self.records.is_empty(), false, false]);
        if !self.records.is_empty() {
            w.seq_of(&self.records, 1, 32, |w, id| {
                w.bit(false);
                w.opt_bits(&[false]);
                w.bit(false);
                match *id {
                    PagingUeIdentity::Ng5gSTmsi(v) => {
                        w.bit(false);
                        w.bitstring(v, 48);
                    }
                    PagingUeIdentity::FullIRnti(v) => {
                        w.bit(true);
                        w.bitstring(v, 40);
                    }
                }
            });
        }
        w.finish()
    }
}

#[cfg(test)]
mod pcch_tests {
    use super::*;

    #[test]
    fn paging_round_trip() {
        let m = PagingMessage {
            records: vec![
                PagingUeIdentity::Ng5gSTmsi(0x1234_5678_9abc),
                PagingUeIdentity::FullIRnti(0xab_cdef_0123),
            ],
        };
        let bytes = m.encode();
        assert_eq!(PagingMessage::decode(&bytes).unwrap(), m);
        // An empty Paging (no records) is 1 byte: 0 0 000 + padding.
        assert_eq!(PagingMessage::decode(&[0x00]).unwrap().records.len(), 0);
    }
}
