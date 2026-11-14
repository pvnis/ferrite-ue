//! Radio bearers: one RLC + PDCP entity pair per logical channel, the
//! MAC-facing [`UpperLayers`] SAP, AS-security installation and the
//! re-establishment bookkeeping (TS 38.331 §5.3.5.5 / §5.3.7.4).
//!
//! The table owns the entities; the stack only routes PDUs through it.

use ferrite_common::{Numerology, SlotPoint};
use ferrite_mac::UpperLayers;
use ferrite_pdcp::{PdcpConfig, PdcpEntity, SecurityConfig, SnLen};
use ferrite_rlc::{AmConfig, RlcEntity, RlcEvent, RlcMode, UmConfig};
use ferrite_rrc::{AsSecurity, BearerSetup, RbId, RlcSetup};
use std::collections::BTreeMap;

/// One radio bearer: its RLC and PDCP entities.
pub struct Bearer {
    pub rb: RbId,
    pub rlc: RlcEntity,
    pub pdcp: PdcpEntity,
    /// PDU session the DRB belongs to (from the SDAP configuration).
    pub pdu_session: Option<u8>,
}

/// What one receive pass produced.
#[derive(Default)]
pub struct Delivered {
    /// `(SRB id, PDCP SDU, raw PDCP PDU)`; the raw PDU is kept so the stack can
    /// verify a SecurityModeCommand / RRCReestablishment MAC-I once the keys
    /// are known.
    pub srb: Vec<(u8, Vec<u8>, Vec<u8>)>,
    /// IP packets from the DRBs.
    pub ip: Vec<Vec<u8>>,
    /// LCIDs whose RLC AM entity reached `maxRetxThreshold`.
    pub rlc_max_retx: Vec<u8>,
}

/// The bearer table.
pub struct Bearers {
    by_lcid: BTreeMap<u8, Bearer>,
    numerology: Numerology,
    /// Between an RRC re-establishment and the reconfiguration that restores
    /// the bearers: every RLC entity has been renewed, PDCP state is kept.
    reestablishing: bool,
}

impl Bearers {
    pub fn new(numerology: Numerology) -> Self {
        Self { by_lcid: BTreeMap::new(), numerology, reestablishing: false }
    }

    /// The data numerology (from SIB1) the entity timers run on.
    pub fn set_numerology(&mut self, numerology: Numerology) {
        self.numerology = numerology;
    }

    pub fn clear(&mut self) {
        self.by_lcid.clear();
        self.reestablishing = false;
    }

    pub fn remove(&mut self, lcid: u8) -> Option<Bearer> {
        self.by_lcid.remove(&lcid)
    }

    pub fn srb(&self, srb: u8) -> Option<&Bearer> {
        self.by_lcid.values().find(|b| b.rb == RbId::Srb(srb))
    }

    pub fn srb_mut(&mut self, srb: u8) -> Option<&mut Bearer> {
        self.by_lcid.values_mut().find(|b| b.rb == RbId::Srb(srb))
    }

    /// LCID of the (lowest) DRB, the default data bearer; `None` while idle
    /// or before the first reconfiguration.
    pub fn drb_lcid(&self) -> Option<u8> {
        self.by_lcid.iter().find(|(_, b)| matches!(b.rb, RbId::Drb(_))).map(|(l, _)| *l)
    }

    pub fn reestablishing(&self) -> bool {
        self.reestablishing
    }

    /// Create or reconfigure the bearer of `b` (TS 38.331 §5.3.5.5 / §5.3.5.6).
    /// An existing bearer keeps its PDCP entity (COUNTs, reordering state)
    /// unless the network asks for a PDCP re-establishment, and its RLC entity
    /// unless `reestablishRLC` (a re-establishment already renewed every RLC
    /// entity). AS security, when active, is installed on a new entity.
    pub fn setup(&mut self, b: BearerSetup, security: Option<&AsSecurity>) {
        let n = self.numerology;
        let rlc = match &b.rlc {
            RlcSetup::Tm => RlcEntity::new(RlcMode::Tm, n),
            RlcSetup::Um { sn_len, t_reassembly_ms } => RlcEntity::new(RlcMode::Um(UmConfig { sn_len: rlc_sn(*sn_len), t_reassembly_ms: *t_reassembly_ms }), n),
            RlcSetup::Am { sn_len, t_poll_retransmit_ms, poll_pdu, poll_byte, max_retx, t_reassembly_ms, t_status_prohibit_ms } => RlcEntity::new(
                RlcMode::Am(AmConfig {
                    sn_len: rlc_sn(*sn_len),
                    t_poll_retransmit_ms: *t_poll_retransmit_ms,
                    poll_pdu: *poll_pdu,
                    poll_byte: *poll_byte,
                    max_retx_threshold: *max_retx,
                    t_reassembly_ms: *t_reassembly_ms,
                    t_status_prohibit_ms: *t_status_prohibit_ms,
                }),
                n,
            ),
        };
        let mut pcfg = match b.rb {
            RbId::Srb(id) => PdcpConfig::srb(id),
            RbId::Drb(id) => PdcpConfig::drb(id, if b.pdcp_sn_len == 18 { SnLen::Len18 } else { SnLen::Len12 }),
        };
        pcfg.integrity_on_drb = b.pdcp_integrity;
        pcfg.sdap_header_ul = b.sdap_header_ul;
        pcfg.sdap_header_dl = b.sdap_header_dl;
        pcfg.qfi = b.qfi;
        pcfg.t_reordering_ms = b.t_reordering_ms.or(pcfg.t_reordering_ms);
        pcfg.discard_timer_ms = b.discard_timer_ms;
        let existing = self.by_lcid.iter().find(|(_, x)| x.rb == b.rb).map(|(l, _)| *l);
        let mut pdcp = match existing.and_then(|l| self.by_lcid.remove(&l)) {
            Some(old) => {
                let mut p = old.pdcp;
                if b.reestablish_pdcp {
                    p.reestablish();
                }
                if !b.reestablish_rlc && !self.reestablishing {
                    // Keep the RLC entity too: only the configuration is refreshed.
                    log::info!("bearer {:?} on LCID {} reconfigured ({:?})", b.rb, b.lcid, b.rlc);
                    self.by_lcid.insert(b.lcid, Bearer { rb: b.rb, rlc: old.rlc, pdcp: p, pdu_session: b.pdu_session.or(old.pdu_session) });
                    return;
                }
                p
            }
            None => PdcpEntity::new(pcfg, n),
        };
        if let Some(sec) = security {
            configure(&mut pdcp, b.rb, sec, b.pdcp_integrity);
        }
        log::info!("bearer {:?} on LCID {} ({:?})", b.rb, b.lcid, b.rlc);
        self.by_lcid.insert(b.lcid, Bearer { rb: b.rb, rlc, pdcp, pdu_session: b.pdu_session });
    }

    /// Install `sec` on every bearer `select` accepts: RRC keys on SRBs, UP
    /// keys on DRBs (integrity only where the DRB is configured for it).
    pub fn install_security(&mut self, sec: &AsSecurity, select: impl Fn(RbId) -> bool) {
        for b in self.by_lcid.values_mut().filter(|b| select(b.rb)) {
            let integ = b.pdcp.config().integrity_on_drb;
            configure(&mut b.pdcp, b.rb, sec, integ);
        }
    }

    /// Ciphering of the SRBs' transmit side (the SecurityModeComplete goes out
    /// integrity protected but not ciphered, TS 38.331 §5.3.4.3).
    pub fn set_srb_tx_cipher(&mut self, enabled: bool) {
        for b in self.by_lcid.values_mut().filter(|b| matches!(b.rb, RbId::Srb(_))) {
            b.pdcp.set_tx_cipher_enabled(enabled);
        }
    }

    /// TS 38.331 §5.3.7.4: RLC re-established for every bearer; SRB1 PDCP
    /// re-established (no security until the new keys are verified); SRB2 /
    /// DRB PDCP state kept, suspended until the network reconfigures them.
    pub fn begin_reestablishment(&mut self) {
        let n = self.numerology;
        for b in self.by_lcid.values_mut() {
            let mode = b.rlc.mode().clone();
            b.rlc = RlcEntity::new(mode, n);
            if b.rb == RbId::Srb(1) {
                b.pdcp = PdcpEntity::new(PdcpConfig::srb(1), n);
            }
        }
        self.reestablishing = true;
    }

    /// The reconfiguration after a re-establishment restored the bearers.
    pub fn end_reestablishment(&mut self) {
        self.reestablishing = false;
    }

    /// Send an RRC PDU on `srb`; `false` when the SRB does not exist.
    pub fn tx_srb(&mut self, srb: u8, pdu: &[u8], now: SlotPoint) -> bool {
        match self.srb_mut(srb) {
            Some(b) => {
                let pdcp_pdu = b.pdcp.tx_sdu(pdu, now);
                b.rlc.tx_sdu(pdcp_pdu);
                true
            }
            None => false,
        }
    }

    /// Send an IP packet on the DRB `lcid`; `false` when it does not exist.
    pub fn tx_drb(&mut self, lcid: u8, packet: &[u8], now: SlotPoint) -> bool {
        match self.by_lcid.get_mut(&lcid) {
            Some(b) => {
                let pdu = b.pdcp.tx_sdu(packet, now);
                b.rlc.tx_sdu(pdu);
                true
            }
            None => false,
        }
    }

    /// Per-slot timers of every entity.
    pub fn tick(&mut self, now: SlotPoint) {
        for b in self.by_lcid.values_mut() {
            b.rlc.tick(now);
            b.pdcp.tick(now);
        }
    }

    /// Move every reassembled RLC SDU through PDCP and collect what came out.
    pub fn deliver_rx(&mut self, now: SlotPoint) -> Delivered {
        let mut out = Delivered::default();
        for (lcid, b) in self.by_lcid.iter_mut() {
            while let Some(sdu) = b.rlc.pop_rx_sdu() {
                let raw = sdu.clone();
                if let Err(e) = b.pdcp.rx_pdu(&sdu, now) {
                    log::warn!("PDCP rx on LCID {lcid}: {e}");
                    continue;
                }
                while let Some(s) = b.pdcp.pop_rx_sdu() {
                    match b.rb {
                        RbId::Srb(id) => out.srb.push((id, s, raw.clone())),
                        RbId::Drb(_) => out.ip.push(s),
                    }
                }
            }
            for ev in b.rlc.events() {
                let RlcEvent::MaxRetxReached { .. } = ev;
                out.rlc_max_retx.push(*lcid);
            }
        }
        out
    }
}

impl UpperLayers for Bearers {
    fn dl_sdu(&mut self, lcid: u8, sdu: &[u8], now: SlotPoint) {
        if let Some(b) = self.by_lcid.get_mut(&lcid) {
            b.rlc.rx_pdu(sdu, now);
        } else {
            log::debug!("DL SDU on unknown LCID {lcid} ({} B)", sdu.len());
        }
    }
    fn ul_pull(&mut self, lcid: u8, max_bytes: usize, now: SlotPoint) -> Option<Vec<u8>> {
        self.by_lcid.get_mut(&lcid).and_then(|b| b.rlc.pull_pdu(max_bytes, now))
    }
    fn ul_buffer_status(&mut self, lcid: u8) -> usize {
        self.by_lcid.get(&lcid).map_or(0, |b| b.rlc.buffer_status())
    }
}

/// The PDCP security configuration of a bearer under `sec` (TS 38.323 §5.8 /
/// §5.9): RRC keys on SRBs, UP keys on DRBs.
fn security_for(sec: &AsSecurity, rb: RbId, integrity_on_drb: bool) -> SecurityConfig {
    match rb {
        RbId::Srb(_) => SecurityConfig { integrity: Some((sec.integrity_alg, sec.k_rrc_int)), cipher: Some((sec.ciphering_alg, sec.k_rrc_enc)) },
        RbId::Drb(_) => SecurityConfig { integrity: integrity_on_drb.then_some((sec.integrity_alg, sec.k_up_int)), cipher: Some((sec.ciphering_alg, sec.k_up_enc)) },
    }
}

fn configure(pdcp: &mut PdcpEntity, rb: RbId, sec: &AsSecurity, integrity_on_drb: bool) {
    if let Err(e) = pdcp.configure_security(security_for(sec, rb, integrity_on_drb)) {
        // Unreachable with the algorithms RRC accepts; never silently ignored.
        log::error!("{rb:?}: PDCP rejected the security configuration: {e}");
    }
}

fn rlc_sn(bits: u8) -> ferrite_rlc::SnLen {
    match bits {
        6 => ferrite_rlc::SnLen::Bits6,
        18 => ferrite_rlc::SnLen::Bits18,
        _ => ferrite_rlc::SnLen::Bits12,
    }
}
