//! DCI resolution: raw DCI fields (TS 38.212 §7.3.1) → FAPI grants, using the
//! PHY configuration (TDRA tables, k1 list, BWP sizes, DMRS/MCS config).

use crate::config::{McsTableSel, PhyConfig, SearchSpaceKind, TddConfig, TdraRow};
use crate::fapi::{Dci, DlGrant, Mcs, RarUlGrant, TimeAlloc, TransformPrecoding, UlGrant};
use ferrite_common::{Rnti, RntiKind, SlotPoint};
use ferrite_phy::coding::dci::{self as dci, DciSizeConfig, DciSizes, HarqAckCodebook};
use ferrite_phy::dmrs::{self, MappingType};
use ferrite_phy::mcs::{self, McsTable};
use ferrite_phy::pdsch_params;

/// Which DCI payload sizes to try for a given search-space / RNTI combination.
#[derive(Clone, Debug)]
pub struct DciResolver {
    pub sizes: DciSizes,
    pub coreset0_rb: Option<usize>,
    pub coreset0_first_crb: usize,
    pub dl_bwp_rb: usize,
    pub ul_bwp_rb: usize,
    pub dl_bwp_start: usize,
    /// Active BWP ids and the number of RRC-configured BWPs (BWP indicator).
    pub dl_bwp_id: u8,
    pub ul_bwp_id: u8,
    pub nof_dl_bwp_rrc: u8,
    pub nof_ul_bwp_rrc: u8,
    pub pdsch_tdra: Vec<TdraRow>,
    pub pusch_tdra: Vec<TdraRow>,
    pub pdsch_tdra_common: Vec<TdraRow>,
    pub pusch_tdra_common: Vec<TdraRow>,
    pub k1_list: Vec<u8>,
    pub dmrs_typea_pos: u8,
    pub pdsch_mcs: McsTable,
    /// PUSCH MCS table for DCI 0_1 (TS 38.214 §6.1.4.1, transform precoding
    /// taken into account).
    pub pusch_mcs: McsTable,
    /// Transform precoding for RAR / DCI 0_0 scheduled PUSCH (`msg3-transformPrecoder`).
    pub msg3_tp: Option<TransformPrecoding>,
    /// Transform precoding for DCI 0_1 scheduled PUSCH.
    pub ded_tp: Option<TransformPrecoding>,
    pub dl_dmrs_add_pos: u8,
    pub ul_dmrs_add_pos: u8,
    pub mu: u8,
    pub msg3_delta: u8,
    /// TDD pattern: a grant whose PDSCH lies in UL symbols or whose PUSCH lies
    /// in DL symbols cannot be meant for this cell and is dropped.
    pub tdd: Option<TddConfig>,
}

fn sel(t: McsTableSel) -> McsTable {
    match t {
        McsTableSel::Qam64 => McsTable::Qam64,
        McsTableSel::Qam256 => McsTable::Qam256,
        McsTableSel::Qam64LowSe => McsTable::Qam64LowSe,
    }
}

impl DciResolver {
    pub fn new(cfg: &PhyConfig, dedicated: bool) -> Self {
        let coreset0 = cfg.coresets.iter().find(|c| c.id == 0);
        let coreset0_rb = coreset0.map(|c| c.rb_mask.iter().filter(|&&b| b).count());
        let mut sc = DciSizeConfig::single_bwp(cfg.dl_bwp.n_rb as usize, coreset0_rb.unwrap_or(0));
        sc.ul_bwp_initial_rb = cfg.ul_bwp.n_rb as usize;
        sc.ul_bwp_active_rb = cfg.ul_bwp.n_rb as usize;
        sc.coreset0_rb = coreset0_rb;
        sc.monitor_0_1_1_1 = dedicated;
        sc.nof_dl_bwp_rrc = usize::from(cfg.nof_dl_bwp_rrc);
        sc.nof_ul_bwp_rrc = usize::from(cfg.nof_ul_bwp_rrc);
        // Fallback formats in a USS only when one is configured for them
        // (TS 38.212 §7.3.1.0 step 1/2: the 0_0/1_0 USS size and the 0_1
        // one-bit padding exist only then).
        sc.monitor_0_0_1_0_in_uss = cfg.search_spaces.iter().any(|s| s.kind == SearchSpaceKind::UeSpecificFallback);
        sc.harq_ack_codebook = if cfg.harq_codebook_dynamic { HarqAckCodebook::Dynamic } else { HarqAckCodebook::SemiStatic };
        let pdsch_rows = if !cfg.pdsch.tdra.is_empty() { cfg.pdsch.tdra.len() } else if !cfg.pdsch_tdra_common.is_empty() { cfg.pdsch_tdra_common.len() } else { 16 };
        let pusch_rows = if !cfg.pusch.tdra.is_empty() { cfg.pusch.tdra.len() } else if !cfg.pusch_tdra_common.is_empty() { cfg.pusch_tdra_common.len() } else { 16 };
        sc.nof_pdsch_tdra_rows = pdsch_rows;
        sc.nof_pusch_tdra_rows = pusch_rows;
        sc.nof_k1 = cfg.pucch.k1_list.len().max(1);
        sc.vrb_to_prb_interleaver = cfg.pdsch.vrb_to_prb_interleaver.is_some();
        sc.frequency_hopping = cfg.pusch.frequency_hopping;
        sc.transform_precoding = cfg.pusch.transform_precoder;
        sc.dynamic_beta_offsets = false;
        sc.dl_harq_bits = 4;
        sc.ul_harq_bits = 4;
        let sizes = dci::dci_sizes(&sc);
        Self {
            sizes,
            coreset0_rb,
            coreset0_first_crb: coreset0.map_or(0, |c| c.start_crb as usize),
            dl_bwp_rb: cfg.dl_bwp.n_rb as usize,
            ul_bwp_rb: cfg.ul_bwp.n_rb as usize,
            dl_bwp_start: cfg.dl_bwp.start_crb as usize,
            dl_bwp_id: cfg.dl_bwp.id,
            ul_bwp_id: cfg.ul_bwp.id,
            nof_dl_bwp_rrc: cfg.nof_dl_bwp_rrc,
            nof_ul_bwp_rrc: cfg.nof_ul_bwp_rrc,
            pdsch_tdra: cfg.pdsch.tdra.clone(),
            pusch_tdra: cfg.pusch.tdra.clone(),
            pdsch_tdra_common: cfg.pdsch_tdra_common.clone(),
            pusch_tdra_common: cfg.pusch_tdra_common.clone(),
            k1_list: cfg.pucch.k1_list.clone(),
            dmrs_typea_pos: cfg.ssb.dmrs_typea_pos,
            pdsch_mcs: sel(cfg.pdsch.mcs_table),
            pusch_mcs: if cfg.pusch.transform_precoder {
                match cfg.pusch.mcs_table_tp {
                    McsTableSel::Qam256 => McsTable::Qam256,
                    // Table 6.1.4.1-2 (qam64LowSE with transform precoding) not implemented: use 6.1.4.1-1.
                    _ => McsTable::Qam64TransformPrecoding,
                }
            } else {
                sel(cfg.pusch.mcs_table)
            },
            msg3_tp: cfg.pusch.msg3_transform_precoder.then_some(TransformPrecoding {
                n_id_rs: cfg.ssb.pci,
                group_hopping: cfg.pusch.msg3_group_hopping,
                sequence_hopping: false,
                pi2_bpsk: false,
            }),
            ded_tp: cfg.pusch.transform_precoder.then_some(TransformPrecoding {
                n_id_rs: cfg.pusch.tp_dmrs.n_pusch_identity.unwrap_or(cfg.ssb.pci),
                group_hopping: cfg.pusch.msg3_group_hopping && !cfg.pusch.tp_dmrs.group_hopping_disabled,
                sequence_hopping: cfg.pusch.tp_dmrs.sequence_hopping,
                pi2_bpsk: cfg.pusch.tp_pi2_bpsk,
            }),
            dl_dmrs_add_pos: cfg.pdsch.dmrs_type_a.additional_position,
            ul_dmrs_add_pos: cfg.pusch.dmrs_type_a.additional_position,
            tdd: cfg.tdd.clone(),
            mu: cfg.numerology.mu,
            msg3_delta: match cfg.numerology.mu {
                0 => 2,
                1 => 3,
                2 => 4,
                _ => 6,
            },
        }
    }

    /// PDSCH TDRA row for a DCI format (TS 38.214 Table 5.1.2.1.1-1): CSS
    /// fallback DCI uses the common list (SIB1 or the default table A); DCI
    /// 1_1 uses the dedicated list when configured.
    pub fn pdsch_tdra_row(&self, row: usize, dedicated: bool, rnti: RntiKind) -> Option<TdraRow> {
        let list: &[TdraRow] = match rnti {
            RntiKind::Si => &[], // SI-RNTI → default table A always (OCUDU behaviour)
            _ if dedicated && !self.pdsch_tdra.is_empty() => &self.pdsch_tdra,
            _ => &self.pdsch_tdra_common,
        };
        if let Some(r) = list.get(row) {
            return Some(*r);
        }
        dci::default_pdsch_tdra(row as u8, self.dmrs_typea_pos).map(|r| TdraRow {
            k: r.k,
            mapping_type_a: matches!(r.mapping, MappingType::TypeA),
            start_symbol: r.s as u8,
            n_symbols: r.l as u8,
        })
    }

    pub fn pusch_tdra_row(&self, row: usize, dedicated: bool) -> Option<TdraRow> {
        let list: &[TdraRow] = if dedicated && !self.pusch_tdra.is_empty() { &self.pusch_tdra } else { &self.pusch_tdra_common };
        if let Some(r) = list.get(row) {
            return Some(*r);
        }
        dci::default_pusch_tdra(row as u8, self.mu).map(|r| TdraRow {
            k: r.k,
            mapping_type_a: matches!(r.mapping, MappingType::TypeA),
            start_symbol: r.s as u8,
            n_symbols: r.l as u8,
        })
    }

    /// BWP-Id named by a DCI bandwidth-part indicator (TS 38.212 Table
    /// 7.3.1.1.2-1): the field value itself when up to 3 BWPs are configured
    /// besides the initial one (0 = initial), else value + 1.
    fn bwp_id_of(indicator: u8, nof_bwp_rrc: u8) -> u8 {
        if nof_bwp_rrc <= 3 {
            indicator
        } else {
            indicator + 1
        }
    }

    /// TS 38.213 §11.1: a PDSCH must not be in UL symbols, a PUSCH not in DL
    /// symbols (flexible symbols are fine when scheduled by a DCI).
    fn direction_ok(&self, slot: SlotPoint, row: &TdraRow, ul: bool) -> bool {
        use crate::config::LinkDirection;
        let Some(t) = &self.tdd else { return true };
        let dir = if ul { LinkDirection::Ul } else { LinkDirection::Dl };
        if t.conflicts(slot.index(), slot.numerology, row.start_symbol, row.n_symbols, dir) {
            log::debug!("{} at {slot} symbols {}+{} conflicts with the TDD pattern: grant dropped", if ul { "PUSCH" } else { "PDSCH" }, row.start_symbol, row.n_symbols);
            return false;
        }
        true
    }

    fn mcs(&self, table: McsTable, i: u8) -> Mcs {
        let (qm, r) = match mcs::mcs_params(table, i) {
            Some((qm, r)) => (qm, Some(r)),
            None => (mcs::mcs_modulation_order(table, i).unwrap_or(2), None),
        };
        Mcs { index: i, qm, r_x1024: r }
    }

    /// PUSCH MCS: the `q` rows of Table 6.1.4.1-1 are `Q_m = 1` (π/2-BPSK) only
    /// with `tp-pi2BPSK`; otherwise `q = 2` (QPSK at half the rate, same TBS).
    fn pusch_mcs_of(&self, table: McsTable, i: u8, pi2_bpsk: bool) -> Mcs {
        let m = self.mcs(table, i);
        if m.qm == 1 && !pi2_bpsk {
            Mcs { index: i, qm: 2, r_x1024: m.r_x1024.map(|r| r / 2) }
        } else {
            m
        }
    }

    fn pdsch_tbs(&self, row: &TdraRow, n_prb: usize, mcs: &Mcs, cdm: u8) -> u32 {
        let Some(r) = mcs.r_x1024 else { return 0 };
        let dm = dmrs::pdsch_dmrs_symbols(
            if row.mapping_type_a { MappingType::TypeA } else { MappingType::TypeB },
            self.dmrs_typea_pos,
            self.dl_dmrs_add_pos,
            row.start_symbol as usize,
            row.n_symbols as usize,
        )
        .map(|v| v.len())
        .unwrap_or(1);
        let n_re = pdsch_params::n_re_per_prb(row.n_symbols as usize, pdsch_params::dmrs_re_per_prb(dm, cdm), 0);
        pdsch_params::tbs(n_re, n_prb, mcs.qm, r, 1) as u32
    }

    fn pusch_tbs(&self, row: &TdraRow, n_prb: usize, mcs: &Mcs, cdm: u8, add_pos: u8) -> u32 {
        let Some(r) = mcs.r_x1024 else { return 0 };
        let dm = dmrs::pusch_dmrs_symbols(
            if row.mapping_type_a { MappingType::TypeA } else { MappingType::TypeB },
            self.dmrs_typea_pos,
            add_pos,
            row.start_symbol as usize,
            row.n_symbols as usize,
        )
        .map(|v| v.len())
        .unwrap_or(1);
        let n_re = pdsch_params::n_re_per_prb(row.n_symbols as usize, pdsch_params::dmrs_re_per_prb(dm, cdm), 0);
        pdsch_params::tbs(n_re, n_prb, mcs.qm, r, 1) as u32
    }

    /// Resolve a DCI 1_0 payload decoded in a CSS (`in_css`) or USS.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_1_0(&self, bits: &[u8], rnti: Rnti, kind: RntiKind, in_css: bool, slot: SlotPoint, cce0: usize, n_cce: usize) -> Option<Dci> {
        let size = if in_css { &self.sizes.f1_0_css } else { self.sizes.f1_0_uss.as_ref().unwrap_or(&self.sizes.f1_0_css) };
        let rk = match kind {
            RntiKind::Si => dci::RntiKind::Si,
            RntiKind::Ra => dci::RntiKind::Ra,
            RntiKind::P => dci::RntiKind::P,
            RntiKind::Tc => dci::RntiKind::Tc,
            RntiKind::C => dci::RntiKind::C,
        };
        let d = dci::parse_dci_1_0(bits, rk, size).ok()?;
        if d.pdcch_order.is_some() {
            return Some(Dci::Other { format: "1_0 pdcch-order" });
        }
        // P-RNTI: only a DCI whose short-messages indicator says "scheduling
        // information for paging present" (bit 0) schedules a PDSCH.
        if matches!(kind, RntiKind::P) && d.short_messages_indicator.is_none_or(|v| v & 1 == 0) {
            return Some(Dci::Other { format: "1_0 paging (short message only)" });
        }
        // Frequency domain: in a CSS with CORESET0 the RIV spans CORESET0 and is
        // numbered from its lowest RB; else the active BWP.
        let (rb_start, n_rb) = if let Some(n) = self.coreset0_rb.filter(|_| in_css) {
            let (s, l) = dci::riv_decode(d.fdra, n)?;
            // A dedicated BWP starting above CORESET#0 cannot carry this PDSCH.
            ((self.coreset0_first_crb + s).checked_sub(self.dl_bwp_start)?, l)
        } else {
            dci::riv_decode(d.fdra, self.dl_bwp_rb)?
        };
        let row = self.pdsch_tdra_row(d.tdra as usize, false, if kind == RntiKind::P { RntiKind::Si } else { kind })?;
        let mcs = self.mcs(McsTable::Qam64, d.mcs);
        // DCI 1_0: 2 CDM groups without data (1 for a 2-symbol allocation).
        let cdm = if row.n_symbols <= 2 { 1 } else { 2 };
        // RA / paging: TB scaling (TS 38.214 Table 5.1.3.2-2) applies to N_info.
        let scale = match d.tb_scaling { Some(1) => 0.5, Some(2) => 0.25, _ => 1.0 };
        let tbs = if scale < 1.0 {
            let mut m = mcs;
            m.r_x1024 = m.r_x1024.map(|r| (f32::from(r) * scale) as u16);
            self.pdsch_tbs(&row, n_rb, &m, cdm)
        } else {
            self.pdsch_tbs(&row, n_rb, &mcs, cdm)
        };
        let pdsch_slot = slot.add(row.k as u64);
        if !self.direction_ok(pdsch_slot, &row, false) {
            return None;
        }
        let (ack_slot, harq_id, ndi, rv, dai, pri, tpc, k1) = match kind {
            RntiKind::Tc | RntiKind::C => {
                let k1 = d.k1_idx.map_or(4, |i| i + 1); // DCI 1_0: field value + 1
                (Some(pdsch_slot.add(k1 as u64)), d.harq_id.unwrap_or(0), u8::from(d.ndi.unwrap_or(false)), d.rv.unwrap_or(0), d.dai.unwrap_or(0), d.pri.unwrap_or(0), d.tpc.unwrap_or(1), k1)
            }
            _ => (None, 0, 0, d.rv.unwrap_or(0), 0, 0, 1, 0),
        };
        let _ = k1;
        let r_pucch = ((2 * cce0) / n_cce.max(1) + 2 * pri as usize) as u8;
        Some(Dci::Dl(DlGrant {
            rnti,
            rnti_kind: kind,
            pdsch_slot,
            prb_start: rb_start as u16,
            n_prb: n_rb as u16,
            time: TimeAlloc { mapping_type_a: row.mapping_type_a, start_symbol: row.start_symbol, n_symbols: row.n_symbols },
            mcs,
            tbs_bits: tbs,
            harq_id,
            ndi,
            rv,
            ack_slot,
            dai,
            pri,
            tpc,
            cdm_groups_wo_data: cdm,
            dmrs_add_pos: 2,
            vrb_to_prb_interleaved: d.vrb_to_prb_interleaved,
            r_pucch_common: r_pucch,
        }))
    }

    pub fn resolve_0_0(&self, bits: &[u8], rnti: Rnti, kind: RntiKind, in_css: bool, slot: SlotPoint) -> Option<Dci> {
        let size = if in_css { &self.sizes.f0_0_css } else { self.sizes.f0_0_uss.as_ref().unwrap_or(&self.sizes.f0_0_css) };
        let rk = if kind == RntiKind::Tc { dci::RntiKind::Tc } else { dci::RntiKind::C };
        let d = dci::parse_dci_0_0(bits, rk, size, self.ul_bwp_rb).ok()?;
        let (rb_start, n_rb) = dci::riv_decode(d.fdra, self.ul_bwp_rb)?;
        let row = self.pusch_tdra_row(d.tdra as usize, false)?;
        let table = if self.msg3_tp.is_some() { McsTable::Qam64TransformPrecoding } else { McsTable::Qam64 };
        let mcs = self.pusch_mcs_of(table, d.mcs, false);
        // Common PUSCH DMRS: pos2, 2 CDM groups (1 for ≤2 symbols).
        let cdm = if row.n_symbols <= 2 { 1 } else { 2 };
        let tbs = self.pusch_tbs(&row, n_rb, &mcs, cdm, 2);
        if !self.direction_ok(slot.add(row.k as u64), &row, true) {
            return None;
        }
        Some(Dci::Ul(UlGrant {
            rnti,
            rnti_kind: kind,
            pusch_slot: slot.add(row.k as u64),
            prb_start: rb_start as u16,
            n_prb: n_rb as u16,
            time: TimeAlloc { mapping_type_a: row.mapping_type_a, start_symbol: row.start_symbol, n_symbols: row.n_symbols },
            mcs,
            tbs_bits: tbs,
            harq_id: d.harq_id.unwrap_or(0),
            ndi: u8::from(d.ndi.unwrap_or(false)),
            rv: d.rv,
            dai: None,
            tpc: d.tpc,
            csi_request: 0,
            ul_sch: true,
            cdm_groups_wo_data: cdm,
            dmrs_add_pos: 2,
            freq_hopping: d.frequency_hopping,
            transform_precoding: self.msg3_tp,
        }))
    }

    pub fn resolve_1_1(&self, bits: &[u8], rnti: Rnti, slot: SlotPoint, cce0: usize, n_cce: usize) -> Option<Dci> {
        let size = self.sizes.f1_1.as_ref()?;
        let d = dci::parse_dci_1_1(bits, size).ok()?;
        if let Some(b) = d.bwp_indicator {
            let id = Self::bwp_id_of(b, self.nof_dl_bwp_rrc);
            if id != self.dl_bwp_id {
                return Some(Dci::BwpSwitch { dl_bwp: Some(id), ul_bwp: None });
            }
        }
        let (rb_start, n_rb) = dci::riv_decode(d.fdra, self.dl_bwp_rb)?;
        let row = self.pdsch_tdra_row(d.tdra as usize, true, RntiKind::C)?;
        let mcs = self.mcs(self.pdsch_mcs, d.mcs);
        let ports = dmrs::dci_1_1_antenna_ports_type1_len1(d.antenna_ports)?;
        let cdm = ports.nof_cdm_groups_without_data;
        let tbs = self.pdsch_tbs(&row, n_rb, &mcs, cdm);
        let pdsch_slot = slot.add(row.k as u64);
        if !self.direction_ok(pdsch_slot, &row, false) {
            return None;
        }
        let k1 = d.k1_idx.and_then(|i| self.k1_list.get(i as usize).copied()).unwrap_or(*self.k1_list.first().unwrap_or(&4));
        let r_pucch = ((2 * cce0) / n_cce.max(1) + 2 * d.pri as usize) as u8;
        Some(Dci::Dl(DlGrant {
            rnti,
            rnti_kind: RntiKind::C,
            pdsch_slot,
            prb_start: rb_start as u16,
            n_prb: n_rb as u16,
            time: TimeAlloc { mapping_type_a: row.mapping_type_a, start_symbol: row.start_symbol, n_symbols: row.n_symbols },
            mcs,
            tbs_bits: tbs,
            harq_id: d.harq_id,
            ndi: u8::from(d.ndi),
            rv: d.rv,
            ack_slot: Some(pdsch_slot.add(k1 as u64)),
            dai: d.dai.unwrap_or(0),
            pri: d.pri,
            tpc: d.tpc,
            cdm_groups_wo_data: cdm,
            dmrs_add_pos: self.dl_dmrs_add_pos,
            vrb_to_prb_interleaved: d.vrb_to_prb_interleaved.unwrap_or(false),
            r_pucch_common: r_pucch,
        }))
    }

    /// The Msg3 PUSCH grant for a RAR UL grant (TS 38.213 §8.2 / §8.3): the
    /// PUSCH is `k2 + Δ` slots after the RAR (Δ from TS 38.214 Table
    /// 6.1.2.1.1-5), on the common PUSCH TDRA row `time_resource`, with the
    /// RIV in the ⌈log2(N(N+1)/2)⌉ LSBs of the 14-bit FDRA (N_BWP ≤ 180; for a
    /// larger BWP the 14 bits are the RIV, the hopping bits being ignored), MCS
    /// from Table 6.1.4.1-1 or 5.1.3.1-1 per `msg3-transformPrecoder`, HARQ
    /// process 0, NDI 0.
    pub fn resolve_rar_grant(&self, rar_slot: SlotPoint, tc_rnti: Rnti, g: &RarUlGrant) -> Option<UlGrant> {
        let n = self.ul_bwp_rb;
        let riv = if n <= 180 {
            let m = n * (n + 1) / 2;
            let bits = (usize::BITS - (m.max(2) - 1).leading_zeros()) as usize;
            u32::from(g.fdra) & ((1u32 << bits.min(14)) - 1)
        } else {
            u32::from(g.fdra)
        };
        let (rb_start, n_rb) = dci::riv_decode(riv, n)?;
        let row = self.pusch_tdra_row(g.time_resource as usize, false)?;
        let table = if self.msg3_tp.is_some() { McsTable::Qam64TransformPrecoding } else { McsTable::Qam64 };
        let mcs = self.pusch_mcs_of(table, g.mcs, false);
        let cdm = if row.n_symbols <= 2 { 1 } else { 2 };
        let tbs = self.pusch_tbs(&row, n_rb, &mcs, cdm, 2);
        let pusch_slot = rar_slot.add(row.k as u64 + self.msg3_delta as u64);
        if !self.direction_ok(pusch_slot, &row, true) {
            return None;
        }
        Some(UlGrant {
            rnti: tc_rnti,
            rnti_kind: RntiKind::Tc,
            pusch_slot,
            prb_start: rb_start as u16,
            n_prb: n_rb as u16,
            time: TimeAlloc { mapping_type_a: row.mapping_type_a, start_symbol: row.start_symbol, n_symbols: row.n_symbols },
            mcs,
            tbs_bits: tbs,
            harq_id: 0,
            ndi: 0,
            rv: 0,
            dai: None,
            tpc: g.tpc,
            csi_request: u8::from(g.csi_request),
            ul_sch: true,
            cdm_groups_wo_data: cdm,
            dmrs_add_pos: 2,
            freq_hopping: g.freq_hopping,
            transform_precoding: self.msg3_tp,
        })
    }

    pub fn resolve_0_1(&self, bits: &[u8], rnti: Rnti, slot: SlotPoint) -> Option<Dci> {
        let size = self.sizes.f0_1.as_ref()?;
        let d = dci::parse_dci_0_1(bits, size).ok()?;
        if let Some(b) = d.bwp_indicator {
            let id = Self::bwp_id_of(b, self.nof_ul_bwp_rrc);
            if id != self.ul_bwp_id {
                return Some(Dci::BwpSwitch { dl_bwp: None, ul_bwp: Some(id) });
            }
        }
        let (rb_start, n_rb) = dci::riv_decode(d.fdra, self.ul_bwp_rb)?;
        let row = self.pusch_tdra_row(d.tdra as usize, true)?;
        let mcs = self.pusch_mcs_of(self.pusch_mcs, d.mcs, self.ded_tp.is_some_and(|t| t.pi2_bpsk));
        // Antenna ports: Table 7.3.1.1.2-6 with transform precoding (always 2
        // CDM groups without data, port = value), Table 7.3.1.1.2-8 otherwise.
        let cdm = if self.ded_tp.is_some() { 2 } else { dmrs::dci_0_1_antenna_ports_type1_len1_rank1(d.antenna_ports).map_or(2, |p| p.nof_cdm_groups_without_data) };
        let tbs = self.pusch_tbs(&row, n_rb, &mcs, cdm, self.ul_dmrs_add_pos);
        if !self.direction_ok(slot.add(row.k as u64), &row, true) {
            return None;
        }
        Some(Dci::Ul(UlGrant {
            rnti,
            rnti_kind: RntiKind::C,
            pusch_slot: slot.add(row.k as u64),
            prb_start: rb_start as u16,
            n_prb: n_rb as u16,
            time: TimeAlloc { mapping_type_a: row.mapping_type_a, start_symbol: row.start_symbol, n_symbols: row.n_symbols },
            mcs,
            tbs_bits: tbs,
            harq_id: d.harq_id,
            ndi: u8::from(d.ndi),
            rv: d.rv,
            dai: Some(d.first_dai),
            tpc: d.tpc,
            csi_request: d.csi_request.unwrap_or(0),
            ul_sch: d.ul_sch,
            cdm_groups_wo_data: cdm,
            dmrs_add_pos: self.ul_dmrs_add_pos,
            freq_hopping: d.frequency_hopping.unwrap_or(false),
            transform_precoding: self.ded_tp,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)] // DCI payload builders mirror the field lists
mod tests {
    use super::*;
    use crate::config::TdraRow;
    use ferrite_common::{DuplexMode, Numerology};
    use ferrite_phy::coding::dci::riv_encode;

    /// MSB-first bit packer, the inverse of the parsers' `BitReader`.
    struct Bits(Vec<u8>);
    impl Bits {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn put(&mut self, v: u32, n: usize) -> &mut Self {
            for i in (0..n).rev() {
                self.0.push(((v >> i) & 1) as u8);
            }
            self
        }
        fn pad_to(&mut self, total: usize) -> Vec<u8> {
            assert!(self.0.len() <= total, "payload {} bits exceeds the format size {total}", self.0.len());
            self.0.resize(total, 0);
            self.0.clone()
        }
    }

    const MU: Numerology = Numerology::KHZ30;
    const N_RB: usize = 24;
    const PCI: u16 = 1;

    /// The post-MIB configuration of a 24-RB CORESET#0 cell at 30 kHz.
    fn cfg() -> PhyConfig {
        PhyConfig::initial(DuplexMode::Tdd, MU, MU, PCI, N_RB, 2, 2, 0, 0)
    }

    fn slot(n: u64) -> SlotPoint {
        SlotPoint::from_index(MU, n)
    }

    fn dl(d: Option<Dci>) -> DlGrant {
        match d {
            Some(Dci::Dl(g)) => g,
            other => panic!("expected a DL grant, got {other:?}"),
        }
    }

    fn ul(d: Option<Dci>) -> UlGrant {
        match d {
            Some(Dci::Ul(g)) => g,
            other => panic!("expected an UL grant, got {other:?}"),
        }
    }

    /// DCI 1_0 payload for the C-/TC-RNTI (§7.3.1.2.1) in the CSS size.
    fn dci_1_0_c(r: &DciResolver, riv: u32, tdra: u32, mcs: u32, ndi: u32, rv: u32, harq: u32, dai: u32, tpc: u32, pri: u32, k1_idx: u32) -> Vec<u8> {
        let s = &r.sizes.f1_0_css;
        Bits::new().put(1, 1).put(riv, s.fdra).put(tdra, 4).put(0, 1).put(mcs, 5).put(ndi, 1).put(rv, 2).put(harq, 4).put(dai, 2).put(tpc, 2).put(pri, 3).put(k1_idx, 3).pad_to(s.total)
    }

    #[test]
    fn initial_sizes_match_the_coreset0_width() {
        let r = DciResolver::new(&cfg(), false);
        // RIV over 24 RBs: ⌈log2(300)⌉ = 9 bits; 1_0 = 28 + 9 = 37; 0_0 padded to it.
        assert_eq!(r.sizes.f1_0_css.fdra, 9);
        assert_eq!(r.sizes.f1_0_css.total, 37);
        assert_eq!(r.sizes.f0_0_css.total, 37);
        assert!(r.sizes.f1_1.is_none(), "no 1_1 before the dedicated configuration");
        assert_eq!(r.msg3_delta, 3, "Δ for 30 kHz (Table 6.1.2.1.1-5)");
    }

    #[test]
    fn si_dci_1_0_schedules_pdsch_over_coreset0() {
        let r = DciResolver::new(&cfg(), false);
        let s = &r.sizes.f1_0_css;
        // fdra | tdra 0 | vrb 0 | mcs 5 | rv 0 | si 0 | 15 reserved
        let bits = Bits::new().put(riv_encode(0, N_RB, N_RB), s.fdra).put(0, 4).put(0, 1).put(5, 5).put(0, 2).put(0, 1).pad_to(s.total);
        let g = dl(r.resolve_1_0(&bits, Rnti(0xffff), RntiKind::Si, true, slot(10), 0, 4));
        assert_eq!((g.prb_start, g.n_prb), (0, 24));
        // Default table A row 1 with dmrs-TypeA-Position 2: k0 = 0, S = 2, L = 12.
        assert_eq!(g.pdsch_slot, slot(10));
        assert_eq!((g.time.start_symbol, g.time.n_symbols, g.time.mapping_type_a), (2, 12, true));
        assert_eq!(g.ack_slot, None, "SI-RNTI: no HARQ-ACK");
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (2, Some(379)));
        assert_eq!(g.cdm_groups_wo_data, 2);
        // Fallback DCI: dmrs-AdditionalPosition pos2 (§5.1.6.2) → 3 DM-RS symbols
        // for S + L = 14, 2 CDM groups; TBS from the §5.1.3.2 procedure.
        assert_eq!(g.dmrs_add_pos, 2);
        let dm = dmrs::pdsch_dmrs_symbols(MappingType::TypeA, 2, 2, 2, 12).unwrap().len();
        assert_eq!(dm, 3);
        let n_re = pdsch_params::n_re_per_prb(12, pdsch_params::dmrs_re_per_prb(dm, 2), 0);
        assert_eq!(g.tbs_bits as usize, pdsch_params::tbs(n_re, 24, 2, 379, 1));
        assert!(g.tbs_bits > 0);
    }

    #[test]
    fn c_rnti_dci_1_0_carries_harq_fields_and_k1() {
        let r = DciResolver::new(&cfg(), false);
        let bits = dci_1_0_c(&r, riv_encode(2, 6, N_RB), 0, 10, 1, 2, 5, 1, 3, 2, 3);
        let g = dl(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(20), 4, 8));
        assert_eq!((g.prb_start, g.n_prb), (2, 6));
        assert_eq!((g.harq_id, g.ndi, g.rv, g.dai, g.tpc, g.pri), (5, 1, 2, 1, 3, 2));
        assert_eq!(g.mcs.qm, 4, "table 1 index 10 is 16-QAM");
        // k1 = field + 1 for the fallback DCI; PUCCH at pdsch_slot + k1.
        assert_eq!(g.ack_slot, Some(slot(20 + 4)));
        // r_PUCCH = ⌊2·n_CCE,0 / N_CCE⌋ + 2·Δ_PRI (§9.2.1).
        assert_eq!(g.r_pucch_common, (2 * 4) / 8 + 2 * 2);
        assert_eq!(g.rnti_kind, RntiKind::C);
    }

    #[test]
    fn tc_rnti_dci_1_0_has_no_dai() {
        let r = DciResolver::new(&cfg(), false);
        let bits = dci_1_0_c(&r, riv_encode(0, 4, N_RB), 0, 3, 0, 0, 0, 3, 1, 0, 0);
        let g = dl(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::Tc, true, slot(5), 0, 4));
        assert_eq!(g.dai, 0, "the 2 DAI bits are reserved for the TC-RNTI");
        assert_eq!(g.ack_slot, Some(slot(5 + 1)));
    }

    #[test]
    fn pdcch_order_is_not_a_grant() {
        let r = DciResolver::new(&cfg(), false);
        let s = &r.sizes.f1_0_css;
        let all_ones = (1u32 << s.fdra) - 1;
        // ident | fdra = all ones | preamble 6 | ul/sul 1 | ssb 6 | mask 4 | 10 reserved
        let bits = Bits::new().put(1, 1).put(all_ones, s.fdra).put(7, 6).put(0, 1).put(0, 6).put(0, 4).pad_to(s.total);
        assert!(matches!(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(0), 0, 4), Some(Dci::Other { format }) if format.contains("pdcch-order")));
    }

    #[test]
    fn paging_dci_schedules_only_with_scheduling_information() {
        let r = DciResolver::new(&cfg(), false);
        let s = &r.sizes.f1_0_css;
        let paging = |indicator: u32, tb_scaling: u32| -> Vec<u8> {
            // short-messages indicator 2 | short messages 8 | fdra | tdra 4 | vrb 1 | mcs 5 | tb scaling 2 | 6 reserved
            Bits::new().put(indicator, 2).put(0, 8).put(riv_encode(0, N_RB, N_RB), s.fdra).put(0, 4).put(0, 1).put(4, 5).put(tb_scaling, 2).pad_to(s.total)
        };
        // 2 = short messages only: nothing to receive.
        assert!(matches!(r.resolve_1_0(&paging(2, 0), Rnti(0xfffe), RntiKind::P, true, slot(0), 0, 4), Some(Dci::Other { .. })));
        let full = dl(r.resolve_1_0(&paging(1, 0), Rnti(0xfffe), RntiKind::P, true, slot(0), 0, 4));
        assert_eq!(full.rnti_kind, RntiKind::P);
        assert_eq!(full.ack_slot, None);
        // TB scaling 0.5 / 0.25 (Table 5.1.3.2-2) shrinks the TBS.
        let half = dl(r.resolve_1_0(&paging(3, 1), Rnti(0xfffe), RntiKind::P, true, slot(0), 0, 4));
        let quarter = dl(r.resolve_1_0(&paging(3, 2), Rnti(0xfffe), RntiKind::P, true, slot(0), 0, 4));
        assert!(full.tbs_bits > half.tbs_bits && half.tbs_bits > quarter.tbs_bits, "{} {} {}", full.tbs_bits, half.tbs_bits, quarter.tbs_bits);
    }

    #[test]
    fn css_grant_is_numbered_from_coreset0_and_rejected_below_a_higher_bwp() {
        // Dedicated DL BWP starting 10 CRBs above CORESET#0 (which starts at CRB 0).
        let mut c = cfg();
        c.dl_bwp.start_crb = 10;
        let r = DciResolver::new(&c, true);
        let s = &r.sizes.f1_0_css;
        let si = |riv: u32| Bits::new().put(riv, s.fdra).put(0, 4).put(0, 1).put(5, 5).put(0, 2).put(0, 1).pad_to(s.total);
        // CORESET#0 RBs 12..16 → BWP RBs 2..6.
        let g = dl(r.resolve_1_0(&si(riv_encode(12, 4, N_RB)), Rnti(0xffff), RntiKind::Si, true, slot(0), 0, 4));
        assert_eq!((g.prb_start, g.n_prb), (2, 4));
        // A PDSCH starting below the BWP cannot be received: no grant rather than a wrapped index.
        assert!(r.resolve_1_0(&si(riv_encode(0, 24, N_RB)), Rnti(0xffff), RntiKind::Si, true, slot(0), 0, 4).is_none());
    }

    /// DCI 0_0 payload (§7.3.1.1.1) in the CSS size.
    fn dci_0_0(r: &DciResolver, riv: u32, tdra: u32, mcs: u32, ndi: u32, rv: u32, harq: u32, tpc: u32) -> Vec<u8> {
        let s = &r.sizes.f0_0_css;
        Bits::new().put(0, 1).put(riv, s.fdra).put(tdra, 4).put(0, 1).put(mcs, 5).put(ndi, 1).put(rv, 2).put(harq, 4).put(tpc, 2).pad_to(s.total)
    }

    #[test]
    fn dci_0_0_uses_the_common_pusch_defaults() {
        let r = DciResolver::new(&cfg(), false);
        let bits = dci_0_0(&r, riv_encode(4, 3, N_RB), 1, 2, 1, 0, 3, 1);
        // TC-RNTI: NDI and HARQ id are reserved.
        let g = ul(r.resolve_0_0(&bits, Rnti(0x4601), RntiKind::Tc, true, slot(30)));
        assert_eq!((g.prb_start, g.n_prb), (4, 3));
        assert_eq!((g.harq_id, g.ndi, g.rv, g.tpc), (0, 0, 0, 1));
        // Default table (Table 6.1.2.1.1-2) row 2 at 30 kHz: k2 = j = 1, S = 0, L = 12.
        assert_eq!(g.pusch_slot, slot(31));
        assert_eq!((g.time.start_symbol, g.time.n_symbols), (0, 12));
        assert_eq!(g.transform_precoding, None);
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (2, Some(193)), "table 1 index 2");
        assert_eq!((g.cdm_groups_wo_data, g.dmrs_add_pos), (2, 2));
        assert!(g.ul_sch && g.tbs_bits > 0);
        // C-RNTI: the same fields are meaningful.
        let g = ul(r.resolve_0_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(30)));
        assert_eq!((g.harq_id, g.ndi), (3, 1));
    }

    #[test]
    fn msg3_transform_precoding_selects_the_tp_mcs_table() {
        let mut c = cfg();
        c.pusch.msg3_transform_precoder = true;
        c.pusch.msg3_group_hopping = true;
        let r = DciResolver::new(&c, false);
        // Index 1 of Table 6.1.4.1-1 is a q-row (π/2-BPSK, R = 314/1024): without
        // tp-pi2BPSK it is sent as QPSK at half the rate (same TBS).
        let g = ul(r.resolve_0_0(&dci_0_0(&r, riv_encode(0, 6, N_RB), 0, 1, 0, 0, 0, 0), Rnti(0x4601), RntiKind::Tc, true, slot(0)));
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (2, Some(157)));
        assert_eq!(g.transform_precoding, Some(TransformPrecoding { n_id_rs: PCI, group_hopping: true, sequence_hopping: false, pi2_bpsk: false }));
        // A plain QPSK row stays as it is.
        let g = ul(r.resolve_0_0(&dci_0_0(&r, riv_encode(0, 6, N_RB), 0, 4, 0, 0, 0, 0), Rnti(0x4601), RntiKind::Tc, true, slot(0)));
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (2, Some(308)));
    }

    #[test]
    fn invalid_riv_is_rejected() {
        let r = DciResolver::new(&cfg(), false);
        // 24·25/2 = 300 valid RIVs; 300.. are not.
        assert!(r.resolve_0_0(&dci_0_0(&r, 300, 0, 0, 0, 0, 0, 0), Rnti(0x4601), RntiKind::C, true, slot(0)).is_none());
        assert!(r.resolve_rar_grant(slot(0), Rnti(0x4601), &RarUlGrant { freq_hopping: false, fdra: 511, time_resource: 0, mcs: 0, tpc: 0, csi_request: false }).is_none());
    }

    #[test]
    fn rar_grant_resolves_msg3_at_k2_plus_delta() {
        let r = DciResolver::new(&cfg(), false);
        let riv = riv_encode(4, 3, N_RB) as u16;
        let grant = RarUlGrant { freq_hopping: false, fdra: riv, time_resource: 0, mcs: 0, tpc: 7, csi_request: false };
        let g = r.resolve_rar_grant(slot(100), Rnti(0x4601), &grant).expect("grant");
        assert_eq!((g.rnti, g.rnti_kind), (Rnti(0x4601), RntiKind::Tc));
        assert_eq!((g.prb_start, g.n_prb), (4, 3));
        // Table 6.1.2.1.1-2 row 1 at 30 kHz: k2 = 1, S = 0, L = 14; Δ = 3.
        assert_eq!(g.pusch_slot, slot(100 + 1 + 3));
        assert_eq!((g.time.start_symbol, g.time.n_symbols), (0, 14));
        assert_eq!((g.harq_id, g.ndi, g.rv, g.tpc), (0, 0, 0, 7));
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (2, Some(120)));
        assert!(g.tbs_bits > 0);
        // N_BWP ≤ 180: only the ⌈log2(N(N+1)/2)⌉ LSBs are the RIV; the hopping
        // bits above them must not change the allocation.
        let with_hop_bits = RarUlGrant { fdra: riv | 0x3e00, ..grant };
        let g2 = r.resolve_rar_grant(slot(100), Rnti(0x4601), &with_hop_bits).expect("grant");
        assert_eq!((g2.prb_start, g2.n_prb, g2.tbs_bits), (g.prb_start, g.n_prb, g.tbs_bits));
    }

    #[test]
    fn rar_grant_uses_the_sib1_pusch_tdra_list() {
        let mut c = cfg();
        c.pusch_tdra_common = vec![TdraRow { k: 4, mapping_type_a: true, start_symbol: 0, n_symbols: 14 }, TdraRow { k: 5, mapping_type_a: false, start_symbol: 2, n_symbols: 10 }];
        let r = DciResolver::new(&c, false);
        let g = r.resolve_rar_grant(slot(0), Rnti(1), &RarUlGrant { freq_hopping: false, fdra: riv_encode(0, 2, N_RB) as u16, time_resource: 1, mcs: 0, tpc: 0, csi_request: false }).expect("grant");
        assert_eq!(g.pusch_slot, slot(5 + 3));
        assert_eq!((g.time.mapping_type_a, g.time.start_symbol, g.time.n_symbols), (false, 2, 10));
        // A row beyond the list is not a grant.
        assert!(r.resolve_rar_grant(slot(0), Rnti(1), &RarUlGrant { freq_hopping: false, fdra: 0, time_resource: 2, mcs: 0, tpc: 0, csi_request: false }).is_none() || r.pusch_tdra_row(2, false).is_some());
    }

    fn dedicated_cfg() -> PhyConfig {
        let mut c = cfg();
        c.pucch.k1_list = vec![4, 5, 6, 7];
        c.pdsch.mcs_table = McsTableSel::Qam256;
        c.pdsch.tdra = vec![TdraRow { k: 0, mapping_type_a: true, start_symbol: 1, n_symbols: 13 }];
        c.pdsch.dmrs_type_a.additional_position = 1;
        c.pusch.tdra = vec![TdraRow { k: 2, mapping_type_a: true, start_symbol: 0, n_symbols: 14 }, TdraRow { k: 3, mapping_type_a: true, start_symbol: 0, n_symbols: 14 }];
        c.pusch.dmrs_type_a.additional_position = 1;
        c
    }

    /// DCI 1_1 payload with the resolver's field widths.
    fn dci_1_1(r: &DciResolver, riv: u32, tdra: u32, mcs: u32, ndi: u32, rv: u32, harq: u32, dai: u32, pri: u32, k1_idx: u32, ports: u32) -> Vec<u8> {
        dci_1_1_bwp(r, 0, riv, tdra, mcs, ndi, rv, harq, dai, pri, k1_idx, ports)
    }

    fn dci_1_1_bwp(r: &DciResolver, bwp: u32, riv: u32, tdra: u32, mcs: u32, ndi: u32, rv: u32, harq: u32, dai: u32, pri: u32, k1_idx: u32, ports: u32) -> Vec<u8> {
        let s = r.sizes.f1_1.as_ref().expect("1_1 size");
        let mut b = Bits::new();
        b.put(1, 1).put(0, s.carrier_indicator).put(bwp, s.bwp_indicator).put(riv, s.fdra).put(tdra, s.tdra).put(0, s.vrb_to_prb).put(0, s.prb_bundling).put(0, s.rate_matching).put(0, s.zp_csi_rs_trigger);
        b.put(mcs, 5).put(ndi, 1).put(rv, 2);
        if s.tb2 > 0 {
            b.put(0, 8);
        }
        b.put(harq, s.harq_id).put(dai, s.dai).put(0, 2).put(pri, 3).put(k1_idx, s.k1).put(ports, s.antenna_ports).put(0, s.tci).put(0, s.srs_request).put(0, s.cbgti).put(0, s.cbgfi).put(0, 1);
        b.pad_to(s.total)
    }

    #[test]
    fn dci_1_1_uses_the_dedicated_tdra_k1_list_and_mcs_table() {
        let r = DciResolver::new(&dedicated_cfg(), true);
        let s = r.sizes.f1_1.as_ref().expect("1_1 size");
        assert_eq!((s.tdra, s.k1, s.antenna_ports, s.dai), (0, 2, 4, 2), "one TDRA row, 4 k1 values, type-1 single-symbol ports, dynamic codebook");
        // Antenna-port value 3 (Table 7.3.1.2.2-1): port 1000 with 2 CDM groups without data.
        let bits = dci_1_1(&r, riv_encode(0, 24, N_RB), 0, 20, 1, 0, 7, 2, 1, 2, 3);
        let g = dl(r.resolve_1_1(&bits, Rnti(0x4601), slot(40), 8, 16));
        assert_eq!((g.time.start_symbol, g.time.n_symbols), (1, 13));
        assert_eq!(g.pdsch_slot, slot(40));
        assert_eq!(g.ack_slot, Some(slot(40 + 6)), "k1 = k1_list[2]");
        assert_eq!(g.mcs.qm, 8, "256-QAM table index 20");
        assert_eq!((g.harq_id, g.ndi, g.dai, g.pri), (7, 1, 2, 1));
        assert_eq!((g.cdm_groups_wo_data, g.dmrs_add_pos), (2, 1));
        assert_eq!(g.r_pucch_common, (2 * 8) / 16 + 2);
        // Value 0: 1 CDM group without data → more REs → larger TBS.
        let g1 = dl(r.resolve_1_1(&dci_1_1(&r, riv_encode(0, 24, N_RB), 0, 20, 1, 0, 7, 2, 1, 2, 0), Rnti(0x4601), slot(40), 8, 16));
        assert_eq!(g1.cdm_groups_wo_data, 1);
        assert!(g1.tbs_bits > g.tbs_bits);
    }

    /// DCI 0_1 payload with the resolver's field widths.
    fn dci_0_1(r: &DciResolver, riv: u32, tdra: u32, mcs: u32, ndi: u32, rv: u32, harq: u32, dai: u32, ports: u32, ul_sch: u32) -> Vec<u8> {
        let s = r.sizes.f0_1.as_ref().expect("0_1 size");
        let mut b = Bits::new();
        b.put(0, 1).put(0, s.carrier_indicator).put(0, s.ul_sul).put(0, s.bwp_indicator).put(riv, s.fdra).put(tdra, s.tdra).put(0, s.frequency_hopping_flag);
        b.put(mcs, 5).put(ndi, 1).put(rv, 2).put(harq, s.harq_id).put(dai, s.first_dai).put(0, s.second_dai).put(0, 2);
        b.put(0, s.srs_resource_indicator).put(0, s.precoding_info).put(ports, s.antenna_ports).put(0, s.srs_request).put(0, s.csi_request).put(0, s.cbgti).put(0, s.ptrs_dmrs_association).put(0, s.beta_offset).put(0, s.dmrs_seq_init).put(ul_sch, 1);
        b.pad_to(s.total)
    }

    #[test]
    fn dci_0_1_antenna_ports_and_transform_precoding() {
        // Without transform precoding: Table 7.3.1.1.2-8, value 0 = 1 CDM group.
        let r = DciResolver::new(&dedicated_cfg(), true);
        let s = r.sizes.f0_1.as_ref().expect("0_1 size");
        assert_eq!(s.tdra, 1, "two dedicated TDRA rows");
        let g = ul(r.resolve_0_1(&dci_0_1(&r, riv_encode(2, 8, N_RB), 1, 12, 1, 0, 9, 1, 0, 1), Rnti(0x4601), slot(50)));
        assert_eq!((g.prb_start, g.n_prb), (2, 8));
        assert_eq!(g.pusch_slot, slot(50 + 3), "row 2: k2 = 3");
        assert_eq!((g.harq_id, g.ndi, g.dai, g.ul_sch), (9, 1, Some(1), true));
        assert_eq!(g.mcs.qm, 4);
        assert_eq!((g.cdm_groups_wo_data, g.dmrs_add_pos), (1, 1));
        assert_eq!(g.transform_precoding, None);
        // CSI-only PUSCH: no UL-SCH.
        let g = ul(r.resolve_0_1(&dci_0_1(&r, riv_encode(2, 8, N_RB), 1, 12, 1, 0, 9, 1, 0, 0), Rnti(0x4601), slot(50)));
        assert!(!g.ul_sch);
        // With transform precoding: Table 7.3.1.1.2-6 — always 2 CDM groups,
        // the dedicated DM-RS identity, π/2-BPSK off unless tp-pi2BPSK.
        let mut c = dedicated_cfg();
        c.pusch.transform_precoder = true;
        c.pusch.tp_dmrs.n_pusch_identity = Some(777);
        let r = DciResolver::new(&c, true);
        let g = ul(r.resolve_0_1(&dci_0_1(&r, riv_encode(2, 8, N_RB), 1, 12, 1, 0, 9, 1, 0, 1), Rnti(0x4601), slot(50)));
        assert_eq!(g.cdm_groups_wo_data, 2);
        assert_eq!(g.transform_precoding, Some(TransformPrecoding { n_id_rs: 777, group_hopping: false, sequence_hopping: false, pi2_bpsk: false }));
        // mcs 12 of Table 6.1.4.1-1 is 16-QAM as well.
        assert_eq!(g.mcs.qm, 4);
        // A q-row (index 1) with tp-pi2BPSK keeps Q_m = 1.
        c.pusch.tp_pi2_bpsk = true;
        let r = DciResolver::new(&c, true);
        let g = ul(r.resolve_0_1(&dci_0_1(&r, riv_encode(2, 8, N_RB), 1, 1, 1, 0, 9, 1, 0, 1), Rnti(0x4601), slot(50)));
        assert_eq!((g.mcs.qm, g.mcs.r_x1024), (1, Some(314)));
        assert_eq!(g.transform_precoding.map(|t| t.pi2_bpsk), Some(true));
    }

    /// T1's pattern: 5 ms = 10 slots, 6 DL, special (8 DL symbols), 3 UL.
    fn tdd_6d_s_3u() -> crate::config::TddConfig {
        use crate::config::{TddConfig, TddPattern};
        TddConfig { reference_scs: MU, pattern1: TddPattern { period_slots: 10, dl_slots: 6, dl_symbols: 8, ul_slots: 3, ul_symbols: 0 }, pattern2: None }
    }

    #[test]
    fn grants_against_the_tdd_pattern_are_dropped() {
        let mut c = cfg();
        c.tdd = Some(tdd_6d_s_3u());
        let r = DciResolver::new(&c, false);
        // PDSCH (k0 = 0) in a DL slot: fine; in a UL slot (7): dropped.
        let bits = dci_1_0_c(&r, riv_encode(0, 4, N_RB), 0, 3, 0, 0, 0, 0, 1, 0, 0);
        assert!(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(2), 0, 4).is_some());
        assert!(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(7), 0, 4).is_none());
        // PDSCH symbols 2..14 in the special slot (6): symbols 8..14 are flexible → allowed.
        assert!(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(6), 0, 4).is_some());
        // PUSCH (k2 = 1 → slot + 1): DCI at slot 6 → PUSCH in UL slot 7: fine; DCI at 2 → slot 3 (DL): dropped.
        let ul = dci_0_0(&r, riv_encode(0, 4, N_RB), 1, 2, 1, 0, 3, 1);
        assert!(r.resolve_0_0(&ul, Rnti(0x4601), RntiKind::C, true, slot(6)).is_some());
        assert!(r.resolve_0_0(&ul, Rnti(0x4601), RntiKind::C, true, slot(2)).is_none());
        // Msg3: RAR at slot 3 → PUSCH at 3 + 1 + 3 = 7 (UL): fine; RAR at 5 → 9 (UL): fine; RAR at 6 → 10 (DL): dropped.
        let g = RarUlGrant { freq_hopping: false, fdra: riv_encode(0, 3, N_RB) as u16, time_resource: 0, mcs: 0, tpc: 0, csi_request: false };
        assert!(r.resolve_rar_grant(slot(3), Rnti(1), &g).is_some());
        assert!(r.resolve_rar_grant(slot(6), Rnti(1), &g).is_none());
        // FDD: never dropped.
        let r = DciResolver::new(&cfg(), false);
        assert!(r.resolve_1_0(&bits, Rnti(0x4601), RntiKind::C, true, slot(7), 0, 4).is_some());
    }

    #[test]
    fn bwp_indicator_switches_the_bandwidth_part() {
        // One BWP besides the initial one: a 1-bit indicator naming BWP 0 or 1.
        let mut c = dedicated_cfg();
        c.nof_dl_bwp_rrc = 1;
        let r = DciResolver::new(&c, true);
        assert_eq!(r.sizes.f1_1.as_ref().unwrap().bwp_indicator, 1);
        let same = dci_1_1_bwp(&r, 0, riv_encode(0, 24, N_RB), 0, 20, 1, 0, 7, 2, 1, 2, 3);
        assert!(matches!(r.resolve_1_1(&same, Rnti(0x4601), slot(40), 8, 16), Some(Dci::Dl(_))));
        let other = dci_1_1_bwp(&r, 1, riv_encode(0, 24, N_RB), 0, 20, 1, 0, 7, 2, 1, 2, 3);
        assert_eq!(r.resolve_1_1(&other, Rnti(0x4601), slot(40), 8, 16), Some(Dci::BwpSwitch { dl_bwp: Some(1), ul_bwp: None }));
        // Four configured BWPs: 2 bits, value + 1 (the initial BWP is not addressable).
        assert_eq!(DciResolver::bwp_id_of(2, 4), 3);
        assert_eq!(DciResolver::bwp_id_of(2, 3), 2);
        // Without configured BWPs the field is absent and nothing switches.
        let r = DciResolver::new(&dedicated_cfg(), true);
        assert_eq!(r.sizes.f1_1.as_ref().unwrap().bwp_indicator, 0);
    }

    #[test]
    fn tdra_rows_fall_back_to_the_default_tables() {
        let r = DciResolver::new(&cfg(), false);
        // Table 5.1.2.1.1-2 row 2 with pos2: S = 2, L = 10; row 16: type B, S = 8, L = 4 (k0 = 0 for both).
        let row = r.pdsch_tdra_row(1, false, RntiKind::C).unwrap();
        assert_eq!((row.k, row.mapping_type_a, row.start_symbol, row.n_symbols), (0, true, 2, 10));
        let row = r.pdsch_tdra_row(15, false, RntiKind::C).unwrap();
        assert_eq!((row.mapping_type_a, row.start_symbol, row.n_symbols), (false, 8, 4));
        assert!(r.pdsch_tdra_row(16, false, RntiKind::C).is_none());
        // The SI-RNTI always uses the default table, even with a SIB1 list.
        let mut c = cfg();
        c.pdsch_tdra_common = vec![TdraRow { k: 1, mapping_type_a: true, start_symbol: 3, n_symbols: 5 }];
        let r = DciResolver::new(&c, false);
        assert_eq!(r.pdsch_tdra_row(0, false, RntiKind::C).unwrap().start_symbol, 3);
        assert_eq!(r.pdsch_tdra_row(0, false, RntiKind::Si).unwrap().start_symbol, 2);
    }
}
