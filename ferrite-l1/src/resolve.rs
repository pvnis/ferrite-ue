//! DCI resolution: raw DCI fields (TS 38.212 §7.3.1) → FAPI grants, using the
//! PHY configuration (TDRA tables, k1 list, BWP sizes, DMRS/MCS config).

use crate::config::{McsTableSel, PhyConfig, SearchSpaceKind, TdraRow};
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
        let (rb_start, n_rb) = dci::riv_decode(d.fdra, self.dl_bwp_rb)?;
        let row = self.pdsch_tdra_row(d.tdra as usize, true, RntiKind::C)?;
        let mcs = self.mcs(self.pdsch_mcs, d.mcs);
        let ports = dmrs::dci_1_1_antenna_ports_type1_len1(d.antenna_ports)?;
        let cdm = ports.nof_cdm_groups_without_data;
        let tbs = self.pdsch_tbs(&row, n_rb, &mcs, cdm);
        let pdsch_slot = slot.add(row.k as u64);
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
        Some(UlGrant {
            rnti: tc_rnti,
            rnti_kind: RntiKind::Tc,
            pusch_slot: rar_slot.add(row.k as u64 + self.msg3_delta as u64),
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
        let (rb_start, n_rb) = dci::riv_decode(d.fdra, self.ul_bwp_rb)?;
        let row = self.pusch_tdra_row(d.tdra as usize, true)?;
        let mcs = self.pusch_mcs_of(self.pusch_mcs, d.mcs, self.ded_tp.is_some_and(|t| t.pi2_bpsk));
        // Antenna ports: Table 7.3.1.1.2-6 with transform precoding (always 2
        // CDM groups without data, port = value), Table 7.3.1.1.2-8 otherwise.
        let cdm = if self.ded_tp.is_some() { 2 } else { dmrs::dci_0_1_antenna_ports_type1_len1_rank1(d.antenna_ports).map_or(2, |p| p.nof_cdm_groups_without_data) };
        let tbs = self.pusch_tbs(&row, n_rb, &mcs, cdm, self.ul_dmrs_add_pos);
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
