//! ASN.1 ↔ configuration bindings: the only module that touches
//! `ferrite_asn1` types. Everything here is a pure function from decoded IEs
//! (plus the MIB / radio facts) to the plain `PhyConfig` / `MacConfig` /
//! `BearerSetup` structures, or from plain arguments to an encoded UL PDU.
//!
//! Spec references are TS 38.331 (IEs), TS 38.213 §13 (CORESET#0 placement),
//! TS 38.214 (TDRA, Msg3 Δ) and TS 38.211 §7.3.2.2 (CORESET RB groups).

use crate::derive::{CellInfo, DlCcch, DlDcch, MibInfo, RadioInfo};
use crate::{BearerSetup, RbId, RlcSetup};
use ferrite_asn1::cellgroup as cg;
use ferrite_asn1::common as cm;
use ferrite_asn1::csi as acsi;
use ferrite_asn1::rrc;
use ferrite_asn1::sib1;
use ferrite_common::{DuplexMode, Numerology};
use ferrite_fapi::config::*;
use ferrite_mac::{
    CsiReportMacConfig, LogicalChannelConfig, MacConfig, PucchMacConfig, RachConfig, SrConfig,
};

// ---------------------------------------------------------------------------
// SIB1 → common configuration
// ---------------------------------------------------------------------------

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

fn numerology_of(scs: cm::SubcarrierSpacing) -> Result<Numerology, String> {
    match scs.mu() {
        mu @ 0..=3 => Ok(Numerology::new(mu)),
        mu => Err(format!("unsupported subcarrier spacing µ={mu}")),
    }
}

/// Pick the `SCS-SpecificCarrier` of the list at numerology `n` (first one otherwise).
fn carrier_at(list: &[cm::ScsSpecificCarrier], n: Numerology) -> Option<Carrier> {
    list.iter()
        .find(|c| c.subcarrier_spacing.mu() == n.mu)
        .or_else(|| list.first())
        .map(|c| Carrier {
            offset_crb: c.offset_to_carrier,
            n_rb: c.carrier_bandwidth,
        })
}

/// `BWP.locationAndBandwidth` → CRBs (`N_BWP^start = O_carrier + RB_start`, TS 38.214 §5.1.2.2.2 / TS 38.213 §12).
fn bwp_of(b: &cm::Bwp, carrier: Carrier, id: u8) -> Result<Bwp, String> {
    let (start, len) = b.start_and_len();
    Ok(Bwp {
        id,
        start_crb: carrier.offset_crb + start,
        n_rb: len,
        scs: numerology_of(b.subcarrier_spacing)?,
    })
}

/// `PDCCH-ConfigCommon` of a BWP: its common CORESET and common search spaces
/// (add/mod by id; the Type0 CSS stays on `ss0_index`).
fn apply_pdcch_common(phy: &mut PhyConfig, pc: &sib1::PdcchConfigCommon) {
    if let Some(c) = pc
        .common_control_resource_set
        .as_ref()
        .and_then(|c| coreset_of(c, phy.dl_bwp.start_crb))
    {
        phy.coresets.retain(|x| x.id != c.id);
        phy.coresets.push(c);
    }
    if let Some(z) = pc.search_space_zero {
        phy.ss0_index = z;
    }
    for ss in &pc.common_search_space_list {
        if let Some(cfg) = search_space_of(ss) {
            if ss.search_space_id != 0 {
                phy.search_spaces.retain(|x| x.id != cfg.id);
                phy.search_spaces.push(cfg);
            }
        }
    }
}

fn tdra_rows_pdsch(rows: &[cm::TdraRow]) -> Vec<TdraRow> {
    rows.iter()
        .map(|r| {
            let (s, l) = r.start_len();
            TdraRow {
                k: r.k0(),
                mapping_type_a: r.mapping_type_a,
                start_symbol: s as u8,
                n_symbols: l as u8,
            }
        })
        .collect()
}

fn tdra_rows_pusch(rows: &[cm::TdraRow], mu: u8) -> Vec<TdraRow> {
    rows.iter()
        .map(|r| {
            let (s, l) = r.start_len();
            TdraRow {
                k: r.k2(mu),
                mapping_type_a: r.mapping_type_a,
                start_symbol: s as u8,
                n_symbols: l as u8,
            }
        })
        .collect()
}

/// `ControlResourceSet` → geometry. RB groups of 6 CRBs start at
/// `6·⌈N_BWP^start/6⌉` (TS 38.213 §10.1 / TS 38.331 `frequencyDomainResources`).
fn coreset_of(c: &cm::ControlResourceSet, bwp_start_crb: u16) -> Option<CoresetConfig> {
    let groups: Vec<u8> = (0..45u8).filter(|&g| c.has_rb_group(g)).collect();
    let (&first, &last) = (groups.first()?, groups.last()?);
    let base = 6 * bwp_start_crb.div_ceil(6);
    let start_crb = base + 6 * first as u16;
    let rb_mask: Vec<bool> = (first..=last)
        .flat_map(|g| std::iter::repeat_n(c.has_rb_group(g), 6))
        .collect();
    let interleaved = match c.cce_reg_mapping_type {
        cm::CceRegMapping::Interleaved {
            reg_bundle_size,
            interleaver_size,
            shift_index,
        } => Some((
            reg_bundle_size,
            interleaver_size,
            shift_index.unwrap_or(u16::MAX),
        )),
        cm::CceRegMapping::NonInterleaved => None,
    };
    Some(CoresetConfig {
        id: c.control_resource_set_id,
        start_crb,
        rb_mask,
        duration: c.duration,
        interleaved,
        dmrs_scrambling_id: c.pdcch_dmrs_scrambling_id,
        ref_lowest_rb: false,
    })
}

fn search_space_of(s: &cm::SearchSpace) -> Option<SearchSpaceConfig> {
    let coreset_id = s.control_resource_set_id?;
    let (period_slots, offset_slots) = s
        .monitoring_slot_periodicity_and_offset
        .map_or((1, 0), |p| (p.period_slots, p.offset));
    let mut symbols = [false; 14];
    for l in s.monitoring_symbols() {
        symbols[l as usize] = true;
    }
    let kind = match &s.search_space_type {
        Some(cm::SearchSpaceType::UeSpecific {
            dci_formats_0_1_and_1_1: true,
        }) => SearchSpaceKind::UeSpecificNonFallback,
        Some(cm::SearchSpaceType::UeSpecific { .. }) => SearchSpaceKind::UeSpecificFallback,
        _ => SearchSpaceKind::Common,
    };
    Some(SearchSpaceConfig {
        id: s.search_space_id,
        coreset_id,
        period_slots,
        offset_slots,
        duration_slots: s.duration.unwrap_or(1),
        symbols,
        candidates: s.nrof_candidates.unwrap_or([0; 5]),
        kind,
    })
}

fn tdd_of(t: &sib1::TddUlDlConfigCommon) -> Result<TddConfig, String> {
    let pat = |p: &sib1::TddPattern| TddPattern {
        period_slots: p.period_slots as u16,
        dl_slots: p.dl_slots as u16,
        dl_symbols: p.dl_symbols as u8,
        ul_slots: p.ul_slots as u16,
        ul_symbols: p.ul_symbols as u8,
    };
    Ok(TddConfig {
        reference_scs: numerology_of(t.reference_subcarrier_spacing)?,
        pattern1: pat(&t.pattern1),
        pattern2: t.pattern2.as_ref().map(pat),
    })
}

/// TS 38.214 Table 6.1.2.1.1-5: Msg3 slot delay Δ per µ.
/// Build the PHY and MAC configuration of a cell from its SIB1 (TS 38.331
/// `ServingCellConfigCommonSIB`) and the MIB-derived CORESET#0 facts.
pub fn cell_from_sib1(
    tb: &[u8],
    mib: &MibInfo,
    radio: &RadioInfo,
    tx_lead: u16,
) -> Result<CellInfo, String> {
    let s = sib1::Sib1::decode(tb).map_err(err("SIB1"))?;
    let sc = s
        .serving_cell()
        .ok_or("SIB1 without servingCellConfigCommon")?;
    let dl = &sc.downlink_config_common;
    let dl_bwp_gen = &dl.initial_downlink_bwp.generic_parameters;
    let numerology = numerology_of(dl_bwp_gen.subcarrier_spacing)?;
    let mu = numerology.mu;
    if mu != mib.mu {
        return Err(format!(
            "initial DL BWP µ={mu} but MIB common SCS µ={}",
            mib.mu
        ));
    }
    let dl_carrier = carrier_at(&dl.frequency_info_dl.scs_specific_carrier_list, numerology)
        .ok_or("no DL SCS-SpecificCarrier")?;
    let dl_bwp = bwp_of(dl_bwp_gen, dl_carrier, 0)?;

    // SSB placement on the CRB grid: offsetToPointA is in 15 kHz RBs (FR1);
    // a leftover 15 kHz RB at µ=1 shifts the SSB by 12 extra 15 kHz subcarriers.
    let o = dl.frequency_info_dl.offset_to_point_a;
    let ssb_crb = o >> mu;
    let k_ssb = mib.k_ssb + 12 * (o & ((1 << mu) - 1)) as u8;
    let ssb_scs = Numerology::from_scs_khz(mib.ssb_scs_khz).ok_or("bad SSB SCS")?;

    // Uplink.
    let ul = sc
        .uplink_config_common
        .as_ref()
        .ok_or("SIB1 without uplinkConfigCommon")?;
    let ul_bwp_gen = &ul.initial_uplink_bwp.generic_parameters;
    let ul_carrier = carrier_at(&ul.frequency_info_ul.scs_specific_carrier_list, numerology)
        .ok_or("no UL SCS-SpecificCarrier")?;
    let ul_bwp = bwp_of(ul_bwp_gen, ul_carrier, 0)?;
    if ul_bwp.scs != numerology {
        return Err("initial UL BWP numerology differs from DL".into());
    }

    // TDD pattern vs the duplex mode the radio was started with.
    let tdd = match (radio.duplex, sc.tdd_ul_dl_configuration_common.as_ref()) {
        (DuplexMode::Tdd, Some(t)) => Some(tdd_of(t)?),
        (DuplexMode::Fdd, None) => None,
        (DuplexMode::Tdd, None) => {
            return Err("radio is TDD but SIB1 has no tdd-UL-DL-ConfigurationCommon".into())
        }
        (DuplexMode::Fdd, Some(_)) => {
            return Err("radio is FDD but SIB1 carries a TDD configuration".into())
        }
    };

    // CORESET#0 (TS 38.213 §13): lowest CRB = SSB CRB − table offset.
    let cs0_start = (ssb_crb as i32 - mib.coreset0_offset_rb).max(0) as u16;
    let mut coresets = vec![CoresetConfig {
        id: 0,
        start_crb: cs0_start,
        rb_mask: vec![true; mib.coreset0_n_rb as usize],
        duration: mib.coreset0_n_symb,
        interleaved: Some((6, 2, mib.pci)),
        dmrs_scrambling_id: None,
        ref_lowest_rb: true,
    }];
    let mut search_spaces = Vec::new();
    let mut ss0_index = mib.ss0_index;
    if let Some(pc) = s.pdcch_config_common() {
        if let Some(c) = pc
            .common_control_resource_set
            .as_ref()
            .and_then(|c| coreset_of(c, dl_bwp.start_crb))
        {
            coresets.retain(|x| x.id != c.id);
            coresets.push(c);
        }
        if let Some(z) = pc.search_space_zero {
            ss0_index = z;
        }
        for ss in &pc.common_search_space_list {
            if let Some(cfg) = search_space_of(ss) {
                // The Type0 CSS (SIB1) is handled by `ss0_index`; the others
                // (RA / paging / OSI) are monitored as common search spaces.
                if ss.search_space_id != 0 {
                    search_spaces.push(cfg);
                }
            }
        }
    }

    // RACH.
    let rach = s
        .rach_config_common()
        .ok_or("SIB1 without rach-ConfigCommon")?;
    let g = &rach.rach_config_generic;
    let msg1_scs_mu = rach.msg1_subcarrier_spacing.map_or(mu, |s| s.mu());
    // Transmitted SS/PBCH blocks (symbols at the data numerology) for the
    // PRACH occasion validity rule (TS 38.211 §6.3.3.2).
    let ssb_symbols: Vec<SsbSlotSymbols> =
        ferrite_ran::ssb::SsbCase::from_scs(mib.ssb_scs_khz, radio.duplex)
            .map(|case| {
                let carrier_hz = ferrite_common::arfcn_to_hz(mib.ssb_arfcn);
                let cands = case.candidate_symbols(carrier_hz);
                let l_max = cands.len() as u8;
                let (ssb_mu, data_mu) = (u32::from(case.mu()), u32::from(mu));
                cands
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| sc.ssb_positions_in_burst.is_transmitted(*i as u8, l_max))
                    .map(|(_, &first)| {
                        let last = first + ferrite_ran::ssb::SSB_SYMBOLS - 1;
                        let (f, l) = if data_mu >= ssb_mu {
                            let sh = data_mu - ssb_mu;
                            (first << sh, ((last + 1) << sh) - 1)
                        } else {
                            let sh = ssb_mu - data_mu;
                            (first >> sh, last >> sh)
                        };
                        SsbSlotSymbols {
                            slot_in_half_frame: (f / 14) as u8,
                            first_symbol: (f % 14) as u8,
                            last_symbol: (l % 14) as u8,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
    let prach = PrachConfig {
        phy: ferrite_ran::prach_config::PrachConfig {
            index: g.prach_configuration_index as u16,
            duplex: radio.duplex,
            mu,
            msg1_scs_mu,
            msg1_fdm: g.msg1_fdm,
            msg1_frequency_start: g.msg1_frequency_start,
        },
        tdd: tdd.clone(),
        ssb_symbols,
        ssb_period_ms: u16::from(sc.ssb_periodicity_ms),
        zero_correlation_zone: g.zero_correlation_zone_config,
        root_sequence_index: match rach.prach_root_sequence_index {
            sib1::PrachRootSequenceIndex::L839(v) => v,
            sib1::PrachRootSequenceIndex::L139(v) => v as u16,
        },
        restricted_set: match rach.restricted_set_config {
            sib1::RestrictedSetConfig::UnrestrictedSet => 0,
            sib1::RestrictedSetConfig::RestrictedSetTypeA => 1,
            sib1::RestrictedSetConfig::RestrictedSetTypeB => 2,
        },
        total_preambles: rach.total_number_of_ra_preambles.unwrap_or(64),
        target_power_dbm: g.preamble_received_target_power,
        power_ramping_step_db: g.power_ramping_step_db,
    };
    let pusch_tdra_common = tdra_rows_pusch(s.pusch_tdra(), mu);
    let pucch_common = s.pucch_config_common();
    let msg3_group_hopping = s
        .initial_uplink_bwp()
        .and_then(|b| b.pusch_config_common.as_ref()?.setup())
        .is_some_and(|p| p.group_hopping_enabled_transform_precoding);

    let paging = {
        let pc = &sc.downlink_config_common.pcch_config;
        let (n_div, offset) = match pc.n_and_paging_frame_offset {
            sib1::PagingFrameOffset::OneT => (1, 0),
            sib1::PagingFrameOffset::HalfT(o) => (2, o),
            sib1::PagingFrameOffset::QuarterT(o) => (4, o),
            sib1::PagingFrameOffset::OneEighthT(o) => (8, o),
            sib1::PagingFrameOffset::OneSixteenthT(o) => (16, o),
        };
        s.pdcch_config_common()
            .and_then(|p| p.paging_search_space)
            .map(|ss| PagingConfig {
                t_rf: pc.default_paging_cycle_rf,
                n_div,
                offset,
                ns: pc.ns,
                search_space_id: ss,
            })
    };
    let phy = PhyConfig {
        duplex: radio.duplex,
        paging,
        numerology,
        ssb: SsbConfig {
            pci: mib.pci,
            scs: ssb_scs,
            period_ms: sc.ssb_periodicity_ms as u16,
            ssb_index: mib.ssb_index,
            k_ssb,
            dmrs_typea_pos: mib.dmrs_typea_pos,
        },
        dl_carrier,
        ul_carrier,
        ssb_crb,
        dl_bwp,
        ul_bwp,
        nof_dl_bwp_rrc: 0,
        nof_ul_bwp_rrc: 0,
        tdd,
        coresets,
        search_spaces,
        ss0_index,
        pdsch_tdra_common: tdra_rows_pdsch(s.pdsch_tdra()),
        pusch_tdra_common: pusch_tdra_common.clone(),
        prach: prach.clone(),
        n_ta_offset_tc: sc.n_timing_advance_offset.unwrap_or(25600),
        pdsch: PdschConfig {
            nof_harq_processes: 8,
            ..PdschConfig::default()
        },
        pusch: PuschConfig {
            transform_precoder: rach.msg3_transform_precoder,
            msg3_transform_precoder: rach.msg3_transform_precoder,
            msg3_group_hopping,
            ..PuschConfig::default()
        },
        srs: Vec::new(),
        pucch: PucchConfig {
            resource_common: pucch_common.and_then(|p| p.pucch_resource_common),
            hopping_id: pucch_common.and_then(|p| p.hopping_id),
            group_hopping: pucch_common.map_or(0, |p| match p.pucch_group_hopping {
                sib1::PucchGroupHopping::Neither => 0,
                sib1::PucchGroupHopping::Enable => 1,
                sib1::PucchGroupHopping::Disable => 2,
            }),
            ..PucchConfig::default()
        },
        csi_reports: Vec::new(),
        harq_codebook_dynamic: true,
        ul_amplitude: 0.5,
    };

    let mut mac = MacConfig::initial(
        numerology,
        RachConfig {
            preamble_trans_max: g.preamble_trans_max as u32,
            power_ramping_step_db: g.power_ramping_step_db,
            target_power_dbm: g.preamble_received_target_power,
            ra_response_window_slots: g.ra_response_window_slots as u16,
            contention_resolution_ms: rach.ra_contention_resolution_timer_sf as u32,
            nof_cb_preambles: rach
                .group_b_configured
                .as_ref()
                .map_or(prach.total_preambles, |b| b.number_of_ra_preambles_group_a),
            cb_preambles_per_ssb: rach
                .ssb_per_rach_occasion_and_cb_preambles_per_ssb
                .map_or(64, |(_, n)| n),
            prach,
        },
        tx_lead,
    );
    mac.time_alignment_timer_ms = ul.time_alignment_timer_common.0.map_or(0, u32::from);

    let plmn = s.plmn().map(|p| {
        let mut out = String::new();
        if let Some(mcc) = p.mcc {
            out.extend(mcc.iter().map(|d| char::from(b'0' + d)));
        }
        out.extend(p.mnc.iter().map(|d| char::from(b'0' + d)));
        out
    });
    Ok(CellInfo {
        plmn: plmn.unwrap_or_default(),
        tac: s.tac().unwrap_or(0),
        cell_identity: s.cell_identity().unwrap_or(0),
        common_phy: phy.clone(),
        common_mac: mac.clone(),
        rlc_bearers: Default::default(),
        phy,
        mac,
        t300_ms: s
            .ue_timers_and_constants
            .as_ref()
            .map_or(1000, |t| t.t300_ms as u32),
        numerology,
        si_scheduled: s
            .si_scheduling_info
            .as_ref()
            .map(|si| {
                si.scheduling_info_list
                    .iter()
                    .filter(|e| e.si_broadcasting)
                    .flat_map(|e| e.sib_mapping_info.iter().filter_map(|m| m.sib_type))
                    .collect()
            })
            .unwrap_or_default(),
        si_window_slots: s
            .si_scheduling_info
            .as_ref()
            .map_or(0, |si| si.si_window_length_slots),
        ssb_arfcn: mib.ssb_arfcn,
        t301_ms: s
            .ue_timers_and_constants
            .as_ref()
            .map_or(1000, |t| t.t301_ms as u32),
        t310_ms: s
            .ue_timers_and_constants
            .as_ref()
            .map_or(1000, |t| t.t310_ms as u32),
        n310: s.ue_timers_and_constants.as_ref().map_or(1, |t| t.n310),
        n311: s.ue_timers_and_constants.as_ref().map_or(1, |t| t.n311),
        t311_ms: s
            .ue_timers_and_constants
            .as_ref()
            .map_or(30000, |t| t.t311_ms as u32),
        bwps: std::collections::BTreeMap::new(),
    })
}

// ---------------------------------------------------------------------------
// CellGroupConfig → dedicated configuration (delta on top of a baseline)
// ---------------------------------------------------------------------------

fn dmrs_dl(
    d: Option<&ferrite_asn1::SetupRelease<cg::DmrsDownlinkConfig>>,
    base: DmrsConfig,
) -> DmrsConfig {
    match d.and_then(|s| s.setup()) {
        Some(c) => DmrsConfig {
            additional_position: c.additional_position(),
            scrambling_id0: c.scrambling_id0,
        },
        None => base,
    }
}

fn dmrs_ul(
    d: Option<&ferrite_asn1::SetupRelease<cg::DmrsUplinkConfig>>,
    base: DmrsConfig,
) -> DmrsConfig {
    match d.and_then(|s| s.setup()) {
        Some(c) => DmrsConfig {
            additional_position: c.additional_position(),
            scrambling_id0: c.transform_precoding_disabled.and_then(|(id0, _)| id0),
        },
        None => base,
    }
}

fn mcs_table_of(t: Option<cg::McsTable>) -> McsTableSel {
    match t {
        Some(cg::McsTable::Qam256) => McsTableSel::Qam256,
        Some(cg::McsTable::Qam64LowSe) => McsTableSel::Qam64LowSe,
        _ => McsTableSel::Qam64,
    }
}

fn pucch_resource_of(r: &cg::PucchResource) -> PucchResource {
    let (start_symbol, n_symbols) = r.format.symbols();
    let format = match r.format {
        cg::PucchFormat::Format0 {
            initial_cyclic_shift,
            ..
        } => PucchFormat::F0 {
            initial_cyclic_shift,
        },
        cg::PucchFormat::Format1 {
            initial_cyclic_shift,
            time_domain_occ,
            ..
        } => PucchFormat::F1 {
            initial_cyclic_shift,
            time_domain_occ,
        },
        cg::PucchFormat::Format2 { nrof_prbs, .. } => PucchFormat::F2 { n_prb: nrof_prbs },
        cg::PucchFormat::Format3 { nrof_prbs, .. } => PucchFormat::F3 { n_prb: nrof_prbs },
        cg::PucchFormat::Format4 {
            occ_length,
            occ_index,
            ..
        } => PucchFormat::F4 {
            occ_length,
            occ_index,
        },
    };
    PucchResource {
        id: r.pucch_resource_id,
        starting_prb: r.starting_prb,
        second_hop_prb: r.second_hop_prb,
        format,
        start_symbol,
        n_symbols,
    }
}

fn format_config_of(
    f: Option<&ferrite_asn1::SetupRelease<cg::PucchFormatConfig>>,
) -> PucchFormatConfig {
    match f.and_then(|s| s.setup()) {
        Some(c) => PucchFormatConfig {
            additional_dmrs: c.additional_dmrs,
            max_code_rate_x100: c.max_code_rate.map(|r| (r.value() * 100.0).round() as u8),
            simultaneous_harq_ack_csi: c.simultaneous_harq_ack_csi,
            pi2_bpsk: c.pi2_bpsk,
        },
        None => PucchFormatConfig::default(),
    }
}

/// Maximum UCI payload (bits, before CRC) a PUCCH resource can carry at its
/// configured code rate: formats 0/1 carry up to 2 bits; format 2 has 8 data
/// REs per PRB per symbol (QPSK), format 3 twelve, with the CRC taken off.
fn pucch_max_bits(r: &PucchResource, f2: &PucchFormatConfig, f3: &PucchFormatConfig) -> u16 {
    let (n_prb, re_per_prb, rate) = match r.format {
        PucchFormat::F0 { .. } | PucchFormat::F1 { .. } | PucchFormat::F4 { .. } => return 2,
        PucchFormat::F2 { n_prb } => (n_prb, 8, f2.max_code_rate_x100.unwrap_or(35)),
        PucchFormat::F3 { n_prb } => (n_prb, 12, f3.max_code_rate_x100.unwrap_or(35)),
    };
    let coded = n_prb as u32 * re_per_prb * r.n_symbols as u32 * 2 * rate as u32 / 100;
    let crc = if coded > 30 {
        11
    } else if coded > 17 {
        6
    } else {
        0
    };
    coded.saturating_sub(crc).max(1) as u16
}

fn csi_rs_resource_of(
    id: u8,
    m: &cm::CsiRsResourceMapping,
    po: Option<cm::PeriodicityAndOffset>,
    zero_power: bool,
    scrambling_id: u16,
    trs: bool,
) -> CsiRsResource {
    CsiRsResource {
        zero_power,
        id,
        row: m.frequency_domain_allocation.row,
        nof_ports: m.nrof_ports,
        freq_bits: m.frequency_domain_allocation.bits,
        first_symbol: m.first_ofdm_symbol_in_time_domain,
        second_symbol: m.first_ofdm_symbol_in_time_domain2,
        density_x2: match m.density {
            cm::CsiRsDensity::Dot5EvenPrbs | cm::CsiRsDensity::Dot5OddPrbs => 1,
            cm::CsiRsDensity::Three => 6,
            _ => 2,
        },
        start_rb: m.freq_band.starting_rb,
        n_rb: m.freq_band.nrof_rbs,
        period_slots: po.map_or(0, |p| p.period_slots),
        offset_slots: po.map_or(0, |p| p.offset),
        scrambling_id,
        trs,
    }
}

/// Apply a `CellGroupConfig` (RRCSetup / RRCReconfiguration) on top of the
/// current configuration. Absent IEs keep their current values.
pub fn apply_cell_group(
    base_phy: &PhyConfig,
    base_mac: &MacConfig,
    c: &cg::CellGroupConfig,
) -> (PhyConfig, MacConfig) {
    apply_cell_group_bwp(
        base_phy,
        base_mac,
        c,
        base_phy.dl_bwp.id,
        base_phy.ul_bwp.id,
    )
}

/// Apply a `CellGroupConfig` delta for the configuration of DL BWP `dl_id` /
/// UL BWP `ul_id` (0 = initial): the BWP's own common part (generic
/// parameters, PDCCH/PDSCH/PUSCH/PUCCH-ConfigCommon) when the message carries
/// it, its dedicated part, and the cell-level items (CSI, HARQ, MAC).
pub fn apply_cell_group_bwp(
    base_phy: &PhyConfig,
    base_mac: &MacConfig,
    c: &cg::CellGroupConfig,
    dl_id: u8,
    ul_id: u8,
) -> (PhyConfig, MacConfig) {
    let mut phy = base_phy.clone();
    let mut mac = base_mac.clone();
    let mu = phy.numerology.mu;
    let (dl_common, dl_ded) = c.dl_bwp(dl_id);
    let (ul_common, ul_ded) = c.ul_bwp(ul_id);

    // --- BWP common parts (non-initial BWPs: TS 38.331 BWP-DownlinkCommon / BWP-UplinkCommon).
    if let Some(bc) = dl_common {
        match bwp_of(&bc.generic_parameters, phy.dl_carrier, dl_id) {
            Ok(b) => phy.dl_bwp = b,
            Err(e) => log::warn!("DL BWP {dl_id}: {e}"),
        }
        if let Some(pc) = bc.pdcch_config_common.as_ref().and_then(|p| p.setup()) {
            apply_pdcch_common(&mut phy, pc);
        }
        if let Some(pd) = bc.pdsch_config_common.as_ref().and_then(|p| p.setup()) {
            phy.pdsch_tdra_common = tdra_rows_pdsch(&pd.pdsch_time_domain_allocation_list);
        }
    }
    if let Some(uc) = ul_common {
        match bwp_of(&uc.generic_parameters, phy.ul_carrier, ul_id) {
            Ok(b) => phy.ul_bwp = b,
            Err(e) => log::warn!("UL BWP {ul_id}: {e}"),
        }
        if let Some(pu) = uc.pusch_config_common.as_ref().and_then(|p| p.setup()) {
            phy.pusch_tdra_common = tdra_rows_pusch(&pu.pusch_time_domain_allocation_list, mu);
            phy.pusch.msg3_group_hopping = pu.group_hopping_enabled_transform_precoding;
        }
        if let Some(pc) = uc.pucch_config_common.as_ref().and_then(|p| p.setup()) {
            phy.pucch.resource_common = pc.pucch_resource_common;
            phy.pucch.hopping_id = pc.hopping_id;
        }
    }
    phy.dl_bwp.id = dl_id;
    phy.ul_bwp.id = ul_id;
    if let Some(scc) = c.serving_cell() {
        phy.nof_dl_bwp_rrc = phy.nof_dl_bwp_rrc.max(
            scc.downlink_bwp_to_add_mod_list
                .iter()
                .filter(|b| b.bwp_id != 0)
                .count() as u8,
        );
        phy.nof_ul_bwp_rrc = phy
            .nof_ul_bwp_rrc
            .max(scc.uplink_config.as_ref().map_or(0, |u| {
                u.uplink_bwp_to_add_mod_list
                    .iter()
                    .filter(|b| b.bwp_id != 0)
                    .count() as u8
            }));
        mac.bwp_inactivity_timer_ms = scc
            .bwp_inactivity_timer_ms
            .map(u32::from)
            .or(mac.bwp_inactivity_timer_ms);
        mac.default_dl_bwp_id = scc.default_downlink_bwp_id.unwrap_or(mac.default_dl_bwp_id);
    }
    mac.dl_bwp_id = dl_id;

    // --- PDCCH: CORESETs and search spaces (add/mod/release by id).
    if let Some(p) = dl_ded.and_then(|d| d.pdcch_config.as_ref()?.setup()) {
        for id in &p.control_resource_set_to_release_list {
            phy.coresets.retain(|x| x.id != *id);
        }
        for cs in &p.control_resource_set_to_add_mod_list {
            if let Some(cfg) = coreset_of(cs, phy.dl_bwp.start_crb) {
                phy.coresets.retain(|x| x.id != cfg.id);
                phy.coresets.push(cfg);
            }
        }
        for id in &p.search_spaces_to_release_list {
            phy.search_spaces.retain(|x| x.id != *id);
        }
        for ss in &p.search_spaces_to_add_mod_list {
            if let Some(cfg) = search_space_of(ss) {
                phy.search_spaces.retain(|x| x.id != cfg.id);
                phy.search_spaces.push(cfg);
            }
        }
    }

    // --- PDSCH.
    if let Some(p) = dl_ded.and_then(|d| d.pdsch_config.as_ref()?.setup()) {
        phy.pdsch.dmrs_type_a = dmrs_dl(
            p.dmrs_downlink_for_pdsch_mapping_type_a.as_ref(),
            phy.pdsch.dmrs_type_a,
        );
        phy.pdsch.dmrs_type_b = dmrs_dl(
            p.dmrs_downlink_for_pdsch_mapping_type_b.as_ref(),
            phy.pdsch.dmrs_type_b,
        );
        phy.pdsch.mcs_table = mcs_table_of(p.mcs_table);
        if let Some(rows) = p.tdra_list() {
            phy.pdsch.tdra = tdra_rows_pdsch(rows);
        }
        phy.pdsch.vrb_to_prb_interleaver = p.vrb_to_prb_interleaver;
        // ZP CSI-RS the PDSCH is rate-matched around (periodic set only):
        // release / add-mod by resource id — a later reconfiguration that
        // carries a pdsch-Config without these lists keeps the resources.
        for id in &p.zp_csi_rs_resource_to_release_list {
            phy.pdsch
                .csi_rs_rate_match
                .retain(|r| !(r.zero_power && r.id == *id));
        }
        for z in &p.zp_csi_rs_resource_to_add_mod_list {
            phy.pdsch
                .csi_rs_rate_match
                .retain(|r| !(r.zero_power && r.id == z.zp_csi_rs_resource_id));
            phy.pdsch.csi_rs_rate_match.push(csi_rs_resource_of(
                z.zp_csi_rs_resource_id,
                &z.resource_mapping,
                z.periodicity_and_offset,
                true,
                0,
                false,
            ));
        }
    }
    phy.pdsch.nof_harq_processes = c.nrof_harq_processes_for_pdsch();

    // --- NZP CSI-RS (rate matching + TRS/CQI measurement) and periodic reports.
    if let Some(m) = c.csi_meas_config() {
        for id in &m.nzp_csi_rs_resource_to_release_list {
            phy.pdsch
                .csi_rs_rate_match
                .retain(|r| r.zero_power || r.id != *id);
        }
        let trs_ids: Vec<u8> = m
            .nzp_csi_rs_resource_set_to_add_mod_list
            .iter()
            .filter(|s| s.trs_info)
            .flat_map(|s| s.nzp_csi_rs_resources.iter().copied())
            .collect();
        for r in &m.nzp_csi_rs_resource_to_add_mod_list {
            let trs = trs_ids.contains(&r.nzp_csi_rs_resource_id)
                || phy
                    .pdsch
                    .csi_rs_rate_match
                    .iter()
                    .any(|x| !x.zero_power && x.id == r.nzp_csi_rs_resource_id && x.trs);
            phy.pdsch
                .csi_rs_rate_match
                .retain(|x| x.zero_power || x.id != r.nzp_csi_rs_resource_id);
            phy.pdsch.csi_rs_rate_match.push(csi_rs_resource_of(
                r.nzp_csi_rs_resource_id,
                &r.resource_mapping,
                r.periodicity_and_offset,
                false,
                r.scrambling_id,
                trs,
            ));
        }
        for id in &m.csi_report_config_to_release_list {
            phy.csi_reports.retain(|c| c.report_id != *id);
        }
        for rc in &m.csi_report_config_to_add_mod_list {
            phy.csi_reports
                .retain(|c| c.report_id != rc.report_config_id);
            if let acsi::CsiReportConfigType::Periodic {
                report_slot_config,
                pucch_csi_resource_list,
            } = &rc.report_config_type
            {
                let Some(res) = pucch_csi_resource_list.first() else {
                    continue;
                };
                phy.csi_reports.push(CsiReportConfig {
                    report_id: rc.report_config_id,
                    period_slots: report_slot_config.period_slots,
                    offset_slots: report_slot_config.offset,
                    pucch_resource: res.pucch_resource,
                    cqi_table: match rc.cqi_table {
                        Some(acsi::CqiTable::Table2) => 1,
                        Some(acsi::CqiTable::Table3) => 2,
                        _ => 0,
                    },
                    quantity: match rc.report_quantity {
                        acsi::CsiReportQuantity::CriRiPmiCqi
                        | acsi::CsiReportQuantity::CriRiLiPmiCqi => CsiReportQuantity::RiPmiCqi,
                        acsi::CsiReportQuantity::CriRiCqi => CsiReportQuantity::RiCqi,
                        _ => CsiReportQuantity::Cqi,
                    },
                    nof_ports: rc.codebook_config.as_ref().map_or(1, |c| c.nof_ports()),
                    ri_restriction: rc
                        .codebook_config
                        .as_ref()
                        .map_or(0x01, |c| c.ri_restriction),
                });
            }
        }
    }

    // --- PUSCH.
    if let Some(p) = ul_ded.and_then(|d| d.pusch_config.as_ref()?.setup()) {
        phy.pusch.dmrs_type_a = dmrs_ul(
            p.dmrs_uplink_for_pusch_mapping_type_a.as_ref(),
            phy.pusch.dmrs_type_a,
        );
        phy.pusch.dmrs_type_b = dmrs_ul(
            p.dmrs_uplink_for_pusch_mapping_type_b.as_ref(),
            phy.pusch.dmrs_type_b,
        );
        phy.pusch.mcs_table = mcs_table_of(p.mcs_table);
        if let Some(rows) = p.tdra_list() {
            phy.pusch.tdra = tdra_rows_pusch(rows, mu);
        }
        // TS 38.214 §6.1.3: without `transformPrecoder` the UE follows `msg3-transformPrecoder`.
        phy.pusch.transform_precoder = p
            .transform_precoder_enabled
            .unwrap_or(phy.pusch.msg3_transform_precoder);
        phy.pusch.mcs_table_tp = mcs_table_of(p.mcs_table_transform_precoder);
        phy.pusch.tp_pi2_bpsk = p.tp_pi2_bpsk;
        phy.pusch.data_scrambling_identity = p.data_scrambling_identity_pusch;
        if let Some(t) = p
            .dmrs_uplink_for_pusch_mapping_type_a
            .as_ref()
            .and_then(|s| s.setup())
            .and_then(|c| c.transform_precoding_enabled)
        {
            phy.pusch.tp_dmrs = TpDmrsConfig {
                n_pusch_identity: t.n_pusch_identity,
                group_hopping_disabled: t.sequence_group_hopping_disabled,
                sequence_hopping: t.sequence_hopping_enabled,
            };
        }
        phy.pusch.frequency_hopping = p.frequency_hopping_intra_slot.is_some();
        if let Some(u) = p.uci_on_pusch.as_ref().and_then(|s| s.setup()) {
            phy.pusch.uci_scaling = u.scaling;
            phy.pusch.beta_offsets = match u.beta_offsets {
                Some(cg::BetaOffsetsConfig::SemiStatic(b)) => Some(b),
                Some(cg::BetaOffsetsConfig::Dynamic(b)) => Some(b[0]),
                None => None,
            }
            .map(|b| BetaOffsets {
                ack_index1: b.beta_offset_ack_index1.unwrap_or(11),
                ack_index2: b.beta_offset_ack_index2.unwrap_or(11),
                ack_index3: b.beta_offset_ack_index3.unwrap_or(11),
                csi1_index1: b.beta_offset_csi_part1_index1.unwrap_or(13),
                csi1_index2: b.beta_offset_csi_part1_index2.unwrap_or(13),
                csi2_index1: b.beta_offset_csi_part2_index1.unwrap_or(13),
                csi2_index2: b.beta_offset_csi_part2_index2.unwrap_or(13),
            });
        }
    }

    // --- PUCCH.
    if let Some(p) = ul_ded.and_then(|d| d.pucch_config.as_ref()?.setup()) {
        for id in &p.resource_set_to_release_list {
            phy.pucch.resource_sets.retain(|x| x.id != *id);
        }
        for s in &p.resource_set_to_add_mod_list {
            phy.pucch
                .resource_sets
                .retain(|x| x.id != s.pucch_resource_set_id);
            phy.pucch.resource_sets.push(PucchResourceSet {
                id: s.pucch_resource_set_id,
                resources: s.resource_list.clone(),
                max_payload: s.max_payload_size,
            });
        }
        for id in &p.resource_to_release_list {
            phy.pucch.resources.retain(|x| x.id != *id);
        }
        for r in &p.resource_to_add_mod_list {
            let cfg = pucch_resource_of(r);
            phy.pucch.resources.retain(|x| x.id != cfg.id);
            phy.pucch.resources.push(cfg);
        }
        phy.pucch.format1 = format_config_of(p.format1.as_ref());
        phy.pucch.format2 = format_config_of(p.format2.as_ref());
        phy.pucch.format3 = format_config_of(p.format3.as_ref());
        for id in &p.scheduling_request_resource_to_release_list {
            phy.pucch.sr_resources.retain(|x| x.sr_resource_id != *id);
        }
        for sr in &p.scheduling_request_resource_to_add_mod_list {
            let Some(cg::SrPeriodicityAndOffset::Slots {
                period_slots,
                offset,
            }) = sr.periodicity_and_offset
            else {
                continue;
            };
            let Some(res) = sr.resource else { continue };
            phy.pucch
                .sr_resources
                .retain(|x| x.sr_resource_id != sr.scheduling_request_resource_id);
            phy.pucch.sr_resources.push(SrResource {
                sr_resource_id: sr.scheduling_request_resource_id,
                sr_id: sr.scheduling_request_id,
                period_slots,
                offset_slots: offset,
                pucch_resource: res,
            });
        }
        if !p.dl_data_to_ul_ack.is_empty() {
            phy.pucch.k1_list = p.dl_data_to_ul_ack.clone();
        }
    }

    if let Some(pg) = &c.physical_cell_group_config {
        phy.harq_codebook_dynamic =
            matches!(pg.pdsch_harq_ack_codebook, cg::HarqAckCodebook::Dynamic);
    }

    // --- MAC: logical channels from the RLC bearers.
    for id in &c.rlc_bearer_to_release_list {
        mac.logical_channels.retain(|l| l.lcid != *id);
    }
    for b in &c.rlc_bearer_to_add_mod_list {
        let lcid = b.logical_channel_identity;
        let ul = b
            .mac_logical_channel_config
            .as_ref()
            .and_then(|m| m.ul_specific_parameters.as_ref());
        let cfg = LogicalChannelConfig {
            lcid,
            priority: ul.map_or(if lcid <= 3 { lcid } else { 8 }, |u| u.priority),
            pbr_bytes_per_ms: ul
                .and_then(|u| u.prioritised_bit_rate_kbps)
                .map(|kbps| kbps / 8),
            bsd_ms: ul.map_or(1000, |u| u.bucket_size_duration_ms as u32),
            lcg: ul.and_then(|u| u.logical_channel_group).unwrap_or(0),
            sr_id: ul.and_then(|u| u.scheduling_request_id),
            sr_mask: ul.is_some_and(|u| u.logical_channel_sr_mask),
        };
        mac.logical_channels.retain(|l| l.lcid != lcid);
        mac.logical_channels.push(cfg);
    }
    mac.logical_channels.sort_by_key(|l| (l.priority, l.lcid));

    // --- MAC cell group: SR, BSR, TAG.
    if let Some(m) = &c.mac_cell_group_config {
        if let Some(src) = &m.scheduling_request_config {
            for id in &src.scheduling_request_to_release_list {
                mac.sr.retain(|s| s.sr_id != *id);
            }
            for s in &src.scheduling_request_to_add_mod_list {
                mac.sr.retain(|x| x.sr_id != s.scheduling_request_id);
                mac.sr.push(SrConfig {
                    sr_id: s.scheduling_request_id,
                    prohibit_ms: s.sr_prohibit_timer_ms.map_or(0, u32::from),
                    trans_max: s.sr_trans_max as u32,
                    resources: Vec::new(),
                });
            }
        }
        if let Some(b) = &m.bsr_config {
            mac.periodic_bsr_ms = b.periodic_bsr_timer_sf.map_or(0, u32::from);
            mac.retx_bsr_ms = b.retx_bsr_timer_sf as u32;
        }
        if let Some(t) = m
            .tag_config
            .as_ref()
            .and_then(|t| t.tag_to_add_mod_list.first())
        {
            mac.time_alignment_timer_ms = t.time_alignment_timer.0.map_or(0, u32::from);
        }
        if let Some(p) = &m.phr_config {
            mac.phr = p.setup().map(|p| ferrite_mac::phr::PhrMacConfig {
                periodic_ms: p.phr_periodic_timer_sf.map(u32::from),
                prohibit_ms: u32::from(p.phr_prohibit_timer_sf),
                tx_power_factor_change_db: p.phr_tx_power_factor_change_db,
            });
        }
        if let Some(d) = &m.drx_config {
            let spsf = mac.numerology.slots_per_subframe();
            mac.drx = d.setup().map(|d| ferrite_mac::DrxMacConfig {
                on_duration_slots: match d.drx_on_duration_timer {
                    // 1/32 ms units: round up to whole slots.
                    cg::DrxOnDurationTimer::SubMilliSeconds(n) => {
                        (u32::from(n) * spsf).div_ceil(32).max(1)
                    }
                    cg::DrxOnDurationTimer::MilliSeconds(ms) => (u32::from(ms) * spsf).max(1),
                },
                inactivity_slots: u32::from(d.drx_inactivity_timer_ms) * spsf,
                harq_rtt_dl_symbols: d.drx_harq_rtt_timer_dl,
                harq_rtt_ul_symbols: d.drx_harq_rtt_timer_ul,
                retx_dl_slots: u32::from(d.drx_retransmission_timer_dl_slots),
                retx_ul_slots: u32::from(d.drx_retransmission_timer_ul_slots),
                long_cycle_ms: u32::from(d.drx_long_cycle_ms),
                start_offset_ms: u32::from(d.drx_long_cycle_start_offset),
                slot_offset_slots: (u32::from(d.drx_slot_offset) * spsf) / 32,
                short: d.short_drx.map(|s| ferrite_mac::ShortDrxMacConfig {
                    cycle_ms: u32::from(s.drx_short_cycle_ms),
                    timer_cycles: u32::from(s.drx_short_cycle_timer),
                }),
            });
        }
    }
    // --- SRS: resources by id (add-mod / release); periodic occasions for MAC.
    if let Some(s) = ul_ded.and_then(|d| d.srs_config.as_ref()?.setup()) {
        for id in &s.srs_resource_to_release_list {
            phy.srs.retain(|r| r.id != *id);
        }
        for r in &s.srs_resource_to_add_mod_list {
            let (k_tc, comb_offset, cyclic_shift) = match r.transmission_comb {
                cg::SrsTransmissionComb::N2 {
                    comb_offset,
                    cyclic_shift,
                } => (2u8, comb_offset, cyclic_shift),
                cg::SrsTransmissionComb::N4 {
                    comb_offset,
                    cyclic_shift,
                } => (4u8, comb_offset, cyclic_shift),
            };
            let (period_slots, offset_slots) = match r.resource_type {
                cg::SrsResourceType::Periodic(po) => (po.period_slots, po.offset),
                _ => (0, 0),
            };
            let cfg = SrsResourceConfig {
                id: r.srs_resource_id,
                params: ferrite_ran::srs::SrsResourceParams {
                    k_tc,
                    comb_offset,
                    cyclic_shift,
                    start_position: r.start_position,
                    nrof_symbols: r.nrof_symbols,
                    repetition_factor: r.repetition_factor,
                    freq_domain_position: r.freq_domain_position,
                    freq_domain_shift: r.freq_domain_shift,
                    c_srs: r.c_srs,
                    b_srs: r.b_srs,
                    b_hop: r.b_hop,
                    sequence_id: r.sequence_id,
                },
                period_slots,
                offset_slots,
            };
            phy.srs.retain(|x| x.id != cfg.id);
            phy.srs.push(cfg);
        }
    }
    mac.srs_occasions = phy
        .srs
        .iter()
        .filter(|r| r.period_slots > 0)
        .map(|r| (r.id, r.period_slots, r.offset_slots))
        .collect();

    // SR resources (PUCCH) attached to their SR configurations.
    for s in &mut mac.sr {
        s.resources = phy
            .pucch
            .sr_resources
            .iter()
            .filter(|r| r.sr_id == s.sr_id)
            .map(|r| (r.period_slots, r.offset_slots, r.pucch_resource))
            .collect();
    }

    // --- MAC view of PUCCH / CSI.
    let f2 = phy.pucch.format2;
    let f3 = phy.pucch.format3;
    mac.pucch = PucchMacConfig {
        resource_sets: phy
            .pucch
            .resource_sets
            .iter()
            .map(|s| {
                (
                    s.id,
                    s.resources.clone(),
                    s.max_payload.unwrap_or(if s.id == 0 { 2 } else { 1706 }),
                )
            })
            .collect(),
        resources: phy
            .pucch
            .resources
            .iter()
            .map(|r| {
                let fmt = match r.format {
                    PucchFormat::F0 { .. } => 0,
                    PucchFormat::F1 { .. } => 1,
                    PucchFormat::F2 { .. } => 2,
                    PucchFormat::F3 { .. } => 3,
                    PucchFormat::F4 { .. } => 4,
                };
                (r.id, fmt, pucch_max_bits(r, &f2, &f3))
            })
            .collect(),
        simultaneous_harq_ack_csi: f2.simultaneous_harq_ack_csi,
    };
    mac.csi_reports = phy
        .csi_reports
        .iter()
        .map(|r| CsiReportMacConfig {
            period_slots: r.period_slots,
            offset_slots: r.offset_slots,
            pucch_resource: r.pucch_resource,
            quantity: r.quantity,
            nof_ports: r.nof_ports,
            allowed_ranks: r.allowed_ranks(),
        })
        .collect();
    mac.csi_enabled = !mac.csi_reports.is_empty();
    mac.harq_codebook_dynamic = phy.harq_codebook_dynamic;
    mac.nof_dl_harq = phy.pdsch.nof_harq_processes.max(1);
    (phy, mac)
}

// ---------------------------------------------------------------------------
// Bearers
// ---------------------------------------------------------------------------

fn rlc_setup_of(r: Option<&cg::RlcConfig>, rb: RbId, previous: Option<&RlcSetup>) -> RlcSetup {
    match r {
        Some(cg::RlcConfig::Am { ul, dl }) => RlcSetup::Am {
            sn_len: ul.sn_field_length.or(dl.sn_field_length).unwrap_or(12),
            t_poll_retransmit_ms: ul.t_poll_retransmit_ms as u32,
            poll_pdu: ul.poll_pdu,
            poll_byte: ul.poll_byte_kb.map(|kb| kb * 1000),
            max_retx: ul.max_retx_threshold as u32,
            t_reassembly_ms: dl.t_reassembly_ms as u32,
            t_status_prohibit_ms: dl.t_status_prohibit_ms as u32,
        },
        Some(cg::RlcConfig::UmBiDirectional { ul, dl }) => RlcSetup::Um {
            sn_len: ul.sn_field_length.or(dl.sn_field_length).unwrap_or(6),
            t_reassembly_ms: dl.t_reassembly_ms as u32,
        },
        Some(cg::RlcConfig::UmUniDirectionalUl { ul }) => RlcSetup::Um {
            sn_len: ul.sn_field_length.unwrap_or(6),
            t_reassembly_ms: 35,
        },
        Some(cg::RlcConfig::UmUniDirectionalDl { dl }) => RlcSetup::Um {
            sn_len: dl.sn_field_length.unwrap_or(6),
            t_reassembly_ms: dl.t_reassembly_ms as u32,
        },
        // rlc-Config is "Need M": absent for a bearer the UE already has means
        // keep the previous configuration (e.g. the reconfiguration after a
        // re-establishment). Otherwise the TS 38.331 §9.2.1 SRB defaults.
        None => match (previous, rb) {
            (Some(p), _) => p.clone(),
            (None, RbId::Srb(_) | RbId::Drb(_)) => RlcSetup::Am {
                sn_len: 12,
                t_poll_retransmit_ms: 45,
                poll_pdu: None,
                poll_byte: None,
                max_retx: 8,
                t_reassembly_ms: 35,
                t_status_prohibit_ms: 0,
            },
        },
    }
}

/// Bearer setups from the RLC bearers of a cell group and the PDCP/SDAP
/// parameters of a `RadioBearerConfig` (when the message carries one).
fn bearers_of(
    c: &cg::CellGroupConfig,
    rbc: Option<&rrc::RadioBearerConfig>,
    previous: &std::collections::BTreeMap<u8, RlcSetup>,
) -> Vec<BearerSetup> {
    let mut out = Vec::new();
    for b in &c.rlc_bearer_to_add_mod_list {
        let rb = match b.served_radio_bearer {
            Some(cg::ServedRadioBearer::Srb(n)) => RbId::Srb(n),
            Some(cg::ServedRadioBearer::Drb(n)) => RbId::Drb(n),
            None => continue,
        };
        let rlc = rlc_setup_of(
            b.rlc_config.as_ref(),
            rb,
            previous.get(&b.logical_channel_identity),
        );
        let mut setup = BearerSetup {
            lcid: b.logical_channel_identity,
            rb,
            rlc,
            pdcp_sn_len: 12,
            pdcp_integrity: matches!(rb, RbId::Srb(_)),
            sdap_header_ul: false,
            sdap_header_dl: false,
            pdu_session: None,
            qfi: 0,
            t_reordering_ms: None,
            discard_timer_ms: None,
            reestablish_pdcp: false,
            reestablish_rlc: b.reestablish_rlc,
        };
        if let Some(rbc) = rbc {
            match rb {
                RbId::Srb(id) => {
                    if let Some(s) = rbc
                        .srb_to_add_mod_list
                        .iter()
                        .find(|s| s.srb_identity == id)
                    {
                        setup.t_reordering_ms = s
                            .pdcp_config
                            .as_ref()
                            .and_then(|p| p.t_reordering_ms)
                            .map(u32::from);
                        setup.reestablish_pdcp = s.reestablish_pdcp;
                    }
                }
                RbId::Drb(id) => {
                    if let Some(d) = rbc
                        .drb_to_add_mod_list
                        .iter()
                        .find(|d| d.drb_identity == id)
                    {
                        setup.reestablish_pdcp = d.reestablish_pdcp;
                        if let Some(p) = &d.pdcp_config {
                            setup.t_reordering_ms = p.t_reordering_ms.map(u32::from);
                            if let Some(drb) = &p.drb {
                                setup.pdcp_sn_len =
                                    drb.pdcp_sn_size_ul.or(drb.pdcp_sn_size_dl).unwrap_or(12);
                                setup.pdcp_integrity = drb.integrity_protection;
                                setup.discard_timer_ms = match drb.discard_timer {
                                    Some(rrc::PdcpDiscardTimer::Ms(ms)) => Some(ms as u32),
                                    _ => None,
                                };
                            }
                        }
                        if let Some(rrc::CnAssociation::SdapConfig(s)) = &d.cn_association {
                            setup.pdu_session = Some(s.pdu_session);
                            setup.sdap_header_ul = s.sdap_header_ul_present;
                            setup.sdap_header_dl = s.sdap_header_dl_present;
                            setup.qfi = s.mapped_qos_flows_to_add.first().copied().unwrap_or(0);
                        }
                    }
                }
            }
        }
        out.push(setup);
    }
    out
}

// ---------------------------------------------------------------------------
// DL message decoding
// ---------------------------------------------------------------------------

/// The per-BWP configurations a `CellGroupConfig` leaves the UE with, and
/// the active one (TS 38.331 `firstActiveDownlinkBWP-Id`, else the BWP that
/// was active before).
#[derive(Clone, Debug)]
pub struct BwpConfigs {
    /// `(PhyConfig, MacConfig)` per DL BWP id (the UL BWP with the same id is
    /// paired with it, the initial UL BWP when there is none).
    pub by_id: std::collections::BTreeMap<u8, (PhyConfig, MacConfig)>,
    pub active_id: u8,
    pub active: (PhyConfig, MacConfig),
}

/// Apply the delta `c` to every BWP the UE knows (the ones in `cell.bwps`
/// plus the ones `c` adds), starting a new BWP from the common configuration.
pub fn cell_group_bwps(cell: &CellInfo, c: &cg::CellGroupConfig) -> BwpConfigs {
    let mut ids: std::collections::BTreeSet<u8> = cell.bwps.keys().copied().collect();
    ids.insert(0);
    ids.extend(c.dl_bwp_ids());
    let ul_ids = c.ul_bwp_ids();
    let mut by_id = std::collections::BTreeMap::new();
    for id in ids {
        let (base_phy, base_mac) = match cell.bwps.get(&id) {
            Some((p, m)) => (p, m),
            None if id == cell.phy.dl_bwp.id => (&cell.phy, &cell.mac),
            None => (&cell.common_phy, &cell.common_mac),
        };
        let ul_id = if id == 0
            || ul_ids.contains(&id)
            || cell.bwps.get(&id).is_some_and(|(p, _)| p.ul_bwp.id == id)
        {
            id
        } else {
            0
        };
        by_id.insert(id, apply_cell_group_bwp(base_phy, base_mac, c, id, ul_id));
    }
    let active_id = c
        .serving_cell()
        .and_then(|s| s.first_active_downlink_bwp_id)
        .filter(|id| by_id.contains_key(id))
        .unwrap_or(cell.phy.dl_bwp.id);
    let active = by_id
        .get(&active_id)
        .or_else(|| by_id.get(&0))
        .cloned()
        .expect("BWP 0 is always present");
    BwpConfigs {
        by_id,
        active_id,
        active,
    }
}

/// Msg4: `DL-CCCH-Message`.
pub fn decode_dl_ccch(pdu: &[u8], cell: &CellInfo, _tx_lead: u16) -> Result<DlCcch, String> {
    match rrc::DlCcchMessage::decode(pdu).map_err(err("DL-CCCH"))? {
        rrc::DlCcchMessage::RrcReject(_) => Ok(DlCcch::Reject),
        rrc::DlCcchMessage::RrcSetup(s) => {
            let bwps = cell_group_bwps(cell, &s.master_cell_group);
            let (phy, mac) = bwps.active.clone();
            let bearers = bearers_of(
                &s.master_cell_group,
                Some(&s.radio_bearer_config),
                &cell.rlc_bearers,
            );
            Ok(DlCcch::Setup {
                tid: s.rrc_transaction_identifier,
                phy,
                mac,
                bearers,
                bwps,
            })
        }
    }
}

/// `DL-DCCH-Message` (a PDCP SDU on SRB1/2).
pub fn decode_dl_dcch(pdu: &[u8], cell: &CellInfo, _tx_lead: u16) -> Result<DlDcch, String> {
    Ok(
        match rrc::DlDcchMessage::decode(pdu).map_err(err("DL-DCCH"))? {
            rrc::DlDcchMessage::RrcReconfiguration(r) => {
                let cgc = r.master_cell_group();
                let bwps = cgc.map(|c| cell_group_bwps(cell, c));
                let (phy, mac) = match &bwps {
                    Some(b) => (Some(b.active.0.clone()), Some(b.active.1.clone())),
                    None => (None, None),
                };
                let bearers = cgc
                    .map(|c| bearers_of(c, r.radio_bearer_config.as_ref(), &cell.rlc_bearers))
                    .unwrap_or_default();
                let released = cgc
                    .map(|c| c.rlc_bearer_to_release_list.clone())
                    .unwrap_or_default();
                DlDcch::Reconfiguration {
                    tid: r.rrc_transaction_identifier,
                    phy,
                    mac,
                    bearers,
                    released,
                    nas: r.dedicated_nas_messages().to_vec(),
                    meas: r.meas_config.clone(),
                    bwps,
                }
            }
            rrc::DlDcchMessage::SecurityModeCommand(m) => {
                let a = &m.security_algorithm_config;
                DlDcch::SecurityModeCommand {
                    tid: m.rrc_transaction_identifier,
                    integrity_alg: a.integrity_prot_algorithm.map_or(0, |i| i as u8),
                    ciphering_alg: a.ciphering_algorithm as u8,
                }
            }
            rrc::DlDcchMessage::UeCapabilityEnquiry(m) => DlDcch::UeCapabilityEnquiry {
                tid: m.rrc_transaction_identifier,
            },
            rrc::DlDcchMessage::DlInformationTransfer(m) => DlDcch::DlInformationTransfer {
                nas: m.dedicated_nas_message,
            },
            rrc::DlDcchMessage::RrcRelease(_) => DlDcch::Release,
            rrc::DlDcchMessage::RrcReestablishment(m) => DlDcch::Reestablishment {
                tid: m.rrc_transaction_identifier,
                ncc: m.next_hop_chaining_count,
            },
            rrc::DlDcchMessage::CounterCheck(_) => DlDcch::Other("CounterCheck"),
        },
    )
}

// ---------------------------------------------------------------------------
// UL message encoding
// ---------------------------------------------------------------------------

fn cause_of(cause: u8) -> rrc::EstablishmentCause {
    use rrc::EstablishmentCause as C;
    match cause {
        0 => C::Emergency,
        1 => C::HighPriorityAccess,
        2 => C::MtAccess,
        4 => C::MoData,
        5 => C::MoVoiceCall,
        6 => C::MoVideoCall,
        7 => C::MoSms,
        8 => C::MpsPriorityAccess,
        9 => C::McsPriorityAccess,
        _ => C::MoSignalling,
    }
}

/// `RRCSetupRequest` with a 39-bit random identity: the 6-octet CCCH SDU.
/// `RRCSetupRequest`: `s_tmsi_part1` = the 39 LSBs of the 5G-S-TMSI when the
/// UE has one (§5.3.3.3), else `random_id`.
pub fn encode_setup_request(random_id: u64, s_tmsi_part1: Option<u64>, cause: u8) -> [u8; 6] {
    let ue_identity = match s_tmsi_part1 {
        Some(v) => rrc::InitialUeIdentity::Ng5gSTmsiPart1(v & ((1 << 39) - 1)),
        None => rrc::InitialUeIdentity::RandomValue(random_id & ((1 << 39) - 1)),
    };
    let pdu = rrc::UlCcchMessage::RrcSetupRequest(rrc::RrcSetupRequest {
        ue_identity,
        establishment_cause: cause_of(cause),
    })
    .encode();
    let mut out = [0u8; 6];
    out[..pdu.len().min(6)].copy_from_slice(&pdu[..pdu.len().min(6)]);
    out
}

/// `RRCSetupComplete`: `s_tmsi` carries the 9 MSBs (`ng-5G-S-TMSI-Part2`)
/// when the request used `ng-5G-S-TMSI-Part1`.
pub fn encode_setup_complete(
    tid: u8,
    selected_plmn: u8,
    nas: &[u8],
    s_tmsi: Option<u64>,
) -> Vec<u8> {
    rrc::UlDcchMessage::RrcSetupComplete(rrc::RrcSetupComplete {
        rrc_transaction_identifier: tid,
        selected_plmn_identity: selected_plmn.max(1),
        registered_amf: None,
        guami_type: None,
        s_nssai_list: Vec::new(),
        dedicated_nas_message: nas.to_vec(),
        ng_5g_s_tmsi_value: s_tmsi.map(|v| rrc::Ng5gSTmsiValue::Part2(((v >> 39) & 0x1ff) as u16)),
    })
    .encode()
}

pub fn encode_security_mode_complete(tid: u8) -> Vec<u8> {
    rrc::UlDcchMessage::SecurityModeComplete {
        rrc_transaction_identifier: tid,
    }
    .encode()
}

pub fn encode_security_mode_failure(tid: u8) -> Vec<u8> {
    rrc::UlDcchMessage::SecurityModeFailure {
        rrc_transaction_identifier: tid,
    }
    .encode()
}

pub fn encode_reconfiguration_complete(tid: u8) -> Vec<u8> {
    rrc::UlDcchMessage::RrcReconfigurationComplete {
        rrc_transaction_identifier: tid,
    }
    .encode()
}

pub fn encode_ue_capability_information(tid: u8, bands: &[u16]) -> Vec<u8> {
    let bands: Vec<u16> = if bands.is_empty() {
        vec![78]
    } else {
        bands.to_vec()
    };
    // The modem does 256-QAM in both directions (PDSCH demapper, PUSCH mapper).
    let container = rrc::UeNrCapability {
        access_stratum_release: rrc::AccessStratumRelease::Rel15,
        supported_band_list_nr: bands,
        pdsch_256qam_fr1: true,
        pusch_256qam: true,
        drx: true,
    }
    .encode();
    rrc::UlDcchMessage::UeCapabilityInformation(rrc::UeCapabilityInformation {
        rrc_transaction_identifier: tid,
        ue_capability_rat_container_list: vec![rrc::UeCapabilityRatContainer {
            rat_type: rrc::RatType::Nr,
            container,
        }],
    })
    .encode()
}

/// `RRCReestablishmentRequest` (SRB0, 48-bit CCCH): `short_mac_i` from
/// [`short_mac_i`], `cause` 0 = reconfigurationFailure, 1 = handoverFailure,
/// 2 = otherFailure.
pub fn encode_reestablishment_request(
    c_rnti: u16,
    pci: u16,
    short_mac_i: u16,
    cause: u8,
) -> [u8; 6] {
    let reestablishment_cause = match cause {
        0 => rrc::ReestablishmentCause::ReconfigurationFailure,
        1 => rrc::ReestablishmentCause::HandoverFailure,
        _ => rrc::ReestablishmentCause::OtherFailure,
    };
    let pdu = rrc::UlCcchMessage::RrcReestablishmentRequest(rrc::RrcReestablishmentRequest {
        c_rnti,
        phys_cell_id: pci,
        short_mac_i,
        reestablishment_cause,
    })
    .encode();
    let mut out = [0u8; 6];
    out[..pdu.len().min(6)].copy_from_slice(&pdu[..pdu.len().min(6)]);
    out
}

/// `shortMAC-I` (TS 38.331 §5.3.7.4): the 16 LSBs of the MAC-I computed with
/// the current K_RRCint / integrity algorithm over the UPER-encoded
/// `VarShortMAC-Input { sourcePhysCellId, targetCellIdentity, source-c-RNTI }`
/// with COUNT = 2^32 − 1, BEARER = 31 and DIRECTION = 1.
pub fn short_mac_i(
    k_rrc_int: &[u8; 16],
    integrity_alg: ferrite_security::IntegrityAlg,
    source_pci: u16,
    target_cell_identity: u64,
    source_c_rnti: u16,
) -> u16 {
    let mut w = ferrite_asn1::uper::BitWriter::new();
    w.uint(u32::from(source_pci), 0, 1007);
    w.bitstring(target_cell_identity & ((1 << 36) - 1), 36);
    w.uint(u32::from(source_c_rnti), 0, 65535);
    let input = w.finish();
    let mac =
        ferrite_security::integrity_mac(integrity_alg, k_rrc_int, 0xffff_ffff, 0x1f, 1, &input)
            .unwrap_or([0u8; 4]);
    u16::from_be_bytes([mac[2], mac[3]])
}

/// `RRCReestablishmentComplete` on SRB1.
pub fn encode_reestablishment_complete(tid: u8) -> Vec<u8> {
    rrc::UlDcchMessage::RrcReestablishmentComplete {
        rrc_transaction_identifier: tid,
    }
    .encode()
}

pub use ferrite_security::kdf::k_ng_ran_star;

/// `MeasurementReport` on SRB1.
pub fn encode_measurement_report(results: &ferrite_asn1::meas::MeasResults) -> Vec<u8> {
    rrc::UlDcchMessage::MeasurementReport(results.clone()).encode()
}

pub fn encode_ul_information_transfer(nas: &[u8]) -> Vec<u8> {
    rrc::UlDcchMessage::UlInformationTransfer(rrc::UlInformationTransfer {
        dedicated_nas_message: Some(nas.to_vec()),
    })
    .encode()
}
