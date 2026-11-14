//! Uplink waveform construction: PRACH (TS 38.211 §6.3.3), PUSCH (§6.3.1 +
//! UCI multiplexing TS 38.212 §6.2.7) and PUCCH (§6.3.2) from UL_TTI PDUs.
//!
//! Each builder returns the samples and the UL stream index at which they
//! start, computed from the [`SampleClock`] (slot start − timing advance, plus
//! the symbol offset).

use crate::cell::CellGeometry;
use crate::config::{PhyConfig, PucchFormat, PucchResource};
use crate::fapi::*;
use crate::timing::SampleClock;
use ferrite_common::{slot::ta::tc_to_samples, Iq, SlotPoint};
use ferrite_phy::coding::dlsch::{dlsch_encode, seg_params};
use ferrite_phy::dmrs::{pusch_dmrs_symbols, MappingType};
use ferrite_phy::prach;
use ferrite_phy::prach_config as pc;
use ferrite_phy::pucch;
use ferrite_phy::pusch::{self, PuschAlloc};
use ferrite_phy::Ofdm;

/// TS 38.213 Table 9.2.1-1: common PUCCH resources before dedicated config —
/// (format, first symbol, nof symbols, PRB offset (None = ⌊N_BWP/4⌋), initial CS set).
/// One row of Table 9.2.1-1.
type PucchCommonRow = (u8, u8, u8, Option<u16>, &'static [u8]);
const PUCCH_COMMON: [PucchCommonRow; 16] = [
    (0, 12, 2, Some(0), &[0, 3]),
    (0, 12, 2, Some(0), &[0, 4, 8]),
    (0, 12, 2, Some(3), &[0, 4, 8]),
    (1, 10, 4, Some(0), &[0, 6]),
    (1, 10, 4, Some(0), &[0, 3, 6, 9]),
    (1, 10, 4, Some(2), &[0, 3, 6, 9]),
    (1, 10, 4, Some(4), &[0, 3, 6, 9]),
    (1, 4, 10, Some(0), &[0, 6]),
    (1, 4, 10, Some(0), &[0, 3, 6, 9]),
    (1, 4, 10, Some(2), &[0, 3, 6, 9]),
    (1, 4, 10, Some(4), &[0, 3, 6, 9]),
    (1, 0, 14, Some(0), &[0, 6]),
    (1, 0, 14, Some(0), &[0, 3, 6, 9]),
    (1, 0, 14, Some(2), &[0, 3, 6, 9]),
    (1, 0, 14, Some(4), &[0, 3, 6, 9]),
    (1, 0, 14, None, &[0, 3, 6, 9]),
];

/// `beta_offset_harq_ack` by index (TS 38.213 Table 9.3-1).
fn beta_offset_harq(index: u8) -> f32 {
    const T: [f32; 16] = [
        1.0, 2.0, 2.5, 3.125, 4.0, 5.0, 6.25, 8.0, 10.0, 12.625, 15.875, 20.0, 31.0, 50.0, 80.0,
        126.0,
    ];
    *T.get(index as usize).unwrap_or(&20.0)
}

pub struct UlBuilder {
    pub ofdm: Ofdm,
    pub geom: CellGeometry,
    pub cfg: PhyConfig,
    pub ul_center_hz: f64,
    pub cell_id: u16,
}

/// A built waveform and its absolute UL start index.
pub struct Waveform {
    pub start: i64,
    pub samples: Vec<Iq>,
    pub tag: &'static str,
}

impl UlBuilder {
    pub fn new(geom: CellGeometry, cfg: PhyConfig, ul_center_hz: f64, cell_id: u16) -> Self {
        Self {
            ofdm: Ofdm::new(geom.fft),
            geom,
            cfg,
            ul_center_hz,
            cell_id,
        }
    }

    fn normalise(&self, w: &mut [Iq]) {
        let pk = w.iter().map(|c| c.norm()).fold(0.0f32, f32::max).max(1e-9);
        let g = self.cfg.ul_amplitude / pk;
        for s in w.iter_mut() {
            *s *= g;
        }
    }

    /// PRACH preamble on `occ`.
    pub fn prach(
        &self,
        clock: &SampleClock,
        occ: &PrachOccasion,
        preamble: u8,
        _power_offset_db: f32,
    ) -> Result<Waveform, String> {
        let p = &self.cfg.prach;
        let params = p
            .phy
            .format_params(occ.time_index)
            .map_err(|e| format!("{e:?}"))?;
        let fm = pc::prach_frequency_mapping(params.delta_f_ra_hz, self.geom.numerology.mu)
            .map_err(|e| format!("{e:?}"))?;
        // UL BWP start relative to the UL stream centre, in PUSCH-SCS RBs.
        let bwp_start_rel = self.cfg.ul_bwp.start_crb as i32
            - self.geom.ul.offset_crb as i32
            - self.geom.ul.n_rb as i32 / 2;
        let first_sc = pc::prach_subcarrier_offset(
            &fm,
            p.phy.msg1_frequency_start,
            occ.freq_index,
            bwp_start_rel,
        );
        let restricted = match p.restricted_set {
            0 => prach::RestrictedSet::Unrestricted,
            1 => prach::RestrictedSet::TypeA,
            _ => prach::RestrictedSet::TypeB,
        };
        let mut w = prach::prach_preamble_waveform(
            params.format,
            self.geom.numerology.mu,
            p.root_sequence_index,
            preamble,
            p.zero_correlation_zone,
            restricted,
            self.geom.fs,
            first_sc,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.normalise(&mut w);
        // Occasion start: `start_tc` from the subframe start (TS 38.211 §5.3.2).
        let subframe_slot = occ.slot.sub(occ.slot.slot_in_subframe() as u64);
        // TS 38.211 §4.3.1: the PRACH is transmitted with N_TA = 0 (the
        // uplink guard and N_TA_offset still apply); the RAR's TA command is
        // what sets N_TA for the connection.
        let start = clock.with_n_ta(0).ul_index(subframe_slot)
            + tc_to_samples(occ.start_tc as i64, self.geom.fs);
        Ok(Waveform {
            start,
            samples: w,
            tag: "prach",
        })
    }

    /// PUSCH for `grant` carrying `tb` (+ UCI).
    pub fn pusch(
        &self,
        clock: &SampleClock,
        grant: &UlGrant,
        tb: &[u8],
        uci: &UciPayload,
    ) -> Result<Waveform, String> {
        let mapping = if grant.time.mapping_type_a {
            MappingType::TypeA
        } else {
            MappingType::TypeB
        };
        let dmrs = pusch_dmrs_symbols(
            mapping,
            self.cfg.ssb.dmrs_typea_pos,
            grant.dmrs_add_pos,
            grant.time.start_symbol as usize,
            grant.time.n_symbols as usize,
        )
        .map_err(|e| format!("{e:?}"))?;
        if grant.cdm_groups_wo_data != 2 {
            // The modulator leaves DM-RS symbols empty of data (2 CDM groups w/o data);
            // 1-group mapping would need data on the odd subcarriers.
            return Err(
                "PUSCH with 1 CDM group without data is not supported by the modulator".into(),
            );
        }
        if grant.transform_precoding.is_some() && !pusch::tp_prb_valid(grant.n_prb as usize) {
            return Err(format!(
                "transform-precoded PUSCH over {} PRBs (not 2^a·3^b·5^c)",
                grant.n_prb
            ));
        }
        let alloc = PuschAlloc {
            rb_start: (self.cfg.ul_bwp.start_crb as usize + grant.prb_start as usize)
                .checked_sub(self.geom.ul.offset_crb as usize)
                .ok_or("UL BWP starts below the UL carrier")?,
            n_rb: grant.n_prb as usize,
            sym_start: grant.time.start_symbol as usize,
            n_sym: grant.time.n_symbols as usize,
            dmrs_symbols: dmrs,
            qm: grant.mcs.qm as usize,
            carrier_rb: self.geom.ul.n_rb as usize,
            crb_offset: self.geom.ul.offset_crb as usize,
            transform_precoding: grant
                .transform_precoding
                .map(|t| pusch::TransformPrecoding {
                    n_id_rs: t.n_id_rs,
                    group_hopping: t.group_hopping,
                    sequence_hopping: t.sequence_hopping,
                }),
        };
        let r_x1024 = grant
            .mcs
            .r_x1024
            .ok_or("reserved MCS without a stored code rate")?;
        let r = r_x1024 as f64 / 1024.0;
        let tbs_bits = grant.tbs_bits as usize;
        let bits: Vec<u8> = tb
            .iter()
            .flat_map(|&b| (0..8).map(move |i| (b >> (7 - i)) & 1))
            .collect();
        if bits.len() != tbs_bits {
            return Err(format!(
                "TB is {} bits, grant TBS is {tbs_bits}",
                bits.len()
            ));
        }
        let beta_ack = self
            .cfg
            .pusch
            .beta_offsets
            .map_or(20.0, |b| beta_offset_harq(b.ack_index1));
        let beta_csi = self
            .cfg
            .pusch
            .beta_offsets
            .map_or(6.25, |b| pusch::beta_offset_csi(b.csi1_index1));
        let alpha = [0.5, 0.65, 0.8, 1.0][self.cfg.pusch.uci_scaling as usize & 3];
        let mut e = pusch::pusch_e_len(&alloc);
        let csi_res: Vec<(usize, usize)> = if uci.csi1.is_empty() {
            Vec::new()
        } else {
            let sp = seg_params(tbs_bits, r);
            pusch::csi1_pusch_res(
                &alloc.dmrs_symbols,
                (alloc.sym_start, alloc.n_sym),
                alloc.n_rb,
                uci.csi1.len(),
                beta_csi,
                alpha,
                sp.c * sp.k,
            )
        };
        e = e
            .checked_sub(alloc.qm * csi_res.len())
            .ok_or("CSI part 1 does not fit the PUSCH")?;
        let ulsch = dlsch_encode(&bits, e, r, alloc.qm, grant.rv);
        let slot = grant.pusch_slot;
        let mut w = pusch::pusch_modulate_slot_uci_csi(
            &self.ofdm,
            &ulsch,
            &alloc,
            self.cell_id,
            slot.slot as u32,
            slot.slot_in_subframe() as usize,
            self.geom.numerology.mu,
            grant.rnti.0,
            self.ul_center_hz,
            self.geom.fs,
            &uci.harq_ack,
            beta_ack,
            tbs_bits,
            &uci.csi1,
            &csi_res,
        );
        self.normalise(&mut w);
        Ok(Waveform {
            start: clock.ul_index(slot),
            samples: w,
            tag: if grant.transform_precoding.is_some() {
                "pusch-tp"
            } else {
                "pusch"
            },
        })
    }

    /// Resolve a PUCCH resource reference to a concrete resource.
    fn pucch_resource(&self, r: PucchResourceRef) -> Option<PucchResource> {
        match r {
            PucchResourceRef::Dedicated(id) => self
                .cfg
                .pucch
                .resources
                .iter()
                .find(|x| x.id == id)
                .copied(),
            PucchResourceRef::Common { r_pucch } => {
                let row = PUCCH_COMMON[self.cfg.pucch.resource_common.unwrap_or(11) as usize & 15];
                let n_bwp = self.cfg.ul_bwp.n_rb;
                let rb_off = row.3.unwrap_or(n_bwp / 4);
                let n_cs = row.4.len() as u16;
                let r = r_pucch as u16;
                // TS 38.213 §9.2.1: the two hops mirror around the BWP; a BWP too
                // narrow for the row has no such resource.
                let mirror = |x: u16| n_bwp.checked_sub(1 + rb_off + x);
                let (prb1, prb2, cs) = if r / 8 == 0 {
                    (
                        rb_off + r / n_cs,
                        mirror(r / n_cs)?,
                        row.4[(r % n_cs) as usize],
                    )
                } else {
                    let r8 = r - 8;
                    (
                        mirror(r8 / n_cs)?,
                        rb_off + r8 / n_cs,
                        row.4[(r8 % n_cs) as usize],
                    )
                };
                let format = if row.0 == 0 {
                    PucchFormat::F0 {
                        initial_cyclic_shift: cs,
                    }
                } else {
                    PucchFormat::F1 {
                        initial_cyclic_shift: cs,
                        time_domain_occ: 0,
                    }
                };
                Some(PucchResource {
                    id: 255,
                    starting_prb: prb1,
                    second_hop_prb: Some(prb2),
                    format,
                    start_symbol: row.1,
                    n_symbols: row.2,
                })
            }
        }
    }

    /// PUCCH in `slot` on `resource` with `uci`.
    pub fn pucch(
        &self,
        clock: &SampleClock,
        slot: SlotPoint,
        resource: PucchResourceRef,
        uci: &UciPayload,
        crnti: u16,
    ) -> Result<Waveform, String> {
        let res = self
            .pucch_resource(resource)
            .ok_or("unknown PUCCH resource")?;
        let n_id = self.cfg.pucch.hopping_id.unwrap_or(self.cell_id);
        let bwp0 = (self.cfg.ul_bwp.start_crb as usize)
            .checked_sub(self.geom.ul.offset_crb as usize)
            .ok_or("UL BWP starts below the UL carrier")?;
        let carrier_rb = self.geom.ul.n_rb as usize;
        let mu = self.geom.numerology.mu;
        let sr = uci.sr == Some(true);
        let w = match res.format {
            PucchFormat::F0 {
                initial_cyclic_shift,
            } => {
                let cfg = pucch::PucchF0 {
                    prb: bwp0 + res.starting_prb as usize,
                    second_hop_prb: res.second_hop_prb.map(|p| bwp0 + p as usize),
                    start_symbol: res.start_symbol as usize,
                    nof_symbols: res.n_symbols as usize,
                    init_cyclic_shift: initial_cyclic_shift as usize,
                    n_id,
                    carrier_rb,
                };
                pucch::pucch_f0_modulate_slot(
                    &self.ofdm,
                    &cfg,
                    &uci.harq_ack,
                    sr,
                    slot.slot as u32,
                    mu,
                    self.ul_center_hz,
                    self.geom.fs,
                )
                .ok_or("F0 UCI combination unsupported")?
            }
            PucchFormat::F1 {
                initial_cyclic_shift,
                time_domain_occ,
            } => {
                let cfg = pucch::PucchF1 {
                    prb1: bwp0 + res.starting_prb as usize,
                    prb2: bwp0 + res.second_hop_prb.unwrap_or(res.starting_prb) as usize,
                    start_symbol: res.start_symbol as usize,
                    nof_symbols: res.n_symbols as usize,
                    init_cyclic_shift: initial_cyclic_shift as usize,
                    occ_index: time_domain_occ as usize,
                    n_id,
                    carrier_rb,
                };
                // F1: 1-2 HARQ-ACK bits, or an empty payload = positive SR.
                let bits: &[u8] = if uci.harq_ack.is_empty() {
                    &[]
                } else {
                    &uci.harq_ack[..uci.harq_ack.len().min(2)]
                };
                pucch::pucch_f1_modulate_slot(
                    &self.ofdm,
                    &cfg,
                    bits,
                    slot.slot as u32,
                    mu,
                    self.ul_center_hz,
                    self.geom.fs,
                )
            }
            PucchFormat::F2 { n_prb } => {
                let cfg = pucch::PucchF2 {
                    prb_start: bwp0 + res.starting_prb as usize,
                    nof_prb: n_prb as usize,
                    start_symbol: res.start_symbol as usize,
                    nof_symbols: res.n_symbols as usize,
                    rnti: crnti,
                    n_id: self.cell_id,
                    n_id0: self.cell_id,
                    carrier_rb,
                };
                // UCI bit order (TS 38.212 §6.3.1.1): HARQ-ACK, SR, CSI part 1.
                let mut bits = uci.harq_ack.clone();
                if let Some(s) = uci.sr {
                    bits.push(u8::from(s));
                }
                bits.extend_from_slice(&uci.csi1);
                if bits.len() < 3 || bits.len() > 11 {
                    return Err(format!(
                        "PUCCH F2 payload of {} bits unsupported",
                        bits.len()
                    ));
                }
                pucch::pucch_f2_modulate_slot(
                    &self.ofdm,
                    &cfg,
                    &bits,
                    slot.slot as u32,
                    mu,
                    self.ul_center_hz,
                    self.geom.fs,
                )
            }
            PucchFormat::F3 { n_prb } => {
                let cfg = pucch::PucchF3 {
                    prb_start: bwp0 + res.starting_prb as usize,
                    nof_prb: n_prb as usize,
                    start_symbol: res.start_symbol as usize,
                    nof_symbols: res.n_symbols as usize,
                    rnti: crnti,
                    n_id: self.cell_id,
                    hopping_id: self.cfg.pucch.hopping_id.unwrap_or(self.cell_id),
                    additional_dmrs: self.cfg.pucch.format3.additional_dmrs,
                    pi2_bpsk: self.cfg.pucch.format3.pi2_bpsk,
                    carrier_rb,
                };
                let mut bits = uci.harq_ack.clone();
                if let Some(s) = uci.sr {
                    bits.push(u8::from(s));
                }
                bits.extend_from_slice(&uci.csi1);
                if bits.len() < 3 || bits.len() > 11 {
                    return Err(format!("PUCCH F3 payload of {} bits unsupported (polar UCI coding not implemented)", bits.len()));
                }
                pucch::pucch_f3_modulate_slot(
                    &self.ofdm,
                    &cfg,
                    &bits,
                    slot.slot as u32,
                    mu,
                    self.ul_center_hz,
                    self.geom.fs,
                )
                .ok_or("PUCCH F3 configuration unsupported")?
            }
            _ => return Err("PUCCH format 4 not supported".into()),
        };
        let mut w = w;
        self.normalise(&mut w);
        Ok(Waveform {
            start: clock.ul_index(slot),
            samples: w,
            tag: "pucch",
        })
    }

    /// SRS resource `resource_id` in `slot` (TS 38.211 §6.4.1.4).
    pub fn srs(
        &self,
        clock: &SampleClock,
        slot: SlotPoint,
        resource_id: u8,
    ) -> Result<Waveform, String> {
        let r = self
            .cfg
            .srs
            .iter()
            .find(|r| r.id == resource_id)
            .ok_or("unknown SRS resource")?;
        let mut w = ferrite_phy::srs::srs_modulate_slot(
            &self.ofdm,
            &r.params,
            self.geom.ul.n_rb as usize,
            self.geom.ul.offset_crb as usize,
            slot.slot as u32,
            self.geom.numerology.mu,
            self.ul_center_hz,
            self.geom.fs,
        )
        .ok_or("unsupported SRS configuration")?;
        self.normalise(&mut w);
        Ok(Waveform {
            start: clock.ul_index(slot),
            samples: w,
            tag: "srs",
        })
    }
}
