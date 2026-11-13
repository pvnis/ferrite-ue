# Ferrite UE backlog

Functional gaps relative to a full-featured software UE (reference point:
OAI `nr-uesoftmodem`), as assessed on 2026-11-13 after the first end-to-end
attaches against OCUDU over ZMQ. Items are grouped by layer and ordered by
the value they add for interoperating with a stock gNB. Status legend:
`[ ]` open, `[~]` in progress, `[x]` done (date).

Over-the-air items are listed last and are deliberately deferred until an
SDR is on the bench; nothing in the other groups may assume the ZMQ
transport (see `ARCHITECTURE.md`, radio backend section).

## PHY / L1

- [x] 2026-11-13 Lockstep uplink pacing at 15 kHz: the ZMQ gNB sends at most
      ~1 ms of DL beyond the UL it has received; the UL serve is now gated by
      an explicit commit mark (UL index up to which every UL_TTI request has
      been built) instead of "one slot behind the DL position".
- [x] 2026-11-13 PUSCH 16/64/256-QAM (the mapper was QPSK-only; the TDD test
      configs hid it with `max_ue_mcs: 9`).
- [x] 2026-11-13 Phantom DCIs: a CORESET#0 PDCCH was decoded a second time
      through an overlapping UE-specific candidate on CORESET#1 and read with
      the USS field layout (phantom PDSCH grants on F1; "UCI-only PUSCH"
      grants on F2 — OCUDU never sends `ul-sch = 0`). Common search spaces
      are decoded first and a repeated payload for the same RNTI is ignored.
- [x] 2026-11-13 Late HARQ-ACKs: the engine could reach the PUCCH-building
      slot before the PDSCH worker had answered when the DL arrived in
      bursts; it now waits for outstanding results before each SLOT.indication.
- [ ] PUSCH without UL-SCH (DCI 0_1 `ul-sch` = 0): UCI-only PUSCH with the
      §6.3.2.4 rate matching (not scheduled by OCUDU; needed for other gNBs).
- [ ] HARQ soft combining per code block in the PDSCH worker (currently
      single-CB).
- [ ] PUSCH with 1 DM-RS CDM group without data (data on the odd subcarriers
      of DM-RS symbols).
- [ ] Double-symbol DM-RS (`maxLength = 2`), DL and UL.
- [ ] PUSCH frequency hopping (intra-slot); MAC currently refuses the grant.
- [ ] PT-RS (DL reception, UL insertion) when configured.
- [ ] SRS transmission (periodic / aperiodic).
- [ ] PUCCH formats 3 and 4.
- [ ] Transform precoding (DFT-s-OFDM) PUSCH transmit path; the MCS table
      exists, the modulator does not.
- [ ] Two-layer PDSCH (2x2 DL MIMO), multi-antenna receive, RI/PMI in the CSI
      report (type-I single-panel codebook).
- [ ] FR2: 120 kHz numerology, beam management (SSB/CSI-RS beam reports).

## MAC

- [x] 2026-11-13 PHR MAC CE (periodic / prohibit timers, pathloss-change
      trigger; values from a `PowerHeadroom` input, nominal until OTA power
      control exists).
- [ ] Connected-mode DRX (the ASN.1 is parsed; MAC ignores it).
- [ ] BWP switching (DCI and timer based).
- [ ] 2-step random access.

## RRC

- [x] 2026-11-13 `measConfig` decode, SSB-based RSRP/RSRQ/SINR, L3 filtering,
      periodical reports and serving-cell events A1/A2; verified against
      OCUDU's periodical serving-cell report (S16).
- [ ] Neighbour cell search (intra-frequency PCI detection on the serving
      SSB raster) so that A3–A6 can trigger and reports carry
      `measResultNeighCells`.
- [x] 2026-11-13 RRC release to idle, paging reception (PF/PO from SIB1 +
      5G-S-TMSI), Service Request for uplink data (mo-Data, S14) and on
      paging (mt-Access, S17; AS keys re-derived from the Service Request's
      NAS COUNT). Note: OCUDU's DU never schedules paging on the T1 TDD
      pattern (its paging look-ahead slot is an UL slot); F1 and T2 page.
- [ ] RRC release with `suspendConfig` (RRC_INACTIVE) and RRCResume.
- [x] 2026-11-13 RRC re-establishment after radio link failure (shortMAC-I,
      horizontal K_NG-RAN*, SRB1 re-establishment with the refreshed keys,
      default L1/MAC config until the reconfiguration, RLC renewed and PDCP
      state kept for the other bearers, fallback to RRCSetup handled as a
      lost connection): S19 passes with an injected RLF, 12/12 pings across
      it. Vertical (NH/NCC) key derivation still missing.
- [x] 2026-11-13 Bearer reconfiguration keeps state: an `RLC-BearerConfig`
      without `rlc-Config` keeps the previous RLC mode; a re-listed bearer
      keeps its PDCP COUNTs unless `reestablishPDCP`.
- [x] 2026-11-13 PRACH transmitted with N_TA = 0 (TS 38.211 §4.3.1) and the
      PHY timing advance reset on MAC reset (re-establishment / idle RAs
      were early by the old TA).
- [ ] RRC resume (RRC_INACTIVE).
- [ ] Handover: `reconfigurationWithSync` (intra-frequency first).
- [x] 2026-11-13 System information beyond SIB1: `SystemInformation` decode
      with SIB2 / SIB3 structured and SIB10+ (e.g. SIB19) raw; SIB2 acquired
      live on T1 (S18). SIB4–SIB9 decoders still missing (a message carrying
      one is rejected).
- [x] 2026-11-13 256-QAM both ways with OCUDU's qam256 tables: the uplink
      failures were the PRACH-only guard leaving the UL 1 µs early (fixed by
      the uplink guard, gNB `t_align = 0.00 µs`); the downlink failures were
      2-PRB MCS-27 blocks in TRS slots because a later reconfiguration wiped
      the CSI-RS rate-match patterns (`apply_cell_group` replaced the lists;
      now add/mod/release deltas by resource id, same for CSI report configs).
- [~] UE capability: `UE-NR-Capability` now advertises 256-QAM (PDSCH FR1,
      PUSCH per band) and OCUDU switches to the qam256 tables (F1 config);
      MIMO / DM-RS / PUCCH-format fields still minimal.

## NAS / upper layers

- [ ] IPv6 and IPv4v6 PDU sessions end to end (NAS plumbed, TUN untested).
- [ ] Multiple concurrent PDU sessions with separate TUN routing.
- [ ] SDAP reflective QoS / QFI mapping beyond the default bearer.
- [ ] Periodic registration update (T3512) and service request from idle.

## Tooling / hygiene

- [x] 2026-11-13 Removed the `max_ue_mcs` caps from the TDD test configs
      (whole matrix runs with link adaptation; 64-QAM both ways).
- [x] 2026-11-13 `lab.sh`: `UE_LOG` filter honoured, S14/S16/S17 stages,
      `DL_PING=1` host-side paging trigger.
- [ ] Warning and clippy cleanup (`left` in `ferrite-mac/src/entity.rs`,
      irrefutable `if let` in `ferrite-ue/src/stack.rs`).
- [ ] README update for the layered crates.
- [ ] Lab matrix in CI form (gNB + qcore scripted, pass/fail from `lab.sh`).

## Over the air (deferred until an SDR is on the bench)

- [ ] Wire the SoapySDR (seify) backend into the `ferrite-ue` binary
      (`--radio sdr`), with the free-running `UlPacing`.
- [ ] UL power control: P0/alpha open loop, TPC accumulation, PRACH power
      ramping, PUCCH/PUSCH/SRS power per TS 38.213 §7.
- [ ] Receive AGC.
- [ ] Connected-mode CFO and timing tracking beyond TA commands.
- [ ] TX/RX sample offset calibration per device (`--tx-rx-offset`).
