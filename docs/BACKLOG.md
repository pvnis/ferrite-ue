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

- [x] 2026-11-14 Radio link monitoring: one `SYNC.indication` per SSB period
      (out-of-sync below Q_out = −8 dB SSB SINR or SSB missing, in-sync above
      Q_in = −6 dB) through FAPI → MAC → RRC; RRC runs N310 / T310 / N311 with
      the SIB1 `ue-TimersAndConstants` values and declares the RLF on T310
      expiry (re-establishment with security, idle without). The engine only
      gives the cell up (re-search) after 250 missed SSB periods, above any
      T310. Lab stages S23 (`--rlm-outage-s 8 --rlm-outage-ms 1500` → RLF →
      re-established) and S24 (500 ms → T310 stopped by N311).
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
- [x] 2026-11-13 Fallback DCI formats (0_0/1_0) are tried only in search
      spaces that monitor them; a non-fallback USS whose 0_1 has the fallback
      size (the case once SRS is configured) had its 0_1 payloads read with
      the 0_0 layout ("hopping" grants refused, no registration).
- [ ] HARQ soft combining per code block in the PDSCH worker (currently
      single-CB).
- [ ] PUSCH with 1 DM-RS CDM group without data (data on the odd subcarriers
      of DM-RS symbols).
- [ ] Double-symbol DM-RS (`maxLength = 2`), DL and UL.
- [ ] PUSCH frequency hopping (intra-slot); MAC currently refuses the grant.
- [ ] PT-RS (DL reception, UL insertion) when configured.
- [x] 2026-11-13 SRS transmission, periodic resources (comb 2/4, cyclic
      shift, C_SRS/B_SRS table, no hopping): OCUDU detects the sounding
      (EPRE +1.5 dB, t_align 0.2 µs, ~55 dB SINR, S20). Aperiodic /
      semi-persistent SRS and frequency/group hopping still missing.
- [x] 2026-11-13 PUCCH format 3 (DFT-s-OFDM data symbols, low-PAPR DM-RS on
      the Table 6.4.1.3.3.2-1 symbols, additional-DM-RS and π/2-BPSK options,
      RM(32,O) payloads of 3–11 bits): T2 runs OCUDU's `f1_and_f3` layout
      and the gNB decodes 569/570 format-3 occasions (S21). Payloads above
      11 bits (polar-coded UCI) and format 4 (block-wise OCC) are still
      missing.
- [x] 2026-11-14 Transform precoding (DFT-s-OFDM) PUSCH: DFT per data symbol,
      low-PAPR DM-RS with group/sequence hopping, π/2-BPSK rows, Table
      6.1.4.1-1 / antenna-port Table 7.3.1.1.2-6 selection, `msg3-transformPrecoder`
      for RAR / DCI 0_0 and `transformPrecoder` for DCI 0_1 (falls back to the
      Msg3 setting). T3 runs OCUDU with `enable_transform_precoding` (S22,
      98/99 PUSCH CRC OK at 64-QAM). `dataScramblingIdentityPUSCH` is parsed
      but not applied (OCUDU never sets it).
- [ ] Two-layer PDSCH (2x2 DL MIMO). Done 2026-11-14: multi-antenna receive
      path (`DlStream` with one stream per antenna, `--tx a,b`), the
      `codebookConfig` decoder, and the CSI report in the Table 6.3.1.1.2-7
      wideband PUCCH layout with RI 1 / PMI 0 — the two-antenna cell T5
      attaches and pings with antenna 0 (before the layout fix OCUDU read the
      4-bit CQI as RI 2 and scheduled two layers). Also done 2026-11-14: the
      per-antenna / per-port channel estimation and the two-layer MMSE
      demapper (`extract_pdsch_mimo`, loopback-tested on a full-rank 2x2
      channel), DCI 1_1 two-layer antenna ports and TBS, and the
      `ri-Restriction` bit order (LSB = rank 1): T5 stage S28 passes with
      two-layer PDSCHs decoded. Also done 2026-11-14: RI / PMI / CQI from the
      two-port NZP-CSI-RS (row 3, FD-CDM2, measured on every receive antenna)
      with the two-port Type I single-panel codebook (`i2`: rank 1
      `[1, e^{jπn/2}]/√2`, rank 2 `[[1, 1], [e^{jπn/2}, −e^{jπn/2}]]/2`;
      OCUDU logs the raw `i2` as `pmi`), rank chosen by sum spectral
      efficiency with post-MMSE SINRs; the MAC keeps the multi-port rank
      across single-port TRS measurements. T5 S28: gNB receives `ri=2`, 82
      two-layer PDSCHs in a 40 s run. Open: three/four layers, the SDR
      two-channel receive path, and the Sionna RT / TS 38.901 channel
      emulator (step 2).
- [ ] FR2: 120 kHz numerology, beam management (SSB/CSI-RS beam reports).

## MAC

- [x] 2026-11-13 PHR MAC CE (periodic / prohibit timers, pathloss-change
      trigger; values from a `PowerHeadroom` input, nominal until OTA power
      control exists).
- [x] 2026-11-14 Connected-mode DRX (`ferrite-mac/src/drx.rs`): on-duration
      from the long / short cycle, inactivity timer, per-HARQ RTT and
      retransmission timers, DRX / Long DRX Command CEs, Active Time for a
      running RA or pending SR; the PHY stops searching C-RNTI candidates
      (`MacToPhy::PdcchMonitoring`), periodic CSI is skipped outside Active
      Time. T4 (`cell_cfg.drx`) lab stage S25. Two interoperability
      findings against OCUDU, both handled on the UE side as supersets of
      the specified Active Time: (1) its scheduler restarts the inactivity
      timer on retransmission grants too (the UE now does the same);
      (2) its TA manager consumes the `time_advance_offset` of every SRS
      indication, detected or not (`cell_event_manager.cpp`
      `handle_srs_indication`), so the SRS occasions a sleeping UE leaves
      empty yield a −1 TA command per DRX cycle and the uplink leaves the
      CP after ~8 cycles → the UE keeps its periodic SRS during sleep
      (`MacConfig::srs_outside_active_time`). The UE also had to advertise
      `longDRX-Cycle`/`shortDRX-Cycle` in `mac-ParametersXDD-Diff`: OCUDU
      configures DRX only for UEs that do.
- [x] 2026-11-14 BWP switching: per-BWP configurations from
      `CellGroupConfig` (generic parameters, common and dedicated parts,
      `firstActiveDownlinkBWP-Id`), DCI 1_1/0_1 bandwidth-part indicator →
      `Dci::BwpSwitch`, bwp-InactivityTimer → default BWP, random access →
      initial BWP, RRC `switch_bwp` → CONFIG.request. Unit-tested only:
      OCUDU configures one BWP. Known simplification: the grant carried by
      the switching DCI is not resolved (the gNB retransmits on the new BWP).
- [x] 2026-11-14 TDD pattern as a scheduling input: PDSCH in UL symbols /
      PUSCH in DL symbols dropped by the resolver; PRACH occasions filtered
      per TS 38.211 §6.3.3.2 (UL symbols, or flexible symbols after the
      slot's SSBs + N_gap). T1/T2/T3 random access unchanged.
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
- [ ] RRC_INACTIVE: RRC release with `suspendConfig`, RAN paging with the
      I-RNTI, RRCResumeRequest / RRCResume, T380 periodic RNA update.
- [ ] Handover: `reconfigurationWithSync` with T304 (intra-frequency first);
      then conditional handover (`condReconfigToAddModList`, Rel-16).
- [ ] 5GMM context persistence across restarts (GUTI, NAS security context,
      last registered TAI; SQN for the USIM) so a restart does a mobility /
      periodic registration update instead of an initial registration.
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
- [x] 2026-11-14 5GMM substates (`DeregisteredSub` / `RegisteredSub`),
      5GMM-IDLE / CONNECTED from the RRC connection (procedures started in
      idle request a mo-Signalling connection), T3511 / T3502 with the
      attempt counter, T3346 back-off, T3519, T3512 only in idle with the
      periodic registration update (lab S27 with `--t3512-s`), per-cause
      REGISTRATION / SERVICE REJECT handling, network-initiated deregistration
      with re-registration, CONFIGURATION UPDATE "registration requested",
      mobility registration update on a new TAI, NOTIFICATION RESPONSE, PDU
      SESSION MODIFICATION COMPLETE, SERVICE ACCEPT / REJECT events, UE
      deregistration (switch off) at exit (lab S26), NAS clock derived from
      the slot indications. `oxirush-nas` 0.7 (Apache-2.0) is a
      dev-dependency: an independent decoder that validates every uplink
      message in the tests.

## Tooling / hygiene

- [x] 2026-11-13 Removed the `max_ue_mcs` caps from the TDD test configs
      (whole matrix runs with link adaptation; 64-QAM both ways).
- [x] 2026-11-13 `lab.sh`: `UE_LOG` filter honoured, S14/S16/S17 stages,
      `DL_PING=1` host-side paging trigger.
- [x] 2026-11-14 Warning and clippy cleanup: zero warnings with
      `cargo clippy --workspace --all-targets` (range loops over several
      arrays allowed in `ferrite-phy` / `ferrite-l1`).
- [x] 2026-11-14 README update for the layered crates.
- [x] 2026-11-14 Unit tests for `DciResolver` (every format, RAR grant, TDRA
      fallbacks, transform precoding), the RRC state machine
      (`ferrite-rrc/tests/state_machine.rs`: establishment, T300, SMC,
      RLF/T301, release, paging, NAS transport against hand-built UPER
      messages) and the stack glue (`ferrite-ue/tests/stack.rs`: SIB1 →
      CONFIG → registration → PRACH, retry after a failed attempt).
- [x] 2026-11-14 GitHub Actions CI (`.github/workflows/ci.yml`): build,
      clippy, release tests, rustdoc with `-D warnings`.
- [ ] Lab matrix in CI form (gNB + qcore scripted, pass/fail from `lab.sh`):
      needs a runner with OCUDU and qcore installed.

## Architecture audit 2026-11-14 (done)

- [x] 2026-11-14 Layering: `ferrite-ran` (spec tables), `ferrite-fapi` (PHY↔MAC
      messages + PhyConfig) and `ferrite-security` (one NIA/NEA/KDF/MILENAGE
      implementation) split out; MAC and RRC no longer link the DSP crate; the
      RAR UL grant is resolved by the PHY (`MacToPhy::RarGrant`); dead
      `*_legacy.rs` files removed.
- [x] 2026-11-14 UP keys derived with the UP distinguishers (TS 33.501 A.8
      0x05/0x06; were the NAS ones) — verified with NEA2/NIA2 on DRBs (F1).
- [x] 2026-11-14 State machines made explicit: L1 `CellPhase` / `tx_enabled`
      (START/STOP honoured) / `RlmState`; MAC `RaState::Msg3Pending`, `SrState`,
      `TaState` with timeAlignmentTimer expiry (HARQ flush, PRACH-only uplink),
      `MacEvent::{SrFailure, TimeAlignmentExpired}`; RRC `state()` private with
      logged transitions, RRCSetup only while Connecting, RA failure while
      connected = RLF, T301 armed by RRC; stack split into `bearers.rs` /
      `userplane.rs` / `stack.rs` (default DRB derived from the table, NAS
      events drained after ticks, PDU-session-down / deregistration tear the
      user plane down, PDCP security errors logged).
- [x] 2026-11-14 Reachable panics removed: DCI payload larger than the
      candidate, CSS RIV above a dedicated BWP, UL BWP below the carrier, common
      PUCCH on a narrow BWP, ICMP echo with a lying Total Length, PUCCH F0 with
      a bad symbol count, CSI-RS row 4 SINR / row 4 two-port measurement.
- [x] 2026-11-14 DL MAC CE parsing per Table 6.2.1-1 (fixed-size CEs 47–52
      no longer mis-parsed as L-field CEs); PDSCH soft buffers reset on NDI
      toggle (combining across different TBs was possible); NAS T3582 for the
      release retry; SR configurations triggered per `schedulingRequestID`.

## Gaps found by the audit (open, non-OTA)

PHY/L1: extended CP and 60/120 kHz data numerology; SSB cases D/E (FR2);
FR2 CORESET#0; SFI (DCI 2_0) not used; the grant carried by a BWP-switching
DCI is dropped; DCI formats 2_x and 0_2/1_2;
MCS-C/CS/SP-CSI RNTIs; DCI-size inputs fixed to one profile (DM-RS type/len,
TCI, rate-match groups, CBG, two codewords…); RA type 0; `ra-SearchSpace` /
`searchSpaceOtherSystemInformation` not distinguished; TDRA default tables
B/C; single-layer / port-0 only (no ports 1001+, n_SCID, DM-RS type 2 /
maxLength 2, PT-RS, TB2); PDSCH rate matching around the SSB / rateMatchPatterns
/ CSI-RS rows other than 1/2/3/4; LBRM; multi-CB soft combining; CBG;
`dataScramblingIdentityPDSCH/PUSCH`; UCI ≥3 ACK bits puncture instead of
rate-matching the UL-SCH; CSI part 2 / polar UCI; PUCCH F4, F2/F3 intra-slot
hopping and group hopping; PRACH restricted sets, FR2 table, MsgA;
aperiodic/semi-persistent SRS; RI/PMI/CSI-IM/L1-RSRP reports; TRS not used
for tracking; PDCCH precoder granularity allContiguousRBs; neighbour cell
search; `EngineEvent::CellFound` / `Measurement` bypass FAPI (MIB and SSB
measurements should be PHY→MAC indications).

MAC: 2-step / contention-free RA (PDCCH order is
`Dci::Other`); SSB-based preamble/occasion selection; preamble group B; Long
Truncated BSR, Multiple-Entry PHR, BFR, Recommended bit rate CEs; BSR
truncation picks the lowest LCG id; padding BSR only with remaining data; LCP
restrictions; logicalChannelSR-DelayTimer; contention-resolution identity
mismatch not failed immediately; configured grants / SPS; semi-static HARQ-ACK
codebook; PDCCH-order RA.

RLC/PDCP: SDU discard from PDCP, delivery indication to PDCP, in-place
reconfiguration, STATUS validation; PDCP TX queue / discard timer, status
report trigger and reception, out-of-order delivery, duplication, ROHC, AM-DRB
re-establishment semantics, COUNT wrap handling, data volume for BSR; SDAP as
its own layer (QoS flows beyond the default, reflective QoS).

RRC: T311 as a real cell-selection timer (the UE re-selects the
serving cell at once today), T302 / `waitTime`, vertical NH key
derivation (`masterKeyUpdate`), `fullConfig`, CounterCheck response,
UECapabilityEnquiry filters, SIB4–9 (a SIB that fails aborts the whole SI
message), SI modification / valueTag, paging short messages, fullI-RNTI
paging, SecurityModeFailure on undecodable SMC, RRCSetup with the registered
PLMN / `registeredAMF`, decode failures of individual optional IEs abort the
whole message (sCellToAddModList, configuredGrantConfig,
beamFailureRecoveryConfig, slotFormatIndicator, crossCarrierSchedulingConfig,
codebookConfig, aperiodicTriggerStateList, …), unified access control.

NAS: EAP-AKA', emergency registration, forbidden PLMN / TA lists kept
across cells (today a forbidden cause only sets the substate), QoS rules
installation from PDU SESSION MODIFICATION COMMAND, IPv6/IPv4v6/Ethernet user
plane, EPCO (DNS/MTU), SUCI profiles A/B (`oxirush-security` has the ECIES
profiles and NIA1/NEA1/NIA3/NEA3 — candidates to replace the hand-written
codec and security), TUAK.

ASN.1: encoders for CellGroupConfig / SIB1 (round-trip tests), extension
additions decoded (120 sites skip them), critical-extension futures / CHOICE
extensions as `Raw` instead of failures, fuzz and property-based round-trip
tests. Open question: a build-time ASN.1 code generator for the RRC codec
instead of the hand-written decoders (the skipped extension sites are the
cost of hand-writing).

Tooling: `#![warn(missing_docs)]`, a crate-level MAC↔RLC↔PDCP chain test,
CI form of the lab matrix (clippy, unit tests and GitHub CI done 2026-11-14).

## Over the air

- [x] Wire the SoapySDR backend into the `ferrite-ue` binary (`--radio sdr`,
      2026-11-15): `time::Contiguous` (gap-free index, zeros for overflows,
      shared `TimeBase`), `TimedPushUlSink` (every block stamped
      `origin + ul_index`, late blocks skipped and counted), the commit-mark
      gate for the free-running pacing too, both chains set up before
      activation (LimeSuiteNG keeps one stream object). Dry run on the XTRX:
      RX streams, TX writes timed zeros, cell search runs. (seify was dropped
      the same day: no RX timestamps, no Lime driver.)
- [ ] gNB side for an OTA lab: OCUDU's build has UHD/ZMQ radios only, no
      USRP on the bench. Options: SoapyUHD's UHD module (Soapy devices appear
      to UHD apps) in front of the LimeSDR-Micro, or an OCUDU SoapySDR radio
      plugin.
- [x] UL power control (2026-11-15, `ferrite_mac::power`, TS 38.213 §7):
      PRACH target + ramp + PL, PUSCH P0/α/`f(i)` (RAR `ΔP_rampup + δ_msg2`,
      accumulated or absolute TPC), PUCCH `g(i)` with `Δ_F` and `Δ_TF`, SRS
      on the PUSCH loop, Type 1 PHR from the same numbers; every UL_TTI PDU
      carries `power_dbm`, the L1 sets the RMS level against the transmitter
      calibration `--tx-power-offset-db` (unset ⇒ peak normalisation, the ZMQ
      default). Open: per-device TX calibration constant (measure with a power
      meter / the gNB's `epre`), `Δ_TF` with deltaMCS, two closed-loop states,
      SRI-mapped P0/α sets, pathloss from CSI-RS.
- [x] Receive AGC (2026-11-15): `ferrite_radio::GainControl`, `ferrite_l1::agc`
      on cell-search captures and SSB slots, device limits learned, gain carried
      in the SSB measurement for the dBm conversion. Open: a dBm calibration
      constant per device (`--rx-power-offset-db`), and gain changes within a
      slot are not compensated in the channel estimate (the hold time covers it).
- [x] CFO and timing tracking (2026-11-15): `ferrite_l1::track::SyncTracker`,
      fractional timing from the SSS phase slope at every SSB and from the
      PDSCH DM-RS (delay and inter-symbol CFO) of every CRC-passed PDSCH,
      second-order timing loop with the drift (ppm) fed forward from the CFO,
      one-sample anchor steps instead of per-measurement slews. Open: the
      first-path vs mean-delay bias in a multipath channel (the loop centres
      the window on the mean delay), CSI-RS/TRS as a measurement source, and
      a Doppler-aware CFO filter for mobility.
- [ ] Two-channel SDR receive for MIMO (`SoapyRadio::streams` opens channel 0;
      a multi-channel stream delivers all antennas in one read, so `DlStream`
      needs a fan-out source rather than one drain thread per antenna).
- [ ] Multi-device lab: `--tx-rx-offset` per device from `tx_rx_cal`, SDR
      run of the ZMQ matrix (TEST_PLAN L4).
