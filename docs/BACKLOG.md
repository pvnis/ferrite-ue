# Ferrite UE backlog

Functional gaps relative to a full-featured software UE (reference point:
OAI `nr-uesoftmodem`), as assessed on 2026-11-13 after the first end-to-end
attaches against OCUDU over ZMQ. Items are grouped by layer and ordered by
the value they add for interoperating with a stock gNB. Status legend:
`[ ]` open, `[~]` in progress, `[x]` done (date).

Over-the-air items are listed last and are deliberately deferred until an
SDR is on the bench; nothing in the other groups may assume the ZMQ
transport (see `ARCHITECTURE.md`, radio backend section).

## Top priority

- [~] **4-port CSI** (a gNB with four DL antenna ports, e.g. 4T4R over the
      air). OCUDU sets the CSI-RS port count from the cell's antennas
      (`csi_params.nof_ports = dl_carrier.nof_ant`), not from the UE, so a
      4T cell configures a 4-port NZP-CSI-RS (row 4), the Type I
      single-panel codebook N1,N2 = 2,1 (mode 1) and an ri-Restriction of
      `max_rank` (or all four ranks) for every UE.
      1. [x] 2026-11-18 Report sizes for any Type I single-panel codebook
         (`ferrite_ran::codebook`: TS 38.212 Table 6.3.1.1.2-1 widths, the
         RI field, rank-2 offsets), checked against OCUDU's
         `get_pmi_sizes_typeI_single_panel`; MAC packs `i1,1 | i1,2 | i1,3 |
         i2` padded to the widest allowed rank. Before, a 4-port report was
         5 bits short: on PUCCH it shares one coded payload with HARQ-ACK
         and SR, so those would have been lost too.
      2. [x] 2026-11-18 4-port measurement: row 4 (two FD-CDM2 groups),
         channel per antenna and port, codebook search over every PMI of
         ranks 1–2 (`csi::type1_precoder`, `pmi_hypotheses`; the beam
         construction is OCUDU's / TS 38.214 Table 5.2.2.2.1-5/-6).
      3. [ ] UE capability that says what the UE does (`featureSets` with
         `maxNumberMIMO-LayersPDSCH` = 2 and the CSI-RS port limits, which
         the band combinations must reference: `featureSetCombinations`,
         `supportedBandCombinationList`). Not needed for OCUDU, which reads
         the capability only for uplink MIMO and the Type II codebook;
         worth doing for a gNB that honours it. A sizeable UPER job; check
         the result with Wireshark (S31).
      4. [x] 2026-11-18 Lab cell T8 (4 TX ports through ferrite-chanem to
         the UE's two; `lab.sh T8`): S28 passes, the gNB decodes the 11-bit
         reports (RI 2, i1,1 = 4, i1,3 = 1, i2 = 1, CQI 15 on the unfaded
         link) and schedules two-layer PDSCHs, 116/0 DL TBs. On the way:
         the emulator requested upstream ports one after another and
         blocked on a port the gNB had nothing for yet, while it held the
         other ports' samples for the same span — with four ports that
         deadlocked (UE starved, no uplink, no new downlink). Every port
         now keeps a request outstanding and replies are taken as they
         come (`zmq::poll`).

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
- [x] 2026-11-16 UCI on PUSCH rewritten after OCUDU's `get_ulsch_information`
      / `ulsch_demultiplex` (`pusch::uci_pusch_layout`): ΣK_r = C·K (it used
      TBS + CRC), α (`uci-OnPUSCH.scaling`) on the ACK count, β_offset index
      by payload size (ACK 1–2 / 3–11 / >11, CSI ≤11 / >11; OCUDU sets index 1
      = 20 and index 2 = 6.25), the UL-SCH rate-matched around 3–11 ACK bits
      (it was punctured), CSI part 1 placed around the reserved ACK REs (also
      with no ACK: OCUDU reserves for two bits) and with Q'_CSI reduced by
      them. Found by the n48 / 10-slot TDD configs: with more DL slots per
      UL slot, two-bit ACKs on PUSCH failed 14 of 15 times and one-bit ACKs
      were read as NACK (DL retransmissions); now C1 / C2 / T1 / T7 run with
      0 UL CRC failures on the ZMQ channel.
- [x] 2026-11-16 PDCCH presence gate robust to timing offsets and fading:
      the gate before the blind decode used `|mean h|² / mean |h|²` over a
      candidate's REGs, which are interleaved across the CORESET, so a DL
      timing error of a few samples (a linear phase over the band) or
      frequency-selective fading scored a real PDCCH near zero and skipped it.
      It now correlates neighbouring REGs (next RB / next symbol). Under the
      emulator's `cell-edge` channel on C1 (TDL-A 100 ns, 5 dB) the UE decoded
      78 % of the UL grants before, 89 % after; the UL went from 3/1142 to
      49/43 PUSCH CRC ok/ko and the attach now completes.
- [x] 2026-11-16 Drift over the cell-search gap and SFN aliasing: the timing
      tracker now starts counting at the acquisition (a dropped search backlog
      of seconds is 129 samples at 1 ppm and 30.72 MHz: the SSB was lost
      after the drop), and the slot clock is re-anchored at the slot-loop
      start (slot ↔ index is modular over the SFN cycle; a backlog over
      5.12 s aliased to the wrong cycle: "timing slew of 314572101 samples").
      The `tracking:` summary is also logged when the engine stops.
- [x] 2026-11-16 Periodic CSI on every configured occasion: the MAC dropped
      a report when the latest measurement predated the current report period
      (a CSI-RS a few slots before the occasion is often still in flight when
      the slot is built), so the gNB decoded nothing on PUCCH and failed the
      PUSCH that should have carried it — on C2 that cost SRB1 and declared an
      RLF. The report now uses the latest measurement (CQI 0 before the
      first).
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
      two-layer PDSCHs in a 40 s run. Done 2026-11-15: the channel
      emulator in Rust (`ferrite-chanem`: TDL-A/B/C, EPA/EVA/ETU fading per
      antenna pair, delay, UE clock error, AWGN; `lab.sh CHANEM=…`, stage
      S30): T5 keeps two layers through 2x2 TDL-A. Open: three/four layers,
      the SDR two-channel receive path, CDL / Sionna RT ray-traced channels
      (spatially correlated antennas), and a faster 2x2 fading path (the
      emulator runs 2x2 TDL at ~0.3–0.6× real time). Fixed 2026-11-18:
      two-layer PDSCH failed a fifth to a third of its TBs under fading
      (T5 indoor 77/19, T8 pedestrian 73/16), in bursts of one TB and its
      retransmissions: the receiver trusted antenna 0 / DM-RS port 0 alone
      twice. Its DM-RS gate (`dmrs_metric < 0.3` → not decoded, not
      combined) dropped every PDSCH while that one path faded, and the
      residual-CFO slope came from that path too (garbage when it faded).
      Both are now measured over every antenna and port (a unit test fades
      that path out completely). With them T5 indoor 75/1, T8 pedestrian
      76/0, T5 pedestrian 77/5. The CQI also maps the capacity-equivalent
      SINR now (the linear mean let the strong RBs / layer hide the weak).
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

- [x] 2026-11-16 No `unwrap` / `expect` / `panic!` in non-test code (the
      CLAUDE.md rule), now enforced: `[workspace.lints.clippy]` warns on
      `unwrap_used` / `expect_used` / `panic` (errors in CI), `clippy.toml`
      exempts tests, examples / benches / integration-test helpers opt out
      at their crate root. 20 sites removed; reachable from outside were
      the polar list decoder's path sort (`partial_cmp().unwrap()` panicked
      on NaN LLRs; now `total_cmp`, regression test), PBCH RE extraction,
      the IMSI parser (a non-digit wrapped around; the configuration now
      rejects anything but 6–15 digits), the CCCH SDU length, and four
      PDSCH asserts on network-configured values (bundle size, DM-RS
      reference CRB, Qm, slot index).
- [ ] Intermittent uplink loss with the downlink fine (about one run in
      several, the rerun of the same scenario passes):
      * cell edge (T1, 5 dB, 3 µs, 2 ppm): the timing loop flipping by ±4
        samples (88 re-alignments in a run), and the gNB detects none of the
        UE's preambles (47 random access attempts);
      * T5 pedestrian (2026-11-18): RRC connects, then the gNB fails most
        PUSCHs (785 KO vs 634 OK; a normal run is 73 / 10), SR failures
        (157) drive C-RNTI random accesses in a loop, registration never
        gets past T3510 — while the timing tracking is clean (0
        re-alignments, drift +1.001 ppm) and 641 DL TBs decoded.
      Look at the UL timing advance and CFO pre-compensation in such a run
      (the capture, `ue.pcap`, shows the procedure side).
- [ ] About 25 `assert!` remain in the DSP crates (`ferrite-phy`: polar,
      LDPC, OFDM, rate matching, PSS / SSS, cell search) on internal shape
      invariants (lengths the same module computed). Not reachable from the
      network as far as reviewed; converting them means `Result`s through
      the DSP API.
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
`dataScramblingIdentityPDSCH/PUSCH`; CSI part 2 / polar UCI (more than 11
bits; UCI on PUSCH refuses them); PUCCH F4, F2/F3 intra-slot
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

## Architecture improvements (osmocom-bb review, 2026-11-16)

Practices taken from OsmocomBB (`src/host/layer23`, `src/host/trxcon`,
`src/target/trx_toolkit`), adapted to ferrite. Its C idioms (msgb, void*
callbacks, 5–7k-line files) are not adopted; the crate split and the typed
FAPI already improve on them.

- [x] 2026-11-19 **Explicit state machines with declared transitions** (priority).
      2026-11-16: helper `ferrite_common::fsm` done; RRC and MAC RA
      converted, with a randomised RRC entity test and two Kani proofs on RA
      (inductive invariant, bounded 6-step), diagrams generated into
      ARCHITECTURE §13. Writing the RRC table exposed three deliberate
      deviations, now visible as `ferrite:` rules: an RA problem ends a
      connection / re-establishment attempt at once (38.331 keeps T300 /
      T301 running and lets MAC retry), and RRCSetup in response to
      RRCReestablishmentRequest aborts and reconnects (38.331 §5.3.3.4
      continues with the setup). Stray RRCRelease / RRCReject outside their
      states are now ignored (were: go to Idle).
      2026-11-16 (second step): NAS 5GMM (state × substate), 5GMM-CM, 5GSM,
      MAC SR / TA / DRX and L1 cell phase / RLM converted; Kani proof on SR;
      randomised NAS entity test. Fixed on the way, each a move the tables
      refused:
      * SERVICE ACCEPT / SERVICE REJECT changed the 5GMM state in any state
        (a stray one "registered" a deregistered UE); now only in
        SERVICE-REQUEST-INITIATED. REGISTRATION REJECT likewise only during
        a registration.
      * A registration *update* rejected with #22 or an abnormal cause, or
        T3520 expiring in one, deregistered locally first (PDU sessions
        dropped, `Deregistered` emitted) and then entered
        REGISTERED.ATTEMPTING-REGISTRATION-UPDATE; now that state directly,
        sessions kept (24.501 §5.5.1.3.5, §5.5.1.3.7).
      * `start_registration` (the stack's retry) registered from
        DEREGISTERED.NO-SUPI / PLMN-SEARCH / LIMITED-SERVICE; now refused
        (`Option`).
      * 5GSM ESTABLISHMENT ACCEPT / REJECT applied to a session in any state
        (a duplicate REJECT tore down an active session); now only in
        ACTIVE-PENDING.
      * SR: a BSR in the slot where SR_COUNTER reached sr-TransMax erased the
        failure, so no random access was started (38.321 §5.4.4); the failure
        now survives until the RA starts (unit test, Kani).
      * L1: a dedicated CONFIG.request before SIB1 is refused.
      Open: `Registered(LimitedService)` / `Registered(PlmnSearch)` are never
      entered (dead substates).
      2026-11-19 (last step): the implicit machines are on tables too —
      DL / UL HARQ processes, the RLC AM transmit-side SDU (an ACK of an SDU
      not fully submitted is now ignored as a malformed STATUS PDU instead of
      dropping the unsent rest), the stack's AS security and connection.
      The composed model `formal/ue.qnt` (Quint: NAS × 5GMM-CM × RRC × stack
      glue, network and timers nondeterministic; properties noStuck,
      t3510Consistent, cmFollowsRrc, backoff) found, by simulation and
      Apalache, that the stack retried a failed RRC establishment by itself
      within a second and restarted the registration, resetting the NAS
      attempt counter: a UE whose random access kept failing never backed
      off to T3502 (24.501 §5.5.1.2.7). Fixed (`NasUe::on_lower_layer_failure`;
      the stack no longer retries by itself); lab: with the uplink at −20 dB
      the UE makes five attempts 10 s apart, then waits T3502. Trace
      validation: `scripts/trace_to_quint.py` replays a lab run's logged
      transitions against the model (`quint test`); the lab logs so far
      replay whole, `formal/traces/ul_failure.qnt` is the failure-path one.
      Not done: a CI job running the model (needs Node + Quint in CI).
      Today 11 FSMs are enums changed by plain assignment: L1 `CellPhase`,
      `RlmState`; MAC `RaState`, `SrState`, `DrxState`, `TaState`; RRC
      `RrcState` (one `set_state` already); NAS `MmState` (with substates),
      `CmState`, `SmState`. Implicit ones live in flags/options: HARQ
      processes, RLC AM windows, the stack's connection-retry and
      AS-security hand-over. Plan, after `osmo_fsm` and the MM/RR
      (state, substate, event) → handler tables:
      1. A small helper in `ferrite-common` (no dependency): per machine a
         fieldless state kind and event kind, a `const` transition table
         `(from, event) → allowed targets` annotated with the spec clause,
         and one `transition(to, event)` entry point that checks the table
         (a violation is an error and a counter, never a panic), logs
         `RRC Connecting → Connected on RRCSetup [38.331 §5.3.3.4]`, and arms
         / cancels the state's spec timers (T300, T3510, …) with the state
         change.
      2. Pilot on RRC and MAC RA; then NAS MM/CM/SM, MAC SR/DRX/TA, L1
         `CellPhase`/RLM; then make the implicit machines explicit.
      3. Generate the diagrams in ARCHITECTURE.md from the tables (Mermaid),
         so the documentation cannot drift from the code.
      4. Verification, in increasing cost: exhaustive tests over every
         (state kind, event kind) pair from the table (no tooling); Kani
         model-checking harnesses on the step functions (`#[cfg(kani)]`,
         needs `cargo-kani` installed: no panics, only table transitions,
         timer invariants such as "T3510 runs iff RegistrationInitiated");
         a composed cross-layer model (NAS × RRC × MAC RA, e.g. in
         TLA+/Quint) for deadlock and liveness ("registration attempts
         always end"), checked against lab runs by validating the logged
         transition traces.
- [x] 2026-11-16 **Protocol capture for Wireshark** (GSMTAP's role): `--pcap
      FILE` writes MAC-NR PDUs (`mac-nr-framed`, or UDP with
      `--pcap-mac-udp` for Wireshark < 4.4), RRC (after PDCP) and NAS (plain
      text) as exported PDUs; `lab.sh` captures every run and stage S31 has
      tshark check it. The first capture showed UL MAC CEs (PHR, C-RNTI)
      placed before the MAC SDUs; 38.321 §6.1.2 puts them after (fixed,
      attach test checks every UL PDU's layout).
- [ ] **Machine-readable state** instead of log greps (`lab.sh` has 49):
      a JSON summary at exit (counters, RRC/NAS state, tracking), later a
      control socket (VTY's role: status, detach, re-register).
- [ ] **RRC / NAS / user plane off the slot thread** (T0): L3 behind
      queues, MAC (HARQ timing) stays on T0, so a slow ASN.1 decode or crypto
      step cannot cost an uplink deadline over the air (osmocom: real-time
      L1, non-real-time L23).
- [ ] **Persisted subscriber state** (`gsm_subscriber`'s role): 5G-GUTI,
      last TAI, NAS security context, forbidden PLMNs, USIM SQN (`NasUe`
      exposes the SQN "to persist" but nothing saves it), so the UE
      re-registers with its GUTI like a real one. Keep settings, subscriber
      state and UE capabilities as separate structs.
- [ ] **Runtime channel-emulator control** (`fake_trx` `FAKE_*`): change
      SNR / ppm or drop N blocks while running, for scripted RLF →
      re-establishment and coverage-gap tests.
- [ ] **Named radio quirks** (`phy_quirks`): per-device workarounds (XTRX
      68-sample offset, Lime timestamp rules) in one struct in
      `ferrite-radio`, selected by configuration.
- [ ] **First-class small tools** (layer23's `cell_log` / `bcch_scan`):
      a `ferrite-scan` binary from `cell_search` / `offline_scan` that logs
      ARFCN, PCI, RSRP, PLMN and TDD pattern (CBRS site surveys).
- [ ] **Instance scoping and a serialisable FAPI** (lower): all state per UE
      with a UE id in log lines; serialisable FAPI messages for FAPI-level
      record / replay and a DSP-free virtual PHY for fast L2/L3 regression
      (`virt_phy`'s role).

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
