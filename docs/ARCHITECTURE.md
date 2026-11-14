# Ferrite UE — architecture

Ferrite is a clean-room 5G NR standalone UE written in Rust from the 3GPP
specifications. This document is the design contract for the rebuilt code base:
what each crate owns, the interfaces between layers, and the state machines each
layer runs. It is deliberately independent of any one cell configuration — every
cell-specific number (numerology, bandwidth, duplex mode, PRACH format, CORESET
geometry, k1/k2, PUCCH resources, …) is **derived at run time** from the MIB,
SIB1 and the dedicated RRC configuration, never transcribed.

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │ ferrite-ue   (binary: config, wiring, runtime threads, TUN/ping, CLI) │
 ├───────────────┬───────────────┬───────────────┬───────────────────────┤
 │ ferrite-nas   │ ferrite-rrc   │ ferrite-pdcp  │ ferrite-rlc           │
 │ 5GMM/5GSM SM  │ RRC SM + cfg  │ SRB/DRB PDCP  │ TM/UM/AM entities     │
 ├───────────────┴───────────────┴───────────────┴───────────────────────┤
 │ ferrite-mac   (RA procedure, HARQ, BSR/SR, LCP, TA, mux/demux)        │
 ├───────────────────────────────────────────────────────────────────────┤
 │ ferrite-l1    (slot engine: sync, PDCCH monitoring, PDSCH/HARQ rx,    │
 │               PRACH/PUSCH/PUCCH tx, UL timing, FAPI-like SAP to MAC)  │
 ├────────────────────────────────┬──────────────────────────────────────┤
 │ ferrite-phy  (numerics: OFDM,  │ ferrite-radio (ZMQ / file / SDR IQ   │
 │  sync, coding, channels, PRACH)│   transports, SampleSource/Sink)     │
 ├────────────────────────────────┴──────────────────────────────────────┤
 │ ferrite-asn1 (UPER codec + TS 38.331 message coders)   ferrite-common │
 └───────────────────────────────────────────────────────────────────────┘
```

Dependency direction is strictly downward. No layer reaches into another
layer's state; every cross-layer interaction is a message or a trait call on a
service-access point (SAP) defined by the lower layer.

## 1. Vocabulary (ferrite-common)

* `Iq` (complex f32), `Error`/`Result`.
* `Numerology { mu }` and `SlotPoint { mu, sfn, slot }`: the slot clock shared
  by every layer. `SlotPoint` supports `+ n`, `- n`, `diff`, `subframe()`,
  `slot_in_subframe()`, `slots_per_frame()`, absolute index arithmetic mod 1024
  frames.
* `Rnti` newtype and the reserved values (SI 0xFFFF, P 0xFFFE).
* `DuplexMode { Fdd, Tdd }`, `Bandwidth`, `Frequency` helpers (ARFCN ↔ Hz,
  GSCN ↔ Hz for both FR1 ranges, band table subset: n1,n3,n7,n28,n41,n77,n78,n79
  with duplex mode and N_TA_offset class).

## 2. Physical layer numerics (ferrite-phy)

Pure functions over slices; no threads, no I/O, no cell state beyond their
arguments. Generalised over `mu ∈ {0,1}` (FR1 15/30 kHz; 60 kHz is reachable
by the same code paths but untested) and any sample rate `fs = N_fft · SCS`.

| module | content | spec |
|---|---|---|
| `numerology`, `ofdm` | SCS, CP lengths per symbol, slot/frame sample counts, `Ofdm` (de)modulator, `PhaseCompensation` (the per-symbol carrier-phase restart of §5.4: applied on every UL waveform at the UL centre frequency, undone on every DL symbol at the DL centre frequency — OCUDU applies it even over ZMQ, and without it the long-CP symbol 7 at 15 kHz breaks cross-symbol channel estimates) | 38.211 §4, §5.3, §5.4 |
| `sync::{pss,sss,ssb,pbch,detect,search,cfo}` | PSS/SSS, SSB cases A/B/C candidate symbol positions and `L_max`, PBCH DMRS + polar MIB decode, CFO | 38.211 §7.4.3, 38.213 §4.1 |
| `coreset0` | Tables 13-1 … 13-6 (CORESET#0) and 13-11 (Type0-PDCCH monitoring occasions) | 38.213 §13 |
| `pdcch` | CORESET geometry (interleaved / non-interleaved CCE→REG, bundle size, shift), search-space candidate hashing (CSS/USS), DMRS, equalisation, coherence gate | 38.211 §7.3.2, 38.213 §10.1 |
| `coding::dci` | polar DCI coding; DCI **field layout & sizes** for 0_0/1_0 (with 38.212 §7.3.1.0 size alignment) and 0_1/1_1 derived from the RRC configuration | 38.212 §7.3.1 |
| `coding::{crc,polar,ldpc,ratematch,dlsch}` | channel coding; the LDPC encoder uses the base-graph double-diagonal structure (O(edges·Zc), ~0.5 ms for the largest TB) rather than a generic GF(2) solve, since a new lifting size must not stall the TX builder | 38.212 §5 |
| `pdsch` | DMRS positions (type A/B, additional positions, `l_d`), CDM groups without data, VRB→PRB (interleaved bundles over the BWP), RE extraction in 38.211 §7.3.1.5 order, rate matching around CSI-RS, TBS (§5.1.3.2) | 38.211 §7.3.1/§7.4.1.1, 38.214 §5.1.3 |
| `mcs` | MCS tables 1/2/3 (qam64, qam256, qam64LowSE) | 38.214 Tables 5.1.3.1-x, 6.1.4.1-x |
| `pusch` | CP-OFDM PUSCH modulation, DMRS, UCI multiplexing (HARQ-ACK / CSI part 1), transform precoding **disabled** (msg3-transformPrecoder absent) | 38.211 §6.3.1, 38.212 §6.2.7 |
| `pusch` | CP-OFDM and DFT-s-OFDM (transform precoding: DFT per data symbol, low-PAPR DM-RS §6.4.1.1.1.2, π/2-BPSK), UCI-on-PUSCH | 38.211 §6.3.1 |
| `pucch` | formats 0, 1, 2, 3 (F3: DFT-s-OFDM data, Table 6.4.1.3.3.2-1 DM-RS, RM(32,O) ≤11 bits) | 38.211 §6.3.2 |
| `prach` | preamble formats 0–3 (L=839) and A1–C2 (L=139); PRACH configuration tables for FR1 FDD (6.3.3.2-2) and TDD (6.3.3.2-3); occasion → (SFN, subframe, start symbol, slot, index) enumeration; waveform generation at any `fs` | 38.211 §6.3.3, 38.213 §8.1 |
| `csi` | NZP-CSI-RS sequence, SINR measurement, CQI mapping | 38.211 §7.4.1.5, 38.214 §5.2 |

Everything that was previously an empirical sweep in the UE (time-first vs
frequency-first data order, CDM-group guessing, TBS brute force, Msg3 timing
offsets, PRACH position sweeps) is replaced by the spec-derived value computed
from configuration.

## 3. Radio transport (ferrite-radio)

`SampleSource` / `SampleSink` traits. Backends: ZMQ (gNB-compatible REQ/REP
lockstep), file, SDR (seify, feature-gated). The ZMQ backend exposes the
lockstep semantics the L1 engine relies on: DL sample index `n` and UL sample
index `n` denote the same instant at the gNB's antenna reference.

## 4. L1 — the slot engine (ferrite-l1)

`ferrite-l1` turns a sample stream into slot-synchronous events for MAC and
turns MAC transmit requests into samples at the right absolute position. It is
the only crate that knows about sample indices.

### 4.1 Threads

```
 radio-rx thread ─▶ BufferedStream ─▶ timeline thread (T0) ─▶ rx-phy workers (pool)
                                            │  ▲                      │
                                            ▼  └── DlResult ◀─────────┘
                                        MAC/RLC/PDCP/RRC/NAS (synchronous on T0)
                                            │
                                            ▼ TxRequest
                                       tx-build thread ─▶ InjectionTable ─▶ radio-tx thread (paced, gated)
```

* **T0** owns the slot clock. Per DL slot it: reads one slot of samples,
  applies the frequency shift to baseband the carrier, tracks timing/CFO,
  runs the PDCCH monitor (all configured search spaces for all active RNTIs),
  pushes a PDSCH decode job for each DL assignment, drains decode results,
  calls `Mac::slot_indication`, then dispatches the MAC's transmit requests.
* **rx-phy workers** run PDSCH demodulation + LDPC + HARQ combining.
* **tx-build** modulates PUSCH/PUCCH/PRACH off the timeline and places samples
  in the `InjectionTable` keyed by absolute UL sample index.
* **radio-tx** serves the gNB's UL requests from the table, paced to real time
  and gated to T0's DL position.

### 4.2 Timing model

* After acquisition L1 knows `(sfn0, dl_index0)`: the DL sample index of the
  start of frame `sfn0`. `dl_index(SlotPoint)` follows by slot arithmetic.
* Uplink: `ul_index(slot) = dl_index(slot) − (N_TA + N_TA_offset) · T_c · fs`
  (38.211 §4.3.1). `N_TA_offset` comes from SIB1 `n-TimingAdvanceOffset`
  (default 25600 for FR1); `N_TA` from the RAR TA command and subsequent
  TA MAC CEs (38.213 §4.2). Any transport-specific constant offset lives in
  the radio backend's `tx_rx_offset()`, measured once, not swept per attach.
* Symbol-level positions use the per-symbol CP table of the numerology, so a
  PRACH occasion starting at symbol `l` of a slot is placed exactly. The
  whole uplink is additionally delayed by the *uplink guard* (`ul_guard`,
  CLI `--prach-offset`, default 1 µs): a detector window may start slightly
  after the slot and reject negative delays (OCUDU does), and over a
  zero-delay transport nothing else provides that margin. The guard must
  apply to every uplink channel, not just the PRACH: the timing-advance
  command the network answers with measures the guard, and a PRACH-only
  delay would then leave PUSCH/PUCCH early by exactly that amount (OCUDU
  reported `t_align = −1.04 µs` and 256-QAM failed on narrow allocations).
  Over the air the propagation delay plays the same role and the guard can
  be zero.
* Lockstep transports (ZMQ) pull uplink blocks in step with the downlink they
  send and will not run more than ~1 ms of DL ahead of the UL they have
  received. The uplink serve is therefore gated by a *commit mark*: after
  handling slot `n` the engine (through the TX builder, so every queued
  build has landed) publishes the UL index up to which the injection table
  is final, `ul_index(n + tx_lead + 1)`, and the serve never passes it. This
  replaces any "stay k slots behind the DL" heuristic, which deadlocks at
  15 kHz where one slot is the whole allowance. A free-running SDR back end
  does not use the mark at all.

### 4.3 FAPI: the PHY ↔ MAC interface (`ferrite_l1::fapi`)

The boundary is modelled on the SCF-222 5G FAPI PHY API, adapted to the UE
direction: PHY → MAC carries SLOT.indication, a DCI indication (the decoded
PDCCH), RX_Data/CRC.indication (PDSCH transport blocks), a CSI measurement,
RACH.indication (preamble transmitted) and ERROR.indication; MAC → PHY carries
CONFIG/START/STOP.request, UL_TTI.request (PRACH / PUSCH / PUCCH PDUs for one
slot, the PUSCH payload being the TX_Data), the RNTI set and the timing advance.

```rust
enum PhyToMac { Slot(SlotIndication), Dci(DciIndication), RxData(RxDataIndication),
                Csi(CsiIndication), Rach(RachIndication), Error(ErrorIndication) }
enum MacToPhy { Config(Box<PhyConfig>), Start, Stop, UlTti(UlTtiRequest),
                SetRntis { c_rnti, tc_rnti, ra_rnti }, TimingAdvance { n_ta_tc },
                Paging { ue_id } }
enum UlTtiPdu { Prach { occasion, preamble, power_offset_db },
                Pusch { grant: UlGrant, tb: Vec<u8>, uci: UciPayload },
                Pucch { resource: PucchResourceRef, uci: UciPayload } }
```

The `Dci` carried in the indication is the *resolved* grant: the PHY holds the
configuration (TDRA tables, k1 list, BWP size, DMRS config, MCS table, PUCCH
resource sets), so it converts the raw DCI fields into `ResolvedDlGrant` /
`ResolvedUlGrant` (PRBs, symbols, DMRS symbols, TBS, HARQ id, NDI, RV, k0/k1/k2,
PUCCH resource indicator, DAI) before handing them to MAC.

Blind decoding notes: common search spaces are decoded before UE-specific
ones, and a payload already decoded for the same RNTI in the slot is not
decoded again (a CORESET#0 PDCCH is physically visible through overlapping
UE-specific candidates on a dedicated CORESET, where the fallback fields would
be read against the active BWP). `Paging { ue_id }` (5G-S-TMSI mod 1024) turns
on P-RNTI decoding in the paging search space during the UE's paging frames
(TS 38.304 §7.1); a paging DCI whose short-message indicator announces
scheduling information yields a PDSCH grant decoded like system information
and delivered as a PCCH transport block.

### 4.4 L1 state machine

```
 Idle ──start──▶ CellSearch ──SSB found + MIB──▶ Sib1Acquire ──SIB1──▶ Synced
   ▲                 │ no SSB after N captures         │ timeout           │
   └─────────────────┴───────────────────────────────◀┘◀── SyncLost ───────┘
```

In `Synced` the engine runs the per-slot loop. Timing tracking re-measures the
PSS every SSB period and slews the slot clock; CFO is tracked from the SSB CP.

## 5. MAC (ferrite-mac)

`MacEntity` implements `ferrite_l1::api::L1Listener` and offers RLC the
`MacSap { tx_sdu_available(lcid, bytes), … }`. Sub-entities:

* **Random access** (38.321 §5.1) — one state machine:
  `Idle → PreambleSelected → PreambleSent{ra_rnti, window} → RarReceived{tc_rnti, ta} → Msg3Sent{conres_timer} → Succeeded | Failed{backoff, attempt}`.
  Preamble/occasion selection uses the PRACH configuration table and
  `ssb-perRACH-Occasion`. Power ramping counter and `preambleTransMax` honoured.
* **DL HARQ** — per process: soft buffer, NDI, first-tx shape; ACK/NACK per
  (slot, DAI) assembled into the dynamic/semi-static codebook (38.213 §9.1).
* **UL HARQ** — per process: stored TB for retransmissions at the signalled RV.
* **BSR** (§5.4.5): regular/periodic/padding BSR with `periodicBSR-Timer` and
  `retxBSR-Timer`; short/long formats.
* **SR** (§5.4.4): `sr-ProhibitTimer`, `sr-TransMax`, SR occasion selection
  from the configured `SchedulingRequestResourceConfig`.
* **LCP** (§5.4.3.1): priority + prioritised bit rate bucket per logical
  channel; MAC CEs ordered per §6.1.2.
* **Timing advance** (§5.2): `timeAlignmentTimer`, TA command application.
* **SRS**: periodic SRS resources from `SRS-Config` are transmitted on
  their occasions when nothing else (PUCCH/PUSCH) goes out in the slot
  (TS 38.214 §6.2.1 dropping rule); the PHY (`ferrite_phy::srs`) builds the
  low-PAPR sequence (φ tables for 6/12/18/24, Zadoff-Chu above) on the comb
  from C_SRS/B_SRS/position/shift (no hopping).
* **PHR** (§5.4.6): `phr-PeriodicTimer` / `phr-ProhibitTimer` /
  `phr-Tx-PowerFactorChange` triggers and the Single Entry PHR MAC CE; the
  reported PH / P_CMAX come from a `PowerHeadroom` value the stack (later:
  L1 power control) sets, so the procedure is transport-agnostic.
* **DL/UL grant handling**: NDI toggling, retransmission detection, CSI /
  HARQ-ACK / SR multiplexing decision (PUSCH vs PUCCH per 38.213 §9.2.5).

## 6. RLC (ferrite-rlc)

`RlcEntity` enum over `Tm`, `Um { sn_len }`, `Am { sn_len, t_poll_retransmit,
poll_pdu, poll_byte, max_retx, t_reassembly, t_status_prohibit }` (38.322).
Each entity is a pure state machine driven by `tx_sdu`, `rx_pdu`, `tick(slot)`
and `pull_pdu(max_bytes)`. AM implements the full window, segmentation of SDUs
and of retransmitted PDUs, STATUS PDU generation (with NACK ranges) and
polling; UM implements segmentation/reassembly with `t-Reassembly`.

## 7. PDCP (ferrite-pdcp)

`PdcpEntity { sn_len (12/18), direction, bearer, integrity: Option<(alg, key)>,
ciphering: Option<(alg, key)>, tx_next, rx_next/rx_deliv, t_reordering }`
(38.323). Algorithms: NIA0/NIA2, NEA0/NEA2 (AES-CMAC / AES-CTR). SRBs carry
the MAC-I; DRBs optionally. Security is activated by RRC after the
SecurityModeCommand is verified.

## 8. RRC (ferrite-rrc)

* `RrcUe` state: `Idle → Connecting{setup_request_sent} → Connected → Idle`
  (release). Procedures: system information acquisition, connection
  establishment, security mode, UE capability transfer, reconfiguration
  (bearer setup, dedicated PHY/MAC config), DL/UL information transfer (NAS),
  release, measurements, paging.
* Measurements (`ferrite-rrc/src/meas.rs`, 38.331 §5.5): `measConfig` from a
  reconfiguration installs objects / report configs / measIds / quantity
  config; the PHY's SSB measurements (SS-RSRP/RSRQ/SINR, `ferrite-phy
  sync::measure`) are L3-filtered per `filterCoefficient` and evaluated for
  periodical reports and the serving-cell events A1/A2 (hysteresis,
  time-to-trigger, reportOnLeave, reportAmount); `MeasurementReport` carries
  `measResultServingMOList`. Neighbour-based events (A3–A6) are evaluated
  with no candidates until neighbour cell search exists.
* Other system information (§5.2.2.3): SIB1's `si-SchedulingInfo` lists the
  broadcast SI messages; the PHY keeps decoding the SI-RNTI in the Type0
  search space, and every `SystemInformation` block is decoded
  (`ferrite-asn1::si`: SIB2/SIB3 structured, SIB10+ raw) and kept by SIB
  type in `RrcUe::sibs`, logged once per change.
* Bearer continuity: a reconfiguration that lists an existing bearer keeps
  its PDCP entity (COUNTs, reordering) unless `reestablishPDCP`, and its RLC
  entity unless `reestablishRLC`; an `RLC-BearerConfig` without `rlc-Config`
  keeps the previously configured RLC mode (Need M).
* Re-establishment (§5.3.7): a radio link failure with AS security active
  puts RRC in `Reestablishing`: `RRCReestablishmentRequest` on SRB0 (old
  C-RNTI, PCI, shortMAC-I = 16 LSBs of the NIA MAC over VarShortMAC-Input
  with COUNT 2³²−1 / BEARER 31 / DIRECTION 1), T301, MAC reset, SRB1 PDCP
  re-established without security; `RRCReestablishment` refreshes the keys
  (K_NG-RAN* by horizontal derivation from K_gNB with PCI + SSB ARFCN,
  TS 33.501 A.11; vertical NH derivation not yet), the stack verifies its
  MAC-I with the new K_RRCint before applying them, and the complete goes on
  SRB1; the network restores the other bearers by reconfiguration. An
  `RRCSetup` instead (network fallback) is treated as a lost connection.
* UE capability: `UE-NR-Capability` advertises the band list plus
  `pdsch-256QAM-FR1` and per-band `pusch-256QAM`, which OCUDU reads to select
  the 256-QAM MCS tables.
* Idle mode: an `RRCRelease` returns RRC to idle while the NAS stays
  registered; the 5G-S-TMSI from the registration is the UE identity for
  paging (PHY monitors the P-RNTI in the paging frames) and for later
  `RRCSetupRequest`s (`ng-5G-S-TMSI-Part1` + `Part2` in the complete). Uplink
  data while idle, or a `Paging` record with the UE's identity, triggers a NAS
  Service Request (`mo-Data` / `mt-Access`); the packets wait in the stack
  until the DRB is restored.
* Configuration derivation (`ferrite-rrc/src/codec.rs`): `cell_from_sib1`
  (MIB facts + SIB1 → `PhyConfig`/`MacConfig`: carriers, BWPs, CORESET#0
  placement, common search spaces, TDD pattern, PRACH, PUCCH common, timers)
  and `apply_cell_group` (a `CellGroupConfig` applied as a delta on the
  current configuration: CORESET/search-space add-mod-release, PDSCH/PUSCH
  DM-RS and TDRA, PUCCH resources/sets/SR/k1, CSI-RS rate matching + periodic
  reports, logical channels, SR/BSR/TAG), plus `bearers_of` (RLC bearers +
  PDCP/SDAP from `RadioBearerConfig`). Nothing below RRC sees ASN.1.
* Codec: `ferrite-asn1` holds the UPER bit reader/writer and the message
  coders (SIB1, RRCSetup/CellGroupConfig, RRCReconfiguration incl.
  RadioBearerConfig & the NAS container list, SecurityModeCommand,
  UECapabilityEnquiry, RRCRelease, and the UL messages).

## 9. NAS (ferrite-nas)

* 5GMM: `Deregistered → RegistrationInitiated → Authenticating → SecurityMode
  → Registered`, plus deregistration. 5G-AKA (MILENAGE, K_AUSF/K_SEAF/K_AMF,
  RES*), NAS security context (NIA2 integrity, NEA0/NEA2 ciphering, counts).
* 5GSM: PDU session establishment (IPv4), per-session state; emits
  `PduSessionUp { psi, ip, qos }` to the application.
* The NAS never touches RRC internals: it exchanges opaque NAS PDUs through
  `RrcNasSap`.

## 10. Application (ferrite-ue)

CLI/TOML config: radio endpoint & rate, centre frequency / ARFCN, optional
SSB ARFCN hint, subscriber credentials, duplex-independent. The app wires the
layers, runs the L1 engine, owns the TUN device and the built-in ICMP probe,
prints a per-layer state log, and exits with a status that the test harness
can assert on (`--exit-after-ping N`, `--timeout`).

## 11. What is explicitly *not* configuration-specific

* No slot-pattern constants: TDD gates come from `tdd-UL-DL-ConfigCommon`;
  for FDD every slot is DL and UL.
* No PRACH timing constants: occasions are enumerated from the configuration
  table and placed by symbol.
* No DCI size constants: sizes are computed per 38.212 from the configuration
  (and size-aligned per §7.3.1.0).
* No PUCCH/CSI resource constants: from `PUCCH-Config` / `CSI-MeasConfig`.
* No `time_first`/CDM/TBS sweeps: the mapping order is the spec order, CDM
  groups come from the DCI antenna-port field, TBS from 38.214 §5.1.3.2.
