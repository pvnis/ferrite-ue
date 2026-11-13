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
| `pucch` | formats 0, 1, 2 | 38.211 §6.3.2 |
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
  preamble is additionally delayed by `prach_offset` (default 1 µs): a
  detector window may start slightly after the slot and reject negative
  delays (OCUDU does), and over a zero-delay transport nothing else provides
  that margin. Over the air the propagation delay plays the same role.

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
                SetRntis { c_rnti, tc_rnti, ra_rnti }, TimingAdvance { n_ta_tc } }
enum UlTtiPdu { Prach { occasion, preamble, power_offset_db },
                Pusch { grant: UlGrant, tb: Vec<u8>, uci: UciPayload },
                Pucch { resource: PucchResourceRef, uci: UciPayload } }
```

The `Dci` carried in the indication is the *resolved* grant: the PHY holds the
configuration (TDRA tables, k1 list, BWP size, DMRS config, MCS table, PUCCH
resource sets), so it converts the raw DCI fields into `ResolvedDlGrant` /
`ResolvedUlGrant` (PRBs, symbols, DMRS symbols, TBS, HARQ id, NDI, RV, k0/k1/k2,
PUCCH resource indicator, DAI) before handing them to MAC.

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
  release.
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
