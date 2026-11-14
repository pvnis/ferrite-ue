# Ferrite UE — architecture

Ferrite is a clean-room 5G NR standalone UE written in Rust from the 3GPP
specifications. This document is the design contract for the code base: what
each crate owns, the interfaces between layers, and the state machine each
layer runs. It is deliberately independent of any one cell configuration —
every cell-specific number (numerology, bandwidth, duplex mode, PRACH format,
CORESET geometry, k1/k2, PUCCH resources, …) is **derived at run time** from the
MIB, SIB1 and the dedicated RRC configuration, never transcribed. Nothing above
`ferrite-radio` knows which transport (ZMQ, file, SDR) carries the samples.

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ ferrite-ue   binary: config, engine wiring, stack glue (bearers, user plane) │
 ├────────────────┬───────────────┬──────────────────┬──────────────────────────┤
 │ ferrite-nas    │ ferrite-rrc   │ ferrite-pdcp     │ ferrite-rlc              │
 │ 5GMM/5GSM SM   │ RRC SM + cfg  │ SRB/DRB PDCP     │ TM/UM/AM entities        │
 ├────────────────┴───────────────┼──────────────────┴──────────────────────────┤
 │ ferrite-mac  RA, HARQ, BSR/SR, │ ferrite-security  NIA/NEA, TS 33.501 KDF,   │
 │  LCP, TA, PHR, mux/demux       │                   MILENAGE (one copy)        │
 ├────────────────────────────────┴─────────────────────────────────────────────┤
 │ ferrite-fapi   PHY ↔ MAC messages + PhyConfig (plain data, no DSP)           │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ ferrite-l1     slot engine: sync, PDCCH monitoring, PDSCH/HARQ rx,           │
 │                PRACH/PUSCH/PUCCH/SRS tx, UL timing, DCI → grant resolution   │
 ├──────────────────────────────┬───────────────────────────────────────────────┤
 │ ferrite-phy  DSP: OFDM, sync,│ ferrite-radio  ZMQ / file / SDR IQ transports │
 │  coding, channels, PRACH     │                (SampleSource / SampleSink)    │
 ├──────────────────────────────┴───────────────────────────────────────────────┤
 │ ferrite-ran  TS 38.21x tables & arithmetic: MCS, TBS, DM-RS positions, PRACH │
 │              configuration, RIV, default TDRA, SRS bandwidth (no DSP)        │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ ferrite-asn1  UPER codec + TS 38.331 message coders        ferrite-common    │
 └──────────────────────────────────────────────────────────────────────────────┘
```

Crate dependencies (Cargo):

| crate | depends on |
|---|---|
| `ferrite-ran` | common |
| `ferrite-fapi` | common, ran |
| `ferrite-phy` | common, ran (+ radio for tests) |
| `ferrite-l1` | common, fapi, phy, radio |
| `ferrite-mac` | common, fapi, ran |
| `ferrite-security` | — (RustCrypto) |
| `ferrite-pdcp`, `ferrite-rlc` | common (+ security for PDCP) |
| `ferrite-rrc` | common, asn1, fapi, ran, mac (MacConfig), security |
| `ferrite-nas` | common, security |
| `ferrite-ue` | everything |

MAC and RRC never link the DSP crate: everything they need about grants and
configuration is plain data in `ferrite-fapi`, and the few spec tables they
compute with (PRACH occasions, TBS) come from `ferrite-ran`. Dependency
direction is strictly downward; every cross-layer interaction is a message or
a trait call on a service-access point defined by the lower layer.

## 1. Vocabulary (ferrite-common)

* `Iq` (complex f32), `Error`/`Result`.
* `Numerology { mu }` and `SlotPoint { mu, sfn, slot }`: the slot clock shared
  by every layer (`add`, `diff`, absolute index arithmetic mod 1024 frames).
* `Rnti` newtype, `RntiKind { Si, P, Ra, Tc, C }`.
* `DuplexMode`, band table subset with ARFCN ↔ Hz / GSCN ↔ Hz.

## 2. Spec tables (ferrite-ran) and DSP (ferrite-phy)

`ferrite-ran` is pure arithmetic over plain data (TS 38.211–38.214 tables):
`mcs` (tables 1/2/3 and 6.1.4.1-1), `tbs` (§5.1.3.2), `dmrs` (DM-RS symbol
positions, antenna-port tables), `prach_config` (configuration tables FR1
FDD/TDD, occasion enumeration), `riv`, `tdra` (default tables), `srs`
(bandwidth table, layout). `ferrite-phy` re-exports them under its old paths.

`ferrite-phy` is signal processing: pure functions over slices, no I/O, no cell
state beyond the arguments, generalised over `mu ∈ {0,1}` and any `fs`.

| module | content | spec |
|---|---|---|
| `numerology`, `ofdm` | CP lengths, (de)modulator, `PhaseCompensation` (§5.4 per-symbol carrier phase, applied on UL, undone on DL) | 38.211 §4, §5.3, §5.4 |
| `sync::*` | PSS/SSS, SSB cases A/B/C, PBCH + MIB, CFO, SS-RSRP/RSRQ/SINR | 38.211 §7.4.3, 38.213 §4.1, 38.215 |
| `coreset0` | Tables 13-1…13-6, 13-11 | 38.213 §13 |
| `pdcch` | CORESET geometry, candidate hashing, DM-RS, equalisation, coherence gate | 38.211 §7.3.2, 38.213 §10.1 |
| `coding::dci` | polar DCI, field layouts and sizes for 0_0/1_0/0_1/1_1 from the RRC configuration | 38.212 §7.3.1 |
| `coding::{crc,polar,ldpc,ratematch,dlsch}` | channel coding (structured LDPC encoder, AVX2 decoder) | 38.212 §5 |
| `pdsch` | RE extraction in §7.3.1.5 order, VRB→PRB, rate matching around CSI-RS, demapping | 38.211 §7.3.1, 38.214 §5.1 |
| `pusch` | CP-OFDM and DFT-s-OFDM PUSCH (transform precoding, low-PAPR DM-RS, π/2-BPSK), UCI multiplexing | 38.211 §6.3.1, 38.212 §6.2.7 |
| `pucch` | formats 0, 1, 2, 3 | 38.211 §6.3.2 |
| `prach` | preamble formats 0–3 and A1–C2, waveform at any `fs` | 38.211 §6.3.3 |
| `srs` | low-PAPR sequences, SRS modulation | 38.211 §6.4.1.4 |
| `csi` | NZP-CSI-RS sequence, SINR, CQI | 38.211 §7.4.1.5, 38.214 §5.2 |

## 3. Radio transport (ferrite-radio)

`SampleSource` / `SampleSink` traits; backends: ZMQ (gNB-compatible REQ/REP
lockstep), file, SDR (seify, feature-gated). The L1 engine only sees sample
indices; the lockstep pacing policy (`UlPacing`) is selected by the backend.

## 4. L1 — the slot engine (ferrite-l1)

`ferrite-l1` turns a sample stream into slot-synchronous FAPI messages for MAC
and turns MAC transmit requests into samples at the right absolute position.
It is the only crate that knows about sample indices.

### 4.1 Threads

```
 radio-rx thread ─▶ BufferedStream ─▶ timeline thread (T0) ─▶ PDSCH worker
                                            │  ▲                   │
                                            ▼  └── RX_Data ◀───────┘
                                   MAC/RLC/PDCP/RRC/NAS (synchronous on T0)
                                            │ UL_TTI.request
                                            ▼
                                       tx-build thread ─▶ InjectionTable ─▶ UL serve thread
```

T0 owns the slot clock: per DL slot it reads the samples, tracks timing/CFO on
the SSB, runs the PDCCH monitor, hands PDSCH jobs to the worker, waits for the
worker's results of earlier slots, then delivers `SLOT.indication` and applies
the MAC's requests.

### 4.2 Timing model

`ul_index(slot) = dl_index(slot) − (N_TA + N_TA_offset)·T_c·fs` (38.211
§4.3.1) plus the *uplink guard* (default 1 µs, applied to every UL channel; the
TA command measures and cancels it). The PRACH is transmitted with `N_TA = 0`
(`SampleClock::with_n_ta(0)`). Lockstep transports are served up to a *commit
mark* (`ul_index(n + tx_lead + 1)` after slot `n`), never a heuristic "k slots
behind"; a free-running SDR does not use the mark.

### 4.3 L1 state

```
 CellSearch ──SSB + MIB──▶ Synced { phase: AwaitSib1 } ──CONFIG.request (SIB1)──▶ { phase: Common }
     ▲                           │                                               │ CONFIG.request (dedicated)
     │ PSS missed for             │                                               ▼
     │ RLM_MAX_MISSED_SSB periods ◀──────────────────────────────────── { phase: Dedicated }
```

`CellPhase` is set by every `CONFIG.request` (dedicated when a UE-specific
search space or PUCCH resource is configured). Orthogonal to it: `tx_enabled`
(`START` / `STOP.request`; a `STOP` makes every UL_TTI request an
`ERROR.indication TxDropped`), the uplink timing (`SampleClock`, N_TA from
MAC) and the HARQ soft buffers of the PDSCH worker (one per `(RntiKind,
process)`, reset when the NDI toggles or the TB size changes).

Radio link monitoring (TS 38.133 §8.1) runs once per SSB period on the
serving SSB: `rlm_evaluate` turns the SSB SINR into `SYNC.indication
in_sync = false` below Q_out (−8 dB, or SSB not found) and `in_sync = true`
above Q_in (−6 dB), nothing in between. The indication goes to MAC, which hands
it to RRC unchanged; RRC runs N310 / T310 / N311 with the cell's values. The
engine's own `RlmState` is separate: after `RLM_MAX_MISSED_SSB` (250) periods
without the PSS the slot timing cannot be trusted any more and it re-searches
and rebuilds `Synced` from the MIB (MAC receives `ErrorIndication::SyncLost`;
RRC must send a new `CONFIG.request` and MAC new RNTIs once the cell is found
again). That limit is above the largest T310 so that RRC declares the failure
first. `EngineParams::rlm_outage` (`--rlm-outage-s/-ms`) forces out-of-sync for
a test window without touching the data path.

## 5. FAPI: the PHY ↔ MAC interface (ferrite-fapi)

Modelled on the SCF-222 5G FAPI PHY API, adapted to the UE direction. The
crate holds plain data only: the messages and `config::PhyConfig` (the
CONFIG.request payload RRC derives from MIB/SIB1/CellGroupConfig).

```rust
enum PhyToMac { Slot(SlotIndication), Dci(DciIndication), RxData(RxDataIndication),
                Csi(CsiIndication), Rach(RachIndication), Sync(SyncIndication),
                Error(ErrorIndication) }
enum MacToPhy { Config(Box<PhyConfig>), Start, Stop, UlTti(UlTtiRequest),
                SetRntis { c_rnti, tc_rnti, ra_rnti }, TimingAdvance { n_ta_tc },
                Paging { ue_id }, RarGrant { rar_slot, tc_rnti, grant: RarUlGrant } }
enum UlTtiPdu { Prach { occasion, preamble, power_offset_db },
                Pusch { grant: UlGrant, tb, uci }, Pucch { resource, uci }, Srs { resource_id } }
trait MacHandler { fn handle(&mut self, msg: PhyToMac, phy: &mut dyn MacToPhySink); }
```

The PHY owns the configuration, so it **resolves** every grant: the `Dci`
indication carries `DlGrant` / `UlGrant` (PRBs, symbols, MCS, TBS, HARQ id,
NDI, RV, timing, PUCCH indicator, DAI, DM-RS and transform-precoding
parameters), never DCI bit fields. The RAR UL grant follows the same rule: MAC
parses the RAR MAC PDU and sends `RarGrant`; the PHY answers with a TC-RNTI
`UlGrant` for `rar_slot + k2 + Δ` (TS 38.213 §8.2/8.3) that MAC turns into
Msg3 like any other PUSCH. Common search spaces are decoded before UE-specific
ones and a payload already decoded for an RNTI in a slot is not decoded again
(phantom grants through overlapping candidates). `Paging { ue_id }` turns on
P-RNTI decoding in the UE's paging frames (TS 38.304 §7.1).

## 6. MAC (ferrite-mac)

`MacEntity::handle_with(msg, phy, upper)` is the FAPI entry; `UpperLayers`
(`dl_sdu`, `ul_pull`, `ul_buffer_status`) is the SAP the bearer table
implements; RRC drives it with `reconfigure`, `start_ra`, `reset` and reads
`take_events()` (`MacEvent`: `RaSucceeded`, `RaFailed`, `Bcch`, `Pcch`, `Ccch`,
`SrFailure`, `TimeAlignmentExpired`, `RadioLinkFailure`, `Sync`). Fields are private;
`ra_state()`, `ta_state()`, `sr_states()`, `c_rnti()`, `stats()` are read-only
views. Sub-procedures and their states:

* **Random access** (§5.1), `RaState`:
  `Idle → SelectResource → PreambleRequested → RarWindow → Msg3Pending →
  ContentionResolution → Succeeded | Failed`, with backoff and power ramping on
  every retry (window / timer expiry) until `preambleTransMax`. `Msg3Pending`
  is the wait for the PHY's resolution of the RAR grant.
* **Scheduling request** (§5.4.4), `SrState`: `Idle → Pending { counter,
  prohibit } → Idle` (a BSR went out) or `→ Failed` (sr-TransMax: the entity
  starts a C-RNTI random access and reports `SrFailure`). An SR configuration
  is triggered only by logical channels mapped to it (`schedulingRequestID`).
* **Timing advance** (§5.2), `TaState`: `NotAligned → Aligned { expiry }` on
  the RAR / every TA Command CE; on `timeAlignmentTimer` expiry the HARQ
  buffers are flushed, no uplink but PRACH is transmitted and RRC is told.
* **HARQ**: DL per process `ndi` / `delivered` (duplicates of a delivered TB
  are dropped); UL per process the stored TB for retransmissions at the
  signalled RV; the HARQ-ACK codebook (dynamic, §9.1.3) is booked per slot.
* **BSR** (§5.4.5, regular/periodic/padding, short/long), **LCP** (§5.4.3.1),
  **PHR** (§5.4.6, Single Entry PHR from a `PowerHeadroom` input), **SRS**
  occasions (dropped when a PUCCH/PUSCH goes out in the slot).
* DL MAC PDU parsing follows TS 38.321 Table 6.2.1-1 (fixed-size CEs, SDUs
  with L fields; eLCID / reserved LCIDs stop the parse).

## 7. RLC (ferrite-rlc) and PDCP (ferrite-pdcp)

`RlcEntity::new(RlcMode::{Tm, Um(UmConfig), Am(AmConfig)}, numerology)` with
`tx_sdu`, `rx_pdu`, `pull_pdu(max_bytes, now)`, `pop_rx_sdu`, `tick`,
`events()` (`MaxRetxReached`). AM: full window, segmentation and
re-segmentation, STATUS with NACK ranges, polling, t-Reassembly /
t-PollRetransmit / t-StatusProhibit. UM: per-SN reassembly with t-Reassembly.

`PdcpEntity` (38.323): SN 12/18, `tx_sdu`, `rx_pdu`, `pop_rx_sdu`, `tick`,
reordering, HFN inference, `configure_security(SecurityConfig)` with the typed
`IntegrityAlg` / `CipherAlg` of `ferrite-security` (NIA1/NIA3/NEA1/NEA3 are
rejected, never silently passed through), `verify_only(pdu, alg, key)` for the
SecurityModeCommand / RRCReestablishment MAC-I checks, `reestablish()`.

## 8. Security (ferrite-security)

One implementation of 128-NIA2 (AES-CMAC), 128-NEA2 (AES-CTR), the null
algorithms, the TS 33.501 Annex A key hierarchy (RES*, K_AUSF, K_SEAF, K_AMF,
K_gNB, the NAS/RRC/UP algorithm keys with their type distinguishers 0x01–0x06,
the horizontal K_NG-RAN*) and MILENAGE. `IntegrityAlg` / `CipherAlg` carry the
identifier and `is_supported()`; the NAS capability advertises exactly the
supported set (EA0/EA2, IA0/IA2).

## 9. RRC (ferrite-rrc)

`RrcUe` keeps `RrcState` (TS 38.331 §4.2.1 plus the two procedure sub-states;
every transition goes through `set_state`, which logs it):

```
 Idle ──connect / connect_for (RRCSetupRequest, T300)──▶ Connecting ──RRCSetup──▶ Connected
 Connecting ──T300 / RRCReject / RA failure──▶ Idle
 Connected ──RRCRelease──▶ Idle          Connected ──RLF, AS security active (T301)──▶ Reestablishing
 Connected ──RLF without security──▶ Idle   Reestablishing ──RRCReestablishment verified──▶ Connected
 Reestablishing ──T301 / RRCReject / RRCSetup fallback / RA failure──▶ Idle
```

Radio link failure (§5.3.10.3) comes from `MacNotification`: T310 expiry
(`SyncIndication`s from the PHY: N310 consecutive out-of-sync start T310, N311
consecutive in-sync stop it; T310/N310/N311 from SIB1 `ue-TimersAndConstants`,
only counted while `Connected`), `RaFailed` while connected, `RlcMaxRetx`, and
`RadioLinkFailure` (the PHY gave the cell up). T311 is trivially satisfied
today: the UE re-selects the serving cell at once. `RRCSetup` is
accepted only while `Connecting`; an algorithm the UE cannot run in a
SecurityModeCommand yields a SecurityModeFailure. RRC never touches the lower
layers: it emits `RrcEvent`s (`CellConfigured`, `Reconfigure`, `SetupBearer`,
`ReleaseBearer`, `StartRa`, `TxSrb`, `VerifySecurity`, `VerifyReestablishment`,
`Reestablishing`/`Reestablished`, `DlNas`, `Connected`, `Released`, `Paged`,
`Failed`) that the stack applies, and reads `MacNotification`s. Procedures:
system information (MIB/SIB1 → `PhyConfig`/`MacConfig`, SI messages), connection
establishment, security mode, UE capability (256-QAM), reconfiguration (bearer
setup with PDCP/RLC continuity, dedicated PHY/MAC as a delta, CSI-RS add/mod/
release), DL/UL information transfer, release to idle (paging with the
5G-S-TMSI, service request for data / paging), re-establishment (shortMAC-I,
horizontal K_NG-RAN*), measurements (`meas.rs`: L3 filtering, periodical and
A1/A2 reports). Configuration derivation lives in `codec.rs`
(`cell_from_sib1`, `apply_cell_group`, `bearers_of`); nothing below RRC sees
ASN.1.

## 10. NAS (ferrite-nas)

`NasUe` keeps `MmState` (`Deregistered → RegistrationInitiated →
Authenticating → SecurityMode → Registered`, plus `ServiceRequestInitiated`
and `DeregistrationInitiated`) and one `SmState` per PDU session (`Inactive →
ActivePending → Active → InactivePending`). Timers T3510, T3512, T3517, T3520,
T3521, T3580, T3582 run on the millisecond clock of `tick`. 5G-AKA with
MILENAGE and SQN management, NAS security context (NIA2 / NEA0 / NEA2), PDU
session establishment (IPv4). The NAS exchanges opaque PDUs with RRC through
the stack (`NasUe::on_dl_nas` → UL PDUs; `NasEvent`s to the stack).

## 11. Application (ferrite-ue)

* `stack.rs`: thin glue implementing `MacHandler`. Owns `MacEntity`, the
  bearer table, `RrcUe`, `NasUe` and the user plane; routes `MacEvent` →
  `MacNotification`, applies `RrcEvent`s, drains `NasEvent`s (after every DL
  NAS message and every NAS tick), holds the AS-security hand-over state (the
  verified `AsSecurity` and the two raw PDUs awaiting MAC-I verification), the
  connection retry policy and the uplink queue of an idle UE.
* `bearers.rs`: `Bearers` (RLC + PDCP per LCID) implementing `UpperLayers`:
  `setup(BearerSetup)` with PDCP/RLC continuity, `install_security`,
  `begin/end_reestablishment`, `deliver_rx`. The default DRB is derived from
  the table (no separate bookkeeping to go stale).
* `userplane.rs`: TUN device, or the built-in ICMP echo client / responder.
* `config.rs`, `main.rs`: CLI/TOML, engine wiring, event reporting, exit code.

## 12. What is explicitly *not* configuration-specific

* No slot-pattern constants: for FDD every slot is DL and UL; TDD gates come
  from `tdd-UL-DL-ConfigCommon`.
* No PRACH timing constants: occasions are enumerated from the configuration
  table and placed by symbol.
* No DCI size constants: sizes are computed per 38.212 from the configuration.
* No PUCCH/CSI resource constants: from `PUCCH-Config` / `CSI-MeasConfig`.
* No mapping-order / CDM / TBS sweeps: spec order, DCI antenna-port field,
  38.214 §5.1.3.2.
