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
| `pusch` | CP-OFDM and DFT-s-OFDM PUSCH (transform precoding, low-PAPR DM-RS, π/2-BPSK), UCI multiplexing (`uci_pusch_layout`: HARQ-ACK / CSI part 1 counts and RE map as OCUDU's demultiplexer reads them) | 38.211 §6.3.1, 38.212 §6.2.7, §6.3.2.4 |
| `pucch` | formats 0, 1, 2, 3 | 38.211 §6.3.2 |
| `prach` | preamble formats 0–3 and A1–C2, waveform at any `fs` | 38.211 §6.3.3 |
| `srs` | low-PAPR sequences, SRS modulation | 38.211 §6.4.1.4 |
| `csi` | NZP-CSI-RS sequence, rows 1/2/3/4 RE patterns, SINR / CQI, two- and four-port rank + PMI selection on the Type I single-panel codebook | 38.211 §7.4.1.5, 38.214 §5.2 |

## 3. Radio transport (ferrite-radio)

`SampleSource` / `SampleSink` traits; backends: ZMQ (gNB-compatible REQ/REP
lockstep), file, SDR (SoapySDR through the `soapysdr` crate, feature-gated).
Time above this crate is counted in samples: a backend with a device time base
reports the sample index of every delivered buffer (`SampleSource::timestamp`)
and takes timed bursts by sample index (`SampleSink::write_at`); the SoapySDR
backend converts to the library's nanoseconds once per buffer with SoapySDR's
own algorithm and the rate its timestamps actually advance at (measured at open
time: the LimeSuiteNG module converts with the requested rate while reporting
the achieved one), and checks that the conversion is the identity. Both chains
are set up before either is activated and torn down together (modules with one
shared stream object need both). `time::Contiguous` pins a timestamped source
to a gap-free index: stream sample `i` is device sample `origin + i`, lost
samples (overflows) come out as zeros, and the shared `TimeBase` publishes the
origin and the receive head to the transmit side. The L1 engine only sees
sample indices; the pacing policy (`UlPacing`) is selected by the backend.

`channel` is a test aid, not a backend: a multipath fading channel
(`Link`) for the `ferrite-chanem` ZMQ proxy (TEST_PLAN §5.2). Per block it
resamples (windowed-sinc, 1024 phases; the sample-clock error), filters with
a per-antenna-pair FIR rebuilt every 64 samples from the faded TDL taps, mixes
the carrier offset and adds noise. The proxy pulls each direction's upstream
blocks in a fetcher thread, keeps the antenna ports sample-aligned when the
transmitter's replies differ in length (carry-over buffers), and answers each
downstream port from its own thread, so a reader that drains one port before
the next never stalls the others.

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

T0 owns the slot clock: per DL slot it reads the samples, tracks timing/CFO
(§4.2b), runs the PDCCH monitor, hands PDSCH jobs to the worker, waits for the
worker's results of earlier slots, then delivers `SLOT.indication` and applies
the MAC's requests.

### 4.2 Timing model

`ul_index(slot) = dl_index(slot) − (N_TA + N_TA_offset)·T_c·fs` (38.211
§4.3.1) plus the *uplink guard* (default 1 µs, applied to every UL channel; the
TA command measures and cancels it). The PRACH is transmitted with `N_TA = 0`
(`SampleClock::with_n_ta(0)`). Lockstep transports are served up to a *commit
mark* (`ul_index(n + tx_lead + 1)` after slot `n`), never a heuristic "k slots
behind". A free-running SDR is gated by the same mark (a block is written only
once its uplink is final) but not paced: `TimedPushUlSink` stamps every block
with its air time `origin + ul_index` in the device clock shared with the
receive side, and skips (counts, logs) a block whose air time is nearer than the
device's write-to-air latency budget (`--sdr-tx-latency-us`) instead of handing
it over late. The RX→TX chain latency of a device is `--tx-rx-offset`,
measured with the `tx_rx_cal` example (loopback burst).

### 4.2b Synchronisation tracking (`track`)

`SyncTracker` owns the CFO estimate and every move of the sample clock's
anchor. It is fed, relative to what the anchor predicts:

* at every SSB, the integer PSS position plus the fractional delay from the
  SSS phase slope (`SsbMeasurement::delay_samples`), and the CP-correlation
  CFO residual;
* for every PDSCH that passes its CRC, the delay from the DM-RS phase rotation
  four subcarriers apart (`pdsch::dmrs_delay`, unaffected by a second port in
  the CDM group or a PRB-wise precoder) and the residual CFO from the rotation
  between DM-RS symbols (`PdschLlrs::cfo_slope`).

Each measurement carries a `SyncTag` (DL index, anchor steps applied so far,
CFO removed from those samples), so results from the worker that arrive after
a step are referred to the current anchor. Timing is a critically damped
second-order loop (offset and drift, 0.5 Hz natural frequency) whose gains
scale with the time between measurements, so the bandwidth does not depend on
the scheduling; the CFO is a first-order filter (100 ms). When LO and sample
clock share a reference (`--independent-lo` says otherwise), the drift is fed
forward as `−CFO/f_c · f_s` samples per second, and the loop's own rate state
only takes the remainder. `advance()` integrates the drift once per slot and
hands out one-sample anchor steps when the modelled offset passes ¾ of a
sample; errors beyond 3 samples (a gap, a transport jump) are taken at once.
Downlink and uplink follow the same anchor, so the transmit timing drifts with
the downlink in small steps. Every 10.24 s the engine logs a `tracking:` line
with CFO, drift (ppm), offset and step counts. Over ZMQ every measurement is
zero and no step is taken.

### 4.2a Receive gain (`agc`)

When the front end has a gain (`ferrite_radio::GainControl`, attached to the
`DlStream`), the engine runs an AGC on downlink power only: every cell-search
capture and every SSB slot (a downlink slot by definition; over TDD the uplink
slots carry the UE's own leakage). It aims the mean slot power at −22 dBFS
(OFDM peaks sit 10–12 dB higher), moves in whole dB outside a ±3 dB band, holds
200 slots after a change so the tracking loops settle, and learns the device's
real limits from what it applies (the XTRX advertises 49 dB and stops at 48).
Every SSB measurement carries the gain in force, and the stack converts
`dBm = dBFS − gain + rx_power_offset_db` (the dBm of full scale at 0 dB gain,
a device constant; 0 over ZMQ).

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

The TDD pattern is a scheduling input: `DciResolver` drops a PDSCH that
would lie in UL symbols and a PUSCH (DCI 0_0/0_1, RAR grant) in DL symbols
(`PhyConfig::dl_allowed` / `ul_allowed`, TS 38.213 §11.1; flexible symbols are
allowed), and `PrachConfig::occasions_in_slot` keeps only the occasions valid
under TS 38.211 §6.3.3.2 (UL symbols, or flexible symbols after the slot's
SS/PBCH blocks plus `N_gap`; the transmitted SSBs come from SIB1 through
`ferrite_ran::ssb`). A DCI 1_1 / 0_1 whose bandwidth-part indicator names
another BWP resolves to `Dci::BwpSwitch` (TS 38.212 Table 7.3.1.1.2-1 value →
BWP-Id); the grant it carries is not resolved, so the gNB's first
transmission on the new BWP is lost and retransmitted — a known simplification.

Receive antennas: `radio::DlStream` holds one `BufferedStream` per antenna
and reads them in lockstep (same sample index everywhere); cell search and
the SSB tracking read antenna 0, the slot loop reads all antennas and hands
`Arc<Vec<Vec<Iq>>>` (per antenna) to the PDSCH worker, which demodulates every
antenna. The PDCCH monitor uses antenna 0. PDSCH: the 1x1 case keeps the
single-port extractor; with several antennas or two layers
`pdsch::extract_pdsch_mimo` estimates the channel of every (antenna, DM-RS
port) from the type-1 DM-RS (ports 0/1 of a CDM group separated by the
frequency OCC over each RE pair, TS 38.211 §7.4.1.1.2), averages the
de-rotated per-symbol estimates per RB, takes the noise variance from the
spread of the pair estimates and equalises every data RE with a regularised
zero-forcing combiner (MRC for one layer); the LLRs come out in codeword
order (layer 0 then layer 1 per RE, §7.3.1.3) and the TBS/rate matching use
`n_layers`. DCI 1_1 antenna-port values with one or two DM-RS ports are
resolved (`DlGrant::{n_layers, dmrs_ports}`); three and four layers are
dropped. The CSI report goes out in the TS 38.212 Table 6.3.1.1.2-7 layout
(`RI | padding | PMI | CQI`). The field widths come from the codebook
(`ferrite_ran::codebook::Codebook`: one port, two ports, or a Type I
single-panel `N1 × N2` panel with `O1 = 4`, `O2 = 4` if `N2 > 1` else 1;
Table 6.3.1.1.2-1, mode 1) and from the `ri-Restriction`, whose bit `i`
(LSB = rank 1) allows rank `i + 1`. The PMI is
`i1,1 | i1,2 | i1,3 | i2`, padded in front to the widest allowed rank; for
4 ports that is 5 bits at ranks 1 and 2 and 4 at ranks 3 and 4. The rank and
PMI come from the two-port NZP-CSI-RS (Table 7.4.1.5.3-1 row 3: one FD-CDM2
group on `k0, k0+1`) or the four-port one (row 4: groups on `k0, k0+1` and
`k0+2, k0+3`); the sequence index is `2n + k'` in both.
`csi::measure_csi_rs_ports` despreads the ports on every receive antenna
per RB, takes the noise from the RB-to-RB spread of the estimates, and
searches every PMI of ranks 1 and 2 (`csi::pmi_hypotheses`,
`csi::type1_precoder`):
* two ports (TS 38.214 Table 5.2.2.2.1-1): rank 1 `[1, φ_n]/√2`, rank 2
  `[[1, 1], [φ_n, −φ_n]]/2`, `φ_n = e^{jπn/2}`;
* `2·N1·N2` ports (Tables 5.2.2.2.1-5/-6): rank 1 `[v_{l,m}; φ_n v_{l,m}]`,
  rank 2 with the second beam `v_{l+k1, m+k2}` and `−φ_n`.

It keeps the PMI that maximises the sum of the per-layer `log2(1 + SINR)`
(MRC gain for rank 1, post-MMSE SINRs for rank 2). The CQI maps the
capacity-equivalent SINR of that choice, `2^(mean log2(1 + SINR)) − 1`
over RBs and layers (one codeword spans them all). The engine queues a CSI measurement on every
occasion of a measured resource: the single-port TRS, and every two- or
four-port resource, measured against the codebook of the report with that
port count. The MAC keeps the rank / PMI of the latest multi-port
measurement and lets a single-port one refresh only the CQI
(`CsiIndication::nof_ports`).

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
                Paging { ue_id }, PdcchMonitoring { c_rnti: bool },
                RarGrant { rar_slot, tc_rnti, grant: RarUlGrant } }
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
* **DRX** (§5.7), `DrxState`: `Off → Long ⇄ Short { until }`. `drx.rs` runs
  drx-onDurationTimer (from `[(SFN×10)+subframe] mod cycle = offset`, plus
  `drx-SlotOffset`), drx-InactivityTimer (restarted by every C-RNTI PDCCH:
  the spec says new transmissions only, but OCUDU extends the Active Time on
  retransmission grants too and staying awake longer never loses data),
  per-HARQ-process RTT → retransmission timers (DL only for a TB that
  was not decoded) and the short-cycle timer; the DRX / Long DRX Command CEs
  end the on-duration. Active Time also covers a running random access and a
  pending SR. Each slot the entity tells the PHY `PdcchMonitoring { c_rnti }`
  on a change, so C-RNTI candidates are not searched while asleep; periodic
  CSI is skipped outside Active Time, HARQ-ACKs are always sent, and the
  periodic SRS keeps going by default (`MacConfig::srs_outside_active_time`:
  OCUDU derives the timing advance from every SRS occasion, empty ones
  included, and walks the uplink out of the cyclic prefix otherwise).
* **Bandwidth parts** (§5.15): `MacConfig::{dl_bwp_id, default_dl_bwp_id,
  bwp_inactivity_timer_ms}`. The bwp-InactivityTimer runs on a non-default
  BWP, restarts on every C-RNTI PDCCH, is stopped by a random access and
  switches back to the default BWP on expiry; a `Dci::BwpSwitch` and a random
  access from a non-initial BWP (only the initial UL BWP has PRACH) also
  request a switch. Every switch is a `MacEvent::BwpSwitch` that RRC answers
  with the BWP's configuration (`Reconfigure` → CONFIG.request).
* **BSR** (§5.4.5, regular/periodic/padding, short/long), **LCP** (§5.4.3.1),
  **PHR** (§5.4.6, Single Entry PHR, Type 1 from the power-control state),
  **SRS** occasions (dropped when a PUCCH/PUSCH goes out in the slot).
* **Uplink power control** (TS 38.213 §7, `power.rs`, `UlPowerControl`): the
  pathloss is `ss-PBCH-BlockPower − filtered SS-RSRP (dBm)`; PRACH =
  target + ramp + PL; PUSCH = `P_O + 10·log10(2^µ·M_RB) + α·PL + f(i)` with
  `f(0) = ΔP_rampup + δ_msg2` from the RAR and the UL-DCI TPC accumulated (or
  absolute); PUCCH adds `Δ_F`, `Δ_TF` (formats 0/1 by symbols, 2–4 by UCI bits
  per RE) and `g(i)` from the DL-DCI TPC; SRS rides the PUSCH loop; all capped
  at `P_CMAX = min(p-Max, device full scale − 12 dB)`. Every UL_TTI PDU carries
  `power_dbm`; the L1 sets the RMS level against the transmitter calibration
  (`PhyConfig::tx_full_scale_dbm`, from `--tx-power-offset-db`) and adds the
  format's `Δ_PREAMBLE` to the PRACH. Without a calibration (ZMQ) powers are
  `None` and waveforms are peak-normalised as before.
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
today: the UE re-selects the serving cell at once. Bandwidth parts: every
`CellGroupConfig` is applied per configured DL BWP (`codec::cell_group_bwps`
→ `apply_cell_group_bwp`: the BWP's generic parameters and common
PDCCH/PDSCH/PUSCH/PUCCH config, its dedicated part, the cell-level items),
kept in `CellInfo::bwps`; `firstActiveDownlinkBWP-Id` selects the active one
and `RrcUe::switch_bwp` (from `MacNotification::BwpSwitch`) activates another
with a `Reconfigure`. The UL BWP with the same id is paired with a DL BWP,
the initial UL BWP otherwise. OCUDU configures a single BWP, so this path has
unit tests only (`tests/codec.rs`). `RRCSetup` is
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

`NasUe` keeps `MmState` with the TS 24.501 §5.1.3.2 substates:
`Deregistered(DeregisteredSub)` (`NormalService`, `LimitedService`,
`AttemptingRegistration`, `PlmnSearch`, `NoSupi`, `InitialRegistrationNeeded`),
the procedure states `RegistrationInitiated → Authenticating → SecurityMode`,
`Registered(RegisteredSub)` (`NormalService`, `NonAllowedService`,
`AttemptingRegistrationUpdate`, `LimitedService`, `PlmnSearch`,
`UpdateNeeded`), `ServiceRequestInitiated` and `DeregistrationInitiated`; and
one `SmState` per PDU session (`Inactive → ActivePending → Active →
InactivePending`). Orthogonal to it, `CmState` (5GMM-IDLE / 5GMM-CONNECTED) is
set by the stack from the RRC connection: a procedure started in 5GMM-IDLE
queues its first message and emits `NasEvent::ConnectionNeeded`; the stack
establishes the RRC connection (mo-Signalling) and carries
`take_pending_initial_message()` in RRCSetupComplete, with the AS keys derived
from that message's uplink NAS COUNT.

Timers (Table 10.2.1) run on the air-interface clock the stack derives from
the slot indications: T3510 (registration), T3511 / T3502 with the
registration attempt counter (§5.5.1.2.7: five T3511 retries, then T3502),
T3512 (periodic registration update, running only in 5GMM-IDLE, §5.3.7),
T3517, T3519 (SUCI reuse), T3520, T3521, T3346 (congestion back-off from a
REJECT or DEREGISTRATION REQUEST; `barred()` holds registrations and service
requests), T3580 / T3582. 5GMM causes map to substates in `cause_outcome`
(#3/#6/#7/#27 → `NoSupi`, #11/#73/#74 → `PlmnSearch`, #12/#13/#15/#72/#75/#76
→ `LimitedService`, #22 → T3346, #9/#10 → a fresh initial registration,
others → the attempt counter). A network DEREGISTRATION REQUEST with
"re-registration required" registers again on the same connection; a
CONFIGURATION UPDATE COMMAND with "registration requested" starts a mobility
registration update when the connection is released; a TAI outside the
registration area does so immediately. NOTIFICATION is answered with the PDU
session status, PDU SESSION MODIFICATION COMMAND with a COMPLETE (the default
QoS rule stays in force). 5G-AKA with MILENAGE and SQN management, NAS
security context (NIA2 / NEA0 / NEA2), PDU session establishment (IPv4). The
NAS exchanges opaque PDUs with RRC through the stack (`NasUe::on_dl_nas` → UL
PDUs; `NasEvent`s to the stack). Every uplink message is cross-checked in the
tests with the independent `oxirush-nas` decoder (`validate()` clean).

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

## 13. Declared state machines (`ferrite_common::fsm`)

A protocol state machine states its transitions as data: a `Machine` lists
its states (as a fieldless *kind* when the state carries data), its events
and a table of rules `(from, event) → to`, each with the specification
clause it implements; a deliberate deviation says `ferrite: …`. The entity
keeps its state in an `Fsm`, and `Fsm::transition` is the only way to change
it. A rule may start from a set of kinds, and a move that keeps the kind is a
data update that needs no rule. A guard asks `Fsm::allows` first, which is
not a violation. Otherwise: a move the table does not allow is refused (state unchanged), counted in
`FsmStats::violations` and logged as an error. It never panics. Every
transition made is logged with its clause, e.g.
`RRC Connecting → Connected on RrcSetup [38.331 §5.3.3.4]`. Leaving a state
stops the timers that belong to it.

Checks, cheapest first:

1. `fsm::check` per machine (unit test): rules use listed kinds and events,
   no self-loops or duplicates, every rule names a clause, every event is
   used, every kind is reachable from the initial one.
2. Scenario and randomised tests drive the real entity and assert no
   violation. RRC: `random_inputs_stay_inside_the_table`, 200 seeds × 120
   inputs, every table edge exercised, T300 only in Connecting, T301 only in
   Reestablishing, T310 only in Connected.
3. Kani proofs (`#[cfg(kani)]`, `cargo kani -p <crate>`) on the real code.
   RA: `ra_step_preserves_the_invariant` is an inductive proof. From *any*
   state with any data satisfying the invariant, one arbitrary input keeps
   the invariant, causes no violation, and does not panic or overflow. The
   invariant is: counter within 1..=preambleTransMax+1; Failed exactly when
   it is preambleTransMax+1; ramping counter ≤ transmission counter. Cover
   checks show that the failure, success and RAR paths are reachable, so
   the proof is not vacuous. `ra_moves_only_along_its_table` replays every
   6-input sequence from a fresh procedure. About 30 s and 10 min.
4. Planned: a composed NAS × RRC × MAC RA model for deadlock and liveness,
   validated against the transition logs of lab runs.

The diagrams below are generated from the tables, and
`ferrite-ue/tests/fsm_docs.rs` fails when they differ.

Machines on tables. This is everything in BACKLOG's plan except the
implicit machines: HARQ processes, RLC AM windows, and the stack's
connection retry and AS-security hand-over.

| Layer | Machine | Kinds | Verified by |
|---|---|---|---|
| L1 | `ferrite_l1::engine::CellPhaseMachine` | AwaitSib1, Common, Dedicated | table check; lab |
| L1 | `ferrite_l1::engine::RlmMachine` | InSync, OutOfSync | table check; unit test |
| MAC | `ferrite_mac::RaMachine` | 8 | Kani (inductive, 6-input bounded); attach test |
| MAC | `ferrite_mac::SrMachine` | Idle, Pending, Failed | Kani (inductive, 6 s); unit tests |
| MAC | `ferrite_mac::TaMachine` | NotAligned, Aligned | table check; unit tests |
| MAC | `ferrite_mac::DrxMachine` | Off, Long, Short | table check; unit tests |
| RRC | `ferrite_rrc::machine::RrcMachine` | 4 | randomised entity test (every edge) |
| NAS | `ferrite_nas::machine::MmMachine` | 15 (state × substate) | randomised entity test |
| NAS | `ferrite_nas::machine::CmMachine` | Idle, Connected | randomised entity test |
| NAS | `ferrite_nas::machine::SmMachine` | 4 (per PDU session) | randomised entity test |

The 5GMM randomised test (150 seeds × 150 inputs, partial registrations
with a fake core) reaches most edges. The ones it misses mostly leave
`Registered(NonAllowedService)` or `Registered(AttemptingRegistrationUpdate)`,
which random inputs rarely reach. `Registered(LimitedService)` and
`Registered(PlmnSearch)` exist in the type, but no procedure enters them,
so the table leaves them out.

<details><summary>L1 cell phase (<code>CellPhaseMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> AwaitSib1
    AwaitSib1 --> Common: CommonConfig
    Dedicated --> Common: CommonConfig
    Common --> Dedicated: DedicatedConfig
```

</details>

<details><summary>L1 radio link (<code>RlmMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> InSync
    InSync --> OutOfSync: SsbMissed
    OutOfSync --> InSync: SsbFound
```

</details>

<details><summary>MAC random access (<code>RaMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> SelectResource: Start
    Succeeded --> SelectResource: Start
    Failed --> SelectResource: Start
    PreambleRequested --> SelectResource: Start
    RarWindow --> SelectResource: Start
    Msg3Pending --> SelectResource: Start
    ContentionResolution --> SelectResource: Start
    SelectResource --> PreambleRequested: OccasionSelected
    PreambleRequested --> RarWindow: PreambleSent
    RarWindow --> Msg3Pending: RarReceived
    RarWindow --> SelectResource: RarWindowExpiry
    RarWindow --> Failed: RarWindowExpiry
    Msg3Pending --> SelectResource: Msg3GrantTimeout
    Msg3Pending --> Failed: Msg3GrantTimeout
    Msg3Pending --> ContentionResolution: Msg3Sent
    ContentionResolution --> Succeeded: ContentionResolved
    ContentionResolution --> SelectResource: ContentionResolutionExpiry
    ContentionResolution --> Failed: ContentionResolutionExpiry
```

</details>

<details><summary>MAC scheduling request (<code>SrMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Pending: Triggered
    Pending --> Failed: TransMaxReached
    Pending --> Idle: BsrSent
    Failed --> Idle: RandomAccessStarted
    Pending --> Idle: Reset
    Failed --> Idle: Reset
```

</details>

<details><summary>MAC time alignment (<code>TaMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> NotAligned
    NotAligned --> Aligned: Command
    Aligned --> NotAligned: TimerExpiry
    Aligned --> NotAligned: Reset
```

</details>

<details><summary>MAC DRX (<code>DrxMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Off
    Off --> Long: Configure
    Short --> Long: Configure
    Long --> Off: Configure
    Short --> Off: Configure
    Long --> Short: InactivityExpiry
    Short --> Long: InactivityExpiry
    Short --> Long: ShortCycleExpiry
    Long --> Short: DrxCommand
    Short --> Long: DrxCommand
    Short --> Long: LongDrxCommand
```

</details>

<details><summary>RRC (<code>RrcMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Connecting: Connect
    Connecting --> Connected: RrcSetup
    Connecting --> Idle: RrcReject
    Connecting --> Idle: T300Expiry
    Connecting --> Idle: RaFailure
    Connected --> Idle: Release
    Connected --> Reestablishing: RadioLinkFailure
    Connected --> Idle: RadioLinkFailure
    Reestablishing --> Connected: ReestablishmentVerified
    Reestablishing --> Idle: ReestablishmentFailure
    Reestablishing --> Idle: T301Expiry
    Reestablishing --> Idle: RrcReject
    Reestablishing --> Idle: RrcSetupFallback
    Reestablishing --> Idle: RaFailure
```

</details>

<details><summary>NAS 5GMM (<code>MmMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Deregistered_InitialRegistrationNeeded
    Deregistered_InitialRegistrationNeeded --> RegistrationInitiated: RegistrationRequested
    Deregistered_NormalService --> RegistrationInitiated: RegistrationRequested
    Deregistered_AttemptingRegistration --> RegistrationInitiated: RegistrationRequested
    Registered_NormalService --> RegistrationInitiated: RegistrationRequested
    Registered_NonAllowedService --> RegistrationInitiated: RegistrationRequested
    Registered_AttemptingRegistrationUpdate --> RegistrationInitiated: RegistrationRequested
    Registered_UpdateNeeded --> RegistrationInitiated: RegistrationRequested
    Authenticating --> RegistrationInitiated: RegistrationRequested
    SecurityMode --> RegistrationInitiated: RegistrationRequested
    RegistrationInitiated --> Authenticating: AuthenticationCompleted
    RegistrationInitiated --> SecurityMode: SecurityModeCompleted
    Authenticating --> SecurityMode: SecurityModeCompleted
    RegistrationInitiated --> Registered_NormalService: RegistrationAccepted
    Authenticating --> Registered_NormalService: RegistrationAccepted
    SecurityMode --> Registered_NormalService: RegistrationAccepted
    Registered_NonAllowedService --> Registered_NormalService: RegistrationAccepted
    Registered_AttemptingRegistrationUpdate --> Registered_NormalService: RegistrationAccepted
    Registered_UpdateNeeded --> Registered_NormalService: RegistrationAccepted
    RegistrationInitiated --> Deregistered_AttemptingRegistration: RegistrationFailed
    Authenticating --> Deregistered_AttemptingRegistration: RegistrationFailed
    SecurityMode --> Deregistered_AttemptingRegistration: RegistrationFailed
    RegistrationInitiated --> Registered_AttemptingRegistrationUpdate: RegistrationFailed
    Authenticating --> Registered_AttemptingRegistrationUpdate: RegistrationFailed
    SecurityMode --> Registered_AttemptingRegistrationUpdate: RegistrationFailed
    RegistrationInitiated --> Deregistered_NormalService: RegistrationRejected
    Authenticating --> Deregistered_NormalService: RegistrationRejected
    SecurityMode --> Deregistered_NormalService: RegistrationRejected
    RegistrationInitiated --> Deregistered_LimitedService: RegistrationRejected
    Authenticating --> Deregistered_LimitedService: RegistrationRejected
    SecurityMode --> Deregistered_LimitedService: RegistrationRejected
    RegistrationInitiated --> Deregistered_AttemptingRegistration: RegistrationRejected
    Authenticating --> Deregistered_AttemptingRegistration: RegistrationRejected
    SecurityMode --> Deregistered_AttemptingRegistration: RegistrationRejected
    RegistrationInitiated --> Deregistered_PlmnSearch: RegistrationRejected
    Authenticating --> Deregistered_PlmnSearch: RegistrationRejected
    SecurityMode --> Deregistered_PlmnSearch: RegistrationRejected
    RegistrationInitiated --> Deregistered_NoSupi: RegistrationRejected
    Authenticating --> Deregistered_NoSupi: RegistrationRejected
    SecurityMode --> Deregistered_NoSupi: RegistrationRejected
    RegistrationInitiated --> Registered_AttemptingRegistrationUpdate: RegistrationRejected
    Authenticating --> Registered_AttemptingRegistrationUpdate: RegistrationRejected
    SecurityMode --> Registered_AttemptingRegistrationUpdate: RegistrationRejected
    RegistrationInitiated --> Deregistered_AttemptingRegistration: AuthenticationAborted
    Authenticating --> Deregistered_AttemptingRegistration: AuthenticationAborted
    SecurityMode --> Deregistered_AttemptingRegistration: AuthenticationAborted
    Registered_NormalService --> Deregistered_AttemptingRegistration: AuthenticationAborted
    Registered_NonAllowedService --> Deregistered_AttemptingRegistration: AuthenticationAborted
    Registered_AttemptingRegistrationUpdate --> Deregistered_AttemptingRegistration: AuthenticationAborted
    Registered_UpdateNeeded --> Deregistered_AttemptingRegistration: AuthenticationAborted
    ServiceRequestInitiated --> Deregistered_AttemptingRegistration: AuthenticationAborted
    DeregistrationInitiated --> Deregistered_AttemptingRegistration: AuthenticationAborted
    RegistrationInitiated --> Registered_AttemptingRegistrationUpdate: AuthenticationAborted
    Authenticating --> Registered_AttemptingRegistrationUpdate: AuthenticationAborted
    SecurityMode --> Registered_AttemptingRegistrationUpdate: AuthenticationAborted
    RegistrationInitiated --> Deregistered_NoSupi: AuthenticationRejected
    Authenticating --> Deregistered_NoSupi: AuthenticationRejected
    SecurityMode --> Deregistered_NoSupi: AuthenticationRejected
    Registered_NormalService --> Deregistered_NoSupi: AuthenticationRejected
    Registered_NonAllowedService --> Deregistered_NoSupi: AuthenticationRejected
    Registered_AttemptingRegistrationUpdate --> Deregistered_NoSupi: AuthenticationRejected
    Registered_UpdateNeeded --> Deregistered_NoSupi: AuthenticationRejected
    ServiceRequestInitiated --> Deregistered_NoSupi: AuthenticationRejected
    DeregistrationInitiated --> Deregistered_NoSupi: AuthenticationRejected
    Registered_NormalService --> Registered_UpdateNeeded: UpdateDue
    Registered_NonAllowedService --> Registered_UpdateNeeded: UpdateDue
    Registered_AttemptingRegistrationUpdate --> Registered_UpdateNeeded: UpdateDue
    Registered_NormalService --> ServiceRequestInitiated: ServiceRequested
    Registered_NonAllowedService --> ServiceRequestInitiated: ServiceRequested
    Registered_AttemptingRegistrationUpdate --> ServiceRequestInitiated: ServiceRequested
    Registered_UpdateNeeded --> ServiceRequestInitiated: ServiceRequested
    ServiceRequestInitiated --> Registered_NormalService: ServiceAccepted
    ServiceRequestInitiated --> Registered_NormalService: ServiceRejected
    ServiceRequestInitiated --> Registered_NonAllowedService: ServiceRejected
    ServiceRequestInitiated --> Deregistered_NormalService: ServiceRejected
    ServiceRequestInitiated --> Deregistered_NoSupi: ServiceRejected
    ServiceRequestInitiated --> Deregistered_PlmnSearch: ServiceRejected
    ServiceRequestInitiated --> Deregistered_LimitedService: ServiceRejected
    ServiceRequestInitiated --> Registered_NormalService: ServiceRequestAbandoned
    Registered_NormalService --> DeregistrationInitiated: DeregistrationRequested
    Registered_NonAllowedService --> DeregistrationInitiated: DeregistrationRequested
    Registered_AttemptingRegistrationUpdate --> DeregistrationInitiated: DeregistrationRequested
    Registered_UpdateNeeded --> DeregistrationInitiated: DeregistrationRequested
    ServiceRequestInitiated --> DeregistrationInitiated: DeregistrationRequested
    Registered_NormalService --> Deregistered_NormalService: SwitchOff
    Registered_NonAllowedService --> Deregistered_NormalService: SwitchOff
    Registered_AttemptingRegistrationUpdate --> Deregistered_NormalService: SwitchOff
    Registered_UpdateNeeded --> Deregistered_NormalService: SwitchOff
    ServiceRequestInitiated --> Deregistered_NormalService: SwitchOff
    DeregistrationInitiated --> Deregistered_NormalService: DeregistrationAccepted
    DeregistrationInitiated --> Deregistered_NormalService: DeregistrationAbandoned
    RegistrationInitiated --> Deregistered_NormalService: NetworkDeregistration
    Authenticating --> Deregistered_NormalService: NetworkDeregistration
    SecurityMode --> Deregistered_NormalService: NetworkDeregistration
    Registered_NormalService --> Deregistered_NormalService: NetworkDeregistration
    Registered_NonAllowedService --> Deregistered_NormalService: NetworkDeregistration
    Registered_AttemptingRegistrationUpdate --> Deregistered_NormalService: NetworkDeregistration
    Registered_UpdateNeeded --> Deregistered_NormalService: NetworkDeregistration
    ServiceRequestInitiated --> Deregistered_NormalService: NetworkDeregistration
    DeregistrationInitiated --> Deregistered_NormalService: NetworkDeregistration
    RegistrationInitiated --> Deregistered_AttemptingRegistration: NetworkDeregistration
    Authenticating --> Deregistered_AttemptingRegistration: NetworkDeregistration
    SecurityMode --> Deregistered_AttemptingRegistration: NetworkDeregistration
    Registered_NormalService --> Deregistered_AttemptingRegistration: NetworkDeregistration
    Registered_NonAllowedService --> Deregistered_AttemptingRegistration: NetworkDeregistration
    Registered_AttemptingRegistrationUpdate --> Deregistered_AttemptingRegistration: NetworkDeregistration
    Registered_UpdateNeeded --> Deregistered_AttemptingRegistration: NetworkDeregistration
    ServiceRequestInitiated --> Deregistered_AttemptingRegistration: NetworkDeregistration
    DeregistrationInitiated --> Deregistered_AttemptingRegistration: NetworkDeregistration
    RegistrationInitiated --> Deregistered_LimitedService: NetworkDeregistration
    Authenticating --> Deregistered_LimitedService: NetworkDeregistration
    SecurityMode --> Deregistered_LimitedService: NetworkDeregistration
    Registered_NormalService --> Deregistered_LimitedService: NetworkDeregistration
    Registered_NonAllowedService --> Deregistered_LimitedService: NetworkDeregistration
    Registered_AttemptingRegistrationUpdate --> Deregistered_LimitedService: NetworkDeregistration
    Registered_UpdateNeeded --> Deregistered_LimitedService: NetworkDeregistration
    ServiceRequestInitiated --> Deregistered_LimitedService: NetworkDeregistration
    DeregistrationInitiated --> Deregistered_LimitedService: NetworkDeregistration
    RegistrationInitiated --> Deregistered_PlmnSearch: NetworkDeregistration
    Authenticating --> Deregistered_PlmnSearch: NetworkDeregistration
    SecurityMode --> Deregistered_PlmnSearch: NetworkDeregistration
    Registered_NormalService --> Deregistered_PlmnSearch: NetworkDeregistration
    Registered_NonAllowedService --> Deregistered_PlmnSearch: NetworkDeregistration
    Registered_AttemptingRegistrationUpdate --> Deregistered_PlmnSearch: NetworkDeregistration
    Registered_UpdateNeeded --> Deregistered_PlmnSearch: NetworkDeregistration
    ServiceRequestInitiated --> Deregistered_PlmnSearch: NetworkDeregistration
    DeregistrationInitiated --> Deregistered_PlmnSearch: NetworkDeregistration
    RegistrationInitiated --> Deregistered_NoSupi: NetworkDeregistration
    Authenticating --> Deregistered_NoSupi: NetworkDeregistration
    SecurityMode --> Deregistered_NoSupi: NetworkDeregistration
    Registered_NormalService --> Deregistered_NoSupi: NetworkDeregistration
    Registered_NonAllowedService --> Deregistered_NoSupi: NetworkDeregistration
    Registered_AttemptingRegistrationUpdate --> Deregistered_NoSupi: NetworkDeregistration
    Registered_UpdateNeeded --> Deregistered_NoSupi: NetworkDeregistration
    ServiceRequestInitiated --> Deregistered_NoSupi: NetworkDeregistration
    DeregistrationInitiated --> Deregistered_NoSupi: NetworkDeregistration
```

</details>

<details><summary>NAS 5GMM-IDLE / CONNECTED (<code>CmMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Connected: ConnectionEstablished
    Connected --> Idle: ConnectionReleased
```

</details>

<details><summary>NAS 5GSM, per PDU session (<code>SmMachine</code>)</summary>

```mermaid
stateDiagram-v2
    [*] --> Inactive
    Inactive --> ActivePending: EstablishmentRequested
    ActivePending --> Active: EstablishmentAccepted
    ActivePending --> Inactive: EstablishmentRejected
    ActivePending --> Inactive: EstablishmentAbandoned
    Active --> InactivePending: ReleaseRequested
    InactivePending --> Active: ReleaseRejected
    InactivePending --> Inactive: ReleaseAbandoned
    ActivePending --> Inactive: NetworkRelease
    Active --> Inactive: NetworkRelease
    InactivePending --> Inactive: NetworkRelease
    Active --> Inactive: StatusSync
    ActivePending --> Inactive: LocalRelease
    Active --> Inactive: LocalRelease
    InactivePending --> Inactive: LocalRelease
```

</details>
