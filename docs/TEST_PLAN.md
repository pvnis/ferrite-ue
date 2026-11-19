# Ferrite UE — test plan

Scope: the rebuilt, layered UE (see `ARCHITECTURE.md`) against an OCUDU gNB
(`/home/dmd/ocudu-pavo`) and the qcore 5G core (`/home/dmd/qcore`) on one host,
over the ZMQ IQ transport first, with the same test matrix re-run over the air
(SoapySDR backend) once a radio is attached. Every test is scripted so it can be
repeated after any change; the lab runner is `scripts/lab.sh`.

## 1. Levels

| level | what | how | gate |
|---|---|---|---|
| L0 unit | pure functions and state machines per crate | `cargo test --workspace` | all green, clippy clean |
| L1 vectors | codecs against captured / reference vectors | fixtures in each crate's `tests/` | byte-exact |
| L2 loopback | PHY tx→channel→rx round trips (PDSCH/PUSCH/PUCCH/PRACH/SSB), RLC/PDCP two-entity simulations, NAS UE ↔ fake core | `cargo test` integration tests | pass at the stated SNR |
| L3 system (ZMQ) | full attach + traffic against OCUDU + qcore, per cell configuration | `scripts/lab.sh <config>` | KPIs below |
| L4 system (OTA) | same as L3 with a real SDR pair | manual, same runner with `--radio sdr` | KPIs below (looser latency) |

## 2. Cell configuration matrix (L3)

Configs live in `test/` and point at qcore (AMF 127.0.0.1, PLMN 001/01, TAC 7).

| id | file | duplex | band | SCS | BW | sample rate | TDD pattern | PRACH |
|---|---|---|---|---|---|---|---|---|
| T1 | `gnb_zmq_tdd_n78_10mhz.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms: 6D+S(8)+3U | idx 159 (short, B4/C-class) |
| T2 | `gnb_zmq_tdd_n78_10mhz_dddsu.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 2.5 ms: DDDSU | idx 159 |
| T3 | `gnb_zmq_tdd_n78_20mhz.yml` | TDD | n78 | 30 kHz | 20 MHz | 30.72 | 5 ms | idx 159 |
| T8 | `gnb_zmq_tdd_n78_10mhz_4x2.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms | idx 159; T5 with `nof_antennas_dl: 4` (ZMQ TX ports 2100/2102/2104/2106) and no `max_rank`: OCUDU configures a 4-port NZP-CSI-RS (row 4), the Type I single-panel codebook N1,N2 = 2,1 and ri-Restriction 1111. The four ports reach the UE's two through ferrite-chanem (always on for T8; unfaded: output o = inputs o and o+2 at half power each) |
| T5 | `gnb_zmq_tdd_n78_10mhz_2x2.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms | idx 159; T1 with `nof_antennas_dl: 2`, `pdsch.max_rank: 2`, one ZMQ TX port per antenna (2100/2102) wired to the UE's two RX ports (`--tx a,b`): the 2x2 MIMO cell, identity channel |
| T4 | `gnb_zmq_tdd_n78_10mhz_drx.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms | idx 159; T1 plus connected-mode DRX (`cell_cfg.drx`: 80 ms long cycle, 10 ms on-duration / inactivity, 8-slot retx timers) |
| T6 | `gnb_zmq_tdd_n78_10mhz_ulheavy.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms: DDSUUUUUUU (S 10D/2U) | idx 159; uplink-heavy |
| T7 | `gnb_zmq_tdd_n78_10mhz_dlheavy.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms: DDDDDDDDSU (S 10D/2U) | idx 159; downlink-heavy: up to eight DL slots acknowledged in one UL slot (multi-bit HARQ-ACK on PUCCH / PUSCH) |
| C1 | `gnb_zmq_tdd_n48_10mhz.yml` | TDD | n48 (CBRS) | 30 kHz | 10 MHz at 3600 MHz | 15.36 | 5 ms: DDDDDDDSUU (S 6D/4U) | idx 159; UL symbols in the special slot |
| C2 | `gnb_zmq_tdd_n48_20mhz.yml` | TDD | n48 (CBRS) | 30 kHz | 20 MHz at 3600 MHz | 30.72 | 5 ms in two patterns: DDDSU (S 6D/4U) + DDSUU (S 8D/2U) | idx 159; `pattern2`, full-width PUCCH |
| F1 | `gnb_zmq_fdd_n3_10mhz.yml` | FDD | n3 | 15 kHz | 10 MHz | 11.52 | – | OCUDU default (idx 16, long format 0) Full AS security (`cu_cp.security`: NEA2 ciphering + NIA2 integrity on SRBs and DRBs). |
| F2 | `gnb_zmq_fdd_n3_20mhz.yml` | FDD | n3 | 15 kHz | 20 MHz | 23.04 | – | default |
| F3 (stretch) | `gnb_zmq_fdd_n3_20mhz_30khz.yml` | FDD | n3 | 30 kHz (SSB 15) | 20 MHz | 30.72 | – | default |

The UE is started with only the radio endpoint, sample rate and carrier
frequency (`--dl-arfcn` or `--center-mhz`); band, duplex mode, numerology,
PRACH, timing tables and PUCCH resources must all be learned over the air.

## 3. System test cases (run per configuration)

| id | case | pass criterion |
|---|---|---|
| S1 | Cell search | PCI, SSB case/index, CFO reported; MIB decoded; SFN tracks for ≥ 5 s with no loss of lock |
| S2 | SIB1 | SIB1 decoded within 2 SI periods; PLMN/TAC match the gNB config; duplex/TDD pattern printed matches the config |
| S3 | Random access | RAR received within ra-ResponseWindow on the first preamble; TA command ≤ 2 (ZMQ) — proves the UL timing model; Msg3 decoded by gNB (gNB log `crc=OK`); contention resolution within ra-ContentionResolutionTimer |
| S4 | RRC connection | RRCSetup parsed (dedicated config applied), RRCSetupComplete sent, UE-specific search space used for all subsequent DCIs |
| S5 | NAS registration | 5G-AKA MAC check OK, SecurityModeCommand integrity verified, RegistrationAccept received, RegistrationComplete sent; AS SecurityModeCommand MAC-I verified with the derived K_gNB |
| S6 | UE capability | UECapabilityEnquiry answered; gNB proceeds to RRCReconfiguration |
| S7 | PDU session + DRB | RRCReconfiguration applied (DRB with RLC UM/AM per config, PDCP SN size from config, SDAP header flags), PDU Session Establishment Accept parsed, IP assigned |
| S8 | User plane, built-in ping | 20 ICMP echoes at 1 Hz to the UPF gateway: 0 % loss; median RTT < 30 ms (TDD 5 ms), < 15 ms (FDD) |
| S9 | User plane, TUN | `ping -c 50` and `iperf3 -u -b 2M` through the TUN namespace: 0 % loss; TCP download ≥ 1 Mbit/s |
| S10 | DL HARQ | Over 60 s of traffic the gNB metrics show DL HARQ-ACK DTX rate < 1 %; UE-side late-ACK counter = 0 |
| S11 | UL HARQ | gNB PUSCH CRC KO rate < 1 % (ZMQ); UE resends identical TB on NDI-unchanged grants |
| S12 | Timing advance | TA command MAC CEs applied; UL stays inside the CP (gNB `ta` estimate stays within ±1 unit) |
| S13 | Idle robustness | UE idle 120 s after attach, then ping again: no RLF, SR → grant → traffic resumes |
| S14 | Release → idle → service request | gNB-initiated release (inactivity timer) → UE returns to RRC idle, NAS stays registered, PHY keeps the cell; the next uplink packet triggers a NAS Service Request (RRCSetupRequest with ng-5G-S-TMSI-Part1, cause mo-Data); the DRB is restored and the queued packet delivered (`lab.sh` with `UE_ARGS="--ping-rounds 2 --ping-round-gap-s 14"` on a gNB with `inactivity_timer: 5`) |
| S15 | Real-time budget | `FERRITE_PERF=1`: T0 slot period at the nominal slot duration ±5 %, rx-phy worker queue drops = 0 over 60 s |
| S16 | Measurement reporting | gNB configured with a periodical serving-cell report (`cu_cp.mobility`): the UE applies `measConfig`, sends `MeasurementReport` (SS-RSRP/RSRQ/SINR) every `reportInterval`; the gNB RRC log shows `Rx SRB1 DCCH UL measurementReport` |
| S19 | RRC re-establishment | With a radio link failure (lab: `UE_ARGS="--rlf-at-s 8"` injects one while connected) the UE sends RRCReestablishmentRequest, receives RRCReestablishment, refreshes the keys and completes; the gNB reconfigures the bearers and the ping probe finishes without a new registration |
| S23 | RLF detection (T310) | PHY out-of-sync indications (lab: `UE_ARGS="--rlm-outage-s 8 --rlm-outage-ms 1500"` forces them for 1.5 s): after N310 of them RRC starts T310 (`T310 started`); when it expires (`T310 expired: radio link failure`) the UE re-establishes (S19 behaviour) and the ping probe still completes |
| S24 | RLM recovery (N311) | A shorter outage (`--rlm-outage-ms 500`) starts T310, then N311 in-sync indications stop it (`T310 stopped`): no re-establishment, no lost pings |
| S26 | Deregistration at exit | Whenever the UE registered: on exit (ping probe done, timeout or Ctrl-C) the UE sends DEREGISTRATION REQUEST (switch off) before the radio stops, from idle through a mo-Signalling connection; the core logs the deregistration |
| S27 | Periodic registration update | `UE_ARGS="--t3512-s 8 --ping-rounds 2 --ping-round-gap-s 25"` on a config with the gNB's inactivity release (T1): after the release the UE is in 5GMM-IDLE, T3512 expires, the UE connects (mo-Signalling) with REGISTRATION REQUEST (periodic) and the core accepts (`registration update complete`); the second ping round, after the next release, still goes through a service request (S14) |
| S28 | Two-layer PDSCH (2x2, 4x2) | gNB with `nof_antennas_dl: 2` / `max_rank: 2` (T5) or four antennas (T8: 4-port CSI-RS, 11-bit CSI reports the gNB decodes as RI 2 + i1,1 / i1,3 / i2 + CQI), the UE's two RX ports wired to the two TX ports: the UE measures the two-port CSI-RS and reports RI 2 (`CSI: … ri=2` in the gNB log; the UE's `CSI <slot>: … ri 2` debug line), the gNB schedules two-layer PDSCHs (`nof_layers=2`) and the UE decodes them with its MMSE demapper (DL TB failures < 10 %); ping 10/10 |
| S29 | CFO tracking, UL frequency pre-compensation | `UE_ARGS="--emulate-lo-ppm 1"` (any config; the ZMQ source and sink mix in the frequency error of a UE oscillator 1 ppm high: DL −ppm·f_DL, UL +ppm·f_UL, sample clock ideal): the UE's `tracking:` CFO equals the injected DL offset within 50 Hz, the gNB's mean `cfo=` over the UE's uplink is within 50 Hz (without the pre-compensation it would be +ppm·f_UL), and no timing step is taken. Verified 2026-11-15 on T1 at +1 and −3 ppm and F1 at +2 ppm (FDD, UL scaled by f_UL/f_DL): gNB UL CFO mean 0 Hz, spread ±4 Hz |
| S31 | Protocol capture | Every `lab.sh` run writes `ue.pcap` (`--pcap`: MAC-NR, RRC and NAS in plain text). With `tshark` installed, Wireshark's own dissectors (MAC-NR → RLC → PDCP → RRC → NAS) must report no error and no warning except the capture's own artifacts (UDP framing checksum, PDCP MAC-I without keys) and RLC ARQ at work (STATUS NACKs, retransmitted SNs), which the stage counts. The first capture found UL MAC CEs placed before SDUs (§6.1.2) |
| S30 | Channel emulator | `CHANEM="<ferrite-chanem options>"` (any config; §5.2): the attach, ping and the configuration's other stages pass through the emulated channel, the emulator reports traffic in both directions, and with `--ppm` the UE's `tracking:` drift and CFO (as ppm of the DL carrier) each match the emulated clock error within 0.1 ppm. Results in §5.2 |
| S25 | Connected-mode DRX | gNB with `cell_cfg.drx` (T4): the UE applies the DRX-Config (`DRX configured`), stops monitoring the C-RNTI PDCCH and sending periodic CSI outside Active Time (`drx_sleep_slots > 0` in the final MAC stats) and the ping probe still completes through the on-duration / SR wake-ups. Note: the periodic SRS is kept during sleep (`MacConfig::srs_outside_active_time`): OCUDU feeds the timing-advance estimate of every SRS occasion to its TA manager, detected or not, and empty occasions produce a −1 TA command per DRX cycle until the uplink leaves the cyclic prefix (observed: UL dead after ~8 cycles, RLF) |
| S20 | SRS | gNB with `cell_cfg.srs.type_enabled: periodic`: the UE transmits its periodic SRS resource; the gNB PHY log shows `SRS:` detections with a sane SINR/EPRE for the UE's C-RNTI |
| S22 | Transform-precoded PUSCH | gNB with `pusch.enable_transform_precoding: true` (T3): Msg3, fallback-DCI and DCI 0_1 PUSCHs are DFT-s-OFDM with the low-PAPR DM-RS and the Table 6.1.4.1-1 MCS mapping; ≥90 % of the gNB's PUSCH CRCs pass |
| S21 | PUCCH format 3 | gNB with `pucch.formats: f1_and_f3` (T2): CSI reports and >2-bit HARQ feedback are sent on PUCCH format 3 (DFT-s-OFDM, RM(32,O) for ≤11 bits); ≥90 % of the gNB's format-3 UCI indications are `detection=4` (no DTX) with the expected payload |
| S18 | Other SI | gNB broadcasting SIB2 (`cell_cfg.sib.si_sched_info`): the UE logs the SI scheduling from SIB1 and acquires SIB2 within one SI period (`acquired SIB2` with the reselection parameters) |
| S17 | Paging | With the UE idle (S14), a host-side ping to the UE IP (`DL_PING=1`) makes the AMF page: the UE decodes the P-RNTI DCI/PCCH in its paging frame, sends a Service Request (cause mt-Access), the DRB is restored and the echo request is answered (0 % loss on the host ping) |

Pass = S1–S12 green on T1, T2, T3, F1, F2. S13–S15 are tracked but not gating.

## 4. Unit / loopback coverage required per crate

* **ferrite-common**: slot arithmetic across the SFN wrap, numerology
  conversions, TA unit conversions, ARFCN/GSCN both ranges, band table.
* **ferrite-phy**: OFDM CP tables for µ 0/1; PSS/SSS/PBCH acquisition at µ 0
  (Case A) and µ 1 (Case C) under CFO and noise; CORESET0 tables spot checks;
  PDCCH blind decode end-to-end (CSS + USS hashing); DCI size matrix vs OCUDU;
  DMRS position tables; TBS vectors incl. > 3824; PDSCH loopback with 1 and 2
  CDM groups, interleaved/non-interleaved VRB→PRB, CSI-RS rate matching;
  PUSCH loopback with UCI; PUCCH F0/F1/F2 sequences; PRACH table spot checks,
  occasion enumeration, format 0 and B4/C0 waveform round trips; LDPC/polar
  BLER sanity at a few SNRs.
* **ferrite-asn1**: live SIB1 / RRCSetup / RRCReconfiguration captures decode
  to the known values (TDD 5 ms, DDDSU, and FDD captures once collected);
  encode→decode round trips for every UL/DL message.
* **ferrite-rlc**: header codecs; UM/AM duplex simulation over a lossy
  reordering channel; STATUS/poll/retx; max-retx event.
* **ferrite-pdcp**: COUNT/HFN, reordering, NIA2/NEA2 test vectors, SRB
  integrity failure, DRB with/without SDAP header.
* **ferrite-nas**: message codecs byte-exact vs captured qcore exchanges, 5G-AKA
  vectors (TS 35.208), full registration + PDU session against a fake core;
  substate / timer scenarios (`tests/registration.rs`: T3511/T3502 attempt
  counter, T3346 congestion, service reject #10/#22/#28, network-initiated
  re-registration, CONFIGURATION UPDATE "registration requested", mobility
  update on a new TAI, NOTIFICATION, PDU SESSION MODIFICATION); every uplink
  message decoded and validated by the independent `oxirush-nas` crate.
* **ferrite-mac**: RA state machine (RAR window expiry, backoff, contention
  resolution timeout, success), HARQ codebook assembly, BSR/SR timers, LCP,
  DRX timers (`drx.rs`), bwp-InactivityTimer and BWP switch requests
  (`tests/attach.rs`).
* **ferrite-rrc**: state machine transitions on each DL message
  (`tests/state_machine.rs`: establishment, T300, SMC verdicts, RLF /
  T301 / T310 / N310 / N311, release, paging, NAS transport); derived
  `PhyConfig`/`MacConfig` for the TDD capture (`tests/codec.rs`).
* **ferrite-l1**: slot clock ↔ sample index mapping, UL position = DL −
  (N_TA + N_TA_offset); injection table; `DciResolver` for every DCI format
  and the RAR grant, TDD direction checks and the BWP indicator (`resolve.rs`
  tests); RLM thresholds; a closed-loop test
  with a simulated gNB (file source/sink) exercising SSB → SIB1 → PRACH
  placement.
* **ferrite-ue**: the stack through the FAPI interface (`tests/stack.rs`:
  SIB1 → CONFIG.request → registration → PRACH; retry after a failure).

## 5. Lab procedure (ZMQ)

```sh
# terminal 1: core (needs root; passwordless sudo on this host)
cd /home/dmd/qcore && sudo ./target/debug/qcore --mcc 001 --mnc 01 --no-dhcp \
    --sim-cred-file ./real-sims.toml --local-ip 127.0.0.1
# terminal 2: gNB
/home/dmd/ocudu-pavo/build/apps/gnb/gnb -c /home/dmd/ferrite-ue/test/<config>.yml
# terminal 3: UE
cargo run --release -p ferrite-ue -- --dl-arfcn <arfcn> --srate <MHz> --ping 20
```

`scripts/lab.sh <config-id> [--duration S] [--ping N]` automates this: it
starts qcore and the gNB, waits for the NG setup, starts the UE with the
matching ARFCN and sample rate, collects `/tmp/ferrite_gnb_zmq.log`, the UE
log and the gNB stdout metrics into `test/results/<id>-<timestamp>/`, and
evaluates S1–S8 from the logs (plus S14/S16/S17/S18/S19/S20/S21/S22 when the run exercised them), printing a pass/fail table. `UE_ARGS` adds UE
flags, `UE_LOG` sets the UE log filter.

Prerequisites on the host: qcore's network (`cd /home/dmd/qcore &&
./setup-routing <external-if>`, creates `qcoretun`/veth; lost on reboot).

### 5.1 Timing calibration aids

The UE derives all uplink timing from the spec (§6); two knobs exist for lab
calibration, both in samples and positive = transmit earlier:

* `--tx-rx-offset` — the radio backend's TX/RX alignment (0 for ZMQ);
* `--prach-offset` — PRACH only; defaults to a 1 µs *delay*. OCUDU's PRACH
  capture window starts ~0.5 µs after the slot and its detector rejects
  negative delays, so over a zero-delay transport a preamble sent exactly on
  time is never detected. The delay is harmless anywhere (inside every PRACH
  CP; the RAR TA absorbs it).

To find such offsets, `FERRITE_PRACH_SWEEP="o1,o2,…"` / `FERRITE_PUSCH_SWEEP`
cycle the uplink timing offset per PRACH attempt / PUSCH transmission and the
gNB PHY log shows which ones were detected (`PRACH: … detected_preambles=[…
ta=…]`, `PUSCH: … crc=OK`).

### 5.2 Channel emulator (`ferrite-chanem`)

`ferrite-chanem` (`ferrite-radio`, feature `zmq`) sits between the gNB and
the UE on the ZMQ transport and applies what an over-the-air link would:
multipath fading (TS 38.901 TDL-A/B/C scaled to a delay spread, or TS 36.101
EPA/EVA/ETU; Jakes Doppler by sum of sinusoids, independent per antenna pair),
a propagation delay, a UE oscillator error (`--ppm`: the sample clock is
resampled by 1+ε and the carrier offset is −ε·f_DL on the downlink, +ε·f_UL on
the uplink, as one crystal would do) and AWGN at a given SNR (measured over the
full sample bandwidth, against the mean power of the non-silent samples).
Without a fading model a multi-antenna link is the identity (each port wired
straight through). `--bench S` measures its throughput without a radio.

`lab.sh` splices it in with `CHANEM`: the gNB keeps its ports, the emulator
binds the UE-facing ports +100 and the UE is pointed at them, e.g.

```
CHANEM="--model tdla --ds-ns 30 --doppler-hz 5 --ppm 1 --delay-ns 500 \
        --dl-snr-db 25 --ul-snr-db 25" scripts/lab.sh T1 --ping 20
```

The emulator log is `chanem.log` in the run directory (every 10 s: samples
in/out, signal power, pace against real time, and the share of time spent
waiting upstream / processing / waiting downstream). The emulator processes up
to six blocks ahead of the downstream requests, per direction; the ZMQ
transport aligns by sample count, so the added wall-clock latency does not
move the radio timing. The emulator requests every upstream port every round (a transmitter produces its ports together; skipping one deadlocks it on that port's full buffer) and carries over unequal reply lengths. Lockstep ZMQ runs at whatever pace the slowest stage
allows: a 2x2 fading link is the emulator's heaviest case and slows the whole
system to ~0.3× real time, which the gNB and UE tolerate.

**Named scenarios.** `scripts/lab.sh <config> --scenario NAME` (or
`SCENARIO=NAME`) picks a channel from a table in `lab.sh`
(`--scenario list` prints it); the Doppler follows from the UE speed and the
cell's downlink carrier (f_D = v·f/c), so a scenario means the same motion on
every band:

| Scenario | Model | Delay spread | Speed | Clock error | Delay | SNR | Stands for |
|---|---|---|---|---|---|---|---|
| ideal | none | – | 0 | 0 | 0 | – | emulator in the path, channel off |
| static | none | – | 0 | 1 ppm | 500 ns | 30 dB | no fading: clock error, 150 m, noise |
| indoor | TDL-A | 30 ns | 1 km/h | 0.5 ppm | 100 ns | 30 dB | indoor small cell (CBRS) |
| pedestrian | EPA | (43 ns) | 3 km/h | 1 ppm | 500 ns | 20 dB | outdoor pedestrian |
| urban | TDL-C | 100 ns | 15 km/h | 1 ppm | 1 µs | 20 dB | urban macro, slow vehicle |
| vehicular | EVA | (357 ns) | 60 km/h | 1 ppm | 1 µs | 20 dB | vehicle |
| dispersive | TDL-C | 300 ns | 3 km/h | 1 ppm | 500 ns | 25 dB | taps beyond the cyclic prefix |
| cell-edge | TDL-A | 100 ns | 3 km/h | 2 ppm | 3 µs | 5 dB | 900 m, low SNR |

`scripts/matrix.sh [-c "T1 C1 …"] [-s "ideal pedestrian …"] [--ping N]`
runs configurations × scenarios (default: all of both; `-s direct` runs
without the emulator) and writes one summary table (result, ping, UE DL
TB ok/ko, gNB PUSCH CRC ok/ko, UE drift, pace, failed stages) to
`test/results/matrix-<timestamp>.md`. The gNB PUSCH count includes the
grants it still issues after the UE has stopped at the end of a run (a few
KO with SINR = inf).

Results 2026-11-15 (1 ppm, 500 ns, 25 dB SNR both ways, unless noted):

| Config | Channel | Ping | UE DL TB ok/ko | gNB PUSCH ok/ko | UE tracking |
|---|---|---|---|---|---|
| T1 | TDL-A 30 ns, 5 Hz | 20/20 | 182/5 | 153/10 | drift +1.03 ppm, CFO −3414 Hz |
| T1 | EPA, 5 Hz | 20/20 | 178/15 | 129/11 | drift +0.99 ppm |
| T1 | TDL-C 300 ns, 10 Hz | 20/20 | 155/15 | 117/54 | — |
| T5 | ideal 2x2, 0 ppm | 20/20 | 182/2 (61 two-layer PDSCHs, S28 pass) | — | — |
| T5 | TDL-A 30 ns, 5 Hz, 2x2 | 20/20 | 119/14 (59 two-layer PDSCHs) | — | — |

TDL-C at 300 ns reaches 2.6 µs, beyond the 2.3 µs cyclic prefix at 30 kHz:
the late taps' inter-symbol interference shows in the uplink. The fading
two-layer case misses S28's 10 % TB-failure limit (set for the clean channel)
by a little; link adaptation, not the receiver, sets that rate.

Full matrix 2026-11-16 (`matrix.sh --ping 10 --duration 180`, 11 configs ×
8 scenarios, `test/results/matrix-20261116-032033.md`): 88 runs, 82 attached
and pinged, 806 of 820 pings answered (72 runs 10/10). Every config passes
`ideal` and `static`, with zero DL TB failures; UL CRC KOs on clean runs are
the post-exit grants noted above. Failures by cause, and their fixes:

| Seen | Cause | Status |
|---|---|---|
| 6 runs hung after sync (T5 under 5 fading scenarios, T1 once) | The emulator let uplink run ahead of the gNB's downlink while the UE was not reading downlink; OCUDU then blocks its one ZMQ I/O thread pushing into a full receive buffer and never drains its transmit side | Fixed: the emulator delivers uplink at most 5 ms ahead of the downlink it has taken from the gNB (`Coupling`). T5 under all five failing scenarios attaches since. One single-antenna hang after a 735 ms search backlog seen once since, not reproduced in three tries; the emulator now logs which side it is waiting on after 2 s |
| 18 S30 failures (vehicular, dispersive, some cell-edge): UE drift 0.2–0.7 ppm off | Not the CFO (within 1 % in every run): the timing loop's rate integrator turned the timing wander of fading multipath into drift, on top of the CFO feed-forward that already carries it | Fixed: rate gain × 0.05 while the feed-forward is on (test `multipath_timing_wander_is_not_drift`); reruns of T1/C1/F1/T6 × vehicular/dispersive all within 0.02 ppm. S30 now also checks the CFO, as ppm of the DL carrier, within 0.1 ppm |
| 10 runs lost 1–3 pings | Mostly cell-edge (5 dB) and 2x2 fading at 0.17–0.3× emulator pace | Open: link margin and the slow emulator path |
| 4 S22 failures (T3 urban, vehicular, dispersive, cell-edge) | S22 asks for ≥ 90 % gNB PUSCH CRC OK, a clean-channel limit; under fading the CP-OFDM configs show the same UL failure rates (T1 urban 54/25), so this is the gNB's decoding and link adaptation, not the UE's DFT-s-OFDM | By design: read S22 on `ideal` / `static` |
| T5 S28 under fading (after the hang fix: indoor 62/33, vehicular 87/22 DL TB ok/ko) | The receiver trusted antenna 0 / DM-RS port 0 alone: its DM-RS gate dropped two-layer PDSCHs (and their retransmissions) whenever that path faded, and the residual-CFO slope came from it | Fixed 2026-11-18: both over every antenna and port; T5 indoor 75/1, T8 pedestrian 76/0 |

## 6. Over-the-air addendum (L4)

Same matrix with `--radio sdr --sdr-args driver=…` on the UE (binary built with `--features sdr`) and an RF gNB config.
Additional checks: PRACH power ramping to detection, TA command > 0 applied,
CFO tracking within ±100 Hz, AGC not saturating, sustained 10 min ping with
< 1 % loss. The ZMQ-specific pacing is not used in this mode; the radio
clock paces the UE (the commit-mark gate still bounds the uplink serve).

### 6.1 Bring-up procedure (bench: LimeSDR XTRX as the UE, LimeSDR-Micro as the gNB)

1. **gNB radio.** OCUDU's build carries `uhd`, `zmq` and `realtime_loopback`
   radio plugins only. For a LimeSDR the UHD path needs the SoapySDR bridge
   module for libuhd (`uhd-soapysdr` on Ubuntu; then `uhd_find_devices` lists
   the Lime) and a `ru_sdr` block with `device_driver: uhd`, `device_args:
   type=soapy,driver=limesuiteng,addr=/dev/limesdr_micro0`, `srate: 15.36`,
   `otw_format: sc16`. Alternatively an OCUDU SoapySDR radio plugin.
2. **UE device check.** `cargo run -p ferrite-radio --example sdr_probe
   --features soapy --release -- "driver=limesuiteng,addr=/dev/limepcie0"
   3.39e9 15.36e6 40`: timestamps must advance at the requested rate with no
   gaps; note the time-rate source (the LimeSuiteNG module converts with the
   requested rate while reporting 15 359 999 Hz).
3. **RX→TX offset.** `cargo run -p ferrite-radio --example tx_rx_cal
   --features soapy --release -- "driver=limesuiteng,addr=/dev/limepcie0"
   3.39e9 15.36e6 55 55 6` (TX→RX coupling through the antennas or a padded
   cable). Six runs must agree to the sample (XTRX: 68 samples at 15.36 MS/s);
   pass the value as `--tx-rx-offset`. The gNB's TA command absorbs an error
   here, but a wrong sign puts the PRACH outside the detector's window.
4. **Gains and calibration.** Start with `--sdr-rx-gain 40` (the AGC takes
   over: `AGC: receive gain a → b dB` in the log, settling near −22 dBFS on the
   SSB slot) and `--sdr-tx-gain 30`. `--rx-power-offset-db` is the dBm of
   full scale at 0 dB gain (sets the RSRP in measurement reports and the
   pathloss); `--tx-power-offset-db` is the dBm of full scale at the TX gain
   and enables uplink power control (debug log `UL power: PUSCH n RB → p dBm
   (PL …, f …)`). Without it waveforms are peak-normalised to `ul_amplitude`.
5. **Run.** `./target/release/ferrite-ue --radio sdr --sdr-args
   "driver=limesuiteng,addr=/dev/limepcie0" --dl-arfcn 626000 --srate 15.36
   --gscn <cell GSCN> --tx-rx-offset 68 --ping 10 --exit-after-ping --timeout
   60`. The GSCN hint cuts a search attempt from ~1 s to tens of ms.
6. **What to read.** UE: `uplink starts at`, no `uplink late by` lines after
   start (raise `--sdr-tx-latency-us` if they recur), `cell found … CFO`, the
   AGC lines, the `tracking:` line every 10 s (CFO, drift in ppm, steps) and
   `timing_steps` / `timing_realignments` in the final stats. gNB: `PRACH: … detected_preambles`
   with `ta` ≈ the propagation delay, `PUSCH: … crc=OK`, `t_align` within a
   few hundred ns, `TA_CMD` lines, and `epre` for the uplink level; its TPC
   (`tpc=` in the UL grants) should settle at 1 (0 dB) once the UE's power is
   right.
