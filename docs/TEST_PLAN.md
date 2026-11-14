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
| L4 system (OTA) | same as L3 with a real SDR pair | manual, same runner with `--sdr` | KPIs below (looser latency) |

## 2. Cell configuration matrix (L3)

Configs live in `test/` and point at qcore (AMF 127.0.0.1, PLMN 001/01, TAC 7).

| id | file | duplex | band | SCS | BW | sample rate | TDD pattern | PRACH |
|---|---|---|---|---|---|---|---|---|
| T1 | `gnb_zmq_tdd_n78_10mhz.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms: 6D+S(8)+3U | idx 159 (short, B4/C-class) |
| T2 | `gnb_zmq_tdd_n78_10mhz_dddsu.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 2.5 ms: DDDSU | idx 159 |
| T3 | `gnb_zmq_tdd_n78_20mhz.yml` | TDD | n78 | 30 kHz | 20 MHz | 30.72 | 5 ms | idx 159 |
| T5 | `gnb_zmq_tdd_n78_10mhz_2x2.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms | idx 159; T1 with `nof_antennas_dl: 2`, `pdsch.max_rank: 2`, one ZMQ TX port per antenna (2100/2102) wired to the UE's two RX ports (`--tx a,b`): the 2x2 MIMO cell, identity channel |
| T4 | `gnb_zmq_tdd_n78_10mhz_drx.yml` | TDD | n78 | 30 kHz | 10 MHz | 15.36 | 5 ms | idx 159; T1 plus connected-mode DRX (`cell_cfg.drx`: 80 ms long cycle, 10 ms on-duration / inactivity, 8-slot retx timers) |
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

### Timing calibration aids

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

## 6. Over-the-air addendum (L4)

Same matrix with `--sdr driver=soapy,...` on the UE and an RF gNB config.
Additional checks: PRACH power ramping to detection, TA command > 0 applied,
CFO tracking within ±100 Hz, AGC not saturating, sustained 10 min ping with
< 1 % loss. The ZMQ-specific pacing/gating is not used in this mode; the radio
clock paces the UE.
