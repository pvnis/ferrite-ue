# Ferrite

A clean-room 5G NR **UE** (user equipment) in Rust, implemented from the 3GPP
specifications (TS 38.211/212/213/214/321/322/323/331, TS 24.501). It borrows no
code from srsRAN, OpenAirInterface, or OCUDU — those serve only as behavioral
references and as a network-side gNB to test against. (Extracting normative
constant tables / reference vectors from the specs is the only thing lifted.)

**Status: end-to-end over ZMQ on 11 cell configurations; over-the-air
bring-up in progress.** Ferrite performs the full SA attach against an
OCUDU gNB and the qcore core — cell search → PRACH → RRC setup → 5G-AKA →
NAS + AS security → registration → PDU session → DRB — and carries IP
traffic through the UPF in real time (500 µs slots at 30 kHz). Ping RTT
medians in the lab are 15–19 ms on the TDD cells and ~29 ms on FDD n3.

The cell configuration is **decoded live, not transcribed**: band and duplex
follow from the ARFCN, the TDD pattern (including `pattern2`) and timing
tables come from SIB1, and the dedicated configuration (k1/k2 lists, DCI field
widths, PUCCH/SR/CSI resources, CSI-RS, CORESET#1, DRX, BWPs, power control,
UCI-on-PUSCH offsets) from the RRC messages. The UE needs only the radio
endpoint, sample rate and carrier frequency.

## Supported and lab-validated cells

Every configuration below attaches and pings against OCUDU over ZMQ
(`scripts/lab.sh <id>`; configs in `test/`, details in
`docs/TEST_PLAN.md` §2):

| Id | Band | Duplex / SCS | Bandwidth | TDD period | Exercises |
|---|---|---|---|---|---|
| T1 | n78 | TDD 30 kHz | 10 MHz | 5 ms: 6D + S + 3U | baseline: SRS, SIB2, measurement reports, inactivity release / paging |
| T2 | n78 | TDD 30 kHz | 10 MHz | 2.5 ms: DDDSU | short period, PUCCH format 3 |
| T3 | n78 | TDD 30 kHz | 20 MHz | 5 ms | wide BWP, DFT-s-OFDM uplink |
| T4 | n78 | TDD 30 kHz | 10 MHz | 5 ms | connected-mode DRX |
| T5 | n78 | TDD 30 kHz | 10 MHz | 5 ms | 2x2 downlink MIMO, two layers, RI/PMI reporting |
| T8 | n78 | TDD 30 kHz | 10 MHz | 5 ms | **4 gNB antennas** into the UE's 2: 4-port CSI-RS, Type I single-panel codebook (N1,N2 = 2,1), ranks 1–4 allowed (through the channel emulator) |
| T6 | n78 | TDD 30 kHz | 10 MHz | 5 ms: DDSUUUUUUU | uplink-heavy |
| T7 | n78 | TDD 30 kHz | 10 MHz | 5 ms: DDDDDDDDSU | downlink-heavy, multi-bit HARQ-ACK |
| C1 | **n48 (US CBRS)** | TDD 30 kHz | 10 MHz at 3600 MHz | 5 ms: DDDDDDDSUU | UL symbols in the special slot |
| C2 | **n48 (US CBRS)** | TDD 30 kHz | 20 MHz at 3600 MHz | 5 ms: DDDSU + DDSUU | two-pattern TDD (`pattern2`), full-width PUCCH |
| F1 | n3 | FDD 15 kHz | 10 MHz | – | FDD, long PRACH format, NEA2/NIA2 ciphering |
| F2 | n3 | FDD 15 kHz | 20 MHz | – | FDD wide BWP |

The band table (`ferrite-common/src/band.rs`) also knows n1, n2, n5, n7, n8,
n20, n28, n38, n40, n41, n66, n71 and n79 (duplex mode, ARFCN ranges, SSB
SCS); those are untested in the lab. On the n78 cells the UE takes the first
matching band, n77, which overlaps n78 at 3390 MHz. Sample rates in the lab configs:
15.36 / 30.72 MSps for TDD 10 / 20 MHz, 11.52 / 23.04 MSps for FDD 10 / 20 MHz.

**Channel emulator.** `ferrite-chanem` sits between the gNB and the UE on
the ZMQ link and applies 3GPP fading (TDL-A/B/C, EPA/EVA/ETU), propagation
delay, a UE oscillator error and noise. `scripts/lab.sh <id> --scenario
<name>` runs a cell through one of the named channels (`ideal`, `static`,
`indoor`, `pedestrian`, `urban`, `vehicular`, `dispersive`, `cell-edge`), and
`scripts/matrix.sh` runs every cell × scenario into one results table
(`docs/TEST_PLAN.md` §5.2).

## Quick start (ZMQ, against an OCUDU gNB + qcore)

The lab runner does everything (core, gNB, UE, log collection, pass/fail per
test stage):

```sh
scripts/lab.sh T1 --ping 20                       # one cell, direct ZMQ
scripts/lab.sh C1 --ping 20 --scenario pedestrian # CBRS cell through a fading channel
scripts/matrix.sh -c "T1 C1 C2" -s "ideal vehicular"
```

By hand: start qcore, then the gNB with one of the bundled configs (ZMQ on
tcp ports 2100 DL / 2101 UL), then the UE with the matching carrier and
sample rate:

```sh
./apps/gnb/gnb -c /path/to/ferrite/test/gnb_zmq_tdd_n48_10mhz.yml   # from the ocudu build dir
cargo build --release -p ferrite-ue
./target/release/ferrite-ue --dl-arfcn 640000 --srate 15.36 --ping 20
```

The built-in ping needs no privileges: it sends ICMP over the DRB to
`--ping-target` and prints each round trip. To carry host traffic instead,
create a TUN interface (needs root):

```sh
sudo ./target/release/ferrite-ue --dl-arfcn 626000 --tun ferrite0 --netns ferritens
sudo ip netns exec ferritens ping 10.255.0.1
```

## Command-line options

All options can also come from a TOML file (`--config`; flags override it).
`ferrite-ue --help` lists everything; the main ones:

| Flag | Default | Meaning |
|---|---|---|
| `--radio` | `zmq` | `zmq` (gNB over ZeroMQ) or `sdr` (SoapySDR, feature `sdr`) |
| `--tx` | `tcp://127.0.0.1:2100` | gNB downlink endpoint(s), one per receive antenna (`a,b` for 2x2) |
| `--rx` | `tcp://127.0.0.1:2101` | gNB uplink endpoint (the UE serves samples here) |
| `--srate` | `15.36` | Sample rate in MHz (must match the gNB) |
| `--dl-arfcn` / `--center-mhz` | `626000` | Downlink carrier centre |
| `--band`, `--ssb-scs`, `--gscn` | derived | Overrides / hints for the cell search |
| `--imsi`, `--ki`, `--opc`, `--dnn` | lab SIM, `internet` | Subscriber credentials |
| `--ping`, `--ping-target`, `--ping-interval-ms` | `20`, `10.255.0.1`, `1000` | Built-in ICMP probe (0 disables) |
| `--tun`, `--netns` | off | Carry host IP over the DRB through a TUN |
| `--timeout`, `--exit-after-ping` | run forever | Stop conditions |
| `--sdr-args`, `--sdr-rx-gain`, `--sdr-tx-gain`, `--sdr-*-antenna` | – | SoapySDR device and gains |
| `--rx-power-offset-db`, `--tx-power-offset-db` | 0 / unset | dBm calibration of the radio (enables uplink power control) |
| `--independent-lo` | off | The radio's LO is not locked to its sample clock (don't predict timing drift from the CFO) |
| `--emulate-lo-ppm`, `--rlf-at-s`, `--rlm-outage-s`, `--t3512-s` | off | Test aids (oscillator error, radio link failure, RLM outage, periodic registration) |
| `--log` | `info` | Log level (`RUST_LOG`-style filters also work) |
| `--pcap FILE` | off | Wireshark capture: MAC-NR PDUs, RRC and NAS in plain text (deciphered), one file of exported PDUs. Opens as is in Wireshark ≥ 4.4 |
| `--pcap-mac-udp` | off | MAC PDUs as UDP datagrams for Wireshark < 4.4 (`wireshark --enable-heuristic mac_nr_udp`) |

Diagnostic environment variables: `FERRITE_PERF` (radio-read overrun
reports), `FERRITE_DRIFT` (uplink waveform overlap audit), and
`FERRITE_PRACH_SWEEP` / `FERRITE_PUSCH_SWEEP` (cycle the uplink timing per
attempt for calibration, TEST_PLAN §5.1).

## Architecture

The L1 (`ferrite-l1`) runs a small set of threads around one slot clock
(`docs/ARCHITECTURE.md` §4):

- **radio-rx** drains the radio into a buffered stream, one per receive antenna;
- **timeline (T0)** owns the slot clock: per slot it tracks timing and CFO,
  monitors the PDCCH, hands PDSCH jobs to the worker, and runs the
  MAC / RLC / PDCP / RRC / NAS stack synchronously;
- **PDSCH worker** does channel estimation, MMSE demapping and LDPC decoding
  with HARQ soft combining;
- **tx-build** turns the MAC's UL_TTI requests (PUSCH with UCI, PUCCH F0–F3,
  PRACH, SRS) into samples at absolute positions;
- **UL serve** hands those samples to the radio: on the ZMQ request in
  lockstep with the gNB, on an SDR as timed bursts on the device clock.

The PHY talks to the MAC only through FAPI-style messages (`ferrite-fapi`), and
nothing above `ferrite-radio` knows which transport is in use.

### Protocol stack (L2 / L3)

L2 and L3 are separate crates with real state machines (see
`docs/ARCHITECTURE.md` for the diagrams): `ferrite-rlc` (TM/UM/AM with
segmentation, reassembly, STATUS and polling), `ferrite-pdcp` (COUNT/HFN,
reordering, NIA/NEA through `ferrite-security`), `ferrite-mac` (random access,
HARQ, BSR/SR/PHR, LCP, timing advance, DRX, bandwidth parts), `ferrite-rrc`
(system information, connection establishment, security mode, reconfiguration,
release and paging, re-establishment, measurements, radio link failure) and
`ferrite-nas` (registration with 5G-AKA, PDU sessions, service request,
deregistration, the 5GMM substates and timers). `ferrite-asn1` holds the
hand-written UPER codecs for SIB1/SI, the RRC messages and `CellGroupConfig`;
`ferrite-ue` is the thin stack glue plus the TUN/ping user plane. The MAC
entity is the only L2 layer that talks to the PHY, through the FAPI-style
messages of `ferrite-fapi`.

## Workspace layout

```
ferrite-common    shared types: Iq, Numerology / SlotPoint clock, RNTIs, bands
ferrite-ran       TS 38.21x tables and arithmetic (MCS, TBS, DM-RS positions,
                  PRACH configuration, RIV, default TDRA, SRS bandwidth)
ferrite-phy       signal processing: OFDM, sync (PSS/SSS/SSB/PBCH), PDCCH, PDSCH,
                  PUSCH (CP-OFDM / DFT-s-OFDM), PUCCH F0-F3, PRACH, SRS, CSI,
                  LDPC / polar coding
ferrite-radio     IQ transports (SampleSource / SampleSink): ZMQ, file, SDR [feature]
                  and the ferrite-chanem fading channel emulator (ZMQ proxy)
ferrite-fapi      the PHY <-> MAC interface (FAPI-style messages) and PhyConfig
ferrite-l1        the slot engine: cell search, PDCCH monitoring, PDSCH + HARQ,
                  DCI -> grant resolution, UL timing, PRACH/PUSCH/PUCCH/SRS tx
ferrite-mac       MAC entity: random access, HARQ, BSR/SR, LCP, TA, PHR
ferrite-rlc       RLC TM / UM / AM entities
ferrite-pdcp      PDCP entities (SN 12/18, reordering, integrity, ciphering)
ferrite-security  NIA/NEA algorithms, TS 33.501 key hierarchy, MILENAGE
ferrite-rrc       RRC entity, measurements, ASN.1 -> PHY/MAC configuration
ferrite-nas       5GMM / 5GSM, 5G-AKA, NAS security
ferrite-asn1      UPER codec and TS 38.331 message coders
ferrite-ue        the binary: config, engine wiring, stack glue, bearers, user plane
```

See `docs/ARCHITECTURE.md` for the layer contracts and state machines and
`docs/TEST_PLAN.md` for the lab matrix, test stages and channel scenarios.

## Roadmap

- **Done (ZMQ):** SA attach and data plane; TDD patterns incl. `pattern2`,
  FDD, 10 / 20 MHz; 2x2 DL MIMO with RI/PMI (2- and 4-port CSI-RS); DRX, BWP switching, RLF and
  re-establishment, paging and service request, periodic registration;
  UCI on PUSCH (HARQ-ACK up to 11 bits, CSI part 1); fine timing / CFO
  tracking with UL frequency pre-compensation; uplink power control and
  receive AGC; the fading channel emulator.
- **Over the air (in progress):** the SoapySDR backend is wired in
  (`--radio sdr`) with a sample-exact device time base and timed uplink
  bursts, verified streaming on a LimeSDR XTRX; an over-the-air gNB is the
  missing piece.
- **Open:** 3–4 layers, polar-coded UCI (>11 bits) and CSI part 2, CDL /
  ray-traced channels, neighbour cells and mobility. The full list is in
  `docs/BACKLOG.md`.

## Build & test

```sh
cargo test --workspace                               # no native libs needed
cargo build --release -p ferrite-ue                  # ZMQ backend
cargo build --release -p ferrite-ue --features sdr   # with SoapySDR
cargo build --release -p ferrite-radio --features zmq --bin ferrite-chanem
./target/release/ferrite-ue --radio sdr --sdr-args "driver=limesuiteng,addr=/dev/limepcie0" \
    --dl-arfcn 640000 --srate 15.36 --sdr-rx-gain 40 --sdr-tx-gain 30
```

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright 2026 Pavonis LLC.
