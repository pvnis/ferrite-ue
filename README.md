# Ferrite

A clean-room 5G NR **UE** (user equipment) in Rust, implemented from the 3GPP
specifications (TS 38.211/212/213/214/321/322/323/331, TS 24.501). It borrows no
code from srsRAN, OpenAirInterface, or OCUDU — those serve only as behavioral
references and as a network-side gNB to test against. (Extracting normative
constant tables / reference vectors from the specs is the only thing lifted.)

**Status: end-to-end works, in real time.** Ferrite performs the full SA
attach over a ZMQ IQ transport against an OCUDU/qcore network — cell search →
PRACH/RACH → 5G-AKA → NAS + AS security → registration → PDU session → DRB — and
carries live IP traffic (ping through qcore's UPF) at the **real-time μ=1 slot
rate (500 µs/slot, 2000 slots/s), 0 % packet loss**.

## Target configuration

| Parameter    | Value                                              |
|--------------|----------------------------------------------------|
| Mode         | 5G SA (standalone)                                 |
| Frequency    | FR1, band **n78**, TDD (pattern DDDDDDSUUU)        |
| Numerology   | `mu = 1` → 30 kHz SCS, 500 µs slot                 |
| Bandwidth    | 10 MHz (24 PRB), sample rate 15.36 MHz             |
| Transport    | ZMQ IQ (`complex<f32>` blocks), no-RF bring-up     |
| Radio (OTA)  | LiteX-M2SDR / BladeRF via SoapySDR *(next)*         |

## Quick start (ZMQ, against an OCUDU gNB + qcore)

**1. Bring up the network side.** Start qcore, then the gNB with the bundled
config (band n78, 10 MHz, ZMQ on tcp ports 2100 DL / 2101 UL):

```sh
# from your ocudu-pavo build dir
./apps/gnb/gnb -c /path/to/ferrite/test/gnb_zmq_ferrite.yml
```

**2. Build and run the UE.** The default binary is `ferrite-ue`:

```sh
cargo build --release -p ferrite-ue --bin ferrite-ue
```

*Built-in ping* (no privileges — sends ICMP over the DRB internally, using the
IP the network assigns in the PDU Session Accept):

```sh
./target/release/ferrite-ue
```

*Real TUN interface* (host traffic over the air; needs root for the interface).
Ferrite creates the TUN, extracts its assigned IP, and configures it — then any
tool can send through it:

```sh
sudo ./target/release/ferrite-ue --tun ferrite0 --netns ferritens
# then, in another shell:
sudo ip netns exec ferritens ping 10.255.0.1
```

The UE prints its progress through each attach stage; `TUN ferrite0 up` (or the
built-in `ICMP echo/reply`) means the full stack is live.

## Command-line options

All have working defaults; override only what your setup needs.

| Flag             | Default                              | Meaning |
|------------------|--------------------------------------|---------|
| `--tx`           | `tcp://127.0.0.1:2100`               | gNB **downlink** ZMQ endpoint (UE reads) |
| `--rx`           | `tcp://127.0.0.1:2101`               | gNB **uplink** ZMQ endpoint (UE writes) |
| `--srate`        | `15.36e6`                            | Sample rate (Hz) — must match the gNB |
| `--center-mhz`   | `3390.0`                             | Carrier centre frequency (MHz) |
| `--tun`          | *(off)*                              | Create this TUN interface and carry host IP over the DRB (needs root) |
| `--netns`        | *(none)*                             | Move the TUN into this network namespace |
| `--tun-mtu`      | `1400`                               | TUN MTU |
| `--ping-target`  | `10.255.0.1`                         | ICMP echo target (built-in ping mode) |
| `--ue-ip`        | *(auto)*                             | Override the UE IP instead of taking it from the PDU Session Accept |
| `--imsi`         | `001010167891203`                    | Subscriber IMSI (SUCI) |
| `--ki`           | `51222502…45fc0`                     | 5G-AKA Milenage key K (32 hex) |
| `--opc`          | `981d464c…d0bcf`                     | 5G-AKA Milenage OPc (32 hex) |
| `--snn`          | `5G:mnc001.mcc001.3gppnetwork.org`   | Serving-network name |
| `--preamble`     | `0`                                  | PRACH preamble index |
| `--amp`          | `0.5`                                | UL transmit peak amplitude |
| `--sweep`        | `384`                                | PRACH occasion offset sweep step (samples) |
| `--msg3-delay`   | `7`                                  | RAR→Msg3 slot delay |
| `--fshift`       | `0`                                  | Extra frequency shift applied to the UL |
| `--toff-lo` / `--toff-hi` / `--toff-step` | `-2800` / `-600` / `25` | Msg3 timing-offset search window (samples) |

## Runtime tuning (environment variables)

Off by default; useful for measurement and for pushing the real-time envelope.

| Var                | Default | Effect |
|--------------------|---------|--------|
| `FERRITE_PERF`     | off     | Per-slot performance reports on stderr: timeline (`[perf-ue-t0]`), RX-PHY worker (`[perf-ue-rxphy]`), HARQ-ACK lag/lateness + job drops (`[perf-ue-ack]`) |
| `FERRITE_PACE_US`  | `500`   | Wall-clock µs/slot the radio thread paces the gNB to (real time). Larger = slower/looser |
| `FERRITE_LEAD`     | `0`     | Slots the UL serve may run ahead of T0's DL consumption. Each slot of lead eats the k1 HARQ-ACK budget |
| `FERRITE_FB`       | off     | Re-enable the no-DCI brute-force PDSCH fallback (off by default: it can't be HARQ-ACKed and its worst case triggers retx storms) |
| `FERRITE_RT`       | off     | Pin the timeline / RX-PHY / radio threads to SCHED_FIFO cores (needs `CAP_SYS_NICE` / root) |
| `FERRITE_DRIFT`    | off     | Diagnostic: log T0-vs-serving drift and each late-ACK's position |
| `FERRITE_PAD_US`   | `0`     | Pad the slot period (study pace vs. the lockstep) |
| `FERRITE_DUMP_FSH` | off     | Dump one granted-slot's frequency-shifted samples to `/tmp/ferrite_fsh.bin` for offline decode timing |

## Architecture

`ferrite-ue` runs a staged, real-time pipeline (OCUDU's task-executor pattern) so
the DL-decode→HARQ-ACK path beats the 500 µs slot deadline:

- **T0 — timeline** (hard real-time): owns the sample clock; reads DL via a
  read-ahead `BufferedStream`, hands each slot to the RX-PHY worker, and runs the
  protocol stack + HARQ-ACK/SR build.
- **Radio thread**: serves the UL from a position-keyed injection table, **paced**
  to real time and **gated** to T0's DL consumption (so the gNB can't out-run its
  own scheduler and the DL buffer can't grow unbounded).
- **RX-PHY worker (T1)**: OFDM demod, PDCCH blind decode, PDSCH LDPC decode + HARQ
  soft-combining, on a small dedicated `rayon` pool (candidates + layouts in
  parallel).
- **TX-build thread**: PUSCH / CSI modulation, off the timeline thread.

See `crates/ferrite-ue/src/rt.rs` for the queue/stage plumbing. Two lessons that
made 500 µs work: the decode→ACK pipeline lag is bounded by the worker **queue
depth** (kept shallow so bursts drop instead of stalling), and the PDSCH
time-domain shape must come from the **DCI's TDRA bit**, not the slot index
(HARQ retransmissions of a short-slot TB keep the short shape in normal slots).

## Workspace layout

```
crates/
  ferrite-common   shared types, errors, IQ sample type
  ferrite-phy      physical layer: numerology, sync (PSS/SSS/SSB), PBCH, PDCCH,
                   PDSCH/PUSCH, PUCCH, PRACH, CSI, LDPC/polar coding
  ferrite-radio    radio HAL (SampleSource/SampleSink): file, SoapySDR [feature],
                   ZMQ [feature] backends
  ferrite-ue       the UE: entry point `ferrite-ue` (attach + data plane) plus
                   milestone/debug harnesses (ssb-scan, sync-track, sib1,
                   pdsch-*, prach-*, rar-rx, msg3-grid, …)
```

## Roadmap

**Milestone 1 — downlink cell search & sync** ✅
PSS/SSS correlation → PCI, CFO estimation, PBCH DMRS + SCL polar decode → MIB.
Cross-validated: Ferrite's emitted SSB decodes in srsRAN's independent receiver
with `crc=OK` and every MIB field correct.

**Milestone 2 — live gNB decode** ✅
ZMQ backend; GSCN scan → SSB lock; continuous sync tracking; PDCCH/CORESET#0 DCI
blind decode; SIB1 PDSCH LDPC decode (CRC OK) — all live against an OCUDU SA gNB.

**Milestone 3 — full SA attach & data plane** ✅
PRACH/RACH → RAR → Msg3/Msg4 contention resolution → RRC setup → 5G-AKA
(Milenage) → NAS + AS security → registration → PDU session → DRB. Uplink PUSCH,
PUCCH (HARQ-ACK / SR / CSI), HARQ soft-combining. **End-to-end ping through
qcore's UPF, at real-time 500 µs/slot, 0 % loss, repeatable.**

**Milestone 4 — over the air** *(next)*
SoapySDR backend (LiteX-M2SDR / BladeRF); the ZMQ lockstep's coordination jitter
goes away with a real radio clock.

## Build & test

```sh
cargo test --workspace                            # core (no native libs needed)
cargo build --release -p ferrite-ue --bin ferrite-ue
cargo build -p ferrite-radio --features soapy     # SoapySDR backend
```
