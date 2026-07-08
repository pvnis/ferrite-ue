# Ferrite

A clean-room 5G NR **UE** (user equipment) in Rust, implemented from the 3GPP
specifications (TS 38.211/212/213/321/322/323/331, TS 24.501). It borrows no
code from srsRAN or OpenAirInterface — those serve only as behavioral references
and as a network-side gNB to test against.

## Target configuration

| Parameter    | Value                                   |
|--------------|-----------------------------------------|
| Mode         | 5G SA (standalone)                      |
| Frequency    | FR1, band **n78**, TDD                  |
| Numerology   | `mu = 1` → 30 kHz SCS                    |
| Radio        | LiteX-M2SDR / BladeRF via SoapySDR      |
| Test gNB     | gNB over a ZMQ IQ transport (no-RF bring-up first) |

## Workspace layout

```
crates/
  ferrite-common   shared types, errors, IQ sample type
  ferrite-phy      physical layer (38.211/212/213)
    numerology       SCS / frame structure
    sync             PSS, SSS, SSB, cell search
  ferrite-radio    radio HAL: SampleSource/SampleSink
    file             interleaved-f32 IQ file backend
    (soapy)          SoapySDR backend        [feature]
    (zmq)            ZMQ IQ transport        [feature]
```

## Roadmap

**Milestone 1 — downlink cell search & sync** ✅ *(complete, synthetic validation)*

- [x] Workspace scaffold + radio HAL trait
- [x] PSS / SSS sequence generation (§7.4.2.2)
- [x] OFDM modulate/demodulate + numerology-driven frame structure
- [x] Time-domain PSS correlation → coarse timing + `N_ID^(2)`
- [x] SSS detection → `N_ID^(1)` → physical cell ID
- [x] Fine CFO estimation & correction (CP autocorrelation over the SSB)
- [x] PBCH: DMRS + blind SSB-index detection, channel estimation/equalization,
      descrambling, rate de-matching, CRC-aided SCL polar decode → **MIB**

All 38.212 constant tables (polar reliability sequence, input interleaver,
sub-block interleaver, PBCH payload interleaver) were transcribed from the
spec text itself and are structurally validated by unit tests.

Demo: `cargo run -p ferrite-phy --example cell_search`

**Cross-validation**: Ferrite's transmitted SSB
(`cargo run -p ferrite-phy --example emit_ssb -- out.iq`) is decoded by
srsRAN's independent `ssb_file_test` receiver with `crc=OK` and every MIB
field correct — confirming the whole chain (sequences, DMRS, scramblers,
interleavers, CRC24C, polar tables, rate matching, QPSK) is spec-conformant.

**Milestone 2 — live gNB & radio** *(in progress)*

- [x] ZMQ radio backend (`ferrite-radio` feature `zmq`), wire-compatible with
      the srsRAN/OCUDU zmq driver (REQ/REP, `complex<f32>` blocks)
- [x] `ssb-scan` (crate `ferrite-ue`): GSCN sync-raster scan on a live DL
      stream → SSB lock → **MIB decoded from a running OCUDU SA gNB**, every
      field matching the gNB's own log (PCI, k_SSB, CORESET#0)
- [x] Continuous sync loop (`sync-track`): acquire in ~0.2 s (parallel GSCN
      scan), then frame-by-frame tracking — narrow PSS re-correlation, CFO EMA,
      per-frame MIB verification. Live vs OCUDU: 200/200 frames, 0 lock losses.
      Radio drain thread decouples the wall-clock gNB from processing
      (`ferrite_ue::stream::BufferedStream`).
- [x] PDCCH / CORESET#0: geometry (38.213 Table 13-4), interleaved CCE→REG
      mapping, PDCCH DMRS + channel est, DCI 1_0 polar decode with
      puncturing/shortening rate-matching + CRC-aided SCL. **Live: blind-decodes
      the SI-RNTI DCI from the OCUDU gNB; RIV/AL/RNTI match the gNB scheduler.**
- [ ] SIB1 PDSCH: LDPC decode (38.212 §5.3.2) + BCCH-DL-SCH ASN.1
- [ ] Over-the-air via SoapySDR (LiteX-M2SDR / BladeRF)

Live scan: `cargo run --release -p ferrite-ue --bin ssb-scan` against a gNB
with `device_driver: zmq` (see `docs` of your gNB for tx/rx port setup).

Later milestones: PRACH (Msg1) → RACH procedure → PDCCH/PDSCH (LDPC) →
MAC/RLC/PDCP → RRC → NAS registration.

## Build

```sh
cargo test --workspace          # core (no native libs required)
cargo build -p ferrite-radio --features soapy   # with SoapySDR backend
```
