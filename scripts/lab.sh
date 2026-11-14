#!/usr/bin/env bash
# Lab runner for the system tests in docs/TEST_PLAN.md (ZMQ transport).
#
#   scripts/lab.sh <config-id> [--duration S] [--ping N] [--no-core]
#
# config-id ∈ T1 (tdd_n78_10mhz) T2 (tdd_n78_10mhz_dddsu) T3 (tdd_n78_20mhz)
#             F1 (fdd_n3_10mhz) F2 (fdd_n3_20mhz)
#
# Starts qcore (sudo) and the OCUDU gNB with the matching config, then the UE
# with the matching ARFCN / sample rate, waits for the ping probe to finish (or
# the duration), stops everything, and evaluates S1–S8 of the test plan from the
# logs. Results land in test/results/<id>-<timestamp>/.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GNB=/home/dmd/ocudu-pavo/build/apps/gnb/gnb
QCORE_DIR=/home/dmd/qcore
QCORE=$QCORE_DIR/target/debug/qcore
ID=${1:?config id}; shift
DURATION=90
PING=20
CORE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION=$2; shift 2;;
    --ping) PING=$2; shift 2;;
    --no-core) CORE=0; shift;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
case "$ID" in
  T1) CFG=gnb_zmq_tdd_n78_10mhz;       ARFCN=626000; SRATE=15.36;;
  T2) CFG=gnb_zmq_tdd_n78_10mhz_dddsu; ARFCN=626000; SRATE=15.36;;
  T3) CFG=gnb_zmq_tdd_n78_20mhz;       ARFCN=626000; SRATE=30.72;;
  F1) CFG=gnb_zmq_fdd_n3_10mhz;        ARFCN=368500; SRATE=11.52;;
  F2) CFG=gnb_zmq_fdd_n3_20mhz;        ARFCN=368500; SRATE=23.04;;
  *) echo "unknown config id $ID"; exit 2;;
esac
OUT="$ROOT/test/results/$ID-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
echo "== $ID: $CFG → $OUT"

cleanup() {
  [ -n "${UE_PID:-}" ] && kill "$UE_PID" 2>/dev/null
  [ -n "${GNB_PID:-}" ] && kill "$GNB_PID" 2>/dev/null
  [ -n "${QCORE_PID:-}" ] && sudo kill "$QCORE_PID" 2>/dev/null
  # The sudo'd qcore is a grandchild: kill it by name so no stale core (with
  # its eBPF datapath hook) survives into the next run.
  [ "$CORE" = 1 ] && sudo pkill -x qcore 2>/dev/null
  sleep 1
  [ -n "${GNB_PID:-}" ] && kill -9 "$GNB_PID" 2>/dev/null
  cp /tmp/ferrite_gnb_zmq.log "$OUT/gnb.log" 2>/dev/null
}
trap cleanup EXIT

# Make sure nothing stale holds the ports.
for p in $(pgrep -x gnb); do kill "$p" 2>/dev/null; done
[ "$CORE" = 1 ] && pgrep -x qcore >/dev/null && { sudo pkill -x qcore; sleep 1; }
sleep 1

if [ "$CORE" = 1 ]; then
  ( cd "$QCORE_DIR" && sudo RUST_LOG=info "$QCORE" --mcc 001 --mnc 01 --no-dhcp \
      --sim-cred-file ./real-sims.toml --local-ip 127.0.0.1 > "$OUT/qcore.log" 2>&1 ) &
  QCORE_PID=$!
  for _ in $(seq 1 20); do grep -q "AMF\|listening\|NGAP\|Started\|started" "$OUT/qcore.log" 2>/dev/null && break; sleep 0.5; done
  sleep 1
fi
rm -f /tmp/ferrite_gnb_zmq.log
GNB_CFG="$ROOT/test/$CFG.yml"
if [ "$CORE" = 0 ]; then
  sed 's/^    addr: 127.0.0.1/    no_core: true\n    addr: 127.0.0.1/' "$GNB_CFG" > "$OUT/gnb.yml"
  GNB_CFG="$OUT/gnb.yml"
fi
stdbuf -oL -eL "$GNB" -c "$GNB_CFG" > "$OUT/gnb.out" 2>&1 &
GNB_PID=$!
# Wait for the cell.
for _ in $(seq 1 30); do grep -q "gNB started" "$OUT/gnb.out" 2>/dev/null && break; sleep 1; done
grep -q "gNB started" "$OUT/gnb.out" || { echo "gNB did not start"; cat "$OUT/gnb.out" | tail -20; exit 1; }
sleep 1

( cd "$ROOT" && RUST_LOG="${UE_LOG:-info}" cargo run --release -p ferrite-ue -q -- --dl-arfcn "$ARFCN" --srate "$SRATE" \
    --ping "$PING" --exit-after-ping --timeout "$DURATION" --log "${UE_LOG:-info}" ${UE_ARGS:-} > "$OUT/ue.log" 2>&1 ) &
UE_PID=$!
# DL_PING=1: once the gNB has released the UE to idle, ping its IP from the
# host (through qcore) so the network has to page it.
if [ "${DL_PING:-0}" = "1" ]; then
  (
    for _ in $(seq 1 120); do grep -q "RRC released (idle)" "$OUT/ue.log" 2>/dev/null && break; sleep 0.5; done
    sleep 1
    UEIP=$(grep -o "PDU session up: [0-9.]*" "$OUT/ue.log" | tail -1 | awk '{print $4}')
    [ -n "$UEIP" ] && ping -c 4 -i 1 -W 3 "$UEIP" > "$OUT/dl_ping.txt" 2>&1
  ) &
fi
wait "$UE_PID"; UE_RC=$?
cleanup
trap - EXIT

# ---- evaluation --------------------------------------------------------------
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; RESULT=1; }
RESULT=0
UE="$OUT/ue.log"
grep -q "cell found" "$UE"              && pass "S1 cell search"      || fail "S1 cell search"
grep -q "cell configured" "$UE"         && pass "S2 SIB1"             || fail "S2 SIB1"
grep -q "RA succeeded" "$UE"            && pass "S3 random access"    || fail "S3 random access"
grep -q "RRC connected" "$UE"           && pass "S4 RRC connection"   || fail "S4 RRC connection"
grep -q "registered" "$UE"              && pass "S5 registration"     || fail "S5 registration"
grep -q "PDU session up" "$UE"          && pass "S7 PDU session"      || fail "S7 PDU session"
if grep -q "ping done" "$UE"; then
  REPL=$(grep "ping done" "$UE" | tail -1 | sed -E 's/.*ping done: ([0-9]+)\/([0-9]+).*/\1 \2/')
  R=${REPL% *}; S=${REPL#* }
  [ "$R" = "$S" ] && [ "$R" -gt 0 ] && pass "S8 ping $R/$S" || fail "S8 ping $R/$S"
else
  fail "S8 ping (no result)"
fi
# S14/S17: idle mode (only when the gNB released the UE during the run): the
# next uplink data must come back through a service request; with DL_PING=1 a
# host-side ping during idle must page the UE.
if grep -q "RRC released (idle)" "$UE"; then
  grep -q "service request (mo-Data)" "$UE" && pass "S14 release → idle → service request (mo-Data)" || fail "S14 release → idle → service request (mo-Data)"
  if [ "${DL_PING:-0}" = "1" ]; then
    grep -q "paged: requesting service" "$UE" && pass "S17 paging → service request (mt-Access)" || fail "S17 paging → service request (mt-Access)"
    # The first host ping is lost while the network pages (the core does not
    # buffer); the UE must answer the ones that arrive after the DRB is back.
    if [ -f "$OUT/dl_ping.txt" ] && [ "$(grep -o '[0-9]* received' "$OUT/dl_ping.txt" | awk '{print $1}')" -gt 0 ] 2>/dev/null; then pass "S17 paging: host ping answered ($(grep -o '[0-9]* received' "$OUT/dl_ping.txt"))"; else fail "S17 paging: host ping answered"; fi
  fi
fi
# S19: RRC re-establishment (only when a radio link failure occurred, e.g. the
# injected one from `--rlf-at-s`): the connection must come back without a
# fresh registration and the ping probe must still complete.
if grep -q "re-establishing" "$UE"; then
  grep -q "RRC re-established" "$UE" && pass "S19 RRC re-establishment" || fail "S19 RRC re-establishment"
fi
# S23/S24: radio link monitoring (only when the UE ran with an RLM outage,
# `UE_ARGS="--rlm-outage-s 8 --rlm-outage-ms 1500"`): N310 out-of-sync
# indications start T310; a long outage expires it (RLF → re-establishment,
# S23), a short one (`--rlm-outage-ms 500`) is stopped by N311 in-sync
# indications and the connection survives (S24).
if grep -q "T310 started" "$UE"; then
  if grep -q "T310 expired" "$UE"; then
    grep -q "RRC re-established" "$UE" && pass "S23 T310 expiry → RLF → re-establishment" || fail "S23 T310 expiry → RLF → re-establishment"
  else
    grep -q "T310 stopped" "$UE" && ! grep -q "re-establishing" "$UE" && pass "S24 T310 stopped by N311 in-sync" || fail "S24 T310 stopped by N311 in-sync"
  fi
fi
# S20: SRS (only when the UE was configured with periodic SRS): the gNB PHY
# must detect the sounding (its SRS log lines carry a per-UE SINR).
if grep -q "srs_sent: [1-9]" "$UE"; then
  N=$(grep "SRS: sector" "$OUT/gnb.log" 2>/dev/null | grep -vc "epre=-inf" || echo 0)
  [ "$N" -gt 0 ] && pass "S20 SRS received by gNB ($N)" || fail "S20 SRS received by gNB"
fi
# S21: PUCCH format 3 (only when the gNB config selects the F1+F3 layout): the
# multi-bit UCI (CSI reports, >2 HARQ bits) rides on format 3 and the gNB must
# report it detected (FAPI UCI.indication `detection=4`, i.e. no DTX) rather
# than DTX (`detection=3`) for the large majority of occasions.
if grep -q "formats: f1_and_f3" "$ROOT/test/$CFG.yml" 2>/dev/null; then
  OK=$(grep "PUCCH format 2/3/4 format=3" "$OUT/gnb.log" 2>/dev/null | grep -c "detection=4" || echo 0)
  ALL=$(grep -c "PUCCH format 2/3/4 format=3" "$OUT/gnb.log" 2>/dev/null || echo 0)
  [ "$OK" -gt 0 ] && [ $((OK * 10)) -ge $((ALL * 9)) ] && pass "S21 PUCCH F3 decoded by gNB ($OK/$ALL)" || fail "S21 PUCCH F3 decoded by gNB ($OK/$ALL)"
fi
# S22: transform-precoded PUSCH (only when the gNB config enables it): the
# gNB must decode the DFT-s-OFDM uplink (≥90 % PUSCH CRC OK).
if grep -q "enable_transform_precoding: true" "$ROOT/test/$CFG.yml" 2>/dev/null; then
  OK=$(grep -c "PUSCH: rnti.*crc=OK" "$OUT/gnb.log" 2>/dev/null || echo 0)
  ALL=$(grep -c "PUSCH: rnti" "$OUT/gnb.log" 2>/dev/null || echo 0)
  [ "$OK" -gt 0 ] && [ $((OK * 10)) -ge $((ALL * 9)) ] && pass "S22 transform-precoded PUSCH decoded by gNB ($OK/$ALL)" || fail "S22 transform-precoded PUSCH decoded by gNB ($OK/$ALL)"
fi
# S18: other system information (only when SIB1 schedules SI messages).
if grep -q "SI scheduling:" "$UE"; then
  grep -q "acquired SIB" "$UE" && pass "S18 other SI ($(grep -o 'acquired SIB[0-9]*' "$UE" | sort -u | tr '\n' ' '))" || fail "S18 other SI"
fi
# S16: measurement reporting (only when the gNB config installs a measConfig).
if grep -q "measConfig applied" "$UE"; then
  if grep -q "MeasurementReport:" "$UE"; then
    if grep -q "DCCH UL measurementReport" "$OUT/gnb.log" 2>/dev/null; then pass "S16 measurement report (gNB received)"; else pass "S16 measurement report (UE sent)"; fi
  else
    fail "S16 measurement report"
  fi
fi
echo "UE exit code $UE_RC; logs in $OUT"
exit $RESULT
