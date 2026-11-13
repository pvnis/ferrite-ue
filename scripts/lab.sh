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
  sleep 1
  [ -n "${GNB_PID:-}" ] && kill -9 "$GNB_PID" 2>/dev/null
  cp /tmp/ferrite_gnb_zmq.log "$OUT/gnb.log" 2>/dev/null
}
trap cleanup EXIT

# Make sure nothing stale holds the ports.
for p in $(pgrep -x gnb); do kill "$p" 2>/dev/null; done; sleep 1

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

( cd "$ROOT" && cargo run --release -p ferrite-ue -q -- --dl-arfcn "$ARFCN" --srate "$SRATE" \
    --ping "$PING" --exit-after-ping --timeout "$DURATION" --log "${UE_LOG:-info}" ${UE_ARGS:-} > "$OUT/ue.log" 2>&1 ) &
UE_PID=$!
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
echo "UE exit code $UE_RC; logs in $OUT"
exit $RESULT
