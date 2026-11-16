#!/usr/bin/env bash
# Run cell configurations × channel scenarios through scripts/lab.sh and
# summarise them in one table.
#
#   scripts/matrix.sh [-c "T1 C1 ..."] [-s "ideal pedestrian ..."] [--ping N] [--duration S]
#
# Defaults: every config that runs through the emulator (T1–T7, C1, C2, F1,
# F2) × every scenario (`scripts/lab.sh X --scenario list`). Use `-s direct`
# for a run without the emulator. Each run's logs stay in
# test/results/<id>-<scenario>-<timestamp>/; the table goes to stdout and to
# test/results/matrix-<timestamp>.md.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGS="T1 T2 T3 T4 T5 T6 T7 C1 C2 F1 F2"
SCENARIOS="ideal static indoor pedestrian urban vehicular dispersive cell-edge"
PING=20
DURATION=120
while [ $# -gt 0 ]; do
  case "$1" in
    -c) CONFIGS=$2; shift 2;;
    -s) SCENARIOS=$2; shift 2;;
    --ping) PING=$2; shift 2;;
    --duration) DURATION=$2; shift 2;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
TABLE="$ROOT/test/results/matrix-$(date +%Y%m%d-%H%M%S).md"
mkdir -p "$ROOT/test/results"
row() { echo "$1" | tee -a "$TABLE"; }
row "| Config | Scenario | Result | Ping | UE DL TB ok/ko | gNB PUSCH ok/ko | UE drift (ppm) | Pace | Failed stages |"
row "|---|---|---|---|---|---|---|---|---|"
for c in $CONFIGS; do
  for s in $SCENARIOS; do
    pkill -9 -x ferrite-ue; pkill -9 -x gnb; pkill -9 -x ferrite-chanem; sudo -n pkill -x qcore
    sleep 1
    LOG=$(mktemp)
    if [ "$s" = direct ]; then
      timeout $((DURATION + 120)) "$ROOT/scripts/lab.sh" "$c" --ping "$PING" --duration "$DURATION" > "$LOG" 2>&1
    else
      timeout $((DURATION + 120)) "$ROOT/scripts/lab.sh" "$c" --ping "$PING" --duration "$DURATION" --scenario "$s" > "$LOG" 2>&1
    fi
    OUT=$(grep -o "→ .*" "$LOG" | head -1 | sed 's/→ //')
    FAILS=$(grep "FAIL" "$LOG" | sed 's/^ *FAIL //; s/ (.*//' | sort -u | paste -sd, -)
    PING_R=$(grep -o "S8 ping [0-9]*/[0-9]*" "$LOG" | head -1 | awk '{print $3}')
    UE="$OUT/ue.log"
    OK=$(grep -o "dl_tb_ok: [0-9]*" "$UE" 2>/dev/null | tail -1 | awk '{print $2}')
    KO=$(grep -o "dl_tb_ko: [0-9]*" "$UE" 2>/dev/null | tail -1 | awk '{print $2}')
    POK=$(grep -c "PUSCH: rnti.*crc=OK" "$OUT/gnb.log" 2>/dev/null)
    PKO=$(grep -c "PUSCH: rnti.*crc=KO" "$OUT/gnb.log" 2>/dev/null)
    DRIFT=$(grep -o "drift [-+0-9.]* ppm" "$UE" 2>/dev/null | tail -1 | awk '{print $2}')
    PACE=$(grep "^DL:.*pace" "$OUT/chanem.log" 2>/dev/null | tail -1 | grep -o "pace [0-9.]*" | awk '{print $2}')
    if [ -z "$FAILS" ] && grep -q "PASS" "$LOG"; then R=pass; else R=FAIL; fi
    row "| $c | $s | $R | ${PING_R:-–} | ${OK:-0}/${KO:-0} | ${POK:-0}/${PKO:-0} | ${DRIFT:-–} | ${PACE:+${PACE}×} | ${FAILS:-} |"
    rm -f "$LOG"
  done
done
pkill -9 -x ferrite-ue; pkill -9 -x gnb; pkill -9 -x ferrite-chanem; sudo -n pkill -x qcore
echo "table: $TABLE"
