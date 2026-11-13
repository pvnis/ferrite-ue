#!/usr/bin/env bash
# Run a fresh no-core gNB and a PHY probe command against it.
#   scripts/probe.sh <gnb-config.yml> <probe command...>
set -u
CFG=$1; shift
OUT=/home/dmd/ferrite-ue/test/results
mkdir -p "$OUT"
for p in $(pgrep -x gnb); do kill "$p" 2>/dev/null; done; sleep 1; for p in $(pgrep -x gnb); do kill -9 "$p" 2>/dev/null; done; sleep 0.5
sed 's/^    addr: 127.0.0.1/    no_core: true\n    addr: 127.0.0.1/' "$CFG" > "$OUT/gnb_nocore.yml"
rm -f /tmp/ferrite_gnb_zmq.log
setsid nohup stdbuf -oL -eL /home/dmd/ocudu-pavo/build/apps/gnb/gnb -c "$OUT/gnb_nocore.yml" > "$OUT/gnb.out" 2>&1 < /dev/null &
GNB=$!
for _ in $(seq 1 120); do grep -q "gNB started" "$OUT/gnb.out" 2>/dev/null && break; sleep 0.5; done
grep -q "gNB started" "$OUT/gnb.out" || { echo "gNB failed"; tail -5 "$OUT/gnb.out"; kill $GNB; exit 1; }
sleep 1
"$@"
RC=$?
kill $GNB 2>/dev/null; sleep 1; kill -9 $GNB 2>/dev/null
cp /tmp/ferrite_gnb_zmq.log "$OUT/gnb.log" 2>/dev/null
exit $RC
