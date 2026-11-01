#!/bin/bash
# Phase 0: connect A, B, C and time the initial block sync of B and C from A.
cd ~/work; . ./lib.sh
OUT=$RES/t0_connect.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }

log "== t0: heights before connecting =="
for n in $NODES; do log "$n height=$(rx $n '. /root/qt.sh; height' | tail -1)"; done
HA=$(rx A '. /root/qt.sh; height' | tail -1)
log "target height (node A) = $HA"

measure_clocks | tee -a "$OUT"; . "$RES/offsets.env"
# pollers on B and C: time until they reach A's height
for n in B C; do bg $n "/root/poll.sh /root/out/t0_$n.txt hcheck $HA" >/dev/null; done
sleep 1
T0=$(date +%s.%N)
log "connecting (local epoch $T0)"
rx A ". /root/qt.sh; \$CLI addnode ${EXTP2P[B]} add; \$CLI addnode ${EXTP2P[C]} add; echo A_addnode_sent \$(now)" | tee -a "$OUT"
rx B ". /root/qt.sh; \$CLI addnode ${EXTP2P[C]} add; echo B_addnode_sent \$(now)" | tee -a "$OUT"
rx C ". /root/qt.sh; \$CLI addnode ${EXTP2P[B]} add; echo C_addnode_sent \$(now)" | tee -a "$OUT"
sleep 12
for n in B C; do
  for i in 1 2 3 4 5 6 7 8 9 10; do f=$(fetch $n /root/out/t0_$n.txt); echo "$f" | grep -q '^mempool_after' && break; sleep 3; done
  hline=$(echo "$f" | grep '^height'); eval "OFF=\$OFF_$n"
  log "$n sync result: $hline"
done
log "== peers =="
for n in $NODES; do
  log "--- $n"
  rx $n '. /root/qt.sh; $CLI getpeerinfo | python3 -c "
import sys,json
for p in json.load(sys.stdin):
    print(\"  peer\", p[\"addr\"], \"inbound=%s\" % p[\"inbound\"], \"subver=%s\" % p[\"subver\"], \"synced_blocks=%s\" % p.get(\"synced_blocks\"), \"minping=%s\" % p.get(\"minping\"))
"; echo "  height=$(height) tip=$(tip)"' | tee -a "$OUT"
done
