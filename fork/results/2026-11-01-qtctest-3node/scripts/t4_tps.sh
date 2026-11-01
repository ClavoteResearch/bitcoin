#!/bin/bash
# Test 4: throughput sample. N independent small payments (one input, one output, no change chains) are broadcast
# from A in a burst; B and C relay them; one block mined on A confirms them.
cd ~/work; . ./lib.sh
N=${1:-50}
OUT=$RES/t4_tps.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
tt() { awk -v e="$1" -v o="$2" 'BEGIN{printf "%.6f", e-o}'; }
ep() { awk -v k="$2" '$1==k {print $NF}' <<<"$1" | head -1; }

log "== t4: throughput sample, N=$N =="
measure_clocks | tee -a "$OUT"
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress tps' | tail -1)

# ---- setup: split one coinbase into N spendable outputs and confirm them (not timed)
S=$(rx A "/root/sp.sh split $N 0.9"); SPLIT=$(kv "$S" SPLIT_TXID); log "split txid=$SPLIT"
MN=$(act A mine "$ADDR_A" 1); log "split confirmed in block: $MN"
sleep 4
P=$(rx A "/root/batch.sh prep $SPLIT $ADDR_B 0.9 0.89"); log "$(echo "$P" | grep prepared)"
log "heights before: A=$(rx A '. /root/qt.sh; height'|tail -1) B=$(rx B '. /root/qt.sh; height'|tail -1) C=$(rx C '. /root/qt.sh; height'|tail -1)   mempools: A=$(rx A '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1)"
H0=$(rx A '. /root/qt.sh; height' | tail -1); H1=$((H0+1))

# ---- timed phase
for n in B C; do bg $n "/root/poll.sh /root/out/t4_steps_$n.txt steps 1 $((N/2)) $N" >/dev/null; done
for n in A B C; do bg $n "/root/poll.sh /root/out/t4_h_$n.txt hcheck $H1" >/dev/null; done
sleep 3
BR=$(rx A '/root/batch.sh bcast 8'); log "$BR"
FS=$(echo "$BR" | grep first_start | tr ' ' '\n' | grep '^first_start=' | cut -d= -f2); LE=$(echo "$BR" | grep first_start | tr ' ' '\n' | grep '^last_end=' | cut -d= -f2)
for i in $(seq 1 30); do s1=$(fetch B /root/out/t4_steps_B.txt); s2=$(fetch C /root/out/t4_steps_C.txt); echo "$s1" | grep -q "size>=$N" && echo "$s2" | grep -q "size>=$N" && break; sleep 1; done
log "mempools after relay: B=$(rx B '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1) C=$(rx C '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1)"
MN=$(act A mine "$ADDR_A" 1); log "block with the batch mined on A: $MN"; MS=$(kv "$MN" mine_start); ME=$(kv "$MN" mine_end); BH=$(kv "$MN" hash)
sleep 6

b0=$(tt "$FS" "$OFF_A")
log "timings (NTP-corrected, seconds, relative to the first broadcast call):"
log "  A: all $N broadcast calls finished after $(sub $(tt $LE $OFF_A) $b0) s  => mempool admission rate $(awk -v n=$N -v d=$(sub $LE $FS) 'BEGIN{printf "%.1f", n/d}') tx/s (8 parallel RPC callers, includes ML-DSA verification)"
for n in B C; do
  eval "o=\$OFF_$n"; st=$(fetch $n /root/out/t4_steps_$n.txt)
  log "  $n mempool reached 1 / $((N/2)) / $N txs at +$(sub $(tt $(ep "$(echo "$st" | grep 'size>=1 ')" 'size>=1') $o) $b0) / +$(sub $(tt $(ep "$(echo "$st" | grep "size>=$((N/2)) ")" "size>=$((N/2))") $o) $b0) / +$(sub $(tt $(ep "$(echo "$st" | grep "size>=$N ")" "size>=$N") $o) $b0) s"
done
log "  mining the block on A took $(sub $ME $MS) s, started at +$(sub $(tt $MS $OFF_A) $b0) s"
for n in A B C; do eval "o=\$OFF_$n"; h=$(fetch $n /root/out/t4_h_$n.txt)
  hh=$(echo "$h" | awk '$1=="height"{print $NF}'); ma=$(echo "$h" | awk '$1=="mempool_after"{print $2}')
  log "  $n reached height $H1 at +$(sub $(tt $hh $o) $b0) s, mempool after = $ma"
done
BI=$(rx B ". /root/qt.sh; \$CLI getblock $BH 1" | python -c 'import sys,json; d=json.load(sys.stdin); print("block %d: %d txs, size=%d bytes, weight=%d" % (d["height"], d["nTx"], d["size"], d["weight"]))')
log "  $BI (as seen by B)"
LAST=$(for n in B C; do eval "o=\$OFF_$n"; h=$(fetch $n /root/out/t4_h_$n.txt); tt $(echo "$h" | awk '$1=="height"{print $NF}') $o; done | sort -n | tail -1)
log "  END-TO-END: $N txs, first broadcast -> confirmed on all nodes in $(sub $LAST $b0) s => $(awk -v n=$N -v d=$(sub $LAST $b0) 'BEGIN{printf "%.1f", n/d}') tx/s (limited by the manual 'mine right after relay' step, not by block capacity)"
log "  block capacity check: $(echo "$BI" | grep -o 'weight=[0-9]*') of 4000000 WU; one 1-input/1-output v2 spend is about 4.2 kWU, so roughly 900 per block at full weight"
