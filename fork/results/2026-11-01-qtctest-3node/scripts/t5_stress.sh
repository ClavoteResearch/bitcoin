#!/bin/bash
# Test 5: stress test of the three-node network.
#   s1_N     burst ladder: N independent spends broadcast from A in a burst, mined after relay completes
#   s2_cold  500 spends broadcast and mined at once, so the block reaches B and C before most transactions have
#   s3       three nodes broadcast 100 spends each at the same instant
#   s4       sustained 20 tx/s for 60 s from A while C mines a block every 10 s
# Raw files go to results/t5/, the analysis to results/t5_stress.txt (run t5_analyze.py).
cd ~/work; . ./lib.sh
D=$RES/t5; rm -rf "$D"; mkdir -p "$D"
LOG=$RES/t5_driver.txt; : > "$LOG"
log() { echo "$*" | tee -a "$LOG"; }
st() { local n=$1; shift; rx "$n" "python3 /root/stress.py $*"; }
save() { fetch "$1" "$2" > "$D/$3"; }
bcastfield() { printf '%s\n' "$1" | tr ' ' '\n' | grep "^$2=" | head -1 | cut -d= -f2; }
waitsteps() { # LABEL N NODES... : until every listed node's mempool reached N
  local L=$1 N=$2; shift 2
  for i in $(seq 1 100); do
    ok=1; for n in "$@"; do fetch $n /root/out/${L}_steps_$n.txt | grep -q "size>=$N " || ok=0; done
    [ $ok = 1 ] && return 0; sleep 2
  done; return 1
}
blockinfo() { rx "$1" ". /root/qt.sh; \$CLI getblock $2 1" | python -c 'import sys,json; d=json.load(sys.stdin); print(d["nTx"], d["size"], d["weight"])'; }

log "== t5: stress test =="
measure_clocks | tee -a "$LOG"; . "$RES/offsets.env"
echo "{\"OFF_A\":$OFF_A,\"OFF_B\":$OFF_B,\"OFF_C\":$OFF_C}" > "$D/offsets.json"
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress rx' | tail -1)
ADDR_C=$(rx C '. /root/qt.sh; $CLI -rpcwallet=wc getnewmldsaaddress rx' | tail -1)
: > "$D/meta.jsonl"

# ---------------- setup: mature more coinbases, create thousands of spendable 0.02 outputs
log "--- setup"
rx A '. /root/qt.sh; echo "A mature balance: $($CLI -rpcwallet=miner getbalances | python3 -c "import sys,json;print(json.load(sys.stdin)[\"mine\"][\"trusted\"])")"' | tee -a "$LOG"
log "mining 20 blocks on A to mature more coinbases: $(act A mine "$ADDR_A" 20 | tail -1)"
for i in 1 2 3 4; do log "split $i: $(st A split miner 900 0.02 | tr '\n' ' ')"; done
log "S3 funding: 100 addresses each on B and C"
JB=$(st B addrs wb 100 s3 | tail -1); JC=$(st C addrs wc 100 s3 | tail -1)
ALL=$(python -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])+json.loads(sys.argv[2])))' "$JB" "$JC")
log "$(echo "$ALL" | rx A 'python3 /root/stress.py sendmany miner 0.02')"
log "confirm everything: $(act A mine "$ADDR_A" 1)"
sleep 8
log "heights: A=$(rx A '. /root/qt.sh; height'|tail -1) B=$(rx B '. /root/qt.sh; height'|tail -1) C=$(rx C '. /root/qt.sh; height'|tail -1); 0.02 outputs: A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner listunspent 1 9999999 "[]" true | python3 -c "import sys,json;print(sum(1 for u in json.load(sys.stdin) if abs(u[\"amount\"]-0.02)<1e-9))"'|tail -1) B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb listunspent 1 9999999 "[]" true | python3 -c "import sys,json;print(sum(1 for u in json.load(sys.stdin) if abs(u[\"amount\"]-0.02)<1e-9))"'|tail -1) C=$(rx C '. /root/qt.sh; $CLI -rpcwallet=wc listunspent 1 9999999 "[]" true | python3 -c "import sys,json;print(sum(1 for u in json.load(sys.stdin) if abs(u[\"amount\"]-0.02)<1e-9))"'|tail -1)"

# ---------------- s1 ladder and s2 cold block
run_burst() { # LABEL N IMMEDIATE
  local L=$1 N=$2 IMM=$3
  log "--- $L: N=$N, mine immediately after broadcast: $IMM"
  log "$(st A prep $L miner $ADDR_B 0.02 0.0198 $N)"
  local H1=$(( $(rx A '. /root/qt.sh; height' | tail -1) + 1 ))
  for n in B C; do bg $n "/root/poll.sh /root/out/${L}_steps_$n.txt steps $((N/4)) $((N/2)) $((3*N/4)) $N" >/dev/null; done
  for n in A B C; do bg $n "/root/poll.sh /root/out/${L}_h_$n.txt hcheck $H1" >/dev/null; done
  sleep 3
  local BR; BR=$(st A bcast $L 12); log "$BR"
  if [ "$IMM" = 0 ]; then waitsteps $L $N B C || log "WARNING: relay did not complete within the wait"; fi
  local MN; MN=$(act A mine "$ADDR_A" 1); log "mine: $MN"
  sleep 12
  for n in A B C; do save $n /root/out/${L}_h_$n.txt ${L}_h_$n.txt; done
  for n in B C; do save $n /root/out/${L}_steps_$n.txt ${L}_steps_$n.txt; done
  printf '%s\n' "$BR" > "$D/${L}_bcast.txt"
  local BH; BH=$(kv "$MN" hash); read BN BS BW <<<"$(blockinfo B $BH)"
  log "block: $BN txs, $BS bytes, $BW WU; mempools after: A=$(rx A '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1) B=$(rx B '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1) C=$(rx C '. /root/qt.sh; $CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])"'|tail -1)"
  echo "{\"label\":\"$L\",\"N\":$N,\"imm\":$IMM,\"mine_start\":$(kv "$MN" mine_start),\"mine_end\":$(kv "$MN" mine_end),\"hash\":\"$BH\",\"H1\":$H1,\"blk_ntx\":$BN,\"blk_size\":$BS,\"blk_weight\":$BW}" >> "$D/meta.jsonl"
}
for N in 100 250 500 900; do run_burst s1_$N $N 0; sleep 5; done
run_burst s2_cold 500 1; sleep 5

# ---------------- s3: three concurrent senders
log "--- s3: 100 spends from each of A, B, C at the same instant"
log "$(st A prep s3_A miner $ADDR_C 0.02 0.0198 100)"
log "$(st B prep s3_B wb $ADDR_A 0.02 0.0198 100)"
log "$(st C prep s3_C wc $ADDR_B 0.02 0.0198 100)"
H1=$(( $(rx A '. /root/qt.sh; height' | tail -1) + 1 ))
for n in A B C; do bg $n "/root/poll.sh /root/out/s3_steps_$n.txt steps 75 150 225 300" >/dev/null; bg $n "/root/poll.sh /root/out/s3_h_$n.txt hcheck $H1" >/dev/null; done
sleep 3
NOWA=$(rx A '. /root/qt.sh; now' | tail -1)
START_TRUE=$(awk -v a="$NOWA" -v o="$OFF_A" 'BEGIN{printf "%.3f", a-o+15}')
SA=$(awk -v s=$START_TRUE -v o=$OFF_A 'BEGIN{printf "%.3f", s+o}'); SB=$(awk -v s=$START_TRUE -v o=$OFF_B 'BEGIN{printf "%.3f", s+o}'); SC=$(awk -v s=$START_TRUE -v o=$OFF_C 'BEGIN{printf "%.3f", s+o}')
( st A bcast s3_A 8 0 $SA > "$D/s3_A_bcast.txt" ) &
( st B bcast s3_B 8 0 $SB > "$D/s3_B_bcast.txt" ) &
( st C bcast s3_C 8 0 $SC > "$D/s3_C_bcast.txt" ) &
wait
log "s3 sends: A: $(head -1 $D/s3_A_bcast.txt | cut -c1-110) | B: $(head -1 $D/s3_B_bcast.txt | cut -c1-110) | C: $(head -1 $D/s3_C_bcast.txt | cut -c1-110)"
waitsteps s3 300 A B C || log "WARNING: not every node reached 300 txs"
MN=$(act C mine "$ADDR_C" 1); log "mine on C: $MN"
sleep 12
for n in A B C; do save $n /root/out/s3_steps_$n.txt s3_steps_$n.txt; save $n /root/out/s3_h_$n.txt s3_h_$n.txt; done
BH=$(kv "$MN" hash); read BN BS BW <<<"$(blockinfo A $BH)"
log "block: $BN txs, $BS bytes, $BW WU"
echo "{\"label\":\"s3\",\"N\":300,\"start_true\":$START_TRUE,\"mine_start\":$(kv "$MN" mine_start),\"mine_end\":$(kv "$MN" mine_end),\"hash\":\"$BH\",\"H1\":$H1,\"blk_ntx\":$BN,\"blk_size\":$BS,\"blk_weight\":$BW}" >> "$D/meta.jsonl"
sleep 5

# ---------------- s4: sustained load
log "--- s4: sustained 20 tx/s for 60 s from A, blocks mined on C every 10 s"
log "$(st A prep s4 miner $ADDR_B 0.02 0.0198 1200)"
for n in A B C; do bg $n "/root/poll.sh /root/out/s4_sample_$n.txt sample 115" >/dev/null; done
sleep 2
NOWA=$(rx A '. /root/qt.sh; now' | tail -1)
START_TRUE=$(awk -v a="$NOWA" -v o="$OFF_A" 'BEGIN{printf "%.3f", a-o+12}')
SA=$(awk -v s=$START_TRUE -v o=$OFF_A 'BEGIN{printf "%.3f", s+o}'); SC=$(awk -v s=$START_TRUE -v o=$OFF_C 'BEGIN{printf "%.3f", s+o}')
( st A bcast s4 16 20 $SA > "$D/s4_A_bcast.txt" ) &
( st C mineloop "$ADDR_C" 10 90 $SC > "$D/s4_C_mine.txt" ) &
wait
log "s4 sender: $(head -2 $D/s4_A_bcast.txt | tr '\n' ' ')"
log "s4 blocks mined on C:"; cat "$D/s4_C_mine.txt" | tee -a "$LOG"
sleep 8
save A /root/out/s4_bcast.json s4_bcast.json; save C /root/out/mineloop.json s4_mineloop.json
for n in A B C; do save $n /root/out/s4_sample_$n.txt s4_sample_$n.txt; done
echo "{\"label\":\"s4\",\"start_true\":$START_TRUE}" >> "$D/meta.jsonl"

log "--- final state"
for n in A B C; do log "$n: $(rx $n '. /root/qt.sh; echo "height=$(height) tip=$(tip | cut -c1-16) mempool=$($CLI getmempoolinfo | python3 -c "import sys,json;print(json.load(sys.stdin)[\"size\"])") peers=$($CLI getconnectioncount)"') errors_in_log=$(rx $n 'grep -c -E "ERROR|Assertion|crash" /root/qtctest-data/qtctest/debug.log' | tail -1)"; done
python t5_analyze.py "$D" | tee "$RES/t5_stress.txt"
