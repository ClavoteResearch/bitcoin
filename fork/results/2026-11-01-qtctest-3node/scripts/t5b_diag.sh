#!/bin/bash
# Diagnostic for the slow block connection seen on node B in the stress test (t5): every burst paid an address of B's
# wallet. Repeat a 450-transaction burst paying an address that no node's wallet owns and compare how long B and C take
# to reach the new block. Clocks are used raw (all measured offsets were under 3 ms).
cd ~/work; . ./lib.sh
OUT=$RES/t5b_diag.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
st() { local n=$1; shift; rx "$n" "python3 /root/stress.py $*"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
N=450
log "== t5b: block connection on B with payments to an address B does not own =="
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
SI=$(python -c 'import secrets;print(secrets.token_hex(32))'); SL=$(python -c 'import secrets;print(secrets.token_hex(32))')
FOREIGN=$(kv "$(rx A "/root/sp.sh addr $SI $SL")" address)
log "foreign v2 address (no wallet owns it): $FOREIGN"
log "split: $(st A split miner $N 0.02 | tr '\n' ' ')"
log "confirm: $(act A mine "$ADDR_A" 1)"; sleep 8
run() { # LABEL DEST
  local L=$1 DEST=$2
  log "--- $L: $N spends paying $DEST"
  log "$(st A prep $L miner $DEST 0.02 0.0198 $N)"
  local H1=$(( $(rx A '. /root/qt.sh; height' | tail -1) + 1 ))
  for n in B C; do bg $n "/root/poll.sh /root/out/${L}_steps_$n.txt steps $N" >/dev/null; done
  for n in A B C; do bg $n "/root/poll.sh /root/out/${L}_h_$n.txt hcheck $H1" >/dev/null; done
  sleep 3
  log "$(st A bcast $L 12 | head -1)"
  for i in $(seq 1 100); do ok=1; for n in B C; do fetch $n /root/out/${L}_steps_$n.txt | grep -q "size>=$N " || ok=0; done; [ $ok = 1 ] && break; sleep 2; done
  local MN; MN=$(act A mine "$ADDR_A" 1); local ME; ME=$(kv "$MN" mine_end)
  sleep 12
  for n in B C; do h=$(fetch $n /root/out/${L}_h_$n.txt | awk '$1=="height"{print $NF}'); log "  $n reached the block $(sub $h $ME) s after A found it"; done
}
run d_foreign "$FOREIGN"
# a repeat to B's own address for comparison on the same machines, same size
log "split: $(st A split miner $N 0.02 | tr '\n' ' ')"
log "confirm: $(act A mine "$ADDR_A" 1)"; sleep 8
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress rx' | tail -1)
run d_ownB "$ADDR_B"
