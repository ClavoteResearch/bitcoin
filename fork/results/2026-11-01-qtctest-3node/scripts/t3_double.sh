#!/bin/bash
# Test 3: double spend. Two conflicting transactions spend the same output, submitted to B and C at the same moment.
#  Round 1: a mempool race, resolved by a block mined on A.
#  Round 2: B and C each mine a block containing their own transaction (a fork), then A extends one side.
cd ~/work; . ./lib.sh
OUT=$RES/t3_double.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
tt() { awk -v e="$1" -v o="$2" 'BEGIN{printf "%.6f", e-o}'; }
short() { cut -c1-12; }
mp() { # NODE -> mempool txids (short)
  rx "$1" '. /root/qt.sh; $CLI getrawmempool' | tr -d '[]" ,' | grep -v '^$' | short | tr '\n' ' '; }
chaintips() { rx "$1" '. /root/qt.sh; $CLI getchaintips' | python -c '
import sys,json
print(" | ".join("h=%d %s %s" % (t["height"], t["status"], t["hash"][:12]) for t in json.load(sys.stdin)))'; }
pstate() { # NODE FILE -> "state@epoch" or "-" (first poll line "seen")
  fetch "$1" "$2" | awk '$1=="seen"{print $2"@"$NF} END{}' | head -1; }
pconf() { fetch "$1" "$2" | awk '$1=="conf"{print $2"@"$NF}' | head -1; }

log "== t3: double spend =="
measure_clocks | tee -a "$OUT"; . "$RES/offsets.env"
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress ds' | tail -1)
ADDR_C=$(rx C '. /root/qt.sh; $CLI -rpcwallet=wc getnewmldsaaddress ds' | tail -1)
UT=$(rx A '/root/sp.sh utxos 49 3'); log "outputs used: $(echo "$UT" | tr '\n' ';')"
read U1 V1 _ <<<"$(echo "$UT" | sed -n 1p)"; read U2 V2 _ <<<"$(echo "$UT" | sed -n 2p)"

run_pair() { # LABEL UTXO_TXID UTXO_VOUT -> sets TXA (pays B) TXB (pays C), HEXA HEXB
  local label=$1
  TXA=$(kv "$(act A prepin miner "$2" "$3" "$ADDR_B" 49.99)" TXID)
  TXB=$(kv "$(act A prepin miner "$2" "$3" "$ADDR_C" 49.99)" TXID)
  log "$label: tx_to_B=$TXA  tx_to_C=$TXB   (both spend $2:$3)"
  HEXA=$(fetch A /root/out/tx_$TXA.hex); HEXB=$(fetch A /root/out/tx_$TXB.hex)
  for n in A B C; do
    bg $n "/root/poll.sh /root/out/${label}_${n}_A.txt tx $TXA" >/dev/null
    bg $n "/root/poll.sh /root/out/${label}_${n}_B.txt tx $TXB" >/dev/null
  done
  sleep 2
}
submit_both() { # submit HEXA to B and HEXB to C at the same moment
  ( echo "$HEXA" | rx B '/root/act.sh bcasthex' > "$RES/t3_subB.txt" ) &
  ( echo "$HEXB" | rx C '/root/act.sh bcasthex' > "$RES/t3_subC.txt" ) &
  wait
  SB=$(cat "$RES/t3_subB.txt"); SC=$(cat "$RES/t3_subC.txt")
  log "  submit to B: $(echo "$SB" | sed 's/bcast_end=[0-9.]* //')"
  log "  submit to C: $(echo "$SC" | sed 's/bcast_end=[0-9.]* //')"
  sb=$(kv "$SB" bcast_start); sc=$(kv "$SC" bcast_start)
  FIRST=$(awk -v a="$(tt $sb $OFF_B)" -v b="$(tt $sc $OFF_C)" 'BEGIN{print (a<b)?a:b}')
  log "  gap between the two submissions (NTP-corrected): $(sub $(tt $sc $OFF_C) $(tt $sb $OFF_B)) s (C minus B)"
}

# ================= Round 1: mempool race, resolved by A
log "--- round 1: mempool race"
run_pair r1 "$U1" "$V1"
submit_both
sleep 10
for n in A B C; do log "  mempool $n after 10 s: $(mp $n)   [B-tx=${TXA:0:12} C-tx=${TXB:0:12}]"; done
MN=$(act A mine "$ADDR_A" 1); log "  block mined on A: $MN"; ME=$(kv "$MN" mine_end)
sleep 8
for n in A B C; do eval "o=\$OFF_$n"
  log "  $n: tx_to_B first=$(pstate $n /root/out/r1_${n}_A.txt) conf=$(pconf $n /root/out/r1_${n}_A.txt) | tx_to_C first=$(pstate $n /root/out/r1_${n}_B.txt) conf=$(pconf $n /root/out/r1_${n}_B.txt)"
done
WIN=none; [ "$(rx A ". /root/qt.sh; txconf $TXA" | tail -1)" -ge 1 ] 2>/dev/null && WIN="tx_to_B (${TXA:0:12})"; [ "$(rx A ". /root/qt.sh; txconf $TXB" | tail -1)" -ge 1 ] 2>/dev/null && WIN="tx_to_C (${TXB:0:12})"
log "  WINNER (confirmed on A): $WIN"
for n in A B C; do log "  $n: tx_to_B conf=$(rx $n ". /root/qt.sh; txconf $TXA"|tail -1) tx_to_C conf=$(rx $n ". /root/qt.sh; txconf $TXB"|tail -1) mempool=[$(mp $n)] tip=$(rx $n '. /root/qt.sh; tip'|tail -1|short)"; done
# resolution time = until the last of B and C sees the winner confirmed
WT=$([ "${WIN#tx_to_B}" != "$WIN" ] && echo A || echo B)
cB=$(fetch B /root/out/r1_B_${WT}.txt | awk '$1=="conf"{print $NF}'); cC=$(fetch C /root/out/r1_C_${WT}.txt | awk '$1=="conf"{print $NF}')
log "  RESOLUTION: first submission -> winner confirmed on B: $(sub $(tt $cB $OFF_B) $FIRST) s, on C: $(sub $(tt $cC $OFF_C) $FIRST) s (includes the 10 s settle wait and a manual block)"

# ================= Round 2: competing blocks
log "--- round 2: competing blocks (fork)"
sleep 3
run_pair r2 "$U2" "$V2"
submit_both
sleep 10
for n in A B C; do log "  mempool $n before mining: $(mp $n)   [B-tx=${TXA:0:12} C-tx=${TXB:0:12}]"; done
( act B mine "$ADDR_B" 1 > "$RES/t3_mineB.txt" ) &
( act C mine "$ADDR_C" 1 > "$RES/t3_mineC.txt" ) &
wait
log "  block mined on B: $(cat $RES/t3_mineB.txt)"
log "  block mined on C: $(cat $RES/t3_mineC.txt)"
sleep 8
for n in A B C; do log "  $n tips after both blocks: $(chaintips $n)"; done
TIPB=$(rx B '. /root/qt.sh; tip' | tail -1); TIPC=$(rx C '. /root/qt.sh; tip' | tail -1); TIPA=$(rx A '. /root/qt.sh; tip' | tail -1)
log "  active tip: A=${TIPA:0:12} B=${TIPB:0:12} C=${TIPC:0:12}   (A follows whichever block reached it first)"
bg B "/root/poll.sh /root/out/r2_chgB.txt chg $TIPB" >/dev/null; bg C "/root/poll.sh /root/out/r2_chgC.txt chg $TIPC" >/dev/null
sleep 2
MN=$(act A mine "$ADDR_A" 1); log "  tie-breaking block mined on A (extends A's active tip ${TIPA:0:12}): $MN"; ME=$(kv "$MN" mine_end)
sleep 10
ch() { fetch "$1" "$2" | awk '$1=="chg"{print $2" "$3}' | head -1; }
rB=$(ch B /root/out/r2_chgB.txt); rC=$(ch C /root/out/r2_chgC.txt)
log "  B tip change: $(echo $rB | cut -c1-12) at +$(sub $(tt $(echo $rB | awk '{print $2}') $OFF_B) $(tt $ME $OFF_A)) s after A's block"
log "  C tip change: $(echo $rC | cut -c1-12) at +$(sub $(tt $(echo $rC | awk '{print $2}') $OFF_C) $(tt $ME $OFF_A)) s after A's block"
for n in A B C; do
  log "  $n: tx_to_B conf=$(rx $n ". /root/qt.sh; txconf $TXA"|tail -1) tx_to_C conf=$(rx $n ". /root/qt.sh; txconf $TXB"|tail -1) mempool=[$(mp $n)] tip=$(rx $n '. /root/qt.sh; tip'|tail -1|short)  tips: $(chaintips $n)"
done
if [ "$(rx A ". /root/qt.sh; txconf $TXA"|tail -1)" -ge 1 ] 2>/dev/null; then log "  WINNER round 2: tx_to_B (mined first on B's fork)"; else log "  WINNER round 2: tx_to_C (C's fork)"; fi
log "  final tips equal on all nodes? A=$(rx A '. /root/qt.sh; tip'|tail -1|short) B=$(rx B '. /root/qt.sh; tip'|tail -1|short) C=$(rx C '. /root/qt.sh; tip'|tail -1|short)"
