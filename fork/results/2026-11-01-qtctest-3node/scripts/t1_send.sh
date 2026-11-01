#!/bin/bash
# Test 1: peer-to-peer sends. A -> B (mined by A), then B -> C (mined by C). Times relay and confirmation.
cd ~/work; . ./lib.sh
OUT=$RES/t1_send.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
tt() { awk -v e="$1" -v o="$2" 'BEGIN{printf "%.6f", e-o}'; }   # epoch on a node -> NTP-corrected time
getp() { # NODE FILE KEY -> epoch (waits for conf line)
  local f; for i in $(seq 1 40); do f=$(fetch "$1" "$2"); echo "$f" | grep -q '^conf' && break; sleep 2; done
  awk -v k="$3" '$1==k {print $NF}' <<<"$f" | head -1
}
getstate() { fetch "$1" "$2" | awk -v k="$3" '$1==k {print $2}' | head -1; }

log "== t1: peer-to-peer send =="
measure_clocks | tee -a "$OUT"
rx B '. /root/qt.sh; $CLI createwallet wb >/dev/null 2>&1; echo wallet-wb-ok'
rx C '. /root/qt.sh; $CLI createwallet wc >/dev/null 2>&1; echo wallet-wc-ok'
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress rx' | tail -1)
ADDR_C=$(rx C '. /root/qt.sh; $CLI -rpcwallet=wc getnewmldsaaddress rx' | tail -1)
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
log "addresses: A=$ADDR_A B=$ADDR_B C=$ADDR_C"
log "heights: A=$(rx A '. /root/qt.sh; height'|tail -1) B=$(rx B '. /root/qt.sh; height'|tail -1) C=$(rx C '. /root/qt.sh; height'|tail -1)"

# ---- leg 1: A -> B, 5 coins, mined by A
P=$(act A prep miner "$ADDR_B" 5); TX1=$(kv "$P" TXID); log "leg1 txid=$TX1"
for n in B C; do bg $n "/root/poll.sh /root/out/t1a_$n.txt tx $TX1" >/dev/null; done
sleep 2
BC=$(act A bcast "$TX1"); log "leg1 broadcast on A: $BC"
sleep 5
MN=$(act A mine "$ADDR_A" 1); log "leg1 block mined on A: $MN"
BS=$(kv "$BC" bcast_start); BE=$(kv "$BC" bcast_end); MS=$(kv "$MN" mine_start); ME=$(kv "$MN" mine_end)
SB=$(getp B /root/out/t1a_B.txt seen); CB=$(getp B /root/out/t1a_B.txt conf)
SC=$(getp C /root/out/t1a_C.txt seen); CC=$(getp C /root/out/t1a_C.txt conf)
b0=$(tt "$BS" "$OFF_A")
log "leg1 timings (NTP-corrected, seconds):"
log "  A: broadcast call took $(sub $BE $BS)"
log "  relay A->B (tx first seen in B mempool): $(sub $(tt $SB $OFF_B) $b0)"
log "  relay A->C (tx first seen in C mempool): $(sub $(tt $SC $OFF_C) $b0)"
log "  mining on A (one generatetoaddress call): $(sub $ME $MS)"
log "  block A->B (block found on A to confirmed on B): $(sub $(tt $CB $OFF_B) $(tt $ME $OFF_A))"
log "  block A->C: $(sub $(tt $CC $OFF_C) $(tt $ME $OFF_A))"
log "  broadcast -> 1 confirmation at B: $(sub $(tt $CB $OFF_B) $b0)   at C: $(sub $(tt $CC $OFF_C) $b0)   (a 5 s relay gap was left before mining on purpose)"
log "  B balance now: $(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getbalances' | tr -d '\n ' )"

# ---- leg 2: B -> C, 2 coins, mined by C
sleep 2
P=$(act B prep wb "$ADDR_C" 2); TX2=$(kv "$P" TXID); log "leg2 txid=$TX2"
for n in A C; do bg $n "/root/poll.sh /root/out/t1b_$n.txt tx $TX2" >/dev/null; done
sleep 2
BC=$(act B bcast "$TX2"); log "leg2 broadcast on B: $BC"
sleep 5
MN=$(act C mine "$ADDR_C" 1); log "leg2 block mined on C: $MN"
BS=$(kv "$BC" bcast_start); BE=$(kv "$BC" bcast_end); MS=$(kv "$MN" mine_start); ME=$(kv "$MN" mine_end)
SA=$(getp A /root/out/t1b_A.txt seen); CA=$(getp A /root/out/t1b_A.txt conf)
SC=$(getp C /root/out/t1b_C.txt seen); CC=$(getp C /root/out/t1b_C.txt conf)
b0=$(tt "$BS" "$OFF_B")
log "leg2 timings (NTP-corrected, seconds):"
log "  B: broadcast call took $(sub $BE $BS)"
log "  relay B->A: $(sub $(tt $SA $OFF_A) $b0)    relay B->C: $(sub $(tt $SC $OFF_C) $b0)"
log "  mining on C (one call): $(sub $ME $MS)"
log "  block C->A: $(sub $(tt $CA $OFF_A) $(tt $ME $OFF_C))"
log "  broadcast -> 1 confirmation at A: $(sub $(tt $CA $OFF_A) $b0)   at C: $(sub $(tt $CC $OFF_C) $b0)"
log "  C balance now: $(rx C '. /root/qt.sh; $CLI -rpcwallet=wc getbalances' | tr -d '\n ' )"
log "heights after: A=$(rx A '. /root/qt.sh; height'|tail -1) B=$(rx B '. /root/qt.sh; height'|tail -1) C=$(rx C '. /root/qt.sh; height'|tail -1)"
log "tips: A=$(rx A '. /root/qt.sh; tip'|tail -1 | cut -c1-16) B=$(rx B '. /root/qt.sh; tip'|tail -1 | cut -c1-16) C=$(rx C '. /root/qt.sh; tip'|tail -1 | cut -c1-16)"
