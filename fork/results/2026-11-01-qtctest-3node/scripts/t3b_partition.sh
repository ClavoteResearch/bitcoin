#!/bin/bash
# Test 3, round 3: a real fork. B is cut off from the network (setnetworkactive false), B and the A/C side each mine
# blocks that contain conflicting spends of the same output, then B reconnects and must reorganise onto the longer chain.
cd ~/work; . ./lib.sh
OUT=$RES/t3b_partition.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
tt() { awk -v e="$1" -v o="$2" 'BEGIN{printf "%.6f", e-o}'; }
short() { cut -c1-12; }
mp() { rx "$1" '. /root/qt.sh; $CLI getrawmempool' | tr -d '[]" ,' | grep -v '^$' | short | tr '\n' ' '; }
chaintips() { rx "$1" '. /root/qt.sh; $CLI getchaintips' | python -c '
import sys,json
print(" | ".join("h=%d len=%d %s %s" % (t["height"], t["branchlen"], t["status"], t["hash"][:12]) for t in json.load(sys.stdin)))'; }
peers() { rx "$1" '. /root/qt.sh; $CLI getconnectioncount' | tail -1; }

log "== t3b: partition and reorg =="
measure_clocks | tee -a "$OUT"
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
ADDR_B=$(rx B '. /root/qt.sh; $CLI -rpcwallet=wb getnewmldsaaddress ds' | tail -1)
ADDR_C=$(rx C '. /root/qt.sh; $CLI -rpcwallet=wc getnewmldsaaddress ds' | tail -1)
UT=$(rx A '/root/sp.sh utxos 49 3'); log "spendable 50-coin outputs: $(echo "$UT" | tr '\n' ';')"
read U V _ <<<"$(echo "$UT" | sed -n 1p)"
TXB=$(kv "$(act A prepin miner "$U" "$V" "$ADDR_B" 49.99)" TXID); TXC=$(kv "$(act A prepin miner "$U" "$V" "$ADDR_C" 49.99)" TXID)
log "conflicting spends of $U:$V : tx_to_B=$TXB  tx_to_C=$TXC"
HEXB=$(fetch A /root/out/tx_$TXB.hex); HEXC=$(fetch A /root/out/tx_$TXC.hex)
H0=$(rx A '. /root/qt.sh; height' | tail -1); log "height before partition: A=$H0 B=$(rx B '. /root/qt.sh; height'|tail -1) C=$(rx C '. /root/qt.sh; height'|tail -1)"

log "--- partition B"
rx B '. /root/qt.sh; $CLI setnetworkactive false >/dev/null; sleep 1; echo "B connections: $($CLI getconnectioncount)"' | tee -a "$OUT"
log "connections: A=$(peers A) B=$(peers B) C=$(peers C)"
R=$(echo "$HEXB" | rx B '/root/act.sh bcasthex'); log "tx_to_B submitted to B (isolated): $(echo "$R" | sed 's/bcast_start=[0-9.]* bcast_end=[0-9.]* //')"
R=$(echo "$HEXC" | rx C '/root/act.sh bcasthex'); log "tx_to_C submitted to C: $(echo "$R" | sed 's/bcast_start=[0-9.]* bcast_end=[0-9.]* //')"
sleep 12
for n in A B C; do log "  mempool $n: $(mp $n)   [tx_to_B=${TXB:0:12} tx_to_C=${TXC:0:12}]"; done

log "--- mine on both sides of the partition"
MB=$(act B mine "$ADDR_B" 1); log "B (isolated) mined 1 block: $MB"
MA=$(act A mine "$ADDR_A" 2); log "A/C side mined 2 blocks: $(echo "$MA" | tr '\n' ' ')"
sleep 3
for n in A B C; do log "  $n: height=$(rx $n '. /root/qt.sh; height'|tail -1) tip=$(rx $n '. /root/qt.sh; tip'|tail -1|short) mempool=[$(mp $n)]"; done
TIPA=$(rx A '. /root/qt.sh; tip' | tail -1); TIPB=$(rx B '. /root/qt.sh; tip' | tail -1)
log "two competing chains: B tip ${TIPB:0:12} (1 block, holds tx_to_B)  vs  A/C tip ${TIPA:0:12} (2 blocks, holds tx_to_C)"

log "--- reconnect B"
bg B "/root/poll.sh /root/out/t3b_B.txt tip $TIPA" >/dev/null
sleep 2
T0=$(rx B '. /root/qt.sh; $CLI setnetworkactive true >/dev/null; now' | tail -1)
log "B network re-enabled at epoch $T0"
rx A ". /root/qt.sh; \$CLI addnode ${EXTP2P[B]} onetry" >/dev/null &
rx C ". /root/qt.sh; \$CLI addnode ${EXTP2P[B]} onetry" >/dev/null &
rx B ". /root/qt.sh; \$CLI addnode ${EXTP2P[C]} onetry" >/dev/null &
wait
for i in $(seq 1 30); do f=$(fetch B /root/out/t3b_B.txt); echo "$f" | grep -q '^tip' && break; sleep 2; done
TB=$(echo "$f" | awk '$1=="tip"{print $NF}'); STATE=$(echo "$f" | awk '$1=="tip"{print $2}')
log "REORG: B's tip became A/C's tip ($STATE) $(sub $(tt $TB $OFF_B) $(tt $T0 $OFF_B)) s after B's network was re-enabled (includes the manual 'addnode onetry' calls and the connection handshake)"
sleep 3
for n in A B C; do log "  $n: height=$(rx $n '. /root/qt.sh; height'|tail -1) tip=$(rx $n '. /root/qt.sh; tip'|tail -1|short) tx_to_B conf=$(rx $n ". /root/qt.sh; txconf $TXB"|tail -1) tx_to_C conf=$(rx $n ". /root/qt.sh; txconf $TXC"|tail -1) mempool=[$(mp $n)]"; done
log "  B chain tips (shows the abandoned branch): $(chaintips B)"
log "  A chain tips: $(chaintips A)"
log "  B log excerpt:"
rx B 'grep -E "REORGANIZE|Disconnect block|reorganiz|UpdateTip" /root/qtctest-data/qtctest/debug.log | tail -6 | cut -c1-170' | tee -a "$OUT"
