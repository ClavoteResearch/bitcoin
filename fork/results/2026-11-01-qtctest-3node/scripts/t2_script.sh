#!/bin/bash
# Test 2: script-path spend across the live 3-node network. Fund a 1-of-1 OP_CHECKMLDSAVERIFY leaf output from
# A's wallet, confirm it, then spend it through the leaf; B and C must relay and confirm it with their own consensus code.
cd ~/work; . ./lib.sh
OUT=$RES/t2_scriptpath.txt; : > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
tt() { awk -v e="$1" -v o="$2" 'BEGIN{printf "%.6f", e-o}'; }
getp() { local f; for i in $(seq 1 40); do f=$(fetch "$1" "$2"); echo "$f" | grep -q '^conf' && break; sleep 2; done; awk -v k="$3" '$1==k {print $NF}' <<<"$f" | head -1; }

log "== t2: script-path spend on the network =="
measure_clocks | tee -a "$OUT"; . "$RES/offsets.env"
SI=$(python -c 'import secrets;print(secrets.token_hex(32))'); SL=$(python -c 'import secrets;print(secrets.token_hex(32))')
ADDR_A=$(rx A '. /root/qt.sh; $CLI -rpcwallet=miner getnewmldsaaddress netmine' | tail -1)
DEST_SPK=$(rx A ". /root/qt.sh; \$CLI validateaddress $ADDR_A" | python -c 'import sys,json; print(json.load(sys.stdin)["scriptPubKey"])')
O=$(rx A "/root/sp.sh addr $SI $SL"); log "$O"
SPADDR=$(kv "$O" address)
log "script-path address: $SPADDR"

# ---- fund the script-path output from A's wallet (10 coins), mined by A
P=$(act A prep miner "$SPADDR" 10); TXF=$(kv "$P" TXID); log "funding txid=$TXF"
for n in B C; do bg $n "/root/poll.sh /root/out/t2f_$n.txt tx $TXF" >/dev/null; done
sleep 2
BC=$(act A bcast "$TXF"); log "funding broadcast: $BC"; sleep 4
MN=$(act A mine "$ADDR_A" 1); log "funding block: $MN"
for n in B C; do getp $n /root/out/t2f_$n.txt conf >/dev/null; done
log "funding confirmed on: A=$(rx A ". /root/qt.sh; txconf $TXF"|tail -1) B=$(rx B ". /root/qt.sh; txconf $TXF"|tail -1) C=$(rx C ". /root/qt.sh; txconf $TXF"|tail -1) confirmations"

# ---- a corrupted leaf signature must be rejected by the OTHER nodes too
O=$(rx A "/root/sp.sh spend $SI $SL $TXF $DEST_SPK bad"); TXB=$(kv "$O" TXID); log "bad-signature spend built: $TXB ($(echo "$O" | grep '^tool'))"
HEXB=$(fetch A /root/out/tx_$TXB.hex)
for n in B C; do R=$(echo "$HEXB" | rx $n '/root/act.sh bcasthex'); log "bad spend submitted to $n -> $(echo "$R" | sed 's/bcast_start=[0-9.]* bcast_end=[0-9.]* //')"; done

# ---- the real script-path spend
O=$(rx A "/root/sp.sh spend $SI $SL $TXF $DEST_SPK"); TXS=$(kv "$O" TXID); log "script-path spend built: $TXS ($(echo "$O" | grep -E '^(tool|vout)' | tr '\n' ' '))"
for n in B C; do bg $n "/root/poll.sh /root/out/t2s_$n.txt tx $TXS" >/dev/null; done
sleep 2
BC=$(act A bcast "$TXS"); log "spend broadcast on A: $BC"
sleep 5
MN=$(act A mine "$ADDR_A" 1); log "spend block mined on A: $MN"
BS=$(kv "$BC" bcast_start); BE=$(kv "$BC" bcast_end); ME=$(kv "$MN" mine_end)
SB=$(getp B /root/out/t2s_B.txt seen); CB=$(getp B /root/out/t2s_B.txt conf)
SC=$(getp C /root/out/t2s_C.txt seen); CC=$(getp C /root/out/t2s_C.txt conf)
b0=$(tt "$BS" "$OFF_A")
log "script-path timings (NTP-corrected, seconds):"
log "  A: broadcast call (includes full script validation) took $(sub $BE $BS)"
log "  relay A->B: $(sub $(tt $SB $OFF_B) $b0)    relay A->C: $(sub $(tt $SC $OFF_C) $b0)"
log "  block A->B: $(sub $(tt $CB $OFF_B) $(tt $ME $OFF_A))    block A->C: $(sub $(tt $CC $OFF_C) $(tt $ME $OFF_A))"
log "  broadcast -> 1 confirmation at B: $(sub $(tt $CB $OFF_B) $b0)   at C: $(sub $(tt $CC $OFF_C) $b0)"
log "  confirmations of the script-path spend: A=$(rx A ". /root/qt.sh; txconf $TXS"|tail -1) B=$(rx B ". /root/qt.sh; txconf $TXS"|tail -1) C=$(rx C ". /root/qt.sh; txconf $TXS"|tail -1)"
rx B ". /root/qt.sh; \$CLI getrawtransaction $TXS true" | python -c '
import sys,json
d=json.load(sys.stdin); w=d["vin"][0]["txinwitness"]
print("  on B: vsize=%d weight=%d witness elements=%d sizes(bytes)=%s first-byte-of-last=%s" % (d["vsize"], d["weight"], len(w), [len(x)//2 for x in w], w[-1][:6]))
' | tee -a "$OUT"
