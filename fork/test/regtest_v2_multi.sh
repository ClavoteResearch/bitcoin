#!/bin/bash
# Qcoin / Option B: generate two extra witness v2 addresses with getnewmldsaaddress, receive to both,
# spend from one, restart the node, spend from the other. Requires QCOIN_WITNESS_V2_EXPERIMENTAL=ON + wallet.
# Usage: regtest_v2_multi.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2m.XXXX")
RPCPORT=18855
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
start_node() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18856 -listen=0 -walletsigscheme=mldsa44 $1 >/dev/null
  for i in $(seq 1 60); do "$BIN/bitcoin-cli" -regtest -datadir="$D" -rpcport=$RPCPORT getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }

start_node ""
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewaddress); $CLI generatetoaddress 101 "$M" >/dev/null

say "== addresses =="
A0=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
A1=$($PQ getnewmldsaaddress "pq1"); A2=$($PQ getnewmldsaaddress "pq2")
say "A0 (auto)  $A0"; say "A1 (rpc)   $A1"; say "A2 (rpc)   $A2"
check "$(printf '%s\n%s\n%s\n' "$A0" "$A1" "$A2" | sort -u | wc -l)" "3" "three distinct v2 addresses"
check "${A1:0:6}${A2:0:6}" "bcrt1zbcrt1z" "both new addresses are bcrt1z"
for a in "$A1" "$A2"; do
  check "$($PQ getaddressinfo "$a" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"], d["desc"][:4], d["labels"][0])')" "True True wpq( $([ "$a" = "$A1" ] && echo pq1 || echo pq2)" "getaddressinfo ${a:0:12}...: ismine solvable wpq label"
done
check "$($PQ listdescriptors | py 'import sys,json; print(sum(1 for d in json.load(sys.stdin)["descriptors"] if d["desc"].startswith("wpq(")))')" "3" "three wpq() descriptors in wallet"
# The dev key store is process-wide, so pq's file also holds the miner wallet's key: 4 keys total
# (header 13 bytes; each ML-DSA-44 entry = 1+20+4+1312+4+2560+1 = 3902 bytes). Known limitation, see doc/WALLET-PQC.md.
check "$(stat -c %s "$D/regtest/wallets/pq/mldsa_keys.dat")" "$((13 + 4*3902))" "key store file holds 4 ML-DSA-44 keys (3 pq + 1 miner; shared store)"

say "== fund A1 and A2 =="
$MINER sendtoaddress "$A1" 3 >/dev/null; $MINER sendtoaddress "$A2" 4 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ getbalance)" "7.00000000" "pq balance 7"
check "$($PQ listunspent | py 'import sys,json; u=json.load(sys.stdin); print(len(u), all(x["solvable"] and x["spendable"] for x in u))')" "2 True" "two v2 coins, all solvable and spendable"

say "== spend from A1 only =="
IN1=$($PQ listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$A1")
R=$($PQ -named send outputs="{\"$M\":2}" options="{\"inputs\":$IN1,\"add_inputs\":false}" 2>&1)
TX1=$(printf '%s' "$R" | py 'import sys,json
try: d=json.load(sys.stdin); print(d.get("txid",""))
except Exception: print("")')
check "${#TX1}" "64" "send from A1 returned a txid"
if [ "${#TX1}" = "64" ]; then
  check "$($CLI getrawtransaction "$TX1" true | py 'import sys,json; d=json.load(sys.stdin); w=d["vin"][0]["txinwitness"]; print(len(d["vin"]), len(w[0])//2, w[0][:6])')" "1 3735 510101" "one input, 3735-byte attestation"
  $CLI generatetoaddress 1 "$M" >/dev/null
  check "$($PQ gettransaction "$TX1" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A1 spend confirmed"
  check "$($PQ listunspent | py 'import sys,json; print(sorted(x["address"]==sys.argv[1] for x in json.load(sys.stdin) if x["amount"]==4)[0])' "$A2")" "True" "A2 coin still unspent"
else
  say "  send error: $(printf '%s' "$R" | head -c 200)"
fi

say "== restart node, reload wallet, spend from A2 =="
$CLI stop >/dev/null; sleep 2
start_node "-wallet=pq -wallet=miner"
check "$(grep -c 'Qcoin: loaded ML-DSA key store' "$D/regtest/debug.log")" "2" "key store reloaded for both wallets after restart"
check "$($PQ getaddressinfo "$A2" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "True True" "A2 still ismine and solvable after restart"
IN2=$($PQ listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$A2")
TX2=$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$IN2,\"add_inputs\":false}" 2>&1 | py 'import sys,json
try: print(json.load(sys.stdin).get("txid",""))
except Exception: print("")')
check "${#TX2}" "64" "send from A2 after restart returned a txid"
if [ "${#TX2}" = "64" ]; then $CLI generatetoaddress 1 "$M" >/dev/null; check "$($PQ gettransaction "$TX2" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A2 spend confirmed"; fi

say "== negative: RPC refused when scheme is ecdsa =="
$CLI stop >/dev/null; sleep 2
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -rpcport=$RPCPORT -port=18856 -listen=0 -wallet=pq >/dev/null
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
check "$($PQ getnewmldsaaddress 2>&1 | grep -c 'scheme is ecdsa')" "1" "getnewmldsaaddress errors under ecdsa scheme"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 MULTI REGTEST OK" || say "V2 MULTI REGTEST FAILED"
exit $fail
