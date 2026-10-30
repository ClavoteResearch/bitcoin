#!/bin/bash
# Qcoin / Option B: multiple witness v2 addresses via getnewmldsaaddress, two wallets in one process with
# wallet-scoped ML-DSA keys (wallet database), spends from each, restart, spend again.
# Requires QCOIN_WITNESS_V2_EXPERIMENTAL=ON + wallet.   Usage: regtest_v2_multi.sh [path/to/build/bin]
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
txid_of() { py 'import sys,json
try: print(json.load(sys.stdin).get("txid",""))
except Exception: print("")'; }
one_input() { py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$1"; }

start_node ""
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewaddress); $CLI generatetoaddress 101 "$M" >/dev/null

say "== addresses =="
A0=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
A1=$($PQ getnewmldsaaddress "pq1"); A2=$($PQ getnewmldsaaddress "pq2")
MA=$($MINER getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
say "pq A0 (auto) $A0"; say "pq A1 (rpc)  $A1"; say "pq A2 (rpc)  $A2"; say "miner MA     $MA"
check "$(printf '%s\n%s\n%s\n%s\n' "$A0" "$A1" "$A2" "$MA" | sort -u | wc -l)" "4" "four distinct v2 addresses across two wallets"
check "${A1:0:6}${A2:0:6}" "bcrt1zbcrt1z" "both new pq addresses are bcrt1z"
for a in "$A1" "$A2"; do
  check "$($PQ getaddressinfo "$a" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"], d["desc"][:4], d["labels"][0])')" "True True wpq( $([ "$a" = "$A1" ] && echo pq1 || echo pq2)" "pq getaddressinfo ${a:0:12}...: ismine solvable wpq label"
done
check "$($PQ listdescriptors | py 'import sys,json; print(sum(1 for d in json.load(sys.stdin)["descriptors"] if d["desc"].startswith("wpq(")))')" "3" "pq has three wpq() descriptors"
check "$($MINER listdescriptors | py 'import sys,json; print(sum(1 for d in json.load(sys.stdin)["descriptors"] if d["desc"].startswith("wpq(")))')" "1" "miner has one wpq() descriptor"

say "== wallet-scoped keys =="
check "$(find "$D/regtest/wallets" -name mldsa_keys.dat | wc -l)" "0" "no external mldsa_keys.dat files (keys live in wallet.dat)"
check "$($MINER getaddressinfo "$A1" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "False False" "miner does not own or solve pq's v2 address"
check "$($PQ getaddressinfo "$MA" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "False False" "pq does not own or solve miner's v2 address"

say "== fund pq A1, pq A2 and miner MA =="
$MINER sendtoaddress "$A1" 3 >/dev/null; $MINER sendtoaddress "$A2" 4 >/dev/null; $MINER sendtoaddress "$MA" 2 >/dev/null
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ getbalance)" "7.00000000" "pq balance 7"
check "$($PQ listunspent | py 'import sys,json; u=json.load(sys.stdin); print(len(u), all(x["solvable"] and x["spendable"] for x in u))')" "2 True" "pq: two v2 coins, all solvable and spendable"
check "$($MINER listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]]; print(len(u), u[0]["solvable"] if u else "-")' "$MA")" "1 True" "miner: its own v2 coin is solvable"

say "== pq spends from A1 only; miner spends its own v2 coin =="
TX1=$($PQ -named send outputs="{\"$M\":2}" options="{\"inputs\":$($PQ listunspent | one_input "$A1"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#TX1}" "64" "pq send from A1 returned a txid"
TXM=$($MINER -named send outputs="{\"$M\":1}" options="{\"inputs\":$($MINER listunspent | one_input "$MA"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#TXM}" "64" "miner send from MA returned a txid"
if [ "${#TX1}" = "64" ]; then
  check "$($CLI getrawtransaction "$TX1" true | py 'import sys,json; d=json.load(sys.stdin); w=d["vin"][0]["txinwitness"]; print(len(d["vin"]), len(w[0])//2, w[0][:6])')" "1 3735 510101" "pq spend: one input, 3735-byte attestation"
fi
$CLI generatetoaddress 1 "$M" >/dev/null
[ "${#TX1}" = "64" ] && check "$($PQ gettransaction "$TX1" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "pq A1 spend confirmed"
[ "${#TXM}" = "64" ] && check "$($MINER gettransaction "$TXM" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "miner MA spend confirmed"
check "$($PQ listunspent | py 'import sys,json; print(sorted(x["address"]==sys.argv[1] for x in json.load(sys.stdin) if x["amount"]==4)[0])' "$A2")" "True" "pq A2 coin still unspent"

say "== restart node, reload wallets from the database, spend from A2 =="
$CLI stop >/dev/null; sleep 2
start_node "-wallet=pq -wallet=miner"
check "$(grep -c 'Qcoin: loaded 1 ML-DSA key(s) for descriptor' "$D/regtest/debug.log")" "4" "4 ML-DSA key records loaded from the two wallet databases (3 pq + 1 miner)"
check "$($PQ getaddressinfo "$A2" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "True True" "A2 still ismine and solvable after restart"
TX2=$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$($PQ listunspent | one_input "$A2"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#TX2}" "64" "pq send from A2 after restart returned a txid"
if [ "${#TX2}" = "64" ]; then $CLI generatetoaddress 1 "$M" >/dev/null; check "$($PQ gettransaction "$TX2" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A2 spend confirmed"; fi

say "== negative: RPC refused when scheme is ecdsa =="
$CLI stop >/dev/null; sleep 2
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -rpcport=$RPCPORT -port=18856 -listen=0 -wallet=pq >/dev/null
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
check "$($PQ getnewmldsaaddress 2>&1 | grep -c 'scheme is ecdsa')" "1" "getnewmldsaaddress errors under ecdsa scheme"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 MULTI REGTEST OK" || say "V2 MULTI REGTEST FAILED"
exit $fail
