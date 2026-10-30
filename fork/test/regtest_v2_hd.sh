#!/bin/bash
# Qcoin / Option B: HD-derived ML-DSA keys. Three v2 addresses from one wallet master, all reproducible via
# derivemldsaaddress, receive to all, spend from two, re-derive after restart and after encryption.
# Requires QCOIN_WITNESS_V2_EXPERIMENTAL=ON + wallet.   Usage: regtest_v2_hd.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2h.XXXX")
RPCPORT=19055
PASS="hd test passphrase"
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
start_node() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=19056 -listen=0 -walletsigscheme=mldsa44 $1 >/dev/null
  for i in $(seq 1 60); do "$BIN/bitcoin-cli" -regtest -datadir="$D" -rpcport=$RPCPORT getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
txid_of() { py 'import sys,json
try: print(json.load(sys.stdin).get("txid",""))
except Exception: print("")'; }
one_input() { py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$1"; }
derive() { $PQ derivemldsaaddress "$1" | py 'import sys,json; print(json.load(sys.stdin)["address"])'; }

start_node ""
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewaddress); $CLI generatetoaddress 101 "$M" >/dev/null

say "== three addresses from one master =="
A0=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
A1=$($PQ getnewmldsaaddress hd1); A2=$($PQ getnewmldsaaddress hd2)
say "A0 $A0"; say "A1 $A1"; say "A2 $A2"
check "$(printf '%s\n%s\n%s\n' "$A0" "$A1" "$A2" | sort -u | wc -l)" "3" "three distinct addresses"
HD=$($PQ getmldsahdinfo)
check "$(printf '%s' "$HD" | py 'import sys,json; d=json.load(sys.stdin); print(d["next_index"], sorted(k["index"] for k in d["keys"]))')" "3 [0, 1, 2]" "getmldsahdinfo: next_index 3, indices 0,1,2"
check "$(printf '%s' "$HD" | py 'import sys,json; d=json.load(sys.stdin); m={k["index"]:k["address"] for k in d["keys"]}; print(m[0]==sys.argv[1], m[1]==sys.argv[2], m[2]==sys.argv[3])' "$A0" "$A1" "$A2")" "True True True" "indices map to A0,A1,A2"
check "$(derive 0) $(derive 1) $(derive 2)" "$A0 $A1 $A2" "derivemldsaaddress 0,1,2 reproduce the stored addresses from the master"
check "$([ "$(derive 3)" != "$A0" ] && [ "$(derive 3)" != "$A1" ] && [ "$(derive 3)" != "$A2" ] && echo distinct)" "distinct" "index 3 derives a new, unused address"
check "$(derive 1)" "$A1" "derivation is stable across calls"
check "$($MINER getmldsahdinfo | py 'import sys,json; d=json.load(sys.stdin); print(d["next_index"], [k["index"] for k in d["keys"]])')" "1 [0]" "miner wallet has its own independent index space"
check "$([ "$($MINER derivemldsaaddress 0 | py 'import sys,json; print(json.load(sys.stdin)["address"])')" != "$A0" ] && echo different)" "different" "different wallets derive different keys at the same index"

say "== fund all three, spend from two =="
$MINER sendtoaddress "$A0" 2 >/dev/null; $MINER sendtoaddress "$A1" 3 >/dev/null; $MINER sendtoaddress "$A2" 4 >/dev/null
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ listunspent | py 'import sys,json; u=json.load(sys.stdin); print(len(u), all(x["solvable"] and x["spendable"] for x in u))')" "3 True" "three v2 coins, all solvable and spendable"
T0=$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$($PQ listunspent | one_input "$A0"),\"add_inputs\":false}" 2>&1 | txid_of)
T2=$($PQ -named send outputs="{\"$M\":3}" options="{\"inputs\":$($PQ listunspent | one_input "$A2"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#T0}${#T2}" "6464" "spends from A0 and A2 returned txids"
$CLI generatetoaddress 1 "$M" >/dev/null
[ "${#T0}" = "64" ] && check "$($PQ gettransaction "$T0" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A0 spend confirmed"
[ "${#T2}" = "64" ] && check "$($PQ gettransaction "$T2" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A2 spend confirmed"
check "$($PQ listunspent | py 'import sys,json; print(sorted(x["address"]==sys.argv[1] for x in json.load(sys.stdin) if x["amount"]==3)[0])' "$A1")" "True" "A1 coin still unspent"

say "== restart: indices reload, derivation still matches =="
$CLI stop >/dev/null; sleep 2
start_node "-wallet=pq -wallet=miner"
check "$($PQ getmldsahdinfo | py 'import sys,json; d=json.load(sys.stdin); print(d["next_index"], sorted(k["index"] for k in d["keys"]))')" "3 [0, 1, 2]" "HD indices reloaded from the database"
check "$(derive 2)" "$A2" "derivemldsaaddress 2 still matches after restart"
A3=$($PQ getnewmldsaaddress hd3)
check "$A3" "$(derive 3)" "getnewmldsaaddress continues at index 3 and matches the pre-derived address"

say "== encryption: derivation needs the unlocked root; pre-encryption keys stay spendable =="
$PQ encryptwallet "$PASS" >/dev/null
check "$($PQ derivemldsaaddress 1 2>&1 | grep -c -i locked)" "1" "derivemldsaaddress refused while locked"
$PQ walletpassphrase "$PASS" 300 >/dev/null
check "$([ "$(derive 0)" != "$A0" ] && echo rotated)" "rotated" "after encryptwallet the active root changed, so index 0 derives a new key (documented)"
T1=$($PQ -named send outputs="{\"$M\":2}" options="{\"inputs\":$($PQ listunspent | one_input "$A1"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#T1}" "64" "pre-encryption key A1 still spends (stored encrypted)"
[ "${#T1}" = "64" ] && { $CLI generatetoaddress 1 "$M" >/dev/null; check "$($PQ gettransaction "$T1" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A1 spend confirmed"; }
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 HD REGTEST OK" || say "V2 HD REGTEST FAILED"
exit $fail
