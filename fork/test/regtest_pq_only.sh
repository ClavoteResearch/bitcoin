#!/bin/bash
# Qcoin value rule on regtest: only witness v2 ML-DSA outputs may carry value. Checks the wallet refuses
# ordinary addresses and recipients, that change goes to an ML-DSA address, that a raw transaction paying a
# P2WPKH output is consensus-rejected by the mempool, that a block paying its coinbase to P2WPKH is rejected
# by the miner, that zero-value OP_RETURN outputs still pass, and that the wallet scheme defaults to mldsa44
# (ecdsa refused). Started WITHOUT -walletsigscheme to prove the default. Works with the default build.
# Usage: regtest_pq_only.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2q.XXXX")
RPCPORT=18795
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }
# a valid P2WPKH address nobody controls (generator point), since the wallet will not hand out ECDSA addresses
ECDSA_DESC="wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"

say "== -walletsigscheme=ecdsa is refused on an ML-DSA-only chain =="
D0=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2q.XXXX")
ERR=$("$BIN/bitcoind" -regtest -datadir="$D0" -rpcport=$RPCPORT -port=18796 -listen=0 -walletsigscheme=ecdsa 2>&1); RC=$?
check "$RC $(printf '%s' "$ERR" | grep -c 'not allowed on this chain')" "1 1" "bitcoind exits with an error naming the rule"

say "== default scheme without -walletsigscheme =="
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18796 -listen=0 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
check "$(grep -c 'wallet signature scheme = mldsa44' "$D/regtest/debug.log")" "1" "wallet scheme defaulted to mldsa44"
$CLI createwallet w >/dev/null; W="$CLI -rpcwallet=w"
M=$($W getnewmldsaaddress mine)
check "${M:0:6}" "bcrt1z" "getnewmldsaaddress works on a default-scheme wallet"
check "$($W getnewaddress 2>&1 | grep -c 'Use getnewmldsaaddress')" "1" "getnewaddress refuses and points at getnewmldsaaddress"
check "$($W getrawchangeaddress 2>&1 | grep -c 'cannot carry value')" "1" "getrawchangeaddress refuses"
E=$($CLI deriveaddresses "$($CLI getdescriptorinfo "$ECDSA_DESC" | jget descriptor)" | jget 0)
check "${E:0:6}" "bcrt1q" "a P2WPKH address can still be formed outside the wallet"

say "== mining: coinbase must be ML-DSA =="
check "$($CLI generatetoaddress 1 "$E" 2>&1 | grep -c 'bad-txns-output-not-mldsa')" "1" "block paying its coinbase to P2WPKH is rejected (TestBlockValidity)"
check "$($CLI getblockcount)" "0" "no block was added"
$CLI generatetoaddress 101 "$M" >/dev/null
check "$($CLI getblockcount) $($W getbalance)" "101 50.00000000" "101 blocks mined to the ML-DSA address, one coinbase mature"
check "$($CLI getblock "$($CLI getbestblockhash)" 2 | py 'import sys,json; b=json.load(sys.stdin)["tx"][0]; print(len(b["vout"]), b["vout"][0]["scriptPubKey"]["hex"][:4], b["vout"][1]["value"], b["vout"][1]["scriptPubKey"]["hex"][:4])')" "2 5220 0.0 6a24" "coinbase: value to OP_2 <32>, zero-value OP_RETURN witness commitment allowed"

say "== wallet refuses ordinary recipients; change is ML-DSA =="
check "$($W sendtoaddress "$E" 1 2>&1 | grep -c 'cannot carry value')" "1" "sendtoaddress to a P2WPKH address refused with a clear error"
check "$($W -named send outputs="{\"$E\":1}" 2>&1 | grep -c 'cannot carry value')" "1" "send refuses as well"
check "$($W -named walletcreatefundedpsbt inputs='[]' outputs="{\"$E\":1}" 2>&1 | grep -c 'cannot carry value')" "1" "walletcreatefundedpsbt refuses as well"
A2=$($W getnewmldsaaddress pay)
TX=$($W sendtoaddress "$A2" 7)
check "${#TX}" "64" "spend to an ML-DSA address accepted"
check "$($CLI getrawtransaction "$TX" true | py 'import sys,json; o=json.load(sys.stdin)["vout"]; print(len(o), all(v["scriptPubKey"]["hex"].startswith("5220") for v in o))')" "2 True" "payment and change are both OP_2 <32> outputs"
check "$($W getaddressesbylabel change | py 'import sys,json; print(len(json.load(sys.stdin)))')" "1" "change address recorded under label \"change\""
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX" | jget confirmations)" "1" "spend with ML-DSA change confirmed"
check "$($W -named send outputs="[{\"$A2\":1},{\"data\":\"aa\"}]" | py 'import sys,json; d=json.load(sys.stdin); print(d["complete"], len(d["txid"]))')" "True 64" "zero-value OP_RETURN data output next to an ML-DSA payment is accepted"

say "== consensus: a raw transaction paying P2WPKH is rejected by the mempool =="
U=$($W listunspent | py 'import sys,json; u=max((x for x in json.load(sys.stdin) if x["spendable"]), key=lambda x: x["amount"]); print(u["txid"], u["vout"], u["amount"])')
set -- $U; UTXID=$1; UVOUT=$2; UAMT=$3
RAW=$($CLI createrawtransaction "[{\"txid\":\"$UTXID\",\"vout\":$UVOUT}]" "{\"$E\":$(py 'import sys; print(round(float(sys.argv[1])-0.001, 8))' "$UAMT")}")
SIGNED=$($W signrawtransactionwithwallet "$RAW" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
check "$($CLI decoderawtransaction "$SIGNED" | py 'import sys,json; d=json.load(sys.stdin); print(len(d["vin"][0]["txinwitness"][0])//2, d["vout"][0]["scriptPubKey"]["type"])')" "3735 witness_v0_keyhash" "wallet signs the ML-DSA input; the output is P2WPKH (the rule is about outputs)"
RES=$($CLI testmempoolaccept "[\"$SIGNED\"]" | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))')
check "$RES" "False bad-txns-output-not-mldsa" "testmempoolaccept: consensus reject bad-txns-output-not-mldsa"
check "$($CLI sendrawtransaction "$SIGNED" 2>&1 | grep -c 'bad-txns-output-not-mldsa')" "1" "sendrawtransaction rejects it"
check "$($CLI generateblock "$M" "[\"$SIGNED\"]" 2>&1 | grep -c 'bad-txns-output-not-mldsa')" "1" "generateblock refuses to mine a block containing it"
# the same input paid to an ML-DSA address is fine
RAW2=$($CLI createrawtransaction "[{\"txid\":\"$UTXID\",\"vout\":$UVOUT}]" "{\"$A2\":$(py 'import sys; print(round(float(sys.argv[1])-0.001, 8))' "$UAMT")}")
TX2=$($CLI sendrawtransaction "$($W signrawtransactionwithwallet "$RAW2" | jget hex)")
check "${#TX2}" "64" "same input paid to an ML-DSA address is accepted"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX2" | jget confirmations)" "1" "...and confirms"

$CLI stop >/dev/null; sleep 1; rm -rf "$D0"
[ $fail -eq 0 ] && say "PQ-ONLY REGTEST OK" || say "PQ-ONLY REGTEST FAILED"
exit $fail
