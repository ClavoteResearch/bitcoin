#!/bin/bash
# Qcoin / Option B end-to-end regtest: receive to a witness v2 ML-DSA-44 address and spend from it.
# Requires a build configured with -DQCOIN_WITNESS_V2_EXPERIMENTAL=ON and the wallet enabled.
# Usage: regtest_v2_spend.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2.XXXX")
RPCPORT=18755
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }

"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18756 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"

$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewaddress)
$CLI generatetoaddress 101 "$M" >/dev/null

say "== v2 address =="
PQADDR=$($PQ getaddressesbylabel mldsa | python3 -I -c 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
say "pq mldsa address: $PQADDR"
check "${PQADDR:0:5}" "bcrt1" "address is bech32m regtest"
check "${PQADDR:5:1}" "z" "address is witness version 2 (bcrt1z...)"
check "$($CLI validateaddress "$PQADDR" | python3 -I -c 'import sys,json; d=json.load(sys.stdin); print(d["isvalid"], d.get("witness_version"))')" "True 2" "validateaddress: witness_version 2"
check "$($PQ getaddressinfo "$PQADDR" | python3 -I -c 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"], d["desc"][:4])')" "True True wpq(" "pq wallet: ismine, solvable, wpq() descriptor"

say "== fund the v2 output =="
FUND=$($MINER sendtoaddress "$PQADDR" 10)
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ getbalance)" "10.00000000" "pq balance after funding"
check "$($PQ listunspent | python3 -I -c 'import sys,json; u=json.load(sys.stdin); print(len(u), u[0]["address"]==sys.argv[1], u[0]["spendable"], u[0]["solvable"])' "$PQADDR")" "1 True True True" "pq listunspent: one spendable, solvable v2 coin"

say "== spend from the v2 output (ML-DSA-44 attestation) =="
SPEND=$($PQ sendtoaddress "$M" 5 2>&1) || true
say "sendtoaddress -> $SPEND"
check "${#SPEND}" "64" "spend txid returned"
if [ "${#SPEND}" = "64" ]; then
  check "$($CLI getrawmempool | grep -c "$SPEND")" "1" "spend is in the mempool (policy accepted)"
  RAW=$($CLI getrawtransaction "$SPEND" true)
  WIT=$(printf '%s' "$RAW" | python3 -I -c 'import sys,json; d=json.load(sys.stdin); w=d["vin"][0]["txinwitness"]; print(len(w), len(w[0])//2, w[0][:6])')
  check "$WIT" "1 3735 510101" "witness: 1 element, 3735-byte attestation, prefix 0x51 n=1 param_id=0x01"
  say "vsize=$(printf '%s' "$RAW" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["vsize"])') weight=$(printf '%s' "$RAW" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["weight"])')"
  $CLI generatetoaddress 1 "$M" >/dev/null
  check "$($PQ gettransaction "$SPEND" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "spend confirmed in a block (consensus accepted)"
  check "$($CLI getblockcount)" "103" "chain height 103"
  say "pq balance now: $($PQ getbalance) (10 - 5 - fee, change returned to a P2WPKH address)"
fi

say "== ECDSA still works in the same wallet (P2WPKH change / miner spends) =="
check "${#M}" "44" "miner address is bech32 P2WPKH"
T=$($MINER sendtoaddress "$($MINER getnewaddress)" 1 2>&1) || true
check "${#T}" "64" "miner ECDSA spend succeeds"

say "== relevant log lines =="
grep -E "Qcoin: (imported|built|generated)" "$D/regtest/debug.log" | sed 's/^[^ ]* //' | head -6
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 REGTEST OK" || say "V2 REGTEST FAILED"
exit $fail
