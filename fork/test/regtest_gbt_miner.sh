#!/bin/bash
# Qcoin: mining through getblocktemplate/submitblock only. Guards two things:
#  1. getblocktemplate itself works on a chain with the value rule (its placeholder coinbase used to be OP_TRUE, which
#     failed TestBlockValidity with bad-txns-output-not-mldsa, so no external miner could work);
#  2. a standalone miner (fork/tools/qtc-gbt-miner.py) can mine valid blocks whose coinbase pays a witness v2 address.
# Usage: regtest_gbt_miner.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-gbt.XXXX")
RPCPORT=18799
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
HERE=$(cd "$(dirname "$0")" && pwd)
MINER="$HERE/../tools/qtc-gbt-miner.py"

"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18800 -listen=0 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet w >/dev/null
ADDR=$($CLI -rpcwallet=w getnewmldsaaddress miner)
check "${ADDR:0:6}" "bcrt1z" "mining address is a witness v2 address"

say "== getblocktemplate on a value-rule chain =="
T=$($CLI getblocktemplate '{"rules":["segwit"]}' 2>&1)
check "$(printf '%s' "$T" | py 'import sys,json; d=json.load(sys.stdin); print(d["height"], "default_witness_commitment" in d, d["coinbasevalue"])' 2>/dev/null)" "1 True 5000000000" "getblocktemplate answers (height, witness commitment, 50-coin subsidy)"

say "== standalone template miner =="
OUT=$(python3 "$MINER" --address "$ADDR" --chain regtest --datadir "$D" --rpcurl "http://127.0.0.1:$RPCPORT" --procs 2 --blocks 3 2>&1)
printf '%s\n' "$OUT" | sed 's/^/  /'
check "$(printf '%s' "$OUT" | grep -c 'submit=OK')" "3" "three blocks submitted and accepted"
check "$($CLI getblockcount)" "3" "chain height 3"
check "$($CLI getblock "$($CLI getblockhash 3)" 2 | py 'import sys,json; d=json.load(sys.stdin); o=d["tx"][0]["vout"][0]; print(o["scriptPubKey"]["hex"][:4], o["value"])')" "5220 50.0" "block 3 coinbase pays an OP_2 <32 bytes> output (50 coins)"
check "$($CLI -rpcwallet=w getbalances | py 'import sys,json; d=json.load(sys.stdin)["mine"]; print(d["immature"])')" "150.0" "wallet sees the three coinbases as immature"

$CLI stop >/dev/null 2>&1; sleep 1
rm -rf "$D"
if [ $fail = 0 ]; then say "ALL OK"; else say "FAILED"; fi
exit $fail
