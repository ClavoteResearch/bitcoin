#!/bin/bash
# Qcoin / Option B end-to-end test of a witness v2 *script-path* spend: an output whose
# commitment covers a single leaf  <pk_hash> OP_0 OP_CHECKMLDSAVERIFY OP_1  is funded by the
# wallet and spent with a witness built by qcoin-v2-scriptpath (the wallet signs key paths
# only). A key-path spend is made alongside so both paths confirm in the same block.
# Usage: regtest_v2_scriptpath.sh [path/to/build/bin]
#        CHAIN=qtctest regtest_v2_scriptpath.sh [bin]   runs the same on qtctest (about 6 minutes:
#        101 blocks at ~3 s each; loopback only, ports 29853/29854).
# Needs: cmake --build <dir> --target qcoin-v2-scriptpath
set -u
BIN="${1:-build/bin}"
CHAIN="${CHAIN:-regtest}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2sp.XXXX")
if [ "$CHAIN" = qtctest ]; then RPCPORT=29853; P2P=29854; HRP=tq1z; else RPCPORT=18797; P2P=18798; HRP=bcrt1z; fi
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
TOOL="$BIN/qcoin-v2-scriptpath"
[ -x "$TOOL" ] || { say "[FAIL] $TOOL missing (cmake --build <dir> --target qcoin-v2-scriptpath)"; exit 1; }

"$BIN/bitcoind" -chain=$CHAIN -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=$P2P -listen=0 -txindex=1 >/dev/null
CLI="$BIN/bitcoin-cli -chain=$CHAIN -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet miner >/dev/null
W="$CLI -rpcwallet=miner"
M=$($W getnewmldsaaddress mine)
mine() { # mine $1 blocks to the miner's ML-DSA address
  if [ "$CHAIN" = qtctest ]; then for _ in $(seq 1 "$1"); do $CLI generatetoaddress 1 "$M" 2000000000 >/dev/null; done
  else $CLI generatetoaddress "$1" "$M" >/dev/null; fi
}
say "== $CHAIN: mining 101 blocks to $M =="
mine 101
check "$($CLI getblockcount)" "101" "height 101"

say "== script-path output: OP_2 <Q>, Q = commit(internal key, leaf <pk_hash> OP_0 OP_CHECKMLDSAVERIFY OP_1) =="
SEED_I=$(printf '11%.0s' $(seq 1 32)); SEED_L=$(printf '22%.0s' $(seq 1 32))
eval "$($TOOL address "$SEED_I" "$SEED_L" | sed 's/^/SP_/')"
check "${#SP_spk}" "68" "scriptPubKey is 34 bytes"
check "${SP_spk:0:4}" "5220" "scriptPubKey is OP_2 <32 bytes>"
check "${#SP_control}" "68" "control block is 34 bytes (leaf_version, param_id, internal pk_hash; no Merkle nodes)"
check "${SP_control:0:4}" "c001" "control block starts with leaf version 0xc0, param_id 0x01"
check "$SP_leaf" "20${SP_leaf_pk_hash}00b351" "leaf script is <pk_hash> OP_0 OP_NOP4(=OP_CHECKMLDSAVERIFY) OP_1"
ADDR=$($CLI decodescript "$SP_spk" | py 'import sys,json; print(json.load(sys.stdin)["address"])')
say "script-path address: $ADDR"
check "${ADDR:0:${#HRP}}" "$HRP" "address is bech32m witness v2"

say "== fund the script-path output from the wallet =="
FUND=$($W sendtoaddress "$ADDR" 10)
check "${#FUND}" "64" "funding txid"
mine 1
VOUT=$($CLI getrawtransaction "$FUND" true | py 'import sys,json; d=json.load(sys.stdin); print([i for i,v in enumerate(d["vout"]) if v["scriptPubKey"]["hex"]==sys.argv[1]][0])' "$SP_spk")
check "$($CLI gettxout "$FUND" "$VOUT" | py 'import sys,json; d=json.load(sys.stdin); print(d["confirmations"], "%.8f" % d["value"])')" "1 10.00000000" "script-path coin confirmed, 10 coins"

say "== key path still works: the wallet spends one of its own v2 coins =="
KP=$($W sendtoaddress "$M" 1 2>&1) || true
check "${#KP}" "64" "key-path spend txid"
check "$($CLI getrawtransaction "$KP" true | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w), len(w[0])//2)')" "1 3735" "key-path witness is a single 3735-byte attestation"

say "== script-path spend: witness <leaf> <control> <attestation>, signed by the leaf key =="
DEST=$($W getnewmldsaaddress dest)
DEST_SPK=$($CLI validateaddress "$DEST" | py 'import sys,json; print(json.load(sys.stdin)["scriptPubKey"])')
BAD=$($TOOL spend "$SEED_I" "$SEED_L" "$FUND" "$VOUT" 1000000000 "$DEST_SPK" 999900000 bad 2>/dev/null)
R=$($CLI sendrawtransaction "$BAD" 2>&1) || true
check "$(printf '%s' "$R" | grep -c 'Invalid ML-DSA signature')" "1" "corrupted leaf signature is rejected by the mempool"
RAW=$($TOOL spend "$SEED_I" "$SEED_L" "$FUND" "$VOUT" 1000000000 "$DEST_SPK" 999900000 2>"$D/tool.err")
say "tool: $(cat "$D/tool.err")"
check "$($CLI testmempoolaccept "[\"$RAW\"]" | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason","-"))')" "True -" "testmempoolaccept allows the script-path spend"
SP=$($CLI sendrawtransaction "$RAW" 2>&1) || true
check "${#SP}" "64" "script-path spend accepted into the mempool"
check "$($CLI getrawtransaction "$SP" true | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w), len(w[0])//2, len(w[1])//2, len(w[2])//2, w[2][:6])')" "3 36 34 3735 510101" "witness: leaf 36 B, control 34 B, attestation 3735 B (0x51, n=1, param 0x01)"
say "script-path spend vsize=$($CLI getrawtransaction "$SP" true | py 'import sys,json; print(json.load(sys.stdin)["vsize"])')"
mine 1
check "$($CLI getrawtransaction "$SP" true | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "script-path spend confirmed in a block"
check "$($CLI getrawtransaction "$KP" true | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "key-path spend confirmed in the same block"
check "$($W getreceivedbyaddress "$DEST" 1)" "9.99900000" "wallet received 9.999 from the script-path spend"
check "$($CLI gettxout "$FUND" "$VOUT" | wc -c)" "0" "the script-path coin is spent"
check "$($CLI getblockcount)" "103" "height 103"

$CLI stop >/dev/null 2>&1; sleep 1
rm -rf "$D"
if [ $fail = 0 ]; then say "ALL OK"; else say "FAILED"; fi
exit $fail
