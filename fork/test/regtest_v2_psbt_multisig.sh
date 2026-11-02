#!/bin/bash
# Qcoin: PSBT aggregation for a 2-of-2 ML-DSA witness v2 script-path spend (regtest). Two wallets, w1 and w2, each hold one
# key named in the leaf  <h1> OP_0 OP_CHECKMLDSAVERIFY <h2> OP_1 OP_CHECKMLDSAVERIFY OP_1 ; the coordinator is the node with no
# wallet (createpsbt, utxoupdatepsbt, addpsbtmldsascriptpath, combinepsbt, finalizepsbt).
#  A. sequential: w1 signs the PSBT, w2 adds its attestation and finalizes; the spend confirms.
#  B. parallel: w1 and w2 sign copies, combinepsbt merges the entries, finalizepsbt assembles; the spend confirms.
#  C. refusals: one entry is not enough, a corrupted entry is not finalized, a script that does not commit to the output is
#     rejected, a wallet that is not named in the leaf adds nothing.
# Works with the default build. Usage: regtest_v2_psbt_multisig.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-psbtms.XXXX")
RPCPORT=19355
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=19356 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
trap '$CLI stop >/dev/null 2>&1; sleep 2; rm -rf "$D"' EXIT
MINER="$CLI -rpcwallet=miner"; W1="$CLI -rpcwallet=w1"; W2="$CLI -rpcwallet=w2"
for w in miner w1 w2; do $CLI createwallet $w >/dev/null; done
M=$($MINER getnewmldsaaddress mine); $CLI generatetoaddress 101 "$M" >/dev/null
# SHA-256 of the public key behind a wallet address (the wpq(HEXPK) descriptor)
pkhash() { py 'import sys,json,hashlib,re; d=json.load(sys.stdin)["desc"]; print(hashlib.sha256(bytes.fromhex(re.match(r"wpq\((.*)\)#", d).group(1))).hexdigest())'; }
K1=$($W1 getnewmldsaaddress k1); H1=$($W1 getaddressinfo "$K1" | pkhash)
K2=$($W2 getnewmldsaaddress k2); H2=$($W2 getaddressinfo "$K2" | pkhash)
check "${#H1} ${#H2}" "64 64" "both wallets expose the hash of an ML-DSA public key"
eval "$(python3 -I "$HERE/v2_scriptpath_addr.py" "$H1" "$H2" | sed 's/^/SP_/')"
check "${#SP_leaf}" "142" "2-of-2 leaf script is 71 bytes"
ADDR=$($CLI decodescript "$SP_spk" | py 'import sys,json; print(json.load(sys.stdin)["address"])')
say "2-of-2 script-path address: $ADDR"
DEST=$($MINER getnewmldsaaddress dest)

fund() { # prints "txid vout"
    local t v
    t=$($MINER sendtoaddress "$ADDR" 10); $CLI generatetoaddress 1 "$M" >/dev/null
    v=$($CLI getrawtransaction "$t" true $($CLI getbestblockhash) | py 'import sys,json; d=json.load(sys.stdin); print([i for i,o in enumerate(d["vout"]) if o["scriptPubKey"]["hex"]==sys.argv[1]][0])' "$SP_spk")
    echo "$t $v"
}
new_psbt() { # txid vout -> PSBT with utxo, leaf and control block
    local p
    p=$($CLI createpsbt "[{\"txid\":\"$1\",\"vout\":$2}]" "[{\"$DEST\":9.999}]")
    p=$($CLI utxoupdatepsbt "$p")
    $CLI addpsbtmldsascriptpath "$p" 0 "$SP_leaf" "$SP_control"
}
# number of ML-DSA attestation entries (qcoin proprietary subtype 3) in input 0, and whether it is finalized
entries() { py 'import sys,json; i=json.load(sys.stdin)["inputs"][0]; print(sum(1 for p in i.get("proprietary", []) if p["subtype"] == 3), "final" if "final_scriptwitness" in i else "open")'; }

say "== A. sequential: w1 signs, w2 adds its attestation and finalizes =="
read -r T1 V1 <<<"$(fund)"
check "$($CLI gettxout "$T1" "$V1" | py 'import sys,json; d=json.load(sys.stdin); print(d["confirmations"], "%.8f" % d["value"])')" "1 10.00000000" "script-path coin confirmed (10 coins)"
P0=$(new_psbt "$T1" "$V1")
check "${P0:0:6}" "cHNidP" "coordinator built a PSBT with the leaf script and control block"
check "$($CLI decodepsbt "$P0" | entries)" "0 open" "no attestation entry yet"
R=$($W1 walletprocesspsbt "$P0")
check "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "False" "w1 alone cannot complete the spend"
P1=$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')
check "$($CLI decodepsbt "$P1" | entries)" "1 open" "w1 added one attestation entry"
R=$($W2 walletprocesspsbt "$P1")
check "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "True" "w2 adds the second entry and the input is finalized"
P2=$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')
check "$($CLI decodepsbt "$P2" | entries)" "0 final" "script-path fields are replaced by the final witness"
HEX=$($CLI finalizepsbt "$P2" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
TX=$($CLI sendrawtransaction "$HEX"); check "${#TX}" "64" "the 2-of-2 spend is accepted by the mempool"
check "$($CLI getrawtransaction "$TX" true | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w), len(w[0])//2, len(w[1])//2, len(w[2])//2, w[2][:6])')" "3 71 34 7468 510201" "witness: leaf 71 B, control 34 B, attestation 7468 B (two entries)"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getrawtransaction "$TX" true $($CLI getbestblockhash) | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "the spend confirmed"
check "$($CLI gettxout "$T1" "$V1" | wc -c)" "0" "the script-path coin is spent"

say "== B. parallel: w1 and w2 sign separate copies, combinepsbt merges them =="
read -r T2 V2 <<<"$(fund)"
P0=$(new_psbt "$T2" "$V2")
PA=$($W1 walletprocesspsbt "$P0" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')
PB=$($W2 walletprocesspsbt "$P0" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')
check "$($CLI decodepsbt "$PA" | entries) / $($CLI decodepsbt "$PB" | entries)" "1 open / 1 open" "each party holds a PSBT with its own entry"
check "$($CLI finalizepsbt "$PA" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "False" "one entry is not enough to finalize"
PC=$($CLI combinepsbt "[\"$PA\",\"$PB\"]")
check "$($CLI decodepsbt "$PC" | entries)" "2 open" "combinepsbt merges both entries"
check "$($CLI analyzepsbt "$PC" | py 'import sys,json; print(json.load(sys.stdin)["inputs"][0]["next"])')" "finalizer" "analyzepsbt: the next role is the finalizer"

say "== C. refusals =="
# a corrupted entry: flip one byte of w2's signature in PB; the combined PSBT must not finalize
BAD=$(py '
import sys, json, base64, subprocess
cli = sys.argv[1].split()
pb = sys.argv[2]
d = json.loads(subprocess.check_output(cli + ["decodepsbt", pb]).decode())
val = bytes.fromhex([p for p in d["inputs"][0]["proprietary"] if p["subtype"] == 3][0]["value"])
raw = base64.b64decode(pb)
assert raw.count(val) == 1
bad = bytearray(val); bad[1400] ^= 1  # inside the ML-DSA signature
print(base64.b64encode(raw.replace(val, bytes(bad))).decode())
' "$CLI" "$PB")
BADC=$($CLI combinepsbt "[\"$PA\",\"$BAD\"]")
check "$($CLI finalizepsbt "$BADC" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "False" "a corrupted entry from another party is not finalized"
# the good PSBT still finalizes and confirms
HEX=$($CLI finalizepsbt "$PC" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
TX=$($CLI sendrawtransaction "$HEX"); $CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getrawtransaction "$TX" true $($CLI getbestblockhash) | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "the combined spend confirmed"
# a script that does not commit to the output
eval "$(python3 -I "$HERE/v2_scriptpath_addr.py" "$H1" | sed 's/^/ONE_/')"
read -r T3 V3 <<<"$(fund)"
PX=$($CLI utxoupdatepsbt "$($CLI createpsbt "[{\"txid\":\"$T3\",\"vout\":$V3}]" "[{\"$DEST\":9.999}]")")
R=$($CLI addpsbtmldsascriptpath "$PX" 0 "$ONE_leaf" "$ONE_control" 2>&1) || true
check "$(printf '%s' "$R" | grep -c 'do not commit to the output')" "1" "a leaf and control block that do not commit to the output are rejected"
# a wallet that holds no key of the leaf adds nothing
PY=$($CLI addpsbtmldsascriptpath "$PX" 0 "$SP_leaf" "$SP_control")
R=$($MINER walletprocesspsbt "$PY")
check "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["complete"])') $($CLI decodepsbt "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')" | entries)" "False 0 open" "a wallet that is not named in the leaf adds no entry"

[ $fail -eq 0 ] && say "V2 PSBT MULTISIG OK" || say "V2 PSBT MULTISIG FAILED"
exit $fail
