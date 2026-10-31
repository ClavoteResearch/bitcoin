#!/bin/bash
# qtc-explorer against a live qtctest node: mine blocks, make a witness v2 spend, and check the HTML/JSON pages
# show the blocks, the transaction (labelled as an ML-DSA attestation) and the tq1z address history.
# Usage: regtest_qtctest_explorer.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-qtcx.XXXX")
RPCPORT=29432; WEB=29480
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }
get() { python3 -I -c 'import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=30).read().decode())' "http://127.0.0.1:$WEB$1"; }
has() { grep -c -- "$2" <<<"$1"; }

"$BIN/bitcoind" -chain=qtctest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29433 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -chain=qtctest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet w >/dev/null; W="$CLI -rpcwallet=w"
M=$($W getnewaddress); $CLI generatetoaddress 101 "$M" >/dev/null
A1=$($W getnewmldsaaddress x)
FUND=$($W sendtoaddress "$A1" 7); $CLI generatetoaddress 1 "$M" >/dev/null
IN=$($W listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$A1")
SPEND=$($W -named send outputs="{\"$M\":3}" options="{\"inputs\":$IN,\"add_inputs\":false}" | jget txid)
$CLI generatetoaddress 1 "$M" >/dev/null
H=$($CLI getblockcount)

say "== start explorer =="
python3 -I "$ROOT/fork/tools/qtc-explorer.py" --chain qtctest --datadir "$D" --rpcurl "http://127.0.0.1:$RPCPORT" --port $WEB --scan 500 > "$D/explorer.log" 2>&1 &
XP=$!
for i in $(seq 1 30); do get /api/status >/dev/null 2>&1 && break; sleep 1; done
check "$(head -1 "$D/explorer.log" | grep -c 'qtc-explorer: chain qtctest')" "1" "explorer connected to the qtctest node"

say "== status page / API =="
ST=$(get /api/status)
check "$(printf '%s' "$ST" | py 'import sys,json; d=json.load(sys.stdin); print(d["chain"], d["blocks"], d["mldsav2"]["active"], d["mldsav2"]["height"])')" "qtctest $H True 0" "api/status: chain, height, mldsav2 active at 0"
HOME_=$(get /)
check "$(has "$HOME_" "mldsav2 deployment")$(has "$HOME_" "active (height 0)")" "11" "status page shows the deployment active"
check "$(has "$HOME_" "/block/$H'")" "1" "status page lists the tip block"
check "$(has "$HOME_" "1 spend</span>")" "1" "status page marks the block with the v2 spend"

say "== block, tx, address pages =="
BH=$($CLI getblockhash "$H")
BP=$(get "/block/$H")
check "$(has "$BP" "Block $H</h2>")$(has "$BP" "$BH")$(has "$BP" "/tx/$SPEND")" "111" "block page: height, hash, links the spend tx"
check "$(has "$BP" 'v2 spend</span>')" "1" "block page labels the v2 spend"
TP=$(get "/tx/$SPEND")
check "$(has "$TP" "ML-DSA attestation: 1 entry, ML-DSA-44, 3735 bytes")" "1" "tx page labels the input as an ML-DSA-44 attestation"
check "$(has "$TP" "confirmation(s)")" "1" "tx page shows confirmations"
FP=$(get "/tx/$FUND")
check "$(has "$FP" "witness v2 ML-DSA (OP_2 &lt;Q&gt;)")$(has "$FP" "/address/$A1")" "11" "funding tx page labels the v2 output and links the tq1z address"
AP=$(get "/address/$A1")
check "$(has "$AP" "witness v2 ML-DSA (key path)")" "1" "address page identifies a tq1z address"
check "$(has "$AP" "Received (1)")$(has "$AP" "Spent (1)")$(has "$AP" "+7.00000000")$(has "$AP" "-7.00000000")" "1111" "address page: one receive, one spend, amounts"
check "$(get "/api/address/$A1" | py 'import sys,json; d=json.load(sys.stdin); print(d["kind"], d["unspent_count"], len(d["received"]), len(d["spent"]), d["spent"][0]["witness"][:18])')" "witness v2 ML-DSA (key path) 0 1 1 ML-DSA attestation" "api/address JSON"
check "$(get "/api/block/0" | jget hash)" "3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60" "api/block/0 returns the qtctest genesis"
MP=$(get /mempool); check "$(has "$MP" "Mempool (0)")" "1" "mempool page (empty)"
$W sendtoaddress "$M" 1 >/dev/null
MP=$(get /mempool); check "$(has "$MP" "Mempool (1)")" "1" "mempool page shows a pending tx"
check "$(python3 -I -c 'import sys,urllib.request
try: urllib.request.urlopen(sys.argv[1], timeout=10); print("200")
except urllib.error.HTTPError as e: print(e.code)' "http://127.0.0.1:$WEB/tx/0000000000000000000000000000000000000000000000000000000000000001")" "404" "unknown txid gives 404"

kill $XP 2>/dev/null; wait $XP 2>/dev/null
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "QTCTEST EXPLORER OK" || say "QTCTEST EXPLORER FAILED"
exit $fail
