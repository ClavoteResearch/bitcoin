#!/bin/bash
# qtc-faucet on a live qtctest node: fund the faucet wallet by mining, serve, claim to a fresh tq1z address from a
# tester wallet, confirm the receive, and check the policy paths (rate limit, non-v2 address, invalid address, CLI send).
# Usage: regtest_qtctest_faucet.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-qtcf.XXXX")
RPCPORT=29532; WEB=29581
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }
http() { python3 -I -c 'import sys,urllib.request,urllib.error
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=120); print(r.status); print(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code); print(e.read().decode())' "http://127.0.0.1:$WEB$1"; }
post() { python3 -I -c 'import sys,urllib.request,urllib.error,urllib.parse
data = urllib.parse.urlencode({"address": sys.argv[2]}).encode()
try:
    r = urllib.request.urlopen(sys.argv[1], data=data, timeout=120); print(r.status); print(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code); print(e.read().decode())' "http://127.0.0.1:$WEB/claim" "$1"; }
FAUCET="python3 -I $ROOT/fork/tools/qtc-faucet.py --chain qtctest --datadir $D --rpcurl http://127.0.0.1:$RPCPORT --state $D/faucet-state.json"

"$BIN/bitcoind" -chain=qtctest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29533 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -chain=qtctest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done

say "== fund the faucet wallet by mining =="
F=$($FAUCET fund --blocks 101)
check "$(printf '%s' "$F" | py 'import sys,json; d=json.load(sys.stdin); print(d["chain"], d["mined"], d["balance"])')" "qtctest 101 50.0" "fund: 101 blocks mined, one coinbase matured (50)"
check "$($CLI listwallets | py 'import sys,json; print("faucet" in json.load(sys.stdin))')" "True" "faucet wallet created"

say "== tester wallet gets a fresh tq1z address =="
$CLI createwallet tester >/dev/null; T="$CLI -rpcwallet=tester"
A=$($T getnewmldsaaddress faucet-claim)
check "${A:0:4}" "tq1z" "tester address is witness v2"
LEGACY=$($T getnewaddress)

say "== serve and claim over HTTP (payout confirmed by --confirm-blocks 1) =="
$FAUCET serve --port $WEB --amount 1.5 --cooldown 3600 --confirm-blocks 1 > "$D/faucet.log" 2>&1 &
FP=$!
for i in $(seq 1 30); do http /api/status >/dev/null 2>&1 && break; sleep 1; done
check "$(head -1 "$D/faucet.log" | grep -c "qtc-faucet: chain qtctest wallet 'faucet' balance 50.0 paying 1.5")" "1" "faucet serving with the funded wallet"
R=$(http "/api/claim?address=$A")
check "$(printf '%s' "$R" | head -1)" "200" "api/claim HTTP 200"
TX=$(printf '%s' "$R" | tail -n +2 | jget txid)
check "${#TX}" "64" "claim returned a txid"
check "$(printf '%s' "$R" | tail -n +2 | py 'import sys,json; d=json.load(sys.stdin); print(d["ok"], d["amount"], d["address_type"], len(d["confirmed_in_block"] or ""))')" "True 1.5 witness v2 ML-DSA 64" "claim JSON: ok, amount, v2 type, mined block"
check "$($T getbalance)" "1.50000000" "tester wallet received 1.5 (confirmed)"
check "$($T gettransaction "$TX" | py 'import sys,json; d=json.load(sys.stdin); print(d["confirmations"], d["details"][0]["address"]==sys.argv[1])' "$A")" "1 True" "receive confirmed to the tq1z address"
check "$($T listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]]; print(len(u), u[0]["solvable"] if u else "-")' "$A")" "1 True" "tester can spend it (solvable)"

say "== policy =="
check "$(http "/api/claim?address=$A" | head -1)" "400" "second claim for the same address within the cooldown is refused"
check "$(http "/api/claim?address=$A" | tail -n +2 | jget error | grep -c 'already paid')" "1" "...with a cooldown message"
check "$(http "/api/claim?address=$LEGACY" | tail -n +2 | jget error | grep -c 'only pays witness v2')" "1" "non-v2 address refused"
check "$(http "/api/claim?address=bcrt1qxyz" | tail -n +2 | jget error | grep -c 'invalid address')" "1" "invalid address refused"
A2=$($T getnewmldsaaddress faucet-claim-2)
P=$(post "$A2")
check "$(printf '%s' "$P" | head -1)$(printf '%s' "$P" | grep -c "Sent 1.5 to")" "2001" "HTML form POST pays a second fresh tq1z address"
check "$(http /api/status | tail -n +2 | py 'import sys,json; d=json.load(sys.stdin); print(d["chain"], d["payouts"], d["v2_only"], d["amount"])')" "qtctest 2 True 1.5" "api/status: two payouts, v2-only"
check "$(python3 -I -c 'import sys,json; print(len(json.load(open(sys.argv[1]))["payouts"]))' "$D/faucet-state.json")" "2" "rate-limit state persisted"
kill $FP 2>/dev/null; wait $FP 2>/dev/null

say "== CLI send (operator, no rate limit) =="
S=$($FAUCET send "$A" --amount 0.25)
check "$(printf '%s' "$S" | py 'import sys,json; d=json.load(sys.stdin); print(d["ok"], d["amount"])')" "True 0.25" "operator send to an already-paid address works (limits bypassed)"
$CLI generatetoaddress 1 "$($T getnewaddress)" 2000000000 >/dev/null
check "$($T getbalance)" "3.25000000" "tester balance 1.5 + 1.5 + 0.25"
check "$($FAUCET send "$LEGACY" 2>/dev/null | py 'import sys,json; print(json.load(sys.stdin)["ok"])')" "False" "CLI send still enforces v2-only without --allow-any-address"
check "$($FAUCET send "$LEGACY" --allow-any-address --amount 0.1 | py 'import sys,json; print(json.load(sys.stdin)["ok"])')" "True" "--allow-any-address pays a tq1q address"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "QTCTEST FAUCET OK" || say "QTCTEST FAUCET FAILED"
exit $fail
