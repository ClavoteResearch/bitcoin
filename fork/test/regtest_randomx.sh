#!/bin/bash
# Qcoin RandomX proof of work on regtest.
#  1. Default regtest: RandomX from genesis (deployment "randomx" buried at height 0). Mines blocks, an independent
#     RandomX evaluation (qtc-randomx-scan, a separate code path from the node) confirms a mined header's nonce, and a
#     normal ML-DSA spend confirms.
#  2. Activation height: with -testactivationheight=randomx@10 blocks 1-9 are proven with double SHA-256 and block 10
#     on with RandomX. At height 10 a header that meets the target only under SHA-256d is rejected ("high-hash"), one
#     that meets it under RandomX is accepted. At height 9 and below a SHA-256d header is the rule.
#  3. The node restarts and reindexes across the transition.
# Works with the default build. Needs: cmake --build <dir> --target qtc-randomx-scan
# Usage: regtest_randomx.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
HERE=$(cd "$(dirname "$0")" && pwd)
SCAN="$BIN/qtc-randomx-scan"
[ -x "$SCAN" ] || { echo "[FAIL] $SCAN missing (cmake --build <dir> --target qtc-randomx-scan)"; exit 1; }
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-rx.XXXX")
RPCPORT=29552
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
start() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29553 -listen=0 -walletsigscheme=mldsa44 "$@" >/dev/null
          for i in $(seq 1 90); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
stop() { $CLI stop >/dev/null 2>&1; for i in $(seq 1 60); do pgrep -f "datadir=$D" >/dev/null || break; sleep 1; done; }
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
trap 'stop; rm -rf "$D"' EXIT
dep() { $CLI getdeploymentinfo | py 'import sys,json; d=json.load(sys.stdin)["deployments"]["randomx"]; print(d["type"], d["active"], d.get("height"))'; }

say "== 1. regtest: RandomX from genesis =="
say "scanner self-test: $("$SCAN" --selftest | tr '\n' ' ')"
check "$("$SCAN" --selftest | grep -c 'ok)')" "1" "RandomX known-answer vector"
start
check "$(dep)" "buried True 0" "randomx deployment is buried and active from height 0"
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
M=$($W getnewmldsaaddress mine)
$CLI generatetoaddress 106 "$M" >/dev/null
check "$($CLI getblockcount)" "106" "106 blocks mined under RandomX"
TIPH=$($CLI getblockhash 106)
HDR=$($CLI getblockheader "$TIPH" false)
TARGET=$($CLI getblockheader "$TIPH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
NONCE=$($CLI getblockheader "$TIPH" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')
check "${#HDR}" "160" "block header is 80 bytes"
check "$(QTC_RX_THREADS=1 "$SCAN" "${HDR:0:152}" "$TARGET" "$NONCE" 1 1)" "$NONCE" "independent RandomX evaluation accepts the mined header's nonce"
B=$($W getnewmldsaaddress dest)
TX=$($W sendtoaddress "$B" 1.0)
check "${#TX}" "64" "ML-DSA spend accepted"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "ML-DSA spend confirmed in a RandomX block"
stop

say "== 2. -testactivationheight=randomx@10: SHA-256d below, RandomX from 10 =="
rm -rf "$D"; mkdir -p "$D"
start -testactivationheight=randomx@10
check "$(dep)" "buried False 10" "randomx activates at height 10 (inactive at the genesis tip)"
$CLI createwallet w >/dev/null
M=$($W getnewmldsaaddress mine)
$CLI generatetoaddress 8 "$M" >/dev/null
check "$(dep)" "buried False 10" "randomx not active for the next block (height 9)"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getblockcount)" "9" "9 blocks mined under SHA-256d"
check "$(dep)" "buried True 10" "randomx active for the next block (height 10)"
TIPH=$($CLI getbestblockhash)
HDR=$($CLI getblockheader "$TIPH" false)
TARGET=$($CLI getblockheader "$TIPH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
SHAONLY=$(python3 -I "$HERE/randomx_headers.py" craft "$HDR" "$SCAN" "$TARGET" sha-only)
RXOK=$(python3 -I "$HERE/randomx_headers.py" craft "$HDR" "$SCAN" "$TARGET" randomx)
R=$($CLI submitheader "$SHAONLY" 2>&1) || true
check "$(printf '%s' "$R" | grep -c 'high-hash')" "1" "height 10: a header that only meets the target under SHA-256d is rejected (high-hash)"
R=$($CLI submitheader "$RXOK" 2>&1) || true
check "${#R}" "0" "height 10: a header that meets the target under RandomX is accepted"
$CLI generatetoaddress 6 "$M" >/dev/null
check "$($CLI getblockcount)" "15" "6 more blocks (heights 10-15) mined under RandomX"
H10=$($CLI getblockhash 10)
check "$(QTC_RX_THREADS=1 "$SCAN" "$($CLI getblockheader "$H10" false | cut -c1-152)" "$TARGET" "$($CLI getblockheader "$H10" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')" 1 1)" "$($CLI getblockheader "$H10" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')" "block 10 satisfies RandomX"

say "== 3. restart and reindex across the transition =="
stop
start -testactivationheight=randomx@10
check "$($CLI getblockcount)" "15" "restart keeps height 15"
stop
start -testactivationheight=randomx@10 -reindex
for i in $(seq 1 120); do [ "$($CLI getblockcount 2>/dev/null)" = "15" ] && break; sleep 1; done
check "$($CLI getblockcount)" "15" "reindex re-validates all 15 blocks (SHA-256d then RandomX)"
check "$($CLI getbestblockhash)" "$($CLI getblockhash 15)" "best block is the same after reindex"

[ $fail -eq 0 ] && say "RANDOMX REGTEST OK" || say "RANDOMX REGTEST FAILED"
exit $fail
