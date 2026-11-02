#!/bin/bash
# Qcoin RandomX key rotation across an epoch boundary (regtest, RandomX from genesis).
# The key of a block at height h is the identifier of the block at RandomXKeyHeight(h): the genesis block for heights
# 1-2112, block 2048 for 2113-4160 (epoch 2048, lag 64). This test mines 2132 blocks, so it takes a few minutes.
#  1. getblocktemplate reports the key (randomxkey / randomxkeyheight): genesis key for height 2112, block 2048's
#     identifier for height 2113.
#  2. At height 2113 a header that meets the target only under the old (genesis) key is rejected ("high-hash"); one
#     that meets it under the new key is accepted.
#  3. 20 blocks are mined on the new key; an independent RandomX evaluation (qtc-randomx-scan) accepts all of them
#     under the new key and rejects at least one under the old key; an ML-DSA spend confirms after the rotation.
#  4. Restart and -reindex re-validate the chain across the boundary.
#  5. A second node syncs with -minimumchainwork set so that its headers presync spans the boundary (it must verify
#     the RandomX proofs of a chain that is not in its block index, with the key block seen earlier in the sync).
# Works with the default build. Needs: cmake --build <dir> --target qtc-randomx-scan
# Usage: regtest_randomx_epoch.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
HERE=$(cd "$(dirname "$0")" && pwd)
SCAN="$BIN/qtc-randomx-scan"
[ -x "$SCAN" ] || { echo "[FAIL] $SCAN missing (cmake --build <dir> --target qtc-randomx-scan)"; exit 1; }
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-rxe.XXXX")
D2=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-rxe2.XXXX")
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=29562"
# note: a node with -listen=1 also binds (P2P port + 1) for onion inbound, so keep RPC ports off P2P port + 1
CLI2="$BIN/bitcoin-cli -regtest -datadir=$D2 -rpcport=29570"
start() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=29562 -port=29563 -listen=1 -walletsigscheme=mldsa44 "$@" >/dev/null
          for i in $(seq 1 120); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
stop() { $CLI stop >/dev/null 2>&1; $CLI2 stop >/dev/null 2>&1
         for i in $(seq 1 90); do pgrep -f "datadir=$D" >/dev/null || pgrep -f "datadir=$D2" >/dev/null || break; sleep 1; done; }
trap 'stop; rm -rf "$D" "$D2"' EXIT
# block identifier (display hex) -> RandomX key (raw bytes in internal order, hex)
keyof() { py 'import sys; print(bytes.fromhex(sys.argv[1])[::-1].hex())' "$1"; }
gbt() { $CLI getblocktemplate '{"rules":["segwit"]}' | py 'import sys,json; d=json.load(sys.stdin); print(d["powalgo"], d["randomxkeyheight"], d["randomxkey"])'; }

start
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
M=$($W getnewmldsaaddress mine)

say "== 1. template key before and after the boundary =="
$CLI generatetoaddress 2111 "$M" >/dev/null
check "$($CLI getblockcount)" "2111" "2111 blocks mined (all with the genesis key)"
GK=$(keyof "$($CLI getblockhash 0)")
check "$(gbt)" "randomx 0 $GK" "template for height 2112 uses the genesis block as key (key height 0)"
$CLI generatetoaddress 1 "$M" >/dev/null
K2=$(keyof "$($CLI getblockhash 2048)")
check "$(gbt)" "randomx 2048 $K2" "template for height 2113 uses block 2048 as key (key height 2048)"
check "$([ "$GK" != "$K2" ] && echo different)" "different" "the key changed at the boundary"

say "== 2. height 2113: old key rejected, new key accepted =="
TIPH=$($CLI getbestblockhash)
HDR=$($CLI getblockheader "$TIPH" false)
TARGET=$($CLI getblockheader "$TIPH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
OLDONLY=$(python3 -I "$HERE/randomx_headers.py" craft "$HDR" "$SCAN" "$TARGET" other-key-only "$K2" "$GK")
NEWOK=$(python3 -I "$HERE/randomx_headers.py" craft "$HDR" "$SCAN" "$TARGET" randomx "$K2")
R=$($CLI submitheader "$OLDONLY" 2>&1) || true
check "$(printf '%s' "$R" | grep -c 'high-hash')" "1" "a header valid only under the old key is rejected (high-hash)"
R=$($CLI submitheader "$NEWOK" 2>&1) || true
check "${#R}" "0" "a header valid under the new key is accepted"

say "== 3. blocks and a spend on the new key =="
$CLI generatetoaddress 20 "$M" >/dev/null
check "$($CLI getblockcount)" "2132" "20 blocks mined on the new key (heights 2113-2132)"
newpass=0; oldpass=0
for h in $(seq 2113 2124); do
    BH=$($CLI getblockhash $h)
    H80=$($CLI getblockheader "$BH" false)
    T=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
    N=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')
    [ "$(QTC_RX_KEY=$K2 QTC_RX_THREADS=1 "$SCAN" "${H80:0:152}" "$T" "$N" 1 1)" = "$N" ] && newpass=$((newpass+1))
    [ "$(QTC_RX_KEY=$GK QTC_RX_THREADS=1 "$SCAN" "${H80:0:152}" "$T" "$N" 1 1)" = "$N" ] && oldpass=$((oldpass+1))
done
check "$newpass" "12" "12 of 12 blocks after the boundary satisfy RandomX under the new key"
check "$([ "$oldpass" -lt 12 ] && echo yes)" "yes" "not all of them satisfy it under the old key ($oldpass of 12 do by chance)"
B=$($W getnewmldsaaddress dest)
TX=$($W sendtoaddress "$B" 1.0)
check "${#TX}" "64" "ML-DSA spend accepted after the rotation"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "ML-DSA spend confirmed in a block on the new key"
TIP=$($CLI getbestblockhash)

say "== 4. restart and reindex across the boundary =="
stop
start
check "$($CLI getbestblockhash)" "$TIP" "restart keeps the tip (height 2133)"
stop
start -reindex
for i in $(seq 1 300); do [ "$($CLI getblockcount 2>/dev/null)" = "2133" ] && break; sleep 1; done
check "$($CLI getbestblockhash)" "$TIP" "reindex re-validates 2133 blocks across the key change"

say "== 5. headers presync across the boundary =="
# every regtest block adds work 2, so 2119 blocks plus genesis reach 0x1090 = 4240: presync lasts to height 2119,
# past the key change at 2113, and the key block (2048) was seen earlier in the same presync
"$BIN/bitcoind" -regtest -datadir="$D2" -daemon -rpcport=29570 -port=29571 -listen=0 -minimumchainwork=0x1090 -debug=net -connect=127.0.0.1:29563 >/dev/null
for i in $(seq 1 120); do $CLI2 getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq 1 600); do [ "$($CLI2 getblockcount 2>/dev/null)" = "2133" ] && break; sleep 1; done
check "$($CLI2 getbestblockhash 2>/dev/null)" "$TIP" "second node synced to height 2133"
LOG="$D2/regtest/debug.log"
check "$(grep -c 'Initial headers sync transition' "$LOG")" "1" "its headers sync used presync and redownload"
PH=$(grep 'Initial headers sync transition' "$LOG" | sed -n 's/.*reached sufficient work at height=\([0-9]*\).*/\1/p' | head -1)
check "$([ -n "$PH" ] && [ "$PH" -ge 2113 ] && echo yes)" "yes" "presync verified RandomX proofs past the key change (sufficient work at height $PH)"
check "$(grep -c 'invalid proof of work' "$LOG")" "0" "no header was rejected for its proof of work"

[ $fail -eq 0 ] && say "RANDOMX EPOCH REGTEST OK" || say "RANDOMX EPOCH REGTEST FAILED"
exit $fail
