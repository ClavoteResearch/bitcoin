#!/bin/bash
# Qcoin optional full-dataset RandomX verification (-randomxfull=1) with pre-built epoch datasets (regtest).
#  1. The node reports the mode: log line and getblockchaininfo.randomx.mode == "full".
#  2. It mines to height 2047; the genesis key's 2 GiB dataset is built in the background (the cache is used until it
#     is ready) and then used (randomx.datasets_ready, hashes_full).
#  3. Pre-build: when block 2048 (the key block of the next epoch) arrives, the node starts building that key's cache and
#     dataset although no block uses it yet (first use is height 2113). The test waits for the dataset, mines up to height
#     2112 and checks that the next dataset is already built when the boundary is reached; the first block on the new key
#     (2113) is hashed with it without a build in progress. An ML-DSA spend confirms after the rotation, and
#     qtc-randomx-scan in full mode accepts a block mined on the new key.
#  4. At the second key block (4096) the third dataset is prepared: three keys are cached (about 6.9 GiB of datasets
#     and caches); the peak resident size is checked.
#  5. The chain mined in full mode is re-validated by a node in light mode (restart plus -reindex): the hashes are
#     identical in both modes, and the light node reports mode "light" and caches no dataset.
# Needs about 8 GiB of free memory, a few minutes, and: cmake --build <dir> --target qtc-randomx-scan
# Usage: regtest_randomx_full.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
SCAN="$BIN/qtc-randomx-scan"
[ -x "$SCAN" ] || { echo "[FAIL] $SCAN missing (cmake --build <dir> --target qtc-randomx-scan)"; exit 1; }
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-rxf.XXXX")
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=29582"
start() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=29582 -port=29583 -listen=0 -walletsigscheme=mldsa44 "$@" >/dev/null
          for i in $(seq 1 120); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
stop() { $CLI stop >/dev/null 2>&1; for i in $(seq 1 90); do pgrep -f "datadir=$D" >/dev/null || break; sleep 1; done; }
trap 'stop; rm -rf "$D"' EXIT
rx() { $CLI getblockchaininfo | py 'import sys,json; r=json.load(sys.stdin)["randomx"]; print(r[sys.argv[1]])' "$1"; }
keyof() { py 'import sys; print(bytes.fromhex(sys.argv[1])[::-1].hex())' "$1"; }
waitfor() { # field value timeout-seconds
    for i in $(seq 1 "$3"); do [ "$(rx "$1")" = "$2" ] && return 0; sleep 1; done; return 1; }
peak_kb() { awk '/VmHWM/ {print $2}' "/proc/$(cat "$D/regtest/bitcoind.pid")/status"; }

say "== 1. mode reporting =="
start -randomxfull=1
check "$(grep -c 'RandomX: full-dataset verification' "$D/regtest/debug.log")" "1" "log line reports full-dataset verification"
check "$(rx mode)" "full" "getblockchaininfo.randomx.mode is full"
check "$(rx active)" "True" "RandomX is active for the next block"
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
M=$($W getnewmldsaaddress mine)

say "== 2. genesis key: dataset built in the background, then used =="
$CLI generatetoaddress 100 "$M" >/dev/null
check "$($CLI getblockcount)" "100" "100 blocks mined while the dataset builds (cache fallback)"
waitfor datasets_ready 1 300; check "$(rx datasets_ready)" "1" "genesis key dataset is built and in use"
H0=$(rx hashes_full)
$CLI generatetoaddress 1947 "$M" >/dev/null
check "$($CLI getblockcount)" "2047" "2047 blocks mined"
check "$([ "$(rx hashes_full)" -gt "$H0" ] && echo yes)" "yes" "blocks were hashed with the dataset (hashes_full rose from $H0 to $(rx hashes_full))"
check "$(rx keys_cached)" "1" "only the genesis key is cached before the key block arrives"

say "== 3. the next epoch's dataset is built before the boundary =="
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getblockcount)" "2048" "block 2048 (the key block of the next epoch) mined"
K2=$(keyof "$($CLI getblockhash 2048)")
waitfor datasets_ready 2 300
check "$(rx keys_cached) $(rx datasets_ready)" "2 2" "the next key's cache and dataset are built at height 2048, 65 blocks before it is first used"
$CLI generatetoaddress 64 "$M" >/dev/null
check "$($CLI getblockcount)" "2112" "64 more blocks mined, still on the genesis key"
check "$(rx datasets_building)" "0" "no dataset is still being built when the boundary is reached"
H1=$(rx hashes_full)
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getblockcount)" "2113" "first block on the new key mined"
check "$($CLI getblocktemplate '{"rules":["segwit"]}' | py 'import sys,json; d=json.load(sys.stdin); print(d["randomxkeyheight"], d["randomxkey"])')" "2048 $K2" "template uses block 2048 as key"
check "$([ "$(rx hashes_full)" -gt "$H1" ] && echo yes)" "yes" "the first new-key block was hashed with the pre-built dataset"
check "$(rx keys_cached) $(rx datasets_ready) $(rx datasets_building)" "2 2 0" "no cache or dataset had to be built at the boundary"
$CLI generatetoaddress 20 "$M" >/dev/null
check "$($CLI getblockcount)" "2133" "20 more blocks on the new key (heights 2114-2133)"
B=$($W getnewmldsaaddress dest)
TX=$($W sendtoaddress "$B" 1.0)
check "${#TX}" "64" "ML-DSA spend accepted after the rotation"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "ML-DSA spend confirmed"
BH=$($CLI getblockhash 2130)
H80=$($CLI getblockheader "$BH" false)
T=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
N=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')
check "$(QTC_RX_FULL=1 QTC_RX_KEY=$K2 QTC_RX_THREADS=16 "$SCAN" "${H80:0:152}" "$T" "$N" 1 1)" "$N" "full-mode scanner accepts a block mined on the new key"

say "== 4. the third dataset: previous, current and next epoch =="
$CLI generatetoaddress 1962 "$M" >/dev/null
check "$($CLI getblockcount)" "4096" "block 4096 (the second key block) mined"
waitfor datasets_ready 3 300
check "$(rx keys_cached) $(rx datasets_ready)" "3 3" "three keys are cached with three built datasets (previous, current, next)"
PEAK=$(peak_kb)
check "$([ "$PEAK" -gt 6000000 ] && [ "$PEAK" -lt 9500000 ] && echo yes)" "yes" "peak resident memory with three datasets is about 6.9 GiB (VmHWM $((PEAK / 1024)) MiB)"
TIP=$($CLI getbestblockhash)

say "== 5. the same chain in light mode =="
stop
start -reindex
for i in $(seq 1 900); do [ "$($CLI getblockcount 2>/dev/null)" = "4096" ] && break; sleep 1; done
check "$($CLI getbestblockhash)" "$TIP" "a light-mode node re-validates all 4096 blocks (same hashes in both modes)"
check "$(rx mode)" "light" "getblockchaininfo.randomx.mode is light"
check "$(rx datasets_ready) $(rx datasets_building)" "0 0" "no dataset in light mode, and no key is prepared ahead"
check "$([ "$(rx keys_cached)" -le 2 ] && echo yes)" "yes" "light mode caches at most two keys ($(rx keys_cached))"
check "$(grep -c 'RandomX: light-mode verification' "$D/regtest/debug.log")" "1" "log line reports light-mode verification"

[ $fail -eq 0 ] && say "RANDOMX FULL REGTEST OK" || say "RANDOMX FULL REGTEST FAILED"
exit $fail
