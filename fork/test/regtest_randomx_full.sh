#!/bin/bash
# Qcoin optional full-dataset RandomX verification (-randomxfull=1) across a key-rotation boundary (regtest).
#  1. The node reports the mode: log line and getblockchaininfo.randomx.mode == "full".
#  2. It mines 2111 blocks; the genesis key's 2 GiB dataset is built in the background (the cache is used until it is
#     ready) and then used (randomx.datasets_ready, hashes_full).
#  3. Across the boundary (heights 2112-2133) the new key gets its own cache and dataset; the node never stalls; both
#     datasets end up built (4.5 GiB with the caches); an ML-DSA spend confirms after the rotation.
#  4. qtc-randomx-scan in full mode (QTC_RX_FAST=1) accepts a block mined on the new key.
#  5. The chain mined in full mode is re-validated by a node in light mode (restart plus -reindex): the hashes are
#     identical in both modes, and the light node reports mode "light".
# Needs about 7 GiB of free memory, a few minutes, and: cmake --build <dir> --target qtc-randomx-scan
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
$CLI generatetoaddress 2011 "$M" >/dev/null
check "$($CLI getblockcount)" "2111" "2111 blocks mined"
check "$([ "$(rx hashes_full)" -gt "$H0" ] && echo yes)" "yes" "blocks were hashed with the dataset (hashes_full rose from $H0 to $(rx hashes_full))"

say "== 3. across the key boundary =="
GK=$(keyof "$($CLI getblockhash 0)")
$CLI generatetoaddress 1 "$M" >/dev/null
K2=$(keyof "$($CLI getblockhash 2048)")
check "$($CLI getblocktemplate '{"rules":["segwit"]}' | py 'import sys,json; d=json.load(sys.stdin); print(d["randomxkeyheight"], d["randomxkey"])')" "2048 $K2" "template for height 2113 uses block 2048 as key"
$CLI generatetoaddress 21 "$M" >/dev/null
check "$($CLI getblockcount)" "2133" "21 blocks mined across the boundary (heights 2113-2133)"
check "$(rx keys_cached)" "2" "the current and the previous key are cached"
waitfor datasets_ready 2 300; check "$(rx datasets_ready)" "2" "both datasets are built (4 GiB of datasets plus 2 caches)"
PEAK_KB=$(awk '/VmHWM/ {print $2}' "/proc/$(cat "$D/regtest/bitcoind.pid")/status")
check "$([ "$PEAK_KB" -gt 4000000 ] && [ "$PEAK_KB" -lt 7000000 ] && echo yes)" "yes" "peak resident memory with two datasets is about 4.5 GiB (VmHWM $((PEAK_KB / 1024)) MiB)"
H1=$(rx hashes_full)
$CLI generatetoaddress 5 "$M" >/dev/null
check "$([ "$(rx hashes_full)" -gt "$H1" ] && echo yes)" "yes" "new-key blocks are hashed with the new dataset"
B=$($W getnewmldsaaddress dest)
TX=$($W sendtoaddress "$B" 1.0)
check "${#TX}" "64" "ML-DSA spend accepted after the rotation"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($W gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "ML-DSA spend confirmed"
TIP=$($CLI getbestblockhash)

say "== 4. scanner in full mode on a new-key block =="
BH=$($CLI getblockhash 2130)
H80=$($CLI getblockheader "$BH" false)
T=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["target"])')
N=$($CLI getblockheader "$BH" | py 'import sys,json; print(json.load(sys.stdin)["nonce"])')
check "$(QTC_RX_FAST=1 QTC_RX_KEY=$K2 QTC_RX_THREADS=16 "$SCAN" "${H80:0:152}" "$T" "$N" 1 1)" "$N" "full-mode scanner accepts the mined nonce under the new key"

say "== 5. the same chain in light mode =="
stop
start -reindex
for i in $(seq 1 600); do [ "$($CLI getblockcount 2>/dev/null)" = "2139" ] && break; sleep 1; done
check "$($CLI getbestblockhash)" "$TIP" "a light-mode node re-validates all 2139 blocks (same hashes in both modes)"
check "$(rx mode)" "light" "getblockchaininfo.randomx.mode is light"
check "$(rx datasets_ready)" "0" "no dataset in light mode"
check "$(grep -c 'RandomX: light-mode verification' "$D/regtest/debug.log")" "1" "log line reports light-mode verification"

[ $fail -eq 0 ] && say "RANDOMX FULL REGTEST OK" || say "RANDOMX FULL REGTEST FAILED"
exit $fail
