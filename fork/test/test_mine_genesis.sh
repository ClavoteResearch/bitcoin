#!/bin/bash
# fork/tools/mine-genesis.py self-test: reproduces the committed qtctest genesis, is deterministic (lowest nonce),
# reproduces the published 1e00ffff candidate, and honours --max-seconds.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MG="python3 -I $ROOT/fork/tools/mine-genesis.py"
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
j() { python3 -I -c 'import sys,json; d=json.load(sys.stdin); print(*[d[k] for k in sys.argv[1:]])' "$@"; }

A=$($MG --nbits 207fffff --time 1761782400 --json 2>/dev/null)
check "$(printf '%s' "$A" | j ok genesis_hash nonce merkle_root)" "True 3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60 0 951bd97f5c87145947cf54618d588de8c47b88c329991c4e21502ef52046c4b6" "reproduces the committed qtctest genesis (nonce 0)"
$MG --nbits 207fffff --time 1761782400 --json --expect 3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60 >/dev/null 2>&1; check "$?" "0" "--expect self-check passes"
$MG --nbits 207fffff --time 1761782400 --json --expect 0000000000000000000000000000000000000000000000000000000000000000 >/dev/null 2>&1; check "$?" "3" "--expect mismatch exits 3"
B=$($MG --nbits 1e00ffff --time 1761782400 --json 2>/dev/null)
check "$(printf '%s' "$B" | j ok genesis_hash nonce pow_limit)" "True 0000007ab165a4d29ff101fc7faf2cd2dd20618f4960c1fd85e3dd3e4a823437 6739749 000000ffff000000000000000000000000000000000000000000000000000000" "reproduces the documented 1e00ffff candidate (lowest nonce)"
check "$(printf '%s' "$B" | j expected_hashes)" "16777472" "expected work for 1e00ffff"
D=$($MG --nbits 1d00ffff --time 1761782400 --json --max-seconds 2 --procs 2 2>/dev/null); rc=$?
check "$rc $(printf '%s' "$D" | j ok error)" "2 False max-seconds reached" "--max-seconds aborts a difficulty-1 search with exit 2"
[ $fail -eq 0 ] && say "MINE-GENESIS OK" || say "MINE-GENESIS FAILED"
exit $fail
