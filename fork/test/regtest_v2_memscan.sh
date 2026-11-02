#!/bin/bash
# Qcoin: how many copies of an ML-DSA secret key does a node hold in memory around a signature? (regtest, Linux, needs root or
# ptrace rights; the secret key is read back from the unencrypted wallet file once, only so that the test knows what to look for)
#  1. a fresh wallet gets an ML-DSA key; its secret key is read from the wallet file; then the wallet is encrypted and the node restarted
#  2. unlocked and idle, after signing a payment, and after walletlock the process memory is scanned for the key
# Prints the counts; the checks are the properties the signing code guarantees:
#  - a locked wallet leaves no copy of the key in memory (full=0, K=0)
#  - after a payment is signed, no copy of the key is left in memory (full=0)
# Usage: regtest_v2_memscan.sh [path/to/build/bin] [mldsa44|mldsa87]   (mldsa87 needs an experimental build)
set -u
BIN="${1:-build/bin}"
SCHEME="${2:-mldsa44}"
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-memscan.XXXX")
RPCPORT=29462
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
PREENV=""
start() { $PREENV "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29463 -listen=0 -walletsigscheme=$SCHEME >/dev/null 2>&1
    for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
stop() { $CLI stop >/dev/null 2>&1; for i in $(seq 1 60); do [ -f "$D/regtest/bitcoind.pid" ] || return 0; sleep 1; done; }
count() { echo "$1" | grep -o "$2=[0-9]*" | cut -d= -f2; }
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
trap '$CLI stop >/dev/null 2>&1; sleep 2; rm -rf "$D"' EXIT
start || { say "node did not start"; exit 1; }
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
A=$($W getnewmldsaaddress)
$CLI generatetoaddress 101 "$A" >/dev/null
PK=$($W getaddressinfo "$A" | py 'import sys,json,re; print(re.match(r"wpq\((.*)\)#", json.load(sys.stdin)["desc"]).group(1))')
$CLI unloadwallet w >/dev/null
stop
# secret key: the wallet record is  scheme | compactsize pk | compactsize sk | hash ; find the public key, the secret key follows
SKFILE="$D/sk.bin"
KEYLEN=$(python3 -I - "$D/regtest/wallets/w/wallet.dat" "$PK" "$SKFILE" <<'EOF'
import sys
data = open(sys.argv[1], "rb").read()
pk = bytes.fromhex(sys.argv[2])
i = -1
while True:
    i = data.find(pk, i + 1)
    if i < 0:
        sys.exit("secret key record not found")
    j = i + len(pk)
    if data[j] == 0xfd:
        n = int.from_bytes(data[j + 1:j + 3], "little")
        if n in (2560, 4896):
            # a record larger than a database page (ML-DSA-87) is split over overflow pages, so only the start of the key is
            # certain to be contiguous in the file: its first 256 bytes (rho, K, tr, start of s1) serve as the "whole key" needle;
            # every full copy of the key contains them in this order
            open(sys.argv[3], "wb").write(data[j + 3:j + 3 + min(n, 256)])
            print(n)
            break
EOF
)
check "$KEYLEN" "$([ "$SCHEME" = mldsa87 ] && echo 4896 || echo 2560)" "secret key read from the wallet file (length)"
start || exit 1
$CLI loadwallet w >/dev/null
# control: the unencrypted wallet keeps the key in its (locked, zero-on-free) memory, so the scanner must see it
CTRL=$(python3 -I "$HERE/memscan_mldsa.py" "$(cat "$D/regtest/bitcoind.pid")" "$SKFILE"); say "control, unencrypted wallet: $CTRL"
check "$([ "$(count "$CTRL" full)" -ge 1 ] && echo found)" "found" "the scanner finds the key of an unencrypted wallet"
$W encryptwallet "pass phrase" >/dev/null 2>&1
# interposer on OQS_SIG_sign_with_ctx_str (needs gcc): counts the key copies in the node's own memory when a signature starts and when it returns
SO="$D/memscan_preload.so"; SIGLOG="$D/sign.log"
if gcc -O1 -shared -fPIC "$HERE/memscan_preload.c" -o "$SO" -ldl 2>/dev/null; then
    PREENV="env LD_PRELOAD=$SO QCOIN_MEMSCAN_SK=$SKFILE QCOIN_MEMSCAN_KEYLEN=$KEYLEN QCOIN_MEMSCAN_LOG=$SIGLOG"
fi
stop; start || exit 1       # a fresh process: memory has only ever seen the encrypted wallet
$CLI loadwallet w >/dev/null
PID=$(cat "$D/regtest/bitcoind.pid")
scan() { python3 -I "$HERE/memscan_mldsa.py" "$PID" "$SKFILE"; }
say "locked, fresh process:      $(scan)"
$W walletpassphrase "pass phrase" 600 >/dev/null
IDLE=$(scan); say "unlocked, idle:            $IDLE"
B=$($W getnewmldsaaddress)
TX=$($W sendtoaddress "$B" 1.0)
check "${#TX}" "64" "payment signed with the encrypted wallet"
if [ -f "$SIGLOG" ]; then
    say "inside the signing call (copies in the node's memory):"; sed 's/^/    /' "$SIGLOG"
    check "$(grep -c '^sign enter' "$SIGLOG" | sed 's/^0$/none/; s/^[1-9][0-9]*$/some/')" "some" "the interposer saw the signature(s)"
    # the one decrypted copy that the signer reads is the only copy: the provider holds none of its own
    check "$(grep '^sign enter' "$SIGLOG" | sed 's/.*enter full=\([0-9]*\) .*/\1/' | sort -u | tr '\n' ' ')" "1 " "exactly one copy of the key is in memory while it signs"
    # liboqs leaves the unpacked key on the stack; the wrapper scrubs it before the wallet wipes its copy
    check "$(grep '^key wiped' "$SIGLOG" | sed 's/.*K=//' | sort -u | tr '\n' ' ')" "0 " "no remnant of the key on the stack below the signer once the key is wiped"
fi
SIGNED=$(scan); say "after signing (unlocked):  $SIGNED"
$W walletlock >/dev/null
LOCKED=$(scan); say "after walletlock:          $LOCKED"
check "$(count "$LOCKED" full) $(count "$LOCKED" K)" "0 0" "no copy of the key (whole or its seed K) in memory once the wallet is locked"
check "$(count "$SIGNED" full)" "0" "no whole copy of the key in memory after signing (unlocked wallet, encrypted at rest)"
[ $fail -eq 0 ] && say "V2 MEMSCAN OK" || say "V2 MEMSCAN FAILED"
exit $fail
