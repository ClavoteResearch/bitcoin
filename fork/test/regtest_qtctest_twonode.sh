#!/bin/bash
# Two qtctest nodes on one machine, LOOPBACK ONLY: both bind 127.0.0.1 with -discover=0 -dnsseed=0, the peer is
# pinned with -connect, and the P2P/RPC ports are overridden (29833/29832 and 29843/29842) so nothing here touches
# the real 28333/28332, a firewall, DNS or the compiled-in seeds. It proves config handling and block propagation,
# not public reachability; for that follow "Publishing a real seed node" in doc/WALLET-PQC.md.
# A "seed" node listens and a second node started from the example fork/contrib/qtctest.conf connects to it. Mines a few blocks on the seed and checks the peer syncs them,
# then mines on the peer and checks the seed follows. Verifies the example config parses and the ports are right.
# Usage: regtest_qtctest_twonode.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DA=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-qtcs.XXXX"); DB=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-qtcp.XXXX")
PA=29833; RA=29832; PB=29843; RB=29842
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
wait_rpc() { for i in $(seq 1 60); do $1 getblockchaininfo >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
wait_height() { for i in $(seq 1 60); do [ "$($1 getblockcount 2>/dev/null)" = "$2" ] && return 0; sleep 1; done; return 1; }
mine() { local n=$1 cli=$2 addr=$3 i; for ((i=0;i<n;i++)); do $cli generatetoaddress 1 "$addr" 2000000000 >/dev/null; done; }

say "== seed node (listening) =="
"$BIN/bitcoind" -chain=qtctest -datadir="$DA" -daemon -listen=1 -port=$PA -rpcport=$RA -bind=127.0.0.1 -discover=0 -dnsseed=0 -fallbackfee=0.0001 -walletsigscheme=mldsa44 >/dev/null
A="$BIN/bitcoin-cli -chain=qtctest -datadir=$DA -rpcport=$RA"
wait_rpc "$A" || { say "[FAIL] seed node did not start"; exit 1; }
check "$($A getnetworkinfo | py 'import sys,json; d=json.load(sys.stdin); print(d["networkactive"], [n["name"] for n in d["networks"] if n["reachable"]][0])')" "True ipv4" "seed node up and reachable on ipv4"
$A createwallet seedw >/dev/null; MA=$($A -rpcwallet=seedw getnewaddress)
mine 3 "$A" "$MA"
check "$($A getblockcount)" "3" "seed mined 3 blocks"

say "== second node from the example config, connecting to the seed =="
cp "$ROOT/fork/contrib/qtctest.conf" "$DB/bitcoin.conf"
check "$(grep -c '^chain=qtctest' "$DB/bitcoin.conf")$(grep -c '^port=28333' "$DB/bitcoin.conf")$(grep -c '^rpcport=28332' "$DB/bitcoin.conf")" "111" "example config declares chain, P2P 28333 and RPC 28332"
# Same machine: override the ports from the command line (command line beats the config) and pin the peer.
"$BIN/bitcoind" -datadir="$DB" -daemon -port=$PB -rpcport=$RB -bind=127.0.0.1 -listen=1 -discover=0 -dnsseed=0 -connect=127.0.0.1:$PA >/dev/null
B="$BIN/bitcoin-cli -chain=qtctest -datadir=$DB -rpcport=$RB"
wait_rpc "$B" || { say "[FAIL] second node did not start (config problem?)"; $A stop >/dev/null; exit 1; }
check "$($B getblockchaininfo | py 'import sys,json; print(json.load(sys.stdin)["chain"])')" "qtctest" "second node picked chain=qtctest from the config"
check "$(ls -d "$DB/qtctest" | wc -l)" "1" "second node uses the qtctest data directory"
check "$($B getindexinfo | py 'import sys,json; print("txindex" in json.load(sys.stdin))')" "True" "txindex=1 from the config is active"
for i in $(seq 1 30); do [ "$($B getconnectioncount)" -ge 1 ] && break; sleep 1; done
check "$($B getconnectioncount)" "1" "second node connected to the seed"
check "$($A getconnectioncount)" "1" "seed sees the inbound peer"
# loopback peers are classified not_publicly_routable (a real remote peer would show ipv4/ipv6)
check "$($A getpeerinfo | py 'import sys,json; p=json.load(sys.stdin)[0]; print(p["inbound"], p["network"], p["addr"].startswith("127.0.0.1:"))')" "True not_publicly_routable True" "seed: peer is inbound from loopback"
wait_height "$B" 3 || true
check "$($B getblockcount) $($B getbestblockhash)" "3 $($A getbestblockhash)" "second node synced to the seed's tip"
check "$($B getdeploymentinfo | py 'import sys,json; print(json.load(sys.stdin)["deployments"]["mldsav2"]["active"])')" "True" "mldsav2 active on the second node too"

say "== blocks flow the other way: peer mines, seed follows =="
$B createwallet peerw >/dev/null; MB=$($B -rpcwallet=peerw getnewaddress)
mine 2 "$B" "$MB"
wait_height "$A" 5 || true
check "$($A getblockcount) $($A getbestblockhash)" "5 $($B getbestblockhash)" "seed synced the peer's 2 blocks"
check "$($A getpeerinfo | py 'import sys,json; p=json.load(sys.stdin)[0]; print(p["synced_blocks"])')" "5" "seed reports peer synced at height 5"

# (spending needs 100 confirmations, about 5 min of mining at 1e00ffff; the v2 spend path is covered by
#  regtest_qtctest.sh, this test is about connectivity and block propagation)
check "$($B getpeerinfo | py 'import sys,json; p=json.load(sys.stdin)[0]; print(p["inbound"], p["relaytxes"])')" "False True" "peer: outbound connection with tx relay enabled"

$A stop >/dev/null; $B stop >/dev/null; sleep 1
[ $fail -eq 0 ] && say "QTCTEST TWO-NODE OK" || say "QTCTEST TWO-NODE FAILED"
exit $fail
