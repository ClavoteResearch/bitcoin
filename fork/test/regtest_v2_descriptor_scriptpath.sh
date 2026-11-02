#!/bin/bash
# Qcoin: the wpq(KEY,TREE) descriptor on two regtest nodes. The tree has two leaves, A = mldsa_all(K1,K2) and B = mldsa_all(K3).
#  - node 1 holds the wallets miner and ws (K1, K2), node 2 the wallet w3 (K3); ws and w3 import the same descriptor
#  - the address comes from deriveaddresses, the coins from the miner
#  - one coin is spent through leaf A by ws, one through leaf B by w3 (createpsbt, walletprocesspsbt, finalizepsbt); the other
#    node confirms both spends
# Works with the default build. Usage: regtest_v2_descriptor_scriptpath.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D1=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-dsp1.XXXX"); D2=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-dsp2.XXXX")
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
OPTS="-regtest -fallbackfee=0.0001 -walletsigscheme=mldsa44"
"$BIN/bitcoind" $OPTS -datadir="$D1" -daemon -rpcport=19365 -port=19366 -listen=1 >/dev/null
"$BIN/bitcoind" $OPTS -datadir="$D2" -daemon -rpcport=19370 -port=19372 -listen=1 -connect=127.0.0.1:19366 >/dev/null
C1="$BIN/bitcoin-cli -regtest -datadir=$D1 -rpcport=19365"; C2="$BIN/bitcoin-cli -regtest -datadir=$D2 -rpcport=19370"
for i in $(seq 1 60); do $C1 getblockchaininfo >/dev/null 2>&1 && $C2 getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
trap '$C1 stop >/dev/null 2>&1; $C2 stop >/dev/null 2>&1; sleep 2; rm -rf "$D1" "$D2"' EXIT
MINER="$C1 -rpcwallet=miner"; WS="$C1 -rpcwallet=ws"; W3="$C2 -rpcwallet=w3"
$C1 createwallet miner >/dev/null; $C1 createwallet ws >/dev/null; $C2 createwallet w3 >/dev/null
M=$($MINER getnewmldsaaddress mine); $C1 generatetoaddress 101 "$M" >/dev/null
sync_blocks() { for i in $(seq 1 60); do [ "$($C1 getbestblockhash)" = "$($C2 getbestblockhash)" ] && return 0; sleep 1; done; return 1; }
sync_blocks; check "$?" "0" "node 2 follows node 1"
# the hex public key behind a wallet address
pk() { py 'import sys,json,re; print(re.match(r"wpq\((.*)\)#", json.load(sys.stdin)["desc"]).group(1))'; }
K1=$($WS getaddressinfo "$($WS getnewmldsaaddress k1)" | pk)
K2=$($WS getaddressinfo "$($WS getnewmldsaaddress k2)" | pk)
K3=$($W3 getaddressinfo "$($W3 getnewmldsaaddress k3)" | pk)
KI=$($MINER getaddressinfo "$($MINER getnewmldsaaddress internal)" | pk)   # internal key: its secret is never used, the key path is closed
check "${#K1} ${#K3} ${#KI}" "2624 2624 2624" "four ML-DSA-44 public keys (1312 bytes)"

TREE="{mldsa_all($K1,$K2),mldsa_all($K3)}"
DESC=$($C1 getdescriptorinfo "wpq($KI,$TREE)" | py 'import sys,json; print(json.load(sys.stdin)["descriptor"])')
check "$(printf '%s' "$DESC" | grep -c '^wpq(.*mldsa_all(.*#........$')" "1" "the descriptor parses and gets a checksum"
check "$($C1 getdescriptorinfo "wpq($KI,{mldsa_all($K1),mldsa_all($K3)})" | py 'import sys,json; print(json.load(sys.stdin)["issolvable"])')" "True" "a script-path descriptor is solvable"
ADDR=$($C1 deriveaddresses "$DESC" | py 'import sys,json; print(json.load(sys.stdin)[0])')
check "${ADDR:0:6}" "bcrt1z" "the address is witness v2"
# branches are sorted (BIP 341), so the order of the two leaves does not matter; the key order inside a leaf does (it is the entry order)
addr_of() { $C1 deriveaddresses "$($C1 getdescriptorinfo "$1" | py 'import sys,json; print(json.load(sys.stdin)["descriptor"])')" | py 'import sys,json; print(json.load(sys.stdin)[0])'; }
check "$(addr_of "wpq($KI,{mldsa_all($K3),mldsa_all($K1,$K2)})")" "$ADDR" "swapping the two leaves gives the same address"
A3=$(addr_of "wpq($KI,{mldsa_all($K2,$K1),mldsa_all($K3)})")
check "$([ "$A3" != "$ADDR" ] && echo different)" "different" "reordering the keys of a leaf gives another address"
# malformed descriptors are refused
for bad in "wpq($KI,mldsa_all($K1)" "wpq($KI,{mldsa_all($K1)})" "wpq($KI,pk($K1))" "wpq($KI,mldsa_all(00))" "wpq($KI,mldsa_all(zz))"; do
    $C1 getdescriptorinfo "$bad" >/dev/null 2>&1 && { say "[FAIL] accepted: ${bad:0:40}..."; fail=1; }
done
say "[PASS] malformed trees are refused"

IMP="[{\"desc\":\"$DESC\",\"timestamp\":\"now\"}]"
check "$($WS importdescriptors "$IMP" | py 'import sys,json; print(json.load(sys.stdin)[0]["success"])')" "True" "ws imports the descriptor"
check "$($W3 importdescriptors "$IMP" | py 'import sys,json; print(json.load(sys.stdin)[0]["success"])')" "True" "w3 imports the descriptor"
check "$($WS getaddressinfo "$ADDR" | py 'import sys,json; print(json.load(sys.stdin)["ismine"])')" "True" "ws recognises the address as its own"
DEST=$($MINER getnewmldsaaddress dest)

fund() { # prints "txid vout"; the coin is 10 coins and the node 2 wallet sees it as well
    local t v
    t=$($MINER sendtoaddress "$ADDR" 10); $C1 generatetoaddress 1 "$M" >/dev/null; sync_blocks
    v=$($C1 getrawtransaction "$t" true "$($C1 getbestblockhash)" | py 'import sys,json; d=json.load(sys.stdin); print([i for i,o in enumerate(d["vout"]) if o["scriptPubKey"].get("address")==sys.argv[1]][0])' "$ADDR")
    echo "$t $v"
}
spend() { # wallet-cli txid vout -> txid of the confirmed spend
    local w="$1" p r h
    p=$($C1 createpsbt "[{\"txid\":\"$2\",\"vout\":$3}]" "[{\"$DEST\":9.999}]")
    p=$($C1 utxoupdatepsbt "$p")
    r=$($w walletprocesspsbt "$p")
    check "$(echo "$r" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "True" "the wallet signs the script-path input" >&2
    h=$($C1 finalizepsbt "$(echo "$r" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
    $C1 sendrawtransaction "$h"
}

say "== leaf A: ws holds K1 and K2 =="
read -r T1 V1 <<<"$(fund)"
check "$($WS listunspent 1 9999 "[\"$ADDR\"]" | py 'import sys,json; print(len(json.load(sys.stdin)))')" "1" "ws lists the script-path coin"
TX1=$(spend "$WS" "$T1" "$V1"); check "${#TX1}" "64" "leaf A spend accepted"
$C1 generatetoaddress 1 "$M" >/dev/null; sync_blocks
check "$($C2 getrawtransaction "$TX1" true "$($C2 getbestblockhash)" | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w), w[2][:6])')" "3 510201" "node 2 sees the confirmed spend: leaf, control block, two attestation entries"
check "$($C2 getrawtransaction "$TX1" true $($C2 getbestblockhash) | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "node 2 confirmed leaf A"

say "== leaf B: w3 on node 2 holds K3 =="
read -r T2 V2 <<<"$(fund)"
TX2=$(spend "$W3" "$T2" "$V2"); check "${#TX2}" "64" "leaf B spend accepted"
$C1 generatetoaddress 1 "$M" >/dev/null; sync_blocks
check "$($C1 getrawtransaction "$TX2" true "$($C1 getbestblockhash)" | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w), w[2][:6])')" "3 510101" "node 1 sees the confirmed spend: one attestation entry"
check "$($C1 getrawtransaction "$TX2" true $($C1 getbestblockhash) | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "node 1 confirmed leaf B"
check "$($C1 gettxout "$T1" "$V1" | wc -c) $($C2 gettxout "$T2" "$V2" | wc -c)" "0 0" "both script-path coins are spent on both nodes"

say "== a wallet that holds no leaf key cannot sign =="
read -r T3 V3 <<<"$(fund)"
P=$($C1 utxoupdatepsbt "$($C1 createpsbt "[{\"txid\":\"$T3\",\"vout\":$V3}]" "[{\"$DEST\":9.999}]")")
R=$($MINER walletprocesspsbt "$P")
check "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "False" "miner (descriptor not imported, no leaf key) adds nothing"

[ $fail -eq 0 ] && say "V2 DESCRIPTOR SCRIPTPATH OK" || say "V2 DESCRIPTOR SCRIPTPATH FAILED"
exit $fail
