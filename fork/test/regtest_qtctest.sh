#!/bin/bash
# Qcoin testnet chain ("qtctest") bring-up: starts, reports the mldsav2 deployment active from genesis, mines at the
# RandomX proof of work at nBits 2000ffff (about 256 hashes per block; generatetoaddress with a large maxtries), issues tq1z addresses, accepts a witness v2
# ML-DSA spend, and confirms the value rule: ordinary (ECDSA) outputs cannot carry value. Works with the default build.
# Usage: regtest_qtctest.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-qtct.XXXX")
RPCPORT=29332
GENESIS=0090e8f80f8d0caecfde17644580d7bd83ef14f243c2f5a26e0d54996c09f11b
COINBASE=04ffff001d01043f51636f696e20746573746e65742033302f4f63742f32303236204d4c2d445341207769746e657373207632206163746976652066726f6d2067656e65736973
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
# generatetoaddress maxtries is a 32-bit total budget for the call (about 256 RandomX hashes per block expected at 2000ffff),
# so mine one block per call with a 2e9 budget each.
mine() { local n=$1 addr=$2 i; for ((i=0;i<n;i++)); do $CLI generatetoaddress 1 "$addr" 2000000000 >/dev/null; done; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }

"$BIN/bitcoind" -chain=qtctest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29333 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -chain=qtctest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done

say "== chain identity =="
check "$($CLI getblockchaininfo | jget chain)" "qtctest" "getblockchaininfo reports chain qtctest"
check "$($CLI getblockhash 0)" "$GENESIS" "genesis hash"
check "$($CLI getblock "$GENESIS" 2 | jget tx.0.vin.0.coinbase)" "$COINBASE" "genesis coinbase carries the Qcoin testnet message"
check "$($CLI getblock "$GENESIS" | py 'import sys,json; d=json.load(sys.stdin); print(d["time"], d["nonce"], d["bits"])')" "1761782400 551 2000ffff" "genesis time/nonce/bits"
check "$(ls -d "$D/qtctest" 2>/dev/null | wc -l)" "1" "data directory is <datadir>/qtctest"
check "$($CLI getdeploymentinfo | py 'import sys,json; d=json.load(sys.stdin)["deployments"]["mldsav2"]; print(d["type"], d["active"], d["height"])')" "buried True 0" "mldsav2 active from genesis"
check "$($CLI getnetworkinfo | py 'import sys,json; d=json.load(sys.stdin); print(d["localservicesnames"][0] if d["localservicesnames"] else "-")' 2>/dev/null | grep -c . )" "1" "node is up"

say "== on-demand mining and ML-DSA addresses =="
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
M=$($W getnewmldsaaddress mine)
check "${M:0:4}" "tq1z" "mining address is an ML-DSA witness v2 address with the tq HRP"
mine 101 "$M"
check "$($CLI getblockcount)" "101" "101 RandomX blocks mined at 2000ffff (one call per block, maxtries 2e9)"
A0=$($W getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
A1=$($W getnewmldsaaddress t1)
check "${A0:0:4} ${A1:0:4}" "tq1z tq1z" "ML-DSA witness v2 addresses use tq1z"
check "$($CLI validateaddress "$A1" | py 'import sys,json; d=json.load(sys.stdin); print(d["isvalid"], d["witness_version"])')" "True 2" "tq1z address decodes as witness version 2"

say "== v2 receive and spend =="
$W sendtoaddress "$A1" 7 >/dev/null; mine 1 "$M"
check "$($W listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]]; print(len(u), u[0]["solvable"] if u else "-")' "$A1")" "1 True" "v2 coin received and solvable"
IN=$($W listunspent | py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$A1")
TX=$($W -named send outputs="{\"$M\":3}" options="{\"inputs\":$IN,\"add_inputs\":false}" | jget txid)
check "${#TX}" "64" "spend from the tq1z coin accepted by the mempool"
check "$($CLI getrawtransaction "$TX" true | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w[0])//2, w[0][:6])')" "3735 510101" "witness is a 3735-byte ML-DSA-44 attestation"
mine 1 "$M"
check "$($W gettransaction "$TX" | jget confirmations)" "1" "spend confirmed on qtctest"

check "$($W gettransaction "$TX" true true | py 'import sys,json; o=json.load(sys.stdin)["decoded"]["vout"]; print(len(o), all(v["scriptPubKey"]["hex"].startswith("5220") for v in o))')" "2 True" "payment and change are both ML-DSA outputs"

say "== value rule: ordinary (ECDSA) outputs cannot carry value on qtctest =="
check "$($W getnewaddress 2>&1 | grep -c 'Use getnewmldsaaddress')" "1" "getnewaddress refuses and points at getnewmldsaaddress"
E=$($CLI deriveaddresses "$($CLI getdescriptorinfo "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["descriptor"])')" | jget 0)
check "${E:0:4}" "tq1q" "a P2WPKH address can still be formed outside the wallet"
check "$($W sendtoaddress "$E" 1 2>&1 | grep -c 'cannot carry value')" "1" "wallet refuses to pay it"
U=$($W listunspent | py 'import sys,json; u=max((x for x in json.load(sys.stdin) if x["spendable"]), key=lambda x: x["amount"]); print(u["txid"], u["vout"], u["amount"])')
set -- $U
RAW=$($CLI createrawtransaction "[{\"txid\":\"$1\",\"vout\":$2}]" "{\"$E\":$(py 'import sys; print(round(float(sys.argv[1])-0.001, 8))' "$3")}")
SIGNED=$($W signrawtransactionwithwallet "$RAW" | jget hex)
check "$($CLI testmempoolaccept "[\"$SIGNED\"]" | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))')" "False bad-txns-output-not-mldsa" "raw P2WPKH payment is consensus-rejected by the mempool"
check "$($CLI generatetoaddress 1 "$E" 2000000000 2>&1 | grep -c 'bad-txns-output-not-mldsa')" "1" "a block paying its coinbase to P2WPKH is rejected"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "QTCTEST CHAIN OK" || say "QTCTEST CHAIN FAILED"
exit $fail
