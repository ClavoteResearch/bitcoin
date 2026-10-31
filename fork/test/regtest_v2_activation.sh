#!/bin/bash
# Qcoin / Option B: DEPLOYMENT_MLDSA_V2 activation. With -testactivationheight=mldsav2@300 the same signed v2 spend is
# rejected by the mempool before height 300 and accepted after; getdeploymentinfo reflects the state.
# Works with the DEFAULT build (activation is runtime).   Usage: regtest_v2_activation.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2a.XXXX")
RPCPORT=19255
ACT=300
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }

"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=19256 -listen=0 -walletsigscheme=mldsa44 -testactivationheight=mldsav2@$ACT >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewmldsaaddress mine)
# Before activation v2 coins cannot be spent (the mempool treats v2 as a reserved witness version), so the miner mines
# its pre-activation rewards to its own P2WPKH address. getnewaddress is refused on this chain, so derive it from the
# wallet's wpkh() descriptor (listdescriptors + deriveaddresses); the coins are ismine and spendable pre-activation.
EM=$($CLI deriveaddresses "$($MINER listdescriptors | py 'import sys,json; print([d["desc"] for d in json.load(sys.stdin)["descriptors"] if d["desc"].startswith("wpkh(") and not d["internal"]][0])')" "[0,0]" | jget 0)
check "${EM:0:6} $($MINER getaddressinfo "$EM" | jget ismine)" "bcrt1q True" "miner's own P2WPKH address derived from its descriptor"
$CLI generatetoaddress 101 "$EM" >/dev/null
E=$($CLI deriveaddresses "$($CLI getdescriptorinfo "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["descriptor"])')" | jget 0)
$CLI generatetoaddress 1 "$E" >/dev/null
check "$($CLI getblockcount)" "102" "before activation an ECDSA (P2WPKH) coinbase is still consensus-valid (value rule gated on mldsav2)"

say "== before activation (height $($CLI getblockcount), activates at $ACT) =="
check "$($CLI getdeploymentinfo | py 'import sys,json; d=json.load(sys.stdin)["deployments"]["mldsav2"]; print(d["type"], d["active"], d["height"])')" "buried False $ACT" "getdeploymentinfo: mldsav2 buried, inactive, height $ACT"
A0=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
$MINER sendtoaddress "$A0" 5 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ getbalance)" "5.00000000" "v2 output received (outputs are always standard)"
# Build and sign the spend via PSBT so nothing is recorded in the wallet if broadcast fails.
PSBT=$($PQ -named walletcreatefundedpsbt inputs='[]' outputs="{\"$M\":5}" options='{"subtractFeeFromOutputs":[0]}' | jget psbt)
SIGNED=$($PQ walletprocesspsbt "$PSBT" | jget psbt)
HEX=$($CLI finalizepsbt "$SIGNED" | jget hex)
check "$([ -n "$HEX" ] && echo signed)" "signed" "wallet can sign a v2 spend before activation"
TMA=$($CLI testmempoolaccept "[\"$HEX\"]")
check "$(printf '%s' "$TMA" | py 'import sys,json; r=json.load(sys.stdin)[0]; print(r["allowed"], r.get("reject-reason",""))')" "False mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)" "testmempoolaccept rejects the v2 spend before activation"
check "$($CLI sendrawtransaction "$HEX" 2>&1 | grep -c 'soft-fork upgrades')" "1" "sendrawtransaction rejects it before activation"
check "$($CLI getrawmempool | py 'import sys,json; print(len(json.load(sys.stdin)))')" "0" "mempool empty"

say "== mine to activation height =="
$CLI generatetoaddress $((ACT - $($CLI getblockcount))) "$M" >/dev/null
check "$($CLI getblockcount)" "$ACT" "chain at height $ACT"
check "$($CLI getdeploymentinfo | py 'import sys,json; d=json.load(sys.stdin)["deployments"]["mldsav2"]; print(d["active"])')" "True" "getdeploymentinfo: mldsav2 active"
check "$($CLI generatetoaddress 1 "$E" 2>&1 | grep -c 'bad-txns-output-not-mldsa')" "1" "after activation an ECDSA coinbase is rejected (value rule active)"
check "$($CLI testmempoolaccept "[\"$HEX\"]" | py 'import sys,json; print(json.load(sys.stdin)[0]["allowed"])')" "True" "the same signed transaction is now accepted by testmempoolaccept"
TX=$($CLI sendrawtransaction "$HEX" 2>&1)
check "${#TX}" "64" "sendrawtransaction accepts it after activation"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($MINER gettransaction "$TX" | jget confirmations)" "1" "spend confirmed in a block"

say "== never-active chain parameter: height INT_MAX =="
$CLI stop >/dev/null; sleep 2
D2=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2a.XXXX")
"$BIN/bitcoind" -regtest -datadir="$D2" -daemon -rpcport=$RPCPORT -port=19256 -listen=0 -testactivationheight=mldsav2@2147483646 >/dev/null
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
CLI2="$BIN/bitcoin-cli -regtest -datadir=$D2 -rpcport=$RPCPORT"
check "$($CLI2 getdeploymentinfo | py 'import sys,json; d=json.load(sys.stdin)["deployments"]["mldsav2"]; print(d["active"], d["height"])')" "False 2147483646" "high activation height keeps it inactive"
$CLI2 stop >/dev/null
[ $fail -eq 0 ] && say "V2 ACTIVATION REGTEST OK" || say "V2 ACTIVATION REGTEST FAILED"
exit $fail
