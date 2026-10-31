#!/bin/bash
# Qcoin / Option B: PSBT flow for witness v2 ML-DSA inputs. A watch-only wallet (wpq() descriptor, no secret)
# creates the PSBT, the key-holding wallet completes it, finalizepsbt + sendrawtransaction confirm. Then the
# same flow across a node restart.  Requires QCOIN_WITNESS_V2_EXPERIMENTAL=ON + wallet.   Usage: regtest_v2_psbt.sh [bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2p.XXXX")
RPCPORT=19155
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
start_node() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=19156 -listen=0 -walletsigscheme=mldsa44 $1 >/dev/null
  for i in $(seq 1 60); do "$BIN/bitcoin-cli" -regtest -datadir="$D" -rpcport=$RPCPORT getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
jget() { py 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)' "$1"; }

start_node ""
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
MINER="$CLI -rpcwallet=miner"; SIGNER="$CLI -rpcwallet=signer"; WATCH="$CLI -rpcwallet=watch"
$CLI createwallet miner >/dev/null; $CLI createwallet signer >/dev/null
$CLI -named createwallet wallet_name=watch disable_private_keys=true blank=true >/dev/null
M=$($MINER getnewmldsaaddress mine); $CLI generatetoaddress 101 "$M" >/dev/null

say "== watch-only wallet imports the signer's wpq() descriptor =="
A0=$($SIGNER getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
WPQ=$($SIGNER listdescriptors | py 'import sys,json; print([d["desc"] for d in json.load(sys.stdin)["descriptors"] if d["desc"].startswith("wpq(")][0])')
check "${WPQ:0:4}" "wpq(" "signer exposes a wpq() descriptor"
IMP=$($WATCH importdescriptors "[{\"desc\":\"$WPQ\",\"timestamp\":\"now\",\"label\":\"pq\"}]" | jget 0.success)
check "$IMP" "True" "watch wallet imported wpq() (public key only)"
check "$($WATCH getaddressinfo "$A0" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "True True" "watch wallet: v2 address ismine and solvable without the secret"

say "== fund, then watch wallet creates an unsigned PSBT =="
$MINER sendtoaddress "$A0" 5 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
check "$($WATCH getbalance)" "5.00000000" "watch wallet sees the v2 coin"
PSBT=$($WATCH -named walletcreatefundedpsbt inputs='[]' outputs="{\"$M\":5}" options='{"subtractFeeFromOutputs":[0]}' | jget psbt)
check "${PSBT:0:6}" "cHNidP" "walletcreatefundedpsbt returned a PSBT"
DEC=$($CLI decodepsbt "$PSBT")
check "$(printf '%s' "$DEC" | py 'import sys,json; d=json.load(sys.stdin); i=d["inputs"][0]; p=i.get("proprietary",[]); print(len(p), p[0]["identifier"] if p else "-", p[0]["subtype"] if p else "-", p[0]["value"][:2] if p else "-", len(p[0]["value"])//2 if p else "-")')" "1 71636f696e 0 01 1313" "proprietary field: identifier 'qcoin', subtype 0, value = 0x01 || 1312-byte ML-DSA-44 pubkey"
check "$(printf '%s' "$DEC" | py 'import sys,json; i=json.load(sys.stdin)["inputs"][0]; print("final_scriptwitness" in i, ("witness_utxo" in i) or ("non_witness_utxo" in i))')" "False True" "unsigned: no final witness, utxo present"
check "$($WATCH walletprocesspsbt "$PSBT" | jget complete)" "False" "watch wallet cannot complete it (no secret)"

say "== signer completes, finalise, broadcast =="
PROC=$($SIGNER walletprocesspsbt "$PSBT")
check "$(printf '%s' "$PROC" | jget complete)" "True" "signer wallet completes the PSBT"
SIGNED=$(printf '%s' "$PROC" | jget psbt)
check "$($CLI decodepsbt "$SIGNED" | py 'import sys,json; i=json.load(sys.stdin)["inputs"][0]; w=i["final_scriptwitness"]; print(len(w), len(w[0])//2, w[0][:6])')" "1 3735 510101" "final_scriptwitness is the 3735-byte attestation"
check "$($CLI analyzepsbt "$SIGNED" | jget next)" "extractor" "analyzepsbt: ready for extraction"
FIN=$($CLI finalizepsbt "$SIGNED")
check "$(printf '%s' "$FIN" | jget complete)" "True" "finalizepsbt complete"
TX=$($CLI sendrawtransaction "$(printf '%s' "$FIN" | jget hex)" 2>&1)
check "${#TX}" "64" "sendrawtransaction accepted the extracted transaction"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($MINER gettransaction "$TX" | jget confirmations)" "1" "spend confirmed (miner received the output)"
check "$($WATCH getbalance)" "0.00000000" "watch wallet balance spent"

say "== across a restart: signer creates unsigned PSBT, restarts, then signs =="
$MINER sendtoaddress "$A0" 3 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
PSBT2=$($SIGNER -named walletcreatefundedpsbt inputs='[]' outputs="{\"$M\":3}" options='{"subtractFeeFromOutputs":[0]}' | jget psbt)
check "$($CLI decodepsbt "$PSBT2" | py 'import sys,json; i=json.load(sys.stdin)["inputs"][0]; print("final_scriptwitness" in i, len(i.get("proprietary",[])))')" "False 1" "unsigned PSBT from the signer carries the pubkey field too"
$CLI stop >/dev/null; sleep 2
start_node "-wallet=signer -wallet=miner"
PROC2=$($SIGNER walletprocesspsbt "$PSBT2")
check "$(printf '%s' "$PROC2" | jget complete)" "True" "after restart the signer completes the PSBT"
FIN2=$($CLI finalizepsbt "$(printf '%s' "$PROC2" | jget psbt)")
TX2=$($CLI sendrawtransaction "$(printf '%s' "$FIN2" | jget hex)" 2>&1)
check "${#TX2}" "64" "second spend broadcast"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($MINER gettransaction "$TX2" | jget confirmations)" "1" "second spend confirmed"

say "== sanity =="
BAD=$(printf '%s' "$PROC2" | jget psbt)
check "$($CLI finalizepsbt "$BAD" | jget complete)" "True" "sanity: untampered signed PSBT finalises"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 PSBT REGTEST OK" || say "V2 PSBT REGTEST FAILED"
exit $fail
