#!/bin/bash
# Qcoin / Option B: a witness v2 spend whose ML-DSA-44 signature is re-encoded non-canonically must be
# rejected by the node, while the original transaction is accepted. The mutation touches only the hint
# area of the FIPS 204 signature (an unused index slot after the last hint is set to 1), which leaves the
# hint vector itself unchanged, so this is exactly the malleation the canonical-encoding rule exists for.
# Works with the default build.
# Usage: regtest_v2_canonical.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2c.XXXX")
RPCPORT=18775
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }

"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18776 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
M=$($MINER getnewmldsaaddress mine); $CLI generatetoaddress 101 "$M" >/dev/null
PQADDR=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
$MINER sendtoaddress "$PQADDR" 10 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null

say "== build a signed v2 spend without broadcasting it =="
HEX=$($PQ -named send outputs="{\"$M\":5}" options='{"add_to_wallet":false}' | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
ATT=$($CLI decoderawtransaction "$HEX" | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; assert len(w)==1; print(w[0])')
check "$(( ${#ATT} / 2 )) ${ATT:0:6}" "3735 510101" "witness is a single 3735-byte ML-DSA-44 attestation"
check "$($CLI testmempoolaccept "[\"$HEX\"]" | py 'import sys,json; print(json.load(sys.stdin)[0]["allowed"])')" "True" "original spend passes testmempoolaccept"

say "== malleate: set an unused hint-index slot to 1 (same hint vector, different encoding) =="
# attestation = 0x51 || 0x01 || param_id || pk(1312) || sig(2420); sig = c_tilde(32) || z(2304) || h(84); h = indices[80] || counts[4]
MUT=$(py 'import sys
att = bytearray.fromhex(sys.argv[1]); sig_off = 3 + 1312; h_off = sig_off + 2420 - 84; omega, k = 80, 4
total = att[h_off + omega + k - 1]
assert total < omega, "all hint slots used (astronomically unlikely); rerun"
slot = h_off + omega - 1
assert att[slot] == 0, "slot not zero?"
att[slot] = 1
print(att.hex(), total)' "$ATT")
BADATT=${MUT% *}; HINTS=${MUT##* }
say "signature uses $HINTS of 80 hint slots; slot 79 set to 1"
BADHEX=$(py 'import sys; h, a, b = sys.argv[1:]; assert h.count(a) == 1; print(h.replace(a, b))' "$HEX" "$ATT" "$BADATT")
check "${#BADHEX}" "${#HEX}" "malleated transaction has the same size"
check "$($CLI decoderawtransaction "$BADHEX" | py 'import sys,json; d=json.load(sys.stdin); print(d["txid"]==sys.argv[1], d["hash"]==sys.argv[2])' "$($CLI decoderawtransaction "$HEX" | py 'import sys,json; print(json.load(sys.stdin)["txid"])')" "$($CLI decoderawtransaction "$HEX" | py 'import sys,json; print(json.load(sys.stdin)["hash"])')")" "True False" "same txid, different wtxid (witness-only malleation)"
RES=$($CLI testmempoolaccept "[\"$BADHEX\"]" | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))')
check "${RES%% *}" "False" "malleated spend rejected by testmempoolaccept"
check "$(printf '%s' "$RES" | grep -c 'Non-canonical ML-DSA signature encoding')" "1" "reject reason names the canonical-encoding rule"
say "reject-reason: ${RES#* }"
ERR=$($CLI sendrawtransaction "$BADHEX" 2>&1 || true)
check "$(printf '%s' "$ERR" | grep -c 'Non-canonical ML-DSA signature encoding')" "1" "sendrawtransaction of the malleated spend fails with the same reason"

say "== consensus, not only policy: a block that contains the malleated spend is invalid =="
H0=$($CLI getblockcount)
GB=$($CLI generateblock "$M" "[\"$BADHEX\"]" 2>&1 || true)
check "$(printf '%s' "$GB" | grep -c 'block-script-verify-flag-failed (Non-canonical ML-DSA signature encoding)')" "1" "generateblock refuses the block (block-script-verify-flag-failed: Non-canonical ML-DSA signature encoding)"
check "$($CLI getblockcount)" "$H0" "the chain did not advance"

say "== the canonical original is still valid and confirms =="
TX=$($CLI sendrawtransaction "$HEX")
check "${#TX}" "64" "original spend accepted"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "original spend confirmed"

$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 CANONICAL REGTEST OK" || say "V2 CANONICAL REGTEST FAILED"
exit $fail
