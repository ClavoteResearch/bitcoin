#!/bin/bash
# Qcoin: canonical ML-DSA signature encoding on the script path (regtest). A valid 2-of-2 script-path spend is built with two
# wallets (PSBT flow, not broadcast); then the hint area of the signature of entry 0, and separately of entry 1, is re-encoded
# non-canonically (an unused hint-index slot set to 1: the same hint vector in different bytes). Each malleated transaction must
# be rejected, as a transaction and as part of a block (consensus, not only policy), while the original is accepted and confirms.
# Works with the default build. Usage: regtest_v2_canonical_scriptpath.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2cs.XXXX")
RPCPORT=19455
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=19456 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
trap '$CLI stop >/dev/null 2>&1; sleep 2; rm -rf "$D"' EXIT
MINER="$CLI -rpcwallet=miner"; W1="$CLI -rpcwallet=w1"; W2="$CLI -rpcwallet=w2"
for w in miner w1 w2; do $CLI createwallet $w >/dev/null; done
M=$($MINER getnewmldsaaddress mine); $CLI generatetoaddress 101 "$M" >/dev/null
pkhash() { py 'import sys,json,hashlib,re; d=json.load(sys.stdin)["desc"]; print(hashlib.sha256(bytes.fromhex(re.match(r"wpq\((.*)\)#", d).group(1))).hexdigest())'; }
H1=$($W1 getaddressinfo "$($W1 getnewmldsaaddress k1)" | pkhash)
H2=$($W2 getaddressinfo "$($W2 getnewmldsaaddress k2)" | pkhash)
eval "$(python3 -I "$HERE/v2_scriptpath_addr.py" "$H1" "$H2" | sed 's/^/SP_/')"
ADDR=$($CLI decodescript "$SP_spk" | py 'import sys,json; print(json.load(sys.stdin)["address"])')
DEST=$($MINER getnewmldsaaddress dest)

say "== build a valid 2-of-2 script-path spend (not broadcast) =="
T=$($MINER sendtoaddress "$ADDR" 10); $CLI generatetoaddress 1 "$M" >/dev/null
V=$($CLI getrawtransaction "$T" true $($CLI getbestblockhash) | py 'import sys,json; d=json.load(sys.stdin); print([i for i,o in enumerate(d["vout"]) if o["scriptPubKey"]["hex"]==sys.argv[1]][0])' "$SP_spk")
P=$($CLI createpsbt "[{\"txid\":\"$T\",\"vout\":$V}]" "[{\"$DEST\":9.999}]")
P=$($CLI addpsbtmldsascriptpath "$($CLI utxoupdatepsbt "$P")" 0 "$SP_leaf" "$SP_control")
P=$($W1 walletprocesspsbt "$P" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')
P=$($W2 walletprocesspsbt "$P" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["psbt"])')
HEX=$($CLI finalizepsbt "$P" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
ATT=$($CLI decoderawtransaction "$HEX" | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; assert len(w)==3; print(w[2])')
check "$(( ${#ATT} / 2 )) ${ATT:0:6}" "7468 510201" "witness holds a two-entry attestation (7468 bytes)"
check "$($CLI testmempoolaccept "[\"$HEX\"]" | py 'import sys,json; print(json.load(sys.stdin)[0]["allowed"])')" "True" "the original spend passes testmempoolaccept"

# set the last unused hint-index slot of entry $1 (0 or 1) to 1: attestation = 0x51 n [param_id pk(1312) sig(2420)]*n;
# sig = c_tilde(32) z(2304) h(84), h = indices[80] counts[4]
mutate() {
    py 'import sys
att = bytearray.fromhex(sys.argv[1]); entry = int(sys.argv[2])
stride = 1 + 1312 + 2420
sig_start = 2 + entry * stride + 1 + 1312
h = sig_start + 2420 - 84
assert att[h + 80 + 3] < 80, "all hint slots in use (astronomically unlikely); rerun"
assert att[h + 79] == 0
att[h + 79] = 1
print(att.hex())' "$ATT" "$1"
}
for entry in 0 1; do
    say "== entry $entry: unused hint slot set to 1 =="
    BADATT=$(mutate $entry)
    BADHEX=$(py 'import sys; h, a, b = sys.argv[1:]; assert h.count(a) == 1; print(h.replace(a, b))' "$HEX" "$ATT" "$BADATT")
    check "${#BADHEX}" "${#HEX}" "malleated transaction has the same size"
    RES=$($CLI testmempoolaccept "[\"$BADHEX\"]" | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))')
    check "${RES%% *}" "False" "malleated script-path spend rejected by testmempoolaccept"
    check "$(printf '%s' "$RES" | grep -c 'Non-canonical ML-DSA signature encoding')" "1" "reject reason names the canonical-encoding rule"
    H0=$($CLI getblockcount)
    GB=$($CLI generateblock "$M" "[\"$BADHEX\"]" 2>&1 || true)
    check "$(printf '%s' "$GB" | grep -c 'Non-canonical ML-DSA signature encoding')" "1" "a block containing it is invalid (consensus): $(printf '%s' "$GB" | tr '\n' ' ' | cut -c1-120)"
    check "$($CLI getblockcount)" "$H0" "the chain did not advance"
done

say "== the canonical original is still valid and confirms =="
TX=$($CLI sendrawtransaction "$HEX")
check "${#TX}" "64" "original script-path spend accepted"
$CLI generatetoaddress 1 "$M" >/dev/null
check "$($CLI getrawtransaction "$TX" true $($CLI getbestblockhash) | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "original script-path spend confirmed"

[ $fail -eq 0 ] && say "V2 CANONICAL SCRIPTPATH OK" || say "V2 CANONICAL SCRIPTPATH FAILED"
exit $fail
