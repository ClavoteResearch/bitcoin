#!/bin/bash
# Qcoin dust and block-weight policy for witness v2 ML-DSA spends (regtest):
#  - a standard ML-DSA spend (about 1 kvB) is accepted by the mempool;
#  - an output below the v2 dust threshold (3054 sat at 3000 sat/kvB) is rejected as dust and one just above is accepted;
#  - the block weight limit is 8,000,000 (getblocktemplate weightlimit) and a block of about 1100 independent spends
#    (more than 4,000,000 WU, which the Bitcoin limit would refuse) is mined and connected, so neither the weight
#    nor the sigop accounting caps ML-DSA spends below the new limit.
# Works with the default build. Usage: regtest_v2_policy.sh [path/to/build/bin]
#   EXPERIMENTAL=1 regtest_v2_policy.sh [bin]   for a QCOIN_WITNESS_V2_EXPERIMENTAL build, whose dust threshold assumes an ML-DSA-87
#   spend (5,670 sat instead of 3,054; see regtest_v2_policy_large.sh)
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-policy.XXXX")
RPCPORT=29442
NSPENDS=${NSPENDS:-1100}
fail=0
if [ "${EXPERIMENTAL:-0}" = 1 ]; then DUST_BAD=0.00005600; DUST_OK=0.00005700; else DUST_BAD=0.00003000; DUST_OK=0.00003100; fi
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }

"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29443 -listen=0 -walletsigscheme=mldsa44 >/dev/null
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
trap '$CLI stop >/dev/null 2>&1; sleep 2; rm -rf "$D"' EXIT
$CLI createwallet w >/dev/null
W="$CLI -rpcwallet=w"
A=$($W getnewmldsaaddress)
$CLI generatetoaddress 101 "$A" >/dev/null

say "== limits =="
check "$($CLI getblocktemplate '{"rules":["segwit"]}' | py 'import sys,json; print(json.load(sys.stdin)["weightlimit"])')" "8000000" "getblocktemplate weightlimit is the Qcoin limit"
check "$($CLI getmempoolinfo | py 'import sys,json; print(json.load(sys.stdin)["minrelaytxfee"] >= 0)')" "True" "node answers mempool queries"

say "== dust threshold for a v2 output =="
B=$($W getnewmldsaaddress)
CHG=$($W getnewmldsaaddress)
spend_to() { # amount_btc -> testmempoolaccept "allowed reason": spend one wallet coin, pay amount to B, rest (minus 0.001 fee) to CHG
    local u raw signed
    u=$($W listunspent 1 9999999 '[]' true | py 'import sys,json; u=max((x for x in json.load(sys.stdin) if x["spendable"]), key=lambda x: x["amount"]); print(u["txid"], u["vout"], u["amount"])')
    set -- $u "$1"
    raw=$($CLI createrawtransaction "[{\"txid\":\"$1\",\"vout\":$2}]" "[{\"$B\":$4},{\"$CHG\":$(py 'import sys; print(round(float(sys.argv[1])-float(sys.argv[2])-0.001, 8))' "$3" "$4")}]")
    signed=$($W signrawtransactionwithwallet "$raw" | py 'import sys,json; d=json.load(sys.stdin); print(d["hex"] if d["complete"] else "")')
    $CLI testmempoolaccept "[\"$signed\"]" 0 | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))'
}
check "$(spend_to $DUST_BAD)" "False dust" "a $DUST_BAD v2 output is dust"
check "$(spend_to $DUST_OK)" "True " "a $DUST_OK v2 output is standard"
check "$(spend_to 1.0)" "True " "a 1 BTC-unit v2 payment is standard"

say "== a standard ML-DSA spend confirms =="
TX=$($W sendtoaddress "$B" 1.0)
V=$($CLI getmempoolentry "$TX" | py 'import sys,json; print(json.load(sys.stdin)["vsize"])')
check "$(py 'import sys; v=int(sys.argv[1]); print(900 <= v <= 1200)' "$V")" "True" "vsize is about 1 kvB ($V vB)"
$CLI generatetoaddress 1 "$A" >/dev/null
check "$($W gettransaction "$TX" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"] >= 1)')" "True" "spend confirmed"

say "== one block above 4 MWU holds more than 1000 spends =="
SPLIT=$(py '
import sys, json, subprocess
cli = sys.argv[1].split()
w = ["-rpcwallet=w"]
def run(*a, wallet=True):
    return subprocess.check_output(cli + (w if wallet else []) + list(a)).decode().strip()
n = int(sys.argv[2])
addrs = [run("getnewmldsaaddress") for _ in range(n)]
out = {a: 0.01 for a in addrs}
print(run("sendmany", "", json.dumps(out)))
' "$CLI" "$NSPENDS")
$CLI generatetoaddress 1 "$A" >/dev/null
check "$($W gettransaction "$SPLIT" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"] >= 1)')" "True" "split into $NSPENDS outputs confirmed"
RES=$(py '
import sys, json, subprocess
cli = sys.argv[1].split()
w = ["-rpcwallet=w"]
def run(*a, wallet=True, stdin=None):
    p = subprocess.run(cli + (w if wallet else []) + list(a), capture_output=True, text=True)
    return p.returncode, p.stdout.strip() + p.stderr.strip()
n = int(sys.argv[2])
rc, o = run("listunspent", "1", "9999999", "[]", "true")
utxos = [u for u in json.loads(o) if abs(u["amount"] - 0.01) < 1e-9][:n]
dest = run("getnewmldsaaddress")[1]
ok = 0
for u in utxos:
    raw = run("-named", "createrawtransaction", "inputs=[{\"txid\":\"%s\",\"vout\":%d}]" % (u["txid"], u["vout"]), "outputs={\"%s\":0.0099}" % dest, wallet=False)[1]
    rc, s = run("signrawtransactionwithwallet", raw)
    hx = json.loads(s)["hex"]
    rc, o = run("sendrawtransaction", hx, wallet=False)
    ok += (rc == 0)
print(len(utxos), ok)
' "$CLI" "$NSPENDS")
set -- $RES
check "$2" "$NSPENDS" "$NSPENDS independent ML-DSA spends accepted into the mempool (of $1 found)"
BH=$($CLI generatetoaddress 1 "$A" | py 'import sys,json; print(json.load(sys.stdin)[0])')
BLK=$($CLI getblock "$BH" 1)
WGT=$(echo "$BLK" | py 'import sys,json; print(json.load(sys.stdin)["weight"])')
NTX=$(echo "$BLK" | py 'import sys,json; print(json.load(sys.stdin)["nTx"])')
say "block weight $WGT WU, $NTX transactions"
check "$(py 'import sys; print(4000000 < int(sys.argv[1]) <= 8000000)' "$WGT")" "True" "block weight is above the Bitcoin 4 MWU limit and within 8 MWU"
check "$($CLI getbestblockhash)" "$BH" "node connected the large block"
check "$($CLI getmempoolinfo | py 'import sys,json; print(json.load(sys.stdin)["size"])')" "0" "mempool drained into that single block"

[ $fail -eq 0 ] && say "V2 POLICY OK" || say "V2 POLICY FAILED"
exit $fail
