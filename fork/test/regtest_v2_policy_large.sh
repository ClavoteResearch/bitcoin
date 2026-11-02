#!/bin/bash
# Qcoin: relay policy for a large (ML-DSA-87, about 7.2 kB witness) input. Needs a QCOIN_WITNESS_V2_EXPERIMENTAL build
# (param id 0x7f); skips on other builds.
#  - measures the virtual size and the minimum relay fee of a one-input ML-DSA-87 key-path spend and of a one-input script-path
#    spend (descriptor wpq(KI,mldsa_all(K))), next to the computed P2WPKH numbers;
#  - the v2 dust threshold of such a build is 5,670 sat at 3,000 sat/kvB (largest accepted spend: ML-DSA-87): an output of 5,600
#    sat is rejected as dust, one of 5,700 sat is accepted, and 3,100 sat (above the ML-DSA-44 threshold of 3,054) is dust.
# Usage: regtest_v2_policy_large.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-policylarge.XXXX")
RPCPORT=29452
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
"$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=29453 -listen=0 -walletsigscheme=mldsa87 >/dev/null 2>&1
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
UP=0
for i in $(seq 1 60); do $CLI getblockchaininfo >/dev/null 2>&1 && { UP=1; break; }; sleep 1; done
if [ $UP -eq 0 ]; then say "SKIP: this build does not accept -walletsigscheme=mldsa87 (needs QCOIN_WITNESS_V2_EXPERIMENTAL)"; rm -rf "$D"; exit 0; fi
trap '$CLI stop >/dev/null 2>&1; sleep 2; rm -rf "$D"' EXIT
$CLI createwallet w >/dev/null; $CLI createwallet ws >/dev/null
W="$CLI -rpcwallet=w"; WS="$CLI -rpcwallet=ws"
A=$($W getnewmldsaaddress)
if [ "$($W getaddressinfo "$A" | py 'import sys,json,re; print(len(re.match(r"wpq\((.*)\)#", json.load(sys.stdin)["desc"]).group(1)))' 2>/dev/null)" != "5184" ]; then
    say "SKIP: this build creates no ML-DSA-87 keys (needs QCOIN_WITNESS_V2_EXPERIMENTAL)"; exit 0
fi
$CLI generatetoaddress 101 "$A" >/dev/null
MINRELAY_SATKVB=$(py 'import sys,json; print(round(json.load(sys.stdin)["minrelaytxfee"]*1e8))' <<<"$($CLI getmempoolinfo)")
say "minrelaytxfee $MINRELAY_SATKVB sat/kvB, dustrelayfee 3000 sat/kvB (defaults)"
txinfo() { # txid -> "vsize weight"
    $CLI getrawtransaction "$1" true "$($CLI getbestblockhash)" | py 'import sys,json; d=json.load(sys.stdin); print(d["vsize"], d["weight"])'
}
minfee() { py 'import sys,math; print(math.ceil(int(sys.argv[1]) * int(sys.argv[2]) / 1000))' "$1" "$MINRELAY_SATKVB"; }

say "== key-path spend, one ML-DSA-87 input =="
B=$($W getnewmldsaaddress)
TX=$($W sendtoaddress "$B" 1.0); $CLI generatetoaddress 1 "$A" >/dev/null
read -r KV KW <<<"$(txinfo "$TX")"
KIN=$($CLI getrawtransaction "$TX" true "$($CLI getbestblockhash)" | py 'import sys,json; print(len(json.load(sys.stdin)["vin"]))')
say "key path: $KIN input(s), $KV vB ($KW WU), minimum relay fee $(minfee "$KV") sat"
check "$(py 'import sys; print(1700 <= int(sys.argv[1]) <= 2100)' "$KV")" "True" "one-input ML-DSA-87 key-path payment is about 1.9 kvB"

say "== script-path spend, one ML-DSA-87 input =="
pk() { py 'import sys,json,re; print(re.match(r"wpq\((.*)\)#", json.load(sys.stdin)["desc"]).group(1))'; }
K=$($WS getaddressinfo "$($WS getnewmldsaaddress k)" | pk)
KI=$($WS getaddressinfo "$($WS getnewmldsaaddress i)" | pk)
check "${#K}" "5184" "ML-DSA-87 public key (2592 bytes)"
DESC=$($CLI getdescriptorinfo "wpq($KI,mldsa_all($K))" | py 'import sys,json; print(json.load(sys.stdin)["descriptor"])')
SADDR=$($CLI deriveaddresses "$DESC" | py 'import sys,json; print(json.load(sys.stdin)[0])')
check "$($WS importdescriptors "[{\"desc\":\"$DESC\",\"timestamp\":\"now\"}]" | py 'import sys,json; print(json.load(sys.stdin)[0]["success"])')" "True" "wallet imports the script-path descriptor"
T=$($W sendtoaddress "$SADDR" 10); $CLI generatetoaddress 1 "$A" >/dev/null
V=$($CLI getrawtransaction "$T" true "$($CLI getbestblockhash)" | py 'import sys,json; d=json.load(sys.stdin); print([i for i,o in enumerate(d["vout"]) if o["scriptPubKey"].get("address")==sys.argv[1]][0])' "$SADDR")
DEST=$($W getnewmldsaaddress)
P=$($CLI utxoupdatepsbt "$($CLI createpsbt "[{\"txid\":\"$T\",\"vout\":$V}]" "[{\"$DEST\":9.999}]")")
R=$($WS walletprocesspsbt "$P")
check "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["complete"])')" "True" "wallet signs the script-path input"
HEX=$($CLI finalizepsbt "$(echo "$R" | py 'import sys,json; print(json.load(sys.stdin)["psbt"])')" | py 'import sys,json; d=json.load(sys.stdin); assert d["complete"]; print(d["hex"])')
SV=$($CLI decoderawtransaction "$HEX" | py 'import sys,json; d=json.load(sys.stdin); print(d["vsize"], d["weight"])')
read -r SPV SPW <<<"$SV"
say "script path (1 leaf, 1 key): 1 input, 1 output, $SPV vB ($SPW WU), minimum relay fee $(minfee "$SPV") sat"
STX=$($CLI sendrawtransaction "$HEX"); $CLI generatetoaddress 1 "$A" >/dev/null
check "$($CLI getrawtransaction "$STX" true "$($CLI getbestblockhash)" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "the script-path spend confirmed"

say "== computed P2WPKH reference (1 input, 2 outputs): 141 vB, input 68 vB, minimum relay fee $(minfee 141) sat =="
say "per input: ML-DSA-87 key path $(py 'import sys; print(round(int(sys.argv[1]) - 10.5 - 2 * 43))' "$KV") vB vs 68 vB"

say "== dust threshold for a v2 output in this build =="
B2=$($W getnewmldsaaddress); CHG=$($W getnewmldsaaddress)
spend_to() { # amount_btc -> testmempoolaccept "allowed reason"
    local u raw signed
    u=$($W listunspent 1 9999999 '[]' true | py 'import sys,json; u=max((x for x in json.load(sys.stdin) if x["spendable"]), key=lambda x: x["amount"]); print(u["txid"], u["vout"], u["amount"])')
    set -- $u "$1"
    raw=$($CLI createrawtransaction "[{\"txid\":\"$1\",\"vout\":$2}]" "[{\"$B2\":$4},{\"$CHG\":$(py 'import sys; print(round(float(sys.argv[1])-float(sys.argv[2])-0.001, 8))' "$3" "$4")}]")
    signed=$($W signrawtransactionwithwallet "$raw" | py 'import sys,json; d=json.load(sys.stdin); print(d["hex"] if d["complete"] else "")')
    $CLI testmempoolaccept "[\"$signed\"]" 0 | py 'import sys,json; d=json.load(sys.stdin)[0]; print(d["allowed"], d.get("reject-reason",""))'
}
check "$(spend_to 0.00003100)" "False dust" "a 3100 sat output is dust (above the ML-DSA-44 threshold, below the ML-DSA-87 one)"
check "$(spend_to 0.00005600)" "False dust" "a 5600 sat output is dust"
check "$(spend_to 0.00005700)" "True " "a 5700 sat output is standard"
check "$(spend_to 1.0)" "True " "a 1 coin payment is standard"

[ $fail -eq 0 ] && say "V2 POLICY LARGE OK" || say "V2 POLICY LARGE FAILED"
exit $fail
