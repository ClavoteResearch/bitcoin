#!/bin/bash
# Helpers that run ON node A (the miner / wallet node). Usage: /root/sp.sh ACTION ARGS...
#   addr SI SL                       print spk=/leaf=/control=/... and address= for a script-path output
#   spend SI SL FUNDTXID DEST_SPK [bad]   sign a script-path spend of the output FUNDTXID pays to that address; print TXID=
#   utxos MINAMT N                   print up to N spendable wallet UTXOs of at least MINAMT: "txid vout amount"
#   split N AMT                      send AMT to each of N fresh wallet addresses in one tx; print SPLIT_TXID=
. /root/qt.sh
mkdir -p /root/out
TOOL=/root/src/qcoin/build/bin/qcoin-v2-scriptpath
pj() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
ACTION=$1; shift
case "$ACTION" in
  addr)
    O=$($TOOL address "$1" "$2") || exit 1
    echo "$O"
    SPK=$(echo "$O" | sed -n 's/^spk=//p')
    echo "address=$($CLI decodescript "$SPK" | pj 'print(d["address"])')"
    ;;
  spend)
    SI=$1; SL=$2; FUND=$3; DEST=$4; BAD=$5
    SPK=$($TOOL address "$SI" "$SL" | sed -n 's/^spk=//p')
    read VOUT SATS < <($CLI getrawtransaction "$FUND" true | python3 -c "
import sys,json
d=json.load(sys.stdin)
for i,v in enumerate(d['vout']):
    if v['scriptPubKey']['hex']=='$SPK':
        print(i, int(round(v['value']*1e8))); break
")
    SEND=$((SATS - 100000))
    HEX=$($TOOL spend "$SI" "$SL" "$FUND" "$VOUT" "$SATS" "$DEST" "$SEND" $BAD 2>/root/out/tool.err)
    echo "tool: $(cat /root/out/tool.err | tr '\n' ' ')"
    [ -n "$HEX" ] || { echo "no hex produced"; exit 1; }
    TXID=$($CLI decoderawtransaction "$HEX" | pj 'print(d["txid"])')
    echo "$HEX" > /root/out/tx_$TXID.hex
    echo "vout=$VOUT sats=$SATS send=$SEND"
    echo "TXID=$TXID"
    ;;
  utxos)
    MIN=$1; N=$2
    $CLI -rpcwallet=miner listunspent 1 9999999 '[]' true "{\"minimumAmount\":$MIN}" | python3 -c "
import sys,json
u=[x for x in json.load(sys.stdin) if x.get('spendable')]
u.sort(key=lambda x:(-x['confirmations'], x['txid']))
for x in u[:$N]: print(x['txid'], x['vout'], x['amount'])
"
    ;;
  split)
    N=$1; AMT=$2
    JSON=$(python3 - "$N" "$AMT" <<'PY'
import sys, subprocess, json
n, amt = int(sys.argv[1]), sys.argv[2]
cli = "/root/src/qcoin/build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data -rpcwallet=miner".split()
out = {}
for i in range(n):
    a = subprocess.check_output(cli + ["getnewmldsaaddress", "batch"]).decode().strip()
    out[a] = float(amt)
print(json.dumps(out))
PY
)
    TXID=$($CLI -rpcwallet=miner sendmany "" "$JSON")
    echo "SPLIT_TXID=$TXID"
    ;;
esac
