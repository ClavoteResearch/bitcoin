#!/bin/bash
# Actions that run ON a node. Usage: /root/act.sh ACTION ARGS...
#   prep WALLET DEST AMOUNT        create+fund+sign a payment, save hex, print TXID=<txid>
#   prepin WALLET TXID VOUT DEST AMOUNT   sign a tx spending exactly TXID:VOUT (no change), print TXID=<txid>
#   bcast TXID                     broadcast the saved hex, print timestamps
#   bcasthex                       broadcast hex read from stdin, print timestamps and txid or error
#   mine ADDR [N]                  mine N (default 1) blocks one call each, print timestamps and hashes
. /root/qt.sh
mkdir -p /root/out
ACTION=$1; shift
pj() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
case "$ACTION" in
  prep)
    W=$1; DEST=$2; AMT=$3
    RAW=$($CLI -named createrawtransaction inputs='[]' outputs="{\"$DEST\":$AMT}") || exit 1
    FUND=$($CLI -rpcwallet=$W fundrawtransaction "$RAW" | pj 'print(d["hex"])') || exit 1
    SIGNED=$($CLI -rpcwallet=$W signrawtransactionwithwallet "$FUND" | pj 'assert d["complete"]; print(d["hex"])') || exit 1
    TXID=$($CLI decoderawtransaction "$SIGNED" | pj 'print(d["txid"])')
    echo "$SIGNED" > /root/out/tx_$TXID.hex
    echo "TXID=$TXID"
    ;;
  prepin)
    W=$1; TXID=$2; VOUT=$3; DEST=$4; AMT=$5
    RAW=$($CLI -named createrawtransaction inputs="[{\"txid\":\"$TXID\",\"vout\":$VOUT}]" outputs="{\"$DEST\":$AMT}") || exit 1
    SIGNED=$($CLI -rpcwallet=$W signrawtransactionwithwallet "$RAW" | pj 'assert d["complete"], d; print(d["hex"])') || exit 1
    NEW=$($CLI decoderawtransaction "$SIGNED" | pj 'print(d["txid"])')
    echo "$SIGNED" > /root/out/tx_$NEW.hex
    echo "TXID=$NEW"
    ;;
  bcast)
    T=$1; HEX=$(cat /root/out/tx_$T.hex)
    t0=$(now); R=$($CLI sendrawtransaction "$HEX" 2>&1); rc=$?; t1=$(now)
    echo "bcast_start=$t0 bcast_end=$t1 rc=$rc result=$R"
    ;;
  bcasthex)
    HEX=$(cat)
    t0=$(now); R=$($CLI sendrawtransaction "$HEX" 2>&1); rc=$?; t1=$(now)
    echo "bcast_start=$t0 bcast_end=$t1 rc=$rc result=$R"
    ;;
  mine)
    ADDR=$1; N=${2:-1}
    for i in $(seq 1 "$N"); do
      t0=$(now); H=$($CLI generatetoaddress 1 "$ADDR" 2000000000 | tr -d '[]" \n'); t1=$(now)
      echo "mine_start=$t0 mine_end=$t1 hash=$H height=$(height)"
    done
    ;;
esac
