#!/bin/bash
# Background poller, runs ON a node. Usage: /root/poll.sh OUTFILE MODE ARGS...
#   tx TXID        -> start / seen <mempool|confirmed> <epoch> / conf confirmed <epoch>
#   tip HASH       -> start / tip tip <epoch> when the best block hash becomes HASH
#   chg INITTIP    -> start / chg <newtip> <epoch> when the best block hash differs from INITTIP
#   steps N1 N2..  -> start / size>=N <epoch> as the mempool first reaches each N
#   hcheck H       -> start / height <epoch> when height>=H, then mempool_after <size> <epoch>
. /root/qt.sh
OUT=$1; MODE=$2; shift 2
mkdir -p "$(dirname "$OUT")"
msize() { $CLI getmempoolinfo 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null; }
case "$MODE" in
  tx)    t=$1; { echo "start $(now)"; echo "seen $(wait_seen "$t" 150)"; echo "conf $(wait_conf "$t" 240)"; } > "$OUT" ;;
  tip)   h=$1; { echo "start $(now)"; echo "tip $(wait_tip "$h" 240)"; } > "$OUT" ;;
  chg)   init=$1
         { echo "start $(now)"; s=$(date +%s); r="chg timeout $(now)"
           while [ $(( $(date +%s) - s )) -lt 240 ]; do t=$(tip); if [ "$t" != "$init" ]; then r="chg $t $(now)"; break; fi; sleep 0.02; done
           echo "$r"; } > "$OUT" ;;
  steps) { echo "start $(now)"; pending="$*"; s=$(date +%s)
           while [ -n "$pending" ] && [ $(( $(date +%s) - s )) -lt 240 ]; do
             sz=$(msize); nxt=""
             for n in $pending; do if [ "${sz:-0}" -ge "$n" ]; then echo "size>=$n $(now)"; else nxt="$nxt $n"; fi; done
             pending=$nxt; sleep 0.02
           done; } > "$OUT" ;;
  hcheck) h=$1; { echo "start $(now)"; echo "height $(wait_height "$h" 240)"; echo "mempool_after $(msize) $(now)"; } > "$OUT" ;;
esac
