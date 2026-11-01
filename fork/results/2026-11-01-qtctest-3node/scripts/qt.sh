#!/bin/bash
# Shared helper, sourced on every node: . /root/qt.sh
CLI="/root/src/qcoin/build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data"
now() { date +%s.%N; }
height() { $CLI getblockcount; }
tip() { $CLI getbestblockhash; }

# confirmations of a txid via txindex; 'none' if unknown, 0 if only in the mempool
txconf() {
  $CLI getrawtransaction "$1" true 2>/dev/null | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print(d.get("confirmations",0))
except Exception:
    print("none")' 2>/dev/null || echo none
}

# wait_seen TXID [LIMIT_S]: print "<mempool|confirmed|timeout> <epoch>" when the node first knows the tx
wait_seen() {
  local t=$1 lim=${2:-90} s; s=$(date +%s)
  while [ $(( $(date +%s) - s )) -lt "$lim" ]; do
    c=$(txconf "$t")
    if [ "$c" != none ]; then
      if [ "$c" -ge 1 ]; then echo "confirmed $(now)"; else echo "mempool $(now)"; fi
      return 0
    fi
    sleep 0.02
  done
  echo "timeout $(now)"; return 1
}

# wait_conf TXID [LIMIT_S]: print "<confirmed|timeout> <epoch>" at the first confirmation
wait_conf() {
  local t=$1 lim=${2:-120} s; s=$(date +%s)
  while [ $(( $(date +%s) - s )) -lt "$lim" ]; do
    c=$(txconf "$t")
    if [ "$c" != none ] && [ "$c" -ge 1 ]; then echo "confirmed $(now)"; return 0; fi
    sleep 0.02
  done
  echo "timeout $(now)"; return 1
}

# wait_tip HASH [LIMIT_S]: print "<tip|timeout> <epoch>" when the best block hash equals HASH
wait_tip() {
  local h=$1 lim=${2:-120} s; s=$(date +%s)
  while [ $(( $(date +%s) - s )) -lt "$lim" ]; do
    if [ "$(tip)" = "$h" ]; then echo "tip $(now)"; return 0; fi
    sleep 0.02
  done
  echo "timeout $(now)"; return 1
}

# wait_mempool_n N [LIMIT_S]: print "<n|timeout> <epoch>" when the mempool holds at least N txs
wait_mempool_n() {
  local n=$1 lim=${2:-120} s sz; s=$(date +%s)
  while [ $(( $(date +%s) - s )) -lt "$lim" ]; do
    sz=$($CLI getmempoolinfo | python3 -c 'import sys,json; print(json.load(sys.stdin)["size"])' 2>/dev/null)
    if [ "${sz:-0}" -ge "$n" ]; then echo "mempool=$sz $(now)"; return 0; fi
    sleep 0.02
  done
  echo "timeout $(now)"; return 1
}

# wait_height H [LIMIT_S]
wait_height() {
  local h=$1 lim=${2:-120} s; s=$(date +%s)
  while [ $(( $(date +%s) - s )) -lt "$lim" ]; do
    if [ "$(height)" -ge "$h" ]; then echo "height=$(height) $(now)"; return 0; fi
    sleep 0.02
  done
  echo "timeout $(now)"; return 1
}

# ntp_offset: seconds the local clock is AHEAD of NTP time (negative = behind); empty if unavailable
ntp_offset() {
  command -v ntpdate >/dev/null 2>&1 || return 0
  ntpdate -q time.cloudflare.com 2>/dev/null | awk '/offset/ {for(i=1;i<=NF;i++) if($i=="offset") {print -$(i+1); exit}}'
}
