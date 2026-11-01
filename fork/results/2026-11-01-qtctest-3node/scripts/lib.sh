#!/bin/bash
# Local driver library (Git Bash). Source it: . lib.sh
KEY=~/.ssh/KEYFILE
SSHO=(-i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15)
declare -A TARGET=([A]="-p PORT root@NODE_A_IP" [B]="-p PORT root@NODE_B_IP" [C]="-p PORT root@NODE_C_IP")  # fill in your own hosts
declare -A EXTP2P=([B]="NODE_B_IP:EXTERNAL_P2P_PORT" [C]="NODE_C_IP:EXTERNAL_P2P_PORT")
NODES="A B C"
W=~/work
RES=$W/results; mkdir -p "$RES"

# rx NODE CMD...: run a command on a node (output filtered of the Vast banner)
rx() { local n=$1; shift; ssh "${SSHO[@]}" ${TARGET[$n]} "$@" 2>&1 | grep -v -i 'welcome to vast\|have fun\|Permanently added' || true; }

# upload LOCALFILE NODE REMOTEPATH
upload() { ssh "${SSHO[@]}" ${TARGET[$2]} "cat > $3 && chmod +x $3" < "$1" 2>&1 | grep -v -i 'welcome to vast\|have fun' || true; }

# bg NODE CMD: start CMD detached on a node
bg() { local n=$1; shift; ssh "${SSHO[@]}" ${TARGET[$n]} "setsid nohup $* >/dev/null 2>&1 < /dev/null & sleep 0.2; echo started" 2>&1 | grep -v -i 'welcome to vast\|have fun' | tail -1; }

# act NODE ACTION ARGS...: run /root/act.sh remotely
act() { local n=$1; shift; rx "$n" "/root/act.sh $*"; }

# fetch NODE REMOTEFILE: print a remote file
fetch() { rx "$1" "cat $2"; }

# kv FILE-TEXT KEY: extract KEY=VALUE from act output
kv() { printf '%s\n' "$1" | tr ' ' '\n' | grep "^$2=" | head -1 | cut -d= -f2-; }

# parse a poller line like "seen mempool 1793571479.72" -> the epoch (last field)
epoch() { awk -v k="$2" '$1==k {print $NF}' <<<"$1" | head -1; }

# clock offsets (seconds each node is ahead of NTP); sets OFF_A OFF_B OFF_C (0 if unavailable)
measure_clocks() {
  for n in $NODES; do
    o=$(rx "$n" '. /root/qt.sh; ntp_offset' | tail -1)
    case "$o" in ''|*[!0-9.eE+-]*) o=0; echo "clock $n: NTP offset unavailable, assuming 0";; *) echo "clock $n: ahead of NTP by $o s";; esac
    eval "OFF_$n=$o"
  done
  # pipes run functions in a subshell, so also write the values where callers can source them
  printf 'OFF_A=%s\nOFF_B=%s\nOFF_C=%s\n' "$OFF_A" "$OFF_B" "$OFF_C" > "$RES/offsets.env"
}
