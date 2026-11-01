#!/bin/bash
# Batch helpers that run ON node A. Usage: /root/batch.sh ACTION ARGS...
#   prep SPLIT_TXID DEST SPLITAMT OUTAMT   sign one independent tx per split output (no change); list in /root/out/batch.list
#   bcast [WORKERS]                        broadcast all prepared txs with N parallel workers and time each call
. /root/qt.sh
mkdir -p /root/out
ACTION=$1; shift
case "$ACTION" in
  prep)
    python3 - "$@" <<'PY'
import sys, subprocess, json, time
split, dest, split_amt, out_amt = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
base = "/root/src/qcoin/build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data".split()
def cli(*a, wallet=None):
    return subprocess.check_output(base + ([f"-rpcwallet={wallet}"] if wallet else []) + list(a)).decode().strip()
t0 = time.time()
tx = json.loads(cli("getrawtransaction", split, "true"))
vouts = [i for i, v in enumerate(tx["vout"]) if abs(v["value"] - split_amt) < 1e-9]
ids = []
for i in vouts:
    raw = cli("-named", "createrawtransaction", f'inputs=[{{"txid":"{split}","vout":{i}}}]', f'outputs={{"{dest}":{out_amt}}}')
    sig = json.loads(cli("signrawtransactionwithwallet", raw, wallet="miner"))
    assert sig["complete"], sig
    txid = json.loads(cli("decoderawtransaction", sig["hex"]))["txid"]
    open(f"/root/out/tx_{txid}.hex", "w").write(sig["hex"] + "\n")
    ids.append(txid)
open("/root/out/batch.list", "w").write("\n".join(ids) + "\n")
print(f"prepared={len(ids)} prep_seconds={time.time()-t0:.2f}")
print("TXIDS=" + ",".join(ids))
PY
    ;;
  bcast)
    python3 - "${1:-8}" <<'PY'
import sys, subprocess, time, json
from concurrent.futures import ThreadPoolExecutor
workers = int(sys.argv[1])
base = "/root/src/qcoin/build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data".split()
ids = [l.strip() for l in open("/root/out/batch.list") if l.strip()]
hexes = {t: open(f"/root/out/tx_{t}.hex").read().strip() for t in ids}
def one(t):
    s = time.time()
    p = subprocess.run(base + ["sendrawtransaction", hexes[t]], capture_output=True, text=True)
    return t, s, time.time(), p.returncode, (p.stdout + p.stderr).strip()[:120]
t0 = time.time()
with ThreadPoolExecutor(workers) as ex:
    res = list(ex.map(one, ids))
ok = [r for r in res if r[3] == 0]
json.dump([{"txid": r[0], "start": r[1], "end": r[2], "rc": r[3], "msg": r[4]} for r in res], open("/root/out/batch_bcast.json", "w"))
first, last = min(r[1] for r in res), max(r[2] for r in res)
durs = sorted(r[2] - r[1] for r in res)
print(f"first_start={first:.6f} last_end={last:.6f} n={len(res)} ok={len(ok)} fail={len(res)-len(ok)} workers={workers}")
print(f"call_seconds median={durs[len(durs)//2]:.3f} max={durs[-1]:.3f} total_window={last-first:.3f}")
for r in res:
    if r[3] != 0: print("ERR", r[0][:12], r[4])
PY
    ;;
esac
