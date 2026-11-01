#!/usr/bin/env python3
"""Stress helpers that run ON a node. Usage: /root/stress.py ACTION ARGS...

  addrs WALLET N LABEL            print a JSON list of N fresh ML-DSA addresses of WALLET
  sendmany WALLET AMT             read a JSON list of addresses on stdin, send AMT to each in one tx; print SENDMANY_TXID=
  split WALLET N AMT              send AMT to each of N fresh addresses of WALLET (one tx, N<=900); print SPLIT_TXID=
  prep LABEL WALLET DEST AMT OUT COUNT   sign COUNT independent txs, each spending one wallet UTXO of exactly AMT and
                                  paying OUT to DEST (no change); list in /root/out/LABEL.list
  bcast LABEL WORKERS [RATE] [START_AT]  broadcast the prepared txs; RATE tx/s paces them; START_AT waits for an epoch
  mineloop ADDR INTERVAL DURATION [START_AT]   mine a block every INTERVAL s for DURATION s; save /root/out/mineloop.json
"""
import sys, json, subprocess, time, os
from concurrent.futures import ThreadPoolExecutor

BASE = "/root/src/qcoin/build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data".split()
os.makedirs("/root/out", exist_ok=True)

def cli(*a, wallet=None, check=True, stdin=None):
    cmd = BASE + ([f"-rpcwallet={wallet}"] if wallet else []) + list(a)
    p = subprocess.run(cmd, capture_output=True, text=True, input=stdin)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(a[:2])}: {p.stderr.strip()[:300]}")
    return p.stdout.strip()

def wait_until(epoch):
    if epoch:
        while time.time() < epoch:
            time.sleep(0.005)

def main():
    act = sys.argv[1]; a = sys.argv[2:]
    if act == "addrs":
        w, n, label = a[0], int(a[1]), a[2]
        print(json.dumps([cli("getnewmldsaaddress", label, wallet=w) for _ in range(n)]))
    elif act == "sendmany":
        w, amt = a[0], float(a[1])
        addrs = json.loads(sys.stdin.read())
        txid = cli("sendmany", "", json.dumps({x: amt for x in addrs}), wallet=w)
        print("SENDMANY_TXID=" + txid)
    elif act == "split":
        w, n, amt = a[0], int(a[1]), float(a[2])
        t0 = time.time()
        addrs = [cli("getnewmldsaaddress", "stress", wallet=w) for _ in range(n)]
        gen = time.time() - t0
        txid = cli("sendmany", "", json.dumps({x: amt for x in addrs}), wallet=w)
        print(f"split n={n} address_gen_s={gen:.2f} total_s={time.time()-t0:.2f}")
        print("SPLIT_TXID=" + txid)
    elif act == "prep":
        label, w, dest, amt, out, count = a[0], a[1], a[2], float(a[3]), a[4], int(a[5])
        t0 = time.time()
        unspent = json.loads(cli("listunspent", "1", "9999999", "[]", "true", wallet=w))
        cand = sorted([u for u in unspent if abs(u["amount"] - amt) < 1e-9 and u.get("spendable")], key=lambda u: (u["txid"], u["vout"]))[:count]
        if len(cand) < count:
            print(f"ERROR only {len(cand)} UTXOs of {amt} available, need {count}"); sys.exit(1)
        ids = []
        for u in cand:
            raw = cli("-named", "createrawtransaction", f'inputs=[{{"txid":"{u["txid"]}","vout":{u["vout"]}}}]', f'outputs={{"{dest}":{out}}}')
            sig = json.loads(cli("signrawtransactionwithwallet", raw, wallet=w))
            assert sig["complete"], sig
            txid = json.loads(cli("decoderawtransaction", sig["hex"]))["txid"]
            open(f"/root/out/tx_{txid}.hex", "w").write(sig["hex"] + "\n")
            ids.append(txid)
        open(f"/root/out/{label}.list", "w").write("\n".join(ids) + "\n")
        print(f"prepared={len(ids)} prep_seconds={time.time()-t0:.2f}")
    elif act == "bcast":
        label, workers = a[0], int(a[1])
        rate = float(a[2]) if len(a) > 2 and a[2] != "0" else 0.0
        start_at = float(a[3]) if len(a) > 3 else 0.0
        ids = [l.strip() for l in open(f"/root/out/{label}.list") if l.strip()]
        hexes = {t: open(f"/root/out/tx_{t}.hex").read().strip() for t in ids}
        def one(t, planned):
            s = time.time()
            p = subprocess.run(BASE + ["sendrawtransaction", hexes[t]], capture_output=True, text=True)
            return {"txid": t, "planned": planned, "start": s, "end": time.time(), "rc": p.returncode, "msg": (p.stdout + p.stderr).strip()[:120]}
        wait_until(start_at)
        t0 = time.time()
        futs = []
        with ThreadPoolExecutor(workers) as ex:
            for i, t in enumerate(ids):
                planned = t0 + (i / rate if rate else 0)
                if rate:
                    wait_until(planned)
                futs.append(ex.submit(one, t, planned))
            res = [f.result() for f in futs]
        json.dump(res, open(f"/root/out/{label}_bcast.json", "w"))
        ok = [r for r in res if r["rc"] == 0]
        first, last = min(r["start"] for r in res), max(r["end"] for r in res)
        durs = sorted(r["end"] - r["start"] for r in res)
        print(f"first_start={first:.6f} last_end={last:.6f} n={len(res)} ok={len(ok)} fail={len(res)-len(ok)} workers={workers} rate={rate}")
        print(f"call_seconds median={durs[len(durs)//2]:.3f} p95={durs[int(len(durs)*0.95)-1]:.3f} max={durs[-1]:.3f} window={last-first:.3f} accepted_per_s={len(ok)/(last-first):.1f}")
        for r in res:
            if r["rc"] != 0:
                print("ERR", r["txid"][:12], r["msg"]); break
    elif act == "mineloop":
        addr, interval, duration = a[0], float(a[1]), float(a[2])
        start_at = float(a[3]) if len(a) > 3 else 0.0
        wait_until(start_at)
        t0 = time.time(); blocks = []; k = 1
        while True:
            wait_until(t0 + k * interval)
            if time.time() - t0 > duration + interval / 2:
                break
            s = time.time()
            h = cli("generatetoaddress", "1", addr, "2000000000")
            e = time.time()
            bh = json.loads(h)[0]
            b = json.loads(cli("getblock", bh, "1"))
            blocks.append({"hash": bh, "height": b["height"], "start": s, "end": e, "ntx": b["nTx"], "size": b["size"], "weight": b["weight"], "txids": b["tx"][1:]})
            k += 1
        json.dump(blocks, open("/root/out/mineloop.json", "w"))
        for b in blocks:
            print(f"block h={b['height']} mined_in={b['end']-b['start']:.2f}s end={b['end']:.3f} ntx={b['ntx']} size={b['size']} weight={b['weight']}")

main()
