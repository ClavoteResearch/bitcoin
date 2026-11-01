#!/usr/bin/env python3
"""Analyse the raw files written by t5_stress.sh. Usage: t5_analyze.py DIR   (DIR = results/t5)"""
import sys, json, re, statistics
from pathlib import Path

D = Path(sys.argv[1])
OFF = json.loads((D / "offsets.json").read_text())
off = {"A": OFF["OFF_A"], "B": OFF["OFF_B"], "C": OFF["OFF_C"]}
meta = [json.loads(l) for l in (D / "meta.jsonl").read_text().splitlines() if l.strip()]
csv = ["scenario,metric,value,unit"]

def rd(name):
    p = D / name
    return p.read_text() if p.exists() else ""

def steps(name, node):
    out = {}
    for l in rd(name).splitlines():
        m = re.match(r"size>=(\d+) ([0-9.]+)", l)
        if m: out[int(m.group(1))] = float(m.group(2)) - off[node]
    return out

def hfile(name, node):
    h = mp = None
    for l in rd(name).splitlines():
        m = re.match(r"height height=(\d+) ([0-9.]+)", l)
        if m: h = float(m.group(2)) - off[node]
        m = re.match(r"mempool_after (\d+) ([0-9.]+)", l)
        if m: mp = int(m.group(1))
    return h, mp

def bc(name):
    t = rd(name); d = {}
    m = re.search(r"first_start=([0-9.]+) last_end=([0-9.]+) n=(\d+) ok=(\d+) fail=(\d+)", t)
    if m: d.update(first=float(m.group(1)), last=float(m.group(2)), n=int(m.group(3)), ok=int(m.group(4)), fail=int(m.group(5)))
    m = re.search(r"median=([0-9.]+) p95=([0-9.]+) max=([0-9.]+) window=([0-9.]+) accepted_per_s=([0-9.]+)", t)
    if m: d.update(med=float(m.group(1)), p95=float(m.group(2)), mx=float(m.group(3)), win=float(m.group(4)), rate=float(m.group(5)))
    m = re.search(r"ERR (\w+) (.*)", t)
    if m: d["err"] = m.group(2)
    return d

def f(x, nd=2): return "-" if x is None else f"{x:.{nd}f}"
def add(s, k, v, u): csv.append(f"{s},{k},{v},{u}")

print("== t5 stress test (times in s, NTP-corrected; offsets A=%.4f B=%.4f C=%.4f) ==" % (off["A"], off["B"], off["C"]))
print()
print("S1/S2 bursts: N independent 1-input 1-output witness-v2 spends broadcast from A (12 parallel RPC callers), one block mined on A")
print(f"{'scenario':10} {'N':>4} {'acc.win':>7} {'acc/s':>6} {'fail':>4} | {'B full':>6} {'C full':>6} {'relay tx/s':>10} | {'blk tx':>6} {'blk MB':>6} {'blk MWU':>7} | {'mine':>5} {'->B':>5} {'->C':>5} {'left B/C':>8}")
for m in meta:
    L = m["label"]
    if not (L.startswith("s1_") or L.startswith("s2_")): continue
    b = bc(f"{L}_bcast.txt"); N = m["N"]
    fs = b["first"] - off["A"]
    sB, sC = steps(f"{L}_steps_B.txt", "B"), steps(f"{L}_steps_C.txt", "C")
    tB = sB.get(N); tC = sC.get(N)
    relB = None if tB is None else tB - fs; relC = None if tC is None else tC - fs
    rate = None if relB is None or relC is None else N / max(relB, relC)
    me = m["mine_end"] - off["A"]
    hB, mpB = hfile(f"{L}_h_B.txt", "B"); hC, mpC = hfile(f"{L}_h_C.txt", "C")
    dB = None if hB is None else hB - me; dC = None if hC is None else hC - me
    print(f"{L:10} {N:4d} {f(b['win']):>7} {f(b['rate'],1):>6} {b['fail']:4d} | {f(relB):>6} {f(relC):>6} {f(rate,1):>10} | {m['blk_ntx']:6d} {m['blk_size']/1e6:6.2f} {m['blk_weight']/1e6:7.3f} | {f(m['mine_end']-m['mine_start']):>5} {f(dB,3):>5} {f(dC,3):>5} {str(mpB)+'/'+str(mpC):>8}")
    for k, v, u in [("accept_window", b["win"], "s"), ("accept_rate", b["rate"], "tx/s"), ("failed", b["fail"], "count"), ("relay_full_B", relB, "s"), ("relay_full_C", relC, "s"),
                    ("relay_rate", rate, "tx/s"), ("block_ntx", m["blk_ntx"], "count"), ("block_size", m["blk_size"], "bytes"), ("block_weight", m["blk_weight"], "WU"),
                    ("mine_call", m["mine_end"] - m["mine_start"], "s"), ("block_to_B", dB, "s"), ("block_to_C", dC, "s")]:
        add(L, k, "" if v is None else (f"{v:.4f}" if isinstance(v, float) else v), u)
    # quarter points
    q = []
    for node, s in (("B", sB), ("C", sC)):
        q.append(node + ": " + " / ".join(f"{(s[k]-fs):.2f}" if k in s else "-" for k in sorted(s) or [N//4, N//2, 3*N//4, N]))
    print("           mempool reached 25/50/75/100%% of N after: %s" % "; ".join(q))
print()

# ---- s3
s3 = next((m for m in meta if m["label"] == "s3"), None)
if s3:
    st = s3["start_true"]
    print("S3: 100 spends each from A, B and C broadcast at the same instant (start epoch %.3f)" % st)
    for n in "ABC":
        b = bc(f"s3_{n}_bcast.txt")
        s = steps(f"s3_steps_{n}.txt", n)
        print(f"  {n}: sent 100 in {f(b.get('win'))} s (ok={b.get('ok')} fail={b.get('fail')}, start offset {f(b['first']-off[n]-st,3)} s); mempool 150/225/300 at +{f(s.get(150,st)-st)} / +{f(s.get(225,st)-st)} / +{f(s.get(300,st)-st)} s")
        for k, v, u in [("send_window", b.get("win"), "s"), ("ok", b.get("ok"), "count"), ("fail", b.get("fail"), "count"), ("mempool_300_at", None if 300 not in s else s[300]-st, "s")]:
            add("s3_" + n, k, "" if v is None else (f"{v:.4f}" if isinstance(v, float) else v), u)
    me = s3["mine_end"] - off["C"]
    hs = {n: hfile(f"s3_h_{n}.txt", n) for n in "ABC"}
    print(f"  block mined on C: {s3['blk_ntx']} txs, {s3['blk_size']/1e6:.2f} MB, {s3['blk_weight']/1e6:.3f} MWU, mining call {f(s3['mine_end']-s3['mine_start'])} s; height reached on A/B/C at "
          + " / ".join(f"+{f(hs[n][0]-me,3)}" for n in "ABC") + f" s after C found it; mempools after: " + "/".join(str(hs[n][1]) for n in "ABC"))
    for k, v, u in [("block_ntx", s3["blk_ntx"], "count"), ("block_size", s3["blk_size"], "bytes"), ("block_weight", s3["blk_weight"], "WU")]:
        add("s3", k, v, u)
    print()

# ---- s4
s4 = next((m for m in meta if m["label"] == "s4"), None)
if s4 and (D / "s4_bcast.json").exists():
    sends = {r["txid"]: r for r in json.loads(rd("s4_bcast.json"))}
    blocks = json.loads(rd("s4_mineloop.json"))
    ok = [r for r in sends.values() if r["rc"] == 0]
    fails = len(sends) - len(ok)
    first = min(r["start"] for r in ok) - off["A"]
    lat = []; per_block = []
    last_conf = first
    for b in blocks:
        bt = b["end"] - off["C"]
        n_in = 0
        for t in b["txids"]:
            if t in sends and sends[t]["rc"] == 0:
                lat.append(bt - (sends[t]["start"] - off["A"])); n_in += 1
                last_conf = max(last_conf, bt)
        per_block.append((b["height"], bt - first, n_in, b["ntx"], b["size"], b["weight"], b["end"] - b["start"]))
    lat.sort()
    send_win = max(r["end"] for r in ok) - min(r["start"] for r in ok)
    print("S4: sustained load, 20 tx/s for 60 s (1200 spends) from A; blocks mined on C every 10 s")
    print(f"  accepted by A: {len(ok)} of {len(sends)} (failed {fails}); send window {send_win:.1f} s => {len(ok)/send_win:.1f} tx/s offered")
    print("  blocks on C (time since first send, spends in block, block txs, MB, MWU, mining s):")
    for h, t, n_in, ntx, size, w, mt in per_block:
        print(f"    h={h} +{t:6.1f}s  spends={n_in:4d} txs={ntx:4d} {size/1e6:5.2f} MB {w/1e6:6.3f} MWU mined_in={mt:.2f}s")
    if lat:
        p = lambda q: lat[min(len(lat)-1, int(q*len(lat)))]
        total_conf = len(lat); span = last_conf - first
        print(f"  confirmed {total_conf} of {len(ok)}; confirmation latency (send to the block that includes it): min {lat[0]:.2f}  median {statistics.median(lat):.2f}  p95 {p(0.95):.2f}  max {lat[-1]:.2f} s")
        print(f"  sustained confirmed throughput: {total_conf} txs over {span:.1f} s = {total_conf/span:.1f} tx/s (includes the 10 s block cadence and the tail)")
        for k, v, u in [("accepted", len(ok), "count"), ("failed", fails, "count"), ("offered_rate", len(ok)/send_win, "tx/s"), ("confirmed", total_conf, "count"),
                        ("latency_min", lat[0], "s"), ("latency_median", statistics.median(lat), "s"), ("latency_p95", p(0.95), "s"), ("latency_max", lat[-1], "s"),
                        ("confirmed_throughput", total_conf/span, "tx/s")]:
            add("s4", k, f"{v:.4f}" if isinstance(v, float) else v, u)
    # resource samples
    print("  node samples during s4 (peak mempool txs, peak bitcoind CPU %, peak RSS MB):")
    for n in "ABC":
        rows = [l.split() for l in rd(f"s4_sample_{n}.txt").splitlines() if l and not l.startswith("#")]
        rows = [r for r in rows if len(r) >= 5]
        if rows:
            pk_mp = max(int(r[1] or 0) for r in rows); pk_cpu = max(float(r[3] or 0) for r in rows); pk_rss = max(int(r[4] or 0) for r in rows) / 1024
            print(f"    {n}: mempool {pk_mp}  cpu {pk_cpu:.0f}%  rss {pk_rss:.0f} MB  ({len(rows)} samples)")
            add("s4_" + n, "peak_mempool", pk_mp, "txs"); add("s4_" + n, "peak_cpu", pk_cpu, "percent"); add("s4_" + n, "peak_rss", f"{pk_rss:.0f}", "MB")
(D.parent / "t5_stress.csv").write_text("\n".join(csv) + "\n")
