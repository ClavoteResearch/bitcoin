#!/usr/bin/env python3
"""qtc-explorer: a minimal status page / block explorer for a Qcoin node.

Standard library only. Talks to bitcoind over JSON-RPC (cookie or user/password
auth) and serves HTML plus a few JSON endpoints. Understands witness v2 ML-DSA
outputs (OP_2 <32 bytes>, tq1z/bcrt1z addresses) and attestations
(0x51 || n || param_id || pk || sig) so they are labelled instead of "unknown".

    qtc-explorer.py --chain qtctest [--datadir ~/.bitcoin] [--rpcurl http://127.0.0.1:28332]
                    [--rpcuser U --rpcpassword P] [--bind 127.0.0.1] [--port 8080]

Pages: /  /blocks?from=H  /block/<hash|height>  /tx/<txid>  /address/<addr>  /mempool
JSON:  /api/status  /api/block/<hash|height>  /api/tx/<txid>  /api/address/<addr>

Address lookups scan recent blocks (no address index is needed); --scan sets how
many blocks back from the tip to look (default 2000).
"""
import argparse, base64, html, json, os, sys, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DEFAULT_RPC_PORT = {"qtctest": 28332, "regtest": 18443, "main": 8332, "test": 18332, "testnet4": 48332, "signet": 38332}
DATADIR_SUBDIR = {"qtctest": "qtctest", "regtest": "regtest", "main": "", "test": "testnet3", "testnet4": "testnet4", "signet": "signet"}
PARAM_NAMES = {0x01: "ML-DSA-44", 0x02: "ML-DSA-65 (reserved)", 0x7f: "ML-DSA-87 (experimental, non-BIP)"}
ATTESTATION_PREFIX = 0x51


# Small HTML helpers. They keep backslashes out of f-string expressions, which Python before 3.12 rejects
# (Ubuntu 22.04 ships 3.10).
def PILL(cls, text):
    return '<span class="pill ' + cls + '">' + text + '</span>'


def ALINK(href, text):
    return '<a href="' + href + '">' + text + '</a>'


class Rpc:
    def __init__(self, url, auth):
        self.url, self.auth, self._id = url, auth, 0

    def __call__(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json", "Authorization": "Basic " + self.auth})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                res = json.loads(e.read().decode())
            except Exception:
                raise RuntimeError(f"RPC HTTP {e.code}") from e
        if res.get("error"):
            raise RuntimeError(f"{method}: {res['error'].get('message')}")
        return res["result"]


def rpc_auth(args):
    if args.rpcuser:
        return base64.b64encode(f"{args.rpcuser}:{args.rpcpassword or ''}".encode()).decode()
    cookie = os.path.join(os.path.expanduser(args.datadir), DATADIR_SUBDIR.get(args.chain, args.chain), ".cookie")
    try:
        with open(cookie) as f:
            return base64.b64encode(f.read().strip().encode()).decode()
    except OSError:
        sys.exit(f"cannot read RPC cookie {cookie}; is the node running? (or pass --rpcuser/--rpcpassword)")


# ---------------------------------------------------------------- v2 helpers
def is_v2_spk(spk):
    h = spk.get("hex", "")
    return len(h) == 68 and h.startswith("5220")  # OP_2 PUSH32


def parse_attestation(hexwit):
    """Return (n, [(param_id, name, pk_len, sig_len)]) or None."""
    try:
        b = bytes.fromhex(hexwit)
    except ValueError:
        return None
    if len(b) < 3 or b[0] != ATTESTATION_PREFIX:
        return None
    n, pos, entries = b[1], 2, []
    sizes = {0x01: (1312, 2420), 0x7f: (2592, 4627)}
    for _ in range(n):
        if pos >= len(b):
            return None
        pid = b[pos]
        if pid not in sizes:
            return None
        pk, sig = sizes[pid]
        if len(b) - pos - 1 < pk + sig:
            return None
        entries.append((pid, PARAM_NAMES.get(pid, f"param_id 0x{pid:02x}"), pk, sig))
        pos += 1 + pk + sig
    return (n, entries) if pos == len(b) else None


def classify_input(vin):
    if "coinbase" in vin:
        return "coinbase"
    w = vin.get("txinwitness") or []
    if len(w) == 1:
        att = parse_attestation(w[0])
        if att:
            n, entries = att
            return f"ML-DSA attestation: {n} entry, {entries[0][1]}, {len(w[0]) // 2} bytes"
    if w:
        return f"witness ({len(w)} element{'s' if len(w) != 1 else ''})"
    return "scriptSig"


def classify_output(vout):
    spk = vout.get("scriptPubKey", {})
    if is_v2_spk(spk):
        return "witness v2 ML-DSA (OP_2 <Q>)"
    return spk.get("type", "?")


# ---------------------------------------------------------------- data access
class Chain:
    def __init__(self, rpc, scan_depth):
        self.rpc, self.scan_depth = rpc, scan_depth
        self._tx_block = {}  # txid -> blockhash (filled while scanning)

    def status(self):
        info = self.rpc("getblockchaininfo")
        dep = self.rpc("getdeploymentinfo")["deployments"]
        mem = self.rpc("getmempoolinfo")
        net = self.rpc("getnetworkinfo")
        return {"chain": info["chain"], "blocks": info["blocks"], "headers": info["headers"], "bestblockhash": info["bestblockhash"],
                "mediantime": info["mediantime"], "difficulty": info["difficulty"], "pruned": info.get("pruned", False),
                "mldsav2": dep.get("mldsav2", {}), "segwit": dep.get("segwit", {}), "mempool_txs": mem["size"], "mempool_bytes": mem["bytes"],
                "connections": net.get("connections", 0), "version": net.get("subversion", ""), "protocolversion": net.get("protocolversion")}

    def block(self, ref):
        bh = self.rpc("getblockhash", int(ref)) if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit() and len(ref) < 64) else ref
        blk = self.rpc("getblock", bh, 2)
        for tx in blk["tx"]:
            self._tx_block[tx["txid"]] = bh
        return blk

    def blocks(self, start, count):
        out = []
        for h in range(start, max(-1, start - count), -1):
            blk = self.block(h)
            n_v2_out = sum(1 for tx in blk["tx"] for o in tx["vout"] if is_v2_spk(o["scriptPubKey"]))
            n_v2_in = sum(1 for tx in blk["tx"] for i in tx["vin"] if classify_input(i).startswith("ML-DSA"))
            out.append({"height": blk["height"], "hash": blk["hash"], "time": blk["time"], "ntx": len(blk["tx"]), "size": blk["size"],
                        "weight": blk["weight"], "v2_outputs": n_v2_out, "v2_spends": n_v2_in})
        return out

    def tx(self, txid):
        try:
            return self.rpc("getrawtransaction", txid, True), None
        except RuntimeError:
            pass
        bh = self._tx_block.get(txid)
        if not bh:
            tip = self.rpc("getblockcount")
            for h in range(tip, max(-1, tip - self.scan_depth), -1):
                blk = self.block(h)
                if txid in self._tx_block:
                    bh = self._tx_block[txid]
                    break
        if not bh:
            return None, "transaction not found in the mempool or the last %d blocks" % self.scan_depth
        return self.rpc("getrawtransaction", txid, True, bh), None

    def address(self, addr):
        va = self.rpc("validateaddress", addr)
        if not va.get("isvalid"):
            return {"address": addr, "valid": False, "error": va.get("error", "invalid address")}
        kind = "witness v2 ML-DSA (key path)" if va.get("witness_version") == 2 and len(va.get("witness_program", "")) == 64 else va.get("type", "?")
        spk = va["scriptPubKey"]
        tip = self.rpc("getblockcount")
        received, spent, utxo = [], [], {}
        for h in range(max(0, tip - self.scan_depth + 1), tip + 1):
            blk = self.block(h)
            for tx in blk["tx"]:
                for o in tx["vout"]:
                    if o["scriptPubKey"].get("hex") == spk:
                        received.append({"txid": tx["txid"], "vout": o["n"], "value": o["value"], "height": h})
                        utxo[(tx["txid"], o["n"])] = o["value"]
                for i in tx["vin"]:
                    key = (i.get("txid"), i.get("vout"))
                    if key in utxo:
                        spent.append({"txid": tx["txid"], "spent_txid": key[0], "spent_vout": key[1], "value": utxo.pop(key), "height": h,
                                      "witness": classify_input(i)})
        return {"address": addr, "valid": True, "kind": kind, "witness_version": va.get("witness_version"), "scriptPubKey": spk,
                "scanned_blocks": min(self.scan_depth, tip + 1), "received": received, "spent": spent,
                "unspent_value": round(sum(utxo.values()), 8), "unspent_count": len(utxo)}


# ---------------------------------------------------------------- HTML
CSS = """body{font-family:system-ui,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}header{background:#1b2430;padding:.8rem 1.2rem;display:flex;gap:1.5rem;align-items:center}
header a{color:#9fd3ff;text-decoration:none;font-weight:600}main{padding:1rem 1.2rem;max-width:1200px}table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{padding:.35rem .5rem;border-bottom:1px solid #2b3744;text-align:left;vertical-align:top}th{color:#9fb3c8}code,.mono{font-family:ui-monospace,monospace;word-break:break-all}
.pill{display:inline-block;padding:.05rem .45rem;border-radius:.6rem;font-size:.8rem;background:#2b3744}.v2{background:#2a5a3a;color:#c9f7d6}.cb{background:#4a3f1f;color:#ffe8a3}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.8rem;margin-bottom:1rem}.card{background:#1b2430;padding:.8rem;border-radius:.5rem}
.card h3{margin:0 0 .3rem;font-size:.8rem;color:#9fb3c8;text-transform:uppercase}.card div{font-size:1.2rem}form input{padding:.4rem;width:28rem;max-width:90%;background:#0f1419;color:#e6e6e6;border:1px solid #2b3744}
a{color:#9fd3ff}.warn{color:#ffb3b3}"""


def page(title, body, chain):
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)} - qtc-explorer</title><style>{CSS}</style></head>
<body><header><a href="/">qtc-explorer</a><span class="pill">{html.escape(chain)}</span><a href="/blocks">blocks</a><a href="/mempool">mempool</a>
<form action="/search" style="margin-left:auto"><input name="q" placeholder="block height / hash, txid, or address"></form></header><main>{body}</main></body></html>"""


def esc(x):
    return html.escape(str(x))


def fmt_time(t):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))


def render_status(st, blocks, chain):
    dep = st["mldsav2"]
    dep_txt = ("active" if dep.get("active") else "inactive") + (f" (height {dep.get('height')})" if dep else " (unknown)")
    cards = f"""<div class="grid">
<div class="card"><h3>Height</h3><div>{st['blocks']}</div></div>
<div class="card"><h3>mldsav2 deployment</h3><div class="{'v2' if dep.get('active') else 'warn'}">{esc(dep_txt)}</div></div>
<div class="card"><h3>Mempool</h3><div>{st['mempool_txs']} tx / {st['mempool_bytes']} B</div></div>
<div class="card"><h3>Peers</h3><div>{st['connections']}</div></div>
<div class="card"><h3>Best block</h3><div class="mono" style="font-size:.8rem"><a href="/block/{st['bestblockhash']}">{st['bestblockhash']}</a></div></div>
<div class="card"><h3>Node</h3><div style="font-size:.9rem">{esc(st['version'])}</div></div></div>"""
    return page("status", cards + render_block_table(blocks), chain)


def render_block_table(blocks):
    rows = "".join(f"<tr><td><a href='/block/{b['height']}'>{b['height']}</a></td><td class='mono'><a href='/block/{b['hash']}'>{b['hash']}</a></td><td>{fmt_time(b['time'])}</td>"
                   f"<td>{b['ntx']}</td><td>{b['size']}</td>"
                   f"<td>{(PILL('v2', str(b['v2_outputs']) + ' out') + ' ') if b['v2_outputs'] else ''}{PILL('v2', str(b['v2_spends']) + ' spend') if b['v2_spends'] else ''}</td></tr>"
                   for b in blocks)
    nav = f"<p><a href='/blocks?from={blocks[-1]['height'] - 1}'>older &rarr;</a></p>" if blocks and blocks[-1]["height"] > 0 else ""
    return f"<h2>Recent blocks</h2><table><tr><th>height</th><th>hash</th><th>time</th><th>txs</th><th>size</th><th>ML-DSA v2</th></tr>{rows}</table>{nav}"


def render_block(blk, chain):
    rows = "".join(f"<tr><td class='mono'><a href='/tx/{tx['txid']}'>{tx['txid']}</a></td><td>{len(tx['vin'])}</td><td>{len(tx['vout'])}</td><td>{tx['vsize']}</td>"
                   f"<td>{''.join(PILL('cb', 'coinbase') for i in tx['vin'] if 'coinbase' in i)}"
                   f"{''.join(PILL('v2', 'v2 spend') for i in tx['vin'] if classify_input(i).startswith('ML-DSA'))}"
                   f"{''.join(PILL('v2', 'v2 out') for o in tx['vout'] if is_v2_spk(o['scriptPubKey']))}</td></tr>" for tx in blk["tx"])
    prev = f"<a href='/block/{blk['previousblockhash']}'>&larr; {blk['height'] - 1}</a>" if "previousblockhash" in blk else ""
    nxt = f"<a href='/block/{blk['nextblockhash']}'>{blk['height'] + 1} &rarr;</a>" if "nextblockhash" in blk else ""
    body = f"""<h2>Block {blk['height']}</h2><p>{prev} {nxt}</p>
<table><tr><th>hash</th><td class="mono">{blk['hash']}</td></tr><tr><th>time</th><td>{fmt_time(blk['time'])} ({blk['time']})</td></tr>
<tr><th>transactions</th><td>{len(blk['tx'])}</td></tr><tr><th>size / weight</th><td>{blk['size']} B / {blk['weight']} WU</td></tr>
<tr><th>bits / nonce</th><td>{blk['bits']} / {blk['nonce']}</td></tr><tr><th>merkle root</th><td class="mono">{blk['merkleroot']}</td></tr></table>
<h3>Transactions</h3><table><tr><th>txid</th><th>in</th><th>out</th><th>vsize</th><th></th></tr>{rows}</table>"""
    return page(f"block {blk['height']}", body, chain)


def render_tx(tx, chain):
    vin_rows = ""
    for i in tx["vin"]:
        if "coinbase" in i:
            vin_rows += f"<tr><td colspan=2><span class='pill cb'>coinbase</span> <code>{esc(i['coinbase'][:120])}{'…' if len(i['coinbase']) > 120 else ''}</code></td><td></td></tr>"
            continue
        kind = classify_input(i)
        cls = "v2" if kind.startswith("ML-DSA") else ""
        vin_rows += f"<tr><td class='mono'><a href='/tx/{i['txid']}'>{i['txid']}</a>:{i['vout']}</td><td><span class='pill {cls}'>{esc(kind)}</span></td><td></td></tr>"
    vout_rows = ""
    for o in tx["vout"]:
        spk = o["scriptPubKey"]
        kind = classify_output(o)
        addr = spk.get("address", "")
        cls = "v2" if is_v2_spk(spk) else ""
        vout_rows += (f"<tr><td>{o['n']}</td><td>{o['value']:.8f}</td><td class='mono'>{ALINK('/address/' + addr, addr) if addr else esc(spk.get('asm',''))}</td>"
                      f"<td><span class='pill {cls}'>{esc(kind)}</span></td></tr>")
    conf = f"{tx.get('confirmations', 0)} confirmation(s), block <a href='/block/{tx['blockhash']}'>{tx['blockhash'][:16]}…</a>" if tx.get("blockhash") else "<span class='warn'>unconfirmed (mempool)</span>"
    body = f"""<h2>Transaction</h2><table><tr><th>txid</th><td class="mono">{tx['txid']}</td></tr><tr><th>status</th><td>{conf}</td></tr>
<tr><th>size / vsize / weight</th><td>{tx['size']} B / {tx['vsize']} vB / {tx['weight']} WU</td></tr><tr><th>version / locktime</th><td>{tx['version']} / {tx['locktime']}</td></tr></table>
<h3>Inputs</h3><table><tr><th>outpoint</th><th>spend type</th><th></th></tr>{vin_rows}</table>
<h3>Outputs</h3><table><tr><th>#</th><th>value</th><th>address / script</th><th>type</th></tr>{vout_rows}</table>"""
    return page(f"tx {tx['txid'][:16]}", body, chain)


def render_address(a, chain):
    if not a["valid"]:
        return page("address", f"<h2>Address</h2><p class='warn'>{esc(a['error'])}</p>", chain)
    cls = "v2" if a["witness_version"] == 2 else ""
    rec = "".join(f"<tr><td><a href='/block/{r['height']}'>{r['height']}</a></td><td class='mono'><a href='/tx/{r['txid']}'>{r['txid']}</a>:{r['vout']}</td><td>+{r['value']:.8f}</td></tr>" for r in reversed(a["received"]))
    spt = "".join(f"<tr><td><a href='/block/{s['height']}'>{s['height']}</a></td><td class='mono'><a href='/tx/{s['txid']}'>{s['txid']}</a> spends {s['spent_txid'][:16]}…:{s['spent_vout']}</td><td>-{s['value']:.8f} <span class='pill v2'>{esc(s['witness'])}</span></td></tr>" for s in reversed(a["spent"]))
    body = f"""<h2>Address</h2><table><tr><th>address</th><td class="mono">{esc(a['address'])}</td></tr><tr><th>type</th><td><span class="pill {cls}">{esc(a['kind'])}</span></td></tr>
<tr><th>scriptPubKey</th><td class="mono">{a['scriptPubKey']}</td></tr><tr><th>unspent</th><td>{a['unspent_value']:.8f} in {a['unspent_count']} output(s)</td></tr>
<tr><th>scanned</th><td>last {a['scanned_blocks']} blocks</td></tr></table>
<h3>Received ({len(a['received'])})</h3><table><tr><th>height</th><th>output</th><th>value</th></tr>{rec or '<tr><td colspan=3>none</td></tr>'}</table>
<h3>Spent ({len(a['spent'])})</h3><table><tr><th>height</th><th>spending tx</th><th>value</th></tr>{spt or '<tr><td colspan=3>none</td></tr>'}</table>"""
    return page("address", body, chain)


def render_mempool(txs, chain):
    rows = "".join(f"<tr><td class='mono'><a href='/tx/{t}'>{t}</a></td><td>{e.get('vsize')}</td><td>{e.get('fees', {}).get('base')}</td><td>{fmt_time(e.get('time', 0))}</td></tr>" for t, e in txs.items())
    return page("mempool", f"<h2>Mempool ({len(txs)})</h2><table><tr><th>txid</th><th>vsize</th><th>fee</th><th>seen</th></tr>{rows or '<tr><td colspan=4>empty</td></tr>'}</table>", chain)


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    chain: Chain = None
    chain_name = ""

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200):
        self.send(code, json.dumps(obj, indent=1), "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)
        c = self.chain
        try:
            if not parts:
                st = c.status()
                return self.send(200, render_status(st, c.blocks(st["blocks"], 15), self.chain_name))
            if parts[0] == "blocks":
                st = c.status()
                start = int(q.get("from", [st["blocks"]])[0])
                return self.send(200, page("blocks", render_block_table(c.blocks(min(start, st["blocks"]), 25)), self.chain_name))
            if parts[0] == "block" and len(parts) == 2:
                return self.send(200, render_block(c.block(parts[1]), self.chain_name))
            if parts[0] == "tx" and len(parts) == 2:
                tx, err = c.tx(parts[1])
                return self.send(200, render_tx(tx, self.chain_name)) if tx else self.send(404, page("tx", f"<p class='warn'>{esc(err)}</p>", self.chain_name))
            if parts[0] == "address" and len(parts) == 2:
                return self.send(200, render_address(c.address(parts[1]), self.chain_name))
            if parts[0] == "mempool":
                return self.send(200, render_mempool(c.rpc("getrawmempool", True), self.chain_name))
            if parts[0] == "search":
                s = q.get("q", [""])[0].strip()
                if s.isdigit() or (len(s) == 64 and s.startswith("00") or len(s) == 64 and self._is_block(s)):
                    return self.redirect(f"/block/{s}")
                if len(s) == 64:
                    return self.redirect(f"/tx/{s}")
                return self.redirect(f"/address/{s}") if s else self.redirect("/")
            if parts[0] == "api":
                if len(parts) == 2 and parts[1] == "status":
                    return self.send_json(c.status())
                if len(parts) == 3 and parts[1] == "block":
                    return self.send_json(c.block(parts[2]))
                if len(parts) == 3 and parts[1] == "tx":
                    tx, err = c.tx(parts[2])
                    return self.send_json(tx) if tx else self.send_json({"error": err}, 404)
                if len(parts) == 3 and parts[1] == "address":
                    return self.send_json(c.address(parts[2]))
            self.send(404, page("not found", "<p class='warn'>not found</p>", self.chain_name))
        except RuntimeError as e:
            self.send(502, page("error", f"<p class='warn'>RPC error: {esc(e)}</p>", self.chain_name))
        except (ValueError, KeyError) as e:
            self.send(400, page("error", f"<p class='warn'>bad request: {esc(e)}</p>", self.chain_name))

    def _is_block(self, h):
        try:
            self.chain.rpc("getblockheader", h)
            return True
        except RuntimeError:
            return False

    def redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chain", default="qtctest")
    ap.add_argument("--datadir", default="~/.bitcoin", help="node data directory (for the RPC cookie)")
    ap.add_argument("--rpcurl", help="default http://127.0.0.1:<chain rpc port>")
    ap.add_argument("--rpcuser"); ap.add_argument("--rpcpassword")
    ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--scan", type=int, default=2000, help="blocks to scan back for address and tx lookups")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    url = args.rpcurl or f"http://127.0.0.1:{DEFAULT_RPC_PORT.get(args.chain, 8332)}"
    rpc = Rpc(url, rpc_auth(args))
    try:
        info = rpc("getblockchaininfo")
    except (RuntimeError, urllib.error.URLError) as e:
        sys.exit(f"cannot reach node at {url}: {e}")
    Handler.chain = Chain(rpc, args.scan)
    Handler.chain_name = info["chain"]
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.verbose = args.verbose
    print(f"qtc-explorer: chain {info['chain']} height {info['blocks']} via {url}; serving http://{args.bind}:{args.port}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
