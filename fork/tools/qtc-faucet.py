#!/usr/bin/env python3
"""qtc-faucet: a minimal faucet for the Qcoin test chain (qtctest).

Standard library only. Pays small amounts from a funded node wallet to tester
addresses, by default only to witness v2 ML-DSA addresses (tq1z...). Three modes:

  qtc-faucet.py fund  [--blocks 101]            mine coins to the faucet wallet (on-demand PoW chains only)
  qtc-faucet.py send  <address> [--amount 1.0]  one payment from the command line
  qtc-faucet.py serve [--port 8081]             HTTP: GET / (form), POST /claim, GET /api/claim?address=, GET /api/status

Common options: --chain qtctest --datadir ~/.bitcoin --rpcurl URL --rpcuser/--rpcpassword
                --wallet faucet (created if missing) --amount 1.0 --allow-any-address
HTTP options:   --bind 127.0.0.1 --cooldown 86400 (seconds per address and per client IP)
                --max-per-ip 5 (claims per IP per cooldown) --state faucet-state.json
                --confirm-blocks N (mine N blocks after each payout; on-demand PoW chains only)

Put a reverse proxy with TLS and basic abuse protection in front of it for a public testnet.
"""
import argparse, base64, html, json, os, sys, threading, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DEFAULT_RPC_PORT = {"qtctest": 28332, "regtest": 18443, "signet": 38332, "testnet4": 48332, "test": 18332, "main": 8332}
DATADIR_SUBDIR = {"qtctest": "qtctest", "regtest": "regtest", "signet": "signet", "testnet4": "testnet4", "test": "testnet3", "main": ""}


class Rpc:
    def __init__(self, url, auth, wallet=None):
        self.url, self.auth, self.wallet, self._id = url, auth, wallet, 0

    def for_wallet(self, name):
        return Rpc(self.url, self.auth, name)

    def __call__(self, method, *params):
        self._id += 1
        url = self.url + (f"/wallet/{self.wallet}" if self.wallet else "")
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "Authorization": "Basic " + self.auth})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                res = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                res = json.loads(e.read().decode())
            except Exception:
                raise RuntimeError(f"RPC HTTP {e.code}") from e
        if res.get("error"):
            raise RuntimeError(res["error"].get("message", str(res["error"])))
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


class Faucet:
    def __init__(self, rpc, args):
        self.node = rpc
        self.args = args
        self.lock = threading.Lock()
        self.state_path = args.state
        self.state = {"addresses": {}, "ips": {}, "payouts": []}
        if args.state and os.path.exists(args.state):
            with open(args.state) as f:
                self.state = json.load(f)
        self.ensure_wallet()

    # -- wallet
    def ensure_wallet(self):
        loaded = self.node("listwallets")
        if self.args.wallet not in loaded:
            try:
                self.node("loadwallet", self.args.wallet)
            except RuntimeError:
                self.node("createwallet", self.args.wallet)
                print(f"faucet: created wallet '{self.args.wallet}'", file=sys.stderr, flush=True)
        self.wallet = self.node.for_wallet(self.args.wallet)

    def balance(self):
        return self.wallet("getbalance")

    def fund_by_mining(self, blocks):
        addr = self.wallet("getnewaddress", "faucet-mining")
        params = self.node("getblockchaininfo")
        hashes = self.node("generatetoaddress", blocks, addr)
        return addr, len(hashes), params["chain"]

    # -- validation and policy
    def check_address(self, address):
        va = self.node("validateaddress", address)
        if not va.get("isvalid"):
            return False, f"invalid address for this chain ({va.get('error', 'unknown')})"
        if not self.args.allow_any_address and va.get("witness_version") != 2:
            return False, "faucet only pays witness v2 ML-DSA addresses (tq1z...); use getnewmldsaaddress"
        return True, va

    def check_limits(self, address, ip):
        now = time.time()
        cd = self.args.cooldown
        last = self.state["addresses"].get(address, 0)
        if now - last < cd:
            return False, f"address already paid {int(now - last)}s ago; try again in {int(cd - (now - last))}s"
        times = [t for t in self.state["ips"].get(ip, []) if now - t < cd]
        self.state["ips"][ip] = times
        if len(times) >= self.args.max_per_ip:
            return False, f"too many claims from this client; limit {self.args.max_per_ip} per {cd}s"
        return True, None

    def save_state(self):
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.state_path)

    # -- payout
    def pay(self, address, ip="cli", enforce_limits=True):
        ok, info = self.check_address(address)
        if not ok:
            return {"ok": False, "error": info}
        with self.lock:
            if enforce_limits:
                ok, err = self.check_limits(address, ip)
                if not ok:
                    return {"ok": False, "error": err}
            bal = self.balance()
            if bal < self.args.amount:
                return {"ok": False, "error": f"faucet is dry (balance {bal}); operator must fund it"}
            try:
                txid = self.wallet("sendtoaddress", address, self.args.amount, "faucet", "", False, True)
            except RuntimeError as e:
                return {"ok": False, "error": f"payment failed: {e}"}
            now = time.time()
            self.state["addresses"][address] = now
            self.state["ips"].setdefault(ip, []).append(now)
            self.state["payouts"].append({"time": int(now), "address": address, "amount": self.args.amount, "txid": txid})
            self.state["payouts"] = self.state["payouts"][-500:]
            self.save_state()
            confirmed_in = None
            if self.args.confirm_blocks > 0:
                mine_to = self.wallet("getnewaddress", "faucet-mining")
                hashes = self.node("generatetoaddress", self.args.confirm_blocks, mine_to)
                confirmed_in = hashes[0] if hashes else None
            return {"ok": True, "txid": txid, "amount": self.args.amount, "address": address,
                    "address_type": "witness v2 ML-DSA" if info.get("witness_version") == 2 else info.get("type"),
                    "confirmed_in_block": confirmed_in}

    def status(self):
        info = self.node("getblockchaininfo")
        return {"chain": info["chain"], "height": info["blocks"], "wallet": self.args.wallet, "balance": self.balance(),
                "amount": self.args.amount, "cooldown_seconds": self.args.cooldown, "max_per_ip": self.args.max_per_ip,
                "v2_only": not self.args.allow_any_address, "payouts": len(self.state["payouts"]),
                "recent": self.state["payouts"][-10:][::-1]}


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Qcoin testnet faucet</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f1419;color:#e6e6e6;margin:0}}main{{max-width:760px;margin:0 auto;padding:1.5rem}}
.card{{background:#1b2430;border-radius:.6rem;padding:1rem 1.2rem;margin-bottom:1rem}}input{{width:100%;padding:.6rem;background:#0f1419;color:#e6e6e6;border:1px solid #2b3744;font-family:ui-monospace,monospace}}
button{{margin-top:.6rem;padding:.6rem 1.2rem;background:#2a5a3a;color:#c9f7d6;border:0;border-radius:.4rem;font-weight:600}}.ok{{color:#c9f7d6}}.err{{color:#ffb3b3}}code{{font-family:ui-monospace,monospace;word-break:break-all}}
table{{width:100%;font-size:.9rem;border-collapse:collapse}}td,th{{padding:.3rem .4rem;border-bottom:1px solid #2b3744;text-align:left}}</style></head><body><main>
<h1>Qcoin testnet faucet <small style="font-size:.6em;color:#9fb3c8">{chain}</small></h1>
<div class="card"><p>Pays <b>{amount}</b> per request to a <b>witness v2 ML-DSA address</b> (<code>tq1z…</code>). Get one from your wallet with
<code>bitcoin-cli -chain=qtctest -rpcwallet=&lt;w&gt; getnewmldsaaddress</code> (node started with <code>-walletsigscheme=mldsa44</code>).</p>
<form method="post" action="/claim"><input name="address" placeholder="tq1z..." required autofocus><button>Send me test coins</button></form>{result}</div>
<div class="card"><b>Faucet balance:</b> {balance} &nbsp; <b>height:</b> {height} &nbsp; <b>cooldown:</b> {cooldown}s per address{recent}</div>
<p style="color:#9fb3c8;font-size:.85rem">API: <code>GET /api/claim?address=tq1z…</code>, <code>GET /api/status</code>. Test coins have no value.</p></main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    faucet: Faucet = None

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def client_ip(self):
        fwd = self.headers.get("X-Forwarded-For")
        return fwd.split(",")[0].strip() if fwd else self.client_address[0]

    def send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def render(self, result_html=""):
        st = self.faucet.status()
        rows = "".join(f"<tr><td>{time.strftime('%H:%M:%S', time.gmtime(p['time']))}</td><td><code>{html.escape(p['address'][:20])}…</code></td><td>{p['amount']}</td><td><code>{p['txid'][:16]}…</code></td></tr>" for p in st["recent"])
        recent = f"<table style='margin-top:.6rem'><tr><th>time (UTC)</th><th>address</th><th>amount</th><th>txid</th></tr>{rows}</table>" if rows else ""
        return PAGE.format(chain=html.escape(st["chain"]), amount=st["amount"], balance=st["balance"], height=st["height"], cooldown=st["cooldown_seconds"], result=result_html, recent=recent)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/":
                return self.send(200, self.render())
            if u.path == "/api/status":
                return self.send(200, json.dumps(self.faucet.status(), indent=1), "application/json")
            if u.path == "/api/claim":
                addr = q.get("address", [""])[0].strip()
                res = self.faucet.pay(addr, self.client_ip())
                return self.send(200 if res["ok"] else 400, json.dumps(res, indent=1), "application/json")
            self.send(404, "not found", "text/plain")
        except RuntimeError as e:
            self.send(502, json.dumps({"ok": False, "error": f"node RPC error: {e}"}), "application/json")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/claim":
            return self.send(404, "not found", "text/plain")
        n = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(n).decode())
        addr = form.get("address", [""])[0].strip()
        try:
            res = self.faucet.pay(addr, self.client_ip())
        except RuntimeError as e:
            res = {"ok": False, "error": f"node RPC error: {e}"}
        if res["ok"]:
            msg = f"<p class='ok'>Sent {res['amount']} to <code>{html.escape(addr)}</code><br>txid <code>{res['txid']}</code>" + (f"<br>confirmed in block <code>{res['confirmed_in_block']}</code>" if res.get("confirmed_in_block") else "") + "</p>"
        else:
            msg = f"<p class='err'>{html.escape(res['error'])}</p>"
        self.send(200 if res["ok"] else 400, self.render(msg))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["fund", "send", "serve"])
    ap.add_argument("address", nargs="?", help="recipient (send mode)")
    ap.add_argument("--chain", default="qtctest"); ap.add_argument("--datadir", default="~/.bitcoin")
    ap.add_argument("--rpcurl"); ap.add_argument("--rpcuser"); ap.add_argument("--rpcpassword")
    ap.add_argument("--wallet", default="faucet"); ap.add_argument("--amount", type=float, default=1.0)
    ap.add_argument("--allow-any-address", action="store_true", help="also pay non-v2 addresses")
    ap.add_argument("--blocks", type=int, default=101, help="fund mode: blocks to mine to the faucet wallet")
    ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--cooldown", type=int, default=86400); ap.add_argument("--max-per-ip", type=int, default=5)
    ap.add_argument("--state", default="faucet-state.json", help="rate-limit state file ('' to keep in memory only)")
    ap.add_argument("--confirm-blocks", type=int, default=0, help="mine this many blocks after each payout (on-demand PoW chains)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if not args.state:
        args.state = None
    url = args.rpcurl or f"http://127.0.0.1:{DEFAULT_RPC_PORT.get(args.chain, 8332)}"
    rpc = Rpc(url, rpc_auth(args))
    try:
        info = rpc("getblockchaininfo")
    except (RuntimeError, urllib.error.URLError) as e:
        sys.exit(f"cannot reach node at {url}: {e}")
    faucet = Faucet(rpc, args)

    if args.mode == "fund":
        addr, n, chain = faucet.fund_by_mining(args.blocks)
        print(json.dumps({"chain": chain, "mined": n, "to": addr, "balance": faucet.balance(), "note": "coinbase matures after 100 blocks"}, indent=1))
        return
    if args.mode == "send":
        if not args.address:
            sys.exit("send mode needs an address")
        res = faucet.pay(args.address, enforce_limits=False)
        print(json.dumps(res, indent=1))
        sys.exit(0 if res["ok"] else 1)
    Handler.faucet = faucet
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.verbose = args.verbose
    print(f"qtc-faucet: chain {info['chain']} wallet '{args.wallet}' balance {faucet.balance()} paying {args.amount}; serving http://{args.bind}:{args.port}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
