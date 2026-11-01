#!/usr/bin/env python3
"""qtc-gbt-miner: a standalone solo CPU miner for a Qcoin node that speaks only getblocktemplate and submitblock.

It proves that mining does not need the node's built-in generatetoaddress: any program that uses the standard
getblocktemplate interface can produce valid blocks on this chain, including the coinbase that must pay a witness v2
ML-DSA output (the value rule). Standard library only; SHA-256d proof of work, so it is slow (about a megahash per
process) but enough for the minimal difficulty of qtctest.

    qtc-gbt-miner.py --address tq1z... [--chain qtctest] [--datadir ~/.bitcoin] [--rpcurl http://127.0.0.1:28332]
                     [--rpcuser U --rpcpassword P] [--procs N] [--blocks N | --until-height H]

The coinbase pays the whole subsidy plus fees to --address and carries the segwit witness commitment from the template.
"""
import argparse, base64, hashlib, json, multiprocessing as mp, os, struct, subprocess, sys, time, urllib.request, urllib.error

DEFAULT_RPC_PORT = {"qtctest": 28332, "regtest": 18443, "main": 8332, "test": 18332, "testnet4": 48332, "signet": 38332}
DATADIR_SUBDIR = {"qtctest": "qtctest", "regtest": "regtest", "main": "", "test": "testnet3", "testnet4": "testnet4", "signet": "signet"}
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def script_num(n):
    out = bytearray()
    while n:
        out.append(n & 0xff); n >>= 8
    if out and out[-1] & 0x80: out.append(0)
    return bytes(out)


def push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b


def script_int(n):
    """The BIP 34 height as bitcoind's CScript() << n encodes it: OP_0, OP_1..OP_16, else a minimal pushed number."""
    if n == 0: return b"\x00"
    if 1 <= n <= 16: return bytes([0x50 + n])
    return push(script_num(n))


# ---- bech32 / bech32m decoding of a segwit address
def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def decode_segwit(addr):
    addr = addr.lower()
    pos = addr.rfind("1")
    hrp, data = addr[:pos], [CHARSET.find(c) for c in addr[pos + 1:]]
    if pos < 1 or len(data) < 7 or -1 in data: raise ValueError("not a bech32 address")
    chk = _polymod([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data)
    if chk not in (1, 0x2bc830a3): raise ValueError("bad address checksum")
    witver, prog5 = data[0], data[1:-6]
    acc, bits, prog = 0, 0, []
    for v in prog5:
        acc = (acc << 5) | v; bits += 5
        while bits >= 8:
            bits -= 8; prog.append((acc >> bits) & 0xff)
    return witver, bytes(prog)


def spk_for(addr):
    ver, prog = decode_segwit(addr)
    return (b"\x00" if ver == 0 else bytes([0x50 + ver])) + push(prog), ver, len(prog)


class Rpc:
    def __init__(self, url, auth):
        self.url, self.auth, self.n = url, auth, 0

    def call(self, method, *params):
        self.n += 1
        req = urllib.request.Request(self.url, json.dumps({"jsonrpc": "1.0", "id": self.n, "method": method, "params": list(params)}).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(self.auth.encode()).decode()})
        try:
            r = json.loads(urllib.request.urlopen(req, timeout=120).read())
        except urllib.error.HTTPError as e:
            r = json.loads(e.read())
        if r.get("error"): raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]


def build_coinbase(height, value, spk, commitment_hex, extranonce):
    script_sig = script_int(height) + push(extranonce) + push(b"qtc-gbt-miner")
    vin = b"\x00" * 32 + b"\xff\xff\xff\xff" + varint(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
    outs = struct.pack("<q", value) + varint(len(spk)) + spk
    n_out = 1
    if commitment_hex:
        c = bytes.fromhex(commitment_hex)
        outs += struct.pack("<q", 0) + varint(len(c)) + c; n_out = 2
    body = varint(1) + vin + varint(n_out) + outs
    nonwit = struct.pack("<I", 2) + body + struct.pack("<I", 0)
    wit = struct.pack("<I", 2) + b"\x00\x01" + body + b"\x01\x20" + b"\x00" * 32 + struct.pack("<I", 0)
    return wit, sha256d(nonwit)


def merkle_root(txids):
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def worker(i, nproc, h76, target, found, q):
    base = hashlib.sha256(h76[:64]); tail = h76[64:76]
    tb = target.to_bytes(32, "big"); z = 0
    while z < 32 and tb[z] == 0: z += 1
    zeros = b"\x00" * z
    sha, pack, frm = hashlib.sha256, struct.pack, int.from_bytes
    n = i
    while n < 2 ** 32:
        for _ in range(8192):
            h = base.copy(); h.update(tail + pack("<I", n))
            d = sha(h.digest()).digest()
            if (z == 0 or d[32 - z:] == zeros) and frm(d, "little") <= target:
                q.put(n); found.set(); return
            n += nproc
            if n >= 2 ** 32: break
        if found.is_set(): return


SCANNER = None   # path of the native qtc-nonce-scan helper, if any


def solve_native(h76, target, nproc):
    """Run one native scanner per process on interleaved nonces; the first to print a nonce wins."""
    procs = [subprocess.Popen([SCANNER, h76.hex(), "%064x" % target, str(i), str(nproc)], stdout=subprocess.PIPE, text=True) for i in range(nproc)]
    nonce = None
    try:
        while nonce is None and procs:
            for p in list(procs):
                if p.poll() is not None:
                    out = p.stdout.read().strip(); procs.remove(p)
                    if out.isdigit():
                        nonce = int(out); break
            else:
                time.sleep(0.002)
    finally:
        for p in procs: p.kill()
        for p in procs: p.wait()
    return nonce


def solve(h76, target, nproc):
    if SCANNER:
        return solve_native(h76, target, nproc)
    ctx = mp.get_context("fork")
    found, q = ctx.Event(), ctx.Queue()
    ps = [ctx.Process(target=worker, args=(i, nproc, h76, target, found, q), daemon=True) for i in range(nproc)]
    for p in ps: p.start()
    nonce = None
    while nonce is None:
        try:
            nonce = q.get(timeout=0.05)
        except Exception:
            if not any(p.is_alive() for p in ps): break
    found.set()
    for p in ps: p.join(timeout=1)
    return nonce


def mine_one(rpc, spk, nproc, extranonce_counter):
    t = rpc.call("getblocktemplate", {"rules": ["segwit"]})
    height, value = t["height"], t["coinbasevalue"]
    txs = t["transactions"]
    while True:
        extranonce = struct.pack("<Q", extranonce_counter)
        cb, cb_txid = build_coinbase(height, value, spk, t.get("default_witness_commitment"), extranonce)
        root = merkle_root([cb_txid] + [bytes.fromhex(x["txid"])[::-1] for x in txs])
        ntime = max(t["curtime"], t["mintime"])
        h76 = struct.pack("<I", t["version"]) + bytes.fromhex(t["previousblockhash"])[::-1] + root + struct.pack("<II", ntime, int(t["bits"], 16))
        target = int(t["target"], 16)
        s0 = time.time()
        nonce = solve(h76, target, nproc)
        if nonce is not None: break
        extranonce_counter += 1   # nonce space exhausted: roll the extranonce
    header = h76 + struct.pack("<I", nonce)
    block = header + varint(1 + len(txs)) + cb + b"".join(bytes.fromhex(x["data"]) for x in txs)
    res = rpc.call("submitblock", block.hex())
    return height, sha256d(header)[::-1].hex(), len(txs), time.time() - s0, res, extranonce_counter + 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--address", required=True, help="witness v2 (or any segwit) address that receives the coinbase")
    ap.add_argument("--chain", default="qtctest"); ap.add_argument("--datadir", default=os.path.expanduser("~/.bitcoin"))
    ap.add_argument("--rpcurl"); ap.add_argument("--rpcuser"); ap.add_argument("--rpcpassword")
    ap.add_argument("--procs", type=int, default=os.cpu_count() or 1)
    g = ap.add_mutually_exclusive_group(); g.add_argument("--blocks", type=int); g.add_argument("--until-height", type=int)
    ap.add_argument("--scanner", help="path of the native qtc-nonce-scan helper (default: the one next to this script, if built)")
    a = ap.parse_args()
    global SCANNER
    cand = a.scanner or os.path.join(os.path.dirname(os.path.abspath(__file__)), "qtc-nonce-scan")
    SCANNER = cand if os.access(cand, os.X_OK) else None
    spk, ver, plen = spk_for(a.address)
    url = a.rpcurl or f"http://127.0.0.1:{DEFAULT_RPC_PORT[a.chain]}"
    if a.rpcuser:
        auth = f"{a.rpcuser}:{a.rpcpassword or ''}"
    else:
        auth = open(os.path.join(a.datadir, DATADIR_SUBDIR[a.chain], ".cookie")).read().strip()
    rpc = Rpc(url, auth)
    print(f"qtc-gbt-miner: {a.chain}, paying witness v{ver} program of {plen} bytes, {a.procs} processes, "
          f"{'native scanner ' + SCANNER if SCANNER else 'pure Python hashing'}", flush=True)
    done, en = 0, int(time.time()) & 0xffffff
    while True:
        h = rpc.call("getblockcount")
        if a.until_height is not None and h >= a.until_height: break
        if a.blocks is not None and done >= a.blocks: break
        height, bh, ntx, secs, res, en = mine_one(rpc, spk, a.procs, en)
        done += 1
        print(f"block height={height} hash={bh} txs={ntx + 1} time={secs:.2f}s submit={'OK' if res is None else res}", flush=True)
        if res is not None: sys.exit(1)
    print(f"done: {done} blocks, tip height {rpc.call('getblockcount')}", flush=True)


if __name__ == "__main__":
    main()
