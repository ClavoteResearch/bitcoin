#!/usr/bin/env python3
"""mine-genesis: mine a Bitcoin-Core-style genesis block at a chosen difficulty and
print the values to paste into CChainParams (kernel/chainparams.cpp).

Standard library only; uses all CPU cores. Reproduces Core's CreateGenesisBlock()
exactly: coinbase scriptSig = PUSH(486604799) PUSH(4) PUSH(message), one output of
`reward` to <pubkey> OP_CHECKSIG, header version/time/bits/nonce.

Examples
  # reproduce the current qtctest genesis (regtest-strength target, finds nonce 0 instantly)
  mine-genesis.py --nbits 207fffff --time 1761782400 --expect 3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60

  # candidate for an open testnet: 1/256 of Bitcoin difficulty 1 (about 16.8 million hashes)
  mine-genesis.py --nbits 1e00ffff --time 1761782400

  # Bitcoin difficulty 1 (about 4.3 billion hashes; minutes to hours in Python, use --procs)
  mine-genesis.py --nbits 1d00ffff

Exit code 0 on success, 2 if --max-seconds elapsed, 3 if --expect does not match.
"""
import argparse, hashlib, json, multiprocessing as mp, os, struct, sys, time

SATOSHI_PUBKEY = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
DEFAULT_MSG = "Qcoin testnet 30/Oct/2026 ML-DSA witness v2 active from genesis"


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def push(b):
    n = len(b)
    if n < 0x4c:
        return bytes([n]) + b
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + b
    raise ValueError("push too long")


def script_num(v):
    # CScriptNum serialisation for small positive ints (as CScript() << int does)
    out = bytearray()
    while v:
        out.append(v & 0xff)
        v >>= 8
    if out and out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def coinbase_tx(message, pubkey_hex, reward):
    script_sig = push(script_num(486604799)) + push(script_num(4)) + push(message.encode())
    spk = push(bytes.fromhex(pubkey_hex)) + b"\xac"
    return (struct.pack("<i", 1) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff" + push(script_sig)[:0] + bytes([len(script_sig)]) + script_sig
            + b"\xff\xff\xff\xff" + b"\x01" + struct.pack("<q", reward) + bytes([len(spk)]) + spk + struct.pack("<I", 0)), script_sig


def nbits_to_target(nbits):
    exp, mant = nbits >> 24, nbits & 0x007fffff
    if nbits & 0x00800000:
        raise ValueError("negative target")
    return mant << (8 * (exp - 3)) if exp > 3 else mant >> (8 * (3 - exp))


def header(version, merkle, ntime, nbits, nonce):
    return struct.pack("<i", version) + b"\x00" * 32 + merkle + struct.pack("<III", ntime, nbits, nonce)


_BEST = None  # shared lowest nonce found so far; inherited by pool workers via _init


def _init(best):
    global _BEST
    _BEST = best


def worker(args):
    # Each worker scans the nonces start, start+step, ... and returns its FIRST success. To make
    # the result deterministic (the lowest valid nonce overall), a worker only gives up once
    # another worker's success is below the nonce it is about to try.
    version, merkle, ntime, nbits, target, start, step, limit, deadline = args
    best = _BEST
    prefix = struct.pack("<i", version) + b"\x00" * 32 + merkle + struct.pack("<II", ntime, nbits)
    nonce, tried = start, 0
    while nonce <= limit:
        if tried & 0xfff == 0:
            if best.value < nonce:
                return None, tried
            if deadline and time.time() > deadline:
                return None, tried
        h = dsha(prefix + struct.pack("<I", nonce))
        tried += 1
        if int.from_bytes(h, "little") < target:
            with best.get_lock():
                if nonce < best.value:
                    best.value = nonce
            return nonce, tried
        nonce += step
    return None, tried


def mine(version, merkle, ntime, nbits, procs, max_seconds):
    target = nbits_to_target(nbits)
    t0 = time.time()
    deadline = t0 + max_seconds if max_seconds else 0
    total = 0
    while True:
        best = mp.Value("Q", 1 << 63)
        chunk = 0xffffffff
        jobs = [(version, merkle, ntime, nbits, target, i, procs, chunk, deadline) for i in range(procs)]
        with mp.Pool(procs, initializer=_init, initargs=(best,)) as pool:
            found = None
            for nonce, tried in pool.imap_unordered(worker, jobs):
                total += tried
                if nonce is not None and (found is None or nonce < found):
                    found = nonce
        if found is not None:
            return found, ntime, total, time.time() - t0
        if deadline and time.time() > deadline:
            return None, ntime, total, time.time() - t0
        ntime += 1  # nonce space exhausted: bump the timestamp and continue


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--message", default=DEFAULT_MSG)
    ap.add_argument("--pubkey", default=SATOSHI_PUBKEY, help="genesis output pubkey (hex); the output is unspendable anyway")
    ap.add_argument("--reward", type=int, default=50 * 100_000_000, help="genesis reward in satoshis")
    ap.add_argument("--version", type=int, default=1)
    ap.add_argument("--time", type=int, default=int(time.time()), help="genesis timestamp (default: now)")
    ap.add_argument("--nbits", default="1e00ffff", help="compact target, hex (e.g. 207fffff regtest, 1e00ffff, 1d00ffff difficulty 1)")
    ap.add_argument("--procs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--max-seconds", type=float, default=0, help="give up after this long (0 = no limit)")
    ap.add_argument("--expect", help="genesis hash this run must reproduce (self-check)")
    ap.add_argument("--json", action="store_true", help="print only JSON")
    a = ap.parse_args()

    nbits = int(a.nbits, 16)
    target = nbits_to_target(nbits)
    pow_limit = target  # a genesis mined exactly at powLimit is the usual choice
    expected_hashes = (1 << 256) // target
    tx, script_sig = coinbase_tx(a.message, a.pubkey, a.reward)
    merkle = dsha(tx)
    if not a.json:
        print(f"mine-genesis: nBits 0x{nbits:08x} target 0x{target:064x}", file=sys.stderr)
        print(f"mine-genesis: expected work ~{expected_hashes:,} hashes; {a.procs} processes", file=sys.stderr)

    nonce, ntime, tried, secs = mine(a.version, merkle, a.time, nbits, a.procs, a.max_seconds)
    if nonce is None:
        print(json.dumps({"ok": False, "error": "max-seconds reached", "hashes_tried": tried, "seconds": round(secs, 1)}))
        sys.exit(2)
    h = dsha(header(a.version, merkle, ntime, nbits, nonce))
    genesis_hash, merkle_hex = h[::-1].hex(), merkle[::-1].hex()
    out = {
        "ok": True, "message": a.message, "time": ntime, "nonce": nonce, "nbits": f"0x{nbits:08x}", "version": a.version,
        "reward_sat": a.reward, "genesis_hash": genesis_hash, "merkle_root": merkle_hex, "coinbase_scriptsig": script_sig.hex(),
        "pow_limit": f"{pow_limit:064x}", "expected_hashes": expected_hashes, "hashes_tried": tried, "seconds": round(secs, 1),
        "rate_hps": int(tried / secs) if secs > 0 else None,
    }
    if a.expect and a.expect.lower() != genesis_hash:
        out["ok"] = False
        out["error"] = f"expected {a.expect}, got {genesis_hash}"
        print(json.dumps(out, indent=1))
        sys.exit(3)
    print(json.dumps(out, indent=1))
    if not a.json:
        print("\n// paste into CQtcTestParams (kernel/chainparams.cpp):", file=sys.stderr)
        print(f'consensus.powLimit = uint256{{"{pow_limit:064x}"}};', file=sys.stderr)
        print(f'genesis = CreateGenesisBlock("{a.message}", genesisOutputScript, {ntime}, {nonce}, 0x{nbits:08x}, {a.version}, {a.reward});', file=sys.stderr)
        print(f'assert(consensus.hashGenesisBlock == uint256{{"{genesis_hash}"}});', file=sys.stderr)
        print(f'assert(genesis.hashMerkleRoot == uint256{{"{merkle_hex}"}});', file=sys.stderr)


if __name__ == "__main__":
    main()
