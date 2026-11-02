#!/usr/bin/env python3
"""Helper for regtest_randomx.sh: craft an 80-byte block header on top of a given tip header.

  randomx_headers.py craft TIP_HEADER_HEX SCANNER TARGET64_HEX sha-only|randomx

TIP_HEADER_HEX is the 80-byte header of the current tip (getblockheader <hash> false). The new header has that tip as
parent, a fixed fake merkle root, the tip's time + 1 and the tip's bits.
  sha-only  finds a nonce whose double SHA-256 meets the target but whose RandomX hash does not
  randomx   finds a nonce whose RandomX hash meets the target (qtc-randomx-scan does the RandomX part)
Prints the header as hex.
"""
import hashlib, os, struct, subprocess, sys


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def block_hash(h80):
    return sha256d(h80)


def main():
    cmd, tip_hex, scanner, target_hex, mode = sys.argv[1:6]
    assert cmd == "craft"
    tip = bytes.fromhex(tip_hex)
    assert len(tip) == 80
    version, bits, ttime = tip[0:4], tip[72:76], struct.unpack("<I", tip[68:72])[0]
    prev = block_hash(tip)  # internal byte order, as stored in the next header
    merkle = hashlib.sha256(b"randomx test header " + prev).digest()
    base = version + prev + merkle + struct.pack("<I", ttime + 1) + bits
    assert len(base) == 76
    target = int(target_hex, 16)
    env = dict(os.environ, QTC_RX_THREADS="1")

    def scan(start, maxcount):
        args = [scanner, base.hex(), target_hex, str(start), "1"] + ([str(maxcount)] if maxcount else [])
        return subprocess.check_output(args, env=env).decode().split()

    if mode == "randomx":
        out = scan(0, 0)
        assert out[0] != "none", out
        print((base + struct.pack("<I", int(out[0]))).hex())
        return
    for nonce in range(0, 1 << 20):
        h = base + struct.pack("<I", nonce)
        if int.from_bytes(sha256d(h), "little") > target:
            continue
        res = scan(nonce, 1)
        if res[0] == "none":  # RandomX rejects this nonce
            print(h.hex())
            return
    sys.exit("no SHA-only nonce found")


main()
