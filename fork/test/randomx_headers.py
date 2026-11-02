#!/usr/bin/env python3
"""Helper for the RandomX regtests: craft an 80-byte block header on top of a given tip header.

  randomx_headers.py craft TIP_HEADER_HEX SCANNER TARGET64_HEX MODE KEY_HEX [OTHER_KEY_HEX]

TIP_HEADER_HEX is the 80-byte header of the current tip (getblockheader <hash> false). The new header has that tip as
parent, a fixed fake merkle root, the tip's time + 1 and the tip's bits. KEY_HEX is the RandomX key of the new block
(32 raw bytes, internal order, hex); qtc-randomx-scan does the RandomX part.
  sha-only       a nonce whose double SHA-256 meets the target but whose RandomX hash under KEY does not
  randomx        a nonce whose RandomX hash under KEY meets the target
  other-key-only a nonce whose RandomX hash meets the target under OTHER_KEY but not under KEY
Prints the header as hex.
"""
import hashlib, os, struct, subprocess, sys


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def main():
    cmd, tip_hex, scanner, target_hex, mode, key_hex = sys.argv[1:7]
    other_key = sys.argv[7] if len(sys.argv) > 7 else None
    assert cmd == "craft"
    tip = bytes.fromhex(tip_hex)
    assert len(tip) == 80
    version, bits, ttime = tip[0:4], tip[72:76], struct.unpack("<I", tip[68:72])[0]
    prev = sha256d(tip)  # internal byte order, as stored in the next header
    merkle = hashlib.sha256(b"randomx test header " + prev).digest()
    base = version + prev + merkle + struct.pack("<I", ttime + 1) + bits
    assert len(base) == 76
    target = int(target_hex, 16)

    def scan(key, start, maxcount):
        env = dict(os.environ, QTC_RX_THREADS="1", QTC_RX_KEY=key)
        args = [scanner, base.hex(), target_hex, str(start), "1"] + ([str(maxcount)] if maxcount else [])
        return subprocess.check_output(args, env=env).decode().split()

    if mode == "randomx":
        out = scan(key_hex, 0, 0)
        assert out[0] != "none", out
        print((base + struct.pack("<I", int(out[0]))).hex())
        return
    for nonce in range(0, 1 << 20):
        h = base + struct.pack("<I", nonce)
        if mode == "sha-only":
            if int.from_bytes(sha256d(h), "little") > target:
                continue
            if scan(key_hex, nonce, 1)[0] == "none":  # RandomX rejects this nonce
                print(h.hex())
                return
        else:  # other-key-only
            if scan(other_key, nonce, 1)[0] == "none":
                continue
            if scan(key_hex, nonce, 1)[0] == "none":
                print(h.hex())
                return
    sys.exit("no suitable nonce found")


main()
