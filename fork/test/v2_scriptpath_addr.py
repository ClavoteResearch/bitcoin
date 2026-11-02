#!/usr/bin/env python3
"""Compute an N-of-N witness v2 script-path output from ML-DSA public key hashes (no node needed).

  v2_scriptpath_addr.py PK_HASH_HEX [PK_HASH_HEX ...]        (1 to 4 keys, SHA-256 of each ML-DSA-44 public key)

Prints  spk=<hex> leaf=<hex> control=<hex>  for the single-leaf tree
  <pk_hash_0> OP_0 OP_CHECKMLDSAVERIFY <pk_hash_1> OP_1 OP_CHECKMLDSAVERIFY ... OP_1
with an unspendable internal key (the hash of a fixed string, so the key path cannot be used: the commitment includes the
Merkle root of the leaf). Mirrors fork/src/script/witness_v2.h (LeafHash, ComputeCommitment, BuildControlBlock).
"""
import hashlib, sys

PARAM_ID_MLDSA44 = 0x01
LEAF_VERSION = 0xC0


def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def compact_size(n):
    assert n < 0xFD
    return bytes([n])


def main():
    hashes = [bytes.fromhex(a) for a in sys.argv[1:]]
    assert 1 <= len(hashes) <= 4 and all(len(h) == 32 for h in hashes), "1 to 4 hashes of 32 bytes"
    leaf = b""
    for i, h in enumerate(hashes):
        leaf += b"\x20" + h + (b"\x00" if i == 0 else bytes([0x50 + i])) + b"\xb3"  # <h> OP_i OP_NOP4 (= OP_CHECKMLDSAVERIFY)
    leaf += b"\x51"  # OP_1
    leaf_hash = tagged_hash("TapLeaf", bytes([LEAF_VERSION]) + compact_size(len(leaf)) + leaf)
    internal = hashlib.sha256(b"qcoin unspendable internal key").digest()
    q = tagged_hash("MLDSAv2/Commit", bytes([PARAM_ID_MLDSA44]) + internal + leaf_hash)
    control = bytes([LEAF_VERSION, PARAM_ID_MLDSA44]) + internal
    print("spk=" + (b"\x52\x20" + q).hex())
    print("leaf=" + leaf.hex())
    print("control=" + control.hex())


main()
