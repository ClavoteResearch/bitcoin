// Qcoin: RandomX proof-of-work hash.
//
// RandomX v1.2.1 is vendored in fork/src/crypto/randomx (see VENDORED.txt). Blocks at or above
// Consensus::Params::RandomXHeight are proven with RandomX over the 80-byte block header (the layout and the
// nonce field are unchanged); the block identifier stays the double SHA-256 of the header. The RandomX key
// changes every epoch: it is the identifier of the block at the epoch's key height (see pow.h,
// RandomXKeyHeight, and doc/WALLET-PQC.md, "RandomX proof of work").
#ifndef QCOIN_CRYPTO_RANDOMX_POW_H
#define QCOIN_CRYPTO_RANDOMX_POW_H

#include <cstddef>

namespace qcoin::pow {

/**
 * RandomX hash of data[0..len) under the given key, written to out[0..32). Light mode: a 256 MiB cache per key,
 * built on first use and kept (the two most recently used keys stay cached, so the epoch boundary and short
 * reorgs across it do not rebuild a cache, and chains that never reach RandomX allocate nothing), and one
 * virtual machine per calling thread. Safe to call from many threads. Throws std::runtime_error if RandomX
 * cannot allocate its cache or virtual machine.
 */
void RandomXHash(const unsigned char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char out[32]);

} // namespace qcoin::pow

#endif // QCOIN_CRYPTO_RANDOMX_POW_H
