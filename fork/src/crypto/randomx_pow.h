// Qcoin: RandomX proof-of-work hash.
//
// RandomX v1.2.1 is vendored in fork/src/crypto/randomx (see VENDORED.txt). Blocks at or above
// Consensus::Params::RandomXHeight are proven with RandomX over the 80-byte block header (the layout and the
// nonce field are unchanged); the block identifier stays the double SHA-256 of the header. The key is fixed for
// all chains for now: there is no key-block rotation (see doc/WALLET-PQC.md, "RandomX proof of work").
#ifndef QCOIN_CRYPTO_RANDOMX_POW_H
#define QCOIN_CRYPTO_RANDOMX_POW_H

#include <cstddef>

namespace qcoin::pow {

/** RandomX key (initialization seed) of every Qcoin chain: 16 ASCII bytes. */
inline constexpr char RANDOMX_KEY[] = "Qcoin-RandomX-v1";
inline constexpr size_t RANDOMX_KEY_LEN = sizeof(RANDOMX_KEY) - 1;

/**
 * RandomX hash of data[0..len) written to out[0..32). Uses light mode (a 256 MiB cache, built on first use, so
 * chains that never reach RandomX allocate nothing) and one virtual machine per calling thread. Throws
 * std::runtime_error if RandomX cannot allocate its cache or virtual machine.
 */
void RandomXHash(const unsigned char* data, size_t len, unsigned char out[32]);

} // namespace qcoin::pow

#endif // QCOIN_CRYPTO_RANDOMX_POW_H
