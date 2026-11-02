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
#include <cstdint>

namespace qcoin::pow {

/**
 * RandomX hash of data[0..len) under the given key, written to out[0..32). The hash is identical in every mode.
 *
 * Light mode (default): a 256 MiB cache per key, built on first use and kept for the two most recently used keys
 * (so the epoch boundary and short reorgs across it do not rebuild a cache), one virtual machine per calling thread.
 * Chains that never reach RandomX allocate nothing.
 *
 * Full mode (SetRandomXFullMode(true), node option -randomxfull): in addition a 2 GiB dataset per cached key
 * (three keys are cached in full mode, about 6.9 GiB with their caches; light mode keeps two). A dataset is built by a background thread pool the first time a key
 * is used; until it is ready hashing falls back to the cache, so a new epoch never stalls validation. Safe to call from
 * many threads. Throws std::runtime_error if RandomX cannot allocate its cache or virtual machine.
 */
void RandomXHash(const unsigned char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char out[32]);

/** Enable the full-dataset mode. Call once at start-up, before the first hash. */
void SetRandomXFullMode(bool full);
bool RandomXFullMode();

/**
 * Full mode only (a no-op in light mode): start building the cache and dataset of `key` in the background, so that they
 * are ready when the first block of the key's epoch arrives. Cheap to call repeatedly: the same key is only started once.
 * In full mode three keys are cached (the previous epoch, the current one and the one being prepared: about 6.9 GiB),
 * in light mode two.
 */
void PrepareRandomXKey(const unsigned char* key, size_t key_len);

struct RandomXStatus {
    bool full_mode{false};
    size_t keys_cached{0};       //!< keys with a built cache (at most 2 in light mode, 3 in full mode)
    size_t datasets_ready{0};    //!< of those, keys whose 2 GiB dataset is built and in use (full mode only)
    size_t datasets_building{0}; //!< of those, keys whose dataset is still being built
    uint64_t hashes_light{0};    //!< hashes computed with a cache since start
    uint64_t hashes_full{0};     //!< hashes computed with a dataset since start
    uint64_t estimated_memory_mib{0}; //!< 256 MiB per cached key plus 2048 MiB per allocated dataset (ready or building)
};
RandomXStatus GetRandomXStatus();

} // namespace qcoin::pow

#endif // QCOIN_CRYPTO_RANDOMX_POW_H
