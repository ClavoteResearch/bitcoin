// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <uint256.h>

class CBlockHeader;
class CBlockIndex;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Qcoin: height of the block whose identifier is the RandomX key for a block at `height`: 0 (the genesis block)
 * while height <= epoch + lag, otherwise the epoch start (height - lag - 1) rounded down to a multiple of the
 * epoch. With the defaults (2048, 64): blocks 1-2112 use the genesis hash, 2113-4160 the hash of block 2048,
 * 4161-6208 the hash of block 4096, and so on (Monero's seed-height rule).
 */
int RandomXKeyHeight(const Consensus::Params& params, int height);
/**
 * Qcoin, full-dataset mode only: called when the tip changes. From the key block of an epoch (a multiple of the epoch
 * length) until the first block that uses its key, nRandomXKeyLag + 1 blocks later, start building that key's cache
 * and dataset in the background, so the dataset is ready when the epoch's first block is validated. No-op in light mode
 * and on chains that never reach RandomX.
 */
void PrebuildRandomXKey(const Consensus::Params& params, const CBlockIndex* tip);
/** Returns the identifier of the block at a key height on the chain being extended, or nullopt if unknown. */
using RandomXKeyLookup = std::function<std::optional<uint256>(int key_height)>;
/** Key lookup along the chain that ends at `prev` (the parent of the block being checked). */
RandomXKeyLookup RandomXKeyLookupFromIndex(const CBlockIndex* prev);

/**
 * Qcoin: the proof-of-work hash of a header at the given height: the double SHA-256 (the block hash) below
 * Consensus::Params::RandomXHeight, RandomX over the 80 serialized header bytes at and above it, keyed with the
 * identifier of the block at RandomXKeyHeight (32 raw bytes in internal order). Throws std::runtime_error if
 * RandomX is needed and the key block is unknown or RandomX cannot allocate its cache.
 */
uint256 GetBlockPoWHash(const CBlockHeader& header, const Consensus::Params&, int height, const RandomXKeyLookup& key_lookup);
/**
 * Qcoin: check a header's proof of work at the given height (nBits range, target comparison). The genesis block
 * is exempt once RandomX applies to height 0. A RandomX height whose key block is unknown fails. With no height
 * (headers whose parent is unknown, used only for the anti-DoS pre-check of a headers message) a header is
 * accepted if it satisfies SHA-256d where that is possible on this chain, and otherwise if its nBits are valid:
 * without the parent the key cannot be known, and headers syncing verifies the real proof itself.
 */
bool CheckBlockHeaderPoW(const CBlockHeader& header, std::optional<int> height, const Consensus::Params&, const RandomXKeyLookup& key_lookup);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);

#endif // BITCOIN_POW_H
