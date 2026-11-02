// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstddef>
#include <cstdint>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits; covers the largest Qcoin block) */
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE{8'000'000};
/** The maximum allowed weight for a block on the Bitcoin chains, see BIP 141 (network rule). Chains read their own limit from Consensus::Params::nMaxBlockWeight. */
inline constexpr unsigned int MAX_BLOCK_WEIGHT{4'000'000};
/** Qcoin: block weight limit of the ML-DSA-only chains (regtest, qtctest). A witness v2 key-path spend is about 3.9k WU
 *  (about 1048 vB per transaction with change), so 8 MWU holds about 1950 of them, twice what 4 MWU does. */
inline constexpr unsigned int QCOIN_MAX_BLOCK_WEIGHT{8'000'000};
/** Upper bound of every chain's block weight; use for static sanity bounds that have no chain parameters at hand. */
inline constexpr unsigned int MAX_BLOCK_WEIGHT_CEILING{QCOIN_MAX_BLOCK_WEIGHT};
/** The maximum allowed number of signature check operations in a block (network rule) */
inline constexpr int64_t MAX_BLOCK_SIGOPS_COST{80'000};
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
inline constexpr int COINBASE_MATURITY = 100;

inline constexpr int WITNESS_SCALE_FACTOR = 4;

inline constexpr size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
inline constexpr size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
inline constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
inline constexpr int64_t MAX_TIMEWARP = 600;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
