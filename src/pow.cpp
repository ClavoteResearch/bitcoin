// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/check.h>
#include "../fork/src/crypto/randomx_pow.h" // Qcoin: RandomX proof of work
#include <uint256.h>
#include <util/check.h>

#include <limits>
#include <stdexcept>
#include <string>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

int RandomXKeyHeight(const Consensus::Params& params, int height)
{
    const int epoch{params.nRandomXKeyEpoch}, lag{params.nRandomXKeyLag};
    Assert(epoch > 0 && (epoch & (epoch - 1)) == 0); // a power of two
    if (height <= epoch + lag) return 0;
    return (height - lag - 1) & ~(epoch - 1);
}

void PrebuildRandomXKey(const Consensus::Params& params, const CBlockIndex* tip)
{
    if (!tip || params.RandomXHeight == std::numeric_limits<int>::max() || !qcoin::pow::RandomXFullMode()) return;
    const int epoch{params.nRandomXKeyEpoch}, lag{params.nRandomXKeyLag};
    const int key_height{tip->nHeight - tip->nHeight % epoch};
    if (key_height == 0) return;                                  // the genesis key is built on first use
    if (tip->nHeight - key_height > lag) return;                  // this epoch's key is already in use
    if (key_height + lag + 1 < params.RandomXHeight) return;      // RandomX does not apply yet at its first use
    const CBlockIndex* key_block{tip->GetAncestor(key_height)};
    if (!key_block) return;
    const uint256 key{key_block->GetBlockHash()};
    qcoin::pow::PrepareRandomXKey(key.begin(), key.size());
}

RandomXKeyLookup RandomXKeyLookupFromIndex(const CBlockIndex* prev)
{
    return [prev](int key_height) -> std::optional<uint256> {
        if (!prev || key_height > prev->nHeight) return std::nullopt;
        const CBlockIndex* key_block{prev->GetAncestor(key_height)};
        if (!key_block) return std::nullopt;
        return key_block->GetBlockHash();
    };
}

uint256 GetBlockPoWHash(const CBlockHeader& header, const Consensus::Params& params, int height, const RandomXKeyLookup& key_lookup)
{
    if (height < params.RandomXHeight) return header.GetHash();
    const std::optional<uint256> key{key_lookup ? key_lookup(RandomXKeyHeight(params, height)) : std::nullopt};
    if (!key) throw std::runtime_error("RandomX key block unavailable at height " + std::to_string(RandomXKeyHeight(params, height)));
    DataStream ss{};
    ss << header; // the 80 header bytes, nonce included
    Assert(ss.size() == 80);
    unsigned char out[32];
    qcoin::pow::RandomXHash(key->begin(), key->size(), UCharCast(ss.data()), ss.size(), out);
    return uint256(std::span<const unsigned char>(out, 32));
}

bool CheckBlockHeaderPoW(const CBlockHeader& header, std::optional<int> height, const Consensus::Params& params, const RandomXKeyLookup& key_lookup)
{
    if (height) {
        if (*height >= params.RandomXHeight && *height == 0 && header.GetHash() == params.hashGenesisBlock) return true;
        if (*height >= params.RandomXHeight && !(key_lookup && key_lookup(RandomXKeyHeight(params, *height)))) return false;
        return CheckProofOfWork(GetBlockPoWHash(header, params, *height, key_lookup), header.nBits, params);
    }
    // Unknown height: heights >= 1 are possible. SHA-256d applies below RandomXHeight, RandomX from it.
    const bool sha_possible = params.RandomXHeight > 1;
    const bool randomx_possible = params.RandomXHeight < std::numeric_limits<int>::max();
    if (sha_possible && CheckProofOfWork(header.GetHash(), header.nBits, params)) return true;
    return randomx_possible && DeriveTarget(header.nBits, params.powLimit).has_value();
}
