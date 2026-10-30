// Experimental ML-DSA-87 signature verification path for the Qcoin (QTC) fork.
//
// This header was referenced by commit 13d6b525 ("route signature verification
// to ML-DSA-87 path") but was never committed. It is a local, build-unblocking
// implementation backed by liboqs (FIPS 204 ML-DSA-87, pure mode, empty ctx).
//
// Semantics: a signature is valid only if the public key and signature have
// exactly the ML-DSA-87 encoded lengths and OQS_SIG_verify succeeds. Anything
// else (including every secp256k1 ECDSA key/signature) is rejected.
//
// Define QCOIN_ECDSA_FALLBACK at compile time to fall back to legacy secp256k1
// ECDSA verification when the inputs are not ML-DSA-87 sized. This keeps
// regtest spends with ordinary wallet keys working during development.
#ifndef QCOIN_FORK_SCRIPT_VERIFY_STUB_H
#define QCOIN_FORK_SCRIPT_VERIFY_STUB_H

#include <consensus/params.h>
#include <pubkey.h>
#include <uint256.h>

#include <oqs/oqs.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

namespace Script {

namespace detail {
struct OqsSigDeleter {
    void operator()(OQS_SIG* s) const noexcept { if (s) OQS_SIG_free(s); }
};
inline OQS_SIG* MlDsa87()
{
    // Thread-safe lazy init; OQS_SIG objects are immutable after construction
    // and OQS_SIG_verify is re-entrant.
    static const std::unique_ptr<OQS_SIG, OqsSigDeleter> sig{OQS_SIG_new(OQS_SIG_alg_ml_dsa_87)};
    return sig.get();
}
} // namespace detail

static constexpr size_t MLDSA87_PUBKEY_LEN = OQS_SIG_ml_dsa_87_length_public_key; // 2592
static constexpr size_t MLDSA87_SIG_LEN    = OQS_SIG_ml_dsa_87_length_signature;  // 4627

inline bool IsMlDsa87Sized(std::span<const uint8_t> sig, std::span<const uint8_t> pubkey)
{
    return sig.size() == MLDSA87_SIG_LEN && pubkey.size() == MLDSA87_PUBKEY_LEN;
}

/** Verify sig over msg (the 32-byte sighash) with ML-DSA-87 public key pubkey. */
inline bool VerifySignature(std::span<const uint8_t> msg,
                            std::span<const uint8_t> sig,
                            std::span<const uint8_t> pubkey,
                            const Consensus::Params& /*params*/)
{
    if (IsMlDsa87Sized(sig, pubkey)) {
        OQS_SIG* s = detail::MlDsa87();
        if (!s) return false;
        return OQS_SIG_verify(s, msg.data(), msg.size(), sig.data(), sig.size(), pubkey.data()) == OQS_SUCCESS;
    }
#ifdef QCOIN_ECDSA_FALLBACK
    if (msg.size() == uint256::size()) {
        CPubKey pk(pubkey.begin(), pubkey.end());
        if (!pk.IsValid()) return false;
        uint256 hash;
        std::memcpy(hash.begin(), msg.data(), uint256::size());
        return pk.Verify(hash, std::vector<unsigned char>(sig.begin(), sig.end()));
    }
#endif
    return false;
}

} // namespace Script

#endif // QCOIN_FORK_SCRIPT_VERIFY_STUB_H
