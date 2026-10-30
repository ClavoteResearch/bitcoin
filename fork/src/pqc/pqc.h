// Qcoin (QTC) post-quantum wallet signature scheme switch and liboqs ML-DSA wrappers.
// ML-DSA secret keys live in the wallet database (walletdescriptormldsakey records);
// this library holds no key state.
//
// This module is wallet/signing-side only. Consensus verification lives in
// fork/src/script/verify_stub.h. See doc/WALLET-PQC.md for the integration plan
// and the list of remaining gaps.
#ifndef QCOIN_FORK_PQC_PQC_H
#define QCOIN_FORK_PQC_PQC_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace qcoin::pqc {

/** Signature scheme the wallet uses when producing new signatures. */
enum class SigScheme : uint8_t {
    ECDSA = 0,   //!< legacy secp256k1 ECDSA (default; keeps existing test flows working)
    MLDSA44 = 1, //!< FIPS 204 ML-DSA-44 (param_id 0x01 in the BIP draft)
    MLDSA87 = 2, //!< FIPS 204 ML-DSA-87 (what fork/src/script/verify_stub.h currently verifies)
};

/** Compile-time default, overridable with -DQCOIN_DEFAULT_SIG_SCHEME=<0|1|2>. */
#ifndef QCOIN_DEFAULT_SIG_SCHEME
#define QCOIN_DEFAULT_SIG_SCHEME 0
#endif

/** Runtime switch. Set once at startup from -walletsigscheme=<ecdsa|mldsa44|mldsa87>. */
SigScheme GetWalletSigScheme();
void SetWalletSigScheme(SigScheme scheme);
std::optional<SigScheme> ParseSigScheme(std::string_view name);
const char* SigSchemeName(SigScheme scheme);
/** Comma-separated list of accepted -walletsigscheme values, for help text. */
std::string SigSchemeNames();

/** Encoded sizes per FIPS 204; 0 for ECDSA (variable-length DER). */
size_t MlDsaPubKeyLen(SigScheme scheme);
size_t MlDsaSecKeyLen(SigScheme scheme);
size_t MlDsaSigLen(SigScheme scheme);

struct MlDsaKeyPair {
    SigScheme scheme{SigScheme::ECDSA};
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

/**
 * Generate a fresh ML-DSA keypair with liboqs.
 * Returns false for SigScheme::ECDSA or if liboqs lacks the parameter set.
 * NOTE: the secret key is NOT wiped on destruction yet; callers must handle that
 * until a proper secure-allocator wrapper lands (see doc/WALLET-PQC.md).
 */
bool MlDsaKeygen(SigScheme scheme, MlDsaKeyPair& out);

/**
 * Sign msg with an ML-DSA secret key (FIPS 204 pure mode, empty context).
 * Returns false if scheme is ECDSA, sk has the wrong length, or liboqs fails.
 * Output sig is exactly MlDsaSigLen(scheme) bytes (no sighash byte appended).
 */
bool MlDsaSign(SigScheme scheme, std::span<const uint8_t> sk, std::span<const uint8_t> msg, std::vector<uint8_t>& sig);

/** Verify an ML-DSA signature. Mirrors the consensus stub; useful for wallet self-checks. */
bool MlDsaVerify(SigScheme scheme, std::span<const uint8_t> pk, std::span<const uint8_t> msg, std::span<const uint8_t> sig);

/**
 * BIP section 6 context string. Duplicated from fork/src/script/witness_v2.h
 * (which this Core-free library cannot include); keep the two in sync.
 */
inline constexpr char SIGNATURE_CONTEXT[] = "BIP-MLDSAv2";
inline constexpr size_t SIGNATURE_CONTEXT_LEN = sizeof(SIGNATURE_CONTEXT) - 1;

/** BIP param_id for a scheme: 0x01 for ML-DSA-44, 0x7f (experimental, not in the BIP) for ML-DSA-87, 0 for ECDSA. */
uint8_t ParamIdFor(SigScheme scheme);

/** Sign/verify with a FIPS 204 context string (pure mode). Empty ctx == MlDsaSign/MlDsaVerify. */
bool MlDsaSignCtx(SigScheme scheme, std::span<const uint8_t> sk, std::span<const uint8_t> msg, std::span<const uint8_t> ctx, std::vector<uint8_t>& sig);
bool MlDsaVerifyCtx(SigScheme scheme, std::span<const uint8_t> pk, std::span<const uint8_t> msg, std::span<const uint8_t> ctx, std::span<const uint8_t> sig);

} // namespace qcoin::pqc

#endif // QCOIN_FORK_PQC_PQC_H
