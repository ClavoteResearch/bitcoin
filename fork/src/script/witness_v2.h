// Qcoin (QTC) Option B: segwit v2 ML-DSA attestation outputs.
//
// This header collects the constants and the pure byte-level pieces of the
// "Segwit v2: ML-DSA Post-Quantum Signatures" BIP draft so that consensus
// (script/interpreter.cpp), the solver, descriptors, and address code can all
// point at one definition. Nothing here is reachable from consensus unless the
// build defines QCOIN_WITNESS_V2_EXPERIMENTAL; without it the interpreter keeps
// treating witness v2 as an unknown, upgradable version exactly as upstream.
//
// Spec references are to section numbers of docs/spec/bip-mldsa-formal.md in
// the clavote-boop/BIP repository. See doc/WALLET-PQC.md for the checklist.
#ifndef QCOIN_FORK_SCRIPT_WITNESS_V2_H
#define QCOIN_FORK_SCRIPT_WITNESS_V2_H

#include <crypto/sha256.h>
#include <hash.h>
#include <uint256.h>

#include <oqs/oqs.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace qcoin::v2 {

// ---- Section 1: output format --------------------------------------------
/** Witness version carried by OP_2. */
inline constexpr int WITNESS_V2_VERSION = 2;
/** scriptPubKey is OP_2 <32-byte program>; any other v2 length stays unencumbered. */
inline constexpr size_t WITNESS_V2_PROGRAM_SIZE = 32;
/** BIP 340 tagged-hash tag for the output commitment Q. */
inline constexpr const char* COMMITMENT_TAG = "MLDSAv2/Commit";

// ---- Section 2: parameter sets --------------------------------------------
inline constexpr uint8_t PARAM_ID_MLDSA44 = 0x01; //!< pk 1312, sig 2420 (the only defined set)
inline constexpr uint8_t PARAM_ID_MLDSA65 = 0x02; //!< reserved; spend invalid until a separate proposal
/**
 * NOT IN THE BIP. Accepted only when QCOIN_WITNESS_V2_EXPERIMENTAL is defined so
 * the existing -walletsigscheme=mldsa87 development path can exercise the v2
 * machinery. Must be removed or replaced by a real proposal before any deployment.
 */
inline constexpr uint8_t PARAM_ID_MLDSA87_EXPERIMENTAL = 0x7f;

inline constexpr size_t MLDSA44_PUBKEY_LEN = 1312;
inline constexpr size_t MLDSA44_SIG_LEN = 2420;
inline constexpr size_t MLDSA87_PUBKEY_LEN = 2592;
inline constexpr size_t MLDSA87_SIG_LEN = 4627;

/** Encoded sizes for a param_id, or nullopt if the id is not spendable. */
struct ParamSizes { size_t pk; size_t sig; };
inline std::optional<ParamSizes> SizesFor(uint8_t param_id)
{
    if (param_id == PARAM_ID_MLDSA44) return ParamSizes{MLDSA44_PUBKEY_LEN, MLDSA44_SIG_LEN};
#ifdef QCOIN_WITNESS_V2_EXPERIMENTAL
    if (param_id == PARAM_ID_MLDSA87_EXPERIMENTAL) return ParamSizes{MLDSA87_PUBKEY_LEN, MLDSA87_SIG_LEN};
#endif
    return std::nullopt; // 0x02 reserved; everything else invalid (section 2)
}

/** param_id implied by an encoded public key length, or nullopt. */
inline std::optional<uint8_t> ParamIdForPubKeyLen(size_t pk_len)
{
    if (pk_len == MLDSA44_PUBKEY_LEN) return PARAM_ID_MLDSA44;
#ifdef QCOIN_WITNESS_V2_EXPERIMENTAL
    if (pk_len == MLDSA87_PUBKEY_LEN) return PARAM_ID_MLDSA87_EXPERIMENTAL;
#endif
    return std::nullopt;
}

/** liboqs algorithm name for a spendable param_id, or nullptr. */
inline const char* OqsAlgFor(uint8_t param_id)
{
    if (param_id == PARAM_ID_MLDSA44) return OQS_SIG_alg_ml_dsa_44;
#ifdef QCOIN_WITNESS_V2_EXPERIMENTAL
    if (param_id == PARAM_ID_MLDSA87_EXPERIMENTAL) return OQS_SIG_alg_ml_dsa_87;
#endif
    return nullptr;
}

// ---- Section 3: witness structure -----------------------------------------
/** First byte of the final witness element when it is an attestation. */
inline constexpr uint8_t ATTESTATION_PREFIX = 0x51;
inline constexpr size_t ATTESTATION_MAX_ENTRIES = 4;

struct AttestationEntry {
    uint8_t param_id{0};
    std::span<const uint8_t> pubkey;    //!< FIPS 204 public key encoding
    std::span<const uint8_t> signature; //!< FIPS 204 canonical signature encoding
};

struct Attestation {
    std::vector<AttestationEntry> entries; //!< 1..4 entries, in witness order
};

/** True if the final witness element should be treated as an attestation (section 3). */
inline bool LooksLikeAttestation(std::span<const uint8_t> last_elem)
{
    return last_elem.size() > 1 && last_elem[0] == ATTESTATION_PREFIX;
}

/**
 * Parse 0x51 || n || (param_id || pk || sig)*n with no slack bytes.
 * Returns nullopt on any structural violation: bad prefix, n outside 1..4,
 * unknown/reserved param_id, or total length not matching the implied sum.
 * Spans point into `bytes`, which must outlive the result.
 */
inline std::optional<Attestation> ParseAttestation(std::span<const uint8_t> bytes)
{
    if (bytes.size() < 2 || bytes[0] != ATTESTATION_PREFIX) return std::nullopt;
    const size_t n = bytes[1];
    if (n < 1 || n > ATTESTATION_MAX_ENTRIES) return std::nullopt;
    Attestation out;
    size_t pos = 2;
    for (size_t i = 0; i < n; ++i) {
        if (pos >= bytes.size()) return std::nullopt;
        const uint8_t param_id = bytes[pos++];
        const auto sizes = SizesFor(param_id);
        if (!sizes) return std::nullopt;
        if (bytes.size() - pos < sizes->pk + sizes->sig) return std::nullopt;
        AttestationEntry e;
        e.param_id = param_id;
        e.pubkey = bytes.subspan(pos, sizes->pk);
        pos += sizes->pk;
        e.signature = bytes.subspan(pos, sizes->sig);
        pos += sizes->sig;
        out.entries.push_back(e);
    }
    if (pos != bytes.size()) return std::nullopt; // no free-form bytes anywhere (section 3)
    return out;
}

/** Serialise a single-entry attestation (key path). Inverse of ParseAttestation for n = 1. */
inline std::vector<uint8_t> BuildAttestation(uint8_t param_id, std::span<const uint8_t> pubkey, std::span<const uint8_t> signature)
{
    std::vector<uint8_t> out;
    out.reserve(3 + pubkey.size() + signature.size());
    out.push_back(ATTESTATION_PREFIX);
    out.push_back(1);
    out.push_back(param_id);
    out.insert(out.end(), pubkey.begin(), pubkey.end());
    out.insert(out.end(), signature.begin(), signature.end());
    return out;
}

// ---- Section 1: output commitment -----------------------------------------
/** pk_hash = SHA256(FIPS 204 public key encoding). */
inline uint256 PubKeyHash(std::span<const uint8_t> pubkey)
{
    uint256 h;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(h.begin());
    return h;
}

/**
 * Q = tagged_hash("MLDSAv2/Commit", param_id || pk_hash || merkle_root)
 * merkle_root is empty for key-path-only outputs, else the 32-byte BIP 341 root.
 */
inline uint256 ComputeCommitment(uint8_t param_id, const uint256& pk_hash, std::span<const uint8_t> merkle_root)
{
    HashWriter w = TaggedHash(COMMITMENT_TAG);
    w << param_id;
    w.write(std::as_bytes(std::span{pk_hash.begin(), pk_hash.size()}));
    if (!merkle_root.empty()) w.write(std::as_bytes(merkle_root));
    return w.GetSHA256();
}

/** True if `program` (the 32-byte v2 witness program) commits to this entry and merkle root. */
inline bool CheckCommitment(std::span<const uint8_t> program, const AttestationEntry& entry, std::span<const uint8_t> merkle_root)
{
    if (program.size() != WITNESS_V2_PROGRAM_SIZE) return false;
    const uint256 q = ComputeCommitment(entry.param_id, PubKeyHash(entry.pubkey), merkle_root);
    return std::equal(q.begin(), q.end(), program.begin());
}

// ---- Section 6: signature message and ML-DSA verification ------------------
/** FIPS 204 context string for every v2 signature. 11 ASCII bytes, no NUL. */
inline constexpr char SIGNATURE_CONTEXT[] = "BIP-MLDSAv2";
inline constexpr size_t SIGNATURE_CONTEXT_LEN = sizeof(SIGNATURE_CONTEXT) - 1;

/**
 * m = param_id || pk_hash || sighash  (1 + 32 + 32 = 65 bytes)
 * sighash is the BIP 341 signature hash of the spending input (SigVersion::TAPROOT
 * for the key path). Committing to param_id and pk_hash here makes a signature
 * meaningless under any other parameter set or key.
 */
inline std::vector<uint8_t> BuildSignatureMessage(uint8_t param_id, const uint256& pk_hash, const uint256& sighash)
{
    std::vector<uint8_t> m;
    m.reserve(65);
    m.push_back(param_id);
    m.insert(m.end(), pk_hash.begin(), pk_hash.end());
    m.insert(m.end(), sighash.begin(), sighash.end());
    return m;
}

/**
 * Pure ML-DSA verify of `signature` over `message` with ctx = SIGNATURE_CONTEXT,
 * using the parameter set named by param_id. Lengths must already match
 * SizesFor(param_id); returns false otherwise.
 *
 * NOT YET ENFORCED: canonical signature encoding (hint count <= omega, canonical
 * hints). liboqs accepts any decodable encoding, so a malleability pre-check is
 * still required before this can be consensus-grade.
 */
inline bool VerifyMlDsa(uint8_t param_id, std::span<const uint8_t> pubkey, std::span<const uint8_t> message, std::span<const uint8_t> signature)
{
    const auto sizes = SizesFor(param_id);
    const char* alg = OqsAlgFor(param_id);
    if (!sizes || !alg) return false;
    if (pubkey.size() != sizes->pk || signature.size() != sizes->sig) return false;
    if (!OQS_SIG_alg_is_enabled(alg)) return false;
    struct Del { void operator()(OQS_SIG* s) const noexcept { if (s) OQS_SIG_free(s); } };
    std::unique_ptr<OQS_SIG, Del> sig{OQS_SIG_new(alg)};
    if (!sig || !sig->sig_with_ctx_support) return false;
    return OQS_SIG_verify_with_ctx_str(sig.get(), message.data(), message.size(),
                                       signature.data(), signature.size(),
                                       reinterpret_cast<const uint8_t*>(SIGNATURE_CONTEXT), SIGNATURE_CONTEXT_LEN,
                                       pubkey.data()) == OQS_SUCCESS;
}

// ---- Section 5: script path (NOT IMPLEMENTED) ------------------------------
// Remaining stack is <inputs...> <leaf script> <control block>; control block
// <= 257 bytes; leaf scripts may not contain OP_SUCCESSx; OP_CHECKMLDSAVERIFY
// (0xb3 / OP_NOP4) pops <pk_hash:32> <i:1> and verifies attestation entry i.
inline constexpr size_t CONTROL_BLOCK_MAX_SIZE = 257;
inline constexpr uint8_t OP_CHECKMLDSAVERIFY_CODE = 0xb3; // OP_NOP4 under v2 leaf semantics only

} // namespace qcoin::v2

#endif // QCOIN_FORK_SCRIPT_WITNESS_V2_H
