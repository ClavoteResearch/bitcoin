// Qcoin (QTC) post-quantum wallet signature scheme switch and liboqs ML-DSA wrappers.
#include <pqc/pqc.h>

#include <oqs/oqs.h>

#include <atomic>
#include <memory>

namespace qcoin::pqc {

namespace {

std::atomic<SigScheme> g_wallet_sig_scheme{static_cast<SigScheme>(QCOIN_DEFAULT_SIG_SCHEME)};

const char* OqsAlgName(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::MLDSA44: return OQS_SIG_alg_ml_dsa_44;
    case SigScheme::MLDSA87: return OQS_SIG_alg_ml_dsa_87;
    case SigScheme::ECDSA: break;
    }
    return nullptr;
}

struct OqsSigDeleter {
    void operator()(OQS_SIG* s) const noexcept { if (s) OQS_SIG_free(s); }
};
using OqsSigPtr = std::unique_ptr<OQS_SIG, OqsSigDeleter>;

OqsSigPtr NewSig(SigScheme scheme)
{
    const char* alg = OqsAlgName(scheme);
    if (!alg || !OQS_SIG_alg_is_enabled(alg)) return nullptr;
    return OqsSigPtr{OQS_SIG_new(alg)};
}

} // namespace

SigScheme GetWalletSigScheme() { return g_wallet_sig_scheme.load(std::memory_order_relaxed); }
void SetWalletSigScheme(SigScheme scheme) { g_wallet_sig_scheme.store(scheme, std::memory_order_relaxed); }

std::optional<SigScheme> ParseSigScheme(std::string_view name)
{
    if (name == "ecdsa") return SigScheme::ECDSA;
    if (name == "mldsa44" || name == "ml-dsa-44") return SigScheme::MLDSA44;
    if (name == "mldsa87" || name == "ml-dsa-87") return SigScheme::MLDSA87;
    return std::nullopt;
}

const char* SigSchemeName(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::ECDSA: return "ecdsa";
    case SigScheme::MLDSA44: return "mldsa44";
    case SigScheme::MLDSA87: return "mldsa87";
    }
    return "unknown";
}

std::string SigSchemeNames() { return "ecdsa, mldsa44, mldsa87"; }

size_t MlDsaPubKeyLen(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::MLDSA44: return OQS_SIG_ml_dsa_44_length_public_key;
    case SigScheme::MLDSA87: return OQS_SIG_ml_dsa_87_length_public_key;
    case SigScheme::ECDSA: break;
    }
    return 0;
}

size_t MlDsaSecKeyLen(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::MLDSA44: return OQS_SIG_ml_dsa_44_length_secret_key;
    case SigScheme::MLDSA87: return OQS_SIG_ml_dsa_87_length_secret_key;
    case SigScheme::ECDSA: break;
    }
    return 0;
}

size_t MlDsaSigLen(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::MLDSA44: return OQS_SIG_ml_dsa_44_length_signature;
    case SigScheme::MLDSA87: return OQS_SIG_ml_dsa_87_length_signature;
    case SigScheme::ECDSA: break;
    }
    return 0;
}

bool MlDsaKeygen(SigScheme scheme, MlDsaKeyPair& out)
{
    OqsSigPtr sig = NewSig(scheme);
    if (!sig) return false;
    out.scheme = scheme;
    out.pk.assign(sig->length_public_key, 0);
    out.sk.assign(sig->length_secret_key, 0);
    if (OQS_SIG_keypair(sig.get(), out.pk.data(), out.sk.data()) != OQS_SUCCESS) {
        OQS_MEM_cleanse(out.sk.data(), out.sk.size());
        out.pk.clear();
        out.sk.clear();
        return false;
    }
    return true;
}

bool MlDsaSign(SigScheme scheme, std::span<const uint8_t> sk, std::span<const uint8_t> msg, std::vector<uint8_t>& sig_out)
{
    OqsSigPtr sig = NewSig(scheme);
    if (!sig) return false;
    if (sk.size() != sig->length_secret_key) return false;
    sig_out.assign(sig->length_signature, 0);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig.get(), sig_out.data(), &sig_len, msg.data(), msg.size(), sk.data()) != OQS_SUCCESS) {
        sig_out.clear();
        return false;
    }
    sig_out.resize(sig_len);
    return true;
}

bool MlDsaVerify(SigScheme scheme, std::span<const uint8_t> pk, std::span<const uint8_t> msg, std::span<const uint8_t> sig_in)
{
    OqsSigPtr sig = NewSig(scheme);
    if (!sig) return false;
    if (pk.size() != sig->length_public_key || sig_in.size() != sig->length_signature) return false;
    return OQS_SIG_verify(sig.get(), msg.data(), msg.size(), sig_in.data(), sig_in.size(), pk.data()) == OQS_SUCCESS;
}

uint8_t ParamIdFor(SigScheme scheme)
{
    switch (scheme) {
    case SigScheme::MLDSA44: return 0x01;
    case SigScheme::MLDSA87: return 0x7f; // experimental; not defined by the BIP
    case SigScheme::ECDSA: break;
    }
    return 0;
}

bool MlDsaSignCtx(SigScheme scheme, std::span<const uint8_t> sk, std::span<const uint8_t> msg, std::span<const uint8_t> ctx, std::vector<uint8_t>& sig_out)
{
    OqsSigPtr sig = NewSig(scheme);
    if (!sig || !sig->sig_with_ctx_support) return false;
    if (sk.size() != sig->length_secret_key) return false;
    sig_out.assign(sig->length_signature, 0);
    size_t sig_len = 0;
    if (OQS_SIG_sign_with_ctx_str(sig.get(), sig_out.data(), &sig_len, msg.data(), msg.size(), ctx.data(), ctx.size(), sk.data()) != OQS_SUCCESS) {
        sig_out.clear();
        return false;
    }
    sig_out.resize(sig_len);
    return true;
}

bool MlDsaVerifyCtx(SigScheme scheme, std::span<const uint8_t> pk, std::span<const uint8_t> msg, std::span<const uint8_t> ctx, std::span<const uint8_t> sig_in)
{
    OqsSigPtr sig = NewSig(scheme);
    if (!sig || !sig->sig_with_ctx_support) return false;
    if (pk.size() != sig->length_public_key || sig_in.size() != sig->length_signature) return false;
    return OQS_SIG_verify_with_ctx_str(sig.get(), msg.data(), msg.size(), sig_in.data(), sig_in.size(), ctx.data(), ctx.size(), pk.data()) == OQS_SUCCESS;
}

} // namespace qcoin::pqc
