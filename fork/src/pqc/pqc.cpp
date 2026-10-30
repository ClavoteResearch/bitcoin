// Qcoin (QTC) post-quantum wallet signature scheme switch and liboqs ML-DSA wrappers.
#include <pqc/pqc.h>

#include <oqs/oqs.h>
#include <crypto/hmac_sha512.h>
#include <oqs/rand.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>

namespace qcoin::pqc {

namespace {

std::atomic<SigScheme> g_wallet_sig_scheme{static_cast<SigScheme>(QCOIN_DEFAULT_SIG_SCHEME)};

/** Serialises every liboqs call made by this module (see MlDsaKeygenFromSeed). */
std::mutex g_oqs_mutex;

// State for the temporary deterministic random source used by MlDsaKeygenFromSeed.
const uint8_t* g_seed_ptr{nullptr};
bool g_seed_served{false};
bool g_seed_unexpected{false};
void SeededRandombytes(uint8_t* buf, size_t n)
{
    if (!g_seed_served && g_seed_ptr && n == MLDSA_SEED_LEN) {
        std::memcpy(buf, g_seed_ptr, n);
        g_seed_served = true;
        return;
    }
    // Any other request means the algorithm is not the single-seed keygen we expect.
    g_seed_unexpected = true;
    std::memset(buf, 0, n);
}

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
    std::lock_guard<std::mutex> l(g_oqs_mutex);
    OqsSigPtr sig = NewSig(scheme);
    if (!sig) return false;
    out.scheme = scheme;
    out.pk.assign(sig->length_public_key, 0);
    out.sk.assign(sig->length_secret_key, 0);
    if (OQS_SIG_keypair(sig.get(), out.pk.data(), out.sk.data()) != OQS_SUCCESS) {
        out.pk.clear();
        WipeSecret(out.sk);
        return false;
    }
    return true;
}

void WipeSecret(SecureBytes& secret)
{
    if (!secret.empty()) OQS_MEM_cleanse(secret.data(), secret.size());
    SecureBytes().swap(secret); // deallocate now; secure_allocator cleanses again on free
}

bool MlDsaSign(SigScheme scheme, std::span<const uint8_t> sk, std::span<const uint8_t> msg, std::vector<uint8_t>& sig_out)
{
    std::lock_guard<std::mutex> l(g_oqs_mutex);
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
    std::lock_guard<std::mutex> l(g_oqs_mutex);
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

bool MlDsaKeygenFromSeed(SigScheme scheme, std::span<const uint8_t> seed, MlDsaKeyPair& out)
{
    if (seed.size() != MLDSA_SEED_LEN) return false;
    std::lock_guard<std::mutex> l(g_oqs_mutex);
    OqsSigPtr sig = NewSig(scheme);
    if (!sig) return false;
    out.scheme = scheme;
    out.pk.assign(sig->length_public_key, 0);
    out.sk.assign(sig->length_secret_key, 0);

    g_seed_ptr = seed.data();
    g_seed_served = false;
    g_seed_unexpected = false;
    OQS_randombytes_custom_algorithm(&SeededRandombytes);
    const OQS_STATUS rc = OQS_SIG_keypair(sig.get(), out.pk.data(), out.sk.data());
    // Restore the system RNG before anything else can run.
    (void)OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    g_seed_ptr = nullptr;
    const bool ok = rc == OQS_SUCCESS && g_seed_served && !g_seed_unexpected;
    if (!ok) {
        out.pk.clear();
        WipeSecret(out.sk);
    }
    return ok;
}

SecureBytes DeriveMlDsaMaster(std::span<const uint8_t> root_privkey)
{
    static const char tag[] = "Qcoin/MLDSAv2/master";
    unsigned char out[CHMAC_SHA512::OUTPUT_SIZE];
    CHMAC_SHA512(reinterpret_cast<const unsigned char*>(tag), sizeof(tag) - 1).Write(root_privkey.data(), root_privkey.size()).Finalize(out);
    SecureBytes master(out, out + MLDSA_SEED_LEN);
    OQS_MEM_cleanse(out, sizeof(out));
    return master;
}

SecureBytes DeriveMlDsaChildSeed(const SecureBytes& master, uint32_t index)
{
    static const char tag[] = "MLDSAv2/child";
    const uint8_t idx[4] = {uint8_t(index), uint8_t(index >> 8), uint8_t(index >> 16), uint8_t(index >> 24)};
    unsigned char out[CHMAC_SHA512::OUTPUT_SIZE];
    CHMAC_SHA512(master.data(), master.size()).Write(reinterpret_cast<const unsigned char*>(tag), sizeof(tag) - 1).Write(idx, 4).Finalize(out);
    SecureBytes seed(out, out + MLDSA_SEED_LEN);
    OQS_MEM_cleanse(out, sizeof(out));
    return seed;
}

} // namespace qcoin::pqc
