// Qcoin (QTC) post-quantum wallet signature scheme switch, liboqs ML-DSA stubs,
// and a minimal development-only ML-DSA key store.
#include <pqc/pqc.h>

#include <oqs/oqs.h>

#include <atomic>
#include <cstring>
#include <fstream>
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

// --- tiny little-endian binary helpers for the key file ---
void PutU8(std::ostream& o, uint8_t v) { o.put(static_cast<char>(v)); }
void PutU32(std::ostream& o, uint32_t v)
{
    for (int i = 0; i < 4; ++i) o.put(static_cast<char>((v >> (8 * i)) & 0xff));
}
void PutBytes(std::ostream& o, std::span<const uint8_t> b)
{
    o.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
bool GetU8(std::istream& i, uint8_t& v)
{
    int c = i.get();
    if (c == std::char_traits<char>::eof()) return false;
    v = static_cast<uint8_t>(c);
    return true;
}
bool GetU32(std::istream& i, uint32_t& v)
{
    v = 0;
    for (int k = 0; k < 4; ++k) {
        uint8_t b;
        if (!GetU8(i, b)) return false;
        v |= static_cast<uint32_t>(b) << (8 * k);
    }
    return true;
}
bool GetBytes(std::istream& i, std::vector<uint8_t>& out, size_t n)
{
    out.resize(n);
    if (n == 0) return true;
    i.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
    return static_cast<size_t>(i.gcount()) == n;
}

constexpr char kMagic[8] = {'Q', 'C', 'O', 'I', 'N', 'P', 'Q', 'K'};
constexpr uint8_t kVersion = 1;

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

// ---------------------------------------------------------------------------
// MlDsaKeyStore
// ---------------------------------------------------------------------------

MlDsaKeyStore& MlDsaKeyStore::Instance()
{
    static MlDsaKeyStore store;
    return store;
}

void MlDsaKeyStore::Add(const KeyId& id, MlDsaKeyPair kp, bool make_default)
{
    std::lock_guard<std::mutex> l(m_mutex);
    m_keys[id] = std::move(kp);
    if (make_default || !m_default) m_default = id;
}

std::optional<MlDsaKeyPair> MlDsaKeyStore::Get(const KeyId& id) const
{
    std::lock_guard<std::mutex> l(m_mutex);
    auto it = m_keys.find(id);
    if (it == m_keys.end()) return std::nullopt;
    return it->second;
}

std::optional<MlDsaKeyPair> MlDsaKeyStore::GetDefault() const
{
    std::lock_guard<std::mutex> l(m_mutex);
    if (!m_default) return std::nullopt;
    auto it = m_keys.find(*m_default);
    if (it == m_keys.end()) return std::nullopt;
    return it->second;
}

std::optional<MlDsaKeyPair> MlDsaKeyStore::GetForSigning(const KeyId& id, SigScheme scheme) const
{
    if (auto k = Get(id); k && k->scheme == scheme) return k;
    if (auto d = GetDefault(); d && d->scheme == scheme) return d;
    return std::nullopt;
}

size_t MlDsaKeyStore::Size() const
{
    std::lock_guard<std::mutex> l(m_mutex);
    return m_keys.size();
}

void MlDsaKeyStore::Clear()
{
    std::lock_guard<std::mutex> l(m_mutex);
    for (auto& [id, kp] : m_keys) OQS_MEM_cleanse(kp.sk.data(), kp.sk.size());
    m_keys.clear();
    m_default.reset();
}

bool MlDsaKeyStore::Save(const std::string& path) const
{
    std::lock_guard<std::mutex> l(m_mutex);
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    if (!o) return false;
    o.write(kMagic, sizeof(kMagic));
    PutU8(o, kVersion);
    PutU32(o, static_cast<uint32_t>(m_keys.size()));
    for (const auto& [id, kp] : m_keys) {
        PutU8(o, static_cast<uint8_t>(kp.scheme));
        PutBytes(o, id);
        PutU32(o, static_cast<uint32_t>(kp.pk.size()));
        PutBytes(o, kp.pk);
        PutU32(o, static_cast<uint32_t>(kp.sk.size()));
        PutBytes(o, kp.sk);
        PutU8(o, (m_default && *m_default == id) ? 1 : 0);
    }
    return static_cast<bool>(o);
}

bool MlDsaKeyStore::Load(const std::string& path)
{
    std::ifstream i(path, std::ios::binary);
    if (!i) return false;
    char magic[8];
    i.read(magic, sizeof(magic));
    if (i.gcount() != static_cast<std::streamsize>(sizeof(magic)) || std::memcmp(magic, kMagic, sizeof(kMagic)) != 0) return false;
    uint8_t ver;
    uint32_t count;
    if (!GetU8(i, ver) || ver != kVersion || !GetU32(i, count)) return false;

    std::map<KeyId, MlDsaKeyPair> loaded;
    std::optional<KeyId> def;
    for (uint32_t n = 0; n < count; ++n) {
        uint8_t scheme_byte, is_default;
        uint32_t pklen, sklen;
        std::vector<uint8_t> idbuf;
        MlDsaKeyPair kp;
        if (!GetU8(i, scheme_byte) || scheme_byte > static_cast<uint8_t>(SigScheme::MLDSA87)) return false;
        kp.scheme = static_cast<SigScheme>(scheme_byte);
        if (!GetBytes(i, idbuf, 20)) return false;
        if (!GetU32(i, pklen) || pklen != MlDsaPubKeyLen(kp.scheme) || !GetBytes(i, kp.pk, pklen)) return false;
        if (!GetU32(i, sklen) || sklen != MlDsaSecKeyLen(kp.scheme) || !GetBytes(i, kp.sk, sklen)) return false;
        if (!GetU8(i, is_default)) return false;
        KeyId id;
        std::memcpy(id.data(), idbuf.data(), id.size());
        if (is_default) def = id;
        loaded.emplace(id, std::move(kp));
    }

    std::lock_guard<std::mutex> l(m_mutex);
    for (auto& [id, kp] : loaded) m_keys[id] = std::move(kp);
    if (def) m_default = def;
    else if (!m_default && !m_keys.empty()) m_default = m_keys.begin()->first;
    return true;
}

} // namespace qcoin::pqc
