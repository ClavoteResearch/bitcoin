// Qcoin / Option B self-test: construct and verify a key-path segwit v2 ML-DSA spend.
//
// Built only with -DQCOIN_WITNESS_V2_EXPERIMENTAL=ON. Exits 0 when every check
// passes. This is not a unit test in the Boost framework (BUILD_TESTS is off
// in the current build); it is the smallest end-to-end exercise of
// VerifyScript -> VerifyWitnessProgram -> CheckMlDsaSignature.
#include "../src/script/witness_v2.h"

#include <consensus/amount.h>
#include <pqc/pqc.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <uint256.h>

#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

namespace {

int g_failures = 0;
void Check(bool ok, const char* what)
{
    std::printf("%s %s\n", ok ? "[PASS]" : "[FAIL]", what);
    if (!ok) ++g_failures;
}

template <class V>
std::span<const uint8_t> Span(const V& v) { return {v.data(), v.size()}; }

struct Fixture {
    qcoin::pqc::MlDsaKeyPair kp;
    uint8_t param_id{qcoin::v2::PARAM_ID_MLDSA44};
    uint256 pk_hash;
    uint256 commitment;
    CScript spk;
    CMutableTransaction funding;
    CMutableTransaction spend;
    PrecomputedTransactionData txdata;
    const CAmount amount{COIN};

    bool Build()
    {
        if (!qcoin::pqc::MlDsaKeygen(qcoin::pqc::SigScheme::MLDSA44, kp)) return false;
        pk_hash = qcoin::v2::PubKeyHash(Span(kp.pk));
        commitment = qcoin::v2::ComputeCommitment(param_id, pk_hash, {});
        spk = CScript() << OP_2 << std::vector<unsigned char>(commitment.begin(), commitment.end());

        funding.version = 2;
        funding.vout.emplace_back(amount, spk);

        spend.version = 2;
        spend.vin.emplace_back(COutPoint(funding.GetHash(), 0));
        spend.vout.emplace_back(amount - 1000, CScript() << OP_TRUE);

        txdata.Init(spend, std::vector<CTxOut>{funding.vout[0]}, /*force=*/true);
        return true;
    }

    std::vector<uint8_t> Sign(const uint256& sighash) const
    {
        const std::vector<uint8_t> msg = qcoin::v2::BuildSignatureMessage(param_id, pk_hash, sighash);
        const std::span<const uint8_t> ctx(reinterpret_cast<const uint8_t*>(qcoin::v2::SIGNATURE_CONTEXT), qcoin::v2::SIGNATURE_CONTEXT_LEN);
        std::vector<uint8_t> sig;
        if (!qcoin::pqc::MlDsaSignCtx(qcoin::pqc::SigScheme::MLDSA44, Span(kp.sk), msg, ctx, sig)) return {};
        return sig;
    }

    uint256 Sighash() const
    {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        uint256 h;
        const bool ok = SignatureHashSchnorr(h, execdata, spend, 0, SIGHASH_DEFAULT, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL);
        if (!ok) std::abort();
        return h;
    }

    bool Verify(const std::vector<uint8_t>& attestation, ScriptError& err,
                script_verify_flags flags = script_verify_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_MLDSA_V2}) const
    {
        CScriptWitness witness;
        witness.stack.push_back(attestation);
        MutableTransactionSignatureChecker checker(&spend, 0, amount, txdata, MissingDataBehavior::FAIL);
        return VerifyScript(CScript(), spk, &witness, flags, checker, &err);
    }
};

} // namespace

int main()
{
    std::printf("qcoin-v2-selftest: segwit v2 ML-DSA-44 key-path spend\n");
    Fixture f;
    Check(f.Build(), "fixture built (ML-DSA-44 keygen, OP_2 <Q> output, spending tx)");
    std::printf("  pk=%zu bytes  Q=%s\n", f.kp.pk.size(), f.commitment.ToString().substr(0, 16).c_str());

    const uint256 sighash = f.Sighash();
    const std::vector<uint8_t> sig = f.Sign(sighash);
    Check(sig.size() == qcoin::v2::MLDSA44_SIG_LEN, "signature over BIP-MLDSAv2 message has ML-DSA-44 length (2420)");

    // 1. Valid spend
    {
        ScriptError err{SCRIPT_ERR_OK};
        const auto att = qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), sig);
        const bool ok = f.Verify(att, err);
        Check(ok && err == SCRIPT_ERR_OK, "valid key-path spend verifies");
        if (!ok) std::printf("  error: %s\n", ScriptErrorString(err).c_str());
        std::printf("  attestation=%zu bytes\n", att.size());
    }
    // 2. Corrupted signature -> SCRIPT_ERR_MLDSA_SIG
    {
        ScriptError err{SCRIPT_ERR_OK};
        auto bad = sig; bad[100] ^= 0x01;
        const bool ok = f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err);
        Check(!ok && err == SCRIPT_ERR_MLDSA_SIG, "flipped signature bit -> SCRIPT_ERR_MLDSA_SIG");
        if (ok || err != SCRIPT_ERR_MLDSA_SIG) std::printf("  got: %s\n", ScriptErrorString(err).c_str());
    }
    // 3. Signature from a different message (wrong sighash) -> SCRIPT_ERR_MLDSA_SIG
    {
        ScriptError err{SCRIPT_ERR_OK};
        uint256 other = sighash; *other.begin() ^= 0xff;
        const bool ok = f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), f.Sign(other)), err);
        Check(!ok && err == SCRIPT_ERR_MLDSA_SIG, "signature over another sighash -> SCRIPT_ERR_MLDSA_SIG");
    }
    // 4. Wrong public key (commitment mismatch) -> SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH
    {
        ScriptError err{SCRIPT_ERR_OK};
        qcoin::pqc::MlDsaKeyPair other;
        qcoin::pqc::MlDsaKeygen(qcoin::pqc::SigScheme::MLDSA44, other);
        const bool ok = f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(other.pk), sig), err);
        Check(!ok && err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "attested pubkey not committed by output -> SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH");
    }
    // 5. Malformed attestation (one slack byte) -> SCRIPT_ERR_MLDSA_ATTESTATION
    {
        ScriptError err{SCRIPT_ERR_OK};
        auto att = qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), sig);
        att.push_back(0x00);
        const bool ok = f.Verify(att, err);
        Check(!ok && err == SCRIPT_ERR_MLDSA_ATTESTATION, "attestation with trailing byte -> SCRIPT_ERR_MLDSA_ATTESTATION");
    }
    // 6. Reserved param_id 0x02 -> SCRIPT_ERR_MLDSA_ATTESTATION
    {
        ScriptError err{SCRIPT_ERR_OK};
        auto att = qcoin::v2::BuildAttestation(qcoin::v2::PARAM_ID_MLDSA65, Span(f.kp.pk), sig);
        const bool ok = f.Verify(att, err);
        Check(!ok && err == SCRIPT_ERR_MLDSA_ATTESTATION, "reserved param_id 0x02 -> SCRIPT_ERR_MLDSA_ATTESTATION");
    }
    // 7. Signature made WITHOUT the BIP context must not verify
    {
        ScriptError err{SCRIPT_ERR_OK};
        const std::vector<uint8_t> msg = qcoin::v2::BuildSignatureMessage(f.param_id, f.pk_hash, sighash);
        std::vector<uint8_t> noctx;
        qcoin::pqc::MlDsaSign(qcoin::pqc::SigScheme::MLDSA44, Span(f.kp.sk), msg, noctx);
        const bool ok = f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), noctx), err);
        Check(!ok && err == SCRIPT_ERR_MLDSA_SIG, "signature without ctx BIP-MLDSAv2 -> SCRIPT_ERR_MLDSA_SIG");
    }

    // 7b. Soft-fork semantics: without SCRIPT_VERIFY_MLDSA_V2 a v2 output is an unknown
    //     upgradable version (anyone-can-spend), and policy discourages it.
    {
        ScriptError err{SCRIPT_ERR_OK};
        auto bad = sig; bad[7] ^= 0x80;
        const script_verify_flags no_flag{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
        Check(f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err, no_flag), "without MLDSA_V2 flag: invalid attestation passes as an unknown witness version (pre-activation consensus)");
        Check(!f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err, no_flag | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) && err == SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
              "without MLDSA_V2 flag + DISCOURAGE: rejected as upgradable witness (pre-activation policy)");
        Check(!f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err) && err == SCRIPT_ERR_MLDSA_SIG, "with MLDSA_V2 flag: invalid attestation rejected");
    }

    // 9. Canonical signature encoding (FIPS 204 HintBitUnpack rules), checked before liboqs
    {
        using qcoin::v2::IsCanonicalMlDsaSignature;
        const auto hp = *qcoin::v2::HintParamsFor(f.param_id);
        const size_t hoff = sig.size() - (hp.omega + hp.k); // start of the hint area h
        Check(IsCanonicalMlDsaSignature(f.param_id, sig), "fresh liboqs signature is canonical");
        const size_t total = sig[hoff + hp.omega + hp.k - 1];
        std::printf("  hints used: %zu of %zu\n", total, hp.omega);
        auto raw_oqs = [&](const std::vector<uint8_t>& s) {
            const std::vector<uint8_t> msg = qcoin::v2::BuildSignatureMessage(f.param_id, f.pk_hash, sighash);
            const std::span<const uint8_t> ctx(reinterpret_cast<const uint8_t*>(qcoin::v2::SIGNATURE_CONTEXT), qcoin::v2::SIGNATURE_CONTEXT_LEN);
            return qcoin::pqc::MlDsaVerifyCtx(qcoin::pqc::SigScheme::MLDSA44, Span(f.kp.pk), msg, ctx, s);
        };
        // 9a. garbage in the unused index area (same hint vector, different bytes)
        if (total < hp.omega) {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = sig; bad[hoff + hp.omega - 1] = 0x01;
            Check(!IsCanonicalMlDsaSignature(f.param_id, bad), "non-zero padding in hint area -> not canonical");
            const bool ok = f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err);
            Check(!ok && err == SCRIPT_ERR_MLDSA_SIG_ENCODING, "padding-malleated signature -> SCRIPT_ERR_MLDSA_SIG_ENCODING");
            std::printf("  (liboqs alone %s this encoding)\n", raw_oqs(bad) ? "ACCEPTS" : "rejects");
        }
        // 9b. cumulative count above omega
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = sig; bad[hoff + hp.omega + hp.k - 1] = static_cast<uint8_t>(hp.omega + 1);
            Check(!IsCanonicalMlDsaSignature(f.param_id, bad), "hint count > omega -> not canonical");
            Check(!f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err) && err == SCRIPT_ERR_MLDSA_SIG_ENCODING, "hint count > omega -> SCRIPT_ERR_MLDSA_SIG_ENCODING");
        }
        // 9c. decreasing cumulative counts
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = sig; bad[hoff + hp.omega] = static_cast<uint8_t>(bad[hoff + hp.omega + 1] + 1);
            Check(!IsCanonicalMlDsaSignature(f.param_id, bad), "decreasing cumulative hint counts -> not canonical");
            Check(!f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err) && err == SCRIPT_ERR_MLDSA_SIG_ENCODING, "decreasing counts -> SCRIPT_ERR_MLDSA_SIG_ENCODING");
        }
        // 9d. repeated index inside the first polynomial (needs >= 2 hints there)
        if (sig[hoff + hp.omega] >= 2) {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = sig; bad[hoff + 1] = bad[hoff + 0];
            Check(!IsCanonicalMlDsaSignature(f.param_id, bad), "non-increasing hint index -> not canonical");
            Check(!f.Verify(qcoin::v2::BuildAttestation(f.param_id, Span(f.kp.pk), bad), err) && err == SCRIPT_ERR_MLDSA_SIG_ENCODING, "repeated hint index -> SCRIPT_ERR_MLDSA_SIG_ENCODING");
            std::printf("  (liboqs alone %s this encoding)\n", raw_oqs(bad) ? "ACCEPTS" : "rejects");
        } else {
            std::printf("  (9d skipped: first polynomial has < 2 hints)\n");
        }
        // 9e. wrong length is not canonical either
        Check(!IsCanonicalMlDsaSignature(f.param_id, std::span<const uint8_t>(sig.data(), sig.size() - 1)), "truncated signature -> not canonical");
    }

    // 8. Seeded keygen is deterministic and seed-sensitive
    {
        qcoin::pqc::SecureBytes master(32, 0x42);
        qcoin::pqc::SecureBytes s0 = qcoin::pqc::DeriveMlDsaChildSeed(master, 0);
        qcoin::pqc::SecureBytes s1 = qcoin::pqc::DeriveMlDsaChildSeed(master, 1);
        qcoin::pqc::MlDsaKeyPair a, b, c;
        const bool ok = qcoin::pqc::MlDsaKeygenFromSeed(qcoin::pqc::SigScheme::MLDSA44, s0, a) &&
                        qcoin::pqc::MlDsaKeygenFromSeed(qcoin::pqc::SigScheme::MLDSA44, s0, b) &&
                        qcoin::pqc::MlDsaKeygenFromSeed(qcoin::pqc::SigScheme::MLDSA44, s1, c);
        Check(ok && a.pk == b.pk && a.sk == b.sk, "seeded keygen: same seed -> same keypair");
        Check(ok && a.pk != c.pk, "seeded keygen: different index -> different key");
        qcoin::pqc::MlDsaKeyPair r;
        Check(qcoin::pqc::MlDsaKeygen(qcoin::pqc::SigScheme::MLDSA44, r) && r.pk != a.pk, "random keygen still works after seeded keygen (system RNG restored)");
    }

    std::printf("%s (%d failure%s)\n", g_failures ? "SELFTEST FAILED" : "SELFTEST OK", g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
