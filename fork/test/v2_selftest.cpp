// Qcoin / Option B self-test: construct and verify key-path and script-path segwit v2 ML-DSA spends.
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

/** One script-path output (internal key + one leaf + Merkle path) and a transaction spending it. */
struct ScriptPathCase {
    uint8_t param_id{qcoin::v2::PARAM_ID_MLDSA44};
    uint8_t leaf_version{qcoin::v2::LEAF_VERSION_MLDSA};
    uint256 internal_pk_hash;
    CScript leaf;
    std::vector<uint256> path;
    uint256 leaf_hash, root, q;
    CScript spk;
    std::vector<uint8_t> control;
    CMutableTransaction spend;
    PrecomputedTransactionData txdata;
    const CAmount amount{COIN};

    void Build(const uint256& internal, const CScript& l, std::vector<uint256> p, uint8_t lv = qcoin::v2::LEAF_VERSION_MLDSA)
    {
        using namespace qcoin::v2;
        leaf_version = lv;
        internal_pk_hash = internal; leaf = l; path = std::move(p);
        leaf_hash = LeafHash(leaf_version, Span(leaf));
        root = leaf_hash;
        for (const uint256& n : path) root = BranchHash(root, n);
        q = ComputeCommitment(param_id, internal_pk_hash, std::span<const uint8_t>(root.begin(), root.size()));
        spk = CScript() << OP_2 << std::vector<unsigned char>(q.begin(), q.end());
        control = BuildControlBlock(leaf_version, param_id, internal_pk_hash, path);
        CMutableTransaction funding; funding.version = 2; funding.vout.emplace_back(amount, spk);
        spend = CMutableTransaction{}; spend.version = 2;
        spend.vin.emplace_back(COutPoint(funding.GetHash(), 0));
        spend.vout.emplace_back(amount - 1000, CScript() << OP_TRUE);
        txdata.Init(spend, std::vector<CTxOut>{funding.vout[0]}, /*force=*/true);
    }
    uint256 LeafSighash() const
    {
        ScriptExecutionData ed; ed.m_annex_init = true; ed.m_annex_present = false;
        ed.m_tapleaf_hash = leaf_hash; ed.m_tapleaf_hash_init = true;
        ed.m_codeseparator_pos = 0xFFFFFFFFUL; ed.m_codeseparator_pos_init = true;
        uint256 h;
        if (!SignatureHashSchnorr(h, ed, spend, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) std::abort();
        return h;
    }
    uint256 KeyPathSighash() const
    {
        ScriptExecutionData ed; ed.m_annex_init = true; ed.m_annex_present = false;
        uint256 h;
        if (!SignatureHashSchnorr(h, ed, spend, 0, SIGHASH_DEFAULT, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)) std::abort();
        return h;
    }
    std::vector<uint8_t> SignWith(const qcoin::pqc::MlDsaKeyPair& k, const uint256& sighash) const
    {
        const std::vector<uint8_t> msg = qcoin::v2::BuildSignatureMessage(param_id, qcoin::v2::PubKeyHash(Span(k.pk)), sighash);
        const std::span<const uint8_t> ctx(reinterpret_cast<const uint8_t*>(qcoin::v2::SIGNATURE_CONTEXT), qcoin::v2::SIGNATURE_CONTEXT_LEN);
        std::vector<uint8_t> s;
        if (!qcoin::pqc::MlDsaSignCtx(qcoin::pqc::SigScheme::MLDSA44, Span(k.sk), msg, ctx, s)) std::abort();
        return s;
    }
    std::vector<unsigned char> LeafBytes() const { return {leaf.begin(), leaf.end()}; }
    bool Verify(std::vector<std::vector<unsigned char>> stack, ScriptError& err,
                script_verify_flags flags = script_verify_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_MLDSA_V2 | SCRIPT_VERIFY_MINIMALDATA}) const
    {
        CScriptWitness w; w.stack = std::move(stack);
        MutableTransactionSignatureChecker checker(&spend, 0, amount, txdata, MissingDataBehavior::FAIL);
        return VerifyScript(CScript(), spk, &w, flags, checker, &err);
    }
};

} // namespace

int main()
{
    std::printf("qcoin-v2-selftest: segwit v2 ML-DSA-44 key-path and script-path spends\n");
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

    // 10. Script path (section 5): <inputs> <leaf> <control> <attestation>, OP_CHECKMLDSAVERIFY
    {
        using namespace qcoin::v2;
        qcoin::pqc::MlDsaKeyPair leafkey;
        Check(qcoin::pqc::MlDsaKeygen(qcoin::pqc::SigScheme::MLDSA44, leafkey), "leaf key generated");
        const uint256 leaf_pk_hash = PubKeyHash(Span(leafkey.pk));
        const uint256 sibling = LeafHash(LEAF_VERSION_MLDSA, Span(CScript() << OP_RETURN)); // an unrelated second leaf
        const std::vector<unsigned char> pkh_leaf(leaf_pk_hash.begin(), leaf_pk_hash.end());
        const std::vector<unsigned char> pkh_internal(f.pk_hash.begin(), f.pk_hash.end());
        const auto err_s = [](ScriptError e) { return ScriptErrorString(e); };

        // A: 1-of-1 leaf on entry 0, two-leaf tree (one Merkle node), internal key = fixture key
        ScriptPathCase A;
        A.Build(f.pk_hash, SingleKeyLeaf(leaf_pk_hash, 0), {sibling});
        Check(A.control.size() == CONTROL_BASE_SIZE + CONTROL_NODE_SIZE, "control block is 34-byte base + one 32-byte node");
        Check(A.leaf == (CScript() << pkh_leaf << OP_0 << OP_NOP4 << OP_1), "1-of-1 leaf is <pk_hash> OP_0 OP_CHECKMLDSAVERIFY(0xb3) OP_1");
        const std::vector<uint8_t> leaf_sig = A.SignWith(leafkey, A.LeafSighash());
        const auto att1 = BuildAttestation(A.param_id, Span(leafkey.pk), leaf_sig);
        {
            ScriptError err{SCRIPT_ERR_OK};
            const bool ok = A.Verify({A.LeafBytes(), A.control, att1}, err);
            Check(ok && err == SCRIPT_ERR_OK, "10a. script-path spend (1-of-1 OP_CHECKMLDSAVERIFY leaf, one-node path) verifies");
            if (!ok) std::printf("  error: %s\n", err_s(err).c_str());
            Check(A.Verify({A.LeafBytes(), A.control, att1}, err, script_verify_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_MLDSA_V2 | SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION}),
                  "10a'. same spend passes with the policy DISCOURAGE flags (OP_NOP4 in a v2 leaf is not an upgradable NOP)");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            Check(!A.Verify({BuildAttestation(A.param_id, Span(f.kp.pk), A.SignWith(f.kp, A.KeyPathSighash()))}, err) && err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
                  "10b. key-path attestation alone cannot spend a script-path output (Merkle root is committed)");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = A.control; bad.back() ^= 0x01;
            Check(!A.Verify({A.LeafBytes(), bad, att1}, err) && err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "10c. wrong Merkle node -> WITNESS_PROGRAM_MISMATCH");
            auto bad2 = A.control; bad2[1] = PARAM_ID_MLDSA65;
            Check(!A.Verify({A.LeafBytes(), bad2, att1}, err) && err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "10c'. wrong internal param_id -> WITNESS_PROGRAM_MISMATCH");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = A.control; bad.push_back(0x00);
            Check(!A.Verify({A.LeafBytes(), bad, att1}, err) && err == SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE, "10d. misaligned control block -> TAPROOT_WRONG_CONTROL_SIZE");
            Check(!A.Verify({A.LeafBytes(), att1}, err) && err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "10d'. leaf without control block -> WITNESS_PROGRAM_MISMATCH");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            Check(!A.Verify({A.LeafBytes(), A.control, BuildAttestation(A.param_id, Span(f.kp.pk), A.SignWith(f.kp, A.LeafSighash()))}, err) && err == SCRIPT_ERR_CHECKMLDSAVERIFY,
                  "10e. attested key is not the leaf's pk_hash -> SCRIPT_ERR_CHECKMLDSAVERIFY");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto bad = leaf_sig; bad[50] ^= 0x01;
            Check(!A.Verify({A.LeafBytes(), A.control, BuildAttestation(A.param_id, Span(leafkey.pk), bad)}, err) && err == SCRIPT_ERR_MLDSA_SIG, "10f. corrupted leaf signature -> SCRIPT_ERR_MLDSA_SIG");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            Check(!A.Verify({A.LeafBytes(), A.control, BuildAttestation(A.param_id, Span(leafkey.pk), A.SignWith(leafkey, A.KeyPathSighash()))}, err) && err == SCRIPT_ERR_MLDSA_SIG,
                  "10g. signature over the key-path sighash fails in the leaf (leaf sighash commits to the leaf hash)");
        }
        {
            ScriptError err{SCRIPT_ERR_OK};
            auto att2 = att1;
            Check(AppendAttestationEntry(att2, A.param_id, Span(f.kp.pk), A.SignWith(f.kp, A.LeafSighash())), "two-entry attestation built");
            Check(!A.Verify({A.LeafBytes(), A.control, att2}, err) && err == SCRIPT_ERR_MLDSA_ENTRY_UNUSED, "10h. unverified second entry -> SCRIPT_ERR_MLDSA_ENTRY_UNUSED");
        }
        // B: 2-of-2 leaf consuming entries 0 (leaf key) and 1 (fixture key); single-leaf tree
        {
            ScriptPathCase B;
            B.Build(f.pk_hash, CScript() << pkh_leaf << OP_0 << OP_CHECKMLDSAVERIFY << pkh_internal << OP_1 << OP_CHECKMLDSAVERIFY << OP_1, {});
            auto att = BuildAttestation(B.param_id, Span(leafkey.pk), B.SignWith(leafkey, B.LeafSighash()));
            AppendAttestationEntry(att, B.param_id, Span(f.kp.pk), B.SignWith(f.kp, B.LeafSighash()));
            ScriptError err{SCRIPT_ERR_OK};
            const bool ok = B.Verify({B.LeafBytes(), B.control, att}, err);
            Check(ok && err == SCRIPT_ERR_OK, "10i. 2-of-2 leaf with a two-entry attestation verifies (no Merkle path)");
            if (!ok) std::printf("  error: %s\n", err_s(err).c_str());
            Check(B.control.size() == CONTROL_BASE_SIZE, "  control block for a single leaf is 34 bytes");
            // swapped entries: entry 0 is now the fixture key, so the first check fails
            auto swapped = BuildAttestation(B.param_id, Span(f.kp.pk), B.SignWith(f.kp, B.LeafSighash()));
            AppendAttestationEntry(swapped, B.param_id, Span(leafkey.pk), B.SignWith(leafkey, B.LeafSighash()));
            Check(!B.Verify({B.LeafBytes(), B.control, swapped}, err) && err == SCRIPT_ERR_CHECKMLDSAVERIFY, "10i'. entries in the wrong order -> SCRIPT_ERR_CHECKMLDSAVERIFY");
            // non-canonical signature encoding inside a script-path attestation: set the last unused hint-index slot of
            // either entry to 1 (same hint vector, different bytes); the encoding rule applies to every entry
            const auto sizes44 = qcoin::v2::SizesFor(B.param_id);
            const auto hp44 = qcoin::v2::HintParamsFor(B.param_id);
            for (int entry = 0; entry < 2; ++entry) {
                auto malleated = att;
                const size_t stride = 1 + sizes44->pk + sizes44->sig;
                const size_t sig_start = 2 + entry * stride + 1 + sizes44->pk;
                const size_t slot = sig_start + sizes44->sig - (hp44->omega + hp44->k) + hp44->omega - 1;
                if (malleated[slot] != 0) continue; // all hint slots in use (astronomically unlikely)
                malleated[slot] = 1;
                ScriptError merr{SCRIPT_ERR_OK};
                Check(!B.Verify({B.LeafBytes(), B.control, malleated}, merr) && merr == SCRIPT_ERR_MLDSA_SIG_ENCODING,
                      entry == 0 ? "10i-nc0. script path: non-canonical signature in entry 0 -> SCRIPT_ERR_MLDSA_SIG_ENCODING"
                                 : "10i-nc1. script path: non-canonical signature in entry 1 -> SCRIPT_ERR_MLDSA_SIG_ENCODING");
            }
        }
        // C: the same entry verified twice
        {
            ScriptPathCase C;
            C.Build(f.pk_hash, CScript() << pkh_leaf << OP_0 << OP_CHECKMLDSAVERIFY << pkh_leaf << OP_0 << OP_CHECKMLDSAVERIFY << OP_1, {});
            ScriptError err{SCRIPT_ERR_OK};
            Check(!C.Verify({C.LeafBytes(), C.control, BuildAttestation(C.param_id, Span(leafkey.pk), C.SignWith(leafkey, C.LeafSighash()))}, err) && err == SCRIPT_ERR_CHECKMLDSAVERIFY,
                  "10j. verifying the same entry twice -> SCRIPT_ERR_CHECKMLDSAVERIFY");
            ScriptPathCase C2;
            C2.Build(f.pk_hash, CScript() << pkh_leaf << OP_1 << OP_CHECKMLDSAVERIFY << OP_1, {});
            Check(!C2.Verify({C2.LeafBytes(), C2.control, BuildAttestation(C2.param_id, Span(leafkey.pk), C2.SignWith(leafkey, C2.LeafSighash()))}, err) && err == SCRIPT_ERR_CHECKMLDSAVERIFY,
                  "10j'. entry index out of range -> SCRIPT_ERR_CHECKMLDSAVERIFY");
        }
        // D: OP_CHECKSIG and OP_SUCCESSx are invalid inside a v2 leaf
        {
            ScriptPathCase D;
            D.Build(f.pk_hash, CScript() << pkh_leaf << OP_0 << OP_CHECKMLDSAVERIFY << OP_0 << OP_0 << OP_CHECKSIG, {});
            ScriptError err{SCRIPT_ERR_OK};
            Check(!D.Verify({D.LeafBytes(), D.control, BuildAttestation(D.param_id, Span(leafkey.pk), D.SignWith(leafkey, D.LeafSighash()))}, err) && err == SCRIPT_ERR_BAD_OPCODE,
                  "10k. OP_CHECKSIG inside a v2 leaf -> SCRIPT_ERR_BAD_OPCODE");
            ScriptPathCase E;
            E.Build(f.pk_hash, CScript() << OP_RESERVED, {}); // 0x50 is OP_SUCCESS80 under tapscript
            Check(!E.Verify({E.LeafBytes(), E.control, BuildAttestation(E.param_id, Span(leafkey.pk), E.SignWith(leafkey, E.LeafSighash()))}, err) && err == SCRIPT_ERR_BAD_OPCODE,
                  "10l. OP_SUCCESSx inside a v2 leaf -> SCRIPT_ERR_BAD_OPCODE (tapscript would succeed)");
        }
        // F: unknown leaf version stays upgradable, as BIP 341
        {
            ScriptPathCase F;
            F.Build(f.pk_hash, CScript() << OP_RETURN, {}, 0xc2);
            ScriptError err{SCRIPT_ERR_OK};
            Check(F.Verify({F.LeafBytes(), F.control, att1}, err), "10m. unknown leaf version 0xc2 -> success (upgradable)");
            Check(!F.Verify({F.LeafBytes(), F.control, att1}, err, script_verify_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_MLDSA_V2 | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION}) && err == SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
                  "10m'. unknown leaf version with the DISCOURAGE flag -> rejected (policy)");
        }
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
