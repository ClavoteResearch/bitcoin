// Qcoin / Option B: command-line helper that builds and signs a witness v2
// *script-path* spend, for fork/test/regtest_v2_scriptpath.sh. The wallet only
// knows the key path (wpq(KEY)); this tool stands in for wpq(KEY,{TREE}) until
// that descriptor exists. Keys are derived from 32-byte seeds given on the
// command line so the two invocations (address, then spend) agree without
// storing anything. Test helper only: the seeds are visible on the command line.
//
//   qcoin-v2-scriptpath address <internal_seed_hex> <leaf_seed_hex>
//       prints spk=<hex> leaf=<hex> control=<hex> leaf_pk_hash=<hex> q=<hex>
//       The output is OP_2 <Q> with Q committing to the internal key and a
//       single leaf  <leaf_pk_hash> OP_0 OP_CHECKMLDSAVERIFY OP_1  (1-of-1).
//   qcoin-v2-scriptpath spend <internal_seed_hex> <leaf_seed_hex> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad]
//       prints the signed raw transaction (hex) spending that output through the
//       leaf with the leaf key; "bad" corrupts the signature (expect rejection).
//   qcoin-v2-scriptpath address2 <internal_seed_hex> <leaf1_seed_hex> <leaf2_seed_hex>
//   qcoin-v2-scriptpath spend2 <internal_seed_hex> <leaf1_seed_hex> <leaf2_seed_hex> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad]
//       the 2-of-2 variant: leaf  <pk_hash1> OP_0 OP_CHECKMLDSAVERIFY <pk_hash2> OP_1 OP_CHECKMLDSAVERIFY OP_1
//       with a two-entry attestation (entry 0 = leaf key 1, entry 1 = leaf key 2); "bad" corrupts the
//       second signature.
#include "../src/script/witness_v2.h"

#include <consensus/amount.h>
#include <pqc/pqc.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <streams.h>
#include <uint256.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

template <class V>
std::span<const uint8_t> Span(const V& v) { return {reinterpret_cast<const uint8_t*>(v.data()), v.size()}; }

std::optional<std::vector<uint8_t>> FromHex(const std::string& s)
{
    if (s.size() % 2) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(c | 0x20);
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int a = nib(s[i]), b = nib(s[i + 1]);
        if (a < 0 || b < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>(a * 16 + b));
    }
    return out;
}

std::string ToHex(std::span<const uint8_t> v)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 15]);
    }
    return s;
}

std::string ToHex(const uint256& h) { return ToHex(std::span<const uint8_t>(h.begin(), h.size())); }

struct Tree {
    qcoin::pqc::MlDsaKeyPair internal;
    std::vector<qcoin::pqc::MlDsaKeyPair> leafkeys; //!< 1 key: <h> OP_0 CMV OP_1; 2 keys: 2-of-2 over entries 0 and 1
    uint256 internal_pk_hash, leaf_pk_hash, leaf_pk_hash2, leaf_hash, q;
    CScript leaf, spk;
    std::vector<uint8_t> control;

    bool Build(std::span<const uint8_t> seed_internal, const std::vector<std::vector<uint8_t>>& seed_leaves)
    {
        using namespace qcoin::v2;
        if (!qcoin::pqc::MlDsaKeygenFromSeed(qcoin::pqc::SigScheme::MLDSA44, seed_internal, internal)) return false;
        leafkeys.resize(seed_leaves.size());
        std::vector<uint256> hashes;
        for (size_t i = 0; i < seed_leaves.size(); ++i) {
            if (!qcoin::pqc::MlDsaKeygenFromSeed(qcoin::pqc::SigScheme::MLDSA44, seed_leaves[i], leafkeys[i])) return false;
            hashes.push_back(PubKeyHash(Span(leafkeys[i].pk)));
        }
        internal_pk_hash = PubKeyHash(Span(internal.pk));
        leaf_pk_hash = hashes[0];
        if (hashes.size() > 1) leaf_pk_hash2 = hashes[1];
        if (hashes.size() == 1) {
            leaf = SingleKeyLeaf(hashes[0], 0);
        } else {
            leaf = CScript() << std::vector<unsigned char>(hashes[0].begin(), hashes[0].end()) << OP_0 << OP_CHECKMLDSAVERIFY
                             << std::vector<unsigned char>(hashes[1].begin(), hashes[1].end()) << OP_1 << OP_CHECKMLDSAVERIFY << OP_1;
        }
        leaf_hash = LeafHash(LEAF_VERSION_MLDSA, Span(leaf));
        // One leaf: the Merkle root is the leaf hash and the control block carries no nodes.
        q = ComputeCommitment(PARAM_ID_MLDSA44, internal_pk_hash, std::span<const uint8_t>(leaf_hash.begin(), leaf_hash.size()));
        spk = CScript() << OP_2 << std::vector<unsigned char>(q.begin(), q.end());
        control = BuildControlBlock(LEAF_VERSION_MLDSA, PARAM_ID_MLDSA44, internal_pk_hash, {});
        return true;
    }
};

int Usage()
{
    std::fprintf(stderr,
                 "usage: qcoin-v2-scriptpath address <internal_seed_hex32> <leaf_seed_hex32>\n"
                 "       qcoin-v2-scriptpath spend <internal_seed_hex32> <leaf_seed_hex32> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad]\n"
                 "       qcoin-v2-scriptpath address2 <internal_seed_hex32> <leaf1_seed_hex32> <leaf2_seed_hex32>\n"
                 "       qcoin-v2-scriptpath spend2 <internal_seed_hex32> <leaf1_seed_hex32> <leaf2_seed_hex32> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad]\n");
    return 2;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 4) return Usage();
    std::string cmd = argv[1];
    const bool two = cmd == "address2" || cmd == "spend2";
    if (two) cmd = cmd.substr(0, cmd.size() - 1);
    const int nleaf = two ? 2 : 1;
    if (argc < 3 + nleaf) return Usage();
    const auto seed_i = FromHex(argv[2]);
    std::vector<std::vector<uint8_t>> seeds_l;
    bool seeds_ok = seed_i && seed_i->size() == qcoin::pqc::MLDSA_SEED_LEN;
    for (int i = 0; i < nleaf && seeds_ok; ++i) {
        const auto sl = FromHex(argv[3 + i]);
        seeds_ok = sl && sl->size() == qcoin::pqc::MLDSA_SEED_LEN;
        if (seeds_ok) seeds_l.push_back(*sl);
    }
    if (!seeds_ok) {
        std::fprintf(stderr, "seeds must be 32-byte hex strings\n");
        return 2;
    }
    argv += nleaf - 1; // the remaining positional arguments are at the 1-of-1 offsets
    argc -= nleaf - 1;
    Tree t;
    if (!t.Build(*seed_i, seeds_l)) {
        std::fprintf(stderr, "ML-DSA-44 keygen from seed failed\n");
        return 1;
    }
    if (cmd == "address") {
        std::printf("spk=%s\nleaf=%s\ncontrol=%s\nleaf_pk_hash=%s\nq=%s\n",
                    ToHex(Span(t.spk)).c_str(), ToHex(Span(t.leaf)).c_str(), ToHex(t.control).c_str(),
                    ToHex(t.leaf_pk_hash).c_str(), ToHex(t.q).c_str());
        if (two) std::printf("leaf_pk_hash2=%s\n", ToHex(t.leaf_pk_hash2).c_str());
        return 0;
    }
    if (cmd != "spend" || argc < 9) return Usage();
    // txid hex is displayed byte-reversed relative to the uint256 in memory (no util lib here).
    auto txid_bytes = FromHex(argv[4]);
    const auto dest = FromHex(argv[7]);
    if (!txid_bytes || txid_bytes->size() != uint256::size() || !dest) {
        std::fprintf(stderr, "bad txid or destination scriptPubKey\n");
        return 2;
    }
    std::reverse(txid_bytes->begin(), txid_bytes->end());
    const std::optional<Txid> txid{Txid::FromUint256(uint256(std::span<const unsigned char>(*txid_bytes)))};
    const uint32_t vout = static_cast<uint32_t>(std::strtoul(argv[5], nullptr, 10));
    const CAmount amount = std::strtoll(argv[6], nullptr, 10);
    const CAmount send = std::strtoll(argv[8], nullptr, 10);
    const bool corrupt = argc > 9 && std::strcmp(argv[9], "bad") == 0;

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint(*txid, vout));
    tx.vout.emplace_back(send, CScript(dest->begin(), dest->end()));
    const CTxOut spent(amount, t.spk);
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);

    // Leaf sighash: BIP 341 hash with the BIP 342 extension (leaf hash, key version 0,
    // code-separator position), SIGHASH_DEFAULT; v2 attestations carry no hashtype byte.
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash = t.leaf_hash;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;
    uint256 sighash;
    if (!SignatureHashSchnorr(sighash, execdata, tx, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
        std::fprintf(stderr, "sighash failed\n");
        return 1;
    }
    const std::span<const uint8_t> ctx(reinterpret_cast<const uint8_t*>(qcoin::v2::SIGNATURE_CONTEXT), qcoin::v2::SIGNATURE_CONTEXT_LEN);
    // One signature per leaf key, all over the same leaf sighash; the message binds each key's own pk_hash.
    std::vector<std::vector<uint8_t>> sigs(t.leafkeys.size());
    bool signed_ok = true;
    for (size_t i = 0; i < t.leafkeys.size(); ++i) {
        const uint256 pkh = qcoin::v2::PubKeyHash(Span(t.leafkeys[i].pk));
        const std::vector<uint8_t> m = qcoin::v2::BuildSignatureMessage(qcoin::v2::PARAM_ID_MLDSA44, pkh, sighash);
        signed_ok &= qcoin::pqc::MlDsaSignCtx(qcoin::pqc::SigScheme::MLDSA44, Span(t.leafkeys[i].sk), m, ctx, sigs[i]);
        qcoin::pqc::WipeSecret(t.leafkeys[i].sk);
    }
    qcoin::pqc::WipeSecret(t.internal.sk);
    if (!signed_ok) {
        std::fprintf(stderr, "ML-DSA sign failed\n");
        return 1;
    }
    if (corrupt) sigs.back()[100] ^= 0x01;

    auto& stack = tx.vin[0].scriptWitness.stack;
    stack.emplace_back(t.leaf.begin(), t.leaf.end());
    stack.push_back(t.control);
    std::vector<uint8_t> att = qcoin::v2::BuildAttestation(qcoin::v2::PARAM_ID_MLDSA44, Span(t.leafkeys[0].pk), sigs[0]);
    for (size_t i = 1; i < t.leafkeys.size(); ++i) {
        qcoin::v2::AppendAttestationEntry(att, qcoin::v2::PARAM_ID_MLDSA44, Span(t.leafkeys[i].pk), sigs[i]);
    }
    stack.push_back(std::move(att));

    ScriptError err{SCRIPT_ERR_OK};
    MutableTransactionSignatureChecker checker(&tx, 0, amount, txdata, MissingDataBehavior::FAIL);
    const bool ok = VerifyScript(CScript(), t.spk, &tx.vin[0].scriptWitness,
                                 script_verify_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_MLDSA_V2 | SCRIPT_VERIFY_MINIMALDATA},
                                 checker, &err);
    std::fprintf(stderr, "local verify: %s (%s)\n", ok ? "ok" : "FAILED", ScriptErrorString(err).c_str());
    if (!ok && !corrupt) return 1;

    DataStream ss;
    ss << TX_WITH_WITNESS(tx);
    std::printf("%s\n", ToHex(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ss.data()), ss.size())).c_str());
    return 0;
}
