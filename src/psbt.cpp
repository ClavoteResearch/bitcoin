// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <common/types.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/signingprovider.h>
#include <util/check.h>
#include <util/result.h>
#include <util/strencodings.h>
#include "../fork/src/script/witness_v2.h" // Qcoin / Option B: witness v2 ML-DSA inputs in PSBTs

#include <algorithm>
#include <set>

using common::PSBTError;

namespace {
// Qcoin / Option B proprietary PSBT input field (BIP 174 type 0xFC):
//   identifier = "qcoin", subtype = 0, value = param_id || ML-DSA public key
// It lets a signer that does not hold the wpq() descriptor map the 32-byte witness v2
// program back to the public key it must attest with. The finished attestation travels
// in the standard final_scriptwitness field; there is no partial-signature form, since a
// key-path v2 input has exactly one signer.
const std::vector<unsigned char> QCOIN_PROP_ID{'q', 'c', 'o', 'i', 'n'};
constexpr uint64_t QCOIN_PROP_MLDSA_PUBKEY = 0;

PSBTProprietary MakeMlDsaPubKeyField(uint8_t param_id, const std::vector<unsigned char>& pk)
{
    PSBTProprietary p;
    p.identifier = QCOIN_PROP_ID;
    p.subtype = QCOIN_PROP_MLDSA_PUBKEY;
    DataStream k;
    k << PSBT_IN_PROPRIETARY << p.identifier;
    WriteCompactSize(k, p.subtype);
    p.key.assign(UCharCast(k.data()), UCharCast(k.data()) + k.size());
    p.value.reserve(1 + pk.size());
    p.value.push_back(param_id);
    p.value.insert(p.value.end(), pk.begin(), pk.end());
    return p;
}

bool ParseMlDsaPubKeyField(const PSBTProprietary& p, uint8_t& param_id, std::vector<unsigned char>& pk)
{
    if (p.identifier != QCOIN_PROP_ID || p.subtype != QCOIN_PROP_MLDSA_PUBKEY || p.value.size() < 2) return false;
    param_id = p.value[0];
    const auto sizes = qcoin::v2::SizesFor(param_id);
    if (!sizes || p.value.size() != 1 + sizes->pk) return false;
    pk.assign(p.value.begin() + 1, p.value.end());
    return true;
}

// Qcoin: witness v2 script-path fields (identifier "qcoin"), see doc/WALLET-PQC.md, "Script-path PSBTs":
//   subtype 1, no key data : value = leaf_version || leaf script
//   subtype 2, no key data : value = control block (leaf_version || param_id || internal pk_hash || 32-byte nodes)
//   subtype 3, key data = pk_hash (32 bytes) : value = one attestation entry, param_id || public key || signature
constexpr uint64_t QCOIN_PROP_SCRIPTPATH_LEAF = 1;
constexpr uint64_t QCOIN_PROP_SCRIPTPATH_CONTROL = 2;
constexpr uint64_t QCOIN_PROP_SCRIPTPATH_ENTRY = 3;

PSBTProprietary MakeQcoinField(uint64_t subtype, std::span<const unsigned char> key_data, std::vector<unsigned char> value)
{
    PSBTProprietary p;
    p.identifier = QCOIN_PROP_ID;
    p.subtype = subtype;
    DataStream k;
    k << PSBT_IN_PROPRIETARY << p.identifier;
    WriteCompactSize(k, p.subtype);
    p.key.assign(UCharCast(k.data()), UCharCast(k.data()) + k.size());
    p.key.insert(p.key.end(), key_data.begin(), key_data.end());
    p.value = std::move(value);
    return p;
}

const PSBTProprietary* FindQcoinField(const PSBTInput& input, uint64_t subtype)
{
    for (const auto& prop : input.m_proprietary) {
        if (prop.identifier == QCOIN_PROP_ID && prop.subtype == subtype) return &prop;
    }
    return nullptr;
}

struct ScriptPathData {
    uint8_t leaf_version{0};
    CScript leaf;
    std::vector<unsigned char> leaf_bytes;
    std::vector<unsigned char> control;
    uint8_t param_id{0};
};

bool GetScriptPathData(const PSBTInput& input, ScriptPathData& out)
{
    const PSBTProprietary* leaf = FindQcoinField(input, QCOIN_PROP_SCRIPTPATH_LEAF);
    const PSBTProprietary* control = FindQcoinField(input, QCOIN_PROP_SCRIPTPATH_CONTROL);
    if (!leaf || !control || leaf->value.size() < 2) return false;
    if (!qcoin::v2::IsValidControlBlockSize(control->value.size())) return false;
    out.leaf_version = leaf->value[0];
    out.leaf_bytes.assign(leaf->value.begin() + 1, leaf->value.end());
    out.leaf = CScript(out.leaf_bytes.begin(), out.leaf_bytes.end());
    out.control = control->value;
    out.param_id = out.control[1];
    return out.control[0] == out.leaf_version && out.leaf_version == qcoin::v2::LEAF_VERSION_MLDSA;
}

/** The witness v2 program (Q) that the leaf and control block commit to. */
uint256 ScriptPathProgram(const ScriptPathData& sp)
{
    uint256 internal_pk_hash;
    std::copy(sp.control.begin() + 2, sp.control.begin() + 2 + 32, internal_pk_hash.begin());
    const uint256 root = qcoin::v2::MerkleRootFromControl(sp.control, qcoin::v2::LeafHash(sp.leaf_version, sp.leaf_bytes));
    return qcoin::v2::ComputeCommitment(sp.param_id, internal_pk_hash, std::span<const uint8_t>(root.begin(), root.size()));
}

/** The (pk_hash, entry index) pairs of the `<pk_hash> <i> OP_CHECKMLDSAVERIFY` triples of a leaf, in script order. */
std::vector<std::pair<uint256, int>> LeafKeys(const CScript& leaf)
{
    std::vector<std::pair<uint256, int>> keys;
    std::vector<unsigned char> hash_bytes;
    int small_int{-1};
    int stage{0}; // 0: nothing, 1: saw a 32-byte push, 2: and then a small integer
    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator it = leaf.begin();
    while (it < leaf.end() && leaf.GetOp(it, op, data)) {
        if (op == OP_NOP4) { // OP_CHECKMLDSAVERIFY inside a v2 leaf
            if (stage == 2) {
                uint256 h;
                std::copy(hash_bytes.begin(), hash_bytes.end(), h.begin());
                keys.emplace_back(h, small_int);
            }
            stage = 0;
        } else if (op <= OP_PUSHDATA4 && data.size() == 32) {
            hash_bytes = data;
            stage = 1;
        } else if (stage == 1 && (op == OP_0 || (op >= OP_1 && op <= OP_16))) {
            small_int = op == OP_0 ? 0 : int(op) - int(OP_1) + 1;
            stage = 2;
        } else {
            stage = 0;
        }
    }
    return keys;
}

/** The leaf sighash of input `index` (BIP 341 hash with the BIP 342 extension, SIGHASH_DEFAULT). */
bool ScriptPathSighash(const ScriptPathData& sp, const CMutableTransaction& tx, unsigned int index, const PrecomputedTransactionData& txdata, uint256& sighash)
{
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash = qcoin::v2::LeafHash(sp.leaf_version, sp.leaf_bytes);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;
    return SignatureHashSchnorr(sighash, execdata, tx, index, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL);
}

/**
 * Qcoin: sign (with the keys the provider holds) and, when every entry of the leaf is present and `finalize` is set,
 * assemble and verify the witness of a witness v2 script-path input. Returns INCOMPLETE until the input is finalized.
 */
util::Expected<void, PSBTError> SignMlDsaScriptPathInput(const SigningProvider& provider, PSBTInput& input, PartiallySignedTransaction& psbt, int index,
                                                         const CMutableTransaction& tx, const PrecomputedTransactionData* txdata,
                                                         const common::PSBTFillOptions& options, const CTxOut& utxo)
{
    input.witness_utxo = utxo; // a v2 spend is a witness spend
    ScriptPathData sp;
    if (!GetScriptPathData(input, sp)) return util::Unexpected{PSBTError::UNSUPPORTED};
    int wv{0};
    std::vector<unsigned char> wp;
    if (!utxo.scriptPubKey.IsWitnessProgram(wv, wp) || wv != qcoin::v2::WITNESS_V2_VERSION) return util::Unexpected{PSBTError::UNSUPPORTED};
    const uint256 q = ScriptPathProgram(sp);
    if (!std::equal(q.begin(), q.end(), wp.begin())) return util::Unexpected{PSBTError::UNSUPPORTED}; // leaf and control block do not commit to this output
    if (input.sighash_type && *input.sighash_type != SIGHASH_DEFAULT) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};

    const auto keys = LeafKeys(sp.leaf);
    if (keys.empty() || keys.size() > qcoin::v2::ATTESTATION_MAX_ENTRIES) return util::Unexpected{PSBTError::UNSUPPORTED};

    auto entry_for = [&](const uint256& pk_hash) -> const PSBTProprietary* {
        for (const auto& prop : input.m_proprietary) {
            if (prop.identifier != QCOIN_PROP_ID || prop.subtype != QCOIN_PROP_SCRIPTPATH_ENTRY) continue;
            if (prop.key.size() >= 32 && std::equal(pk_hash.begin(), pk_hash.end(), prop.key.end() - 32)) return &prop;
        }
        return nullptr;
    };

    // Sign for every key of the leaf the provider holds and that has no entry yet.
    if (options.sign && txdata) {
        uint256 sighash;
        bool have_sighash = false;
        for (const auto& [pk_hash, entry_index] : keys) {
            if (entry_for(pk_hash)) continue;
            qcoin::pqc::MlDsaKeyPair kp;
            if (!provider.GetMlDsaKey(pk_hash, kp)) continue;
            if (qcoin::pqc::ParamIdFor(kp.scheme) != sp.param_id) { qcoin::pqc::WipeSecret(kp.sk); continue; }
            if (!have_sighash) {
                if (!ScriptPathSighash(sp, tx, index, *txdata, sighash)) { qcoin::pqc::WipeSecret(kp.sk); return util::Unexpected{PSBTError::INVALID_TX}; }
                have_sighash = true;
            }
            const std::vector<uint8_t> msg = qcoin::v2::BuildSignatureMessage(sp.param_id, pk_hash, sighash);
            const std::span<const uint8_t> ctx(reinterpret_cast<const uint8_t*>(qcoin::v2::SIGNATURE_CONTEXT), qcoin::v2::SIGNATURE_CONTEXT_LEN);
            std::vector<uint8_t> sig;
            const bool ok = qcoin::pqc::MlDsaSignCtx(kp.scheme, kp.sk, msg, ctx, sig);
            qcoin::pqc::WipeSecret(kp.sk);
            if (!ok) continue;
            std::vector<unsigned char> value;
            value.push_back(sp.param_id);
            value.insert(value.end(), kp.pk.begin(), kp.pk.end());
            value.insert(value.end(), sig.begin(), sig.end());
            input.m_proprietary.insert(MakeQcoinField(QCOIN_PROP_SCRIPTPATH_ENTRY, std::span<const unsigned char>(pk_hash.begin(), pk_hash.size()), std::move(value)));
        }
    }

    if (!options.finalize || !txdata) return util::Unexpected{PSBTError::INCOMPLETE};

    // Complete when every index 0..n-1 of the leaf has an entry; entries go into the attestation in index order.
    int n_entries = 0;
    for (const auto& [_, entry_index] : keys) n_entries = std::max(n_entries, entry_index + 1);
    std::vector<const PSBTProprietary*> by_index(n_entries, nullptr);
    for (const auto& [pk_hash, entry_index] : keys) {
        if (const PSBTProprietary* e = entry_for(pk_hash)) by_index[entry_index] = e;
    }
    for (const PSBTProprietary* e : by_index) {
        if (!e) return util::Unexpected{PSBTError::INCOMPLETE};
    }
    std::vector<uint8_t> attestation;
    for (const PSBTProprietary* e : by_index) {
        const auto& v = e->value;
        const auto sizes = v.empty() ? std::nullopt : qcoin::v2::SizesFor(v[0]);
        if (!sizes || v.size() != 1 + sizes->pk + sizes->sig) return util::Unexpected{PSBTError::INCOMPLETE};
        const std::span<const uint8_t> pk(v.data() + 1, sizes->pk), sig(v.data() + 1 + sizes->pk, sizes->sig);
        if (attestation.empty()) attestation = qcoin::v2::BuildAttestation(v[0], pk, sig);
        else if (!qcoin::v2::AppendAttestationEntry(attestation, v[0], pk, sig)) return util::Unexpected{PSBTError::UNSUPPORTED};
    }

    // Set the witness and verify the whole input; a bad entry from another party must not produce a finalized input.
    input.final_script_witness.stack = {sp.leaf_bytes, sp.control, attestation};
    if (!PSBTInputSignedAndVerified(psbt, index, txdata)) {
        input.final_script_witness.SetNull();
        return util::Unexpected{PSBTError::INCOMPLETE};
    }
    for (auto it = input.m_proprietary.begin(); it != input.m_proprietary.end();) {
        if (it->identifier == QCOIN_PROP_ID && it->subtype >= QCOIN_PROP_SCRIPTPATH_LEAF && it->subtype <= QCOIN_PROP_SCRIPTPATH_ENTRY) it = input.m_proprietary.erase(it);
        else ++it;
    }
    return {};
}
} // namespace

bool PSBTInputHasMlDsaScriptPath(const PSBTInput& input)
{
    ScriptPathData sp;
    return GetScriptPathData(input, sp);
}

std::vector<CScript> PSBTMlDsaScriptPathKeyScripts(const PSBTInput& input)
{
    std::vector<CScript> scripts;
    ScriptPathData sp;
    if (!GetScriptPathData(input, sp)) return scripts;
    for (const auto& [pk_hash, _] : LeafKeys(sp.leaf)) {
        const uint256 q = qcoin::v2::ComputeCommitment(sp.param_id, pk_hash, {});
        scripts.push_back(CScript() << OP_2 << std::vector<unsigned char>(q.begin(), q.end()));
    }
    return scripts;
}

std::vector<std::pair<uint256, CScript>> MlDsaLeafKeyScripts(const std::vector<unsigned char>& leaf_script, uint8_t param_id)
{
    std::vector<std::pair<uint256, CScript>> out;
    for (const auto& [pk_hash, _] : LeafKeys(CScript(leaf_script.begin(), leaf_script.end()))) {
        const uint256 q = qcoin::v2::ComputeCommitment(param_id, pk_hash, {});
        out.emplace_back(pk_hash, CScript() << OP_2 << std::vector<unsigned char>(q.begin(), q.end()));
    }
    return out;
}

bool SetPSBTMlDsaScriptPath(PSBTInput& input, const std::vector<unsigned char>& leaf_script, const std::vector<unsigned char>& control, std::string& error)
{
    if (!qcoin::v2::IsValidControlBlockSize(control.size())) {
        error = "control block must be 34 bytes plus at most 8 nodes of 32 bytes";
        return false;
    }
    if (control[0] != qcoin::v2::LEAF_VERSION_MLDSA) {
        error = "control block leaf version must be 0xc0";
        return false;
    }
    if (leaf_script.empty()) {
        error = "empty leaf script";
        return false;
    }
    std::vector<unsigned char> leaf_value;
    leaf_value.push_back(control[0]);
    leaf_value.insert(leaf_value.end(), leaf_script.begin(), leaf_script.end());
    ScriptPathData sp;
    sp.leaf_version = control[0];
    sp.leaf_bytes = leaf_script;
    sp.leaf = CScript(leaf_script.begin(), leaf_script.end());
    sp.control = control;
    sp.param_id = control[1];
    if (LeafKeys(sp.leaf).empty()) {
        error = "the leaf names no ML-DSA key (<pk_hash> <i> OP_CHECKMLDSAVERIFY)";
        return false;
    }
    CTxOut utxo;
    if (input.GetUTXO(utxo)) {
        int wv{0};
        std::vector<unsigned char> wp;
        const uint256 q = ScriptPathProgram(sp);
        if (!utxo.scriptPubKey.IsWitnessProgram(wv, wp) || wv != qcoin::v2::WITNESS_V2_VERSION || !std::equal(q.begin(), q.end(), wp.begin())) {
            error = "the leaf script and control block do not commit to the output being spent";
            return false;
        }
    }
    // replace earlier values (and any stale entries: they signed a different script)
    for (auto it = input.m_proprietary.begin(); it != input.m_proprietary.end();) {
        if (it->identifier == QCOIN_PROP_ID && it->subtype >= QCOIN_PROP_SCRIPTPATH_LEAF && it->subtype <= QCOIN_PROP_SCRIPTPATH_ENTRY) it = input.m_proprietary.erase(it);
        else ++it;
    }
    input.m_proprietary.insert(MakeQcoinField(QCOIN_PROP_SCRIPTPATH_LEAF, {}, std::move(leaf_value)));
    input.m_proprietary.insert(MakeQcoinField(QCOIN_PROP_SCRIPTPATH_CONTROL, {}, control));
    return true;
}

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx, uint32_t version) : m_version(version)
{
    assert(m_version == 0 || m_version == 2);

    tx_version = tx.version;
    fallback_locktime = tx.nLockTime;
    inputs.reserve(tx.vin.size());
    for (const CTxIn& input : tx.vin) {
        inputs.emplace_back(GetVersion(), input.prevout.hash, input.prevout.n, input.nSequence);
    }
    outputs.reserve(tx.vout.size());
    for (const CTxOut& output : tx.vout) {
        outputs.emplace_back(GetVersion(), output.nValue, output.scriptPubKey);
    }
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    std::optional<Txid> this_id = GetUniqueID();
    std::optional<Txid> psbt_id = psbt.GetUniqueID();
    if (!this_id || !psbt_id || this_id != psbt_id) {
        return false;
    }
    if (GetVersion() != psbt.GetVersion()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    MergeGlobalXPubs(psbt);
    if (fallback_locktime == std::nullopt && psbt.fallback_locktime != std::nullopt) fallback_locktime = psbt.fallback_locktime;

    // Set m_tx_modifiable only if either PSBT had it set
    if (m_tx_modifiable.has_value() || psbt.m_tx_modifiable.has_value()) {
        // In general, we AND the modifiable flags
        std::bitset<8> this_modifiable = m_tx_modifiable.value_or(0);
        std::bitset<8> psbt_modifiable = psbt.m_tx_modifiable.value_or(0);
        std::bitset<8> final_modifiable = this_modifiable & psbt_modifiable;
        // SIGHASH_SINGLE Modifiable (bit 2) needs to be bitwise OR'd
        final_modifiable.set(2, this_modifiable[2] || psbt_modifiable[2]);

        m_tx_modifiable = final_modifiable;
    }

    m_proprietary.insert(psbt.m_proprietary.begin(), psbt.m_proprietary.end());
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

void PartiallySignedTransaction::MergeGlobalXPubs(const PartiallySignedTransaction& psbt)
{
    for (const auto& [origin, xpubs] : psbt.m_xpubs) {
        for (const CExtPubKey& xpub : xpubs) {
            const bool known{std::ranges::any_of(m_xpubs, [&](const auto& entry) { return entry.second.contains(xpub); })};
            if (!known) m_xpubs[origin].insert(xpub);
        }
    }
}

std::optional<uint32_t> PartiallySignedTransaction::ComputeTimeLock() const
{
    if (GetVersion() >= 2) {
        std::optional<uint32_t> time_lock{0};
        std::optional<uint32_t> height_lock{0};
        for (const PSBTInput& input : inputs) {
            if (input.time_locktime.has_value() && !input.height_locktime.has_value()) {
                height_lock.reset(); // Transaction can no longer have a height locktime
                if (!time_lock.has_value()) {
                    return std::nullopt;
                }
            } else if (!input.time_locktime.has_value() && input.height_locktime.has_value()) {
                time_lock.reset(); // Transaction can no longer have a time locktime
                if (!height_lock.has_value()) {
                    return std::nullopt;
                }
            }
            if (input.time_locktime && time_lock.has_value()) {
                time_lock = std::max(time_lock, input.time_locktime);
            }
            if (input.height_locktime && height_lock.has_value()) {
                height_lock = std::max(height_lock, input.height_locktime);
            }
        }
        if (height_lock.has_value() && *height_lock > 0) {
            return *height_lock;
        }
        if (time_lock.has_value() && *time_lock > 0) {
            return *time_lock;
        }
    }
    return fallback_locktime.value_or(0);
}

std::optional<CMutableTransaction> PartiallySignedTransaction::GetUnsignedTx() const
{
    CMutableTransaction mtx;
    mtx.version = tx_version;
    std::optional<uint32_t> locktime = ComputeTimeLock();
    if (!locktime) {
        return std::nullopt;
    }
    mtx.nLockTime = *locktime;
    uint32_t max_sequence = CTxIn::SEQUENCE_FINAL;
    for (const PSBTInput& input : inputs) {
        CTxIn txin;
        txin.prevout.hash = input.prev_txid;
        txin.prevout.n = input.prev_out;
        txin.nSequence = input.sequence.value_or(max_sequence);
        mtx.vin.push_back(txin);
    }
    for (const PSBTOutput& output : outputs) {
        CTxOut txout;
        txout.nValue = output.amount;
        txout.scriptPubKey = output.script;
        mtx.vout.push_back(txout);
    }
    return mtx;
}

std::optional<Txid> PartiallySignedTransaction::GetUniqueID() const
{
    // Get the unsigned transaction
    std::optional<CMutableTransaction> mtx = GetUnsignedTx();
    if (!mtx) {
        return std::nullopt;
    }
    if (GetVersion() >= 2) {
        for (CTxIn& txin : mtx->vin) {
            txin.nSequence = 0;
        }
    }
    return mtx->GetHash();
}

bool PartiallySignedTransaction::AddInput(const PSBTInput& psbtin)
{
    // The input being added must be for this PSBT's version
    if (psbtin.GetVersion() != GetVersion()) {
        return false;
    }

    // Prevent duplicate inputs
    if (std::find_if(inputs.begin(), inputs.end(),
        [psbtin](const PSBTInput& psbt) {
            return psbt.prev_txid == psbtin.prev_txid && psbt.prev_out == psbtin.prev_out;
        }
    ) != inputs.end()) {
        return false;
    }

    if (GetVersion() < 2) {
        // This is a v0 psbt, so do the v0 AddInput
        inputs.push_back(psbtin);
        inputs.back().partial_sigs.clear();
        inputs.back().final_script_sig.clear();
        inputs.back().final_script_witness.SetNull();
        return true;
    }

    // Check inputs modifiable flag
    if (!m_tx_modifiable.has_value() || !m_tx_modifiable->test(0)) {
        return false;
    }

    // Determine if we need to iterate the inputs.
    // For now, we only do this if the new input has a required time lock.
    // BIP 370 states that we should also do this if m_tx_modifiable's bit 2 is set
    // (Has SIGHASH_SINGLE flag) but since we are only adding inputs at the end of the vector,
    // we don't care about that.
    bool iterate_inputs = psbtin.time_locktime != std::nullopt || psbtin.height_locktime != std::nullopt;
    if (iterate_inputs) {
        std::optional<uint32_t> old_timelock = ComputeTimeLock();
        if (!old_timelock) {
            return false;
        }

        std::optional<uint32_t> time_lock = psbtin.time_locktime;
        std::optional<uint32_t> height_lock = psbtin.height_locktime;
        bool has_sigs = false;
        for (const PSBTInput& input : inputs) {
            if (input.time_locktime.has_value() && !input.height_locktime.has_value()) {
                height_lock.reset(); // Transaction can no longer have a height locktime
                if (time_lock == std::nullopt) {
                    return false;
                }
            } else if (!input.time_locktime.has_value() && input.height_locktime.has_value()) {
                time_lock.reset(); // Transaction can no longer have a time locktime
                if (height_lock == std::nullopt) {
                    return false;
                }
            }
            if (input.time_locktime && time_lock.has_value()) {
                time_lock = std::max(time_lock, input.time_locktime);
            }
            if (input.height_locktime && height_lock.has_value()) {
                height_lock = std::max(height_lock, input.height_locktime);
            }
            if (input.HasSignatures()) {
                has_sigs = true;
            }
        }
        uint32_t new_timelock = fallback_locktime.value_or(0);
        if (height_lock.has_value() && *height_lock > 0) {
            new_timelock = *height_lock;
        } else if (time_lock.has_value() && *time_lock > 0) {
            new_timelock = *time_lock;
        }
        if (has_sigs && *old_timelock != new_timelock) {
            return false;
        }
    }

    // Add the input to the end
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const PSBTOutput& psbtout)
{
    // The output being added must be for this PSBT's version
    if (psbtout.GetVersion() != GetVersion()) {
        return false;
    }

    if (GetVersion() < 2) {
        // This is a v0 psbt, do the v0 AddOutput
        outputs.push_back(psbtout);
        return true;
    }

    // No global tx, must be PSBTv2
    // Check outputs are modifiable
    if (!m_tx_modifiable.has_value() || !m_tx_modifiable->test(1)) {
        return false;
    }
    outputs.push_back(psbtout);

    return true;
}

bool PSBTInput::GetUTXO(CTxOut& utxo) const
{
    if (non_witness_utxo) {
        if (prev_out >= non_witness_utxo->vout.size()) {
            return false;
        }
        if (non_witness_utxo->GetHash() != prev_txid) {
            return false;
        }
        utxo = non_witness_utxo->vout[prev_out];
    } else if (!witness_utxo.IsNull()) {
        utxo = witness_utxo;
    } else {
        return false;
    }
    return true;
}

COutPoint PSBTInput::GetOutPoint() const
{
    return COutPoint(prev_txid, prev_out);
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_key_sig.empty()) {
        sigdata.taproot_key_path_sig = m_tap_key_sig;
    }
    for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
        sigdata.taproot_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!m_tap_internal_key.IsNull()) {
        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
    }
    if (!m_tap_merkle_root.IsNull()) {
        sigdata.tr_spenddata.merkle_root = m_tap_merkle_root;
    }
    for (const auto& [leaf_script, control_block] : m_tap_scripts) {
        sigdata.tr_spenddata.scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
    for (const auto& [hash, preimage] : ripemd160_preimages) {
        sigdata.ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sha256_preimages) {
        sigdata.sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash160_preimages) {
        sigdata.hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : hash256_preimages) {
        sigdata.hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    sigdata.musig2_pubkeys.insert(m_musig2_participants.begin(), m_musig2_participants.end());
    for (const auto& [agg_key_lh, pubnonces] : m_musig2_pubnonces) {
        sigdata.musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : m_musig2_partial_sigs) {
        sigdata.musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.taproot_key_path_sig.empty()) {
        m_tap_key_sig = sigdata.taproot_key_path_sig;
    }
    for (const auto& [pubkey_leaf, sig] : sigdata.taproot_script_sigs) {
        m_tap_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (!sigdata.tr_spenddata.merkle_root.IsNull()) {
        m_tap_merkle_root = sigdata.tr_spenddata.merkle_root;
    }
    for (const auto& [leaf_script, control_block] : sigdata.tr_spenddata.scripts) {
        m_tap_scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
    m_musig2_participants.insert(sigdata.musig2_pubkeys.begin(), sigdata.musig2_pubkeys.end());
    for (const auto& [agg_key_lh, pubnonces] : sigdata.musig2_pubnonces) {
        m_musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : sigdata.musig2_partial_sigs) {
        m_musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
    for (const auto& [hash, preimage] : sigdata.ripemd160_preimages) {
        ripemd160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.sha256_preimages) {
        sha256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.hash160_preimages) {
        hash160_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
    for (const auto& [hash, preimage] : sigdata.hash256_preimages) {
        hash256_preimages.emplace(std::vector<unsigned char>(hash.begin(), hash.end()), preimage);
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    m_proprietary.insert(input.m_proprietary.begin(), input.m_proprietary.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    // Merge by control block, the serialized key (BIP 371), to avoid duplicate keys. Keep the
    // leaf script already present; BIP 174 lets the Combiner pick arbitrarily on conflict.
    std::set<std::vector<unsigned char>> seen_control_blocks;
    for (const auto& [_, control_blocks] : m_tap_scripts) {
        seen_control_blocks.insert(control_blocks.begin(), control_blocks.end());
    }
    for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
        for (const auto& control_block : control_blocks) {
            if (seen_control_blocks.insert(control_block).second) m_tap_scripts[leaf].insert(control_block);
        }
    }
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
    if (m_tap_key_sig.empty() && !input.m_tap_key_sig.empty()) m_tap_key_sig = input.m_tap_key_sig;
    if (m_tap_internal_key.IsNull() && !input.m_tap_internal_key.IsNull()) m_tap_internal_key = input.m_tap_internal_key;
    if (m_tap_merkle_root.IsNull() && !input.m_tap_merkle_root.IsNull()) m_tap_merkle_root = input.m_tap_merkle_root;
    m_musig2_participants.insert(input.m_musig2_participants.begin(), input.m_musig2_participants.end());
    for (const auto& [agg_key_lh, pubnonces] : input.m_musig2_pubnonces) {
        m_musig2_pubnonces[agg_key_lh].insert(pubnonces.begin(), pubnonces.end());
    }
    for (const auto& [agg_key_lh, psigs] : input.m_musig2_partial_sigs) {
        m_musig2_partial_sigs[agg_key_lh].insert(psigs.begin(), psigs.end());
    }
    if (sighash_type == std::nullopt && input.sighash_type != std::nullopt) sighash_type = input.sighash_type;
    if (sequence == std::nullopt && input.sequence != std::nullopt) sequence = input.sequence;
    if (time_locktime == std::nullopt && input.time_locktime != std::nullopt) time_locktime = input.time_locktime;
    if (height_locktime == std::nullopt && input.height_locktime != std::nullopt) height_locktime = input.height_locktime;
}

bool PSBTInput::HasSignatures() const
{
    return !final_script_sig.empty()
           || !final_script_witness.IsNull()
           || !partial_sigs.empty()
           || !m_tap_key_sig.empty()
           || !m_tap_script_sigs.empty()
           || !m_musig2_partial_sigs.empty();
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_tree.empty() && m_tap_internal_key.IsFullyValid()) {
        TaprootBuilder builder;
        for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
            builder.Add((int)depth, script, (int)leaf_ver, /*track=*/true);
        }
        assert(builder.IsComplete());
        builder.Finalize(m_tap_internal_key);
        TaprootSpendData spenddata = builder.GetSpendData();

        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
        sigdata.tr_spenddata.Merge(spenddata);
        sigdata.tr_builder = builder;
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
        sigdata.tap_pubkeys.emplace(Hash160(pubkey), pubkey);
    }
    sigdata.musig2_pubkeys.insert(m_musig2_participants.begin(), m_musig2_participants.end());
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (sigdata.tr_builder.has_value() && sigdata.tr_builder->HasScripts()) {
        m_tap_tree = sigdata.tr_builder->GetTreeTuples();
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
    m_musig2_participants.insert(sigdata.musig2_pubkeys.begin(), sigdata.musig2_pubkeys.end());
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    m_proprietary.insert(output.m_proprietary.begin(), output.m_proprietary.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
    if (m_tap_internal_key.IsNull() && !output.m_tap_internal_key.IsNull()) m_tap_internal_key = output.m_tap_internal_key;
    if (m_tap_tree.empty() && !output.m_tap_tree.empty()) m_tap_tree = output.m_tap_tree;
    m_musig2_participants.insert(output.m_musig2_participants.begin(), output.m_musig2_participants.end());
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction& psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(input_index < psbt.inputs.size());
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }

    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return false;
    }
    const CMutableTransaction& tx = *unsigned_tx;
    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return;
    }
    const CTxOut& out = unsigned_tx->vout.at(index);
    PSBTOutput& psbt_out = psbt.outputs.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    CMutableTransaction tx{};
    tx.vin.emplace_back();
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, {.sighash_type = SIGHASH_ALL});
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

std::optional<PrecomputedTransactionData> PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{
    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return std::nullopt;
    }
    const CMutableTransaction& tx = *unsigned_tx;
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos;
    for (const PSBTInput& input : psbt.inputs) {
        if (!input.GetUTXO(utxos.emplace_back())) have_all_spent_outputs = false;
    }
    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

util::Expected<void, PSBTError> SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, const common::PSBTFillOptions& options,  SignatureData* out_sigdata)
{
    PSBTInput& input = psbt.inputs.at(index);
    std::optional<CMutableTransaction> unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return util::Unexpected{PSBTError::INVALID_TX};
    }
    const CMutableTransaction& tx = *unsigned_tx;

    if (PSBTInputSignedAndVerified(psbt, index, txdata)) {
        return {};
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return util::Unexpected{PSBTError::MISSING_INPUTS};
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return util::Unexpected{PSBTError::MISSING_INPUTS};
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return util::Unexpected{PSBTError::MISSING_INPUTS};
    }

    bool is_qcoin_v2 = false;
    const SigningProvider* sign_provider = &provider;
    // Qcoin / Option B: witness v2 ML-DSA input. Publish the ML-DSA public key as a
    // proprietary field when we know it; otherwise take it from the field (if the
    // commitment checks out) so the signer can find the matching secret.
    std::unique_ptr<MultiSigningProvider> qcoin_provider;
    {
        int wv{0};
        std::vector<unsigned char> wp;
        if (utxo.scriptPubKey.IsWitnessProgram(wv, wp) && wv == qcoin::v2::WITNESS_V2_VERSION && wp.size() == qcoin::v2::WITNESS_V2_PROGRAM_SIZE) {
            is_qcoin_v2 = true;
            std::vector<unsigned char> pk;
            if (provider.GetMlDsaPubKey(wp, pk)) {
                if (const auto param_id = qcoin::v2::ParamIdForPubKeyLen(pk.size())) {
                    input.m_proprietary.insert(MakeMlDsaPubKeyField(*param_id, pk)); // no-op if already present
                }
            } else {
                for (const auto& prop : input.m_proprietary) {
                    uint8_t param_id{0};
                    if (!ParseMlDsaPubKeyField(prop, param_id, pk)) continue;
                    const uint256 q = qcoin::v2::ComputeCommitment(param_id, qcoin::v2::PubKeyHash(pk), {});
                    if (!std::equal(q.begin(), q.end(), wp.begin())) continue; // field does not match this output
                    auto extra = std::make_unique<FlatSigningProvider>();
                    extra->mldsa_pubkeys[wp] = pk;
                    qcoin_provider = std::make_unique<MultiSigningProvider>();
                    qcoin_provider->AddProvider(std::make_unique<HidingSigningProvider>(&provider, /*hide_secret=*/false, /*hide_origin=*/false));
                    qcoin_provider->AddProvider(std::move(extra));
                    sign_provider = qcoin_provider.get();
                    break;
                }
            }
        }
    }

    // Qcoin: a witness v2 input that carries script-path fields is signed with the keys named by its leaf and finalized
    // from the attestation entries gathered in the PSBT (see SignMlDsaScriptPathInput)
    if (is_qcoin_v2 && PSBTInputHasMlDsaScriptPath(input)) {
        return SignMlDsaScriptPathInput(provider, input, psbt, index, tx, txdata, options, utxo);
    }

    // Get the sighash type
    // If both the field and the parameter are provided, they must match
    // If only the parameter is provided, use it and add it to the PSBT if it is other than SIGHASH_DEFAULT
    // for all input types, and not SIGHASH_ALL for non-taproot input types.
    // If neither are provided, use SIGHASH_DEFAULT if it is taproot, and SIGHASH_ALL for everything else.
    // (Qcoin: a witness v2 ML-DSA input carries no hashtype byte and always uses SIGHASH_DEFAULT, like taproot.)
    int sighash{options.sighash_type.value_or((utxo.scriptPubKey.IsPayToTaproot() || is_qcoin_v2) ? SIGHASH_DEFAULT : SIGHASH_ALL)};

    // For user safety, the desired sighash must be provided if the PSBT wants something other than the default set in the previous line.
    if (input.sighash_type && input.sighash_type != sighash) {
        return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
    }
    // Set the PSBT sighash field when sighash is not DEFAULT or ALL
    // DEFAULT is allowed for non-taproot inputs since DEFAULT may be passed for them (e.g. the psbt being signed also has taproot inputs)
    // Note that signing already aliases DEFAULT to ALL for non-taproot inputs.
    if ((utxo.scriptPubKey.IsPayToTaproot() || is_qcoin_v2) ? sighash != SIGHASH_DEFAULT :
                                            (sighash != SIGHASH_DEFAULT && sighash != SIGHASH_ALL)) {
        input.sighash_type = sighash;
    }

    // Check all existing signatures use the sighash type
    if (sighash == SIGHASH_DEFAULT) {
        if (!input.m_tap_key_sig.empty() && input.m_tap_key_sig.size() != 64) {
            return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.m_tap_script_sigs) {
            if (sig.size() != 64) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
    } else {
        if (!input.m_tap_key_sig.empty() && (input.m_tap_key_sig.size() != 65 || input.m_tap_key_sig.back() != sighash)) {
            return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.m_tap_script_sigs) {
            if (sig.size() != 65 || sig.back() != sighash) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
        for (const auto& [_, sig] : input.partial_sigs) {
            if (sig.second.back() != sighash) return util::Unexpected{PSBTError::SIGHASH_MISMATCH};
        }
    }

    sigdata.witness = false;
    bool sig_complete;
    if (txdata == nullptr) {
        sig_complete = ProduceSignature(*sign_provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, {.sighash_type = sighash});
        sig_complete = ProduceSignature(*sign_provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return util::Unexpected{PSBTError::INCOMPLETE};

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!options.finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // We can remove the non_witness_utxo if and only if there are no non-segwit or segwit v0
        // inputs in this transaction. Since this requires inspecting the entire transaction, this
        // is something for the caller to deal with (i.e. FillPSBT).
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    if (!sig_complete) return util::Unexpected{PSBTError::INCOMPLETE};
    return {};
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx)
{
    // Figure out if any non_witness_utxos should be dropped
    std::vector<unsigned int> to_drop;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const auto& input = psbtx.inputs.at(i);
        int wit_ver;
        std::vector<unsigned char> wit_prog;
        if (input.witness_utxo.IsNull() || !input.witness_utxo.scriptPubKey.IsWitnessProgram(wit_ver, wit_prog)) {
            // There's a non-segwit input, so we cannot drop any non_witness_utxos
            to_drop.clear();
            break;
        }
        if (wit_ver == 0) {
            // Segwit v0, so we cannot drop any non_witness_utxos
            to_drop.clear();
            break;
        }
        // non_witness_utxos cannot be dropped if the sighash type includes SIGHASH_ANYONECANPAY
        // Since callers should have called SignPSBTInput which updates the sighash type in the PSBT, we only
        // need to look at that field. If it is not present, then we can assume SIGHASH_DEFAULT or SIGHASH_ALL.
        if (input.sighash_type != std::nullopt && (*input.sighash_type & 0x80) == SIGHASH_ANYONECANPAY) {
            to_drop.clear();
            break;
        }

        if (input.non_witness_utxo) {
            to_drop.push_back(i);
        }
    }

    // Drop the non_witness_utxos that we can drop
    for (unsigned int i : to_drop) {
        psbtx.inputs.at(i).non_witness_utxo = nullptr;
    }
}

bool FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    std::optional<PrecomputedTransactionData> txdata_res = PrecomputePSBTData(psbtx);
    if (!txdata_res) {
        return false;
    }
    const PrecomputedTransactionData& txdata = *txdata_res;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);
        const auto sign_result = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, {.sighash_type = input.sighash_type, .finalize = true}, /*out_sigdata=*/nullptr);
        complete &= sign_result.has_value();
    }

    return complete;
}

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result)
{
    // It's not safe to extract a PSBT that isn't finalized, and there's no easy way to check
    //   whether a PSBT is finalized without finalizing it, so we just do this.
    if (!FinalizePSBT(psbtx)) {
        return false;
    }

    std::optional<CMutableTransaction> unsigned_tx = psbtx.GetUnsignedTx();
    if (!unsigned_tx) {
        return false;
    }
    result = *unsigned_tx;
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        result.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }
    return true;
}

std::optional<PartiallySignedTransaction> CombinePSBTs(const std::vector<PartiallySignedTransaction>& psbtxs)
{
    PartiallySignedTransaction out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return std::nullopt;
        }
    }
    return out;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

util::Result<PartiallySignedTransaction> DecodeBase64PSBT(const std::string& base64_tx)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        return util::Error{Untranslated("invalid base64")};
    }
    return DecodeRawPSBT(MakeByteSpan(*tx_data));
}

util::Result<PartiallySignedTransaction> DecodeRawPSBT(std::span<const std::byte> tx_data)
{
    SpanReader ss_data{tx_data};
    try {
        PartiallySignedTransaction psbt(deserialize, ss_data);
        if (!ss_data.empty()) {
            return util::Error{Untranslated("extra data after PSBT")};
        }
        return psbt;
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

uint32_t PartiallySignedTransaction::GetVersion() const
{
    if (m_version != std::nullopt) {
        return *m_version;
    }
    return 0;
}
