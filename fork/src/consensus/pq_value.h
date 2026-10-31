// Qcoin: the value rule. On chains with Consensus::Params::fMlDsaOnlyValue, once
// DEPLOYMENT_MLDSA_V2 is active, every transaction output that carries value must
// be a witness version 2 ML-DSA program (OP_2 <32 bytes>, see
// fork/src/script/witness_v2.h). Ordinary ECDSA outputs (P2PKH, P2SH, P2WPKH,
// P2WSH, P2TR, bare multisig, P2A, ...) are consensus-invalid when nValue > 0.
// Zero-value outputs are unrestricted so OP_RETURN commitments (the segwit
// witness commitment in the coinbase among them) keep working.
//
// Inputs are not restricted: whatever an output is, spending it is governed by
// the script rules. Since no value-carrying non-v2 output can exist after
// activation, the only ECDSA coins that can ever be spent on such a chain are
// ones created before activation (regtest with -testactivationheight) or
// zero-value ones.
//
// Enforced in src/validation.cpp: ContextualCheckBlock (blocks) and
// MemPoolAccept::PreChecks (mempool), both as consensus failures with
// REJECT_REASON. The wallet (src/wallet/spend.cpp) refuses to build such
// outputs on these chains. This header deliberately has no liboqs dependency.
#ifndef QCOIN_FORK_CONSENSUS_PQ_VALUE_H
#define QCOIN_FORK_CONSENSUS_PQ_VALUE_H

#include <primitives/transaction.h>
#include <script/script.h>

#include <cstddef>
#include <optional>
#include <vector>

namespace qcoin::pq {

/** Reject reason used by both the block and the mempool check. */
inline constexpr const char* REJECT_REASON = "bad-txns-output-not-mldsa";

/** True for OP_2 <32-byte program>, the only scriptPubKey allowed to hold value. */
inline bool IsMlDsaValueScript(const CScript& script_pub_key)
{
    int version{0};
    std::vector<unsigned char> program;
    return script_pub_key.IsWitnessProgram(version, program) && version == 2 && program.size() == 32;
}

/** True if the output is allowed under the value rule. */
inline bool OutputMayCarryValue(const CTxOut& out)
{
    return out.nValue == 0 || IsMlDsaValueScript(out.scriptPubKey);
}

/** Index of the first output that violates the value rule, or nullopt if the transaction complies. */
inline std::optional<size_t> FirstNonMlDsaValueOutput(const CTransaction& tx)
{
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (!OutputMayCarryValue(tx.vout[i])) return i;
    }
    return std::nullopt;
}

} // namespace qcoin::pq

#endif // QCOIN_FORK_CONSENSUS_PQ_VALUE_H
