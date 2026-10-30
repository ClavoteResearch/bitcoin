# Wallet post-quantum (ML-DSA) integration: status and gaps

This document tracks the Qcoin (QTC placeholder) fork's path from secp256k1
ECDSA wallet signing to FIPS 204 ML-DSA. It is a working note, not a spec; the
normative design is the "Segwit v2: ML-DSA Post-Quantum Signatures" BIP draft
in the clavote-boop/BIP repository (`docs/spec/bip-mldsa-formal.md`).

## Current status

| Piece | Location | State |
|---|---|---|
| Consensus verify stub | `fork/src/script/verify_stub.h` | ML-DSA-87 only, via liboqs. All legacy ECDSA checks in `script/interpreter.cpp` are routed here. |
| ECDSA fallback | CMake option `QCOIN_ECDSA_FALLBACK` (default ON) | When ON, inputs that are not ML-DSA-87 sized fall back to secp256k1 verification, so regtest spends with ordinary wallets work. Turn OFF to test strict routing. |
| Wallet scheme switch | `fork/src/pqc/pqc.h`, `-walletsigscheme=<ecdsa\|mldsa44\|mldsa87>` | Runtime, read once in `WalletInit::ParameterInteraction`. Compile-time default via `-DQCOIN_DEFAULT_SIG_SCHEME=<0\|1\|2>`. Default `ecdsa`. |
| ML-DSA keygen / sign / verify | `fork/src/pqc/pqc.cpp` | Thin liboqs wrappers for ML-DSA-44 and ML-DSA-87. Functional. |
| ML-DSA key store (dev only) | `qcoin::pqc::MlDsaKeyStore` | Process-wide, in memory, mutex-guarded. Keys indexed by the 20-byte ID of the HD seed key they were generated with; one key is the wallet "default". Saved **unencrypted** to `mldsa_keys.dat` next to the wallet database and reloaded in `CWallet::LoadExisting`. |
| Keygen call site | `wallet/wallet.cpp`, `CWallet::SetupOwnDescriptorScriptPubKeyMans` | With a non-ECDSA scheme, a keypair is generated, added to the store as default, and saved to disk. |
| Witness v2 definitions (Option B) | `fork/src/script/witness_v2.h` | Constants, attestation parser/builder, commitment computation, section 6 message builder and ML-DSA verify with context, per BIP sections 1-3 and 6. Wired into the interpreter only under `QCOIN_WITNESS_V2_EXPERIMENTAL`; `Qcoin / Option B` marker comments in solver, key_io, descriptor, outputtype and addresstype show where the rest attaches. |
| Signing call site | `script/sign.cpp`, `MutableTransactionSignatureCreator::CreateSig` | With a non-ECDSA scheme, the store is queried by key ID, then by default. If a key is found a real ML-DSA signature is produced and logged. The spend still fails at `VerifyScript` because the UTXO commits to a secp256k1 pubkey. |

The ECDSA path is untouched when `-walletsigscheme=ecdsa` (the default), so all
existing wallet and functional test flows keep working.

### Why an ML-DSA "spend" still fails

`ProduceSignature` finishes by running `VerifyScript` with the freshly built
witness. The interpreter hands `(sighash, sig, pubkey)` to the verify stub;
`pubkey` is the 33-byte secp256k1 key from the P2WPKH output, so the input is
not ML-DSA-87 sized and, with the fallback on, secp256k1 verification of a
4627-byte ML-DSA signature fails. Without the fallback it fails the same way.
Nothing short of outputs that commit to an ML-DSA public key can make this pass.

### Known limitations of the key store

- Secret keys are written in plaintext and are not covered by the wallet
  passphrase. They are never wiped from memory except on `Clear()`.
- One store per process. Two loaded wallets share it, and a second wallet's
  keygen overrides the default key.
- Lookups by the spending key's ID almost always miss (the stored ID is the
  seed key's), so every spend uses the default key. This is intentional for
  now; see "Descriptors" below.
- No RPC exposes the keys; inspect `debug.log` or the file.

## The decision to make first: interpreter routing vs. witness v2

Two incompatible designs are present in this tree and only one can survive.

### Option A: hard-wired ECDSA-path routing (what the branch does today)

Commit 13d6b525 replaces `VerifyECDSASignature` in the interpreter with an
ML-DSA-87 check. Signatures and keys travel in the existing scriptSig /
witness v0 positions.

- Pro: minimal code. Reuses every existing script template, descriptor and
  address type once the wallet can produce ML-DSA material.
- Con: it is a **hard fork**. Every pre-fork ECDSA UTXO becomes unspendable
  unless the fallback stays on forever, and then nothing is post-quantum.
- Con: a 2592-byte pubkey and 4627-byte signature as witness stack items
  violate the BIP 110 rule-2 limit (256 bytes) that the BIP draft was
  rewritten to respect, and bloat the UTXO set if the pubkey is in the
  scriptPubKey.
- Con: ML-DSA-87 (the current stub) is not the parameter set the BIP picks.

### Option B: witness version 2 attestation field (what the BIP specifies)

A v2 output is `OP_2 <32-byte commitment>`. The final witness element, if it
starts with `0x51`, is an *attestation* of up to four `param_id || pk || sig`
entries that consensus parses before the interpreter runs. Key-path spends
never touch the script stack; script-path spends use `OP_CHECKMLDSAVERIFY`
with only 32-byte stack operands. ML-DSA-44 is the only parameter set defined.

- Pro: soft fork. Legacy ECDSA verification is left exactly as it is; commit
  13d6b525 is reverted.
- Pro: satisfies BIP 110 by construction; no stack item over 32 bytes.
- Pro: sighash commits to `param_id` and `pk_hash` under ctx `BIP-MLDSAv2`,
  closing cross-parameter-set replay.
- Con: substantially more code (new witness version, attestation parser, new
  opcode semantics, bech32m v2 addresses, descriptor type, dust rule).

### Recommendation

Choose B. Everything built so far is reusable under B: `pqc.h` already models
both parameter sets, `MlDsaKeyStore` becomes the interim backing for a
`mldsa()` descriptor key, and `verify_stub.h` collapses to a helper that the
attestation verifier calls. If A is kept instead, document it as a hard-fork
testnet experiment and delete the BIP compliance section from the draft.

## Sighash and signature message (BIP section 6)

What changed in this step:

- **Consensus (experimental).** `GenericTransactionSignatureChecker::CheckMlDsaSignature`
  computes the BIP 341 sighash with `SigVersion::TAPROOT` and `SIGHASH_DEFAULT`
  (v2 carries no hashtype byte), builds `m = param_id || SHA256(pk) || sighash`
  (65 bytes), and verifies the attestation's signature with liboqs
  `OQS_SIG_verify_with_ctx_str` under ctx `BIP-MLDSAv2`. The key path in
  `VerifyWitnessProgram` now calls it after the commitment check and returns
  success on a valid signature. New script errors: `SCRIPT_ERR_MLDSA_ATTESTATION`
  and `SCRIPT_ERR_MLDSA_SIG`. All of this compiles only with the CMake option
  `QCOIN_WITNESS_V2_EXPERIMENTAL=ON`.
- **Wallet.** With a non-ECDSA scheme the signer no longer signs the raw sighash.
  It signs the same 65-byte section 6 message under the same context. Because
  today's wallet still spends P2WPKH inputs, the sighash it feeds in is the
  legacy/segwit-v0 one, not the BIP 341 hash; the message framing and context
  are already the BIP's, so when a v2 output type exists only the sighash
  source changes.
- **Self-test.** `qcoin-v2-selftest` (built with the option ON) generates an
  ML-DSA-44 key, builds `OP_2 <Q>`, signs the section 6 message for a spending
  transaction, assembles the one-entry attestation witness, and runs
  `VerifyScript`. It asserts success, then asserts the right error for a
  corrupted signature, a wrong commitment, and a malformed attestation.

Still open from section 6: canonical signature-encoding enforcement (liboqs
accepts non-canonical hints), the BIP 342-style extension of the sighash for
the script path, and the deployment flag so the branch is not active
unconditionally once enabled.

## Option B checklist: what a spendable ML-DSA output needs

Each item names the file that owns it and the marker comment (search for
`Qcoin / Option B`) or stub already placed there. Items are ordered so each
one can be built and tested on top of the previous ones. Everything below is
gated behind `QCOIN_WITNESS_V2_EXPERIMENTAL` until it is complete; without the
define, v2 stays an unknown upgradable witness version exactly as upstream.

### 1. Shared definitions: `fork/src/script/witness_v2.h` (exists)
- [x] Constants: version 2, 32-byte program, tag `MLDSAv2/Commit`, prefix 0x51,
      `param_id` 0x01 = ML-DSA-44 (1312/2420), 0x02 reserved, ctx `BIP-MLDSAv2`.
- [x] `ParseAttestation`: fixed-layout parser with the no-slack-bytes rule.
- [x] `PubKeyHash`, `ComputeCommitment`, `CheckCommitment`.
- [ ] Canonical FIPS 204 signature-encoding check (hint count <= omega).
- [x] Section 6 message builder: `param_id || pk_hash || sighash_v2`.

### 2. New witness version in consensus: `script/interpreter.cpp`
- [x] Guarded v2 branch in `VerifyWitnessProgram` ahead of the v0/v1 chain
      that pops the attestation and checks the commitment (key path).
- [ ] `SCRIPT_VERIFY_MLDSA_V2` flag plus deployment in `consensus/params.h`
      and `deploymentinfo.cpp`; branch runs only when the flag is set.
- [x] Key path: ML-DSA.Verify over the section 6 message (`CheckMlDsaSignature`;
      liboqs with ctx `BIP-MLDSAv2`).
- [ ] Script path: control block <= 257 bytes, leaf hash and merkle proof as
      BIP 341, OP_SUCCESSx forbidden in leaves, `SigVersion::MLDSA_V2`.
- [ ] `OP_CHECKMLDSAVERIFY` at 0xb3 under v2 leaf semantics: pops `<i:1>` and
      `<pk_hash:32>`, requires an attestation, i < n, SHA256(pk_i) == pk_hash,
      ML-DSA.Verify(entry i).
- [x] Dedicated `ScriptError` codes (`SCRIPT_ERR_MLDSA_ATTESTATION`, `SCRIPT_ERR_MLDSA_SIG`);
      the script path still returns `SCRIPT_ERR_UNKNOWN_ERROR`.
- [~] v2 sighash: key path uses `SignatureHashSchnorr(TAPROOT, SIGHASH_DEFAULT)`;
      `param_id`/`pk_hash` are committed in the message, not the hash. Script-path
      extension pending.
- [ ] Revert commit 13d6b525 (ECDSA-path routing) and drop
      `QCOIN_ECDSA_FALLBACK` once the v2 path verifies end to end.

### 3. Output commitment and classification: `script/solver.cpp`, `script/script.h`
- [ ] `TxoutType::WITNESS_V2_MLDSA` returned for v2 + 32 bytes (marker in
      `Solver`); `vSolutionsRet` carries Q.
- [ ] `CScript::IsWitnessV2MlDsa()` helper alongside `IsPayToAnchor()`.
- [ ] `GetScriptForDestination` emits `OP_2 <Q>` for the new destination.
- [ ] Policy: `IsStandard` accepts the type; dust threshold uses the ML-DSA
      spend size (about 940 vbytes per key-path input).

### 4. Address type: `addresstype.h`, `key_io.cpp`, `outputtype.h`
- [ ] `struct WitnessV2MlDsa : uint256` added to the `CTxDestination` variant
      (marker in `addresstype.h`).
- [ ] `DecodeDestination`: `version == 2 && size == 32` returns it (marker in
      `key_io.cpp`); `EncodeDestination` emits bech32m at version 2
      (`bc1z...`, `bcrt1z...`).
- [ ] `OutputType::BECH32M_V2` (marker in `outputtype.h`), parse/format string,
      `OutputTypeFromDestination`, `-addresstype`/`-changetype` acceptance.
- [ ] Test vectors: address encoding, commitment construction for key path
      and script path (the BIP's Test Vectors section is still empty).

### 5. Descriptor change: `script/descriptor.cpp`, `script/signingprovider.h`
- [ ] ML-DSA `PubkeyProvider`: parses a 1312-byte hex key or an HD-seed form,
      exposes `pk_hash`, and resolves the secret key for signing.
- [ ] `wpq(KEY)` and `wpq(KEY,{TREE})` `DescriptorImpl` whose `MakeScripts`
      emits `OP_2 <ComputeCommitment(0x01, pk_hash, merkle_root)>` (names are
      reserved with a not-implemented error today).
- [ ] `SigningProvider::GetMlDsaKey(pk_hash, sk)`; replace the
      `MlDsaKeyStore` default-key fallback in `script/sign.cpp` with it.
- [ ] Wallet DB record type for ML-DSA secrets, encrypted via `crypter.cpp`,
      replacing `mldsa_keys.dat`.

### 6. Parser and signer: `script/sign.cpp`, `script/interpreter.cpp`
- [ ] `ProduceSignature`: for a `WITNESS_V2_MLDSA` output build the section 6
      message, sign with ML-DSA-44 under ctx `BIP-MLDSAv2`, and emit the
      witness as `[attestation]` (key path) or
      `[inputs..., leaf, control, attestation]` (script path).
- [ ] `SignatureExtractorChecker` / `DataFromTransaction` understand the
      attestation so partially signed inputs round-trip through PSBT.
- [ ] PSBT fields for ML-DSA pubkeys and partial signatures.
- [ ] Functional test: create `wpq()` wallet on regtest, fund it, spend
      key-path and script-path, assert both confirm; negative tests for every
      structural rule in section 3.

### Exit criteria
A regtest wallet with `-walletsigscheme=mldsa44 -addresstype=bech32m-v2`
receives to a `bcrt1z` address and spends it in a block that the node accepts
with `QCOIN_ECDSA_FALLBACK=OFF` and commit 13d6b525 reverted.

## Remaining gaps (both options unless noted)

### Key material and storage
- Replace `MlDsaKeyStore` with wallet-DB records (encrypted via `crypter.cpp`,
  which currently assumes 32-byte secrets) and a secure-allocator key type.
- `SigningProvider` has no `GetMlDsaKey(...)`; the signer bypasses it.
- No HD derivation. FIPS 204 keygen takes a 32-byte seed, so a BIP32-style
  path to a seed is plausible, but it needs a spec.

### Descriptors and script
- No descriptor fragment for an ML-DSA key (e.g. `mldsa(KEY)` / `wpq(...)`).
- No `OutputType` for witness v2; `-addresstype`/`-changetype` cannot request it.
- `solver.cpp` has no template for the v2 program (B) or for an ML-DSA pubkey
  in legacy positions (A), so the wallet cannot recognise its own PQ outputs.
- `OP_CHECKMLDSAVERIFY` (0xb3 under v2 leaf semantics) is not implemented (B).

### Address format (B)
- Witness v2 bech32m addresses (`bc1z...`, `bcrt1z...`). `key_io.cpp` encodes
  v0 and v1 only.
- Commitment `tagged_hash(param_id || pk_hash || merkle_root)` is not computed anywhere.

### Witness v2 encoding and sighash (B)
- Attestation field (`0x51 || n || entries`) serialisation/parsing.
- v2 sighash extending BIP 341/342 with `param_id`, `pk_hash`, ctx `BIP-MLDSAv2`.
  The current signer signs the raw legacy sighash with an empty context.
- Canonical-encoding check on signatures (hint count <= omega); liboqs accepts
  any valid encoding.

### Policy, fees, tests
- Dust threshold from the ML-DSA spend size (~940 vbytes per input for ML-DSA-44).
- No unit, functional, or fuzz tests for any of the above. `test/` is excluded
  from the current build (`-DBUILD_TESTS=OFF`).
- Benchmark per-block ML-DSA verification cost (BIP section 7).

## How to exercise what exists

```bash
# default: ECDSA, regtest spends work
build/bin/bitcoind -regtest -daemon

# wallet generates and stores an ML-DSA-87 key at creation, signs with it on
# spend attempts (see debug.log), but the spend is rejected at VerifyScript
build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

# the key survives a restart via <walletdir>/mldsa_keys.dat
build/bin/bitcoin-cli -regtest stop && build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

# strict consensus routing (no ECDSA fallback)
cmake -B build -DQCOIN_ECDSA_FALLBACK=OFF && cmake --build build --target bitcoind
```
