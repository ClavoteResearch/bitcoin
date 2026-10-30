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
