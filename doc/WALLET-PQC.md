# Wallet post-quantum (ML-DSA) integration: status and gaps

This document tracks the Qcoin (QTC placeholder) fork's path from secp256k1
ECDSA wallet signing to FIPS 204 ML-DSA. It is a working note, not a spec; the
normative design is the "Segwit v2: ML-DSA Post-Quantum Signatures" BIP draft
in the clavote-boop/BIP repository (`docs/spec/bip-mldsa-formal.md`).

## What exists today

| Piece | Location | State |
|---|---|---|
| Consensus verify stub | `fork/src/script/verify_stub.h` | ML-DSA-87 only, via liboqs. All legacy ECDSA checks in `script/interpreter.cpp` are routed here. |
| ECDSA fallback | CMake option `QCOIN_ECDSA_FALLBACK` (default ON) | When ON, inputs that are not ML-DSA-87 sized fall back to secp256k1 verification, so regtest spends with ordinary wallets work. Turn OFF to test strict routing. |
| Wallet scheme switch | `fork/src/pqc/pqc.h`, `-walletsigscheme=<ecdsa\|mldsa44\|mldsa87>` | Runtime, read once in `WalletInit::ParameterInteraction`. Compile-time default via `-DQCOIN_DEFAULT_SIG_SCHEME=<0\|1\|2>`. Default `ecdsa`. |
| ML-DSA keygen / sign / verify stubs | `fork/src/pqc/pqc.cpp` | Thin liboqs wrappers for ML-DSA-44 and ML-DSA-87. Functional, but nothing persists the keys yet. |
| Signing call site | `script/sign.cpp`, `MutableTransactionSignatureCreator::CreateSig` | When the scheme is not ECDSA the ML-DSA path is taken. It currently fails (returns false) because the `SigningProvider` has no ML-DSA secret key to hand over. |
| Keygen call site | `wallet/wallet.cpp`, descriptor wallet setup | When the scheme is not ECDSA a keypair is generated and logged, then discarded. |

The ECDSA path is untouched when `-walletsigscheme=ecdsa` (the default), so all
existing wallet and functional test flows keep working.

## Mismatch to resolve first

The BIP draft specifies **ML-DSA-44** carried in a **witness v2 attestation
field** that never touches the script stack. The current branch instead
routes **legacy ECDSA checks** to **ML-DSA-87** inside the interpreter. These
are different designs. Before any of the gaps below are closed, pick one:

1. Follow the BIP: add witness version 2, the attestation parser, and
   `OP_CHECKMLDSAVERIFY`; leave legacy ECDSA verification alone. The
   interpreter routing commit (13d6b525) would then be reverted.
2. Keep the experiment: ML-DSA-87 signatures in legacy/segwit-v0 script
   positions. This violates the BIP 110 witness-item size rule the BIP was
   written to satisfy and needs a hard fork.

`pqc.h` exposes both parameter sets so either choice is a one-line default.

## Remaining gaps

### Key material and storage
- No `CKey`-equivalent for ML-DSA. `MlDsaKeyPair` is a plain struct; secret
  bytes are not held in a secure allocator and are not wiped on destruction.
- `SigningProvider` has no `GetMlDsaKey(...)`. `CreateSig` cannot obtain a
  secret key, which is why ML-DSA signing currently fails.
- Wallet DB has no record type for ML-DSA keys (encrypted or plain).
  `crypter.cpp` assumes 32-byte secrets.
- No HD derivation. FIPS 204 keygen takes a 32-byte seed, so a BIP32-style
  path to a seed is plausible, but it needs a spec.

### Descriptors and script
- No descriptor fragment for an ML-DSA key (e.g. `mldsa(KEY)` or a `wpq(...)`
  output type). `script/descriptor.cpp` and `PubkeyProvider` are secp256k1-only.
- No `OutputType` for witness v2; `-addresstype`/`-changetype` cannot request it.
- `solver.cpp` has no template for the v2 program, so the wallet cannot
  recognise its own PQ outputs as spendable.
- `OP_CHECKMLDSAVERIFY` (0xb3 under v2 leaf semantics) is not implemented.

### Address format
- Witness v2 bech32m addresses (`bc1z...` mainnet, `bcrt1z...` regtest) are not
  produced. `key_io.cpp` encodes v0 and v1 only; decoding v2 as a 34-byte
  program also needs the commitment check from BIP section 1.
- The commitment is `tagged_hash(param_id || pk_hash || merkle_root)`; no code
  computes it yet.

### Witness v2 encoding
- Attestation field (`0x51 || n || entries`) serialisation and parsing is
  missing from both the interpreter and the signer.
- Sighash for v2 must extend BIP 341/342 and commit to `param_id` and
  `pk_hash` with context string `BIP-MLDSAv2`. `SignatureHashSchnorr` would
  need a v2 variant; the current stub signs the raw 32-byte legacy sighash.
- Canonical-encoding check on ML-DSA signatures (hint count <= omega,
  canonical hints) is not enforced; liboqs verify accepts any valid encoding.

### Policy, fees, tests
- Dust threshold must use the ML-DSA spend size (~940 vbytes per input).
- No unit, functional, or fuzz tests for any of the above. The `test/` tree is
  excluded from the current build (`-DBUILD_TESTS=OFF`).
- Benchmark the ML-DSA verification budget per block (BIP section 7).

## How to exercise what exists

```bash
# default: ECDSA, regtest spends work
build/bin/bitcoind -regtest -daemon

# wallet announces the PQ scheme and generates (and discards) a keypair at setup;
# spends fail with "Signing transaction failed" until key storage lands
build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

# strict consensus routing (no ECDSA fallback)
cmake -B build -DQCOIN_ECDSA_FALLBACK=OFF && cmake --build build --target bitcoind
```
