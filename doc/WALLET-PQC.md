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
| ML-DSA key storage | `walletdescriptormldsakey` records (`wallet/walletdb.cpp`), `DescriptorScriptPubKeyMan::m_map_mldsa_keys` | One record per key, keyed by (descriptor id, SHA256(pk)), value (scheme, pk, sk, hash). Loaded with the descriptor and exposed to signing through `SigningProvider::GetMlDsaKey`. Encrypted wallets store `walletdescriptormldsackey` records instead: the secret is AES-256-CBC under the wallet master key with IV = SHA256(pk), exactly like secp256k1 descriptor keys; `encryptwallet` converts existing plaintext records and erases them. Unlocking verifies every ML-DSA record decrypts to the parameter set's secret-key length. The former process-wide `mldsa_keys.dat` store is gone. |
| Keygen call site | `wallet/wallet.cpp`, `CWallet::SetupOwnDescriptorScriptPubKeyMans` | With a non-ECDSA scheme, a keypair is generated, added to the store as default, and saved to disk. |
| Witness v2 definitions (Option B) | `fork/src/script/witness_v2.h` | Constants, attestation parser/builder, commitment computation, section 6 message builder and ML-DSA verify with context, per BIP sections 1-3 and 6. Wired into the interpreter only under `QCOIN_WITNESS_V2_EXPERIMENTAL`; `Qcoin / Option B` marker comments in solver, key_io, descriptor, outputtype and addresstype show where the rest attaches. |
| Signing call site | `script/sign.cpp`, `MutableTransactionSignatureCreator::CreateMlDsaAttestation` | Witness v2 programs are routed here by `ProduceSignature` (experimental builds). ECDSA inputs are ECDSA-signed again. |
| wpq() descriptor + wallet import | `script/descriptor.cpp`, `wallet/wallet.cpp` | `wpq(HEXPK)` emits `OP_2 <Q>`; imported under label `mldsa` at wallet creation with a non-ECDSA scheme. Address is `bcrt1z...` via `WitnessUnknown`. |

The ECDSA path is untouched when `-walletsigscheme=ecdsa` (the default), so all
existing wallet and functional test flows keep working.

### Why an ML-DSA "spend" still fails

`ProduceSignature` finishes by running `VerifyScript` with the freshly built
witness. The interpreter hands `(sighash, sig, pubkey)` to the verify stub;
`pubkey` is the 33-byte secp256k1 key from the P2WPKH output, so the input is
not ML-DSA-87 sized and, with the fallback on, secp256k1 verification of a
4627-byte ML-DSA signature fails. Without the fallback it fails the same way.
Nothing short of outputs that commit to an ML-DSA public key can make this pass.

### Key storage: what is and is not covered

- Keys are wallet-scoped. Two wallets in one process each load only their own
  records; one wallet cannot see or spend the other's v2 coins. A wallet backup
  (`backupwallet`) includes them.
- Encryption matches secp256k1 keys. `encryptwallet` re-writes every
  `walletdescriptormldsakey` as a `walletdescriptormldsackey` and erases the
  plaintext record in the same transaction; `walletpassphrase` must succeed
  before `getnewmldsaaddress` or a v2 spend works; a wrong passphrase is
  rejected by `CheckDecryptionKey`, which also covers ML-DSA-only descriptors.
- `encryptwallet` also re-runs descriptor setup with a fresh seed (upstream
  behaviour for descriptor wallets), so the creation hook adds one more ML-DSA
  key and `wpq()` address at that point, written encrypted. Spending while locked
  cannot sign: `send` returns an unsigned PSBT and `sendtoaddress` errors.
- Secrets are held in `qcoin::pqc::SecureBytes`, a `std::vector` on Core's
  `secure_allocator` (locked pool, `memory_cleanse` on free), the same type as
  `CKeyingMaterial`. Decrypted keys move straight from the crypter into it, the
  database loader deserialises into it, and the signer calls `WipeSecret` as soon
  as liboqs has produced the signature. What liboqs does with its own internal
  copies during signing is up to liboqs (it cleanses them).
- Keys are HD-derived from the wallet root (see "HD derivation"); each is still
  stored with its descriptor (about 3.9 KB for ML-DSA-44) plus its index.
- No RPC exposes the keys; `listdescriptors true` cannot print a private form
  of `wpq()`.

## Activation: DEPLOYMENT_MLDSA_V2

The witness v2 path is no longer gated by a compile-time define. It is a
buried (height-based) deployment, `Consensus::DEPLOYMENT_MLDSA_V2`, with a new
script-verify flag `SCRIPT_VERIFY_MLDSA_V2`:

- **Consensus.** `GetBlockScriptFlags` adds `SCRIPT_VERIFY_MLDSA_V2` from
  `Consensus::Params::MLDSAv2Height`. Before that height a 32-byte witness v2
  program is an unknown upgradable witness version, exactly as upstream
  (anyone-can-spend in blocks), so activation is a soft fork.
- **Policy.** `SCRIPT_VERIFY_MLDSA_V2` is in `STANDARD_SCRIPT_VERIFY_FLAGS`, and
  `MemPoolAccept::PolicyScriptChecks` strips it until the deployment is active,
  so pre-activation v2 spends are rejected with
  `mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)`
  and are not relayed. `AreInputsStandard` accepts v2 inputs and leaves the
  decision to the script flags.
- **Chains.** mainnet, testnet3, testnet4 and signet: `INT_MAX` (not deployed).
  regtest: height 0 (always active) unless overridden with
  `-testactivationheight=mldsav2@<height>`. `getdeploymentinfo` lists `mldsav2`
  with its height and active state.
- **Wallet.** Signing is independent of activation (the wallet verifies with
  the full standard flags), so a wallet can prepare and sign a v2 spend before
  activation; the node simply refuses to accept it until the height is reached.
- **Build option.** `QCOIN_WITNESS_V2_EXPERIMENTAL` now only unlocks non-BIP
  extras: the ML-DSA-87 `param_id` 0x7f and the `qcoin-v2-selftest` binary.
  The default build contains the complete v2 path.

## Testnet launch

A dedicated chain, `-chain=qtctest`, exists for the public testnet. Its parameters
(`src/kernel/chainparams.cpp`, `CQtcTestParams`):

| Parameter | Value |
|---|---|
| Chain name / data dir | `qtctest` (`<datadir>/qtctest`, config section `[qtctest]`) |
| Network magic | `d1 54 43 54` ("QTCT" with the high bit set) |
| P2P / RPC ports | 28333 / 28332 |
| Address HRP | `tq` (legacy segwit `tq1q...`, ML-DSA witness v2 `tq1z...`); base58 and xpub prefixes as testnet |
| Genesis | time 1761782400 (2026-10-30 00:00 UTC), nonce 0, nBits 0x207fffff, coinbase text "Qcoin testnet 30/Oct/2026 ML-DSA witness v2 active from genesis" |
| Genesis hash | `3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60` |
| Genesis merkle root | `951bd97f5c87145947cf54618d588de8c47b88c329991c4e21502ef52046c4b6` |
| Deployments | BIP34/65/66/CSV at height 1, segwit and **mldsav2 at height 0** (active from genesis); testdummy never |
| Proof of work | regtest-strength `powLimit`, non-retargeting, min-difficulty blocks allowed: blocks are produced on demand with `generatetoaddress` |
| Seeds / checkpoints / assumevalid | none yet |

Bring-up:

```bash
bitcoind -chain=qtctest -walletsigscheme=mldsa44 -fallbackfee=0.0001 -daemon
bitcoin-cli -chain=qtctest getblockchaininfo      # "chain": "qtctest"
bitcoin-cli -chain=qtctest getdeploymentinfo      # deployments.mldsav2.active == true, height 0
bitcoin-cli -chain=qtctest createwallet w
bitcoin-cli -chain=qtctest -rpcwallet=w getnewmldsaaddress   # tq1z...
```

Launch checklist (in order):

1. **Binary.** Tag a release built from this branch with `QCOIN_WITNESS_V2_EXPERIMENTAL=OFF`
   (the default build has the whole v2 path; the option only adds the non-BIP
   ML-DSA-87 extras). Publish reproducible builds for Linux at least, with liboqs
   either statically linked or pinned (0.14.0) in the install instructions.
   Revert commit 13d6b525 (legacy ECDSA-path routing) and drop
   `QCOIN_ECDSA_FALLBACK` first, otherwise legacy spends are not a soft fork.
2. **Genesis and PoW.** The genesis block above is final for a closed
   `qtctest`. For an open testnet follow "Raising the proof-of-work difficulty":
   pick `nBits`, mine a new genesis with `fork/tools/mine-genesis.py`, update
   `CQtcTestParams` (a candidate at `1e00ffff` is already mined and listed), and
   wipe data directories. Set `nMinimumChainWork`/`defaultAssumeValid` once a
   few thousand blocks exist.
3. **Seed nodes.** Run at least two always-on nodes, add their addresses to
   `vSeeds` (DNS) or `vFixedSeeds`, and open port 28333. Until then, peers use
   `-addnode`/`-connect`.
4. **Explorer.** `fork/tools/qtc-explorer.py` (see "Status page and explorer")
   gives a read-only web view with ML-DSA labelling; run it behind a reverse
   proxy on a seed node. Third-party explorers must learn the `tq` HRP and that
   witness version 2 outputs are ML-DSA attestations (`OP_2 <Q>`, 3735-byte
   witness); until then they show as "unknown witness v2".
5. **Faucet.** `fork/tools/qtc-faucet.py` (see "Faucet") on an always-on node
   started with `-walletsigscheme=mldsa44`: `fund` it from on-demand mining
   before the PoW regime changes, then `serve` it behind a reverse proxy. It
   pays `tq1z` addresses by default (`--allow-any-address` for `tq1q`).
6. **Documentation for testers.** How to build with liboqs, how to start with
   `-chain=qtctest`, how to get a `tq1z` address (`getnewmldsaaddress`), how to
   read `getdeploymentinfo`, and what is still experimental (see "Testnet
   readiness" below).

## Status page and explorer

`fork/tools/qtc-explorer.py` is a standard-library-only Python companion that
serves a small HTML explorer and JSON API over the node's JSON-RPC, so a qtctest
node can be inspected without external tools. It knows what witness v2 outputs
and ML-DSA attestations are and labels them.

```bash
# node (cookie auth is picked up from <datadir>/qtctest/.cookie)
bitcoind -chain=qtctest -walletsigscheme=mldsa44 -fallbackfee=0.0001 -daemon

# explorer on http://127.0.0.1:8080/
python3 fork/tools/qtc-explorer.py --chain qtctest
#   --datadir DIR        node data directory if not ~/.bitcoin
#   --rpcurl URL         if the RPC port is not the chain default (28332 for qtctest)
#   --rpcuser/--rpcpassword   instead of the cookie
#   --bind 0.0.0.0 --port 8080   to expose it (put a reverse proxy in front for a public testnet)
#   --scan N             blocks to scan back for address and txid lookups (default 2000)
```

Pages: `/` (height, mldsav2 deployment state, mempool, peers, recent blocks with
ML-DSA markers), `/blocks?from=H`, `/block/<height|hash>`, `/tx/<txid>`,
`/address/<addr>`, `/mempool`, and a search box. JSON: `/api/status`,
`/api/block/<ref>`, `/api/tx/<txid>`, `/api/address/<addr>`.

- Outputs `OP_2 <32 bytes>` are shown as "witness v2 ML-DSA (OP_2 <Q>)"; inputs
  whose single witness element parses as `0x51 || n || param_id || pk || sig`
  are shown as "ML-DSA attestation: n entry, ML-DSA-44, 3735 bytes".
- No address or transaction index is required: address history and txid lookups
  scan the most recent `--scan` blocks (fine for a young testnet; enable
  `-txindex` on the node for instant txid lookups of old transactions).
- It is a read-only viewer bound to localhost by default. It is not a wallet and
  never sees keys.

`fork/test/regtest_qtctest_explorer.sh` starts a node and the explorer, mines,
makes a tq1z spend, and checks every page.

## Faucet

`fork/tools/qtc-faucet.py` pays small amounts from a node wallet to tester
addresses. Standard library only; by default it pays **only witness v2 ML-DSA
addresses** (`tq1z…`) so every tester exercises the PQ path.

```bash
# node with a wallet-capable scheme
bitcoind -chain=qtctest -walletsigscheme=mldsa44 -fallbackfee=0.0001 -daemon

# 1. fund the faucet wallet (creates wallet "faucet"; on-demand PoW chains only)
python3 fork/tools/qtc-faucet.py fund --blocks 101        # coinbase matures after 100 blocks

# 2a. operator one-off payment (no rate limit)
python3 fork/tools/qtc-faucet.py send tq1z... --amount 1.0

# 2b. public faucet on http://127.0.0.1:8081/ (form + API)
python3 fork/tools/qtc-faucet.py serve --amount 1.0 --cooldown 86400 --max-per-ip 5
#   GET /api/claim?address=tq1z...   POST /claim (form)   GET /api/status
#   --confirm-blocks 1   mine a block after each payout (on-demand PoW only), so the
#                        tester sees a confirmed receive immediately
#   --allow-any-address  also pay tq1q (legacy segwit) addresses
#   --state FILE         rate-limit state (per address and per client IP), default faucet-state.json
#   --bind 0.0.0.0       expose it; run behind a reverse proxy with TLS, which sets X-Forwarded-For
```

Common options match the explorer (`--chain`, `--datadir`, `--rpcurl`,
`--rpcuser/--rpcpassword`); the wallet is loaded or created on start. Refusals
are explicit: invalid address, non-v2 address, address or client in cooldown,
faucet dry. Test coins have no value; the state file is the only persistence.

`fork/test/regtest_qtctest_faucet.sh` funds a faucet by mining, serves it,
claims to a fresh `tq1z` address from a second wallet, confirms the receive, and
checks the refusal paths and the operator CLI.

## Raising the proof-of-work difficulty

`qtctest` currently uses a regtest-strength target so blocks (and the genesis) can
be produced instantly; anyone can also re-mine that genesis. Before an open
testnet the target has to be raised, and because the genesis block commits to
`nBits`, a new genesis must be mined. `fork/tools/mine-genesis.py` does that and
prints the exact lines to paste.

### How the numbers relate

- `nBits` is the compact-encoded target in the genesis header; a header is
  valid when `sha256d(header)` as a little-endian 256-bit number is below it.
  Expected work for one block is `2^256 / target` hashes.
- `powLimit` is the easiest target the chain ever allows. Mining the genesis
  exactly at `powLimit` (the Bitcoin convention) keeps `nBits == powLimit` and
  lets the first retarget period start from the floor.
- `fPowNoRetargeting = true` means the difficulty never changes (fine for a
  closed, mine-on-demand chain); an open testnet wants `false` plus
  `fPowAllowMinDifficultyBlocks = true` (testnet-style: a block may fall back
  to `powLimit` after 2x the target spacing without a block).

### Choosing a target

| `nBits` | expected hashes per block | genesis (message and time as in `qtctest`) | notes |
|---|---|---|---|
| `207fffff` (current regtest-strength) | ~2 | `3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60` | nonce 0, time 1761782400; instant; anyone can re-mine it |
| `1e00ffff` (1/256 of Bitcoin difficulty 1) | ~16.8 million | `0000007ab165a4d29ff101fc7faf2cd2dd20618f4960c1fd85e3dd3e4a823437` | nonce 6739749, time 1761782400, powLimit `000000ffff000000000000000000000000000000000000000000000000000000`; about 5 s per block on one modern CPU, a few seconds for the genesis with the helper |
| `1d00ffff` (Bitcoin difficulty 1, testnet-like) | ~4.3 billion | `0000000086f43233c3863a31d6fd58b66fc47d6a21be15015bbb3e6768a13815` | nonce 207307031, time 1761782400, powLimit `00000000ffff0000000000000000000000000000000000000000000000000000`; mined in 55.5 s at ~4,314,179 H/s |

The `1e00ffff` row is a reasonable open-testnet starting point: honest block
production takes seconds of CPU, re-mining the genesis or grinding reorgs is no
longer free, and `generatetoaddress` still works for bootstrapping if given a
large `maxtries`. Difficulty 1 behaves like Bitcoin testnet and effectively
requires an external miner.

### Procedure

1. Pick `nBits` from the table (or any value; the helper prints expected work).
   Keep the message and timestamp, or choose new ones; the timestamp must not be
   in the future when the first nodes start.
2. Mine the genesis (uses all cores; `--max-seconds` bounds the run):
   ```bash
   python3 fork/tools/mine-genesis.py --nbits 1e00ffff --time 1761782400
   ```
   It prints JSON (hash, merkle root, nonce, time, powLimit, work done) and the
   four C++ lines to paste. Run it twice: the result is deterministic (lowest
   valid nonce), so a second run must print the same nonce. `--expect <hash>`
   turns it into a self-check that exits non-zero on mismatch.
3. Edit `CQtcTestParams` in `src/kernel/chainparams.cpp`:
   - `consensus.powLimit` = the printed value;
   - `consensus.fPowNoRetargeting = false` for an open testnet (keep
     `fPowAllowMinDifficultyBlocks = true`);
   - replace the `CreateGenesisBlock(...)` call and both `assert(...)` lines with
     the printed ones; set `chainTxData.nTime` to the genesis time.
   - Optionally change `pchMessageStart` so old-genesis nodes cannot even
     handshake with the new network.
4. Update `fork/test/regtest_qtctest.sh` (`GENESIS`, and the time/nonce/bits
   check) and `fork/test/test_mine_genesis.sh` (the committed-genesis check),
   and rebuild. Note that `generatetoaddress` defaults to `maxtries` 1,000,000,
   which is below the expected work at `1e00ffff`; the regtest must pass a
   larger `maxtries` (for example `generatetoaddress 101 <addr> 100000000`) or
   mine with an external miner via `getblocktemplate`.
5. Wipe every `qtctest` data directory: a new genesis is a new network.
6. For an open network, publish the new parameters, re-run the launch
   checklist (seeds, explorer, faucet), and set `nMinimumChainWork` /
   `defaultAssumeValid` after a few thousand blocks.

`fork/test/test_mine_genesis.sh` keeps the helper honest: it must reproduce the
committed genesis and the `1e00ffff` candidate above and abort on `--max-seconds`.

## Testnet readiness

What a public Qcoin testnet (its own chain params, `-walletsigscheme=mldsa44`)
would get today, and what is still missing.

Done:
- Consensus: key-path witness v2 ML-DSA-44 verification over the BIP section 6
  message with ctx `BIP-MLDSAv2`; output commitment check; buried-deployment
  activation with the pre-activation soft-fork semantics above; `getdeploymentinfo`.
- Policy: v2 spends standard once active, discouraged before; input sizing and
  fee estimation through the inferred `wpq()` descriptor.
- Wallet: `wpq(HEXPK)` descriptor, bech32m v2 addresses (`bc1z`/`tb1z`/`bcrt1z`
  via `WitnessUnknown`), `getnewmldsaaddress`, HD derivation from the BIP32 root,
  keys stored per descriptor in the wallet database, encrypted with the
  passphrase, held in secure memory and wiped after signing, PSBT create/sign/
  finalise with a proprietary public-key field, watch-only tracking.
- Tests: `qcoin-v2-selftest` and the `fork/test/regtest_v2_*.sh` scripts
  (spend, multi, encrypt, hd, psbt, activation).

Missing before a public testnet:
- **Chain parameters**: `qtctest` exists (see "Testnet launch") but still needs
  seed nodes, a proof-of-work decision, checkpoints/assumevalid, and the revert of
  legacy ECDSA-path routing (commit 13d6b525, `QCOIN_ECDSA_FALLBACK`), which a
  soft-fork design requires.
- **Canonical signature encoding**: FIPS 204 hint-count/canonical-hint check
  before `OQS_SIG_verify` (malleability, txid stability).
- **Script path**: BIP sections 5 (`OP_CHECKMLDSAVERIFY`, control block, leaf
  rules) and the v2 sighash extension for leaves; `wpq(KEY,{TREE})`.
- **Dust and weight policy**: dust threshold from the ML-DSA spend size;
  benchmark of worst-case per-block verification cost (BIP section 7).
- **Address type plumbing**: dedicated `CTxDestination`/`OutputType` so
  `getnewaddress`/`-addresstype` can produce v2 addresses.
- **Derivation spec**: a published path and seed-expansion rule replacing the
  single-level HMAC scheme; `encryptwallet` currently rotates the root.
- **Test coverage**: Boost unit tests and Python functional tests (the current
  checks are shell scripts), fuzz targets for the attestation parser and PSBT
  field, and a BIP test-vector set (the BIP's vectors section is empty).
- **Review**: the deterministic-RNG seeded keygen (`MlDsaKeygenFromSeed`) and
  the proprietary PSBT field should be reviewed against the final BIP text.

## PSBT

Witness v2 inputs work with the standard PSBT flow (`walletcreatefundedpsbt`,
`walletprocesspsbt`, `finalizepsbt`, `sendrawtransaction`) in experimental
builds:

- **Creation.** A wallet that tracks a `wpq()` descriptor, with or without the
  secret, funds the PSBT as usual (the coin is solvable through the inferred
  descriptor). `SignPSBTInput` recognises a 32-byte witness v2 program and adds a
  proprietary input field, BIP 174 type `0xFC`, identifier `qcoin`, subtype `0`,
  value `param_id || ML-DSA public key`, whenever the filling wallet knows the key.
  `decodepsbt` shows it under `inputs[].proprietary`.
- **Signing.** The signer's `ProduceSignature` builds the attestation and the
  input is finalised directly: the 3735-byte attestation lands in
  `final_scriptwitness`. There is no partial-signature stage because a key-path
  v2 input has exactly one signer. If the signer's own descriptors do not know
  the public key behind the program, it is taken from the proprietary field,
  provided it matches the output commitment, so a signer holding only the
  secret can still complete the input.
- **Sighash.** v2 inputs are treated like taproot: `SIGHASH_DEFAULT`, no
  hashtype byte, and no `sighash_type` field is written for the default.
- **Finalisation.** `PSBTInputSignedAndVerified` runs the consensus verifier on
  the final witness, so a bad attestation is rejected before extraction.

Not done: a partial/aggregate form for a future multi-entry attestation, PSBT
fields for the script path, and an exported secret-key format for offline
signers (the secret is only ever in the wallet database).

## HD derivation

`getnewmldsaaddress` no longer generates independent keypairs. Every ML-DSA key
is derived from the wallet's existing BIP32 root:

```
master     = HMAC-SHA512(key = "Qcoin/MLDSAv2/master", data = root_xprv_privkey)[0:32]
seed_i     = HMAC-SHA512(key = master, data = "MLDSAv2/child" || i_le32)[0:32]
(pk_i, sk_i) = FIPS 204 KeyGen_internal(seed_i)        # ML-DSA-44 (0x01) or, experimentally, ML-DSA-87
Q_i        = tagged_hash("MLDSAv2/Commit", param_id || SHA256(pk_i))
```

- The root private key is the one an active HD descriptor already stores, so
  the ML-DSA master needs no new secret record and inherits wallet encryption
  and unlock semantics automatically (`DescriptorScriptPubKeyMan::GetMlDsaMasterSecret`,
  `CWallet::GetMlDsaMasterSecret`).
- Seeded key generation goes through liboqs's public API by temporarily
  installing a deterministic random source (`MlDsaKeygenFromSeed`): ML-DSA
  keygen draws exactly one 32-byte value, which is the FIPS 204 seed. All liboqs
  calls in `fork/src/pqc` are serialised by one mutex so no other ML-DSA
  operation can observe the temporary source, and the system RNG is restored
  immediately. If liboqs ever asks for anything but one 32-byte draw the
  derivation fails closed.
- The derived key is still stored with its descriptor (plaintext or encrypted
  record) together with its index (`walletdescriptormldsahd`), so signing is
  unchanged and `getmldsahdinfo` can list indices. `derivemldsaaddress <index>`
  re-derives without storing, which is how the regtest proves every stored
  address is reproducible from the master. `NextMlDsaHdIndex` is max stored
  index + 1.
- Caveats: this is a single-level, non-hardened-style derivation with no chain
  code and no BIP32 path, chosen for minimality; a real proposal should pick a
  purpose/coin/account path and a published seed-expansion rule. `encryptwallet`
  re-runs descriptor setup with a fresh root, so keys created after encryption
  derive from the new root while earlier ones remain stored and spendable but
  are not reproducible from it. Keys created before this commit have no index
  and are listed without one.

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
both parameter sets, the `walletdescriptormldsakey` records become the backing for a
`mldsa()` descriptor key, and `verify_stub.h` collapses to a helper that the
attestation verifier calls. If A is kept instead, document it as a hard-fork
testnet experiment and delete the BIP compliance section from the draft.

## Receiving to and spending from a witness v2 output

With a build configured `-DQCOIN_WITNESS_V2_EXPERIMENTAL=ON` and a node started
with `-walletsigscheme=mldsa44`, a wallet can now receive to and spend from a
key-path witness v2 ML-DSA output end to end on regtest.

What exists:

- **Descriptor.** `wpq(HEXPK)` (`script/descriptor.cpp`, `WpqDescriptor`).
  HEXPK is the 1312-byte FIPS 204 ML-DSA-44 public key (2592-byte ML-DSA-87 is
  accepted only in experimental builds, as `param_id` 0x7f). `MakeScripts`
  emits `OP_2 <Q>` with `Q = tagged_hash("MLDSAv2/Commit", param_id ||
  SHA256(pk))` and registers `Q -> pk` in the `FlatSigningProvider` it expands
  into. There is no PubkeyProvider yet: the key is a literal and the secret is
  supplied by `SigningProvider::GetMlDsaKey`. Available in
  all builds; `getdescriptorinfo "wpq(<hex>)"` works. `InferDescriptor` maps
  `OP_2 <Q>` back to `wpq(pk)` when the provider knows the key behind Q; the wallet sizes
  inputs from the inferred descriptor's `MaxSatisfactionWeight`, so this is what
  makes the coin solvable and selectable.
- **Address.** No new `CTxDestination`. `OP_2 <Q>` decodes as the existing
  `WitnessUnknown{2, Q}`, which `EncodeDestination` already renders as bech32m
  version 2 (`bcrt1z...` on regtest, `bc1z...` on mainnet), and
  `GetScriptForDestination` round-trips. The `Qcoin / Option B` markers for a
  dedicated destination and `OutputType` remain for when `-addresstype` support
  is wanted.
- **Wallet import and address generation.** `CWallet::CreateMlDsaKeyAndImportWithDB`
  generates a keypair, stores it under `Hash160(pk)`, and imports `wpq(<pk>)` as a
  non-ranged descriptor with a label. Wallet creation with a non-ECDSA scheme
  calls it once (label `mldsa`, marked as the store's default key). The
  `getnewmldsaaddress [label]` RPC calls it again on demand, so each call yields
  a new key and a new `bcrt1z` address with no manual descriptor import. Keys
  are HD-derived from the wallet root (see "HD derivation") and stored as
  `walletdescriptormldsakey` records plus an index, so a wallet backup covers them. `getnewaddress`/`-addresstype` still cannot
  produce v2 addresses, since that needs the dedicated `OutputType`.
- **Signing.** `BaseSignatureCreator::CreateMlDsaAttestation` builds the
  one-entry attestation. `ProduceSignature` routes any 32-byte witness v2
  program to it (experimental builds only), skipping the script solver, and
  finalises with `VerifyScript`. The mutable creator asks the provider for the
  public key behind the program and then for its secret (`GetMlDsaPubKey`,
  `GetMlDsaKey`), computes the BIP 341 sighash
  (`SIGHASH_DEFAULT`), signs the section 6 message under ctx `BIP-MLDSAv2`
  and emits `0x51 || 1 || param_id || pk || sig`. The dummy creator emits a
  real-pk, zero-sig attestation so fee estimation and coin selection see a
  3735-byte witness.
- **Consensus/policy plumbing (experimental builds).**
  `PrecomputedTransactionData::Init` treats a spent `OP_2 <32>` output like
  taproot so the BIP 341 midstate is computed during block validation;
  `AreInputsStandard` accepts such inputs so the mempool does not reject the
  spend as `bad-txns-nonstandard-inputs`.
- **CreateSig is ECDSA again.** The earlier stopgap that made legacy/segwit-v0
  inputs sign with ML-DSA is removed: a wallet with `-walletsigscheme=mldsa44`
  spends its P2WPKH coins with ECDSA and its `wpq()` coin with ML-DSA. The
  scheme now only selects which ML-DSA parameter set the wallet generates and
  attests with.

Regtest flow (see the `fork/test/regtest_v2_*.sh` scripts: spend, multi, encrypt, hd, psbt, activation):

```bash
bitcoind -regtest -walletsigscheme=mldsa44 -fallbackfee=0.0001 -daemon
bitcoin-cli -regtest createwallet miner;  bitcoin-cli -regtest createwallet pq
M=$(bitcoin-cli -regtest -rpcwallet=miner getnewaddress); bitcoin-cli -regtest generatetoaddress 101 $M
PQ=$(bitcoin-cli -regtest -rpcwallet=pq getaddressesbylabel mldsa | jq -r 'keys[0]')   # bcrt1z... (created with the wallet)
PQ2=$(bitcoin-cli -regtest -rpcwallet=pq getnewmldsaaddress "second")                 # another bcrt1z..., fresh key
bitcoin-cli -regtest -rpcwallet=miner sendtoaddress $PQ 10; bitcoin-cli -regtest generatetoaddress 1 $M
bitcoin-cli -regtest -rpcwallet=pq sendtoaddress $M 5                                  # ML-DSA attestation spend
bitcoin-cli -regtest generatetoaddress 1 $M                                            # accepted into a block
```

Not done: `-addresstype` / `getnewaddress` for v2 (needs the dedicated
destination and `OutputType`; use `getnewmldsaaddress` instead), script-path `wpq(KEY,{TREE})`, PSBT fields,
encrypted key storage, HD derivation, and any of the canonical-encoding and
deployment-flag items below.

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
- [x] `SCRIPT_VERIFY_MLDSA_V2` flag plus buried `DEPLOYMENT_MLDSA_V2` in
      `consensus/params.h`, `deploymentinfo.cpp`, `kernel/chainparams.cpp`; the
      branch runs only when the flag is set; mempool strips it pre-activation.
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
- [~] `wpq(HEXPK)` key-path `DescriptorImpl` emitting `OP_2 <ComputeCommitment(param_id, pk_hash)>`.
      `wpq(KEY,{TREE})` script path not implemented.
- [x] `SigningProvider::GetMlDsaKey(pk_hash, key)` replaces the old global store
      lookup in `script/sign.cpp`.
- [x] Wallet DB record types for ML-DSA secrets, plaintext and encrypted via `crypter.cpp`.

### 6. Parser and signer: `script/sign.cpp`, `script/interpreter.cpp`
- [~] `ProduceSignature`: key path done (`CreateMlDsaAttestation`, witness `[attestation]`).
      Script path pending.
- [~] PSBT round-trip works for key-path inputs (create unsigned, sign elsewhere,
      finalise). `DataFromTransaction` extraction of an attestation is not implemented.
- [~] PSBT: proprietary `qcoin`/0 input field carrying the ML-DSA public key;
      finished attestations use `final_scriptwitness`. No partial form (none needed
      for the key path).
- [~] Regtest script `fork/test/regtest_v2_spend.sh` funds and spends a `wpq()`
      output (key path). Script path and a proper functional test pending.

### Exit criteria
A regtest wallet with `-walletsigscheme=mldsa44 -addresstype=bech32m-v2`
receives to a `bcrt1z` address and spends it in a block that the node accepts
with `QCOIN_ECDSA_FALLBACK=OFF` and commit 13d6b525 reverted.

## Remaining gaps (both options unless noted)

### Key material and storage
- [~] ML-DSA keys are wallet-DB records (`walletdescriptormldsakey` /
  `walletdescriptormldsackey`, per descriptor), encrypted with the wallet
  passphrase, held in memory in a secure-allocator type and wiped after signing.
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

# the key survives a restart: it is a record in wallet.dat
build/bin/bitcoin-cli -regtest stop && build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

# strict consensus routing (no ECDSA fallback)
cmake -B build -DQCOIN_ECDSA_FALLBACK=OFF && cmake --build build --target bitcoind
```
