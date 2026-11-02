# Wallet post-quantum (ML-DSA) integration: status and gaps

This document tracks the Qcoin (QTC placeholder) fork's path from secp256k1
ECDSA wallet signing to FIPS 204 ML-DSA. It is a working note, not a spec. The
normative design of the witness v2 output and its attestation is the "Segwit
v2: ML-DSA Post-Quantum Signatures" BIP draft in the clavote-boop/BIP
repository (`docs/spec/bip-mldsa-formal.md`). The BIP draft describes those
rules as a soft fork of Bitcoin; Qcoin adopts the output format but is a
separate coin with an additional rule, the value rule below, and the Qcoin
white paper (kept outside this repository, see "White paper") is the document
that states Qcoin's own rules.

The wallet is called the Entangled wallet (a nod to "spooky action at a distance"). Only this document uses the name so far;
RPC names, descriptors and help text are unchanged.

## Current status

Last refreshed with the script-path commit (31 Oct 2026). Everything below is exercised by
the shell tests in `fork/test/` on the default build unless marked otherwise.

| Piece | Location | State |
|---|---|---|
| Witness v2 output (Option B) | `fork/src/script/witness_v2.h`, `script/interpreter.cpp` (`VerifyWitnessProgram`) | **Working.** `OP_2 <Q>` with `Q = tagged_hash("MLDSAv2/Commit", param_id \|\| SHA256(pk))`. The spend's last witness element is the attestation `0x51 \|\| n \|\| param_id \|\| pk \|\| sig`; the interpreter checks the commitment and verifies the ML-DSA signature over `param_id \|\| pk_hash \|\| sighash` (BIP341 sighash, SIGHASH_DEFAULT) with context `BIP-MLDSAv2`. Param id `0x01` = ML-DSA-44 (3735-byte attestation). Signatures must be in FIPS 204 canonical hint encoding (`IsCanonicalMlDsaSignature`, checked before liboqs). Errors `SCRIPT_ERR_MLDSA_ATTESTATION` / `SCRIPT_ERR_MLDSA_SIG_ENCODING` / `SCRIPT_ERR_MLDSA_SIG`. Tests: `qcoin-v2-selftest`, `regtest_v2_canonical.sh`. |
| Script path (`OP_CHECKMLDSAVERIFY`) | `fork/src/script/witness_v2.h` (section 5 helpers), `script/interpreter.cpp` (`VerifyWitnessProgram`, `EvalScript` case `OP_NOP4`), `fork/test/v2_scriptpath_tool.cpp` | **Working in consensus; multi-party signing through PSBTs works ("Script-path PSBTs"), the wallet cannot yet create the output itself (no `wpq(KEY,{TREE})` descriptor).** Witness `<inputs...> <leaf script> <control block> <attestation>`. Control block `leaf_version \|\| param_id \|\| internal pk_hash \|\| node*m` (34-byte base, at most 8 nodes); `Q = tagged_hash("MLDSAv2/Commit", param_id \|\| pk_hash \|\| merkle_root)` with BIP 341 `TapLeaf`/`TapBranch` hashing. Leaf version `0xc0` runs with tapscript semantics and these changes: `OP_NOP4` (0xb3) is `OP_CHECKMLDSAVERIFY`, pops `<pk_hash:32> <i>`, requires `SHA256(pk_i) == pk_hash` and verifies entry *i* of the attestation over the BIP 342-style leaf sighash (`SigVersion::TAPSCRIPT`, so the leaf hash is committed); `OP_CHECKSIG`/`OP_CHECKSIGVERIFY`/`OP_CHECKSIGADD` and `OP_SUCCESSx` are invalid (`SCRIPT_ERR_BAD_OPCODE`); every attestation entry must be verified exactly once (`SCRIPT_ERR_MLDSA_ENTRY_UNUSED`, `SCRIPT_ERR_CHECKMLDSAVERIFY`). Unknown leaf versions stay upgradable as in BIP 341. The control-block layout and the exactly-once rule are this implementation's choices (the BIP's section 5 text was not available) and must be reconciled with the BIP before any public chain. `qcoin-v2-scriptpath` (both configurations, target not in the default build) derives keys from seeds, prints a 1-of-1 leaf output and signs a spend of it. Tests: `qcoin-v2-selftest` section 10, `regtest_v2_scriptpath.sh` (regtest; `CHAIN=qtctest` runs it on qtctest). |
| Value rule (ML-DSA-only) | `fork/src/consensus/pq_value.h`, `validation.cpp`, `Consensus::Params::fMlDsaOnlyValue` | **Working.** On regtest and `qtctest`, once mldsav2 is active every output with value must be `OP_2 <32>`; ordinary ECDSA outputs (P2PKH, P2WPKH, P2TR, bare multisig, ...) are consensus-invalid in blocks (coinbase included) and in the mempool (`bad-txns-output-not-mldsa`). Zero-value outputs are unrestricted (OP_RETURN, witness commitment). Wallet: `getnewaddress`/`getrawchangeaddress` refuse, recipients and custom change must be v2, change is derived as a fresh ML-DSA key, `-walletsigscheme` defaults to mldsa44 and `ecdsa` is rejected. Qcoin is therefore a separate coin, not a Bitcoin soft fork; the Bitcoin chain parameters still in the tree keep Bitcoin's rules. Test: `regtest_pq_only.sh`. |
| Activation | `Consensus::DEPLOYMENT_MLDSA_V2` ("mldsav2"), `SCRIPT_VERIFY_MLDSA_V2`, `validation.cpp` | **Working.** Buried deployment: height 0 on regtest (override `-testactivationheight=mldsav2@N`) and `qtctest`; never on mainnet/testnet/signet. Before activation v2 inputs are anyone-can-spend for blocks and rejected by the mempool (`mempool-script-verify-flag-failed`); after it the flag is enforced in blocks and policy, and `AreInputsStandard` accepts v2. Shown by `getdeploymentinfo`. Test: `regtest_v2_activation.sh`. |
| Legacy ECDSA path | `script/interpreter.cpp` (`VerifyECDSASignature`) | **Upstream again.** The first experiment (commit 13d6b525) routed every legacy ECDSA check through an ML-DSA-87 stub with a secp256k1 fallback; that routing, `fork/src/script/verify_stub.h` and the `QCOIN_ECDSA_FALLBACK` option are removed. Legacy inputs never touch liboqs. What makes Qcoin incompatible with Bitcoin is the value rule above, not the script rules. |
| ML-DSA primitives | `fork/src/pqc/pqc.{h,cpp}` (library `qcoin_pqc`) | **Working.** liboqs 0.14 wrappers: keygen (random and from a 32-byte seed via a temporary custom RNG under a mutex), sign/verify with context, HD master/child seed derivation, `SecureBytes` on Core's `secure_allocator`, `WipeSecret`. ML-DSA-44 and ML-DSA-87. |
| Wallet scheme switch | `-walletsigscheme=<ecdsa\|mldsa44\|mldsa87>` (`wallet/init.cpp`) | **Working.** Default `ecdsa` leaves the wallet upstream-identical. `mldsa44` makes wallet creation also generate an ML-DSA key and import a `wpq()` descriptor. `mldsa87` only in experimental builds (param id `0x7f`, non-BIP). |
| Addresses and descriptors | `script/descriptor.cpp` (`WpqDescriptor`), `wallet/rpc/addresses.cpp` | **Working.** `wpq(HEXPK)` emits `OP_2 <Q>`; `InferDescriptor` maps `OP_2 <Q>` back to `wpq()` (needed for fee estimation). RPCs `getnewmldsaaddress [label]`, `derivemldsaaddress <index>`, `getmldsahdinfo`. Addresses are bech32m witness version 2: `bcrt1z...` (regtest), `tq1z...` (qtctest), `bc1z...` (mainnet, never active). Destination type is still `WitnessUnknown{2,Q}` (no dedicated `OutputType`). |
| Spending | `script/sign.cpp` (`ProduceSignature` v2 branch, `CreateMlDsaAttestation`), `script/signingprovider.*` | **Working.** `sendtoaddress`/`send`/`fundrawtransaction`+`signrawtransactionwithwallet` from a v2 coin build the attestation, pass `VerifyScript`, are accepted by the mempool and confirm. Mixed ECDSA + v2 inputs sign correctly. Tests: `regtest_v2_spend.sh`, `regtest_v2_multi.sh`, `regtest_qtctest.sh`. |
| Key storage | `wallet/walletdb.cpp`, `DescriptorScriptPubKeyMan::m_map_mldsa_keys` | **Working.** One `walletdescriptormldsakey` record per key, wallet-scoped, included in `backupwallet`. Details below. |
| Encryption | `walletdescriptormldsackey` records, `wallet/scriptpubkeyman.cpp` | **Working.** AES-256-CBC under the wallet master key, IV = SHA256(pk), like secp256k1 descriptor keys; `encryptwallet` converts and erases plaintext records; locked wallets cannot sign v2 inputs. Test: `regtest_v2_encrypt.sh`. |
| HD derivation | `walletdescriptormldsahd` record, `CWallet::DeriveMlDsaDestination` | **Working.** `master = HMAC-SHA512("Qcoin/MLDSAv2/master", root key)[0:32]`, `seed_i = HMAC-SHA512(master, "MLDSAv2/child" \|\| i)[0:32]`, deterministic keygen from the seed. Same wallet seed reproduces the same `tq1z`/`bcrt1z` addresses. Test: `regtest_v2_hd.sh`. |
| PSBT | `psbt.cpp` | **Working.** Proprietary input field (identifier `qcoin`, subtype 0) carries `param_id \|\| pk`; the attestation goes in `final_scriptwitness`. `walletprocesspsbt` signs v2 inputs; non-key-holding wallets pass the PSBT through unchanged. Test: `regtest_v2_psbt.sh`. |
| `qtctest` chain | `src/kernel/chainparams.cpp` (`CQtcTestParams`), `chainparamsbase.cpp` | **Live (single operator).** `-chain=qtctest`, P2P 28333, RPC 28332, HRP `tq`, genesis `0090e8f80f8d0caecfde17644580d7bd83ef14f243c2f5a26e0d54996c09f11b` at nBits 2000ffff, **RandomX proof of work from genesis** (about 6 s per block on one CPU in light mode, one block per `generatetoaddress` call with `maxtries` 2000000000), mldsav2 active from genesis. No seeds, checkpoints or assumevalid yet; peers use `addnode=`. Example config `fork/contrib/qtctest.conf`. Tests: `regtest_qtctest.sh`, `regtest_qtctest_twonode.sh`, `regtest_randomx.sh`. |
| Explorer | `fork/tools/qtc-explorer.py` | **Working.** Stdlib-only HTTP status page: chain summary, deployment state, recent blocks, block/tx/address pages, mempool. Test: `regtest_qtctest_explorer.sh`. |
| Faucet | `fork/tools/qtc-faucet.py` | **Working.** `fund` (mines to the faucet wallet), `send`, `serve` (HTTP form, pays `tq1z...` addresses only by default, per-address cooldown and per-IP limit via `X-Forwarded-For`, state in `faucet-state.json`). Test: `regtest_qtctest_faucet.sh`. |
| Genesis helper | `fork/tools/mine-genesis.py` | **Working.** Deterministic multi-process genesis miner; prints the C++ lines to paste. Test: `test_mine_genesis.sh`. |
| Launch docs | this file: "Public launch", "Testnet launch", "Raising the proof-of-work difficulty" | Runbook for seed node, second node, explorer, faucet and seed publishing. Hostnames are placeholders until a public host exists. |
| Network measurements | `fork/results/2026-11-01-qtctest-3node/` | **Measured once.** Three Vast.ai nodes on `qtctest` at 27ff8a7: peer-to-peer sends, a script-path spend, three double-spend rounds (including a partition and a 1.5 s reorg) and a 50-transaction burst all behaved correctly. Transactions relay in about 3.5 to 5 s (Bitcoin Core's announcement batching), blocks in under 0.3 s, and a one-input spend is about 1 kvB. A stress run followed (bursts up to 900 spends in one 3.7 MWU block, three concurrent senders, 20 tx/s sustained for 60 s) with no rejected transaction; block validation was not a bottleneck, though a wallet receiving a large burst slowed its node's block connection. One run per row, minimal difficulty, manual mining; `RESULTS.md` there lists the caveats, including a clock-correction bug in the first runs. |
| Experimental build | `-DQCOIN_WITNESS_V2_EXPERIMENTAL=ON` | Adds ML-DSA-87 (param id `0x7f`) and the `qcoin-v2-selftest` binary. Nothing in the default build depends on it. |

With `-walletsigscheme=ecdsa` (the default) the wallet, address types and
signing are unchanged from upstream, so existing wallet and functional test
flows keep working. Consensus differs from upstream only where `mldsav2` is
active (regtest and `qtctest`).

### What a v2 spend looks like

Receiving: `getnewmldsaaddress` returns `tq1z...`; the output script is
`OP_2 <32-byte Q>`. Spending: the wallet finds the ML-DSA key by `SHA256(pk)`,
signs `param_id || pk_hash || sighash` and places the 3735-byte attestation as
the single witness element. With the witness discount a v2 input weighs about
1 kvB (3.7 kB of witness data plus the 41-byte input); fees are estimated from
`wpq()`'s `MaxSatisfactionWeight`. What does not work yet is
listed under "Testnet readiness" and "Remaining gaps".

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

## Value rule: Qcoin is a separate coin

Since commit `9f7b45d` the script rules alone would have made witness v2 a soft
fork over Bitcoin. That is no longer the goal: Qcoin is its own post-quantum
coin, and ordinary ECDSA outputs must not be able to hold value. The rule
(`fork/src/consensus/pq_value.h`):

- On chains with `Consensus::Params::fMlDsaOnlyValue` (regtest, `qtctest`, and
  any future Qcoin mainnet), once `mldsav2` is active, **every output with
  `nValue > 0` must be a witness v2 program** `OP_2 <32 bytes>`. This applies to
  coinbase outputs too, so mining rewards go to `tq1z`/`bcrt1z` addresses.
- Zero-value outputs are unrestricted, so OP_RETURN data and the segwit witness
  commitment keep working. Inputs are unrestricted; after activation the only
  ECDSA coins that can exist are zero-value ones or coins created before
  activation (regtest with `-testactivationheight`).
- Enforcement: `ContextualCheckBlock` (blocks) and `MemPoolAccept::PreChecks`
  (mempool) both fail with `bad-txns-output-not-mldsa`. The mempool check runs
  before standardness, so such a transaction is consensus-invalid, which
  subsumes being non-standard.
- Wallet: `getnewaddress` and `getrawchangeaddress` refuse with a pointer to
  `getnewmldsaaddress`; `CreateTransaction` (sendtoaddress, send, sendmany,
  fundrawtransaction, walletcreatefundedpsbt) refuses any recipient or custom
  change address that is not v2 with "Ordinary (ECDSA) outputs cannot carry
  value on this chain"; change is derived as a fresh HD ML-DSA key stored under
  the label `change`; `-walletsigscheme` defaults to `mldsa44` on these chains
  and `-walletsigscheme=ecdsa` is an init error.
- The Bitcoin chain parameters kept in the tree (mainnet, testnet, signet) have
  `fMlDsaOnlyValue = false` and `mldsav2` never active, so the binary still
  validates those chains with Bitcoin's rules.
- This is a hard fork of the existing `qtctest` chain: blocks whose coinbase
  paid `tq1q` are now invalid, so every `qtctest` data directory must be wiped.
  The genesis block is unchanged (it is never run through `ContextualCheckBlock`
  and its output is unspendable).

Gaps: change keys are created even when no change is needed and are not reused
(one 3.9 KB record per transaction); `sendall` bypasses `CreateTransaction` and
only fails at the mempool; a dedicated standardness reason is not emitted
because the consensus check fires first. Test: `fork/test/regtest_pq_only.sh`;
`regtest_v2_activation.sh` shows the rule switching on with the deployment.

### White paper

The Qcoin white paper is not part of this repository (no `docs/Qcoin-Whitepaper.md`
or similar exists here; as of commit d8afb83 it lives with the BIP draft in the
clavote-boop/BIP repository). It must be updated to match the code, and the
statements it needs are these:

- Qcoin is a separate post-quantum coin, not a soft fork of Bitcoin. Its chains
  (`qtctest` now, a Qcoin mainnet later) share Bitcoin Core's code base but not
  Bitcoin's ledger, consensus rules or coins.
- **Witness version 2 ML-DSA outputs (`OP_2 <32-byte commitment>`, addresses
  `tq1z…`/`bc1z…`) are the only monetary output type.** Every output with a
  non-zero value, mining rewards included, must be one. Keys are ML-DSA-44
  (FIPS 204); signatures are carried in the attestation defined by the BIP
  draft and must be canonically encoded.
- Ordinary ECDSA outputs (pay-to-pubkey-hash, pay-to-script-hash, P2WPKH,
  P2WSH, Taproot, bare multisig, pay-to-anchor) cannot carry value. A block or
  transaction containing one with a non-zero value is invalid
  (`bad-txns-output-not-mldsa`), and the reference wallet refuses to create
  one. Zero-value outputs (OP_RETURN data, the witness commitment) are
  permitted.
- The rule is enforced from the first block after genesis on every Qcoin
  chain (`Consensus::Params::fMlDsaOnlyValue`, see above), so there has never
  been an ECDSA coin on a Qcoin chain and no migration period exists.

Any sentence in the white paper that calls Qcoin a soft fork, promises
compatibility with Bitcoin addresses or wallets, or describes ECDSA outputs as
spendable for value is out of date and should be replaced by the above.

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

## RandomX proof of work

From `Consensus::Params::RandomXHeight` on, a block is proven with RandomX instead of double SHA-256. The
80-byte header layout and the 32-bit nonce are unchanged, and so are the target comparison and the difficulty
adjustment (`nBits`, retargeting, minimum-difficulty rules); only the hash function that is compared to the
target changes. The block identifier (the hash used in `getblockhash`, `prevhash`, `txindex` and the P2P
inventory) stays the double SHA-256 of the header, so everything that refers to blocks is unaffected and a
block hash no longer shows how much work it carries; mining tools replace the SHA-256d proof-of-work hash by
RandomX and keep computing the block id with SHA-256d.

| Parameter | Value |
|---|---|
| Library | RandomX v1.2.1 (tevador/RandomX, commit `102f8acf`), BSD-3-Clause, vendored unmodified in `fork/src/crypto/randomx` (`VENDORED.txt`) |
| RandomX configuration | upstream defaults (2 MiB scratchpad, 256 MiB Argon2 cache, 2 GiB dataset, 8 programs of 2048 iterations) |
| Key | **rotates every 2,048 blocks** (Monero's interval): the key of a block at height *h* is the identifier (double SHA-256 block hash, the 32 raw bytes in internal byte order) of the block at key height `RandomXKeyHeight(h)`; see "Key rotation" below |
| Input | the 80 serialized header bytes, nonce included |
| Output to target | the 32-byte RandomX hash read as a little-endian 256-bit integer (the same convention as a SHA-256d block hash), compared to the `nBits` target |
| Activation | buried deployment `randomx` (`Consensus::DEPLOYMENT_RANDOMX`, shown by `getdeploymentinfo`): height **0 on regtest and `qtctest`**, never (`INT_MAX`) on mainnet, testnet, testnet4 and signet, so the Bitcoin chains are unaffected. Regtest override: `-testactivationheight=randomx@<n>` |
| Below the height | double SHA-256 (the block hash), as before |
| At and above the height | RandomX is the only accepted proof of work; a header that meets the target only under SHA-256d is rejected with `high-hash` |
| Genesis | exempt once the height is 0 (its hash is fixed by an assertion in the chain parameters) |
| Verification | light mode by default (full-dataset mode with `-randomxfull`, see below): a 256 MiB cache per key, built on first use (about a second) and kept for the two most recently used keys, one virtual machine per thread, JIT and hardware AES when the CPU has them (the hash is identical either way). Chains that never reach RandomX allocate nothing |
| Cost | about 20 ms per hash in light mode on one thread here (about 256 hashes per qtctest block, 118 s for 20 blocks). `AcceptBlockHeader` and the headers anti-DoS pre-check stop at the first invalid header, so an invalid header costs one hash. A RandomX proof is not recomputed when the block index is loaded or a block is read from disk (the SHA-256d check still is, below the height) |

Where the check happens: `CheckBlockHeaderPoW` (`src/pow.cpp`, given a key lookup) at `AcceptBlockHeader` with height `parent + 1`
(the context-free `CheckBlock` check is skipped on chains where RandomX can activate), at the headers
pre-check in `net_processing` (height and key from the first header's parent; if the parent is unknown, see
"Key rotation"), in headers presync (`HeadersSyncState`), and in `generatetoaddress` /
`generateblock` (`GenerateBlock`, light mode, single thread). `getblocktemplate` reports `"powalgo":
"randomx"` or `"sha256d"` for the template's height.

### Key rotation

Consensus parameters `nRandomXKeyEpoch` = 2048 (a power of two) and `nRandomXKeyLag` = 64, the same for every chain.
For a block at height *h*:

```
key_height(h) = 0                                   if h <= 2048 + 64
              = (h - 64 - 1) & ~(2048 - 1)           otherwise      (round down to a multiple of 2048)
key(h)        = block identifier at key_height(h) on the chain being extended, 32 raw bytes in internal order
```

So blocks 1-2112 use the genesis block's identifier, blocks 2113-4160 use the identifier of block 2048, blocks
4161-6208 that of block 4096, and so on. The 64-block lag buries a key block before it is used, so a short reorg at an
epoch start does not change the key of the next epoch; a reorg deeper than the lag switches to the other chain's key
block, as the chain it belongs to requires. A different genesis gives a different key, so chains never share one.
The key is a function of the chain, not of the header, so every check has to be given the chain:
- `AcceptBlockHeader` resolves the key block through the parent (`CBlockIndex::GetAncestor`).
- The headers pre-check in `net_processing` takes the key block from the first header's parent or, when the key
  height lies inside the batch, from the batch itself. If the first parent is unknown only the `nBits` range is
  checked (SHA-256d heights are still fully checked).
- Headers presync (`HeadersSyncState`) holds chains that are not in the block index, so it verifies each RandomX
  proof itself and records the identifier of every header at a multiple of 2048 (one entry per 2048 headers) as the
  key block of later headers; key blocks before the sync's start come from the last known header.
- `generatetoaddress` / `generateblock` resolve the key once per block; `getblocktemplate` returns it as
  `randomxkey` (hex, the raw bytes to pass to the scanner) and `randomxkeyheight` next to `"powalgo": "randomx"`.
- The node keeps the caches of the two most recently used keys (2 x 256 MiB), so the epoch boundary and a
  reorg across it do not rebuild a cache each time; an evicted cache is freed once its last user finishes.
- `fork/test/regtest_randomx_epoch.sh` mines across the first boundary (heights 2111-2133): the template key changes
  from the genesis block to block 2048, a header valid only under the old key is rejected at height 2113, blocks
  and an ML-DSA spend confirm on the new key, restart and `-reindex` cross the boundary, and a second node with
  `-minimumchainwork` set so that its presync spans the boundary syncs.

### Full-dataset mode

Light mode (the default) verifies with a 256 MiB cache per key, about 20 ms per hash on one thread. The optional
full-dataset mode adds a 2 GiB dataset per key and hashes with it, about three times faster per hash on the 16-thread test machine (1,295 against 383 hashes/s)
(it speeds up initial block download and `generatetoaddress`); the hash is identical in both modes, so the modes can
be mixed across nodes, and the consensus rules, the 2,048-block epoch and the key derivation are unchanged.

| | Light (default) | Full (`-randomxfull`) |
|---|---|---|
| Memory per key | 256 MiB cache | 256 MiB cache + 2 GiB dataset (about 2.3 GiB) |
| Keys cached | 2 (current and previous epoch) | 3 (previous, current and the next epoch, pre-built) |
| Peak memory for the node | about 0.5 GiB (two caches) | **about 6.9 GiB** (three datasets of 2 GiB plus three 256 MiB caches; measured peak resident size 7,100 MiB with three datasets built, checked by `regtest_randomx_full.sh`; 4.6 GiB while only two keys exist, i.e. until the second key block, height 4096) |
| Start-up cost | cache built on first use, about a second | the same, then the dataset is built in the background (about 50 s with 16 threads) |
| Speed (`qtc-randomx-scan`, 16 threads) | about 48 hashes/s per thread, 383/s in total | 1,295/s in total once the dataset is ready |

Enable it with `-randomxfull=1` (or `randomxfull=1` in `bitcoin.conf`, in the `[qtctest]` or `[regtest]` section for
those chains). A dataset is built by a background thread pool (all cores, about 50 s with 16 threads) the first time a key
is used; **until it is ready the node hashes with the cache, so a new epoch never stalls validation**. At an epoch
boundary nothing has to be built: **the next epoch's dataset is pre-built.** The key block of an epoch (a multiple of
2,048) is known 65 blocks before the first block that uses its key (`nRandomXKeyLag` = 64), and when it becomes the tip
the node starts building that key's cache (about a second, on a helper thread) and dataset (about 50 s with 16 threads, in
the background), long before the epoch's first block arrives (65 blocks, about 11 hours at 10 minutes per block). So the
node holds three keys in full mode: the previous epoch (kept for reorgs), the current one, and the next one being
prepared; the least recently used key is evicted when a fourth is added, and it releases its memory when its last user
finishes (an unfinished dataset build is stopped). The pre-build runs from `Chainstate::UpdateTip` (`PrebuildRandomXKey`),
so it also happens after a restart that finds the tip inside the 65-block window; during initial block download, header
verification runs ahead of the tip and may need a key before it is prepared, in which case it hashes with the cache until
the dataset is ready. Light mode never pre-builds and keeps two keys.
If the dataset cannot be allocated the key simply stays in light mode.

Checking the mode and the memory: the log prints one line at start-up. Light: `RandomX: light-mode verification (a 256
MiB cache per key, two keys cached: about 0.5 GiB of memory)`. Full: `RandomX: full-dataset verification (...)` with the peak
by chain height: about 2.3 GiB with one key (below block 2048), 4.6 GiB with two keys (from block 2048, when the next key
is pre-built) and 6.9 GiB with three keys (from block 4096). These are peak resident sizes as measured by
`regtest_randomx_full.sh` (2,304 MiB per key of cache and dataset, plus the node's working set of about 140 to 190 MiB;
measured 4,750 MiB with two datasets and 7,100 MiB with three). `getblockchaininfo` has a `randomx` object: `mode`
(`light` or `full`), `active` (whether the next block is proven with RandomX), `keys_cached` (at most 2 in light mode, 3 in
full mode), `datasets_ready` and `datasets_building` (full mode), `estimated_memory_mib` (256 MiB per cached key plus 2,048
MiB per allocated dataset, ready or building: 512 in light mode, 2,304 / 4,608 / 6,912 in full mode with one / two / three
keys; add the working set for the resident size) and the counters `hashes_light` / `hashes_full` (hashes computed with a
cache / a dataset since the node started). An earlier log line and help text said "about 4.5 GiB with two keys"; that was
true only for two keys and is corrected.

Mining tools: `generatetoaddress` and `generateblock` use the node's mode (the node hashes with the dataset once it is
ready). `qtc-randomx-scan` has its own switch, `QTC_RX_FULL=1` (or `QTC_RX_FAST=1`; the dataset is built for the key in
`QTC_RX_KEY`, about 2.3 GiB and about 50 s to start with 16 threads), and `qtc-gbt-miner.py --randomxfull` (alias `--fast`) sets it.
`fork/test/regtest_randomx_full.sh` runs with `-randomxfull=1` across two key blocks (heights 2048 and 4096): the mode
reporting; the next key's dataset built at height 2048 and still ready, with nothing building, when the boundary (height
2113) is reached; the first new-key block hashed with it; an ML-DSA spend after the rotation; a full-mode scanner check;
three cached datasets and the peak memory after block 4096; and a light-mode node that re-validates the same chain.

Known limits of this design, to settle before a public launch:
- the key rotation protects against a dataset that is built once and reused, but a miner can still prepare the
  next epoch's dataset in advance (the key block is known 64 blocks before it is used, as in Monero).
- a header whose parent is unknown is only range-checked during the pre-check; the real proof is checked when
  its chain is accepted (or, for a presync chain, as it is processed).
- the full-dataset mode (see "Full-dataset mode") is optional and off by default.
- the upstream unit and functional tests mine regtest blocks with SHA-256d and no longer work on regtest
  (this project uses the shell regtests in `fork/test`).
- the proof of a block is not re-checked when it is read back from disk or the index is loaded.

### How to mine on qtctest

Build the node and the scanner: `cmake --build build --target bitcoind bitcoin-cli qtc-randomx-scan`.

1. The node's own CPU miner (one block per call, about 6 s each; light mode, one thread; measured 20 blocks in 118 s;
   start the node with `-randomxfull=1` for the dataset, see "Full-dataset mode"):
   ```bash
   bitcoind -chain=qtctest -daemon
   bitcoin-cli -chain=qtctest createwallet miner
   M=$(bitcoin-cli -chain=qtctest -rpcwallet=miner getnewmldsaaddress mine)
   for i in $(seq 1 10); do bitcoin-cli -chain=qtctest generatetoaddress 1 "$M" 2000000000 >/dev/null; done
   bitcoin-cli -chain=qtctest getblockchaininfo | grep -E '"(blocks|difficulty)"'
   bitcoin-cli -chain=qtctest getdeploymentinfo | grep -A3 '"randomx"'   # buried, active, height 0
   ```
2. A multi-threaded external miner over `getblocktemplate` (`fork/tools/qtc-gbt-miner.py` uses
   `qtc-randomx-scan` automatically when the template says `"powalgo": "randomx"`):
   ```bash
   python3 fork/tools/qtc-gbt-miner.py --address "$M" --chain qtctest --procs 8 --blocks 20
   python3 fork/tools/qtc-gbt-miner.py --address "$M" --chain qtctest --procs 16 --randomxfull --blocks 200   # 2 GiB dataset
   ```
   `qtc-randomx-scan HEADER76_HEX TARGET64_HEX START STRIDE [MAXCOUNT]` is the building block for other miners:
   same arguments as `qtc-nonce-scan`, RandomX instead of SHA-256d, keyed with the template's `randomxkey` in the
   environment (`QTC_RX_KEY`, required; also `QTC_RX_THREADS`, `QTC_RX_FULL=1`);
   `qtc-randomx-scan --selftest` checks the RandomX known-answer vector.
3. Regtest and the activation height: `fork/test/regtest_randomx.sh` mines under RandomX, checks a mined nonce
   with the independent scanner, confirms an ML-DSA spend, and with `-testactivationheight=randomx@10` shows
   SHA-256d blocks 1 to 9, RandomX from 10, the rejection of a SHA-256d-only header at height 10, and a
   restart and `-reindex` across the transition.

## Dust and block weight policy

A witness v2 key-path spend carries a 3735-byte attestation (3 header bytes, the 1312-byte ML-DSA-44
public key and the 2420-byte signature), 3739 witness bytes with the item count and length. One input
therefore costs 3903 WU (976 vB), and a typical one-input, two-output payment is 1073 vB (measured by
`regtest_v2_policy.sh`).

| Setting | Bitcoin chains in the tree | Qcoin chains (regtest, `qtctest`) | Where |
|---|---|---|---|
| Block weight limit | 4,000,000 WU | **8,000,000 WU** | `Consensus::Params::nMaxBlockWeight`, set in `kernel/chainparams.cpp`; checked in `CheckBlock` and `ContextualCheckBlock` |
| Blocks of v2 spends | about 950 | about 1,900 (the test mines and connects a 4.53 MWU block of 1,101 transactions) | |
| Dust threshold, v2 output | 294 sat (P2WPKH formula) | **3,054 sat** at 3,000 sat/kvB: (43-byte output + 41-byte input + 934 witness vB) x 3 sat/B | `GetDustThreshold`, `MLDSA_V2_SPEND_WITNESS_BYTES` in `policy/policy.h` |
| Sigop cost of a v2 spend | n/a | **0, unchanged** | `CountWitnessSigOps` only counts witness v0 |
| Max standard transaction | 400,000 WU | 400,000 WU (about 100 key-path inputs) | `MAX_STANDARD_TX_WEIGHT`, unchanged |
| P2P message limit | 4,000,000 B | 8,000,000 B on every chain (a full block is up to 8,000,000 bytes) | `MAX_PROTOCOL_MESSAGE_LENGTH` |

Reasons for the numbers:

- **Weight.** The attestation is witness data and already gets the 75% discount, yet a transaction is
  still about 4.2 kWU, so a 4 MWU block holds only about 950 payments. 8 MWU holds about 1,900. This is
  a consensus rule of the Qcoin chains only: every block-level check reads the limit from the chain
  parameters, so the Bitcoin chains keep 4 MWU. Static sanity bounds with no chain parameters at hand
  (coin-cache estimate, merkle block and compact block transaction counts, `bad-txns-oversize`) use
  `MAX_BLOCK_WEIGHT_CEILING` (8 MWU); on a Bitcoin chain the block weight check still rejects anything
  above 4 MWU. `getblocktemplate` reports the chain's `weightlimit`, the block assembler defaults to it,
  and `-blockmaxweight` above the chain limit is refused.
- **Dust.** An output is only worth relaying if spending it costs less than it holds. A v2 output needs
  about 976 vB to spend, roughly fourteen times a P2WPKH output, so the P2WPKH threshold (294 sat) would
  let through outputs that cost more to spend than they hold. Outputs below 3,054 sat at the default dust
  relay fee are non-standard (`dust`). This is relay policy, not consensus.
- **Sigops.** Not changed, on purpose. Verifying one ML-DSA-44 signature takes about as long as one
  ECDSA verification (`fork/results/2026-11-01-qtctest-3node/bench/microbench.txt`), and every
  verification needs a 3.7 kB signature in the block, so weight already limits verifications to about
  2,000 per 8 MWU block against the 80,000 sigop cost limit. A sigop charge per v2 input would never
  bind. Script-path spends are limited the same way (one signature per attestation entry, at most four
  entries) plus the tapscript validation weight budget.
- **Standard transaction size.** 400,000 WU allows about 100 key-path inputs, so consolidating coins is
  limited to roughly 100 inputs per transaction. Left unchanged.

Not covered: `-blockmaxweight` help text and fee estimation (`policy/fees/mempool_estimator.cpp`) still
assume 4 MWU blocks, so fee estimates on a Qcoin chain assume half the real capacity (conservative).
The Qt GUI network style is not wired for `qtctest`. The block-weight test runs on regtest because
`qtctest` needs real proof of work for every block; both chains get the same limit.
Test: `fork/test/regtest_v2_policy.sh`.

## Coin selection with ML-DSA inputs

Observation from the two-node RandomX test (regtest, 2,400 blocks mined to one wallet): a `sendtoaddress` of 1.0 produced
a 40,060 vB transaction, 41 inputs and no change, where the same payment normally takes one input and 1,073 vB. It is
not a bug in the wallet or in the ML-DSA input size; it is upstream's coin selection doing what it is designed to do, made
expensive by the size of an ML-DSA input (about 976 vB, fourteen times a P2WPKH input). Reproduced locally with the same
numbers (41 inputs, 40,060 vB, fee 0.00403 BTC at 10 sat/vB):

- **Many small coins.** The regtest halving interval is 150 blocks, so of the 2,300 mature coinbase outputs only 299 are
  25 coins or more, 600 are 1 to 25, 1,050 are 0.01 to 1 and 351 are below 0.01 (median 0.39).
- **Consolidation.** The wallet's `-consolidatefeerate` (default 10 sat/vB, `DEFAULT_CONSOLIDATE_FEERATE`) is "the maximum
  feerate at which transaction building may use more inputs than strictly necessary so that the wallet's UTXO pool can be
  reduced". The regtest fallback fee is exactly 10 sat/vB, so the wallet treats every send as a chance to consolidate and,
  by its waste metric, prefers a changeless selection of many coins to one coin plus change. The selection log
  (`-debug=selectcoins`) shows the Knapsack "best subset" of small coins winning.
- **Confirmation.** With `-consolidatefeerate=0.00001` (1 sat/vB) the same wallet and chain send with 1 input, 2 outputs,
  1,073 vB (also with a 20 sat/vB fallback fee). The fee paid was the real size times the rate in every case, so the size
  estimate for v2 inputs is right.

Consequences: on a real chain at a feerate above `-consolidatefeerate` the wallet behaves normally. At or below 10 sat/vB
(regtest, qtctest, quiet periods) it can spend dozens of ML-DSA inputs in one payment, each costing about 10,000 sat at
10 sat/vB, and transactions beyond about 100 inputs (`MAX_STANDARD_TX_WEIGHT`) are not relayed. The default is tuned for
68 vB inputs, so for Qcoin it should be set lower (roughly 1 sat/vB, or scaled with the 14x input size) before a public
launch; nothing was changed here, because this is not a defect. Users can lower it today with `-consolidatefeerate`.

## Running multi-node tests on rented instances

Notes from the Vast.ai two-node RandomX test, for the next one:

- **The "qcoin-qtctest-p2p" template builds the repository itself.** Its start-up script runs `apt-get install`, installs
  liboqs from apt or from source (not necessarily 0.14.0), clones the whole `experimental-pqc` history to `/root/qcoin` and builds with `-j$(nproc)`.
  `nproc` shows the host's cores (80 on one machine) although the container has 10, so the build is slow and can run out
  of memory, its liboqs may differ from the 0.14.0 the fork is built against, and it competes with your own build (a
  script that waits for it to finish waited five minutes and more). Kill its top-level shell and its clone before
  starting your own build: `pkill -f "[e]xec > /root/setup.log"; pkill -f "[g]it clone -b experimental-pqc"` (the
  square brackets keep `pkill` from matching the ssh command that runs it). A build of `bitcoind` and `bitcoin-cli`
  from a `--depth 1` clone with liboqs 0.14.0 then takes about 2 minutes on 10 cores and 2 minutes on 18.
- **Ports.** Only the ports in the template are reachable from outside (28333 is mapped; read the external port from
  `/proc/1/environ`, `VAST_TCP_PORT_28333`). A node with `-listen=1` also binds its P2P port + 1 for onion inbound, so
  keep other services (the RPC port of a second node on the same host) off it.
- **Cost.** Read the price breakdown (hover the price) before renting: the internet rate varies by host (from $1.33/TB to
  $4/TB here, against $40/TB on the host that overcharged earlier). Two instances for 25 minutes cost $0.06.
- **Clean up.** Stop the nodes, copy the logs, then destroy the instances; check the billing page afterwards.

## Public launch

Exact commands for the first public `qtctest` deployment: one seed node, a
second node connecting to it, and the explorer and faucet on the seed.
`fork/contrib/qtctest.conf` is the example configuration used below (ports
28333/28332, `txindex=1`, `walletsigscheme=mldsa44`, RPC on localhost only).
`fork/test/regtest_qtctest_twonode.sh` runs this topology on one machine over
loopback (no firewall, DNS or seed involved).

### Seed node (machine A, public IP or DNS name `seed1.example.net`)

```bash
# 0. build (see "Build") and install liboqs 0.14.0; a fresh data directory (new genesis = new network)
mkdir -p ~/.bitcoin && cp fork/contrib/qtctest.conf ~/.bitcoin/bitcoin.conf
# edit ~/.bitcoin/bitcoin.conf: keep listen=1; remove the addnode= lines on the first seed

# 1. firewall: allow inbound 28333/tcp (P2P). Do NOT open 28332 (RPC).
sudo ufw allow 28333/tcp          # or the equivalent for your firewall

# 2. start
bitcoind -daemon
bitcoin-cli -chain=qtctest getblockchaininfo          # "chain": "qtctest", height 0
bitcoin-cli -chain=qtctest getnetworkinfo | grep -A1 '"localaddresses"'   # should list the public address

# 3. produce the first blocks (RandomX; one block per call, about 6 s each at 2000ffff)
bitcoin-cli -chain=qtctest createwallet faucet
M=$(bitcoin-cli -chain=qtctest -rpcwallet=faucet getnewmldsaaddress mine)   # tq1z: only ML-DSA outputs may hold value
for i in $(seq 1 110); do bitcoin-cli -chain=qtctest generatetoaddress 1 "$M" 2000000000 > /dev/null; done
```

### Second node (machine B)

```bash
cp fork/contrib/qtctest.conf ~/.bitcoin/bitcoin.conf
# edit: addnode=seed1.example.net:28333 (uncomment, set the real host); listen=0 is fine behind NAT
bitcoind -daemon
bitcoin-cli -chain=qtctest getconnectioncount          # 1 once the handshake completes
bitcoin-cli -chain=qtctest getblockchaininfo           # height/bestblockhash equal to the seed's
bitcoin-cli -chain=qtctest getdeploymentinfo           # mldsav2 active
bitcoin-cli -chain=qtctest createwallet w
bitcoin-cli -chain=qtctest -rpcwallet=w getnewmldsaaddress     # tq1z... to paste into the faucet
```

If the second node stays at 0 connections: check the seed's firewall, that both
nodes print the same genesis (`getblockhash 0` =
`0090e8f80f8d0caecfde17644580d7bd83ef14f243c2f5a26e0d54996c09f11b`), and that
neither data directory predates the current genesis.

### Explorer and faucet (on the seed)

```bash
# explorer on 127.0.0.1:8080, faucet on 127.0.0.1:8081; both read the RPC cookie
nohup python3 fork/tools/qtc-explorer.py --chain qtctest --bind 127.0.0.1 --port 8080 > explorer.log 2>&1 &
nohup python3 fork/tools/qtc-faucet.py serve --chain qtctest --wallet faucet --amount 1.0 \
      --cooldown 86400 --max-per-ip 5 --bind 127.0.0.1 --port 8081 > faucet.log 2>&1 &
```

Expose them only through a reverse proxy that terminates TLS and sets
`X-Forwarded-For` (the faucet rate-limits on it), for example nginx locations
`/` -> `http://127.0.0.1:8080` and `/faucet/` -> `http://127.0.0.1:8081/`. Keep
the faucet wallet funded from mining while the chain is small.

### Publishing a real seed node

Until a seed is published, every node needs an `addnode=` line. To turn machine A
into a seed that new nodes find on their own:

1. **Give it a stable address.** A static public IPv4 (and IPv6 if available)
   and a DNS A/AAAA record, for example `seed1.example.net`. Start the node
   with that address so it advertises it to peers:
   `externalip=seed1.example.net` (or the IP) in the `[qtctest]` section, or
   `-externalip=...` on the command line. Keep `listen=1`.
2. **Open the port.** Allow inbound TCP 28333 in the host firewall
   (`sudo ufw allow 28333/tcp`) and in any cloud security group or router NAT
   rule. Leave 28332 (RPC) closed. Check from another machine:
   `nc -vz seed1.example.net 28333`, then
   `bitcoin-cli -chain=qtctest addnode seed1.example.net:28333 onetry` and
   `getpeerinfo` on that machine must show the seed.
3. **Update the example config.** Replace the placeholder lines in
   `fork/contrib/qtctest.conf` with the real host, one `addnode=` per seed:
   ```
   addnode=seed1.example.net:28333
   ```
   and change the `seed1.example.net` placeholders in this section. Any node
   started from the updated file connects without further setup.
4. **Compile the seed in** so nodes find it with an empty config. In
   `CQtcTestParams` (`src/kernel/chainparams.cpp`) replace
   ```cpp
   vFixedSeeds.clear(); // TODO(launch): add seed nodes before announcing the network
   vSeeds.clear();
   ```
   with
   ```cpp
   vSeeds.emplace_back("seed1.example.net."); // DNS seed: every A/AAAA record is a peer
   vFixedSeeds.clear();
   ```
   A plain A record is enough: Core resolves the name and adds all returned
   addresses, so a second seed is just a second record (or a second
   `emplace_back`). Fixed seeds are optional and need the same pipeline as
   upstream: list `host:port` entries in `contrib/seeds/nodes_qtctest.txt`,
   run `contrib/seeds/generate-seeds.py` to emit a
   `chainparams_seed_qtctest[]` array into `src/chainparamsseeds.h`, and set
   `vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_qtctest), std::end(chainparams_seed_qtctest));`.
   Rebuild and re-run `fork/test/regtest_qtctest.sh` and
   `regtest_qtctest_twonode.sh`. The two-node test passes `-dnsseed=0` and is
   unaffected; the single-node tests (`-listen=0`, no `addnode=`) will start
   querying the DNS seed and may make outbound connections once one exists, so
   add `-dnsseed=0` to their `bitcoind` lines at that point to keep them
   hermetic.
5. **Test from a fresh machine.** Install the new binary, start `bitcoind
   -chain=qtctest` with no config, and confirm `getconnectioncount` reaches 1
   and `getblockchaininfo` matches the seed. Run at least two seeds on
   different hosts before announcing.

### Before announcing

- Publish at least two seeds as described above (`vSeeds` set, example config
  and this runbook updated with the real hostnames).
- Publish: the git commit, the genesis hash, the P2P port, the seed names, the
  explorer and faucet URLs, and the note that test coins have no value.
- Re-run `fork/test/regtest_qtctest.sh` and `regtest_qtctest_twonode.sh` on the
  release build; run `qcoin-v2-selftest` from an experimental build.

## Testnet launch

A dedicated chain, `-chain=qtctest`, exists for the public testnet. Its parameters
(`src/kernel/chainparams.cpp`, `CQtcTestParams`):

| Parameter | Value |
|---|---|
| Chain name / data dir | `qtctest` (`<datadir>/qtctest`, config section `[qtctest]`) |
| Network magic | `d1 54 43 54` ("QTCT" with the high bit set) |
| P2P / RPC ports | 28333 / 28332 |
| Address HRP | `tq` (legacy segwit `tq1q...`, ML-DSA witness v2 `tq1z...`); base58 and xpub prefixes as testnet |
| Genesis | time 1761782400 (2026-10-30 00:00 UTC), nonce 551, nBits 0x2000ffff, coinbase text "Qcoin testnet 30/Oct/2026 ML-DSA witness v2 active from genesis" |
| Genesis hash | `0090e8f80f8d0caecfde17644580d7bd83ef14f243c2f5a26e0d54996c09f11b` |
| Genesis merkle root | `951bd97f5c87145947cf54618d588de8c47b88c329991c4e21502ef52046c4b6` |
| Deployments | BIP34/65/66/CSV at height 1, segwit and **mldsav2 at height 0** (active from genesis); testdummy never |
| Proof of work | **RandomX** from height 0 (see "RandomX proof of work"); `powLimit` 00ffff… (nBits 0x2000ffff, about 256 RandomX hashes per block), retargeting on, testnet-style min-difficulty blocks allowed; `generatetoaddress` works; `maxtries` is a 32-bit total budget for the call, so mine one block per call with 2000000000 (about 6 s per block on one core in light mode) |
| Seeds / checkpoints / assumevalid | none yet |

Bring-up:

```bash
bitcoind -chain=qtctest -walletsigscheme=mldsa44 -fallbackfee=0.0001 -daemon
bitcoin-cli -chain=qtctest getblockchaininfo      # "chain": "qtctest"
bitcoin-cli -chain=qtctest getdeploymentinfo      # deployments.mldsav2.active == true, height 0
bitcoin-cli -chain=qtctest createwallet w
bitcoin-cli -chain=qtctest -rpcwallet=w getnewmldsaaddress   # tq1z...
bitcoin-cli -chain=qtctest generatetoaddress 1 <addr> 2000000000   # one block per call; maxtries is a 32-bit total budget
```

Launch checklist (in order):

1. **Binary.** Tag a release built from this branch with `QCOIN_WITNESS_V2_EXPERIMENTAL=OFF`
   (the default build has the whole v2 path; the option only adds the non-BIP
   ML-DSA-87 extras). Publish reproducible builds for Linux at least, with liboqs
   either statically linked or pinned (0.14.0) in the install instructions.
   Commit 13d6b525 (legacy ECDSA-path routing) is reverted. On `qtctest` the
   value rule makes Qcoin a separate coin (ECDSA outputs with value are invalid);
   the Bitcoin chains in the tree keep upstream rules.
2. **Genesis and PoW.** The genesis above (`2000ffff`, RandomX) is the open-testnet
   value. To change it again follow "Raising the proof-of-work difficulty" (a
   difficulty-1 candidate is already mined and listed) and wipe data
   directories. Set `nMinimumChainWork`/`defaultAssumeValid` once a
   few thousand blocks exist.
3. **Seed nodes.** Run at least two always-on nodes (see "Public launch" for the
   exact commands and `fork/contrib/qtctest.conf`), add their addresses to
   `vSeeds` (DNS) or `vFixedSeeds`, and open port 28333. Until then, peers use
   `addnode=`/`-connect`.
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

`qtctest` started with a regtest-strength target so blocks (and the genesis)
could be produced instantly; it now runs RandomX at `2000ffff` (see the table; the table below lists the SHA-256d candidates, whose hash counts are SHA-256d counts). Raising
the target further means mining a new genesis, because the genesis block commits
to `nBits`. `fork/tools/mine-genesis.py` does that and
prints the exact lines to paste.

### How the numbers relate

- `nBits` is the compact-encoded target in the genesis header; a header is
  valid when its proof-of-work hash (RandomX on `qtctest` and regtest, `sha256d(header)` on the Bitcoin chains) as a little-endian 256-bit number is below it.
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
| `207fffff` (original bring-up value) | ~2 | `3ad80dc81cd929844ede7ee0c9f7b1fd85227c644dab5ff232a7ca01a0d06d60` | nonce 0, time 1761782400; instant; anyone can re-mine it |
| `2000ffff` (**current**, RandomX) | ~256 RandomX hashes | `0090e8f80f8d0caecfde17644580d7bd83ef14f243c2f5a26e0d54996c09f11b` | nonce 551 (a valid SHA-256d nonce; the genesis block is exempt from the RandomX check), time 1761782400, powLimit `00ffff0000000000000000000000000000000000000000000000000000000000`; about 6 s per block on one CPU in light mode |
| `1e00ffff` (previous SHA-256d value, 1/256 of Bitcoin difficulty 1) | ~16.8 million | `0000007ab165a4d29ff101fc7faf2cd2dd20618f4960c1fd85e3dd3e4a823437` | nonce 6739749, time 1761782400, powLimit `000000ffff000000000000000000000000000000000000000000000000000000`; about 5 s per block on one modern CPU, a few seconds for the genesis with the helper |
| `1d00ffff` (Bitcoin difficulty 1, testnet-like) | ~4.3 billion | `0000000086f43233c3863a31d6fd58b66fc47d6a21be15015bbb3e6768a13815` | nonce 207307031, time 1761782400, powLimit `00000000ffff0000000000000000000000000000000000000000000000000000`; mined in 55.5 s at ~4,314,179 H/s |

`2000ffff` is the value now in `CQtcTestParams` (a RandomX hash costs thousands of
times more CPU than SHA-256d, so the target is far easier than `1e00ffff` was). `generatetoaddress` works for bootstrapping; it is a 32-bit total budget for the whole call, so mine one block per
call with 2000000000 (the regtests and the faucet do exactly that). Difficulty 1 behaves like Bitcoin testnet and effectively
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
   larger `maxtries`; note it is a 32-bit total budget for the whole call and
   about 16.8 million hashes per block are expected at `1e00ffff`, so mine one
   block per call (`generatetoaddress 1 <addr> 2000000000` in a loop) or use an
   external miner via `getblocktemplate`.
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
- Wallet: `wpq(HEXPK)` descriptor, bech32m v2 addresses (`bc1z`/`tq1z`/`bcrt1z`
  via `WitnessUnknown`), `getnewmldsaaddress`, HD derivation from the BIP32 root,
  keys stored per descriptor in the wallet database, encrypted with the
  passphrase, held in secure memory and wiped after signing, PSBT create/sign/
  finalise with a proprietary public-key field, watch-only tracking.
- Tests: `qcoin-v2-selftest` and the `fork/test/regtest_v2_*.sh` scripts
  (spend, multi, encrypt, hd, psbt, activation).
- Chain and tools: `qtctest` with its genesis and RandomX target (2000ffff), example
  config, two-node test, explorer, faucet, genesis helper, launch runbook
  ("Public launch").
- Value rule: only ML-DSA outputs may carry value (see "Value rule"); the
  wallet cannot create ordinary outputs.

### Open items for public testnet

Status at commit 31bda30. **Nothing below is broken**: every implemented path
passes its tests; each row is missing functionality, an unfinished cleanup, or
an operational step. "Before announcing" marks what should land before the
network is opened to outside testers, because changing it afterwards means a
new genesis or a soft fork of the testnet.

| Item | Status | Before announcing? |
|---|---|---|
| Value rule (separate coin) | **Done.** `fMlDsaOnlyValue` on regtest and `qtctest`; ordinary ECDSA outputs with value are consensus-invalid and the wallet refuses to create them. Existing `qtctest` data directories are invalid and must be wiped before relaunch. | Yes (done) |
| Legacy ECDSA-path routing | **Done.** `VerifyECDSASignature` is upstream `pubkey.Verify` again; `fork/src/script/verify_stub.h` and the `QCOIN_ECDSA_FALLBACK` option are removed. `regtest_qtctest.sh` confirms an ordinary P2WPKH spend next to a v2 spend. | Yes (done) |
| Canonical ML-DSA signature encoding | **Done.** `qcoin::v2::IsCanonicalMlDsaSignature` re-implements the FIPS 204 HintBitUnpack acceptance rules (cumulative hint counts non-decreasing and at most omega, strictly increasing indices per polynomial, zero padding) and runs before liboqs; failures are `SCRIPT_ERR_MLDSA_SIG_ENCODING`. Consensus therefore does not depend on a library version's strictness. `regtest_v2_canonical.sh` re-encodes a real spend's hint area and shows the node rejects it while the original confirms. | Yes (done) |
| Real seed host | Open, procedure written ("Publishing a real seed node"). Needs a public host, `vSeeds` set in `CQtcTestParams`, placeholders in `fork/contrib/qtctest.conf` and the runbook replaced, `-dnsseed=0` added to the single-node tests. | Yes |
| Script path | **In progress.** Consensus done: `OP_CHECKMLDSAVERIFY` (0xb3) under leaf version 0xc0, control block `leaf_version \|\| param_id \|\| pk_hash \|\| nodes`, BIP 341 leaf/branch hashing, BIP 342-style leaf sighash, OP_SUCCESSx and OP_CHECKSIG* invalid in leaves, exactly-once verification of attestation entries; a 1-of-1 leaf spend confirms on regtest and qtctest via `qcoin-v2-scriptpath`. PSBT fields, aggregation and wallet signing are done (`regtest_v2_psbt_multisig.sh`). Open: the `wpq(KEY,{TREE})` descriptor so the wallet can create and recognise the output, policy limits for leaf stack items, and reconciling the control-block layout with the BIP text. | No for a key-path testnet; the consensus rules are in before launch, so a later wallet does not need a soft fork |
| Checkpoints / assumevalid / `chainTxData` | Open. Set once the chain has a few thousand blocks; irrelevant at launch. | No |
| Proof-of-work regime | Decided for now: RandomX ("RandomX proof of work"), nBits 2000ffff on `qtctest` (about 6 s per block on one CPU). Open: the real difficulty for a public chain. | No (changing it later means a new genesis) |
| Dust and weight policy | Open. Dust threshold still assumes a 148-byte input; a v2 input is about 1 kvB. Worst-case per-block verification cost not benchmarked (BIP section 7). | No |
| Dedicated destination / output type | Open. v2 addresses are `WitnessUnknown{2,Q}`; `getnewaddress`/`-addresstype` cannot produce them, `getnewmldsaaddress` does. | No |
| Derivation spec | Open. Single-level HMAC scheme ("HD derivation") works and is deterministic, but is not a published path; `encryptwallet` rotates the root, so users must back up after encrypting. | No (document the backup rule for testers) |
| `DataFromTransaction` attestation extraction | Open, minor. Re-signing a partially signed raw transaction does not recover an existing v2 attestation; PSBT and wallet signing are unaffected. | No |
| Unit / functional / fuzz tests, BIP vectors | Open. Coverage is the shell scripts in `fork/test/` plus `qcoin-v2-selftest`; no Boost unit tests, Python functional tests, fuzz targets for the attestation parser or PSBT field, and the BIP's test-vector section is empty. | No for launch, yes before external review |
| Review items | Open. Seeded keygen via a temporary liboqs RNG (`MlDsaKeygenFromSeed`) and the proprietary PSBT field should be checked against the final BIP text. | No |
| Explorer and faucet exposure | Documented, not deployed. Run behind a TLS reverse proxy that sets `X-Forwarded-For`; keep RPC on localhost. | Operational, at launch |

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

The script path (several attestations) has its own fields and flow, below ("Script-path PSBTs").
Not done: an exported secret-key format for offline signers (the secret is only ever in the wallet database).

### Script-path PSBTs (multi-party ML-DSA spends)

A witness v2 script-path spend (`<leaf> <control block> <attestation>`) needs one attestation entry per key named in the
leaf, and the keys belong to different parties. The PSBT carries the leaf, the control block and the entries gathered so
far; `combinepsbt` is the aggregator, so no new role is needed. The key-path fields and behaviour above are unchanged.

Three proprietary **input** fields (BIP 174 type `0xFC`, identifier `qcoin` = `71636f696e`):

| Subtype | Key data | Value | Meaning |
|---|---|---|---|
| 1 | none | `leaf_version \|\| leaf script` | the leaf being spent (leaf version must be `0xc0`) |
| 2 | none | control block: `leaf_version \|\| param_id \|\| internal pk_hash \|\| 32-byte nodes` (34 + 32m bytes, m <= 8) | the path to the commitment `Q` of the output |
| 3 | `pk_hash` (32 bytes) | one attestation entry: `param_id \|\| ML-DSA public key \|\| signature` | the signature of the key whose hash is `pk_hash` over the leaf sighash; one field per signer |

(subtype 0, unchanged, is the key-path public key.) The entry index of each key is not stored: it is the operand `i` of
the leaf's `<pk_hash> <i> OP_CHECKMLDSAVERIFY` triple, and the finalizer writes the entries into the attestation
(`0x51 || n || entry_0 || ... || entry_{n-1}`) in that order. A leaf names up to four keys. Fields serialize in
the normal proprietary form (`PSBTProprietary`, ordered by key), so unknown software keeps them; `decodepsbt` shows them under
`inputs[].proprietary`.

Flow (the coordinator needs no wallet):

1. **Create.** `createpsbt` spends the script-path coin, `utxoupdatepsbt` adds the UTXO, and the new RPC
   `addpsbtmldsascriptpath <psbt> <input> <leaf_hex> <control_hex>` adds subtypes 1 and 2. It refuses a leaf and control
   block that do not commit to the output being spent and a leaf that names no ML-DSA key; it replaces earlier script-path
   data, including entries that signed another script.
2. **Sign.** Each party runs `walletprocesspsbt` (or `SignPSBTInput` with any signing provider). For every key in the leaf
   that the wallet holds and that has no entry yet, it signs the leaf sighash (BIP 341 hash with the BIP 342 extension,
   `SIGHASH_DEFAULT`, `SigVersion::TAPSCRIPT`; the message is the section 6 message for that key) and adds a subtype 3 field.
   A wallet holds a leaf key if it is the key behind one of its own `wpq()` addresses (`getnewmldsaaddress`): the wallet looks
   up the key-path script `OP_2 <commit(pk_hash)>` of every `pk_hash` in the leaf. A wallet that holds no key of the leaf adds
   nothing. The parties can pass one PSBT along (each adds its entry) or sign copies.
3. **Aggregate.** `combinepsbt` merges the entries of the copies (the standard merge of proprietary fields).
4. **Finalize.** `finalizepsbt`, or the last signer's `walletprocesspsbt`, assembles `<leaf> <control> <attestation>` into
   `final_scriptwitness` once every index of the leaf has an entry. The finished witness is checked with the consensus
   verifier (`PSBTInputSignedAndVerified`) before the input counts as final: a wrong or corrupted entry from another party
   leaves the input unfinalized instead of producing an invalid transaction. The three field types are removed from a
   finalized input.

`fork/test/regtest_v2_psbt_multisig.sh` runs it on regtest with two wallets: a 2-of-2 leaf, one party signing and the other
adding its attestation and finalizing (the witness is a 71-byte leaf, a 34-byte control block and a 7,468-byte attestation;
the spend is about 2 kvB), then both parties signing copies that `combinepsbt` merges, with the refusals: one entry is
not enough, a corrupted entry is not finalized, a script that does not commit to the output is rejected, and a wallet
that is not named in the leaf adds nothing. `fork/test/v2_scriptpath_addr.py` computes the `scriptPubKey`, leaf and control
block of an N-of-N leaf from the public key hashes (the wallet cannot yet build the output itself).

Limits: one leaf per input (the control block selects it; only single-leaf trees are tested), leaf keys must be the keys behind the signers' own `wpq()` addresses (there is still no `wpq(KEY,{TREE})`
descriptor, so a wallet cannot derive or recognise the script-path output itself), at most four entries, `SIGHASH_DEFAULT`
only, and an entry is not verified when it is merged, only when the input is finalized. The internal key of the example
outputs is the hash of a fixed string, so the key path is unusable (the commitment includes the Merkle root).


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

### Option A: hard-wired ECDSA-path routing (what the branch did until the revert)

Commit 13d6b525 replaced `VerifyECDSASignature` in the interpreter with an
ML-DSA-87 check (reverted; kept here as the record of the decision). Signatures and keys travel in the existing scriptSig /
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

Choose B (done: 13d6b525 is reverted). Everything built so far is reusable under B: `pqc.h` already models
both parameter sets, the `walletdescriptormldsakey` records become the backing for a
`mldsa()` descriptor key, and `verify_stub.h` is deleted (the attestation
verifier in `witness_v2.h` has its own liboqs call). If A is kept instead, document it as a hard-fork
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
- **Consensus/policy plumbing.**
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
M=$(bitcoin-cli -regtest -rpcwallet=miner getnewmldsaaddress mine); bitcoin-cli -regtest generatetoaddress 101 $M
PQ=$(bitcoin-cli -regtest -rpcwallet=pq getaddressesbylabel mldsa | jq -r 'keys[0]')   # bcrt1z... (created with the wallet)
PQ2=$(bitcoin-cli -regtest -rpcwallet=pq getnewmldsaaddress "second")                 # another bcrt1z..., fresh key
bitcoin-cli -regtest -rpcwallet=miner sendtoaddress $PQ 10; bitcoin-cli -regtest generatetoaddress 1 $M
bitcoin-cli -regtest -rpcwallet=pq sendtoaddress $M 5                                  # ML-DSA attestation spend
bitcoin-cli -regtest generatetoaddress 1 $M                                            # accepted into a block
```

Not done: `-addresstype` / `getnewaddress` for v2 (needs the dedicated
destination and `OutputType`; use `getnewmldsaaddress` instead) and the
script path `wpq(KEY,{TREE})`. PSBT, encrypted key storage, HD derivation,
the canonical-encoding check and the deployment flag are all in place (see
"Current status").

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

Canonical signature encoding (section 6) is enforced by
`IsCanonicalMlDsaSignature` ahead of the ML-DSA verify, and activation is the
`mldsav2` buried deployment. The script path uses the BIP 342-style leaf
sighash (`SigVersion::TAPSCRIPT`, leaf hash and code-separator position committed).

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
- [x] Canonical FIPS 204 signature-encoding check (`IsCanonicalMlDsaSignature`: hint
      counts <= omega and non-decreasing, strictly increasing indices, zero padding;
      `SCRIPT_ERR_MLDSA_SIG_ENCODING`).
- [x] Section 6 message builder: `param_id || pk_hash || sighash_v2`.

### 2. New witness version in consensus: `script/interpreter.cpp`
- [x] Guarded v2 branch in `VerifyWitnessProgram` ahead of the v0/v1 chain
      that pops the attestation and checks the commitment (key path).
- [x] `SCRIPT_VERIFY_MLDSA_V2` flag plus buried `DEPLOYMENT_MLDSA_V2` in
      `consensus/params.h`, `deploymentinfo.cpp`, `kernel/chainparams.cpp`; the
      branch runs only when the flag is set; mempool strips it pre-activation.
- [x] Key path: ML-DSA.Verify over the section 6 message (`CheckMlDsaSignature`;
      liboqs with ctx `BIP-MLDSAv2`).
- [x] Script path: control block `leaf_version || param_id || pk_hash || nodes`
      (34 + 32*m bytes, m <= 8), leaf hash and Merkle proof as BIP 341, OP_SUCCESSx
      and OP_CHECKSIG* invalid in leaves. Leaves run as `SigVersion::TAPSCRIPT` with
      `ScriptExecutionData::m_mldsa_attestation` set (no new SigVersion).
- [x] `OP_CHECKMLDSAVERIFY` at 0xb3 under v2 leaf semantics: pops `<pk_hash:32> <i>`,
      requires i < n, SHA256(pk_i) == pk_hash, ML-DSA.Verify(entry i) over the leaf
      sighash; each entry exactly once.
- [x] Dedicated `ScriptError` codes (`SCRIPT_ERR_MLDSA_ATTESTATION`, `SCRIPT_ERR_MLDSA_SIG`,
      `SCRIPT_ERR_MLDSA_SIG_ENCODING`, `SCRIPT_ERR_CHECKMLDSAVERIFY`, `SCRIPT_ERR_MLDSA_ENTRY_UNUSED`).
- [x] v2 sighash: key path uses `SignatureHashSchnorr(TAPROOT, SIGHASH_DEFAULT)`, the
      script path `SignatureHashSchnorr(TAPSCRIPT, SIGHASH_DEFAULT)` with the leaf hash;
      `param_id`/`pk_hash` are committed in the message, not the hash.
- [x] Revert commit 13d6b525 (ECDSA-path routing) and drop
      `QCOIN_ECDSA_FALLBACK`: `VerifyECDSASignature` is upstream again, `verify_stub.h` deleted.

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
      Script-path signing exists only in `fork/test/v2_scriptpath_tool.cpp`, not in the wallet.
- [~] PSBT round-trip works for key-path inputs (create unsigned, sign elsewhere,
      finalise). `DataFromTransaction` extraction of an attestation is not implemented.
- [~] PSBT: proprietary `qcoin`/0 input field carrying the ML-DSA public key;
      finished attestations use `final_scriptwitness`. No partial form (none needed
      for the key path).
- [~] Regtest script `fork/test/regtest_v2_spend.sh` funds and spends a `wpq()`
      output (key path); `regtest_v2_scriptpath.sh` spends a 1-of-1 leaf. A proper
      functional test is pending.

### Exit criteria
A regtest wallet with `-walletsigscheme=mldsa44 -addresstype=bech32m-v2`
receives to a `bcrt1z` address and spends it in a block that the node accepts
with commit 13d6b525 reverted (done; `QCOIN_ECDSA_FALLBACK` no longer exists).

## Remaining gaps

Everything that was listed here as missing for the key path (attestation
encoding, commitment, v2 sighash and context, bech32m v2 addresses, `wpq()`,
`SigningProvider` access to ML-DSA keys, wallet-DB storage, encryption, HD
derivation, PSBT) is implemented and tested; see "Current status". What remains,
with status, is the table under "Open items for public testnet". In short:

- Wallet: script-path descriptor `wpq(KEY,{TREE})`, signer and PSBT fields (the
  consensus side of the script path is in).
- Wallet and policy: dedicated `CTxDestination`/`OutputType` for v2; dust
  threshold from the v2 input size; a published derivation path; attestation
  extraction in `DataFromTransaction`.
- Network: seed hosts, checkpoints/assumevalid once the chain has history.
- Verification: unit, functional and fuzz tests; BIP test vectors; per-block
  verification benchmark; review of the seeded keygen and PSBT field.

## How to exercise what exists

```bash
# default: ECDSA, regtest spends work
build/bin/bitcoind -regtest -daemon

# wallet generates and stores an ML-DSA-87 key at creation, signs with it on
# spend attempts (see debug.log), but the spend is rejected at VerifyScript
build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

# the key survives a restart: it is a record in wallet.dat
build/bin/bitcoin-cli -regtest stop && build/bin/bitcoind -regtest -daemon -walletsigscheme=mldsa87

```
