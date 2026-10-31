Bitcoin Core integration/staging tree
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

Qcoin: ML-DSA post-quantum fork (experimental)
----------------------------------------------

This tree is the `experimental-pqc` branch of **Qcoin**, a Bitcoin Core fork
that adds post-quantum signatures with ML-DSA (FIPS 204, via
[liboqs](https://github.com/open-quantum-safe/liboqs) 0.14). It is research
code: no mainnet, no stability promises, test coins have no value. Qcoin is a
separate coin, not a Bitcoin soft fork: on its chains only ML-DSA (witness v2)
outputs may carry value, and ordinary ECDSA outputs are consensus-invalid.

**Start here:** [doc/WALLET-PQC.md](doc/WALLET-PQC.md) is the living status
document. It has the build notes, the design decision, the activation rules,
the `qtctest` launch runbook, and the list of remaining gaps.

Current state (October 2026):

- **Value rule.** On regtest and `qtctest` every output with value must be a
  witness v2 ML-DSA program; P2PKH, P2WPKH, P2TR and other ECDSA outputs are
  rejected by consensus (`bad-txns-output-not-mldsa`) and the wallet refuses to
  create them (`getnewaddress` points at `getnewmldsaaddress`; change is ML-DSA).
- **Witness v2 (ML-DSA) outputs.** Address programs `OP_2 <Q>` commit to an
  ML-DSA-44 public key; the spend carries a `param_id || pk || sig`
  attestation in the witness, verified over the BIP341 sighash with the
  `BIP-MLDSAv2` signing context. Gated by the buried deployment `mldsav2`
  (`getdeploymentinfo`), active from genesis on regtest and `qtctest`, never on
  mainnet/testnet/signet. The wallet supports it end to end: `wpq()`
  descriptors, `getnewmldsaaddress`, HD-derived keys stored encrypted in the
  wallet database, PSBT, and `-walletsigscheme=mldsa44`. Addresses are
  bech32m version 2 (`bcrt1z…`, `tq1z…`).
- **`qtctest` chain.** A dedicated test network (`-chain=qtctest`, P2P 28333,
  RPC 28332, genesis
  `0000007ab165a4d29ff101fc7faf2cd2dd20618f4960c1fd85e3dd3e4a823437`,
  difficulty 1e00ffff, about 3 s per block on one CPU). Example configuration in
  [fork/contrib/qtctest.conf](fork/contrib/qtctest.conf); seed nodes are not
  published yet, so peers use `addnode=`.
- **Explorer and faucet.** Dependency-free Python tools in
  [fork/tools](fork/tools): `qtc-explorer.py` (status page, blocks,
  transactions, address lookup) and `qtc-faucet.py` (pays ML-DSA addresses,
  rate-limited). Both talk to a local node over RPC.
- **Tests.** Shell regression tests in [fork/test](fork/test):
  `regtest_v2_*.sh` (spend, multi-wallet, encryption, HD, PSBT, activation),
  `regtest_qtctest.sh` (single node, v2 spend confirmed on `qtctest`),
  `regtest_qtctest_twonode.sh` (two nodes over loopback), explorer and faucet
  tests. `qcoin-v2-selftest` is built with `-DQCOIN_WITNESS_V2_EXPERIMENTAL=ON`.

Build as upstream (`doc/build-*.md`) with liboqs installed and
`-DENABLE_IPC=OFF`; the ML-DSA code lives under [fork/src](fork/src) and in
marked `Qcoin` sections of `src/script`, `src/wallet`, `src/kernel/chainparams.cpp`
and `src/validation.cpp`. Known open items (seed nodes, script
path, dedicated address type) are tracked in
[doc/WALLET-PQC.md](doc/WALLET-PQC.md) under "Testnet readiness".

The remainder of this file is the unchanged upstream Bitcoin Core README.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/license/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly from release branches to indicate new official, stable release versions of Bitcoin Core.

The https://github.com/bitcoin-core/gui repository is used exclusively for the
development of the GUI. Its master branch is identical in all monotree
repositories. Release branches and tags do not exist, so please do not fork
that repository unless it is for development reasons.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with: `build/test/functional/test_runner.py`
(assuming `build` is your build directory).

The CI (Continuous Integration) systems make sure that every pull request is tested on Windows, Linux, and macOS.
The CI must pass on all commits before merge to avoid unrelated CI failures on new pull requests.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://explore.transifex.com/bitcoin/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
