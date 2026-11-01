# Qcoin roadmap: queued work

This is the queue of things we have decided to build or test, with what exists today. It is a working list, not a promise
of dates. Current measurements are in `fork/results/`; the protocol state is in `doc/WALLET-PQC.md`.

## 1. Mining tools

Bitcoin launched with a built-in CPU miner only; pools appeared in late 2010 and Stratum in 2012. Qcoin starts with a little
more, and the rest is queued.

| Item | State |
|---|---|
| Built-in miner (`generatetoaddress`) | Works. One CPU thread, about 5 s a block at the minimal qtctest difficulty. |
| `getblocktemplate` | Fixed. It failed on this chain because its placeholder coinbase was `OP_TRUE`, which the value rule rejects (`bad-txns-output-not-mldsa`). It now uses a placeholder ML-DSA output. Guarded by `fork/test/regtest_gbt_miner.sh`. |
| Standalone solo miner `fork/tools/qtc-gbt-miner.py` + `qtc-nonce-scan.c` | Works. Speaks only `getblocktemplate` and `submitblock`, builds a coinbase paying a witness v2 address, about 1.5 MH/s per core with the native scanner. |
| Third-party miners (cgminer, bfgminer, cpuminer, ASIC firmware) | Untested. The only packaged miner on Ubuntu 22.04 (`cgminer`) has no CPU mode. Most need to accept a bech32m witness v2 payout address; many will not. |
| Stratum pool | Queued. A Stratum v1 server over `getblocktemplate` would let any existing miner connect with a user name and password, because the pool sets the v2 payout outputs. Needs per-miner extranonce, share difficulty, payout accounting. |
| Miner GUI | Queued, after the pool. |

## 2. Payment channels (L2) for fast and tiny payments

Not built. On-chain a v2 spend is about 1 kvB and confirms with the block interval, so coffee-sized payments need a layer on top.

Simplest design, a one-way channel:

- The customer funds one script-path output with two leaves: a settlement leaf needing both ML-DSA signatures (customer and
  merchant, two attestation entries) and a refund leaf the customer can spend alone after a relative timelock
  (`OP_CHECKSEQUENCEVERIFY`).
- To pay, the customer signs a settlement transaction with a higher merchant balance each time and hands it to the merchant
  off-chain (about 2.4 KB per update). Nothing touches the chain.
- The merchant keeps only the latest one and settles later by adding their signature. If the merchant disappears, the customer
  refunds after the timeout.

Costs and open questions: each update carries a 2.4 KB signature and keys are 1.3 KB, with no signature aggregation; channel
open and close are about 1 kvB each; the wallet cannot yet create or sign script-path outputs; dispute and fee handling need
a written spec.

Variants to evaluate:

- A hash-chain channel (PayWord style), where each payment reveals the next preimage: 32 bytes per payment, hash-only, so no
  new quantum assumption beyond SHA-256. A script cannot loop, so settlement must verify the chain in segments.
- Hash-locked multi-hop payments (HTLC leaves) for a routed network, much larger than the one-way channel.
- Moving bulk traffic to a separate PQ chain or rollup ("L3") is a research item, not a plan.

Reusing Alby Hub as is does not work: it is a Lightning node (secp256k1 signatures, Bitcoin scripts). The architecture is worth
copying: a self-hosted hub, a web UI, and a connection protocol like Nostr Wallet Connect so apps can request payments with
scoped permissions.

## 3. Entangled wallet (phone and desktop)

The wallet is called the Entangled wallet. Today it is the node's descriptor wallet over RPC: `getnewmldsaaddress`, HD
derivation, encryption, PSBT, automatic ML-DSA change. Queued:

- A GUI (the Qt build flag exists and is off).
- A phone app. Two routes: a light client (needs compact block filters and on-device ML-DSA keys; signing is fast enough, the
  keys and signatures are just large), or a thin app that talks to the user's own node, the hub model above.
- A published key-derivation spec and a seed-phrase format for ML-DSA keys.
- Script-path support (`wpq(KEY,{TREE})`), needed by channels.
- Profile why a wallet receiving a large burst slows its node's block connection (0.355 s against 0.037 s for the same block).

## 4. Explorer

Built (`fork/tools/qtc-explorer.py`). Queued: label script-path inputs (today shown as "witness (3 elements)"), an address
index, public hosting.

## 5. Difficulty and stability

qtctest runs at minimal difficulty with Bitcoin's 10-minute target and two-week retarget. A first retarget run and its results
are in `fork/results/`. Queued: a genuinely harder chain (a harder genesis exists, 1d00ffff), reorg frequency against block
interval and propagation time, and timestamp-manipulation cases.

## 6. Speed and size, to state plainly

ML-DSA-44 verification is a little faster than ECDSA or Schnorr: medians of 27, 35 and 36 µs over eight single-thread runs on
one Ryzen 7 5800H, where single runs vary by up to 30%. Signing is three to four times slower (76 µs against 25 and 20).
The cost is size: 2,420-byte signatures and 1,312-byte keys against 64 and 33 bytes, so a one-input,
one-output spend is about 1,048 vB against about 110 vB for a Taproot or segwit spend. Capacity per block, not CPU time, is what
Qcoin gives up. See `fork/results/2026-11-01-qtctest-3node/bench/`.

## 7. What is still classical

Value is protected by ML-DSA only: ordinary ECDSA outputs cannot carry value. Still classical: the P2P transport encryption
(BIP 324 uses elliptic-curve Diffie-Hellman, which protects confidentiality of public data only), the wallet's BIP 32 root,
RPC authentication, and old script types and Schnorr and ECDSA code that remain in the tree for zero-value use. Proof of work
and Merkle trees use SHA-256, which quantum computers weaken but do not break.

## 8. Operations

Seed hosts and checkpoints before any public chain; the open items table in `doc/WALLET-PQC.md` tracks the rest.
