# Results

All times are seconds from the nodes' own clocks. Each node's offset from NTP was measured before every test and was under 3 ms, but a driver bug meant it was not subtracted, so cross-node deltas in sections 1 to 3 are good to about 5 ms (the stress analysis in section 8 does apply it). One run per row unless noted,
so treat them as samples, not distributions. Raw outputs are in `tests/`; every number is also in `timings.csv`.

## 1. Correctness on a live three-node network

| Test | Result |
|---|---|
| Initial sync | B and C each downloaded 105 blocks from A in 1.2 s and 2.0 s. |
| Peer-to-peer send A to B (5 coins) | Accepted by B and C, confirmed on both; final balances matched. |
| Peer-to-peer send B to C (2 coins), mined by C | Accepted by A and C, confirmed on all three. |
| Script-path spend (1-of-1 `OP_CHECKMLDSAVERIFY` leaf, 10 coins) | Funded, relayed and confirmed on A, B, C. A copy with a flipped signature bit was rejected by B and C with `mempool-script-verify-flag-failed (Invalid ML-DSA signature)`. |
| Double spend, mempool race | Same output spent to B's address and to C's address, submitted to B and C 0.106 s apart. The earlier one held the mempools of A and B, C held the other. After one block on A all three nodes had the same winner and the loser was gone from every mempool. |
| Double spend, competing blocks | B and C mined at the same moment; C's block was found 0.71 s earlier and reached everyone first, so no lasting fork formed. C's transaction won; B kept its block as a side branch. |
| Double spend, partition | B isolated with `setnetworkactive false` and mined one block holding its spend; A and C mined two blocks holding the conflicting spend. After reconnecting, B reorganised in 1.52 s, its transaction was dropped, and the A/C chain's transaction confirmed. |
| Chain agreement at the end | A, B and C at height 116, identical tip `000000835bd054c2...`, empty mempools, no errors in any `debug.log`. |

## 2. Latency

| Measure | Samples (s) |
|---|---|
| Transaction relay to a peer, first seen in mempool | 4.93, 4.48, 5.25, 5.08 (key-path sends); 3.46, 4.12 (script-path spend) |
| Block relay, found to confirmed on a peer | 0.073, 0.091, 0.281 (sends); 0.082, 0.074 (script-path) |
| Broadcast to first confirmation | 6.51, 6.53 (A to B); 8.58, 8.37 (B to C); 6.47, 6.46 (script-path). Each includes a deliberate 5 s wait before the block was mined |
| Reorganisation after reconnect | 1.52 |

Transaction relay is slow because of Bitcoin Core's default transaction announcement batching (average 2 s for outbound
peers, 5 s for inbound) plus a 2 s delay before requesting from peers that connected inward. It is not specific to Qcoin.
Blocks are announced immediately and arrive in under 0.3 s. The ping between nodes was 28 to 62 ms.

## 3. Throughput sample (50 transactions)

| Phase | Result |
|---|---|
| Acceptance on A | all 50 in 1.18 s (42 tx/s) with 8 parallel `sendrawtransaction` callers; median call 0.19 s |
| Relay | B and C held all 50 after 3.61 s and 3.68 s (the first arrived at 3.4 s) |
| Block | 51 transactions, 192,010 bytes, 206,782 WU, mined on A in 3.5 s, confirmed on all nodes within 0.05 s of A |
| First broadcast to all nodes confirmed | 16.0 s, dominated by the manual wait and mining step |

This is not a capacity measurement. Mining was manual and started after relay finished, so the 16 s is mostly waiting. Block
capacity can be estimated from size instead: a one-input, one-output witness v2 spend weighs about 4.1 kWU (about 1 kvB),
so a 4 MWU block holds about 970. Sustained throughput is then 970 divided by the block interval. Policy limits and
verification cost at full blocks were not tested.

## 4. Transaction size

| Item | Value |
|---|---|
| Key-path attestation | 3,735 bytes (`0x51`, n=1, param_id `0x01`, 1,312-byte public key, 2,420-byte signature) |
| Script-path witness | leaf 36 B, control block 34 B, attestation 3,735 B |
| Script-path spend, one input one output | 1,048 vB, 4,189 WU |
| Key-path spend with change, from the single-node regtest | 1,073 vB, 4,289 WU |

## 5. Unit and regression tests at commit 27ff8a7

Run on the build host before the network run; all passed.

| Suite | Result |
|---|---|
| `qcoin-v2-selftest`, both build configurations | all checks pass, including the new script-path section (valid 1-of-1 and 2-of-2 leaves, Merkle path, wrong node or `param_id`, control size, wrong key, bad and duplicate entry index, unused entry, key-path sighash in a leaf, `OP_CHECKSIG` and `OP_SUCCESSx` rejected, unknown leaf version) |
| `regtest_v2_scriptpath.sh` | 20 of 20 on regtest, both builds, and on qtctest |
| `regtest_qtctest.sh` | 21 of 21 |
| `regtest_v2_spend.sh` | 15 of 15 |
| `regtest_v2_canonical.sh` | 9 of 9 |
| `regtest_v2_activation.sh` | 15 of 15 |
| `regtest_pq_only.sh` (value rule) | 24 of 24 |
| `regtest_v2_psbt.sh` | 20 of 20 |

## 6. Single-node run (same commit)

Ten blocks mined in 56 s on one node (about 5.6 s per block at difficulty 0.0039). All ten coinbases pay a witness v2 output,
which is the value rule working; the genesis coinbase is the only non-v2 output. See `single-node-run/chain-summary.txt`.

## 7. Limits to state in a paper

- Three nodes, one region, one run per measurement, so no confidence intervals.
- Blocks were mined by hand with `generatetoaddress`; confirmation times therefore include manual steps and are not a
  statement about block intervals on a live chain. Difficulty is minimal.
- Node A had no inbound port; its peers were reached by outbound connections only.
- The script-path control-block layout (34-byte base, at most 8 nodes) and the rule that every attestation entry is
  verified exactly once are this implementation's choices; the BIP draft's section 5 text was not available.
- The wallet signs key-path spends only. Script-path spends were built and signed by a test tool.

## 8. Stress test

Setup: 3,600 spendable outputs of 0.02 coin were created by four 900-output transactions on A. Every test spend has one input and one
output and pays 0.0198 coin (fee 0.0002). Senders used `sendrawtransaction` through parallel `bitcoin-cli` callers. One run per row.
Raw data and the analysis are in `tests/stress/`.

| Burst from A | A accepts all in (s) | A rate (tx/s) | B has all (s) | C has all (s) | Block txs | Block MB | Block MWU | Block to B (s) | Block to C (s) |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 2.47 | 40.4 | 9.28 | 4.95 | 101 | 0.38 | 0.413 | 0.042 | 0.046 |
| 250 | 5.87 | 42.6 | 9.33 | 8.71 | 251 | 0.96 | 1.030 | 0.055 | 0.055 |
| 500 | 11.82 | 42.3 | 14.56 | 19.59 | 501 | 1.92 | 2.059 | 2.678 | 0.052 |
| 900 | 21.26 | 42.3 | 27.24 | 25.79 | 901 | 3.45 | 3.706 | 6.545 | 0.055 |

"Has all" is time from the first broadcast until the node's mempool held every transaction. The block was mined on A after relay finished.

- No transaction was rejected in any run: 3,750 in the main run and 900 in the diagnostic.
- Acceptance on A was flat at about 42 tx/s whatever the burst size, so it does not depend on how many transactions are queued. The cause (validation or RPC overhead) was not profiled.
- Relay finished 3 to 8 s after A's last acceptance. Overall full-mempool relay throughput was 11 to 33 tx/s.
- A block of 901 spends is 3.45 MB and 3.706 MWU, 93% of the 4 MWU limit, and was accepted by all nodes.
- Cold block: with 500 spends mined the moment A had accepted them, B held at least 375 and C at least 250 of the 500 when the block arrived. The block reached C in 0.48 s and B in 4.6 s.
- Concurrent senders: 100 spends each from A, B and C at the same instant, 300 in total. All were accepted. The senders finished in 2.4 s (A), 3.1 s (B) and 6.9 s (C). Every node held all 300 within 8.9 s of the common start. One block mined on C held 301 transactions (1.15 MB, 1.236 MWU, mining call 5.0 s) and reached A, B and C within 0.05 s.
- Sustained load: 20 tx/s for 60 s from A (1,200 spends, none rejected) while C mined a block every 10 s. Confirmation latency, from send to the block holding the transaction: minimum 3.4 s, median 14.8 s, 95th percentile 21.8 s, maximum 24.1 s. Overall 1,200 confirmed in 71.4 s, 16.8 tx/s including the tail. Blocks held 66 to 253 spends (the last, at +102 s, was empty). Peak mempool was 464 (A), 429 (B), 393 (C) transactions and peak resident memory 471 MB (A), 144 MB (B), 88 MB (C). One block took 22 s to find, which is ordinary variance for one CPU core at this difficulty.

### Block connection time and the wallet

Block-to-B was 2.7 s and 6.5 s for the 500 and 900 bursts but 0.05 s on C. In the stress run every burst paid an address of B's wallet, which is the difference between B and C. A diagnostic (`tests/stress/t5b_diag.txt`) repeated a 450-spend burst twice:

| Payments to | B reached the block (s) | C reached the block (s) |
|---|---|---|
| an address no wallet owns | 0.037 | 0.065 |
| an address of B's wallet | 0.355 | 0.055 |

So when no wallet is involved, a block of 450 to 901 spends reached the nodes in 37 to 65 ms including propagation, which bounds validation, ML-DSA verification of every input included, at under about 65 ms. I did not measure why it is that fast; Bitcoin Core's script-execution cache, which skips re-verifying transactions already accepted into the mempool, is the likely reason. The slowdown on B is consistent with its wallet processing its own incoming payments; the diagnostic supports that but it was not profiled.

### Limits specific to the stress test

- Blocks were mined by hand, so latency under sustained load reflects the 10 s cadence I chose, not a live block interval.
- Acceptance rate depends on the number of callers and the speed of `bitcoin-cli` process start-up; it is a lower bound for the node.
- The CPU figures in the raw node samples are `ps` lifetime averages and carry no information about load; they are left out of `timings.csv`.
- Three nodes, one run per row.
