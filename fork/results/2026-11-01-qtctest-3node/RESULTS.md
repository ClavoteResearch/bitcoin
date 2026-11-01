# Results

All times are seconds, corrected for each node's measured NTP offset (all offsets were under 3 ms). One run per row unless noted,
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
