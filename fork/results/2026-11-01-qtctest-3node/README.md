# Qcoin qtctest measurements, 2026-11-01

Data behind the first multi-node run of the Qcoin (QTC placeholder) experimental fork: a post-quantum coin whose only
monetary output type is witness v2 ML-DSA-44 (FIPS 204 via liboqs). Everything here was produced by the scripts in
`scripts/` against `-chain=qtctest` on rented machines. See `RESULTS.md` for the tables and `timings.csv` for the numbers.

## What was run

| | |
|---|---|
| Software | `experimental-pqc` at commit `27ff8a7d5` (witness v2 script path, `OP_CHECKMLDSAVERIFY`), Release build, gcc 11.4.0, liboqs 0.14.0 |
| Build flags | `-DENABLE_IPC=OFF -DBUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release`, `cmake --build -j4` |
| Chain | `qtctest`, nBits `1e00ffff` (difficulty 0.0039), genesis `0000007ab165a4d29ff101fc7faf2cd2dd20618f4960c1fd85e3dd3e4a823437`, `mldsav2` active from genesis, value rule on |
| Nodes | A: Ryzen 9 5900X, 24 vCPU, 64 GB (miner, outbound-only). B: Core i5-10400F, 12 vCPU, 16 GB. C: EPYC 7551P, 12.8 vCPU, 26 GB. All on Vast.ai, Quebec and Saskatchewan |
| Network | public IPs, round-trip 28 to 62 ms between nodes (`minping` in `nodes/*/getpeerinfo.json`) |
| Peers | A connects out to B and C; B and C connect to each other. `-dnsseed=0 -txindex=1`; B and C `-listen=1 -port=28333` |
| Clocks | each node's offset from NTP measured with `ntpdate -q` before every test and subtracted, so cross-node deltas are good to a few milliseconds |

## Layout

- `RESULTS.md` paper-ready tables and caveats
- `timings.csv` every timing as `test,metric,value,unit,note`
- `tests/` the raw output of each test script
- `nodes/{A,B,C}/` per-node RPC snapshots (`getblockchaininfo`, `getpeerinfo`, `getchaintips`, `getmempoolinfo`, `getnetworkinfo`, `getnettotals`), `debug.log`, key events, build log, raw poller outputs
- `single-node-run/` the earlier one-node run: 11 blocks as JSON (`blocks.jsonl`), per-block summary, deployment info
- `scripts/` the drivers (`t0`..`t4`, `t3b`), remote helpers (`qt.sh`, `poll.sh`, `act.sh`, `sp.sh`, `batch.sh`), `nodebuild34.sh`

## Scrubbing

Host IP addresses are replaced by `NODE_A_IP`, `NODE_B_IP`, `NODE_C_IP` and other addresses by `x.x.x.x`; SSH ports, key paths and
local paths are removed. Wallet files and key material were never collected. Addresses, transaction ids and block hashes are
public testnet data and are left as they were.

## Reproducing

`scripts/nodebuild34.sh` builds a node on Ubuntu 22.04 (apt dependencies, liboqs 0.14.0 from source, this repository).
`scripts/lib.sh` holds the host table (fill in your own), then run `t0_connect.sh`, `t1_send.sh`, `t2_script.sh`,
`t3_double.sh`, `t3b_partition.sh`, `t4_tps.sh`. The per-node helpers expect `/root/src/qcoin/build/bin` and `/root/qtctest-data`.
