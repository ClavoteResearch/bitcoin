Qcoin qtctest run on Vast.ai instance 58709187 (Ryzen 9 5900X, 24 vCPU, 64 GB), 2026-11-01.
Built from experimental-pqc at 27ff8a7d5 (witness v2 script path), configured with
-DENABLE_IPC=OFF -DBUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release, built with -j4.
Node: bitcoind -chain=qtctest -txindex=1 -listen=0 -dnsseed=0. 10 blocks mined to one ML-DSA address.

analysis/                text-only bundle pulled from the instance (sha256 of analysis.tgz in MANIFEST.txt)
  chain-summary.txt      height, per-block hash/time/nonce/weight/coinbase script (0x5220 = witness v2)
  blocks.jsonl           every block at verbosity 2, one JSON object per line
  getblockchaininfo.json, getdeploymentinfo.json, getnetworkinfo.json, getmempoolinfo.json,
  getwalletinfo.json, getbalances.json, getmldsahdinfo.json   RPC snapshots
  build2.log             both build passes and node starts (first pass failed in unit-test targets)
  template-setup.log     the template's own startup script (failed at SQLite, installed liboqs 0.16)
  debug.log              node log;  git-*.txt, bitcoind-version.txt, host-info.txt
push-result.txt          the push of 27ff8a7
Not saved on purpose: wallet files, key material, API keys.
