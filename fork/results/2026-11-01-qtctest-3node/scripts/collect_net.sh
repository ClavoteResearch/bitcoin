#!/bin/bash
# Collect text data from all three nodes into results/<node>/ (no wallet files, no keys).
cd ~/work; . ./lib.sh
cat > /tmp/collect_node.sh <<'EOS'
. /root/qt.sh
D=/root/analysis_net; rm -rf $D; mkdir -p $D
cd /root/src/qcoin
git log --oneline -3 > $D/git-log.txt
build/bin/bitcoind --version | head -2 > $D/version.txt
{ uname -a; lscpu | head -20; free -m; df -h /; nproc; } > $D/host-info.txt
cat /root/endpoint.txt > $D/endpoint.txt 2>/dev/null
$CLI getblockchaininfo > $D/getblockchaininfo.json
$CLI getnetworkinfo    > $D/getnetworkinfo.json
$CLI getmempoolinfo    > $D/getmempoolinfo.json
$CLI getchaintips      > $D/getchaintips.json
$CLI getpeerinfo | python3 -c '
import sys,json
keep=["id","addr","addrbind","network","inbound","connection_type","subver","version","startingheight","synced_headers","synced_blocks","conntime","timeoffset","pingtime","minping","bytessent","bytesrecv","bytessent_per_msg","bytesrecv_per_msg"]
json.dump([{k:p.get(k) for k in keep} for p in json.load(sys.stdin)], sys.stdout, indent=1)' > $D/getpeerinfo.json
$CLI getnettotals > $D/getnettotals.json
cp /root/qtctest-data/qtctest/debug.log $D/debug.log
grep -E "UpdateTip|REORGANIZE|reorganize|Disconnect|ERROR|WARNING|Invalid|bad-|conflict|mldsa|ML-DSA" /root/qtctest-data/qtctest/debug.log | tail -400 > $D/debug-key-events.log
cp /root/build2.log $D/build2.log 2>/dev/null
cp /root/mine.log $D/mine.log 2>/dev/null
mkdir -p $D/poller-out; cp /root/out/*.txt $D/poller-out/ 2>/dev/null; cp /root/out/*.json $D/poller-out/ 2>/dev/null
ls /root/out/tx_*.hex 2>/dev/null | wc -l > $D/n-tx-hex-files.txt
tar czf /root/analysis_net.tgz -C /root analysis_net
EOS
for n in $NODES; do
  upload /tmp/collect_node.sh $n /root/collect_node.sh
  rx $n 'bash /root/collect_node.sh; ls -la /root/analysis_net.tgz' | tail -1
  mkdir -p "$RES/node_$n"
  ssh "${SSHO[@]}" ${TARGET[$n]} 'cat /root/analysis_net.tgz' 2>/dev/null > "$RES/node_$n/analysis_net.tgz"
  ( cd "$RES/node_$n" && tar xzf analysis_net.tgz && sha256sum analysis_net.tgz | cut -c1-16 )
done
echo "collected into $RES"
ls "$RES"
