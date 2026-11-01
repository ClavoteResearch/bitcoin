#!/bin/bash
# Qcoin qtctest node build for a Vast.ai instance (P2P node). Started detached; logs to /root/build2.log.
# Markers: BUILD_DONE, BUILD_FAILED, NODE_OK, NODE_FAILED. Endpoint written to /root/endpoint.txt.
export DEBIAN_FRONTEND=noninteractive HOME=/root
LOG=/root/build2.log
exec >>"$LOG" 2>&1
set -o pipefail
step() { echo; echo "=== STEP $* ($(date -u +%FT%TZ)) ==="; }
fail() { echo "BUILD_FAILED at: $1 ($(date -u +%FT%TZ))"; exit 1; }
get_env() { tr '\0' '\n' </proc/1/environ | grep "^$1=" | cut -d= -f2; }

EXT_IP=$(get_env PUBLIC_IPADDR); EXT_PORT=$(get_env VAST_TCP_PORT_28333)
echo "endpoint: $EXT_IP:$EXT_PORT  label: $(get_env VAST_CONTAINERLABEL)"
echo "$EXT_IP:$EXT_PORT" > /root/endpoint.txt

step wait-for-template-startup
for i in $(seq 1 240); do
  if pgrep -f 'root/setup.log' >/dev/null || pgrep -x 'apt-get|apt|dpkg|ninja|cmake|make|cc1|cc1plus|git' >/dev/null; then sleep 5; else break; fi
done
nproc; free -g | head -2; df -h / | tail -1

step deps
apt-get update || fail apt-update
apt-get install -y build-essential cmake libboost-all-dev libsqlite3-dev pkg-config python3 libssl-dev libevent-dev git ca-certificates || fail apt-install

step swap
swapon --show; free -g | tail -1

step liboqs-0.14.0
if [ ! -e /usr/local/lib/liboqs.so.0.14.0 ]; then
  rm -f /usr/local/lib/liboqs.so* /usr/local/lib/pkgconfig/liboqs.pc
  rm -rf /usr/local/include/oqs /usr/local/lib/cmake/liboqs /root/liboqs
  git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git /root/liboqs || fail liboqs-clone
  cmake -S /root/liboqs -B /root/liboqs/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON || fail liboqs-configure
  cmake --build /root/liboqs/build -j8 || fail liboqs-build
  cmake --install /root/liboqs/build || fail liboqs-install
  ldconfig
fi
ls -la /usr/local/lib | grep -i oqs

step clone-qcoin
rm -rf /root/src/qcoin; mkdir -p /root/src
git clone --depth 1 --branch experimental-pqc https://github.com/ClavoteResearch/bitcoin.git /root/src/qcoin || fail clone
cd /root/src/qcoin || fail cd
git log --oneline -1
case "$(git rev-parse HEAD)" in 27ff8a7d5*) echo "commit check: 27ff8a7 OK";; *) echo "WARNING: tip is not 27ff8a7";; esac

step configure
cmake -B build -DENABLE_IPC=OFF -DBUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release || fail configure

step build-j4
cmake --build build -j4 || fail build
cmake --build build -j4 --target qcoin-v2-scriptpath || fail build-scriptpath-tool
ls -la build/bin
echo "BUILD_DONE $(date -u +%FT%TZ)"

step start-node-qtctest-listening
mkdir -p /root/qtctest-data
build/bin/bitcoind -chain=qtctest -datadir=/root/qtctest-data -daemon -txindex=1 -listen=1 -port=28333 -dnsseed=0 -fallbackfee=0.0001 || fail bitcoind-start
for i in $(seq 1 60); do
  build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data getblockchaininfo >/dev/null 2>&1 && break
  sleep 2
done
if build/bin/bitcoin-cli -chain=qtctest -datadir=/root/qtctest-data getblockchaininfo; then
  echo "NODE_OK $(date -u +%FT%TZ) endpoint=$EXT_IP:$EXT_PORT"
else
  echo "NODE_FAILED $(date -u +%FT%TZ)"; tail -20 /root/qtctest-data/qtctest/debug.log 2>&1
fi
