#!/bin/bash
# Qcoin / Option B: ML-DSA keys under wallet encryption. Create an ML-DSA wallet, fund a v2 coin, encryptwallet,
# verify the secret is no longer a plaintext record, that spending needs an unlock, that a wrong passphrase is
# rejected, that new keys are written encrypted, and that everything survives a restart.
# Requires QCOIN_WITNESS_V2_EXPERIMENTAL=ON + wallet.   Usage: regtest_v2_encrypt.sh [path/to/build/bin]
set -u
BIN="${1:-build/bin}"
D=$(mktemp -d "${TMPDIR:-/tmp}/qcoin-v2e.XXXX")
RPCPORT=18955
PASS="correct horse battery staple"
fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then say "[PASS] $3 ($1)"; else say "[FAIL] $3 (got '$1', want '$2')"; fail=1; fi; }
py() { python3 -I -c "$@"; }
start_node() { "$BIN/bitcoind" -regtest -datadir="$D" -daemon -fallbackfee=0.0001 -rpcport=$RPCPORT -port=18956 -listen=0 -walletsigscheme=mldsa44 $1 >/dev/null
  for i in $(seq 1 60); do "$BIN/bitcoin-cli" -regtest -datadir="$D" -rpcport=$RPCPORT getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; }
txid_of() { py 'import sys,json
try: print(json.load(sys.stdin).get("txid",""))
except Exception: print("")'; }
# `send` on a locked wallet cannot sign, so it returns an unsigned PSBT (complete=false, no txid) instead of broadcasting.
locked_send_result() { py 'import sys,json
try:
    d=json.load(sys.stdin); print(d.get("complete"), "txid" in d)
except Exception: print("error")'; }
one_input() { py 'import sys,json; u=[x for x in json.load(sys.stdin) if x["address"]==sys.argv[1]][0]; print(json.dumps([{"txid":u["txid"],"vout":u["vout"]}]))' "$1"; }
# Count wallet.dat records by type: plaintext ML-DSA (key prefix 0x18"walletdescriptormldsakey") vs encrypted (0x19"...ckey").
db_counts() { py 'import sys,sqlite3
c=sqlite3.connect(sys.argv[1]); rows=[r[0] for r in c.execute("select key from main")]
p=sum(1 for k in rows if k.startswith(b"\x18walletdescriptormldsakey")); e=sum(1 for k in rows if k.startswith(b"\x19walletdescriptormldsackey"))
print(p, e)' "$D/regtest/wallets/pq/wallet.dat"; }

start_node ""
CLI="$BIN/bitcoin-cli -regtest -datadir=$D -rpcport=$RPCPORT"
MINER="$CLI -rpcwallet=miner"; PQ="$CLI -rpcwallet=pq"
$CLI createwallet miner >/dev/null; $CLI createwallet pq >/dev/null
M=$($MINER getnewaddress); $CLI generatetoaddress 101 "$M" >/dev/null
A0=$($PQ getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
$MINER sendtoaddress "$A0" 5 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
check "$($PQ getbalance)" "5.00000000" "pq holds a 5-coin v2 output before encryption"

say "== encrypt =="
$PQ encryptwallet "$PASS" >/dev/null
check "$($PQ getwalletinfo | py 'import sys,json; print(json.load(sys.stdin)["unlocked_until"])')" "0" "wallet is encrypted and locked"
check "$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$($PQ listunspent | one_input "$A0"),\"add_inputs\":false}" 2>&1 | locked_send_result)" "False False" "spend while locked cannot sign (unsigned PSBT, nothing broadcast)"
check "$($CLI getrawmempool | py 'import sys,json; print(len(json.load(sys.stdin)))')" "0" "mempool empty after locked spend attempt"
check "$($PQ getnewmldsaaddress 2>&1 | grep -c -i 'locked')" "1" "getnewmldsaaddress while locked is refused"
check "$($PQ walletpassphrase "wrong passphrase" 60 2>&1 | grep -c -i 'incorrect')" "1" "wrong passphrase rejected (CheckDecryptionKey covers ML-DSA)"
$PQ walletpassphrase "$PASS" 300 >/dev/null
check "$($PQ getwalletinfo | py 'import sys,json; print(int(json.load(sys.stdin)["unlocked_until"]>0))')" "1" "unlocked with the right passphrase"

say "== spend after unlock; new key written encrypted =="
TX0=$($PQ -named send outputs="{\"$M\":2}" options="{\"inputs\":$($PQ listunspent | one_input "$A0"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#TX0}" "64" "v2 spend after unlock returned a txid"
if [ "${#TX0}" = "64" ]; then check "$($CLI getrawtransaction "$TX0" true | py 'import sys,json; w=json.load(sys.stdin)["vin"][0]["txinwitness"]; print(len(w[0])//2, w[0][:6])')" "3735 510101" "witness is a 3735-byte ML-DSA-44 attestation"; fi
A1=$($PQ getnewmldsaaddress enc1)
check "${A1:0:6}" "bcrt1z" "new v2 address created while unlocked"
$MINER sendtoaddress "$A1" 3 >/dev/null; $CLI generatetoaddress 1 "$M" >/dev/null
[ "${#TX0}" = "64" ] && check "$($PQ gettransaction "$TX0" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "spend confirmed"
$PQ walletlock >/dev/null

say "== on-disk records (node stopped) =="
$CLI stop >/dev/null; sleep 2
# 3 encrypted: the original key (converted), the key encryptwallet created when it re-ran descriptor setup with a fresh
# seed (Core does this for descriptor wallets; our hook adds an ML-DSA key too), and the getnewmldsaaddress key.
check "$(db_counts)" "0 3" "wallet.dat: 0 plaintext ML-DSA records, 3 encrypted"
check "$(py 'import sys,sqlite3; c=sqlite3.connect(sys.argv[1]); print(sum(1 for (k,) in c.execute("select key from main") if b"wpq(" in k or b"wpq(" in bytes(c.execute("select value from main where key=?",(k,)).fetchone()[0])))' "$D/regtest/wallets/pq/wallet.dat")" "3" "wallet.dat: 3 wpq() descriptors"
check "$(grep -c 'Qcoin: loaded' "$D/regtest/debug.log")" "0" "sanity: no load lines yet from a restart"

say "== restart: encrypted records load, unlock, spend from the new key =="
start_node "-wallet=pq -wallet=miner"
check "$(grep -c 'ML-DSA key(s) for descriptor .* (0 plaintext, 1 encrypted)' "$D/regtest/debug.log")" "3" "all three pq wpq() descriptors loaded one encrypted ML-DSA key"
check "$($PQ getaddressinfo "$A1" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "True True" "A1 ismine and solvable after restart (public key available while locked)"
check "$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$($PQ listunspent | one_input "$A1"),\"add_inputs\":false}" 2>&1 | locked_send_result)" "False False" "spend while locked after restart cannot sign (unsigned PSBT)"
$PQ walletpassphrase "$PASS" 300 >/dev/null
TX1=$($PQ -named send outputs="{\"$M\":1}" options="{\"inputs\":$($PQ listunspent | one_input "$A1"),\"add_inputs\":false}" 2>&1 | txid_of)
check "${#TX1}" "64" "spend from A1 after restart+unlock returned a txid"
if [ "${#TX1}" = "64" ]; then $CLI generatetoaddress 1 "$M" >/dev/null; check "$($PQ gettransaction "$TX1" | py 'import sys,json; print(json.load(sys.stdin)["confirmations"])')" "1" "A1 spend confirmed"; fi
MA=$($MINER getaddressesbylabel mldsa | py 'import sys,json; print(list(json.load(sys.stdin).keys())[0])')
check "$($MINER getaddressinfo "$MA" | py 'import sys,json; d=json.load(sys.stdin); print(d["ismine"], d["solvable"])')" "True True" "unencrypted miner wallet unaffected"
$CLI stop >/dev/null
[ $fail -eq 0 ] && say "V2 ENCRYPT REGTEST OK" || say "V2 ENCRYPT REGTEST FAILED"
exit $fail
