// qtc-randomx-scan: RandomX nonce scanner used by qtc-gbt-miner.py (the RandomX counterpart of qtc-nonce-scan.c).
//
//   qtc-randomx-scan HEADER76_HEX TARGET64_HEX START STRIDE [MAXCOUNT]
//   qtc-randomx-scan --selftest
//
// HEADER76_HEX is the 76 header bytes before the nonce (version, previous hash, merkle root, time, bits), TARGET64_HEX the
// 256-bit target (big-endian hex). It tries nonces START, START+STRIDE, ... with RandomX over the 80-byte header and prints
// the first nonce whose hash, read as a little-endian 256-bit number like a block hash, is at or below the target, or
// "none". With MAXCOUNT it stops after that many tries per thread and prints "none <hashes_per_second>" (a benchmark).
//
// Environment: QTC_RX_KEY=<hex> (required: the RandomX key of the block being mined, i.e. the "randomxkey" field of the
// getblocktemplate result: the identifier of the key block as 32 raw bytes in internal order, hex),
// QTC_RX_THREADS=<n> (default: all hardware threads), QTC_RX_FAST=1 (use the 2 GiB dataset: about
// ten times the hash rate after a start-up of tens of seconds; default is the 256 MiB cache, which is what nodes use).
// The thread t of n scans START + t*STRIDE, START + (t+n)*STRIDE, ...
// --selftest checks the RandomX known-answer vector of the upstream test suite (key "test key 000", input "This is a test").
#include "../src/crypto/randomx/src/randomx.h"
#include "../src/crypto/randomx_pow.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

int Hv(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

bool LessOrEqualTarget(const unsigned char* hash, const unsigned char* target_be)
{
    for (int k = 0; k < 32; ++k) { // most significant byte of the hash is hash[31]
        const unsigned char a = hash[31 - k], b = target_be[k];
        if (a < b) return true;
        if (a > b) return false;
    }
    return true;
}

int SelfTest()
{
    randomx_flags flags = static_cast<randomx_flags>(randomx_get_flags() & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES));
    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) { flags = RANDOMX_FLAG_DEFAULT; cache = randomx_alloc_cache(flags); }
    if (!cache) { std::fprintf(stderr, "cannot allocate the cache\n"); return 1; }
    const char key[] = "test key 000";
    randomx_init_cache(cache, key, sizeof(key) - 1);
    randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
    if (!vm) { std::fprintf(stderr, "cannot create a vm\n"); return 1; }
    const char input[] = "This is a test";
    unsigned char out[32];
    randomx_calculate_hash(vm, input, sizeof(input) - 1, out);
    static const char* want = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f";
    char got[65];
    for (int i = 0; i < 32; ++i) std::snprintf(got + 2 * i, 3, "%02x", out[i]);
    randomx_destroy_vm(vm);
    randomx_release_cache(cache);
    const bool ok = std::strcmp(got, want) == 0;
    std::printf("randomx known answer: %s (%s)\n", got, ok ? "ok" : "MISMATCH");
    // The node's wrapper must agree with the library and keep keys apart: same key and input, same hash; another
    // key, another hash; and the known-answer vector again through the wrapper.
    unsigned char a[32], b[32], c[32], d[32];
    const unsigned char hdr[80] = {1};
    const unsigned char key1[32] = {1}, key2[32] = {2};
    qcoin::pow::RandomXHash(key1, sizeof(key1), hdr, sizeof(hdr), a);
    qcoin::pow::RandomXHash(key2, sizeof(key2), hdr, sizeof(hdr), c);
    qcoin::pow::RandomXHash(key1, sizeof(key1), hdr, sizeof(hdr), b);
    qcoin::pow::RandomXHash(reinterpret_cast<const unsigned char*>(key), sizeof(key) - 1, reinterpret_cast<const unsigned char*>(input), sizeof(input) - 1, d);
    char got2[65];
    for (int i = 0; i < 32; ++i) std::snprintf(got2 + 2 * i, 3, "%02x", d[i]);
    const bool det = std::memcmp(a, b, 32) == 0 && std::memcmp(a, c, 32) != 0 && std::strcmp(got2, want) == 0;
    std::printf("node wrapper: deterministic, key-dependent, known answer: %s\n", det ? "ok" : "MISMATCH");
    return ok && det ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--selftest") == 0) return SelfTest();
    if (argc < 5 || std::strlen(argv[1]) != 152 || std::strlen(argv[2]) != 64) {
        std::fprintf(stderr, "usage: %s HEADER76_HEX TARGET64_HEX START STRIDE [MAXCOUNT]\n       %s --selftest\n", argv[0], argv[0]);
        return 2;
    }
    unsigned char h76[76], target[32];
    for (int i = 0; i < 76; ++i) h76[i] = static_cast<unsigned char>(Hv(argv[1][2 * i]) << 4 | Hv(argv[1][2 * i + 1]));
    for (int i = 0; i < 32; ++i) target[i] = static_cast<unsigned char>(Hv(argv[2][2 * i]) << 4 | Hv(argv[2][2 * i + 1]));
    const uint64_t start = std::strtoull(argv[3], nullptr, 10), stride = std::strtoull(argv[4], nullptr, 10);
    const uint64_t maxcount = argc > 5 ? std::strtoull(argv[5], nullptr, 10) : 0;
    unsigned nthreads = std::thread::hardware_concurrency();
    if (const char* t = std::getenv("QTC_RX_THREADS")) nthreads = static_cast<unsigned>(std::strtoul(t, nullptr, 10));
    if (nthreads == 0) nthreads = 1;
    const bool fast = std::getenv("QTC_RX_FAST") && std::strcmp(std::getenv("QTC_RX_FAST"), "1") == 0;

    const char* key_env = std::getenv("QTC_RX_KEY");
    if (!key_env || std::strlen(key_env) == 0 || std::strlen(key_env) % 2) {
        std::fprintf(stderr, "set QTC_RX_KEY to the block template's randomxkey (hex)\n");
        return 2;
    }
    std::vector<unsigned char> rx_key;
    for (size_t i = 0; i + 1 < std::strlen(key_env) + 1 && key_env[i]; i += 2) rx_key.push_back(static_cast<unsigned char>(Hv(key_env[i]) << 4 | Hv(key_env[i + 1])));
    randomx_flags flags = static_cast<randomx_flags>(randomx_get_flags() & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES));
    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) { flags = RANDOMX_FLAG_DEFAULT; cache = randomx_alloc_cache(flags); }
    if (!cache) { std::fprintf(stderr, "cannot allocate the RandomX cache\n"); return 1; }
    randomx_init_cache(cache, rx_key.data(), rx_key.size());
    randomx_dataset* dataset = nullptr;
    if (fast) {
        dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
        if (!dataset) { std::fprintf(stderr, "cannot allocate the 2 GiB dataset (use light mode)\n"); return 1; }
        const unsigned long items = randomx_dataset_item_count();
        std::vector<std::thread> init;
        for (unsigned t = 0; t < nthreads; ++t) {
            const unsigned long a = items * t / nthreads, b = items * (t + 1) / nthreads;
            init.emplace_back([&, a, b] { randomx_init_dataset(dataset, cache, a, b - a); });
        }
        for (auto& th : init) th.join();
        flags = static_cast<randomx_flags>(flags | RANDOMX_FLAG_FULL_MEM);
    }

    std::atomic<bool> done{false};
    std::atomic<uint64_t> winner{UINT64_MAX};
    std::atomic<uint64_t> total_tries{0};
    const auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (unsigned t = 0; t < nthreads; ++t) {
        workers.emplace_back([&, t] {
            randomx_vm* vm = randomx_create_vm(flags, dataset ? nullptr : cache, dataset);
            if (!vm) { done = true; return; }
            unsigned char hdr[80];
            std::memcpy(hdr, h76, 76);
            unsigned char hash[32];
            uint64_t tries = 0;
            for (uint64_t k = t; !done.load(std::memory_order_relaxed); k += nthreads) {
                const uint64_t n = start + k * stride;
                if (n >= (1ULL << 32)) break;
                hdr[76] = n & 255; hdr[77] = (n >> 8) & 255; hdr[78] = (n >> 16) & 255; hdr[79] = (n >> 24) & 255;
                randomx_calculate_hash(vm, hdr, sizeof(hdr), hash);
                ++tries;
                if (LessOrEqualTarget(hash, target)) {
                    uint64_t cur = winner.load();
                    while (n < cur && !winner.compare_exchange_weak(cur, n)) {}
                    done = true;
                    break;
                }
                if (maxcount && tries >= maxcount) break;
            }
            total_tries += tries;
            randomx_destroy_vm(vm);
        });
    }
    for (auto& th : workers) th.join();
    if (dataset) randomx_release_dataset(dataset);
    randomx_release_cache(cache);
    if (winner.load() != UINT64_MAX) {
        std::printf("%llu\n", static_cast<unsigned long long>(winner.load()));
        return 0;
    }
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (maxcount) std::printf("none %.1f\n", static_cast<double>(total_tries.load()) / (secs > 0 ? secs : 1));
    else std::printf("none\n");
    return 0;
}
