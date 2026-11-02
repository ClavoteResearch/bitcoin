// Qcoin: RandomX proof-of-work hash (light mode and optional full-dataset mode, keyed caches). See randomx_pow.h.
#include "randomx_pow.h"

#include "randomx/src/randomx.h"

#include <algorithm>
#include <atomic>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace qcoin::pow {
namespace {

std::atomic<bool> g_full_mode{false};
std::atomic<uint64_t> g_hashes_light{0};
std::atomic<uint64_t> g_hashes_full{0};

// A holder is shared and read-only once built. RandomX hashes are identical whatever the flags (JIT, hardware AES,
// Argon2 implementation, cache or dataset), so using the best flags the CPU supports does not affect consensus.
struct CacheHolder {
    randomx_cache* cache{nullptr};
    randomx_flags flags{RANDOMX_FLAG_DEFAULT};
    randomx_dataset* dataset{nullptr};          // full mode only
    std::atomic<bool> dataset_ready{false};
    std::atomic<bool> stop{false};
    std::thread builder;

    ~CacheHolder()
    {
        stop.store(true);
        if (builder.joinable()) builder.join();
        if (dataset) randomx_release_dataset(dataset);
        if (cache) randomx_release_cache(cache);
    }

    // Build the 2 GiB dataset from the cache in the background, in chunks so that destruction can interrupt it.
    void StartDatasetBuild()
    {
        dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
        if (!dataset) return; // out of memory: this key stays in light mode
        const unsigned threads = std::max(1u, std::thread::hardware_concurrency());
        builder = std::thread([this, threads] {
            const unsigned long items = randomx_dataset_item_count();
            const unsigned long chunk = 1UL << 15;
            std::atomic<unsigned long> next{0};
            auto work = [&] {
                for (;;) {
                    if (stop.load(std::memory_order_relaxed)) return;
                    const unsigned long start = next.fetch_add(chunk);
                    if (start >= items) return;
                    randomx_init_dataset(dataset, cache, start, std::min(chunk, items - start));
                }
            };
            std::vector<std::thread> workers;
            for (unsigned t = 1; t < threads; ++t) workers.emplace_back(work);
            work();
            for (auto& w : workers) w.join();
            if (!stop.load()) dataset_ready.store(true, std::memory_order_release);
        });
    }
};

// Light mode: the current and the previous epoch. Full mode adds the next epoch, prepared in advance.
size_t MaxCachedKeys() { return g_full_mode.load() ? 3 : 2; }

std::mutex g_cache_mutex;
std::list<std::pair<std::string, std::shared_ptr<CacheHolder>>> g_caches; // most recently used first

std::shared_ptr<CacheHolder> GetCache(const unsigned char* key, size_t key_len)
{
    const std::string k(reinterpret_cast<const char*>(key), key_len);
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    for (auto it = g_caches.begin(); it != g_caches.end(); ++it) {
        if (it->first == k) {
            g_caches.splice(g_caches.begin(), g_caches, it);
            return g_caches.front().second;
        }
    }
    auto holder = std::make_shared<CacheHolder>();
    // The dataset is requested explicitly and the large-pages flag is never used.
    holder->flags = static_cast<randomx_flags>(randomx_get_flags() & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES));
    holder->cache = randomx_alloc_cache(holder->flags);
    if (!holder->cache) {
        holder->flags = RANDOMX_FLAG_DEFAULT; // portable interpreter
        holder->cache = randomx_alloc_cache(holder->flags);
    }
    if (!holder->cache) throw std::runtime_error("RandomX: cannot allocate the 256 MiB cache");
    randomx_init_cache(holder->cache, key, key_len);
    if (g_full_mode.load()) holder->StartDatasetBuild();
    g_caches.emplace_front(k, holder);
    // An evicted holder lives until its last user finishes; its dataset build is stopped when it is destroyed.
    while (g_caches.size() > MaxCachedKeys()) g_caches.pop_back();
    return holder;
}

// One light-mode VM (bound to a cache) and one full-mode VM (bound to a dataset) per thread, created on demand. The
// bound holder is only remembered weakly, so an evicted key's memory is released once its users are done; a VM is
// always rebound to the holder in use before it hashes.
struct ThreadVms {
    randomx_vm* light{nullptr};
    randomx_vm* full{nullptr};
    std::weak_ptr<CacheHolder> light_bound, full_bound;
    ~ThreadVms()
    {
        if (light) randomx_destroy_vm(light);
        if (full) randomx_destroy_vm(full);
    }
};

bool Bound(const std::weak_ptr<CacheHolder>& w, const std::shared_ptr<CacheHolder>& h)
{
    const auto locked = w.lock();
    return locked && locked == h;
}

randomx_vm& GetLightVm(ThreadVms& tvm, const std::shared_ptr<CacheHolder>& h)
{
    if (!tvm.light) {
        tvm.light = randomx_create_vm(h->flags, h->cache, nullptr);
        if (!tvm.light) tvm.light = randomx_create_vm(RANDOMX_FLAG_DEFAULT, h->cache, nullptr);
        if (!tvm.light) throw std::runtime_error("RandomX: cannot create a virtual machine");
        tvm.light_bound = h;
    } else if (!Bound(tvm.light_bound, h)) {
        randomx_vm_set_cache(tvm.light, h->cache);
        tvm.light_bound = h;
    }
    return *tvm.light;
}

randomx_vm& GetFullVm(ThreadVms& tvm, const std::shared_ptr<CacheHolder>& h)
{
    const randomx_flags full_flags = static_cast<randomx_flags>(h->flags | RANDOMX_FLAG_FULL_MEM);
    if (!tvm.full) {
        tvm.full = randomx_create_vm(full_flags, nullptr, h->dataset);
        if (!tvm.full) tvm.full = randomx_create_vm(static_cast<randomx_flags>(RANDOMX_FLAG_FULL_MEM), nullptr, h->dataset);
        if (!tvm.full) throw std::runtime_error("RandomX: cannot create a full-mode virtual machine");
        tvm.full_bound = h;
    } else if (!Bound(tvm.full_bound, h)) {
        randomx_vm_set_dataset(tvm.full, h->dataset);
        tvm.full_bound = h;
    }
    return *tvm.full;
}

} // namespace

void RandomXHash(const unsigned char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char out[32])
{
    const std::shared_ptr<CacheHolder> holder = GetCache(key, key_len);
    thread_local ThreadVms tvm;
    if (holder->dataset && holder->dataset_ready.load(std::memory_order_acquire)) {
        g_hashes_full.fetch_add(1, std::memory_order_relaxed);
        randomx_calculate_hash(&GetFullVm(tvm, holder), data, len, out);
    } else {
        g_hashes_light.fetch_add(1, std::memory_order_relaxed);
        randomx_calculate_hash(&GetLightVm(tvm, holder), data, len, out);
    }
}

void SetRandomXFullMode(bool full) { g_full_mode.store(full); }
bool RandomXFullMode() { return g_full_mode.load(); }

namespace {
// Prepares one key at a time on a helper thread (building a cache takes about a second and must not stall the caller,
// which is the validation thread holding cs_main). The dataset itself is built by GetCache's own background threads.
struct Preparer {
    std::mutex mutex;
    std::string last_key;
    std::thread thread;
    ~Preparer()
    {
        if (thread.joinable()) thread.join();
    }
};
Preparer g_preparer;
} // namespace

void PrepareRandomXKey(const unsigned char* key, size_t key_len)
{
    if (!g_full_mode.load()) return;
    const std::string k(reinterpret_cast<const char*>(key), key_len);
    std::lock_guard<std::mutex> lock(g_preparer.mutex);
    if (k == g_preparer.last_key) return;
    g_preparer.last_key = k;
    if (g_preparer.thread.joinable()) g_preparer.thread.join(); // the previous key was prepared an epoch ago
    g_preparer.thread = std::thread([k] {
        try {
            GetCache(reinterpret_cast<const unsigned char*>(k.data()), k.size()); // builds the cache and starts the dataset
        } catch (const std::exception&) {
            // out of memory: the key is built on first use instead
        }
    });
}

RandomXStatus GetRandomXStatus()
{
    RandomXStatus st;
    st.full_mode = g_full_mode.load();
    st.hashes_light = g_hashes_light.load();
    st.hashes_full = g_hashes_full.load();
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    st.keys_cached = g_caches.size();
    for (const auto& entry : g_caches) {
        if (!entry.second->dataset) continue;
        if (entry.second->dataset_ready.load()) ++st.datasets_ready;
        else ++st.datasets_building;
    }
    return st;
}

} // namespace qcoin::pow
