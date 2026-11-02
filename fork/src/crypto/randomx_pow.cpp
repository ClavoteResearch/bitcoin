// Qcoin: RandomX proof-of-work hash (light mode, keyed caches). See randomx_pow.h.
#include "randomx_pow.h"

#include "randomx/src/randomx.h"

#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace qcoin::pow {
namespace {

// A cache is shared and read-only once built. RandomX hashes are identical whatever the flags (JIT, hardware AES,
// Argon2 implementation), so using the best flags the CPU supports does not affect consensus.
struct CacheHolder {
    randomx_cache* cache{nullptr};
    randomx_flags flags{RANDOMX_FLAG_DEFAULT};
    ~CacheHolder()
    {
        if (cache) randomx_release_cache(cache);
    }
};

constexpr size_t MAX_CACHED_KEYS = 2;

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
    // Light mode never uses the dataset or large pages.
    holder->flags = static_cast<randomx_flags>(randomx_get_flags() & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES));
    holder->cache = randomx_alloc_cache(holder->flags);
    if (!holder->cache) {
        holder->flags = RANDOMX_FLAG_DEFAULT; // portable interpreter
        holder->cache = randomx_alloc_cache(holder->flags);
    }
    if (!holder->cache) throw std::runtime_error("RandomX: cannot allocate the 256 MiB cache");
    randomx_init_cache(holder->cache, key, key_len);
    g_caches.emplace_front(k, holder);
    while (g_caches.size() > MAX_CACHED_KEYS) g_caches.pop_back(); // threads using an evicted cache keep it alive
    return holder;
}

struct ThreadVm {
    randomx_vm* vm{nullptr};
    std::shared_ptr<CacheHolder> cache;
    ~ThreadVm()
    {
        if (vm) randomx_destroy_vm(vm);
    }
};

randomx_vm& GetThreadVm(const std::shared_ptr<CacheHolder>& wanted)
{
    thread_local ThreadVm tvm;
    if (!tvm.vm) {
        tvm.vm = randomx_create_vm(wanted->flags, wanted->cache, nullptr);
        if (!tvm.vm) tvm.vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, wanted->cache, nullptr);
        if (!tvm.vm) throw std::runtime_error("RandomX: cannot create a virtual machine");
        tvm.cache = wanted;
    } else if (tvm.cache != wanted) {
        randomx_vm_set_cache(tvm.vm, wanted->cache);
        tvm.cache = wanted; // releases the previous cache if this thread was its last user
    }
    return *tvm.vm;
}

} // namespace

void RandomXHash(const unsigned char* key, size_t key_len, const unsigned char* data, size_t len, unsigned char out[32])
{
    const std::shared_ptr<CacheHolder> cache = GetCache(key, key_len);
    randomx_calculate_hash(&GetThreadVm(cache), data, len, out);
}

} // namespace qcoin::pow
