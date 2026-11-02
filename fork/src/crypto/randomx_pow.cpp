// Qcoin: RandomX proof-of-work hash (light mode). See randomx_pow.h.
#include "randomx_pow.h"

#include "randomx/src/randomx.h"

#include <memory>
#include <mutex>
#include <stdexcept>

namespace qcoin::pow {
namespace {

// The cache is shared and read-only once built. RandomX hashes are identical whatever the flags (JIT, hardware AES,
// Argon2 implementation), so using the best flags the CPU supports does not affect consensus.
struct SharedCache {
    randomx_cache* cache{nullptr};
    randomx_flags flags{RANDOMX_FLAG_DEFAULT};
    ~SharedCache()
    {
        if (cache) randomx_release_cache(cache);
    }
};

SharedCache& GetSharedCache()
{
    static SharedCache shared;
    static std::once_flag once;
    std::call_once(once, [] {
        // Light mode never uses the dataset or large pages.
        randomx_flags flags = static_cast<randomx_flags>(randomx_get_flags() & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES));
        randomx_cache* cache = randomx_alloc_cache(flags);
        if (!cache) {
            flags = RANDOMX_FLAG_DEFAULT; // portable interpreter
            cache = randomx_alloc_cache(flags);
        }
        if (!cache) throw std::runtime_error("RandomX: cannot allocate the 256 MiB cache");
        randomx_init_cache(cache, RANDOMX_KEY, RANDOMX_KEY_LEN);
        shared.cache = cache;
        shared.flags = flags;
    });
    if (!shared.cache) throw std::runtime_error("RandomX: cache unavailable");
    return shared;
}

struct VmDeleter {
    void operator()(randomx_vm* vm) const { randomx_destroy_vm(vm); }
};

randomx_vm& GetThreadVm()
{
    thread_local std::unique_ptr<randomx_vm, VmDeleter> vm;
    if (!vm) {
        SharedCache& shared = GetSharedCache();
        randomx_vm* created = randomx_create_vm(shared.flags, shared.cache, nullptr);
        if (!created) created = randomx_create_vm(RANDOMX_FLAG_DEFAULT, shared.cache, nullptr);
        if (!created) throw std::runtime_error("RandomX: cannot create a virtual machine");
        vm.reset(created);
    }
    return *vm;
}

} // namespace

void RandomXHash(const unsigned char* data, size_t len, unsigned char out[32])
{
    randomx_calculate_hash(&GetThreadVm(), data, len, out);
}

} // namespace qcoin::pow
