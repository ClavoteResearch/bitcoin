// Qcoin test helper: LD_PRELOAD interposer for OQS_SIG_sign_with_ctx_str / OQS_SIG_sign that counts the copies of a known ML-DSA
// secret key in the signing process's own memory when the signature starts and when it returns.
//
//   gcc -O1 -shared -fPIC memscan_preload.c -o memscan_preload.so -ldl
//   QCOIN_MEMSCAN_SK=<file with the secret key> QCOIN_MEMSCAN_LOG=<log file> LD_PRELOAD=./memscan_preload.so bitcoind ...
//
// Counted in anonymous private mappings (heap, stacks, locked pool arenas), not in file-backed ones. The needle and the read
// buffer live in the interposer's initialised data (file-backed), so they are never counted themselves.
// Log line per signature: "sign enter full=<n> K=<n> | leave full=<n> K=<n>"
//   full = whole secret key (a copy of the key), K = the 32-byte signing seed sk[32:64] (also found in unpacked remnants).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define CHUNK (1u << 20)
static unsigned char g_sk[8192] = {1};
static size_t g_sk_len = 0;
static unsigned char g_buf[CHUNK + 8192] = {1};
static int g_loaded = 0;
static size_t g_key_len = 0;

static void load_needle(void)
{
    g_loaded = 1;
    const char* path = getenv("QCOIN_MEMSCAN_SK");
    if (!path) return;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, g_sk, sizeof g_sk);
    close(fd);
    if (n >= 64) g_sk_len = (size_t)n;
    // the needle may be a prefix of the key (QCOIN_MEMSCAN_KEYLEN is then the real key length, which the wipe is recognised by)
    const char* kl = getenv("QCOIN_MEMSCAN_KEYLEN");
    g_key_len = kl ? (size_t)strtoul(kl, NULL, 10) : g_sk_len;
}

static void count_in(const unsigned char* data, size_t len, size_t* full, size_t* k)
{
    const unsigned char* p = data;
    size_t left = len;
    while (g_sk_len && left >= g_sk_len && (p = memmem(p, left, g_sk, g_sk_len))) { ++*full; ++p; left = len - (size_t)(p - data); }
    p = data; left = len;
    while (g_sk_len && left >= 32 && (p = memmem(p, left, g_sk + 32, 32))) { ++*k; ++p; left = len - (size_t)(p - data); }
}

static void scan(size_t* full, size_t* k)
{
    *full = *k = 0;
    if (!g_sk_len) return;
    FILE* maps = fopen("/proc/self/maps", "r");
    int mem = open("/proc/self/mem", O_RDONLY);
    if (!maps || mem < 0) { if (maps) fclose(maps); if (mem >= 0) close(mem); return; }
    char line[512];
    while (fgets(line, sizeof line, maps)) {
        unsigned long start, end;
        char perms[8], path[400] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %399[^\n]", &start, &end, perms, path) < 3) continue;
        if (perms[0] != 'r' || perms[3] != 'p') continue;
        const char* pp = path;
        while (*pp == ' ') ++pp;
        if (*pp == '/' || !strncmp(pp, "[vvar", 5) || !strncmp(pp, "[vdso", 5) || !strncmp(pp, "[vsys", 5)) continue;
        for (unsigned long off = start; off < end; off += CHUNK) {
            size_t want = end - off < CHUNK + g_sk_len ? end - off : CHUNK + g_sk_len; // overlap so a copy across a chunk edge is found
            ssize_t got = pread(mem, g_buf, want, (off_t)off);
            if (got <= 0) break;
            count_in(g_buf, (size_t)got, full, k);
            if (off + CHUNK >= end) break;
        }
    }
    fclose(maps);
    close(mem);
}

// The part of this thread's stack below the current frame, where the signer's own frames (unpacked s1, s2, t0, K) were just
// popped. Plain loops only, no calls, so nothing here overwrites what is being looked at. The stack bounds are fetched
// before the signature (stack_bounds) so that the lookup itself does not use the stack that is inspected.
static size_t g_dead_k;
static const unsigned char* g_stack_low;
__attribute__((noinline)) static void stack_bounds(void)
{
    pthread_attr_t at;
    void* low = NULL; size_t sz = 0;
    g_stack_low = NULL;
    if (pthread_getattr_np(pthread_self(), &at) != 0) return;
    pthread_attr_getstack(&at, &low, &sz);
    pthread_attr_destroy(&at);
    g_stack_low = (const unsigned char*)low;
}

__attribute__((noinline)) static void dead_stack_scan(void)
{
    g_dead_k = 0;
    if (!g_sk_len || !g_stack_low) return;
    volatile unsigned char probe;
    const unsigned char* hi = (const unsigned char*)&probe - 512;
    const unsigned char* lo = hi - 256 * 1024;
    if (lo < g_stack_low) lo = g_stack_low;
    for (const unsigned char* q = lo; q + 32 <= hi; ++q) {
        size_t i = 0;
        while (i < 32 && q[i] == g_sk[32 + i]) ++i;
        if (i == 32) ++g_dead_k;
    }
}

static void log_line(const char* what, size_t f0, size_t k0, size_t f1, size_t k1)
{
    const char* path = getenv("QCOIN_MEMSCAN_LOG");
    if (!path) return;
    FILE* f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%s enter full=%zu K=%zu | leave full=%zu K=%zu | dead stack below the signer K=%zu\n", what, f0, k0, f1, k1, g_dead_k);
    fclose(f);
}

// OQS_MEM_cleanse of exactly the secret key's length is the wallet wiping its copy right after the signature: the stack below
// the wiper is then looked at once more (after the code under test has scrubbed it).
typedef void (*cleanse_fn)(void*, size_t);
void OQS_MEM_cleanse(void* ptr, size_t len)
{
    static cleanse_fn real;
    if (!real) real = (cleanse_fn)dlsym(RTLD_NEXT, "OQS_MEM_cleanse");
    if (!g_loaded) load_needle();
    const int is_key = g_sk_len && len == g_key_len;
    if (is_key) stack_bounds();
    real(ptr, len);
    if (is_key) {
        dead_stack_scan();
        const char* path = getenv("QCOIN_MEMSCAN_LOG");
        FILE* f = path ? fopen(path, "a") : NULL;
        if (f) { fprintf(f, "key wiped: dead stack below the wiper K=%zu\n", g_dead_k); fclose(f); }
    }
}

typedef int (*sign_ctx_fn)(void*, unsigned char*, size_t*, const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*);

int OQS_SIG_sign_with_ctx_str(void* sig, unsigned char* signature, size_t* signature_len, const unsigned char* message, size_t message_len,
                              const unsigned char* ctx, size_t ctx_len, const unsigned char* secret_key)
{
    static sign_ctx_fn real;
    if (!real) real = (sign_ctx_fn)dlsym(RTLD_NEXT, "OQS_SIG_sign_with_ctx_str");
    if (!g_loaded) load_needle();
    size_t f0, k0, f1, k1;
    scan(&f0, &k0);
    stack_bounds();
    int rc = real(sig, signature, signature_len, message, message_len, ctx, ctx_len, secret_key);
    dead_stack_scan();
    scan(&f1, &k1);
    log_line("sign", f0, k0, f1, k1);
    return rc;
}
