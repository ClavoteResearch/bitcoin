/* qtc-nonce-scan: single-thread SHA-256d nonce scanner used by qtc-gbt-miner.py.
 *
 *   qtc-nonce-scan HEADER76_HEX TARGET64_HEX START STRIDE [MAXCOUNT]
 *
 * HEADER76_HEX is the 76 header bytes before the nonce (version, previous hash, merkle root, time, bits), TARGET64_HEX the
 * 256-bit target (big-endian hex). It tries nonces START, START+STRIDE, ... and prints the first nonce whose double SHA-256
 * is at or below the target, or "none". With MAXCOUNT it stops after that many tries and prints "none <hashes_per_second>"
 * (a benchmark). Build: gcc -O3 -march=native -Wno-deprecated-declarations -o qtc-nonce-scan qtc-nonce-scan.c -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>

static int hv(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

int main(int argc, char **argv)
{
    if (argc < 5 || strlen(argv[1]) != 152 || strlen(argv[2]) != 64) { fprintf(stderr, "usage: %s HEADER76_HEX TARGET64_HEX START STRIDE [MAXCOUNT]\n", argv[0]); return 2; }
    unsigned char h76[76], tb[32];
    for (int i = 0; i < 76; i++) h76[i] = (unsigned char)(hv(argv[1][2 * i]) << 4 | hv(argv[1][2 * i + 1]));
    for (int i = 0; i < 32; i++) tb[i] = (unsigned char)(hv(argv[2][2 * i]) << 4 | hv(argv[2][2 * i + 1]));
    uint64_t start = strtoull(argv[3], 0, 10), stride = strtoull(argv[4], 0, 10), maxcount = argc > 5 ? strtoull(argv[5], 0, 10) : 0, tries = 0;
    SHA256_CTX base; SHA256_Init(&base); SHA256_Update(&base, h76, 64);
    unsigned char tail[16]; memcpy(tail, h76 + 64, 12);
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t n = start; n < (1ULL << 32); n += stride) {
        tail[12] = n & 255; tail[13] = (n >> 8) & 255; tail[14] = (n >> 16) & 255; tail[15] = (n >> 24) & 255;
        SHA256_CTX c = base; unsigned char d1[32], d2[32];
        SHA256_Update(&c, tail, 16); SHA256_Final(d1, &c); SHA256(d1, 32, d2);
        int ok = 1;
        for (int k = 0; k < 32; k++) {              /* most significant byte of the hash is d2[31] */
            unsigned char a = d2[31 - k], b = tb[k];
            if (a < b) break;
            if (a > b) { ok = 0; break; }
        }
        if (ok) { printf("%llu\n", (unsigned long long)n); return 0; }
        if (maxcount && ++tries >= maxcount) {
            struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
            printf("none %.0f\n", tries / ((t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9));
            return 0;
        }
    }
    printf("none\n");
    return 0;
}
