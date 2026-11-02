# liboqs pin

Qcoin verifies ML-DSA signatures with [liboqs](https://github.com/open-quantum-safe/liboqs) in the consensus path
(`CheckMlDsaSignature`, `fork/src/script/witness_v2.h`). A different liboqs version, or a different build of the same version,
is a different consensus rule set, so the library is pinned and the build refuses anything else.

## The pin

| | |
|---|---|
| Version | `0.14.0` |
| Tag | `0.14.0` |
| Commit | `94b421ebb82405c843dba4e9aa521a56ee5a333d` |
| Repository | `https://github.com/open-quantum-safe/liboqs.git` |
| Configuration | portable build: `-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic -DOQS_USE_OPENSSL=ON` (no AVX2 ML-DSA code, see finding 1) |

Where it lives:
- `fork/third_party/liboqs/PIN`: the values above (`KEY=VALUE`, read by the script and by CMake).
- `fork/contrib/build-liboqs.sh PREFIX [JOBS]`: clones the tag, **refuses to build unless the checked-out commit is the pinned one**,
  builds the pinned configuration, installs it into `PREFIX`, and checks that the installed `oqsconfig.h` reports the pinned
  version and does not enable the AVX2 ML-DSA implementations.
- `src/CMakeLists.txt`: configure fails if the liboqs it finds has another version or enables the AVX2 ML-DSA implementations.
  `-DQCOIN_ALLOW_UNPINNED_LIBOQS=ON` turns the error into a warning for development; a binary built that way must not validate a
  public chain.

Clean build:

```bash
fork/contrib/build-liboqs.sh $HOME/liboqs-pinned
cmake -B build -DENABLE_IPC=OFF -DCMAKE_PREFIX_PATH=$HOME/liboqs-pinned   # add -DQCOIN_WITNESS_V2_EXPERIMENTAL=ON for ML-DSA-87
cmake --build build
```

(a system-wide `liboqs` in `/usr/local` or from a distribution is found only if `CMAKE_PREFIX_PATH` does not point at the pin,
and is then rejected unless it happens to be this exact portable configuration.)

## What the earlier binaries were linked to

Recorded before the pin, from the `build` and `build-v2` directories of the development checkout:

| | |
|---|---|
| Library | `/usr/local/lib/liboqs.so.0.14.0` (SONAME `liboqs.so.8`), 12,287,352 bytes, installed 2026-10-30 12:13 |
| SHA-256 of the file | `469d0017341efb3483905d498258eff6563fe9c2beb958e3d78b4ce44efa900c` |
| Headers | `/usr/local/include/oqs` (`OQS_VERSION_TEXT "0.14.0"`), `pkgconfig` version 0.14.0 |
| Source | `/root/src/liboqs`, `git describe` = `0.14.0`, commit `94b421ebb82405c843dba4e9aa521a56ee5a333d` (the tag; an unmodified clone of the upstream repository) |
| Configuration | `OQS_DIST_BUILD=1`, `OQS_OPT_TARGET "generic"`, OpenSSL on, **`OQS_ENABLE_SIG_ml_dsa_44_avx2`, `_65_avx2` and `_87_avx2` enabled**: AVX2 ML-DSA code compiled in and chosen at run time on CPUs that have AVX2 and POPCNT (`sig_ml_dsa_*.c`) |

So the version was already 0.14.0 at that commit; the pin keeps the version and changes the configuration (finding 1). The portable
library built by the pin has another file hash (`3b4c0919171cebc20ea6ad1384f399c6804fb5fd7f940d22767ecb8d05eecd80`, 5,431,496 bytes on
the development machine); shared-object hashes are not reproducible across machines, so the pin is the commit plus the configuration.

## Advisory review (2026-11-02)

Sources are public web pages and mailing-list posts read on that date; where only a search result or a summary was available it is
said. Nothing below was tested against attack vectors; the code claims in finding 1 are from reading the 0.14.0 source.

### 1. The AVX2 ML-DSA verifier of liboqs 0.14.0 lacks two FIPS 204 checks: handled by the pin

On 2026-06-03/04 the pq-crystals reference repository fixed, and Eric Biggers reported on the NIST
[pqc-forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/BJaNS6BkTaE), two bugs in the **AVX2** ML-DSA (Dilithium) verifier that
"caused the verifier to accept some invalid signatures"; the portable `ref/` code is not affected, and "projects that have copied this AVX2
code should apply these fixes":

1. `crypto_sign_verify_internal()` in `avx2/sign.c` did not check that every coefficient of `z` is below `GAMMA1 - BETA` (FIPS 204
   Algorithm 8, line 13); fix [d35ba3f](https://github.com/pq-crystals/dilithium/commit/d35ba3fe5449bee3e6d43e1f296c3ca818bd36be)
   (issue [#113](https://github.com/pq-crystals/dilithium/issues/113)).
2. `use_hint_avx()` in `avx2/rounding.c` tested `r0 < 0` where the specification says `r0 <= 0`; fix
   [bba9534](https://github.com/pq-crystals/dilithium/commit/bba9534a3c5cbef66481cd6518d786e23ae601b5).

**liboqs 0.14.0 contains the unfixed AVX2 code** (checked in the tagged source, not run): in
`src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-{44,65,87}_avx2/`, `sign.c` calls `polyz_unpack` in the verifier (line 408 of the
44 variant) with no `poly_chknorm` there (its only calls, lines 248 to 270, are in the signing function) and `rounding.c`
`use_hint_avx` has no `f = _mm256_sub_epi32(f, h)` line that the fix adds. The portable `ref/sign.c` verifier does the check
(line 316). liboqs picks the AVX2 code at run time on x86-64 CPUs that have it when built as a distribution build (as it was), so
a node's verdict on a crafted signature would depend on its CPU.

The liboqs published advisories list (read on 2026-11-02: ten advisories, none about ML-DSA) does not mention this, so the absence of
an advisory is not evidence of absence.

My reading of the impact, not demonstrated: the `z` norm bound leaves only a thin band in the 18-bit packing (`|z| >= 130,994` up to
131,072), and the `UseHint` error needs a hint at a zero low part, so the accepted "invalid" signatures look like ones that only the
holder of the secret key can produce, not forgeries by a third party. That is still a consensus hazard: such a signature would be
valid on AVX2 nodes and invalid on portable ones, splitting the chain on demand by whoever controls the key of an output.

**Handled:** the pin builds the portable configuration only (`OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=generic`), so no node runs the
AVX2 verifier, all nodes run the same reference code, and the configure step rejects a liboqs that enables it.
Cost: the portable code is slower than AVX2 (verification time was not re-measured here).
**Not done (suggested):**
- a library-independent check of the `z` norm in `IsCanonicalMlDsaSignature` (the 18-bit `z` encoding can be decoded without
  the library), as defence in depth against the first bug;
- running the Wycheproof / CCTV ML-DSA vectors named in the reports (the ones for "violate index" and `use_hint(1, 0)`) against the
  pinned build and against the old one, to confirm the difference; they were not downloaded for this review;
- evaluating liboqs 0.16.0 (finding 2).

### 2. Newer liboqs: 0.16.0 changes the ML-DSA implementation (not adopted)

Per the [0.16.0 release notes](https://newreleases.io/project/github/open-quantum-safe/liboqs/release/0.16.0) (2026-07-09, read via a
mirror), mldsa-native is the default implementation behind `ml_dsa_44/65/87` and Wycheproof tests were added for ML-DSA; Dilithium
implementations were removed in 0.15.0. Moving to it would replace the code that verifies consensus signatures and must be done
deliberately (vectors, the self-test, the regtests, a multi-node run) rather than as part of a pin. Later 0.16.x and 0.17.0 releases fix LMS/HSS and XMSS
advisories (finding 6) that do not concern Qcoin.

### 3. CVE-2024-31510: ML-DSA-44 secret key via fault injection: signing only

Recorded against liboqs 0.10.0 (`pqcrystals-dilithium-standard_ml-dsa-44-ipd_avx2/sign.c`, `crypto_sign_signature`), titled "leakable Secret
Key of ML-DSA via Rowhammer" by [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2283376); the
[CVE record](https://cve.circl.lu/vuln/CVE-2024-31510) rates it 9.8 (its description says "escalate privileges", which does not match the
fault-injection title; treat the wording with care) and names no fixed version. It concerns signing on a machine under a physical or
co-tenant fault attack, not verification, and it names the `ipd` (pre-standard) code, which 0.14.0 no longer contains (its directories
are `pqcrystals-dilithium-standard_*`). Wallet hosts should not sign on hardware an attacker can fault; consensus nodes do not sign.

### 4. HQC and KEM advisories: not used

CVE-2025-52473 (secret-dependent branches in HQC) is fixed in 0.14.0 according to its release notes and
[CVE-2025-48946](https://cve.circl.lu/vuln/cve-2025-48946) (a design flaw in HQC) is why HQC is disabled by default since 0.13.0. The
advisories list also holds entries for HQC, Kyber, NTRU and FrodoKEM. Qcoin calls only the ML-DSA signature functions
(`OQS_SIG_*` for `ML-DSA-44` and, in experimental builds, `ML-DSA-87`); no key-encapsulation code runs.

### 5. liboqs-python GHSA-w696-4vrr-x6x3: length checks

The Python wrapper, [0.16.0.2](https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.2), fixed a missing public-key and
ciphertext length check that let a forged ML-DSA signature verify. Qcoin does not use the wrapper, and its verifier checks the exact
public-key and signature lengths before calling the library (`CheckMlDsaSignature`: `pubkey.size() != sizes->pk || sig.size() != sizes->sig`
is `SCRIPT_ERR_MLDSA_ATTESTATION`). The lesson is to keep that check ahead of every liboqs call.

### 6. Stateful signature advisories (LMS/HSS, XMSS): not used

The advisories list read on 2026-11-02 names LMS/HSS (GHSA-xv6c-h66p-6mfq, GHSA-wh5q-mpc8-67wf, fixed in 0.17.0) and XMSS
(GHSA-2wxh-55qf-c7wg, GHSA-wf7v-fhxj-73m2, fixed in 0.16.0). Qcoin never calls them. They are in the library only because the library
is built whole (`OQS_BUILD_ONLY_LIB`); trimming the algorithm set (`-DOQS_MINIMAL_BUILD`) is a possible later hardening that would also
change the file hash.

### 7. Same bug class elsewhere, and the specification

The libcrux ML-DSA advisories ([RUSTSEC-2026-0077](https://osv.dev/vulnerability/RUSTSEC-2026-0077), GHSA-fhvh-vw7h-9xf3: a wrong norm bound and
an AVX2 `use_hint` edge case) and the
[Symbolic Software write-up](https://symbolic.software/blog/2026-02-17-ce-labs-mldsa/) show the same two mistakes in another implementation;
they do not affect Qcoin but support the portable-only choice. The hint-encoding malleability discussed on the pqc-forum (a signature has
more than one accepted encoding unless the hint area is checked) is handled by the canonical-encoding rule in
`doc/WALLET-PQC.md` ("Canonical ML-DSA signature encoding").

## Verification of the pinned build

On the development machine (WSL2 Ubuntu, 16 cores, x86-64 with AVX2):
- `fork/contrib/build-liboqs.sh /root/liboqs-pinned` built the pinned commit in 43 s and passed its checks.
- A fresh build directory configured with `-DCMAKE_PREFIX_PATH=/root/liboqs-pinned` and `-DQCOIN_WITNESS_V2_EXPERIMENTAL=ON` built `bitcoind`,
  `bitcoin-cli`, `qcoin-v2-selftest`, `qcoin-v2-scriptpath` and `qtc-randomx-scan` without errors (233 s), linked to
  `/root/liboqs-pinned/lib/liboqs.so.0.14.0`. The old build directories are rejected by the new configure check unless
  `-DQCOIN_ALLOW_UNPINNED_LIBOQS=ON` is given (verified).
- `qcoin-v2-selftest`: 0 failures. Regtests against the pinned build: `regtest_v2_spend`, `regtest_v2_canonical`,
  `regtest_v2_canonical_scriptpath`, `regtest_v2_scriptpath`, `regtest_v2_psbt`, `regtest_v2_psbt_multisig`, `regtest_v2_policy`,
  `regtest_randomx`: all pass.
- Multi-node qtctest smoke test (one miner with a RandomX full dataset, a second node, two wallets, ML-DSA-44): the running miner mapped
  `/root/liboqs-pinned/lib/liboqs.so.0.14.0`, 101 blocks mined, one 20-coin transfer relayed, confirmed in block 102 and present on
  both nodes (1,073 vB, a 3,735-byte attestation), no errors in either log.

## Changing the pin

Change `fork/third_party/liboqs/PIN` (version, tag, commit, flags) and this document together: record the new commit, re-read the
advisories for it, build with `build-liboqs.sh`, run the self-test, the canonical-encoding, script-path and PSBT regtests and a multi-node
run, and say in the commit message that consensus code depends on the library. A new liboqs is a consensus change for any chain that
already exists.
