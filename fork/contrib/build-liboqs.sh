#!/bin/bash
# Build and install the pinned liboqs (fork/third_party/liboqs/PIN) into a prefix.
#
#   fork/contrib/build-liboqs.sh PREFIX [JOBS]
#
# then configure Qcoin with  -DCMAKE_PREFIX_PATH=PREFIX . The script clones the pinned tag, refuses to continue unless the
# checked-out commit is exactly the pinned one, builds the portable configuration of the pin file, and checks the result:
# the installed headers must report the pinned version and must not enable the AVX2 ML-DSA implementations.
set -euo pipefail
PREFIX="${1:?usage: build-liboqs.sh PREFIX [JOBS]}"
JOBS="${2:-$(nproc)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PIN="$HERE/../third_party/liboqs/PIN"
get() { sed -n "s/^$1=//p" "$PIN" | head -1; }
VERSION=$(get LIBOQS_VERSION); TAG=$(get LIBOQS_TAG); COMMIT=$(get LIBOQS_COMMIT); REPO=$(get LIBOQS_REPO); FLAGS=$(get LIBOQS_CMAKE_FLAGS)
[ -n "$VERSION" ] && [ -n "$TAG" ] && [ -n "$COMMIT" ] && [ -n "$REPO" ] && [ -n "$FLAGS" ] || { echo "incomplete pin file $PIN"; exit 1; }
SRC="$PREFIX-src"
rm -rf "$SRC"
git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$SRC"
GOT=$(git -C "$SRC" rev-parse HEAD)
if [ "$GOT" != "$COMMIT" ]; then
    echo "liboqs tag $TAG is at $GOT, the pin says $COMMIT: refusing to build" >&2
    exit 1
fi
echo "liboqs $VERSION at $COMMIT"
# shellcheck disable=SC2086
cmake -S "$SRC" -B "$SRC/build" -DCMAKE_INSTALL_PREFIX="$PREFIX" $FLAGS
cmake --build "$SRC/build" -j"$JOBS"
cmake --install "$SRC/build"
H="$PREFIX/include/oqs/oqsconfig.h"
grep -q "#define OQS_VERSION_TEXT \"$VERSION\"" "$H" || { echo "installed liboqs does not report version $VERSION" >&2; exit 1; }
if grep -Eq "#define OQS_ENABLE_SIG_ml_dsa_[0-9]+_avx2" "$H"; then
    echo "the AVX2 ML-DSA implementations are enabled in this build: not the pinned configuration" >&2
    exit 1
fi
echo "OK: liboqs $VERSION ($COMMIT) installed in $PREFIX, portable ML-DSA only"
