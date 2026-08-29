#!/bin/sh
# Prepare libde265 for a benchmark build, without cmake.
#
# libde265 is C++ behind a C API, and it is here for two reasons. It is the first C++
# target in the suite, so it exercises the emitter router and the clang++ path. And it
# ships its OWN hand-written fuzz harness in `fuzzing/stream_fuzzer.cc` — which means the
# gold column for this case is one we MEASURE on this machine at this budget, rather than
# one we cite. That is strictly better evidence than a published figure.
#
#   ./libde265.sh /b/libde265
#
# libde265's build normally generates two headers with cmake. cmake is not in the benchmark
# image and adding it to run a configure step would make the build less reproducible, not
# more, so the two headers are written here with their values stated.
set -eu
SRC="${1:-/b/libde265}"

# Version 1.1.1, BCD-encoded the way CMakeLists.txt computes it:
#   (major/10)*16 + major%10, shifted per component -> 0x010101 -> 65793
cat > "$SRC/libde265/de265-version.h" <<'HDR'
#ifndef LIBDE265_VERSION_H
#define LIBDE265_VERSION_H
#define LIBDE265_NUMERIC_VERSION 0x010101
#define LIBDE265_VERSION "1.1.1"
#endif
HDR

# Every HAVE_ symbol the sources reference, resolved for linux/aarch64/glibc. The x86 and
# arm32 SIMD paths are OFF: this is aarch64, the arm32 directory is armv7 NEON, and a
# harness certified against a SIMD path the benchmark machine cannot run would be a
# certificate describing something other than what ran.
cat > "$SRC/config.h" <<'HDR'
#ifndef LIBDE265_BENCH_CONFIG_H
#define LIBDE265_BENCH_CONFIG_H
#define HAVE_MALLOC_H       1
#define HAVE_ALLOCA_H       1
#define HAVE_POSIX_MEMALIGN 1
#define HAVE_VISIBILITY     1
/* OFF, deliberately: no x86 SIMD on aarch64, no armv7 NEON on aarch64, no OpenSSL. */
/* #undef HAVE_SSE4_1 */
/* #undef HAVE_AVX2 */
/* #undef HAVE_AVX512 */
/* #undef HAVE_ARM32 */
/* #undef HAVE_OPENSSL */
#define PACKAGE_VERSION "1.1.1"
#endif
HDR

echo "libde265: wrote de265-version.h and config.h"
echo "sources: $(ls "$SRC"/libde265/*.cc | wc -l) core .cc files (encoder/ and SIMD dirs excluded)"
