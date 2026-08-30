#!/bin/sh
# Prepare wabt for a benchmark build, without cmake.
#
# wabt is a GENUINE C++ class-and-namespace API and the third case where this engine
# derives the library's own harness from headers alone. Its entry point
#
#   ReadBinaryIr(const char* filename, const uint8_t* data, size_t size,
#                const ReadBinaryOptions&, Errors*, Module* out_module)
#
# needs an implicit default constructor (`struct Module` declares none), a type alias
# resolved and QUALIFIED (`using Errors = std::vector<Error>` inside namespace wabt), and
# a `const char*` recognised as an incidental label rather than the input. wabt ships
# fuzzers/wasm2wat_fuzzer.cc, so gold here is MEASURED, not cited.
#
#   ./wabt.sh /b/wabt
#
# wabt normally generates include/wabt/config.h with cmake. cmake is not in the benchmark
# image, and adding a configure step would make the build LESS reproducible, not more --
# the same argument libde265.sh makes. So the template is filled in here with the values
# for this image stated explicitly, and anyone can check them against config.h.in.
#
# NOTE: wabt requires C++20. `using ByteSpan = std::span<const uint8_t>` in base-types.h
# does not compile under C++17, so the case must carry --cflag=-std=c++20.
set -eu
SRC="${1:-/b/wabt}"
IN="$SRC/src/config.h.in"
OUT="$SRC/include/wabt/config.h"

[ -f "$IN" ] || { echo "wabt.sh: $IN not found" >&2; exit 1; }

# Values for THIS image: Linux, clang, little-endian, 64-bit, exceptions on, no OpenSSL
# and no Windows console. Each one is a configure probe that has a fixed answer here.
sed \
  -e 's|#cmakedefine WABT_VERSION_STRING "@WABT_VERSION_STRING@"|#define WABT_VERSION_STRING "1.0.41"|' \
  -e 's|#cmakedefine WABT_DEBUG @WABT_DEBUG@|/* #undef WABT_DEBUG */|' \
  -e 's|#cmakedefine01 HAVE_ALLOCA_H|#define HAVE_ALLOCA_H 1|' \
  -e 's|#cmakedefine01 HAVE_UNISTD_H|#define HAVE_UNISTD_H 1|' \
  -e 's|#cmakedefine01 HAVE_SNPRINTF|#define HAVE_SNPRINTF 1|' \
  -e 's|#cmakedefine01 HAVE_SSIZE_T|#define HAVE_SSIZE_T 1|' \
  -e 's|#cmakedefine01 HAVE_STRCASECMP|#define HAVE_STRCASECMP 1|' \
  -e 's|#cmakedefine01 HAVE_WIN32_VT100|#define HAVE_WIN32_VT100 0|' \
  -e 's|#cmakedefine01 WABT_BIG_ENDIAN|#define WABT_BIG_ENDIAN 0|' \
  -e 's|#cmakedefine01 HAVE_OPENSSL_SHA_H|#define HAVE_OPENSSL_SHA_H 0|' \
  -e 's|#cmakedefine01 COMPILER_IS_CLANG|#define COMPILER_IS_CLANG 1|' \
  -e 's|#cmakedefine01 COMPILER_IS_GNU|#define COMPILER_IS_GNU 0|' \
  -e 's|#cmakedefine01 COMPILER_IS_MSVC|#define COMPILER_IS_MSVC 0|' \
  -e 's|#cmakedefine01 WITH_EXCEPTIONS|#define WITH_EXCEPTIONS 1|' \
  -e 's|#define SIZEOF_SIZE_T @SIZEOF_SIZE_T@|#define SIZEOF_SIZE_T 8|' \
  "$IN" > "$OUT"

# A generated header that still carries a cmake directive would fail far away from here,
# with an error about a stray `#cmakedefine`. Say it now instead.
if grep -q "cmakedefine\|@[A-Z_]*@" "$OUT"; then
  echo "wabt.sh: config.h still has unsubstituted entries:" >&2
  grep -n "cmakedefine\|@[A-Z_]*@" "$OUT" >&2
  exit 1
fi
echo "wabt.sh: wrote $OUT"
