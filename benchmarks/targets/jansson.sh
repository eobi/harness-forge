#!/bin/sh
# Prepare jansson for a benchmark build, without autotools.
#
# jansson.h includes jansson_config.h, which configure generates. Without it the C
# preprocessor fails on the public header — the same class of missing generated file as
# leptonica's endianness.h and libde265's config.h, and with the same silent consequence:
# the parse falls back to raw text and the producer reasons from an incomplete view.
set -eu
SRC="${1:-/b/jansson}"
cat > "$SRC/src/jansson_config.h" <<'HDR'
#ifndef JANSSON_CONFIG_H
#define JANSSON_CONFIG_H
/* hashtable.c and lookup3.h use uint32_t; configure arranges this include. */
#include <stdint.h>
#define JSON_INLINE inline
#define JSON_INTEGER_IS_LONG_LONG 1
#define JSON_HAVE_LOCALECONV 1
#define JSON_HAVE_ATOMIC_BUILTINS 1
#define JSON_HAVE_SYNC_BUILTINS 1
#define JSON_PARSER_MAX_DEPTH 2048
#endif
HDR
echo "jansson: wrote src/jansson_config.h"

# jansson_private.h includes jansson_private_config.h, which autoconf/cmake generates and
# the tarball does not carry. Without it every .c in src/ fails to compile. The values below
# are what cmake's checks resolve to on Linux; INITIAL_HASHTABLE_ORDER is jansson's own
# default of 3.
cat > "$SRC/src/jansson_private_config.h" <<'PRIV'
#define HAVE_ENDIAN_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SCHED_H 1
#define HAVE_UNISTD_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_STDINT_H 1
#define HAVE_CLOSE 1
#define HAVE_GETPID 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_OPEN 1
#define HAVE_READ 1
#define HAVE_SCHED_YIELD 1
#define HAVE_SYNC_BUILTINS 1
#define HAVE_ATOMIC_BUILTINS 1
#define HAVE_LOCALE_H 1
#define HAVE_SETLOCALE 1
#define HAVE_INT32_T 1
#define HAVE_UINT32_T 1
#define HAVE_UINT16_T 1
#define HAVE_UINT8_T 1
#define HAVE_SSIZE_T 1
#define USE_URANDOM 1
#define INITIAL_HASHTABLE_ORDER 3
PRIV
echo "jansson: wrote src/jansson_private_config.h"
