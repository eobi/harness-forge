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
