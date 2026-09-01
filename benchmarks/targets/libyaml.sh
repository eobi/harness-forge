#!/bin/sh
# Prepare libyaml for a benchmark build, without autotools.
#
# yaml_private.h includes "config.h" unconditionally under HAVE_CONFIG_H, and configure
# generates it. Without the file every source in src/ fails to compile, and the failure does
# not surface there: the harness dies at LINK time on undefined yaml_parser_initialize, an
# error far from its cause. Same class as jansson's two generated headers and leptonica's
# endianness.h -- a missing generated file whose absence is silent until something
# downstream breaks.
set -eu
SRC="${1:-/b/libyaml}"
cat > "$SRC/src/config.h" <<'HDR'
#ifndef YAML_BENCH_CONFIG_H
#define YAML_BENCH_CONFIG_H
/* The version macros yaml_private.h expects configure to have substituted. */
#define YAML_VERSION_MAJOR 0
#define YAML_VERSION_MINOR 2
#define YAML_VERSION_PATCH 5
#define YAML_VERSION_STRING "0.2.5"
#define HAVE_CONFIG_H 1
#endif
HDR
echo "libyaml: wrote src/config.h"
