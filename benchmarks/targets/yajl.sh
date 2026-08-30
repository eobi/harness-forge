#!/bin/sh
# Stage yajl's public headers the way its build would.
#
# yajl does not ship an include tree. CMake copies src/api/*.h into
# <build>/yajl/ and generates yajl_version.h from a .cmake template, and every public
# header says `#include <yajl/yajl_common.h>` -- so without that directory the angle-bracket
# include never resolves, the header does not parse, and the producer proposes nothing at
# all. That is exactly what run-026 reported for this target: NO PLAN, which reads like an
# engine failure and was a missing directory.
set -eu
SRC="${1:-/b/yajl}"
mkdir -p "$SRC/inc/yajl"
cp "$SRC"/src/api/*.h "$SRC/inc/yajl/" 2>/dev/null || true

# Versions from the project's own CMakeLists, not guessed: SET (YAJL_MAJOR 2) etc.
cat > "$SRC/inc/yajl/yajl_version.h" <<'HDR'
#ifndef YAJL_VERSION_H_
#define YAJL_VERSION_H_
#include <yajl/yajl_common.h>
#define YAJL_MAJOR 2
#define YAJL_MINOR 1
#define YAJL_MICRO 0
#define YAJL_VERSION ((YAJL_MAJOR * 10000) + (YAJL_MINOR * 100) + YAJL_MICRO)
#ifdef __cplusplus
extern "C" {
#endif
extern int YAJL_API yajl_version(void);
#ifdef __cplusplus
}
#endif
#endif /* YAJL_VERSION_H_ */
HDR
echo "yajl: staged inc/yajl/ ($(ls "$SRC/inc/yajl" | wc -l | tr -d ' ') headers) incl. generated yajl_version.h"
