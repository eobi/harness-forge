#!/bin/sh
# Prepare libpng for a benchmark build, without configure.
#
# libpng generates pnglibconf.h — the list of features the build actually has — and ships
# a prebuilt one for exactly this case. Without it png.h does not parse and the producer
# reasons from an incomplete view of the API, which is the fourth target in this suite to
# need a generated header after leptonica, libde265 and jansson. Worth noting as a pattern:
# a benchmark case is not just a source tree, it is a source tree plus whatever its build
# system would have produced.
set -eu
SRC="${1:-/b/libpng}"
# The prebuilt lives in scripts/ in the git tree and at the root in some release tarballs.
# Look in both rather than assume, because guessing wrong here does not fail loudly: png.h
# still parses badly and the producer just sees a smaller API.
for cand in "$SRC/scripts/pnglibconf.h.prebuilt" "$SRC/pnglibconf.h.prebuilt"; do
  if [ -f "$cand" ]; then
    cp "$cand" "$SRC/pnglibconf.h"
    echo "libpng: staged pnglibconf.h from $cand"
    exit 0
  fi
done
echo "libpng: no pnglibconf.h.prebuilt found under $SRC" >&2
exit 1
