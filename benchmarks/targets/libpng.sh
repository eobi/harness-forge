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
cp "$SRC/pnglibconf.h.prebuilt" "$SRC/pnglibconf.h"
echo "libpng: staged pnglibconf.h from pnglibconf.h.prebuilt"
