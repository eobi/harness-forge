#!/bin/sh
# Generate a seed corpus for libwebp using LIBWEBP'S OWN ENCODER.
#
# THE ARGUMENT. A WebP is a RIFF container wrapping a VP8 bitstream. libFuzzer does not
# produce one by accident, and libwebp keeps its corpus outside the repository, so the case
# ran with seeds=0 and spent its budget failing the container check.
#
# The library ships the thing that makes valid input: WebPEncodeRGBA. An encoder IS a seed
# generator, and this is the round-trip idea at its simplest — encode, then hand the result
# back to the decoder under test.
#
# MEASURED JUSTIFICATION, not a hunch. leptonica went 10.73 -> 20.67 when it got real BMP
# headers, while jansson moved 0.16 with real JSON, because a mutator reaches "{}" in two
# bytes and never reaches a RIFF header. libwebp is at the leptonica end of that scale.
#
# The seeds are DELIBERATELY VARIED rather than one clean image: sizes that cross the
# block boundaries a codec cares about, alpha and no alpha, lossy and lossless, and a few
# degenerate dimensions. A corpus of one image teaches the mutator one shape.
set -eu
SRC="${1:-/b/libwebp}"
OUT="${2:-$SRC/hf-seeds}"
mkdir -p "$OUT"

cat > /tmp/webp_seedgen.c <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "webp/encode.h"

static void emit(const char *dir, const char *name, int w, int h, int lossless, int q) {
  if (w <= 0 || h <= 0) return;
  uint8_t *rgba = (uint8_t *)malloc((size_t)w * h * 4);
  if (!rgba) return;
  /* Structure, not noise: gradients and edges give the encoder something to compress, so
     the bitstream exercises real prediction modes instead of one flat block. */
  for (int y = 0; y < h; y++) {
    for (int x = 0; x < w; x++) {
      uint8_t *p = rgba + ((size_t)y * w + x) * 4;
      p[0] = (uint8_t)(x * 7 + y * 3);
      p[1] = (uint8_t)(x ^ y);
      p[2] = (uint8_t)((x / 8) * 32);
      p[3] = (uint8_t)((x + y) % 2 ? 255 : 128);   /* alpha varies: exercises the ALPH chunk */
    }
  }
  uint8_t *out = NULL;
  size_t n = lossless ? WebPEncodeLosslessRGBA(rgba, w, h, w * 4, &out)
                      : WebPEncodeRGBA(rgba, w, h, w * 4, (float)q, &out);
  if (n && out) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(out, 1, n, f); fclose(f); }
  }
  WebPFree(out);
  free(rgba);
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : ".";
  /* Sizes chosen to cross the boundaries a block codec cares about: below one macroblock,
     exactly one, one plus a partial, and a non-square. */
  int dims[][2] = {{1,1},{1,16},{16,1},{16,16},{17,17},{32,16},{15,33},{64,64},{100,7}};
  char name[64];
  for (unsigned i = 0; i < sizeof dims / sizeof dims[0]; i++) {
    snprintf(name, sizeof name, "lossy_%dx%d.webp", dims[i][0], dims[i][1]);
    emit(dir, name, dims[i][0], dims[i][1], 0, 75);
    snprintf(name, sizeof name, "lossless_%dx%d.webp", dims[i][0], dims[i][1]);
    emit(dir, name, dims[i][0], dims[i][1], 1, 0);
  }
  /* Quality sweep at one size: different quality settings take different code paths. */
  for (int q = 0; q <= 100; q += 20) {
    snprintf(name, sizeof name, "q%d_32x32.webp", q);
    emit(dir, name, 32, 32, 0, q);
  }
  return 0;
}
CSRC

clang -O1 -I"$SRC/src" -I"$SRC" /tmp/webp_seedgen.c \
      "$SRC"/src/enc/*.c "$SRC"/src/dsp/*.c "$SRC"/src/utils/*.c \
      "$SRC"/sharpyuv/*.c \
      -lm -o /tmp/webp_seedgen
/tmp/webp_seedgen "$OUT"
echo "libwebp: generated $(ls "$OUT" | wc -l) seeds with the library's own encoder into $OUT"
