#!/bin/sh
# Generate a seed corpus for zstd using ZSTD'S OWN COMPRESSOR.
#
# THE ARGUMENT, and zstd is the strongest case in this suite for it. A zstd frame opens with
# a four-byte magic number, then a frame header whose descriptor byte decides which of the
# optional fields follow. libFuzzer reaches that by chance essentially never, so run-026
# measured ZSTD_decompress with seeds=0: 15.4 million executions, 30.04%, and every one of
# those executions rejected at the magic check before any of the decode paths ran.
#
# mbedTLS settled the question earlier today. Eleven real certificates took X.509 parsing
# from 12.22% to 27.08% on a campaign one TENTH as long. The library ships the thing that
# makes valid input; an encoder is a seed generator.
#
# The seeds vary deliberately along the axes the FRAME FORMAT cares about, not just the
# payload: compression level changes the block layout, content shape decides whether blocks
# come out raw, RLE or compressed, and the checksum and multi-frame variants exercise header
# flags a single clean frame never sets.
set -eu
SRC="${1:-/b/zstd}"
OUT="${2:-$SRC/hf-seeds}"
mkdir -p "$OUT"

cat > /tmp/zstd_seedgen.c <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

static void emit(const char *dir, const char *name, const void *buf, size_t n) {
  char path[512];
  snprintf(path, sizeof path, "%s/%s", dir, name);
  FILE *f = fopen(path, "wb");
  if (!f) return;
  fwrite(buf, 1, n, f);
  fclose(f);
}

static void roundtrip(const char *dir, const char *name,
                      const void *src, size_t n, int level, int checksum) {
  size_t cap = ZSTD_compressBound(n);
  void *dst = malloc(cap);
  if (!dst) return;
  size_t got;
  if (checksum) {
    ZSTD_CCtx *c = ZSTD_createCCtx();
    if (!c) { free(dst); return; }
    ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1);
    got = ZSTD_compress2(c, dst, cap, src, n);
    ZSTD_freeCCtx(c);
  } else {
    got = ZSTD_compress(dst, cap, src, n, level);
  }
  if (!ZSTD_isError(got)) emit(dir, name, dst, got);
  free(dst);
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : ".";
  enum { N = 64 * 1024 };
  unsigned char *b = malloc(N);
  if (!b) return 1;

  /* Highly repetitive: the compressor emits RLE and long matches. */
  memset(b, 'A', N);
  roundtrip(dir, "rle_l1.zst",  b, N, 1,  0);
  roundtrip(dir, "rle_l19.zst", b, N, 19, 0);
  roundtrip(dir, "rle_sum.zst", b, N, 3,  1);

  /* Text-shaped: real literal and match distributions, so the Huffman and FSE tables in
     the frame are populated rather than degenerate. */
  size_t t = 0;
  while (t < N - 64)
    t += (size_t)snprintf((char *)b + t, N - t,
                          "the quick brown fox jumps over the lazy dog %zu\n", t);
  roundtrip(dir, "text_l1.zst",  b, t, 1,  0);
  roundtrip(dir, "text_l9.zst",  b, t, 9,  0);
  roundtrip(dir, "text_sum.zst", b, t, 3,  1);

  /* Incompressible: forces RAW blocks, a different branch from compressed ones. */
  unsigned s = 12345u;
  for (size_t i = 0; i < N; i++) { s = s * 1103515245u + 12345u; b[i] = (unsigned char)(s >> 16); }
  roundtrip(dir, "rand_l1.zst", b, N, 1, 0);
  roundtrip(dir, "rand_l3.zst", b, N, 3, 1);

  /* Tiny and empty frames: the header's size-field encodings at their smallest. */
  roundtrip(dir, "tiny.zst",  "hello", 5, 3, 0);
  roundtrip(dir, "empty.zst", "",      0, 3, 0);

  /* Two frames back to back, and a skippable frame ahead of a real one. The decoder's
     frame loop and its skippable-magic branch are unreachable from any single frame. */
  {
    size_t cap = ZSTD_compressBound(64);
    unsigned char *one = malloc(cap), *cat = malloc(cap * 2 + 16);
    if (one && cat) {
      size_t g = ZSTD_compress(one, cap, "concatenated frame payload", 26, 3);
      if (!ZSTD_isError(g)) {
        memcpy(cat, one, g); memcpy(cat + g, one, g);
        emit(dir, "two_frames.zst", cat, g * 2);
        unsigned char skip[16] = {0x50,0x2A,0x4D,0x18, 0x04,0x00,0x00,0x00, 0xDE,0xAD,0xBE,0xEF};
        memcpy(cat, skip, 12); memcpy(cat + 12, one, g);
        emit(dir, "skippable_then_frame.zst", cat, 12 + g);
      }
    }
    free(one); free(cat);
  }
  free(b);
  return 0;
}
CSRC

# zstd's amalgamated build: the common and compress trees are all the encoder needs.
# shellcheck disable=SC2046
clang -O1 -w -I"$SRC/lib" -I"$SRC/lib/common" -o /tmp/zstd_seedgen /tmp/zstd_seedgen.c \
  $(ls "$SRC"/lib/common/*.c "$SRC"/lib/compress/*.c 2>/dev/null) 2>/dev/null || {
    echo "zstd: seed generator did not build; leaving the corpus empty rather than faking it" >&2
    exit 0
  }
/tmp/zstd_seedgen "$OUT" || true
echo "zstd: generated $(ls -1 "$OUT" 2>/dev/null | wc -l | tr -d ' ') seed frame(s) with the library's own compressor"
