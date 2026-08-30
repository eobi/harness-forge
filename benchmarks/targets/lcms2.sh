#!/bin/sh
# Generate an ICC seed corpus for lcms2 using LITTLE-CMS'S OWN PROFILE WRITER.
#
# THE ARGUMENT. `cmsOpenProfileFromMem` reads an ICC profile: a 128-byte header, a tag
# table, and tag data whose offsets must agree with each other. A mutator does not reach
# that by accident, and the case has been running on whatever the testbed directory happened
# to contain -- 10 files, 5.00% coverage across 43 million executions, almost all of them
# rejected in the header.
#
# mbedTLS settled the argument on this suite: eleven real certificates took X.509 parsing
# from 12.22% to 32.10% on the same budget. zstd showed the other half of it -- twelve real
# frames reached the same ceiling in a TENTH of the time. The library ships the thing that
# makes valid input.
#
# The profiles vary along the axes the PARSER branches on, not the pixels: colour space
# (RGB, grey, Lab, XYZ), profile version (v2 and v4 have different tag layouts), and tone
# curve shape (a table-based curve writes a very different tag from a parametric one).
set -eu
SRC="${1:-/b/lcms2}"
OUT="${2:-$SRC/hf-seeds}"
mkdir -p "$OUT"

cat > /tmp/lcms_seedgen.c <<'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

static void emit(const char *dir, const char *name, cmsHPROFILE h) {
  if (!h) return;
  cmsUInt32Number n = 0;
  if (cmsSaveProfileToMem(h, NULL, &n) && n) {
    void *buf = malloc(n);
    if (buf && cmsSaveProfileToMem(h, buf, &n)) {
      char path[512];
      snprintf(path, sizeof path, "%s/%s", dir, name);
      FILE *f = fopen(path, "wb");
      if (f) { fwrite(buf, 1, n, f); fclose(f); }
    }
    free(buf);
  }
  cmsCloseProfile(h);
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : ".";
  cmsCIExyY d50 = { 0.3457, 0.3585, 1.0 };

  emit(dir, "srgb.icc",  cmsCreate_sRGBProfile());
  emit(dir, "xyz.icc",   cmsCreateXYZProfile());
  emit(dir, "lab4.icc",  cmsCreateLab4Profile(NULL));
  emit(dir, "lab2.icc",  cmsCreateLab2Profile(NULL));
  emit(dir, "lab4_d50.icc", cmsCreateLab4Profile(&d50));
  emit(dir, "null.icc",  cmsCreateNULLProfile());

  /* Grey with a PARAMETRIC curve and with a TABLE curve: two different tag encodings
     for the same conceptual thing, and the parser takes a different branch for each. */
  {
    cmsToneCurve *g22 = cmsBuildGamma(NULL, 2.2);
    emit(dir, "gray_gamma22.icc", cmsCreateGrayProfile(&d50, g22));
    if (g22) cmsFreeToneCurve(g22);
  }
  {
    cmsUInt16Number tbl[32];
    for (int i = 0; i < 32; i++) tbl[i] = (cmsUInt16Number)(i * 65535 / 31);
    cmsToneCurve *lin = cmsBuildTabulatedToneCurve16(NULL, 32, tbl);
    emit(dir, "gray_table.icc", cmsCreateGrayProfile(&d50, lin));
    if (lin) cmsFreeToneCurve(lin);
  }

  /* An RGB profile built from primaries and three curves: the largest tag set of the lot,
     so the tag table itself has something to get wrong. */
  {
    cmsCIExyYTRIPLE prim = { { 0.6400, 0.3300, 1.0 },
                             { 0.3000, 0.6000, 1.0 },
                             { 0.1500, 0.0600, 1.0 } };
    cmsToneCurve *c[3];
    c[0] = c[1] = c[2] = cmsBuildGamma(NULL, 2.2);
    emit(dir, "rgb_primaries.icc", cmsCreateRGBProfile(&d50, &prim, c));
    if (c[0]) cmsFreeToneCurve(c[0]);
  }
  return 0;
}
CSRC

# shellcheck disable=SC2046
clang -O1 -w -I"$SRC/include" -o /tmp/lcms_seedgen /tmp/lcms_seedgen.c \
  $(ls "$SRC"/src/*.c 2>/dev/null) -lm 2>/dev/null || {
    echo "lcms2: seed generator did not build; leaving the corpus empty rather than faking it" >&2
    exit 0
  }
/tmp/lcms_seedgen "$OUT" || true
echo "lcms2: generated $(ls -1 "$OUT" 2>/dev/null | wc -l | tr -d ' ') ICC profile(s) with the library's own writer"
