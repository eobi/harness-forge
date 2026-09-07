# Powered coverage run — honest status (2026-09-07)

Goal: >=5 budget-matched paired comparisons (our harness vs the library's OWN developer /
OSS-Fuzz harness) to settle the OGHarn axis (1.14x) with a real sign test instead of an
underpowered one.

## What the census produced
Ran tools/p3lift_batch.py across 7 staged libs (cjson, jansson, expat, libyaml, libpng,
libwebp, zlib). **2 valid paired comparisons**, both consistent with every prior measurement:

| lib | our best | developer | ratio |
|-----|---------:|----------:|------:|
| cjson | 279 | 323 | 0.86x |
| jansson | 585 | 662 | 0.88x |

Still UNDERPOWERED (need >=5). The consistency (~0.87x across runs) reinforces the honest
scorecard position: below the developer harness, well below OGHarn's +14% bar.

## Why the other 5 did not yield a comparison (structural, not a quick fix)
- **libpng, libwebp (codec class): 0 "ours".** Test-lift needs the library's UNIT TESTS to
  lift; codec libs ship none, so nothing is generated to compare. "Ours" for a codec must
  come from the app-lift path (WebPDecode / png_image_begin_read), which is a different
  producer than the test-lift benchmark drives. Their DEV harnesses also don't build
  generically: libpng_read_fuzzer needs zlib linked; libwebp's needs a full-tree build and
  the correct harness (dec_fuzzer, not the sharpyuv one the glob picked).
- **expat: dev harness is LPM-based** (xml_lpm_fuzzer.cpp needs libprotobuf-mutator); our
  own expat candidates were killed at the stricter campaign build step.
- **libyaml, zlib: no in-repo developer fuzzer** to pair against; our candidates also killed
  at build.

## The recipe for a real powered run (a focused build-integration task)
1. Pick >=5 UNIT-TEST-RICH C libs with a buildable OSS-Fuzz harness (jansson, cjson done;
   add e.g. yajl, libucl, a couple more JSON/markup parsers with tests + a plain (data,size)
   OSS-Fuzz harness -- avoid LPM-only harnesses).
2. For each: wire the dev-harness build (its exact sources/defines/deps) into libspec so
   build() links cleanly (the libpng+zlib, expat+LPM nuances are the work).
3. For codec libs, generate "ours" via app-lift (not test-lift) so there is something to
   compare, then run app-entry vs the codec's own decode fuzzer.
4. Run 3x >=300s budget-matched paired, feed rows to tools/benchmark.py scoreboard.

This is genuinely multi-hour build engineering per library, and it is the honest gate on the
OGHarn claim -- not an engine limitation.
