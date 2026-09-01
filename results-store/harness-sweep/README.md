# Harness generation sweep

**1495 gate-passing harnesses across 15 of 18 libraries**, generated
2026-09-01T04:32:18Z. Raw record: `sweep-2026-08-31.json`.

This is the yield of the METHOD, not of a library someone picked. Every earlier harness count
came from a library chosen by hand, which reports whatever that library happened to give.

| library | harnesses | seconds |
|---|---|---|
| leptonica | 196 | 264.0 |
| zstd | 192 | 0.5 |
| lcms2 | 178 | 1.8 |
| zlib | 176 | 0.4 |
| cjson | 153 | 1.7 |
| libde265 | 132 | 0.6 |
| mbedtls | 101 | 0.5 |
| expat | 97 | 0.6 |
| libwebp | 82 | 0.4 |
| libyaml | 78 | 0.5 |
| jansson | 36 | 0.4 |
| yajl | 32 | 0.3 |
| brotli | 27 | 0.3 |
| jbig2dec | 14 | 0.3 |
| zopfli | 1 | 0.3 |

## What produced nothing, and why that is recorded

none produced **zero**: every base plan and every
synthesised candidate was rejected by the static gates. The engine reported "nothing this
engine will stand behind" and handed nothing over, which is the intended behaviour -- a
harness the gates reject is not emitted just to raise a count. These are not failures to
explain away in a paper; they are the refusal rate of the method, and they belong in the
same table as the successes.

leptonica took 264.0s against under
two seconds for everything else. It has 533 .c files and `allheaders.h` pulls in the whole
library, so the cost is the header graph, not the gates.

## Caveat, stated once

These harnesses **pass the static gates and emit valid C**. That is what is claimed. It is
NOT a claim that they compile against every library, that they find bugs, or that they beat
developer-written harnesses -- the measured comparison against developer harnesses was
+0.40% against a +14% target, and it is recorded as such in METRICS.json.
