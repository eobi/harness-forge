# Harness generation sweep

**1495 gate-passing harnesses across 15 of 18 libraries**, of which
**1491 (99.7%) compile** against the real library headers. Generated 2026-09-01T04:52:44Z.
Raw records: `sweep-2026-08-31.json`, `compile-2026-08-31.json`.

This is the yield of the METHOD, not of a library someone picked. Every earlier harness count
came from a library chosen by hand, which reports whatever that library happened to give.

| library | harnesses | compile | rate |
|---|---|---|---|
| brotli | 27 | 27 | 100.0% |
| cjson | 153 | 153 | 100.0% |
| expat | 97 | 97 | 100.0% |
| jansson | 36 | 36 | 100.0% |
| jbig2dec | 14 | 14 | 100.0% |
| lcms2 | 178 | 178 | 100.0% |
| leptonica | 196 | 196 | 100.0% |
| libde265 | 132 | 132 | 100.0% |
| libwebp | 82 | 82 | 100.0% |
| libyaml | 78 | 78 | 100.0% |
| yajl | 32 | 32 | 100.0% |
| zlib | 176 | 176 | 100.0% |
| zopfli | 1 | 1 | 100.0% |
| zstd | 192 | 192 | 100.0% |
| mbedtls | 101 | 97 | 96.0% |

## The one library that does not reach 100%

mbedtls, at 96.0%. The 4 failures are all the same thing and it is worth naming: the
producer proposed entry points such as `mbedtls_x509_crt_verify_with_ca_cb`, which the
header DECLARES but only inside `#ifdef MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK`. The
default build does not set it, so the declaration is not there and the call does not
compile. The engine reads a header's text and does not evaluate its preprocessor conditions,
so a config-gated API looks exactly like an available one. That is a real limitation of the
method with a clean statement, and it stays in the table.

## What produced nothing, and why that is recorded

libpng, wabt and woff2 produced **zero**: every base plan and every synthesised candidate was
rejected by the static gates. The engine reported "nothing this engine will stand behind" and
handed nothing over, which is the intended behaviour -- a harness the gates reject is not
emitted to raise a count. That is the refusal rate of the method, and it belongs in the same
table as the successes.

leptonica took 264s against under two seconds for everything else. It has 533 .c files and
`allheaders.h` pulls in the whole library, so the cost is the header graph, not the gates.

## Caveat, stated once

`compile` here means **-fsyntax-only against the library's real headers**. It is not linking,
and it is emphatically not a claim that these harnesses find bugs or beat developer-written
ones -- that comparison was measured at +0.40% against a +14% target and is recorded as such
in METRICS.json.
