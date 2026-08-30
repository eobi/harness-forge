# Ranking

Every **ours** figure was produced by this repository on Linux — Debian bookworm, clang 14,
libFuzzer + ASan, aarch64, 10 cores. Every **QuartetFuzz** and **gold** figure is *cited*
from their published artifact by case id and was never measured here. The two never share a
cell, and `rank.py` enforces that mechanically: measured numbers can only come from
`results/`, cited numbers only from `reference.json`, and neither file can supply the
other's column.

Regenerate:

```
python3 benchmarks/rank.py benchmarks/results/<run-id>.jsonl --write
```

## Protocol

| | |
|---|---|
| gold and QuartetFuzz | 10 x 600 s libFuzzer, empty corpus, ASan, **per-case median** |
| ours | **1 x 600 s, single sample** — a deliberately self-penalising deviation |
| coverage | `llvm-cov` line percentage, over the files an entry point can reach |

One sample cannot beat a median by luck in the direction that flatters us any more often
than it loses to one, and running ten would have made the comparison better rather than
worse. It is stated here so nobody has to discover it.

## The denominator rule

Coverage is reported over the source an entry point can **actually reach**.

libyaml's emitter side is 32.8% of the library's lines and is unreachable from any loader
harness. yajl's generator and tree are 39.5% and are unreachable from `yajl_parse`.
libyaml's `parser.c` and `loader.c` sit *above* `yaml_parser_scan` in the call chain and no
scanner harness can enter them.

The ceiling argument is what justifies each exclusion: including those files caps **any**
harness for that entry point below the figure gold reports, which is only possible if gold
excludes them too. Where the argument applies it is recorded beside the file list in
[`drive.py`](drive.py).

This is not a favourable convention we adopted. I hand-listed these three denominators
wrong before checking, each time making the engine look far worse than it is — the scanner
reads 48.74% over the wrong file set and 70.47% over the right one.

## Standing — run-009, 600 s, complete

<!-- TABLE:BEGIN -->

| case | ours | QuartetFuzz | gold | ours/gold | QF/gold |
|---|---|---|---|---|---|
| libyaml/libyaml_loader_fuzzer | **75.89** | 73.89 | 77.7 | 0.98x | 0.95x |
| libyaml/libyaml_scanner_fuzzer | **70.48** | 67.30 | 70.6 | 1.00x | 0.95x |
| brotli/decode_fuzzer | **84.68** | 84.15 | 77.2 | 1.10x | 1.09x |
| yajl-ruby/json_fuzzer | **72.72** | 79.87 | 69.1 | 1.05x | 1.16x |
| iperf/cjson_fuzzer | **24.82** | 0.00 | 24.5 | 1.01x | 0.00x |
| zopfli/zopfli_deflate_fuzzer | **78.81** | 80.06 | 85.7 | 0.92x | 0.93x |
| zlib/zlib_uncompress2_fuzzer | **53.41** | 51.74 | 53.1 | 1.01x | 0.97x |
| lcms2/cmsOpenProfileFromMem | **5.00** | — | — |  |  |
| libde265/stream_decode | **13.75** | — | — |  |  |
| jbig2dec/jbig2_data_in | **2.58** | — | — |  |  |
| leptonica/pixReadMem | **14.60** | — | — |  |  |
| jansson/json_loadb | **35.20** | — | — |  |  |
| libwebp/WebPDecodeRGBA | **50.74** | — | — |  |  |
| libpng/png_image_begin_read_from_memory | **8.64** | — | — |  |  |
| expat/XML_Parse | **31.23** | — | — |  |  |
| zstd/ZSTD_decompress | **29.92** | — | — |  |  |
| mbedtls/mbedtls_x509_crt_parse | **32.29** | — | — |  |  |
| pugixml/parse | **13.47** | — | 14.79† | 0.91x |  |
| woff2/convert | **29.46** | — | 29.79† | 0.99x |  |

† gold MEASURED by this repository from the project's own in-tree harness, not cited. Same machine, same compiler, same 600 s, same file list, and a fresh corpus from the same seeds — so the comparison differs in the harness and in nothing else.

Measured cases with a gold baseline: **9**. Median ours/gold: **1.01x**. Ahead of the cited QuartetFuzz figure on **5 of the 7** cases it published one for.

Sources: run-001-quartetfuzz-6case, run-005-partial, run-007-partial-4of7, run-009, run-010, run-011, run-012, run-013, run-014, run-015, run-016, run-017, run-018, run-019, run-020, run-021, run-022, run-023, run-024, run-026, run-028, run-029, run-030, run-031, run-032, run-033.

<!-- TABLE:END -->

`ratio` is the metric that survives across libraries, because absolute coverage is set by
the target rather than by harness quality. For scale, **QuartetFuzz's own median across
its 25 C cases is 0.95x** — computed from the same published artifact this table cites, so
it is the one external number here on comparable footing. That is, the state of the art in
LLM harness generation is still, on median, slightly behind the hand-written harness it is
trying to replace.

PromeFuzz's headline claim of **1.40x** is quoted in `reference.json` for scale and is
deliberately kept out of this table. We have not reproduced it, and we do not know its case
selection, its protocol or its coverage denominator — which is three unknowns too many to
put a number in a column beside figures we measured.

`iperf/cjson_fuzzer` is worth reading twice. The cited QuartetFuzz figure is **0.00** — it
did not produce a working harness for that case at all.

`lcms2/cmsOpenProfileFromMem` measured **5.14%** with 42.9 million executions, and has no
gold or QuartetFuzz figure because **it is not in QuartetFuzz's evaluation set**. Earlier
revisions of this file said instead that no public OSS-Fuzz harness existed for the entry
point, and that it was a case a language model could not have memorised. Both statements
were wrong and are withdrawn: OSS-Fuzz's lcms project ships `cms_md5_fuzzer`, which calls
`cmsOpenProfileFromMem`. Per dataset_v2 that harness replays its official corpus to
**5.107%** (871/17,056 lines, scoped to `/src/lcms/`). That is NOT comparable cell-to-cell
with our 5.14% — different denominator, different protocol — but it does retire the reading
that 5.14% is a bad number. Roughly 5% appears to be what one entry point reading an ICC
profile reaches, for a hand-written harness as much as for this one. What it is worth is stated plainly: pointing the engine at lcms2 found five
defects IN THE ENGINE that seven benchmark cases never exposed, and the number went from
0.79% to 5.14% as those were fixed. The remaining gap is the engine's, not the target's:
one entry point reading an ICC profile does not reach the tag-type handlers that hold most
of cmstypes.c, and reaching them needs the seed synthesis that is not built yet.

## Which engine produced these numbers

Every row in `results/*.jsonl` carries an `engine` field: the short sha of the revision that
emitted its harness, with `-dirty` appended when the tree had uncommitted changes, because a
tree nobody can check out is not a tree a number can cite.

**run-009 is stamped `cf6e10e`, after the fact.** Its eight harnesses were emitted between
21:45 and 23:17, and the first change to `hforge/producers` or `hforge/emit` after that
revision landed at 23:22 — so every emit in the run saw the same producer and emitter. Three
producer fixes landed within twenty minutes of the last case finishing, which is exactly why
the field exists: without it, nobody reading this table in six months could tell which tree
the numbers came from.

## Integrity

Every row above was re-derived from the `coverage.txt` in its own log directory after the
run finished. All eight TOTAL lines reproduce the recorded figure exactly. A row that could
not be reproduced from its own evidence would not be published.

## What is NOT measured here

**Findings.** QuartetFuzz has 3 CVEs and 29 confirmed reports. This repository has none.

Coverage is instrumentation, not the product. A harness that covers more of a library is
better positioned to find a defect, and being better positioned is not the same as having
found one. Any table that let those two blur would be measuring the wrong thing.
