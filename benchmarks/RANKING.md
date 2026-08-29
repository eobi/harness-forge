# Ranking

Every "ours" figure was produced by this repository on Linux (Debian bookworm, clang 14,
libFuzzer + ASan, aarch64, 10 cores). Every QuartetFuzz and gold figure is **cited** from
their published artifact by case id, never measured here. The two never share a cell.

## Protocol

- gold and QuartetFuzz: 10 x 600 s libFuzzer, empty corpus, ASan, per-case median
- ours: **1 x 600 s**, single sample — a deliberately self-penalising deviation
- coverage by `llvm-cov`, line percentage, over the files an entry point can reach

## The denominator rule

Coverage is reported over the source an entry point can actually reach. libyaml's emitter
side (32.8% of lines) is unreachable from any loader harness; yajl's generator and tree
(39.5%) are unreachable from `yajl_parse`. Including them caps any parse harness below the
figure gold reports, which proves gold excludes them too. Where that argument applies it is
stated in the row.

## Standing (run-007, 600 s)

Filled from `results/` as each run completes. `ratio` is ours / gold — the metric that
survives across libraries, because the absolute percentage is set by the target rather than
by harness quality. PromeFuzz's headline claim is 1.40x over hand-written harnesses; QF's
median across its own 25 cases is 0.95x.

| case | ours | QF | gold | ours/gold | QF/gold |
|---|---|---|---|---|---|
| libyaml/libyaml_loader_fuzzer | 77.77 | 73.89 | 77.7 | **1.00x** | 0.95x |
| libyaml/libyaml_scanner_fuzzer | 48.61 | 67.3 | 70.6 | 0.69x | 0.95x |
| brotli/decode_fuzzer | pending | 84.15 | 77.2 | | 1.09x |
| yajl-ruby/json_fuzzer | pending | 79.87 | 69.1 | | 1.16x |
| iperf/cjson_fuzzer | pending | 0.0 | 24.5 | | 0.00x |
| zopfli/zopfli_deflate_fuzzer | pending | 80.06 | 85.7 | | 0.93x |
| zlib/zlib_uncompress2_fuzzer | pending | 51.74 | 53.1 | | 0.97x |

Verified individually at 60-90 s before this run: brotli 84.42, zlib 53.93, zopfli 84.85,
yajl 65.12.

## What is not measured here

Findings. QuartetFuzz has 3 CVEs and 29 confirmed reports; this repository has none.
Coverage is instrumentation, not the product.
