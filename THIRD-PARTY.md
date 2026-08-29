# Third-party material

**Nothing third-party is vendored into this repository.** That is deliberate and worth
stating, because the benchmark work depends on other people's artifacts.

## QuartetFuzz

`github.com/OwenSanzas/QuartetFuzz` — the reproduction artifact for *"Quality-Assured Fuzz
Harness Generation via the Four Principles Framework"* (arXiv 2605.21824).

It publishes a 100-case benchmark, gold OSS-Fuzz coverage baselines, and precomputed
per-case results. **It carries no LICENSE file**, so:

- we clone it OUTSIDE this tree, read it, and reproduce against it;
- we copy none of its code, prompts, or data here;
- its numbers appear in our comparisons as **citations with the case id**, so any reader can
  check them at source.

Public on GitHub is not the same as open-source licensed. Absent a licence, default
copyright applies and reuse rights are unclear.

## Benchmark targets

The libraries measured in `benchmarks/` (libyaml, brotli, zlib, zopfli, yajl, cJSON,
pugixml) are fetched from their own upstreams at benchmark time under their own licences.
None is redistributed here.

## Jazzer

The Java backend emits harnesses for Jazzer (Code Intelligence, Apache-2.0). Jazzer is a
runtime dependency an operator installs; no Jazzer code is included.
