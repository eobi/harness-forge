# Benchmarks

Every run recorded here is reproducible from the command it stores, and every number was
measured on this machine rather than cited.

## Layout

```
benchmarks/
  README.md                  this file
  drive.py                   one benchmark case: propose -> gate -> build -> fuzz -> cover
  suite.py                   the whole-suite coverage driver
  rank.py                    regenerates the standing table from results/ + reference.json
  reference.json             THIRD-PARTY figures only, cited by case id, never measured here
  RANKING.md                 the standing table, with the protocol and the denominator rule
  results/<run-id>.jsonl     one JSON line per case: plan, sequence, seeds, dict, coverage
  results/logs/<run-id>/     the raw artifacts each row was derived from — see logs/README.md
```

Regenerate the table after a run:

```
python3 benchmarks/rank.py benchmarks/results/run-009.jsonl --write
```

That rewrites the table in both `RANKING.md` and the top-level `README.md` between their
markers. The prose around the table stays hand-written; the numbers are never typed by
hand, because the table drifted twice when they were — once carrying a figure from a plan
our own S1 gate blocks, once carrying a 60-second number in a column headed 600 seconds.

## The rule, enforced mechanically

A row may only carry a number this repository produced. Numbers from other systems are
recorded in a separate column and always labelled with their source, because a figure we
measured and a figure someone published are not the same kind of evidence and must never
share a cell.

## Third-party benchmark data

The QuartetFuzz artifact (`github.com/OwenSanzas/QuartetFuzz`) publishes a 100-case
benchmark, gold OSS-Fuzz coverage baselines and precomputed per-case results. It carries
**no LICENSE file**, so it is read and reproduced against, never vendored into this tree.
Its numbers appear here as citations with the case id, so anyone can check them at source.

## Logs

Every run keeps the harness it measured, the compiler and fuzzer invocations, libFuzzer's
full output and the per-file coverage table. See [`results/logs/README.md`](results/logs/README.md)
for the layout and for why a summary row is not sufficient evidence.
