# Benchmarks

Every run recorded here is reproducible from the command it stores, and every number was
measured on this machine rather than cited.

## Layout

```
benchmarks/
  README.md                 this file
  results/<run-id>.json     one record per benchmark run, with environment + per-case rows
  RANKING.md                the standing table, regenerated from results/
```

## The rule

A row may only carry a number this repository produced. Numbers from other systems are
recorded in a separate column and always labelled with their source, because a figure we
measured and a figure someone published are not the same kind of evidence and must never
share a cell.

## Third-party benchmark data

The QuartetFuzz artifact (`github.com/OwenSanzas/QuartetFuzz`) publishes a 100-case
benchmark, gold OSS-Fuzz coverage baselines and precomputed per-case results. It carries
**no LICENSE file**, so it is read and reproduced against, never vendored into this tree.
Its numbers appear here as citations with the case id, so anyone can check them at source.
