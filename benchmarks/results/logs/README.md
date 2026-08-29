# Run logs

One directory per run, one directory per case inside it. These are the raw artifacts a
benchmark row was derived from, kept so that anyone — including us, six months later — can
check the row rather than trust it.

```
logs/<run-id>/<case>/
    harness.c        the exact harness that was measured, byte for byte
    plan.hir.json    the IR it was emitted from
    build.cmd        the compiler invocation
    build.log        compiler output, written only when the build failed
    target.dict      the dictionary the engine mined from the target's own source
    fuzz.cmd         the libFuzzer invocation
    fuzz.log         libFuzzer's full output, verbatim
    coverage.txt     the per-file llvm-cov table, not just the TOTAL row
```

## Why the raw log and not the summary

A benchmark row is a summary, and a summary cannot be audited.

Three of this project's four wrong diagnoses were caught by re-reading a raw libFuzzer log
*after* the number had already been written down. The worst of them — every streaming
harness decoding a NULL buffer, because a scratch buffer was initialised before the slice
pointer was assigned — was invisible in every JSON field we recorded. What exposed it was
one line of libFuzzer output: `corp: 1/1b` with coverage frozen at 42 execs in. Fixing it
moved brotli from 6.32% to 84.42% and zlib from 11.43% to 53.93%.

No summary field would have shown that. The log did. So the log outlives the run.

`coverage.txt` keeps the **per-file** breakdown rather than the TOTAL row alone, because the
denominator rule in [`../../RANKING.md`](../RANKING.md) is only checkable by someone who can
see which files were counted and which were excluded.

## run-009 is incomplete, and here is what is missing

`run-009` retains `harness.c`, `target.dict` and `coverage.txt`, but **not `fuzz.log`** — at
the time it started, the driver captured libFuzzer's output into a variable, parsed the
execution count out of it, and let it go. The gap is exactly what motivated this directory.
[`drive.py`](../../drive.py) now persists all of the above, so run-010 onwards is complete.

The three `coverage.txt` files here were regenerated from each case's retained
`run.profdata`, and their TOTAL lines reproduce the recorded figures exactly — 77.77, 70.47
and 85.50. That is a check on the recorded numbers, not a substitute for the missing log.
