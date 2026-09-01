# Results store

Every number a paper might quote, with the artifact that produced it.

## Layout

```
METRICS.json          derived by tools/consolidate.py -- NEVER hand-edited
../benchmarks/audits/ one JSON per experiment, written when the experiment ran
../benchmarks/results/ raw per-run jsonl, 62 files
../benchmarks/gui/results/ raw GUI campaign logs
../findings/          upstream-reportable defects, with the evidence for each
```

**`METRICS.json` derives, it does not restate.** If an audit record changes, rerun
`python3 tools/consolidate.py` rather than editing the output. The audit files are the
provenance; this is the index.

## Every metric carries three things

| field | why |
|---|---|
| `value` | what was measured |
| `source` | the audit file, so a reviewer can recheck it |
| `caveat` | what makes it **wrong to quote alone** |

The caveat is not decoration. Several numbers here are actively misleading without it:

- **"0 false positives"** is over 496 *trusted* lifts, 25% of what the engine sees. It
  declines to opine on the other 75%. QuartetFuzz's 4.8% covers everything they judged.
- **"reachable surface 8% → 52%"** is a **ceiling**, not coverage. The floor did not move.
- **"jansson reaches 3 of 83 functions"** is a floor: unreachable *through this plan's own
  calls*, not proof the library is unreached.
- **"1.18× on woff2"** has an exact Mann-Whitney **p = 1.0**. It is noise.

## What is deliberately recorded

`NEGATIVE_RESULTS_WORTH_PUBLISHING` — four experiments that returned nothing, kept because
a null result bounds how much is left to find.

`CORRECTIONS_MADE_TO_OUR_OWN_CLAIMS` — nine numbers this project published and then had to
withdraw, each with the reason. They are here because the failure mode is consistent and
worth a section of its own: **every one was caught by a number moving further than the
change could explain, and none by the test suite.**
