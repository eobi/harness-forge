# Corpus audit with the contract gates live

**879 harnesses from 124 projects. Six blocking candidates. ZERO reportable defects.**

Generated 2026-09-01T21:21:37Z. Raw: `audit-2026-09-01.json`, `harvest-2026-09-01.json`.

QuartetFuzz audited 586 harnesses across 70 projects. This is 879 across
124, and it is the **first audit at any scale where S2 could actually run**: the
gate fires off a DECLARATION, a lifted harness carries call sites, and the previous corpus
kept no headers. All 1,401 harnesses graded before this reported S2 NOT RUN, which is not the
same as PASS.

| | |
|---|---|
| harnesses | 879 |
| lifted | 518 |
| high fidelity | 154 |
| declarations parsed | 26,901 |
| contracts attached | 578 |
| BLOCK on high-fidelity lifts | **6** |
| BLOCK on low-fidelity lifts | 293 — **not counted** |

## All six candidates, triaged by hand

**Four are one test fixture.** `bazel-rules-fuzzing-test` and `-java` both ship
`010_oom_fuzz_test.cc`, flagged S3.NO_WORK and S5.INPUT_NOT_CONSUMED. Both are TRUE -- it is
a deliberate out-of-memory demo that ignores its input -- and neither is reportable, because
it is a test of the bazel fuzzing RULES, not a harness for a library.

**Two are defects in this engine, and both are FALSE POSITIVES.**

`htslib/fuzz_expr.c`, S2.CSTRING. The harness is correct:

```c
char expr[8192];
size_t len = strnlen((char *)data, size);
memcpy(expr, data, len);
expr[len] = 0;
hts_filter_t *filt = hts_filter_init(expr);
```

It copies into a stack buffer and terminates it. The lifter does not follow a memcpy into a
fixed-size local array, so it believes `hts_filter_init` receives the raw input slice.

`http-parser/fuzz_url.c`, S6.UNCHECKED_ERROR. The message claims the harness "dereferences
the failure value", but `u` is a STACK STRUCT and `http_parser_url_init` returns void. S6
attributed a negative error return to a resource that cannot fail that way.

## What this does to the false-positive claim

The recorded claim is **0 false positives on 496 trusted lifts**. With the contract gates
live that no longer holds: **2 false positives on 154 high-fidelity lifts, 1.3%.**

That is still below QuartetFuzz's 4.8%, and the denominators still differ -- but the honest
statement is now "1.3% measured with contract gates running", not "zero". Turning a gate on
is allowed to cost precision; hiding that it did would not be.

## The result nobody wants to write down

At a scale larger than the published competitor's, with a capability they have and we did not
until today, this audit produced **no defect worth reporting to anyone**. That is the finding.
It is also the third consecutive scaled run to say the same thing, and it is the strongest
available evidence that the findings axis is not won by grading more harnesses.
