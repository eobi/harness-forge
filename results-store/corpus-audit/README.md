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

## After fixing both engine defects

Re-run on the same 879 harnesses, same headers: `audit-2026-09-01-after-fixes.json`.

| | before | after |
|---|---|---|
| BLOCK on high-fidelity lifts | 6 | **4** |
| of those, false positives | **2** | **0** |
| BLOCK on low-fidelity lifts | 293 | 279 |

The four remaining are the bazel fixture, and all four are TRUE. **Zero false positives on
154 high-fidelity lifts, with the contract gates running.**

The two fixes:

**The lifter now follows a copy into a terminated buffer.** `buf[len] = 0` marks the buffer a
C string, and an argument naming it binds to a `cstring` slice rather than the raw bytes one.
The first version of this fix traded one false positive for another -- the new slice claimed
`remainder` alongside `s_data`, which is S5.MULTIPLE_REMAINDERS -- because the two slices are
the same input seen two ways and the IR has no way to say so. The copy does not claim the
remainder.

**S6 no longer fires on a caller-owned struct.** Its claim is that the harness "dereferences
the failure value", which can only happen when the resource's EXISTENCE depends on the call:
a handle the library allocates, or an out-parameter it fills. A struct the harness declared on
its own stack is there either way, so using it after a failed call reads stale-but-valid
memory -- wrong results, not a crash.

## What this did to the false-positive claim

Turning the contract gates on cost precision before it was paid back. The first run measured
**2 false positives on 154 high-fidelity lifts, 1.3%** -- against a recorded claim of zero.
Both were defects in this engine, both were found by running the corpus, and both are fixed.
The claim now reads **0 false positives on 154 high-fidelity lifts WITH the contract gates
running**, which is a stronger statement than the original because S2 was dark when the
original was measured.

The 1.3% is kept on this page. A precision number that only ever appears after it has been
restored is not evidence of anything.

## The result nobody wants to write down

At a scale larger than the published competitor's, with a capability they have and we did not
until today, this audit produced **no defect worth reporting to anyone**. That is the finding.
It is also the third consecutive scaled run to say the same thing, and it is the strongest
available evidence that the findings axis is not won by grading more harnesses.
