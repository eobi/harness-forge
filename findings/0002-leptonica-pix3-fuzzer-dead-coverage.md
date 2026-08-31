# Finding 0002 — leptonica `pix3_fuzzer.cc` tests `pixAverageByRow` with NULL on every input

**Status:** confirmed against leptonica `main`. NOT yet reported upstream.
**Found by:** `S1.USE_AFTER_DESTROY` + `S1.DOUBLE_DESTROY` on a high-fidelity lift.
**Class:** dead coverage — the harness believes it is testing a function it never executes.
**Fix:** one line.

## The harness

`prog/fuzzing/pix3_fuzzer.cc`, present in current `main`:

```c
box1 = boxCreate(150, 130, 1500, 355);
pix_pointer_payload = pixCopy(NULL, pixs_payload);        /* <-- created */
return_numa = pixAverageByColumn(pix_pointer_payload, box1, L_BLACK_IS_MAX);
boxDestroy(&box1);
pixDestroy(&pix_pointer_payload);                          /* <-- destroyed, and NULLed */
numaDestroy(&return_numa);

box1 = boxCreate(150, 130, 1500, 355);
return_numa = pixAverageByRow(pix_pointer_payload, box1,   /* <-- NULL every time */
                              L_WHITE_IS_MAX);
boxDestroy(&box1);
pixDestroy(&pix_pointer_payload);
numaDestroy(&return_numa);
```

The second block is missing the `pix_pointer_payload = pixCopy(NULL, pixs_payload);` that
every other block in the file performs.

## Why it is a defect and not a crash

Both halves are verified in leptonica's own source:

- `pixDestroy(PIX **ppix)` ends with `*ppix = NULL;` (`src/pix1.c`). The pointer is not
  dangling, it is null.
- `pixAverageByRow` opens with `if (!pix) return (NUMA *)ERROR_PTR("pix not defined", ...)`
  (`src/pix3.c:2447`). It returns immediately.

So this is not memory corruption — it is worse in one specific way: it is **silent**.
`pixAverageByRow` is never executed on any input. The fuzzer, the coverage report, and the
maintainer all believe that function is under test. It is not; only its NULL check is.

The following `pixDestroy(&pix_pointer_payload)` is a no-op for the same reason, and the
harness continues without complaint.

## Fix

```c
   box1 = boxCreate(150, 130, 1500, 355);
+  pix_pointer_payload = pixCopy(NULL, pixs_payload);
   return_numa = pixAverageByRow(pix_pointer_payload, box1, L_WHITE_IS_MAX);
```

This matches the shape of every other block in the file.

## How it was found

The gate reported a use-after-destroy and a double destroy. Both readings were literally
wrong — leptonica nulls the pointer, so neither a dangling use nor a double free occurs —
but the SEQUENCE the gate objected to was real, and reading it found a defect of a
different kind. Worth recording as such: the violation label was inaccurate and the
violation was still worth chasing.

## Provenance

- Corpus: `github.com/DanBloomberg/leptonica`, shallow clone of `main`
- Library source: same tree, `src/pix1.c` and `src/pix3.c`
- Lift: high fidelity
