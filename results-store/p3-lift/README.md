# P3.LIFT: lifting a library's own test into a fuzzing harness

**First end-to-end result: 9.50x the coverage of our best generated plan, same conditions.**

| harness | coverage | executions |
|---|---|---|
| **P3.LIFT, from jansson's `decode_any`** | **456** | 742,810 |
| best generated plan (of 6) | 48 | 8,712,638 |
| worst generated plan | 4 | 13,102,247 |

Same seed corpus, same 15s budget, same build flags, same library sources. The emitted C is
kept beside this file as `jansson-decode_any-2026-09-02.c`.

Note the execution counts run the OTHER way: the generated plans execute 12-17x MORE often
and reach a twentieth of the code. That is the whole argument for this work in one row --
throughput was never the constraint, reachable surface was.

## How it works, and the one thing that makes it safe

The test is NEVER COMPILED. Its call sequence is lifted to IR and re-emitted as our own C, so
test frameworks, fixtures and helper linkage are irrelevant. The IR is the firewall.

Two things are dropped, both recorded rather than done silently:

**Assertions.** A test asserts expected values for FIXED input; under fuzzing they are
meaningless, and an assertion that fires ABORTS -- which burns the whole campaign. All 8
top-ranked libyaml synthesis candidates died exactly that way.

**Calls the library does not export.** Test-local helpers, stdio, framework entry points. A
helper may itself call library APIs, so the count of what was dropped travels with the plan.

## Six defects found by building it, each of which produced a plausible-looking wrong answer

1. **A format string is not data.** The seam finder first ranked `json_pack`'s `"b"` and `"n"`
   specifiers as jansson's deepest seams -- 99 ops deep. Substituting there does not test the
   parser; it makes the HARNESS interpret attacker-controlled format directives.
2. **Depth measures how much the RESULT is used, not how much work the call does.** With
   formats excluded the top seam became `json_string("foo")`: reused 84 times, and it merely
   wraps a C string. A name-based parse preference now ranks above depth, recorded as a PRIOR
   that campaigning is expected to confirm or overturn.
3. **The seam matched by NAME.** The header calls the parameter `input`; the lift saw a call
   site with no names and called it `a0`. Nothing was substituted and the harness emitted
   `json_loads(0, 0, &err)` -- it compiled, ran, and fed the parser a literal zero.
4. **Only the first occurrence was substituted.** `decode_any` calls `json_loads` four times;
   three kept reading a literal zero.
5. **`static inline` definitions in a public header are invisible.** jansson's `json_decref`
   is `static JSON_INLINE void json_decref(json_t *)` inside jansson.h, so `parse_header` does
   not return it. All four `json_decref` calls were dropped as "not a library call", turning a
   correct test into a harness that leaks on every input. Its RETURN TYPE mattered too --
   without it the emitter wrote `hf_sink += (long)json_decref(json)`, casting void to long.
6. **The emitter included the test file.** The lifter records where it SAW each call, which
   for a lifted test is `test_load.c`, so the harness tried to `#include "test_load.c"`.
   Resource types came from the lift as `void *` for the same reason, and the build failed on
   `passing 'void **' to parameter of type 'json_error_t *'`. Both now come from the header.

## Against the DEVELOPER-WRITTEN harness, which is the comparison that counts

| library | best lifted | developer | ratio |
|---|---|---|---|
| jansson | 449 | 657 | **0.68x** |
| cjson | 198 | 304 | **0.65x** |

Paired, same mined seed corpus, same budget, same flags, arms alternating order.

**P3.LIFT closes most of OUR OWN gap and does not close OGHarn's.** Our generated plans sit at
0.06-0.07x of the developer harness; a lifted test reaches 0.65-0.68x. That is a 9-10x
improvement on the thing we control, and it is still a THIRD BELOW the human-written baseline
-- where OGHarn reports 1.14x. The axis is not contested yet.

Why the developer harness still wins, as a hypothesis rather than a conclusion:
`json_load_dump_fuzzer.cc` loads AND dumps, exercising both directions of the library, while a
single lifted test does one thing. Combining sequences from several tests, or ranking
candidates by the BREADTH of the lifted sequence rather than only by seam quality, is the
obvious next move -- the current ranking prefers a good seam and takes whatever breadth comes
with it.

## Where it does not work yet

**expat: 0 candidates passed the gates, and its own harness did not build either.** Not
diagnosed. A technique that works on 2 of 3 libraries tried is not a technique yet.

**cjson needed a fix that jansson had hidden.** The lift reads call sites, which do not state
return types, so its Api carries a default. Overriding that only for STATIC-INLINE definitions
fixed jansson's json_decref and left every normally-declared void function broken: cjson's
cJSON_AddItemToObject is void, the emitter wrote `hf_sink += (long)cJSON_AddItemToObject(...)`,
and all four cjson candidates died at build for that one reason. Return types now come from
the header for every API.

## What is NOT claimed

**n = 1 library, 1 test function, 1 run, 15 seconds.** No repeats, so the variance is unknown.
This is an existence proof that the pipeline works and that the ceiling is real, not a
measured effect size. The comparison that matters -- against the library's own
DEVELOPER-WRITTEN harness, over many libraries, repeated -- has not been run.

**A general engine gap, recorded not fixed:** static-inline functions in public headers are
invisible to every producer, not just this one. Teaching `parse_header` to return them would
change what the whole engine proposes and would invalidate the recorded corpus, compile-rate
and audit numbers, so it is scoped to P3.LIFT here and left as its own piece of work.
