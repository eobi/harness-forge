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

## Breadth ranking: REFUTED, and it says something useful

The hypothesis for the remaining gap was that the developer harness wins by being broader.
Ranking candidates by the number of DISTINCT library APIs the lifted sequence keeps:

| candidate | distinct APIs | coverage | vs developer |
|---|---|---|---|
| `test_equal_complex` | **5** | 58 | 0.09x |
| `allow_nul` -> `json_loads` | 4 | **444** | **0.67x** |

**More APIs gave LESS coverage.** `test_equal_complex` calls five comparison functions that
each touch very little; one `json_loads` reaches the whole parser. Distinct-API count is a bad
proxy for reachable code, and the seam is what matters.

That refines rather than kills the idea. The developer harness loads AND dumps -- two DEEP
subsystems, not many shallow functions. The refined hypothesis is that what counts is the
number of deep entry points reached, and it is untested because of the limitation below.

## Deep entry points, CONFIRMED: 0.67x -> 0.88x

Following a variable back to the literal that fills it unblocked jansson's `embed()`, which
does one load and three dumps. Measured against the same developer baseline:

| harness | coverage | vs developer |
|---|---|---|
| our generated plans | 48 | 0.07x |
| lifted, parse only (`allow_nul`) | 444 | 0.67x |
| **lifted, parse + dump (`embed`)** | **584** | **0.88x** |
| developer (`json_load_dump_fuzzer.cc`) | 662 | 1.00x |

**What matters is the number of DEEP subsystems a harness reaches, not how many APIs it
calls.** Breadth by API count was refuted at 0.09x; breadth by subsystem takes the same
technique from 0.67x to 0.88x. The developer harness wins by loading AND dumping, and a lifted
test that does both nearly matches it.

Still below 1.00x, and OGHarn reports 1.14x over developer harnesses. The axis is closer to
contested than it has ever been and is not contested yet.

## The limitation that blocked it, and the bug inside the fix

jansson's `embed()` does exactly what the refined hypothesis wants -- one load and three dumps
-- and the seam finder finds NOTHING in it:

```c
static const char *plains[] = {"{\"bar\":[],\"foo\":{}}", "[[],{}]", "{}", "[]", NULL};
...
const char *plain = plains[i];
parse = json_loads(plain, 0, NULL);
```

A seam used to be required to be a STRING LITERAL AT THE CALL SITE. Here the literals sit in a
static table and the call receives a variable, which is a very common test idiom -- so this
was not one awkward function but a whole class of tests the finder could not see. The trace
now follows two hops: assignment from a literal, and assignment from a subscript of an array
initialised with literals. Deeper chains are left alone rather than guessed at, because a
wrong seam produces a harness that runs and tests nothing.

**A bug inside that fix, worth recording because it failed silently.** Matching the array
initialiser with a non-greedy `\{(.*?)\}` stops at the FIRST closing brace -- and jansson's
table begins `{"{\"bar\":[],\"foo\":{}}", ...}`, whose first `}` is four characters into the
first element. The captured initialiser was a truncated fragment containing no complete
literal, so the trace found the array, found nothing in it, and reported no seam at all. The
closing brace must end the statement.

## The ranker, automated -- and the bound it exposes

`deep` = how many DEEP subsystems a lifted sequence enters (parse, serialise, transform), name-
matched. Ranked above seam depth. 3 repeats, paired, same mined corpus, arms alternating.

| library | best lifted | developer | ratio | subsystems available |
|---|---|---|---|---|
| jansson | 584 (`embed`, deep=2) | 646 | **0.90x** | parse + serialise |
| jansson | 520 / 513 (deep=1) | 646 | 0.79-0.80x | parse only |
| cjson | 198 (deep=1) | 307 | **0.64x** | parse only -- **no deep=2 test exists** |
| libwebp | none | 2675 | -- | 0 candidates past the gates |

**The ranker now picks `embed` by itself**, the candidate previously found by hand, and the
ordering confirms the prior WITHIN jansson: deep=2 scores 0.90x against 0.79-0.80x for deep=1.

**And it exposes the real bound. P3.LIFT can only be as good as the best SINGLE test
function.** cjson's suite has no function that both parses and serialises, so every candidate
is deep=1 and the library is stuck at 0.64x however it is ranked. The developer harness
combines subsystems that no single test combines -- which is exactly why it wins.

That points at the next idea rather than a tuning knob: COMPOSE a sequence from several tests
(a parse test joined to a dump test) instead of lifting one. A composed plan could exceed any
single test in the suite, and nothing measured so far can.

## The two zeros, diagnosed

`libwebp` and `expat` produced no candidates. Different causes, and only one is a defect.

**expat -- a real gap, and a fixable one.** Its 18 test files yield 194 liftable sequences and
ZERO seams, because the suite calls the parser through its own wrapper: `_XML_Parse_SINGLE_BYTES`
appears 152 times against 32 direct `XML_Parse` calls. The lifted op is the WRAPPER, which is
not in the header, so it is dropped as scaffolding and the library call inside it is never
seen. **Tests that reach the library through a test-local helper are invisible to this
technique.** Resolving one level of wrapper -- inlining a helper defined in the test file whose
body calls a library API -- is the fix, and it is likely to affect many suites.

Finding this also required fixing the SAME defect twice: test directories were searched only at
the checkout root, so expat's `expat/expat/tests` went unread. `test_sequences.py` had already
been fixed for exactly that after expat, lcms2 and libpng all reported 0% of their exported
surface. A zero from a tool is a claim about the tool until it is checked, and this is the
second time the same zero meant the same thing.

**libwebp -- not a defect, and it exposed a circularity.** libwebp ships NO unit tests. Its
`tests/` directory contains only `tests/fuzzer/*.c` -- the developer harnesses themselves. The
technique correctly yields nothing.

Worse than nothing, though: the driver was scanning those files AS TESTS. Lifting one would
mean lifting the very harness this experiment measures against and comparing it with itself.
It produced a clean "0 candidates" while attempting something that should never be attempted,
which is the most dangerous shape of failure -- a correct-looking result from a wrong method.
Fuzz harnesses are now excluded from the test scan by name and by directory.

## Test-local wrappers: built, and expat is still not measurable

`resolve_wrappers` maps a test helper to the library call it wraps. A WITNESS is required
rather than a name match: the helper must call exactly one library API, take the same number
of parameters, and actually PASS its own parameter at the position claimed -- checked by
finding that parameter name as the corresponding argument inside the body. Without the last
condition a helper that reorders its arguments would have its seam mapped to the wrong
parameter, producing a harness that runs and tests nothing.

It resolves `_XML_Parse_SINGLE_BYTES -> XML_Parse` with all four parameters witnessed, and
expat went **0 seams -> 31 seams -> 3 candidates past the gates**, from zero.

**It is still not a measurement.** All three candidates die at build, on a fourth distinct
cause: the lifter classifies `XML_Parser` as an inline struct and emits `&parser`, but
`XML_Parser` is already a pointer typedef (`struct XML_ParserStruct *`). That is a
storage-classification defect, not a seam problem.

Four independent blockers were found in expat, each hidden behind the last:

1. test directories searched only at the checkout root (the same defect fixed earlier in
   `test_sequences.py` -- the second time that zero meant the same thing);
2. the suite reaches the parser through a helper 152 times against 32 direct calls;
3. `_body_of_function` could not find a MACRO-declared body (`START_TEST(name)`), so every
   variable trace searched an EMPTY string and failed silently;
4. inputs are declared `char text[] = "..."`, and the tracer required `=` to follow the name
   immediately.

Fixes 3 and 4 are general and help every suite, not only expat. `resolve_wrappers` is general
too. Whether expat itself ever produces a measurement is a separate question, and it is not
answered.

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
