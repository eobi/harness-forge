# Harness Forge

**A certification authority for fuzzing harnesses. Generators are plug-ins.**

The field builds generators. The field's own numbers say the generator is not the
bottleneck: harness defects produce false-positive crash rates **as high as 94%**, and an
audit of **586 production harnesses** found 53 protocol violations, 35 of which were fixed
upstream. The bottleneck is that nobody can tell you whether a harness is any good until
after it has wasted a campaign or produced a false finding.

So this is not a generator. It is an **IR**, a **gate bank** and an **evidence record**.
A producer proposes a plan; the gates certify it; confidence decides nothing.

---

## Working today: phases 1, 2, and half of 3

```
$ python3 -m hforge validate examples/hf_demo.broken.hir.json

[PASS] S1  lifetime: created once, destroyed once, never used after
[FAIL] S2  contract: NUL-termination, (ptr,len) pairs, ownership, non-null
        [block] S2.CSTRING: op o_parse: hd_parse requires 'json' to be NUL-terminated,
                but slice 'json' is kind='bytes' and adds no terminator. The library will
                read past the end of EVERY input, so every input becomes a crash and every
                finding is the harness's own.
                fix: set slice 'json' kind to 'cstring', or call the length-delimited
                     variant of hd_parse instead
...
3 blocking violation(s). This plan must not be emitted as-is.
Note that every one was found WITHOUT compiling anything.
```

That is the cJSON exact-size-buffer defect, the one that produced eight false reports
against a library that was behaving correctly, caught in the plan. No compiler ran.

Then the whole pipeline:

```
$ python3 -m hforge certify examples/hf_demo.good.hir.json --valid-corpus examples/corpus
```

emits C, builds it, runs the dynamic gates, and prints a certificate whose last section is
the one nobody else prints: **what this harness cannot find.**

---

## Why an IR

Every published generator emits C for one backend. A harness validated for libFuzzer on
Linux tells you nothing about the same API under TinyInst on Windows, and its defects are
only discoverable by compiling and running it.

Here a harness is a **plan**: a resource graph with lifetimes, a call sequence, a mapping
from fuzzer bytes to arguments, and the API contracts the plan must respect.

1. **One plan, many backends.** The same IR emits a libFuzzer harness, an AFL++ persistent
   loop, a TinyInst in-process driver, a GUI file-drop driver, or an interpreter program.
   Certified semantics travel across OS and architecture.
2. **Gates before compilation.** Lifetime correctness, protocol compliance and ordering are
   properties of the plan.
3. **The IR is the certifiable artifact.** Versionable, diffable, publishable.
4. **Third-party harnesses lift into it**, so somebody else's C can be graded.

---

## The gates

**Static — on the plan, before a compiler exists**

| | | principle |
|---|---|---|
| S1 | lifetime: created once, destroyed once, never used after | P1 |
| S2 | contract: NUL-termination, (ptr,len) pairs, ownership, non-null | P2 |
| S3 | ordering: create before use before destroy | P2 |
| S4 | boundary: public interface only | P3 |
| S5 | input flow: the fuzzer's bytes reach the target | P4 |
| S6 | error handling: failure returns checked before use | P1 |

**Dynamic — against a build**

| | | phase |
|---|---|---|
| D1 | liveness: the target call survived the optimiser | 1 |
| D2 | positive control: the harness finds a planted bug | 2 |
| D3 | valid input must not crash | 1 |
| D4 | sink reachability | 2 |
| D5 | execution rate is plausible | 1 |
| D6 | determinism, reported as a **rate** | 1 |
| D7 | knobs recorded, and **what they exclude computed** | 1 |
| D9 | misuse provenance | 2 |
| D11 | differential consistency across producers | 2 |

A gate never returns a boolean. It returns a verdict plus the evidence, and **NOT RUN is a
distinct outcome** so an absent check never reads as a passed one.

---

## Platforms

`python3 -m hforge platforms` prints the full matrix: Linux (glibc, musl, x86, x86-64,
aarch64), Windows (MSVC, MinGW, x86, x64, ARM64), macOS (Intel, Apple Silicon, arm64e),
Android (emulator and device, arm64/armv7/x86-64), iOS/iPadOS/tvOS (simulator and device).

Each carries its sanitizers, allocator, coverage backends, crash artifact and **trust
ceiling** — the highest ladder rung a finding observed only there may reach.

> **Fuzz where instrumentation is cheap. Prove reachability where the target actually runs.**

An iOS device run is a **reachability oracle**, never the discovery mechanism. A macOS ASan
finding carries an explicit, labelled iOS reachability hypothesis, or an explicit refusal to
make one.

Variant disagreement is itself an oracle: reproduces at 32 bits and not 64 means
width-dependent arithmetic; reproduces on glibc and not musl means allocator-dependent;
reproduces only under DBI means an instrumentation artifact and must not be reported.

---

## Running it on your machine

Three operator commands, in the order you would use them.

```
python3 -m hforge doctor      # what this machine can do, and what each missing tool COSTS
python3 -m hforge devices     # attached Android devices and iOS simulators
python3 -m hforge selftest    # the whole pipeline, end to end, on this host
```

`doctor` reports a missing tool together with what its absence stops you proving, because a
warning with no stated cost is a warning people learn to ignore. `selftest` runs every stage
and distinguishes **SKIP from PASS** — a check this machine could not run is never counted as
one that passed.

On a Mac with the NDK and an emulator attached, all fourteen stages run:

```
[ PASS ] exit-code classification      12 exit codes classified correctly across linux/windows
[ PASS ] static gates REJECT bad plan  blocked by 3 violation(s), incl. S2.CSTRING — no compiler ran
[ PASS ] D2 positive control           mutants_tested=2, killed=1, survived=1
[ PASS ] android cross-build           arm64-v8a api29 with asan (downgraded from hwasan:
                                       stock system image; HWASan needs a HWASan image)
[ PASS ] android device run            emulator-5554: ok
14 passed, 0 failed, 0 skipped
```

### Platform support

| platform | status |
|---|---|
| **macOS** arm64 | verified end to end |
| **Linux** aarch64 glibc | verified end to end — 92 tests, 11/11 runnable stages |
| **Linux** aarch64 musl | verified end to end — different allocator, correctly detected |
| **Linux** x86-64 glibc | verified end to end under emulation |
| **Android** arm64-v8a API 35 | verified end to end: cross-build, push, run, differential |
| **Windows** MSVC / MinGW | exit-code semantics implemented and unit-tested from any host; **not yet run on a Windows host** |
| **iOS** simulator | detected via `simctl`; harness emission not yet wired |

Nothing above claims more than was executed. Windows is honestly *implemented and
unit-tested*, not *verified* — run `python3 -m hforge selftest` there and it will tell you
which of the two it is.

### Verifying Linux yourself

```
./scripts/verify-linux.sh          # needs only a running docker daemon
```

Three containers, because the platform model claims those variants differ and an unexercised
claim is a guess: aarch64/glibc, aarch64/musl, and x86-64/glibc under emulation. The last
step certifies the **same plan** on all three and compares the gate verdicts.

```
GATE   linux-aarch64-glibc linux-aarch64-musl  linux-x86_64-glibc
D1     pass                pass                pass
S2     pass                pass                pass
...
All platforms agree. The harness behaves the same across allocator and word
size, so no variant-dependence is implicated.
```

**A disagreement there is not a build failure.** It is the variant-disagreement oracle
firing: glibc-not-musl means allocator-dependent, x86-64-not-aarch64 means width-dependent
arithmetic. `scripts/compare_certs.py` says which, and exits 0 either way, because a script
that failed the build on real information is a script people stop running.

## The claim, in one table

libmagic (`file` 5.44 from source), one `hforge batch` run, 8-second campaigns:

| | |
|---|---|
| plans proposed | 36 |
| rejected before a compiler ran | 2 |
| **reach ≥ 8 edges — shipped** | **26** |
| **reach < 8 edges — refused** | **10** |

**28% of what a conventional generator would ship reaches essentially nothing**, and the
engine says which in under a minute, before any campaign budget is spent.

The same entry point, proposed three ways and chosen by measurement:

| plan | edges | grew | executions |
|---|---|---|---|
| `magic_buffer` | 36 | no | 6,321,959 |
| `magic_buffer_with_magic_load` | 542 | yes | — |
| `magic_buffer_setup` | **551** | yes | 664,461 |

15× the reach — and the search finds *which* call mattered, rather than assuming. See [`plans/03-WHAT-THE-FIELD-CANNOT-DO.md`](../plans/03-WHAT-THE-FIELD-CANNOT-DO.md) for
why emitting C makes this impossible, and
[`plans/04-QUARTETFUZZ-COMPARISON.md`](../plans/04-QUARTETFUZZ-COMPARISON.md) for a
side-by-side against the state of the art that does not flatter us — they have 3 CVEs and we
have none.

## A dictionary the target wrote itself

A coverage-guided fuzzer finds `CREATE TABLE` by mutating bytes until it stumbles on it.
That is a long walk, and it is unnecessary: **a parser's vocabulary is written down inside
the parser.** `sqlite3.c` contains every SQL keyword it compares against.

```
$ python3 -m hforge batch sqlite3.h --source sqlite3.c ...
$ cat build/suite/sq_sqlite3_exec/target.dict
k0="AND"
k1="BEGIN"
k2="COMMIT"
k3="INTEGER"
k4=":memory:"
...
```

Every shipped harness gets a `target.dict` mined from the target's own string literals, and
gate D8 runs the campaign *with* it and records that it did. The effect is measured, not
assumed. On sqlite, 138 SQL keywords came out of `sqlite3.c` and the same harness over the
same 20 seconds went:

| `sqlite3_exec` | edges | executions |
|---|---|---|
| without dictionary | 867 | 706,530 |
| **with dictionary** | **5,441** | 438,430 |

**6.3x the coverage.** Executions fall because each one does more work: the fuzzer stops
guessing at syntax and starts exercising the engine.

Filtering is deliberately conservative: format specifiers, source file names and camelCase C
symbols are about the program rather than about its input language, and a dictionary full of
them costs the fuzzer time instead of saving it.

## Detection, measured

`--no-positive-control` had hidden this in every earlier run. With D2 enabled on libmagic
(`file` 5.44 from source):

| plan | edges | grew | **kill** | sinks |
|---|---|---|---|---|
| `magic_buffer_setup` | 551 | yes | **83%** | 85% |
| `magic_buffer_with_magic_load` | 547 | yes | **100%** | 84% |
| `magic_file_setup` | 129 | yes | **83%** | 87% |
| `magic_file_with_magic_load` | 124 | yes | **100%** | 87% |

Kill rate is the fraction of *planted* defects the harness detected — mutation testing
against the real target, not a proxy. A harness that reaches deep code and kills nothing is
a harness that will find nothing.

**What D2 costs.** A mutant changes one translation unit, and the build now recompiles only
that unit and links the rest from a cached archive. That is a large win on a 33-file target
like libmagic and **nothing on sqlite**, whose single 243k-line amalgamation has no other
files to reuse. So: D2 is affordable on multi-file targets and a deliberate expense on a
large amalgamation — not, as an earlier note here claimed, simply "affordable".

### Where the defects were caught

```
WHERE THE DEFECTS WERE CAUGHT
  before any compiler ran :    2
        2  S2.TYPE_CONFUSION
  needed a built binary   :    0
  100% of blocking defects cost zero compilation and zero campaign time.
```

This is the axis worth comparing on. The published state of the art intercepts
harness-induced crashes by **running** the harness and attributing the crash afterwards.
Every `S`-coded violation here was found on the plan — no build, no campaign, no triage.

## Seeds from the target's own test data

The dictionary supplies the format's words; a seed supplies a whole sentence. Both are mined
from the repository, and both are measured rather than assumed.

```
python3 -m hforge batch magic.h --source ... --seed-dir /src/file-5.44/tests
```

| `magic_buffer_setup`, 20s | edges |
|---|---|
| no seeds | 565 |
| **117 seeds mined from `file`'s tests** | **634** (+12%) |

Modest here, and worth saying why: the setup variant already calls `magic_load`, so most of
libmagic is reachable before any seed helps. Compare the dictionary's **6.3x** on sqlite,
where the fuzzer had no idea what SQL looked like. The lesson is that neither is a universal
win, which is why D8 reports the number instead of the engine claiming one.

Selection is conservative — de-duplicated by content hash, size-bounded, source files
excluded, deterministic across machines, and a truncated corpus **says** it was truncated.

## Scale, and four wrong diagnoses

sqlite (243,646 lines, 4,368 functions, 8,116 sinks) is where every performance assumption
broke. Ordering 524 candidates by reachable sink surface took **29 minutes at one core** before
a single harness was built, and it took four attempts to find out why:

| fix | what it actually cost | still slow because |
|---|---|---|
| cache the target archive | 24 rebuilds of 243k lines | the sink map was rebuilt per plan |
| cache the sink map | 52s x 524 | the reachability walk ran per plan |
| cache the walk | 5.6s x 315 distinct entry sets | the walk itself was O(V·E) |
| mark `seen` on enqueue | 5.6s -> 0ms | **`k not in reached` scanned a LIST** |

The last one was the real cost the whole time: `sink_surface` diffed 8,116 sinks against a
list with dataclass equality, once per plan — **66 million comparisons**. The three earlier
fixes were each real and none of them touched it.

Measured on the full workload after all four:

```
build_map              52.4s   (once, cached)
propose 648 plans       0.2s
pre-rank ALL 648       55.5s   -> 86ms each     (was ~29 minutes)
```

**A note on how those numbers were got wrong.** A "14.6x speedup" was reported here earlier
from a 40-plan benchmark that happened to be mostly cache hits. The full 648 plans contain
315 distinct entry sets; the sample had 20. Measure the workload, not a slice of it — the
same discipline the engine applies to a harness, applied to claims about the engine.

## Real targets

Three Linux CLI libraries, in Docker, with nothing special done to them.

| target | plans | winner | verdict | why |
|---|---|---|---|---|
| **libmagic** (`file` 5.44, from source) | 10 | `magic_buffer` | PROVISIONAL | full suite ran; **D2 killed 2 of 6 planted defects** |
| **libyaml** (installed) | 21 | `yaml_parser_set_input_string` | PROVISIONAL | caller-allocated `yaml_parser_t`, chained to `yaml_parser_scan` |
| **libxml2** (`xmllint`, installed) | 74 | `xmlReadMemory` | **REJECTED** | D1: three calls elided by the optimiser |

The libxml2 result is the one to read. The harness built and ran; every static gate passed.
D1 then found that `xmlReadMemory`, `xmlNewDocNode` and `xmlUnlinkNode` did not appear as
undefined symbols in the object, meaning the optimiser had deleted them — *"the campaign
would search an empty function and report nothing."* A generator would have shipped that
harness and it would have fuzzed nothing, forever, silently.

```
python3 -m hforge propose /usr/include/magic.h --name libmagic --link=-lmagic -o out --dynamic
python3 -m hforge certify out/libmagic_magic_buffer.hir.json
```

`--link` gates against an installed library; `--source` and `--cflag=-DHAVE_CONFIG_H` gate
against real sources, which is what D2 and D4 need. Gates that cannot run say so.

## Ten real libraries

Every one parsed and planned from its installed system header, in about a second total.

| library | plans | entry point | verdict | runtime gates |
|---|---|---|---|---|
| expat | 14 | `XML_Parse` | PROVISIONAL | 4/4 |
| libmagic | 10 | `magic_buffer` | PROVISIONAL | 4/4 |
| sqlite3 | 114 | `sqlite3_exec` | PROVISIONAL | 4/4 |
| libyaml | 21 | `yaml_parser_set_input_string` | PROVISIONAL | 4/4 |
| libxml2 | 117 | `xmlReadMemory` | PROVISIONAL | 4/4 |
| libarchive | 92 | `archive_read_open_memory` | **REJECTED** | 3/4 |
| zlib | 5 | `gzgets` | **REJECTED** | 3/4 |
| libpng / pcre2 / lzma | 25 / 117 / 9 | — | parsed, no byte entry point planned | — |

The generated expat harness is what a person would write by hand:

```c
hf_r_h = XML_ParserCreate(0);
if (hf_r_h) hf_sink += (long)XML_Parse(hf_r_h, (const char *)hf_s_s, hf_len_s, 0);
XML_ParserFree(hf_r_h);
```

and libxml2's is the upstream one: `xmlReadMemory(buffer, len, NULL, NULL, 0)`.

**The two rejections are the point.** libarchive fails D3 — *10 of 10 inputs the library
should accept caused the harness to fault* — so every finding it produced would be its own.
Nothing about that plan is shippable, and no campaign had to run to learn it.

### What real libraries broke

Four of the eight parsed to **nothing** by text alone. The fix was to stop guessing and run
the actual C preprocessor, keeping only what came from the target header so the producer does
not propose harnesses for libc. That, plus:

- **Typedef aliases.** libpng declares `png_structp`, `png_structrp` and `png_const_structp`
  for one `png_struct`; the constructor returns one and every consumer takes another.
  Comparing typedef *names* made them different types — 245 parsed declarations, no handle,
  no plans. Handles are now compared by what they point at.
- **Three ways to acquire a handle, not one.** A library returns it (expat), the caller
  allocates it (libyaml, zlib), or it comes back through an out-parameter —
  `sqlite3_open(name, sqlite3 **ppDb)`. Modelling only the first left sqlite3's constructor
  inferred as `sqlite3_context_db_handle()`, which opens no database.
- **`XML_DefaultCurrent` was chosen as expat's destructor**, because it returns void and
  takes exactly the handle. It is a callback helper. The parser was never freed, so every
  iteration leaked and a LeakSanitizer campaign would report nothing but the harness.
  Destructors are now identified by name as well as by shape — and may return a status,
  which is why `sqlite3_close` was previously passed over for `sqlite3_interrupt`.
- **A callback bound to fuzzer bytes.** `sqlite3_exec`'s function pointer was fed input,
  which would have called an address made of fuzzer data. `S2.TYPE_CONFUSION` blocked it;
  the producer now passes NULL, which is also the conventional call.
- **One fuzzer-controlled buffer per plan.** Giving a second buffer a bounded slice produced
  a layout where the remainder consumed every byte, the bounded slice got zero, and the
  harness jumped to cleanup **on every input** — no library call ever ran. clang proved it
  and deleted them; D1 reported three elided calls. Secondary pointers are NULL now.

## Two limitations, and what closing them cost

**Ranking had no signal without sources.** D2 and D4 need the target's code, so against an
installed library every candidate tied at zero and the winner fell out alphabetically —
printed under the words *"Selected by gate evidence."* Nothing had been selected. The fix is
not a better heuristic, because a heuristic here is a producer supplying a preference, which
the doctrine forbids. The fix is to **say so**:

```
UNRANKED. 33 plan(s) are shippable and NO GATE DISTINGUISHES THEM.
The order above is alphabetical, which is a tie-break, not a measurement.
Naming a winner here would be inventing one.

The gates that would have separated them did not run:
  - D4: target.sources is empty, so there is no code to map
```

Give it the sources and the same command ranks properly, on measurements:

```
RANK  PLAN                     BLOCK    KILL   SINKS  N/RUN  WARN
 1    libmagic_magic_check         0    100%    39%      2     1
 5    libmagic_magic_file          0     33%    65%      2     2
x8    libmagic_magic_getparam      1     33%     6%      2     4
```

**Caller-allocated handles were inexpressible.** libyaml never returns a handle: the caller
declares a `yaml_parser_t` and passes its address. So do zlib's `z_stream` and most C APIs
built on a context struct. `Resource` now carries `storage: handle | inline`, and the
emitter declares the object, zeroes it, passes `&`, and tracks liveness in a separate flag —
because a struct always exists, so a failed initialiser would otherwise go unnoticed.

libyaml went from 2 shallow plans to 21, including its real parser lifecycle. Closing it
surfaced three more defects worth having:

- **Only one lifecycle was ever considered.** libyaml has a parser *and* an emitter; the
  most-used handle won, which was the emitter — so the parser, the only half that consumes
  serialised bytes, was never proposed at all.
- **A setter is not a harness.** `yaml_parser_set_input_string` stores a pointer and
  returns; nothing is parsed until `yaml_parser_scan` runs. The plan now chains the call
  that does the work, with the driver's pointer parameters bound as **out**-parameters —
  never as input, which would be the type confusion below.
- **S2.TYPE_CONFUSION**, the most valuable of the three. A proposed harness cast raw fuzzer
  bytes to `yaml_document_t *`. The library dereferences that as a real object, so *every*
  crash is the harness's own invalid pointer rather than a defect in the target. That is the
  single largest source of false findings in the published literature, and it is decidable
  from the plan — no compiler, no campaign, no triage.

## Layout

```
hforge/
  ir.py                 the Harness IR
  platform.py           OS x arch x variant, with trust ceilings
  certificate.py        the shipped artifact
  cli.py                validate | emit | certify | gates | platforms
  emit/c_libfuzzer.py   the C backend
  gates/static_gates.py S1..S6
  gates/dynamic_gates.py D1..D11
examples/
  lib/                  a tiny demo library so this runs on a clean clone
  hf_demo.good.hir.json    contract-correct plan
  hf_demo.broken.hir.json  the cJSON mistake, reproduced
tests/test_phase1.py    24 tests, each pinning a failure that really happened
```

```
python3 tests/test_phase1.py    # 24/24
python3 tests/test_phase2.py    # 21/21
python3 tests/test_phase3.py    # 17/17
python3 tests/test_portability.py  # 30/30
python3 tests/test_real_headers.py # 22/22
python3 tools/plancheck.py      # repository vs plan: no drift
```

## plancheck

`tools/plancheck.py` is the Auditor doctrine turned on ourselves. It holds the repository
against `hforge/manifest.py` — the plan as data — and fails when they disagree. Eight
checks: declared gates exist, code gates are declared, every DONE deliverable's evidence
resolves, tests pass, plan platforms are modelled, the doctrine invariants hold, phase docs
agree, and nothing claims DONE inside a PLANNED phase.

**A deliverable may only be marked DONE when something executable proves it.** Run it after
every increment; a status field nobody checks is a status field that lies.

## Producers propose, gates rank

```
$ python3 -m hforge propose examples/lib/hf_demo.h --source examples/lib/hf_demo.c --dynamic

RANK  PLAN                  PRODUCER       BLOCK    KILL   SINKS  N/RUN  WARN
 1    hf_demo_hd_parse_n    header_graph       0   100%    67%      2     1
 2    hf_demo_hd_parse      header_graph       0    50%   100%      2     1

Winner: hf_demo_hd_parse_n. Selected by gate evidence. No producer supplied a score,
a confidence or a preference.
```

No model involved. The header-graph producer parses declarations, infers roles and
contracts from signatures, and emits candidate IR. The ranking is by gate evidence only:
blocking violations, then positive-control kill rate, then sink surface, then gates that
did not run.

The winner is correct for a real reason. On the `cstring` plan the off-by-one mutant reads
the NUL terminator, which is in bounds, so that mutant survives; the length-delimited plan
has no such cover and kills both.

---

## Defects found in this engine while building it, kept on the record

The first replay driver read inputs into `static uint8_t buf[1 << 22]`. libFuzzer hands a
harness an *exactly-sized heap* allocation, so a read one byte past `size` lands in an ASan
redzone and faults. Read the same byte out of a large static buffer and it lands in valid
memory, ASan says nothing, and a harness that over-reads every input is certified clean.

Gate **D3 passed a plan that gate S2 had already rejected.** The static gate was right and
the dynamic gate was lying, because the driver was not equivalent to the thing it claimed to
model. It is fixed, `test_driver_uses_an_exactly_sized_heap_buffer` pins it, and the reason
is written into the generated driver so nobody reintroduces it.

**2. The mutation operator could not count parentheses.** `_op_shrink_alloc` used a
non-greedy regex, so `calloc(1, sizeof(hd_ctx))` matched only to the *inner* `)`. Every
mutant of every allocation using `sizeof` left a stray paren, failed to compile, and was
silently counted as unbuildable — gate D2 reported a smaller denominator instead of an
error. Pinned by `test_shrink_alloc_balances_parentheses` and `test_mutants_compile`.

**3. The producer's declaration regex dropped every constructor.** It required whitespace
between the return type and the function name, so `hd_ctx *hd_open(void);` never matched —
and that shape is every constructor in every C library with an opaque handle. The producer
found no handle type, inferred every role as `query`, and proposed **zero plans while
reporting no error at all**. Pinned by
`test_producer_parses_pointer_returning_declarations`.

**4. Fault detection was POSIX-only, so on Windows every crash would have read as a clean
run.** The check was `rc < 0 or rc >= 128 or rc == 1`. On Windows a crash returns an NTSTATUS
such as `0xC0000005`, which matches none of those. D2 would have reported a 0% kill rate
against a working harness, D3 would have passed a harness that crashes on valid input, and
the engine would have certified harnesses that detect nothing — while printing that
everything passed. Classification now lives in `toolchain.classify_exit`, which is pure and
therefore tested for all three platforms from any one of them.

**5. The Android detector was chosen from the CPU, not from the device.** `build_android`
selected HWASan whenever the target was arm64 at API ≥ 29. HWASan binaries need a HWASan
*system image*; on a stock image they SIGSEGV on startup, every input, every time — a 100%
false-positive rate that looks exactly like a working campaign. Found by running it on a real
emulator, not by reading it.

The fix that generalises is not the capability check but the **differential**: every device
run now executes an uninstrumented baseline alongside the instrumented one.

| instrumented | baseline | sanitizer report | verdict |
|---|---|---|---|
| fault | fault | — | real fault in the target |
| fault | clean | yes | real defect the detector caught |
| fault | clean | no | **instrumentation artifact — refuse to report** |
| fault | not run | — | fault, explicitly *undistinguishable* from an artifact |

Verified adversarially: forcing HWASan back on produces a SIGSEGV that the differential
classifies as non-reportable.

### Then it met real software, and found seven more

The producer worked flawlessly on the demo header and proposed **zero plans** for libmagic,
libyaml and libxml2 — reporting no error at all. Seven distinct defects, each pinned by a
test in `tests/test_real_headers.py` that reproduces the shape inline, so they run without
Docker:

**6. A `#define` continued with a backslash leaked into the statement stream.** The leaked
text carried unbalanced parentheses, so the depth counter never returned to zero and no `;`
ever split a statement again. `yaml.h` — 54KB — parsed to **nothing**.

**7. `extern "C" {` swallowed entire headers.** Comments and strings are blanked before
parsing, so the text is really `extern     {`, and a pattern looking for the literal `"C"`
misses it. Every declaration then sat at depth 1. `magic.h` parsed as ONE statement.

**8. Typedef'd pointer handles were invisible.** `typedef struct magic_set *magic_t` is a
pointer, but not textually. `const char *` won as libmagic's handle instead, every role was
inferred wrongly, and no plan formed. This shape is `magic_t`, `xmlDocPtr`, `sqlite3`, `FILE`
— most real C libraries.

**9. A refused emit printed `CERTIFIED`.** When emission failed, the pipeline added no
dynamic gate results *at all* — and a certificate with six passing static gates and nothing
else read as success. The engine certified a harness whose C had never been generated.
`NOT_RUN is a distinct verdict` has to hold for a whole stage, not just for a gate that
chooses to report it.

**10. Ranking rewarded plans that failed to build.** Same root cause, worse consequence: a
plan that could not be emitted contributed zero not-run gates, while every plan that built
and ran contributed several. **Failing scored better than working**, and a broken plan
ranked first. An emit refusal is now a blocking defect.

**11. The sink scanner could not see BSD-style definitions** — return type on its own line,
name on the next. `file`, OpenSSH and much of BSD-derived C are written that way, so D4
reported *"reaches 0 of 19 sinks"* on real software. That reads like a finding. It was a
parser artifact.

**12. A typedef-only header contributed nothing.** Typedefs were gathered from parsed
declarations, so a header with only typedefs — `forward.h`, `types.h` — dropped all of them.
libxml2 happened to put both in `tree.h` and hid it; a test written from the fixture caught
it.

**13. The handle was paired as a fuzzable buffer.** Type-based `(ptr, len)` inference saw
`magic_setparam(magic_t, int, const void *)`, noticed a pointer followed by a size-shaped
int, and paired the *handle* with it. The plan then bound an argument to a slice that did
not exist.

All thirteen share a shape worth naming: **the failure was silent**. Nothing crashed, nothing
warned, and the output looked like a clean result. Three were found by writing an adversarial test, one by moving to another platform, one only
by plugging in a real device, and seven only by pointing the engine at software somebody else
wrote. That is precisely the class of defect this engine exists to catch in other people's
harnesses, and it has now found thirteen of them in itself.

An engine that only ever confirms is not an engine.
