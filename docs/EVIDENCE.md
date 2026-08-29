# Evidence

Every claim here was produced by running the engine, and each section says what was
measured and on what. The front page links here rather than carrying it, because a README
that contains its own appendix stops being read.

For the benchmark comparison against QuartetFuzz and the hand-written OSS-Fuzz harnesses,
see [`benchmarks/RANKING.md`](../benchmarks/RANKING.md).

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

15× the reach — and the search finds *which* call mattered, rather than assuming. 15x the reach is the argument for an IR: emitting C directly makes this search impossible,
because the thing being compared has already been flattened into text. The side-by-side
against the state of the art is below, and it does not flatter us — QuartetFuzz has 3 CVEs
and this repository has none.

---

---

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

---

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

---

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

---

## Scale

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

Those figures are from the full 648-plan workload, not a sample of it: 315 distinct entry
sets, where a 40-plan slice contains 20 and is mostly cache hits.

---

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

---

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

### What real libraries require

Four of the eight parse to **nothing** by text alone, so the producer runs the actual C
preprocessor and keeps only what came from the target header — otherwise it proposes
harnesses for libc. Beyond that, each of these is a real shape a header producer has to
model, and each was found by a library that uses it:

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

---

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

---

## Producers propose, gates rank

The ranking [shown above](#1-propose-harnesses-from-a-header-and-rank-them-by-evidence)
involves no model. The header-graph producer parses declarations, infers roles and
contracts from signatures, and emits candidate IR. The ranking is by gate evidence only:
blocking violations, then positive-control kill rate, then sink surface, then gates that
did not run.

The winner is correct for a real reason. On the `cstring` plan the off-by-one mutant reads
the NUL terminator, which is in bounds, so that mutant survives; the length-delimited plan
has no such cover and kills both.

---

---
