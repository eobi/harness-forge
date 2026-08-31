# Where this stands — 2026-08-31

Written for whoever picks this up next, human or model. It says what is true, what is
filed, what is running, and what to distrust.

---

## The strategy, in one paragraph

Two competitors define the bar. **QuartetFuzz** (arXiv:2605.21824) audited 586 production
harnesses across 70 projects and landed 29 fixes including 3 CVEs — that is the FINDINGS
axis. **OGHarn** (ICSE 2025) beats developer-written harnesses by +14% median coverage —
that is the COVERAGE axis. On 2026-08-31 the operator overruled the earlier "differentiate,
do not compete" plan and directed us to contest both niches head-on. The reasoning and the
reversal are recorded in `plans/HOW-WE-WIN.md` under "DECISION, 2026-08-31".

---

## Session close: 2026-08-31

Everything below was true at the end of the 2026-08-31 session. Repo pushed, CI green.

**Done this session:** corpus scaled to 2,693 harnesses; two defects found, verified and
filed; gate false-rejection driven from 1.18% to **0.00% on 412 trusted lifts**; mutational
plan synthesis built (14-17x more valid candidates); and the negative-capability bound
finally published — **115 of 1,374 OSS-Fuzz projects cannot report a leak.**

**Not done, and blocked on hardware this project does not have:** campaigning the
synthesised candidates for the +14% coverage claim, and woff2's n=5.

**THE MACHINE IS NEVER IDLE.** Checked 2026-08-31: load average 37-41 on ten cores, with a
Jackalope fuzzing campaign nine days into its run and a VM three days into its. That is a
standing floor, not a passing spike. A fixed-TIME campaign measures spare CPU, so this box
cannot produce a valid coverage number at all -- not later, not overnight.

**THE "SECOND MACHINE" IS NOT ONE.** The Ubuntu VM at 192.168.68.2 answers on `bridge100`,
the macOS Virtualization.framework bridge. It is a guest on the same Mac, sharing the same
cores and the same load. It cannot serve the purpose PAPERS.md asks of it -- separating
campaign variance from host effects -- because it is the host. It CAN serve the GUI track,
which needs Linux and AT-SPI rather than CPU isolation.

Coverage work needs genuinely separate hardware: another physical box or a cloud instance.

---

## What is FILED upstream (real, verifiable)

| # | what | where | status |
|---|---|---|---|
| 0001 | bluez `fuzz_gobex.c` leaks a `GError` on every failed decode | [google/oss-fuzz#16081](https://github.com/google/oss-fuzz/pull/16081) | open |
| 0002 | leptonica `pix3_fuzzer.cc` passes NULL to three functions it means to test | [DanBloomberg/leptonica#813](https://github.com/DanBloomberg/leptonica/pull/813) | open |

Write-ups with full evidence are in `harness-forge/findings/`. Both were verified against
the library's own source before filing, not merely against our gate.

**0001** matters beyond the leak: `projects/bluez/build.sh` sets `detect_leaks=0` for that
target ALONE, and it is the only bluez harness touching a GError. The workaround and the
defect line up, and the cost is that the target can no longer report a leak in gobex
itself. The PR deliberately does NOT remove `detect_leaks=0` — we have not run the target
under LSan and cannot claim no other leaks remain. That follow-up is offered in the body.

**0002** is dead coverage, not a crash: `pixDestroy` nulls the pointer and each entry point
returns on `!pix`, so the functions are never executed and nothing says so. The first patch
attempt fixed one of three instances; the gate caught the other two before filing.

---

## The numbers that are real

    corpus              harnesses   lifted   trusted   blocking
    OSS-Fuzz tree             420      400       126          0
    upstream repos          2,273    1,542       286          2
                            -----
    total                   2,693    1,942       412          2

QuartetFuzz audited 586. About 45 candidates have been triaged BY READING THEM; **2 were
real, and both surviving blocking verdicts are correct** — leptonica/pix3 (filed) and
bazel-rules-fuzzing/oom_fuzz_test, a fixture whose own header says it is deliberately
broken. **False rejection: 0 of 412 = 0.00%.**

**The denominator must travel with that number.** 412 of 1,942 lifted harnesses is 21%; on
the other 79% the engine declines to opine. QuartetFuzz's 4.8% covers everything they
judged. Quoting 0.00% without that sentence would be dishonest.

Every other candidate was a defect in our own engine. Fixing them is what made the two real
ones visible.

## Negative capability, published

`tools/bounds.py`. **115 of 1,374 projects (8.4%) have `detect_leaks=0`** and cannot report
a leak; 24 cap input length; 5 allow allocations to return NULL silently. Every signal is a
literal build setting, never an inference.

`--cross-reference` asks which harnesses the gates say LEAK inside projects whose detector
is off. Answer across the tree: **one, bluez/fuzz_gobex — the one already filed.** The
method reproduces the hand-found case and finds nothing else, which is worth knowing: that
seam is not rich.

## Mutational synthesis

`hforge/producers/mutate.py`. Valid candidates **x14.2 (jansson), x16.6 (expat)**; gate
rejection **33.8% and 0.8%** on sound bases. Enumerated, not sampled — no seed to record.

**The +14% median coverage is NOT measured and NOT claimed.** Volume is the means; coverage
is the result. Only widen plans that already PASS the gates: mutating an invalid base
cannot make it valid, and measuring it reports base-plan quality instead of the mutation's
(that error was made and corrected in-session).

**pugixml is 1.00x, n=5**, five distinct libFuzzer seeds, gold measured in the same
container each run: ours 14.79 spread 0.00, gold 14.79 spread 0.49. We are more
reproducible than the hand-written harness on that case.

---

## What to DISTRUST

**woff2 has no valid number.** Three runs were taken while a 372-harness audit and a
421-test suite ran on the same 10-core box; executions came out 5.1M / 22.9M / 85.6M, a 16x
spread that is the machine, not the harness. The run was killed, not reported. Every record
now carries `load_average` and `machine_was_busy`. **Do not run anything else while a
benchmark runs.** woff2 needs a clean n=5 on an idle machine; it is the last single-sample
C++ row.

**Instrument defects are the recurring failure mode here, not code bugs.** Five so far, and
every one was caught by a number moving further than the change could explain, never by a
test:
- a fidelity signal that worked by GREPPING CLI TEXT, which "improved" 130 harnesses when
  the message changed
- a gold measured by a more generous method than ours
- an audit tool that never globbed `.cpp` and silently dropped ~half the upstream corpus
- a benchmark blind to machine load
- two regexes that did not terminate (the C++ producer's, and a declarator pattern that
  hung on freetype2 and openexr while passing 423 tests)

If a number moves more than your change justifies, the instrument is wrong. Check it first.

**A gate's LABEL can be wrong while the gate is right.** Finding 0002 was reported as a
use-after-free and a double free. Both are literally incorrect — the pointer is nulled, not
dangling — but the sequence was real and reading it found a genuine defect of another
class.

---

## What is running / parked

- **Nothing is running** as of this writing. The harvest (479 projects) is complete.
- Corpus lives at `/tmp/corpus2` (~2,262 files, ~7MB) and `/tmp/ossfz` — both are
  REPRODUCIBLE, not precious. `/tmp/harvest.sh` + `/tmp/repolist.txt` rebuild them.
- Docker benchmark image is required for any coverage work; `benchmarks/Dockerfile` pins
  clang/LLVM 14.0.6.

---

## Next, in order

1. **Campaign the synthesised candidates.** The +14% median is the only unmet target on the
   coverage axis, and the mechanism is built. NEEDS AN IDLE MACHINE.
2. **woff2 n=5 on an idle machine** — the last single-sample row. Same constraint.
3. **Chase the two open PRs.** oss-fuzz#16081 and leptonica#813. The findings-axis target
   was >=5 PRs with >=1 merged; we have 2 open, 0 merged.
4. **More bound signals.** `tools/bounds.py` currently reads four settings. Missing
   sanitizers, absent seed corpora and unbuilt code paths are all literal, checkable
   facts in the same vein.
5. **Wire the bound into the benchmark record.** `certificate.py` computes an unreachable
   list per plan; no benchmark result carries it. The corpus survey is published, the
   per-plan bound still is not.

---

## Rules that are not negotiable

- The engine never auto-prints "zero-day". That is a human act after triage.
- Coordinated disclosure, 90-day windows. Fuzz only authorised software.
- A benchmark row may carry only a number THIS repository produced; third-party figures go
  in a separate labelled column with a case id.
- QuartetFuzz's artifact carries no LICENSE: cloned outside the tree, read and reproduced
  against, never vendored.
- No Claude co-author trailer on commits.
- Never publish a finding without reading the library's own source first. Every candidate
  this engine has produced except two was its own defect.
