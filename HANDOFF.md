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

    corpus              harnesses   lifted   trusted   flagged
    OSS-Fuzz tree             420      400       130         0
    upstream repos          2,262    1,542       294        ~9
                            -----
    total                   2,682                 424

QuartetFuzz audited 586. Roughly 40 candidates have been triaged BY READING THEM; 2 were
real. Every other one was a defect in our own engine, and fixing them is what took the
leak tier from 26 trusted reports to single digits while the trusted tier GREW.

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

1. **Triage the remaining ~9 flagged candidates** in the upstream corpus. `pix4_fuzzer.cc`
   is mid-triage: `na1` reports a double destroy and the cause is not yet established.
2. **woff2 n=5 on an idle machine** — the last single-sample row.
3. **Gate false-rejection rate against known-good harnesses.** This is the PREREQUISITE for
   mutational synthesis and it is unmeasured. Starting synthesis without it is flying blind
   into the item most likely to fail.
4. **Mutational plan synthesis** — the OGHarn axis. Measured fact: our RANKING is not the
   bottleneck (selection costs 0.63 points on libyaml, 0.00 on libpng); the CANDIDATE SPACE
   is. Target: candidate volume 10x, gate rejection rate published, >= +14% median.
5. **Publish the reachability bound.** It is computed in `certificate.py` and recorded in
   NO benchmark result. Half the differentiator, sitting unused.

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
