# Contributing

## The one rule

**A claim in this repository must be backed by something that runs.**

`tools/plancheck.py` enforces it: every deliverable the manifest marks `DONE` must name a
module that imports and a test that exists. CI runs it as a gate. If you cannot point at a
test, the status is `PARTIAL` or `PLANNED` — both are respectable, and both are used
throughout `hforge/manifest.py`.

The same rule governs the benchmark tables. `benchmarks/rank.py` regenerates them from
`results/*.jsonl` and `reference.json`, and the split between those two files is what keeps
measured figures and cited figures out of each other's columns. Numbers are never typed by
hand into a table; the table drifted twice when they were.

## Setup

```
git clone https://github.com/eobi/harness-forge
cd harness-forge
pip install pytest          # the only dependency, and only for the tests
python -m pytest -q
python tools/plancheck.py
python -m hforge selftest   # end to end on this machine; needs clang
```

The engine itself has **no runtime dependencies**. That is a constraint, not an accident:
it has to run where the target builds — inside somebody's OSS-Fuzz image, on a CI runner,
on an air-gapped box — and every dependency is one more thing that has to be there.

## Adding a producer

Producers propose; they do not decide. A producer emits candidate `HarnessIR` plans and
supplies **no score, no confidence and no preference** — ranking is by gate evidence alone.
If your producer wants to express that one plan is better, encode the reason as something a
gate can measure.

1. Emit `HarnessIR`, never C. The IR is the certifiable artifact; a backend that emits text
   directly cannot be compared, diffed or re-targeted.
2. Register with the emitter router (`hforge/emit/__init__.py`) if you add a language.
   No caller should name a backend; `plancheck` gate C12 enforces this.
3. Every shape you teach the producer needs a test named after the behaviour, not the
   function — `test_a_hungarian_prefixed_length_is_still_a_length`, not `test_lenish_2`.

## Adding a gate

A gate returns a **verdict plus its evidence**, never a boolean, and `NOT_RUN` is a distinct
outcome from `PASS`. If your gate cannot run — no sources, no sanitizer, no second producer
to compare against — say so with the reason. A gate that silently passes when it could not
check is worse than no gate.

State which phase it belongs to: static gates run on the plan before a compiler exists,
dynamic gates need a build, findings gates need a crash.

## Benchmarks

Read [`benchmarks/README.md`](benchmarks/README.md) first. Two things to know before adding
a case:

- **The denominator needs a ceiling argument.** Coverage is reported over the source an
  entry point can actually reach, and the justification goes beside the file list in
  `drive.py`. Three of this project's coverage figures were badly wrong because the file
  list included code the entry point cannot enter.
- **Logs outlive the run.** `results/logs/<run-id>/<case>/` keeps the harness, both
  invocations, libFuzzer's full output and the per-file coverage table. A summary row
  cannot be audited.

## Disclosure

Read [`SECURITY.md`](SECURITY.md). It is short and it is binding on contributions: fuzz only
what you are authorised to fuzz, findings go to the maintainer first, and nothing this
engine emits will call something a zero-day.
