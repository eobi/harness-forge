# Replicating these numbers, and what to do when they disagree

Every figure in this repository was produced by one person on one machine. That is the
single largest weakness in the evidence, it is not fixable from inside, and this file
exists to make disagreeing with us cheap.

**We would rather publish your contradiction than keep an unverified number.** If a run of
yours disagrees with a row here, open an issue with the two JSON records attached; the
disagreement gets recorded in `results/` beside our own, and the table gets a note. A
number nobody else has reproduced is a claim, not a measurement.

---

## What you need

Docker, and about 8 GB of disk for the target trees. Nothing else — the engine has no
runtime dependencies beyond Python 3.9+, and the compiler, sanitizers and coverage tooling
are all inside the image so that two runs differ in the engine and not in the toolchain.

```console
$ git clone https://github.com/eobi/harness-forge && cd harness-forge
$ docker build -t hforge-linuxbench benchmarks/                # the reference environment
$ benchmarks/fetch.sh /tmp/hf-bench                            # targets, at pinned tags
$ benchmarks/run.sh myrun-001 600                              # the whole suite, 600s/case
```

`fetch.sh` clones every target at a pinned tag and writes `/tmp/hf-bench/versions.json` by
reading the resolved SHA back out of each clone. **Check that file first.** If your SHAs
differ from ours, nothing after this point is comparable, and that is worth knowing before
you spend the machine time rather than after.

A single case, if the full suite is more than you want to run:

```console
$ benchmarks/run.sh myrun-001 600 pugixml/parse
```

---

## How to compare, and it is not by comparing one number to one number

**Run each case at least five times.** This is the part most likely to produce a false
disagreement, and we learned it the hard way on our own numbers:

| case | our spread over 5 runs | what a single sample proves |
|---|---|---|
| pugixml/parse | **±0.00 points** | almost everything |
| libyaml loader | ±3.55 over 9 runs, bimodal | little |
| woff2/convert | **±16.4 points** | nothing at all |

There is no such thing as "fuzzing variance" as a number you measure once and reuse — it is
a property of the target. On woff2 the campaign starts from an empty corpus with no fixed
libFuzzer seed, and on a format where a valid container must be built before the decoder is
reached at all, run-to-run luck dominates everything else. Our own median there was 1.39x
the developer harness and an exact Mann-Whitney test put it at **p = 0.55**: no difference
at all.

So:

* compare **medians with their spreads**, not points;
* `rank.py` prints `n=N ±spread` for any case measured more than once, and prints
  `n.s. (p=…)` in place of a ratio the samples cannot support;
* a disagreement inside the spread is agreement.

Every result record carries `libfuzzer_seed`, so a single surprising run can be replayed
exactly with `-seed=N` rather than only re-rolled.

---

## Two confounds we found in our own comparison, in case you inherit them

Both were fixed on 2026-08-30. If you are comparing against numbers published before then,
these are why they moved:

1. **The D3 gate seeded our campaign and not the baseline's.** It ran the harness for 400
   executions against the campaign's own corpus directory, and libFuzzer writes
   newly-interesting inputs back into any corpus directory it is given. Our harness
   therefore started with inputs a fuzzer had already found for it; the developer's, which
   does not run our gates, started from the mined seeds alone. On a case with no seeds the
   effect is the entire starting corpus. **This ran in our favour.**
2. **The baseline was scored by a more generous coverage method.** Ours came from replaying
   the retained corpus; the baseline's came from the profile the campaign itself wrote,
   which counts every input ever executed. **This ran against us.**

Both are now symmetric, and each result records `corpus_files_at_start` and
`coverage_from` so you can check rather than trust. If you find a third asymmetry, that is
exactly the kind of issue we want.

---

## What counts as a real disagreement

* **Different SHAs in `versions.json`** — not a disagreement, a different experiment.
* **A gap inside the spread** — agreement. Publish it anyway; agreement is evidence too.
* **A gap outside the spread, same SHAs, same budget** — a real disagreement, and the most
  useful thing you can send us.
* **A case that refuses to build on your host** — also worth an issue. Nine of our platform
  claims are "emits but never run on hardware", and a build failure on a machine we do not
  have is information we cannot get any other way.

## The machine is part of the experiment

**Added 2026-08-31, after it invalidated a run.**

Every case here is a fixed-TIME campaign: 600 seconds, however far the target gets. So
coverage is a function of available CPU, and anything else running on the box is part of
the measurement whether you meant it to be or not.

This was found the expensive way. Three supposedly identical woff2 runs, taken while a
372-harness audit and a 421-test suite were running on the same 10-core machine, produced
executions of **5.1M, 22.9M and 85.6M** — a 16x spread. Coverage followed: 14.36%, 29.79%,
29.79%, against a gold that itself swung 39.50% to 29.79%. Nothing in the driver noticed,
and the medians looked publishable.

woff2 is unusually exposed to this because it runs with **no seed corpus at all**
(`seeds: 0`, `corpus_files_at_start: 0`): both sides start from nothing, so the result is
whatever libFuzzer discovered in the time it was given. A case with seeds is steadier —
pugixml, seeded, returned 14.79% five times with a spread of 0.00 — but no case is immune.

**The rule: do not run anything else while a benchmark runs.** Not a test suite, not an
audit, not a build.

Each record now carries `load_average` (1/5/15-minute and CPU count) and a
`machine_was_busy` flag, set when the 1-minute load exceeds a quarter of the cores. This is
recorded, not enforced: refusing to start on a loaded machine would silently produce no
data, which is worse than producing data you can filter. A sample with `machine_was_busy`
true is not evidence and should be discarded or re-run.
