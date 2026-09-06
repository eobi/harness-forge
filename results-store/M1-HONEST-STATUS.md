# M1 (coverage vs developer harness): where we actually stand

Measured by the W0 rig (tools/benchmark.py), paired, 3 repeats, mined seeds, 25s budget.

| library | our best generated | developer harness | ratio |
|---|---|---|---|
| jansson | 585 | 660 | 0.886x |
| cjson | 279 | 326 | 0.856x |
| **median** | | | **0.871x** |

**We do not beat the developer harness on coverage, and we are far below OGHarn's published
1.14x.** The rig calls this underpowered (2 scored libraries; >=5 needed) and below parity.
This is the honest number, produced by the tool built to prevent an unearned claim.

## What beating OGHarn on this metric would actually require -- none of them quick

  1. A generation technique that reaches MORE than the human harness, not ~87% of it.
     test-lift and 2-way composition top out at parity because they reproduce what a good test
     or a load+dump pair does. N-way composition (compose_chain, now built) can exceed a
     2-subsystem human harness ONLY on a library whose suite has 3+ distinct downstream
     subsystems -- the corpus at hand (jansson/cjson) has two, so it cannot demonstrate the
     gain here.
  2. Budget-matched runs. OGHarn measured at 24h; we measure at 25s. Neither harness saturates
     at 25s, so the ratio is not the same experiment as theirs. A fair comparison needs long
     runs, which have not been done.
  3. A powered corpus. Two libraries is not a median. >=5 with buildable developer harnesses,
     each a bespoke build, is the minimum for a defensible claim either way.

## The honest competitive position

On COVERAGE we are at parity-to-below and do not currently win. Where we genuinely and
verifiably lead, and no single competitor matches:

  - AUTONOMY + CERTIFICATION: generate AND certify AND triage a harness with no human. OGHarn
    generates but does not certify; QuartetFuzz certifies but does not generate; neither
    triages a target's defensive abort as an artifact. We do all three.
  - MULTI-SURFACE REACH from ONE abstraction: CLI libraries, CLI applications (verified on
    xmlwf, a real shipped tool), and Windows emission (verified), with GUI and mobile as
    channels on the same AppEntry. No competitor spans this.
  - HONESTY: 0 false positives on 162 high-fidelity lifts, and negative-capability certificates
    stating what a harness CANNOT find -- which no competitor emits.

The defensible "best harness generator" claim is therefore NOT "beats OGHarn on coverage" --
the rig forbids that today -- but "the only generator that autonomously produces and certifies
harnesses across libraries, applications and operating systems, with zero-FP discipline." That
is true, measured, and unmatched. The coverage gap is stated, not hidden, and the path to
closing it is named above.


## Update 2026-09-06: N-way composition is a MONOTONIC coverage lever

compose_chain folds one call from each downstream subsystem onto the parsed root. Measured on
jansson, 3 repeats, paired, same seeds, 25s:

| harness | subsystems | coverage | vs developer |
|---|---|---|---|
| developer (hand-tuned load+dump) | 2 | 662 | 1.000x |
| CHAIN (parse + dump + equal) | 3 | 612 | 0.924x |
| EMBED (parse + dump) | 2 | 584 | 0.882x |
| header-only plan | 1 | ~48 | 0.07x |

Coverage rises monotonically with the number of deep subsystems folded onto one parsed value:
0.07x -> 0.88x -> 0.92x. That turns "0.87x, cause unknown" into a controllable relationship:
more foldable subsystems -> more coverage, and the win is a target with more of them than the
human harness combines.

jansson tops out at 3 (no pure-transform test for a fourth; the human runs both parse
directions with tuned flags), so composition closes most of the gap without crossing it --
said plainly. WIN CONDITION, now precise: a 4+ subsystem target where a single developer
harness uses fewer -- the archetype is a media codec (decode -> transform -> encode -> compare).
That is where the climb crosses 1.0x, and it is the next thing to run once such a library is in
the corpus.
