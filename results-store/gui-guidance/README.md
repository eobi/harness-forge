# Does coverage guidance beat blind mutation on a GUI target?

**As implemented on 2026-09-01: no. It was worse, and sometimes it collapsed.**

Raw: `guided-vs-blind-as-implemented-2026-09-01.jsonl`. Target eog over instrumented libpng,
20 inputs per campaign, 4 paired repeats per arm, same seed file, RNG paired so repeat *k* of
each arm starts from the same mutation stream.

Both arms are instrumented IDENTICALLY. Only the selection differs: the guided arm breeds
from inputs that reached a region nothing else did, the blind arm always mutates the original
seed. Turning instrumentation off in the blind arm would compare two different programs and
credit the difference to guidance.

| arm | cumulative regions | median | spread |
|---|---|---|---|
| guided | 2112, 2125, 3141, 3282 | 2633 | **1170** |
| blind | 3250, 3250, 3264, 3275 | 3257 | **25** |

Exact Mann-Whitney U=4.0, two-sided **p=0.2857**. At n=4 per arm this is **not significant**,
and it is not claimed to be. The minimum attainable two-sided p for 4-vs-4 is 0.0286, so this
design could have detected a clean separation and did not.

## What is worth reporting is not the median, it is the spread

Blind varied by 25 regions across four runs. Guided varied by 1170 and was bimodal: two runs
matched blind, two collapsed to about 2110 with **0 of 20 inputs accepted by the target**.

The mechanism is mechanical rather than statistical. The guided arm breeds from mutants, so
corruption compounds and the lineage drifts away from being a valid PNG; the blind arm always
returns to the pristine seed. Once the guided arm's corpus contains only damaged inputs it
cannot recover, because nothing ever puts a valid input back.

This is not a subtle finding about search. It is a missing invariant: **the seed belongs in
the corpus permanently**, which is what every production fuzzer does and this loop did not.

## Status

This file records the AS-IMPLEMENTED behaviour so the fix can be measured against it. A
guidance loop that loses access to a valid parent is not a fair test of whether guidance
helps -- it is a test of whether this particular bug hurts, and it does.
