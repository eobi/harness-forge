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

---

# After the fix: guidance is not worse. It is also not better.

Raw: `guided-vs-blind-seed-retained-2026-09-01.jsonl`. Same design, 8 paired repeats
(one guided campaign failed to record its row, so guided n=7, blind n=8).

| arm | cumulative regions | median | spread |
|---|---|---|---|
| guided | 2148, 3246, 3251, 3257, 3259, 3273, 3281 | 3257 | 1133 |
| blind | 3250, 3250, 3253, 3264, 3275, 3278, 3278, 3284 | 3270 | 34 |

Exact Mann-Whitney U=19.0, two-sided **p=0.3211**. Median ratio guided/blind = **0.996**.

**Keeping the seed in the corpus fixed the collapse it was supposed to fix.** Campaigns that
accepted zero of 20 inputs went from 2 of 4 to 1 of 7, and the guided median rose from 2633
to 3257 -- level with blind.

**It bought nothing else.** Guidance now performs identically to blind mutation: a 0.4%
difference in medians, with blind still six times more consistent (spread 34 against 1133).

## This design could have found a difference

For n=7 against n=8 the minimum attainable two-sided p is 0.00031. The experiment had ample
power to detect a clean separation and did not find one. The claim is therefore not "we could
not tell" but "at this scale there is nothing to tell".

## Why, stated as a hypothesis rather than a conclusion

Coverage guidance pays off over many generations. A GUI campaign cannot afford them: each
input costs several seconds of application startup, so 20 inputs is the whole budget, and the
seed is already a valid file. Blind mutation from a known-good parent is a strong baseline
under exactly those conditions, and guidance has too few generations to compound an advantage.

That is a claim about the regime, not about guidance in general, and it is falsifiable: run
the same comparison with a budget large enough for hundreds of generations and it should
change. Nothing here licenses the broader claim.

## What is NOT claimed

That coverage guidance is useless. That GUI fuzzing should be blind. Only that on this
target, at this budget, with this seed, guidance did not beat mutating the seed directly --
and that the first version of it was actively harmful because it dropped the seed.
