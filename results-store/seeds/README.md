# Does mining a library's own repository for seeds change coverage?

**It depends on the format, and the split is the result.** Paired campaigns: the SAME BINARY
runs both arms back to back with the same 30s budget, and only the corpus differs. Arms
alternate which runs first. Sign test, not Mann-Whitney, because the arms are paired.

| round | formats | pairs | better / tied / worse | median ratio |
|---|---|---|---|---|
| 1 | cjson, jansson, zlib, libyaml (text) | 20 | 10 / 4 / 6 | **1.0015** (+0.15%) |
| 2 | libwebp, lcms2 (binary, pilot) | 6 | **4 / 2 / 0** | **1.0169** (+1.69%) |
| 3 | libwebp, lcms2, jbig2dec (binary) | 10 | **8 / 2 / 0** | **1.25** (+25%) |

**Round 3 settles it: exact sign test on 8 non-ties, two-sided p = 0.0078.** On structured
binary formats, seeds mined from the library's own repository significantly improve coverage.

Round 1 sign test p=0.4545. Round 2 is 4 wins and no losses, but only 4 non-ties, so the
smallest attainable two-sided p is 0.125 -- **directionally clean, not significant.** A
larger binary-format round is what decides it.

Per library, which is where the story is:

| library | n | median ratio | note |
|---|---|---|---|
| libwebp | 4 | **1.1250** | two harnesses at +25%, two unchanged |
| lcms2 | 2 | 1.0169 | both +1.7% |
| zlib | 8 | 1.0561 | the one binary-ish format in round 1 |
| jansson | 4 | 1.0000 | its harnesses sit at coverage **4**; nothing could help |
| cjson | 8 | **0.9151** | seeds made it WORSE |

## The number that matters, and it is not the median

The median ratio of 1.25 hides a bimodal result. Per library:

| library | n | median ratio | |
|---|---|---|---|
| jbig2dec | 4 | **24.96** | 20.98, 23.71, 26.22, 27.25 |
| libwebp | 4 | 1.125 | two at +25%, two unchanged |
| lcms2 | 2 | 1.017 | both +1.7% |

**jbig2dec is the whole argument in one table:**

| arm | executions | edges covered |
|---|---|---|
| empty corpus | **2,825,426** | 32 |
| seeded (5 files) | **155** | **839** |

2.8 MILLION random inputs die at the JBIG2 signature check and reach 32 edges. 155 inputs
mutated from one real 860-byte `.jbig2` file reach 839. That is not a tuning gain; it is the
difference between fuzzing a format and fuzzing its header check. The arms alternated which
ran first, so it is not an ordering artifact.

Note also that only ONE of the five mined seeds is a real .jbig2 file -- the others are a
makefile and two extensionless files the miner could not rule out. The miner does not need to
be precise, because libFuzzer discards what adds no coverage. It needs to find the one file
that matters.

## What this means for every coverage number already recorded

Every campaign in the corpus-scale sweep ran with an EMPTY corpus, and probe_synth runs on a
single synthetic `a: 1\n`. For text formats that changes little. For structured binary
formats it means those numbers measure the signature check, not the parser -- and the
mutational-synthesis verdict of +0.40% was measured in exactly that condition.

The coverage axis has to be re-measured seeded before anything about it is claimed again.

## Why round 1 was the wrong test, stated plainly

Three of its four libraries parse TEXT -- JSON twice and YAML. A fuzzer reaches valid JSON
from an empty corpus in seconds, so a seed corpus has almost nothing to add, and cjson shows
it can actively cost: the mined seeds crowd out the mutator's own progress. The hypothesis
that seeds matter is about STRUCTURED BINARY formats, where a random mutation is rejected at
the signature check. Round 1 does not test it. It is kept because it bounds where seeding
does NOT help, which is a real thing to know.

## The result that was nearly thrown away

Every seeded libyaml campaign reported no coverage, and the first reading counted 8 "failed
campaigns". They were not failures. **libFuzzer exits on finding a leak and prints no final
stats** -- the seeds had found one in seconds that the empty arm never reached in 30s.

The leak was OURS: a plan called four `yaml_*_event_initialize` calls on one event struct
with a single `yaml_event_delete`, and every call but the last leaked. Now refused at the
producer.

**An arm that "fails" more often may be the arm that works.** A summary line alone would
have said seeding was unstable on libyaml.

## What is NOT claimed

That seeding helps in general. On text formats it did nothing and on cjson it hurt. The
binary-format result is 4 wins from 6 pairs and needs the larger round before it is a claim.
