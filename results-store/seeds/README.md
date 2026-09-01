# Does mining a library's own repository for seeds change coverage?

**It depends on the format, and the split is the result.** Paired campaigns: the SAME BINARY
runs both arms back to back with the same 30s budget, and only the corpus differs. Arms
alternate which runs first. Sign test, not Mann-Whitney, because the arms are paired.

| round | formats | pairs | better / tied / worse | median ratio |
|---|---|---|---|---|
| 1 | cjson, jansson, zlib, libyaml (text) | 20 | 10 / 4 / 6 | **1.0015** (+0.15%) |
| 2 | libwebp, lcms2 (binary, pilot) | 6 | **4 / 2 / 0** | **1.0169** (+1.69%) |

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
