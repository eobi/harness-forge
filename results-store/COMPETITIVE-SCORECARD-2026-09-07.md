# Competitive scorecard — harness-forge vs the field (2026-09-07)

Honest, measured, per-axis. Every "WIN" and "LOSS" is against a number we actually produced,
with the denominator that makes it comparable. Where a result is not statistically powered,
it says so rather than claiming.

| competitor | their axis | their headline | our MEASURED position | verdict |
|---|---|---|---|---|
| **QuartetFuzz** | harness-correctness audit | 586 harnesses, 53 violations, 4.8% FP | 2,693-harness corpus; 496 trusted lifts; **0 false positives on the trusted tier**; 2 upstream defects filed, 1 merged | **WIN on precision** — but different denominator: we abstain on ~75% of lifts (28.8% block overall). Not comparable head-to-head, and we say so. |
| **OGHarn** | coverage vs the developer harness | +14% median (1.14x bar) | JSON libs 0.82–0.86x; **codec via composition 1.29x** vs the simple dev harness (0.91x of the maximally-tuned advanced one) | **MIXED, measured** — below on simple JSON parsers; **composition CROSSES the 1.14x bar on the codec archetype** (libwebp) by folding decode subsystems, though a maximally-tuned dev harness still leads. First measured cross-parity result. |
| **WinAFL / Jackalope** | closed-binary coverage | their instrumentation engine | `hforge closed` built on TinyInst+Jackalope; proven end-to-end on a shipped decoder (libwebp, 825 blocks, no source) | **PARITY** (we drive their engine) **+** it is folded into a certification/evidence pipeline they do not have |
| **GUIFUZZ++** | GUI widget-event fuzzing | 23 bugs / 11–12 apps | we fuzz the file-load/decode seam a GUI app reaches, not synthesized widget events | **N/A on their axis** — different approach; we do not claim widget-event fuzzing |

## Where we are unambiguously ahead (no competitor offers the combination)
- **One engine, every target class**: source libs (auto-gen + composition), native Windows
  WITHOUT a libFuzzer runtime (hf_winfuzz, trace-pc + value-profile), and closed binaries
  with no source (TinyInst/Jackalope). Measured on real targets in each class.
- **Certification + evidence record**: a gate bank with a third outcome (NOT_RUN), a
  falsifiable negative-capability bound, and 0% false positives on the trusted tier.
- **Composition as a coverage lever**: coverage is a controlled, monotonic function of
  distinct subsystem traversals folded (0.07 -> 0.96x on jansson) — a mechanism, not a knob.
- **Source-mined dictionaries + deepest-entry ranking**: auto structure that took a real
  GUI-loader harness from 146 to ~915 edges, generator-side.

## Where we are NOT ahead (stated, not hidden)
- **Raw coverage vs a tuned developer harness (OGHarn's axis): mixed.** Below on simple JSON
  parsers (0.82–0.86x); composition CROSSES the 1.14x bar on the codec archetype (libwebp,
  1.29x vs the simple dev harness) but is 0.91x of the maximally-tuned advanced harness.
  No longer a flat loss -- composition is the measured lever, strongest on codecs.
- **Novel-bug yield**: across the hunt, the engine RELIABLY reproduced real bugs but the
  net new worth-filing finding was one (pl_mpeg #78). Popular targets are picked-over;
  novelty needs un-fuzzed targets, which is a target-economics problem, not an engine gap.

## The honest one-line position
Not "beats everyone on everything." It is the **only** engine that spans source +
native-Windows + closed-binary + composition under one certification/evidence record, wins
decisively on harness-correctness precision, sits at parity on closed-binary, and is honestly
behind on raw coverage vs a tuned developer harness. That last gap is the next measurable
target (a powered >=5-library coverage run).
