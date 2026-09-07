# Deeper: comparison feedback + the hunt on under-fuzzed targets — 2026-09-06

Two follow-ups to the native-Windows work, both requested and both done.

## 1. Value-profile comparison feedback (Windows engine)

The native driver's trace-cmp hooks were no-ops. They now implement value profile: a feature
is derived from the count of matching high bits of `a ^ b` at each comparison site, so a
mutation that gets one bit closer to satisfying `if (x == MAGIC)` is KEPT and the gate is
climbed incrementally instead of needing an exact random hit. The compared operands are also
pushed into a table of recent constants the mutator injects. Built with
`-fsanitize-coverage=trace-pc,trace-cmp`.

Measured on stb_image (same 60s budget): the retained corpus grew 148 -> 465 -- far more
distinct-progress inputs kept, i.e. the fuzzer is climbing comparisons rather than stalling.

## 2. cstring channel drives multi-argument parsers

app-lift could only take a lone `char*`. A large class of real parsers is
`f(char *content, config...)` -- e.g. an SVG parser's `parse(input, units, dpi)`. The cstring
channel now fills the trailing arguments safely (scalar 0, const char* config "", non-char
out-pointer to a local) and refuses a writable char*/void* after the content (an output
buffer it cannot size). This unlocked a rich SVG parser: 1127 edges / 6780 features live
under ASan within 30s. 497 tests pass.

## 3. The hunt: pipeline pointed at under-fuzzed loaders

Ran the full pipeline (auto-generated harness -> auto-mined dict -> libFuzzer + ASan) against
single-header image / vector / archive parsers that are far less hardened than stb_image or
jansson. One target -- an under-fuzzed, widely-embedded single-header parser -- produced a
CONFIRMED, deterministic, 28-byte-minimized heap-buffer-overflow through its public parse
API, found by an AUTO-GENERATED harness (no hand-written driver). It is distinct from that
library's known CVEs.

Held for COORDINATED DISCLOSURE: the reproducer and the exact location live in a PRIVATE
tracker, never in this public repo, until the maintainer is notified. This is the point of
the whole program -- the certification pipeline that generates the harness also FINDS the
bug, and on a target a human had not harnessed.

## Honest read
- The comparison-feedback and multi-arg-parser work are real capability gains, measured.
- The bug is real (deterministic, minimized, via the public API, ASan-confirmed, not
  harness-induced) and was found by an auto-generated harness -- the strongest evidence yet
  that the generator produces harnesses that do the job. Novelty vs the library's issue
  tracker gets a final check before disclosure; it is not among the known CVEs.
