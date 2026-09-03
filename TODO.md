# What is left, and what would make it beat the field

Written 2026-09-03 against `hforge/manifest.py` (the deliverable record), `README.md` (what
this project claims to be) and `results-store/` (what has actually been measured). Every
target below is a NUMBER, not a direction, so each item can be closed or abandoned on evidence.

---

## The tension to name first

The README is explicit: **"this is not a generator. It is an IR, a gate bank and an evidence
record."** That identity decides which competitor each fight is with.

- **QuartetFuzz is the on-identity competitor.** It audits harnesses; so do we. Beating it is
  a certification claim.
- **OGHarn is the off-identity competitor.** It generates harnesses and reports +14% coverage
  over developer-written ones. Contesting that means competing as a GENERATOR, which the
  README says we are not.

Both fights are worth having, but they are not the same fight, and the second one changes what
this project is if it succeeds. That should be a deliberate choice rather than a drift.

---

## Depth — beat a specific competitor at its own number

### D1. Composed sequences (P3, producers)
**Beats OGHarn when:** a generated harness reaches **>1.14x** the coverage of the library's own
developer-written harness, median over >=5 libraries, >=3 repeats, seeded, paired.

**Where we are: 0.90x on jansson, 0.64x on cjson.** P3.LIFT lifts a single test; jansson had
one test (`embed`) that both parses and dumps, cjson has none, and cjson is pinned at 0.64x
however it is ranked. **A lifted harness can only be as good as the best single test function.**
Composition -- joining a parse test to a dump test -- is the only idea that can exceed the
suite, and it is the first that INVENTS a sequence rather than observing one. That is the
territory where mutational synthesis failed (libyaml: all 8 candidates aborted on valid input),
so the smoke test and gates are what keep it honest.

### D2. Long campaigns (T0.4 -- infrastructure done, never run)
**Beats nobody on its own.** OGHarn runs 24 hours per benchmark; every number we hold is from
15-30 seconds. This converts reach into findings and must come AFTER D1, because running longer
on a harness that touches 3 of 83 functions does not lift a ceiling.

### D3. Target selection (T0.1 -- done, never pointed anywhere new)
**Beats QuartetFuzz when:** we land upstream fixes in parsers nobody has fuzzed. **We are 1
merged against their 29.** Three scaled audit runs (62, 879, 1401 harnesses) found nothing
reportable, so grading MORE harnesses is measured as a dead end. The remaining lever is
choosing targets nobody has looked at -- the DjVuLibre pattern.

### D4. GUI search (P6.TERM answered, search unbuilt)
**Beats GUIFUZZ++ when:** we find bugs in real desktop applications. They found 23 across
11-12 apps; we have found 0. Our AT-SPI oracle is genuinely ahead -- it separates a target
REFUSING an input from one that HUNG. The search around it is not, and coverage guidance is
measured level with blind at GUI budgets. Needs a different idea, not tuning.

---

## Breadth — make the matrix true

### B1. IR application entry point (blocks P5, P6, P7)
Roles today are `create / consume / destroy / query / reset`: all C FUNCTION lifecycle. There
is no application entry point of any kind. **This is why CLI apps, GUI apps and mobile apps are
blocked by ONE missing abstraction rather than three platform efforts.** Highest-leverage
breadth item on this page.

### B2. Windows (P5, 0/2)
Zero emission across all four variants, while NTSTATUS handling and `.exe` suffixing are
implemented and unit-tested FROM macOS and have never executed on Windows. Small once a VM
exists, and independent of B1. **Closes an unverified leg of the cross-platform claim.**

### B3. GUI into the engine (P6.DROP / P6.DIALOG, both PARTIAL)
The Linux GUI RESEARCH track is finished: AT-SPI oracle, coverage feedback, 5,000-input
campaigns, ~20 applications, and P6.TERM now has data. **None of it is in the engine** -- every
line is hand-written script under `benchmarks/gui/`. There is no GUI entry-point type, producer
or emitter, so Harness Forge can RUN a GUI harness and cannot GENERATE one. Needs B1.

### B4. Verify the nine platforms that emit and were never run (PX)
Each is a short exercise that either confirms a claim or finds a defect. The Linux CI pass
found four real ones this way.

### B5. Mobile applications (P7, 0/3)
Intents, deep links, content providers, Binder/XPC, WebView. NOT the Android native-library
track, which already works end to end on a real device. Needs B1 and is the largest item here.

---

## Sequencing, and the argument for it

**D1 first.** It is the only item with a measured number justifying it (0.07x -> 0.90x already),
and it is the only one that can contest a published figure this quarter.

**B2 second.** Small, independent, and it removes an unverified claim from the matrix.

**B1 third**, then B3 and B5 behind it.

**D3 runs in parallel with anything** -- it is target choice and machine time, not engineering.

Deliberately NOT on this list: more harness auditing. 879 harnesses across 124 projects with
the contract gates live produced zero reportable defects, and that is the third run to say so.
