# Where this project stands, and what is left to do

Written 2026-09-01 from measurements in this directory. Every number below is either produced
by this repository or cited as a competitor's published figure, and the two are never mixed
in the same column.

---

## The TODO

### Depth — beating each competitor at its own game

| # | item | why | effort |
|---|---|---|---|
| **D1** | **P3.LIFT: lift test sequences into IR plans** | The decision gate passed: a library's own tests reach a **median 66.7%** of the exported surface where our widest plan reaches **3.6%**. The only untried hypothesis on the coverage axis, and mutational synthesis — the other one — is refuted at +0.40%. | large |
| D2 | Long campaigns on the deepest harnesses | OGHarn runs **24 hours** per benchmark; we run 30 seconds. Sequenced AFTER D1: running longer on a harness that can touch 3 of 83 functions does not lift the ceiling. | time, not code |
| D3 | Target selection | We aim at saturated libraries. The DjVuLibre pattern — a parser shipped on millions of systems and never fuzzed — is where a finding actually lives. The one findings-axis item not refuted by measurement. | small |
| D4 | Apply seeds everywhere | The miner is built and measured. `fuzz_sweep` still starts every campaign empty, understating binary formats by up to **26x**. | small |
| D5 | GUI search | The oracle leads; the search does not, and guidance is measured level with blind at GUI budgets. Needs a different idea, not tuning. | medium |

**Deliberately NOT on this list: more harness auditing.** Three scaled runs found nothing
reportable. That is measured, not assumed.

### Breadth — the platform matrix

| # | item | why | effort |
|---|---|---|---|
| **B1** | **IR application entry point** | Roles today are `create/consume/destroy/query/reset`, all C-FUNCTION lifecycle. There is no application entry point, which is why CLI apps, GUI apps and mobile apps are blocked by ONE missing abstraction rather than three platform efforts. | large |
| B2 | Windows | Zero emission across all four variants. NTSTATUS handling and `.exe` suffixing are implemented and unit-tested from macOS and have never run on Windows. | small once a VM is up |
| B3 | Verify the 9 platforms that emit and were never run | The Linux CI pass found four real defects this way. | small each |
| B4 | GUI into the engine | Oracle, coverage and campaigns all work — in `benchmarks/`, driven by hand-written scripts. No GUI entry-point type, producer or emitter. | medium, needs B1 |
| B5 | Mobile applications | Intents, deep links, Binder/XPC, WebView. NOT the Android native-library track, which already works end to end on a real device. | large, needs B1 |
| B6 | iOS simulator emission | Detected and enumerated; nothing emitted. | medium |

---

## Comparison with the competition

Competitor figures are their published claims. Ours are measured here, with the file that
produced them.

| | QuartetFuzz | OGHarn | GUIFUZZ++ | **Harness Forge** | source (ours) |
|---|---|---|---|---|---|
| harnesses audited | 586 / 70 projects | — | — | **879 / 124 projects** | `corpus-audit/` |
| upstream fixes landed | **29 fixed, 3 CVEs** | — | — | 1 merged, 1 open | `AXIS_1_FINDINGS` |
| bugs found | via audit | **41** | **23** across 11–12 apps | **0** | — |
| coverage vs developer harnesses | — | **+14% median** | — | ~parity; synthesis **+0.40%** | `AXIS_2_COVERAGE` |
| false-positive rate | 4.8% of everything judged | 0 | — | **0 of 154 high-fidelity** | `corpus-audit/` |
| campaign length | — | **24 hours** | — | 30 seconds | `fuzz-campaign/` |
| C++ class APIs | — | C only | — | **yes** | `COMPETITORS.md` |
| negative-capability certificate | **none stated** | none | none | **yes** | `AXIS_3` |
| silent-failure taxonomy | none | none | none | **7 mechanisms** | `NEGATIVE_RESULTS` |
| seed mining, measured | — | — | — | **20–27x on binary formats** | `seeds/` |
| GUI oracle: refused vs hung | — | — | signal-based | **AT-SPI** | `GUI_TRACK` |
| platforms emitting | — | — | — | 12 (no Windows, no iOS) | `hforge platforms` |

### Reading it honestly

We lead on scale, on C++ class APIs, and on the two axes nobody contests. We lose on the two
that are published and peer-reviewed: **1 upstream fix against 29, and +0.40% against +14%.**

Our 0% false-positive rate is **not comparable** to QuartetFuzz's 4.8%. Theirs is over
everything they judged; ours is over the 154 lifts of 518 the engine will opine on at all. We
buy precision by abstaining on about 70%.

**The two losing cells are connected.** Findings are downstream of coverage: a harness that
reaches 3 of 83 exported functions cannot find much, however long it runs. D1 is the only item
on the list with a measured number justifying it, and it is the one that could move both.
