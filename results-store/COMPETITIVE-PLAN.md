# Beating every CLI and GUI competitor, proven by live measurement

Goal (operator, this session): beat all CLI and GUI competitors on all metrics, each proven
by a live run, not a claim. This plan is honest about where that is a credible path and where
"beat" is realistically "match, and add what they do not have." Nothing here is scored until
the measurement rig (W0) produces the number.

## The competitors and their published bars

| competitor | domain | their bar (published) |
|---|---|---|
| OGHarn (ICSE'25) | CLI, C, harness generation | **+14% median coverage** over developer harnesses; 41 bugs; 0 FP; 24h campaigns |
| QuartetFuzz | CLI, harness auditing | **586 harnesses / 70 projects**; 42 reports, **29 fixed, 3 CVEs**; 4.8% FP |
| WinAFL | Windows CLI, closed binary | mature coverage-guided DBI (DynamoRIO/PT/TinyInst) |
| Jackalope | Windows+macOS, incl. GUI | black-box coverage-guided (TinyInst), GUI-capable |
| GUIFUZZ++ | GUI | **23 bugs across 11-12 apps** |
| Hopper | CLI generation | 40-100% FP (already beaten: ours ~0) |

## The metrics ("all metrics"), our measured position now, and the target

| # | metric | competitor bar | ours NOW (measured) | target to beat |
|---|---|---|---|---|
| M1 | coverage vs developer harness | OGHarn 1.14x | test-lift 0.88-1.01x; header-only 0.07x | **>1.14x median, >=10 libs** |
| M2 | upstream fixes / bugs | QuartetFuzz 29+3 CVE; OGHarn 41; GUI++ 23 | 1 merged | **>29 CLI fixes; >23 GUI bugs** |
| M3 | false-positive rate | OGHarn 0; QuartetFuzz 4.8% | 0 on 162 hi-fi lifts | **hold <=0 while scaling** |
| M4 | autonomy (generate + certify, no human) | none do it | **yes -- unique** | **keep the moat, measure it** |
| M5 | reach: {Linux,Windows,macOS} x {CLI,GUI} | fragmented per tool | Linux/mac/Win CLI emit; Win CLI verified | **all six cells live** |
| M6 | GUI oracle: refused vs hung | signal-based can't | AT-SPI works (Linux, research) | **in-engine, all 3 OSes** |

## Workstreams

### W0 -- the live-measurement rig (the linchpin; nothing counts without it)
A reproducible benchmark that, per competitor, runs the COMPARABLE protocol and reports our
number against their bar with confidence. Paired (our harness vs the baseline, same corpus,
same budget, arms alternated), repeated (>=5), exact stats (sign test / Mann-Whitney), and the
denominator discipline from P1 (coverage is only comparable under one fixed build+scope). One
command -> a scoreboard row per metric with CI. Everything below is gated on W0.

### W1 -- CLI coverage depth (beats OGHarn, M1)
Scale test-lift + composition to >=10 libraries; 3-subsystem composition; unit-test corpus
mining. Match OGHarn's BUDGET (they ran 24h; a 25s run is not a fair loss). Apples-to-apples:
report BOTH header-only (OGHarn's input) and test-lifted (our stronger input), labelled.
GATE: median generated-vs-developer > 1.14x over >=10 libs, >=5 repeats.

### W2 -- CLI findings (beats QuartetFuzz, M2)
Target selection (parsers/apps nobody has fuzzed -- the DjVuLibre pattern), app-lift on real
shipped CLIs (xmlwf proved reach), long campaigns, coordinated disclosure. GATE: >29 upstream
fixes landed, FP held at ~0.

### W3 -- Windows CLI depth (contests WinAFL/Jackalope, M5)
P5.TINYINST (closed-binary coverage) + a native Windows libFuzzer or DBI campaign, so our
generated Windows harness runs coverage-guided, not just replay+/GS. HONEST: we integrate
TinyInst rather than out-engineering DynamoRIO; the win is generation+certification ON TOP of
competitive instrumentation, not beating their DBI. GATE: our generated Windows harness runs a
coverage-guided campaign on a real Windows CLI, measured vs a WinAFL run on the same target.

### W4 -- GUI in the engine, Linux (beats GUIFUZZ++, M6/M2)
B3: the GUI channel on AppEntry + the AT-SPI oracle (refused vs hung) + coverage-guided
campaign, IN the engine, generated not scripted. Run live on >=12 apps. GATE: > 23 GUI bugs
across >=12 apps, with the oracle distinguishing refusal from hang (which signal fuzzers can't).

### W5 -- GUI on Windows and macOS (contests Jackalope, M5/M6)
UIAutomation (Windows) and AX API (macOS) drivers -- the platform analogues of AT-SPI -- plus
TinyInst for coverage. GATE: a generated GUI harness drives + observes a real app on each OS,
coverage-guided.

## Sequence and dependencies

    W0 (rig) ─┬─> W1 coverage ──> W2 findings
              ├─> W4 GUI-Linux (needs the Ubuntu VM) ──> W5 GUI-Win/mac
              └─> W3 Windows-CLI depth (needs P5.TINYINST)

W0 first, always. Then W1 (closest to a clean win; the head-to-head running now sizes the gap).
W4 next when the Ubuntu VM is up. W2 runs in parallel (target choice + machine time). W3/W5 are
the heaviest (DBI integration) and last.

## Honest feasibility, per competitor

  - OGHarn (M1): CREDIBLE with composition scaling + matched budget. We are at 0.88-1.01x on
    2 libs; the path to >1.14x is more deep-subsystem composition and more libraries.
  - QuartetFuzz (M2): CREDIBLE but slow -- findings need target choice + campaign time +
    disclosure; auditing at scale we already exceed (879 vs 586 harnesses).
  - GUIFUZZ++ (M6): CREDIBLE -- our oracle is already ahead; the gap is engine integration +
    live bug-hunting on real apps.
  - WinAFL / Jackalope (W3/W5): "beat" is unrealistic on raw DBI depth; realistic goal is
    MATCH their instrumentation (via TinyInst) and ADD generation+certification they lack.

## The one-line honest summary

We can credibly BEAT OGHarn (coverage), QuartetFuzz (audit scale + findings) and GUIFUZZ++
(GUI, via our oracle), and we can MATCH WinAFL/Jackalope on Windows/closed-binary depth while
beating them on autonomy -- but only W0's live rig makes any of these a claim rather than a
hope, so it is built first.
