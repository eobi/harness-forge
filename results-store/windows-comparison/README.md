# Depth comparison: Windows CLI and Windows GUI vs competitors

Grounded in what Harness Forge has VERIFIED (results-store/b2-windows), not what it models.
Competitor capabilities are described, not scored with invented numbers.

## What we have actually verified on Windows

  - windows-x64-msvc EMISSION end to end: the generated application harness compiles with
    MSVC cl.exe, runs, and a gross overflow is caught natively (STATUS_STACK_BUFFER_OVERRUN
    via /GS); benign input exits clean. ONE target, under x64 emulation on a Windows-ARM64 VM.
  - Windows GUI: NOTHING. Zero verified, zero in the engine.

Named gaps (recorded, not hidden): no libFuzzer on windows-arm64 (used the replay driver, not
a coverage-guided Windows campaign); ASan broke under x64 emulation, so SUBTLE-overrun
sensitivity is unproven natively; no native windows-arm64 build; no closed-binary
instrumentation (P5.TINYINST is planned, not done).

---

## Windows CLI

| capability | WinAFL (DynamoRIO/PT/TinyInst) | Jackalope | libFuzzer + clang-cl | **Harness Forge** |
|---|---|---|---|---|
| coverage-guided in-process Windows fuzzing | **yes, mature** | **yes (black-box, TinyInst)** | yes (source) | not yet -- replay driver only, no Windows libFuzzer campaign verified |
| closed / no-source binary | **yes** (DBI) | **yes** (DBI) | no | no (P5.TINYINST planned) |
| GENERATES the harness | no -- you provide a target function | no -- you provide a target | no -- you write LLVMFuzzerTestOneInput | **yes -- from the app's entry point, no hand-written glue** |
| CERTIFIES the harness | no | no | no | **yes -- gates, negative capability, channel recorded** |
| defensive abort() not a finding | manual triage | manual triage | manual triage | **yes -- deterministic, in the pipeline** |
| verified native bug detection | mature (ASan/DBI) | mature | yes | **/GS on one emulated target** |

**Honest verdict, Windows CLI.** We do NOT beat WinAFL or Jackalope at Windows fuzzing depth
-- they are mature instrumentation engines that fuzz closed binaries coverage-guided, deployed
for years, finding real bugs. Our fuzzing on Windows is EARLY: emission + a replay run + /GS
detection on a single emulated target.

Where we do something they do not: we GENERATE a Windows application harness from the app's
entry point and CERTIFY it, and we triage the app's own defensive aborts as artifacts. WinAFL
and Jackalope assume you bring a harness or a target-function offset; that authoring + triage
burden is exactly what this engine removes. So the honest claim is a NARROW capability edge
(generation + certification of the Windows harness), not a depth win on fuzzing.

---

## Windows GUI

| capability | Jackalope | WinAFL (GUI/custom modes) | **Harness Forge** |
|---|---|---|---|
| coverage-guided GUI fuzzing on Windows | **yes -- built for it** | yes, with effort | **no** |
| closed GUI binary | **yes** (TinyInst DBI) | yes | **no** |
| drive the GUI / deliver input | **yes** | yes | **no Windows GUI at all** |
| any verified Windows GUI result | yes | yes | **none** |

**Honest verdict, Windows GUI.** We have nothing. Jackalope and WinAFL win outright. Our GUI
research (AT-SPI oracle, coverage feedback, campaigns) is Linux/GTK, it is not in the engine
(B3 pending), and none of it is Windows. On Windows GUI we are at zero and should say so.

---

## The strategic read

  - Windows CLI: contest on HARNESS GENERATION + CERTIFICATION, not on instrumentation depth.
    The path to a real depth claim is P5.TINYINST (closed-binary coverage) + a native
    windows-arm64/x64 libFuzzer or DBI campaign -- until then it is "generates + certifies +
    compiles + detects gross bugs", verified once.
  - Windows GUI: a genuine hole. Closing it means the GUI channel (B3) PLUS a Windows GUI
    driver (UIAutomation, the Windows analogue of the Linux AT-SPI oracle) PLUS TinyInst for
    coverage. That is the only place a "beat a Windows-GUI-specialised competitor" claim could
    come from, and it is unbuilt.

The uniform application-entry abstraction (B1) means the Windows CLI and Windows GUI paths are
the same AppEntry with different channels/drivers -- so the work is additive, not a new engine
-- but the depth on both is not there yet, and the comparison says so plainly.
