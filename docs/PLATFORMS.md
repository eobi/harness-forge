# Platforms, and verifying them yourself

The platform model claims that variants differ — allocator, word size, instrumentation —
and an unexercised claim is a guess. This page is the matrix and the commands that check
it on your own hardware.

## Platforms

`python3 -m hforge platforms` prints the full matrix: Linux (glibc, musl, x86, x86-64,
aarch64), Windows (MSVC, MinGW, x86, x64, ARM64), macOS (Intel, Apple Silicon, arm64e),
Android (emulator and device, arm64/armv7/x86-64), iOS/iPadOS/tvOS (simulator and device).

Each carries its sanitizers, allocator, coverage backends, crash artifact and **trust
ceiling** — the highest ladder rung a finding observed only there may reach.

> **Fuzz where instrumentation is cheap. Prove reachability where the target actually runs.**

An iOS device run is a **reachability oracle**, never the discovery mechanism. A macOS ASan
finding carries an explicit, labelled iOS reachability hypothesis, or an explicit refusal to
make one.

Variant disagreement is itself an oracle: reproduces at 32 bits and not 64 means
width-dependent arithmetic; reproduces on glibc and not musl means allocator-dependent;
reproduces only under DBI means an instrumentation artifact and must not be reported.

---

---

## Running it on your machine

Three operator commands, in the order you would use them.

```
python3 -m hforge doctor      # what this machine can do, and what each missing tool COSTS
python3 -m hforge devices     # attached Android devices and iOS simulators
python3 -m hforge selftest    # the whole pipeline, end to end, on this host
```

`doctor` reports a missing tool together with what its absence stops you proving, because a
warning with no stated cost is a warning people learn to ignore. `selftest` runs every stage
and distinguishes **SKIP from PASS** — a check this machine could not run is never counted as
one that passed.

On a Mac with the NDK and an emulator attached, all fourteen stages run:

```
[ PASS ] exit-code classification      12 exit codes classified correctly across linux/windows
[ PASS ] static gates REJECT bad plan  blocked by 3 violation(s), incl. S2.CSTRING — no compiler ran
[ PASS ] D2 positive control           mutants_tested=2, killed=1, survived=1
[ PASS ] android cross-build           arm64-v8a api29 with asan (downgraded from hwasan:
                                       stock system image; HWASan needs a HWASan image)
[ PASS ] android device run            emulator-5554: ok
14 passed, 0 failed, 0 skipped
```

### Platform support

| platform | status |
|---|---|
| **macOS** arm64 | verified end to end |
| **Linux** aarch64 glibc | verified end to end — 92 tests, 11/11 runnable stages |
| **Linux** aarch64 musl | verified end to end — different allocator, correctly detected |
| **Linux** x86-64 glibc | verified end to end under emulation |
| **Android** arm64-v8a API 35 | verified end to end: cross-build, push, run, differential |
| **Windows** MSVC / MinGW | exit-code semantics implemented and unit-tested from any host; **not yet run on a Windows host** |
| **iOS** simulator | detected via `simctl`; harness emission not yet wired. The platform matrix used to claim `EMIT yes` for both simulators and that claim was wrong: `--platform ios-arm64-simulator` was accepted and then dropped, producing a build.sh byte-identical to the default with no `-isysroot` and no `-target`. The matrix now agrees with this table, and asking for a platform the backend cannot target prints a note rather than emitting a host build in silence |

Nothing above claims more than was executed. Windows is honestly *implemented and
unit-tested*, not *verified* — run `python3 -m hforge selftest` there and it will tell you
which of the two it is.

### Verifying Linux yourself

```
./scripts/verify-linux.sh          # needs only a running docker daemon
```

Three containers, because the platform model claims those variants differ and an unexercised
claim is a guess: aarch64/glibc, aarch64/musl, and x86-64/glibc under emulation. The last
step certifies the **same plan** on all three and compares the gate verdicts.

```
GATE   linux-aarch64-glibc linux-aarch64-musl  linux-x86_64-glibc
D1     pass                pass                pass
S2     pass                pass                pass
...
All platforms agree. The harness behaves the same across allocator and word
size, so no variant-dependence is implicated.
```

**A disagreement there is not a build failure.** It is the variant-disagreement oracle
firing: glibc-not-musl means allocator-dependent, x86-64-not-aarch64 means width-dependent
arithmetic. `scripts/compare_certs.py` says which, and exits 0 either way, because a script
that failed the build on real information is a script people stop running.

---
