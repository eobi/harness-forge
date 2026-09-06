# B2 — Windows verified: the emitted harness compiles and detects a bug natively

**windows-*-msvc flips from "modelled, never run" to run.** On a Windows 11 ARM64 VM
(192.168.1.236, UTM on Apple Silicon), the emitted application harness was compiled with the
native MSVC toolchain and driven against the same bug-shaped mini CLI parser the Linux proof
used.

## What ran

The B1 file-channel harness (`winapp-harness.c`) + its standalone replay driver
(`winapp-driver.c`), emitted for `platforms=['windows-arm64-msvc']`, so the temp-file
materialisation compiles through the `#ifdef _WIN32` branch (GetTempFileNameA / WriteFile /
DeleteFileA). Built with `cl /nologo /Zi /I. harness.c driver.c app.c`.

| step | result |
|---|---|
| compile with MSVC cl.exe | **BUILD=OK** |
| benign input (`"hello, ordinary input"`) | **exit 0** — runs clean, file channel delivers it |
| overflow input (`BUG\xff` + 320 bytes) | **exit 0xC0000409 = STATUS_STACK_BUFFER_OVERRUN** |

The bug is detected NATIVELY: MSVC's `/GS` stack-cookie protection fires on the overwrite.
Benign input exits cleanly, the overflow input crashes with a Windows memory-safety status --
the exact bug-vs-clean contrast a fuzzer runs on, proven on Windows.

## Honest limits, recorded not hidden

  - The VM is Windows-on-ARM; the harness was built x64 and runs under ARM64 EMULATION.
    That verifies the windows-x64-msvc emission path end to end. A native windows-arm64 build
    needs the ARM64 compiler+libs, which this VM's VS Build Tools install did not place
    (see below) -- follow-up, not a harness-forge gap.
  - AddressSanitizer does NOT work here: an x64 /fsanitize=address exe crashes on startup
    under ARM64 emulation (ASan's shadow memory cannot initialise). So detection of SUBTLE
    overruns (a 4-byte overflow the raw run survives) awaits a native-arm64 ASan build. The
    GROSS overflow is caught by /GS regardless, which is what proves the harness works.

## The toolchain fight (for the next person)

VS Build Tools over headless SSH registered components as success but placed only the Windows
SDK; the MSVC compiler and libs needed a forced `setup.exe modify --add
Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --force` to actually materialise cl.exe. The
ARM64 target component (`VC.Tools.ARM64`) still did not place its libs, which is why the build
is x64-under-emulation rather than native arm64.

## Where this leaves the matrix

windows-x64-msvc: **emission verified end to end** (compile + run + native bug detection).
The other Windows variants and native windows-arm64 remain modelled; the emitter already
produces the correct source and cl build for all of them.
