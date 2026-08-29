"""Host and toolchain detection — everything that differs between machines, in one place.

The gates were written on a Mac and quietly assumed one. Five things differ off that host,
and one of them is not cosmetic:

  1. the compiler lives somewhere else, and on Windows may be `clang-cl` rather than `clang`
  2. `nm` may be absent entirely; Windows needs `llvm-nm`
  3. an executable needs `.exe`
  4. **what a crash looks like in an exit code is completely different.** POSIX returns a
     negative signal number; Windows returns an NTSTATUS such as 0xC0000005. A check written
     as `rc >= 128` never fires on Windows, so every crash reads as a clean run, every gate
     passes, and the engine certifies harnesses that detect nothing. That is a silent
     wrong-answer bug, which is the only kind that matters.
  5. a device target is reached over `adb` or `simctl`, not by running a local binary

`classify_exit` is the load-bearing function here and it is pure, so it is tested against
recorded exit codes from all three platforms without needing all three platforms.
"""
from __future__ import annotations

import os
import platform as _plat
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── outcomes ─────────────────────────────────────────────────────────────────
OK = "ok"                  # ran to completion, no fault
FAULT = "fault"            # the target or the harness died, or a sanitizer aborted
DRIVER_ERROR = "driver"    # our own replay driver could not do its job
TIMEOUT = "timeout"

# NTSTATUS values that mean "this process crashed". Windows returns these as the exit code.
_NTSTATUS_CRASH = {
    0xC0000005,  # ACCESS_VIOLATION            — the Windows SIGSEGV
    0xC0000374,  # HEAP_CORRUPTION
    0xC000001D,  # ILLEGAL_INSTRUCTION
    0xC0000094,  # INTEGER_DIVIDE_BY_ZERO
    0xC00000FD,  # STACK_OVERFLOW
    0xC0000409,  # STACK_BUFFER_OVERRUN  (also /GS and __fastfail)
    0xC0000417,  # INVALID_CRT_PARAMETER
    0x80000003,  # BREAKPOINT  — what a sanitizer trap looks like
    0xC0000006,  # IN_PAGE_ERROR
    0xC0000008,  # INVALID_HANDLE
    0xC000008C,  # ARRAY_BOUNDS_EXCEEDED
}

# The replay driver this engine emits returns 2, and only 2, when it cannot read its input.
DRIVER_ERROR_RC = 2


@dataclass(frozen=True)
class Host:
    os: str                    # linux | windows | macos
    arch: str                  # x86_64 | aarch64 | x86
    exe_suffix: str
    platform_id: str           # best-matching id from hforge.platform

    @property
    def is_windows(self) -> bool:
        return self.os == "windows"


def host() -> Host:
    sysname = _plat.system().lower()
    machine = _plat.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64",
            "aarch64": "aarch64", "i386": "x86", "i686": "x86"}.get(machine, machine)

    if sysname == "darwin":
        pid = "macos-arm64" if arch == "aarch64" else "macos-x86_64"
        return Host("macos", arch, "", pid)
    if sysname == "windows":
        pid = {"x86_64": "windows-x86_64-msvc", "x86": "windows-x86-msvc",
               "aarch64": "windows-arm64-msvc"}.get(arch, "windows-x86_64-msvc")
        return Host("windows", arch, ".exe", pid)
    libc = "musl" if _is_musl() else "glibc"
    pid = f"linux-{'x86_64' if arch == 'x86_64' else arch}-{libc}"
    return Host("linux", arch, "", pid)


def _is_musl() -> bool:
    """musl and glibc are different allocators, so the distinction is a platform variant and
    not a detail. `ldd --version` names whichever one is present."""
    try:
        r = subprocess.run(["ldd", "--version"], capture_output=True, text=True, timeout=5)
        return "musl" in (r.stdout + r.stderr).lower()
    except Exception:                                       # noqa: BLE001
        return Path("/lib/ld-musl-x86_64.so.1").exists()


# ── exit-code classification ─────────────────────────────────────────────────

def classify_exit(rc: Optional[int], *, os_name: str, sanitized: bool) -> str:
    """What a process's exit code means on this platform. Pure, so it is testable anywhere.

    `sanitized` matters because a sanitizer with `abort_on_error=0` reports and then exits
    with status 1, which on an unsanitized build would be an ordinary failure rather than a
    fault. Treating 1 as a crash unconditionally would misread every normal error path.
    """
    if rc is None:
        return TIMEOUT
    if rc == 0:
        return OK
    if rc == DRIVER_ERROR_RC:
        return DRIVER_ERROR

    if os_name == "windows":
        u = rc & 0xFFFFFFFF          # Python may hand back the signed form
        if u in _NTSTATUS_CRASH:
            return FAULT
        # Anything in the NTSTATUS error space is a crash we did not enumerate.
        if u >= 0xC0000000:
            return FAULT
        return FAULT if (sanitized and rc == 1) else OK

    # POSIX: negative is "killed by signal N"; 128+N is the shell's spelling of the same.
    if rc < 0 or rc >= 128:
        return FAULT
    if sanitized and rc == 1:
        return FAULT
    return OK


def is_fault(rc: Optional[int], *, os_name: str, sanitized: bool) -> bool:
    return classify_exit(rc, os_name=os_name, sanitized=sanitized) == FAULT


def describe_exit(rc: Optional[int], os_name: str) -> str:
    if rc is None:
        return "timed out"
    if os_name == "windows":
        u = rc & 0xFFFFFFFF
        names = {0xC0000005: "ACCESS_VIOLATION", 0xC0000374: "HEAP_CORRUPTION",
                 0xC00000FD: "STACK_OVERFLOW", 0xC0000409: "STACK_BUFFER_OVERRUN",
                 0x80000003: "BREAKPOINT"}
        if u in names:
            return f"0x{u:08X} {names[u]}"
        return f"exit {rc}"
    if rc < 0:
        return f"killed by signal {-rc}"
    if rc >= 128:
        return f"killed by signal {rc - 128}"
    return f"exit {rc}"


# ── tool discovery ───────────────────────────────────────────────────────────

@dataclass
class Tool:
    name: str
    path: Optional[str]
    required_for: str
    cost_if_absent: str

    @property
    def present(self) -> bool:
        return bool(self.path)


def _first(*cands) -> Optional[str]:
    for c in cands:
        if not c:
            continue
        p = shutil.which(c) if not os.path.sep in str(c) else (c if Path(c).exists() else None)
        if p:
            return str(p)
    return None


def find_cc() -> Optional[str]:
    """A compiler able to build the harness on this host.

    Apple's clang ships the sanitizer runtimes but NOT the libFuzzer one, so Homebrew LLVM
    is preferred on macOS. On Windows, `clang` from LLVM is preferred over `clang-cl`
    because the emitted harness is plain C.
    """
    h = host()
    if h.os == "macos":
        return _first(os.environ.get("CC"), "/opt/homebrew/opt/llvm/bin/clang",
                      "/usr/local/opt/llvm/bin/clang", "clang", "cc")
    if h.os == "windows":
        return _first(os.environ.get("CC"), "clang", "clang-cl",
                      r"C:\Program Files\LLVM\bin\clang.exe")
    return _first(os.environ.get("CC"), "clang", "gcc", "cc")


_LIBFUZZER_PROBE: dict = {}


def libfuzzer_probe() -> tuple:
    """(compiler_or_None, why_not). Cached, because the probe COMPILES.

    D8 ran this once per plan. Under four parallel sqlite builds the 90-second probe timed
    out, and D8 then reported "no libFuzzer runtime on this host" — a claim about the
    machine, when the truth was that our own probe lost a race against our own build. Every
    campaign in that run was skipped and the certificates said the host was at fault.
    """
    cc = find_cc()
    if not cc:
        return None, "no C compiler on this host"
    if cc in _LIBFUZZER_PROBE:
        return _LIBFUZZER_PROBE[cc]
    try:
        import tempfile
        d = Path(tempfile.mkdtemp())
        src = d / "t.c"
        src.write_text("#include <stdint.h>\n#include <stddef.h>\n"
                       "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
                       "{(void)d;(void)n;return 0;}\n")
        r = subprocess.run([cc, "-fsanitize=fuzzer", str(src),
                            "-o", str(d / ("t" + host().exe_suffix))],
                           capture_output=True, text=True, timeout=180)
        out = (cc, "") if r.returncode == 0 else \
            (None, f"{cc} has no libFuzzer runtime: {r.stderr.strip()[-160:]}")
    except subprocess.TimeoutExpired:
        # NOT cached: a timeout is a statement about load, not about the toolchain, and
        # caching it would poison every later gate in the run.
        return None, ("the libFuzzer probe timed out — the host is loaded, not missing a "
                      "runtime. This is our own probe losing a race with our own builds.")
    except Exception as e:                                  # noqa: BLE001
        out = (None, f"could not probe for libFuzzer: {e}")
    _LIBFUZZER_PROBE[cc] = out
    return out


def find_libfuzzer_cc() -> Optional[str]:
    """A compiler whose runtime includes libFuzzer. Absence means campaigns cannot run, but
    every gate in this engine still can: the certification half never needed a fuzzer."""
    return libfuzzer_probe()[0]


def _find_libfuzzer_cc_uncached() -> Optional[str]:
    cc = find_cc()
    if not cc:
        return None
    try:
        import tempfile
        d = Path(tempfile.mkdtemp())
        src = d / "t.c"
        src.write_text("#include <stdint.h>\n#include <stddef.h>\n"
                       "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
                       "{(void)d;(void)n;return 0;}\n")
        r = subprocess.run([cc, "-fsanitize=fuzzer", str(src),
                            "-o", str(d / ("t" + host().exe_suffix))],
                           capture_output=True, text=True, timeout=90)
        return cc if r.returncode == 0 else None
    except Exception:                                       # noqa: BLE001
        return None


def find_nm() -> Optional[str]:
    return _first("llvm-nm", "/opt/homebrew/opt/llvm/bin/llvm-nm", "nm")


def find_adb() -> Optional[str]:
    return _first(os.environ.get("ADB"), "adb",
                  str(Path.home() / "Library/Android/sdk/platform-tools/adb"),
                  str(Path.home() / "Android/Sdk/platform-tools/adb"))


def find_ndk() -> Optional[str]:
    """The NDK root. Without it, nothing can be BUILT for Android, though a device can still
    be inventoried and a prebuilt binary still run."""
    for env in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT"):
        v = os.environ.get(env)
        if v and Path(v).exists():
            return v
    for base in (Path.home() / "Library/Android/sdk/ndk",
                 Path.home() / "Android/Sdk/ndk",
                 Path("/opt/android-ndk")):
        if base.exists():
            vers = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
            if vers:
                return str(vers[0])
    return None


def find_xcrun() -> Optional[str]:
    return _first("xcrun") if host().os == "macos" else None


def ndk_clang(ndk: str, abi: str, api: int) -> Optional[str]:
    """The NDK's clang for one ABI and API level, or None."""
    triple = {"arm64-v8a": "aarch64-linux-android",
              "armeabi-v7a": "armv7a-linux-androideabi",
              "x86_64": "x86_64-linux-android",
              "x86": "i686-linux-android"}.get(abi)
    if not triple:
        return None
    for hosttag in ("darwin-x86_64", "linux-x86_64", "windows-x86_64"):
        p = Path(ndk) / "toolchains/llvm/prebuilt" / hosttag / "bin" / f"{triple}{api}-clang"
        if p.exists():
            return str(p)
        if (q := p.with_suffix(".cmd")).exists():
            return str(q)
    return None


# ── the inventory ────────────────────────────────────────────────────────────

@dataclass
class Toolchain:
    host: Host
    tools: list = field(default_factory=list)

    def get(self, name: str) -> Optional[Tool]:
        return next((t for t in self.tools if t.name == name), None)

    def have(self, name: str) -> bool:
        t = self.get(name)
        return bool(t and t.present)

    @property
    def can_gate(self) -> bool:
        """Everything the certification half needs. Deliberately small: no fuzzer, no model,
        no network."""
        return self.have("cc")

    @property
    def missing(self) -> list:
        return [t for t in self.tools if not t.present]


def inventory() -> Toolchain:
    h = host()
    cc = find_cc()
    return Toolchain(host=h, tools=[
        Tool("cc", cc, "building the harness and every dynamic gate",
             "all dynamic gates report NOT RUN; static gates still run"),
        Tool("libfuzzer-cc", find_libfuzzer_cc(),
             "running an actual coverage-guided campaign",
             "certification is unaffected; you cannot fuzz"),
        Tool("nm", find_nm(), "gate D1, which proves the target call survived the optimiser",
             "D1 reports NOT RUN, so a harness the compiler emptied could pass unnoticed"),
        Tool("adb", find_adb(), "reaching an Android device",
             "Android targets are unreachable; the platform model still records them"),
        Tool("ndk", find_ndk(), "BUILDING for Android",
             "Android harnesses cannot be built here, only run if prebuilt"),
        Tool("xcrun", find_xcrun(), "the iOS Simulator, which is the practical iOS path",
             "iOS discovery is unavailable; device runs were never the discovery path"),
    ])


# ── the emitted C is OUR code, and a warning about it is evidence about us ────────────
#
# `unsigned char hf_r_err = NULL;` followed by `hf_r_err = yajl_get_error(...)` is an
# incompatible pointer-to-integer conversion. clang said so. The build succeeded. Nobody
# read it, two 600-second campaigns were spent, and three diagnoses were wrong before
# somebody read the generated declaration.
#
# That is S2.TYPE_CONFUSION — a gate this engine already has — occurring at the C level
# AFTER emission, which is the one place no gate was looking.
EMITTER_DEFECT_WARNINGS = (
    "int-conversion",                  # a pointer squeezed into an integer, or the reverse
    "incompatible-pointer-types",      # the wrong pointer type passed to a parameter
    "implicit-function-declaration",   # a call to something never declared: a missing header
    "return-type",                     # a value returned from a function declared void
)


def check_emitted_c(cc: str, source, include_dirs=(), cflags=(), is_cxx: bool = False):
    """Compile the harness ALONE with the emitter-defect warnings as errors.

    Returns [] when the emitted code is clean, or a list of diagnostics when it is not.

    Compiled ALONE, to an object, and deliberately not as part of the real build. The
    target's own sources routinely carry warnings of exactly these classes — that is the
    target's business and not a reason to refuse a harness. Attributing somebody else's
    warning to our plan would be the same error in the opposite direction.
    """
    import subprocess
    import tempfile
    from pathlib import Path

    src = Path(source)
    with tempfile.TemporaryDirectory() as td:
        cmd = [cc, "-fsyntax-only"]
        if is_cxx:
            cmd.append("-std=c++11")
        cmd += [f"-Werror={w}" for w in EMITTER_DEFECT_WARNINGS]
        cmd += [f"-I{d}" for d in include_dirs] + list(cflags) + [str(src)]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            return []
        return [l for l in (r.stderr or "").splitlines()
                if "error:" in l or "warning:" in l][:8]
