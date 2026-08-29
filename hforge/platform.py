"""The platform model — OS family x architecture x ABI/runtime variant.

A vulnerability is a property of a build, not of a source file. So a harness is never
"certified" in the abstract; it is certified *for a set of platforms*, and the certificate
names the ones it was not certified for.

Three things are recorded per platform and all three change what a finding is worth:

  * which sanitizers exist there (source ASan > binary ASan > HWASan > nothing),
  * which allocator is in use (glibc's inline metadata and Android's hardened Scudo lead to
    completely different exploitability inferences),
  * the TRUST CEILING: the highest ladder rung a finding observed only on this platform may
    reach. An iOS device with no instrumentation cannot certify what a Linux ASan build can.

The mobile principle, encoded here rather than remembered:

    fuzz where instrumentation is cheap; prove reachability where the target actually runs.

Pure data + lookup. No I/O, no subprocess.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ── trust ceilings ────────────────────────────────────────────────────────────
# Mirrors 12.7's observation hierarchy: the more the observation disturbs the observed,
# the lower the claim it can support.
TRUST_FULL = "full"                  # source sanitizer available; rung 5 reachable
TRUST_SANITIZER_LIMITED = "sanitizer-limited"   # partial/absent sanitizer; rung 4 ceiling
TRUST_DBI_LIMITED = "dbi-limited"    # instrumentation-only coverage; native replay mandatory
TRUST_REACHABILITY_ONLY = "reachability-only"   # can show a path exists, cannot certify a fault

_CEILING_RUNG = {
    TRUST_FULL: 5,
    TRUST_SANITIZER_LIMITED: 4,
    TRUST_DBI_LIMITED: 3,
    TRUST_REACHABILITY_ONLY: 2,
}


@dataclass(frozen=True)
class Platform:
    id: str
    os: str                      # linux | windows | macos | android | ios
    arch: str                    # x86_64 | x86 | aarch64 | armv7 | arm64e
    variant: str                 # glibc | musl | msvc | mingw | simulator | device | api level
    toolchain: str
    sanitizers: tuple            # available detectors
    allocator: str
    coverage: tuple              # usable coverage backends
    crash_artifact: str          # what the proof object looks like
    trust_ceiling: str
    notes: str = ""
    emit_ready: bool = False     # does P1's C emitter target this today?

    @property
    def ceiling_rung(self) -> int:
        return _CEILING_RUNG[self.trust_ceiling]

    @property
    def has_source_sanitizer(self) -> bool:
        return any(s in ("asan", "hwasan", "msan") for s in self.sanitizers)


def _p(**kw) -> Platform:
    return Platform(**kw)


PLATFORMS: dict[str, Platform] = {p.id: p for p in [
    # ── Linux ────────────────────────────────────────────────────────────────
    _p(id="linux-x86_64-glibc", os="linux", arch="x86_64", variant="glibc",
       toolchain="clang", sanitizers=("asan", "ubsan", "msan", "tsan"),
       allocator="glibc-ptmalloc",
       coverage=("libfuzzer", "aflpp", "retrowrite", "qemu-user"),
       crash_artifact="sanitizer-report", trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="reference platform: every sanitizer works, binary ASan available via RetroWrite"),
    _p(id="linux-x86_64-musl", os="linux", arch="x86_64", variant="musl",
       toolchain="clang", sanitizers=("asan", "ubsan"), allocator="musl-mallocng",
       coverage=("libfuzzer", "aflpp"), crash_artifact="sanitizer-report",
       trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="mallocng differs from ptmalloc; adjacency findings do not transfer"),
    _p(id="linux-aarch64-glibc", os="linux", arch="aarch64", variant="glibc",
       toolchain="clang", sanitizers=("asan", "ubsan", "msan", "mte"),
       allocator="glibc-ptmalloc", coverage=("libfuzzer", "aflpp", "retrowrite-arm"),
       crash_artifact="sanitizer-report", trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="MTE where the silicon supports it; near-fatal for linear heap overflow"),
    _p(id="linux-aarch64-musl", os="linux", arch="aarch64", variant="musl",
       toolchain="clang", sanitizers=("asan", "ubsan"), allocator="musl-mallocng",
       coverage=("libfuzzer",), crash_artifact="sanitizer-report",
       trust_ceiling=TRUST_FULL, emit_ready=True),
    _p(id="linux-x86-glibc", os="linux", arch="x86", variant="glibc",
       toolchain="clang -m32", sanitizers=("asan", "ubsan"), allocator="glibc-ptmalloc",
       coverage=("libfuzzer", "aflpp"), crash_artifact="sanitizer-report",
       trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="ILP32: 32-bit-only integer bugs live here and nowhere else"),

    # ── Windows ──────────────────────────────────────────────────────────────
    _p(id="windows-x86_64-msvc", os="windows", arch="x86_64", variant="msvc",
       toolchain="clang-cl", sanitizers=("asan-partial",), allocator="nt-heap-lfh",
       coverage=("tinyinst", "dynamorio", "target-embedded-snapshot"),
       crash_artifact="seh-ntstatus", trust_ceiling=TRUST_SANITIZER_LIMITED,
       notes="SEH can swallow access violations: zero crashes is not evidence of robustness"),
    _p(id="windows-x86_64-mingw", os="windows", arch="x86_64", variant="mingw",
       toolchain="clang", sanitizers=("asan",), allocator="msvcrt",
       coverage=("tinyinst",), crash_artifact="seh-ntstatus",
       trust_ceiling=TRUST_SANITIZER_LIMITED),
    _p(id="windows-x86-msvc", os="windows", arch="x86", variant="msvc",
       toolchain="clang-cl", sanitizers=("asan-partial",), allocator="nt-heap-lfh",
       coverage=("tinyinst", "dynamorio", "page-heap"), crash_artifact="seh-ntstatus",
       trust_ceiling=TRUST_SANITIZER_LIMITED,
       notes="Delphi targets use FastMM with inline metadata; page heap relocates allocations"),
    _p(id="windows-arm64-msvc", os="windows", arch="aarch64", variant="msvc",
       toolchain="clang-cl", sanitizers=(), allocator="nt-heap",
       coverage=("tinyinst",), crash_artifact="seh-ntstatus",
       trust_ceiling=TRUST_DBI_LIMITED),

    # ── macOS ────────────────────────────────────────────────────────────────
    _p(id="macos-x86_64", os="macos", arch="x86_64", variant="intel",
       toolchain="homebrew-clang", sanitizers=("asan", "ubsan", "tsan"),
       allocator="libmalloc-magazine", coverage=("libfuzzer", "tinyinst"),
       crash_artifact="mach-exception", trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="no MSan on Darwin; Apple clang lacks the libFuzzer runtime, use Homebrew LLVM"),
    _p(id="macos-arm64", os="macos", arch="aarch64", variant="apple-silicon",
       toolchain="homebrew-clang", sanitizers=("asan", "ubsan", "tsan"),
       allocator="libmalloc-magazine", coverage=("libfuzzer", "tinyinst"),
       crash_artifact="mach-exception", trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="plain arm64: no pointer authentication, unlike arm64e"),
    _p(id="macos-arm64e", os="macos", arch="arm64e", variant="apple-silicon-pac",
       toolchain="apple-clang", sanitizers=("asan",), allocator="libmalloc-magazine+pac",
       coverage=("tinyinst",), crash_artifact="mach-exception",
       trust_ceiling=TRUST_DBI_LIMITED,
       notes="TinyInst needs arm64e entitlements. Frida Stalker is SIGKILLed by PAC/codesign "
             "enforcement on arm64e: do not build the macOS path on it"),

    # ── Android ──────────────────────────────────────────────────────────────
    # ── the JVM ──────────────────────────────────────────────────────────────
    #
    # The JVM abstracts the operating system, so the axis that matters is the RUNTIME rather
    # than the OS: a finding on OpenJDK x86_64 holds on OpenJDK aarch64, and the interesting
    # boundary is a different implementation or a different compilation model.
    #
    # `sanitizers` is not empty here and that is the point: the JVM's bounds, cast and null
    # checks are ALWAYS ON. They are the platform's memory-safety oracle, they cannot be
    # switched off, and an ArrayIndexOutOfBoundsException in library code is the JVM catching
    # what C would have let through.
    _p(id="jvm-openjdk-x86_64", os="jvm", arch="x86_64", variant="openjdk",
       toolchain="javac+jazzer", sanitizers=("jvm-checks", "jazzer-sanitizers"),
       allocator="gc", coverage=("jazzer",), crash_artifact="stack trace",
       trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="rung 5 is REACHABLE and strong here — a Jazzer sanitizer firing is direct "
             "evidence that attacker data crossed a trust boundary, needing no heap-layout "
             "argument. Rung 3 means 'a defect rather than the documented contract', not "
             "'memory-safety violation'; there is no ASan to mean the latter"),
    _p(id="jvm-openjdk-aarch64", os="jvm", arch="aarch64", variant="openjdk",
       toolchain="javac+jazzer", sanitizers=("jvm-checks", "jazzer-sanitizers"),
       allocator="gc", coverage=("jazzer",), crash_artifact="stack trace",
       trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="the JVM abstracts the OS, so a finding here and on x86_64 are the same finding "
             "unless it depends on the JIT — which is exactly what the -Xint differential "
             "is for"),
    _p(id="jvm-graalvm-native-x86_64", os="jvm", arch="x86_64", variant="native-image",
       toolchain="native-image", sanitizers=("jvm-checks",),
       allocator="native", coverage=("libfuzzer",), crash_artifact="stack trace or signal",
       trust_ceiling=TRUST_SANITIZER_LIMITED,
       notes="AOT-compiled, so C-CLASS MEMORY FAULTS BECOME POSSIBLE AGAIN and the JVM's "
             "guarantees no longer hold uniformly. A finding does not transfer across this "
             "boundary in either direction and must not be claimed to"),
    _p(id="android-arm64-emulator", os="android", arch="aarch64", variant="emulator",
       toolchain="ndk-clang", sanitizers=("asan", "hwasan", "ubsan"),
       allocator="scudo", coverage=("libfuzzer", "tinyinst", "frida"),
       crash_artifact="tombstone", trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="scale here; claim nothing from an emulator that was not re-checked on a device"),
    _p(id="android-arm64-device", os="android", arch="aarch64", variant="device",
       toolchain="ndk-clang", sanitizers=("hwasan", "gwp-asan", "mte"),
       allocator="scudo", coverage=("libfuzzer", "frida"), crash_artifact="tombstone",
       trust_ceiling=TRUST_SANITIZER_LIMITED, emit_ready=True,
       notes="HWASan is the right detector on device, not ASan. Scudo is hardened against the "
             "classic heap techniques: overflow does NOT imply write-what-where here"),
    _p(id="android-armv7-device", os="android", arch="armv7", variant="device",
       toolchain="ndk-clang", sanitizers=("asan",), allocator="scudo-or-jemalloc",
       coverage=("libfuzzer", "frida"), crash_artifact="tombstone",
       trust_ceiling=TRUST_SANITIZER_LIMITED,
       notes="low-memory devices may still use jemalloc rather than Scudo"),
    _p(id="android-x86_64-emulator", os="android", arch="x86_64", variant="emulator",
       toolchain="ndk-clang", sanitizers=("asan", "hwasan", "ubsan"), allocator="scudo",
       coverage=("libfuzzer",), crash_artifact="tombstone", trust_ceiling=TRUST_FULL,
       emit_ready=True),

    # ── iOS and the Apple embedded family ────────────────────────────────────
    _p(id="ios-arm64-simulator", os="ios", arch="aarch64", variant="simulator",
       toolchain="xcode-clang", sanitizers=("asan", "ubsan", "tsan"),
       allocator="libmalloc", coverage=("libfuzzer",), crash_artifact="mach-exception",
       trust_ceiling=TRUST_FULL, emit_ready=True,
       notes="THE practical iOS discovery path: normal libFuzzer and ASan, no signing fight"),
    _p(id="ios-x86_64-simulator", os="ios", arch="x86_64", variant="simulator",
       toolchain="xcode-clang", sanitizers=("asan", "ubsan"), allocator="libmalloc",
       coverage=("libfuzzer",), crash_artifact="mach-exception", trust_ceiling=TRUST_FULL,
       emit_ready=True),
    _p(id="ios-arm64-device", os="ios", arch="aarch64", variant="device",
       toolchain="xcode-clang+entitlements", sanitizers=("asan-devsigned",),
       allocator="libmalloc+pac", coverage=(), crash_artifact="ips-crash-report",
       trust_ceiling=TRUST_REACHABILITY_ONLY,
       notes="discovery does not happen here. Device runs are a REACHABILITY oracle for a "
             "finding discovered on macOS or the simulator"),
    _p(id="ipados-arm64-device", os="ios", arch="aarch64", variant="ipados-device",
       toolchain="xcode-clang+entitlements", sanitizers=(), allocator="libmalloc+pac",
       coverage=(), crash_artifact="ips-crash-report",
       trust_ceiling=TRUST_REACHABILITY_ONLY),
    _p(id="tvos-arm64-device", os="ios", arch="aarch64", variant="tvos-device",
       toolchain="xcode-clang+entitlements", sanitizers=(), allocator="libmalloc+pac",
       coverage=(), crash_artifact="ips-crash-report",
       trust_ceiling=TRUST_REACHABILITY_ONLY),
]}


# Platform families that share source, so a finding on one carries a *reachability
# hypothesis* (never a certification) on the others.
SHARED_CODE_FAMILIES: dict[str, tuple] = {
    "apple": ("macos-x86_64", "macos-arm64", "macos-arm64e",
              "ios-arm64-simulator", "ios-x86_64-simulator", "ios-arm64-device",
              "ipados-arm64-device", "tvos-arm64-device"),
    "linux": ("linux-x86_64-glibc", "linux-x86_64-musl",
              "linux-aarch64-glibc", "linux-aarch64-musl", "linux-x86-glibc"),
    "jvm": ("jvm-openjdk-x86_64", "jvm-openjdk-aarch64", "jvm-graalvm-native-x86_64"),
    "android": ("android-arm64-emulator", "android-arm64-device",
                "android-armv7-device", "android-x86_64-emulator"),
    "windows": ("windows-x86_64-msvc", "windows-x86_64-mingw",
                "windows-x86-msvc", "windows-arm64-msvc"),
}


def get(platform_id: str) -> Platform:
    try:
        return PLATFORMS[platform_id]
    except KeyError:
        raise KeyError(f"unknown platform {platform_id!r}; "
                       f"known: {', '.join(sorted(PLATFORMS))}") from None


def emit_ready() -> list[Platform]:
    """Platforms the P1 C emitter targets today."""
    return [p for p in PLATFORMS.values() if p.emit_ready]


def family_of(platform_id: str) -> Optional[str]:
    for fam, members in SHARED_CODE_FAMILIES.items():
        if platform_id in members:
            return fam
    return None


def reachability_siblings(platform_id: str) -> list[str]:
    """Platforms that likely share the target's source with this one.

    A finding here becomes a *reachability hypothesis* there, never a certification.
    This is what lets a macOS ASan finding carry an explicit, labelled iOS claim.
    """
    fam = family_of(platform_id)
    if not fam:
        return []
    return [p for p in SHARED_CODE_FAMILIES[fam] if p != platform_id]


def ceiling(platform_ids: list[str]) -> tuple[int, str]:
    """The highest rung certifiable across a set of platforms, and which one allows it."""
    best_id, best = "", -1
    for pid in platform_ids:
        r = get(pid).ceiling_rung
        if r > best:
            best, best_id = r, pid
    return best, best_id


def disagreement_meaning(reproduced: set, not_reproduced: set) -> list[str]:
    """Variant disagreement is an oracle. Translate a repro/no-repro split into findings.

    Pure function of two id sets, so it is testable with no targets.
    """
    out: list[str] = []
    if not reproduced or not not_reproduced:
        return out
    arch = lambda ids: {get(i).arch for i in ids}          # noqa: E731
    alloc = lambda ids: {get(i).allocator for i in ids}    # noqa: E731
    osf = lambda ids: {get(i).os for i in ids}             # noqa: E731

    if "x86" in arch(reproduced) and "x86" not in arch(not_reproduced) \
            and {"x86_64", "aarch64"} & arch(not_reproduced):
        out.append("width-dependent arithmetic: reproduces at 32 bits and not at 64. "
                   "The bug is a property of the ILP32 build.")
    if arch(reproduced) != arch(not_reproduced) and "x86" not in arch(reproduced):
        out.append("architecture-dependent: check integer widths, alignment and "
                   "calling-convention assumptions before claiming portability.")
    if alloc(reproduced).isdisjoint(alloc(not_reproduced)):
        out.append(f"allocator-dependent: present under {sorted(alloc(reproduced))}, absent "
                   f"under {sorted(alloc(not_reproduced))}. Adjacency claims do not transfer.")
    if osf(reproduced) != osf(not_reproduced):
        out.append("OS-dependent: the fault may be in platform library code rather than the "
                   "target, or an OS-specific detector is doing the detecting.")
    return out
