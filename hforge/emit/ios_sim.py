"""iOS Simulator backend: the same certified plan, cross-compiled for the iOS Simulator.

`emit/__init__.backend_for` routes a C/C++ plan whose `platforms` name an iOS *simulator*
target here. Like the Android backend, the HARNESS SOURCE is identical and this rewrites
only the build commands -- but for iOS the point is `-target` and `-isysroot`, which is the
exact thing the platform table used to LIE about: `--platform ios-arm64-simulator` was
accepted and then emitted a host build with neither flag, so the flag was silently ignored.
This backend applies both, which is the precondition the platform model states for flipping
`ios-*-simulator.emit_ready` to True.

The iOS Simulator's trust ceiling is REACHABILITY-ONLY relative to a real device, and the
doctrine is "fuzz where instrumentation is cheap, prove reachability where the target runs":
discovery happens on the macOS host, the simulator confirms the path exists. Accordingly the
primary build is an ASAN + standalone-driver binary that runs under `simctl spawn` and pairs
with an uninstrumented baseline for the on-device differential -- NOT a libFuzzer campaign.

That is also what the toolchain permits honestly. Apple's clang ships the ASan runtime for
the simulator (`libclang_rt.asan_iossim_dynamic.dylib`) but NOT libFuzzer's
(`libclang_rt.fuzzer_iossim.a`), so a `-fsanitize=fuzzer` link fails outright. This backend
PROBES for the fuzzer runtime: if a future toolchain ships it the campaign build is emitted
with `-fsanitize=fuzzer,address`; otherwise the reachability/replay build is emitted and the
build.sh says why in one line, rather than emitting a command that cannot link.
"""
from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Optional

from ..ir import HarnessIR
from . import c_libfuzzer
from .c_libfuzzer import Emitted, EmitError

# Which -target triple each modelled simulator platform builds for. iOS 13 is the floor that
# still carries the sanitizer runtimes.
_PLATFORM_TARGET = {
    "ios-arm64-simulator": "arm64-apple-ios13.0-simulator",
    "ios-x86_64-simulator": "x86_64-apple-ios13.0-simulator",
}


def target_triple(ir: HarnessIR) -> str:
    for p in ir.platforms:
        if p in _PLATFORM_TARGET:
            return _PLATFORM_TARGET[p]
    return "arm64-apple-ios13.0-simulator"


@lru_cache(maxsize=1)
def _xcrun_clang() -> Optional[str]:
    try:
        r = subprocess.run(["xcrun", "-sdk", "iphonesimulator", "--find", "clang"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() or None
    except Exception:                                                # noqa: BLE001
        return None


@lru_cache(maxsize=1)
def _sdk_path() -> Optional[str]:
    try:
        r = subprocess.run(["xcrun", "-sdk", "iphonesimulator", "--show-sdk-path"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() or None
    except Exception:                                                # noqa: BLE001
        return None


@lru_cache(maxsize=1)
def has_fuzzer_runtime() -> bool:
    """Whether this toolchain ships libFuzzer's iOS-simulator runtime. Apple's clang does not
    today, which is why the simulator is a reachability oracle rather than a discovery box."""
    cc = _xcrun_clang()
    if not cc:
        return False
    try:
        r = subprocess.run([cc, "-print-resource-dir"], capture_output=True, text=True,
                           timeout=30)
        rd = r.stdout.strip()
        if not rd:
            return False
        return (Path(rd) / "lib" / "darwin" / "libclang_rt.fuzzer_iossim.a").exists()
    except Exception:                                                # noqa: BLE001
        return False


def emit(ir: HarnessIR, *, with_driver: bool = True) -> Emitted:
    """Emit the host C harness, then rewrite the build commands as an iOS-sim cross-build."""
    base = c_libfuzzer.emit(ir, with_driver=with_driver)
    triple = target_triple(ir)
    cc = _xcrun_clang() or "$IOS_SIM_CLANG"
    sdk = _sdk_path() or "$IOS_SIM_SDK"

    incs = [f"-I{d}" for d in ir.target.include_dirs] + list(ir.target.cflags)
    common = [cc, "-target", triple, "-isysroot", sdk,
              "-g", "-O1", "-fno-omit-frame-pointer", *incs]
    srcs = list(ir.target.sources)
    libs = list(ir.target.link_libs)
    stem = f"{ir.name}_iossim"

    if has_fuzzer_runtime():
        # A real coverage-guided campaign is possible on this toolchain.
        build = [*common, "-fsanitize=fuzzer,address", "harness.c",
                 *srcs, *libs, "-o", f"{stem}-fuzz"]
    else:
        # Reachability/replay build: ASan + the standalone driver, runnable under
        # `simctl spawn <udid> <bin> <input>`. This is the simulator's actual role.
        build = [*common, "-fsanitize=address", "harness.c", "driver.c",
                 *srcs, *libs, "-o", f"{stem}-asan"]
    # Uninstrumented baseline for the differential (the simulator/device oracle).
    dbuild = [*common, "harness.c", "driver.c", *srcs, *libs, "-o", f"{stem}-baseline"]

    return Emitted(source=base.source, driver=base.driver, build_command=build,
                   driver_build_command=dbuild, entry_symbols=base.entry_symbols)
