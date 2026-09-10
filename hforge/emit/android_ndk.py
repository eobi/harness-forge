"""Android NDK backend: the same certified plan, cross-compiled for an Android device.

`emit/__init__.backend_for` routes a C/C++ plan whose `platforms` name an Android target
here instead of to the host `c_libfuzzer`. The HARNESS SOURCE is identical -- one IR, many
backends -- so this delegates to `c_libfuzzer.emit` for `harness.c`, the replay driver and
the entry symbols, and rewrites only the two build commands so the emitted `build.sh` is a
real cross-build rather than a host build silently mislabelled Android.

The cross-compile line is lifted from `devices.build_android` / `toolchain.ndk_clang` so the
artifact an operator receives matches what the on-device pipeline (`hforge run-on-device`)
actually runs. Two binaries are produced because the device oracle is a DIFFERENTIAL:

  * build_command        -> the INSTRUMENTED device binary (HWASan, the on-device detector),
  * driver_build_command -> the UNINSTRUMENTED BASELINE, so a HWASan-on-stock-image startup
                            fault can be told from a real target fault ("downgrade, do not
                            drop"). `run-on-device` rebuilds these itself with the correct
                            per-device detector downgrade; the script is the honest default.

HWASan is the on-device detector, not ASan (a shipping device is realistically limited to
HWASan/GWP-ASan). It needs arm64 and API>=29 AND a HWASan system image, so the emitted line
carries `-fsanitize=hwaddress`; the build.sh comment and `run-on-device` handle the silent
degrade to ASan when the image cannot carry it.
"""
from __future__ import annotations

from typing import Optional

from ..ir import HarnessIR
from . import c_libfuzzer
from .c_libfuzzer import Emitted, EmitError

# Which NDK ABI / API level each modelled Android platform cross-compiles for.
_PLATFORM_ABI = {
    "android-arm64-emulator": ("arm64-v8a", 29),
    "android-arm64-device": ("arm64-v8a", 29),
    "android-armv7-device": ("armeabi-v7a", 24),
    "android-x86_64-emulator": ("x86_64", 29),
}


def target_abi(ir: HarnessIR) -> tuple:
    """(abi, api) for the first Android platform on the plan, defaulting to arm64/29."""
    for p in ir.platforms:
        if p in _PLATFORM_ABI:
            return _PLATFORM_ABI[p]
    return ("arm64-v8a", 29)


def _ndk_clang(abi: str, api: int) -> Optional[str]:
    from .. import toolchain as tc                                   # noqa: PLC0415
    from .. import devices                                          # noqa: PLC0415
    ndk = tc.find_ndk()
    if not ndk:
        return None
    return devices.ndk_clang_for(ndk, abi, api)


def emit(ir: HarnessIR, *, with_driver: bool = True) -> Emitted:
    """Emit the host C harness, then rewrite the build commands as an NDK cross-build."""
    base = c_libfuzzer.emit(ir, with_driver=with_driver)
    abi, api = target_abi(ir)
    # The compiler token: a resolved NDK clang path when the NDK is present, else an honest
    # `$NDK_CLANG` placeholder so the script names what is missing rather than pretending
    # `clang` is a cross-compiler. Never silently emit the host compiler for an Android plan.
    cc = _ndk_clang(abi, api) or "$NDK_CLANG"

    incs = [f"-I{d}" for d in ir.target.include_dirs] + list(ir.target.cflags)
    common = [cc, "-O1", "-g", "-fno-omit-frame-pointer", *incs]
    srcs = list(ir.target.sources)
    libs = list(ir.target.link_libs)
    stem = f"{ir.name}_android_{abi}"

    # Instrumented device binary (harness + standalone driver: the device runs `bin input`,
    # there is no libFuzzer runtime in play on the device oracle).
    build = [*common, "-fsanitize=hwaddress", "-fsanitize-recover=hwaddress",
             "harness.c", "driver.c", *srcs, *libs, "-o", f"{stem}-hwasan"]
    # Uninstrumented baseline for the on-device differential.
    dbuild = [*common, "harness.c", "driver.c", *srcs, *libs, "-o", f"{stem}-baseline"]

    return Emitted(source=base.source, driver=base.driver, build_command=build,
                   driver_build_command=dbuild, entry_symbols=base.entry_symbols)
