"""The portable coverage-guided driver for hosts WITHOUT a libFuzzer runtime.

Windows-on-ARM ships clang but no clang_rt.fuzzer.lib, so a libFuzzer harness cannot link
there. `-fsanitize-coverage=trace-pc` still instruments, so this driver supplies the missing
engine: edge feedback (return-address hashed into a bitmap, no sections that Windows COFF
would not resolve), byte + dictionary mutation, a corpus that keeps any input reaching a new
edge, and SEH to catch the access violation. It drives the SAME LLVMFuzzerTestOneInput a
libFuzzer harness defines -- one harness, every host.
"""
from __future__ import annotations

from pathlib import Path

_DRIVER = Path(__file__).parent / "resources" / "hf_winfuzz.c"


def driver_source() -> str:
    return _DRIVER.read_text()


def build_commands(harness: str, sources: list, out: str, *, clang: str = "clang",
                   includes: tuple = (), defines: tuple = (),
                   driver: str = "hf_winfuzz.c") -> list:
    """The clang command lines that build a native coverage-guided binary for this host.

    The target and harness are compiled with `-fsanitize-coverage=trace-pc`; the driver is
    not (it must not instrument its own feedback). ubsan's auto-linked runtime is skipped --
    trace-pc needs none of it.
    """
    cov = "-fsanitize-coverage=trace-pc"
    inc = [f"-I{i}" for i in includes]
    dfs = [f"-D{d}" for d in defines]
    objs = []
    cmds = []
    for src in [*sources, harness]:
        obj = str(Path(src).with_suffix(".o").name)
        objs.append(obj)
        cmds.append([clang, cov, "-g", "-O1", "-w", *inc, *dfs, "-c", src, "-o", obj])
    cmds.append([clang, "-g", "-O1", "-w", "-c", driver, "-o", "hf_winfuzz.o"])
    cmds.append([clang, *objs, "hf_winfuzz.o", "-o", out,
                 "-Xlinker", "/nodefaultlib:clang_rt.ubsan_standalone.lib"])
    return cmds
