#!/usr/bin/env python3
"""What each library needs to BUILD: its sources, its include dirs, its defines, its seeds.

Separated from fuzz_sweep because none of it requires a fuzzer. fuzz_sweep imports
NemesisForge at module scope, so anything importing it needed NemesisForge installed -- which
stopped the seed experiment running on a machine that only has clang, for no reason except
where the constants happened to live.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compile_rate import _incdirs                                  # noqa: E402


def _include_dirs(lib: str, work: Path) -> list:
    """The same include set the compile probe uses, for the same reason.

    Guessing at {root, src, include} put brotli's public header out of reach -- its headers
    live under c/include and are included as <brotli/port.h>. compile_rate._incdirs already
    solved this, including the part that must be left OUT: mbedtls ships
    tests/include/baremetal-override/time.h, which shadows the system header and #errors.
    """
    return [d[2:] for d in _incdirs(work / lib)]


# Build-time defines the library's own build passes. An autotools library compiled without
# -DHAVE_CONFIG_H reads a different branch of its own headers, fails to compile ONE source,
# and dies at link time on a symbol thirty lines from the cause.
DEFINES = {
    "jansson": ["HAVE_CONFIG_H"],
    "libyaml": ["HAVE_CONFIG_H", "YAML_VERSION_STRING=\"0.2.5\"",
                "YAML_VERSION_MAJOR=0", "YAML_VERSION_MINOR=2", "YAML_VERSION_PATCH=5"],
    # zconf.h only declares read/close when the build says unistd.h exists, so gzread.c and
    # gzwrite.c fail to compile and the harness dies at link on _gzclose_r -- the same
    # far-from-the-cause shape as jansson and libyaml, for the third time.
    "zlib":    ["HAVE_UNISTD_H"],
    "expat":   ["XML_POOR_ENTROPY", "HAVE_MEMMOVE"],
}

SOURCES = {
    "cjson":     ["cJSON.c"],
    "jansson":   ["src/*.c"],
    "libyaml":   ["src/*.c"],
    "yajl":      ["src/*.c"],
    "zlib":      ["*.c"],
    "expat":     ["expat/lib/*.c"],
    "jbig2dec":  ["*.c"],
    "zopfli":    ["src/zopfli/*.c"],
    "brotli":    ["c/dec/*.c", "c/common/*.c"],
    "lcms2":     ["src/*.c"],
    "libpng":    ["*.c"],
    "libwebp":   ["src/dec/*.c", "src/dsp/*.c", "src/utils/*.c", "src/webp/*.c"],
}


# `int` and `main(` are OFTEN ON SEPARATE LINES -- jbig2dec, zopfli and most K&R-descended C
# write the return type on its own line. A per-line pattern matches none of them, which is
# worse than useless here: it silently accepts every file.
# Extensions worth preferring when mining seeds, where the library's format is obvious from
# its name. Absent an entry the miner ranks by directory instead, which is weaker but never
# wrong -- libFuzzer discards a seed that adds no coverage.
SEED_FORMATS = {
    "libpng": (".png",), "libwebp": (".webp", ".png"), "jbig2dec": (".jb2", ".jbig2"),
    "lcms2": (".icc", ".icm"), "libde265": (".bin", ".h265", ".265"),
    "jansson": (".json",), "cjson": (".json",), "yajl": (".json",),
    "libyaml": (".yaml", ".yml"), "expat": (".xml",), "zstd": (".zst",),
    "brotli": (".br", ".compressed"), "zlib": (".gz", ".zlib"),
}


_MAIN = re.compile(r"(?:^|\n)\s*(?:int|void)\s*\n?\s*main\s*\(")


def _defines_main(p: Path) -> bool:
    """Does this file define main() UNCONDITIONALLY?

    The nesting check is the whole point. A C library routinely ships a self-test main()
    behind `#ifdef TEST`, and jbig2dec has three: jbig2_arith.c, jbig2_huffman.c and sha1.c.
    Matching main() anywhere dropped all three from the link, and the build then failed on an
    undefined jbig2_table -- a symbol from a file the filter had silently removed, with
    nothing in the error pointing back at the filter.

    Excluding a needed file gives that obscure undefined-symbol error; keeping a file with a
    guarded main() costs nothing, because if the guard IS defined the linker says "duplicate
    symbol _main", which names the problem exactly.
    """
    try:
        text = p.read_text(errors="ignore")
    except OSError:
        return False
    # Keep only the lines that are NOT inside a preprocessor conditional, then match across
    # newlines. Doing it in one pass per line cannot see a declaration split over two.
    kept, depth = [], 0
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("#if"):
            depth += 1
            continue
        if st.startswith("#endif"):
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            kept.append(line)
    return bool(_MAIN.search("\n".join(kept)))


# Sources that belong to the library but pull in an EXTERNAL dependency the harness does not
# need. jbig2dec ships jbig2_image_png.c, an optional PNG *output writer* that needs libpng;
# linking it fails on png_error and takes every jbig2dec harness with it, for a file no
# decoding harness ever calls.
SOURCE_EXCLUDE = {
    "jbig2dec": ("jbig2_image_png.c",),
}


def _sources_for(lib: str, work: Path) -> list[str]:
    """The library's translation units, MINUS any that defines main().

    A library ships its command-line tool beside its implementation. Linking that main()
    alongside the libFuzzer driver produces a binary that is the TOOL, not a fuzzer: zopfli's
    harness answered "Please provide filename" and the campaign recorded 0 executions while
    reporting itself built. Same silent-nothing as the rejected dictionary and the missing
    -D, arriving by a third route -- so this is filtered structurally rather than by
    maintaining a list of which files to avoid per library.
    """
    out: list[str] = []
    for pat in SOURCES.get(lib, []):
        skip = SOURCE_EXCLUDE.get(lib, ())
        out.extend(str(q) for q in sorted((work / lib).glob(pat))
                   if not _defines_main(q) and q.name not in skip)
    return out


