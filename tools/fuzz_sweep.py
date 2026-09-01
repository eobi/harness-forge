#!/usr/bin/env python3
"""Fuzz the generated harnesses with NemesisForge, and record what each campaign did.

THE TWO HALVES FIT. harness-forge PROPOSES and CERTIFIES; NemesisForge HUNTS. This runs the
join at corpus scale: every harness that compiles gets a real libFuzzer campaign, and the
result of each one is written down.

WHAT IS RECORDED PER HARNESS, and why each field is here:
  execs     -- ZERO EXECUTIONS IS NOT A CLEAN RESULT. A campaign that fails to build, or one
               whose dictionary libFuzzer rejects, returns "no findings" in about a second.
               Both of those happened during this work and both looked exactly like success.
               Recording execs is what makes the difference visible without reading a clock.
  coverage  -- how much of the library the harness actually reached.
  crashed   -- a crash is a CANDIDATE, not a finding. Triage decides, a human confirms, and
               this engine never prints the words "zero-day" on its own.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

FORGE = Path.home() / "Documents" / "NemesisForge"

# The library sources each harness is compiled against. A harness needs the translation
# units that define the symbols it calls; more than that only slows the build.
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
        out.extend(str(q) for q in sorted((work / lib).glob(pat)) if not _defines_main(q))
    return out


def _include_dirs(lib: str, work: Path) -> list[str]:
    """The same include set the compile probe uses, for the same reason.

    Guessing at {root, src, include} put brotli's public header out of reach -- its headers
    live under c/include and are included as <brotli/port.h>, so every brotli harness failed
    to build. compile_rate._incdirs already solved this, including the part that must be
    left OUT: mbedtls ships tests/include/baremetal-override/time.h, which shadows the
    system header and #errors. Two copies of that logic would have drifted apart.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from compile_rate import _incdirs                              # noqa: PLC0415
    return [d[2:] for d in _incdirs(work / lib)]


# IMPORT NEMESISFORGE ONCE, AT MODULE SCOPE.
#
# These imports used to sit inside run(), so the FIRST call imported the package while later
# calls did not, and the two took measurably different paths: campaigns intermittently fell
# through to the fallback discovery agent, which builds the harness WITHOUT the library
# sources or include directories. That produced "jbig2.h file not found", no findings, and a
# row saying status="built" -- a build failure reported as a successful build, which is the
# worst version of the silent-failure shape this driver exists to expose.
sys.path.insert(0, str(FORGE))
import asyncio                                                     # noqa: E402

from forge.job import lab_job, run_job                             # noqa: E402
from forge.targets.source import SourceTarget                      # noqa: E402


def run(harness: Path, lib: str, work: Path, budget: int, out: Path) -> dict:

    seen: dict = {}
    of = SourceTarget.fuzz

    def spy(self, *a, **k):
        r = of(self, *a, **k)
        # fuzz_ran RECORDS THAT THE STEP HAPPENED AT ALL. Without it, a campaign where the
        # fuzz call was never reached is indistinguishable from one that ran and executed
        # nothing: both leave the counters absent and both report status "built".
        seen.update(fuzz_ran=True, execs=r.execs, coverage=r.coverage, corpus=r.corpus,
                    crashed=bool(r.crashed))
        return r

    SourceTarget.fuzz = spy
    t0 = time.time()
    try:
        ctx, disc, orc, esc, llm = lab_job(
            f"fz-{harness.stem[:28]}", harness.read_text(), artifacts_root=out,
            name=lib, fuzz_time=budget, provider=None, defines=DEFINES.get(lib),
            target_sources=_sources_for(lib, work),
            include_dirs=_include_dirs(lib, work))
        findings = asyncio.run(run_job(ctx, discovery=disc, oracles=orc,
                                       escalation=esc, llm=llm))
        bf = str(getattr(ctx, "build_failure", "") or "")
    except Exception as ex:                                        # noqa: BLE001
        return {"harness": harness.name, "library": lib, "status": "error",
                "error": str(ex)[:160], "seconds": round(time.time() - t0, 1)}
    finally:
        SourceTarget.fuzz = of
    # COUNT CANDIDATES, NOT FINDINGS. Triage de-rates a harness artifact to
    # novelty="artifact" but deliberately keeps it in the list, because a human still
    # decides. Reporting len(findings) therefore counts the engine's own mistakes as
    # discoveries -- four yajl harnesses that freed their own memory were counted that way.
    by_novelty: dict = {}
    for f in findings:
        by_novelty[getattr(f, "novelty", "?")] = by_novelty.get(getattr(f, "novelty", "?"), 0) + 1
    # "built" REQUIRES THAT THE FUZZ STEP ACTUALLY RAN.
    #
    # A build can fail without the failure reaching ctx.build_failure -- under heavy load the
    # compile times out and the agent returns having set nothing. The row then read
    # status="built", fuzz_ran=False, and a reader would count it as a working harness. There
    # is no honest name for that state except "we do not know", so it gets one.
    status = "build-failed" if bf else ("built" if seen.get("fuzz_ran") else "no-campaign")
    return {"harness": harness.name, "library": lib,
            "status": status,
            "build_error": bf.strip().splitlines()[-1][:140] if bf else "",
            "findings": len(findings), "candidates": by_novelty.get("candidate", 0),
            "artifacts": by_novelty.get("artifact", 0), "novelty": by_novelty,
            "fuzz_ran": False, "seconds": round(time.time() - t0, 1), **seen}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--harnesses", default="/tmp/hf-harnesses")
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--out", default="/tmp/hf-fuzz")
    ap.add_argument("--per-lib", type=int, default=5)
    ap.add_argument("--budget", type=int, default=30)
    ap.add_argument("--libs", default="", help="comma-separated; default = all with sources")
    a = ap.parse_args()

    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    want = [x for x in a.libs.split(",") if x] or sorted(SOURCES)
    rows: list[dict] = []
    rec = out / "fuzz.jsonl"
    for lib in want:
        hdir = Path(a.harnesses) / lib / lib
        if not hdir.is_dir():
            continue
        for h in sorted(hdir.glob("*.c"))[:a.per_lib]:
            r = run(h, lib, Path(a.work), a.budget, out)
            rows.append(r)
            with rec.open("a") as f:
                f.write(json.dumps(r) + "\n")
            print(f"  {lib:10s} {h.stem[:44]:46s} {r.get('status','?'):12s} "
                  f"execs={r.get('execs', 0):>10,} cov={r.get('coverage', 0):<5} "
                  f"{'CRASH' if r.get('crashed') else ''}", flush=True)

    built = [r for r in rows if r.get("status") == "built"]
    ran = [r for r in built if (r.get("execs") or 0) > 0]
    crashes = [r for r in rows if r.get("crashed")]
    cand = sum(r.get("candidates") or 0 for r in rows)
    arte = sum(r.get("artifacts") or 0 for r in rows)
    summary = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "budget_seconds": a.budget, "harnesses": len(rows),
               "built": len(built), "executed": len(ran),
               "total_execs": sum(r.get("execs") or 0 for r in ran),
               "crashed": len(crashes), "candidates": cand, "artifacts": arte,
               "rows": rows}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(f"\n{len(ran)}/{len(rows)} campaigns executed, "
          f"{summary['total_execs']:,} total executions, {len(crashes)} crash(es) -> "
          f"{cand} candidate(s), {arte} known harness artifact(s)")
    print(f"recorded: {out / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
