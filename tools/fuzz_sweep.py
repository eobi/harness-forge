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


def _sources_for(lib: str, work: Path) -> list[str]:
    out: list[str] = []
    for pat in SOURCES.get(lib, []):
        out.extend(str(p) for p in sorted((work / lib).glob(pat)))
    return out


def run(harness: Path, lib: str, work: Path, budget: int, out: Path) -> dict:
    sys.path.insert(0, str(FORGE))
    import asyncio

    from forge.job import lab_job, run_job                        # noqa: PLC0415
    from forge.targets.source import SourceTarget                 # noqa: PLC0415

    seen: dict = {}
    of = SourceTarget.fuzz

    def spy(self, *a, **k):
        r = of(self, *a, **k)
        seen.update(execs=r.execs, coverage=r.coverage, corpus=r.corpus,
                    crashed=bool(r.crashed))
        return r

    SourceTarget.fuzz = spy
    t0 = time.time()
    try:
        ctx, disc, orc, esc, llm = lab_job(
            f"fz-{harness.stem[:28]}", harness.read_text(), artifacts_root=out,
            name=lib, fuzz_time=budget, provider=None, defines=DEFINES.get(lib),
            target_sources=_sources_for(lib, work),
            include_dirs=[str(work / lib), str(work / lib / "src"),
                          str(work / lib / "include")])
        findings = asyncio.run(run_job(ctx, discovery=disc, oracles=orc,
                                       escalation=esc, llm=llm))
        bf = str(getattr(ctx, "build_failure", "") or "")
    except Exception as ex:                                        # noqa: BLE001
        return {"harness": harness.name, "library": lib, "status": "error",
                "error": str(ex)[:160], "seconds": round(time.time() - t0, 1)}
    finally:
        SourceTarget.fuzz = of
    return {"harness": harness.name, "library": lib,
            "status": "built" if not bf else "build-failed",
            "build_error": bf.strip().splitlines()[-1][:140] if bf else "",
            "findings": len(findings), "seconds": round(time.time() - t0, 1), **seen}


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
    summary = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "budget_seconds": a.budget, "harnesses": len(rows),
               "built": len(built), "executed": len(ran),
               "total_execs": sum(r.get("execs") or 0 for r in ran),
               "crashed": len(crashes), "rows": rows}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(f"\n{len(ran)}/{len(rows)} campaigns executed, "
          f"{summary['total_execs']:,} total executions, {len(crashes)} crash candidate(s)")
    print(f"recorded: {out / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
