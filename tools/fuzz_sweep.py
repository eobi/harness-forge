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
from libspec import (DEFINES, SEED_FORMATS, SOURCES, _defines_main,  # noqa: E402
                     _include_dirs, _sources_for)

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




def seed_campaign(lib: str, work: Path, corpus: Path, max_files: int = 200) -> int:
    """Fill a campaign's corpus from the library's own repository. Returns how many."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from seed_mine import install, mine                            # noqa: PLC0415
    chosen, _ = mine(work / lib, formats=SEED_FORMATS.get(lib, ()), max_files=max_files)
    return install(chosen, corpus)


def run(harness: Path, lib: str, work: Path, budget: int, out: Path,
        seeds: bool = True) -> dict:

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
    job = f"fz-{harness.stem[:28]}"
    n_seeds = 0
    if seeds:
        # BEFORE the job runs: lab_job points the campaign at <root>/<job>/corpus, and
        # target.fuzz passes that directory to libFuzzer, which loads whatever is in it.
        n_seeds = seed_campaign(lib, work, out / job / "corpus")
    try:
        ctx, disc, orc, esc, llm = lab_job(
            job, harness.read_text(), artifacts_root=out,
            name=lib, fuzz_time=budget, provider=None, defines=DEFINES.get(lib),
            target_sources=_sources_for(lib, work),
            include_dirs=_include_dirs(lib, work))
        findings = asyncio.run(run_job(ctx, discovery=disc, oracles=orc,
                                       escalation=esc, llm=llm))
        bf = str(getattr(ctx, "build_failure", "") or "")
    except Exception as ex:                                        # noqa: BLE001
        return {"harness": harness.name, "library": lib, "seeds": n_seeds,
                "status": "error",
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
    return {"harness": harness.name, "library": lib, "seeds": n_seeds,
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
    ap.add_argument("--no-seeds", action="store_true",
                    help="run with an EMPTY corpus, for the seeded-vs-unseeded comparison")
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
            r = run(h, lib, Path(a.work), a.budget, out, seeds=not a.no_seeds)
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
