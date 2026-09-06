#!/usr/bin/env python3
"""Where do P3.LIFT candidates die, per library?

Every "0 candidates" this project has produced turned out to be a defect in this tooling
rather than a fact about the library: a root-only test-directory search, macro-declared tests,
a return type taken from the lift instead of the header, an arity refusal, a const qualifier,
a truncated label. Diagnosing them one at a time has cost a day each.

This reports the WHOLE FUNNEL at once -- test files, sequences, seams, propose failures by
reason, gate blocks by code -- so the next zero names its own cause. No compiling, so it is
cheap enough to run on every library.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from hforge.gates.static_gates import BLOCK, run_static_gates       # noqa: E402
from hforge.producers.header_graph import parse_header              # noqa: E402
from hforge.producers.test_lift import inline_api, propose, resolve_wrappers  # noqa: E402
from libspec import _include_dirs                                   # noqa: E402
from p3lift_batch import LIBS, subsystems                           # noqa: E402
from seam_finder import seams_for                                   # noqa: E402
from test_sequences import _TEST_DIRS, sequences_in                 # noqa: E402


def funnel(lib: str, work: Path) -> dict:
    r = {"library": lib, "stage": {}, "propose_failures": {}, "gate_blocks": {},
         "emit_failures": 0, "notes": []}
    hdr = work / lib / LIBS[lib][0]
    if not hdr.exists():
        r["notes"].append(f"public header missing: {LIBS[lib][0]}")
        return r
    incs = tuple(_include_dirs(lib, work))
    decls = {d.name: d for d in parse_header(str(hdr), incs, ())}
    extra = inline_api([str(hdr)])
    r["stage"]["declarations"] = len(decls)
    r["stage"]["static_inline_api"] = len(extra)
    if not decls:
        r["notes"].append("the header parsed to ZERO declarations")
        return r

    tdirs = [d for d in sorted((work / lib).rglob("*"))
             if d.is_dir() and d.name.lower() in _TEST_DIRS and ".git" not in d.parts]
    files = sorted({f for d in tdirs for f in list(d.rglob("*.c"))[:200]})
    r["stage"]["test_dirs"] = len(tdirs)
    r["stage"]["test_files"] = len(files)
    if not files:
        r["notes"].append("no .c files under any test-shaped directory")
        return r

    api = set(decls) | set(extra)
    wrappers = resolve_wrappers(files, decls)
    r["stage"]["wrappers_resolved"] = len(wrappers)

    seqs = seams = props = gated = ok = 0
    deep_ok = 0
    pf, gb = Counter(), Counter()
    for f in files:
        try:
            src = f.read_text(errors="replace")
        except OSError:
            continue
        for sq in sequences_in(f, api):
            seqs += 1
            ss = seams_for(f, sq["function"], decls, src, wrappers=wrappers)
            seams += len(ss)
            if not ss:
                continue
            plan, rec = propose(str(f), sq["function"], decls, seam=ss[0],
                                target_name=lib, headers=[Path(LIBS[lib][0]).name],
                                also_api=extra, wrappers=wrappers)
            props += 1
            if plan is None:
                pf[rec.get("status", "?")] += 1
                continue
            blocks = [v for g in run_static_gates(plan) for v in g.violations
                      if v.severity == BLOCK]
            if blocks:
                gated += 1
                gb.update(b.code for b in blocks)
                continue
            ok += 1
            if len(subsystems({o.api for o in plan.sequence}) - {"validate"}) >= 2:
                deep_ok += 1
    r["stage"].update({"sequences": seqs, "seams": seams, "proposed": props,
                       "gated": gated, "passed_gates": ok, "passed_deep2": deep_ok})
    r["propose_failures"] = dict(pf.most_common())
    r["gate_blocks"] = dict(gb.most_common())
    if ok == 0:
        for label, cond in (("no sequences with >=2 library calls", seqs == 0),
                            ("sequences exist but NO SEAM was found", seqs and not seams),
                            ("seams exist but every propose failed", seams and props and not ok
                             and sum(pf.values())),
                            ("plans proposed but every one was GATED", gated and not ok)):
            if cond:
                r["notes"].append(label)
                break
    return r


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--libs", default=",".join(LIBS))
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    rows = []
    for lib in [x for x in a.libs.split(",") if x in LIBS]:
        try:
            r = funnel(lib, Path(a.work))
        except Exception as ex:                                     # noqa: BLE001
            r = {"library": lib, "stage": {}, "notes": [f"{type(ex).__name__}: {ex}"]}
        rows.append(r)
        st = r.get("stage", {})
        print(f"\n{lib}: " + "  ".join(f"{k}={v}" for k, v in st.items()), flush=True)
        if r.get("propose_failures"):
            print("   propose failures:", r["propose_failures"], flush=True)
        if r.get("gate_blocks"):
            print("   gate blocks     :", r["gate_blocks"], flush=True)
        for n in r.get("notes", []):
            print(f"   -> {n}", flush=True)
    if a.out:
        Path(a.out).write_text(json.dumps(
            {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "work": a.work, "rows": rows}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
