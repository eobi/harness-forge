#!/usr/bin/env python3
"""Which benchmark plans does the current engine still emit, byte for byte?

WHY THIS EXISTS. Every published row is a measurement of a specific harness. A producer
change that alters a plan silently invalidates that row -- the number stays on the page and
now describes something the engine no longer emits. During one afternoon's work on the C++
producer I checked two plans by hand after every commit, which does not scale to seventeen
and does not survive being forgotten once.

    python3 tools/plandrift.py --write     # record the current plans as the baseline
    python3 tools/plandrift.py             # compare against it, exit 1 on drift

The cases come from benchmarks/drive.py and are read against the local work directory
(HF_BENCH_WORK, default /tmp/hf-bench) rather than the container's /b, so this runs without
Docker and without disturbing a measurement in flight.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
WORK = os.environ.get("HF_BENCH_WORK", "/tmp/hf-bench")
BASELINE = ROOT / "benchmarks" / "plan-baseline.json"


def _cases() -> dict:
    """The case table, imported without running a benchmark."""
    src = (ROOT / "benchmarks" / "drive.py").read_text()
    start = src.index("CASES = {")
    depth, i = 0, src.index("{", start)
    j = i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    ns: dict = {}
    exec("import glob\nCASES = " + src[i:j + 1], ns)     # noqa: S102 -- our own file
    return ns["CASES"]


def _plan_for(case: str, c: dict):
    from hforge.ir import Knobs, Target
    def local(p):
        return p.replace("/b/", f"{WORK}/") if isinstance(p, str) else p
    hdrs = [local(c["hdr"])] + [local(x) for x in c.get("also", [])]
    if not all(Path(h).exists() for h in hdrs):
        return None, "sources not fetched"
    t = Target(name=case.split("/")[0],
               public_headers=hdrs,
               include_dirs=[local(x) for x in c["inc"]],
               sources=[local(x) for x in c["src"]], cflags=list(c.get("cflags") or []))
    knobs = Knobs(max_len=c.get("max_len", 4096))
    if c.get("lang") == "c++":
        from hforge.producers import cxx_header as prod
        t.language = "c++"
        plans = prod.propose(hdrs, t, platforms=["linux-aarch64-glibc"], knobs=knobs)
    else:
        from hforge.producers import header_graph as prod
        plans = prod.propose(hdrs, t, platforms=["linux-aarch64-glibc"], knobs=knobs)
    want = [p for p in plans if any(o.api == c["fn"] for o in p.sequence)]
    if not want:
        return None, "no plan calls the target function"
    # The same tie-break drive.py applies, so this compares the plan that WOULD be measured.
    want.sort(key=lambda p: (0 if any(o.id.startswith("o_consume") and o.api == c["fn"]
                                      for o in p.sequence) else 1,
                             0 if ("_setup" not in p.name and "_with_" not in p.name) else 1,
                             -len(p.sequence), len(p.name)))
    return want[0], ""


def main(argv) -> int:
    write = "--write" in argv
    cases = _cases()
    now: dict = {}
    for case, c in sorted(cases.items()):
        p, why = _plan_for(case, c)
        now[case] = ({"sha": hashlib.sha256(p.dumps().encode()).hexdigest()[:16],
                      "plan": p.name, "ops": [o.id for o in p.sequence]}
                     if p else {"sha": None, "why": why})

    if write:
        BASELINE.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n")
        n = sum(1 for v in now.values() if v["sha"])
        print(f"baseline written: {n} of {len(now)} cases have a plan")
        return 0

    if not BASELINE.exists():
        print("no baseline; run with --write first", file=sys.stderr)
        return 1
    was = json.loads(BASELINE.read_text())
    drift = []
    for case in sorted(set(was) | set(now)):
        a, b = was.get(case, {}), now.get(case, {})
        if a.get("sha") != b.get("sha"):
            drift.append(f"{case}: {a.get('sha') or a.get('why')} -> "
                         f"{b.get('sha') or b.get('why')}")
    for d in drift:
        print(f"[ DRIFT ] {d}")
    unmeasurable = [c for c, v in now.items() if not v["sha"]]
    print(f"{len(now) - len(unmeasurable)} plan(s) compared, {len(drift)} changed"
          + (f", {len(unmeasurable)} without a plan" if unmeasurable else ""))
    if drift:
        print("\nA changed plan means the published row for that case now describes a "
              "harness the engine no longer emits. Re-measure it, or say why the change "
              "does not affect what was measured.")
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
