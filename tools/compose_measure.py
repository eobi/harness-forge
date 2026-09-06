#!/usr/bin/env python3
"""Measure a COMPOSED plan against the best single lifted test and the developer harness.

Paired, repeated, same mined seeds, same flags, arms alternating order. Three arms:
  DEVELOPER   the library's own harness
  EMBED       the best single lifted test (parse + serialise in one function)
  COMPOSED    a parse-only test with a serialise test's call rebound onto its parsed value
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tools"))

from hforge.emit import emit                                        # noqa: E402
from hforge.gates.static_gates import BLOCK, run_static_gates       # noqa: E402
from hforge.producers.compose import compose                        # noqa: E402
from hforge.producers.header_graph import parse_header              # noqa: E402
from hforge.producers.test_lift import inline_api, propose, resolve_wrappers  # noqa: E402
from libspec import SEED_FORMATS, _include_dirs                     # noqa: E402
from p3lift_batch import LIBS, build, campaign, smoke, subsystems   # noqa: E402
from seam_finder import seams_for                                   # noqa: E402
from seed_mine import install, mine                                 # noqa: E402
from test_sequences import sequences_in                             # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", default=str(Path.home() / "hf-work/libs"))
    ap.add_argument("--lib", default="jansson")
    ap.add_argument("--a", default="decode_any", help="parse-only test to compose onto")
    ap.add_argument("--embed", default="embed", help="best single deep=2 test, for comparison")
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="/tmp/compose-measure")
    a = ap.parse_args()
    W, lib = Path(a.work), a.lib
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    hdr = W / lib / LIBS[lib][0]
    decls = {d.name: d for d in parse_header(str(hdr), tuple(_include_dirs(lib, W)), ())}
    extra = inline_api([str(hdr)]); api = set(decls) | set(extra)
    tf = [f for f in sorted((W / lib).rglob("*.c"))
          if "test" in str(f).lower() and "fuzz" not in str(f).lower()]
    w = resolve_wrappers(tf, decls)
    from hforge.producers.compose import _produced_resources                # noqa: PLC0415
    A = E = None; Bs = []; A_cands = []
    for f in tf:
        src = f.read_text(errors="replace")
        for sq in sequences_in(f, api):
            subs = subsystems(set(sq["calls"])) - {"validate"}
            ss = seams_for(f, sq["function"], decls, src, wrappers=w)
            if sq["function"] == a.a and ss and A is None:
                A, _ = propose(str(f), a.a, decls, seam=ss[0], target_name=lib,
                               headers=[hdr.name], also_api=extra, wrappers=w)
            # AUTO-CANDIDATES: parse-only plans whose seam produces a parse-output root. The
            # cjson composition lost because --a was a shallow hand-pick; the strongest such
            # plan is chosen when --a is not given or does not compose.
            if subs == {"parse"} and ss and [x for x in ss if x["parse_like"]]:
                pa, _ = propose(str(f), sq["function"], decls,
                                seam=[x for x in ss if x["parse_like"]][0],
                                target_name=lib, headers=[hdr.name], also_api=extra, wrappers=w)
                if pa is not None:
                    from hforge.gates.static_gates import run_static_gates, BLOCK  # noqa: PLC0415,E501
                    if not [v for g in run_static_gates(pa) for v in g.violations
                            if v.severity == BLOCK]:
                        pr = _produced_resources(pa, decls)
                        if any(is_p for _, _, is_p, _ in pr):
                            A_cands.append((sq["function"], pa, len(pa.sequence)))
            if sq["function"] == a.embed and ss and E is None:
                E, _ = propose(str(f), a.embed, decls, seam=ss[0], target_name=lib,
                               headers=[hdr.name], also_api=extra, wrappers=w)
            if "serialise" in subs and "parse" not in subs:
                B, _ = propose(str(f), sq["function"], decls, seam=None, target_name=lib,
                               headers=[hdr.name], also_api=extra, wrappers=w)
                if B is not None:
                    Bs.append(B)
    # Strongest base A first: given by --a if it composes, else the parse-entered plan with
    # the most ops. Each is tried against every B until one composition passes the gates.
    ordered_A = ([("--a:" + a.a, A)] if A is not None else []) + [
        (n, pa) for n, pa, _ in sorted(A_cands, key=lambda c: -c[2])]
    if not ordered_A:
        print("no parse-entered plan A"); return 1
    composed = None
    for an, A in ordered_A:
      for B in Bs:
        plan, rec = compose(A, B, decls)
        if plan and not [v for g in run_static_gates(plan) for v in g.violations
                         if v.severity == BLOCK]:
            composed = plan
            print(f"composed A={an} + B={rec['b']} rebind={rec.get('rebound_resource')}")
            break
      if composed is not None:
          break
    if composed is None:
        print("no composition passed the gates"); return 1

    corpus = out / "corpus"; corpus.mkdir(exist_ok=True)
    chosen, _ = mine(W / lib, formats=SEED_FORMATS.get(lib, ()), max_files=120)
    install(chosen, corpus)
    arms = []
    for name, plan in (("COMPOSED", composed), ("EMBED", E)):
        if plan is None: continue
        c = out / f"{name}.c"; c.write_text(emit(plan).source)
        b = out / f"{name}.bin"
        if build(c, lib, W, b) and smoke(b, corpus):
            arms.append((name, b))
        else:
            print(f"{name}: killed at build or smoke")
    dev = next((q for q in sorted((W / lib).glob(LIBS[lib][2])) if "main" not in q.name), None)
    if dev is not None:
        b = out / "DEVELOPER.bin"
        if build(dev, lib, W, b): arms.append(("DEVELOPER", b))
    rows = []
    for k in range(a.repeats):
        for name, b in (arms if k % 2 == 0 else list(reversed(arms))):
            cov, ex = campaign(b, corpus, a.budget)
            rows.append({"arm": name, "repeat": k, "cov": cov, "execs": ex})
            print(f"  r{k} {name:10s} cov={cov:<6} execs={ex:,}", flush=True)
    per = {}
    for r in rows:
        if r["cov"] > 0: per.setdefault(r["arm"], []).append(r["cov"])
    dev_med = st.median(per.get("DEVELOPER", [0]))
    print("\n=== medians ===")
    for k, v in sorted(per.items(), key=lambda kv: -st.median(kv[1])):
        print(f"  {k:10s} {st.median(v):6.0f}  {st.median(v)/dev_med:.2f}x dev" if dev_med else f"  {k} {st.median(v)}")
    (out / "result.json").write_text(json.dumps(
        {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "lib": lib,
         "budget": a.budget, "repeats": a.repeats, "rows": rows}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
