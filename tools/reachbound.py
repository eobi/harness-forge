#!/usr/bin/env python3
"""What a PLAN cannot reach, stated per plan rather than per corpus.

`tools/bounds.py` answers the question at corpus scale by reading build configuration: 115
of 1374 OSS-Fuzz projects cannot report a leak because the detector is off. This answers it
for one harness, from the API surface: a library exports N functions, a plan calls K of
them, and it can find nothing in the other N-K however long it runs.

That is the number a campaign's silence needs beside it. Coverage over the PROJECT tells
you how much of the code ran; coverage over the REACHABLE set tells you how much of what
this harness could ever touch actually ran, and the gap between the two is the harness's
bound rather than the fuzzer's failure.

Deliberately a floor, not a prediction. A function the plan never calls is unreachable
THROUGH THIS PLAN's own calls; the library may still reach it internally, and this tool
never claims otherwise. Every symbol it names comes from the header, and every call it
counts comes from the plan.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def surface(headers, include_dirs=(), cflags=()) -> set:
    """Every function the header declares -- what a caller could reach directly."""
    from hforge.producers import header_graph
    out = set()
    for h in headers:
        for d in header_graph.parse_header(h, tuple(include_dirs), tuple(cflags)):
            name = getattr(d, "name", None)
            if name:
                out.add(name)
    return out


def bound(ir, exported: set) -> dict:
    called = {op.api for op in ir.sequence}
    unreached = sorted(exported - called)
    return {
        "plan": ir.name,
        "exported": len(exported),
        "called": len(called & exported),
        "unreachable_through_this_plan": len(unreached),
        "reachable_fraction": (round(len(called & exported) / len(exported), 4)
                               if exported else None),
        "cannot_find_defects_in": unreached,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("header")
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--target", default="lib")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("-o", "--out")
    a = ap.parse_args(argv)

    from hforge.ir import Knobs, Target
    from hforge.producers import header_graph

    tgt = Target(name=a.target, include_dirs=a.include)
    plans = header_graph.propose([a.header], tgt, knobs=Knobs())
    exported = surface([a.header], a.include)
    if not plans:
        print("no plan proposed from this header; nothing to bound", file=sys.stderr)
        return 1

    rows = [bound(p, exported) for p in plans]
    rows.sort(key=lambda r: -r["called"])
    print(f"header exports              {len(exported)} function(s)")
    print(f"plans proposed              {len(plans)}")
    print()
    print("  reached  unreachable  plan")
    for r in rows[:a.top]:
        print(f"  {r['called']:7}  {r['unreachable_through_this_plan']:11}  {r['plan']}")
    best = rows[0]
    print()
    print(f"The widest plan calls {best['called']} of {best['exported']} exported functions "
          f"({best['reachable_fraction']:.1%}).")
    print(f"It CANNOT find a defect in the other "
          f"{best['unreachable_through_this_plan']}, however long it runs. Examples:")
    for s in best["cannot_find_defects_in"][:6]:
        print(f"    {s}")
    print()
    print("A floor, not a prediction: these are unreachable through the plan's OWN calls.")
    print("The library may reach them internally, and this tool does not claim otherwise.")
    if a.out:
        Path(a.out).write_text(json.dumps(rows, indent=1))
        print(f"\nwritten to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
