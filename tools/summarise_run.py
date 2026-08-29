#!/usr/bin/env python3
"""Read a suite directory and print what the run actually established.

Written because reading a 600-line ranking table by eye is how numbers get misreported —
and this session has already produced three claims from samples that did not hold on the
full workload.

Every figure here comes from a certificate on disk, and anything unmeasured is printed as
unmeasured rather than as zero.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main(suite: str) -> int:
    root = Path(suite)
    certs = sorted(root.rglob("certificate.json"))
    if not certs:
        print(f"no certificates under {root}")
        return 1

    rows = []
    for c in certs:
        try:
            d = json.loads(c.read_text())
        except Exception:                                        # noqa: BLE001
            continue
        g = {x["gate"]: x for x in d.get("gates", [])}
        d8 = g.get("D8", {}).get("evidence", {}) or {}
        d4 = g.get("D4", {}).get("evidence", {}) or {}
        d2 = g.get("D2", {}).get("evidence", {}) or {}
        rows.append({
            "name": d.get("harness", c.parent.name),
            "verdict": d.get("verdict", "?"),
            "edges": d8.get("edges") if g.get("D8", {}).get("verdict") != "not-run" else None,
            "grew": d8.get("coverage_grew"),
            "seeds": d8.get("mined_seeds", 0),
            "dict": d8.get("dictionary", False),
            "sinks": d4.get("fraction") if g.get("D4", {}).get("verdict") != "not-run"
            else None,
            "kill": d2.get("kill_rate") if g.get("D2", {}).get("verdict") != "not-run"
            else None,
            "unestablished": len(d.get("unreachable", [])),
        })

    measured = [r for r in rows if r["edges"] is not None]
    measured.sort(key=lambda r: -(r["edges"] or 0))

    print(f"{'HARNESS':<44}{'EDGES':>7}{'GREW':>6}{'SINKS':>7}{'KILL':>7}  VERDICT")
    print("-" * 86)
    for r in measured[:25]:
        print(f"{r['name'][:43]:<44}{r['edges']:>7}"
              f"{('yes' if r['grew'] else '-'):>6}"
              f"{(f'{r['sinks']:.0%}' if r['sinks'] is not None else '?'):>7}"
              f"{(r['kill'] or '?'):>7}  {r['verdict']}")

    unmeasured = [r for r in rows if r["edges"] is None]
    print()
    print(f"shipped certificates : {len(rows)}")
    print(f"depth measured       : {len(measured)}")
    print(f"depth NOT measured   : {len(unmeasured)}  (reported as unknown, not as zero)")
    if measured:
        deep = [r for r in measured if (r["edges"] or 0) >= 100]
        print(f"reaching >=100 edges : {len(deep)}")
        print(f"deepest              : {measured[0]['name']} at {measured[0]['edges']} edges")
        print(f"total edges (sum)    : {sum(r['edges'] or 0 for r in measured)}")
        withdict = sum(1 for r in measured if r["dict"])
        withseed = sum(1 for r in measured if (r["seeds"] or 0) > 0)
        print(f"had a dictionary     : {withdict}/{len(measured)}")
        print(f"had mined seeds      : {withseed}/{len(measured)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "build/suite"))
