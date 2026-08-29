#!/usr/bin/env python3
"""Compare certificates for the same plan produced on different platforms.

The platform model asserts that variants are distinct in ways that matter. This is where
that assertion gets tested rather than assumed. Two certificates for the same IR should
reach the same gate verdicts; where they do not, the disagreement is the finding.

    reproduces on glibc, absent on musl        -> allocator-dependent
    reproduces on x86_64, absent on aarch64    -> width-dependent arithmetic
    reproduces under one toolchain only        -> treat as an instrumentation artifact

Exit status is 0 whether or not the platforms agree. A disagreement is information, not an
error, and a script that failed the build on it would teach people to stop running it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def verdicts(path: Path) -> tuple:
    c = json.loads(path.read_text())
    gates = {g["gate"]: g["verdict"] for g in c.get("gates", [])}
    return c.get("verdict", "?"), gates


def main(paths) -> int:
    if len(paths) < 2:
        print("need at least two certificates to compare; "
              f"got {len(paths)}. Nothing to say.")
        return 0

    loaded = {p.stem.replace(".cert", ""): verdicts(p) for p in paths}
    names = sorted(loaded)
    all_gates = sorted({g for _, gs in loaded.values() for g in gs})

    width = max(len(n) for n in names)
    print(f"{'GATE':<6} " + " ".join(f"{n:<{width}}" for n in names))
    print("-" * (7 + (width + 1) * len(names)))

    disagreements = []
    for g in all_gates:
        row = [loaded[n][1].get(g, "absent") for n in names]
        mark = "" if len(set(row)) == 1 else "   <-- DISAGREE"
        if mark:
            disagreements.append((g, dict(zip(names, row))))
        print(f"{g:<6} " + " ".join(f"{v:<{width}}" for v in row) + mark)

    print()
    for n in names:
        print(f"  {n:<{width}}  overall verdict: {loaded[n][0]}")
    print()

    if not disagreements:
        print("All platforms agree. The harness behaves the same across allocator and word")
        print("size, so no variant-dependence is implicated.")
        return 0

    print(f"{len(disagreements)} gate(s) disagree across platforms. This is the")
    print("variant-disagreement ORACLE, not a build failure. Read it:")
    for g, row in disagreements:
        print(f"\n  {g}: " + ", ".join(f"{k}={v}" for k, v in row.items()))
        keys = list(row)
        if any("musl" in k for k in keys) and any("glibc" in k for k in keys):
            print("    glibc vs musl differ -> allocator-dependent behaviour")
        if any("x86_64" in k for k in keys) and any("aarch64" in k for k in keys):
            print("    x86_64 vs aarch64 differ -> width-dependent arithmetic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main([Path(a) for a in sys.argv[1:]]))
