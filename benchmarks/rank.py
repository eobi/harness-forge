#!/usr/bin/env python3
"""Regenerate the standing table from measured results plus cited references.

    python3 benchmarks/rank.py benchmarks/results/run-009.jsonl

THE ONE RULE THIS SCRIPT ENFORCES MECHANICALLY: a cell holding a number this repository
measured and a cell holding a number somebody else published are different kinds of
evidence, and they never merge. Measured figures come only from the results file; cited
figures come only from reference.json; neither file can supply the other's column.

Written because the table was maintained by hand and drifted twice — once carrying a
figure from a plan our own S1 gate blocks, once carrying a 60-second number in a column
headed 600 seconds. A table nobody can regenerate is a table nobody can check.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _ratio(ours: float | None, gold: float | None) -> str:
    if ours is None or not gold:
        return ""
    return f"{ours / gold:.2f}x"


def main(results: str, write: bool = False) -> int:
    rp = Path(results)
    if not rp.exists():
        print(f"no such results file: {rp}", file=sys.stderr)
        return 1
    ref = json.loads((HERE / "reference.json").read_text())["cases"]

    measured: dict[str, dict] = {}
    for line in rp.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        measured[d["case"]] = d

    order = list(ref)
    for case in measured:                                  # cases with no reference at all
        if case not in order:
            order.append(case)

    lines: list[str] = []
    def print(*a, **k):                                    # noqa: A001 — capture, then emit
        lines.append(" ".join(str(x) for x in a))

    print("| case | ours | QuartetFuzz | gold | ours/gold | QF/gold |")
    print("|---|---|---|---|---|---|")
    wins = comparable = 0
    for case in order:
        r = ref.get(case, {})
        m = measured.get(case)
        gold, qf = r.get("gold"), r.get("quartetfuzz")

        if m is None:
            ours_s, ours = "*not yet run*", None
        elif m.get("result") != "measured":
            # A case that failed to build is NOT a zero. It is an absent measurement, and
            # printing 0.00 for it would be a lie in our favour's opposite direction.
            ours_s, ours = f"*{m['result']}*", None
        else:
            ours = float(m["lines_pct"])
            ours_s = f"**{ours:.2f}**"

        if ours is not None and gold:
            comparable += 1
            if qf is not None and ours > qf:
                wins += 1

        print(f"| {case} | {ours_s} "
              f"| {'—' if qf is None else f'{qf:.2f}'} "
              f"| {'—' if gold is None else f'{gold:.1f}'} "
              f"| {_ratio(ours, gold)} | {_ratio(qf, gold)} |")

    ours_r = [float(m["lines_pct"]) / ref[c]["gold"]
              for c, m in measured.items()
              if m.get("result") == "measured" and ref.get(c, {}).get("gold")]
    if ours_r:
        ours_r.sort()
        med = ours_r[len(ours_r) // 2] if len(ours_r) % 2 else \
            (ours_r[len(ours_r) // 2 - 1] + ours_r[len(ours_r) // 2]) / 2
        print()
        print(f"Measured cases with a gold baseline: **{comparable}**. "
              f"Median ours/gold: **{med:.2f}x**. "
              f"Ahead of the cited QuartetFuzz figure on **{wins} of {comparable}**.")

    table = "\n".join(lines)
    if not write:
        sys.stdout.write(table + "\n")
        return 0

    # Splice between markers so the prose around the table stays hand-written and the
    # numbers stay generated. Editing the numbers by hand is how the table drifted before.
    targets = [(HERE / "RANKING.md", "TABLE"),
               (HERE.parent / "README.md", "BENCH")]
    rc = 0
    for md, marker in targets:
        a, b = f"<!-- {marker}:BEGIN -->", f"<!-- {marker}:END -->"
        doc = md.read_text()
        if a not in doc or b not in doc:
            sys.stderr.write(f"{md.name} has no {a} / {b} markers — skipped\n")
            rc = 1
            continue
        head, rest = doc.split(a, 1)
        _, tail = rest.split(b, 1)
        md.write_text(f"{head}{a}\n\n{table}\n\n{b}{tail}")
        sys.stderr.write(f"{md.name}: table regenerated from {rp.name}\n")
    return rc


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if a != "--write"]
    raise SystemExit(main(argv[0] if argv else str(HERE / "results" / "run-009.jsonl"),
                          write="--write" in sys.argv))
