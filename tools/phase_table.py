#!/usr/bin/env python3
"""Print the phase table, generated from the manifest.

    python3 tools/phase_table.py            # print it
    python3 tools/phase_table.py --write    # splice it into README.md

The README carried the heading "working today: phases 1, 2, and half of 3" long after P3
reached 28 of 33 and five other phases had completed. A status a human maintains by hand is
a status that drifts in whichever direction flatters the last person to touch it — here it
drifted DOWNWARD, which is the less common failure and no more accurate for it.

So the table is generated. `plancheck` already refuses to let a DONE claim stand without a
module that imports and a test that exists, which makes the manifest the one place in this
repository where status is load-bearing rather than descriptive.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hforge import manifest as M                                        # noqa: E402

MARK = "PHASES"


def table() -> str:
    rows = ["| phase | | done | |", "|---|---|---|---|"]
    for ph in M.PHASES:
        ds = list(ph.deliverables)
        done = sum(1 for d in ds if d.status == M.DONE)
        mark = {"done": "**done**", "partial": "partial", "planned": "planned"}[ph.status]
        rows.append(f"| `{ph.id}` | {ph.name} | {done}/{len(ds)} | {mark} |")
    total = [d for ph in M.PHASES for d in ph.deliverables]
    rows.append("")
    rows.append(f"**{sum(1 for d in total if d.status == M.DONE)} of {len(total)} "
                f"deliverables done**, and `plancheck` refuses to let any of them say so "
                f"without a module that imports and a test that exists.")
    return "\n".join(rows)


def main(write: bool) -> int:
    t = table()
    if not write:
        print(t)
        return 0
    md = Path(__file__).resolve().parent.parent / "README.md"
    a, b = f"<!-- {MARK}:BEGIN -->", f"<!-- {MARK}:END -->"
    doc = md.read_text()
    if a not in doc or b not in doc:
        sys.stderr.write(f"README.md has no {a} / {b} markers\n")
        return 1
    head, rest = doc.split(a, 1)
    _, tail = rest.split(b, 1)
    md.write_text(f"{head}{a}\n\n{t}\n\n{b}{tail}")
    sys.stderr.write("README.md: phase table regenerated from the manifest\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main("--write" in sys.argv))
