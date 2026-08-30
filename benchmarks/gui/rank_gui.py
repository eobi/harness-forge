"""Regenerate the GUI ranking from measured rows.

Same rule as the C track: a table nobody can regenerate is a table nobody can check, and a
figure this repository measured never shares a cell with one taken from somebody else's
paper. There is no cited column here yet, because no published desktop-GUI work reports the
quantity this table reports.

    python3 benchmarks/gui/rank_gui.py benchmarks/gui/results/*.jsonl --write
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEGIN, END = "<!-- GUIBENCH:BEGIN -->", "<!-- GUIBENCH:END -->"


def main(files, write: bool = False) -> int:
    rows = []
    for f in files:
        for line in Path(f).read_text().splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        print("no rows")
        return 1

    # later rows win for the same (app, mutator, inputs) key, as on the C side
    latest = {}
    for r in rows:
        latest[(r["app"], r["mutator"], r["inputs"])] = r

    out = [
        "| app | format | mutator | n | control | past the parser | rejected | findings |",
        "|---|---|---|---:|---|---:|---:|---:|",
    ]
    for (app, mut, n), r in sorted(latest.items()):
        ctl = r.get("control", "?")
        ctl_cell = f"{ctl} ({r.get('control_nodes','?')} nodes)"
        out.append(
            f"| {app} | {r.get('format','')} | {mut} | {n} | {ctl_cell} | "
            f"**{r.get('past_front_door_pct',0)}%** | {r.get('rejected',0)} | "
            f"{r.get('findings',0)} |")
    table = "\n".join(out)
    src = ", ".join(sorted({Path(f).stem for f in files}))
    table += (f"\n\nSources: {src}. **findings** counts only crashes and genuine hangs — a "
              f"target refusing an input is the target working, and is never counted here.")

    print(table)
    if write:
        md = HERE / "RANKING.md"
        s = md.read_text() if md.exists() else ""
        if BEGIN in s and END in s:
            pre, rest = s.split(BEGIN, 1)
            _, post = rest.split(END, 1)
            md.write_text(pre + BEGIN + "\n\n" + table + "\n\n" + END + post)
            print(f"\n{md.name}: table regenerated from {src}")
        else:
            print(f"\n{md.name}: no {BEGIN} markers; not written", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if a != "--write"]
    sys.exit(main(argv, write="--write" in sys.argv))
