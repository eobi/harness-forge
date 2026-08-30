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


def _gold_cell(gold, gold_measured, m) -> str:
    """The gold figure, with ITS spread when we have repeats of it.

    Printing our dispersion and not the baseline's would make a stable number look better
    than a wobbly one for the wrong reason. On pugixml it is the DEVELOPER's harness that
    moves (14.79-15.28 over five runs) while ours does not, and a reader has to be able to
    see that.
    """
    if gold is None:
        return "—"
    if not gold_measured:
        return f"{gold:.1f}"
    cell = f"{gold:.2f}†"
    if m and m.get("_gold_spread") is not None and m.get("_n"):
        cell += f" <sub>n={m['_n']} ±{m['_gold_spread']:.2f}</sub>"
    return cell


def main(results, write: bool = False) -> int:
    # SEVERAL RESULTS FILES, LATER ONES WINNING PER CASE.
    #
    # The standing table is per CASE, not per run: run-009 measured eight cases and run-010
    # measured one, and regenerating from run-010 alone would blank the other eight rather
    # than update the one. A row is only ever replaced by a newer measurement of the SAME
    # case, never by the absence of one.
    paths = [Path(r) for r in ([results] if isinstance(results, str) else results)]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"no such results file(s): {', '.join(str(m) for m in missing)}",
              file=sys.stderr)
        return 1
    ref = json.loads((HERE / "reference.json").read_text())["cases"]

    # REPEATS OF THE SAME CASE BECOME A MEDIAN, NOT A LAST-ONE-WINS.
    #
    # Five runs of pugixml against a fixed engine put OUR harness at 14.79% every time and
    # the developer's at 14.79, 14.79, 14.79, 15.28 -- so "both are deterministic" was an
    # artifact of stopping at three, and whichever run happened to be read last would have
    # become the published figure. A single sample is still printed as a single sample;
    # only a case measured more than once is aggregated, and its spread is printed beside
    # it so the reader can see how much the number is worth.
    samples: dict[str, list] = {}
    for rp in paths:
        for line in rp.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            samples.setdefault(d["case"], []).append(d)

    measured: dict[str, dict] = {}
    for case, ds in samples.items():
        ok = [d for d in ds if d.get("result") == "measured" and d.get("lines_pct")]
        if len(ok) < 2:
            measured[case] = ds[-1]
            continue
        # The median SAMPLE, not a synthesised row: every other field on it stays coherent
        # with the number in the `ours` column.
        ok.sort(key=lambda d: float(d["lines_pct"]))
        med = ok[len(ok) // 2]
        med = dict(med)
        vals = [float(d["lines_pct"]) for d in ok]
        med["_n"] = len(ok)
        med["_spread"] = round(max(vals) - min(vals), 2)
        gvals = [float((d.get("gold_measured_here") or {}).get("lines_pct") or 0) for d in ok]
        gvals = [g for g in gvals if g]
        if gvals:
            gv = sorted(gvals)
            med["_gold_median"] = gv[len(gv) // 2]
            med["_gold_spread"] = round(max(gvals) - min(gvals), 2)
        measured[case] = med

    order = list(ref)
    for case in measured:                                  # cases with no reference at all
        if case not in order:
            order.append(case)

    lines: list[str] = []
    def print(*a, **k):                                    # noqa: A001 — capture, then emit
        lines.append(" ".join(str(x) for x in a))

    print("| case | ours | QuartetFuzz | gold | ours/gold | QF/gold |")
    print("|---|---|---|---|---|---|")
    wins = comparable = head_to_head = 0
    for case in order:
        r = ref.get(case, {})
        m = measured.get(case)
        gold, qf = r.get("gold"), r.get("quartetfuzz")

        # A gold figure THIS REPOSITORY MEASURED outranks a cited one: same machine, same
        # compiler, same budget, same denominator. It goes in the gold column with a mark,
        # never merged with a citation.
        if m is not None and (m.get("gold_measured_here") or {}).get("lines_pct"):
            gold = float(m.get("_gold_median") or m["gold_measured_here"]["lines_pct"])
            gold_measured = True
        else:
            gold_measured = False

        if m is None:
            ours_s, ours = "*not yet run*", None
        elif m.get("result") != "measured":
            # A case that failed to build is NOT a zero. It is an absent measurement, and
            # printing 0.00 for it would be a lie in our favour's opposite direction.
            ours_s, ours = f"*{m['result']}*", None
        else:
            ours = float(m["lines_pct"])
            ours_s = f"**{ours:.2f}**"
            if m.get("_n"):
                ours_s += f" <sub>n={m['_n']} ±{m['_spread']:.2f}</sub>"

        if ours is not None and gold:
            comparable += 1
        # The QuartetFuzz record needs its OWN denominator. libde265 has no QF figure at
        # all, and counting it as a case we did not win understates the record just as
        # surely as dropping a loss would overstate it.
        if ours is not None and qf is not None:
            head_to_head += 1
            if ours > qf:
                wins += 1

        print(f"| {case} | {ours_s} "
              f"| {'—' if qf is None else f'{qf:.2f}'} "
              f"| {_gold_cell(gold, gold_measured, m)} "
              f"| {_ratio(ours, gold)} | {_ratio(qf, gold)} |")

    if any((m.get("gold_measured_here") or {}).get("lines_pct") for m in measured.values()):
        print("")
        print("† gold MEASURED by this repository from the project's own in-tree harness, "
              "not cited. Same machine, same compiler, same 600 s, same file list, and a "
              "fresh corpus from the same seeds — so the comparison differs in the harness "
              "and in nothing else.")

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
              f"Ahead of the cited QuartetFuzz figure on "
              f"**{wins} of the {head_to_head}** cases it published one for.")
    print("")
    print("Sources: " + ", ".join(sorted(p.stem for p in paths)) + ".")

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
        sys.stderr.write(f"{md.name}: table regenerated from "
                         f"{', '.join(p.name for p in paths)}\n")
    return rc


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if a != "--write"]
    raise SystemExit(main(argv or sorted(str(p) for p in (HERE / "results").glob("run-*.jsonl")),
                          write="--write" in sys.argv))
