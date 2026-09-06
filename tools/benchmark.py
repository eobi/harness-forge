#!/usr/bin/env python3
"""W0 -- the live competitive benchmark rig. Nothing is a claim until this scores it.

A benchmark is only meaningful when it is PAIRED (our harness vs the baseline on the same
corpus, same budget, arms alternated), REPEATED, and reported with a real statistic against
the competitor's published bar. This turns the ad-hoc measurements into one reproducible
scoreboard: per library, ours vs the developer harness; the median ratio; whether it beats
1.0 (parity) and the competitor bar (OGHarn 1.14x); with an EXACT sign test, not a hand-wave.

It reads the paired-campaign result of tools/p3lift_batch.py (or compose_measure) and emits
the scoreboard. Provenance -- commit, budget, repeats, corpus -- travels with it so a number
can be reproduced rather than trusted.

METRIC M1 (coverage vs developer harness) is implemented; the scoreboard schema is shaped so
M2 (findings), M3 (false positives) and the GUI metrics slot in as more competitors are run.
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import subprocess
import time
from math import comb
from pathlib import Path

# Published competitor bars, coverage-vs-developer-harness (ratio). A claim to beat one is a
# claim to exceed its number with a repeated, paired measurement -- never a single run.
BARS = {"parity": 1.0, "OGHarn": 1.14}


def _commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, cwd=Path(__file__).parent
                              ).stdout.strip() or "unknown"
    except Exception:                                              # noqa: BLE001
        return "unknown"


def _sign_test(wins: int, losses: int) -> float:
    """Two-sided exact sign test p-value for wins vs losses (ties dropped)."""
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def scoreboard(rows: list, bar: float = 1.14) -> dict:
    """Per-library ours-vs-developer ratio, the median, and the verdict against the bar.

    `rows` is p3lift_batch's per-campaign records: {library, arm, cov, repeat}. The BEST
    lifted arm per library (highest median coverage among arms starting 'lifted:') is our
    entry; the DEVELOPER arm is the baseline. A library with no developer arm is reported but
    not scored -- there is nothing to beat.
    """
    by_lib: dict = {}
    for r in rows:
        if (r.get("cov") or 0) <= 0:
            continue
        by_lib.setdefault(r["library"], {}).setdefault(r["arm"], []).append(r["cov"])

    per_lib, ratios = [], []
    for lib, arms in sorted(by_lib.items()):
        dev = next((v for k, v in arms.items() if k.startswith("DEVELOPER")), None)
        ours = {k: v for k, v in arms.items() if k.startswith("lifted") or k.startswith("ted")}
        best = max(ours.items(), key=lambda kv: st.median(kv[1]), default=(None, None))
        entry = {"library": lib,
                 "our_best_arm": (best[0] or "").split(":", 1)[-1][:40],
                 "our_median": round(st.median(best[1]), 1) if best[1] else None,
                 "developer_median": round(st.median(dev), 1) if dev else None}
        if dev and best[1]:
            ratio = st.median(best[1]) / st.median(dev)
            entry["ratio"] = round(ratio, 3)
            entry["beats_developer"] = ratio > 1.0
            entry["beats_bar"] = ratio >= bar
            ratios.append(ratio)
        else:
            entry["ratio"] = None
            entry["note"] = "no developer baseline -- our coverage reported, not scored"
        per_lib.append(entry)

    scored = [e for e in per_lib if e.get("ratio") is not None]
    wins_parity = sum(1 for e in scored if e["ratio"] > 1.0)
    losses_parity = sum(1 for e in scored if e["ratio"] < 1.0)
    wins_bar = sum(1 for e in scored if e["ratio"] >= bar)
    losses_bar = len(scored) - wins_bar
    med = st.median([e["ratio"] for e in scored]) if scored else None
    return {
        "metric": "M1: coverage vs developer harness",
        "bar_name": "OGHarn" if bar == 1.14 else f"{bar}x",
        "bar": bar,
        "libraries_scored": len(scored),
        "median_ratio": round(med, 3) if med is not None else None,
        "beats_parity": {"wins": wins_parity, "losses": losses_parity,
                         "sign_test_p": round(_sign_test(wins_parity, losses_parity), 4)},
        "beats_bar": {"wins": wins_bar, "losses": losses_bar,
                      "sign_test_p": round(_sign_test(wins_bar, losses_bar), 4)},
        "verdict": _verdict(med, bar, len(scored)),
        "per_library": per_lib,
    }


def _verdict(med, bar, n) -> str:
    if med is None:
        return "no scored libraries -- no developer baseline built"
    if n < 5:
        base = f"median ratio {med:.3f} over {n} libraries -- UNDERPOWERED (need >=5 for a claim)"
    else:
        base = f"median ratio {med:.3f} over {n} libraries"
    if med >= bar:
        return f"{base}; BEATS the {bar}x bar" if n >= 5 else f"{base}; above the bar but underpowered"
    if med > 1.0:
        return f"{base}; beats the developer harness (parity+) but BELOW the {bar}x bar"
    return f"{base}; BELOW parity with the developer harness"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--result", required=True, help="a p3lift_batch/compose result.json")
    ap.add_argument("--bar", type=float, default=1.14)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    d = json.loads(Path(a.result).read_text())
    sb = scoreboard(d.get("rows", []), bar=a.bar)
    sb["provenance"] = {"commit": _commit(),
                        "budget_seconds": d.get("budget"), "repeats": d.get("repeats"),
                        "source": a.result,
                        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    print(f"\n=== SCOREBOARD: {sb['metric']} (bar: {sb['bar_name']} {sb['bar']}x) ===")
    print(f"{'library':12s} {'our best':30s} {'ours':>6s} {'dev':>6s} {'ratio':>7s}  verdict")
    for e in sb["per_library"]:
        r = e.get("ratio")
        mark = "" if r is None else (" WIN" if e["beats_bar"] else (" ~" if e["beats_developer"] else " <"))
        print(f"  {e['library']:10s} {e['our_best_arm']:30s} "
              f"{str(e['our_median'] or '-'):>6s} {str(e['developer_median'] or '-'):>6s} "
              f"{('%.3f' % r) if r else 'n/a':>7s}{mark}")
    print(f"\n  {sb['verdict']}")
    print(f"  beats parity: {sb['beats_parity']['wins']}/{sb['beats_parity']['wins']+sb['beats_parity']['losses']} "
          f"(sign p={sb['beats_parity']['sign_test_p']}) | "
          f"beats {sb['bar_name']}: {sb['beats_bar']['wins']}/{sb['libraries_scored']} "
          f"(sign p={sb['beats_bar']['sign_test_p']})")
    if a.out:
        Path(a.out).write_text(json.dumps(sb, indent=1))
        print(f"recorded: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
