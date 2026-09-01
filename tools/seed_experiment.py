#!/usr/bin/env python3
"""Does mining the library's own repository for seeds change coverage?

CONTROLLED ON PURPOSE. The SAME BINARY runs both arms, back to back, with the same time
budget. The only difference is what is in the corpus directory: empty, or the mined seeds.
Building twice, or comparing across harnesses, would measure the build and the harness.

NO NemesisForge IN THIS EXPERIMENT. The oracle, the triage and the dictionary are all
irrelevant to the question and each is a way for the two arms to differ. clang and libFuzzer
directly is fewer moving parts, and this is a measurement, not a pipeline.

Coverage is libFuzzer's own `cov:` counter, which is edges covered in THIS binary. It is not
comparable across harnesses and no total is reported over them -- the comparison is PAIRED,
each harness against itself.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import statistics as st
import subprocess
import sys
import time
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from compile_rate import _incdirs                                  # noqa: E402
from libspec import DEFINES, SEED_FORMATS, _sources_for            # noqa: E402
from seed_mine import install, mine                                # noqa: E402

_COV = re.compile(r"\bcov:\s*(\d+)")
_EXECS = re.compile(r"number_of_executed_units:\s*(\d+)")


def build(h: Path, lib: str, work: Path, out: Path, cc: str) -> Path | None:
    out.mkdir(parents=True, exist_ok=True)
    binp = out / "h.bin"
    argv = [cc, "-fsanitize=fuzzer,address", "-g", "-O1", "-w",
            *[f"-D{d}" for d in (DEFINES.get(lib) or [])],
            *_incdirs(work / lib), str(h),
            *_sources_for(lib, work), "-o", str(binp)]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    return binp if p.returncode == 0 else None


def campaign(binp: Path, corpus: Path, budget: int) -> tuple:
    """Return (cov, execs). libFuzzer prints both; -1 if it did not run."""
    corpus.mkdir(parents=True, exist_ok=True)
    p = subprocess.run([str(binp), f"-max_total_time={budget}", "-print_final_stats=1",
                        str(corpus)], capture_output=True, text=True,
                       timeout=budget + 120)
    txt = (p.stdout or "") + (p.stderr or "")
    cov = [int(m) for m in _COV.findall(txt)]
    ex = _EXECS.search(txt)
    return (max(cov) if cov else -1, int(ex.group(1)) if ex else -1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--harnesses", default="/tmp/hf-harnesses")
    ap.add_argument("--libs", default="cjson,jansson,zlib,libyaml")
    ap.add_argument("--per-lib", type=int, default=4)
    ap.add_argument("--budget", type=int, default=30)
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--out", default="/tmp/seed-exp.json")
    a = ap.parse_args()

    work = Path(a.work)
    rows: list = []
    for lib in [x for x in a.libs.split(",") if x]:
        hdir = Path(a.harnesses) / lib / lib
        if not hdir.is_dir():
            continue
        seed_src = Path(f"/tmp/seedsrc-{lib}")
        shutil.rmtree(seed_src, ignore_errors=True)
        chosen, rep = mine(work / lib, formats=SEED_FORMATS.get(lib, ()), max_files=200)
        n_seeds = install(chosen, seed_src)
        print(f"{lib}: mined {n_seeds} seed(s)", flush=True)
        for h in sorted(hdir.glob("*.c"))[:a.per_lib]:
            wd = Path(f"/tmp/seedexp/{lib}/{h.stem[:32]}")
            shutil.rmtree(wd, ignore_errors=True)
            binp = build(h, lib, work, wd, a.cc)
            if binp is None:
                print(f"  {h.stem[:44]:46s} BUILD FAILED", flush=True)
                continue
            # Alternate which arm runs first across harnesses, so any warm-up or thermal
            # drift does not land on the same arm every time.
            first_seeded = len(rows) % 2 == 1
            res = {}
            for seeded in ([True, False] if first_seeded else [False, True]):
                cdir = wd / ("corpus_seeded" if seeded else "corpus_empty")
                cdir.mkdir(parents=True, exist_ok=True)
                if seeded:
                    install(chosen, cdir)
                cov, ex = campaign(binp, cdir, a.budget)
                res["seeded" if seeded else "empty"] = {"cov": cov, "execs": ex}
            row = {"library": lib, "harness": h.name, "seeds": n_seeds,
                   "empty": res["empty"], "seeded": res["seeded"],
                   "first_arm": "seeded" if first_seeded else "empty"}
            rows.append(row)
            e, s = res["empty"]["cov"], res["seeded"]["cov"]
            delta = (100.0 * (s - e) / e) if e > 0 else float("nan")
            print(f"  {h.stem[:44]:46s} empty cov={e:<6} seeded cov={s:<6} "
                  f"{delta:+.1f}%", flush=True)

    ok = [r for r in rows if r["empty"]["cov"] > 0 and r["seeded"]["cov"] > 0]
    summary = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "budget_seconds": a.budget, "pairs": len(ok), "rows": rows}
    if ok:
        ratios = [r["seeded"]["cov"] / r["empty"]["cov"] for r in ok]
        wins = sum(1 for x in ratios if x > 1.0)
        ties = sum(1 for x in ratios if x == 1.0)
        summary["median_ratio"] = round(st.median(ratios), 4)
        summary["median_gain_pct"] = round(100.0 * (st.median(ratios) - 1.0), 2)
        summary["seeded_better"] = wins
        summary["tied"] = ties
        summary["seeded_worse"] = len(ratios) - wins - ties
        # SIGN TEST, not Mann-Whitney: the arms are PAIRED (same binary), so the right
        # question is how often seeding wins, not whether two independent samples differ.
        n = wins + (len(ratios) - wins - ties)
        if n:
            from math import comb
            tail = sum(comb(n, k) for k in range(wins, n + 1)) / (2 ** n)
            summary["sign_test_p_one_sided"] = round(min(1.0, 2 * tail if wins > n / 2 else 1.0), 4)
        print(f"\npaired on {len(ok)} harness(es), {a.budget}s per arm")
        print(f"  seeded better {wins}, tied {ties}, worse {len(ratios)-wins-ties}")
        print(f"  median ratio {summary['median_ratio']} "
              f"({summary['median_gain_pct']:+.2f}%)")
    Path(a.out).write_text(json.dumps(summary, indent=1))
    print(f"recorded: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
