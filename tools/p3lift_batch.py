#!/usr/bin/env python3
"""Lift a library's tests into harnesses, and measure them against its DEVELOPER harness.

The comparison that decides the coverage axis. OGHarn reports +14% median over
developer-written harnesses; our generated plans sit at parity and mutational synthesis added
+0.40%. A single lifted test beat our best generated plan on jansson by 9.50x, from n=1 -- so
the question now is whether it beats the harness a human wrote.

PAIRED AND REPEATED. Every arm builds with the same flags, runs the same seed corpus for the
same budget, and the arms alternate order across repeats so drift cannot land on one of them.
Coverage is libFuzzer's own `cov:` counter, which is edges in THAT binary -- so it is only
ever compared within a library, never summed across them.

A CANDIDATE THAT ABORTS ON A VALID INPUT IS KILLED BEFORE IT COSTS A CAMPAIGN. libyaml's
synthesis run lost all 8 top-ranked candidates that way, and each had a full campaign spent
on it first.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics as st
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from hforge.emit import emit                                        # noqa: E402
from hforge.gates.static_gates import BLOCK, run_static_gates       # noqa: E402
from hforge.producers.header_graph import parse_header              # noqa: E402
from hforge.producers.test_lift import inline_api, propose          # noqa: E402
from libspec import (DEFINES, SEED_FORMATS, _include_dirs,          # noqa: E402
                     _sources_for)
from seam_finder import seams_for                                   # noqa: E402
from test_sequences import sequences_in                             # noqa: E402

CC = "/opt/homebrew/opt/llvm/bin/clang"

# DEEP SUBSYSTEMS: the kinds of work that reach a lot of code behind one call.
#
# Measured, not assumed. Ranking candidates by the COUNT of distinct APIs was refuted at
# 0.09x of the developer harness -- five comparison functions touch almost nothing while one
# json_loads reaches the whole parser. Ranking by how many of these SUBSYSTEMS a sequence
# enters took the same technique from 0.67x to 0.88x, because the developer harness wins by
# loading AND dumping rather than by calling many functions.
#
# Name-based, and therefore a prior: it is expected to be confirmed or overturned by
# campaigning, in the same way probe_select ranks statically and coverage decides.
_SUBSYSTEMS = {
    "parse":     re.compile(r"(?:^|_)(load|loads|loadb|parse|read|decode|scan|deserial|"
                            r"unmarshal|from_)", re.I),
    "serialise": re.compile(r"(?:^|_)(dump|dumps|dumpb|write|encode|serial|marshal|print|"
                            r"emit|to_|save)", re.I),
    "transform": re.compile(r"(?:^|_)(compress|decompress|inflate|deflate|convert|transform|"
                            r"resize|scale|rotate)", re.I),
    "validate":  re.compile(r"(?:^|_)(verify|validate|check|equal|compare)", re.I),
}


def subsystems(apis) -> set:
    """Which deep subsystems this sequence enters."""
    out = set()
    for a in apis:
        for name, pat in _SUBSYSTEMS.items():
            if pat.search(a):
                out.add(name)
    return out
_COV = re.compile(r"\bcov:\s*(\d+)")
_EXECS = re.compile(r"number_of_executed_units:\s*(\d+)")

# library -> (public header relative to the checkout, seed corpus glob, dev harness glob)
LIBS = {
    "jansson":  ("src/jansson.h", "test/suites/**/*.json", "**/*fuzzer*.c*"),
    "cjson":    ("cJSON.h", "tests/inputs/*", "fuzzing/*fuzzer*.c*"),
    "expat":    ("expat/lib/expat.h", "expat/tests/**/*.xml", "**/*fuzzer*.c*"),
    "zstd":     ("lib/zstd.h", "tests/**/*.zst", "**/*fuzzer*.c*"),
    "libwebp":  ("src/webp/decode.h", "tests/**/*.webp", "**/*fuzzer*.c*"),
    "libpng":   ("png.h", "contrib/pngsuite/*.png", "**/*fuzzer*.c*"),
}


def build(cfile: Path, lib: str, work: Path, out: Path) -> bool:
    """Compile the harness in ITS language and the library in C, then link.

    A C++ developer harness has to be compiled as C++, but passing -x c++ to the whole
    command compiles the LIBRARY as C++ too -- and C code is not valid C++. jansson's own
    json_load_dump_fuzzer.cc failed on `cannot initialize 'struct key_len *' with an lvalue
    of type 'const void *'`, an implicit conversion C allows and C++ forbids. Reported as
    "the developer harness did not build", which would have removed the ONLY baseline that
    makes this comparison mean anything.
    """
    cxx = cfile.suffix in (".cc", ".cpp", ".cxx")
    common = ["-fsanitize=fuzzer,address", "-g", "-O1", "-w",
              *[f"-D{d}" for d in (DEFINES.get(lib) or [])],
              *[f"-I{i}" for i in _include_dirs(lib, work)]]
    objdir = out.parent / (out.stem + "_obj")
    objdir.mkdir(parents=True, exist_ok=True)
    objs: list = []
    for i, src in enumerate(_sources_for(lib, work)):
        o = objdir / f"{i:03d}.o"
        if not o.exists():
            r = subprocess.run([CC, "-c", *common, src, "-o", str(o)],
                               capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                return False
        objs.append(str(o))
    ho = objdir / "harness.o"
    hargs = [CC, "-c", *common]
    if cxx:
        hargs += ["-x", "c++", "-std=c++17"]
    r = subprocess.run([*hargs, str(cfile), "-o", str(ho)],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        return False
    link = [CC, "-fsanitize=fuzzer,address", str(ho), *objs, "-o", str(out)]
    if cxx:
        link += ["-lc++"]
    return subprocess.run(link, capture_output=True, text=True,
                          timeout=600).returncode == 0


def campaign(binp: Path, corpus: Path, budget: int) -> tuple:
    try:
        p = subprocess.run([str(binp), f"-max_total_time={budget}",
                            "-print_final_stats=1", str(corpus)],
                           capture_output=True, text=True, timeout=budget + 180)
    except subprocess.TimeoutExpired:
        return (-1, -1)
    t = (p.stdout or "") + (p.stderr or "")
    cov = [int(x) for x in _COV.findall(t)]
    ex = _EXECS.search(t)
    return (max(cov) if cov else -1, int(ex.group(1)) if ex else -1)


def smoke(binp: Path, corpus: Path) -> bool:
    """Does it survive a handful of VALID inputs? A candidate that aborts is not a harness."""
    p = subprocess.run([str(binp), "-runs=64", str(corpus)],
                       capture_output=True, text=True, timeout=180)
    return p.returncode == 0


def lifted_candidates(lib: str, work: Path, out: Path, top: int) -> list:
    hdr = work / lib / LIBS[lib][0]
    incs = tuple(_include_dirs(lib, work))
    decls = {d.name: d for d in parse_header(str(hdr), incs, ())}
    extra = inline_api([str(hdr)])
    api = set(decls) | set(extra)

    seams: list = []
    for d in ("test", "tests", "testbed", "check"):
        base = work / lib / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*.c"))[:200]:
            try:
                src = f.read_text(errors="replace")
            except OSError:
                continue
            for s in sequences_in(f, api):
                seams.extend(seams_for(f, s["function"], decls, src))
    seams.sort(key=lambda s: (not s["parse_like"], -s["depth"]))

    # RANK BY BREADTH, NOT ONLY BY SEAM QUALITY.
    #
    # Ranking on the seam alone picked jansson's json_loads tests, which reached 0.68x the
    # developer harness. That harness loads AND dumps -- it exercises both directions, while
    # a test chosen for its seam does one thing well. Breadth is the number of DISTINCT
    # library APIs the lifted sequence keeps, and it is only knowable after proposing, so
    # every viable candidate is built first and ranked afterwards.
    #
    # A seam is still required: breadth with no seam is a harness the fuzzer does not drive.
    built, seen = [], set()
    for s in seams:
        key = (s["file"], s["function"], s["api"], s["param_index"])
        if key in seen:
            continue
        seen.add(key)
        src_file = next((q for q in (work / lib).rglob(s["file"])), None)
        if src_file is None:
            continue
        plan, rec = propose(str(src_file), s["function"], decls, seam=s,
                            target_name=lib, headers=[Path(LIBS[lib][0]).name],
                            also_api=extra)
        if plan is None:
            continue
        blocks = [v for g in run_static_gates(plan) for v in g.violations
                  if v.severity == BLOCK]
        if blocks:
            rec["status"] = "gated"
            rec["blocked_by"] = [b.code for b in blocks[:3]]
            continue
        names = {o.api for o in plan.sequence}
        breadth = len(names)
        subs = subsystems(names)
        # A candidate that never enters a deep subsystem is not worth a campaign slot: it is
        # the 0.09x shape, calling several shallow functions well.
        deep = subs - {"validate"}
        built.append({"plan": plan, "record": rec, "seam": s, "breadth": breadth,
                      "subsystems": sorted(subs), "deep": len(deep)})
        if len(built) >= top * 6:          # a pool to rank, not the final selection
            break

    # DEEP SUBSYSTEM COUNT FIRST, then the seam, then breadth as a last tie-break.
    built.sort(key=lambda c: (-c["deep"], not c["seam"]["parse_like"],
                              -c["seam"]["depth"], -c["breadth"]))
    made: list = []
    for c in built:
        try:
            csrc = emit(c["plan"]).source
        except Exception as ex:                                     # noqa: BLE001
            c["record"]["status"] = f"emit-refused: {str(ex)[:60]}"
            continue
        cf = out / (f"{lib}_d{c['deep']}_{c['seam']['function'][:24]}"
                    f"_{c['seam']['api'][:18]}.c")
        cf.write_text(csrc)
        c["record"]["breadth"] = c["breadth"]
        c["record"]["subsystems"] = c["subsystems"]
        c["record"]["deep_subsystems"] = c["deep"]
        made.append({"file": cf, "record": c["record"], "seam": c["seam"],
                     "breadth": c["breadth"], "deep": c["deep"],
                     "subsystems": c["subsystems"]})
        if len(made) >= top:
            break
    return made


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--libs", default="jansson,cjson,expat")
    ap.add_argument("--top", type=int, default=4)
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="/tmp/p3batch")
    a = ap.parse_args()

    work = Path(a.work)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    rows: list = []
    for lib in [x for x in a.libs.split(",") if x in LIBS]:
        ldir = out / lib; ldir.mkdir(parents=True, exist_ok=True)
        corpus = ldir / "corpus"; corpus.mkdir(exist_ok=True)
        # THE MINER, not a hand-written glob. `test/suites/**/*.json` matched nothing in
        # jansson and the first run campaigned on an EMPTY corpus -- which for a binary
        # format is a 26x error, and for any format is not the experiment intended.
        from seed_mine import install, mine                          # noqa: PLC0415
        chosen, _rep = mine(work / lib, formats=SEED_FORMATS.get(lib, ()), max_files=120)
        n = install(chosen, corpus)
        print(f"\n{lib}: {n} seed(s) mined", flush=True)

        cands = lifted_candidates(lib, work, ldir, a.top)
        print(f"  {len(cands)} lifted candidate(s) passed the gates", flush=True)
        for c in cands:
            print(f"      deep={c['deep']} {','.join(c['subsystems']) or '-':24s} "
                  f"{c['file'].stem[:46]}", flush=True)

        dev = next((q for q in sorted((work / lib).glob(LIBS[lib][2]))
                    if "main" not in q.name), None)
        arms: list = []
        for c in cands:
            b = ldir / (c["file"].stem + ".bin")
            if build(c["file"], lib, work, b) and smoke(b, corpus):
                arms.append(("lifted:" + c["file"].stem[:34], b))
            else:
                print(f"    killed (build or smoke): {c['file'].stem[:40]}", flush=True)
        if dev is not None:
            b = ldir / "developer.bin"
            if build(dev, lib, work, b):
                arms.append(("DEVELOPER:" + dev.name, b))
            else:
                print(f"    developer harness did not build: {dev.name}", flush=True)

        for k in range(a.repeats):
            order = arms if k % 2 == 0 else list(reversed(arms))
            for name, b in order:
                cov, ex = campaign(b, corpus, a.budget)
                rows.append({"library": lib, "arm": name, "repeat": k,
                             "cov": cov, "execs": ex})
                print(f"    r{k} {name[:44]:46s} cov={cov:<6} execs={ex:,}", flush=True)

    res = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "budget_seconds": a.budget, "repeats": a.repeats, "rows": rows}
    Path(a.out + "/result.json").write_text(json.dumps(res, indent=1))
    print("\n=== median coverage per arm ===")
    for lib in {r["library"] for r in rows}:
        per: dict = {}
        for r in rows:
            if r["library"] == lib and r["cov"] > 0:
                per.setdefault(r["arm"], []).append(r["cov"])
        dev_med = next((st.median(v) for k, v in per.items() if k.startswith("DEVELOPER")), 0)
        for k, v in sorted(per.items(), key=lambda kv: -st.median(kv[1])):
            ratio = f"{st.median(v)/dev_med:.2f}x dev" if dev_med else "no dev baseline"
            print(f"  {lib:9s} {k[:44]:46s} median {st.median(v):<7.0f} {ratio}")
    print(f"recorded: {a.out}/result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
