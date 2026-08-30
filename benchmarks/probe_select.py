"""Is the static tie-break costing us coverage?

OGHarn selects harnesses by MEASURED coverage and beats developer-written harnesses by a
median 14%. This suite selects by static evidence and, when nothing distinguishes two plans,
sorts by name -- `hforge propose` admits it: "UNRANKED. N plan(s) are shippable and NO GATE
DISTINGUISHES THEM. The order above is alphabetical, which is a tie-break, not a
measurement."

Before replacing that with a probe, find out what it costs. For one case: propose, keep the
plans that pass the static gates, build and briefly campaign EVERY one, and compare the plan
the current rule picks against the best available.

    docker run --rm -v "$PWD:/hf:ro" -v /tmp/hf-bench:/b hforge-linuxbench \\
        python3 /hf/benchmarks/probe_select.py libyaml/libyaml_loader_fuzzer 45
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, "/hf")
sys.path.insert(0, "/hf/benchmarks")

from drive import CASES                                            # noqa: E402
from hforge.emit import emit                                       # noqa: E402
from hforge.emit.c_libfuzzer import EmitError                      # noqa: E402
from hforge.gates.result import BLOCK                              # noqa: E402
from hforge.gates.static_gates import run_static_gates             # noqa: E402
from hforge.ir import Knobs, Target                                # noqa: E402
from hforge.producers import header_graph as hg                    # noqa: E402
from hforge.toolchain import check_emitted_c                       # noqa: E402


def rank_key(pl, fn):
    """The driver's current rule, replicated so the comparison is against what ships."""
    op = next((o for o in pl.sequence if o.api == fn), None)
    driven = 1 if op and any(a.source == "input" for a in op.args) else 0
    # THE TARGET MUST BE THE o_consume OP, not merely present in the sequence. Approximating
    # this by position ("is it early in the plan?") re-created the exact defect drive.py
    # documents: it selects a plan whose consumer is yaml_parser_set_input -- a callback
    # bound to NULL -- with the real target demoted to setup, and that harness scores 0.00%.
    # My first version of this probe did precisely that and then reported the resulting
    # 70-point difference as the cost of the tie-break. It was the cost of my own bug.
    is_entry = 1 if any(o.id.startswith("o_consume") and o.api == fn
                        for o in pl.sequence) else 0
    plain = 0 if ("_setup" not in pl.name and "_with_" not in pl.name) else 1
    return (-is_entry, -driven, plain, -len(pl.sequence), len(pl.name))


def probe(plan, c, cc, work, seconds, mlen):
    work.mkdir(parents=True, exist_ok=True)
    try:
        e = emit(plan)
    except EmitError as ex:
        return None, f"emit refused: {str(ex)[:40]}"
    (work / "harness.c").write_text(e.source)
    if check_emitted_c(cc[0], work / "harness.c", c["inc"], c["cflags"],
                       is_cxx=bool(c.get("cxx"))):
        return None, "emitter defect"
    binp = work / "fuzz"
    cmd = cc + ["-g", "-O1", "-fno-omit-frame-pointer",
                "-fprofile-instr-generate", "-fcoverage-mapping"]
    cmd += [f"-I{i}" for i in c["inc"]] + c["cflags"]
    cmd += ["-fsanitize=fuzzer,address", str(work / "harness.c")] + c["src"] + ["-o", str(binp)]
    if subprocess.run(cmd, capture_output=True, text=True).returncode != 0:
        return None, "build failed"
    corp = work / "corpus"
    corp.mkdir(exist_ok=True)
    n = 0
    for d in c.get("seeds", []):
        p = pathlib.Path(d)
        if not p.is_dir():
            continue
        for s in sorted(p.rglob("*")):
            if s.is_file() and s.stat().st_size <= mlen and n < 200:
                (corp / f"s{n}").write_bytes(s.read_bytes()); n += 1
    env = dict(os.environ, LLVM_PROFILE_FILE=str(work / "run.profraw"))
    try:
        subprocess.run([str(binp), str(corp), f"-max_total_time={seconds}",
                        f"-max_len={mlen}", "-print_final_stats=1"],
                       capture_output=True, text=True, env=env, timeout=seconds + 240)
    except subprocess.TimeoutExpired:
        return None, "campaign timeout"
    if subprocess.run(["llvm-profdata-14", "merge", "-sparse", str(work / "run.profraw"),
                       "-o", str(work / "run.profdata")],
                      capture_output=True, text=True).returncode != 0:
        return None, "no profile"
    r = subprocess.run(["llvm-cov-14", "report", str(binp),
                        f"-instr-profile={work}/run.profdata"] + c["cover"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("TOTAL"):
            return float(line.split()[9].rstrip("%")), "ok"
    return None, "no TOTAL row"


def main() -> int:
    case = sys.argv[1]
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 45
    c = CASES[case]
    mlen = c.get("max_len", 4096)
    t = Target(name=case.split("/")[0],
               public_headers=[c["hdr"]] + list(c.get("also", [])),
               include_dirs=c["inc"], sources=c["src"], cflags=c["cflags"])
    plans = hg.propose(t.public_headers, t, platforms=["linux-aarch64-glibc"],
                       knobs=Knobs(max_len=mlen))
    cands = [p for p in plans if any(o.api == c["fn"] for o in p.sequence)]
    ok = [p for p in cands
          if not [v for r in run_static_gates(p) for v in r.violations if v.severity == BLOCK]]
    print(f"{case}: {len(plans)} proposed, {len(cands)} name the target, "
          f"{len(ok)} pass the static gates")
    if len(ok) < 2:
        print("  only one candidate survives; the tie-break never fires here")
        return 0
    ranked = sorted(ok, key=lambda x: rank_key(x, c["fn"]))
    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]
    base = pathlib.Path("/b/probe") / case.replace("/", "__")
    rows = []
    for i, pl in enumerate(ranked):
        cov, note = probe(pl, c, cc, base / f"c{i:02d}", seconds, mlen)
        rows.append((pl.name, cov, note))
        print(f"  {'PICKED ' if i == 0 else '       '}{pl.name[:44]:46} "
              f"{(f'{cov:.2f}%' if cov is not None else note):>12}")
    scored = [(n, v) for n, v, _ in rows if v is not None]
    if len(scored) >= 2:
        picked = next((v for n, v, _ in rows if n == ranked[0].name and v is not None), None)
        best_name, best = max(scored, key=lambda x: x[1])
        print(f"\n  static pick : {ranked[0].name[:44]} = "
              f"{f'{picked:.2f}%' if picked is not None else 'unmeasured'}")
        print(f"  best by cov : {best_name[:44]} = {best:.2f}%")
        if picked is not None:
            gap = best - picked
            print(f"  COST OF THE TIE-BREAK: {gap:+.2f} points"
                  + ("  (the static rule already picks the best)" if gap <= 0.005 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
