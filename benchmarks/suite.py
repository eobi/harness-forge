"""Suite coverage: what the WHOLE set of harnesses reaches, not the best single one.

Every published system is measured one harness per entry point, and so is our benchmark.
That is not how a library gets covered. `yajl_gen.c` and `yajl_tree.c` are 485 lines that no
`yajl_parse` harness can reach — gold's included — and our producer proposes 30 gate-passing
plans across 15 distinct entry points for the same library.

This measures the union: build every shipped harness, fuzz each briefly, merge the profiles,
and report coverage of the library as a whole. It is the number that predicts finding a bug,
because a bug lives wherever it lives.
"""
import glob, json, os, pathlib, subprocess, sys
sys.path.insert(0, "/hf")
from hforge.emit import emit
from hforge.emit.c_libfuzzer import EmitError
from hforge.gates.result import BLOCK
from hforge.gates.static_gates import run_static_gates
from hforge.ir import Knobs, Target
from hforge.producers import header_graph as hg

sys.path.insert(0, "/b")
from drive import CASES


def main():
    key = sys.argv[1]                       # a project name present in CASES
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    case = next(c for k, c in CASES.items() if k.split("/")[0] == key)

    t = Target(name=key, public_headers=[case["hdr"]] + list(case.get("also", [])),
               include_dirs=case["inc"], sources=case["src"], cflags=case["cflags"])
    plans = hg.propose(t.public_headers, t, platforms=["linux-aarch64-glibc"],
                       knobs=Knobs(max_len=4096))
    ok = [p for p in plans
          if not {v.code for r in run_static_gates(p) for v in r.violations
                  if v.severity == BLOCK}]
    # One harness per ENTRY POINT: variants of the same call add little to a union.
    by_entry = {}
    for p in ok:
        e = next((o.api for o in p.sequence if o.id.startswith("o_consume")), p.name)
        by_entry.setdefault(e, p)
    chosen = list(by_entry.values())[:cap]

    wd = pathlib.Path(f"/b/suite/{key}"); wd.mkdir(parents=True, exist_ok=True)
    profs, built, failed = [], 0, 0
    for i, p in enumerate(chosen):
        d = wd / f"h{i}"; d.mkdir(exist_ok=True)
        try:
            e = emit(p)
        except EmitError:
            failed += 1; continue
        (d/"harness.c").write_text(e.source)
        cmd = ["clang", "-g", "-O1", "-fno-omit-frame-pointer",
               "-fprofile-instr-generate", "-fcoverage-mapping"]
        cmd += [f"-I{x}" for x in case["inc"]] + case["cflags"]
        cmd += ["-fsanitize=fuzzer,address", str(d/"harness.c")] + case["src"]
        cmd += ["-o", str(d/"fuzz")]
        if subprocess.run(cmd, capture_output=True, text=True).returncode != 0:
            failed += 1; continue
        built += 1
        corp = d/"corpus"; corp.mkdir(exist_ok=True)
        if case.get("seeds"):
            from hforge.analysis import seeds as seedmod
            seedmod.write(seedmod.mine(case["seeds"], max_bytes=4096), corp)
        prof = d/"p.profraw"
        subprocess.run([str(d/"fuzz"), str(corp), f"-max_total_time={per}",
                        "-max_len=4096"], capture_output=True, text=True,
                       env=dict(os.environ, LLVM_PROFILE_FILE=str(prof)),
                       timeout=per+180)
        if prof.exists():
            profs.append(str(prof))

    merged = wd/"suite.profdata"
    subprocess.run(["llvm-profdata-14", "merge", "-sparse", *profs, "-o", str(merged)],
                   capture_output=True)
    # Report against the FIRST binary; the profile is the union across all of them.
    rep = subprocess.run(["llvm-cov-14", "report", str(wd/"h0"/"fuzz"),
                          f"-instr-profile={merged}"] + case["cover"],
                         capture_output=True, text=True)
    tot = [l for l in rep.stdout.splitlines() if l.startswith("TOTAL")]
    out = {"project": key, "entry_points": len(by_entry), "harnesses_built": built,
           "harnesses_failed": failed, "seconds_each": per}
    if tot:
        f = tot[0].split()
        out.update(regions_pct=f[3].rstrip('%'), functions_pct=f[6].rstrip('%'),
                   lines_pct=f[9].rstrip('%'), branches_pct=f[12].rstrip('%'))
    print(json.dumps(out))


main()
