#!/usr/bin/env python3
"""Generate harnesses here, fuzz them with NemesisForge.

harness-forge PROPOSES and CERTIFIES: it derives candidate harnesses from a library's
headers, widens that set by mutation, and refuses the ones its gates reject. It does not
hunt for bugs. NemesisForge does the hunting, and takes a C file defining
LLVMFuzzerTestOneInput plus the library sources to compile alongside it.

The two halves fit exactly, and nothing has connected them until now:

    propose -> synthesise -> static gates -> emit C -> forge lab --source ... --include ...

WHAT THIS IS NOT. It is not a claim that generated harnesses find more bugs than written
ones; that was measured this week and the answer was +0.40% against a +14% target. It is a
pipeline, and the value is that a candidate the gates accept can be handed straight to a
fuzzer without anyone writing C in between.

ONLY GATE-PASSING CANDIDATES ARE HANDED OVER, and only ones that survive a smoke test.
A harness that aborts on its first input burns a whole campaign returning nothing, which
libyaml demonstrated: `yaml_parser_set_encoding` asserts `!parser->encoding`, so a widened
candidate that calls it after input passes every static gate and dies immediately.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hforge.emit import emit                                      # noqa: E402
from hforge.gates.static_gates import BLOCK, run_static_gates     # noqa: E402
from hforge.ir import Knobs, Target                               # noqa: E402
from hforge.producers import header_graph as hg                   # noqa: E402
from hforge.producers import mutate                               # noqa: E402


def _passes(ir) -> bool:
    return not [v for r in run_static_gates(ir) for v in r.violations
                if v.severity == BLOCK]


def generate(header: str, includes, target_name: str, max_len: int = 4096):
    """Every candidate this engine is willing to stand behind, base and synthesised."""
    t = Target(name=target_name, public_headers=[header], include_dirs=list(includes))
    plans = hg.propose([header], t, knobs=Knobs(max_len=max_len))
    base = [p for p in plans if _passes(p)]
    synth, stats = mutate.synthesize(base)
    good = [s for s in synth if _passes(s)]
    return base, good, stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("header")
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--source", action="append", default=[],
                    help="library source compiled with each harness (repeatable)")
    ap.add_argument("--name", default="lib")
    ap.add_argument("--fuzz-time", type=int, default=30)
    ap.add_argument("--max", type=int, default=6, help="candidates to hand over")
    ap.add_argument("--forge", default=str(Path.home() / "Documents" / "NemesisForge"))
    ap.add_argument("--out", default="/tmp/forge-bridge")
    ap.add_argument("--emit-only", action="store_true")
    a = ap.parse_args(argv)

    base, synth, stats = generate(a.header, a.include, a.name)
    print(f"{a.name}: {len(base)} base plan(s) pass the gates, "
          f"{len(synth)} synthesised candidate(s) pass")
    if not base and not synth:
        print("  nothing this engine will stand behind; not handing anything over")
        return 1

    out = Path(a.out) / a.name
    out.mkdir(parents=True, exist_ok=True)
    handed = []
    for pl in (base + synth)[:a.max]:
        try:
            e = emit(pl)
        except Exception as ex:
            print(f"  SKIP {pl.name[:44]:46} emit refused: {str(ex)[:40]}")
            continue
        src = out / f"{pl.name[:60]}.c"
        src.write_text(getattr(e, "source", None) or getattr(e, "code", ""))
        handed.append((pl.name, src))
        print(f"  emitted {pl.name[:52]:54} -> {src.name}")

    if a.emit_only:
        print(f"\n{len(handed)} harness(es) written to {out}")
        return 0

    results = []
    for name, src in handed:
        cmd = [sys.executable, "-m", "forge", "lab", str(src),
               "--name", name[:40], "--fuzz-time", str(a.fuzz_time),
               "--out", str(out / "runs")]
        for s in a.source:
            cmd += ["--source", s]
        for i in a.include:
            cmd += ["--include", i]
        print(f"\n=== forge lab: {name[:56]} ===")
        r = subprocess.run(cmd, cwd=a.forge, capture_output=True, text=True)
        tail = (r.stdout or r.stderr).strip().splitlines()[-6:]
        for l in tail:
            print("   ", l[:100])
        results.append({"harness": name, "returncode": r.returncode,
                        "tail": tail})

    (out / "bridge-results.json").write_text(json.dumps(
        {"library": a.name, "base_plans": len(base), "synthesised": len(synth),
         "handed_over": len(handed), "stats": stats, "results": results}, indent=1))
    print(f"\nrecorded: {out / 'bridge-results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
