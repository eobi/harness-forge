#!/usr/bin/env python3
"""Point the gate bank at a corpus of third-party harnesses and report what it says.

    python3 tools/fleet_audit.py ~/oss-fuzz/projects            # audit a tree
    python3 tools/fleet_audit.py ~/oss-fuzz/projects -o out.json

WHY THIS IS A TOOL AND NOT A SCRIPT SOMEBODY RAN ONCE. Every figure in
benchmarks/audits/ came from a throwaway file in /tmp, which would have vanished with the
session that produced it -- the same failure as the benchmark image that existed only on
one machine and made every published number unreproducible. An audit nobody else can re-run
is an anecdote.

IT ASKS THE LIFTER DIRECTLY rather than parsing CLI output. The first version of this
detected fidelity by grepping the audit command's text for a phrase; changing that phrase
then made 130 harnesses appear to become trustworthy and the flags appear to vanish, a
result manufactured entirely by the measuring script. Read the objects, not the report.

WHAT THE NUMBERS MEAN, because two of them are easy to over-read:

  lifted          the entry point was found and produced a plan
  high-fidelity   the lifter believes it read the harness -- no call it could not see, no
                  use of the input it could not follow. ONLY these can support a finding.
  flagged         a blocking violation on a high-fidelity lift: a CANDIDATE, never a
                  finding. Every candidate this has ever produced was a false positive
                  traced to the lifter, so read the harness before believing it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def audit(root: Path, patterns=("*/*fuzz*.c", "*/*fuzz*.cc")) -> list:
    from hforge.lift import c_harness
    from hforge.gates.static_gates import run_static_gates

    files: list = []
    for pat in patterns:
        files += list(root.glob(pat))
    out = []
    for i, f in enumerate(sorted(files)):
        rec = {"file": str(f.relative_to(root))}
        try:
            lifted = c_harness.lift(str(f))
        except Exception as e:                                    # noqa: BLE001
            rec.update(lifted=False, why=type(e).__name__)
            out.append(rec)
            continue
        blocks = sorted({v.code for g in run_static_gates(lifted.ir)
                         for v in g.violations if v.severity == "block"})
        rec.update(lifted=True, high_fidelity=bool(lifted.high_fidelity),
                   missed=lifted.missed[:3], unread=len(lifted.unread), blocks=blocks)
        out.append(rec)
        if i and i % 100 == 0:
            print(f"  {i}/{len(files)}", file=sys.stderr, flush=True)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="a directory of third-party harnesses")
    ap.add_argument("-o", "--out", help="write the full per-harness records here")
    a = ap.parse_args(argv)

    recs = audit(Path(a.root).expanduser())
    lifted = [r for r in recs if r.get("lifted")]
    hi = [r for r in lifted if r.get("high_fidelity")]
    flagged = [r for r in hi if r["blocks"]]

    print(f"harnesses      {len(recs)}")
    print(f"  lifted       {len(lifted)}")
    print(f"  high-fidelity{len(hi):>5}   ({100 * len(hi) / max(1, len(recs)):.0f}%)")
    print(f"  flagged      {len(flagged):>5}   candidates, not findings")
    for r in flagged:
        print(f"     {r['file']}  {','.join(r['blocks'])}")
    if a.out:
        Path(a.out).write_text(json.dumps(recs, indent=1) + "\n")
        print(f"\nper-harness records written to {a.out}")
    if flagged:
        print("\nEvery candidate this tool has produced so far has been a FALSE POSITIVE "
              "traced to the lifter.\nRead the harness before reporting anything upstream.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
