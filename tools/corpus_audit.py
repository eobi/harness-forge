#!/usr/bin/env python3
"""Grade a harvested corpus WITH the contract gates live.

The point of the harvest. Every previous audit at scale ran with S2 dark, because a lifted
harness carries call sites and S2 fires off declarations. 1,401 harnesses were graded that
way and S2 reported NOT RUN on every one -- which is not PASS. Each project here carries its
own headers, so the contract gates run against the library's real declarations.

WHAT IS COUNTED, and the distinction is the whole discipline:
  - a BLOCK on a HIGH-FIDELITY lift is a defect claim, and is counted;
  - a BLOCK on a low-fidelity lift is NOT, because the lifter did not read the whole harness
    and a violation may be an artifact of what it missed;
  - NOT RUN is reported separately from PASS, always.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hforge.cli import _attach_contracts, _contracts_from_headers   # noqa: E402
from hforge.gates.static_gates import BLOCK, WARN, run_static_gates  # noqa: E402
from hforge.lift.c_harness import LiftError                          # noqa: E402
from hforge.lift.c_harness import lift as lift_c_harness             # noqa: E402


def audit_project(pdir: Path, max_headers: int) -> dict:
    hdir, idir = pdir / "harness", pdir / "include"
    harnesses = sorted(hdir.glob("*")) if hdir.is_dir() else []
    if not harnesses:
        return {"project": pdir.name, "status": "no-harness"}
    headers = sorted(idir.glob("*.h"))[:max_headers] if idir.is_dir() else []
    contracts = _contracts_from_headers([str(h) for h in headers], [str(idir)])

    rec = {"project": pdir.name, "status": "ok", "harnesses": len(harnesses),
           "headers": len(headers), "declarations": len(contracts),
           "lifted": 0, "high_fidelity": 0, "contracts_attached": 0,
           "blocks_high_fidelity": 0, "blocks_low_fidelity": 0, "warns": 0,
           "codes": {}, "findings": []}
    for h in harnesses:
        try:
            lifted = lift_c_harness(str(h), target_name=pdir.name)
        except (LiftError, Exception):                              # noqa: BLE001
            continue
        if lifted is None:
            continue
        rec["lifted"] += 1
        rec["contracts_attached"] += _attach_contracts(lifted.ir, contracts)
        blocks, warns = [], []
        for g in run_static_gates(lifted.ir):
            for v in g.violations:
                (blocks if v.severity == BLOCK else
                 warns if v.severity == WARN else []).append(v)
        rec["warns"] += len(warns)
        if lifted.high_fidelity:
            rec["high_fidelity"] += 1
            rec["blocks_high_fidelity"] += len(blocks)
            for v in blocks:
                rec["codes"][v.code] = rec["codes"].get(v.code, 0) + 1
                rec["findings"].append({"harness": h.name, "code": v.code,
                                        "message": v.message[:220]})
        else:
            rec["blocks_low_fidelity"] += len(blocks)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default="/tmp/hf-corpus")
    ap.add_argument("--max-headers", type=int, default=60)
    ap.add_argument("--out", default="/tmp/hf-corpus/audit.json")
    a = ap.parse_args()

    projects = sorted(p for p in Path(a.corpus).iterdir()
                      if p.is_dir() and (p / "harness").is_dir())
    print(f"auditing {len(projects)} project(s) with contract gates live", flush=True)
    rows: list = []
    for p in projects:
        r = audit_project(p, a.max_headers)
        rows.append(r)
        if r.get("blocks_high_fidelity"):
            print(f"  {r['project'][:26]:28s} {r['blocks_high_fidelity']:3d} BLOCK "
                  f"({r['high_fidelity']}/{r['lifted']} high-fidelity, "
                  f"{r['declarations']} decls)", flush=True)

    codes = Counter()
    for r in rows:
        codes.update(r.get("codes", {}))
    summary = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "projects": len(rows),
        "harnesses": sum(r.get("harnesses", 0) for r in rows),
        "lifted": sum(r.get("lifted", 0) for r in rows),
        "high_fidelity": sum(r.get("high_fidelity", 0) for r in rows),
        "declarations": sum(r.get("declarations", 0) for r in rows),
        "contracts_attached": sum(r.get("contracts_attached", 0) for r in rows),
        "blocks_high_fidelity": sum(r.get("blocks_high_fidelity", 0) for r in rows),
        "blocks_low_fidelity_NOT_COUNTED":
            sum(r.get("blocks_low_fidelity", 0) for r in rows),
        "codes": dict(codes.most_common()), "rows": rows}
    Path(a.out).write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['harnesses']} harness(es) from {summary['projects']} project(s)")
    print(f"  lifted           : {summary['lifted']}")
    print(f"  high fidelity    : {summary['high_fidelity']}")
    print(f"  contracts attached: {summary['contracts_attached']} "
          f"(from {summary['declarations']} declarations)")
    print(f"  BLOCK (high-fid) : {summary['blocks_high_fidelity']}")
    print(f"  BLOCK (low-fid)  : {summary['blocks_low_fidelity_NOT_COUNTED']}  NOT COUNTED")
    for c, n in codes.most_common(10):
        print(f"      {c:28s} {n}")
    print(f"recorded: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
