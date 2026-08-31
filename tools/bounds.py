#!/usr/bin/env python3
"""What a corpus of harnesses CANNOT find, read from how they are built.

A campaign that reports nothing is ambiguous: the library may be clean, or the harness may
never have been able to see the defect. Coverage does not settle it, because a harness can
execute a function thoroughly with the detector for its whole bug class switched off.

This reads the OSS-Fuzz build configuration and reports, per target, bug classes that are
DISABLED rather than unexercised. It is deliberately narrow: every signal here is a literal
setting in a build file, not an inference. A bound nobody can check is worth nothing.

Motivated by a real finding. bluez/fuzz_gobex leaks a GError on every failed decode
(google/oss-fuzz#16081), and `projects/bluez/build.sh` sets detect_leaks=0 for that target
and no other -- so the workaround for a harness defect had removed leak detection from the
library's coverage entirely. The question this tool asks is how often that happens.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Each entry: (name, pattern, what the target consequently cannot find).
SIGNALS = [
    ("leaks_disabled", re.compile(r"detect_leaks\s*=\s*0"),
     "memory leaks in the library: LeakSanitizer is off for this target"),
    ("odr_disabled", re.compile(r"detect_odr_violation\s*=\s*0"),
     "one-definition-rule violations: two definitions of the same symbol can silently "
     "disagree, and the resulting mismatch is never reported"),
    ("alloc_null_ok", re.compile(r"allocator_may_return_null\s*=\s*1"),
     "allocation-failure handling: an over-large allocation returns NULL instead of "
     "reporting, so the library's own OOM path is exercised rather than flagged"),
]

_MAXLEN = re.compile(r"max_len\s*=\s*(\d+)")


def survey(root: Path) -> dict:
    out: dict = {}
    for proj in sorted(p for p in root.iterdir() if p.is_dir()):
        hits: dict = {}
        for f in list(proj.glob("*.sh")) + list(proj.glob("*.options")) \
                + list(proj.glob("Dockerfile")):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for name, pat, why in SIGNALS:
                if pat.search(text):
                    hits.setdefault(name, {"why": why, "seen_in": []})
                    hits[name]["seen_in"].append(f.name)
            m = _MAXLEN.search(text)
            if m:
                hits.setdefault("input_truncated", {
                    "why": f"any defect needing more than {m.group(1)} bytes of input: "
                           f"libFuzzer is capped at max_len={m.group(1)}",
                    "seen_in": []})
                hits["input_truncated"]["seen_in"].append(f.name)
        if hits:
            out[proj.name] = hits
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", help="an oss-fuzz projects/ directory")
    ap.add_argument("-o", "--out")
    a = ap.parse_args(argv)

    root = Path(a.root)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    found = survey(root)
    total = len([p for p in root.iterdir() if p.is_dir()])

    print(f"projects surveyed        {total}")
    print(f"  with a bound declared  {len(found)}")
    per: dict = {}
    for proj, hits in found.items():
        for k in hits:
            per.setdefault(k, []).append(proj)
    for k, projs in sorted(per.items(), key=lambda kv: -len(kv[1])):
        print(f"    {k:20} {len(projs):4}  e.g. {', '.join(sorted(projs)[:3])}")
    print()
    print("These are bounds, not defects. A project may disable a detector for a good "
          "reason.\nWhat is NOT reasonable is a campaign reporting nothing while a whole "
          "class is off\nand nobody says so.")

    if a.out:
        Path(a.out).write_text(json.dumps(
            {"projects_surveyed": total, "with_a_bound": len(found),
             "by_signal": {k: sorted(v) for k, v in per.items()},
             "detail": found}, indent=1))
        print(f"\nwritten to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
