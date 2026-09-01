#!/usr/bin/env python3
"""Mine a library's own repository for seed inputs.

WHY. A campaign that starts from nothing spends its budget being rejected at the first
signature check. benchmarks/drive.py already carries seed paths for 17 targets, but they were
chosen BY HAND -- which does not scale to the 479 projects the audit track needs, and which
left the corpus-scale sweep and probe_synth running on nothing (probe_synth writes a single
synthetic `a: 1\\n`, and its own docstring records that unseeded campaigns are noise).

WHAT COUNTS AS A SEED. A file in the repository that is DATA rather than code: test inputs,
fixtures, sample documents, regression corpora. The blocklist is the load-bearing part --
a repository is mostly source, and feeding a parser its own .c files measures nothing except
how fast it rejects them.

WHAT THIS DOES NOT DO. It does not know what format the target consumes. It ranks by how
strongly a directory name suggests test data and by extension when a format is supplied, but
an unfiltered mine will contain files the harness rejects. That is acceptable -- libFuzzer
discards what does not increase coverage -- and it is the reason the miner reports what it
chose rather than silently seeding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path

# Directories whose name says "this is test data". Ordered: earlier means better.
_SEED_DIRS = ("testdata", "test-data", "test_data", "data_files", "fuzz", "corpus",
              "seeds", "fixtures", "regression", "samples", "sample", "cases",
              "testbed", "pngsuite", "tests", "test", "examples", "example", "data")

# NEVER a seed. A repository is mostly source, and a parser fed its own headers measures how
# fast it rejects them. Extensions only -- guessing from content would be slower and wronger.
_NOT_DATA = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc", ".s", ".asm",
    ".py", ".sh", ".bash", ".pl", ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".m", ".mm", ".cs", ".js", ".ts", ".lua", ".php",
    ".am", ".ac", ".m4", ".cmake", ".mk", ".make", ".ninja", ".gradle", ".bazel",
    ".md", ".rst", ".adoc", ".1", ".3", ".man", ".po", ".pot",
    ".o", ".a", ".so", ".dylib", ".dll", ".lib", ".exe", ".pyc", ".class",
    ".gitignore", ".gitattributes", ".gitmodules", ".yml", ".yaml", ".toml", ".cfg",
    ".in", ".sym", ".def", ".map", ".pc", ".spec",
}
_NOT_DATA_NAMES = {"LICENSE", "COPYING", "AUTHORS", "NEWS", "ChangeLog", "Makefile",
                   "CMakeLists.txt", "configure", "config.guess", "config.sub", "README"}


def _rank(p: Path, root: Path) -> int:
    """Lower is better. Ranked by how strongly the PATH says 'test data'."""
    parts = [x.lower() for x in p.relative_to(root).parts[:-1]]
    for i, name in enumerate(_SEED_DIRS):
        if any(name in part for part in parts):
            return i
    return len(_SEED_DIRS)


def mine(root: Path, *, formats: tuple = (), max_files: int = 200,
         max_bytes: int = 1 << 20, min_bytes: int = 1) -> tuple:
    """Return (chosen, report). `formats` are extensions to prefer, e.g. ('.png',)."""
    seen: set = set()
    cands: list = []
    skipped = {"source": 0, "too_big": 0, "empty": 0, "duplicate": 0}
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        if ".git" in p.parts:
            continue
        if p.suffix.lower() in _NOT_DATA or p.name in _NOT_DATA_NAMES:
            skipped["source"] += 1
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz < min_bytes:
            skipped["empty"] += 1
            continue
        if sz > max_bytes:
            skipped["too_big"] += 1
            continue
        try:
            h = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            continue
        if h in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(h)
        # A format match beats directory ranking: a .png anywhere is a better seed for a PNG
        # decoder than an unknown file inside tests/.
        fmt = 0 if (formats and p.suffix.lower() in formats) else 1
        cands.append((fmt, _rank(p, root), sz, p))
    cands.sort(key=lambda t: (t[0], t[1], t[2]))
    chosen = [c[3] for c in cands[:max_files]]
    report = {"root": str(root), "candidates": len(cands), "chosen": len(chosen),
              "skipped": skipped, "formats_preferred": list(formats),
              "by_rank": {}, "total_bytes": sum(c[2] for c in cands[:max_files])}
    for c in cands[:max_files]:
        key = _SEED_DIRS[c[1]] if c[1] < len(_SEED_DIRS) else "(elsewhere)"
        report["by_rank"][key] = report["by_rank"].get(key, 0) + 1
    return chosen, report


def install(chosen: list, dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in chosen:
        try:
            shutil.copyfile(p, dest / f"seed_{n:04d}{p.suffix.lower()[:8]}")
            n += 1
        except OSError:
            continue
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root")
    ap.add_argument("--dest", default="", help="copy the chosen seeds here")
    ap.add_argument("--format", action="append", default=[],
                    help="extension to prefer, e.g. .png (repeatable)")
    ap.add_argument("--max-files", type=int, default=200)
    ap.add_argument("--max-bytes", type=int, default=1 << 20)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    fmts = tuple(f if f.startswith(".") else "." + f for f in (a.format or []))
    chosen, report = mine(Path(a.root), formats=fmts, max_files=a.max_files,
                          max_bytes=a.max_bytes)
    if a.dest:
        report["installed"] = install(chosen, Path(a.dest))
        report["dest"] = a.dest
    report["generated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"{report['chosen']} seed(s) from {report['candidates']} candidate(s) "
          f"({report['total_bytes']:,} bytes)")
    for k, v in sorted(report["by_rank"].items(), key=lambda kv: -kv[1]):
        print(f"  {k:14s} {v}")
    print(f"  skipped: {report['skipped']}")
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
