"""Seed corpora mined from the target's own test data.

Same principle as the dictionary, and the other half of it. A dictionary tells the fuzzer
what the format's *words* are; a seed tells it what a *sentence* looks like. Starting from
two synthetic bytes means the fuzzer spends its first minutes discovering that the input is,
say, a PNG at all — and on a format with a magic number and a checksum it may never get in.

The files are already in the repository. `file` ships `magic/` and test inputs, sqlite ships
`test/*.db`, libpng ships `contrib/pngsuite/*.png`. Every project that has tests has example
inputs, and they are by construction valid.

Selection is conservative, because a bad corpus is worse than none:

  * size-bounded — a 40MB fixture makes every execution slow and teaches the fuzzer nothing
    a 4KB one does not
  * de-duplicated by content hash, since test suites repeat fixtures
  * source code excluded — a `.c` file is not an input to the library, it is the library
  * capped, and the cap is REPORTED, because a silently truncated corpus looks like a
    complete one
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Directories that hold example inputs in the overwhelming majority of C projects.
_DATA_DIRS = re.compile(
    r"(^|/)(test|tests|testdata|test-data|testsuite|t|data|samples?|examples?|fixtures?|"
    r"corpus|corpora|seeds?|inputs?|cases?|regress|regression|contrib|doc|docs)(/|$)", re.I)

# Never seeds: the project's own source, build output, and version control.
_NOT_INPUT = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hh", ".m", ".mm", ".s", ".S",
              ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".lo", ".la", ".pyc",
              ".am", ".ac", ".in", ".m4", ".mk", ".cmake", ".sh", ".bat", ".ps1",
              ".md", ".rst", ".txt.in", ".gitignore", ".patch", ".diff"}
_SKIP_DIR = re.compile(r"(^|/)(\.git|\.svn|node_modules|build|_build|cmake-build|\.deps|"
                       r"autom4te\.cache)(/|$)")


@dataclass
class Corpus:
    files: list = field(default_factory=list)      # (path, bytes)
    scanned: int = 0
    skipped_large: int = 0
    skipped_dupe: int = 0
    capped: int = 0                                # how many were dropped by the cap

    @property
    def total_bytes(self) -> int:
        return sum(len(b) for _, b in self.files)

    def summary(self) -> str:
        bits = [f"{len(self.files)} seed(s), {self.total_bytes} bytes, "
                f"from {self.scanned} candidate file(s)"]
        if self.skipped_dupe:
            bits.append(f"{self.skipped_dupe} duplicate(s) dropped")
        if self.skipped_large:
            bits.append(f"{self.skipped_large} over the size limit")
        if self.capped:
            bits.append(f"{self.capped} DROPPED BY THE CAP (raise --max-seeds to keep them)")
        return "; ".join(bits)


def mine(roots: Iterable[str], *, max_bytes: int = 65536, max_seeds: int = 256) -> Corpus:
    """Example inputs from a project's test data, de-duplicated and size-bounded."""
    c = Corpus()
    seen: set = set()
    found: list = []

    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        if base.is_file():
            paths = [base]
        else:
            # Sorted, so which of two identical fixtures survives de-duplication is the same
            # on every machine. A corpus that varies between runs makes a campaign's result
            # unreproducible for the reason hardest to notice.
            paths = sorted((p for p in base.rglob("*") if p.is_file()), key=str)
        for p in paths:
            rel = str(p)
            if _SKIP_DIR.search(rel):
                continue
            # The data-directory filter exists to stop a whole REPOSITORY being mined as
            # input. When the operator names a directory outright it is redundant, and it
            # cost us every one of lcms2's ICC profiles because they live in `testbed/`
            # rather than a directory the pattern recognises. Only screen when recursing
            # below the named root.
            if (base.is_dir() and p.parent != base
                    and not _DATA_DIRS.search(str(p.parent))):
                continue
            if p.suffix.lower() in _NOT_INPUT:
                continue
            c.scanned += 1
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size == 0 or size > max_bytes:
                if size > max_bytes:
                    c.skipped_large += 1
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            h = hashlib.sha256(data).hexdigest()
            if h in seen:
                c.skipped_dupe += 1
                continue
            seen.add(h)
            found.append((str(p), data))

    # Smallest first: a fuzzer gets more from many small distinct examples than from a few
    # large ones, and small inputs execute faster.
    found.sort(key=lambda t: (len(t[1]), t[0]))
    if len(found) > max_seeds:
        c.capped = len(found) - max_seeds
        found = found[:max_seeds]
    c.files = found
    return c


def write(corpus: Corpus, out_dir: Path) -> int:
    """Write the seeds under content-addressed names, so re-mining is idempotent."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for path, data in corpus.files:
        h = hashlib.sha256(data).hexdigest()[:16]
        ext = Path(path).suffix[:8]
        (out_dir / f"{h}{ext}").write_bytes(data)
    return len(corpus.files)
