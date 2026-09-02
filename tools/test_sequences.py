#!/usr/bin/env python3
"""What API sequences does a library's OWN TEST SUITE express?

THE QUESTION THIS ANSWERS, BEFORE ANY GENERATOR IS BUILT. Our negative-capability measurement
says jansson's widest single plan calls 3 of 83 exported functions, and the union over every
valid base plan reaches 7. A single `setup -> consume -> destroy` shape cannot express a state
machine, and mutational synthesis was measured at +0.40% against OGHarn's +14%, so widening
the candidate space by mutation is refuted.

Unit tests are the remaining hypothesis: a project's tests are a description of CORRECT API
usage, they compile, and they encode the ordering no header states -- libyaml's
`yaml_parser_set_encoding` asserts `!parser->encoding`, and nothing in yaml.h says so.

So: extract the ordered library calls each test function makes, and report how much of the
exported surface they touch. If tests reach little more than our plans do, the hypothesis is
dead and no generator should be written. That number is the point of this tool.

WHAT IT IS NOT. It does not emit harnesses. It measures a ceiling, the same way
tools/reachbound.py does, so the two are directly comparable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from hforge.producers.header_graph import parse_header              # noqa: E402

# Matched ANYWHERE in the tree, not only at the root. expat keeps its tests at
# expat/expat/tests, lcms2 at testbed/, libpng under contrib/ -- looking only at the root
# reported 0% of the exported surface for all three, which reads as "the tests express
# nothing" when it means "the tool did not find them". Three of the first six libraries
# measured were wrong for that reason.
_TEST_DIRS = ("test", "tests", "testing", "check", "testbed", "contrib", "examples",
              "regress", "unittest", "unittests")
# A function DEFINITION: a return type, a name, a parameter list, then a brace.
_FUNC = re.compile(r"^[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.M)
# TESTS ARE OFTEN DECLARED BY A MACRO, not as a plain C function. expat uses the `check`
# framework's START_TEST(name); googletest uses TEST(suite, name). Matching only plain
# definitions reported expat as reaching 0% of its exported surface from 18 test files that
# plainly call XML_ParserCreate -- a fact about the extractor, read as a fact about expat.
_MACRO_FUNC = re.compile(
    r"\b(?:START_TEST|TEST|TEST_F|TEST_P|CTEST|CTEST2|ZTEST|UTEST)\s*\(\s*"
    r"([A-Za-z_]\w*)[^)]*\)\s*\{", re.M)
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _body(src: str, brace_at: int) -> str:
    depth, i = 0, brace_at
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace_at + 1:i]
        i += 1
    return ""


def exported(headers: list, incs: tuple) -> set:
    out: set = set()
    for h in headers:
        try:
            out |= {d.name for d in parse_header(str(h), incs, ())}
        except Exception:                                           # noqa: BLE001
            continue
    return out


def sequences_in(path: Path, api: set) -> list:
    try:
        src = _COMMENT.sub(" ", path.read_text(errors="replace"))
    except OSError:
        return []
    out: list = []
    seen_at: set = set()
    for m in list(_FUNC.finditer(src)) + list(_MACRO_FUNC.finditer(src)):
        if m.start() in seen_at:
            continue
        seen_at.add(m.start())
        body = _body(src, src.index("{", m.end() - 1))
        if not body.strip():
            continue
        # ORDER IS THE WHOLE POINT. Duplicates are kept -- `yaml_parser_parse` called in a
        # loop is a different sequence from one call, and that repetition is exactly what a
        # single setup/consume/destroy plan cannot express.
        calls = [c for c in _CALL.findall(body) if c in api]
        if len(calls) >= 2:
            out.append({"function": m.group(1), "file": path.name, "calls": calls})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", help="the library checkout")
    ap.add_argument("--header", action="append", default=[], required=True)
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    root = Path(a.root)
    api = exported([Path(h) for h in a.header], tuple(a.include))
    if not api:
        print("no exported functions parsed from the header(s); nothing to match against")
        return 1

    files: list = []
    seen_dirs: set = set()
    for d in sorted(root.rglob("*")):
        if not d.is_dir() or ".git" in d.parts:
            continue
        if d.name.lower() not in _TEST_DIRS or d in seen_dirs:
            continue
        seen_dirs.add(d)
        files.extend(sorted(q for q in d.rglob("*.c")))
        files.extend(sorted(q for q in d.rglob("*.cc")))
    files = sorted(set(files))
    seqs: list = []
    for f in files[:400]:
        seqs.extend(sequences_in(f, api))

    reached = Counter()
    for s in seqs:
        reached.update(set(s["calls"]))
    lens = sorted(len(s["calls"]) for s in seqs)
    widest = max(seqs, key=lambda s: len(set(s["calls"])), default=None)

    res = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "library": root.name, "exported": len(api),
           "test_files": len(files), "sequences": len(seqs),
           "distinct_functions_reached": len(reached),
           "surface_reached_pct": round(100.0 * len(reached) / len(api), 1) if api else 0.0,
           "median_sequence_length": lens[len(lens) // 2] if lens else 0,
           "max_sequence_length": lens[-1] if lens else 0,
           "widest_single_test": ({"function": widest["function"], "file": widest["file"],
                                   "distinct": len(set(widest["calls"])),
                                   "calls": widest["calls"][:24]} if widest else None),
           "most_called": dict(reached.most_common(12))}
    print(f"{root.name}: {len(api)} exported function(s), {len(files)} test file(s)")
    print(f"  sequences found          : {len(seqs)}")
    print(f"  distinct functions reached: {len(reached)}  "
          f"({res['surface_reached_pct']}% of the exported surface)")
    print(f"  sequence length          : median {res['median_sequence_length']}, "
          f"max {res['max_sequence_length']}")
    if widest:
        print(f"  widest single test       : {widest['function']} in {widest['file']}, "
              f"{len(set(widest['calls']))} distinct call(s)")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
