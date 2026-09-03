#!/usr/bin/env python3
"""Where should the fuzzer's bytes enter a lifted test?

P3.LIFT, phase 2. A unit test supplies FIXED data -- a string literal, a fixture file, a
hand-built buffer -- and a harness must supply the fuzzer's. Deciding where that substitution
happens is the whole difficulty: get it wrong and the sequence still runs but exercises
nothing, which is a harness that looks fine and finds nothing.

THE RULE. A seam is a call argument that is (a) a literal in the source and (b) bound to a
parameter the library's own header declares as a byte buffer or C string. Both halves are
required. The literal alone would substitute into any string, including a format specifier or
a key name; the declaration alone would substitute into a buffer the test never fills.

RANKED BY DEPTH, not by position. The seam worth taking is the one the most later calls
depend on -- substituting into a value that is immediately discarded changes nothing. Depth
is measured as the number of ops after the seam that use a resource the seam's call produced.

WHAT IT DOES NOT DO. It does not decide that a test is worth lifting, and it does not modify
anything. It reports candidate seams with the evidence for each, so the substitution is a
recorded decision rather than a silent one.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from hforge.producers.header_graph import base_type, parse_header   # noqa: E402
from hforge.lift.c_harness import LiftError                         # noqa: E402
from hforge.lift.c_harness import lift                              # noqa: E402
from test_sequences import _body, sequences_in                      # noqa: E402

_STR_LIT = re.compile(r'"(?:[^"\\]|\\.)*"')
_IDENT = re.compile(r"^[A-Za-z_]\w*$")


def _literal_source(var: str, body: str, filesrc: str, depth: int = 0):
    """Follow `var` back to the string literal that fills it, or None.

    A SEAM DOES NOT HAVE TO BE A LITERAL AT THE CALL SITE. jansson's embed() -- one load and
    three dumps, exactly the shape worth testing -- keeps its inputs in a static table:

        static const char *plains[] = {"{\"bar\":[],\"foo\":{}}", "[[],{}]", ...};
        const char *plain = plains[i];
        parse = json_loads(plain, 0, NULL);

    Requiring a literal at the call site made that whole class of tests invisible, and it is a
    very common idiom. Two hops are followed and no more: assignment from a literal, and
    assignment from a subscript of an array initialised with literals. Deeper chains are left
    alone rather than guessed at -- a wrong seam produces a harness that runs and tests
    nothing, which is worse than no candidate.
    """
    if depth > 2 or not _IDENT.match(var or ""):
        return None
    # X = "literal";  const char *X = "literal";  or  char X[] = "literal";
    #
    # The array form is the common way a C test holds its input, and requiring `=` to follow
    # the name immediately missed all of it: expat writes `char text[] = "<doc/>"`.
    m = re.search(rf"\b{re.escape(var)}\s*(?:\[[^\]]*\])?\s*=\s*({_STR_LIT.pattern})",
                  body)
    if m:
        return m.group(1)
    # X = ARR[...];  then  ARR[] = {"lit", ...}  anywhere in the file
    m = re.search(rf"\b{re.escape(var)}\s*=\s*([A-Za-z_]\w*)\s*\[", body)
    if m:
        arr = m.group(1)
        # `\}` MUST END THE STATEMENT. A non-greedy match to the first closing brace stops
        # INSIDE a string literal: jansson's table begins {"{\"bar\":[],\"foo\":{}}", ...},
        # whose first `}` is four characters into the first element. The captured initialiser
        # was a truncated fragment containing no complete literal, so the trace found the
        # array, found nothing in it, and reported no seam.
        a = re.search(rf"\b{re.escape(arr)}\s*\[\s*\]\s*=\s*\{{(.*?)\}}\s*;",
                      filesrc, re.S)
        if a:
            lits = _STR_LIT.findall(a.group(1))
            if lits:
                return lits[0]
    # X = Y;  one alias hop
    m = re.search(rf"\b{re.escape(var)}\s*=\s*([A-Za-z_]\w*)\s*;", body)
    if m:
        return _literal_source(m.group(1), body, filesrc, depth + 1)
    return None
_BYTEISH = {"char", "unsigned char", "void", "uint8_t", "int8_t"}


_FORMATISH = re.compile(r"^(fmt|format|spec|pattern|template)$", re.I)

# APIs whose NAME says they consume a serialised representation. A PRIOR, not a conclusion.
#
# Ranking seams by how many later ops use the result put `json_string("foo")` at the top of
# jansson: its value is reused 84 times, and it does almost nothing -- it wraps a C string.
# `json_loads` is the call that runs the parser. Depth measures how much the RESULT is used,
# which is not the same as how much WORK the call does, and nothing in a header states the
# latter.
#
# So this is a documented guess that campaigning is expected to confirm or overturn, in the
# same way probe_select ranks candidates statically and coverage decides. Where it is wrong,
# the generator still emits the other seams as separate candidates.
_PARSEISH = re.compile(
    r"(?:^|_)(load|loads|loadb|parse|read|decode|scan|deserial|unmarshal|from_)", re.I)


def _buffer_params(decl) -> list:
    """Indices of parameters the HEADER says are byte buffers the CALLER FILLS WITH DATA.

    A FORMAT STRING IS NOT DATA. `json_pack(const char *fmt, ...)` declares a char*, and the
    first run of this tool ranked its "b" and "n" specifiers as the deepest seams in jansson
    -- 99 ops deep, and completely wrong. Substituting fuzzer bytes there does not test the
    parser; it makes the HARNESS interpret attacker-controlled format directives, which is a
    defect in the harness rather than a finding in the library.

    Two signals, either sufficient: the function is VARIADIC (a variadic function's leading
    string is a format in essentially every C API), or the parameter is named for one.
    """
    if getattr(decl, "variadic", False):
        return []
    out = []
    for i, (ty, nm) in enumerate(decl.params):
        if "*" not in ty or base_type(ty) not in _BYTEISH:
            continue
        if nm and _FORMATISH.match(nm):
            continue
        out.append(i)
    return out


_MACRO_ENTRY = ("START_TEST", "TEST", "TEST_F", "TEST_P", "CTEST", "CTEST2",
                "ZTEST", "UTEST")


def _body_of_function(src: str, fn: str) -> str:
    """The body of `fn`, whether declared plainly or by a framework macro.

    A macro-declared test is written `START_TEST(test_nul_byte)` and then `{`, so a pattern
    requiring `name(` finds nothing and the body comes back EMPTY -- which makes every
    variable trace fail silently, since there is nothing to search. expat's whole suite is
    written that way.
    """
    pats = [rf"\b{re.escape(fn)}\s*\([^;{{}}]*\)\s*\{{"]
    pats += [rf"\b{mac}\s*\(\s*{re.escape(fn)}\b[^)]*\)\s*\{{"
             for mac in _MACRO_ENTRY]
    for pat in pats:
        m = re.search(pat, src)
        if m:
            return _body(src, src.index("{", m.end() - 1))
    return ""


def seams_for(path: Path, fn: str, decls: dict, src: str,
              wrappers: dict = None) -> list:
    """Candidate seams in one test function, deepest first."""
    try:
        lifted = lift(str(path), target_name=path.stem, entry=fn)
    except (LiftError, Exception):                                  # noqa: BLE001
        return []
    ops = lifted.ir.sequence
    # The call text, in order, so a literal argument can be matched back to its op.
    calls = re.findall(r"\b([A-Za-z_]\w*)\s*\(([^;]*?)\)\s*[;,)]", src, re.S)
    by_api: dict = {}
    for name, argstr in calls:
        by_api.setdefault(name, []).append(argstr)

    wmap = wrappers or {}
    out: list = []
    for i, op in enumerate(ops):
        # Resolve a test-local wrapper to the library call it wraps, and look for the seam
        # under the WRAPPER's own name at the call site -- the source says
        # _XML_Parse_SINGLE_BYTES(parser, text, ...), not XML_Parse(...).
        api_sym = op.api
        call_sym = op.api
        if api_sym in wmap:
            api_sym = wmap[api_sym][0]
        d = decls.get(api_sym)
        if d is None:
            continue
        bufs = _buffer_params(d)
        if not bufs:
            continue
        argstrs = by_api.get(call_sym) or []
        for argstr in argstrs[:3]:
            args = [a.strip() for a in re.split(r",(?![^(]*\))", argstr)]
            fnbody = _body_of_function(src, fn)
            for idx in bufs:
                if idx >= len(args):
                    continue
                lit = args[idx] if _STR_LIT.fullmatch(args[idx]) else None
                via = "literal at the call"
                if lit is None:
                    lit = _literal_source(args[idx], fnbody, src)
                    via = "traced through a variable"
                if lit is None:
                    continue
                # DEPTH: how many later ops touch what this call produced.
                produced = op.binds
                depth = sum(1 for later in ops[i + 1:]
                            if produced and any(a.ref == produced for a in later.args))
                parseish = bool(_PARSEISH.search(api_sym))
                out.append({"function": fn, "file": path.name, "api": api_sym,
                            "via_wrapper": call_sym if call_sym != api_sym else None,
                            "param_index": idx, "literal": lit[:60],
                            "argument": args[idx][:40], "seam_via": via,
                            "depth": depth, "op": op.id, "parse_like": parseish,
                            "rank_reason": ("name says it parses" if parseish
                                            else "ranked on depth alone")})
    out.sort(key=lambda s: (not s["parse_like"], -s["depth"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root")
    ap.add_argument("--header", action="append", default=[], required=True)
    ap.add_argument("--include", action="append", default=[])
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    decls: dict = {}
    for h in a.header:
        try:
            for d in parse_header(h, tuple(a.include), ()):
                decls[d.name] = d
        except Exception:                                           # noqa: BLE001
            continue
    api = set(decls)
    root = Path(a.root)

    found: list = []
    files = [q for d in ("test", "tests", "testbed", "check")
             if (root / d).is_dir() for q in sorted((root / d).rglob("*.c"))]
    for f in files[:300]:
        try:
            src = f.read_text(errors="replace")
        except OSError:
            continue
        for s in sequences_in(f, api):
            found.extend(seams_for(f, s["function"], decls, src))

    found.sort(key=lambda s: (not s["parse_like"], -s["depth"]))
    print(f"{len(found)} candidate seam(s) in {root.name}")
    for s in found[:15]:
        mark = "PARSE" if s["parse_like"] else "     "
        print(f"  {mark} depth {s['depth']:3d}  {s['api']:20s} arg{s['param_index']} "
              f"{s['literal'][:30]:32s} {s['function'][:20]}  {s['file']}")
    if a.out:
        Path(a.out).write_text(json.dumps(
            {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "library": root.name, "seams": found}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
