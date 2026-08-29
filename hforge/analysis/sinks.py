"""A dependency-free C/C++ code-intelligence pass.

Not a parser. It strips comments and strings, brace-matches to recover function bodies,
builds a name-based call graph, locates memory-safety-relevant sinks, and computes which of
them are reachable from a given set of entry points.

Two gates depend on it and neither could exist without it:

  D4  what fraction of the reachable sink surface does this harness actually touch?
  D2  where should a planted defect go, so that a surviving mutant means the harness has a
      gap rather than that the mutation landed in unreachable code?

Heuristic by design, and it says so. A name-based call graph over-approximates through
function pointers and under-approximates through them too. It informs the gates; it never
asserts a bug, because that is what oracles are for.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# sink kind -> (pattern, danger weight). Higher weight = more classically exploitable.
SINKS: dict = {
    "gets":     (re.compile(r"\bgets\s*\("), 6.0),
    "strcpy":   (re.compile(r"\b(?:strcpy|strcat|stpcpy|wcscpy)\s*\("), 4.5),
    "sprintf":  (re.compile(r"\b(?:sprintf|vsprintf)\s*\("), 4.5),
    "alloca":   (re.compile(r"\balloca\s*\("), 4.0),
    "memcpy":   (re.compile(r"\b(?:memcpy|memmove|bcopy|memset)\s*\("), 3.5),
    "strlen":   (re.compile(r"\b(?:strlen|wcslen)\s*\("), 3.0),
    "strncpy":  (re.compile(r"\b(?:strncpy|strncat|snprintf)\s*\("), 2.0),
    "alloc":    (re.compile(r"\b(?:malloc|calloc|realloc|reallocarray)\s*\("), 1.5),
    "free":     (re.compile(r"\bfree\s*\("), 1.5),
    "index":    (re.compile(r"\w+\s*\[[^\]]*\b[a-zA-Z_]\w*\b[^\]]*\]\s*="), 1.5),
    "ptrarith": (re.compile(r"\*\s*\(\s*\w+\s*\+"), 1.0),
    "shift":    (re.compile(r"<<\s*[a-zA-Z_]\w*"), 0.8),
}

# A function definition, INCLUDING the BSD/K&R layout where the return type sits on its own
# line and the name starts the next:
#
#     file_public struct magic_set *
#     magic_open(int flags)
#     {
#
# The first version of this pattern used `[\w \t\*]` for the type, which cannot cross a
# newline, so it matched none of those. `file`, OpenSSH and a large amount of BSD-derived C
# are written that way — so gate D4 reported "reaches 0 of 19 sinks" on real software and
# the warning read like a finding when it was a parser artifact. Reachability was empty for
# the same reason: the entry points were never located.
#
# The type span is `[^;{}()]*?` — it may contain newlines but no brace, paren or semicolon,
# so it can span a wrapped declaration while remaining unable to run into a function body or
# across a statement.
_FUNC_DEF = re.compile(
    r"(?:^|\n)[ \t]*"
    r"(?![ \t]*(?:if|for|while|switch|return|else|do|case|sizeof)\b)"
    r"[A-Za-z_][^;{}()]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.M)
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
             "defined", "static_assert", "typeof", "alignof"}


@dataclass
class Sink:
    kind: str
    weight: float
    file: str
    line: int
    function: str
    text: str

    @property
    def id(self) -> str:
        return f"{Path(self.file).name}:{self.line}:{self.kind}"


@dataclass
class Function:
    name: str
    file: str
    start_line: int
    end_line: int
    body: str
    calls: set = field(default_factory=set)
    sinks: list = field(default_factory=list)


@dataclass
class CodeMap:
    functions: dict          # name -> Function
    sinks: list              # every sink found
    files: list

    _reach_cache: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def _all_sink_ids(self) -> set:
        c = getattr(self, "__sink_ids", None)
        if c is None:
            c = {k.id for k in self.sinks}
            object.__setattr__(self, "__sink_ids", c)
        return c

    @property
    def _total_weight(self) -> float:
        c = getattr(self, "__total_w", None)
        if c is None:
            c = sum(k.weight for k in self.sinks) or 1.0
            object.__setattr__(self, "__total_w", c)
        return c

    def reachable_from(self, entries: Iterable[str], max_depth: int = 12) -> set:
        """Name-based transitive closure. Over-approximates through same-named statics and
        under-approximates through function pointers; both are stated rather than hidden.

        Cached on the entry set. The MAP was already cached, but the WALK was not, and on
        sqlite's 4,368-function graph it costs 5.6 seconds. Ordering 524 candidates by sink
        surface therefore took 49 minutes at one core before a single harness was built —
        a serial prologue longer than the parallel work it was scheduling. Plans share entry
        points heavily (the same consumer at several max_len values, with and without setup
        calls), so this hits far more often than it misses.
        """
        key = (frozenset(entries), max_depth)
        hit = self._reach_cache.get(key)
        if hit is not None:
            return hit
        # Mark on ENQUEUE, not on dequeue.
        #
        # The previous version added a function to `seen` only when it was popped, so every
        # caller of a shared helper pushed it again and `nxt` filled with duplicates. On a
        # dense graph that is O(V*E) with a frontier orders of magnitude larger than the
        # vertex set — 5.6 seconds to walk 4,368 functions, which is what made ordering
        # sqlite's candidates take half an hour. Marking on enqueue visits each function
        # exactly once.
        frontier = [e for e in entries if e in self.functions]
        seen: set = set(frontier)
        depth = 0
        while frontier and depth < max_depth:
            nxt: list = []
            for fn in frontier:
                for c in self.functions[fn].calls:
                    if c not in seen and c in self.functions:
                        seen.add(c)
                        nxt.append(c)
            frontier, depth = nxt, depth + 1
        self._reach_cache[key] = seen
        return seen

    def sinks_in(self, funcs: Iterable[str]) -> list:
        s = set(funcs)
        return [k for k in self.sinks if k.function in s]

    def sink_surface(self, entries: Iterable[str]) -> dict:
        reach = self.reachable_from(entries)
        reached = self.sinks_in(reach)
        # `reached` is a LIST. `k not in reached` below was therefore a linear scan with
        # dataclass equality, run once per sink: 8,116 x 8,116 = 66 MILLION comparisons per
        # plan on sqlite. That, not the call-graph walk, was the real reason ordering
        # candidates took half an hour — and fixing the walk first did nothing for it.
        reached_ids = {k.id for k in reached}
        total_w = self._total_weight
        reach_w = sum(k.weight for k in reached)
        return {
            "functions_total": len(self.functions),
            "functions_reachable": len(reach),
            "sinks_total": len(self.sinks),
            "sinks_reachable": len(reached),
            "fraction": round(len(reached) / len(self.sinks), 3) if self.sinks else 0.0,
            "weighted_fraction": round(reach_w / total_w, 3),
            # The COUNT is exact; the list is capped. Sorting 3,719 names per plan and
            # storing them in every certificate cost time on 648 plans and produced 22KB
            # artifacts nobody reads. A truncated list that says it is truncated beats a
            # complete one that nobody opens.
            "reachable_functions": sorted(reach)[:200],
            "reachable_functions_truncated": max(0, len(reach) - 200),
            "unreached_sinks": sorted(self._all_sink_ids - reached_ids)[:40],
            "by_kind": _by_kind(reached),
            "caveat": "name-based call graph: over-approximates through same-named statics, "
                      "under-approximates through function pointers. A lead, not a proof.",
        }


def _by_kind(sinks: list) -> dict:
    out: dict = {}
    for s in sinks:
        out[s.kind] = out.get(s.kind, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def strip_noise(src: str) -> str:
    """Blank out comments and string literals while preserving line numbers, so a `memcpy`
    inside a comment or a log message is not counted as a sink."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c in "\"'":
            q, j = c, i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_body(src: str, open_brace: int) -> int:
    depth, i, n = 0, open_brace, len(src)
    while i < n:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def scan_file(path: str) -> tuple:
    raw = Path(path).read_text(errors="replace")
    src = strip_noise(raw)
    funcs: dict = {}
    sinks: list = []

    for m in _FUNC_DEF.finditer(src):
        name = m.group(1)
        if name in _KEYWORDS:
            continue
        ob = src.find("{", m.start())
        if ob < 0:
            continue
        cb = _match_body(src, ob)
        body = src[ob:cb + 1]
        start = src.count("\n", 0, m.start()) + 1
        end = src.count("\n", 0, cb) + 1

        calls = {c for c in _CALL.findall(body) if c not in _KEYWORDS and c != name}
        fn = Function(name=name, file=path, start_line=start, end_line=end,
                      body=body, calls=calls)

        base = src.count("\n", 0, ob)
        for kind, (pat, weight) in SINKS.items():
            for sm in pat.finditer(body):
                line = base + body.count("\n", 0, sm.start()) + 1
                snippet = body[max(0, sm.start() - 20):sm.start() + 60].strip()
                s = Sink(kind=kind, weight=weight, file=path, line=line,
                         function=name, text=" ".join(snippet.split())[:90])
                fn.sinks.append(s)
                sinks.append(s)
        funcs[name] = fn

    return funcs, sinks


_MAP_CACHE: dict = {}


def build_map(sources: Iterable[str]) -> CodeMap:
    """Cached by source set. sqlite3.c is 243,646 lines and a batch run asks for the sink
    map once per candidate plan; on 262 candidates that is the same scan repeated 262 times.
    The map depends only on the sources, so it is built once."""
    key = tuple(sorted(str(x) for x in sources))
    hit = _MAP_CACHE.get(key)
    if hit is not None:
        return hit
    m = _build_map_uncached(key)
    _MAP_CACHE[key] = m
    return m


def _build_map_uncached(sources: Iterable[str]) -> CodeMap:
    funcs: dict = {}
    sinks: list = []
    files: list = []
    for s in sources:
        p = Path(s)
        if not p.exists() or p.suffix not in (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"):
            continue
        f, k = scan_file(str(p))
        funcs.update(f)
        sinks.extend(k)
        files.append(str(p))
    return CodeMap(functions=funcs, sinks=sinks, files=files)
