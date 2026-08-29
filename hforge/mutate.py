"""Mutation operators for the positive control.

Gate D2 answers the one question every other gate assumes: **can this harness find anything
at all?** A harness that reaches the target, honours its contract and runs fast is still
worthless if a defect placed directly in its path goes unnoticed.

So D2 plants defects and requires the harness to notice. This is mutation testing, applied
to harness adequacy rather than test-suite adequacy: a mutant that survives means either the
harness never reaches that code, or it reaches it and cannot tell. Gate D4's reachability
map is what separates those two readings, which is why mutation sites are restricted to
functions D4 says are reachable.

Each operator introduces a *real* memory-safety defect that AddressSanitizer detects, not a
synthetic assert. And the differential is mandatory: a mutant only counts as killed when the
mutant faults AND the unmutated build is clean on the same input. Without that second half,
a harness that crashes on everything would score a perfect kill rate.

Regex-based, and honest about it: this rewrites text, it does not understand C. Every mutant
is compiled, and one that fails to build is discarded rather than counted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .analysis.sinks import strip_noise


@dataclass
class Mutant:
    id: str
    operator: str
    file: str
    line: int
    function: str
    original: str
    mutated: str
    source: str            # the full mutated file contents
    expect: str            # the defect class this should produce
    rationale: str


# ── operators ─────────────────────────────────────────────────────────────────
# Each returns a list of (span, replacement, description, expect) for one file.

_ALLOC_HEAD = re.compile(r"\b(malloc|calloc|realloc)\s*\(")
_FOR_LT = re.compile(r"(for\s*\([^;]*;\s*[A-Za-z_]\w*\s*)<(\s*[A-Za-z_][\w\.\->]*\s*[;\)])")
_MEMCPY_HEAD = re.compile(r"\b(memcpy|memmove|memset)\s*\(")
_NULL_GUARD = re.compile(r"^([ \t]*)if\s*\(\s*!\s*([A-Za-z_]\w*)\s*\)\s*(return[^;]*;)",
                         re.M)


def _close_paren(src: str, open_idx: int) -> int:
    """Index of the `)` matching the `(` at `open_idx`, or -1.

    A regex cannot do this, and the first version of this file tried. `calloc(1,
    sizeof(hd_ctx))` has an inner `)`, so a non-greedy `[^;]*?\\)` matched
    `calloc(1, sizeof(hd_ctx)` and the replacement left a stray `)` behind. Every mutant of
    every allocation that used `sizeof` failed to compile, was silently counted as
    unbuildable, and the gate reported a smaller denominator instead of an error.
    """
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_args(argstr: str) -> list:
    """Top-level comma split, so `calloc(1, sizeof(struct x))` yields two arguments."""
    args, depth, cur = [], 0, []
    for ch in argstr:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append("".join(cur).strip())
    return args


def _op_shrink_alloc(src: str) -> list:
    """Shrink a heap allocation the target then writes into.

    The most reliable operator by a distance: any code that fills the object it just
    allocated overflows immediately, ASan reports a heap-buffer-overflow, and the defect is
    reachable from every input that reaches the allocating function.
    """
    out = []
    for m in _ALLOC_HEAD.finditer(src):
        fn = m.group(1)
        ob = m.end() - 1
        cb = _close_paren(src, ob)
        if cb < 0:
            continue
        args = _split_args(src[ob + 1:cb])
        if not args:
            continue
        if fn == "calloc":
            if len(args) != 2 or all(a.strip() == "1" for a in args):
                continue
            repl = "calloc(1, 1)"
        elif fn == "realloc":
            if len(args) != 2 or args[1].strip() == "1":
                continue
            repl = f"realloc({args[0]}, 1)"
        else:
            if args[0].strip() == "1":
                continue
            repl = "malloc(1)"
        out.append(((m.start(), cb + 1), repl,
                    f"{fn}({', '.join(a[:24] for a in args)}) -> {repl}",
                    "heap-buffer-overflow (write into a shrunken allocation)"))
    return out


def _op_off_by_one(src: str) -> list:
    """Relax a loop bound from `<` to `<=`: the classic off-by-one, one character wide."""
    return [(m.span(), f"{m.group(1)}<={m.group(2)}",
             f"loop bound `<` -> `<=`",
             "off-by-one read or write past the end")
            for m in _FOR_LT.finditer(src)]


def _op_widen_copy(src: str) -> list:
    """Copy more than the length says: a direct out-of-bounds write."""
    out = []
    for m in _MEMCPY_HEAD.finditer(src):
        fn = m.group(1)
        ob = m.end() - 1
        cb = _close_paren(src, ob)
        if cb < 0:
            continue
        args = _split_args(src[ob + 1:cb])
        if len(args) != 3:
            continue
        out.append(((m.start(), cb + 1),
                    f"{fn}({args[0]}, {args[1]}, ({args[2]}) + 8)",
                    f"{fn} length {args[2][:30]} -> {args[2][:30]} + 8",
                    "out-of-bounds write past the destination"))
    return out


def _op_drop_null_guard(src: str) -> list:
    """Remove an early `if (!p) return ...;`, turning a rejected input into a null deref."""
    return [(m.span(), f"{m.group(1)}/* guard removed by mutation */",
             f"dropped `if (!{m.group(2)}) {m.group(3)[:24]}`",
             "null pointer dereference on a path the guard protected")
            for m in _NULL_GUARD.finditer(src)]


OPERATORS = {
    "shrink_alloc": _op_shrink_alloc,
    "off_by_one": _op_off_by_one,
    "widen_copy": _op_widen_copy,
    "drop_null_guard": _op_drop_null_guard,
}


def _function_at(src: str, offset: int) -> str:
    """Best-effort: the name of the function containing this offset."""
    head = src[:offset]
    m = None
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{", head):
        pass
    return m.group(1) if m else "?"


def generate_mutants(sources: list, *, reachable: Optional[set] = None,
                     operators: Optional[list] = None,
                     limit: int = 8) -> list:
    """Produce compilable single-point mutants of the target sources.

    `reachable` is the function-name set from gate D4. Restricting sites to it is what makes
    a surviving mutant mean 'the harness has a gap' rather than 'the mutation landed in code
    nothing calls'.
    """
    ops = operators or list(OPERATORS)
    mutants: list = []

    for path in sources:
        p = Path(path)
        if not p.exists() or p.suffix not in (".c", ".cc", ".cpp", ".cxx"):
            continue
        raw = p.read_text(errors="replace")
        clean = strip_noise(raw)          # find sites in code, never in comments or strings

        for opname in ops:
            for (start, end), repl, desc, expect in OPERATORS[opname](clean):
                fn = _function_at(clean, start)
                if reachable is not None and fn not in reachable:
                    continue
                mutated_src = raw[:start] + repl + raw[end:]
                if mutated_src == raw:
                    continue
                line = raw.count("\n", 0, start) + 1
                mutants.append(Mutant(
                    id=f"{p.stem}:{line}:{opname}",
                    operator=opname, file=str(p), line=line, function=fn,
                    original=" ".join(raw[start:end].split())[:70],
                    mutated=" ".join(repl.split())[:70],
                    source=mutated_src, expect=expect,
                    rationale=desc))
                if len(mutants) >= limit:
                    return mutants
    return mutants
