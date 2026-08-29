"""A small statement structure for C harness bodies — enough control flow to stop lying.

Not a compiler front end. It answers exactly three questions that a flat regex over
statements answers wrongly, and that produced every false positive the audit made against
sqlite's production harnesses:

  1. **Does this call actually run?**  `if (sqlite3_open(":memory:", &db)) return 0;`
     puts the call in the CONDITION, which always executes. A statement regex anchored on
     `;` never saw it, so `db` looked as though nothing created it and the later
     `sqlite3_close(db)` was reported as a use-before-create.

  2. **Does it run on every path?**  A call inside an `if` body may not. A destroy that
     happens only on one branch, followed by a use, is a POSSIBLE use-after-free, not a
     certain one, and the difference decides whether a maintainer should be emailed.

  3. **Is an early `return` fatal to what follows?**  No. `if (size < 4) return 0;` is a
     guard: everything after it still runs on the path that matters.

Nesting depth is the whole model. Depth 0 means unconditional; deeper means guarded. That
is coarse, and it is honest about being coarse — it turns confident-but-wrong findings into
correctly-hedged ones rather than pretending to a precision it does not have.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

_KEYWORD_HEAD = re.compile(r"^\s*(if|for|while|switch|else|do)\b")


@dataclass
class Stmt:
    """One statement, with the branch nesting it sits under."""
    text: str
    depth: int                       # 0 = runs unconditionally
    is_condition: bool = False       # text came from an if/while/for header
    kind: str = "plain"              # plain | branch | loop | return


@dataclass
class Body:
    stmts: list = field(default_factory=list)
    branches: int = 0
    early_returns: int = 0

    @property
    def unconditional(self) -> list:
        return [s for s in self.stmts if s.depth == 0]


def _match_brace(src: str, i: int) -> int:
    depth = 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(src) - 1


def _match_paren(src: str, i: int) -> int:
    depth = 0
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(src) - 1


def parse(body: str, depth: int = 0, out: Body = None) -> Body:
    """Split a function body into statements, tracking branch nesting.

    A control-flow HEADER's condition is emitted at the CURRENT depth, because it executes
    whenever the statement is reached. Only the controlled block is emitted deeper.
    """
    out = out if out is not None else Body()
    i, n = 0, len(body)
    buf: list = []

    def flush():
        text = "".join(buf).strip()
        buf.clear()
        if not text:
            return
        kind = "return" if re.match(r"^\s*return\b", text) else "plain"
        if kind == "return":
            out.early_returns += 1
        out.stmts.append(Stmt(text=text, depth=depth, kind=kind))

    while i < n:
        ch = body[i]

        m = _KEYWORD_HEAD.match(body[i:]) if (i == 0 or body[i - 1] in ";{}\n \t") else None
        if m:
            flush()
            kw = m.group(1)
            j = i + m.end()
            if kw != "else" and kw != "do":
                # The condition runs at THIS depth: `if (f(x))` calls f unconditionally.
                p = body.find("(", j)
                if p >= 0:
                    q = _match_paren(body, p)
                    cond = body[p + 1:q]
                    if cond.strip():
                        out.stmts.append(Stmt(text=cond, depth=depth,
                                              is_condition=True, kind="branch"))
                    j = q + 1
                out.branches += 1

            # The controlled statement or block sits one level deeper.
            k = j
            while k < n and body[k] in " \t\r\n":
                k += 1
            if k < n and body[k] == "{":
                close = _match_brace(body, k)
                parse(body[k + 1:close], depth + 1, out)
                i = close + 1
            else:
                end = body.find(";", k)
                end = n - 1 if end < 0 else end
                inner = body[k:end + 1].strip()
                if inner:
                    parse(inner, depth + 1, out)
                i = end + 1
            continue

        if ch == "{":
            flush()
            close = _match_brace(body, i)
            parse(body[i + 1:close], depth, out)
            i = close + 1
            continue

        if ch == ";":
            buf.append(ch)
            flush()
            i += 1
            continue

        buf.append(ch)
        i += 1

    flush()
    return out


def statements(body: str) -> Iterator:
    """Every statement in the body, with its branch depth. Order is textual within a depth,
    which is exactly what the lifter needs and no more than it can justify."""
    yield from parse(body).stmts
