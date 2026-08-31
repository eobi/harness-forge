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
    # WHICH ARM, not just how deep. Depth alone cannot tell two statements in DIFFERENT
    # branches from two in the same one, and that distinction decides whether a second
    # assignment is a leak or an alternative. openvpn's harness assigns `tmp` in several
    # mutually exclusive switch cases and frees it in each; read as a flat list it looks
    # like a resource created twice with the first leaked. The arm is a dotted path --
    # "" at the top, "1" and "2" for two sibling blocks, "1.1" for a block inside the
    # first -- so two statements are mutually exclusive when neither path is a prefix of
    # the other.
    arm: str = ""
    # The `if` conditions this statement sits under, innermost last, joined by " && ".
    # Only `if` contributes: an `else` runs under the NEGATION of its condition, and a
    # loop body may not run at all, so neither may claim the guard as a fact.
    guard: str = ""


def returning_arms(b) -> set:
    """Arms that leave the function, so nothing after the branch is reachable from them.

    `if (bad) { free(a); free(b); return 0; }` cleans up and LEAVES. The frees on the
    normal path further down are not second frees of the same objects, because control
    never arrives at both -- but the arm path of the early return is a DESCENDANT of the
    top level, not a sibling, so mutual exclusion alone cannot see it.
    """
    return {st.arm for st in b.stmts if st.kind == "return" and st.arm}


@dataclass
class Body:
    stmts: list = field(default_factory=list)
    branches: int = 0
    early_returns: int = 0
    arms: int = 0                    # counter for handing out distinct arm paths

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


_CASE_LABEL = re.compile(r"^[ \t]*(?:case\b[^:]*|default)\s*:", re.M)


def _split_cases(body: str) -> list:
    """A switch body cut into its alternatives, one per `case`/`default` label.

    Labels at the TOP level of the body only: a `case` inside a nested switch belongs to
    that switch. Text before the first label (rare, unreachable in practice) rides with the
    first alternative rather than being dropped.
    """
    cuts = []
    depth = 0
    for i, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            m = _CASE_LABEL.match(body, i)
            if m and (i == 0 or body[i - 1] == "\n"):
                cuts.append(i)
    if not cuts:
        return [body]
    out = []
    for a, b in zip(cuts, cuts[1:] + [len(body)]):
        piece = body[a:b]
        # Drop the label itself. `case 1:` ends with a colon rather than a semicolon, so
        # without this it glues onto the next statement and every statement in the arm
        # reads as `case 1:\n  p();`. The call regex still matched, so this was cosmetic
        # -- but a statement list that does not say what the statements are is a poor thing
        # to debug the next false positive with.
        piece = _CASE_LABEL.sub("", piece, count=1)
        out.append(piece)
    if cuts[0] > 0 and body[:cuts[0]].strip():
        out[0] = body[:cuts[0]] + out[0]
    return out


def mutually_exclusive(a: str, b: str) -> bool:
    """Whether two arm paths can never both run.

    Sibling blocks diverge at some component; a nested block shares its parent's prefix and
    is therefore NOT exclusive with it. "" (top level) is a prefix of everything and so is
    exclusive with nothing.
    """
    if a == b or not a or not b:
        return False
    return not (a.startswith(b + ".") or b.startswith(a + "."))


def parse(body: str, depth: int = 0, out: Body = None, arm: str = "",
          guard: str = "") -> Body:
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
        out.stmts.append(Stmt(text=text, depth=depth, kind=kind, arm=arm,
                              guard=guard))

    while i < n:
        ch = body[i]

        m = _KEYWORD_HEAD.match(body[i:]) if (i == 0 or body[i - 1] in ";{}\n \t") else None
        if m:
            flush()
            kw = m.group(1)
            j = i + m.end()
            if kw != "else" and kw != "do":
                # The condition runs at THIS depth: `if (f(x))` calls f unconditionally.
                cond_text = ""
                p = body.find("(", j)
                if p >= 0:
                    q = _match_paren(body, p)
                    cond = cond_text = body[p + 1:q]
                    if cond.strip():
                        out.stmts.append(Stmt(text=cond, depth=depth,
                                              is_condition=True, kind="branch", arm=arm,
                                              guard=guard))
                    j = q + 1
                out.branches += 1

            # The controlled statement or block sits one level deeper.
            _inner = guard
            if kw == "if" and cond_text.strip():
                _inner = f"{guard} && {cond_text}" if guard else cond_text
            k = j
            while k < n and body[k] in " \t\r\n":
                k += 1
            if k < n and body[k] == "{":
                close = _match_brace(body, k)
                inner_text = body[k + 1:close]
                if kw == "switch":
                    # EACH `case` IS ITS OWN ARM. A switch body is not one block, it is a
                    # set of alternatives, and treating it as one made every assignment in
                    # it a sibling of every other -- so openvpn's `tmp`, assigned in
                    # thirteen mutually exclusive cases and freed in each, read as a
                    # resource created thirteen times and leaked twelve.
                    for piece in _split_cases(inner_text):
                        out.arms += 1
                        parse(piece, depth + 1, out,
                              arm=(f"{arm}.{out.arms}" if arm else str(out.arms)),
                              guard=_inner)
                else:
                    out.arms += 1
                    parse(inner_text, depth + 1, out,
                          arm=(f"{arm}.{out.arms}" if arm else str(out.arms)),
                          guard=_inner)
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
