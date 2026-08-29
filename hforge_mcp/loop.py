"""The repair loop — the thing that makes a verifier useful to a model.

`08` Layer 2 describes it: the model emits a plan, `hf_validate` returns violations each
carrying `where` and `fix`, the model repairs, revalidates. Bounded rounds. Nothing compiles
and nothing executes, so it is cheap enough to run hundreds of times and safe enough to run
unattended.

It works only because `Violation.fix` exists, and that field was written for humans:

> *a verifier that returns "invalid" produces a model that guesses. A verifier that returns
> "set slice 'json' kind to 'cstring', or call the length-delimited variant" produces a model
> that converges.*

The `Repairer` below is deliberately an interface with a deterministic reference
implementation. That is not a stand-in for a model — it is the **control**. If a mechanical
repairer that reads nothing but the returned `fix` strings can converge, then the strings
carry enough information to act on, and a model's contribution is diversity rather than
comprehension. If it cannot, no model will do better on the same output, and the gate
messages are the thing to fix.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Round:
    n: int
    blocking: list
    repaired: bool
    note: str = ""


@dataclass
class LoopResult:
    plan: dict
    rounds: list = field(default_factory=list)
    converged: bool = False
    gave_up: str = ""

    @property
    def summary(self) -> str:
        L = [f"repair loop: {len(self.rounds)} round(s), "
             f"{'CONVERGED' if self.converged else 'did not converge'}"]
        for r in self.rounds:
            codes = ", ".join(v["code"] for v in r.blocking) or "clean"
            L.append(f"  round {r.n}: {codes}"
                     + ("" if r.repaired or not r.blocking else f"  <- {r.note}"))
        if self.gave_up:
            L.append(f"  gave up: {self.gave_up}")
        return "\n".join(L)


class Repairer:
    """Anything that turns a plan plus its violations into a better plan, or None."""

    name = "abstract"

    def repair(self, plan: dict, violations: list) -> Optional[dict]:  # pragma: no cover
        raise NotImplementedError


class FixStringRepairer(Repairer):
    """Acts on the `fix` text the gates already return, and on nothing else.

    Every branch below is driven by what `hf_validate` said, not by knowledge of the target.
    That is the point: it measures whether the messages are actionable.
    """

    name = "fix-string"

    def repair(self, plan: dict, violations: list) -> Optional[dict]:
        p = copy.deepcopy(plan)
        changed = False
        for v in violations:
            code = v.get("code", "")
            where = v.get("where", "")
            fix = v.get("fix", "")

            if code == "S2.CSTRING" and "kind to 'cstring'" in fix:
                # "set slice 'json' kind to 'cstring', or call the length-delimited variant"
                name = _quoted(fix, "slice")
                for s in p.get("slices", []):
                    if s.get("id") == name and s.get("kind") != "cstring":
                        s["kind"] = "cstring"
                        changed = True

            elif code == "S2.TYPE_CONFUSION":
                # The library dereferences it, so it must not receive fuzzer bytes.
                param = _quoted(v.get("message", ""), "parameter")
                for op in p.get("sequence", []):
                    if where and op.get("id") != where:
                        continue
                    for a in op.get("args", []):
                        if a.get("param") == param and a.get("source") == "input":
                            a["source"], a["value"] = "literal", 0
                            a.pop("ref", None)
                            changed = True

            elif code == "S2.MISSING_ARG":
                param = _quoted(v.get("message", ""), "parameter")
                for op in p.get("sequence", []):
                    if op.get("id") == where and not any(
                            a.get("param") == param for a in op.get("args", [])):
                        op.setdefault("args", []).append(
                            {"param": param, "source": "literal", "value": 0})
                        changed = True

            elif fix.startswith("add '") and "to guarded_by on op" in fix:
                # "add 'ctx' to guarded_by on op o_parse" — S2.UNGUARDED_NONNULL and
                # S6.UNCHECKED_ERROR both say exactly this, and both are satisfied by it.
                res_id = _quoted(fix, "add")
                op_id = fix.rsplit("op", 1)[-1].strip().rstrip(".")
                for op in p.get("sequence", []):
                    if op.get("id") == op_id or (not op_id and op.get("id") == where):
                        g = op.setdefault("guarded_by", [])
                        if res_id and res_id not in g:
                            g.append(res_id)
                            changed = True

            elif code == "S1.USE_AFTER_DESTROY":
                # "move the destroy after the last use"
                seq = p.get("sequence", [])
                di = next((i for i, o in enumerate(seq) if o.get("targets")), None)
                if di is not None and di < len(seq) - 1:
                    seq.append(seq.pop(di))
                    changed = True

        return p if changed else None


def _quoted(text: str, after: str) -> str:
    """The first `'name'` following a keyword, which is how the gates name things."""
    i = text.find(after)
    if i < 0:
        return ""
    seg = text[i:]
    a = seg.find("'")
    b = seg.find("'", a + 1)
    return seg[a + 1:b] if a >= 0 and b > a else ""


def repair_loop(plan: dict, repairer: Repairer,
                validate: Callable[[dict], dict],
                max_rounds: int = 8) -> LoopResult:
    """Validate, repair, revalidate — until clean, stuck, or out of rounds."""
    cur = copy.deepcopy(plan)
    out = LoopResult(plan=cur)

    for n in range(1, max_rounds + 1):
        res = validate(cur)
        if res.get("error"):
            out.rounds.append(Round(n, [], False, res["error"]))
            out.gave_up = res["error"]
            return out
        blocking = res.get("blocking", [])
        if not blocking:
            out.rounds.append(Round(n, [], False, "clean"))
            out.converged = True
            out.plan = cur
            return out

        nxt = repairer.repair(cur, blocking)
        if nxt is None:
            out.rounds.append(Round(n, blocking, False,
                                    "the repairer could not act on these violations"))
            out.gave_up = ("no repair available for "
                           + ", ".join(v["code"] for v in blocking))
            return out
        out.rounds.append(Round(n, blocking, True))
        cur = nxt

    out.plan = cur
    out.gave_up = f"still blocking after {max_rounds} rounds"
    return out
