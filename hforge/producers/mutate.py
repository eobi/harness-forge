"""Mutational plan synthesis — widening the CANDIDATE SPACE, not the ranking.

OGHarn (ICSE 2025) beats developer-written harnesses by +14% median coverage by stitching
candidates together mutationally and filtering them through dynamic oracles: compilation,
execution, and code coverage. Every candidate costs a compile and a run.

We measured our own gap against it and it is NOT the ranking. `benchmarks/probe_select.py`
built and campaigned every gate-passing candidate for two cases and compared the plan the
static rule picks against the best available: 0.63 points behind on libyaml, against a
run-to-run variance of 3.55 on that same case, and 0.00 behind on libpng, where all twelve
candidates score identically because the case is capped by a missing capability. Selection
is not where the coverage went.

**The candidate space is.** The header graph proposes one plan per consuming entry point:
create, consume, destroy. It never proposes a plan that calls a function belonging to a
DIFFERENT entry point against the same object, and that is the shape OGHarn reaches by
mutation. This module generates those.

The asymmetry we are betting on: their oracles are all dynamic, so a rejected candidate has
already cost a compile and a 24-hour campaign slot. Ours are static, so a rejected candidate
costs microseconds. If the bet is right we can afford a candidate space an order of
magnitude larger. The measured prior for that bet is the gates' false-rejection rate on
known-good production harnesses: 1.18% on lifts we trust (see
benchmarks/audits/upstream-repos-2026-08-31.json).

DETERMINISTIC BY CONSTRUCTION. Mutations are ENUMERATED, not sampled: the same inputs give
the same candidates in the same order, every run, with no seed to record and no variance to
explain. A benchmark that cannot be replayed is not evidence, and this project has already
retracted one set of numbers for a reason of exactly that kind.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from ..ir import Arg, HarnessIR, Op
from ..ir import ROLE_CONSUME, ROLE_CREATE, ROLE_DESTROY, ROLE_QUERY
from ..ir import SRC_INPUT, SRC_LENGTH_OF, SRC_LITERAL, SRC_RESOURCE


def _renumber(seq: list) -> list:
    """Op ids must be unique and ordered; a spliced sequence has neither."""
    return [replace(op, id=f"o{i}") for i, op in enumerate(seq)]


def _role_of(ir: HarnessIR, op: Op) -> str:
    api = ir.apis.get(op.api)
    return api.role if api else ROLE_QUERY


def _window(ir: HarnessIR) -> tuple:
    """Where a new call may legally go: after the last create, before the first destroy.

    Outside that window the object either does not exist yet or has already been released,
    and the gates would reject the candidate anyway -- cheaply, but there is no reason to
    generate what we know is invalid.
    """
    last_create, first_destroy = -1, len(ir.sequence)
    for i, op in enumerate(ir.sequence):
        r = _role_of(ir, op)
        if r == ROLE_CREATE:
            last_create = i
        if r == ROLE_DESTROY and first_destroy == len(ir.sequence):
            first_destroy = i
    return last_create + 1, first_destroy


def _slice_is_terminated(ir, slice_id: str) -> bool:
    sl = ir.slice_by_id(slice_id)
    return bool(sl is not None and getattr(sl, "is_nul_terminated", False))


def _looks_like_a_length(name: str) -> str:
    n = (name or "").lower()
    return any(k in n for k in ("len", "size", "count", "nbyte", "num"))


def _base_type(name: str) -> str:
    """`const json_t *` -> `json_t`. Qualifiers and indirection are not identity."""
    t = (name or "").replace("*", " ")
    for q in ("const", "volatile", "struct", "unsigned", "signed"):
        t = t.replace(q + " ", " ")
    return t.strip().split()[0] if t.strip() else ""


def _satisfiable(api, ir: HarnessIR, live: list) -> Optional[list]:
    """Can this call be made from what the plan already has?

    Returns the argument list, or None. A parameter is satisfiable when it is a pointer we
    hold a resource for, a byte slice we can pass the input through, or a scalar we can
    pass a literal for. Anything else -- a callback, a struct by value, a type we have no
    instance of -- makes the whole call unsatisfiable, and it is dropped rather than
    guessed at.
    """
    args = []
    slice_id = ir.slices[0].id if ir.slices else None
    by_type = {_base_type(r.type.name): r.id for r in ir.resources if r.id in live}
    for p in api.params:
        kind = getattr(p.type, "kind", "")
        name = getattr(p.type, "name", "")
        base = _base_type(name)
        if kind == "pointer" and base in by_type:
            # THE TYPE MUST MATCH. The first version of this handed the most recent
            # resource to ANY pointer parameter, which is how 3600 jansson candidates were
            # generated and 99.3% of them correctly rejected: `json_object_set_new(json_t*,
            # const char*, json_t*)` was being passed a json_t for its key. Volume of
            # nonsense is not volume.
            args.append(Arg(p.name, SRC_RESOURCE, by_type[base]))
        elif kind == "pointer" and base == "void" and slice_id:
            args.append(Arg(p.name, SRC_INPUT, slice_id))
        elif kind == "pointer" and base == "char" and slice_id:
            # RAW FUZZER BYTES ARE NOT A C STRING -- BUT ONLY WHERE THE CONTRACT SAYS SO.
            #
            # Passing the slice to every `char *` produced 641 jansson candidates rejected
            # as S2.CSTRING: the slice carries no terminator, so the library reads past the
            # end of every input. Dropping every `char *` call instead cost 32 candidates
            # that were VALID, because not every char pointer is a C string -- some are
            # byte buffers with a length beside them.
            #
            # So the CONTRACT decides, which is the same source the gate consults, rather
            # than the spelling of the type.
            if p.name in getattr(api.contract, "nul_terminated", ()) \
                    and not _slice_is_terminated(ir, slice_id):
                return None
            args.append(Arg(p.name, SRC_INPUT, slice_id))
        elif kind == "scalar" and _looks_like_a_length(p.name) and slice_id:
            # A LENGTH MUST BE THE LENGTH OF ITS BUFFER. A literal 0 beside a real pointer
            # is an out-of-bounds access the harness caused -- 846 candidates, correctly
            # rejected as S2.LEN_SOURCE.
            args.append(Arg(p.name, SRC_LENGTH_OF, slice_id))
        elif kind == "scalar":
            args.append(Arg(p.name, SRC_LITERAL, value=0))
        else:
            return None
    return args


def synthesize(plans: list, *, max_per_plan: int = 40) -> tuple:
    """Widen a set of proposed plans into a larger candidate set.

    Returns `(candidates, stats)`. Candidates are IR, not verdicts: every one still has to
    survive the gates, and the rejection rate is the number this module is judged on.

    The catalogue is the UNION of the APIs across all proposed plans, which needs no extra
    parsing and is exactly the cross-entry-point surface the header graph declines to mix.
    """
    catalogue: dict = {}
    for p in plans:
        catalogue.update(p.apis)

    out, stats = [], {"base_plans": len(plans), "catalogue": len(catalogue),
                      "widen": 0, "repeat": 0}
    for base in plans:
        lo, hi = _window(base)
        called = {op.api for op in base.sequence}
        live = [r.id for r in base.resources]
        made = 0

        # WIDEN: call a function this plan does not, against the object it already holds.
        # Enumerated in sorted order so the candidate list is stable across runs.
        for sym in sorted(catalogue):
            if made >= max_per_plan:
                break
            if sym in called:
                # DECLARED IS NOT CALLED. Skipping every symbol the plan DECLARES skipped
                # the ones it merely knows about and never invokes -- which is exactly the
                # surface worth reaching. Only an actual call site disqualifies a symbol.
                continue
            api = catalogue[sym]
            if api.role in (ROLE_CREATE, ROLE_DESTROY):
                continue          # lifetimes belong to the base plan, not to a mutation
            args = _satisfiable(api, base, live)
            if args is None:
                continue
            # A NEW CALL INHERITS THE OBLIGATIONS OF WHAT IT TOUCHES.
            #
            # Inserting the call and stopping there produced candidates the gates rejected
            # 99% of the time -- 8704 S2.UNGUARDED_NONNULL and 2312 S6.UNCHECKED_ERROR on
            # jansson alone. Neither was the gates being strict: a plan that uses a handle
            # from a fallible producer without guarding it really does dereference the
            # failure value on a rejected input. The base producer emits those guards and
            # the mutation was not.
            #
            # So every resource the inserted call uses is named in its guarded_by, which is
            # exactly the fix both violations spell out.
            guards = [a.ref for a in args if a.source == SRC_RESOURCE and a.ref]
            seq = list(base.sequence)
            seq.insert(hi, Op(id="tmp", api=sym, args=args, guarded_by=guards))
            cand = replace(base, name=f"{base.name}__widen_{sym}",
                           apis={**base.apis, sym: api}, sequence=_renumber(seq))
            out.append(cand)
            stats["widen"] += 1
            made += 1

        # REPEAT: consume the same input twice. Re-entrancy and accumulated state are
        # reached by no other shape, and it is the cheapest mutation there is.
        for i, op in enumerate(base.sequence):
            if made >= max_per_plan:
                break
            if _role_of(base, op) != ROLE_CONSUME:
                continue
            seq = list(base.sequence)
            seq.insert(i + 1, replace(op, id="tmp",
                                      guarded_by=list(op.guarded_by)))
            out.append(replace(base, name=f"{base.name}__repeat_{op.api}",
                               sequence=_renumber(seq)))
            stats["repeat"] += 1
            made += 1

    stats["candidates"] = len(out)
    return out, stats
