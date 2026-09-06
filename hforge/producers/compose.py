"""Compose two lifted tests into one plan: parse in one, serialise in the other.

WHY. A lifted test can only be as good as the best single test function. jansson's `embed`
reaches 0.88x of the developer harness because it both loads and dumps; the suite has no other
test that does, and cjson's best is 0.85x for the same reason. The developer harness wins by
combining subsystems no single test combines. Composition is the only way past that ceiling,
and it is the FIRST thing in this line of work that invents a sequence rather than observing
one -- exactly where mutational synthesis died on libyaml, with every widened candidate
aborting on valid input. The smoke test and the gates are what keep it honest.

HOW. Plan A is parse-entered: it carries the seam, and its parser call produces a resource.
Plan B enters a different deep subsystem (serialise, transform). B's ops in that subsystem are
taken -- not B's own setup or teardown -- and the parameter that names B's handle is rebound to
A's parsed resource, by declared type. They are inserted just before A's final destroy of that
resource, so the value is live when they run and released once afterwards.

WHAT IS RECORDED. Which ops came from which test, which parameter was rebound and to what,
and how many of B's ops were left behind because their handle type did not match. A composed
plan that says none of this is a harness nobody can audit.
"""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Optional

from ..ir import Api, Arg, Contract, HarnessIR, Op, ParamDecl, Resource, TypeRef

PRODUCER = "compose"

_SUBSYSTEM = {
    "parse":     re.compile(r"(?:^|_)(load|loads|loadb|parse|read|decode|scan|deserial|"
                            r"unmarshal|from_)", re.I),
    "serialise": re.compile(r"(?:^|_)(dump|dumps|dumpb|write|encode|serial|marshal|print|"
                            r"emit|to_|save)", re.I),
    "transform": re.compile(r"(?:^|_)(compress|decompress|inflate|deflate|convert|transform|"
                            r"resize|scale|rotate|copy|dup|clone)", re.I),
    "validate": re.compile(r"(?:^|_)(equal|compare|validate|verify|check)(?:$|_)", re.I),
}


def _subsystem(sym: str) -> Optional[str]:
    for name, pat in _SUBSYSTEM.items():
        if pat.search(sym):
            return name
    return None


def _base(ty: str) -> str:
    return re.sub(r"\bconst\b|\*|\s+", " ", ty or "").strip()


def _deallocator_for(base_ty: str, decls: dict) -> str:
    """The library function that frees a value of this pointer type: *_decref / *_free /
    *_delete / *_destroy taking exactly that type. json_copy returns json_t*, which
    json_decref releases -- freeing it with free() would be a mismatched free. Returns the
    symbol, or '' (the caller uses free() for a raw char*/void* buffer)."""
    import re as _re
    for name, d in decls.items():
        if not _re.search(r"(?:^|_)(decref|unref|free|delete|destroy|release)(?:$|_|[A-Z])",
                          name):
            continue
        params = list(getattr(d, "params", []) or [])
        if len(params) == 1 and _base(params[0][0]) == base_ty:
            return name
    return ""


def _produced_resources(plan: HarnessIR, decls: dict) -> list:
    """Every (resource id, declared type) A produces AT OR AFTER its seam, latest first.

    The seam call is not always what produces the value worth handing on. jansson's
    json_loads returns the json_t* directly; libyaml's yaml_parser_set_input_string returns
    VOID and the document comes two calls later from yaml_parser_load(&parser, &document).
    Matching only the seam call's return type composed nothing for libyaml -- "none of B's
    calls takes a 'void'". So every resource bound after the seam is a candidate, typed from
    the producing call's return when it returns it and from the declared parameter when it
    fills an out-parameter, and B's calls are matched against all of them, latest first.
    """
    seam_slices = {s.id for s in plan.slices}
    start = None
    for i, op in enumerate(plan.sequence):
        if any(a.source == "input" and a.ref in seam_slices for a in op.args):
            start = i
            break
    if start is None:
        return []
    out: list = []
    for pos, op in enumerate(plan.sequence[start:]):
        if not op.binds:
            continue
        d = decls.get(op.api)
        rt = getattr(d, "ret", "") if d else ""
        ty = _base(rt) if rt and "*" in rt else ""
        if not ty and d is not None:
            # An out-parameter: the resource is what the pointer parameter points AT.
            for j, a in enumerate(op.args):
                if a.source == "resource" and a.ref == op.binds and j < len(d.params):
                    ty = _base(d.params[j][0])
                    break
        if ty and ty != "void":
            # (id, type, is_parse_output, position). A resource that is the DIRECT output of
            # a parse-subsystem call is the ROOT of the parsed value; anything else is derived
            # from it -- a looked-up child, a copy. Serialising the root covers the whole
            # tree, serialising a child covers one branch, which is why cjson composition
            # LOST when it rebound to r_found (GetObjectItem's result) instead of the root.
            out.append((op.binds, ty, _subsystem(op.api) == "parse", pos))
    return out


def _last_destroy_of(plan: HarnessIR, rid: str) -> int:
    idx = len(plan.sequence)
    for i, op in enumerate(plan.sequence):
        a = plan.apis.get(op.api)
        if a is not None and a.role == "destroy" and op.targets == rid:
            idx = i
    return idx


def compose(a: HarnessIR, b: HarnessIR, decls: dict, want: str = "serialise",
            first_only: bool = False, only_symbol: str = "") -> tuple:
    """Return (plan or None, record)."""
    rec = {"producer": PRODUCER, "a": a.name, "b": b.name, "subsystem": want,
           "taken_from_b": 0, "left_behind": 0, "rebound_param": None, "why_not": ""}
    prods = _produced_resources(a, decls)
    if not prods:
        rec["why_not"] = "plan A produces no typed resource at or after its seam"
        return None, rec
    if only_symbol:
        # Folding a SPECIFIC distinct function (json_deep_copy after json_copy). The
        # subsystem may already be present; what matters is that THIS symbol is not, because
        # a different traversal of the same subsystem is different code and adds coverage.
        if any(o.api == only_symbol for o in a.sequence):
            rec["why_not"] = f"{only_symbol} already in the plan"
            return None, rec
    elif any(_subsystem(o.api) == want for o in a.sequence):
        rec["why_not"] = f"plan A already enters '{want}' -- composition adds nothing"
        return None, rec

    taken, left = [], 0
    _obj_dtors: dict = {}
    for op in b.sequence:
        if only_symbol:
            if op.api != only_symbol:
                continue
        elif _subsystem(op.api) != want:
            continue
        d = decls.get(op.api)
        if d is None:
            left += 1
            continue
        # THE HANDLE PARAMETER, BY DECLARED TYPE. The first parameter whose base type is A's
        # parsed type gets A's resource; nothing else about B's call changes.
        # PREFER THE PARSE OUTPUT (the root), EARLIEST FIRST, then anything else latest
        # first. When B serialises, this hands it the whole parsed value rather than a child
        # of it; when B needs a resource a parser produced downstream (libyaml's document
        # from parser_load), that resource is still the parse output and is chosen.
        ranked = sorted(prods, key=lambda r: (not r[2], r[3] if r[2] else -r[3]))
        hit = None; rid = rtype = None
        for cand_rid, cand_ty, _is_parse, _pos in ranked:
            for j, (pty, _pn) in enumerate(d.params):
                if _base(pty) == cand_ty and j < len(op.args):
                    hit, rid, rtype = j, cand_rid, cand_ty
                    break
            if hit is not None:
                break
        if hit is None:
            left += 1
            continue
        # REBIND EVERY PARAMETER OF THE ROOT'S TYPE, not only the first. json_equal(a, b)
        # takes two json_t* -- binding one to the parsed root and leaving the other as B's
        # own resource left that second argument dangling (S1.UNKNOWN_RESOURCE, caught by the
        # gate). Both now point at the parsed value: equal(root, root) exercises the
        # comparator's full traversal on the parsed tree, which is the coverage we want.
        args = list(op.args)
        for j, (pty, _pn) in enumerate(d.params):
            if j < len(args) and _base(pty) == rtype:
                args[j] = Arg(args[j].param, "resource", rid)
        # A SERIALISER THAT RETURNS A POINTER RETURNS SOMETHING THAT MUST BE FREED.
        #
        # json_dumps returns a malloc'd char*. In B's test it was assigned to a variable the
        # lifter dropped, so the taken op bound nothing, and the first composed harness leaked
        # that string on EVERY input -- LeakSanitizer would have flagged the harness itself
        # and every later finding would have been our own. The op now binds a fresh resource
        # and a free() is appended for it.
        binds = op.binds
        rt = _base(getattr(d, "ret", "") or "")
        dtor_sym = ""
        if not binds and "*" in (getattr(d, "ret", "") or ""):
            if rt in ("char", "void", "unsigned char"):
                binds = f"r_c{len(taken)}"          # raw buffer -> free()
            else:
                # A library object the call ALLOCATED (json_copy -> json_t*). Bind it and
                # release it with the type's own deallocator, not free().
                dtor_sym = _deallocator_for(rt, decls)
                if dtor_sym:
                    binds = f"r_o{len(taken)}"
                    _obj_dtors[binds] = (dtor_sym, rt)
        taken.append(replace(op, args=args, id=f"c{len(taken)}", binds=binds,
                             guarded_by=[g for g in (op.guarded_by or []) if g == rid]))
        rec["rebound_param"] = d.params[hit][1] or f"a{hit}"
        if first_only:
            # ONE representative call per subsystem. A lifted test may call json_copy seven
            # times reusing one variable; folding all seven binds one resource seven times
            # and trails six decrefs -- DOUBLE_DESTROY, which the gate rightly refuses. For a
            # chain, one call of each subsystem on the parsed root is the harness we want.
            break
    rec["taken_from_b"], rec["left_behind"] = len(taken), left
    if not taken:
        rec["why_not"] = (f"none of B's '{want}' calls takes any of "
                          f"{sorted({t for _, t, _p, _q in prods})} -- nothing to rebind")
        return None, rec
    rec["rebound_resource"] = rid
    cut = _last_destroy_of(a, rid)
    seq = list(a.sequence[:cut]) + taken + list(a.sequence[cut:])
    # B's ops that bind resources need those resources declared, and their APIs known.
    apis = dict(a.apis)
    apis.update({o.api: b.apis[o.api] for o in taken if o.api in b.apis})
    res = list(a.resources)
    have = {r.id for r in res}
    for o in taken:
        if o.binds and o.binds not in have:
            src = next((r for r in b.resources if r.id == o.binds), None)
            if src is not None:
                res.append(src); have.add(o.binds)
    # Release what B's calls allocated, after A's own teardown: B's own destroy if it had one,
    # else a plain free() for a pointer we bound ourselves.
    for o in taken:
        if not o.binds:
            continue
        dtor = next((x for x in b.sequence
                     if b.apis.get(x.api) is not None and b.apis[x.api].role == "destroy"
                     and x.targets == o.binds), None)
        if dtor is not None:
            seq.append(replace(dtor, id=f"cd{o.binds}"))
            apis.setdefault(dtor.api, b.apis[dtor.api])
        elif o.binds in _obj_dtors:
            # A library object the taken call allocated: release it with the type's own
            # deallocator (json_copy -> json_decref), so the composed harness does not leak
            # the copy and does not mismatched-free it.
            dsym, dty = _obj_dtors[o.binds]
            if o.binds not in have:
                res.append(Resource(o.binds, TypeRef(dty + " *", "pointer")))
                have.add(o.binds)
            apis.setdefault(dsym, Api(symbol=dsym, header="",
                                      role="destroy",
                                      params=[ParamDecl("o", TypeRef(dty + " *", "pointer"))],
                                      returns=TypeRef("void", "scalar"), contract=Contract()))
            seq.append(Op(f"cd{o.binds}", dsym, [Arg("o", "resource", o.binds)],
                          binds="", targets=o.binds, guarded_by=[o.binds]))
        elif o.binds.startswith("r_c"):
            if o.binds not in have:
                res.append(Resource(o.binds, TypeRef("char *", "pointer"))); have.add(o.binds)
            apis.setdefault("free", Api(symbol="free", header="stdlib.h", role="destroy",
                                        params=[ParamDecl("p", TypeRef("void *", "pointer"))],
                                        returns=TypeRef("void", "scalar"), contract=Contract()))
            seq.append(Op(f"cd{o.binds}", "free", [Arg("p", "resource", o.binds)],
                          binds="", targets=o.binds, guarded_by=[o.binds]))
    plan = replace(a, name=f"{a.name}__with_{want}_from_{b.name}"[:60], sequence=seq,
                   apis=apis, resources=res, producer=PRODUCER)
    return plan, rec


def compose_chain(a: HarnessIR, pool_by_subsystem: dict, decls: dict,
                  wants: tuple = ("serialise", "transform", "validate")) -> tuple:
    """Fold ONE call from each downstream subsystem onto A's parsed root, in turn.

    Two-test composition matched the developer harness where the suite already had a rich
    integrated test (cjson) and beat the best single test where it did not (jansson). To
    EXCEED the developer harness -- OGHarn's +14% bar is over the human harness, not the best
    single test -- the composed harness must exercise MORE subsystems than the human combined.
    This chains a serialise, a transform and a validate call (whichever the pool provides)
    onto the same parsed value, so one harness parses the fuzzer's bytes and then dumps,
    transforms and compares them.

    `pool_by_subsystem` maps a subsystem name to a list of candidate B plans that enter it.
    Each fold is the existing two-test compose(), which rebinds to the parse root and inserts
    before the final destroy; composing a second subsystem onto the result is legal because
    compose() only refuses a subsystem A ALREADY enters, and each fold enters a new one.
    """
    rec = {"producer": PRODUCER, "base": a.name, "folded": [], "skipped": []}
    plan = a
    for want in wants:
        folded = False
        for b in pool_by_subsystem.get(want, []):
            cand, r = compose(plan, b, decls, want=want, first_only=True)
            if cand is not None:
                plan = cand
                rec["folded"].append({"subsystem": want, "from": r.get("b"),
                                      "rebound": r.get("rebound_resource")})
                folded = True
                break
        if not folded:
            rec["skipped"].append(want)
    rec["subsystems_added"] = len(rec["folded"])
    return (plan if rec["folded"] else None), rec


def compose_max(a: HarnessIR, pool_by_subsystem: dict, decls: dict) -> tuple:
    """Fold ONE call of EVERY DISTINCT downstream function that accepts the parsed root.

    The coverage lever is not the abstract subsystem -- it is each distinct traversal of the
    parsed structure. json_copy and json_deep_copy are both "transform" but different code
    (shallow vs recursive); json_dumps is another traversal again. compose_chain folded one
    per subsystem NAME and so took only one of copy/deep_copy. This folds one call of every
    distinct SYMBOL across serialise, transform and validate, maximising the number of
    distinct traversals a single harness runs on the parsed value -- which is what pushes
    coverage toward and past the developer harness.
    """
    seen: set = set()
    plan = a
    rec = {"producer": PRODUCER, "base": a.name, "folded": []}
    for want in ("serialise", "transform", "validate"):
        for b in pool_by_subsystem.get(want, []):
            sym = next((o.api for o in b.sequence if _subsystem(o.api) == want), None)
            if not sym or sym in seen:
                continue
            cand, r = compose(plan, b, decls, want=want, first_only=True, only_symbol=sym)
            if cand is not None and r.get("taken_from_b"):
                plan = cand
                seen.add(sym)
                rec["folded"].append({"subsystem": want, "symbol": sym})
    rec["distinct_folded"] = len(rec["folded"])
    return (plan if rec["folded"] else None), rec
