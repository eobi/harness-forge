"""P3.LIFT: turn a library's own unit test into a fuzzing harness plan.

THE MEASUREMENT THAT JUSTIFIES THIS. A library's tests reach a median 66.7% of its exported
surface; our widest generated plan for jansson reaches 3 of 83 functions, and mutational
synthesis -- the other candidate for widening the candidate space -- was measured at +0.40%
against OGHarn's +14% and is refuted. Tests express orderings no header states, which is
exactly what killed synthesis on libyaml: `yaml_parser_set_encoding` asserts
`!parser->encoding` and nothing in yaml.h says so.

THE TEST IS NEVER COMPILED. Its call SEQUENCE is lifted to IR and re-emitted as our own C, so
test frameworks, fixtures and helper linkage are irrelevant. The IR is the firewall, which is
the whole point of a proposer/prover split.

TWO THINGS ARE DROPPED, AND BOTH ARE RECORDED RATHER THAN DONE SILENTLY.

  Assertions. A test asserts expected values for FIXED input. Under fuzzing those values are
  meaningless, and an assertion that fires ABORTS -- which burns the entire campaign
  returning nothing. That is not hypothetical: all 8 top-ranked libyaml synthesis candidates
  died exactly that way.

  Calls the library does not export. Test-local helpers, stdio, framework entry points. A
  helper may itself call library APIs, so dropping it can LOSE real sequence; the plan
  records how many were dropped so a reader can see how much of the test survived.
"""
from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Optional

from ..ir import (
    SLICE_BYTES,
    TypeRef,
    SLICE_CSTRING,
    Arg,
    HarnessIR,
    InputSlice,
    Knobs,
    Target,
)
from ..lift.c_harness import LiftError, lift

PRODUCER = "test_lift"

# Calls that are the TEST TALKING, not the library working.
_SCAFFOLD = re.compile(
    r"^(assert\w*|ck_assert\w*|fail\w*|expect\w*|EXPECT_\w+|ASSERT_\w+|REQUIRE\w*|"
    r"CHECK\w*|printf|fprintf|sprintf|snprintf|puts|fputs|fwrite|exit|abort|"
    r"perror|strcmp|strncmp|memcmp|free|malloc|calloc|realloc)$", re.I)


def _is_scaffold(sym: str) -> bool:
    return bool(_SCAFFOLD.match(sym or ""))


# `static inline` DEFINITIONS IN A PUBLIC HEADER ARE PART OF THE API.
#
# jansson declares its reference-count release as
# `static JSON_INLINE void json_decref(json_t *json)` inside jansson.h. parse_header returns
# DECLARATIONS, so json_decref is invisible to the engine -- and the first lifted plan
# dropped all four of decode_any's json_decref calls as "not a library call", turning a
# correct test into a harness that leaks a json_t on every input.
#
# Scoped to P3.LIFT on purpose. Teaching parse_header to return these would change what every
# producer proposes and would invalidate the recorded corpus, compile rate and audit numbers,
# so it is recorded as a separate gap rather than fixed in passing here.
_INLINE_DEF = re.compile(
    r"^\s*static\s+((?:[A-Za-z_]\w*\s+|\*)*?)([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.M)


def inline_api(headers: list) -> dict:
    """{name: return_type} for functions DEFINED static-inline in the library's headers.

    The RETURN TYPE matters as much as the name. json_decref returns void, and without that
    the emitter wrote `hf_sink += (long)json_decref(json)` -- casting void to long, which
    does not compile. A name alone would have produced a plan that no build could use.
    """
    out: dict = {}
    for h in headers or []:
        try:
            txt = Path(h).read_text(errors="replace")
        except OSError:
            continue
        for pre, name in _INLINE_DEF.findall(txt):
            words = [w for w in pre.split() if w not in ("inline",) and not w.isupper()]
            out[name] = " ".join(words).strip() or "void"
    return out


def propose(path: str, entry: str, decls: dict, seam: Optional[dict] = None,
            target_name: str = "", headers: Optional[list] = None,
            also_api: Optional[set] = None) -> tuple:
    """Lift one test into a plan. Returns (HarnessIR or None, record).

    `decls` is {symbol: Decl} from the library's public header -- the authority on what is a
    library call and what is the test's own scaffolding. Without it every helper would be
    treated as part of the API under test.
    """
    rec = {"file": Path(path).name, "entry": entry, "status": "ok",
           "ops_lifted": 0, "ops_kept": 0, "dropped_assertions": 0,
           "dropped_non_library": 0, "seam": None, "why_not": ""}
    try:
        lifted = lift(path, target_name=target_name or Path(path).stem, entry=entry)
    except (LiftError, Exception) as ex:                            # noqa: BLE001
        rec["status"] = "lift-failed"
        rec["why_not"] = f"{type(ex).__name__}: {str(ex)[:120]}"
        return None, rec

    ir = lifted.ir
    rec["ops_lifted"] = len(ir.sequence)
    inline_ret = dict(also_api or {}) if isinstance(also_api, dict) else {}
    api_names = set(decls) | set(inline_ret) | (
        set(also_api) if not isinstance(also_api, dict) else set())
    kept, dropped_assert, dropped_alien = [], 0, 0
    for op in ir.sequence:
        if op.api in api_names:
            kept.append(op)
        elif _is_scaffold(op.api):
            dropped_assert += 1
        else:
            dropped_alien += 1
    rec["dropped_assertions"] = dropped_assert
    rec["dropped_non_library"] = dropped_alien
    rec["ops_kept"] = len(kept)

    if not kept:
        rec["status"] = "no-library-calls"
        rec["why_not"] = "every call in this test is scaffolding or a test-local helper"
        return None, rec

    # THE SEAM. Without one the plan calls the library with the test's own fixed values and
    # the fuzzer drives nothing -- S5.INPUT_NOT_CONSUMED, and correctly refused.
    slices: list = []
    if seam:
        api_sym, pidx = seam["api"], seam["param_index"]
        d = decls.get(api_sym)
        tgt = next((o for o in kept if o.api == api_sym), None)
        if d is None or tgt is None or pidx >= len(d.params):
            rec["status"] = "seam-not-in-plan"
            rec["why_not"] = f"{api_sym} is not among the calls this test makes"
            return None, rec
        # POSITION, NOT NAME. The header calls json_loads' first parameter `input`; the lift
        # saw a call site with no names and called it `a0`. Matching on the name substituted
        # nothing at all and emitted `json_loads(0, 0, &err)` -- a harness that compiles,
        # runs, and feeds the parser a literal zero. The same mismatch cost the audit its
        # contract gates until it was fixed there too.
        if pidx >= len(tgt.args):
            rec["status"] = "seam-arity-mismatch"
            rec["why_not"] = (f"{api_sym} is declared with {len(d.params)} parameter(s) but "
                              f"the lifted call has {len(tgt.args)} argument(s)")
            return None, rec
        pname = tgt.args[pidx].param
        # A (buffer, length) pair takes raw bytes; a lone pointer must be terminated, or the
        # library reads past the end of every input. Same rule the header_graph producer uses.
        lname = ""
        for j, (jty, jnm) in enumerate(d.params):
            if j == pidx or "*" in jty or j >= len(tgt.args):
                continue
            if re.match(r"^(size_t|unsigned|int|long)", jty.strip()) and jnm and \
                    re.search(r"(len|size|count|n)$", jnm, re.I):
                lname = tgt.args[j].param        # positional, for the same reason
                break
        sid = "s_seam"
        slices.append(InputSlice(sid, SLICE_BYTES if lname else SLICE_CSTRING,
                                 remainder=True, min_len=1))
        # EVERY call of the seam API that still holds a literal there, not just the first.
        #
        # decode_any calls json_loads four times with four different literals. Substituting
        # only the first left three calls reading `json_loads(0, 0, &err)` -- the fuzzer
        # driving one quarter of the parse calls and a literal zero driving the rest.
        n_sub = 0
        newkept = []
        for o in kept:
            if o.api != api_sym or pidx >= len(o.args):
                newkept.append(o)
                continue
            if o.args[pidx].source != "literal":
                newkept.append(o)
                continue
            na = []
            for j, a in enumerate(o.args):
                if j == pidx:
                    na.append(Arg(a.param, "input", sid))
                elif lname and a.param == lname:
                    na.append(Arg(a.param, "length_of", sid))
                else:
                    na.append(a)
            newkept.append(replace(o, args=na))
            n_sub += 1
        kept = newkept
        rec["seam_substitutions"] = n_sub
        rec["seam"] = {"api": api_sym, "param": pname, "length_param": lname or None,
                       "slice_kind": SLICE_BYTES if lname else SLICE_CSTRING,
                       "replaced_literal": seam.get("literal")}

    # LIFT-INTERNAL MARKERS ARE NOT GUARDS. The lifter annotates ops with `__refills:`,
    # `__exits:`, `__guard:` and `__cleared:` to carry facts the gates read. The emitter has
    # never seen them on this path and wrote them straight into the C: `if
    # (hf_r___refills:r_error)`, which is not an expression. They are stripped here, and the
    # count is recorded -- dropping a real guard would make an op run unconditionally, and a
    # reader is entitled to know how many were removed.
    _markers = 0
    cleaned = []
    for o in kept:
        gb = [g for g in (o.guarded_by or []) if not g.startswith("__")]
        _markers += len(o.guarded_by or []) - len(gb)
        cleaned.append(replace(o, guarded_by=gb) if gb != (o.guarded_by or []) else o)
    kept = cleaned
    rec["stripped_markers"] = _markers

    # THE HEADER IS THE LIBRARY'S, NEVER THE TEST'S. The lifter records where it SAW each
    # call, which for a lifted test is the test file -- and the emitter faithfully wrote
    # `#include "test_load.c"`, a harness that tries to compile the test suite it came from.
    # The test is never compiled; only its sequence travels.
    apis = {k: replace(a, header=(hdrs0[0] if (hdrs0 := list(headers or [])) else ""))
            for k, a in ir.apis.items()}

    # THE HEADER'S RETURN TYPE, FOR EVERY API -- not only the static-inline ones.
    #
    # The lift reads call sites, which do not state return types, so its Api carries a
    # default. Overriding that only for inline definitions fixed jansson's json_decref and
    # left every NORMALLY declared void function broken: cjson's cJSON_AddItemToObject is
    # `void`, and the emitter wrote `hf_sink += (long)cJSON_AddItemToObject(...)` --
    # "operand of type 'void' where arithmetic or pointer type is required". All four cjson
    # candidates died at build for that one reason.
    for nm, d in decls.items():
        a = apis.get(nm)
        rt = getattr(d, "ret", "") or ""
        if a is not None and rt:
            apis[nm] = replace(a, returns=TypeRef(
                rt, "pointer" if "*" in rt else "scalar"))
    for nm, rt in inline_ret.items():
        a = apis.get(nm)
        if a is not None and rt:
            apis[nm] = replace(a, returns=TypeRef(rt, "scalar" if "*" not in rt else
                                                  "pointer"))

    # RESOURCE TYPES COME FROM THE HEADER, not from the lift.
    #
    # The lifter types every resource `void *` -- it reads call sites, which do not state
    # types. That is fine for grading a harness and useless for emitting one: the first build
    # failed on `passing 'void **' to parameter of type 'json_error_t *'`. The declaration
    # knows, so each resource takes the type of the parameter it is passed to, with one
    # pointer level removed when the harness owns the storage and passes its address.
    rtypes: dict = {}
    for op in kept:
        d = decls.get(op.api)
        if d is None:
            continue
        for j, arg in enumerate(op.args):
            if arg.source != "resource" or not arg.ref or j >= len(d.params):
                continue
            rtypes.setdefault(arg.ref, d.params[j][0])
    res_out = []
    for r in ir.resources:
        ty = rtypes.get(r.id)
        if not ty:
            res_out.append(r)
            continue
        if r.storage == "inline" and ty.count("*") >= 1:
            ty = ty.replace("*", "", 1).strip()
        res_out.append(replace(r, type=TypeRef(
            ty, "pointer" if "*" in ty else "struct")))

    hdrs = headers or []
    plan = HarnessIR(
        name=f"{target_name or Path(path).stem}_{entry}"[:60],
        target=Target(name=target_name or Path(path).stem, public_headers=list(hdrs)),
        apis=apis,
        slices=slices,
        resources=res_out,
        sequence=kept,
        knobs=Knobs(),
        platforms=["linux-x86_64-glibc"],
        producer=PRODUCER,
    )
    return plan, rec
