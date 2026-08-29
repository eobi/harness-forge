"""Static gates — run on the plan, before a compiler exists.

This is where Harness Forge goes past the published work. The Four Principles framework
probes a *compiled* harness with reach and run checks; but lifetime correctness, protocol
compliance and call ordering are properties of the plan, and checking a plan is strictly
stronger than checking one execution of a binary built from it.

Six gates, mapped to the published correctness principles:

  S1  lifetime          resources created once, destroyed once, never used after   P1
  S2  contract          NUL-termination, (ptr,len) pairs, ownership, non-null      P2
  S3  ordering          create before use before destroy                           P2
  S4  boundary          public headers only; no internal-symbol bypass             P3
  S5  input flow        every slice is consumed; the target actually sees input    P4
  S6  error handling    failure returns are checked before dependent use           P1

S2 is the one that pays for the whole module. Feeding an exact-size buffer to an API whose
contract requires NUL termination makes *every* input a crash, which is how a cJSON harness
in LAB-07 produced eight false findings against a library that was behaving correctly. That
defect is visible in the plan without building anything.

Pure functions of a HarnessIR. No I/O, no subprocess, no model.
"""
from __future__ import annotations

import re

from ..ir import (
    SOURCES, SRC_SCRATCH, SRC_SCRATCH_ADDR,
    HarnessIR, Op, ROLE_CREATE, ROLE_DESTROY, ROLE_CONSUME, ROLE_QUERY, ROLE_RESET,
    SRC_INPUT, SRC_RESOURCE, SRC_LENGTH_OF, SRC_LITERAL, SRC_OUT, ROLES, SLICE_KINDS,
)
from .result import BLOCK, WARN, INFO, GateResult, Violation, decide, passed

ALL_STATIC = ("S1", "S2", "S3", "S4", "S5", "S6")


# ── S1 — lifetime ─────────────────────────────────────────────────────────────

def s1_lifetime(ir: HarnessIR) -> GateResult:
    """Every resource is created exactly once, destroyed exactly once, and never touched
    after destruction. A stale handle in the plan is a use-after-free in the harness, and
    the crash it produces belongs to us, not to the target."""
    v: list[Violation] = []
    UNBORN, ALIVE, DEAD = 0, 1, 2
    # A CALLER-DECLARED OUT SLOT IS ALIVE FROM ITS DECLARATION.
    #
    # `json_error_t err; json_loadb(buf, n, 0, &err);` — the harness declares and zeroes it
    # and the LIBRARY fills it. No call creates it, so scoring it UNBORN reported
    # S1.USE_BEFORE_CREATE against a correct plan, and jansson's only entry point was
    # refused. There is also nothing to destroy: it is storage, not a lifetime the library
    # manages. The IR says which kind it is; the gate reads that rather than inferring it.
    state = {r.id: (ALIVE if r.storage == "out" else UNBORN) for r in ir.resources}
    born_at: dict[str, str] = {}

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue

        # uses first: an argument referencing a resource requires it to be alive.
        #
        # Except for the op that CREATES a caller-allocated resource, which necessarily
        # references it — `yaml_parser_initialize(&parser)` receives the very object it is
        # about to initialise. That is the creation, not a use before it. The storage
        # already exists in both cases; what the initialiser establishes is that the object
        # is usable, and every rule after this one is unchanged.
        # `by_address` covers both forms that hand the resource to its own constructor:
        # a caller-allocated object (`yaml_parser_initialize(&p)`) and an out-parameter
        # constructor (`sqlite3_open(name, &db)`). Keying this on the caller-allocated case
        # alone left every sqlite3 plan blocked as use-before-create.
        inline_self_init = ({r.id for r in ir.resources if r.by_address}
                            & ({op.binds} - {""}))

        for a in op.args:
            if a.source != SRC_RESOURCE or not a.ref:
                continue
            if a.ref in inline_self_init:
                continue
            if a.ref not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} uses undeclared resource {a.ref!r}",
                                   where=op.id, principle="P1",
                                   fix=f"declare {a.ref!r} in resources[]"))
            elif state[a.ref] == UNBORN:
                v.append(Violation("S1.USE_BEFORE_CREATE", BLOCK,
                                   f"op {op.id} uses {a.ref!r} before anything creates it",
                                   where=op.id, principle="P1"))
            elif state[a.ref] == DEAD:
                v.append(Violation("S1.USE_AFTER_DESTROY", BLOCK,
                                   f"op {op.id} uses {a.ref!r} after it was destroyed"
                                   f" (a use-after-free in the harness itself)",
                                   where=op.id, principle="P1",
                                   fix="move the destroy after the last use"))

        if op.binds:
            if op.binds not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} binds undeclared resource {op.binds!r}",
                                   where=op.id, principle="P1"))
            elif state[op.binds] != UNBORN:
                v.append(Violation("S1.DOUBLE_CREATE", BLOCK,
                                   f"resource {op.binds!r} is created twice "
                                   f"(first at {born_at.get(op.binds)}, again at {op.id}); "
                                   f"the first is leaked",
                                   where=op.id, principle="P1"))
            else:
                state[op.binds] = ALIVE
                born_at[op.binds] = op.id
            if api.role != ROLE_CREATE:
                v.append(Violation("S1.BIND_NON_CREATE", WARN,
                                   f"op {op.id} binds a resource but {api.symbol} is declared "
                                   f"role={api.role!r}, not {ROLE_CREATE!r}",
                                   where=op.id, principle="P2"))

        if op.targets:
            if op.targets not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} destroys undeclared resource {op.targets!r}",
                                   where=op.id, principle="P1"))
            elif state[op.targets] == UNBORN:
                v.append(Violation("S1.DESTROY_BEFORE_CREATE", BLOCK,
                                   f"op {op.id} destroys {op.targets!r} before it exists",
                                   where=op.id, principle="P1"))
            elif state[op.targets] == DEAD:
                v.append(Violation("S1.DOUBLE_DESTROY", BLOCK,
                                   f"resource {op.targets!r} is destroyed twice; the second "
                                   f"is a double free attributable to the harness",
                                   where=op.id, principle="P1"))
            else:
                state[op.targets] = DEAD

    for rid, st in state.items():
        if st == ALIVE:
            v.append(Violation("S1.LEAK", BLOCK if ir.knobs.detect_leaks else WARN,
                               f"resource {rid!r} is still alive when the harness returns; "
                               f"under LeakSanitizer every input reports a leak and real "
                               f"findings drown in it",
                               where=rid, principle="P1",
                               fix="add a destroy op, or disable leak detection deliberately "
                                   "and record that you did"))
        elif st == UNBORN:
            v.append(Violation("S1.UNUSED_RESOURCE", INFO,
                               f"resource {rid!r} is declared and never created",
                               where=rid, principle="P1"))

    return decide("S1", "lifetime: created once, destroyed once, never used after", v,
                  resources=len(ir.resources), ops=len(ir.sequence))


# ── S2 — contract ─────────────────────────────────────────────────────────────

# Pointer targets a fuzzer may legitimately fill with raw bytes. Everything else is a
# structured object the library will dereference field by field.
_BYTE_TARGETS = {"void", "char", "unsigned char", "signed char", "uint8_t", "int8_t",
                 "xmlChar", "byte", "u_char"}


# Library spellings of "a byte". Kept beside _BYTE_TARGETS rather than imported from the
# producer, because a gate must not depend on the thing it judges.
_BYTE_TYPEDEFS = frozenset({
    "Bytef", "Byte", "uch", "u8", "U8", "UInt8", "uint8", "guint8", "gchar",
    "xmlChar", "JOCTET", "png_byte", "Uint8", "uchar", "u_char",
})


def _points_to_bytes(type_name: str, resolved: str = "") -> bool:
    """A single pointer to a byte-sized type, and nothing else.

    The star count matters. `char **` is not a buffer of bytes — it is a pointer to a
    pointer, almost always an out-parameter the library writes (`sqlite3_exec`'s `errmsg`).
    Stripping every `*` before the comparison made `char **` look like `char *`, so fuzzer
    bytes were bound to it and the library would write through an address made of input.
    """
    t = re.sub(r"\b(const|volatile|struct|restrict|__restrict)\b", " ", type_name)
    if t.count("*") != 1:
        return False
    base = " ".join(t.replace("*", " ").split())
    # The IR may state what a typedef bottoms out in. `const l_uint8 *` is a byte buffer and
    # only leptonica's own header says so; without this the gate refuses the one correct
    # harness for pixReadMem. Still independent: the gate reads a fact RECORDED IN THE
    # ARTIFACT, which is printed and auditable, not a claim passed from the producer.
    if resolved and resolved in _BYTE_TARGETS:
        return True
    if base in _BYTE_TARGETS:
        return True
    # A library that typedefs its byte is still handing you bytes. zlib's `const Bytef *`
    # was read as a structured pointer, so S2 refused the only correct binding for
    # `uncompress2` — the gate blocking the fix rather than the mistake.
    return base in _BYTE_TYPEDEFS


def s2_contract(ir: HarnessIR) -> GateResult:
    """The API's stated requirements versus what the plan actually feeds it."""
    v: list[Violation] = []
    checked = 0

    # Type confusion: fuzzer bytes bound to a pointer the library will DEREFERENCE.
    #
    # Found in a proposed libyaml harness, which cast the input straight to a structured
    # type:
    #
    #     yaml_document_get_node((yaml_document_t *)hf_s_document, 0)
    #
    # That harness crashes on almost every input, and every crash is the harness's own
    # invalid pointer rather than a defect in the library. It is the single largest source
    # of false findings in the published literature, and it is decidable from the plan — no
    # compiler, no campaign, no crash triage required.
    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue
        for a in op.args:
            if a.source != SRC_INPUT:
                continue
            pd = ir.param_decl(api, a.param)
            if pd is None or "*" not in pd.type.name:
                continue
            checked += 1
            if not _points_to_bytes(pd.type.name, pd.type.resolved):
                v.append(Violation(
                    "S2.TYPE_CONFUSION", BLOCK,
                    f"op {op.id}: parameter {a.param!r} of {api.symbol} has type "
                    f"{pd.type.name!r}, and the plan fills it with raw fuzzer bytes. The "
                    f"library will dereference that as a real object, so EVERY crash is the "
                    f"harness's own invalid pointer and not a defect in the target.",
                    where=op.id, principle="P2",
                    fix=f"drive {api.symbol} through the API that BUILDS a "
                        f"{pd.type.name.replace('*','').strip()} from bytes, or bind "
                        f"{a.param!r} to a resource the plan constructs, or drop this "
                        f"entry point: it does not consume serialised input"))

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            v.append(Violation("S2.UNKNOWN_API", BLOCK,
                               f"op {op.id} calls {op.api!r}, which is not declared in apis[]",
                               where=op.id, principle="P2"))
            continue

        by_param = {a.param: a for a in op.args}

        # every declared parameter must be supplied
        for pd in api.params:
            if pd.name not in by_param:
                v.append(Violation("S2.MISSING_ARG", BLOCK,
                                   f"op {op.id} omits parameter {pd.name!r} of {api.symbol}",
                                   where=op.id, principle="P2"))
        for a in op.args:
            if ir.param_decl(api, a.param) is None:
                v.append(Violation("S2.UNKNOWN_PARAM", BLOCK,
                                   f"op {op.id} passes {a.param!r}, which {api.symbol} does "
                                   f"not declare", where=op.id, principle="P2"))
            if a.source not in SOURCES:
                v.append(Violation("S2.BAD_SOURCE", BLOCK,
                                   f"op {op.id} arg {a.param!r} has unknown source "
                                   f"{a.source!r}", where=op.id, principle="P2"))
            if a.source == SRC_INPUT and ir.slice_by_id(a.ref) is None:
                v.append(Violation("S2.UNKNOWN_SLICE", BLOCK,
                                   f"op {op.id} arg {a.param!r} references undeclared slice "
                                   f"{a.ref!r}", where=op.id, principle="P2"))

        # ── the one that matters: NUL termination ──
        for pname in api.contract.nul_terminated:
            checked += 1
            a = by_param.get(pname)
            if a is None:
                continue
            if a.source == SRC_LITERAL:
                continue  # a C string literal is terminated by construction
            if a.source != SRC_INPUT:
                v.append(Violation("S2.CSTRING_SOURCE", WARN,
                                   f"op {op.id}: {api.symbol} requires {pname!r} to be "
                                   f"NUL-terminated but it comes from {a.source!r}; "
                                   f"termination cannot be checked here",
                                   where=op.id, principle="P2"))
                continue
            sl = ir.slice_by_id(a.ref)
            if sl is None:
                continue
            if not sl.is_nul_terminated:
                v.append(Violation(
                    "S2.CSTRING", BLOCK,
                    f"op {op.id}: {api.symbol} requires {pname!r} to be NUL-terminated, but "
                    f"slice {sl.id!r} is kind={sl.kind!r} and adds no terminator. The library "
                    f"will read past the end of EVERY input, so every input becomes a crash "
                    f"and every finding is the harness's own.",
                    where=op.id, principle="P2",
                    fix=f"set slice {sl.id!r} kind to 'cstring', or call the "
                        f"length-delimited variant of {api.symbol} instead"))

        # ── (ptr, len) pairs must agree ──
        for pair in api.contract.length_delimited:
            checked += 1
            if len(pair) != 2:
                v.append(Violation("S2.BAD_PAIR", BLOCK,
                                   f"{api.symbol}: length_delimited entry {pair!r} is not a "
                                   f"(pointer, length) pair", where=op.id, principle="P2"))
                continue
            pptr, plen = pair
            ap, al = by_param.get(pptr), by_param.get(plen)
            if ap is None or al is None:
                continue
            if ap.source == SRC_INPUT:
                if al.source != SRC_LENGTH_OF:
                    v.append(Violation(
                        "S2.LEN_SOURCE", BLOCK,
                        f"op {op.id}: {plen!r} must be the length of {pptr!r}, but it is "
                        f"sourced as {al.source!r}. A length that does not match its buffer "
                        f"is an out-of-bounds access the harness caused.",
                        where=op.id, principle="P2",
                        fix=f"set {plen!r} to source 'length_of' with ref {ap.ref!r}"))
                elif al.ref != ap.ref:
                    v.append(Violation(
                        "S2.LEN_MISMATCH", BLOCK,
                        f"op {op.id}: {plen!r} is the length of slice {al.ref!r} but {pptr!r} "
                        f"points at slice {ap.ref!r}. Mismatched pair.",
                        where=op.id, principle="P2"))
            if ap.source == SRC_INPUT:
                sl = ir.slice_by_id(ap.ref)
                if sl is not None and sl.is_nul_terminated:
                    v.append(Violation(
                        "S2.CSTRING_TO_LEN_API", INFO,
                        f"op {op.id}: slice {sl.id!r} is NUL-terminated but {api.symbol} takes "
                        f"an explicit length; the terminator is harmless here but the extra "
                        f"byte is never tested",
                        where=op.id, principle="P2"))

        # ── non-null ──
        for pname in api.contract.requires_nonnull:
            checked += 1
            a = by_param.get(pname)
            if a is None:
                continue
            if a.source == SRC_LITERAL and a.value in (None, 0, "NULL"):
                v.append(Violation("S2.NULL_ARG", BLOCK,
                                   f"op {op.id}: {api.symbol} requires {pname!r} to be "
                                   f"non-null and the plan passes NULL",
                                   where=op.id, principle="P2"))
            if a.source == SRC_RESOURCE and a.ref and a.ref not in op.guarded_by:
                producer = next((o for o in ir.sequence if o.binds == a.ref), None)
                if producer is not None:
                    papi = ir.api_of(producer)
                    if papi and papi.contract.error_return in ("null", "negative", "zero"):
                        v.append(Violation(
                            "S2.UNGUARDED_NONNULL", BLOCK,
                            f"op {op.id}: {api.symbol} requires {pname!r} non-null, and "
                            f"{a.ref!r} comes from {papi.symbol} which signals failure by "
                            f"returning {papi.contract.error_return!r}. Unguarded.",
                            where=op.id, principle="P1",
                            fix=f"add {a.ref!r} to guarded_by on op {op.id}"))

        # ── ownership ──
        for pname in api.contract.transfers_ownership:
            a = by_param.get(pname)
            if a is None or a.source != SRC_RESOURCE or not a.ref:
                continue
            later = ir.sequence[ir.sequence.index(op) + 1:]
            if any(o.targets == a.ref for o in later):
                v.append(Violation(
                    "S2.DOUBLE_FREE_OWNERSHIP", BLOCK,
                    f"op {op.id}: {api.symbol} takes ownership of {a.ref!r}, but a later op "
                    f"destroys it as well. That is a double free the harness performed.",
                    where=op.id, principle="P2",
                    fix=f"remove the later destroy of {a.ref!r}"))

    return decide("S2", "contract: NUL-termination, (ptr,len) pairs, ownership, non-null", v,
                  contract_clauses_checked=checked)


# ── S3 — ordering ─────────────────────────────────────────────────────────────

def s3_ordering(ir: HarnessIR) -> GateResult:
    """Roles must appear in a legal order, and the sequence must actually do something."""
    v: list[Violation] = []
    seen_roles: list[str] = []

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue
        if api.role not in ROLES:
            v.append(Violation("S3.BAD_ROLE", BLOCK,
                               f"{api.symbol} declares unknown role {api.role!r}",
                               where=op.id, principle="P2"))
            continue
        seen_roles.append(api.role)
        if api.role == ROLE_DESTROY and not op.targets:
            v.append(Violation("S3.DESTROY_NO_TARGET", BLOCK,
                               f"op {op.id} calls destroy-role {api.symbol} without naming "
                               f"the resource it releases", where=op.id, principle="P2"))
        if api.role == ROLE_CREATE and not op.binds:
            v.append(Violation("S3.CREATE_NO_BIND", WARN,
                               f"op {op.id} calls create-role {api.symbol} but binds nothing; "
                               f"the returned resource is dropped on the floor",
                               where=op.id, principle="P1"))

    if not ir.sequence:
        v.append(Violation("S3.EMPTY", BLOCK, "the plan has no ops: this harness tests nothing",
                           principle="P4"))
    elif (not any(r in (ROLE_CONSUME, ROLE_CREATE) for r in seen_roles)
          and not any(a.source in (SRC_INPUT, SRC_SCRATCH, SRC_SCRATCH_ADDR)
                      for op in ir.sequence for a in op.args)):
        v.append(Violation("S3.NO_WORK", BLOCK,
                           "no op consumes input or creates a resource; the harness performs "
                           "no work on the target", principle="P4"))

    return decide("S3", "ordering: create before use before destroy", v,
                  roles=seen_roles)


# ── S4 — boundary ─────────────────────────────────────────────────────────────

def s4_boundary(ir: HarnessIR) -> GateResult:
    """Exercise the public interface. A harness that reaches past the library's own
    validation finds bugs no attacker can reach, and every one is a wasted report."""
    v: list[Violation] = []
    public = set(ir.target.public_headers)

    for sym, api in ir.apis.items():
        if api.contract.internal_only:
            v.append(Violation("S4.INTERNAL", BLOCK,
                               f"{sym} is marked internal-only. Calling it bypasses the "
                               f"library's own validation, so any crash it produces is not "
                               f"reachable by an attacker through the public API.",
                               where=sym, principle="P3",
                               fix="call the public entry point that wraps it"))
        elif public and api.header not in public:
            v.append(Violation("S4.NON_PUBLIC_HEADER", WARN,
                               f"{sym} is declared in {api.header!r}, which is not listed in "
                               f"target.public_headers; it may not be part of the supported "
                               f"surface", where=sym, principle="P3"))

    if not public:
        v.append(Violation("S4.NO_PUBLIC_SET", INFO,
                           "target.public_headers is empty, so the boundary check could not "
                           "discriminate. Populate it to make this gate meaningful.",
                           principle="P3"))

    return decide("S4", "boundary: public interface only", v,
                  apis=len(ir.apis), public_headers=sorted(public))


# ── S5 — input flow ───────────────────────────────────────────────────────────

def _input_reaches_via_scratch(ir: HarnessIR) -> bool:
    """A streaming API takes the input through a CURSOR, not as an argument.

    `BrotliDecoderDecompressStream(state, &avail_in, &next_in, ...)` never receives the
    slice directly: `next_in` is a pointer variable initialised FROM it. S5 counted no
    op as receiving input and refused a correctly-bound plan — the gate right about its
    own rule and wrong about the world.
    """
    from ..ir import SRC_SCRATCH_ADDR
    slice_ids = {s.id for s in ir.slices}
    fed = {sc.id for sc in ir.scratch if sc.init_from in slice_ids}
    return any(a.source == SRC_SCRATCH_ADDR and a.ref in fed
               for op in ir.sequence for a in op.args)


def s5_input_flow(ir: HarnessIR) -> GateResult:
    """The fuzzer's bytes must actually reach the target, and every declared slice must be
    used. An unused slice is input the fuzzer spends effort mutating for no effect."""
    v: list[Violation] = []
    used: set[str] = set()
    input_reaching_ops = 0

    for op in ir.sequence:
        touches_input = False
        for a in op.args:
            if a.source in (SRC_INPUT, SRC_LENGTH_OF) and a.ref:
                used.add(a.ref)
                touches_input = True
        if touches_input:
            input_reaching_ops += 1

    for s in ir.slices:
        if s.id not in used:
            v.append(Violation("S5.UNUSED_SLICE", WARN,
                               f"slice {s.id!r} is declared and never passed to any op; the "
                               f"fuzzer will mutate bytes that change nothing",
                               where=s.id, principle="P4"))
        if s.kind not in SLICE_KINDS:
            v.append(Violation("S5.BAD_SLICE_KIND", BLOCK,
                               f"slice {s.id!r} has unknown kind {s.kind!r}",
                               where=s.id, principle="P4"))

    remainders = [s.id for s in ir.slices if s.remainder]
    if len(remainders) > 1:
        v.append(Violation("S5.MULTIPLE_REMAINDERS", BLOCK,
                           f"slices {remainders} all claim the remainder of the input; at most "
                           f"one may", principle="P4"))

    if not ir.slices:
        v.append(Violation("S5.NO_INPUT", BLOCK,
                           "the plan declares no input slices: nothing the fuzzer produces "
                           "reaches the target", principle="P4"))
    elif input_reaching_ops == 0 and not _input_reaches_via_scratch(ir):
        v.append(Violation("S5.INPUT_NOT_CONSUMED", BLOCK,
                           "no op receives fuzzer input; the harness runs a fixed program and "
                           "the campaign cannot find anything", principle="P4"))

    return decide("S5", "input flow: the fuzzer's bytes reach the target", v,
                  slices=len(ir.slices), used_slices=sorted(used),
                  input_reaching_ops=input_reaching_ops)


# ── S6 — error handling ───────────────────────────────────────────────────────

def s6_error_handling(ir: HarnessIR) -> GateResult:
    """A failure return that is not checked becomes a null dereference in the harness,
    reported against the library."""
    v: list[Violation] = []
    checked = 0

    for i, op in enumerate(ir.sequence):
        api = ir.api_of(op)
        if api is None or not op.binds:
            continue
        er = api.contract.error_return
        if er == "none":
            continue
        checked += 1
        consumers = [o for o in ir.sequence[i + 1:]
                     if any(a.source == SRC_RESOURCE and a.ref == op.binds for a in o.args)
                     or o.targets == op.binds]
        for c in consumers:
            capi = ir.api_of(c)
            tolerant = bool(capi and capi.role == ROLE_DESTROY
                            and op.binds not in capi.contract.requires_nonnull)
            if op.binds in c.guarded_by or tolerant:
                continue
            v.append(Violation(
                "S6.UNCHECKED_ERROR", BLOCK,
                f"op {op.id} ({api.symbol}) signals failure by returning {er!r}, and op "
                f"{c.id} uses {op.binds!r} without a guard. On a rejected input the harness "
                f"dereferences the failure value and reports its own crash.",
                where=c.id, principle="P1",
                fix=f"add {op.binds!r} to guarded_by on op {c.id}"))

    return decide("S6", "error handling: failure returns are checked before use", v,
                  error_returning_ops=checked)


# ── driver ────────────────────────────────────────────────────────────────────

_GATES = {
    "S1": s1_lifetime,
    "S2": s2_contract,
    "S3": s3_ordering,
    "S4": s4_boundary,
    "S5": s5_input_flow,
    "S6": s6_error_handling,
}


def run_static_gates(ir: HarnessIR, only: tuple = ALL_STATIC) -> list[GateResult]:
    results = [_GATES[g](ir) for g in only if g in _GATES]
    if ir.raw_blocks:
        ids = [b.id for b in ir.raw_blocks]
        r = passed("S0", "schema coverage: how much of this plan is certifiable")
        r.violations = [Violation(
            "S0.RAW_BLOCK", WARN,
            f"{len(ids)} raw block(s) {ids} contain verbatim C the schema does not model. "
            f"Nothing inside them is certified by any static gate.",
            principle="P1",
            fix="express the block in IR, or accept it as an uncertified region on the "
                "certificate")]
        results.insert(0, r)
    return results
