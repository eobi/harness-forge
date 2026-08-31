"""Lift somebody else's C harness into the IR, so it can be graded like one of ours.

This is the half of the engine that sells itself without finding a bug in a target: point it
at a production harness and it reports the defects that harness carries. QuartetFuzz's
strongest third-party result is exactly this — 586 harnesses audited across 70 projects, 53
violations found, 35 fixed upstream — and it is the domain where a checker is judged on
other people's code rather than its own.

Lifting is deliberately conservative and says what it could not read. A harness is C, and C
is not a format; anything the lifter cannot express becomes a RAW BLOCK, which is recorded on
the IR as an uncertified region rather than quietly dropped. A certificate that silently
ignored half a harness would be worse than no certificate.

What the lift recovers:

  * the fuzzer's entry point and its (data, size) parameters
  * local declarations that look like resources — pointers assigned from a call
  * the call sequence, in order, with each call's arguments classified as
    input / length / resource / literal
  * which call creates a resource and which destroys it

What it cannot recover without the target's headers is CONTRACT: whether a parameter must be
NUL-terminated, whether ownership transfers. Those gates report NOT RUN unless `--header` is
supplied, because guessing them would produce exactly the confident-but-wrong verdicts this
project exists to prevent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..analysis.sinks import strip_noise
from . import cflow
from ..ir import (
    Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, RawBlock, Resource,
    Target, TypeRef, ROLE_CONSUME, ROLE_CREATE, ROLE_DESTROY, ROLE_QUERY,
    SLICE_BYTES,
)

class LiftError(Exception):
    """Why a harness could not be lifted, in the caller's words rather than a guess.

    Three different conditions used to return None here and the CLI reported all of them as
    "no LLVMFuzzerTestOneInput entry point found". Pointing this engine at a third-party
    harness produced exactly that message for a file that plainly declares one -- the entry
    point was found, the harness simply makes no library calls, and the diagnostic sent the
    reader looking for a defect that was not there.
    """


_ENTRY = re.compile(
    r"\bLLVMFuzzerTestOneInput\s*\(\s*(?:const\s+)?(?:uint8_t|unsigned\s+char|char)\s*\*\s*"
    r"([A-Za-z_]\w*)\s*,\s*(?:size_t|unsigned\s+long|long)\s+([A-Za-z_]\w*)\s*\)")

_CALL = re.compile(r"(?:([A-Za-z_]\w*)\s*=\s*)?([A-Za-z_]\w*)\s*\(([^;]*?)\)\s*;")
_DECL = re.compile(r"^\s*([A-Za-z_][\w\s]*?[\w\s\*]*?)\s+(\*+\s*)?([A-Za-z_]\w*)\s*"
                   r"(?:=\s*[^;]+)?;", re.M)

# Functions that return owned heap memory whatever the declared type says. `auto` and
# `std::string` hide a pointer; these do not.
_RAW_DEALLOCATORS = {"free", "cfree"}

# C++ FACTORIES THAT RETURN AN OWNING WRAPPER. The object is heap-allocated but the
# wrapper's destructor releases it at scope exit, so `auto p = make_unique<T>()` is a value
# local and not a handle. Named explicitly because `make_unique` matches _NEW_ISH.
_SMART_FACTORIES = {"make_unique", "make_shared", "unique_ptr", "shared_ptr",
                    "allocate_shared", "absl::make_unique", "std::make_unique",
                    "std::make_shared"}


def _returns_an_owned_handle(fn: str) -> bool:
    """Does a call bound to `auto` yield something the harness must release?

    `auto` hides pointer-ness, so the declaration cannot answer it. The name can, using the
    same new-ish vocabulary the producer already ranks with: `exif_data_new_from_data`
    returns a handle, `set_options` returns a value. Smart-pointer factories match new-ish
    on "make" and are carved out, since their whole point is that the destructor runs.
    """
    base = fn.rsplit("::", 1)[-1]
    if base in _SMART_FACTORIES or fn in _SMART_FACTORIES:
        return False
    return bool(_NEW_ISH.search(fn))


_RAW_ALLOCATORS = {"malloc", "calloc", "realloc", "strdup", "strndup", "new",
                   "aligned_alloc", "memalign", "posix_memalign", "valloc", "reallocarray"}



def _resources_named_at(argstr: str, resources: dict) -> list:
    """The resources a callsite names, read from its ARGUMENT TEXT rather than from the
    lifted args.

    A resource can be tainted -- `msg` in `msg = protobuf_c_message_unpack(.., data)`
    carries the input's taint -- and argument classification checks taint FIRST, so the
    free that follows saw an `input` argument and no `resource` argument, lifted as a
    consume, and the resource read as leaked. Reordering the classifier would be the wider
    fix and the wrong one here: a call that takes a tainted object really does consume
    input, and S5 depends on saying so. Ownership is the question destroy-detection asks,
    and it is answered by the name.
    """
    return [resources[n] for n in dict.fromkeys(re.findall(r"[A-Za-z_]\w*", argstr or ""))
            if n in resources]

# `if (x) free(x);` and `if (x != NULL) free(x);` -- the shape of nearly every cleanup in C.
_LIVE_TEST = (
    r"^\s*(?:{n}\s*(?:!=\s*(?:NULL|nullptr|0))?"          # x   /   x != NULL
    r"|(?:NULL|nullptr|0)\s*!=\s*{n})\s*$")


def _guarded_by_own_liveness(guard: str, args, resources, rid: str) -> bool:
    """Is this destroy guarded by a POSITIVE null-test of the very resource it frees?

    `if (msg != NULL) protobuf_c_message_free_unpacked(msg, NULL);` is not conditional
    cleanup. The arm where the free does not run is the arm where the resource was never
    created, so across both paths nothing survives the return -- and reading it as a branch
    made protobuf-c/unpack_fuzzer.c report a leak it does not have.

    Deliberately strict. `||` is rejected outright: under `if (a || x)` the free can run
    with x null, or not run with x live, and neither reading is safe. `x == NULL` and `!x`
    are rejected because they guard the arm where the resource is ABSENT -- a free there is
    a real defect and must keep reaching the gates.
    """
    if not guard or "||" in guard:
        return False
    names = [n for n, r in resources.items() if r == rid]
    for clause in guard.split("&&"):
        for n in names:
            if re.match(_LIVE_TEST.format(n=re.escape(n)), clause):
                return True
    return False

_NOT_A_CALL = {"if", "for", "while", "switch", "return", "sizeof", "assert", "static_assert",
               "printf", "fprintf", "abort", "exit", "memset", "malloc", "free",
               "calloc", "realloc", "strlen", "strcpy", "puts", "fwrite"}

# Calls that COPY the fuzzer's bytes somewhere else. They are not target calls, but ignoring
# them loses the data flow: a harness that memcpy's `data` into a buffer and parses the
# buffer was reported as never consuming its input at all.
_COPIERS = {"memcpy", "memmove", "strncpy", "strlcpy", "bcopy"}

# Types that are a STATUS, not a resource. `int rc = sqlite3_open(...)` is the most common
# line in C fuzz harnesses, and treating `rc` as a created object reported DOUBLE_CREATE and
# LEAK on every one of them — ordinary C, flagged as a defect. Only a pointer-typed variable
# can be a resource the harness owns.
_SCALARISH = re.compile(
    r"^\s*(?:const\s+|volatile\s+|static\s+|unsigned\s+|signed\s+)*"
    r"(?:int|long|short|char|size_t|ssize_t|unsigned|sqlite3_int64|int64_t|int32_t|"
    r"uint64_t|uint32_t|uint8_t|u8|u32|i64|float|double|_Bool|bool)\b")

_FREE_ISH = re.compile(
    r"(free|destroy|delete|close|cleanup|release|dispose|fini|end|unref)", re.I)

# REFCOUNTS COME IN PAIRS. `exif_mnote_data_ref(md); ...; exif_mnote_data_unref(md);` leaves
# md exactly as it found it, and reading the unref as a destroy would report every later use
# as a use-after-free. An unref releases the resource only when nothing took a ref first.
_REF_ISH = re.compile(r"(?:^|_)ref$", re.I)
_UNREF_ISH = re.compile(r"unref|deref", re.I)
_NEW_ISH = re.compile(r"(new|create|open|init|alloc|make|parse|load|decode|read)", re.I)


# Control flow the lifter does not model. Their presence means the op list is a linear read
# of a program that does not run linearly.
_CONTROL_FLOW = re.compile(r"\b(if|else|for|while|switch|goto)\b")
_RETURN = re.compile(r"\breturn\b")


@dataclass
class Lifted:
    ir: HarnessIR
    unread: list = field(default_factory=list)     # what the lifter could not express
    missed: list = field(default_factory=list)     # calls in the body that never became ops
    entry_data: str = ""
    entry_size: str = ""
    branches: int = 0                              # control-flow statements in the body
    hedged: list = field(default_factory=list)     # conditional effects, recorded not asserted

    @property
    def high_fidelity(self) -> bool:
        """Whether this lift is good enough to support a FINDING about someone's code.

        It is not enough to be careful about other people's harnesses if we are careless
        about our own confidence. This lifter reads a flat statement list; a body with
        branches does not execute in that order, so `sqlite3_open` inside an `if` looks like
        it never happens and the later use looks like a use-before-create. Four separate
        false positives against sqlite's real harnesses came from exactly that, and every
        one of them would have been a wasted report to a maintainer.

        So: branches, or a large share of values the lifter could not attribute, means the
        lift is LOW FIDELITY. Findings are still computed and still shown — `downgrade, do
        not drop` — but they are labelled unverified and are not counted as defects.
        """
        # Branches are now MODELLED — a call in an `if` condition is unconditional, a call
        # in the controlled block is guarded, and a conditional free is hedged rather than
        # asserted. So branching alone no longer disqualifies a lift. What still does is not
        # being able to attribute the values: if most arguments are opaque, the call graph
        # this reports is not the one that runs.
        # A MISSED CALL IS INVISIBLE TO AN UNATTRIBUTED-VALUE COUNT, and that is how four
        # false positives reached the reportable pile in one audit of 372 production
        # harnesses. nettle's harness calls
        #     asn1_der_iterator_first(&iter, size, data)
        # inside an `if` condition; the lifter dropped the call entirely, reported ZERO
        # unattributed values because every call it DID read was clean, and declared the
        # lift high fidelity. The gate then correctly observed that no op consumed the
        # input, and the conclusion -- "this harness fuzzes nothing" -- was about a library
        # that fuzzes fine.
        #
        # So fidelity now asks whether the body contains calls we never turned into ops.
        # It fails CLOSED: a shape the lifter does not model makes the lift untrusted
        # without anyone having to predict the shape in advance.
        ops = max(1, len(self.ir.sequence))
        if self.missed:
            return False
        return (len(self.unread) / ops) < 1.5

    @property
    def why_low_fidelity(self) -> str:
        bits = []
        ops = max(1, len(self.ir.sequence))
        if self.missed:
            bits.append(f"{len(self.missed)} call(s) in the body the lifter did not read: "
                        + ", ".join(sorted(self.missed)[:4]))
        if (len(self.unread) / ops) >= 1.5:
            bits.append(f"{len(self.unread)} unattributed value(s) across {ops} call(s)")
        return "; ".join(bits)


def _body_of(src: str, start: int) -> str:
    """The entry function's body, brace-matched."""
    ob = src.find("{", start)
    if ob < 0:
        return ""
    depth, i = 0, ob
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[ob + 1:i]
        i += 1
    return src[ob + 1:]


def _split_args(s: str) -> list:
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur and "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _classify_args(args_raw, data, size, tainted, resources, is_ptr, unread, fn,
                   decl_type=None, caller_owned=None, size_alias=None):
    """Turn a call's textual arguments into IR Args, and say what could not be attributed."""
    args, params, out_created = [], [], []
    for i, a in enumerate(args_raw):
        pname = f"a{i}"
        # A C++ CAST IS UNWRAPPED FIRST, on the raw text. `readJson(reinterpret_cast<const
        # char*>(Data), Size)` is how a C++ harness hands bytes to a C API. Doing this
        # after the character-strip below does not work and quietly did nothing: that strip
        # removes the trailing `)`, so the cast expression no longer ends in one and the
        # pattern never matched. The fix looked correct, changed no behaviour, and was only
        # caught by re-checking the harness it was written for.
        _raw = a.strip()
        _cxx = re.match(
            r"^(?:reinterpret_cast|static_cast|const_cast|dynamic_cast)\s*<[^>]*>\s*\((.*)\)\s*$",
            _raw)
        if _cxx:
            _raw = _cxx.group(1).strip()
        bare = _raw.lstrip("&*( ").rstrip(" )")
        bare = re.sub(r"^\([^)]*\)\s*", "", bare).strip()          # drop a C cast
        # `s.data()` IS `s`. A C++ harness reaches a C API through an accessor, and the
        # value it yields carries whatever taint the object had.
        _acc = re.match(r"^([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)\s*\(\s*\)$", bare)
        if _acc and _acc.group(2) in _STD_ACCESSOR and _acc.group(1) in tainted:
            bare = _acc.group(1)
        if bare in tainted:
            args.append(Arg(pname, "input", "s_data"))
            params.append(ParamDecl(pname, TypeRef("const uint8_t *", "pointer")))
        elif (bare in (size_alias or {size})
              or any(re.fullmatch(rf"{re.escape(a)}\s*[-+]\s*\d+", bare)
                     for a in (size_alias or {size}) if a)):
            args.append(Arg(pname, "length_of", "s_data"))
            params.append(ParamDecl(pname, TypeRef("size_t", "scalar")))
        elif a.strip().startswith("&") and is_ptr(bare):
            # An OUT-parameter: the library allocates and writes the pointer back.
            #
            # THIS MUST BE TESTED BEFORE `bare in resources`. A slot can be filled more
            # than once -- libevent's harness does `getaddrinfo_common_(.., &res, ..);
            # freeaddrinfo(res); res = NULL; getaddrinfo_common_(.., &res, ..);` -- and
            # once `res` was known, the second `&res` matched the plain-resource branch,
            # so the SECOND create bound nothing and its free read as a double destroy of
            # the first lifetime.
            rid = f"r_{bare}"
            # ...UNLESS THE HARNESS DECLARED IT, in which case the storage exists from the
            # declaration and no call needs to create it. `yajl_parser_config cfg = {...};`
            # passed as `&cfg` is a config the CALLER fills in, not a handle the library
            # returns; scoring it as a resource awaiting a create reported
            # S1.USE_BEFORE_CREATE against four correct production harnesses.
            if caller_owned is not None and (decl_type or {}).get(bare) is not None:
                caller_owned[rid] = ("out_param" if "*" in (decl_type or {})[bare]
                                     else "inline")
            resources.setdefault(bare, rid)
            out_created.append(rid)
            args.append(Arg(pname, "resource", rid))
            params.append(ParamDecl(pname, TypeRef("void **", "pointer")))
        elif bare in resources:
            args.append(Arg(pname, "resource", resources[bare]))
            params.append(ParamDecl(pname, TypeRef("void *", "pointer")))
        elif re.fullmatch(r"-?\d+|NULL|nullptr|0|true|false", bare):
            val = 0 if bare in ("NULL", "nullptr", "0", "false") else (
                1 if bare == "true" else int(bare))
            args.append(Arg(pname, "literal", value=val))
            params.append(ParamDecl(pname, TypeRef("int", "scalar")))
        else:
            args.append(Arg(pname, "literal", value=0))
            params.append(ParamDecl(pname, TypeRef("int", "scalar")))
            unread.append(f"argument {i} of {fn}: {a.strip()[:48]!r} could not be "
                          f"attributed; treated as an opaque literal")
    return args, params, out_created


# NAMES THAT ARE NOT A LIBRARY CALL, for the missed-call check only. This started life as
# a second `_NOT_A_CALL`, which SHADOWED the module's own set defined above -- so `memcpy`,
# `malloc`, `free`, `calloc` and the rest silently dropped out of the exclusion the LIFTER
# uses at its call loop, and began appearing as library ops in every lift. 394 tests and a
# 20-case plan-drift check both passed through it: the tests do not assert on which
# housekeeping calls get lifted, and drift only watches the producers. Union, never shadow.
# STANDARD CONTAINER PLUMBING, not the library under test. `s.data()`, `v.size()`,
# `s.c_str()` are how a C++ harness hands its bytes to a C API; counting them as calls the
# lifter failed to read made them the top blocker in .cc harnesses -- 85 occurrences of
# `data` alone. They are excluded here AND their taint is propagated below, because
# excluding them without following the value through would trade false positives for the
# worse kind: a lift trusted while a flow went unfollowed.
_STD_ACCESSOR = {
    "data", "size", "c_str", "begin", "end", "empty", "length", "at", "front", "back",
    "remaining_bytes", "str", "get", "value", "count", "capacity", "resize", "reserve",
    "push_back", "emplace_back", "clear", "substr", "find", "append",
}

# Copiers are READ, not missed. `memcpy(buf, data, size)` is handled specially -- it moves
# taint from the source to the destination and is deliberately not lifted as a library
# operation -- and then it was reported as a call the lifter failed to read, which made
# every harness that copies its input before parsing it untrusted. Handled is not missed.
_NOT_A_CALLSITE = _NOT_A_CALL | _STD_ACCESSOR | _COPIERS | {
    "alignof", "defined", "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast",
    "catch", "offsetof", "va_start", "va_end", "va_arg", "typeof", "__typeof__",
    "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize",
}
_CALLISH = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_MEMBER_CALL = re.compile(r"(?:\.|->)\s*([A-Za-z_]\w*)\s*\(")


def _missed_calls(body: str, lifted_symbols: set) -> list:
    """Call names in the body that never became ops.

    Deliberately NAME-based and deliberately noisy in the safe direction: the point is not
    to enumerate the harness's semantics, it is to notice that the lifter's view is
    incomplete. A name we cannot classify counts as missed, because the alternative --
    assuming anything we did not recognise was unimportant -- is exactly what let a dropped
    `asn1_der_iterator_first` be reported as "this harness consumes no input".
    """
    seen = {m.group(1) for m in _CALLISH.finditer(body)}
    # MEMBER CALLS TOO. This is a C lifter, and it is routinely handed `.cc` files:
    # sentencepiece's harness calls `push_back` on a std::vector and the gate then
    # complained that `push_back` does not declare the parameter it was passed -- a C++
    # method the lifter never modelled, graded as though it were a C function. A shape
    # this lifter cannot read has to make the lift untrusted rather than produce a verdict
    # about someone's code.
    seen |= {m.group(1) for m in _MEMBER_CALL.finditer(body)}
    return sorted(seen - _NOT_A_CALLSITE
                  - {s.rsplit("::", 1)[-1] for s in lifted_symbols})


_FDP_DECL = re.compile(r"\bFuzzedDataProvider\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*,")
_FDP_CONSUME = re.compile(
    r"(?:([A-Za-z_]\w*)\s*=\s*)?\b([A-Za-z_]\w*)\s*\.\s*(Consume\w*)\s*(?:<[^>]*>)?\s*\(")


_ASSIGN = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s:<>,]*?[\s\*&]+)?([A-Za-z_]\w*)\s*=\s*([^;]+);")


def _mentions_tainted(expr: str, tainted: set) -> bool:
    """Whether an expression is derived from the fuzzer's bytes.

    A cast, a `+ offset`, an accessor -- the value is still attacker-controlled, and the
    point of this check is the plan's INPUT binding rather than an exact dataflow. It is
    deliberately generous in one direction only: a name that is not tainted can never make
    an expression tainted, so this cannot invent an input binding out of nothing.
    """
    return any(re.search(r"\b" + re.escape(t) + r"\b", expr) for t in tainted if t)


def _fdp_taint(body: str, data: str, tainted: set) -> list:
    """Follow the fuzzer's bytes through FuzzedDataProvider.

    927 files in the OSS-Fuzz tree build their inputs this way:

        FuzzedDataProvider fdp(data, size);
        std::string s = fdp.ConsumeRandomLengthString(1024);
        int n         = fdp.ConsumeIntegralInRange<int>(0, 5);

    Every value it hands back IS the fuzzer's input, reshaped. Without this the lifter sees
    a `data` that is used once and never reaches a library call, and every such harness is
    untrusted -- which was most of the fleet. Returns the Consume* names so they can be
    excluded from "calls the lifter did not read": they are read, they are just not library
    calls.
    """
    names = set()
    for m in _FDP_DECL.finditer(body):
        if m.group(2) == data or m.group(2) in tainted:
            names.add(m.group(1))
    if not names:
        return []
    consumed = []
    for m in _FDP_CONSUME.finditer(body):
        assigned, obj, meth = m.group(1), m.group(2), m.group(3)
        if obj not in names:
            continue
        consumed.append(meth)
        if assigned:
            tainted.add(assigned)          # the value came from the fuzzer's bytes
    return consumed


def lift(path: str, target_name: str = "", platforms: Optional[list] = None):
    """Read a C harness and produce an IR plan plus a record of what could not be read."""
    raw = Path(path).read_text(errors="replace")
    src = strip_noise(raw)

    # A DEFINITION, not a prototype. `ossshell.c` declares the entry point and calls it from
    # main; matching that prototype and taking the next `{` graded an unrelated function.
    m = None
    for cand in _ENTRY.finditer(src):
        if src[cand.end():].lstrip().startswith("{"):
            m = cand
            break
    if not m:
        raise LiftError("no LLVMFuzzerTestOneInput definition found (a declaration without "
                        "a body does not lift)")
    data, size = m.group(1), m.group(2)
    body = _body_of(src, m.end())
    if not body.strip():
        raise LiftError("LLVMFuzzerTestOneInput has an empty body")

    decl_type: dict = {}
    for dm in _DECL.finditer(body):
        base, stars, name = dm.group(1) or "", dm.group(2) or "", dm.group(3)
        decl_type[name] = (base + " " + stars).strip()

    def is_ptr(name: str) -> bool:
        t = decl_type.get(name)
        if t is None:
            return False                      # undeclared here: do not guess
        return "*" in t or not _SCALARISH.match(t)

    unread: list = []
    hedged: list = []
    ops: list = []
    resources: dict = {}
    apis: dict = {}
    tainted: set = {data}
    by_address: set = set()          # resources created through an out-parameter
    member_calls: list = []          # `x.f()` / `x->f()`: not C, not modelled
    caller_owned: dict = {}          # rid -> storage, for slots the harness declares
    refs: dict = {}                  # rid -> outstanding explicit refcount increments
    # Values a FuzzedDataProvider hands back ARE the fuzzer's bytes, reshaped. Taint them
    # before the call loop so a library call receiving one is seen to consume input.
    fdp_methods = set(_fdp_taint(body, data, tainted))
    size_alias: set = {size} if size else set()
    order = 0

    parsed = cflow.parse(body)
    _exiting = cflow.returning_arms(parsed)
    for stmt in parsed.stmts:
        if stmt.kind == "return":
            continue
        text = stmt.text if stmt.text.rstrip().endswith(";") else stmt.text + ";"

        # AN ALIAS CARRIES THE TAINT. `const uint8_t *payload = data; size_t payload_len =
        # size; parse(payload, payload_len);` is the single most common shape among
        # harnesses this lifter could not follow -- it bound both arguments as LITERALS and
        # reported that the harness consumes no input. It is not a C++ problem and not an
        # exotic one: it is an assignment. Handled here, in statement order, so a name
        # tainted later does not appear tainted earlier.
        _asn = _ASSIGN.match(text)
        if _asn:
            _lhs, _rhs = _asn.group(1), _asn.group(2)
            if _lhs not in tainted and _mentions_tainted(_rhs, tainted):
                tainted.add(_lhs)
            # `size_t payload_len = size;` is the same aliasing on the LENGTH side, and
            # binding it as a literal leaves a call reading `parse(payload, 0)` -- input
            # bound, length thrown away, which is worse than either alone.
            if _lhs not in size_alias and _mentions_tainted(_rhs, size_alias):
                size_alias.add(_lhs)
        for cm in _CALL.finditer(text):
            assigned, fn, argstr = cm.group(1), cm.group(2), cm.group(3)
            # A MEMBER CALL IS NOT A C LIBRARY CALL. `sentences.push_back(s)` matched as a
            # call to a function named `push_back`, was lifted as an op, and the gate then
            # objected that push_back does not declare the parameter it was passed -- a
            # verdict about a std::vector method, delivered against sentencepiece's
            # harness. This is a C lifter and it is routinely handed .cc files; a shape it
            # cannot model has to make the lift untrusted, not produce an opinion.
            _before = text[:cm.start(2)].rstrip()
            if _before.endswith(".") or _before.endswith("->"):
                member_calls.append(fn)
                continue
            args_raw = _split_args(argstr)

            if fn in _COPIERS:
                if len(args_raw) >= 2:
                    srcv = args_raw[1].strip().lstrip("&*( ").rstrip(" )")
                    dstv = args_raw[0].strip().lstrip("&*( ").rstrip(" )")
                    if any(t in srcv for t in tainted):
                        tainted.add(re.sub(r"^\([^)]*\)\s*", "", dstv).strip())
                continue
            # `free(x)` IS A DESTROY, even though free is not a library API worth
            # modelling. It is excluded from callsites so that allocator noise does not
            # become ops -- but that exclusion also erased the single most common cleanup
            # in C, so every resource released by a plain free read as leaked.
            # s2geometry's harness mallocs through a local wrapper and frees the result
            # two lines later; the gate called it a leak.
            #
            # Admitted ONLY when it names a known resource, so `free(buf)` on a plain
            # buffer still contributes nothing.
            if (fn in _RAW_DEALLOCATORS and _resources_named_at(argstr, resources)):
                _rid = _resources_named_at(argstr, resources)[0]
                apis.setdefault(fn, Api(symbol=fn, header="stdlib.h", role=ROLE_DESTROY,
                                        params=[ParamDecl("p", TypeRef("void *",
                                                                       "pointer"))],
                                        returns=TypeRef("void", "scalar"),
                                        contract=Contract()))
                ops.append(Op(f"o{order}", fn,
                              [Arg("p", "resource", _rid)], binds="", targets=_rid,
                              guarded_by=([] if stmt.depth == 0
                                          or _guarded_by_own_liveness(stmt.guard, [],
                                                                      resources, _rid)
                                          else [f"__branch:{stmt.arm}"]
                                          + ([f"__exits:{stmt.arm}"]
                                             if stmt.arm in _exiting else []))))
                order += 1
                continue
            if fn in _NOT_A_CALL or fn.startswith("__"):
                continue

            args, params, out_created = _classify_args(
                args_raw, data, size, tainted, resources, is_ptr, unread, fn,
                decl_type=decl_type, caller_owned=caller_owned,
                size_alias=size_alias)

            role, binds, targets = ROLE_QUERY, "", ""
            if out_created and not (assigned and is_ptr(assigned)):
                # WHICH `&x` IS THE OUT-PARAMETER. Taking the first one is wrong whenever a
                # call is handed an input struct by address before the slot it fills:
                # `evutil_getaddrinfo_common_(NULL, s, &hints, &res, &portnum)` binds
                # `hints`, a struct the harness memsets and fills itself, and leaves `res`
                # -- the handle actually returned -- created by nothing. libevent's harness
                # then read as destroying `res` twice and using it after free, three
                # blocking violations from one mis-chosen argument.
                #
                # `caller_owned` already separates them: a slot DECLARED by the harness
                # with a non-pointer type is storage it owns and passes IN, while a
                # declared pointer is a slot for the library to fill. Prefer the first
                # argument that is not caller-owned inline storage.
                _out = next((r for r in out_created
                             if caller_owned.get(r) != "inline"), out_created[0])
                binds, role = _out, ROLE_CREATE
                # `sqlite3_open(":memory:", &db)` both CREATES db and takes it as an
                # argument. Without recording that, S1 reads the argument as a use of a
                # resource nothing has created yet — the same exemption the producer side
                # already had, keyed on Resource.storage.
                by_address.add(binds)
            if assigned and is_ptr(assigned):
                rid = f"r_{assigned}"
                resources[assigned] = rid
                binds, role = rid, ROLE_CREATE
                # A C++ VALUE LOCAL IS DESTROYED AT SCOPE EXIT AND CANNOT LEAK.
                #
                # `auto opts = set_options();` binds a class object with automatic
                # storage; its destructor runs on return, including when the harness
                # returns through an exception. `is_ptr` answers True for it because it
                # asks "is this type non-scalar", which is the right question for
                # argument passing and the wrong one for ownership -- so S1 read
                # boost/boost_programoptions_fuzzer.cc, whose every object is a stack
                # local, as leaking.
                #
                # Marked `inline`, reusing the storage exemption S1 already honours,
                # rather than by changing `is_ptr` -- that predicate decides argument
                # shape in four other places.
                #
                # `auto p = malloc(n)` is the hole in this: `auto` hides the pointer. So
                # a raw allocator keeps its handle regardless of how the slot was
                # declared. That leaves a false NEGATIVE for allocators not on the list,
                # which is the direction to fail in -- a missed leak costs a finding, a
                # false leak costs the whole tier's triageability.
                _t = (decl_type or {}).get(assigned) or ""
                # `auto` is the hard case: it hides whether the initialiser returned a
                # pointer. Treating every `auto` as a value local suppressed a real class
                # of leak -- `auto d = exif_data_new_from_data(..)` is a handle somebody
                # has to release -- so the name decides, not the declaration.
                _auto = _t.strip() == "auto"
                if (caller_owned is not None and _t and "*" not in _t
                        and not (_auto and _returns_an_owned_handle(fn))
                        and not _SCALARISH.match(_t) and fn not in _RAW_ALLOCATORS):
                    caller_owned[rid] = "inline"
            elif assigned:
                role = (ROLE_CONSUME if any(a.source == "input" for a in args)
                        else ROLE_QUERY)
            elif (not binds and _REF_ISH.search(fn)
                  and _resources_named_at(argstr, resources)):
                # Taking a ref is not creating and not destroying; record it so the
                # matching unref can be recognised as balanced.
                refs[_resources_named_at(argstr, resources)[0]] = refs.get(
                    _resources_named_at(argstr, resources)[0], 0) + 1
            elif not binds and _FREE_ISH.search(fn) and (
                    any(a.source == "resource" for a in args)
                    or _resources_named_at(argstr, resources)):
                rid = next((a.ref for a in args if a.source == "resource"), None) \
                    or _resources_named_at(argstr, resources)[0]
                if _UNREF_ISH.search(fn) and refs.get(rid, 0) > 0:
                    # Balanced against an earlier ref: the resource outlives this call.
                    refs[rid] -= 1
                    rid = None
                if rid is None:
                    pass
                elif stmt.depth == 0 or _guarded_by_own_liveness(stmt.guard, args,
                                                                 resources, rid):
                    role, targets = ROLE_DESTROY, rid
                else:
                    # A destroy on ONE branch only. Marking the resource dead would report
                    # every later use as a use-after-free on a path that may never run.
                    #
                    # The role stays `query`, deliberately. An earlier version hedged by
                    # dropping `targets` while still declaring the role `destroy` — and S3
                    # then reported "destroy names no resource", a false positive created by
                    # the hedge itself. A claim that is being withheld must be withheld
                    # whole.
                    hedged.append(f"{fn} frees {rid} inside a branch; a later use is a "
                                  f"POSSIBLE use-after-free, not a certain one")
            elif not binds and any(a.source == "input" for a in args):
                role = ROLE_CONSUME

            apis[fn] = Api(symbol=fn, header=Path(path).name, role=role, params=params,
                           returns=TypeRef("void *" if binds else "int",
                                           "pointer" if binds else "scalar"),
                           contract=Contract())
            ops.append(Op(f"o{order}", fn, args, binds=binds, targets=targets,
                          guarded_by=([] if stmt.depth == 0
                                      else [f"__branch:{stmt.arm}"]
                                      + ([f"__exits:{stmt.arm}"]
                                         if stmt.arm in _exiting else []))))
            order += 1

    if not ops:
        raise LiftError("the entry point was found, but it makes no calls into a library: "
                        "every call in it is a libc primitive the lift excludes. A "
                        "self-contained harness that inlines its own bug has nothing to "
                        "grade against an API contract")

    notes = (f"lifted from {Path(path).name}; {parsed.branches} branch(es) modelled by "
             f"nesting depth. Contract gates need the target's headers; without them S2 "
             f"reports NOT RUN rather than guessing.")
    blocks = []
    if unread:
        blocks.append(RawBlock(id="unread", where="prologue", code="\n".join(unread),
                               reason="values the lifter could not attribute; UNCERTIFIED"))
    if hedged:
        blocks.append(RawBlock(id="hedged", where="prologue", code="\n".join(hedged),
                               reason="conditional lifetime effects, recorded not asserted"))

    ir = HarnessIR(
        name=Path(path).stem,
        target=Target(name=target_name or Path(path).stem),
        apis=apis,
        slices=[InputSlice("s_data", SLICE_BYTES, remainder=True, min_len=0)],
        resources=[Resource(rid, TypeRef("void *", "pointer"),
                            storage=caller_owned.get(
                                rid, "out_param" if rid in by_address else "handle"))
                   for rid in dict.fromkeys(resources.values())],
        sequence=ops,
        knobs=Knobs(),
        platforms=platforms or ["linux-x86_64-glibc"],
        producer="lift:c_harness",
        raw_blocks=blocks,
        notes=notes)
    _syms = {a.symbol for a in ir.apis.values()} if hasattr(ir, "apis") else set()
    _missed = [x for x in _missed_calls(body, _syms) if x not in fdp_methods]
    # Member calls the lifter deliberately skips are SKIPPED, not missed. `.data()`,
    # `.size()`, `.c_str()` are already excluded from the name-based check as plumbing --
    # and were then re-added here through the member-call path, which subtracted only the
    # FuzzedDataProvider methods. Thirty-three harnesses were untrusted because a std
    # accessor was both recognised and reported as unrecognised, by two checks that
    # disagreed about the same set.
    _missed += sorted(set(member_calls) - fdp_methods - _NOT_A_CALLSITE)

    # AN INPUT USE WE DID NOT BIND IS A FLOW WE DID NOT FOLLOW.
    #
    # haproxy's harness reaches its parser through a designated initialiser --
    #     struct cfgfile dummy_cfg = { .content = (const char *)data, .size = size };
    # -- and lcms consumes bytes as `data[0]`, `data[1]`. In both, every CALL was lifted, so
    # the missed-call check above stays silent, and both were reported as harnesses that
    # consume no input. They consume it; the lifter could not see the path.
    #
    # So: count how often the entry's data parameter is named in the body, and how often we
    # actually bound it. Fewer bindings than uses means a flow we did not follow, and the
    # lift is untrusted -- again failing closed, without naming the shapes in advance.
    # Count each parameter against ITS OWN bindings. Counting `input` and `length_of`
    # together against uses of the DATA name let zlib's single length binding of `size`
    # mask the fact that `d` -- assigned straight into a global and never seen again --
    # was bound nowhere. The harness works; the lifter cannot see through the global, and
    # the check written to notice exactly that missed it.
    for _name, _src in ((data, "input"), (size, "length_of")):
        if not _name:
            continue
        # A GUARD IS NOT A FLOW. `if (size < 4) return 0;` names the parameter without
        # passing it anywhere, and nearly every harness has one; counting guards made a
        # correct lift of a branching sqlite harness untrusted. Only uses that are not a
        # comparison against the parameter are candidates for a flow we failed to follow.
        _n = re.escape(_name)
        _all = len(re.findall(r"\b" + _n + r"\b", body))
        _guards = len(re.findall(r"\b" + _n + r"\b\s*(?:<|>|<=|>=|==|!=)", body)) \
            + len(re.findall(r"(?:<|>|<=|>=|==|!=)\s*\b" + _n + r"\b", body))
        _uses = _all - _guards
        if _name == data and fdp_methods:
            # `FuzzedDataProvider fdp(data, size)` consumes the parameter once, in full,
            # and everything downstream flows from the provider rather than from `data`.
            _uses -= 1
        _bound = sum(1 for o in ops for a in o.args if a.source == _src)
        if _uses > _bound:
            _missed.append(f"{_uses - _bound} use(s) of {_name!r} the lifter did not bind")

    return Lifted(ir=ir, unread=unread, entry_data=data, entry_size=size,
                  branches=parsed.branches, hedged=hedged, missed=_missed)
