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

_FREE_ISH = re.compile(r"(free|destroy|delete|close|cleanup|release|dispose|fini|end)",
                       re.I)
_NEW_ISH = re.compile(r"(new|create|open|init|alloc|make|parse|load|decode|read)", re.I)


# Control flow the lifter does not model. Their presence means the op list is a linear read
# of a program that does not run linearly.
_CONTROL_FLOW = re.compile(r"\b(if|else|for|while|switch|goto)\b")
_RETURN = re.compile(r"\breturn\b")


@dataclass
class Lifted:
    ir: HarnessIR
    unread: list = field(default_factory=list)     # what the lifter could not express
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
        ops = max(1, len(self.ir.sequence))
        return (len(self.unread) / ops) < 1.5

    @property
    def why_low_fidelity(self) -> str:
        bits = []
        ops = max(1, len(self.ir.sequence))
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


def _classify_args(args_raw, data, size, tainted, resources, is_ptr, unread, fn):
    """Turn a call's textual arguments into IR Args, and say what could not be attributed."""
    args, params, out_created = [], [], []
    for i, a in enumerate(args_raw):
        pname = f"a{i}"
        bare = a.strip().lstrip("&*( ").rstrip(" )")
        bare = re.sub(r"^\([^)]*\)\s*", "", bare).strip()          # drop a cast
        if bare in tainted:
            args.append(Arg(pname, "input", "s_data"))
            params.append(ParamDecl(pname, TypeRef("const uint8_t *", "pointer")))
        elif bare == size or re.fullmatch(rf"{re.escape(size)}\s*[-+]\s*\d+", bare):
            args.append(Arg(pname, "length_of", "s_data"))
            params.append(ParamDecl(pname, TypeRef("size_t", "scalar")))
        elif bare in resources:
            args.append(Arg(pname, "resource", resources[bare]))
            params.append(ParamDecl(pname, TypeRef("void *", "pointer")))
        elif a.strip().startswith("&") and is_ptr(bare):
            # An OUT-parameter: the library allocates and writes the pointer back.
            rid = f"r_{bare}"
            resources.setdefault(bare, rid)
            out_created.append(rid)
            args.append(Arg(pname, "resource", rid))
            params.append(ParamDecl(pname, TypeRef("void **", "pointer")))
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
    order = 0

    parsed = cflow.parse(body)
    for stmt in parsed.stmts:
        if stmt.kind == "return":
            continue
        text = stmt.text if stmt.text.rstrip().endswith(";") else stmt.text + ";"
        for cm in _CALL.finditer(text):
            assigned, fn, argstr = cm.group(1), cm.group(2), cm.group(3)
            args_raw = _split_args(argstr)

            if fn in _COPIERS:
                if len(args_raw) >= 2:
                    srcv = args_raw[1].strip().lstrip("&*( ").rstrip(" )")
                    dstv = args_raw[0].strip().lstrip("&*( ").rstrip(" )")
                    if any(t in srcv for t in tainted):
                        tainted.add(re.sub(r"^\([^)]*\)\s*", "", dstv).strip())
                continue
            if fn in _NOT_A_CALL or fn.startswith("__"):
                continue

            args, params, out_created = _classify_args(
                args_raw, data, size, tainted, resources, is_ptr, unread, fn)

            role, binds, targets = ROLE_QUERY, "", ""
            if out_created and not (assigned and is_ptr(assigned)):
                binds, role = out_created[0], ROLE_CREATE
                # `sqlite3_open(":memory:", &db)` both CREATES db and takes it as an
                # argument. Without recording that, S1 reads the argument as a use of a
                # resource nothing has created yet — the same exemption the producer side
                # already had, keyed on Resource.storage.
                by_address.add(binds)
            if assigned and is_ptr(assigned):
                rid = f"r_{assigned}"
                resources[assigned] = rid
                binds, role = rid, ROLE_CREATE
            elif assigned:
                role = (ROLE_CONSUME if any(a.source == "input" for a in args)
                        else ROLE_QUERY)
            elif not binds and _FREE_ISH.search(fn) and any(a.source == "resource"
                                                            for a in args):
                rid = next(a.ref for a in args if a.source == "resource")
                if stmt.depth == 0:
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
                          guarded_by=[] if stmt.depth == 0 else ["__branch"]))
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
                            storage="out_param" if rid in by_address else "handle")
                   for rid in dict.fromkeys(resources.values())],
        sequence=ops,
        knobs=Knobs(),
        platforms=platforms or ["linux-x86_64-glibc"],
        producer="lift:c_harness",
        raw_blocks=blocks,
        notes=notes)
    return Lifted(ir=ir, unread=unread, entry_data=data, entry_size=size,
                  branches=parsed.branches, hedged=hedged)
