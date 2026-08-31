#!/usr/bin/env python3
"""The per-plan bound: what a harness cannot reach through its own calls."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import reachbound  # noqa: E402
from hforge.ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs,  # noqa: E402
                       Op, ParamDecl, Target, TypeRef)


def _ir(calls):
    apis = {c: Api(symbol=c, header="t.h", role="consume",
                   params=[ParamDecl("buf", TypeRef("void *", "pointer"))],
                   returns=TypeRef("int", "scalar"), contract=Contract())
            for c in calls}
    return HarnessIR(
        name="p", target=Target(name="t"), apis=apis,
        slices=[InputSlice("s", "bytes", remainder=True, min_len=0)],
        resources=[],
        sequence=[Op(f"o{i}", c, [Arg("buf", "input", "s")])
                  for i, c in enumerate(calls)],
        knobs=Knobs(), platforms=["linux-x86_64-glibc"])


def test_it_names_what_the_plan_cannot_reach():
    b = reachbound.bound(_ir(["lib_parse"]), {"lib_parse", "lib_write", "lib_verify"})
    assert b["called"] == 1
    assert b["unreachable_through_this_plan"] == 2
    assert set(b["cannot_find_defects_in"]) == {"lib_write", "lib_verify"}


def test_the_fraction_is_over_the_EXPORTED_surface():
    """Coverage over the project says how much code ran. This says how much of what the
    harness could ever touch it touches at all -- the gap is the harness's bound, not the
    fuzzer's failure."""
    b = reachbound.bound(_ir(["a", "b"]), {"a", "b", "c", "d"})
    assert b["reachable_fraction"] == 0.5


def test_calls_outside_the_header_do_not_inflate_the_count():
    """A plan calling libc or a local helper has not reached more of the LIBRARY. Counting
    those would let a harness look broader by calling memcpy."""
    b = reachbound.bound(_ir(["lib_parse", "memcpy", "helper"]), {"lib_parse", "lib_write"})
    assert b["called"] == 1
    assert b["unreachable_through_this_plan"] == 1
