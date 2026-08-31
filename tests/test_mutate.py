#!/usr/bin/env python3
"""Mutational plan synthesis — the OGHarn axis.

Every test here pins a property the CANDIDATES must have, not a coverage number. Coverage
is measured by campaigning, not by asserting.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs,  # noqa: E402
                       Op, ParamDecl, Resource, Target, TypeRef)
from hforge.producers import mutate                                       # noqa: E402


def _plan() -> HarnessIR:
    apis = {
        "thing_new": Api(symbol="thing_new", header="t.h", role="create",
                         params=[], returns=TypeRef("thing_t *", "pointer"),
                         contract=Contract()),
        "thing_parse": Api(symbol="thing_parse", header="t.h", role="consume",
                           params=[ParamDecl("t", TypeRef("thing_t *", "pointer")),
                                   ParamDecl("buf", TypeRef("void *", "pointer"))],
                           returns=TypeRef("int", "scalar"), contract=Contract()),
        "thing_free": Api(symbol="thing_free", header="t.h", role="destroy",
                          params=[ParamDecl("t", TypeRef("thing_t *", "pointer"))],
                          returns=TypeRef("void", "scalar"), contract=Contract()),
        # Belongs to another entry point: the header graph never mixes it in here.
        "thing_count": Api(symbol="thing_count", header="t.h", role="query",
                           params=[ParamDecl("t", TypeRef("thing_t *", "pointer"))],
                           returns=TypeRef("int", "scalar"), contract=Contract()),
    }
    return HarnessIR(
        name="thing", target=Target(name="thing"), apis=apis,
        slices=[InputSlice("s_data", "bytes", remainder=True, min_len=0)],
        resources=[Resource("r_t", TypeRef("thing_t", "struct"))],
        sequence=[Op("o0", "thing_new", [], binds="r_t"),
                  Op("o1", "thing_parse", [Arg("t", "resource", "r_t"),
                                           Arg("buf", "input", "s_data")]),
                  Op("o2", "thing_free", [Arg("t", "resource", "r_t")],
                     targets="r_t")],
        knobs=Knobs(), platforms=["linux-x86_64-glibc"])


def test_it_reaches_a_call_the_base_plan_never_makes():
    """The whole point. The header graph proposes create -> consume -> destroy and never
    calls a function belonging to a different entry point against the same object."""
    cands, stats = mutate.synthesize([_plan()])
    assert any("thing_count" in c.apis for c in cands)
    assert stats["widen"] >= 1


def test_a_mutation_never_moves_a_lifetime():
    """Creates and destroys belong to the base plan. A mutation that inserted either would
    be proposing a different lifetime, which is the gates' business and not this module's."""
    cands, _ = mutate.synthesize([_plan()])
    for c in cands:
        roles = [c.apis[o.api].role for o in c.sequence]
        assert roles.count("create") == 1, c.name
        assert roles.count("destroy") == 1, c.name


def test_an_inserted_call_sits_inside_the_objects_lifetime():
    """After the last create, before the first destroy. Outside that window the object does
    not exist yet or has already been released."""
    for c in mutate.synthesize([_plan()])[0]:
        seq = [c.apis[o.api].role for o in c.sequence]
        assert seq.index("create") < seq.index("destroy")
        for i, r in enumerate(seq):
            if r == "query":
                assert seq.index("create") < i < seq.index("destroy"), c.name


def test_an_inserted_call_carries_its_guards():
    """A plan that uses a handle from a fallible producer without guarding it dereferences
    the failure value on a rejected input. Omitting these made the gates reject 99% of
    candidates -- correctly."""
    for c in mutate.synthesize([_plan()])[0]:
        for op in c.sequence:
            refs = [a.ref for a in op.args if a.source == "resource" and a.ref]
            if refs and op.api == "thing_count":
                assert set(refs) <= set(op.guarded_by), (c.name, op.id)


def test_op_ids_stay_unique_after_splicing():
    for c in mutate.synthesize([_plan()])[0]:
        ids = [o.id for o in c.sequence]
        assert len(ids) == len(set(ids)), c.name


def test_synthesis_is_deterministic():
    """Enumerated, not sampled. A benchmark that cannot be replayed is not evidence, and
    this project has already retracted one set of numbers for a reason of that kind."""
    a = [c.name for c in mutate.synthesize([_plan()])[0]]
    b = [c.name for c in mutate.synthesize([_plan()])[0]]
    assert a == b and a
