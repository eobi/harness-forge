"""compose_chain: fold several downstream subsystems onto one parsed root."""
from types import SimpleNamespace

from hforge.ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op,
                       ParamDecl, Resource, Target, TypeRef)
from hforge.producers.compose import compose_chain


def _api(sym, role, params, ret):
    return Api(symbol=sym, header="j.h", role=role,
               params=[ParamDecl(n, TypeRef(t, "pointer" if "*" in t else "scalar")) for t, n in params],
               returns=TypeRef(ret, "pointer" if "*" in ret else "scalar"), contract=Contract())


def _decl(name, params, ret):
    return SimpleNamespace(name=name, params=params, ret=ret)


def test_chain_folds_serialise_then_transform_onto_the_parsed_root():
    decls = {
        "loads": _decl("loads", [("const char *", "s")], "obj *"),
        "decref": _decl("decref", [("obj *", "o")], "void"),
        "dumps": _decl("dumps", [("obj *", "o")], "char *"),
        "copy": _decl("copy", [("obj *", "o")], "obj *"),
    }
    api = {k: _api(k, r, decls[k].params, decls[k].ret) for k, r in
           (("loads", "create"), ("decref", "destroy"), ("dumps", "query"), ("copy", "query"))}
    A = HarnessIR(name="A", target=Target(name="j"), apis=dict(api),
                  slices=[InputSlice("s_seam", "cstring", remainder=True, min_len=1)],
                  resources=[Resource("r_o", TypeRef("obj *", "pointer"))],
                  sequence=[Op("o0", "loads", [Arg("s", "input", "s_seam")], binds="r_o"),
                            Op("o1", "decref", [Arg("o", "resource", "r_o")], targets="r_o")],
                  knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")

    def _b(sym):
        return HarnessIR(name="B_" + sym, target=Target(name="j"), apis=dict(api), slices=[],
                         resources=[Resource("r_x", TypeRef("obj *", "pointer"))],
                         sequence=[Op("o0", sym, [Arg("o", "resource", "r_x")])],
                         knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")

    pool = {"serialise": [_b("dumps")], "transform": [_b("copy")], "validate": []}
    plan, rec = compose_chain(A, pool, decls)
    assert plan is not None
    apis = {o.api for o in plan.sequence}
    assert "dumps" in apis and "copy" in apis, "both downstream subsystems folded"
    assert rec["subsystems_added"] == 2
    # both operate on the parsed root
    for sym in ("dumps", "copy"):
        op = next(o for o in plan.sequence if o.api == sym)
        assert op.args[0].ref == "r_o"
