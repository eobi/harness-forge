"""compose_max: fold one call of every DISTINCT downstream traversal onto the parsed root.

The coverage lever is distinct traversals (json_copy vs json_deep_copy vs json_dumps are
different code), not abstract subsystem names. compose_max folds one of each distinct symbol.
"""
from types import SimpleNamespace

from hforge.ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op,
                       ParamDecl, Resource, Target, TypeRef)
from hforge.producers.compose import compose_max


def _api(sym, role, params, ret):
    return Api(symbol=sym, header="j.h", role=role,
               params=[ParamDecl(n, TypeRef(t, "pointer" if "*" in t else "scalar")) for t, n in params],
               returns=TypeRef(ret, "pointer" if "*" in ret else "scalar"), contract=Contract())


def _decl(name, params, ret):
    return SimpleNamespace(name=name, params=params, ret=ret)


def test_folds_distinct_transform_symbols_not_just_one_per_subsystem():
    decls = {
        "loads": _decl("loads", [("const char *", "s")], "obj *"),
        "decref": _decl("decref", [("obj *", "o")], "void"),
        "copy": _decl("copy", [("obj *", "o")], "obj *"),
        "deep_copy": _decl("deep_copy", [("obj *", "o")], "obj *"),
        "dumps": _decl("dumps", [("obj *", "o")], "char *"),
    }
    api = {k: _api(k, r, decls[k].params, decls[k].ret) for k, r in
           (("loads", "create"), ("decref", "destroy"), ("copy", "query"),
            ("deep_copy", "query"), ("dumps", "query"))}
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

    pool = {"serialise": [_b("dumps")], "transform": [_b("copy"), _b("deep_copy")], "validate": []}
    plan, rec = compose_max(A, pool, decls)
    folded = {x["symbol"] for x in rec["folded"]}
    assert folded == {"dumps", "copy", "deep_copy"}, "both copy AND deep_copy fold, not one"
    assert rec["distinct_folded"] == 3
