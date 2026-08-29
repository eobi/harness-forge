"""Phase 3 tests — producers propose, gates rank, confidence decides nothing.

Run:  python3 tests/test_phase3.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.gates.result import BLOCK, WARN, GateResult, Violation, decide, not_run  # noqa: E402
from hforge.gates.static_gates import run_static_gates                 # noqa: E402
from hforge.ir import Target, ROLE_CREATE, ROLE_CONSUME, ROLE_DESTROY, ROLE_QUERY  # noqa: E402
from hforge.producers import rank as ranking                           # noqa: E402
from hforge.producers.header_graph import (                            # noqa: E402
    base_type, infer_role, parse_header, propose, to_api, _handle_type,
)

ROOT = Path(__file__).resolve().parents[1]
HDR = ROOT / "examples" / "lib" / "hf_demo.h"


def _decls():
    return parse_header(str(HDR))


def _target() -> Target:
    return Target(name="hf_demo", public_headers=["hf_demo.h"],
                  include_dirs=[str(HDR.parent)],
                  sources=[str(HDR.parent / "hf_demo.c")])


# ── header parsing ────────────────────────────────────────────────────────────

def test_producer_parses_pointer_returning_declarations():
    """Regression. The declaration regex required whitespace between the return type and
    the name, so `hd_ctx *hd_open(void);` never matched — and that shape is every
    constructor in every C library with an opaque handle. The producer then inferred no
    handle type, called every function a `query`, and proposed zero plans while reporting
    no error at all."""
    names = {d.name for d in _decls()}
    assert "hd_open" in names, "a pointer-returning constructor must parse"
    assert names == {"hd_open", "hd_parse", "hd_parse_n", "hd_close", "hd_depth"}


def test_base_type_normalises_qualifiers_and_stars():
    assert base_type("const hd_ctx *") == base_type("hd_ctx *") == "hd_ctx"
    assert base_type("struct foo **") == "foo"


def test_parser_ignores_prototypes_inside_comments():
    import tempfile
    p = Path(tempfile.mkdtemp()) / "x.h"
    p.write_text("/* void ghost(int a); */\nint real(int a);\n")
    assert {d.name for d in parse_header(str(p))} == {"real"}


# ── inference ─────────────────────────────────────────────────────────────────

def test_handle_type_is_inferred():
    assert base_type(_handle_type(_decls())) == "hd_ctx"


def test_role_inference_from_signatures():
    d = _decls()
    h = _handle_type(d)
    roles = {x.name: infer_role(x, h) for x in d}
    assert roles["hd_open"] == ROLE_CREATE
    assert roles["hd_close"] == ROLE_DESTROY
    assert roles["hd_parse"] == ROLE_CONSUME
    assert roles["hd_parse_n"] == ROLE_CONSUME
    assert roles["hd_depth"] == ROLE_QUERY


def test_contract_inference_finds_cstrings_and_length_pairs():
    d = _decls()
    h = _handle_type(d)
    apis = {x.name: to_api(x, h) for x in d}
    # `const char *json` with no size partner is a C string: termination is the contract
    assert apis["hd_parse"].contract.nul_terminated == ["json"]
    # `const uint8_t *buf, size_t n` is a pair, and must NOT be called a C string
    assert apis["hd_parse_n"].contract.length_delimited == [["buf", "n"]]
    assert apis["hd_parse_n"].contract.nul_terminated == []
    # a constructor returning a pointer signals failure with NULL
    assert apis["hd_open"].contract.error_return == "null"
    assert "c" in apis["hd_parse"].contract.requires_nonnull


# ── plan synthesis ────────────────────────────────────────────────────────────

def test_proposed_plans_pass_the_static_gates():
    """The producer is allowed to be wrong. What it may not do is produce plans that the
    gates then wave through — so every proposal is gated, and here they must be clean."""
    plans = propose([str(HDR)], _target())
    # Several plans per consuming entry point now, not one: the producer proposes structural
    # and knob variants and lets D8 measure which reaches further. What must hold is that
    # every entry point is covered and every proposal is clean.
    entries = {ir.name.split("_len")[0] for ir in plans}
    assert entries >= {"hf_demo_hd_parse", "hf_demo_hd_parse_n"}, sorted(entries)
    assert len({ir.knobs.max_len for ir in plans}) > 1, \
        "max_len is a single guessed constant again; it should be measured"
    for ir in plans:
        blocking = [v for g in run_static_gates(ir) for v in g.violations
                    if v.severity == BLOCK]
        assert not blocking, f"{ir.name}: {[v.code for v in blocking]}"


def test_proposed_plan_feeds_a_cstring_api_a_terminated_slice():
    plans = {p.name: p for p in propose([str(HDR)], _target())}
    ir = plans["hf_demo_hd_parse"]
    assert [s.kind for s in ir.slices] == ["cstring"]


def test_proposed_plan_feeds_a_length_api_a_raw_buffer_and_its_length():
    plans = {p.name: p for p in propose([str(HDR)], _target())}
    ir = plans["hf_demo_hd_parse_n"]
    assert [s.kind for s in ir.slices] == ["bytes"]
    consume = next(o for o in ir.sequence if o.api == "hd_parse_n")
    srcs = {a.param: a.source for a in consume.args}
    assert srcs["buf"] == "input" and srcs["n"] == "length_of"


def test_proposed_plans_are_create_consume_destroy():
    for ir in propose([str(HDR)], _target()):
        assert [o.api for o in ir.sequence][0] == "hd_open"
        assert [o.api for o in ir.sequence][-1] == "hd_close"
        assert ir.producer == "header_graph"


def test_producer_declines_rather_than_guessing():
    """A header with nothing attacker-controllable yields no plan, not a bad one."""
    import tempfile
    p = Path(tempfile.mkdtemp()) / "y.h"
    p.write_text("int version(void);\nvoid reset(void);\n")
    assert propose([str(p)], _target()) == []


# ── ranking ───────────────────────────────────────────────────────────────────

def _g(gate: str, viol=(), **ev) -> GateResult:
    return decide(gate, gate, list(viol), **ev)


def _blocking() -> Violation:
    return Violation("X.BLOCK", BLOCK, "blocking")


def test_ranking_prefers_a_shippable_plan():
    bad = ranking.score("bad", "p", [_g("S2", [_blocking()]),
                                     _g("D2", kill_rate="9/9"), _g("D4", fraction=1.0)])
    good = ranking.score("good", "p", [_g("S2"), _g("D2", kill_rate="1/9"),
                                       _g("D4", fraction=0.1)])
    assert ranking.rank([bad, good])[0].plan_name == "good"
    assert not bad.shippable and good.shippable


def test_ranking_prefers_a_higher_kill_rate():
    lo = ranking.score("lo", "p", [_g("D2", kill_rate="1/4"), _g("D4", fraction=0.9)])
    hi = ranking.score("hi", "p", [_g("D2", kill_rate="4/4"), _g("D4", fraction=0.3)])
    assert ranking.rank([lo, hi])[0].plan_name == "hi", \
        "finding planted defects outranks touching more sinks"


def test_ranking_penalises_gates_that_did_not_run():
    ran = ranking.score("ran", "p", [_g("D2", kill_rate="2/4"), _g("D4", fraction=0.5)])
    unrun = ranking.score("unrun", "p", [_g("D2", kill_rate="2/4"), _g("D4", fraction=0.5),
                                         not_run("D11", "t", "no sibling")])
    assert ranking.rank([unrun, ran])[0].plan_name == "ran"


def test_ranking_is_deterministic_under_ties():
    """An earlier ranking in this programme's own research reported P@50 = 1.00 because a
    stable sort preserved filesystem order inside a large tie group. The number measured
    os.listdir, not the method. Ties break on name here, deterministically."""
    a = ranking.score("bbb", "p", [_g("D2", kill_rate="1/1")])
    b = ranking.score("aaa", "p", [_g("D2", kill_rate="1/1")])
    assert [s.plan_name for s in ranking.rank([a, b])] == ["aaa", "bbb"]
    assert [s.plan_name for s in ranking.rank([b, a])] == ["aaa", "bbb"]


def test_ranking_records_why_a_plan_is_unshippable():
    s = ranking.score("bad", "p", [_g("S2", [_blocking()])])
    assert s.reasons and "X.BLOCK" in s.reasons[0]


def test_producer_supplies_no_score_of_its_own():
    """The doctrine, mechanically: nothing a producer emits may influence selection."""
    from hforge.ir import HarnessIR
    for ir in propose([str(HDR)], _target()):
        assert not hasattr(ir, "confidence")
        assert not hasattr(ir, "score")
        assert "confidence" not in ir.to_json()



def test_a_const_pointer_is_never_an_out_parameter():
    """`sqlite3_blob_write(blob, const void *z, int n, int iOffset)` takes a buffer the
    CALLER supplies. Calling it an out-parameter made the emitter declare
    `void hf_out_... = {0};`, which is not valid C — and the plan shipped anyway and was
    named the winner off six static gates."""
    from hforge.emit.c_libfuzzer import emit
    from hforge.producers import header_graph as hg
    from hforge.ir import Knobs, Target
    import tempfile, os
    src = """
typedef struct blob blob;
blob *blob_open(void);
void blob_close(blob *b);
int blob_set_name(blob *b, const char *n);
int blob_write(blob *b, const void *z, int n, int iOffset);
"""
    d = tempfile.mkdtemp()
    h = os.path.join(d, "b.h")
    open(h, "w").write(src)
    t = Target(name="b", public_headers=["b.h"], include_dirs=[d])
    for p in hg.propose([h], t, platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096)):
        c = emit(p).source            # must not raise, and must not contain `void x = {0}`
        assert "void hf_out_" not in c, c


def test_a_void_out_parameter_is_refused_rather_than_miscompiled():
    from hforge.emit.c_libfuzzer import emit, EmitError
    from hforge.ir import (Api, Arg, Contract, HarnessIR, Knobs, Op, ParamDecl, Target,
                           TypeRef, ROLE_CONSUME)
    apis = {"f": Api("f", "a.h", [ParamDecl("z", TypeRef("void *", "pointer"))],
                     TypeRef("int"), ROLE_CONSUME, Contract())}
    ir = HarnessIR(name="t", target=Target("a", public_headers=["a.h"]), apis=apis,
                   sequence=[Op("o_drive", "f", [Arg("z", "out")])],
                   knobs=Knobs(), platforms=["linux-x86_64-glibc"])
    try:
        emit(ir)
    except EmitError as e:
        assert "out-parameter" in str(e)
    else:
        raise AssertionError("a void out-parameter must be refused, not emitted as C")



def test_a_plan_that_never_compiled_is_not_measured():
    """Three rounds of this, each one shipping harnesses that had never run.

    A plan handed to the measuring pass counted as measured even when its harness compiled
    to nothing. The first fix accepted any non-NOT_RUN gate starting with D — and D4 is
    STATIC reachability needing no binary, so three uncompilable sqlite harnesses shipped on
    D4 alone. The second fix included D1, which inspects undefined symbols in an OBJECT
    FILE: four more plans, for APIs behind -DSQLITE_ENABLE_RTREE and -DSQLITE_ENABLE_SNAPSHOT,
    compiled fine, failed to LINK, and shipped on D1 alone."""
    import inspect
    from hforge import cli
    src = inspect.getsource(cli.cmd_batch)
    assert '_RAN_THE_HARNESS = ("D2", "D3", "D5", "D6", "D8")' in src
    assert "g.gate in _RAN_THE_HARNESS" in src
    listed = src.split("_RAN_THE_HARNESS =")[1].split(")")[0]
    # D4 is static reachability; D1 inspects an object file. Neither runs the harness, and
    # four sqlite plans shipped on D1 alone after failing to LINK.
    assert "D4" not in listed and "D1" not in listed


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    bad = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as e:                                    # noqa: BLE001
            bad += 1
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - bad}/{len(fns)} passed")
    raise SystemExit(1 if bad else 0)
