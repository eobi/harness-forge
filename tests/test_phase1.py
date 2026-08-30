"""Phase 1 tests.

Every test here pins a failure that has actually happened, either in this codebase or in the
research corpus it is built from. A control you have not seen fire is a control you do not
know works, so each gate test constructs the defect deliberately and asserts the gate names
it.

Run:  python3 -m pytest tests -q      (or: python3 tests/test_phase1.py)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge import platform as plat                                    # noqa: E402
from hforge.certificate import build_certificate                       # noqa: E402
from hforge.emit.c_libfuzzer import emit, EmitError                    # noqa: E402
from hforge.gates.result import BLOCK, FAIL, NOT_RUN                   # noqa: E402
from hforge.gates.static_gates import run_static_gates                 # noqa: E402
from hforge.ir import (                                                # noqa: E402
    Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Resource,
    Target, TypeRef, SLICE_BYTES, SLICE_CSTRING, ROLE_CREATE, ROLE_CONSUME, ROLE_DESTROY,
)

ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "examples" / "hf_demo.good.hir.json"
BROKEN = ROOT / "examples" / "hf_demo.broken.hir.json"


# ── helpers ───────────────────────────────────────────────────────────────────

def _codes(results) -> set:
    return {v.code for r in results for v in r.violations}


def _blocking(results) -> set:
    return {v.code for r in results for v in r.violations if v.severity == BLOCK}


def _minimal(*, slice_kind=SLICE_CSTRING, guard=True, close=True,
             extra_ops=()) -> HarnessIR:
    """A small, valid plan we then break one field at a time."""
    ptr = TypeRef("hd_ctx *", "pointer")
    apis = {
        "hd_open": Api("hd_open", "d.h", [], ptr, ROLE_CREATE,
                       Contract(error_return="null")),
        "hd_parse": Api("hd_parse", "d.h",
                        [ParamDecl("c", ptr),
                         ParamDecl("json", TypeRef("const char *", "pointer", True))],
                        TypeRef("int"), ROLE_CONSUME,
                        Contract(nul_terminated=["json"], requires_nonnull=["c"],
                                 error_return="negative")),
        "hd_close": Api("hd_close", "d.h", [ParamDecl("c", ptr)],
                        TypeRef("void", "void"), ROLE_DESTROY, Contract()),
    }
    seq = [
        Op("o_open", "hd_open", [], binds="ctx"),
        Op("o_parse", "hd_parse",
           [Arg("c", "resource", "ctx"), Arg("json", "input", "json")],
           guarded_by=(["ctx"] if guard else [])),
    ]
    if close:
        seq.append(Op("o_close", "hd_close", [Arg("c", "resource", "ctx")], targets="ctx"))
    seq.extend(extra_ops)
    return HarnessIR(
        name="t", target=Target("d", public_headers=["d.h"]), apis=apis,
        slices=[InputSlice("json", slice_kind, remainder=True, min_len=1)],
        resources=[Resource("ctx", ptr)], sequence=seq,
        knobs=Knobs(sanitizers=["address"]), platforms=["linux-x86_64-glibc"])


# ── IR ────────────────────────────────────────────────────────────────────────

def test_ir_round_trip():
    ir = HarnessIR.loads(GOOD.read_text())
    again = HarnessIR.loads(ir.dumps())
    assert again.to_json() == ir.to_json()
    assert again.name == "hf_demo_parse"


def test_ir_rejects_major_version_mismatch():
    d = json.loads(GOOD.read_text())
    d["schema_version"] = "9.0"
    try:
        HarnessIR.from_json(d)
    except ValueError as e:
        assert "schema" in str(e)
    else:
        raise AssertionError("a major-version mismatch must be refused, not coerced")


# ── the headline: S2 catches the cJSON mistake without compiling ─────────────

def test_s2_rejects_non_terminated_buffer_to_cstring_api():
    """The exact-size-buffer defect that produced eight false findings against cJSON.
    It is visible in the plan. Nothing is compiled."""
    ir = _minimal(slice_kind=SLICE_BYTES)
    assert "S2.CSTRING" in _blocking(run_static_gates(ir))


def test_s2_accepts_terminated_buffer():
    assert "S2.CSTRING" not in _codes(run_static_gates(_minimal()))


def test_example_plans_behave_as_documented():
    assert _blocking(run_static_gates(HarnessIR.loads(GOOD.read_text()))) == set()
    assert "S2.CSTRING" in _blocking(run_static_gates(HarnessIR.loads(BROKEN.read_text())))


# ── S1 lifetime ───────────────────────────────────────────────────────────────

def test_s1_use_after_destroy():
    extra = (Op("o_again", "hd_parse",
                [Arg("c", "resource", "ctx"), Arg("json", "input", "json")],
                guarded_by=["ctx"]),)
    assert "S1.USE_AFTER_DESTROY" in _blocking(run_static_gates(_minimal(extra_ops=extra)))


def test_s1_double_destroy():
    extra = (Op("o_close2", "hd_close", [Arg("c", "resource", "ctx")], targets="ctx"),)
    assert "S1.DOUBLE_DESTROY" in _blocking(run_static_gates(_minimal(extra_ops=extra)))


def test_s1_leak_is_blocking_only_when_leak_detection_is_on():
    ir = _minimal(close=False)
    codes = _codes(run_static_gates(ir))
    assert "S1.LEAK" in codes
    assert "S1.LEAK" not in _blocking(run_static_gates(ir))   # leaks off: a warning
    ir.knobs.detect_leaks = True
    assert "S1.LEAK" in _blocking(run_static_gates(ir))       # leaks on: it would drown you


# ── S5, S6 ────────────────────────────────────────────────────────────────────

def test_s5_flags_input_that_never_reaches_the_target():
    ir = _minimal()
    ir.sequence[1].args = [Arg("c", "resource", "ctx"),
                           Arg("json", "literal", value="{}")]
    codes = _blocking(run_static_gates(ir))
    assert "S5.INPUT_NOT_CONSUMED" in codes


def test_s6_unchecked_failure_return():
    codes = _blocking(run_static_gates(_minimal(guard=False)))
    assert "S6.UNCHECKED_ERROR" in codes
    assert "S2.UNGUARDED_NONNULL" in codes


def test_s4_blocks_internal_symbols():
    ir = _minimal()
    ir.apis["hd_parse"].contract.internal_only = True
    assert "S4.INTERNAL" in _blocking(run_static_gates(ir))


# ── emitter ───────────────────────────────────────────────────────────────────

def test_emitter_terminates_cstring_slices():
    src = emit(_minimal()).source
    assert "hf_s_json[hf_len_json] = '\\0';" in src
    assert "malloc(hf_len_json + 1)" in src


def test_emitter_refuses_non_pointer_resources():
    ir = _minimal()
    ir.resources[0] = Resource("ctx", TypeRef("hd_ctx", "scalar"))
    try:
        emit(ir)
    except EmitError as e:
        assert "pointer" in str(e)
    else:
        raise AssertionError("the emitter must refuse rather than emit C that lies")


def test_driver_uses_an_exactly_sized_heap_buffer():
    """Regression. The first driver read inputs into `static uint8_t buf[1 << 22]`, so an
    over-read past `size` landed in valid memory, ASan stayed silent, and gate D3 CERTIFIED
    a plan gate S2 had already rejected. libFuzzer passes an exactly-sized heap allocation;
    a replay driver that does not is not modelling the thing it claims to model."""
    drv = emit(_minimal()).driver
    assert "malloc(n ? n : 1)" in drv
    assert "LLVMFuzzerTestOneInput(exact, n)" in drv
    assert "LLVMFuzzerTestOneInput(buf" not in drv


def test_emitter_guards_are_real_conditions():
    src = emit(_minimal()).source
    assert "if (hf_r_ctx) {" in src


# ── platform model ────────────────────────────────────────────────────────────

def test_ios_device_cannot_certify_what_the_simulator_can():
    dev = plat.get("ios-arm64-device")
    sim = plat.get("ios-arm64-simulator")
    assert dev.ceiling_rung < sim.ceiling_rung
    assert dev.trust_ceiling == plat.TRUST_REACHABILITY_ONLY


def test_android_device_records_scudo_and_tombstones():
    p = plat.get("android-arm64-device")
    assert p.allocator == "scudo"
    assert p.crash_artifact == "tombstone"
    assert "hwasan" in p.sanitizers          # not ASan: HWASan is the on-device detector


def test_macos_arm64e_is_dbi_limited_not_full():
    assert plat.get("macos-arm64e").trust_ceiling == plat.TRUST_DBI_LIMITED


def test_reachability_siblings_cross_apple_platforms():
    sibs = plat.reachability_siblings("macos-arm64")
    assert "ios-arm64-device" in sibs and "ios-arm64-simulator" in sibs


def test_variant_disagreement_is_read_as_an_oracle():
    msgs = plat.disagreement_meaning({"linux-x86-glibc"}, {"linux-x86_64-glibc"})
    assert any("width-dependent" in m for m in msgs)
    msgs2 = plat.disagreement_meaning({"linux-x86_64-glibc"}, {"linux-x86_64-musl"})
    assert any("allocator-dependent" in m for m in msgs2)


def test_ceiling_picks_the_strongest_platform_in_the_claim():
    rung, best = plat.ceiling(["ios-arm64-device", "linux-x86_64-glibc"])
    assert best == "linux-x86_64-glibc" and rung == 5


# ── certificate ───────────────────────────────────────────────────────────────

def test_certificate_is_provisional_when_a_gate_did_not_run():
    """A certificate with an unrun gate is never 'certified'. It is provisional, and the
    reason appears in the unreachability section rather than in an appendix."""
    ir = HarnessIR.loads(GOOD.read_text())
    gates = run_static_gates(ir)
    from hforge.gates.dynamic_gates import d11_differential
    gates.append(d11_differential([ir], [None], [b"{}"]))   # one plan: cannot compare
    cert = build_certificate(ir, gates, None)
    assert cert.verdict == "provisional"
    assert any("D11 did not run" in u for u in cert.unreachable)


def test_certificate_states_what_the_harness_cannot_find():
    ir = HarnessIR.loads(GOOD.read_text())
    from hforge.gates.dynamic_gates import d7_knobs
    cert = build_certificate(ir, list(run_static_gates(ir)) + [d7_knobs(ir)], None)
    joined = " ".join(cert.unreachable)
    assert "larger than 4096 bytes" in joined
    assert "MemorySanitizer is off" in joined


def test_certificate_rejects_a_plan_with_blocking_violations():
    ir = HarnessIR.loads(BROKEN.read_text())
    assert build_certificate(ir, run_static_gates(ir), None).verdict == "rejected"


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


# ── S2 catches the zstd inversion: input bound to the OUTPUT parameter ────────

def _two_buffer_ir(*, bind_to: str) -> HarnessIR:
    """A decompress-shaped API: an output buffer first, the const input second.

    This is ZSTD_decompress(void *dst, size_t dstCapacity, const void *src, size_t
    srcSize) reduced to the part that matters.
    """
    apis = {
        "zz_decompress": Api(
            "zz_decompress", "z.h",
            [ParamDecl("dst", TypeRef("void *", "pointer")),
             ParamDecl("dstCapacity", TypeRef("size_t")),
             ParamDecl("src", TypeRef("const void *", "pointer", True)),
             ParamDecl("srcSize", TypeRef("size_t"))],
            TypeRef("size_t"), ROLE_CONSUME,
            Contract(length_delimited=[("src", "srcSize")])),
    }
    other = "src" if bind_to == "dst" else "dst"
    seq = [Op("o_consume", "zz_decompress",
              [Arg(bind_to, "input", "buf"),
               Arg("dstCapacity" if bind_to == "dst" else "srcSize", "length_of", "buf"),
               Arg(other, "literal", value=0),
               Arg("srcSize" if bind_to == "dst" else "dstCapacity", "literal", value=0)])]
    return HarnessIR(
        name="t", target=Target("z", public_headers=["z.h"]), apis=apis,
        slices=[InputSlice("buf", SLICE_BYTES, remainder=True, min_len=1)],
        resources=[], sequence=seq,
        knobs=Knobs(sanitizers=["address"]), platforms=["linux-x86_64-glibc"])


def test_s2_rejects_input_bound_to_the_output_buffer():
    """The defect that produced a harness decompressing nothing while writing attacker
    bytes through a destination pointer. Every gate passed it, coverage fell from 30.04%
    to 2.24%, and the 2.24% still looked like a measurement."""
    codes = _blocking(run_static_gates(_two_buffer_ir(bind_to="dst")))
    assert "S2.INPUT_TO_OUTPUT" in codes, codes


def test_s2_accepts_input_bound_to_the_const_parameter():
    """The same API bound the right way round must not trip the new rule -- a gate that
    fires on the correct shape is worse than no gate."""
    codes = _blocking(run_static_gates(_two_buffer_ir(bind_to="src")))
    assert "S2.INPUT_TO_OUTPUT" not in codes, codes
