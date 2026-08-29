#!/usr/bin/env python3
"""The JVM track. Every test here is a defect that was found by running the thing."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hforge.emit import backend_for, emit, normalise                   # noqa: E402
from hforge.emit.c_libfuzzer import EmitError                          # noqa: E402
from hforge.ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op,  # noqa: E402
                       ParamDecl, Resource, Target, TypeRef, SLICE_CSTRING,
                       ROLE_CONSUME, ROLE_CREATE)
from hforge.java import exceptions as jx                               # noqa: E402
from hforge.java import ladder as jl                                   # noqa: E402
from hforge.java import sinks as jsinks                                # noqa: E402
from hforge.java import toolchain as jt                                # noqa: E402
from hforge.producers import java_api as ja                            # noqa: E402

_results = []


def case(fn):
    _results.append(fn)
    return fn


# ── fixtures ─────────────────────────────────────────────────────────────────

LIB = """package com.example;

public class Parser implements AutoCloseable {
    private final int[] slots = new int[8];
    public Parser() { }
    public static class BadRecord extends RuntimeException {
        public BadRecord(String m) { super(m); }
    }
    public int parse(String text) throws BadRecord {
        if (text == null || text.isEmpty()) throw new BadRecord("empty");
        if (text.startsWith("DEEP")) { int i = text.length() - 4; slots[i] = 1; return slots[i]; }
        return text.length();
    }
    @Override public void close() { }
}
"""

_BUILT: dict = {}


def _fixture() -> tuple:
    """A compiled fixture library, built once."""
    if "cp" in _BUILT:
        return _BUILT["cp"], _BUILT["src"]
    javac = jt.find_javac()
    if not javac:
        return "", ""
    d = Path(tempfile.mkdtemp(prefix="hf-java-fix-"))
    pkg = d / "com" / "example"
    pkg.mkdir(parents=True)
    src = pkg / "Parser.java"
    src.write_text(LIB)
    classes = d / "classes"
    classes.mkdir()
    r = subprocess.run([javac, "--release", "17", "-d", str(classes), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return "", ""
    _BUILT["cp"], _BUILT["src"] = str(classes), str(src)
    return _BUILT["cp"], _BUILT["src"]


def _plan():
    cp, src = _fixture()
    t = Target(name="parser", public_headers=[], include_dirs=[])
    t.language = "java"
    t.link_libs = [cp]
    t.sources = [src]
    plans = ja.propose(cp, t, knobs=Knobs(max_len=4096))
    return next(p for p in plans if "parse" in p.name)


# ── the router ───────────────────────────────────────────────────────────────

@case
def test_a_language_with_no_backend_is_refused_not_emitted_as_c():
    """`Target.language` existed from Phase 1 and NOTHING dispatched on it. A plan naming an
    unsupported language would have been emitted as C — compiling, passing the static gates,
    and certifying a harness for a language it was not written in."""
    try:
        backend_for("rust")
    except EmitError as e:
        assert "no backend" in str(e) and "rust" in str(e)
    else:
        raise AssertionError("an unknown language must be refused")


@case
def test_the_router_accepts_the_spellings_producers_actually_write():
    for spelling in ("c++", "cpp", "cxx"):
        assert normalise(spelling) == "c++"
    for spelling in ("java", "jvm", "kotlin"):
        assert normalise(spelling) == "java"


# ── the classifier: Java's S2 ────────────────────────────────────────────────

_DEFECT_TRACE = """java.lang.ArrayIndexOutOfBoundsException: Index 64 out of bounds for length 8
\tat com.example.Parser.parse(Parser.java:14)
\tat Harness.fuzzerTestOneInput(Harness.java:9)
"""

_CONTRACT_TRACE = """com.example.Parser$BadRecord: empty
\tat com.example.Parser.parse(Parser.java:18)
\tat Harness.fuzzerTestOneInput(Harness.java:9)
"""

_HARNESS_TRACE = """java.lang.NullPointerException
\tat Harness.fuzzerTestOneInput(Harness.java:12)
"""


@case
def test_a_jvm_check_in_library_frames_is_a_defect():
    """Java's bounds check is the always-on memory-safety oracle: one firing in library code
    is the moral equivalent of a sanitizer report."""
    j = jx.classify(_DEFECT_TRACE, library_packages=["com.example"],
                    harness_classes=["Harness", "Harness.java"])
    assert j.verdict == jx.DEFECT, j.reason
    assert j.thrower.file == "Parser.java"


@case
def test_a_librarys_own_exception_type_is_recognised():
    """`_THROWN` required the class name to end in Exception/Error. A library's OWN type
    frequently does not — `Parser$BadRecord` — and that is the single most common case, the
    one the CONTRACT verdict exists for. It parsed to nothing and every such trace read as
    'no exception class in the trace'."""
    cls, _msg, frames = jx.parse_trace(_CONTRACT_TRACE)
    assert cls == "com.example.Parser$BadRecord", cls
    assert frames


@case
def test_a_declared_exception_is_the_contract_not_a_finding():
    """A parser handed a random byte string throws, and that is the parser working. Without
    this, every downstream gate judges noise."""
    j = jx.classify(_CONTRACT_TRACE, library_packages=["com.example"],
                    declared_throws=["com.example.Parser$BadRecord"])
    assert j.verdict == jx.CONTRACT, j.reason


@case
def test_an_exception_from_harness_frames_is_ours():
    j = jx.classify(_HARNESS_TRACE, library_packages=["com.example"],
                    harness_classes=["Harness", "Harness.java"])
    assert j.verdict == jx.HARNESS, j.reason


@case
def test_the_last_caused_by_is_what_is_judged():
    """A library that wraps a defect in its own ParseException would otherwise be judged on
    the wrapper — which a maintainer would call a misreading."""
    wrapped = ("com.example.Parser$BadRecord: bad\n\tat com.example.Parser.parse(Parser.java:5)\n"
               "Caused by: java.lang.ArrayIndexOutOfBoundsException: Index 9\n"
               "\tat com.example.Parser.body(Parser.java:14)\n")
    j = jx.classify(wrapped, library_packages=["com.example"],
                    declared_throws=["com.example.Parser$BadRecord"])
    assert j.verdict == jx.DEFECT, j.reason


@case
def test_resource_exhaustion_needs_a_ratio_not_a_threshold():
    """A 40-byte input consuming 2GB is a denial of service; a 2MB input doing so is
    arithmetic. A fixed threshold reports every large input and misses the one that matters."""
    trace = "java.lang.OutOfMemoryError: Java heap space\n\tat com.example.Parser.parse(Parser.java:9)\n"
    j = jx.classify(trace, library_packages=["com.example"])
    assert j.verdict == jx.EXHAUSTION
    big = jx.with_amplification(j, input_bytes=40, consumed_bytes=2_000_000_000)
    assert big.verdict == jx.DEFECT
    j2 = jx.classify(trace, library_packages=["com.example"])
    small = jx.with_amplification(j2, input_bytes=2_000_000, consumed_bytes=4_000_000)
    assert small.verdict == jx.CONTRACT, small.reason


@case
def test_no_ratio_stays_unmeasured_rather_than_becoming_a_claim():
    trace = "java.lang.StackOverflowError\n\tat com.example.Parser.parse(Parser.java:9)\n"
    j = jx.classify(trace, library_packages=["com.example"])
    out = jx.with_amplification(j, input_bytes=0)
    assert out.verdict == jx.EXHAUSTION and "UNMEASURED" in out.reason


# ── the ladder ───────────────────────────────────────────────────────────────

@case
def test_the_contract_cannot_climb_the_ladder():
    r, _w = jl.assign(escaped=True, reproduce_rate=1.0, minimised=True,
                      verdict=jx.CONTRACT)
    assert r == jl.J1_ESCAPED


@case
def test_a_defect_needs_an_independent_execution_mode_for_rung_three():
    """Rung 3 demands an oracle independent of the one that discovered the fault. On the JVM
    that is -Xint versus the JIT, not a second sanitizer."""
    low, _ = jl.assign(escaped=True, reproduce_rate=1.0, minimised=True, verdict=jx.DEFECT,
                       attributed_to_library=True, independent_oracle=False)
    high, _ = jl.assign(escaped=True, reproduce_rate=1.0, minimised=True, verdict=jx.DEFECT,
                        attributed_to_library=True, independent_oracle=True)
    assert low == jl.J2_REPRODUCIBLE and high == jl.J3_DEFECT


@case
def test_a_sanitizer_report_reaches_rung_five_without_a_layout_argument():
    """Stronger than its C counterpart, not weaker: the tool fired because attacker data
    reached the sink."""
    r, _w = jl.assign(escaped=True, reproduce_rate=1.0, minimised=True, verdict=jx.DEFECT,
                      attributed_to_library=True, independent_oracle=True,
                      sanitizer="SqlInjection")
    assert r == jl.J5_TRUST_BOUNDARY


@case
def test_the_c_ladder_would_make_every_java_finding_unreportable():
    """The reason this module exists. The C rung 3 is 'a memory-safety violation', witnessed
    by a second sanitizer. There is no ASan for the JVM, so on the C ladder nothing Java ever
    passes rung 2 and `reportable` is never true."""
    from hforge.findings import ladder as c_ladder
    r, _w = c_ladder.assign(faulted=True, reproduce_rate=1.0, minimised=True,
                            attributed_to_target=True, independent_oracle=False)
    assert r == c_ladder.R2_REPRODUCIBLE
    assert c_ladder.describe(3).claim != jl.describe(3).claim


@case
def test_the_ladder_is_selected_by_language_not_overloaded():
    tab, _assign, _desc = jl.for_language("java")
    assert tab is jl.LADDER
    tab2, _a2, _d2 = jl.for_language("c")
    assert tab2 is not jl.LADDER


# ── the producer ─────────────────────────────────────────────────────────────

@case
def test_javap_gives_the_throws_clause_a_c_header_cannot():
    cp, _src = _fixture()
    if not cp:
        return
    c = ja.parse_class("com.example.Parser", cp)
    m = next(x for x in c.methods if x.name == "parse")
    assert m.throws == ["com.example.Parser$BadRecord"], m.throws


@case
def test_autocloseable_is_a_declared_lifetime_not_an_inferred_one():
    """In C we guess a destructor from a name and got sqlite3_finalize wrong for weeks. The
    interface declares it here."""
    cp, _src = _fixture()
    if not cp:
        return
    assert ja.parse_class("com.example.Parser", cp).closeable


@case
def test_the_declared_contract_travels_on_the_plan():
    cp, _src = _fixture()
    if not cp:
        return
    p = _plan()
    api = p.apis["com.example.Parser.parse"]
    assert api.contract.declared_exceptions == ["com.example.Parser$BadRecord"]
    assert HarnessIR.loads(p.dumps()).apis["com.example.Parser.parse"] \
        .contract.declared_exceptions == ["com.example.Parser$BadRecord"]


# ── the emitter ──────────────────────────────────────────────────────────────

@case
def test_the_harness_catches_exactly_what_the_library_declares():
    """Run unmodified against a parser that declares BadRecord for empty input, Jazzer stops
    on the FIRST input and reports the library's own documented rejection as a crash — the
    campaign never starts. MEASURED: with the declared catch and keep_going, the same target
    ran 11.5M executions and reached the planted defect."""
    cp, _src = _fixture()
    if not cp:
        return
    src = emit(_plan()).source
    assert "catch (com.example.Parser.BadRecord" in src, src
    # A binary name spells a nested class with `$`; Java source needs `.`.
    assert "Parser$BadRecord" not in src


@case
def test_a_supertype_is_never_caught_on_a_subclass_declaration():
    """Catching RuntimeException because a method declares one subclass of it would swallow
    every real defect underneath — the opposite of the mistake being fixed."""
    cp, _src = _fixture()
    if not cp:
        return
    src = emit(_plan()).source
    assert "catch (java.lang.RuntimeException hfDeclared" not in src


@case
def test_the_local_takes_the_declared_parameter_type_not_the_slice_kind():
    """A `boolean` parameter whose slice is u8 would otherwise get
    `byte x = data.consumeByte();` passed where a boolean is wanted, and the harness would
    not compile."""
    apis = {"a.B.f": Api("a.B.f", "a.B",
                         [ParamDecl("p0", TypeRef("boolean", "scalar"))],
                         TypeRef("void", "void"), ROLE_CONSUME, Contract())}
    t = Target(name="t", public_headers=[])
    t.language = "java"
    ir = HarnessIR(name="t", target=t, apis=apis,
                   slices=[InputSlice("s", "u8", remainder=False, max_len=1)],
                   sequence=[Op("o_consume", "a.B.f", [Arg("p0", "input", "s")])],
                   knobs=Knobs(), platforms=["jvm-openjdk-x86_64"])
    src = emit(ir).source
    assert "boolean hf_s = data.consumeBoolean();" in src, src


@case
def test_the_replay_driver_implements_every_method_the_emitter_can_generate():
    """It first shipped without consumeChar, so any plan with a char parameter produced a
    Replay.java that did not compile — and D2, D3, D6 and minimisation then reported NOT_RUN
    'the replay driver was not built', which reads as a toolchain problem."""
    from hforge.emit.java_jazzer import _mini_provider, _BY_DECLARED, _CONSUME
    provider = _mini_provider()
    for _jtype, call in _BY_DECLARED.values():
        assert call.split("(")[0] in provider, call
    for _jt, remainder, bounded in _CONSUME.values():
        assert remainder.split("(")[0] in provider, remainder
        assert bounded.split("(")[0] in provider, bounded


@case
def test_a_java_plan_may_not_carry_raw_blocks():
    from hforge.ir import RawBlock
    t = Target(name="t", public_headers=[])
    t.language = "java"
    ir = HarnessIR(name="t", target=t, apis={}, sequence=[],
                   raw_blocks=[RawBlock(id="r", where="prologue", code="System.exit(0);")],
                   knobs=Knobs(), platforms=["jvm-openjdk-x86_64"])
    try:
        emit(ir)
    except EmitError as e:
        assert "raw blocks" in str(e)
    else:
        raise AssertionError("verbatim source is what the static gates cannot see into")


@case
def test_a_c_shape_has_no_java_spelling_and_is_refused():
    """`length_of` and `out` are C shapes: FuzzedDataProvider carries its own length, and
    Java returns values rather than writing through pointers."""
    apis = {"a.B.f": Api("a.B.f", "a.B", [ParamDecl("p0", TypeRef("int", "scalar"))],
                         TypeRef("void", "void"), ROLE_CONSUME, Contract())}
    t = Target(name="t", public_headers=[])
    t.language = "java"
    ir = HarnessIR(name="t", target=t, apis=apis,
                   slices=[InputSlice("s", SLICE_CSTRING, remainder=True)],
                   sequence=[Op("o_consume", "a.B.f", [Arg("p0", "length_of", "s")])],
                   knobs=Knobs(), platforms=["jvm-openjdk-x86_64"])
    try:
        emit(ir)
    except EmitError as e:
        assert "length_of" in str(e)
    else:
        raise AssertionError("a C argument shape must be refused, not guessed at")


# ── the toolchain ────────────────────────────────────────────────────────────

@case
def test_a_jvm_fault_is_read_from_output_never_from_the_exit_code():
    """A JVM process that dies of an uncaught exception exits 1 — and so does a missing file,
    a bad classpath and a JVM that would not start. Passing that to `classify_exit` reports
    `ok` for every Java crash, so every D3/D5/D6 result would have read clean."""
    from hforge.java import CLEAN_MARKER, FAULT_MARKER
    from hforge import toolchain as ctc
    assert jt.classify_output(FAULT_MARKER + "\njava.lang.NullPointerException", 0) == jt.FAULT
    assert jt.classify_output(CLEAN_MARKER, 0) == jt.OK
    # the C classifier, given the same JVM status, reports a clean run
    assert ctc.classify_exit(1, os_name="linux", sanitized=False) == ctc.OK


@case
def test_no_marker_at_all_is_a_broken_run_not_a_clean_one():
    """The driver never reached its own printout: a missing class, a bad classpath. Calling
    that OK is how a certificate comes to rest on nothing."""
    assert jt.classify_output("Error: Could not find or load main class Replay", 1) \
        == jt.DRIVER_ERROR


@case
def test_a_fault_only_under_the_jit_is_refused_as_a_library_defect():
    """Rung 3's independence check. A fault that appears only under C2 is a compiler artifact
    and reporting it to the library's maintainer would be wrong."""
    faulted = jt.JvmRun(jt.FAULT, "", 0)
    clean = jt.JvmRun(jt.OK, "", 0)
    ok, reading = jt.decide_jit_differential(faulted, faulted)
    assert ok and "-Xint" in reading
    bad, reading2 = jt.decide_jit_differential(faulted, clean)
    assert not bad and "JIT" in reading2


# ── the sink table ───────────────────────────────────────────────────────────

@case
def test_the_highest_value_jvm_sink_would_score_zero_under_the_c_table():
    """Nothing is overwritten when readObject deserialises attacker bytes, and it is the most
    damaging bug class the platform has."""
    from hforge.analysis.sinks import SINKS as C_SINKS
    src = "ObjectInputStream in = new ObjectInputStream(s); Object o = in.readObject();"
    assert "deserialize" in jsinks.scan(src)
    assert not any(pat.search(src) for pat, _w in C_SINKS.values())


@case
def test_a_disarmed_sink_is_not_reported():
    """A DocumentBuilderFactory with secure processing on is not an XXE risk, and scoring it
    as one sends a maintainer to a line that is already safe."""
    unsafe = "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();"
    safe = unsafe + " f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);"
    assert "xml" in jsinks.scan(unsafe)
    assert "xml" not in jsinks.scan(safe)


# ── the platform model ───────────────────────────────────────────────────────

@case
def test_native_image_has_a_lower_ceiling_because_memory_faults_return():
    """AOT-compiled, so C-class memory faults become possible again and the JVM's guarantees
    no longer hold uniformly. A finding must not be claimed to transfer across it."""
    from hforge import platform as pl
    assert pl.get("jvm-openjdk-x86_64").ceiling_rung > \
        pl.get("jvm-graalvm-native-x86_64").ceiling_rung


@case
def test_the_jvm_checks_are_modelled_as_an_always_on_oracle():
    from hforge import platform as pl
    assert "jvm-checks" in pl.get("jvm-openjdk-x86_64").sanitizers


# ── end to end, if a JDK is present ──────────────────────────────────────────

@case
def test_the_emitted_replay_driver_compiles_and_finds_the_planted_defect():
    cp, src = _fixture()
    if not cp:
        return
    from hforge.java import gates as jg
    p = _plan()
    em = emit(p)
    art = jg.build(p, em, classpath=cp)
    assert art.replay_ok, art.log
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"DEEP" + b"A" * 12)
        bad = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello")
        good = f.name
    assert jt.replay(str(art.classes), bad, classpath=cp).outcome == jt.FAULT
    assert jt.replay(str(art.classes), good, classpath=cp).outcome == jt.OK


@case
def test_minimisation_shrinks_and_keeps_the_same_fault():
    """The first replay ran INSIDE the `with` block, before the temp file was flushed: the
    driver read an empty file, saw no fault, and minimise returned 'did not shrink' every
    time. Every reproducer stayed at its campaign size and nothing looked wrong."""
    cp, _src = _fixture()
    if not cp:
        return
    from hforge.java import gates as jg
    p = _plan()
    art = jg.build(p, emit(p), classpath=cp)
    if not art.replay_ok:
        return
    small, shrank = jg.minimise(art, b"DEEP" + b"A" * 200, classpath=cp)
    assert shrank and len(small) < 30, (len(small), shrank)
    assert small.startswith(b"DEEP")


@case
def test_a_reduction_that_changes_the_exception_is_not_a_reduction():
    """Reducing on 'still crashes' alone turns a 91-byte ArrayIndexOutOfBounds into a 2-byte
    NumberFormatException and reports the wrong bug with a confident minimal reproducer."""
    from hforge.java.gates import _signature
    a = jt.JvmRun(jt.FAULT, "java.lang.ArrayIndexOutOfBoundsException\n"
                            "\tat com.example.Parser.parse(Parser.java:14)\n", 0)
    b = jt.JvmRun(jt.FAULT, "java.lang.NumberFormatException\n"
                            "\tat com.example.Parser.parse(Parser.java:26)\n", 0)
    assert _signature(a) != _signature(b)


@case
def test_d1_reads_the_constant_pool_for_the_target_call():
    cp, _src = _fixture()
    if not cp:
        return
    from hforge.java import gates as jg
    p = _plan()
    em = emit(p)
    art = jg.build(p, em, classpath=cp)
    if not art.ok:
        return                       # no Jazzer API jar on this host
    g = jg.d1_liveness(p, em, art)
    assert g.verdict == "pass", g.evidence
    assert any("Parser.parse" in r for r in g.evidence["bytecode_refs"])


if __name__ == "__main__":
    ok = 0
    for fn in _results:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
            ok += 1
        except AssertionError as e:
            print(f"  FAIL {fn.__name__}\n       {e}")
        except Exception as e:                                   # noqa: BLE001
            print(f"  FAIL {fn.__name__}\n       {type(e).__name__}: {e}")
    print(f"\n{ok}/{len(_results)} passed")
    raise SystemExit(0 if ok == len(_results) else 1)
