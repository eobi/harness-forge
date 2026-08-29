"""Phase 2 tests — positive control, sink reachability, misuse provenance, consistency.

Two of these pin defects found in this engine while building it, which is the point of
having them: a control you have not seen fire is a control you do not know works.

Run:  python3 tests/test_phase2.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge import corpus                                              # noqa: E402
from hforge.analysis.sinks import build_map, strip_noise               # noqa: E402
from hforge.emit.c_libfuzzer import emit                               # noqa: E402
from hforge.gates.dynamic_gates import (                               # noqa: E402
    attribute_allocation, build, d4_sink_reachability, d11_differential,
    decide_positive_control, find_cc,
)
from hforge.gates.result import BLOCK, WARN, NOT_RUN                   # noqa: E402
from hforge.ir import HarnessIR                                        # noqa: E402
from hforge.mutate import OPERATORS, generate_mutants, _close_paren, _split_args  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "examples" / "hf_demo.good.hir.json"
BROKEN = ROOT / "examples" / "hf_demo.broken.hir.json"
LIB = ROOT / "examples" / "lib" / "hf_demo.c"


def _ir(p: Path) -> HarnessIR:
    ir = HarnessIR.loads(p.read_text())
    ir.target.sources = [str(ROOT / s) for s in ir.target.sources]
    ir.target.include_dirs = [str(ROOT / d) for d in ir.target.include_dirs]
    return ir


# ── corpus ────────────────────────────────────────────────────────────────────

def test_corpus_generator_is_deterministic():
    """A gate whose verdict changes with the weather is not a gate."""
    ir = _ir(GOOD)
    a = corpus.generate(ir, seed=7).inputs
    b = corpus.generate(ir, seed=7).inputs
    c = corpus.generate(ir, seed=8).inputs
    assert a == b
    assert a != c
    assert all(len(x) <= ir.knobs.max_len for x in a)


def test_corpus_respects_the_knobs_that_bound_the_search():
    ir = _ir(GOOD)
    ir.knobs.max_len = 8
    assert all(len(x) <= 8 for x in corpus.generate(ir).inputs)


# ── mutation engine ───────────────────────────────────────────────────────────

def test_mutation_operators_change_the_source():
    ms = generate_mutants([str(LIB)], limit=20)
    assert ms, "no mutation site found in the demo library"
    for m in ms:
        assert m.source != LIB.read_text()
        assert m.operator in OPERATORS
        assert m.expect


def test_shrink_alloc_balances_parentheses():
    """Regression. The first operator used a non-greedy regex, so `calloc(1, sizeof(x))`
    matched only up to the INNER `)`. Every mutant of every allocation using sizeof left a
    stray paren, failed to compile, and was silently counted as unbuildable — the gate
    reported a smaller denominator instead of an error."""
    src = "void f(void){ void *p = calloc(1, sizeof(struct thing)); (void)p; }"
    sites = OPERATORS["shrink_alloc"](src)
    assert sites, "the operator must find an allocation using sizeof"
    (start, end), repl, _desc, _exp = sites[0]
    mutated = src[:start] + repl + src[end:]
    assert mutated.count("(") == mutated.count(")")
    assert "))" not in mutated.replace("(void)p", "")


def test_close_paren_and_split_args_handle_nesting():
    s = "calloc(1, sizeof(struct x))"
    assert _close_paren(s, s.index("(")) == len(s) - 1
    assert _split_args("1, sizeof(struct x)") == ["1", "sizeof(struct x)"]


def test_mutants_restricted_to_reachable_code():
    ir = _ir(GOOD)
    cmap = build_map(ir.target.sources)
    reach = cmap.reachable_from({op.api for op in ir.sequence})
    for m in generate_mutants(ir.target.sources, reachable=reach, limit=20):
        assert m.function in reach, f"{m.id} landed in unreachable {m.function}"


def test_mutants_compile():
    """An uncompilable mutant is not evidence about the harness; it is a defect in us."""
    if find_cc() is None:
        return
    import subprocess, tempfile
    for m in generate_mutants([str(LIB)], limit=20):
        d = Path(tempfile.mkdtemp())
        f = d / "m.c"
        f.write_text(m.source)
        r = subprocess.run([find_cc(), "-c", f"-I{LIB.parent}", str(f), "-o", str(d / "m.o")],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"{m.id} does not compile: {r.stderr[:200]}"


# ── D2 decision core ──────────────────────────────────────────────────────────

def test_d2_blocks_a_harness_that_cannot_find_a_planted_bug():
    v = decide_positive_control(killed=0, survived=4, baseline=0, corpus_size=50)
    assert any(x.code == "D2.NO_KILL" and x.severity == BLOCK for x in v)


def test_d2_warns_on_a_low_kill_rate():
    v = decide_positive_control(killed=1, survived=5, baseline=0, corpus_size=50)
    assert any(x.code == "D2.LOW_KILL" and x.severity == WARN for x in v)


def test_d2_passes_a_harness_that_kills_most_mutants():
    assert decide_positive_control(killed=4, survived=1, baseline=0, corpus_size=50) == []


def test_d2_flags_a_baseline_that_already_faults():
    """A harness that crashes on everything would otherwise score a perfect kill rate.
    The differential is what stops that, and the warning says so."""
    v = decide_positive_control(killed=3, survived=0, baseline=12, corpus_size=50)
    assert any(x.code == "D2.BASELINE_FAULTS" for x in v)


# ── sink scanner and reachability ─────────────────────────────────────────────

def test_sink_scanner_finds_memory_sinks():
    cmap = build_map([str(LIB)])
    kinds = {s.kind for s in cmap.sinks}
    assert "alloc" in kinds and "free" in kinds and "strlen" in kinds
    assert "hd_scan" in cmap.functions


def test_sink_scanner_ignores_comments_and_strings():
    src = '/* memcpy(a,b,c) */ void f(void){ const char *s = "strcpy("; (void)s; }'
    clean = strip_noise(src)
    assert "memcpy" not in clean and "strcpy" not in clean
    assert clean.count("\n") == src.count("\n")      # line numbers preserved


def test_reachability_from_entry_points():
    ir = _ir(GOOD)
    cmap = build_map(ir.target.sources)
    reach = cmap.reachable_from({"hd_parse"})
    assert "hd_parse" in reach and "hd_scan" in reach
    assert "hd_depth" not in reach            # nothing on the harness's path calls it


def test_d4_reports_a_fraction_not_a_boolean():
    ev = d4_sink_reachability(_ir(GOOD)).evidence
    assert 0.0 <= ev["fraction"] <= 1.0
    assert ev["sinks_total"] >= ev["sinks_reachable"]
    assert "caveat" in ev, "a name-based call graph must state that it is heuristic"


def test_d4_not_run_when_there_are_no_sources():
    ir = _ir(GOOD)
    ir.target.sources = []
    assert d4_sink_reachability(ir).verdict == NOT_RUN


# ── D9 misuse provenance ──────────────────────────────────────────────────────

_HARNESS_ALLOC = """
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000112
READ of size 1 at 0x602000000112 thread T0
    #0 0x1 in hd_scan hf_demo.c:31
0x602000000112 is located 0 bytes after 2-byte region
allocated by thread T0 here:
    #0 0x2 in malloc
    #1 0x3 in LLVMFuzzerTestOneInput harness.c:28
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""

_LIBRARY_ALLOC = """
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000112
WRITE of size 4 at 0x602000000112 thread T0
    #0 0x1 in hd_scan hf_demo.c:44
0x602000000112 is located 0 bytes after 1-byte region
allocated by thread T0 here:
    #0 0x2 in calloc
    #1 0x3 in hd_open hf_demo.c:13
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""


def test_d9_attributes_a_harness_allocated_overflow():
    verdict, ev = attribute_allocation(_HARNESS_ALLOC, ["harness.c", "driver.c"],
                                       ["examples/lib/hf_demo.c"])
    assert verdict == "harness"
    assert "harness.c:28" in ev["frame"]


def test_d9_attributes_a_library_allocated_overflow():
    verdict, ev = attribute_allocation(_LIBRARY_ALLOC, ["harness.c", "driver.c"],
                                       ["examples/lib/hf_demo.c"])
    assert verdict == "library"
    assert "hf_demo.c:13" in ev["frame"]


def test_d9_says_unknown_rather_than_guessing():
    verdict, _ = attribute_allocation("no allocation stack here", ["harness.c"], ["x.c"])
    assert verdict == "unknown"


# ── D11 differential consistency ──────────────────────────────────────────────

def test_d11_not_run_with_a_single_plan():
    ir = _ir(GOOD)
    assert d11_differential([ir], [None], [b"{}"]).verdict == NOT_RUN


def test_d11_flags_disagreeing_plans():
    """The contract-correct plan and the cJSON-mistake plan must disagree on valid input.
    They are harnesses for the SAME entry point, so a disagreement is a defect in one of
    them rather than a finding about the target."""
    if find_cc() is None:
        return
    good, bad = _ir(GOOD), _ir(BROKEN)
    ga, ba = build(good, emit(good)), build(bad, emit(bad))
    if not (ga.replay_bin and ba.replay_bin):
        return
    r = d11_differential([good, bad], [ga, ba], corpus.valid_only(good).inputs)
    assert r.evidence["disagreements"], "the broken plan faults where the good one does not"
    assert any(v.code == "D11.DISAGREE" for v in r.violations)



# ── D9 and D11: gates that existed and had never run ─────────────────────────

_STACK_REPORT = """==73944==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x16af85ae8
WRITE of size 64 at 0x16af85ae8 thread T0
    #0 0x105639bb8 in __asan_memcpy+0x4b8
    #1 0x104e78f8c in body tiny.c:14
    #2 0x104e789f8 in LLVMFuzzerTestOneInput harness.c:40
Address 0x16af85ae8 is located in stack of thread T0 at offset 40 in frame
    #0 0x104e78e00 in tny_parse tiny.c:23
"""

_GLOBAL_REPORT = """==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0x5f0
READ of size 1 at 0x5f0 thread T0
    #0 0x1000 in scan tiny.c:31
0x5f0 is located 0 bytes to the right of global variable 'table' defined in 'tiny.c:9'
"""


def test_a_stack_overflow_is_attributed_not_abstained_on():
    """A stack or global buffer has no allocation stack, so D9 answered 'unknown' for every
    one of them — and stack-buffer-overflow is among the most common findings there is. It
    went unnoticed because no caller had ever passed D9 a report at all."""
    v, ev = attribute_allocation(_STACK_REPORT, ["harness.c", "driver.c"], ["tiny.c"])
    assert v == "library", (v, ev)
    assert ev["memory"] == "stack"


def test_a_global_overflow_is_attributed():
    v, ev = attribute_allocation(_GLOBAL_REPORT, ["harness.c"], ["tiny.c"])
    assert v == "library", (v, ev)


def test_a_harness_owned_stack_buffer_is_ours():
    rpt = _STACK_REPORT.replace("in tny_parse tiny.c:23", "in LLVMFuzzerTestOneInput harness.c:23")
    v, ev = attribute_allocation(rpt, ["harness.c", "driver.c"], ["tiny.c"])
    assert v == "harness", (v, ev)


def test_the_campaign_hands_its_sanitizer_report_to_the_attributing_gate():
    """D8 is the only thing in the engine that produces a sanitizer report, and D9's whole
    job is attributing one. They were never connected, so D9 reported NOT_RUN on every
    certificate ever written."""
    import inspect
    from hforge.gates import dynamic_gates as dg
    src = inspect.getsource(dg.run_dynamic_gates)
    assert "sanitizer_report" in src, "D8's report never reaches D9"
    assert "d9_misuse(ir, art, san)" in src


def test_the_libfuzzer_probe_is_cached_and_a_timeout_is_not_a_missing_runtime():
    """The probe COMPILES. Run once per plan under parallel builds it timed out, and D8 then
    reported 'no libFuzzer runtime on this host' — a claim about the machine, when the truth
    was our own probe losing a race with our own builds."""
    from hforge import toolchain as tc
    tc._LIBFUZZER_PROBE.clear()
    a = tc.libfuzzer_probe()
    b = tc.libfuzzer_probe()
    assert a == b
    assert tc.find_cc() is None or tc.find_cc() in tc._LIBFUZZER_PROBE


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
