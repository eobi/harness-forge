#!/usr/bin/env python3
"""Tier F — the gates that judge a FINDING.

Sixteen gates existed before this and all sixteen judged harnesses. The engine's discipline
stopped at exactly the moment a human was about to email a maintainer.

The most important test here is `test_the_entry_point_does_not_make_it_harness_owned`. F3 as
first written matched `LLVMFuzzerTestOneInput` anywhere in the allocation stack — and that
symbol sits at the bottom of EVERY allocation stack, because it is the entry point. It would
have suppressed every real finding the gate exists to let through.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.findings import auditor, gates, ladder, pipeline, report   # noqa: E402

_pass = _fail = 0


def check(name, fn):
    global _pass, _fail
    try:
        fn()
        print(f"  ok   {name}")
        _pass += 1
    except AssertionError as e:
        print(f"  FAIL {name}\n       {e}")
        _fail += 1
    except Exception as e:                                             # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


LIB_REPORT = """ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 84
allocated by thread T0:
    #0 0x1 in calloc
    #1 0x2 in v_open vuln.c:5
    #3 0x3 in LLVMFuzzerTestOneInput harness.c:7
"""
HARNESS_REPORT = """ERROR: AddressSanitizer: heap-buffer-overflow
allocated by thread T0:
    #0 0x1 in malloc
    #1 0x2 in hf_s_json harness.c:12
    #2 0x3 in LLVMFuzzerTestOneInput harness.c:7
"""


# ── the ladder ───────────────────────────────────────────────────────────────

def test_asan_confirming_asan_does_not_reach_rung_three():
    """The thesis in one check: the proof may never come from the thing that proposed it."""
    rung, why = ladder.assign(faulted=True, reproduce_rate=1.0, minimised=True,
                              attributed_to_target=True, independent_oracle=False)
    assert rung == ladder.R2_REPRODUCIBLE, (rung, why)
    assert "one witness, not two" in why


def test_an_independent_oracle_reaches_rung_three():
    rung, _ = ladder.assign(faulted=True, reproduce_rate=1.0, minimised=True,
                            attributed_to_target=True, independent_oracle=True)
    assert rung == ladder.R3_MEMORY_SAFETY, rung


def test_harness_owned_memory_caps_at_rung_two():
    rung, why = ladder.assign(faulted=True, reproduce_rate=1.0, minimised=True,
                              attributed_to_target=False, independent_oracle=True)
    assert rung == ladder.R2_REPRODUCIBLE
    assert "HARNESS" in why


def test_a_platform_ceiling_downgrades_rather_than_drops():
    """A finding seen only where the platform cannot witness it is downgraded, not deleted —
    the rung number platform.py has been citing since Phase 1."""
    rung, why = ladder.assign(faulted=True, reproduce_rate=1.0, minimised=True,
                              attributed_to_target=True, independent_oracle=True,
                              input_derived_access=True, ceiling=3)
    assert rung == 3 and "Downgraded, not dropped" in why


def test_an_unreproducible_fault_stops_at_rung_one():
    rung, _ = ladder.assign(faulted=True, reproduce_rate=0.0, minimised=False,
                            attributed_to_target=True, independent_oracle=True)
    assert rung == ladder.R1_FAULT


# ── F3 attribution ───────────────────────────────────────────────────────────

def test_the_entry_point_does_not_make_it_harness_owned():
    """`LLVMFuzzerTestOneInput` is at the bottom of EVERY allocation stack. Matching it
    anywhere marked all memory harness-owned, which would have suppressed every real finding
    this gate exists to let through — a false positive in the direction that hides bugs."""
    g = gates.f3_attribute(gates.Crash(input_bytes=b"x", report=LIB_REPORT))
    assert g.evidence["attributed_to"] == "target", g.evidence
    assert "v_open" in g.evidence["allocation_site"]


def test_harness_allocated_memory_is_still_caught():
    g = gates.f3_attribute(gates.Crash(input_bytes=b"x", report=HARNESS_REPORT))
    assert g.evidence["attributed_to"] == "harness", g.evidence
    assert any(v.code == "F3.HARNESS_OWNED" for v in g.violations)


def test_no_report_means_not_run_not_a_pass():
    g = gates.f3_attribute(gates.Crash(input_bytes=b"x", report=""))
    assert g.verdict == "not-run" and g.reason


# ── F7 circular oracle ───────────────────────────────────────────────────────

def test_naming_the_discovering_sanitizer_as_independent_is_refused():
    c = gates.Crash(input_bytes=b"x", report=LIB_REPORT)
    assert c.discovering_oracle == "AddressSanitizer"
    g = gates.f7_rung(c, [], independent_oracle="AddressSanitizer")
    assert any(v.code == "F7.CIRCULAR_ORACLE" for v in g.violations), g.violations


def test_a_genuinely_different_oracle_is_accepted():
    c = gates.Crash(input_bytes=b"x", report=LIB_REPORT)
    g = gates.f7_rung(c, [], independent_oracle="valgrind")
    assert not any(v.code == "F7.CIRCULAR_ORACLE" for v in g.violations)


# ── F8 exclusions ────────────────────────────────────────────────────────────

def test_every_rung_above_the_one_reached_is_listed_as_unshown():
    c = gates.Crash(input_bytes=b"x", report=LIB_REPORT)
    g = gates.f8_exclusions(c, [], rung=2)
    text = " ".join(g.evidence["unestablished"])
    for n in (3, 4, 5, 6):
        assert f"rung {n}" in text, text


# ── the Auditor ──────────────────────────────────────────────────────────────

def test_the_auditor_catches_a_circular_confirmation():
    r = auditor.a1_circularity([{"discovering_oracle": "AddressSanitizer",
                                 "independent_oracle": "AddressSanitizer"}])
    assert any(v.code == "A1.CIRCULAR" for v in r.violations)


def test_the_auditor_groups_one_defect_reached_many_ways():
    """The most common form of inflated counts in this field."""
    r = auditor.a3_grouping([{"signature": "s1"}, {"signature": "s1"}, {"signature": "s2"}])
    assert r.evidence["crashes"] == 3 and r.evidence["distinct"] == 2


def test_the_auditor_will_not_pass_a_baseline_it_never_ran():
    r = auditor.a2_trivial_baseline(auditor.AuditInput(findings=[{"signature": "s"}]))
    assert r.verdict == "not-run" and r.reason


def test_a_null_harness_matching_the_suite_is_blocking():
    r = auditor.a2_trivial_baseline(auditor.AuditInput(
        findings=[{"signature": "a"}, {"signature": "b"}], null_harness_faults=2))
    assert any(v.code == "A2.BASELINE_COMPARABLE" for v in r.violations)


# ── the artifact ─────────────────────────────────────────────────────────────

def test_a_blocked_finding_is_not_reportable():
    f = report.Finding(id="F-0001", input_sha256="a" * 64, input_bytes=b"x", rung=2,
                       rung_reason="", signature="s",
                       gates=[gates.f3_attribute(gates.Crash(input_bytes=b"x",
                                                             report=HARNESS_REPORT))])
    assert not f.reportable
    assert "NOT REPORTABLE" in report.render(f)


def test_the_artifact_carries_the_chain_a_maintainer_needs():
    """A maintainer's first question is how to reproduce it and the second is what exactly
    was run. A report that answers neither is asking to be ignored."""
    f = report.Finding(id="F-1", input_sha256="b" * 64, input_bytes=b"xy", rung=3,
                       rung_reason="r", signature="s",
                       provenance=report.Provenance(target="libfoo", plan_name="p",
                                                    ir_sha256="c" * 64, compiler="clang",
                                                    sanitizers=["address"]))
    j = f.to_json()
    assert j["provenance"]["ir_sha256"] and j["provenance"]["compiler"]
    assert j["rung_claim"] and j["rung_oracle"]
    assert j["input_sha256"] == "b" * 64


def test_the_pipeline_refuses_a_harness_owned_crash():
    c = gates.Crash(input_bytes=b"AAAA", report=HARNESS_REPORT)
    found, audit = pipeline.triage(pipeline.Inputs(crashes=[c], campaign_seconds=10))
    assert len(found) == 1 and not found[0].reportable
    assert "not a failed run" in pipeline.summarise(found, audit)


# ── a display cap must never become a functional one ─────────────────────────

def test_a_capped_evidence_field_is_not_fed_to_a_gate():
    """D4's `reachable_functions` is capped at 200 for the certificate. `run_dynamic_gates`
    fed exactly that field to D2 as the set of functions to plant defects in, so mutants
    landed in the 200 alphabetically-first reachable functions — obscure ones no corpus
    reaches. D2 reported 0/6 kills on sqlite and looked like a weak harness rather than a
    starved gate. It now recomputes the full set."""
    src = (Path(__file__).resolve().parents[1]
           / "hforge/gates/dynamic_gates.py").read_text()
    import re
    fn = src[src.index("def run_dynamic_gates"):]
    fn = fn[:fn.index("\n    return [")] if "\n    return [" in fn else fn
    assert 'd4.evidence.get("reachable_functions"' not in fn, \
        "the truncated evidence field is being fed to a gate again"
    assert "cmap.reachable_from" in fn, "the full reachable set is not recomputed"


def test_the_evidence_says_when_it_was_truncated():
    from hforge.analysis import sinks
    src = Path(__file__).resolve().parents[1] / "examples/lib/hf_demo.c"
    m = sinks.build_map([str(src)])
    s = m.sink_surface(["hd_parse"])
    assert "reachable_functions_truncated" in s, \
        "a capped list that does not say it was capped reads as complete"
    assert s["functions_reachable"] >= len(s["reachable_functions"])



# ── our own false-positive rate ──────────────────────────────────────────────

def test_every_constructed_defect_is_a_harness_bug_not_a_library_bug():
    """The experiment's whole validity rests on this: if a "defective" plan were actually
    fine, a real library bug would be counted as our false positive."""
    from hforge.findings import fprate
    assert len(fprate.DEFECTS) >= 5
    for d in fprate.DEFECTS:
        assert d.why_false, d.id
        assert d.what, d.id


def test_the_static_gates_intercept_the_known_defect_classes():
    """The axis this engine exists on. QuartetFuzz attributes its 58 harness-induced
    crashes AFTER running them."""
    from hforge.findings import fprate
    from hforge.gates.static_gates import run_static_gates
    from hforge.gates.result import BLOCK
    from hforge.ir import Target
    t = Target(name="sqlite3", public_headers=["sqlite3.h"])
    for d in fprate.DEFECTS:
        rs = run_static_gates(d.build(t))
        blocked = {v.code for r in rs for v in r.violations if v.severity == BLOCK}
        assert blocked, f"{d.id} was not intercepted by any static gate"


def test_no_crashes_is_reported_as_unmeasured_not_as_zero():
    """An engine that refused everything would otherwise report a 0% false-positive rate
    and have measured its finding gates not at all."""
    from hforge.findings import fprate
    out = [fprate.Outcome(defect="x", intercepted_by=["S2.TYPE_CONFUSION"], built=False)]
    text = fprate.render(out)
    assert "UNMEASURED" in text
    assert "0.0%" not in text


def test_a_defect_that_never_fired_is_no_evidence_either_way():
    """sqlite3_open allocates a handle even when it fails, so the unchecked-handle plan
    never receives the NULL its defect depends on. Counting that as a pass would credit the
    engine for a defect that never ran."""
    from hforge.findings import fprate
    out = [fprate.Outcome(defect="a", intercepted_by=["S1.X"], built=True, crashes=2,
                          escaped=0, rungs=[2]),
           fprate.Outcome(defect="b", intercepted_by=["S2.Y"], built=True, crashes=0,
                          note="the defect did not manifest on this library: no crash to "
                               "judge, which is no evidence either way")]
    text = fprate.render(out)
    assert "NO OBSERVATION" in text
    assert "2 defect classes" not in text          # only one class actually manifested


def test_the_rate_states_both_denominators():
    from hforge.findings import fprate
    out = [fprate.Outcome(defect="a", built=True, crashes=4, escaped=1, rungs=[2, 3]),
           fprate.Outcome(defect="b", built=True, crashes=4, escaped=0, rungs=[2])]
    text = fprate.render(out)
    assert "8 crashing inputs" in text and "2 defect classes" in text
    assert "12.5%" in text


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"findings — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
