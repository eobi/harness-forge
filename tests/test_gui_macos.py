"""macOS GUI/out-of-process track: the crash oracle and AX role mapping, tested without a
display or a real crash (the judgement is what is exercised, not the OS).

These mirror test_gui.py: the pure classifier is the contribution, so it is judged on
fixtures -- an .ips body dict and (role, name) tuples -- not on a live process.
"""
import os
import time

import pytest

from hforge.gui import macos_ax as M
from hforge.gui import GuiOutcome, driver_for_host, classify


# ── the crash oracle: memory-safety vs mere abort ────────────────────────────

def _body(exc_type, signal, indicator="", faulting=0):
    return {
        "exception": {"type": exc_type, "signal": signal},
        "termination": {"indicator": indicator},
        "faultingThread": faulting,
    }


def test_wild_write_is_a_memory_safety_crash():
    r = M.classify_ips(_body("EXC_BAD_ACCESS", "SIGSEGV", "Segmentation fault: 11"))
    assert r["memory_safety"] is True
    assert r["signal"] == "SIGSEGV"


def test_bus_error_is_memory_safety():
    assert M.classify_ips(_body("EXC_BAD_ACCESS", "SIGBUS"))["memory_safety"] is True


def test_illegal_instruction_trap_is_a_candidate():
    # a bounds/overflow check firing traps; still a candidate, not discarded
    assert M.classify_ips(_body("EXC_BAD_INSTRUCTION", "SIGILL"))["memory_safety"] is True


def test_abort_is_a_crash_but_not_memory_safety():
    # an ASan abort / failed assert / escaped C++ throw -> SIGABRT is NOT a memsafe bug
    r = M.classify_ips(_body("EXC_CRASH", "SIGABRT", "Abort trap: 6"))
    assert r["memory_safety"] is False
    assert r["exc_type"] == "EXC_CRASH"


def test_empty_body_does_not_raise_or_over_claim():
    r = M.classify_ips({})
    assert r["memory_safety"] is False
    assert r["exc_type"] == "" and r["signal"] == ""


# ── the crash verdict feeds the shared taxonomy ──────────────────────────────

def test_crash_verdict_is_a_finding_and_carries_the_class():
    v = M.crash_verdict(M.classify_ips(_body("EXC_BAD_ACCESS", "SIGSEGV")))
    assert v.outcome is GuiOutcome.CRASHED
    assert v.is_finding() is True
    assert "memory-safety" in v.note


def test_abort_verdict_is_still_a_finding_but_labelled_other():
    v = M.crash_verdict(M.classify_ips(_body("EXC_CRASH", "SIGABRT")))
    assert v.outcome is GuiOutcome.CRASHED
    assert v.is_finding() is True          # a crash is a crash
    assert "abort/other" in v.note         # but triage knows it is not memsafe


# ── AX role normalisation into the shared error-role family ──────────────────

def test_ax_sheet_maps_to_the_error_role_family():
    # an attached modal ("could not open the file") is a rejection surface
    assert M.normalize_ax_role("AXSheet") == "dialog"
    assert M.normalize_ax_role("AXAlert") == "alert"


def test_unknown_ax_role_is_lowercased_without_prefix():
    assert M.normalize_ax_role("AXWindow") == "window"
    assert M.normalize_ax_role("") == ""


def test_ax_error_sheet_classifies_as_rejected_not_hang():
    # a normalised AX error sheet named "error" must read as REJECTED (a pass), not a hang
    tree = [("window", "Preview"), ("dialog", "The file could not be opened. Error")]
    v = classify(tree=tree, exited=False, window_ms=0.0, serviced_action=None)
    assert v.outcome is GuiOutcome.REJECTED
    assert v.is_finding() is False


def test_no_error_nodes_reads_as_accepted_not_hang():
    # MEASURED FACT 4: absence of AX observation must not manufacture a finding
    v = classify(tree=[("window", "Preview")], exited=False, window_ms=0.0,
                 serviced_action=None)
    assert v.outcome is GuiOutcome.ACCEPTED
    assert v.is_finding() is False


# ── the crash oracle attributes reports by time, not just name ───────────────

def test_newest_crash_ignores_reports_older_than_the_cutoff(tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    old = d / "victim-2020.ips"
    old.write_text('{"header":1}\n' + '{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"}}')
    old_mtime = time.time() - 1000
    os.utime(old, (old_mtime, old_mtime))
    # cutoff after the old report -> nothing attributed to this input
    assert M.newest_crash("victim", time.time(), reports_dir=str(d)) is None
    # cutoff before it -> found
    r = M.newest_crash("victim", old_mtime - 1, reports_dir=str(d))
    assert r is not None and r["memory_safety"] is True


def test_new_path_attribution_ignores_a_pre_existing_report(tmp_path):
    # the bug live-testing caught: two back-to-back runs inside one mtime tick must not
    # blame a clean input for the previous crasher's report. Attribution is by NEW path.
    d = tmp_path / "reports"
    d.mkdir()
    prior = d / "victim-0001.ips"
    prior.write_text('{"h":1}\n{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"}}')
    before = M.report_paths("victim", reports_dir=str(d))
    # a clean run adds no new report -> excluding the snapshot yields None
    assert M.newest_crash("victim", exclude=before, reports_dir=str(d)) is None
    # a new report NOT in the snapshot is attributed
    newp = d / "victim-0002.ips"
    newp.write_text('{"h":1}\n{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"}}')
    r = M.newest_crash("victim", exclude=before, reports_dir=str(d))
    assert r is not None and r["path"].endswith("victim-0002.ips")


def test_parse_ips_rejects_a_non_ips_file(tmp_path):
    p = tmp_path / "junk.ips"
    p.write_text("not json at all, one line only")
    assert M.parse_ips(str(p)) is None


# ── the environment strips the throughput shim ───────────────────────────────

def test_clean_env_removes_crashcatch_preload():
    env = M.clean_env({"DYLD_INSERT_LIBRARIES": "/x/forge-crashcatch.dylib", "PATH": "/bin"})
    assert "DYLD_INSERT_LIBRARIES" not in env
    assert env["PATH"] == "/bin"


# ── host selection is additive and never raises ──────────────────────────────

def test_driver_for_host_returns_a_module_or_none():
    d = driver_for_host()
    # on this repo's supported hosts it is a module exposing run_one; unknown host -> None
    assert d is None or hasattr(d, "GuiOutcome")
