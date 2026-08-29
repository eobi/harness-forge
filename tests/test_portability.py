#!/usr/bin/env python3
"""Phase 3.5 — the cross-platform hardening pass.

Every test here pins a defect that WOULD have shipped. The engine was written on a Mac and
worked perfectly on that Mac, which is exactly the condition under which portability bugs
survive: nothing fails, so nothing gets looked at.

The headline one is `test_windows_crash_is_not_read_as_a_clean_run`. The original fault
check was `rc < 0 or rc >= 128 or rc == 1` — the POSIX spelling. On Windows a crash comes
back as an NTSTATUS such as 0xC0000005, which is neither negative nor between 128 and 255 in
the way that check expects. Every crash would have read as a clean run. D2 would have
reported a 0% kill rate against a harness that was working, D3 would have passed a harness
that crashes on valid input, and the engine would have certified harnesses that detect
nothing while printing that everything passed.

That is the failure mode this entire project exists to catch in other people's harnesses.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge import devices as dev, platform as plat, toolchain as tc   # noqa: E402

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
    except Exception as e:                                    # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


# ── exit-code classification: the wrong-answer bug ───────────────────────────

def test_windows_crash_is_not_read_as_a_clean_run():
    """THE defect. An access violation must classify as a fault on Windows."""
    for status in (0xC0000005, 0xC0000374, 0xC00000FD, 0xC0000409, 0x80000003):
        got = tc.classify_exit(status, os_name="windows", sanitized=True)
        assert got == tc.FAULT, (
            f"NTSTATUS 0x{status:08X} classified as {got!r}, not a fault. On Windows this "
            f"means every crash reads as a clean run and the engine certifies harnesses "
            f"that detect nothing.")


def test_windows_signed_ntstatus_is_handled():
    """Python may hand back the signed form of the same value. Both must agree."""
    assert tc.classify_exit(-1073741819, os_name="windows", sanitized=True) == tc.FAULT
    assert (tc.classify_exit(-1073741819, os_name="windows", sanitized=True)
            == tc.classify_exit(0xC0000005, os_name="windows", sanitized=True))


def test_unenumerated_ntstatus_still_faults():
    """The NTSTATUS error space is large. A crash we did not list must not read as success."""
    assert tc.classify_exit(0xC0000123, os_name="windows", sanitized=True) == tc.FAULT


def test_posix_signal_forms_both_fault():
    assert tc.classify_exit(-11, os_name="linux", sanitized=True) == tc.FAULT
    assert tc.classify_exit(139, os_name="linux", sanitized=True) == tc.FAULT
    assert tc.classify_exit(-6, os_name="macos", sanitized=True) == tc.FAULT


def test_posix_signal_number_is_not_a_windows_crash():
    """139 is SIGSEGV's shell spelling on POSIX and an ordinary exit code on Windows.
    Reading it as a crash on Windows would invent faults that did not happen."""
    assert tc.classify_exit(139, os_name="linux", sanitized=True) == tc.FAULT
    assert tc.classify_exit(139, os_name="windows", sanitized=True) == tc.OK


def test_sanitizer_exit_1_only_counts_when_sanitized():
    """ASan with abort_on_error=0 exits 1. On an UNsanitized build, 1 is an ordinary error
    return, and treating it as a crash would turn every failure path into a finding."""
    assert tc.classify_exit(1, os_name="linux", sanitized=True) == tc.FAULT
    assert tc.classify_exit(1, os_name="linux", sanitized=False) == tc.OK


def test_driver_error_is_distinct_from_a_fault():
    """Our replay driver returns 2 when it cannot read its input. That is our bug, not the
    target's, and conflating them would manufacture findings out of I/O errors."""
    for os_name in ("linux", "macos", "windows"):
        assert tc.classify_exit(2, os_name=os_name, sanitized=True) == tc.DRIVER_ERROR


def test_timeout_is_its_own_verdict():
    assert tc.classify_exit(None, os_name="linux", sanitized=True) == tc.TIMEOUT
    assert tc.classify_exit(None, os_name="windows", sanitized=True) == tc.TIMEOUT


def test_clean_exit_is_ok_everywhere():
    for os_name in ("linux", "macos", "windows"):
        assert tc.classify_exit(0, os_name=os_name, sanitized=True) == tc.OK


def test_describe_exit_names_the_windows_status():
    assert "ACCESS_VIOLATION" in tc.describe_exit(0xC0000005, "windows")
    assert "signal 11" in tc.describe_exit(-11, "linux")


# ── host and toolchain ───────────────────────────────────────────────────────

def test_host_maps_to_a_modelled_platform():
    """If the host does not resolve to a modelled platform, every certificate produced on it
    would carry an unknown trust ceiling."""
    h = tc.host()
    assert h.platform_id in plat.PLATFORMS, (
        f"host resolves to {h.platform_id!r}, which the platform model does not contain")


def test_exe_suffix_matches_the_host():
    h = tc.host()
    assert h.exe_suffix == (".exe" if h.os == "windows" else "")


def test_inventory_states_a_cost_for_every_tool():
    """A missing-tool warning with no stated cost is a warning people learn to ignore."""
    for t in tc.inventory().tools:
        assert t.required_for and t.cost_if_absent, f"{t.name} does not say what it costs"


def test_gates_use_the_shared_toolchain():
    """dynamic_gates must not re-implement discovery; that is how the Mac paths got baked
    in the first time."""
    src = (Path(__file__).resolve().parents[1] / "hforge/gates/dynamic_gates.py").read_text()
    assert "find_cc = tc.find_cc" in src, "dynamic_gates has its own compiler discovery again"
    assert "opt/homebrew" not in src, "a Homebrew path is hardcoded in the gates again"


def test_replay_binary_gets_an_exe_suffix():
    src = (Path(__file__).resolve().parents[1] / "hforge/gates/dynamic_gates.py").read_text()
    assert "tc.host().exe_suffix" in src, (
        "the replay binary is named without a platform suffix, so it cannot build or run "
        "on Windows")


def test_run_once_delegates_classification():
    """Check the CODE, not the prose. The first version of this test read the raw file and
    tripped on the docstring that EXPLAINS the old check — a false positive of exactly the
    kind the Auditor doctrine says to expect from a control nobody adversarially tested.
    So: parse to an AST, drop the docstring, and inspect what actually executes."""
    import ast
    src = (Path(__file__).resolve().parents[1] / "hforge/gates/dynamic_gates.py").read_text()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_run_once"), None)
    assert fn is not None, "_run_once no longer exists"
    body = [n for n in fn.body if not (isinstance(n, ast.Expr)
                                       and isinstance(n.value, ast.Constant)
                                       and isinstance(n.value.value, str))]
    code = "\n".join(ast.unparse(n) for n in body)
    assert "tc.is_fault(" in code, "fault classification is inlined again instead of delegated"
    assert "128" not in code, "a hardcoded POSIX signal threshold is back in _run_once"


# ── devices ──────────────────────────────────────────────────────────────────

def test_every_device_platform_id_is_modelled():
    """The abi -> platform mapping must land on ids that actually exist, or a device run
    would carry a trust ceiling nobody defined."""
    for tmpl in dev._ABI_TO_PLATFORM.values():
        for kind in ("device", "emulator"):
            pid = tmpl.format(kind=kind)
            assert pid in plat.PLATFORMS, f"device mapping produces unmodelled platform {pid}"


def test_device_functions_degrade_without_hardware():
    """No adb, no device, no NDK: these must return emptiness and a reason, never raise and
    never claim a check ran."""
    assert isinstance(dev.android_devices(), list)
    assert isinstance(dev.ios_simulators(), list)
    cap = dev.capability_report()
    for key in ("can_build_android", "can_run_android", "blocked"):
        assert key in cap


def test_missing_ndk_reports_a_reason_not_a_silent_false():
    """A build that fails must say why. Returning ok=False with an empty reason is the
    silent-failure shape this project keeps finding in itself."""
    import os
    saved = {k: os.environ.pop(k, None) for k in
             ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT")}
    try:
        if tc.find_ndk():
            return                                    # an NDK is installed; nothing to prove
        b = dev.build_android([Path("nonexistent.c")], Path("/tmp/hf-nonexistent"))
        assert not b.ok and b.reason, "failed Android build reported no reason"
    finally:
        for k, v in saved.items():
            if v:
                os.environ[k] = v


def test_hwasan_downgrades_loudly_not_silently():
    """HWASan needs arm64 and API>=29. When it cannot be used, the build must REPORT that it
    fell back to ASan: a certificate claiming HWASan while running ASan overstates what the
    run was capable of detecting."""
    if not tc.find_ndk():
        return
    import tempfile
    src = Path(tempfile.mkdtemp()) / "t.c"
    src.write_text("int main(void){return 0;}\n")
    b = dev.build_android([src], src.parent, abi="armeabi-v7a", api=24, detector="hwasan")
    assert b.detector == "asan", (
        f"requested hwasan on armv7/api24 and the build reported {b.detector!r}; "
        f"HWASan is unavailable there, so this claim would be false")


def test_android_run_classifies_with_linux_semantics():
    """Android is Linux underneath. Using Windows semantics there, or POSIX semantics on
    Windows, is the same bug in either direction."""
    src = (Path(__file__).resolve().parents[1] / "hforge/devices.py").read_text()
    assert 'os_name="linux"' in src, "device runs do not classify exits with Linux semantics"


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_operator_commands_are_registered():
    src = (Path(__file__).resolve().parents[1] / "hforge/cli.py").read_text()
    for cmd in ("doctor", "devices", "selftest"):
        assert f'sub.add_parser("{cmd}"' in src, f"'{cmd}' is not a registered command"


def test_selftest_treats_skip_as_distinct_from_pass():
    """The whole doctrine in one line: an absent check must never read as a passed one."""
    src = (Path(__file__).resolve().parents[1] / "hforge/cli.py").read_text()
    assert "SKIPPED is not PASSED" in src


# ── the Android instrumentation-artifact oracle ──────────────────────────────
# Added after a live emulator run produced a SIGSEGV that was not a bug in anything.

def _run(outcome, tomb=None):
    return dev.DeviceRun(ok=True, outcome=outcome, exit_code=None, detail="", tombstone=tomb)


def test_instrumented_only_fault_is_an_artifact_not_a_finding():
    """The defect this whole section exists for. A HWASan binary on a stock Android image
    SIGSEGVs on startup. Without a baseline that is a crash, a signal 11 and a finding."""
    v, why = dev.decide_differential(_run(tc.FAULT), _run(tc.OK))
    assert v == dev.ARTIFACT, f"instrumented-only fault classified as {v!r}, not an artifact"
    assert "REFUSE" in why


def test_fault_in_both_builds_is_a_real_fault():
    v, _ = dev.decide_differential(_run(tc.FAULT), _run(tc.FAULT))
    assert v == tc.FAULT


def test_sanitizer_report_makes_an_instrumented_only_fault_real():
    """A sanitizer that produced a report caught something the baseline silently tolerated.
    That is the entire point of instrumentation and must not be discarded as an artifact."""
    v, _ = dev.decide_differential(
        _run(tc.FAULT, tomb="SUMMARY: AddressSanitizer: heap-buffer-overflow"), _run(tc.OK))
    assert v == tc.FAULT


def test_missing_baseline_is_stated_not_assumed():
    """No baseline means the question was not answered. It must not silently become a pass
    OR silently become a finding."""
    v, why = dev.decide_differential(_run(tc.FAULT), None)
    assert v == tc.FAULT and "CANNOT be distinguished" in why


def test_artifact_is_not_reportable():
    r = dev.DifferentialRun(dev.ARTIFACT, _run(tc.FAULT), _run(tc.OK), "")
    assert not r.reportable
    assert dev.DifferentialRun(tc.FAULT, _run(tc.FAULT), _run(tc.FAULT), "").reportable


def test_hwasan_needs_a_hwasan_system_image_not_just_arm64():
    """Selecting HWASan from ABI and API alone makes every run on a stock image fault. The
    presence of libclang_rt.hwasan on the device is NOT evidence — stock images ship it for
    HWASan apps."""
    import inspect
    src = inspect.getsource(dev.device_supports_hwasan)
    assert "ro.build.flavor" in src
    assert "libclang_rt" not in src.split('"""')[2], (
        "the runtime library's presence is being used as the capability check; it is present "
        "on stock images too")
    live = [d for d in dev.android_devices() if d.kind in ("device", "emulator")]
    if not live:
        return
    ok, why = dev.device_supports_hwasan(live[0].serial)
    assert isinstance(ok, bool) and why


def test_build_records_the_detector_it_was_denied():
    """A downgrade must be legible. A certificate claiming HWASan while ASan ran overstates
    what the campaign was capable of detecting."""
    b = dev.AndroidBuild(True, None, "arm64-v8a", 29, "asan", "", "", "hwasan", "stock image")
    assert b.downgraded and b.requested_detector == "hwasan" and b.downgrade_reason
    assert not dev.AndroidBuild(True, None, "arm64-v8a", 29, "hwasan", "", "",
                                "hwasan", "").downgraded


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"portability — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
