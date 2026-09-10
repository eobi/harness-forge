"""P7: the mobile MESSAGE SURFACE — platform-aware emit and the SMS/PDU + media producer.

Pinned because the platform axis is the one the router was missing: `Target.language` alone
chose the backend, so a plan whose `platforms` said Android or the iOS Simulator got a host
build and the platform was a comment. These tests hold the router to honouring the platform,
and hold the iOS `emit_ready` flag to the invariant that flipping it True requires emit to
actually apply -target/-isysroot.
"""
from pathlib import Path

from hforge import platform as plat
from hforge.emit import backend_for, emit, normalise
from hforge.emit import android_ndk, ios_sim
from hforge.emit.c_libfuzzer import EmitError
from hforge.ir import APP_BUFFER, AppEntry, HarnessIR, Target
from hforge.producers import message_surface as ms

EX = Path(__file__).resolve().parent.parent / "examples" / "lib"
MSG_H = str(EX / "hf_msg.h")


def _app_ir(platforms):
    ae = AppEntry(symbol="sms_pdu_decode", channel=APP_BUFFER, header="hf_msg.h")
    return HarnessIR(name="m", target=Target(name="hfmsg", sources=["hf_msg.c"],
                                             include_dirs=["examples/lib"]),
                     platforms=list(platforms), app_entry=ae)


# ── the router now honours platforms, and still refuses an unknown language ────

def test_backend_for_still_refuses_an_unknown_language():
    """The pre-existing contract must not regress: a language nothing emits is refused, not
    silently emitted as C."""
    try:
        backend_for("rust")
    except EmitError as e:
        assert "no backend" in str(e) and "rust" in str(e)
    else:
        raise AssertionError("an unknown language must still be refused")


def test_a_language_string_alone_routes_exactly_as_before():
    assert normalise("c") == "c" and normalise("cpp") == "c++"
    # No platforms given -> the language backend, unchanged.
    from hforge.emit import c_libfuzzer
    assert backend_for("c") is c_libfuzzer.emit


def test_android_platform_routes_to_the_ndk_backend():
    assert backend_for("c", ["android-arm64-emulator"]) is android_ndk.emit


def test_ios_simulator_platform_routes_to_the_ios_sim_backend():
    assert backend_for("c", ["ios-arm64-simulator"]) is ios_sim.emit


def test_android_wins_when_a_plan_lists_both_mobile_platforms():
    """Android is the discovery platform, the iOS Simulator a reachability oracle: fuzz where
    instrumentation is cheap, prove reachability where the target runs."""
    assert backend_for("c", ["android-arm64-emulator", "ios-arm64-simulator"]) is android_ndk.emit


def test_the_jvm_never_cross_compiles_for_a_mobile_platform():
    """The JVM abstracts the OS; a Java plan stays on Jazzer regardless of platform."""
    from hforge.emit import java_jazzer
    assert backend_for("java", ["android-arm64-emulator"]) is java_jazzer.emit


# ── the emitted build commands are real cross-builds, not host builds ──────────

def test_android_emit_keeps_the_source_but_cross_builds_with_the_ndk():
    e = emit(_app_ir(["android-arm64-emulator"]))
    assert "LLVMFuzzerTestOneInput" in e.source     # one plan, many backends: same source
    assert any("hwaddress" in a for a in e.build_command), "HWASan is the on-device detector"
    joined = " ".join(e.build_command)
    assert "android" in joined.lower(), "the NDK clang triple names android"
    # the baseline (driver) build carries no sanitizer: it is the differential's control
    assert not any("sanitize" in a for a in e.driver_build_command)


def test_ios_sim_emit_applies_target_and_isysroot():
    """The load-bearing invariant: emit_ready may be True only because emit actually applies
    -target and -isysroot for the simulator. If this fails, emit_ready must go back to False."""
    e = emit(_app_ir(["ios-arm64-simulator"]))
    assert "LLVMFuzzerTestOneInput" in e.source
    assert "-target" in e.build_command
    ti = e.build_command.index("-target")
    assert e.build_command[ti + 1] == "arm64-apple-ios13.0-simulator"
    assert "-isysroot" in e.build_command


def test_ios_simulator_emit_ready_is_backed_by_target_and_isysroot():
    """Tie the flag to the behaviour directly: if the table says emit-ready, the emitter must
    prove it applies the cross-build flags — the honest-refusal invariant, as a test."""
    for pid in ("ios-arm64-simulator", "ios-x86_64-simulator"):
        p = plat.get(pid)
        if not p.emit_ready:
            continue
        e = emit(_app_ir([pid]))
        assert "-target" in e.build_command and "-isysroot" in e.build_command, (
            f"{pid}.emit_ready is True but emit did not apply -target/-isysroot")


def test_ios_device_is_never_emit_ready_reachability_only():
    """An iOS *device* is a reachability oracle with no discovery toolchain: never emitted."""
    dev_p = plat.get("ios-arm64-device")
    assert dev_p.emit_ready is False
    assert dev_p.trust_ceiling == plat.TRUST_REACHABILITY_ONLY
    # and the router does not route a device to a mobile backend
    from hforge.emit import c_libfuzzer
    assert backend_for("c", ["ios-arm64-device"]) is c_libfuzzer.emit


# ── the producer recognises the two messaging surfaces ─────────────────────────

def test_surface_of_separates_sms_from_media():
    assert ms.surface_of("sms_pdu_decode") == "sms"
    assert ms.surface_of("gsm7_unpack") == "sms"
    assert ms.surface_of("mms_image_decode_rgba") == "media"
    assert ms.surface_of("heif_decode") == "media"
    assert ms.surface_of("unrelated_helper") == ""


def test_discover_partitions_the_demo_messaging_header():
    disc = ms.discover([MSG_H], ("examples/lib",))
    syms = lambda cs: {c["symbol"] for c in cs}
    assert "sms_pdu_decode" in syms(disc["sms"])
    assert "mms_image_decode_rgba" in syms(disc["media"])


def test_sms_surface_proposes_a_mobile_app_entry_plan():
    tgt = Target(name="hfmsg", sources=[str(EX / "hf_msg.c")], include_dirs=[str(EX)])
    plan, rec = ms.propose([MSG_H], tgt, includes=(str(EX),), surface="sms")
    assert plan is not None and plan.producer == "message_surface"
    assert plan.app_entry is not None and plan.app_entry.symbol == "sms_pdu_decode"
    # default platforms are the mobile targets, so emit cross-builds
    assert "android-arm64-emulator" in plan.platforms
    assert rec["surface"] == "sms"


def test_media_surface_folds_the_attachment_decode_family():
    tgt = Target(name="hfmsg", sources=[str(EX / "hf_msg.c")], include_dirs=[str(EX)])
    plan, rec = ms.propose([MSG_H], tgt, includes=(str(EX),), surface="media",
                           platforms=["ios-arm64-simulator"])
    assert plan is not None and plan.producer == "message_surface"
    # compose_app is reused: several decoders fold onto ONE input (the zero-click shape)
    assert plan.app_entry is not None and len(plan.app_entry.fold) >= 1
    assert plan.platforms == ["ios-arm64-simulator"]
    e = emit(plan)
    assert "-target" in e.build_command and "-isysroot" in e.build_command


def test_a_proposed_message_plan_passes_the_static_gates():
    from hforge.gates.static_gates import run_static_gates
    from hforge.gates.result import BLOCK
    tgt = Target(name="hfmsg", sources=[str(EX / "hf_msg.c")], include_dirs=[str(EX)])
    plan, _ = ms.propose([MSG_H], tgt, includes=(str(EX),), surface="sms")
    blocking = [v for g in run_static_gates(plan) for v in g.violations
               if v.severity == BLOCK]
    assert not blocking, f"unexpected blocks: {[v.code for v in blocking]}"


# ── device execution degrades honestly (no device required) ────────────────────

def test_ios_run_reports_unavailable_for_a_missing_binary():
    from hforge import devices
    r = devices.ios_run("nonexistent-udid", Path("/no/such/binary"), b"x")
    assert r.outcome == "unavailable" and not r.ok


def test_ios_differential_downgrades_an_instrumentation_artifact():
    """The shared, pure decision: an instrumented fault with no sanitizer report, where the
    baseline is clean, is an artifact — downgraded, not dropped. Same rule Android uses."""
    from hforge import devices, toolchain as tc
    inst = devices.DeviceRun(True, tc.FAULT, 134, "killed by signal 6", tombstone=None)
    base = devices.DeviceRun(True, tc.OK, 0, "exit 0")
    verdict, why = devices.decide_differential(inst, base)
    assert verdict == devices.ARTIFACT and "REFUSE" in why
