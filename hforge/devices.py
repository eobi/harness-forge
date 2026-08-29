"""Reaching real devices: Android over adb, iOS over simctl.

The principle this module exists to enforce, from the platform model:

    fuzz where instrumentation is cheap; prove reachability where the target actually runs.

So the two paths are deliberately asymmetric, and the asymmetry is the design rather than a
limitation:

  * **Android** has a real toolchain. The NDK builds a harness, adb pushes and runs it, and
    the proof object is a debuggerd tombstone. Discovery can happen here. HWASan is the
    right detector on device, not ASan.
  * **iOS** does not. Code signing and JIT restrictions mean a device is a REACHABILITY
    ORACLE, never the discovery mechanism. Discovery happens on the Simulator or on macOS,
    where libFuzzer and ASan work normally, and the device confirms the path exists.

Everything here degrades cleanly. No adb, no device, no NDK: the functions report what is
absent and why it matters, and never pretend a check ran.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import toolchain as tc

_ABI_TO_PLATFORM = {
    "arm64-v8a": "android-arm64-{kind}",
    "armeabi-v7a": "android-armv7-device",
    "x86_64": "android-x86_64-emulator",
    "x86": "android-x86_64-emulator",
}


@dataclass
class Device:
    serial: str
    kind: str                    # device | emulator | simulator
    os: str                      # android | ios
    abi: str = ""
    api: int = 0
    model: str = ""
    release: str = ""
    platform_id: str = ""
    rooted: bool = False
    supports_hwasan: bool = False
    notes: list = field(default_factory=list)

    def to_json(self) -> dict:
        return {"serial": self.serial, "kind": self.kind, "os": self.os, "abi": self.abi,
                "api": self.api, "model": self.model, "release": self.release,
                "platform_id": self.platform_id, "rooted": self.rooted,
                "supports_hwasan": self.supports_hwasan, "notes": self.notes}


def _adb(serial: Optional[str], *args, timeout: float = 20.0) -> tuple:
    adb = tc.find_adb()
    if not adb:
        return 127, "", "adb not found"
    cmd = [adb] + (["-s", serial] if serial else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except Exception as e:                                   # noqa: BLE001
        return -1, "", str(e)


def _getprop(serial: str, prop: str) -> str:
    rc, out, _ = _adb(serial, "shell", "getprop", prop, timeout=10)
    return out if rc == 0 else ""


def android_devices() -> list:
    """Every attached Android device or emulator, with the platform id it maps to.

    The mapping matters: an emulator and a physical device are different platforms with
    different trust ceilings, because an emulator can carry ASan and a shipping device is
    realistically limited to HWASan and GWP-ASan.
    """
    if not tc.find_adb():
        return []
    rc, out, _ = _adb(None, "devices", "-l")
    if rc != 0:
        return []

    found: list = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line and " " not in line:
            continue
        parts = line.split()
        serial, state = parts[0], parts[1] if len(parts) > 1 else "?"
        if state != "device":
            found.append(Device(serial=serial, kind="unknown", os="android",
                                notes=[f"state is {state!r}, not 'device': "
                                       f"unauthorised, offline, or still booting"]))
            continue

        abi = _getprop(serial, "ro.product.cpu.abi")
        sdk = _getprop(serial, "ro.build.version.sdk")
        qemu = _getprop(serial, "ro.kernel.qemu") or _getprop(serial, "ro.boot.qemu")
        kind = "emulator" if (serial.startswith("emulator-") or qemu == "1") else "device"
        api = int(sdk) if sdk.isdigit() else 0

        tmpl = _ABI_TO_PLATFORM.get(abi, "")
        pid = tmpl.format(kind=kind) if tmpl else ""

        rc_root, out_root, _ = _adb(serial, "shell", "id", timeout=10)
        rooted = "uid=0" in out_root
        hwasan_ok, hwasan_why = device_supports_hwasan(serial)

        notes: list = []
        if kind == "emulator":
            notes.append("emulator: scale here, but re-check anything you intend to claim "
                         "on a physical device")
        else:
            notes.append("physical device: HWASan is the right detector here, not ASan")
        if not rooted:
            notes.append("not rooted: /data/tombstones is unreadable, so the crash artifact "
                         "must come from logcat or an app-private path")
        if abi == "arm64-v8a":
            notes.append("Scudo allocator: hardened against the classic heap techniques, so "
                         "'overflow implies write-what-where' is NOT a safe inference here")
        notes.append(("HWASan usable: this is a HWASan system image" if hwasan_ok
                      else f"HWASan NOT usable: {hwasan_why} — ASan is the detector here"))

        found.append(Device(serial=serial, kind=kind, os="android", abi=abi, api=api,
                            model=_getprop(serial, "ro.product.model"),
                            release=_getprop(serial, "ro.build.version.release"),
                            platform_id=pid, rooted=rooted,
                            supports_hwasan=hwasan_ok, notes=notes))
    return found


def device_supports_hwasan(serial: str) -> tuple:
    """Whether this device can actually RUN a `-fsanitize=hwaddress` binary.

    Found the hard way, on a real emulator. A HWASan binary needs a HWASan *system image*,
    not merely an arm64 CPU and a recent API level: the runtime, the loader's tagged-pointer
    setup and the shadow mapping all live in the image. Google ships those separately, named
    with a `_hwasan` suffix.

    Selecting HWASan from ABI and API alone — which is what this module did first — makes a
    stock image SIGSEGV on startup, every single time. Every run reports a fault, the fault
    is the instrumentation rather than the target, and a device campaign produces a 100%
    false-positive rate while looking like it is working.

    Note that `/system/lib64/libclang_rt.hwasan-aarch64-android.so` is present on stock
    images too, for HWASan *apps*. Its presence is NOT evidence and must not be used as the
    check.
    """
    for prop in ("ro.build.flavor", "ro.product.name", "ro.build.product",
                 "ro.product.system.name"):
        if "hwasan" in _getprop(serial, prop).lower():
            return True, f"{prop} names a hwasan image"
    return False, "stock system image (no _hwasan build); HWASan needs a HWASan image"


def ios_simulators(booted_only: bool = True) -> list:
    """Booted iOS Simulators. This is the practical iOS discovery path: normal libFuzzer and
    ASan, no signing fight, and the same source as the device."""
    x = tc.find_xcrun()
    if not x:
        return []
    try:
        r = subprocess.run([x, "simctl", "list", "devices", "--json"],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout or "{}").get("devices", {})
    except Exception:                                        # noqa: BLE001
        return []

    out: list = []
    for runtime, devs in data.items():
        if "iOS" not in runtime:
            continue
        ver = re.sub(r".*iOS[-. ]", "", runtime).replace("-", ".")
        for d in devs:
            if booted_only and d.get("state") != "Booted":
                continue
            out.append(Device(
                serial=d.get("udid", ""), kind="simulator", os="ios",
                abi=tc.host().arch, model=d.get("name", ""), release=ver,
                platform_id=("ios-arm64-simulator" if tc.host().arch == "aarch64"
                             else "ios-x86_64-simulator"),
                notes=["the practical iOS path: ASan and libFuzzer work normally here",
                       "a finding here is a REACHABILITY HYPOTHESIS on a real device, "
                       "never a certification"]))
    return out


def all_devices() -> list:
    return android_devices() + ios_simulators()


# ── running something on an Android device ───────────────────────────────────

@dataclass
class DeviceRun:
    ok: bool
    outcome: str                 # ok | fault | driver | timeout | unavailable
    exit_code: Optional[int]
    detail: str
    tombstone: Optional[str] = None


def push_and_run(serial: str, binary: Path, data: bytes, *,
                 remote_dir: str = "/data/local/tmp/hforge",
                 timeout: float = 30.0) -> DeviceRun:
    """Push a prebuilt harness and one input, run it, and classify the exit.

    Deliberately does not build: building for Android needs the NDK, and this path must work
    for a binary produced elsewhere. If the binary is not an Android ELF, the device says so
    and this reports it rather than guessing.
    """
    if not tc.find_adb():
        return DeviceRun(False, "unavailable", None, "adb not found")
    if not binary.exists():
        return DeviceRun(False, "unavailable", None, f"{binary} does not exist")

    _adb(serial, "shell", "mkdir", "-p", remote_dir)
    rbin = f"{remote_dir}/{binary.name}"
    rc, _, err = _adb(serial, "push", str(binary), rbin, timeout=120)
    if rc != 0:
        return DeviceRun(False, "unavailable", None, f"push failed: {err}")
    _adb(serial, "shell", "chmod", "755", rbin)

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        local_in = f.name
    rin = f"{remote_dir}/input.bin"
    rc, _, err = _adb(serial, "push", local_in, rin, timeout=60)
    Path(local_in).unlink(missing_ok=True)
    if rc != 0:
        return DeviceRun(False, "unavailable", None, f"input push failed: {err}")

    # `echo $?` is how the shell's exit status comes back; adb's own rc is the shell's.
    rc, out, err = _adb(serial, "shell", f"{rbin} {rin}; echo __rc=$?", timeout=timeout)
    m = re.search(r"__rc=(\d+)", out or "")
    code = int(m.group(1)) if m else None
    # Android is Linux underneath, so 128+N is the shell's spelling of a fatal signal.
    outcome = tc.classify_exit(code, os_name="linux", sanitized=True)

    tomb = None
    if outcome == tc.FAULT:
        rc2, listing, _ = _adb(serial, "shell", "ls", "-t", "/data/tombstones", timeout=15)
        if rc2 == 0 and listing:
            newest = listing.split()[0]
            rc3, body, _ = _adb(serial, "shell", "cat",
                                f"/data/tombstones/{newest}", timeout=30)
            if rc3 == 0 and body:
                tomb = body
        if tomb is None:
            rc4, log, _ = _adb(serial, "logcat", "-d", "-t", "200", "-s", "DEBUG",
                               timeout=30)
            if rc4 == 0 and "signal" in (log or ""):
                tomb = log

    return DeviceRun(
        ok=outcome != "unavailable", outcome=outcome, exit_code=code,
        detail=(f"{tc.describe_exit(code, 'linux')}"
                + ("" if tomb or outcome != tc.FAULT
                   else "; no tombstone readable — an unrooted device is the usual cause")),
        tombstone=tomb)


def capability_report() -> dict:
    """What this host can and cannot do with devices, stated so an absent capability is
    never mistaken for a clean result."""
    adb, ndk, xcrun = tc.find_adb(), tc.find_ndk(), tc.find_xcrun()
    andro = android_devices() if adb else []
    sims = ios_simulators() if xcrun else []
    return {
        "adb": adb, "ndk": ndk, "xcrun": xcrun,
        "android_devices": [d.to_json() for d in andro],
        "ios_simulators": [d.to_json() for d in sims],
        "can_build_android": bool(ndk),
        "can_run_android": bool(adb and andro),
        "can_build_ios_sim": bool(xcrun),
        "blocked": [m for m in (
            None if adb else "adb absent: no Android device is reachable",
            None if ndk else "NDK absent: an Android harness cannot be BUILT here, only run "
                             "if it was built elsewhere",
            None if xcrun else "xcrun absent: the iOS Simulator, which is the practical iOS "
                               "discovery path, is unavailable",
            None if andro or not adb else "adb present but no device attached",
        ) if m],
    }


# ── building for Android ─────────────────────────────────────────────────────

@dataclass
class AndroidBuild:
    ok: bool
    binary: Optional[Path]
    abi: str
    api: int
    detector: str
    log: str
    reason: str = ""
    requested_detector: str = ""
    downgrade_reason: str = ""

    @property
    def downgraded(self) -> bool:
        return bool(self.requested_detector and self.requested_detector != self.detector)


def build_android(sources: list, out_dir: Path, *, abi: str = "arm64-v8a", api: int = 24,
                  include_dirs: Optional[list] = None, detector: str = "hwasan",
                  extra: Optional[list] = None, serial: Optional[str] = None,
                  suffix: str = "") -> AndroidBuild:
    """Cross-compile a harness for Android with the NDK.

    `detector` defaults to HWASan rather than ASan, and that is a deliberate platform call
    rather than a preference. HWASan is tag-based, costs a fraction of ASan's memory, and is
    the detector that can realistically run on a physical device; ASan on device tends to
    need a wrapper and a writable system image. HWASan requires arm64 and API 29+, so this
    silently degrades to ASan when the requested target cannot carry it — and SAYS so in
    `detector`, because a certificate that claims HWASan while running ASan is lying about
    what it could have detected.
    """
    ndk = tc.find_ndk()
    if not ndk:
        return AndroidBuild(False, None, abi, api, "none", "",
                            "no NDK: set ANDROID_NDK_HOME or install it via the SDK manager")

    chosen, why = detector, ""
    if detector == "hwasan":
        if not (abi == "arm64-v8a" and api >= 29):
            chosen, why = "asan", f"HWASan needs arm64-v8a and API>=29; this is {abi}/{api}"
        elif serial:
            ok, reason = device_supports_hwasan(serial)
            if not ok:
                chosen, why = "asan", reason
    cc = ndk_clang_for(ndk, abi, api)
    if not cc:
        return AndroidBuild(False, None, abi, api, chosen, "",
                            f"NDK has no clang for {abi} at API {api}")

    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / f"harness-{abi}-api{api}{suffix or ('-' + chosen)}"
    flags = ["-O1", "-g", "-fno-omit-frame-pointer"]
    if chosen == "none":
        pass
    elif chosen == "hwasan":
        flags += ["-fsanitize=hwaddress", "-fsanitize-recover=hwaddress"]
    elif chosen == "asan":
        flags += ["-fsanitize=address", "-fsanitize-address-use-after-scope"]
    for d in (include_dirs or []):
        flags += ["-I", str(d)]

    cmd = [cc, *flags, *[str(s) for s in sources], *(extra or []), "-o", str(binary)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:                                    # noqa: BLE001
        return AndroidBuild(False, None, abi, api, chosen, str(e), "compiler invocation failed")

    if r.returncode != 0:
        return AndroidBuild(False, None, abi, api, chosen, r.stderr[-3000:],
                            "cross-compile failed", detector, why)
    return AndroidBuild(True, binary, abi, api, chosen, f"$ {' '.join(cmd)}\nrc=0",
                        "", detector, why)


def ndk_clang_for(ndk: str, abi: str, api: int) -> Optional[str]:
    """The NDK ships one clang per (triple, API level). Newer NDKs also ship a generic
    driver, so fall back to the nearest available API level rather than failing outright."""
    direct = tc.ndk_clang(ndk, abi, api)
    if direct:
        return direct
    for cand in range(max(api, 21), 36):
        if (p := tc.ndk_clang(ndk, abi, cand)):
            return p
    return None


def emulators_available() -> list:
    """AVDs that could be booted. Having one is the difference between 'Android is modelled'
    and 'Android is testable right now'."""
    for exe in ("emulator", str(Path.home() / "Library/Android/sdk/emulator/emulator"),
                str(Path.home() / "Android/Sdk/emulator/emulator")):
        path = tc._first(exe)
        if not path:
            continue
        try:
            r = subprocess.run([path, "-list-avds"], capture_output=True, text=True,
                               timeout=30)
            return [l.strip() for l in r.stdout.splitlines() if l.strip()]
        except Exception:                                     # noqa: BLE001
            return []
    return []


# ── the device-side differential ─────────────────────────────────────────────

ARTIFACT = "instrumentation-artifact"


@dataclass
class DifferentialRun:
    verdict: str                 # ok | fault | instrumentation-artifact | unavailable
    instrumented: Optional[DeviceRun]
    baseline: Optional[DeviceRun]
    detail: str

    @property
    def reportable(self) -> bool:
        """Whether this may be carried forward as a candidate finding at all."""
        return self.verdict == tc.FAULT


def run_differential(serial: str, instrumented: Path, baseline: Path, data: bytes,
                     **kw) -> DifferentialRun:
    """Run the same input against an instrumented build and an uninstrumented one.

    This is the variant-disagreement oracle applied on device, and it exists because the
    engine's own first Android run produced a SIGSEGV that had nothing to do with the target:
    a HWASan binary on a stock image dies on startup. Without this check that is a crash, a
    tombstone, and a finding. With it, it is what it actually is.

        instrumented faults, baseline clean, no sanitizer report -> INSTRUMENTATION ARTIFACT
        instrumented faults, baseline faults                     -> a real fault
        instrumented faults, baseline clean, sanitizer reported   -> a real fault the
                                                                    detector caught early

    The doctrine is `downgrade, do not drop`: an artifact is recorded with its evidence, not
    silently discarded, because the next person needs to know the run happened.
    """
    a = push_and_run(serial, instrumented, data, **kw)
    if a.outcome == "unavailable" or a.outcome != tc.FAULT:
        v, why = decide_differential(a, None)
        return DifferentialRun(v, a, None, why)
    b = push_and_run(serial, baseline, data, **kw)
    v, why = decide_differential(a, b)
    return DifferentialRun(v, a, b, why)


def decide_differential(instrumented: DeviceRun,
                        baseline: Optional[DeviceRun]) -> tuple:
    """The decision, separated from the I/O so it can be tested without a device.

    Most machines that run this engine will not have a phone plugged into them, and a control
    that can only be exercised on the one machine that has one is a control nobody checks.
    """
    a, b = instrumented, baseline
    if a.outcome == "unavailable":
        return "unavailable", a.detail
    if a.outcome != tc.FAULT:
        return a.outcome, f"instrumented build: {a.detail}"
    if b is None:
        return tc.FAULT, ("instrumented build faults and no baseline was run, so this "
                          "CANNOT be distinguished from an instrumentation artifact")
    if b.outcome == tc.FAULT:
        return tc.FAULT, ("both builds fault on this input: the fault is in the target, "
                          "not the instrumentation")
    if a.tombstone and any(k in a.tombstone for k in
                           ("AddressSanitizer", "HWAddressSanitizer", "SUMMARY:")):
        return tc.FAULT, ("only the instrumented build faults, and the sanitizer produced a "
                          "report: a real defect the detector caught")
    return ARTIFACT, ("only the instrumented build faults and no sanitizer report was "
                      "produced. This is an artifact of the instrumentation, not a property "
                      "of the target. REFUSE to report it as a finding.")
