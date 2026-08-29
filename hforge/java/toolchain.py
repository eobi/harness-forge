"""JVM toolchain, and the one exit-code fact that would have made every Java gate lie.

On POSIX a crash is a negative return or 128+N; `classify_exit` reads that and is correct.
**A JVM process that dies of an uncaught exception exits 1** — and so does a missing input
file, a bad classpath, a JVM that would not start, and `System.exit(1)` in the library. There
is no exit code that means "this faulted", so a status-based classifier is not merely
imprecise on the JVM, it is *unable in principle* to answer the question.

That is why `emit/java_jazzer.py` makes its replay driver print a marker and exit 0. The
fault is read from the output. This module is the reader, and it refuses to guess from a
status.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import CLEAN_MARKER, FAULT_MARKER

# outcomes, matching hforge.toolchain so callers do not learn a second vocabulary
OK = "ok"
FAULT = "fault"
DRIVER_ERROR = "driver"
TIMEOUT = "timeout"


def _first(*cands) -> Optional[str]:
    for c in cands:
        if not c:
            continue
        p = shutil.which(c) if os.path.sep not in str(c) else (c if Path(c).exists() else None)
        if p:
            return str(p)
    return None


def find_java() -> Optional[str]:
    return _first(os.environ.get("JAVA"), "java",
                  str(Path(os.environ.get("JAVA_HOME", "/nonexistent")) / "bin/java"),
                  "/opt/homebrew/opt/openjdk/bin/java")


def find_javac() -> Optional[str]:
    return _first(os.environ.get("JAVAC"), "javac",
                  str(Path(os.environ.get("JAVA_HOME", "/nonexistent")) / "bin/javac"),
                  "/opt/homebrew/opt/openjdk/bin/javac")


def find_javap() -> Optional[str]:
    return _first("javap", "/opt/homebrew/opt/openjdk/bin/javap")


def find_jazzer() -> Optional[str]:
    """The Jazzer driver, if one is installed. Absent means campaigns cannot run — and every
    gate that feeds a chosen input still can, which is why the replay driver depends on
    nothing."""
    return _first(os.environ.get("JAZZER"), "jazzer",
                  str(Path.home() / ".jazzer/jazzer"))


def find_jazzer_standalone() -> Optional[str]:
    """The standalone driver jar. It is run as `java -cp <driver>:<api>:<classes>` rather than
    `java -jar`, because `--cp` on the standalone jar does not put the target on the
    classloader the harness is resolved from: the driver reports `'Harness' not found on
    classpath` while listing only its own jar."""
    for env in ("JAZZER_STANDALONE", "JAZZER_JAR"):
        v = os.environ.get(env)
        if v and Path(v).exists():
            return v
    for base in (Path.home() / ".jazzer", Path("/usr/local/lib"), Path("/opt/jazzer")):
        if base.is_dir():
            hits = sorted(base.glob("jazzer-standalone*.jar")) or sorted(
                base.glob("jazzer-[0-9]*.jar"))
            if hits:
                return str(hits[-1])
    return None


def jazzer_api_jar() -> Optional[str]:
    """`jazzer_standalone.jar` or `jazzer-api.jar` — needed to COMPILE a harness, separately
    from running one."""
    for env in ("JAZZER_API", "JAZZER_JAR"):
        v = os.environ.get(env)
        if v and Path(v).exists():
            return v
    for base in (Path.home() / ".jazzer", Path("/usr/local/lib"), Path("/opt/jazzer")):
        if base.is_dir():
            for pat in ("jazzer_standalone*.jar", "jazzer-api*.jar", "jazzer*.jar"):
                hits = sorted(base.glob(pat))
                if hits:
                    return str(hits[0])
    return None


def java_version() -> Optional[int]:
    j = find_java()
    if not j:
        return None
    try:
        r = subprocess.run([j, "-version"], capture_output=True, text=True, timeout=30)
    except Exception:                                            # noqa: BLE001
        return None
    m = re.search(r'version "(\d+)', (r.stderr or "") + (r.stdout or ""))
    return int(m.group(1)) if m else None


def classify_output(stdout: str, rc: Optional[int]) -> str:
    """What a replay run meant. Reads the OUTPUT; the status is only consulted for the two
    things it can actually distinguish.

    Passing a JVM exit code to `hforge.toolchain.classify_exit` would report `ok` for an
    uncaught exception (rc 1 is not >= 128 and the build is not "sanitized"), so every Java
    D3/D5/D6 result would have read clean and the engine would have certified harnesses that
    detect nothing. It is the Windows NTSTATUS bug again, in a different runtime.
    """
    if rc is None:
        return TIMEOUT
    text = stdout or ""
    if FAULT_MARKER in text:
        return FAULT
    if CLEAN_MARKER in text:
        return OK
    if rc == 2:
        return DRIVER_ERROR          # our driver's own "cannot read input"
    # No marker at all: the driver never reached its own printout — a missing class, a bad
    # classpath, a JVM that would not start. That is a broken run, not a clean one, and
    # calling it OK is how a certificate comes to rest on nothing.
    return DRIVER_ERROR


@dataclass
class JvmRun:
    outcome: str
    stdout: str
    rc: Optional[int]

    @property
    def faulted(self) -> bool:
        return self.outcome == FAULT


def replay(classes_dir: str, input_path: str, *, classpath: str = "",
           timeout: float = 30.0, interpreted: bool = False,
           main: str = "Replay") -> JvmRun:
    """Run one chosen input through the replay driver.

    `interpreted=True` passes `-Xint`. That flag is the JVM's answer to rung 3's independence
    requirement: a fault that reproduces interpreted AND compiled belongs to the library,
    while one that appears only under C2 is a JIT artifact. It is the same question
    `devices.decide_differential` asks of two Android instrumentation modes.
    """
    j = find_java()
    if not j:
        return JvmRun(DRIVER_ERROR, "", None)
    cp = ":".join([x for x in (classes_dir, classpath) if x])
    cmd = [j] + (["-Xint"] if interpreted else []) + ["-cp", cp, main, input_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return JvmRun(TIMEOUT, "", None)
    text = (r.stdout or "") + (r.stderr or "")
    return JvmRun(classify_output(text, r.returncode), text, r.returncode)


def decide_jit_differential(compiled: JvmRun, interpreted: JvmRun) -> tuple:
    """Rung 3's independent oracle on the JVM. Returns (independent, reading).

    Two execution modes of the same program, which is the closest thing the JVM has to a
    second sanitizer — and the disagreement is itself the signal, exactly as musl-versus-glibc
    is in the C engine.
    """
    if compiled.outcome == TIMEOUT or interpreted.outcome == TIMEOUT:
        return False, ("one execution mode timed out, so the two cannot be compared. Not "
                       "independent confirmation.")
    if compiled.faulted and interpreted.faulted:
        return True, ("the fault reproduces both JIT-compiled and interpreted (-Xint), so it "
                      "is not an artifact of the optimising compiler")
    if compiled.faulted and not interpreted.faulted:
        return False, ("the fault appears ONLY under the JIT. That is a compiler artifact or "
                       "a JIT bug, not a library defect — and reporting it to the library's "
                       "maintainer would be wrong. Refuse it, or take it to the JDK.")
    if interpreted.faulted and not compiled.faulted:
        return False, ("the fault appears only when interpreted, which usually means a "
                       "timing- or JIT-dependent guard. Not a library defect on this "
                       "evidence.")
    return False, "neither execution mode faulted, so there is nothing to confirm"
