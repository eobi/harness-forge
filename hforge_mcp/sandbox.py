"""Isolation for Ring 2, which compiles and runs code.

`08` calls this non-negotiable and it was the one part still hand-waved: the opt-in and the
flag allow-list existed, but a `--allow-build` session compiled on the host. An allow-list
narrows what a compiler will accept; it does not contain what the compiled program then does.
A fuzzer is, by construction, a program running attacker-shaped input against a parser, and
it is the last process on the machine that should hold a socket.

The rule here is **fail closed**. If isolation is unavailable, Ring 2 is refused rather than
quietly downgraded to running on the host — a sandbox that silently turns itself off is worse
than no sandbox, because the operator believes there is one.

What the container gets:

  * **no network at all** (`--network none`)
  * the target root mounted **read-only**, and one writable scratch directory
  * a memory cap, a process cap, and a wall-clock cap
  * no new privileges, all capabilities dropped, a non-root user
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .safety import Refused

DEFAULT_IMAGE = "hforge-runtime"


@dataclass
class Isolation:
    available: bool
    engine: str = ""                  # docker | podman
    why_not: str = ""
    image: str = DEFAULT_IMAGE


def detect(image: str = DEFAULT_IMAGE) -> Isolation:
    """Whether Ring 2 can be isolated on this host, and if not, why not."""
    engine = shutil.which("docker") or shutil.which("podman")
    if not engine:
        return Isolation(False, why_not="neither docker nor podman is on PATH", image=image)
    name = Path(engine).name
    try:
        r = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=30)
    except Exception as e:                                       # noqa: BLE001
        return Isolation(False, engine=name, why_not=f"{name} info failed: {e}", image=image)
    if r.returncode != 0:
        return Isolation(False, engine=name,
                         why_not=f"{name} is installed but its daemon is not responding",
                         image=image)
    try:
        q = subprocess.run([engine, "image", "inspect", image],
                           capture_output=True, text=True, timeout=30)
        if q.returncode != 0:
            return Isolation(False, engine=name,
                             why_not=f"the runtime image {image!r} is not present; build it "
                                     f"before enabling Ring 2", image=image)
    except Exception as e:                                       # noqa: BLE001
        return Isolation(False, engine=name, why_not=str(e), image=image)
    return Isolation(True, engine=name, image=image)


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run(argv: list, *, iso: Isolation, target_root: Path, scratch: Path,
        timeout: int = 900, memory: str = "2g", pids: int = 256,
        workdir: str = "/work") -> Result:
    """Run a command with the target read-only, one writable scratch, and no network."""
    if not iso.available:
        raise Refused(
            f"Ring 2 needs isolation and there is none: {iso.why_not}. It is refused rather "
            f"than run on the host — a sandbox that silently turns itself off is worse than "
            f"no sandbox, because the operator believes there is one.")

    scratch.mkdir(parents=True, exist_ok=True)
    cmd = [
        iso.engine, "run", "--rm",
        "--network", "none",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--memory", memory, "--pids-limit", str(pids),
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,size=512m",
        "-v", f"{target_root}:/src:ro",
        "-v", f"{scratch}:{workdir}:rw",
        "-w", workdir,
        iso.image, *argv,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
        return Result(r.returncode, r.stdout, r.stderr)
    except subprocess.TimeoutExpired:
        return Result(-1, "", f"timed out after {timeout}s", timed_out=True)


def describe(iso: Isolation) -> dict:
    return {
        "available": iso.available,
        "engine": iso.engine,
        "image": iso.image,
        "why_not": iso.why_not,
        "guarantees": [
            "no network (--network none)",
            "target root mounted read-only",
            "one writable scratch directory, everything else read-only",
            "memory, pid and wall-clock caps",
            "no-new-privileges, all capabilities dropped",
        ] if iso.available else [],
        "policy": "fail closed: Ring 2 is refused when isolation is unavailable",
    }
