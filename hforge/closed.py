"""The CLOSED-BINARY track (P5): coverage-guided fuzzing of a binary with NO source.

Every source-based path in this engine ends at the same wall -- a shipped binary you cannot
recompile. TinyInst answers it: dynamic instrumentation gives edge coverage of an
uninstrumented module, so `litecov` measures a closed target and `jackalope` fuzzes it with
that coverage as feedback. This module is the ORCHESTRATION: it builds the exact command
lines, parses the result into the same kind of evidence record the source track produces, and
never decides anything a tool did not report. The tools are optional, discovered by
`toolchain` and reported by `doctor`, exactly like the compiler -- absent, this track reports
NOT_RUN rather than failing.

`instrument_modules` must be the EXACT names as they appear in the loaded image list (the
version is part of the name: `libwebp.7.2.0.dylib`, not `libwebp.7.dylib`). `target_args`
uses `@@` where the input file goes, the libFuzzer/AFL convention.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

INPUT = "@@"


def litecov_cmd(litecov: str, binary: str, instrument_modules: list, coverage_file: str,
                target_args: list) -> list:
    """One-shot coverage of a closed binary: run it once, dump covered offsets."""
    cmd = [litecov]
    for m in instrument_modules:
        cmd += ["-instrument_module", m]
    cmd += ["-coverage_file", coverage_file, "--", binary]
    cmd += list(target_args)
    return cmd


def jackalope_cmd(fuzzer: str, binary: str, instrument_modules: list, seeds: str, out: str,
                  target_args: list, *, timeout_ms: int = 2000, nthreads: int = 1,
                  persist: bool = False, target_method: str = "", nargs: int = 1) -> list:
    """A coverage-guided closed-binary campaign command (file delivery by default)."""
    cmd = [fuzzer, "-in", seeds, "-out", out, "-t", str(timeout_ms),
           "-delivery", "file", "-nthreads", str(nthreads)]
    for m in instrument_modules:
        cmd += ["-instrument_module", m]
    if persist and target_method:
        cmd += ["-target_module", Path(binary).name, "-target_method", target_method,
                "-nargs", str(nargs), "-persist", "-loop"]
    cmd += ["--", binary] + list(target_args)
    return cmd


def _sub_input(target_args: list, path: str) -> list:
    return [path if a == INPUT else a for a in target_args]


def coverage_once(binary: str, instrument_modules: list, seed: str, *,
                  litecov: str, target_args: Optional[list] = None,
                  timeout: int = 60) -> int:
    """Blocks of coverage a single input reaches in the instrumented modules, or -1 on error.

    The input-sensitivity of this number (a deeper input covering more) is the whole feedback
    signal the campaign runs on, so it doubles as the smoke test for a closed target.
    """
    target_args = _sub_input(target_args or [INPUT], seed)
    cov = str(Path(seed).with_suffix(".cov"))
    cmd = litecov_cmd(litecov, binary, instrument_modules, cov, target_args)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return -1
    m = re.findall(r"Found (\d+) new offsets", out)
    if m:
        return sum(int(x) for x in m)
    try:
        return sum(1 for _ in open(cov)) if Path(cov).exists() else 0
    except OSError:
        return 0


@dataclass
class ClosedResult:
    ran: bool = False
    unique_samples: int = 0
    crashes: int = 0
    hangs: int = 0
    out_dir: str = ""
    note: str = ""

    def to_json(self) -> dict:
        return {"ran": self.ran, "unique_samples": self.unique_samples,
                "crashes": self.crashes, "hangs": self.hangs,
                "out_dir": self.out_dir, "note": self.note}


def parse_jackalope(output: str) -> dict:
    """Pull (unique_samples, crashes, hangs) from Jackalope's periodic status lines."""
    def last(pat: str) -> int:
        vals = re.findall(pat, output)
        return int(vals[-1]) if vals else 0
    return {"unique_samples": last(r"Unique samples:\s*(\d+)"),
            "crashes": last(r"Crashes:\s*(\d+)"),
            "hangs": last(r"Hangs:\s*(\d+)")}


def campaign(binary: str, instrument_modules: list, seeds: str, out: str, *,
             jackalope: str, target_args: Optional[list] = None,
             budget_s: int = 60, timeout_ms: int = 2000) -> ClosedResult:
    """Run a closed-binary campaign and return the evidence, or a NOT_RUN result on failure."""
    target_args = target_args or [INPUT]
    Path(out).mkdir(parents=True, exist_ok=True)
    cmd = jackalope_cmd(jackalope, binary, instrument_modules, seeds, out, target_args,
                        timeout_ms=timeout_ms)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=budget_s + 30)
        stats = parse_jackalope(proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired as ex:
        stats = parse_jackalope((ex.stdout or b"").decode("utf-8", "replace")
                                if isinstance(ex.stdout, bytes) else (ex.stdout or ""))
    except OSError as ex:
        return ClosedResult(ran=False, out_dir=out, note=f"could not launch: {ex}")
    crashes = len(list(Path(out, "crashes").glob("*"))) if Path(out, "crashes").is_dir() else stats["crashes"]
    hangs = len(list(Path(out, "hangs").glob("*"))) if Path(out, "hangs").is_dir() else stats["hangs"]
    return ClosedResult(ran=True, unique_samples=stats["unique_samples"],
                        crashes=crashes, hangs=hangs, out_dir=out)
