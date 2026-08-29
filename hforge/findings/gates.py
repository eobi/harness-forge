"""F1-F8 — the gates that judge a FINDING, not a harness.

Sixteen gates existed before this file and all sixteen judged harnesses. The discipline the
engine applies to a plan — a verdict, its evidence, `NOT_RUN` when a check could not run,
and a statement of what is not established — stopped at exactly the moment a human was about
to email a maintainer. That is the worst place to stop being careful.

Much of this is assembly rather than invention, and deliberately so:

  * `D6` already measures a reproduction RATE rather than a boolean
  * `D9` already attributes a sanitizer report to harness-owned or library-owned memory,
    and its output has until now reached nobody
  * `devices.decide_differential` is already the instrumentation-artifact oracle — written
    for Android, general in substance

What is new is F2 (minimisation), F4 (cross-variant replay), F6 (novelty) and F7 (the rung).
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import DEVNULL
from typing import Optional

from .. import toolchain as tc
from ..gates.result import BLOCK, INFO, WARN, GateResult, Violation, decide, not_run
from . import ladder

# A sanitizer's own name in its report. Confirming a fault with the tool that found it is one
# witness, not two, so F3/rung-3 needs to know which tool spoke.
_SANITIZER = re.compile(r"(AddressSanitizer|HWAddressSanitizer|MemorySanitizer|"
                        r"ThreadSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)")
# The allocator frames themselves say nothing about who owns the memory.
_ALLOCATOR_FRAME = re.compile(r"\b(malloc|calloc|realloc|reallocarray|operator new|"
                              r"_Znwm|_Znam|memalign|posix_memalign|strdup|asan_)")
# Frames belonging to OUR harness, not to the target.
_HARNESS_FRAME = re.compile(r"\bhf_[a-z_]+\b|harness\.c|driver\.c")
_ENTRY_FRAME = re.compile(r"LLVMFuzzerTestOneInput")


@dataclass
class Crash:
    """One candidate finding, before anything has been proved about it."""
    input_bytes: bytes
    origin: str = ""                       # where the input came from
    report: str = ""                       # sanitizer output, if any

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.input_bytes).hexdigest()

    @property
    def discovering_oracle(self) -> str:
        m = _SANITIZER.search(self.report or "")
        return m.group(1) if m else ""


@dataclass
class Replay:
    """How to run one input. Supplied by the caller so this module never builds anything —
    the thing that judges a finding should not also be the thing that produced it."""
    binary: Path
    label: str                             # "asan", "none", "musl", "-O0", ...
    sanitized: bool = True
    oracle: str = ""                       # which tool witnesses here, if any


def _run(binary: Path, data: bytes, timeout: float = 20.0) -> tuple:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        r = subprocess.run([str(binary), path], stdout=DEVNULL, stderr=subprocess.PIPE,
                           stdin=DEVNULL, timeout=timeout,
                           env={**os.environ,
                                "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0"},
                           text=True, errors="replace")
        return r.returncode, r.stderr or ""
    except subprocess.TimeoutExpired:
        return None, "timeout"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _faults(replay: Replay, data: bytes) -> tuple:
    rc, err = _run(replay.binary, data)
    return tc.is_fault(rc, os_name=tc.host().os, sanitized=replay.sanitized), err


# ── F1: does it reproduce, and how often ────────────────────────────────────

def f1_reproduce(crash: Crash, replay: Optional[Replay], runs: int = 10) -> GateResult:
    title = "reproduction: the same input faults again, reported as a rate"
    if replay is None:
        return not_run("F1", title, "no replay binary was supplied")
    hits = 0
    for _ in range(runs):
        ok, _ = _faults(replay, crash.input_bytes)
        hits += 1 if ok else 0
    rate = hits / runs
    v: list = []
    if rate == 0.0:
        v.append(Violation("F1.NO_REPRO", BLOCK,
                           f"the input did not fault in {runs} attempts. Whatever was seen "
                           f"originally is not reproducible here, and an irreproducible "
                           f"crash is not a finding.",
                           fix="check the build matches the one that crashed, and that the "
                               "campaign's ASAN_OPTIONS are the same"))
    elif rate < 1.0:
        v.append(Violation("F1.FLAKY", WARN,
                           f"faults in {hits} of {runs} runs. A rate below 1.0 usually means "
                           f"uninitialised memory, address-space layout, or a timing "
                           f"dependency — and it is a different object from a deterministic "
                           f"crash. Report the rate, never round it to 'crashes'."))
    return decide("F1", title, v, reproduce_rate=rate, runs=runs, hits=hits)


# ── F2: minimisation ────────────────────────────────────────────────────────

def f2_minimise(crash: Crash, replay: Optional[Replay],
                max_rounds: int = 12) -> tuple:
    """Delta-debugging by halves. Returns (GateResult, minimised bytes).

    An unminimised crash is unreadable by a maintainer, and minimisation frequently
    *dissolves* the crash — which is itself the finding, because it means the original was
    incidental.
    """
    title = "minimisation: a reduced input that still faults"
    if replay is None:
        return not_run("F2", title, "no replay binary was supplied"), crash.input_bytes

    ok, _ = _faults(replay, crash.input_bytes)
    if not ok:
        return (not_run("F2", title,
                        "the original input does not fault here, so there is nothing to "
                        "reduce"), crash.input_bytes)

    best = crash.input_bytes
    chunk = max(1, len(best) // 2)
    rounds = 0
    while chunk >= 1 and rounds < max_rounds:
        i = 0
        shrunk = False
        while i < len(best):
            cand = best[:i] + best[i + chunk:]
            if cand and _faults(replay, cand)[0]:
                best = cand
                shrunk = True
            else:
                i += chunk
            rounds += 1
            if rounds >= max_rounds:
                break
        if not shrunk:
            chunk //= 2
    ratio = len(best) / max(1, len(crash.input_bytes))
    v: list = []
    if ratio > 0.9 and len(crash.input_bytes) > 64:
        v.append(Violation("F2.NOT_REDUCED", INFO,
                           f"reduced only to {ratio:.0%} of the original. A large "
                           f"irreducible input often means the fault depends on structure "
                           f"the reducer cannot see."))
    return (decide("F2", title, v, original_bytes=len(crash.input_bytes),
                   minimised_bytes=len(best), ratio=round(ratio, 3)), best)


# ── F3: whose memory was it ─────────────────────────────────────────────────

def f3_attribute(crash: Crash, report: str = "") -> GateResult:
    """Harness-owned or target-owned memory.

    D9 already answers this for a campaign report and its output has reached nobody. A fault
    in the harness's own buffer is the harness's bug, and reporting it to a maintainer is
    the single most common way to waste their time.
    """
    title = "attribution: the offending access is the target's memory, not the harness's"
    text = report or crash.report
    if not text.strip():
        return not_run("F3", title,
                       "no sanitizer report was captured, so the access cannot be attributed")

    alloc = re.search(r"allocated by thread[\s\S]{0,900}?(?:\n\n|SUMMARY|$)", text)
    block = alloc.group(0) if alloc else text
    frame_lines = re.findall(r"#\d+\s+0x[0-9a-f]+\s+in\s+(.+)$", block, re.M)

    # Who ALLOCATED it, not who appears in the stack. `LLVMFuzzerTestOneInput` sits at the
    # bottom of every allocation stack because it is the entry point, so matching it
    # anywhere marked every allocation as harness-owned — which would have suppressed every
    # real finding this gate exists to let through. The allocation site is the innermost
    # frame that is neither the allocator itself nor the fuzzer entry point.
    site = ""
    for fr in frame_lines:
        if _ALLOCATOR_FRAME.search(fr) or _ENTRY_FRAME.search(fr):
            continue
        site = fr.strip()
        break

    harness_owned = bool(site and _HARNESS_FRAME.search(site))
    if not site and frame_lines:
        # Only allocator and entry frames: the harness itself allocated it directly.
        harness_owned = any(_ENTRY_FRAME.search(f) for f in frame_lines)

    v: list = []
    if harness_owned:
        v.append(Violation("F3.HARNESS_OWNED", BLOCK,
                           "the offending memory was allocated inside the harness, so this "
                           "is a defect in our own code and not in the target. Every report "
                           "of one of these costs a maintainer time and costs us standing.",
                           fix="fix the harness (S1/S2 usually already say how) and re-run "
                               "before considering this a finding"))
    return decide("F3", title, v, attributed_to="harness" if harness_owned else "target",
                  allocation_site=site or "(none identified)",
                  discovering_oracle=crash.discovering_oracle)


# ── F4: cross-variant replay ────────────────────────────────────────────────

def f4_variant(crash: Crash, replays: Optional[list]) -> GateResult:
    """Replay across builds that differ in one property.

    The platform model has declared this an oracle since Phase 1: glibc-not-musl means
    allocator-dependent, 32-not-64 means width-dependent arithmetic, and a fault that
    appears under one optimisation level only is usually undefined behaviour the optimiser
    exploited. Disagreement is information, not noise.
    """
    title = "cross-variant replay: which builds show the fault"
    if not replays or len(replays) < 2:
        return not_run("F4", title,
                       "fewer than two builds were supplied; disagreement needs something "
                       "to disagree with")
    seen: dict = {}
    for r in replays:
        seen[r.label] = _faults(r, crash.input_bytes)[0]

    agree = len(set(seen.values())) == 1
    v: list = []
    if not agree:
        faulting = sorted(k for k, ok in seen.items() if ok)
        clean = sorted(k for k, ok in seen.items() if not ok)
        meaning = []
        if any("musl" in k for k in clean) and any("glibc" in k for k in faulting):
            meaning.append("allocator-dependent")
        if any("32" in k or "x86" == k for k in clean) != any("32" in k for k in faulting):
            meaning.append("possibly width-dependent")
        if any("O0" in k for k in faulting) and any("O1" in k or "O2" in k for k in clean):
            meaning.append("undefined behaviour the optimiser removed")
        v.append(Violation("F4.DISAGREE", INFO,
                           f"faults on {faulting}, clean on {clean}"
                           + (f" — {', '.join(meaning)}" if meaning else "")
                           + ". A finding is a property of a build, so the report must name "
                             "the builds it holds on."))
    return decide("F4", title, v, per_variant=seen, agree=agree)


# ── F5: is the instrumentation the cause ────────────────────────────────────

def f5_artifact(crash: Crash, instrumented: Optional[Replay],
                baseline: Optional[Replay]) -> GateResult:
    """Does the fault survive without the instrumentation that found it?

    `devices.decide_differential` already does this for Android; the logic is not
    Android-specific and belongs to every platform. A fault that only appears under the
    sanitizer, with no sanitizer report to show for it, is the tooling's, not the target's.
    """
    title = "instrumentation: the fault is the target's, not the tooling's"
    if instrumented is None or baseline is None:
        return not_run("F5", title,
                       "needs both an instrumented and an uninstrumented build of the same "
                       "harness")
    inst_ok, inst_err = _faults(instrumented, crash.input_bytes)
    if not inst_ok:
        return not_run("F5", title, "the instrumented build does not fault on this input")
    base_ok, _ = _faults(baseline, crash.input_bytes)
    spoke = bool(_SANITIZER.search(inst_err) or _SANITIZER.search(crash.report or ""))

    v: list = []
    if not base_ok and not spoke:
        v.append(Violation("F5.INSTRUMENTATION_ARTIFACT", BLOCK,
                           "only the instrumented build faults and no sanitizer produced a "
                           "report. This is an artifact of the instrumentation, not a "
                           "property of the target. REFUSE to report it.",
                           fix="if the sanitizer runtime is missing or mismatched on this "
                               "host, fix that first; otherwise discard"))
    return decide("F5", title, v, instrumented_faults=inst_ok, baseline_faults=base_ok,
                  sanitizer_reported=spoke)


# ── F6: is it already known ─────────────────────────────────────────────────

def f6_novelty(crash: Crash, minimised: bytes, ledger: Optional[dict]) -> GateResult:
    """Against a LOCAL ledger. A duplicate report costs a maintainer more than silence."""
    title = "novelty: not already recorded in the local ledger"
    if ledger is None:
        return not_run("F6", title,
                       "no ledger supplied; novelty against public trackers is a human step "
                       "and is deliberately not automated here")
    key = hashlib.sha256(minimised).hexdigest()
    sig = _signature(crash.report)
    dup = ledger.get(key) or (ledger.get(sig) if sig else None)
    v: list = []
    if dup:
        v.append(Violation("F6.KNOWN", BLOCK,
                           f"already recorded as {dup!r}. Re-reporting a known defect costs "
                           f"the maintainer more than saying nothing."))
    return decide("F6", title, v, input_key=key[:16], signature=sig)


def _signature(report: str) -> str:
    """A crash signature from the top frames — enough to group the same defect reached by
    different inputs, which is the most common source of inflated finding counts."""
    if not report:
        return ""
    frames = re.findall(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", report)[:4]
    kind = re.search(r"ERROR:\s*\w+:\s*([a-z\-]+)", report)
    base = (kind.group(1) if kind else "fault") + "|" + "|".join(frames)
    return hashlib.sha256(base.encode()).hexdigest()[:16]


# ── F7: the rung ────────────────────────────────────────────────────────────

def f7_rung(crash: Crash, results: list, *, independent_oracle: str = "",
            ceiling: int = 6) -> GateResult:
    """Place the finding on the ladder at the highest rung whose oracle PASSED.

    `independent_oracle` names a tool that confirmed the fault and is NOT the one that
    discovered it. Passing the discovering sanitizer's own name here is rejected, because
    that is the failure this rung exists to prevent.
    """
    title = "ladder: the highest rung whose oracle passed"
    ev = {g.gate: g for g in results}

    def ok(gate: str) -> bool:
        g = ev.get(gate)
        return bool(g and g.verdict == "pass")

    rate = float(ev["F1"].evidence.get("reproduce_rate", 0.0)) if "F1" in ev else 0.0
    minimised = ok("F2")
    to_target = (ev["F3"].evidence.get("attributed_to") == "target") if "F3" in ev else False

    indep = bool(independent_oracle) and independent_oracle != crash.discovering_oracle
    rejected = bool(independent_oracle) and not indep

    rung, why = ladder.assign(
        faulted=rate > 0.0 or bool(crash.report),
        reproduce_rate=rate, minimised=minimised,
        attributed_to_target=to_target, independent_oracle=indep,
        ceiling=ceiling)

    v: list = []
    if rejected:
        v.append(Violation("F7.CIRCULAR_ORACLE", BLOCK,
                           f"{independent_oracle!r} is the tool that DISCOVERED this fault, "
                           f"so it cannot also be the independent confirmation. One witness, "
                           f"not two.",
                           fix="confirm with a different sanitizer, a debug allocator or "
                               "valgrind, or accept rung 2"))
    r = ladder.describe(rung)
    return decide("F7", title, v, rung=rung, claim=r.claim, oracle=r.oracle, reason=why,
                  ceiling=ceiling)


# ── F8: what this finding does NOT establish ────────────────────────────────

def f8_exclusions(crash: Crash, results: list, rung: int) -> GateResult:
    """The certificate's best section, applied to the artifact that matters.

    A maintainer reading a report needs the boundary of the claim as much as the claim. This
    gate produces that boundary mechanically so it cannot be quietly omitted when the finding
    is exciting.
    """
    title = "exclusions: what this finding does not establish"
    ev = {g.gate: g for g in results}
    out: list = []

    for n in range(rung + 1, 7):
        out.append(f"rung {n}: {ladder.describe(n).claim} — not shown "
                   f"({ladder.describe(n).oracle})")

    if "F1" in ev and ev["F1"].evidence.get("reproduce_rate", 1.0) < 1.0:
        out.append(f"determinism: faults in "
                   f"{ev['F1'].evidence.get('hits')}/{ev['F1'].evidence.get('runs')} runs, "
                   f"so this is not a deterministic crash")
    if "F4" in ev:
        if ev["F4"].verdict == "not-run":
            out.append("other builds: only one build was tried, so nothing is known about "
                       "allocator or word-size dependence")
        elif not ev["F4"].evidence.get("agree", True):
            per = ev["F4"].evidence.get("per_variant", {})
            clean = sorted(k for k, o in per.items() if not o)
            out.append(f"does NOT hold on: {', '.join(clean)}")
    if "F5" in ev and ev["F5"].verdict == "not-run":
        out.append("instrumentation: no uninstrumented baseline was run, so this cannot be "
                   "distinguished from a tooling artifact")
    if "F6" in ev and ev["F6"].verdict == "not-run":
        out.append("novelty: not checked against any tracker; it may be long known")
    if "F3" in ev and ev["F3"].verdict == "not-run":
        out.append("attribution: no sanitizer report, so harness-owned memory has not been "
                   "ruled out")

    return decide("F8", title, [], unestablished=out)
