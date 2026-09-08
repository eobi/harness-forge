"""macOS GUI driver: DiagnosticReports (.ips) as the crash oracle, Accessibility (AX)
as the rejection oracle, one isolated launch per input.

This is the Darwin sibling of `linux_atspi`. The JUDGEMENT is not re-implemented: the
outcome taxonomy and the rejection-vs-hang rule live in `linux_atspi.classify()` and are
imported here unchanged. What is macOS-specific is only (a) how a crash is observed and
(b) how the accessibility tree is read. Both were measured on this host before this module
was written; the measured facts are recorded because two of them cost a wrong theory.

MEASURED FACT 1 -- a crash is a FILE, not an exit code. On macOS a faulting process is
taken over by ReportCrash, which writes `~/Library/Logs/DiagnosticReports/<proc>-<ts>.ips`.
For a GUI app launched with `open -a`, the launching shell already returned 0, so the exit
code says nothing -- the .ips is the only crash signal. The report is two JSON documents:
a header line, then the body carrying `exception{type,signal}`, `termination{indicator}`
and `faultingThread`.

MEASURED FACT 2 -- not every .ips is a memory-safety bug. An `abort()` (a failed assert,
a C++ `throw` that escapes, a Swift trap) writes `EXC_CRASH / SIGABRT`; a genuine
out-of-bounds writes `EXC_BAD_ACCESS / SIGSEGV` (or SIGBUS). Both are `CRASHED`, but only
the second is a memory-safety candidate, and reporting the first as one is the mirror of
the false-hang this track exists to refuse. `MEMSAFE_EXC`/`MEMSAFE_SIG` below encode that
line; it was checked against a real ASan abort (SIGABRT -> not memsafe) and a real wild
write (SIGSEGV -> memsafe) on this host.

MEASURED FACT 3 -- ReportCrash is asynchronous. The .ips lands a beat AFTER the process
dies; polling the moment the child returns finds nothing. Poll with a short deadline and a
settle interval, never read once. (Symmetric to the Linux window-map poll.)

MEASURED FACT 4 -- the AX tree is permissioned, so it is BEST-EFFORT, and its absence must
not manufacture a finding. Reading another process's accessibility tree requires a TCC
Accessibility grant for the driving process (osascript/terminal). When the grant is
missing, the walk returns no nodes -- which, fed to the shared classifier, yields ACCEPTED,
not a false REJECTED or hang. The crash oracle (.ips) needs no such grant and is always
available; it is the load-bearing signal, and the AX walk only adds rejection
discrimination on top when permission exists.

A NOTE ON THROUGHPUT AND THE OTHER ENGINE. NemesisForge speeds its in-process fuzz loop up
by preloading a `crashcatch` shim that turns a fatal signal into `_exit(128+n)` so
ReportCrash never runs (a suspended corpse costs ~24 s). That is the correct choice there
and the wrong one here: this driver DEPENDS on ReportCrash writing the .ips. The two must
not share an environment -- a GUI launch must not inherit `DYLD_INSERT_LIBRARIES` pointing
at crashcatch. `clean_env()` strips it.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import time
from typing import Optional, Sequence

# The judgement is imported, not re-derived. A second copy of the rejection-vs-hang rule is
# a second place for it to be wrong.
from .linux_atspi import (  # noqa: F401
    GuiOutcome,
    GuiVerdict,
    TerminationReason,
    classify,
    error_nodes,
)

DIAGNOSTIC_REPORTS = os.path.expanduser("~/Library/Logs/DiagnosticReports")

# The line between a crash and a memory-safety crash. EXC_BAD_ACCESS/SIGSEGV/SIGBUS is a
# bad dereference; EXC_BAD_INSTRUCTION/SIGILL/SIGTRAP is a trap (often a bounds/overflow
# check firing) and still a candidate; EXC_CRASH/SIGABRT is a deliberate abort and is NOT.
MEMSAFE_EXC: frozenset = frozenset(
    {"EXC_BAD_ACCESS", "EXC_BAD_INSTRUCTION", "EXC_GUARD", "EXC_ARITHMETIC"}
)
MEMSAFE_SIG: frozenset = frozenset({"SIGSEGV", "SIGBUS", "SIGILL", "SIGTRAP", "SIGFPE"})

# Cocoa spells its error surfaces differently from GTK/AT-SPI. Normalise the AX role to the
# same FAMILY the shared classifier already knows (`linux_atspi.ERROR_ROLES`), so one rule
# serves both toolkits. AXSheet is the attached modal ("could not open the file"); AXPopover
# and system alerts map to the same family. Anything else passes through lower-cased so the
# classifier's name-hint check ("error", "failed", ...) still applies.
_AX_ROLE_FAMILY: dict = {
    "AXSheet": "dialog",
    "AXDialog": "dialog",
    "AXPopover": "notification",
    "AXSystemDialog": "alert dialog",
    "AXAlert": "alert",
}


def normalize_ax_role(ax_role: str) -> str:
    """Map a Cocoa AX role to the toolkit-independent error-role family.

    Pure and tiny so the mapping is testable without a display, the same way the Linux
    role vocabulary is exercised without an X server.
    """
    r = (ax_role or "").strip()
    if r in _AX_ROLE_FAMILY:
        return _AX_ROLE_FAMILY[r]
    # AXRoleName without the AX prefix, lower-cased, so "AXWindow" -> "window" etc.
    if r.startswith("AX"):
        r = r[2:]
    return r.lower()


# ── the crash oracle: .ips parsing, pure where it can be ─────────────────────

def classify_ips(body: dict) -> dict:
    """Given a parsed .ips body, return the crash's exception, signal and whether it is a
    memory-safety candidate. Pure -- fed a dict, so it is testable with a fixture and no
    real crash.
    """
    exc = body.get("exception", {}) or {}
    term = body.get("termination", {}) or {}
    etype = str(exc.get("type", "") or "")
    signal = str(exc.get("signal", "") or "")
    memory_safety = (etype in MEMSAFE_EXC) or (signal in MEMSAFE_SIG)
    return {
        "exc_type": etype,
        "signal": signal,
        "termination": str(term.get("indicator", "") or ""),
        "faulting_thread": body.get("faultingThread"),
        "memory_safety": memory_safety,
    }


def parse_ips(path: str) -> Optional[dict]:
    """Parse a .ips file (header JSON line + body JSON) into the classify_ips() shape,
    with the report path attached. Returns None if the file is not the expected format."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return None
    nl = txt.find("\n")
    if nl < 0:
        return None
    try:
        body = json.loads(txt[nl + 1:])
    except json.JSONDecodeError:
        return None
    out = classify_ips(body)
    out["path"] = path
    return out


def report_paths(proc: str, *, reports_dir: str = DIAGNOSTIC_REPORTS) -> frozenset:
    """The set of existing .ips paths for `proc`. Snapshot this BEFORE a launch so a report
    from a previous input is never attributed to this one -- MEASURED FACT 3a below."""
    return frozenset(glob.glob(os.path.join(reports_dir, f"{glob.escape(proc)}-*.ips")))


def newest_crash(proc: str, since_ts: float = 0.0, *, exclude: frozenset = frozenset(),
                 reports_dir: str = DIAGNOSTIC_REPORTS) -> Optional[dict]:
    """The newest crash report for `proc` attributable to the current input, classified.

    Attribution is by PATH, not timestamp: `exclude` is the set of reports that existed
    before the launch, and a report already in it is a previous input's, never this one's.

    MEASURED FACT 3a -- a timestamp cutoff alone is not enough. ReportCrash writes with
    ~1 s mtime resolution, so two back-to-back runs (a crasher then a clean input) can land
    inside the same tick, and a `since_ts` filter then blames the clean run for the
    crasher's report. A brand-new PATH cannot be confused that way. `since_ts` is kept only
    as a cheap secondary filter for the very first run (empty exclude set).
    """
    hits = []
    for p in glob.glob(os.path.join(reports_dir, f"{glob.escape(proc)}-*.ips")):
        if p in exclude:
            continue
        try:
            if os.path.getmtime(p) >= since_ts:
                hits.append(p)
        except OSError:
            continue
    if not hits:
        return None
    return parse_ips(max(hits, key=os.path.getmtime))


def poll_for_crash(proc: str, since_ts: float = 0.0, *, exclude: frozenset = frozenset(),
                   deadline_s: float = 3.0, interval_s: float = 0.15,
                   reports_dir: str = DIAGNOSTIC_REPORTS) -> Optional[dict]:
    """Poll for a NEW crash report until the deadline (MEASURED FACT 3: ReportCrash is
    async). `exclude` is the pre-launch snapshot from `report_paths()`.

    Returns the classified report as soon as one appears, or None if none does inside the
    budget -- the common, correct case for an input the target handled.
    """
    end = time.time() + deadline_s
    while True:
        r = newest_crash(proc, since_ts, exclude=exclude, reports_dir=reports_dir)
        if r is not None:
            return r
        if time.time() >= end:
            return None
        time.sleep(interval_s)


def crash_verdict(report: dict, *, nodes: int = 0) -> GuiVerdict:
    """A CRASHED verdict carrying the memory-safety classification as evidence. The shared
    `is_finding()` already treats CRASHED as a candidate; the .ips detail says whether it is
    a memory-safety candidate or a mere abort, which is what decides triage priority."""
    kind = "memory-safety" if report.get("memory_safety") else "abort/other"
    ev = [(report.get("exc_type", ""), report.get("signal", ""))]
    note = (f"the process died: {report.get('exc_type','?')}/{report.get('signal','?')} "
            f"({kind}); {report.get('termination','')}".strip())
    return GuiVerdict(GuiOutcome.CRASHED, nodes=nodes, evidence=ev, note=note,
                      termination=TerminationReason.QUIESCED)


# ── the accessibility walk: best-effort, degrades to empty ───────────────────

# System Events walks the AX tree of a running app. It needs an Accessibility TCC grant for
# the process running osascript; without it the script errors and we return no nodes rather
# than raising -- MEASURED FACT 4: absence of the grant must not manufacture a finding.
_AX_SCRIPT = r'''
on run argv
  set appName to item 1 of argv
  set out to ""
  try
    tell application "System Events"
      if not (exists process appName) then return "NO_PROCESS"
      tell process appName
        repeat with w in windows
          set out to out & "AXWindow\t" & (name of w as string) & "\n"
          try
            repeat with sh in sheets of w
              set out to out & "AXSheet\t" & (description of sh as string) & "\n"
            end repeat
          end try
        end repeat
      end tell
    end tell
  on error errMsg
    return "AX_ERROR\t" & errMsg
  end try
  return out
end run
'''


def ax_tree(app_name: str, *, timeout_s: float = 4.0) -> list:
    """Best-effort (role, name) pairs from an app's accessibility tree via System Events.

    Returns a possibly-empty list. An empty list means "nothing observed" (no window yet,
    no grant, or a genuinely bare UI) and is fed to the shared classifier as-is; the
    classifier reads no-error-nodes as ACCEPTED, never as a hang. Roles are normalised to
    the shared error-role family.
    """
    try:
        proc = subprocess.run(
            ["osascript", "-", app_name],
            input=_AX_SCRIPT, capture_output=True, text=True, timeout=timeout_s,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    text = (proc.stdout or "").strip()
    if not text or text.startswith("NO_PROCESS") or text.startswith("AX_ERROR"):
        return []
    tree = []
    for line in text.splitlines():
        parts = line.split("\t", 1)
        role = normalize_ax_role(parts[0])
        name = parts[1] if len(parts) > 1 else ""
        tree.append((role, name))
    return tree


# ── the environment: strip the throughput shim so ReportCrash runs ───────────

def clean_env(base: Optional[dict] = None) -> dict:
    """A launch environment with NemesisForge's crashcatch preload removed, so a fault is
    written to DiagnosticReports instead of being swallowed by `_exit(128+n)`."""
    env = dict(os.environ if base is None else base)
    env.pop("DYLD_INSERT_LIBRARIES", None)
    return env


# ── the live driver: one input, one launch ───────────────────────────────────

def run_one(*, app: str, input_path: str, proc_name: Optional[str] = None,
            gui: bool = True, argv_template: Optional[Sequence[str]] = None,
            settle_s: float = 1.2, crash_deadline_s: float = 3.0,
            timeout_s: float = 20.0) -> GuiVerdict:
    """Drive one input into a target and return a GuiVerdict.

    `gui=True`  launches a `.app` with `open -a <app> <input>` (document-open), reads the
                AX tree of `proc_name` after a settle, and polls DiagnosticReports.
    `gui=False` runs a CLI binary from `argv_template` (with `@@` replaced by input_path)
                and relies on the .ips crash oracle alone -- the same out-of-process crash
                signal serves a CLI parser.

    The verdict comes from the shared `classify()`; this function only gathers the three
    observations it consumes (crash, window/nodes, and -- for GUI -- the AX tree).
    """
    proc = proc_name or os.path.splitext(os.path.basename(app))[0]
    env = clean_env()
    before = report_paths(proc)  # snapshot so a prior input's .ips is never attributed here

    if gui:
        try:
            subprocess.run(["open", "-a", app, input_path], env=env,
                           timeout=timeout_s, capture_output=True, text=True)
        except (subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(settle_s)  # let the window map and any error sheet attach
        report = poll_for_crash(proc, exclude=before, deadline_s=crash_deadline_s)
        if report is not None:
            return crash_verdict(report)
        tree = ax_tree(proc)
        window_ms = 0.0 if tree else None  # a mapped window is implied by any AX node
        return classify(tree=tree, exited=False, window_ms=window_ms,
                        serviced_action=None, termination=TerminationReason.QUIESCED)

    # CLI target: crash oracle only.
    argv = [a.replace("@@", input_path) for a in (argv_template or [app, "@@"])]
    try:
        subprocess.run(argv, env=env, timeout=timeout_s,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return GuiVerdict(GuiOutcome.UNRESPONSIVE, note="CLI target exceeded the timeout",
                          termination=TerminationReason.DEADLINE)
    except OSError:
        return GuiVerdict(GuiOutcome.NO_WINDOW, note="CLI target failed to launch")
    report = poll_for_crash(proc, exclude=before, deadline_s=crash_deadline_s)
    if report is not None:
        return crash_verdict(report)
    return GuiVerdict(GuiOutcome.ACCEPTED, note="ran to completion without a crash report",
                      termination=TerminationReason.QUIESCED)
