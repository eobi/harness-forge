#!/usr/bin/env python3
"""plancheck — hold the repository against the plan, and fail when they disagree.

Run this after every build increment. It is the Auditor doctrine turned on ourselves: a
control that executes rather than a rule in a document, because a rule is applied by a
person who has already decided the work is finished.

Eight checks:

  C1  every gate the manifest declares is registered in code
  C2  every gate in code is declared in the manifest        (drift in the other direction)
  C3  every DONE deliverable's evidence actually resolves
  C4  no deliverable claims DONE while its tests fail
  C5  every platform named in the plan document exists in the platform model
  C6  the doctrine invariants hold in the source
  C7  the phase docs and the manifest agree on phase names
  C8  nothing is marked DONE in a phase whose status is PLANNED
  C12 no module imports a language backend directly; emit goes through the router

C2 matters as much as C1. A gate that exists but is not in the manifest is work nobody
planned, and a certificate that reports it is claiming something the plan never promised.
"""
from __future__ import annotations

import ast
import importlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLANS = ROOT.parent / "plans"
sys.path.insert(0, str(ROOT))

from hforge import manifest as M            # noqa: E402

OK, BAD, WARN = "ok", "FAIL", "warn"
_results: list[tuple] = []


def record(check: str, status: str, msg: str) -> None:
    _results.append((check, status, msg))


# ── helpers ───────────────────────────────────────────────────────────────────

def _gate_ids_in_source() -> set:
    """Gate ids the code actually registers, read from the source rather than by importing,
    so a syntax error is reported as a failure instead of an exception."""
    found: set = set()
    for f in (ROOT / "hforge" / "gates").glob("*.py"):
        src = f.read_text()
        # decide("S2", ...) / passed("D1", ...) / not_run("D4", ...) / failed(...)
        found |= set(re.findall(r'(?:decide|passed|failed|not_run)\(\s*"([SD]\d+)"', src))
    return found


def _test_functions() -> set:
    names: set = set()
    for p in sorted((ROOT / "tests").glob("test_*.py")):
        if not p.exists():
            continue
        tree = ast.parse(p.read_text())
        names |= {n.name for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}
    return names


def _cli_commands() -> set:
    src = (ROOT / "hforge" / "cli.py").read_text()
    return set(re.findall(r'sub\.add_parser\(\s*"([a-z_]+)"', src))


def _module_exists(dotted: str) -> bool:
    try:
        importlib.import_module(dotted)
        return True
    except Exception:                                        # noqa: BLE001
        return False


def _run_tests() -> tuple:
    outs = []
    ok = True
    for f in ("test_phase1.py", "test_phase2.py", "test_phase3.py",
              "test_portability.py", "test_real_headers.py",
              "test_lift.py", "test_tier0.py", "test_findings.py",
              "test_mcp.py", "test_cxx.py"):
        p = ROOT / "tests" / f
        if not p.exists():
            continue
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True,
                           cwd=str(ROOT))
        tail = (r.stdout or r.stderr).strip().splitlines()
        outs.append(f"{f}: {tail[-1] if tail else 'no output'}")
        ok = ok and r.returncode == 0
    return ok, "; ".join(outs) or "no test files"


# ── checks ────────────────────────────────────────────────────────────────────

def c1_declared_gates_exist() -> None:
    declared = M.declared_gates()
    in_code = _gate_ids_in_source()
    missing = sorted(declared - in_code)
    if missing:
        record("C1", BAD, f"manifest declares gates the code does not register: {missing}")
    else:
        record("C1", OK, f"all {len(declared)} declared gates registered in code")


def c2_code_gates_are_declared() -> None:
    declared = M.declared_gates()
    in_code = _gate_ids_in_source()
    # S0 is the schema-coverage pseudo-gate, emitted only when raw blocks exist.
    undeclared = sorted(in_code - declared - {"S0"})
    if undeclared:
        record("C2", BAD,
               f"code registers gates the manifest never promised: {undeclared}. "
               f"Unplanned work a certificate would report as if it were planned.")
    else:
        record("C2", OK, "no undeclared gates in code")


def c3_done_evidence_resolves() -> None:
    problems: list[str] = []
    tests = _test_functions()
    cmds = _cli_commands()
    for d in M.all_deliverables():
        if d.status != M.DONE:
            continue
        for mod in d.modules:
            if not _module_exists(mod):
                problems.append(f"{d.id}: module {mod} does not import")
        for t in d.tests:
            if t not in tests:
                problems.append(f"{d.id}: test {t} does not exist")
        for c in d.cli:
            if c not in cmds:
                problems.append(f"{d.id}: CLI command '{c}' not registered")
    if problems:
        record("C3", BAD, "; ".join(problems))
    else:
        n = sum(1 for d in M.all_deliverables() if d.status == M.DONE)
        record("C3", OK, f"evidence resolves for all {n} DONE deliverables")


def c4_tests_pass() -> None:
    ok, detail = _run_tests()
    record("C4", OK if ok else BAD, detail)


def c5_plan_platforms_modelled() -> None:
    from hforge import platform as plat
    doc = PLANS / "02-HARNESS-FORGE-PHASES.md"
    if not doc.exists():
        record("C5", WARN, "phase document not found; platform table unchecked")
        return
    ids = set(re.findall(r'`(linux-[a-z0-9_-]+|windows-[a-z0-9_-]+|macos-[a-z0-9_-]+|'
                         r'android-[a-z0-9{}_-]+|ios-[a-z0-9_-]+)`', doc.read_text()))
    concrete = {i for i in ids if "{" not in i}
    known = set(plat.PLATFORMS)

    # The plan legitimately writes families as well as ids: the variant-disagreement table
    # says `linux-x86_64` meaning "any libc". A candidate is satisfied when it is an exact
    # id OR a prefix of one, so the check flags genuinely absent platforms and not shorthand.
    def satisfied(cand: str) -> bool:
        return cand in known or any(k.startswith(cand + "-") for k in known)

    missing = sorted(c for c in concrete if not satisfied(c))
    families = sorted(c for c in concrete if c not in known and satisfied(c))
    if missing:
        record("C5", BAD, f"platforms named in the plan but absent from the model: {missing}")
    else:
        record("C5", OK, f"{len(known)} platforms modelled; {len(concrete)} named in the "
                         f"plan all resolve ({len(families)} as families)")


def c6_doctrine_invariants() -> None:
    problems: list[str] = []
    dyn = (ROOT / "hforge" / "gates" / "dynamic_gates.py").read_text()
    stat = (ROOT / "hforge" / "gates" / "static_gates.py").read_text()
    res = (ROOT / "hforge" / "gates" / "result.py").read_text()
    cert = (ROOT / "hforge" / "certificate.py").read_text()

    if "NOT_RUN" not in res:
        problems.append("NOT_RUN_EXISTS: result.py has no NOT_RUN verdict")
    if "not_run(" not in dyn:
        problems.append("NOT_RUN_EXISTS: no dynamic gate can report NOT_RUN")
    fnd = (ROOT / "hforge" / "findings" / "gates.py")
    if fnd.exists():
        fsrc = fnd.read_text()
        if "not_run(" not in fsrc:
            problems.append("NOT_RUN_EXISTS: no finding gate can report NOT_RUN")
        if "independent_oracle != crash.discovering_oracle" not in fsrc:
            problems.append("INDEPENDENT_ORACLE: F7 does not check that the confirming "
                            "oracle differs from the discovering one")
    if re.search(r'def [ds]\d+_\w+\([^)]*\)\s*->\s*bool', dyn + stat):
        problems.append("NO_BARE_BOOL: a gate returns bool instead of a GateResult")
    if '"unreachable"' not in cert:
        problems.append("UNREACHABLE_ALWAYS: the certificate does not emit `unreachable`")
    if "fault_rate" not in dyn:
        problems.append("RATE_NOT_BOOLEAN: determinism is not reported as a rate")
    # the model may propose but never certify: no gate module may import an LLM client
    for name, src in (("dynamic_gates", dyn), ("static_gates", stat)):
        if re.search(r'import\s+(openai|anthropic)|from\s+\.\.llm', src):
            problems.append(f"MODEL_NEVER_CERTIFIES: {name} imports a model client")

    if problems:
        record("C6", BAD, "; ".join(problems))
    else:
        record("C6", OK, f"all {len(M.DOCTRINE)} doctrine invariants hold")


def c7_phase_docs_agree() -> None:
    doc = PLANS / "02-HARNESS-FORGE-PHASES.md"
    if not doc.exists():
        record("C7", WARN, "phase document not found")
        return
    text = doc.read_text()
    missing = [p.id for p in M.PHASES if f"**{p.id}**" not in text]
    if missing:
        record("C7", BAD, f"phases in the manifest but not in the phase document: {missing}")
    else:
        record("C7", OK, f"all {len(M.PHASES)} phases appear in the plan document")


def c8_no_done_inside_planned_phase() -> None:
    bad = [f"{p.id}/{d.id}" for p in M.PHASES if p.status == M.PLANNED
           for d in p.deliverables if d.status == M.DONE]
    if bad:
        record("C8", BAD,
               f"deliverables marked DONE inside a PLANNED phase: {bad}. Either the phase "
               f"is further along than the plan says, or the status is optimistic.")
    else:
        record("C8", OK, "no DONE deliverable sits inside a PLANNED phase")


def c9_mcp_never_gates() -> None:
    """No gate may import the MCP surface or a model client.

    C6 forbade a model client inside a gate before the MCP surface existed. This extends it
    to that surface: the arbiter was built before the model arrived, and that is the entire
    reason it can be trusted to judge one.
    """
    problems: list[str] = []
    for f in list((ROOT / "hforge" / "gates").glob("*.py")) + \
            list((ROOT / "hforge" / "findings").glob("*.py")):
        src = f.read_text()
        if re.search(r"\bimport\s+hforge_mcp|from\s+hforge_mcp|from\s+\.\.\.?hforge_mcp",
                     src):
            problems.append(f"{f.name} imports the MCP surface")
        if re.search(r"\bimport\s+(openai|anthropic)\b", src):
            problems.append(f"{f.name} imports a model client")
    record("C9", BAD if problems else OK,
           "; ".join(problems) if problems else
           "no gate imports the MCP surface or a model client")


def c10_rank_is_producer_blind() -> None:
    """`producer` may never enter the sort key.

    The day a model producer exists is the day someone is tempted to weight it. Asserted over
    a real pair of scores differing only in producer, not by reading the source.
    """
    from dataclasses import replace as _replace
    from hforge.gates.result import passed
    from hforge.producers import rank

    g = [passed("D8", "campaign", edges=100, coverage_grew=True)]
    a = rank.score("same_name", "header_graph", g)
    b = rank.score("same_name", "llm:claude@5", g)
    problems: list[str] = []
    if a.key != b.key:
        problems.append(f"the sort key differs by producer: {a.key} vs {b.key}")
    src = (ROOT / "hforge" / "producers" / "rank.py").read_text()
    if re.search(r"def key[\s\S]{0,400}?self\.producer", src):
        problems.append("rank.key() reads self.producer")
    record("C10", BAD if problems else OK,
           "; ".join(problems) if problems else
           "the ranking cannot see who proposed a plan")


def c11_mcp_may_not_verdict() -> None:
    """No MCP module may construct a verdict. It surfaces the engine's; it never issues one."""
    mcp = ROOT / "hforge_mcp"
    if not mcp.exists():
        record("C11", WARN, "no MCP surface present")
        return
    problems: list[str] = []
    for f in mcp.glob("*.py"):
        src = f.read_text()
        for ctor in ("GateResult(", "Violation(", "decide(", "passed(", "failed("):
            if ctor in src:
                problems.append(f"{f.name} constructs {ctor.rstrip('(')}")
    record("C11", BAD if problems else OK,
           "; ".join(problems) if problems else
           "the MCP surface reports verdicts, it does not issue them")


def c12_backends_go_through_the_router():
    """No module outside `hforge/emit/` may import a language backend by name.

    `Target.language` existed from Phase 1 and NOTHING dispatched on it: `cli.py` imported
    `emit` from `c_libfuzzer` directly, so a second backend was reachable only from a test
    that imported it directly. The router fixed that once; this keeps it fixed, because the
    tempting shortcut when adding a language is to import its emitter where you need it and
    the result is a plan emitted as C for a language it was not written in.

    `EmitError` is exempt: it is the shared exception type, not a backend.
    """
    backends = ("c_libfuzzer", "cxx_libfuzzer", "java_jazzer")
    problems: list[str] = []
    for f in sorted(ROOT.rglob("*.py")):
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith(("hforge/emit/", "tests/", "tools/")):
            continue
        src = f.read_text(errors="replace")
        for b in backends:
            for line in src.splitlines():
                if f"emit.{b} import" not in line and f"emit import {b}" not in line:
                    continue
                names = line.split("import", 1)[1]
                if {n.strip() for n in names.split(",")} <= {"EmitError", "Emitted"}:
                    continue          # the shared types, not a backend entry point
                problems.append(f"{rel}: {line.strip()}")
    record("C12", BAD if problems else OK,
           "; ".join(problems) if problems else
           "every emit goes through the language router")


CHECKS = (c1_declared_gates_exist, c2_code_gates_are_declared, c3_done_evidence_resolves,
          c4_tests_pass, c5_plan_platforms_modelled, c6_doctrine_invariants,
          c7_phase_docs_agree, c8_no_done_inside_planned_phase,
          c9_mcp_never_gates, c10_rank_is_producer_blind, c11_mcp_may_not_verdict,
          c12_backends_go_through_the_router)


def main() -> int:
    print("=" * 74)
    print("PLANCHECK   repository vs plan")
    print("=" * 74)
    for fn in CHECKS:
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            record(fn.__name__[:2].upper(), BAD, f"{type(e).__name__}: {e}")

    width = max(len(c) for c, _, _ in _results)
    for check, status, msg in _results:
        tag = {"ok": "  ok  ", "FAIL": " FAIL ", "warn": " warn "}[status]
        print(f"[{tag}] {check:<{width}}  {msg}")

    print()
    print("PHASE STATUS")
    for line in M.summary().splitlines():
        print("  " + line)

    fails = [r for r in _results if r[1] == BAD]
    print()
    if fails:
        print(f"DRIFT: {len(fails)} check(s) failed. The repository and the plan disagree.")
        print("Fix the code, or change the plan and say why. Do not leave them apart.")
    else:
        print("No drift. Every DONE claim is backed by something that runs.")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
