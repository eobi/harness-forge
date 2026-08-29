"""Our own false-positive rate, measured rather than asserted.

QuartetFuzz reports 4.8%: the fraction of its reported crashes that turned out to be caused
by the harness rather than the library. We had never measured the equivalent, which made
every comparison we drew an argument from architecture. An engine whose whole claim is that
it refuses things with reasons does not get to leave its own error rate unstated.

**The ground truth.** Measuring a false-positive rate needs cases known in advance to be
false. Waiting for a real campaign and adjudicating the results by hand yields a number
nobody can check and a denominator that moves. Instead the defects are CONSTRUCTED: each
plan below contains a bug in the HARNESS, against a library that is not at fault. Every
crash any of them produces is, by construction, a false finding. There is no adjudication
and nothing to argue about.

**The two numbers this produces**, and they answer different questions:

  * `intercepted` — how many defective plans a STATIC gate refuses before a compiler runs.
    This is the axis this engine exists on, and the one the field has no equivalent for:
    QuartetFuzz attributes its 58 harness-induced crashes *after* running them.
  * `escaped` — of the crashes produced by defective plans that were NOT intercepted, how
    many the F-gates nonetheless place at rung 3 or above, which is where a human would be
    told to email a maintainer. That fraction IS our false-positive rate, and unlike the
    first number a low value is only meaningful if crashes were actually produced.

A defect that is intercepted contributes no crashes, so the two numbers must be reported
together. Quoting the second alone would let an engine that refuses everything claim 0%.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..gates.result import BLOCK
from ..gates.static_gates import run_static_gates
from ..ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl,
                  Resource, Target, TypeRef, SLICE_BYTES, SLICE_CSTRING,
                  ROLE_CONSUME, ROLE_CREATE, ROLE_DESTROY)


@dataclass
class Defect:
    """One constructed harness bug, and what makes it a bug."""
    id: str
    what: str                     # the mistake
    why_false: str                # why any crash it produces is the harness's fault
    build: object                 # (target) -> HarnessIR
    literature: str = ""


@dataclass
class Outcome:
    defect: str
    intercepted_by: list = field(default_factory=list)   # static gate codes that blocked it
    built: bool = False
    build_error: str = ""
    crashes: int = 0
    escaped: int = 0              # crashes the F-gates placed at rung >= 3
    rungs: list = field(default_factory=list)
    note: str = ""

    @property
    def intercepted(self) -> bool:
        return bool(self.intercepted_by)


# ── the constructed defects ──────────────────────────────────────────────────
#
# Each takes a Target describing a real library and returns a plan containing exactly one
# harness mistake. They are drawn from the defect classes the literature reports, not
# invented: cast-to-struct, unchecked handle, length/buffer disagreement, lifetime misuse.

def _sqlite_apis() -> dict:
    db = TypeRef("sqlite3 *", "pointer")
    return {
        "sqlite3_open": Api("sqlite3_open", "sqlite3.h",
                            [ParamDecl("filename", TypeRef("const char *", "pointer", True)),
                             ParamDecl("ppDb", TypeRef("sqlite3 **", "pointer"))],
                            TypeRef("int"), ROLE_CREATE, Contract(error_return="negative")),
        "sqlite3_close": Api("sqlite3_close", "sqlite3.h", [ParamDecl("db", db)],
                             TypeRef("int"), ROLE_DESTROY, Contract()),
        "sqlite3_exec": Api("sqlite3_exec", "sqlite3.h",
                            [ParamDecl("db", db),
                             ParamDecl("sql", TypeRef("const char *", "pointer", True)),
                             ParamDecl("cb", TypeRef("void *", "pointer")),
                             ParamDecl("arg", TypeRef("void *", "pointer")),
                             ParamDecl("err", TypeRef("char **", "pointer"))],
                            TypeRef("int"), ROLE_CONSUME,
                            Contract(nul_terminated=["sql"], requires_nonnull=["db"],
                                     error_return="negative")),
        "sqlite3_errmsg": Api("sqlite3_errmsg", "sqlite3.h", [ParamDecl("db", db)],
                              TypeRef("const char *", "pointer", True), ROLE_CONSUME,
                              Contract(requires_nonnull=["db"])),
    }


def _base(target: Target, name: str, *, slices, seq, resources) -> HarnessIR:
    return HarnessIR(name=name, target=target, apis=_sqlite_apis(), slices=slices,
                     resources=resources, sequence=seq,
                     knobs=Knobs(sanitizers=["address"], max_len=4096),
                     platforms=["linux-x86_64-glibc"], producer="fprate-control")


def _d_unterminated(target: Target) -> HarnessIR:
    """Raw bytes handed to an API that reads to a NUL terminator."""
    db = TypeRef("sqlite3 *", "pointer")
    return _base(target, "fp_unterminated",
                 slices=[InputSlice("sql", SLICE_BYTES, remainder=True, min_len=1)],
                 resources=[Resource("db", db, storage="out_param")],
                 seq=[Op("o_open", "sqlite3_open",
                         [Arg("filename", "literal", value=":memory:"),
                          Arg("ppDb", "resource", "db")], binds="db"),
                      Op("o_exec", "sqlite3_exec",
                         [Arg("db", "resource", "db"), Arg("sql", "input", "sql"),
                          Arg("cb", "literal", value=0), Arg("arg", "literal", value=0),
                          Arg("err", "literal", value=0)], guarded_by=["db"]),
                      Op("o_close", "sqlite3_close", [Arg("db", "resource", "db")],
                         targets="db", guarded_by=["db"])])


def _d_unchecked_handle(target: Target) -> HarnessIR:
    """The constructor's result is never checked, so the API is called with NULL whenever
    the open fails."""
    db = TypeRef("sqlite3 *", "pointer")
    return _base(target, "fp_unchecked_handle",
                 slices=[InputSlice("sql", SLICE_CSTRING, remainder=True, min_len=1)],
                 resources=[Resource("db", db, storage="out_param")],
                 seq=[Op("o_open", "sqlite3_open",
                         [Arg("filename", "literal", value="/nonexistent/dir/x.db"),
                          Arg("ppDb", "resource", "db")], binds="db"),
                      Op("o_exec", "sqlite3_exec",
                         [Arg("db", "resource", "db"), Arg("sql", "input", "sql"),
                          Arg("cb", "literal", value=0), Arg("arg", "literal", value=0),
                          Arg("err", "literal", value=0)]),
                      Op("o_close", "sqlite3_close", [Arg("db", "resource", "db")],
                         targets="db")])


def _d_use_after_destroy(target: Target) -> HarnessIR:
    """The handle is used after it has been destroyed."""
    db = TypeRef("sqlite3 *", "pointer")
    return _base(target, "fp_use_after_destroy",
                 slices=[InputSlice("sql", SLICE_CSTRING, remainder=True, min_len=1)],
                 resources=[Resource("db", db, storage="out_param")],
                 seq=[Op("o_open", "sqlite3_open",
                         [Arg("filename", "literal", value=":memory:"),
                          Arg("ppDb", "resource", "db")], binds="db"),
                      Op("o_close", "sqlite3_close", [Arg("db", "resource", "db")],
                         targets="db", guarded_by=["db"]),
                      Op("o_exec", "sqlite3_exec",
                         [Arg("db", "resource", "db"), Arg("sql", "input", "sql"),
                          Arg("cb", "literal", value=0), Arg("arg", "literal", value=0),
                          Arg("err", "literal", value=0)], guarded_by=["db"])])


def _d_double_destroy(target: Target) -> HarnessIR:
    """The handle is destroyed twice."""
    db = TypeRef("sqlite3 *", "pointer")
    return _base(target, "fp_double_destroy",
                 slices=[InputSlice("sql", SLICE_CSTRING, remainder=True, min_len=1)],
                 resources=[Resource("db", db, storage="out_param")],
                 seq=[Op("o_open", "sqlite3_open",
                         [Arg("filename", "literal", value=":memory:"),
                          Arg("ppDb", "resource", "db")], binds="db"),
                      Op("o_exec", "sqlite3_exec",
                         [Arg("db", "resource", "db"), Arg("sql", "input", "sql"),
                          Arg("cb", "literal", value=0), Arg("arg", "literal", value=0),
                          Arg("err", "literal", value=0)], guarded_by=["db"]),
                      Op("o_close1", "sqlite3_close", [Arg("db", "resource", "db")],
                         guarded_by=["db"]),
                      Op("o_close2", "sqlite3_close", [Arg("db", "resource", "db")],
                         targets="db", guarded_by=["db"])])


def _d_bytes_to_struct(target: Target) -> HarnessIR:
    """Fuzzer bytes bound to a pointer the library will dereference as a structure — the
    largest single source of false findings in the literature."""
    db = TypeRef("sqlite3 *", "pointer")
    return _base(target, "fp_bytes_to_struct",
                 slices=[InputSlice("db", SLICE_BYTES, remainder=True, min_len=1)],
                 resources=[],
                 seq=[Op("o_errmsg", "sqlite3_errmsg", [Arg("db", "input", "db")])])


DEFECTS = [
    Defect("bytes-to-struct",
           "fuzzer bytes bound to a pointer the library dereferences as a struct",
           "the library is handed an invalid pointer; the fault is the harness's own",
           _d_bytes_to_struct,
           "the dominant false-finding class in reported LLM-generated harnesses"),
    Defect("unterminated-cstring",
           "raw bytes passed to an API that reads to a NUL terminator",
           "the library reads past the buffer because the harness never terminated it",
           _d_unterminated,
           "the cJSON defect: eight false findings from one missing NUL"),
    Defect("unchecked-handle",
           "the constructor's result is never checked before the handle is used",
           "the library is called with NULL, which its contract forbids",
           _d_unchecked_handle),
    Defect("use-after-destroy",
           "the handle is used after it has been destroyed",
           "the harness violates the lifetime it was given",
           _d_use_after_destroy),
    Defect("double-destroy",
           "the handle is destroyed twice",
           "the harness violates the lifetime it was given",
           _d_double_destroy),
]


# ── running the experiment ───────────────────────────────────────────────────

def _build_campaign(ir: HarnessIR, wd: Path) -> tuple:
    """Compile one defective plan into a fuzzer, PAST its own static verdict.

    Forcing a build here is deliberate and is not a shipping path: the point is to measure
    the second line of defence on its own, with the first switched off. An engine that
    reports 0% escapes because it refused everything has measured its static gates twice
    and its finding gates not at all.
    """
    from .. import toolchain as tc
    from ..emit import emit

    cc = tc.find_libfuzzer_cc()
    if cc is None:
        return None, "no libFuzzer runtime on this host"
    try:
        em = emit(ir)
    except Exception as e:                                       # noqa: BLE001
        return None, f"emit refused: {e}"

    wd.mkdir(parents=True, exist_ok=True)
    (wd / "harness.c").write_text(em.source)
    binary = wd / ("fuzz" + tc.host().exe_suffix)
    cmd = [cc, "-g", "-O1", "-fno-omit-frame-pointer"]
    cmd += [f"-I{x}" for x in ir.target.include_dirs] + list(ir.target.cflags)
    cmd += ["-fsanitize=fuzzer,address", str(wd / "harness.c"),
            *ir.target.sources, *ir.target.link_libs, "-o", str(binary)]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        return None, f"build failed: {r.stderr[-300:]}"

    # The replay binary the F-gates need: same harness, no fuzzer runtime, so a chosen
    # input can be fed to it.
    replay = wd / ("replay" + tc.host().exe_suffix)
    if em.driver:
        (wd / "driver.c").write_text(em.driver)
        cmd2 = [cc, "-g", "-O1", "-fno-omit-frame-pointer"]
        cmd2 += [f"-I{x}" for x in ir.target.include_dirs] + list(ir.target.cflags)
        cmd2 += ["-fsanitize=address", str(wd / "harness.c"), str(wd / "driver.c"),
                 *ir.target.sources, *ir.target.link_libs, "-o", str(replay)]
        r2 = subprocess.run(cmd2, capture_output=True, text=True, errors="replace")
        if r2.returncode != 0:
            replay = None
    else:
        replay = None
    return (binary, replay), ""


def _fuzz(binary: Path, wd: Path, seconds: int, max_len: int) -> list:
    """Run briefly and return the crashing inputs, with the report that came with each."""
    from ..gates.dynamic_gates import _asan_env

    art = wd / "artifacts"
    art.mkdir(exist_ok=True)
    corp = wd / "corpus"
    corp.mkdir(exist_ok=True)
    (corp / "seed0").write_bytes(b"SELECT 1;")
    # `-fork=1 -ignore_crashes=1`: without them libFuzzer stops at the FIRST crash, so each
    # defect contributed exactly one input and the whole rate rested on n=4. A false-positive
    # rate quoted over four samples is a number with no power behind it.
    try:
        r = subprocess.run(
            [str(binary), str(corp), f"-artifact_prefix={art}/", f"-max_len={max_len}",
             f"-max_total_time={seconds}", "-fork=1", "-ignore_crashes=1",
             "-ignore_timeouts=1", "-ignore_ooms=1"],
            capture_output=True, text=True, errors="replace",
            env=_asan_env(), timeout=seconds + 180)
        log = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        log = ""
    files = [q for q in sorted(art.rglob("*")) if q.is_file()]
    return [(q.read_bytes(), log) for q in files]


def run(target: Target, *, seconds: int = 20, workdir: Optional[Path] = None,
        defects: Optional[list] = None) -> list:
    """Both numbers, for every constructed defect."""
    from . import gates as fg
    from . import pipeline as fp
    from . import report as fr

    wd = Path(workdir or tempfile.mkdtemp(prefix="hforge-fp-"))
    out = []
    for d in (defects or DEFECTS):
        o = Outcome(defect=d.id)
        ir = d.build(target)
        results = run_static_gates(ir)
        o.intercepted_by = sorted({v.code for r in results for v in r.violations
                                   if v.severity == BLOCK})

        built, err = _build_campaign(ir, wd / d.id)
        if built is None:
            o.build_error = err
            out.append(o)
            continue
        o.built = True
        binary, replay = built
        crashes = _fuzz(binary, wd / d.id, seconds, ir.knobs.max_len or 4096)
        o.crashes = len(crashes)

        if crashes:
            inp = fp.Inputs(
                crashes=[fg.Crash(input_bytes=b, origin=d.id, report=log)
                         for b, log in crashes],
                instrumented=(fg.Replay(binary=replay, label="instrumented", sanitized=True)
                              if replay else None),
                provenance=fr.Provenance(target=target.name, plan_name=ir.name),
                campaign_seconds=float(seconds),
                platform_id="linux-x86_64-glibc")
            found, _audit = fp.triage(inp)
            o.rungs = [f.rung for f in found]
            o.escaped = sum(1 for f in found if f.rung >= 3)
            o.note = found[0].rung_reason if found else ""
        else:
            # Not the same thing as "handled correctly". sqlite3_open allocates a handle
            # even when it fails, so the unchecked-handle plan never receives the NULL its
            # defect depends on. Recorded as NO OBSERVATION, because counting it as a pass
            # would credit the engine for a defect that never fired.
            o.note = ("the defect did not manifest on this library: no crash to judge, "
                      "which is no evidence either way")
        out.append(o)
    return out


def render(outcomes: list) -> str:
    L = ["", f"{'DEFECT':<22} {'STATIC':<28} {'BUILT':<6} {'CRASHES':<8} {'ESCAPED':<8} RUNGS",
         "-" * 92]
    for o in outcomes:
        static = ",".join(o.intercepted_by) or "not intercepted"
        rungs = ",".join(str(r) for r in sorted(set(o.rungs))) or "-"
        L.append(f"{o.defect:<22} {static[:27]:<28} {str(o.built):<6} {o.crashes:<8} "
                 f"{o.escaped:<8} {rungs}")
        if o.build_error:
            L.append(f"{'':<22} {o.build_error[:66]}")

    n = len(outcomes)
    icept = sum(1 for o in outcomes if o.intercepted)
    total_crashes = sum(o.crashes for o in outcomes)
    total_escaped = sum(o.escaped for o in outcomes)
    manifested = [o for o in outcomes if o.crashes]
    silent = [o for o in outcomes if o.built and not o.crashes]
    L += ["",
          f"INTERCEPTED  {icept}/{n} defective plans refused by a static gate, before any "
          f"compiler ran.",
          f"ESCAPED      {total_escaped}/{total_crashes} crashes from the SAME plans, built "
          f"anyway, reached rung 3+."]
    if total_crashes:
        L.append(f"             false-positive rate {100.0 * total_escaped / total_crashes:.1f}% "
                 f"over {total_crashes} crashing inputs across "
                 f"{len(manifested)} defect classes.")
        L.append("             Both denominators are stated because they answer different "
                 "questions and")
        L.append("             neither is large. A defect crashes on nearly every input, so "
                 "the input")
        L.append("             count is not an independent sample; the class count is the "
                 "honest one.")
    else:
        L.append("             no crashes produced, so the escape rate is UNMEASURED — not "
                 "zero. Reporting it as zero would let an engine that refuses everything "
                 "claim perfection.")
    if silent:
        L.append("")
        for o in silent:
            L.append(f"NO OBSERVATION  {o.defect}: {o.note}")
    L += ["",
          "Every plan above contains a bug in the HARNESS, so every crash is false by",
          "construction. Both lines are needed: the second is only meaningful when crashes",
          "were actually produced, and the first is why many were not."]
    return "\n".join(L)
