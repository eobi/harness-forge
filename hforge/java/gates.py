"""The dynamic gates, asked of the JVM.

Same questions, different instruments. Three answers change materially and the reasons are
worth stating on the certificate rather than buried here:

  * **D1** used `nm -u` to prove the target call survived the optimiser. javac barely
    optimises, so the compile-time risk is gone — but the JIT can still eliminate a call
    whose result is unused, and it does so at run time where no static check can see it. So
    D1 reads the constant pool via `javap -c` AND the harness folds every return value into
    a `volatile` sink. The gate transfers; its justification does not.
  * **D2** mutates the target. On the JVM this is cheaper than in C, not dearer: a mutant
    `.class` is swapped on the classpath with no rebuild of the project.
  * **D9** attributed a sanitizer's allocation stack. Here it is stack-trace attribution,
    which is the easier of the two, and it lives in `java/exceptions.py` because on the JVM
    attribution and classification are the same act.

D2 lives in this file but is deliberately the last thing implemented, per the plan: it is the
most work and the least likely to fail loudly.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..gates.result import BLOCK, WARN, GateResult, Violation, decide, not_run
from ..ir import HarnessIR
from . import exceptions as jx
from . import toolchain as jt
from .sinks import SINKS, scan as scan_sinks


@dataclass
class JavaBuild:
    """What a Java plan compiles to. The analogue of BuildArtifacts."""
    workdir: Path
    harness_java: Path
    replay_java: Optional[Path]
    classes: Optional[Path]
    replay_ok: bool
    log: str
    ok: bool


# Jazzer's bundled ASM refuses class files newer than it knows, and on a JDK 26 host every
# class we compile is newer. Targeting an older bytecode level is therefore not a nicety: it
# is the difference between a campaign and a misleading "'Harness' not found on classpath".
DEFAULT_RELEASE = 17


def build(ir: HarnessIR, em, workdir: Optional[Path] = None,
          classpath: str = "", release: int = DEFAULT_RELEASE) -> JavaBuild:
    """Compile the harness and the replay driver.

    The harness needs Jazzer's API jar to compile; the replay driver needs nothing but the
    target. They are compiled SEPARATELY and their success is tracked separately, so a host
    with no Jazzer still gets every gate that feeds a chosen input — which is most of them.
    """
    wd = Path(workdir or tempfile.mkdtemp(prefix="hforge-j-"))
    wd.mkdir(parents=True, exist_ok=True)
    hj, rj = wd / "Harness.java", wd / "Replay.java"
    hj.write_text(em.source)
    if em.driver:
        rj.write_text(em.driver)

    javac = jt.find_javac()
    if not javac:
        return JavaBuild(wd, hj, rj if em.driver else None, None, False,
                         "no javac on this host", False)

    classes = wd / "classes"
    classes.mkdir(exist_ok=True)
    cp = ":".join([x for x in (classpath, *ir.target.link_libs) if x]) or "."
    log = []

    rel = ["--release", str(release)] if release else []
    api = jt.jazzer_api_jar()
    hcp = f"{cp}:{api}" if api else cp
    r1 = subprocess.run([javac, *rel, "-cp", hcp, "-d", str(classes), str(hj)],
                        capture_output=True, text=True, errors="replace")
    log.append(r1.stderr)

    replay_ok = False
    if em.driver:
        r2 = subprocess.run([javac, *rel, "-cp", cp, "-d", str(classes), str(rj)],
                            capture_output=True, text=True, errors="replace")
        log.append(r2.stderr)
        replay_ok = r2.returncode == 0

    return JavaBuild(wd, hj, rj if em.driver else None, classes,
                     replay_ok, "\n".join(x for x in log if x),
                     r1.returncode == 0)


# ── D1: the call survived ────────────────────────────────────────────────────

_INVOKE = re.compile(r"invoke(?:virtual|static|interface|special|dynamic)\s+#\d+\s*//"
                     r"\s*(?:Method|InterfaceMethod)\s+(?P<ref>[\w$./]+)")
_NEW = re.compile(r"\bnew\s+#\d+\s*//\s*class\s+(?P<ref>[\w$./]+)")


def d1_liveness(ir: HarnessIR, em, art: JavaBuild) -> GateResult:
    title = "liveness: the target call is present in the bytecode"
    if not art.classes or not art.ok:
        return not_run("D1", title, "the harness class was not compiled")
    javap = jt.find_javap()
    if not javap:
        return not_run("D1", title, "no javap on PATH, so the constant pool cannot be read")

    r = subprocess.run([javap, "-c", "-p", "-classpath", str(art.classes), "Harness"],
                       capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        return not_run("D1", title, f"javap could not read the harness class: "
                                    f"{r.stderr.strip()[-160:]}")
    text = r.stdout
    refs = {m.group("ref").replace("/", ".") for m in _INVOKE.finditer(text)}
    refs |= {m.group("ref").replace("/", ".") + ".<init>" for m in _NEW.finditer(text)}

    missing = []
    for sym in em.entry_symbols:
        owner, member = sym.rsplit(".", 1)
        want = f"{owner}.{member}"
        if not any(ref.startswith(want) or ref.startswith(f'"{want}') for ref in refs):
            missing.append(sym)

    v: list = []
    for s in missing:
        v.append(Violation(
            "D1.CALL_ABSENT", BLOCK,
            f"{s} does not appear in the harness's constant pool. The call is not in the "
            f"compiled bytecode, so the campaign would exercise an empty method.",
            where=s,
            fix="check the plan actually sequences this API, and that the class compiled "
                "against the intended version of the library"))

    return decide("D1", title, v, expected=list(em.entry_symbols),
                  bytecode_refs=sorted(refs)[:60],
                  note=("javac performs almost no optimisation, so unlike C the compiler is "
                        "not the risk here. The JIT CAN eliminate a call whose result is "
                        "unused, at run time, where no static check can see it — which is "
                        "why the harness folds every return value into a volatile sink."))


# ── D3 / D5 / D6 over the replay driver ──────────────────────────────────────

def d3_valid_input(ir: HarnessIR, art: JavaBuild, corpus: list,
                   classpath: str = "") -> GateResult:
    """Inputs the library is supposed to accept must not produce a DEFECT.

    The Java form is stricter than a crash check and had to be: on the JVM a valid input
    routinely throws, because throwing is how an API says no. So this asks the classifier,
    not the exit code — an input that provokes the library's own documented exception is the
    library working, and only a DEFECT verdict is a failure.
    """
    title = "valid input does not provoke a defect"
    if not art.replay_ok or not art.classes:
        return not_run("D3", title, "the replay driver was not built")
    if not corpus:
        return not_run("D3", title, "no valid corpus was supplied")

    packages = _library_packages(ir)
    bad = []
    for i, data in enumerate(corpus[:24]):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        run = jt.replay(str(art.classes), path, classpath=classpath)
        if run.outcome != jt.FAULT:
            continue
        j = jx.classify(run.stdout, library_packages=packages,
                        harness_classes={"Harness", "Replay", "Harness.java", "Replay.java"},
                        declared_throws=_declared(ir))
        if j.verdict in (jx.DEFECT, jx.HARNESS):
            bad.append({"index": i, "verdict": j.verdict, "exception": j.exception,
                        "reason": j.reason[:200]})

    v: list = []
    if bad:
        harness_owned = [b for b in bad if b["verdict"] == jx.HARNESS]
        v.append(Violation(
            "D3.VALID_INPUT_DEFECT", BLOCK,
            f"{len(bad)} of {min(len(corpus), 24)} valid inputs produced a "
            f"{'harness' if harness_owned else 'library'} fault. "
            + ("The harness itself threw, so every finding from this plan would be ours."
               if harness_owned else
               "Either the corpus is not valid, or the plan violates the API's contract."),
            where=str(bad[0]["index"]), principle="P2",
            fix="check the constructor arguments and the order of the sequence"))

    return decide("D3", title, v, tested=min(len(corpus), 24), defects=bad[:6],
                  note=("a valid input that throws the library's OWN declared exception is "
                        "not a failure here: on the JVM that is how an API says no"))


def d6_determinism(art: JavaBuild, probe: bytes, trials: int = 8,
                   classpath: str = "") -> GateResult:
    title = "determinism: the same input gives the same outcome"
    if not art.replay_ok or not art.classes:
        return not_run("D6", title, "the replay driver was not built")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(probe)
        path = f.name
    outcomes = [jt.replay(str(art.classes), path, classpath=classpath).outcome
                for _ in range(trials)]
    distinct = sorted(set(outcomes))
    v: list = []
    if len(distinct) > 1:
        v.append(Violation(
            "D6.NONDETERMINISTIC", WARN,
            f"{trials} runs of one input produced {distinct}. A harness whose outcome varies "
            f"cannot support a reproduction rate, and on the JVM the usual causes are a "
            f"static field carried between runs, a hash-ordered collection, or a timeout.",
            principle="P3",
            fix="reset any static state the plan touches, and prefer ordered collections"))
    return decide("D6", title, v, trials=trials, outcomes=distinct)


# ── D9: whose frame threw ────────────────────────────────────────────────────

def d9_provenance(ir: HarnessIR, trace: str) -> GateResult:
    """Attribution, which on the JVM is the same act as classification."""
    title = "provenance: library defect, harness bug, or the documented contract"
    if not trace:
        return not_run("D9", title,
                       "no stack trace to attribute. This gate runs when a campaign or a "
                       "replay produces one, not during certification of a clean harness.")
    j = jx.classify(trace, library_packages=_library_packages(ir),
                    harness_classes={"Harness", "Replay", "Harness.java", "Replay.java"},
                    declared_throws=_declared(ir))
    v: list = []
    if j.verdict == jx.HARNESS:
        v.append(Violation(
            "D9.HARNESS_THREW", BLOCK,
            f"the exception escaped from harness frames: {j.reason}",
            principle="P1",
            fix="the plan is calling the API in a way its contract forbids; fix the plan "
                "rather than reporting the crash"))
    elif j.verdict == jx.CONTRACT:
        # WARN, not BLOCK. A harness that provokes the library's documented exception is
        # working correctly; the exception simply is not a finding. Blocking here refused a
        # perfectly good plan because ONE of its crash inputs was a contract exception —
        # confusing "this crash is not a finding" with "this harness is defective". Only a
        # harness-thrown exception is the plan's fault.
        v.append(Violation(
            "D9.CONTRACT_NOT_DEFECT", WARN,
            f"this crash is the library's documented way of rejecting input, not a defect: "
            f"{j.reason}",
            principle="P1",
            fix="nothing to fix in the harness — it is working. This particular crash is "
                "not a finding and must not be sent to a maintainer."))
    return decide("D9", title, v, provenance=j.verdict, exception=j.exception,
                  thrower=(f"{j.thrower.file}:{j.thrower.line}" if j.thrower else ""),
                  sanitizer=j.sanitizer, reading=j.reason)


# ── D4: what dangerous destinations does this plan reach ─────────────────────

def d4_sinks(ir: HarnessIR, sources: Optional[list] = None) -> GateResult:
    """The JVM sink surface. A different table answering the same question.

    Porting the C table would have scored every Java target zero and read as a weak harness
    rather than an inapplicable measure — `strcpy` and `alloca` do not exist here. What
    matters on the JVM is where a TRUST BOUNDARY is crossed: nothing is overwritten when
    `readObject` deserialises attacker bytes, and it is the most damaging bug class the
    platform has.
    """
    title = "sink surface: dangerous destinations in the target"
    srcs = [Path(s) for s in (sources or ir.target.sources) if str(s).endswith(".java")]
    if not srcs:
        return not_run("D4", title,
                       "no Java sources supplied, so the sink surface cannot be read. "
                       "Bytecode-level analysis would lift this; source is what is wired.")
    found: dict = {}
    for s in srcs:
        try:
            for k, n in scan_sinks(s.read_text(errors="replace")).items():
                found[k] = found.get(k, 0) + n
        except OSError:
            continue
    weight = sum(SINKS[k][1] * min(n, 4) for k, n in found.items() if k in SINKS)
    return decide("D4", title, [], sinks=found, sink_weight=round(weight, 1),
                  files=len(srcs),
                  note=("C sinks corrupt memory; JVM sinks cross a trust boundary. A "
                        "deserialization sink is the highest-value destination on this "
                        "platform and would score zero under the C table."))


# ── helpers ──────────────────────────────────────────────────────────────────

def _library_packages(ir: HarnessIR) -> set:
    """Package prefixes that ARE the target, taken from the APIs the plan calls.

    Without these nothing can be attributed and the honest verdict is UNKNOWN. Deriving them
    from the plan rather than asking the operator means the attribution cannot drift from
    what the harness actually calls.
    """
    out = set()
    for api in ir.apis.values():
        owner = api.symbol.rsplit(".", 1)[0]
        parts = owner.split(".")
        if len(parts) >= 2:
            out.add(".".join(parts[:2]))
        out.add(owner)
    return {p for p in out if p and not p.startswith(("java.", "javax.", "jdk.", "sun."))}


def _declared(ir: HarnessIR) -> set:
    out: set = set()
    for api in ir.apis.values():
        out |= set(api.contract.declared_exceptions)
    return out


# ── D8: will a campaign against this actually find anything ──────────────────

_MAJOR_MISMATCH = re.compile(r"Unsupported class file major version (\d+)")


def d8_campaign(ir: HarnessIR, em, art: JavaBuild, *, seconds: int = 20,
                classpath: str = "", keep_going: int = 25) -> GateResult:
    """Run Jazzer briefly and report what it could actually see.

    Two JVM-specific things this gate has to get right, both found by running it:

    **`--keep_going`.** In C, halting at the first crash is correct — a crash is a finding.
    On the JVM most escaped exceptions are NOT findings, so halting there ends the campaign
    on a non-event. Run unmodified against a parser that throws on empty input, Jazzer
    stopped at the FIRST input and reported the library's own documented rejection; the
    campaign never started. With the declared-exception catch in the harness AND keep_going,
    the same target ran 15.9M executions and reached the planted defect.

    **The bytecode version.** Jazzer's bundled ASM refuses class files newer than it knows,
    and the error it surfaces is `'Harness' not found on classpath` — which sends you to
    debug a classpath that is correct. The real message is buried in a warning fifty lines
    up. This gate reads for it and says so.
    """
    title = "campaign productivity: what the fuzzer can actually see"
    if not art.ok or not art.classes:
        return not_run("D8", title, "the harness class was not compiled")

    driver = jt.find_jazzer_standalone()
    api = jt.jazzer_api_jar()
    if not driver:
        return not_run("D8", title,
                       "no Jazzer on this host, so no campaign can be built. Certification "
                       "is unaffected: every gate that feeds a CHOSEN input runs through the "
                       "replay driver, which depends on nothing.")

    java = jt.find_java()
    wd = art.workdir
    arts = wd / "artifacts"
    arts.mkdir(exist_ok=True)
    corp = wd / "corpus"
    corp.mkdir(exist_ok=True)
    if not any(corp.iterdir()):
        (corp / "seed0").write_bytes(b"hello")

    cp = ":".join([x for x in (driver, api, str(art.classes), classpath,
                               *ir.target.link_libs) if x])
    cmd = [java, "-cp", cp, "com.code_intelligence.jazzer.Jazzer",
           "--target_class=Harness", f"--keep_going={keep_going}",
           f"-artifact_prefix={arts}/", f"-max_total_time={seconds}",
           f"-max_len={ir.knobs.max_len or 4096}", str(corp)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=seconds + 180)
    except subprocess.TimeoutExpired:
        return not_run("D8", title, "the campaign did not terminate within its budget")

    text = (r.stdout or "") + (r.stderr or "")

    if "not found on classpath" in text:
        mm = _MAJOR_MISMATCH.search(text)
        if mm:
            return not_run("D8", title,
                           f"Jazzer could not read the compiled classes: class file major "
                           f"version {mm.group(1)} is newer than its bundled ASM supports. "
                           f"It reports this as \"'Harness' not found on classpath\", which "
                           f"sends you to debug a classpath that is correct. Compile with "
                           f"--release 17, or use a newer Jazzer.")
        return not_run("D8", title, "Jazzer could not find the harness class on the classpath")

    covs = [int(m) for m in re.findall(r"cov:\s*(\d+)", text)]
    edges = max(covs) if covs else 0
    grew = bool(covs) and covs[-1] > covs[0]
    execs = re.search(r"#(\d+)\s+DONE", text)
    exceptions = re.findall(r"== Java Exception: ([^\n]+)", text)
    crashes = sorted(p for p in arts.iterdir() if p.is_file())

    v: list = []
    if edges <= 2:
        v.append(Violation(
            "D8.NO_COVERAGE", WARN,
            f"the campaign reached {edges} edge(s). The harness is not getting into the "
            f"target's code at all.",
            principle="P4",
            fix="check the constructor arguments and whether the entry point needs a setup "
                "call the plan omits"))
    elif not grew:
        v.append(Violation(
            "D8.COVERAGE_PLATEAU", WARN,
            f"coverage never grew beyond {edges} edge(s) during the run.",
            principle="P4", fix="seed the corpus with a real input the library accepts"))

    return decide("D8", title, v, edges=edges, coverage_grew=grew,
                  executions=int(execs.group(1)) if execs else 0,
                  seconds=seconds, keep_going=keep_going,
                  crash_inputs=[str(p) for p in crashes],
                  exceptions_seen=exceptions[:12],
                  note=("keep_going is required on the JVM: halting at the first escaped "
                        "exception ends the campaign on the library's own error path"))


def triage_campaign(ir: HarnessIR, art: JavaBuild, crash_paths: list, *,
                    classpath: str = "") -> list:
    """Judge every crash the campaign produced. Returns a list of rows.

    Replay happens TWICE — JIT-compiled and interpreted — because that pair is the JVM's
    answer to rung 3's demand for an oracle independent of the one that discovered the
    fault. Jazzer found it; `-Xint` is a different execution mode confirming it.
    """
    from . import ladder as jladder

    rows = []
    packages = _library_packages(ir)
    declared = _declared(ir)
    harness = {"Harness", "Replay", "Harness.java", "Replay.java"}

    for path in crash_paths:
        raw = Path(path).read_bytes() if Path(path).exists() else b""
        small, shrank = minimise(art, raw, classpath=classpath)
        if shrank:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(small)
                path = f.name
        jit = jt.replay(str(art.classes), path, classpath=classpath)
        xint = jt.replay(str(art.classes), path, classpath=classpath, interpreted=True)
        indep, reading = jt.decide_jit_differential(jit, xint)
        j = jx.classify(jit.stdout, library_packages=packages, harness_classes=harness,
                        declared_throws=declared)
        rung, why = jladder.assign(
            escaped=jit.faulted, reproduce_rate=1.0 if jit.faulted else 0.0,
            minimised=True, verdict=j.verdict,
            attributed_to_library=(j.verdict == jx.DEFECT),
            independent_oracle=indep, sanitizer=j.sanitizer)
        rows.append({
            "input": path,
            "bytes": len(small),
            "original_bytes": len(raw),
            "minimised": shrank,
            "exception": j.exception, "verdict": j.verdict, "rung": rung,
            "why": why, "independent": indep, "independence_reading": reading,
            "thrower": (f"{j.thrower.file}:{j.thrower.line}" if j.thrower else ""),
            "sanitizer": j.sanitizer,
        })
    return rows


# ── F2 for the JVM: a minimised reproducer ───────────────────────────────────

def _signature(run) -> tuple:
    """What must stay the same for a reduction to count as the same fault.

    The exception CLASS and the frame that threw it. Reducing on "still crashes" alone
    happily turns a 91-byte ArrayIndexOutOfBounds into a 2-byte NumberFormatException and
    reports the wrong bug with a confident minimal reproducer attached.
    """
    cls, _msg, frames = jx.parse_trace(run.stdout)
    top = next((f for f in frames if f.file), None)
    return cls, (f"{top.file}:{top.line}" if top else "")


def minimise(art: JavaBuild, data: bytes, *, classpath: str = "",
             rounds: int = 6) -> tuple:
    """Shrink an input while it still produces the SAME fault. Returns (bytes, shrank).

    Without this nothing can climb past rung 1: the ladder requires `minimised` for rung 2,
    and rung 3 sits above it. The gate existed for C and had no JVM implementation, so every
    Java finding would have capped at 'an exception escaped' no matter how good the evidence
    — a whole ladder made unreachable by one missing step, the same shape as rung 3 being
    unreachable without a Java ladder at all.
    """
    if not art.replay_ok or not art.classes:
        return data, False

    def faults_the_same(candidate: bytes, want: tuple) -> bool:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(candidate)
            path = f.name
        run = jt.replay(str(art.classes), path, classpath=classpath)
        return run.faulted and _signature(run) == want

    # The replay must happen AFTER the file is closed. Running it inside the `with` block
    # read an unflushed, empty file: the driver saw no input, the parser did not fault, and
    # minimise returned immediately with "did not shrink" — every reproducer stayed at its
    # campaign size and nothing ever looked wrong.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        seed_path = f.name
    first = jt.replay(str(art.classes), seed_path, classpath=classpath)
    if not first.faulted:
        return data, False
    want = _signature(first)

    best = data
    for _ in range(rounds):
        shrank = False
        # Halve from the tail, then from the head: a magic prefix must survive, and a
        # length-triggered defect needs the tail.
        for cut in (len(best) // 2, len(best) // 4, 1):
            if cut <= 0 or cut >= len(best):
                continue
            for cand in (best[:-cut], best[cut:]):
                if cand and faults_the_same(cand, want):
                    best = cand
                    shrank = True
                    break
            if shrank:
                break
        if not shrank:
            break
    return best, len(best) < len(data)


# ── D2: would this harness notice a defect placed in its path? ───────────────

@dataclass
class Mutation:
    id: str
    what: str
    find: str
    replace: str


# Operators from PIT's catalogue, chosen for one property: each turns a correct guard into an
# incorrect one, so a harness that reaches the site SHOULD see an exception it did not see
# before. Mutations that merely change a value are useless as a positive control — nothing
# observable happens.
MUTATIONS = (
    Mutation("bounds-off-by-one", "a length guard is loosened by one", "<", "<="),
    Mutation("bounds-removed", "a length guard always passes", "if (", "if (true || "),
    Mutation("negate-guard", "an equality guard is inverted", "==", "!="),
)


def _mutant_sources(sources: list, m: Mutation, site: int) -> Optional[dict]:
    """One mutant: the Nth occurrence of an operator, flipped. None if there is no Nth."""
    seen = 0
    for path in sources:
        try:
            text = Path(path).read_text(errors="replace")
        except OSError:
            continue
        idx = 0
        while True:
            idx = text.find(m.find, idx)
            if idx < 0:
                break
            # Skip occurrences inside a string or a comment: mutating those changes a
            # message, not behaviour, and a mutant nothing can observe is a free pass.
            line_start = text.rfind("\n", 0, idx) + 1
            line = text[line_start:text.find("\n", idx)]
            if line.lstrip().startswith(("//", "*", "/*")) or line.count('"') % 2 == 1:
                idx += len(m.find)
                continue
            if seen == site:
                return {path: text[:idx] + m.replace + text[idx + len(m.find):]}
            seen += 1
            idx += len(m.find)
    return None


def d2_positive_control(ir: HarnessIR, em, art: JavaBuild, corpus: list, *,
                        classpath: str = "", mutants: int = 6,
                        release: int = DEFAULT_RELEASE) -> GateResult:
    """Plant defects in the TARGET and check the harness notices.

    The only gate that asks whether a harness can find anything, rather than whether it is
    correct. A harness can be perfectly well-formed, reach deep coverage and be incapable of
    observing a defect on the line it runs through.

    The mutant changes the target, never the harness — so on the JVM only the target's
    classes are recompiled and swapped on the classpath, which is cheaper than the C
    equivalent where the whole library is rebuilt. (Bytecode mutation with ASM would be
    cheaper still and needs no source; source is what is wired, and that is a limit worth
    stating rather than a claim.)
    """
    title = "positive control: the harness finds a planted defect"
    srcs = [s for s in ir.target.sources if str(s).endswith(".java")]
    if not srcs:
        return not_run("D2", title,
                       "no Java sources supplied, so no defect can be planted. Bytecode "
                       "mutation would lift this; source mutation is what is wired.")
    if not art.replay_ok or not art.classes:
        return not_run("D2", title, "the replay driver was not built")
    javac = jt.find_javac()
    if not javac:
        return not_run("D2", title, "no javac on this host")

    baseline = _outcomes(art, corpus, classpath)

    killed, survived, built = 0, 0, 0
    detail: list = []
    for m in MUTATIONS:
        for site in range(max(1, mutants // len(MUTATIONS))):
            mutated = _mutant_sources(srcs, m, site)
            if not mutated:
                continue
            wd = Path(tempfile.mkdtemp(prefix="hforge-mut-"))
            mclasses = wd / "classes"
            mclasses.mkdir()
            files = []
            for path, text in mutated.items():
                f = wd / Path(path).name
                f.write_text(text)
                files.append(str(f))
            others = [s for s in srcs if Path(s).name not in
                      {Path(p).name for p in mutated}]
            r = subprocess.run([javac, "--release", str(release), "-d", str(mclasses),
                                *files, *others],
                               capture_output=True, text=True, errors="replace")
            if r.returncode != 0:
                continue                   # a mutant that does not compile is not evidence
            built += 1

            # The harness's own classes, with the MUTANT target ahead of the original.
            probe = JavaBuild(art.workdir, art.harness_java, art.replay_java,
                              art.classes, True, "", True)
            got = _outcomes(probe, corpus, f"{mclasses}:{classpath}", prefix=str(mclasses))
            if got != baseline:
                killed += 1
                detail.append({"mutation": m.id, "site": site, "what": m.what,
                               "result": "killed"})
            else:
                survived += 1
                detail.append({"mutation": m.id, "site": site, "what": m.what,
                               "result": "survived"})

    if built == 0:
        return not_run("D2", title,
                       "no mutant compiled, so nothing was proved either way. That is not a "
                       "pass.")

    rate = killed / float(built)
    v: list = []
    if killed == 0:
        v.append(Violation(
            "D2.NO_KILL", BLOCK,
            f"the harness noticed NONE of {built} defects planted in the target. It runs, it "
            f"reaches code, and it cannot observe a bug on the line it executes.",
            principle="P4",
            fix="check that the plan reads the result of the call and that the corpus "
                "actually reaches the mutated site"))
    return decide("D2", title, v, mutants_built=built, killed=killed, survived=survived,
                  kill_rate=round(rate, 2), detail=detail[:8],
                  note=("a mutant changes the TARGET, never the harness, so only the "
                        "target's classes are recompiled and swapped on the classpath"))


def _outcomes(art: JavaBuild, corpus: list, classpath: str,
              prefix: str = "") -> tuple:
    """The outcome vector over a corpus: what this build does with each input."""
    out = []
    for data in (corpus or [b"hello"])[:12]:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        cp = f"{prefix}:{classpath}" if prefix else classpath
        run = jt.replay(str(art.classes), path, classpath=cp)
        cls, _m, _f = jx.parse_trace(run.stdout) if run.faulted else ("", "", [])
        out.append((run.outcome, cls))
    return tuple(out)


def run_java_gates(ir: HarnessIR, em, art: JavaBuild, *, valid_corpus=None,
                   drive_corpus=None, classpath: str = "", probe: bytes = b"",
                   positive_control: bool = True, campaign: bool = True,
                   campaign_seconds: int = 20) -> list:
    """Every dynamic gate, asked of the JVM. Same shape as `run_dynamic_gates`.

    The gates that are INAPPLICABLE here return NOT_RUN with the reason, rather than being
    omitted. A Java certificate showing five passes and no mention of D5 would read as
    stronger than one that says D5 measures a fault RATE over a mutating pointer and has no
    JVM meaning — and the second is the true statement.
    """
    corpus = list(valid_corpus or [])
    drive = list(drive_corpus or corpus)
    p = probe or (corpus[0] if corpus else b"hello")

    d2 = (d2_positive_control(ir, em, art, drive, classpath=classpath)
          if positive_control
          else not_run("D2", "positive control: the harness finds a planted defect",
                       "disabled for this run"))
    d8 = (d8_campaign(ir, em, art, seconds=campaign_seconds, classpath=classpath)
          if campaign
          else not_run("D8", "campaign productivity: what the fuzzer can actually see",
                       "disabled for this run"))

    trace = ""
    for path in d8.evidence.get("crash_inputs", [])[:1]:
        run = jt.replay(str(art.classes), path, classpath=classpath)
        trace = run.stdout

    return [
        d1_liveness(ir, em, art),
        d2,
        d3_valid_input(ir, art, corpus, classpath=classpath),
        d4_sinks(ir),
        not_run("D5", "fault rate across a mutating input",
                "D5 measures how often a fault appears as one pointer is walked across a "
                "buffer. There is no such pointer on the JVM: an index out of range raises "
                "immediately and deterministically, which is what D3 and D6 already "
                "measure. Not applicable rather than passed."),
        d6_determinism(art, p, classpath=classpath),
        not_run("D7", "knobs are consistent with the platform",
                "sanitizer and allocator knobs describe a native build. The JVM equivalents "
                "are the execution mode and the heap limit, and they are recorded on the "
                "campaign rather than as knobs."),
        d8,
        d9_provenance(ir, trace),
        not_run("D11", "differential consistency across producers",
                "only one Java producer exists, so there is nothing to disagree with. The "
                "gate is unchanged and will run when a second one lands."),
    ]
