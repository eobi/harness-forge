"""Dynamic gates — run against a build.

  D1  liveness        the target call survived the optimiser                    (no field equiv.)
  D2  positive ctrl   the harness detects defects PLANTED in code it reaches           P4
  D3  valid input     valid inputs must not crash: if they do, the harness is broken   P1/P2
  D4  reachability    what fraction of the sink surface this harness can touch         P4
  D5  rate            exec/s sane in both directions                            (no field equiv.)
  D6  determinism     same input, N runs, report the RATE not a boolean         (no field equiv.)
  D7  knobs           record every knob and COMPUTE what it excludes            (no field equiv.)
  D9  misuse          whose buffer overflowed, ours or the library's                   P1
  D11 consistency     two plans for one entry point must agree on valid input          P2

D2 is the one that pays for the rest. Every other gate assumes the harness can find
something; D2 is the only one that checks, by planting a real defect in code the harness
reaches and requiring it to be noticed. A gate that cannot run says NOT_RUN with a reason,
because an absent check must never read as a passed one.

Two engineering details, both learned the expensive way and both encoded rather than
remembered:

  * a faulting child on macOS is inspected by ReportCrash, which holds an inherited pipe
    open and can wedge a replay loop for tens of seconds per crash. Every child here writes
    to /dev/null and is never given a pipe.
  * `nm` on the harness *object* is the portable liveness check. A call the optimiser
    deleted leaves no undefined symbol behind, on ELF and Mach-O alike.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

from .. import corpus, toolchain as tc
from ..analysis import dictionary, seeds
from ..analysis.sinks import build_map
from ..emit.c_libfuzzer import Emitted
from ..ir import HarnessIR
from ..mutate import generate_mutants
from .result import BLOCK, WARN, INFO, GateResult, Violation, decide, not_run

ALL_DYNAMIC = ("D1", "D2", "D3", "D4", "D5", "D6", "D7", "D9", "D11")
PHASE1_DYNAMIC = ("D1", "D3", "D5", "D6", "D7")

DEVNULL = subprocess.DEVNULL


@dataclass
class BuildArtifacts:
    workdir: Path
    harness_c: Path
    driver_c: Optional[Path]
    obj: Optional[Path]
    replay_bin: Optional[Path]
    log: str
    ok: bool


# Host-specific resolution lives in hforge.toolchain so every gate on every OS asks the
# same question the same way. These are thin re-exports kept for call-site readability.
find_cc = tc.find_cc
_nm = tc.find_nm


# Compiled target objects, keyed by what went into them. sqlite3.c is 243,646 lines and a
# batch run builds two dozen plans against it; recompiling the target for every plan is the
# same work done twenty-four times. The archive is built once and linked thereafter.
#
# Gate D2 deliberately bypasses this: mutation testing exists to compile a CHANGED target,
# so a cache keyed on the unmutated sources would hand it the wrong binary and every mutant
# would survive.
_ARCHIVE_CACHE: dict = {}

# Mutants generated per (sources, reachable set). D2 plants defects in the TARGET, which does
# not change between plans, so a batch of 30 candidates was regenerating and recompiling the
# same mutants 30 times. This is the difference between D2 being affordable in a batch and
# being the flag everyone turns off — which is what happened for weeks, leaving KILL at 0%.
_MUTANT_CACHE: dict = {}

# Compiled MUTANT OBJECTS, keyed on the mutated source's content.
#
# A mutant changes the target, not the harness. The same mutant is then tested against every
# candidate plan, and each of those rebuilt it from scratch — 24 mutants x N plans full
# rebuilds of a 243k-line amalgamation, which is why D2 was switched off for weeks and KILL
# read `?` in every table.
#
# The object depends only on (source text, flags). Compile it once, link it against each
# harness. This is the same move as the target archive, applied to the thing the archive
# deliberately cannot cache.
_MUTANT_OBJ_CACHE: dict = {}


def _mutant_object(src_path: str, content: str, cc: str, common: list, san: str,
                   log: list) -> Optional[str]:
    key = hashlib.sha256(
        ("\x00".join([cc, san, *common]) + "\x00" + content).encode()).hexdigest()
    hit = _MUTANT_OBJ_CACHE.get(key)
    if hit and Path(hit).exists():
        return hit
    d = Path(tempfile.mkdtemp(prefix="hforge-mut-"))
    src = d / Path(src_path).name
    src.write_text(content)
    obj = d / (src.stem + ".o")
    cmd = [*common] + ([f"-fsanitize={san}"] if san else []) + \
          ["-c", str(src), "-o", str(obj)]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        log.append(f"$ compile mutant -> rc={r.returncode}\n{r.stderr[-1200:]}")
        return None
    _MUTANT_OBJ_CACHE[key] = str(obj)
    return str(obj)


def _target_archive(ir: HarnessIR, cc: str, common: list, san: str) -> Optional[str]:
    """Compile the target's sources once into a static archive and reuse it."""
    if not ir.target.sources:
        return None
    key = hashlib.sha256(
        "\x00".join([cc, san, *sorted(ir.target.sources), *ir.target.cflags,
                      *ir.target.include_dirs, ir.knobs.optimisation]).encode()).hexdigest()
    hit = _ARCHIVE_CACHE.get(key)
    if hit and Path(hit).exists():
        return hit

    d = Path(tempfile.mkdtemp(prefix="hforge-target-"))
    objs = []
    for i, src in enumerate(ir.target.sources):
        o = d / f"t{i}.o"
        cmd = [*common]
        if san:
            cmd.append(f"-fsanitize={san}")
        cmd += ["-c", str(src), "-o", str(o)]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            return None
        objs.append(str(o))

    ar = shutil.which("llvm-ar") or shutil.which("ar")
    if not ar:
        return None
    lib = d / "libtarget.a"
    r = subprocess.run([ar, "rcs", str(lib), *objs], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    _ARCHIVE_CACHE[key] = str(lib)
    return str(lib)


def build(ir: HarnessIR, em: Emitted, workdir: Optional[Path] = None,
          source_override: Optional[dict] = None) -> BuildArtifacts:
    """Compile the harness to an object, and the harness+driver to a replay binary.

    The object is what D1 inspects. The replay binary is what D3/D5/D6 run: it is the same
    harness with no fuzzer runtime, which is the only way to feed it a chosen input.

    `source_override` maps a target source path to replacement contents. Gate D2 uses it to
    build the identical harness against a mutant, which is the only honest way to ask
    whether the harness would notice a defect placed in its path.
    """
    wd = Path(workdir or tempfile.mkdtemp(prefix="hforge-"))
    wd.mkdir(parents=True, exist_ok=True)
    hc, dc = wd / "harness.c", wd / "driver.c"
    hc.write_text(em.source)
    if em.driver:
        dc.write_text(em.driver)

    cc = find_cc()
    if not cc:
        return BuildArtifacts(wd, hc, dc if em.driver else None, None, None,
                              "no C compiler found", False)

    sources = list(ir.target.sources)
    if source_override:
        patched = wd / "mutant"
        patched.mkdir(exist_ok=True)
        for i, s in enumerate(sources):
            if s in source_override:
                q = patched / f"{i}_{Path(s).name}"
                q.write_text(source_override[s])
                sources[i] = str(q)

    incs = ([f"-I{d}" for d in ir.target.include_dirs]
            + list(ir.target.cflags))    # -DHAVE_CONFIG_H and friends
    common = [cc, "-g", ir.knobs.optimisation, "-fno-omit-frame-pointer", *incs]
    log: list[str] = []

    obj = wd / "harness.o"
    r = subprocess.run([*common, "-c", str(hc), "-o", str(obj)],
                       capture_output=True, text=True)
    log.append(f"$ compile object -> rc={r.returncode}\n{r.stderr[-2000:]}")
    if r.returncode != 0:
        return BuildArtifacts(wd, hc, dc, None, None, "\n".join(log), False)

    replay = None
    if em.driver:
        san = ",".join(ir.knobs.sanitizers)
        cmd = [*common]
        if san:
            cmd.append(f"-fsanitize={san}")
        exe = wd / ("replay" + tc.host().exe_suffix)
        if source_override:
            # A mutant changes ONE translation unit. Two caches make this affordable:
            #   * the mutated file compiles to an object ONCE and is linked against every
            #     harness thereafter — the object depends on the source, not on the plan;
            #   * the untouched files come from an archive keyed on "everything except this
            #     file".
            # Together they turn (mutants x plans) full rebuilds into (mutants) compiles
            # plus a link per plan, which is what a 243k-line amalgamation needs before D2
            # can be left on.
            untouched = [x for x in ir.target.sources if x not in source_override]
            rest = _target_archive(replace(ir, target=replace(ir.target,
                                                             sources=untouched)),
                                   cc, common, san) if untouched else None
            objs = []
            ok = True
            for orig, content in source_override.items():
                o = _mutant_object(orig, content, cc, common, san, log)
                if o is None:
                    ok = False
                    break
                objs.append(o)
            if ok:
                target_inputs = objs + ([rest] if rest else [])
            else:
                target_inputs = sources
        else:
            arch = _target_archive(ir, cc, common, san)
            target_inputs = [arch] if arch else sources
        cmd += [str(hc), str(dc), *target_inputs, *ir.target.link_libs, "-o", str(exe)]
        r2 = subprocess.run(cmd, capture_output=True, text=True)
        log.append(f"$ link replay -> rc={r2.returncode}\n{r2.stderr[-2000:]}")
        if r2.returncode == 0:
            replay = exe

    return BuildArtifacts(wd, hc, dc if em.driver else None, obj, replay,
                          "\n".join(log), True)


def _asan_env() -> dict:
    env = dict(os.environ)
    # abort_on_error=1 wedges on macOS: the process enters state UE and never exits.
    env.setdefault("ASAN_OPTIONS",
                   "abort_on_error=0:detect_leaks=0:allocator_may_return_null=1")
    return env


def _run_once(binary: Path, data: bytes, timeout: float = 10.0,
              sanitized: bool = True) -> tuple[Optional[int], bool]:
    """Run one input. Returns (returncode, faulted). Never gives the child a pipe.

    Fault classification is delegated to `toolchain.classify_exit`, because it is completely
    different per OS. An earlier version tested `rc >= 128 or rc == 1`, which is the POSIX
    spelling: on Windows a crash returns an NTSTATUS such as 0xC0000005 and that check never
    fires. Every crash would have read as a clean run, every gate would have passed, and the
    engine would have certified harnesses that detect nothing.
    """
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    osname = tc.host().os
    try:
        r = subprocess.run([str(binary), path], stdout=DEVNULL, stderr=DEVNULL,
                           stdin=DEVNULL, env=_asan_env(), timeout=timeout)
        return r.returncode, tc.is_fault(r.returncode, os_name=osname, sanitized=sanitized)
    except subprocess.TimeoutExpired:
        return None, False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ── D1 liveness ───────────────────────────────────────────────────────────────

def d1_liveness(ir: HarnessIR, em: Emitted, art: BuildArtifacts) -> GateResult:
    """Did the target call survive the compiler?

    A harness whose body the optimiser deleted runs at enormous speed and reports nothing,
    and is indistinguishable from a clean target. The portable check: every API the plan
    calls must appear as an UNDEFINED symbol in the harness object. If it does not, no call
    site remains.
    """
    if not art.obj:
        return not_run("D1", "liveness: the target call survived the optimiser",
                       "the harness object was not built")
    nm = _nm()
    if not nm:
        return not_run("D1", "liveness: the target call survived the optimiser",
                       "no nm / llvm-nm on PATH, so undefined symbols cannot be read")

    r = subprocess.run([nm, "-u", str(art.obj)], capture_output=True, text=True)
    text = r.stdout
    undefined = {ln.split()[-1].lstrip("_") for ln in text.splitlines() if ln.strip()}

    v: list[Violation] = []
    missing = [s for s in em.entry_symbols if s.lstrip("_") not in undefined]
    for s in missing:
        v.append(Violation(
            "D1.CALL_ELIDED", BLOCK,
            f"{s} does not appear as an undefined symbol in the compiled harness object. "
            f"The call was removed by the optimiser, so the campaign would search an empty "
            f"function and report nothing.",
            where=s,
            fix="read the result of the call, or store it through a volatile sink, so the "
                "call is not dead code"))

    return decide("D1", "liveness: the target call survived the optimiser", v,
                  expected=em.entry_symbols, undefined_symbols=sorted(undefined),
                  optimisation=ir.knobs.optimisation)


# ── D3 valid input ────────────────────────────────────────────────────────────

def d3_valid_input(ir: HarnessIR, art: BuildArtifacts,
                   corpus: list[bytes]) -> GateResult:
    """Feed the harness inputs the library is supposed to accept.

    If a valid input crashes, the defect is in the harness, not the target. This is the
    check that would have caught the exact-size-buffer cJSON harness before it produced
    eight reports against a library that was behaving correctly.
    """
    if not art.replay_bin:
        return not_run("D3", "valid input must not crash",
                       "the standalone replay binary was not built")
    if not corpus:
        return not_run("D3", "valid input must not crash",
                       "no valid-input corpus supplied; without one this gate is vacuous")

    v: list[Violation] = []
    crashed = []
    for i, data in enumerate(corpus):
        rc, faulted = _run_once(art.replay_bin, data)
        if faulted:
            crashed.append({"index": i, "rc": rc, "len": len(data),
                            "head": data[:32].hex()})

    if crashed:
        v.append(Violation(
            "D3.VALID_INPUT_CRASH", BLOCK,
            f"{len(crashed)} of {len(corpus)} inputs the library should accept caused the "
            f"harness to fault. Every finding this harness produces is its own until that "
            f"is fixed.",
            fix="check NUL-termination, (ptr,len) pairs, and call ordering against the "
                "library's documented contract — gate S2 usually names the clause"))

    return decide("D3", "valid input must not crash", v,
                  corpus_size=len(corpus), crashed=crashed)


# ── D5 rate ───────────────────────────────────────────────────────────────────

def d5_rate(ir: HarnessIR, art: BuildArtifacts, probe: bytes,
            runs: int = 40) -> GateResult:
    """Executions per second, checked in BOTH directions.

    Too slow means file I/O or printing left in the harness. Too fast, on a real parser,
    usually means the body is gone — the same failure D1 catches, visible from the other
    side.
    """
    if not art.replay_bin:
        return not_run("D5", "execution rate is plausible",
                       "the standalone replay binary was not built")

    t0 = time.time()
    for _ in range(runs):
        _run_once(art.replay_bin, probe, timeout=10.0)
    elapsed = time.time() - t0
    per_run = elapsed / max(runs, 1)

    v: list[Violation] = []
    # process-per-run, so this measures process cost, not in-process throughput.
    if per_run > 0.75:
        v.append(Violation("D5.TOO_SLOW", WARN,
                           f"{per_run * 1000:.0f} ms per execution. On a small parser that "
                           f"usually means file I/O, printing or a sleep is still in the "
                           f"harness. Every millisecond is executions you do not get.",
                           fix="remove I/O from the harness body"))
    return decide("D5", "execution rate is plausible", v,
                  runs=runs, seconds=round(elapsed, 3),
                  ms_per_run=round(per_run * 1000, 2),
                  note="process-per-run measurement; in-process throughput is measured by "
                       "the campaign itself")


# ── D6 determinism ────────────────────────────────────────────────────────────

def d6_determinism(art: BuildArtifacts, probe: bytes, trials: int = 20) -> GateResult:
    """Report a RATE, never a boolean.

    A genuine bug in a nine-line program was measured faulting in 187 of 200 identical
    native runs. A single replay would have reported 'does not reproduce' about 7% of the
    time. So the gate records the fraction and lets the reader weigh it.
    """
    if not art.replay_bin:
        return not_run("D6", "behaviour is deterministic across identical runs",
                       "the standalone replay binary was not built")

    faults = 0
    codes: dict[int, int] = {}
    for _ in range(trials):
        rc, faulted = _run_once(art.replay_bin, probe)
        codes[rc] = codes.get(rc, 0) + 1
        faults += int(faulted)

    v: list[Violation] = []
    if 0 < faults < trials:
        v.append(Violation("D6.FLAKY", WARN,
                           f"the same input faulted in {faults} of {trials} runs. Report the "
                           f"rate, never a boolean: a one-shot replay of a bug like this "
                           f"lies a measurable fraction of the time.",
                           fix="record the rate on every finding this harness produces"))
    if len(codes) > 1:
        v.append(Violation("D6.MULTI_OUTCOME", INFO,
                           f"identical input produced {len(codes)} distinct exit codes "
                           f"{dict(sorted(codes.items()))}: allocator or layout variance"))

    return decide("D6", "behaviour is deterministic across identical runs", v,
                  trials=trials, fault_rate=f"{faults}/{trials}",
                  exit_codes=dict(sorted(codes.items())))


# ── D7 knobs ──────────────────────────────────────────────────────────────────

def d7_knobs(ir: HarnessIR) -> GateResult:
    """Record every knob, and COMPUTE what it makes unreachable.

    This is the gate that turns 'we found nothing' into 'we could not have found X'. No
    published harness generator emits this, and for an assurance deliverable it is the most
    valuable line on the page.
    """
    k = ir.knobs
    excluded: list[str] = []
    v: list[Violation] = []

    if k.max_len:
        excluded.append(f"any input larger than {k.max_len} bytes cannot be generated")
        if k.max_len <= 4096:
            v.append(Violation(
                "D7.DEFAULT_MAX_LEN", WARN,
                f"max_len is {k.max_len}, at or below libFuzzer's silent default. A defect "
                f"needing a larger input is not hard to find here, it is IMPOSSIBLE TO "
                f"EXPRESS, and no amount of runtime changes that.",
                fix="raise max_len, or state this exclusion on every negative result"))

    fm = ir.format_model
    if fm and fm.max_nesting_expressible:
        excluded.append(f"structures nested deeper than {fm.max_nesting_expressible} levels "
                        f"cannot be constructed under this max_len")
    if fm and fm.requires_checksum:
        excluded.append("inputs behind a checksum are unreachable by mutation alone; "
                        "comparison feedback cannot invert a hash, so seeds are decisive")
    if fm and fm.requires_compression:
        excluded.append("inputs behind compression are unreachable by mutation alone")

    if k.rss_limit_mb:
        excluded.append(f"allocations beyond {k.rss_limit_mb} MB are reported as the "
                        f"campaign's resource policy, not as target defects")
    if k.timeout_s:
        excluded.append(f"defects requiring more than {k.timeout_s}s of work per input "
                        f"are cut short and surface as timeouts")
    if not k.detect_leaks:
        excluded.append("leaks are not detected: LeakSanitizer is off")
    if "memory" not in k.sanitizers:
        excluded.append("uninitialised-memory reads are not detected: MemorySanitizer is off")
    if "undefined" not in k.sanitizers:
        excluded.append("integer truncation and other undefined behaviour is not detected "
                        "at the arithmetic; only its downstream memory error is")
    if len(ir.sequence) <= 2 and not any(
            (a := ir.apis.get(o.api)) and a.role == "reset" for o in ir.sequence):
        excluded.append("temporal defects needing a sequence (use-after-free, double free, "
                        "state-machine violations) are outside this harness's input language")

    return decide("D7", "knobs recorded, and what they exclude computed", v,
                  knobs=k.to_json(), unreachable=excluded)


# ── D4 sink reachability ──────────────────────────────────────────────────────

def d4_sink_reachability(ir: HarnessIR) -> GateResult:
    """What fraction of the target's memory-safety sink surface can this harness reach?

    'We harnessed it' meaning 3 of 47 sinks is a different claim from 'we harnessed it', and
    only one of them is checkable. This gate also feeds D2: mutation sites are restricted to
    reachable functions, so a surviving mutant means a gap in the harness rather than a
    mutation nobody could have reached.
    """
    if not ir.target.sources:
        return not_run("D4", "sink reachability: fraction of the sink surface reached",
                       "target.sources is empty, so there is no code to map")
    cmap = build_map(list(ir.target.sources) + list(ir.target.public_headers))
    if not cmap.functions:
        return not_run("D4", "sink reachability: fraction of the sink surface reached",
                       f"no function bodies recovered from {ir.target.sources}")

    entries = sorted({op.api for op in ir.sequence})
    surface = cmap.sink_surface(entries)
    surface["entry_points"] = entries

    v: list[Violation] = []
    unknown = [e for e in entries if e not in cmap.functions]
    if unknown:
        v.append(Violation("D4.ENTRY_NOT_FOUND", INFO,
                           f"entry points {unknown} were not found in the mapped sources; "
                           f"they may live in a translation unit that is linked but not "
                           f"listed in target.sources",
                           principle="P4"))
    frac = surface["fraction"]
    if surface["sinks_total"] and frac < 0.25:
        v.append(Violation(
            "D4.NARROW_SURFACE", WARN,
            f"this harness reaches {surface['sinks_reachable']} of "
            f"{surface['sinks_total']} sinks ({frac:.0%}). That is a narrow slice of the "
            f"target, and a clean campaign says nothing about the other {1 - frac:.0%}.",
            principle="P4",
            fix="add harnesses for the unreached entry points; the suite covers the target, "
                "one harness does not"))
    return decide("D4", "sink reachability: fraction of the sink surface reached", v,
                  **surface)


# ── D2 positive control ───────────────────────────────────────────────────────

def decide_positive_control(killed: int, survived: int, baseline: int,
                            corpus_size: int) -> list[Violation]:
    """Pure decision core, so the verdict is testable with no compiler and no target.

    Zero kills is blocking, not a warning. A harness that notices nothing when defects are
    placed directly in its path has not been shown to find anything, and a clean campaign
    against it is uninterpretable rather than reassuring.
    """
    tested = killed + survived
    v: list[Violation] = []
    if tested and not killed:
        v.append(Violation(
            "D2.NO_KILL", BLOCK,
            f"the harness detected 0 of {tested} defects planted in code it reaches. "
            f"Nothing establishes that this harness can find anything, and a clean campaign "
            f"against it would be uninterpretable.",
            principle="P4",
            fix="check that input actually reaches the mutated function (gate D4), that the "
                "sanitizer is enabled and effective, and that the harness reads the results "
                "it computes"))
    elif tested and killed < tested / 2:
        v.append(Violation(
            "D2.LOW_KILL", WARN,
            f"the harness detected {killed} of {tested} planted defects. The survivors are "
            f"code it reaches but does not exercise hard enough to disturb.",
            principle="P4"))
    if baseline:
        v.append(Violation(
            "D2.BASELINE_FAULTS", WARN,
            f"{baseline} of {corpus_size} corpus inputs fault on the UNMUTATED build. Those "
            f"inputs were excluded from every kill, but their existence usually means the "
            f"harness has a defect of its own (see D3).",
            principle="P1"))
    return v


def d2_positive_control(ir: HarnessIR, em: Emitted, art: BuildArtifacts,
                        corpus: list[bytes], *, reachable: Optional[set] = None,
                        limit: int = 6, cap: int = 24,
                        workdir: Optional[Path] = None) -> GateResult:
    """Plant defects in the target and require the harness to notice.

    Every other gate assumes the harness can find something. This is the one that checks.
    Mutation testing applied to harness adequacy: a defect is placed in code the harness
    reaches, the identical harness is rebuilt against the mutant, and the mutant counts as
    killed only when it faults on an input the UNMUTATED build handles cleanly.

    That second half is not optional. Without the differential, a harness that crashes on
    everything scores a perfect kill rate, which is exactly the failure mode the gate exists
    to catch.
    """
    title = "positive control: the harness finds a planted defect"
    if not art.replay_bin:
        return not_run("D2", title, "the standalone replay binary was not built")
    if not corpus:
        return not_run("D2", title, "no corpus to drive the mutants with")

    mkey = hashlib.sha256("\x00".join(
        sorted(ir.target.sources) + sorted(reachable or []) + [str(limit)]).encode()
    ).hexdigest()
    mutants = _MUTANT_CACHE.get(mkey)
    if mutants is None:
        mutants = generate_mutants(list(ir.target.sources), reachable=reachable,
                                   limit=limit)
        _MUTANT_CACHE[mkey] = mutants
    if not mutants:
        return not_run("D2", title,
                       "no mutation site found in reachable code. Either the target sources "
                       "are unavailable, or nothing the harness reaches contains an "
                       "allocation, copy, loop bound or null guard to perturb.")

    # Cost control. D2 is by far the most expensive gate: one build and up to |corpus| process
    # spawns PER MUTANT. Two bounds keep it usable without weakening the verdict:
    #   * the drive set is capped, because a mutant a large corpus cannot kill is very rarely
    #     killed by a larger one, and the cap is reported so the reader can weigh it;
    #   * the inner loop stops at the FIRST killing input. Killed is killed, and counting how
    #     many more inputs also kill it buys nothing.
    drive = corpus[:cap] if cap and len(corpus) > cap else corpus
    truncated = len(corpus) - len(drive)

    # baseline: which inputs already fault without any mutation?
    baseline = {i for i, d in enumerate(drive) if _run_once(art.replay_bin, d)[1]}

    killed, survived, unbuildable = [], [], []
    for n, mu in enumerate(mutants):
        sub = Path(workdir or art.workdir) / f"mut-{n}"
        mart = build(ir, em, sub, source_override={mu.file: mu.source})
        if not mart.replay_bin:
            unbuildable.append({"id": mu.id, "operator": mu.operator,
                                "note": "mutant did not compile; excluded from the "
                                        "denominator rather than counted as survived"})
            continue
        first = None
        for i, d in enumerate(drive):
            if i in baseline:
                continue                     # already faults unmutated: proves nothing
            if _run_once(mart.replay_bin, d)[1]:
                first = i
                break
        rec = {"id": mu.id, "operator": mu.operator, "function": mu.function,
               "line": mu.line, "change": f"{mu.original} -> {mu.mutated}",
               "expect": mu.expect,
               "killed_by_input": first,
               "killed_by_bytes": drive[first][:24].hex() if first is not None else None}
        (killed if first is not None else survived).append(rec)

    tested = len(killed) + len(survived)
    if tested == 0:
        return not_run("D2", title,
                       f"all {len(unbuildable)} mutants failed to compile; the operators "
                       f"produced no valid C for this target")
    v = decide_positive_control(len(killed), len(survived), len(baseline), len(drive))

    return decide("D2", title, v,
                  mutants_tested=tested, killed=len(killed), survived=len(survived),
                  unbuildable=len(unbuildable),
                  kill_rate=f"{len(killed)}/{tested}",
                  killed_detail=killed, survived_detail=survived,
                  baseline_faulting_inputs=len(baseline),
                  drive_corpus=len(drive), corpus_truncated=truncated,
                  method="mutation testing with a mandatory differential: a mutant counts "
                         "as killed only when it faults on an input the unmutated build "
                         "handles cleanly")


# ── D9 misuse provenance ──────────────────────────────────────────────────────

_ALLOC_SECTION = re.compile(r"allocated by thread.*?(?=\n\S|\Z)", re.S | re.I)
_FRAME_FILE = re.compile(r"\bin\s+\S+\s+([^\s:]+\.(?:c|cc|cpp|h|hpp)):(\d+)")


# "Address 0x... is located in stack of thread T0 at offset 40 in frame
#     #0 0x... in body tiny.c:14"  — the frame that OWNS the buffer, not the one that wrote.
_STACK_FRAME = re.compile(
    r"located in stack of thread.*?in frame\s*(?:#\d+\s+\S+\s+in\s+\S+\s+)?"
    r"(?P<file>[\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp)):(?P<line>\d+)", re.S)
# "0x... is located 0 bytes to the right of global variable 'buf' defined in 'tiny.c:9'"
_GLOBAL_DEF = re.compile(
    r"global variable.*?defined in '(?P<file>[\w./+-]+):(?P<line>\d+)'", re.S)


def attribute_allocation(report: str, harness_files: list[str],
                         target_files: list[str]) -> tuple:
    """Pure function: whose buffer overflowed, ours or the library's?

    An overflow of a buffer the HARNESS allocated is a harness defect and must not be
    reported. An overflow of a buffer the LIBRARY manages is the strong signal. Returns
    (verdict, evidence) where verdict is 'harness' | 'library' | 'unknown'.
    """
    hset = {Path(p).name for p in harness_files}
    tset = {Path(p).name for p in target_files}
    text = report or ""
    sec = _ALLOC_SECTION.search(text)
    if not sec:
        # A STACK or GLOBAL buffer has no allocation stack — there was no allocation. This
        # gate abstained on every one of them, and stack-buffer-overflow is among the most
        # common findings there is. It went unnoticed because D9 had never run: no caller
        # had ever passed it a report.
        #
        # ASan names the owner directly: "in frame #N <fn> <file>:<line>" for a stack
        # buffer, "<file>:<line>" beside the global's definition. That is the same question
        # this function answers for the heap, asked of a different memory class.
        m = _STACK_FRAME.search(text) or _GLOBAL_DEF.search(text)
        if m:
            base = Path(m.group("file")).name
            where = f"{base}:{m.group('line')}"
            kind = "stack" if "stack" in m.group(0).lower() else "global"
            if base in hset:
                return "harness", {"frame": where, "memory": kind,
                                   "reading": f"the overflowed {kind} buffer belongs to the "
                                              f"harness; this crash is ours, not the "
                                              f"target's"}
            if base in tset:
                return "library", {"frame": where, "memory": kind,
                                   "reading": f"the overflowed {kind} buffer belongs to the "
                                              f"library; a strong real-bug signal"}
            return "unknown", {"frame": where, "memory": kind,
                               "reason": "the owning frame matches neither the harness nor "
                                         "the listed target sources"}
        return "unknown", {"reason": "no allocation stack, and no stack or global frame "
                                     "naming an owner"}
    frames = _FRAME_FILE.findall(sec.group(0))
    if not frames:
        return "unknown", {"reason": "allocation stack carries no source locations"}
    for fname, line in frames:
        base = Path(fname).name
        if base in hset:
            return "harness", {"frame": f"{base}:{line}",
                               "reading": "the overflowed buffer was allocated by the "
                                          "harness; this crash is ours, not the target's"}
        if base in tset:
            return "library", {"frame": f"{base}:{line}",
                               "reading": "the overflowed buffer is managed by the library; "
                                          "a strong real-bug signal"}
    return "unknown", {"frames": frames[:4],
                       "reason": "allocation frames match neither the harness nor the "
                                 "listed target sources"}


def d9_misuse(ir: HarnessIR, art: BuildArtifacts,
              report: Optional[str] = None) -> GateResult:
    title = "misuse provenance: harness-allocated or library-allocated"
    if not report:
        return not_run("D9", title,
                       "no sanitizer report to attribute. This gate runs when a campaign "
                       "produces a crash, not during certification of a clean harness.")
    verdict, ev = attribute_allocation(
        report, [str(art.harness_c), "driver.c"], list(ir.target.sources))
    v: list[Violation] = []
    if verdict == "harness":
        v.append(Violation("D9.HARNESS_ALLOCATED", BLOCK,
                           "the overflowed buffer was allocated inside the harness. This "
                           "crash is the harness's, and reporting it would spend the "
                           "credibility you need for a real one.",
                           principle="P1", **{}))
    return decide("D9", title, v, provenance=verdict, **ev)


# ── D11 differential consistency ──────────────────────────────────────────────

def d11_differential(plans: list, arts: list, corpus: list[bytes]) -> GateResult:
    """Two plans for the same entry point must agree on valid inputs.

    Producers compete. When two of them disagree about whether an input faults, one of them
    is wrong, and the disagreement is a defect in a harness rather than a finding about the
    target.
    """
    title = "differential consistency across producers"
    built = [(p, a) for p, a in zip(plans, arts) if a and a.replay_bin]
    if len(built) < 2:
        return not_run("D11", title,
                       f"only {len(built)} buildable plan(s) for this entry point; "
                       f"consistency needs at least two producers to have emitted one")
    if not corpus:
        return not_run("D11", title, "no shared corpus to compare on")

    vectors = {}
    for p, a in built:
        vectors[p.name] = tuple(_run_once(a.replay_bin, d)[1] for d in corpus)

    names = list(vectors)
    disagreements = []
    for i in range(len(corpus)):
        outcomes = {n: vectors[n][i] for n in names}
        if len(set(outcomes.values())) > 1:
            disagreements.append({"input_index": i, "len": len(corpus[i]),
                                  "head": corpus[i][:24].hex(), "outcomes": outcomes})

    v: list[Violation] = []
    if disagreements:
        v.append(Violation(
            "D11.DISAGREE", WARN,
            f"{len(disagreements)} of {len(corpus)} inputs produce different outcomes across "
            f"{len(names)} plans for the same entry point. At least one plan is wrong about "
            f"the target, and the difference is a harness defect rather than a finding.",
            principle="P2",
            fix="diff the plans: the usual cause is one honouring a contract clause the "
                "other does not (S2 names it)"))
    return decide("D11", title, v, plans=names, corpus_size=len(corpus),
                  disagreements=disagreements[:10],
                  agreement=f"{len(corpus) - len(disagreements)}/{len(corpus)}")


# ── driver ────────────────────────────────────────────────────────────────────

def run_dynamic_gates(ir: HarnessIR, em: Emitted, art: BuildArtifacts, *,
                      valid_corpus: Optional[list[bytes]] = None,
                      probe: Optional[bytes] = None,
                      drive_corpus: Optional[list[bytes]] = None,
                      sibling_plans: Optional[list] = None,
                      sibling_arts: Optional[list] = None,
                      report: Optional[str] = None,
                      positive_control: bool = True,
                      campaign: bool = True,
                      campaign_seconds: int = 8) -> list[GateResult]:
    corpus = valid_corpus or []
    p = probe if probe is not None else (corpus[0] if corpus else b"\x00")
    drive = drive_corpus or corpus

    d4 = d4_sink_reachability(ir)
    # Recomputed, NOT read from D4's evidence. That field is capped at 200 names for the
    # certificate, and feeding a truncated set to D2 plants every mutant in the 200
    # alphabetically-first reachable functions — obscure ones no corpus reaches. D2 then
    # reported 0/6 kills and looked like a weak harness rather than a starved gate.
    #
    # A display cap must never become a functional one. The consumer needs the whole set.
    reachable = None
    if d4.ok and ir.target.sources:
        cmap = build_map(list(ir.target.sources) + list(ir.target.public_headers))
        reachable = cmap.reachable_from(sorted({op.api for op in ir.sequence}))

    d2 = (d2_positive_control(ir, em, art, drive, reachable=reachable)
          if positive_control
          else not_run("D2", "positive control: the harness finds a planted defect",
                       "disabled for this run (--no-positive-control)"))

    d11 = (d11_differential([ir, *sibling_plans], [art, *sibling_arts], drive)
           if sibling_plans and sibling_arts
           else d11_differential([ir], [art], drive))

    d8 = (d8_campaign(ir, em, seconds=campaign_seconds) if campaign
          else not_run("D8", "campaign productivity: edges the fuzzer can actually see",
                       "disabled for this run (--no-campaign)"))

    # A caller-supplied report wins; otherwise use whatever the campaign just produced.
    # Leaving these unconnected meant the gate that decides whether a crash belongs to the
    # harness or the library never saw a crash.
    san = report or str(d8.evidence.get("sanitizer_report") or "")

    return [d1_liveness(ir, em, art), d2, d3_valid_input(ir, art, corpus), d4,
            d5_rate(ir, art, p), d6_determinism(art, p), d7_knobs(ir), d8,
            d9_misuse(ir, art, san), d11]


# ── D8: will a campaign against this actually find anything? ─────────────────

def d8_campaign(ir: HarnessIR, em: Emitted, workdir: Optional[Path] = None,
                seconds: int = 8) -> GateResult:
    """Build the real fuzzer and run it briefly. Report the edges it can actually see.

    Every other gate asks whether the HARNESS is correct. This one asks whether the
    CAMPAIGN can work, and they are not the same question. A perfectly correct harness
    linked against a prebuilt system library produces this:

        #11775224  DONE  cov: 2  ft: 3  corp: 1/1b  exec/s: 255983

    Eleven million executions, and coverage never moved off 2 — because `-fsanitize=fuzzer`
    instruments `harness.c` and nothing else. libFuzzer sees the harness's own two edges and
    has no signal to steer by, so it is doing random testing at high speed. ASan is equally
    blind: it cannot see allocations made inside the uninstrumented library.

    That is invisible to every static gate and to D1 through D7, all of which passed. It is
    the difference between a harness that is correct and a campaign that is worth running,
    and it belongs on the certificate.
    """
    title = "campaign productivity: edges the fuzzer can actually see"
    instrumented = bool(ir.target.sources)

    cc, why = tc.libfuzzer_probe()
    if cc is None:
        return not_run("D8", title,
                       f"no campaign could be built: {why}. Certification is unaffected; "
                       f"this gate reports what a RUN would do.")

    wd = Path(workdir or tempfile.mkdtemp(prefix="hforge-d8-"))
    wd.mkdir(parents=True, exist_ok=True)
    hc = wd / "harness.c"
    hc.write_text(em.source)
    binary = wd / ("campaign" + tc.host().exe_suffix)

    cmd = [cc, "-g", "-O1", "-fno-omit-frame-pointer"]
    cmd += [f"-I{x}" for x in ir.target.include_dirs] + list(ir.target.cflags)
    common_c = [cc, "-g", "-O1", "-fno-omit-frame-pointer"]
    common_c += [f"-I{x}" for x in ir.target.include_dirs] + list(ir.target.cflags)
    arch = _target_archive(ir, cc, common_c, "fuzzer,address")
    cmd += ["-fsanitize=fuzzer,address", str(hc),
            *([arch] if arch else ir.target.sources),
            *ir.target.link_libs, "-o", str(binary)]
    # `errors="replace"`: libFuzzer echoes the raw bytes of interesting inputs, which are
    # by construction not valid UTF-8. Decoding strictly crashed the gate on the one output
    # it exists to read.
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        return not_run("D8", title,
                       f"the campaign binary did not build: {r.stderr[-300:]}")

    corp = wd / "corpus"
    corp.mkdir(exist_ok=True)
    for i, b in enumerate(corpus.valid_only(ir).inputs[:8] or [b"{}"]):
        (corp / f"seed{i}").write_bytes(b)

    # Real example inputs from the target's own test data, if any were mined onto the plan.
    # Two synthetic bytes make the fuzzer spend its first minutes discovering that the input
    # is a PNG at all; a real PNG starts it inside the format.
    n_seeds = 0
    if ir.target.seed_dirs:
        mined = seeds.mine(ir.target.seed_dirs, max_bytes=ir.knobs.max_len or 65536)
        n_seeds = seeds.write(mined, corp)

    # A dictionary built from the target's own string literals. Its effect shows up in the
    # edge count like everything else here — if it does not move coverage, the number says so.
    dict_args: list = []
    if ir.target.sources:
        dpath = wd / "target.dict"
        if dictionary.write(ir.target.sources, dpath):
            dict_args = [f"-dict={dpath}"]

    try:
        run = subprocess.run(
            [str(binary), str(corp), *dict_args, f"-max_len={ir.knobs.max_len}",
             f"-max_total_time={seconds}", "-print_final_stats=1"],
            capture_output=True, text=True, errors="replace",
            env=_asan_env(), timeout=seconds + 60)
    except subprocess.TimeoutExpired:
        return not_run("D8", title, "the campaign did not terminate within its time budget")

    text = run.stdout + run.stderr
    covs = [int(m) for m in re.findall(r"cov:\s*(\d+)", text)]
    execs = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
    rate = re.search(r"stat::average_exec_per_sec:\s*(\d+)", text)
    edges = max(covs) if covs else 0
    grew = bool(covs) and covs[-1] > covs[0]

    v: list = []
    if not instrumented:
        v.append(Violation(
            "D8.NO_INSTRUMENTATION", WARN,
            f"the target is a prebuilt library, so only the harness is instrumented. "
            f"libFuzzer saw {edges} edge(s) — its own — and has NO coverage feedback to "
            f"steer with, and ASan cannot see allocations inside the library. This campaign "
            f"is random testing at high speed, not guided fuzzing.",
            principle="P4",
            fix="rebuild the target from source with the same -fsanitize flags and pass its "
                "sources on the plan (target.sources), so coverage and ASan reach inside it"))
    elif edges <= 2:
        v.append(Violation(
            "D8.NO_COVERAGE", WARN,
            f"the campaign reached {edges} edge(s) despite an instrumented target. The "
            f"harness is not getting into the target's code at all.",
            principle="P4",
            fix="check that the entry point needs no setup call the plan omits"))
    elif not grew:
        v.append(Violation(
            "D8.COVERAGE_PLATEAU", WARN,
            f"coverage never grew beyond {edges} edge(s) during the run. Usually a required "
            f"initialisation call is missing: libmagic's magic_buffer reaches almost nothing "
            f"until magic_load has loaded the magic database.",
            principle="P4",
            fix="add the setup call the API requires between create and consume"))

    # The campaign is the only thing in this engine that produces a sanitizer report, and
    # D9 — whose entire job is attributing one — was called with report=None by every caller
    # that has ever existed. It has reported NOT_RUN on every certificate ever written.
    san = ""
    m = re.search(r"==\d+==\s*ERROR:\s*\w*Sanitizer.*", text, re.S)
    if m:
        san = m.group(0)[:8000]

    return decide("D8", title, v,
                  edges=edges, coverage_grew=grew, dictionary=bool(dict_args),
                  mined_seeds=n_seeds,
                  target_instrumented=instrumented,
                  executions=int(execs.group(1)) if execs else 0,
                  exec_per_sec=int(rate.group(1)) if rate else 0,
                  crashed=bool(san), sanitizer_report=san,
                  seconds=seconds)
