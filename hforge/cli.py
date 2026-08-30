"""Harness Forge command line.

    python -m hforge <command> [options]

Design notes, because they are why this file looks the way it does:

  * every command runs with no API key and no network. Phase 1 is entirely deterministic;
    a model only ever proposes a plan, and proposing is Phase 3.
  * every command prints what it could NOT do. A gate that did not run is displayed as
    NOT RUN with its reason, never as a pass, because an absent check must not look like a
    satisfied one.
  * nothing talks to a server. Output is files you can read with cat.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
from collections import Counter
from dataclasses import replace
import sys
from pathlib import Path

from . import corpus, devices as dev, platform as plat, toolchain as tc
from .analysis import dictionary, seeds
from .certificate import build_certificate, render_text
from .emit import emit                      # routes on target.language
from .emit.c_libfuzzer import EmitError
from .gates.dynamic_gates import (build, d4_sink_reachability, d11_differential,
                                  find_cc,
                                  run_dynamic_gates)
from .gates.result import (BLOCK, FAIL, NOT_RUN, WARN, Violation, failed as gate_failed,
                           not_run as gate_not_run)
from .lift.c_harness import LiftError, lift as lift_c_harness
from .findings import gates as findings_gates, pipeline as findings_pipeline, report as findings_report
from .targets import ossfuzz
from .gates.static_gates import run_static_gates
from .ir import HarnessIR, Knobs, Target
from .producers import header_graph, rank as ranking


# Every dynamic gate, with the title the certificate prints. Kept here so that a stage
# which could not run still yields one NOT_RUN result per gate instead of yielding nothing.
_DYNAMIC_GATES = (
    ("D1", "liveness: the target call survived the optimiser"),
    ("D2", "positive control: the harness finds a planted bug"),
    ("D3", "valid input must not crash"),
    ("D4", "sink reachability"),
    ("D5", "execution rate is plausible"),
    ("D6", "determinism, reported as a rate"),
    ("D7", "knobs recorded, and what they exclude computed"),
    ("D8", "campaign productivity: edges the fuzzer can actually see"),
    ("D9", "misuse provenance"),
    ("D11", "differential consistency across producers"),
)


def _all_dynamic_not_run(reason: str) -> list:
    """The dynamic gates as NOT RUN, with a reason.

    Without this, a refused emit or a failed build produced NO dynamic gate results at all —
    and a certificate with six passing static gates and nothing else printed **CERTIFIED**.
    The engine certified a harness whose C had never been generated. `NOT_RUN is a distinct
    verdict` has to hold for a whole stage, not only for a gate that chose to report it.
    """
    return [gate_not_run(g, title, reason) for g, title in _DYNAMIC_GATES]


def _emit_refused(err) -> list:
    """A refused emit, expressed as results rather than as a printed line.

    This closes the same hole in two places. A plan whose C could not be generated used to
    contribute NO gate results at all: `certify` then printed CERTIFIED off six passing
    static gates, and `propose` ranked the broken plan FIRST, because it had zero gates
    that did not run while every plan that actually built and ran had several. Failing was
    literally scoring better than working.

    So emission is reported as what it is: a blocking defect in the plan, plus every dynamic
    gate marked NOT RUN with the reason.
    """
    return [gate_failed("EMIT", "the plan can be turned into a harness", [Violation(
        code="EMIT.REFUSED", severity=BLOCK, message=str(err),
        fix="fix the plan, or express the unsupported construct as a raw block and accept "
            "it as an uncertified region")])] + _all_dynamic_not_run(f"emit refused: {err}")


def _load(path: str) -> HarnessIR:
    return HarnessIR.loads(Path(path).read_text())


def _load_corpus(d: str | None) -> list[bytes]:
    if not d:
        return []
    p = Path(d)
    if not p.exists():
        return []
    return [f.read_bytes() for f in sorted(p.iterdir()) if f.is_file()]


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_platforms(args) -> int:
    rows = sorted(plat.PLATFORMS.values(), key=lambda p: (p.os, p.arch, p.variant))
    print(f"{'PLATFORM':<28} {'SAN':<26} {'ALLOCATOR':<22} {'CEILING':<20} EMIT")
    print("-" * 110)
    for p in rows:
        san = ",".join(p.sanitizers) or "-"
        print(f"{p.id:<28} {san[:25]:<26} {p.allocator[:21]:<22} "
              f"{p.trust_ceiling:<20} {'yes' if p.emit_ready else '-'}")
    print()
    print("CEILING is the highest ladder rung a finding observed ONLY on that platform may")
    print("reach. EMIT marks what the Phase-1 C backend targets today; the rest are modelled")
    print("so a certificate can say which platforms it is NOT claiming.")
    print()
    print("The mobile principle: fuzz where instrumentation is cheap, prove reachability")
    print("where the target actually runs. iOS device runs are a reachability oracle, never")
    print("the discovery mechanism.")
    return 0


def cmd_validate(args) -> int:
    ir = _load(args.ir)
    results = run_static_gates(ir)
    bad = 0
    for g in results:
        v = {"pass": "PASS", "fail": "FAIL", "not-run": " -  "}[g.verdict]
        print(f"[{v}] {g.gate}  {g.title}")
        for viol in g.violations:
            print(f"        [{viol.severity}] {viol.code}: {viol.message}")
            if viol.fix:
                print(f"                fix: {viol.fix}")
            if viol.severity == BLOCK:
                bad += 1
    print()
    if bad:
        print(f"{bad} blocking violation(s). This plan must not be emitted as-is.")
        print("Note that every one was found WITHOUT compiling anything.")
    else:
        print("static gates pass. The plan is internally consistent and contract-compliant.")
    return 1 if bad else 0


def cmd_emit(args) -> int:
    ir = _load(args.ir)
    try:
        em = emit(ir)
    except EmitError as e:
        print(f"emit refused: {e}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    _h, _d = _artifact_names(ir)
    (out / _h).write_text(em.source)
    (out / _d).write_text(em.driver)
    instrumented = bool(ir.target.sources)
    (out / "build.sh").write_text(
        "#!/bin/sh\n"
        "# Generated by Harness Forge. Run it from this directory.\n"
        "set -eu\n"
        'CC="${CC:-clang}"\n'
        "\n"
        + ("" if instrumented else
           "# WARNING: this harness links a PREBUILT library. -fsanitize=fuzzer instruments\n"
           "# only harness.c, so libFuzzer sees no edges inside the target: the campaign has\n"
           "# NO coverage feedback and is random testing, not guided fuzzing. ASan will also\n"
           "# not see allocations made inside the library. Rebuild the target from source\n"
           "# with the same flags to fix both.\n\n")
        + f"# fuzzer\n{' '.join(em.build_command)}\n\n"
        f"# standalone replay (no fuzzer runtime)\n{' '.join(em.driver_build_command)}\n")
    (out / "build.sh").chmod(0o755)
    print(f"wrote {out/'harness.c'}")
    print(f"wrote {out/'driver.c'}   (replay: the campaign binary ignores stdin)")
    print(f"wrote {out/'build.sh'}")
    return 0


def cmd_certify(args) -> int:
    ir = _load(args.ir)
    gates = list(run_static_gates(ir))

    static_blocked = any(v.severity == BLOCK for g in gates for v in g.violations)
    em = None
    if static_blocked and not args.force:
        print("static gates blocked; not building. Re-run with --force to emit anyway.\n")
    else:
        try:
            em = emit(ir)
        except EmitError as e:
            print(f"emit refused: {e}\n", file=sys.stderr)
            gates += _emit_refused(e)

    if em is None and not static_blocked:
        pass
    if static_blocked and not args.force:
        gates += _all_dynamic_not_run(
            "static gates blocked, so nothing was built or run")

    if em is not None:
        if find_cc() is None:
            print("no C compiler found; dynamic gates will report NOT RUN.\n")
            art = build(ir, em, Path(args.work) if args.work else None)
        else:
            art = build(ir, em, Path(args.work) if args.work else None)
            if not art.ok:
                print("build failed; dynamic gates that need a binary will report NOT RUN.")
                if args.verbose:
                    print(art.log)
        valid = _load_corpus(args.valid_corpus) or corpus.valid_only(ir).inputs
        drive = corpus.generate(ir, seed=args.seed).inputs
        gates += run_dynamic_gates(ir, em, art, valid_corpus=valid, drive_corpus=drive,
                                   positive_control=not args.no_positive_control,
                                   campaign=not args.no_campaign,
                                   campaign_seconds=args.campaign_seconds)

    cert = build_certificate(ir, gates, em)
    print(render_text(cert))

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(cert.dumps())
        print(f"\ncertificate written to {out}")

    return {"certified": 0, "provisional": 0, "rejected": 1}[cert.verdict]


def _artifact_names(ir):
    """What the emitted files are called. A Java harness written to `harness.c` is a file
    that cannot be compiled by the command in its own build.sh."""
    if (ir.target.language or "").lower() in ("java", "jvm", "kotlin"):
        return "Harness.java", "Replay.java"
    return "harness.c", "driver.c"


def _java_plans(args):
    """A Java target and its plans, from a classpath instead of a header.

    Dispatching here rather than in a separate command keeps one flow for every language:
    the same static gates, the same ranking, the same certificate. Only the producer and the
    emitter differ, which is the whole point of the router.
    """
    from .producers import java_api
    cp = args.classpath
    tgt = Target(name=args.name or Path(cp.rstrip("/")).stem,
                 public_headers=[], include_dirs=[],
                 sources=args.source or [], link_libs=[cp] + (args.link or []),
                 seed_dirs=args.seed_dir or [])
    tgt.language = "java"
    plats = args.platform or ["jvm-openjdk-x86_64"]
    plans = java_api.propose(cp, tgt, platforms=plats,
                             knobs=Knobs(max_len=args.max_len),
                             only=args.java_class or None)
    return tgt, plans


def cmd_propose(args) -> int:
    """Synthesise candidate plans from a header or a classpath, gate them, rank by evidence."""
    if args.classpath:
        tgt, plans = _java_plans(args)
    else:
        headers = [args.header] + (args.also_header or [])
        tgt = Target(name=args.name or Path(args.header).stem,
                     public_headers=[Path(h).name for h in headers],
                     include_dirs=sorted({str(Path(h).parent) for h in headers}
                                         | set(args.include or [])),
                     sources=args.source or [],
                     link_libs=args.link or [],
                     cflags=args.cflag or [],
                     seed_dirs=args.seed_dir or [])
        plats = args.platform or ["linux-x86_64-glibc"]
        # A FLAG THAT IS SILENTLY IGNORED IS WORSE THAN ONE THAT REFUSES. The C backend
        # emits a host build and consults the platform only to name it in a comment, so
        # `--platform ios-arm64-simulator` produced a build.sh byte-identical to the
        # default -- no -isysroot, no -target. Say so rather than let the caller believe a
        # cross-build happened.
        _ready = {q.id for q in plat.emit_ready()}
        _not_ready = [x for x in plats if x not in _ready]
        if _not_ready:
            print(f"note: {', '.join(_not_ready)} is modelled but NOT emit-ready. The C "
                  f"backend will emit a HOST build; the platform is recorded on the plan "
                  f"and is not applied to the compiler.", file=sys.stderr)
        plans = header_graph.propose(headers, tgt, platforms=plats,
                                     knobs=Knobs(max_len=args.max_len))
    if not plans:
        print(f"no plan proposed from {args.classpath or args.header}.")
        print("Either no function consumes attacker-controllable input, or the header uses "
              "a form the parser skips rather than guesses at.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    scored = []
    for ir in plans:
        gates = list(run_static_gates(ir))
        # `or link_libs`: gating against an INSTALLED library is the normal case for real
        # software, and requiring sources here meant --dynamic silently did nothing and
        # every plan reported 0% kill as though it had been measured.
        if args.dynamic and find_cc() and (ir.target.sources or ir.target.link_libs):
            try:
                em = emit(ir)
                art = build(ir, em)
                gates += run_dynamic_gates(
                    ir, em, art, valid_corpus=corpus.valid_only(ir).inputs,
                    drive_corpus=corpus.generate(ir, seed=args.seed).inputs,
                    positive_control=not args.no_positive_control, campaign=False)
            except EmitError as e:
                print(f"  {ir.name}: emit refused: {e}")
                gates += _emit_refused(e)
        (out / f"{ir.name}.hir.json").write_text(ir.dumps())
        scored.append(ranking.score(ir.name, ir.producer, gates))

    print(f"{len(plans)} plan(s) proposed from {args.classpath or args.header}, "
          f"written to {out}/")
    print(ranking.render(ranking.rank(scored)))
    return 0 if any(s.shippable for s in scored) else 1


def cmd_batch(args) -> int:
    """Generate every plan for a target, gate them all, and ship only what measures well.

    This is the command that produces a fuzzing SUITE rather than a harness. The output
    directory holds one buildable folder per surviving plan plus a report ranking them by
    the depth a real campaign actually reached — because reach is a prerequisite for
    detection, and a harness that cannot get past a library's error path finds nothing no
    matter how correct it is.

    Static gates run on everything, which is cheap. The expensive gates — a real libFuzzer
    campaign per plan — run only on candidates that survived, and only on the top `--top` of
    them, with what was skipped stated rather than quietly dropped.
    """
    if args.classpath:
        tgt, plans = _java_plans(args)
    else:
        headers = [args.header] + (args.also_header or [])
        tgt = Target(name=args.name or Path(args.header).stem,
                     public_headers=[Path(h).name for h in headers],
                     include_dirs=sorted({str(Path(h).parent) for h in headers}
                                         | set(args.include or [])),
                     sources=args.source or [], link_libs=args.link or [],
                     cflags=args.cflag or [],
                     seed_dirs=args.seed_dir or [])
        plans = header_graph.propose(headers, tgt, platforms=args.platform
                                     or ["linux-x86_64-glibc"],
                                     knobs=Knobs(max_len=args.max_len))
    if not plans:
        print(f"no plan proposed from {args.header}.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"{len(plans)} plan(s) proposed. Static gates first (no compiler needed).")

    survivors, rejected = [], []
    for ir in plans:
        gates = list(run_static_gates(ir))
        if any(v.severity == BLOCK for g in gates for v in g.violations):
            rejected.append((ir, gates))
        else:
            survivors.append((ir, gates))
    print(f"  {len(survivors)} passed the static gates, {len(rejected)} blocked.")

    # Which plans get an expensive campaign is itself a decision, and taking the first N in
    # proposal order is alphabetical order wearing a budget. On sqlite that measured
    # `autovacuum_pages` and `blob_open` while `sqlite3_exec` was never built.
    #
    # D4 is static source analysis — it maps the sink surface reachable from each entry
    # point without compiling anything — so it can order 262 candidates in seconds and spend
    # the campaign budget on the ones that reach dangerous code.
    if survivors and args.source:
        # SCHEDULING, not ranking. This decides which plans get an expensive campaign, never
        # which plan wins — that is `rank.py`, and it reads gate evidence only.
        #
        # Two corrections, both from a sqlite run that measured twelve variants of ONE entry
        # point and shipped nothing:
        #
        #   1. Spread across DISTINCT entry points before spending a second slot on any of
        #      them. Ranks 1-10 were all `sqlite3_autovacuum_pages` at different max_len,
        #      so eleven-twelfths of the budget answered the same question.
        #   2. Prefer plans the fuzzer actually drives. Static sink reach alone put
        #      `autovacuum_pages` (a callback registration) above `sqlite3_exec`, and every
        #      one of the twelve then failed D3 by crashing on valid input.
        def _input_boundness(ir) -> tuple:
            """How much serialised input this plan actually feeds the target.

            NOT a fraction. A fraction rewards a one-argument call whose single argument is
            input and punishes the canonical shape — `sqlite3_exec(db, sql, NULL, NULL,
            NULL)` scores 0.2 against `sqlite3_errmsg(db)` at 1.0, which is exactly
            backwards. What matters is whether UNBOUNDED bytes reach the target at all, then
            how many arguments carry input.
            """
            cons = next((o for o in ir.sequence if o.id.startswith("o_consume")), None)
            if cons is None or not cons.args:
                return (0, 0, 0)
            ids = {a.ref for a in cons.args if a.source == "input"}
            remainder = any(sl.remainder for sl in ir.slices if sl.id in ids)
            n_input = sum(1 for a in cons.args if a.source == "input")
            paired = sum(1 for a in cons.args if a.source == "length_of")
            # a (ptr,len) pair is the strongest shape: the target is told how much there is
            return (int(remainder), n_input + paired, paired)

        def _incomplete(ir) -> int:
            """1 when the plan declares a resource that NO op ever creates.

            Such a plan hands the library NULL, passes every static gate, and is refused by
            D3 only after a full build and campaign. In a deep sqlite run 13 of 14 measured
            plans were this shape — sqlite3_blob has no recognised constructor, because
            sqlite3_blob_open returns int and writes through `sqlite3_blob **` — so the entire
            budget went to plans that could not work, while the good sqlite3_exec plan sat
            unmeasured at rank 700 and the run shipped nothing.

            This is scheduling, not ranking: rank.py still reads gate evidence only, and C10
            enforces that. It decides where to spend a campaign, not what the campaign means.
            """
            bound = {o.binds for o in ir.sequence if o.binds}
            return 1 if any(r.id not in bound for r in ir.resources) else 0

        scored_pre = []
        for ir, gates in survivors:
            g4 = d4_sink_reachability(ir)
            frac = float(g4.evidence.get("fraction", 0.0)) if g4.ok else 0.0
            entry = next((o.api for o in ir.sequence
                          if o.id.startswith("o_consume")), ir.name)
            scored_pre.append({"entry": entry, "drive": _input_boundness(ir),
                               "sink": frac, "item": (ir, gates), "name": ir.name,
                               "incomplete": _incomplete(ir)})

        # best variant of each entry point first, then the next best of each, and so on
        by_entry: dict = {}
        for r in scored_pre:
            by_entry.setdefault(r["entry"], []).append(r)
        for rs in by_entry.values():
            rs.sort(key=lambda r: (r["incomplete"], tuple(-x for x in r["drive"]),
                                   -r["sink"], r["name"]))
        order = sorted(by_entry.values(),
                       key=lambda rs: (rs[0]["incomplete"],
                                       tuple(-x for x in rs[0]["drive"]), -rs[0]["sink"],
                                       rs[0]["entry"]))
        n_incomplete = sum(1 for rs in by_entry.values() for r in rs if r["incomplete"])
        if n_incomplete:
            print(f"  {n_incomplete} plan(s) declare a resource nothing constructs; they are "
                  f"scheduled LAST. They pass the static gates and hand the library NULL, and "
                  f"D3 refuses them only after a full build.")
        survivors, rr = [], 0
        while any(len(rs) > rr for rs in order):
            for rs in order:
                if len(rs) > rr:
                    survivors.append(rs[rr]["item"])
            rr += 1
        print(f"  scheduled across {len(by_entry)} distinct entry point(s), best variant of "
              f"each first, preferring plans the fuzzer actually drives. This allocates the "
              f"campaign budget; it does not rank anything.")

    if not find_cc():
        print("no C compiler: nothing further can be measured on this host.")
        deep = []
    else:
        deep = survivors[:args.top]

        # The scheduler above spreads the budget across DISTINCT entry points, best variant
        # of each first. That is right for coverage and it makes D11 impossible: comparing
        # producers needs two plans for the SAME entry point, and with hundreds of entry
        # points the round-robin never reaches its second pass. The gate was not merely
        # unwired — the scheduling policy guaranteed it could never fire.
        #
        # So one pair is reserved explicitly. Two slots, taken from the best-scheduled entry
        # point that actually has a second variant.
        if len(deep) >= 2:
            chosen = {id(x) for x in deep}
            entries = [next((o.api for o in ir.sequence
                             if o.id.startswith("o_consume")), ir.name)
                       for ir, _ in deep]
            have_pair = len(entries) != len(set(entries))
            if not have_pair:
                for item in survivors[args.top:]:
                    e = next((o.api for o in item[0].sequence
                              if o.id.startswith("o_consume")), item[0].name)
                    if e in entries and id(item) not in chosen:
                        deep = deep[:-1] + [item]
                        print(f"  one campaign slot reserved for a second variant of "
                              f"{e}, so D11 can compare producers at all.")
                        break

        if len(survivors) > len(deep):
            print(f"  measuring the first {len(deep)} of {len(survivors)}; "
                  f"{len(survivors) - len(deep)} were NOT measured (raise --top). "
                  f"They are reported as unmeasured, not as passing.")
        print(f"  building and running a {args.campaign_seconds}s campaign for each...")

    def _measure(item):
        """Build one plan and run its gates. Pure per-plan work, so it parallelises."""
        ir, gates = item
        if (ir.target.language or "").lower() in ("java", "jvm", "kotlin"):
            # Dispatch on language exactly as `emit` does. Running the C gates against a JVM
            # plan would compile nothing, report NOT_RUN across the board, and the plan would
            # then be treated as unmeasured — which is honest but useless.
            from .java import gates as jgates
            try:
                em = emit(ir)
                jart = jgates.build(ir, em, classpath=":".join(ir.target.link_libs))
                return ir, gates + jgates.run_java_gates(
                    ir, em, jart,
                    valid_corpus=corpus.valid_only(ir).inputs,
                    drive_corpus=corpus.generate(ir, seed=args.seed).inputs,
                    classpath=":".join(ir.target.link_libs),
                    positive_control=not args.no_positive_control,
                    campaign=True, campaign_seconds=args.campaign_seconds), None, []
            except EmitError as e:
                return ir, gates + _emit_refused(e), None, []
        try:
            em = emit(ir)
            art = build(ir, em)
            # The drive corpus is what D2 uses to try to kill a planted defect, and
            # synthetic bytes do not reach deep code. We MINE real inputs from the target's
            # own tests and were then not giving them to the gate that most needs them —
            # so D2 reported 0/4 kills against sqlite and looked like a weak harness rather
            # than a starved corpus.
            drive = corpus.generate(ir, seed=args.seed).inputs
            if ir.target.seed_dirs:
                mined = seeds.mine(ir.target.seed_dirs,
                                   max_bytes=ir.knobs.max_len or 65536)
                drive = [d for _, d in mined.files] + drive
            return ir, gates + run_dynamic_gates(
                ir, em, art, valid_corpus=corpus.valid_only(ir).inputs,
                drive_corpus=drive,
                positive_control=not args.no_positive_control,
                campaign=True, campaign_seconds=args.campaign_seconds), art, drive
        except EmitError as e:
            return ir, gates + _emit_refused(e), None, []

    measured: dict = {}
    built: dict = {}                  # plan name -> (ir, BuildArtifacts, drive corpus)
    if deep:
        # Each plan is compiled and campaigned independently, so the wall clock is the
        # slowest one rather than the sum. Measuring 18 candidates serially at 10s each is
        # three minutes of mostly-idle CPU.
        workers = max(1, min(args.jobs, len(deep)))
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            for ir, gates, art, drive in pool.map(_measure, deep):
                measured[ir.name] = gates
                if art is not None:
                    built[ir.name] = (ir, art, drive)

        # D11 compares plans for the SAME entry point, and no caller had ever supplied a
        # second one: `run_dynamic_gates` takes sibling_plans and nothing in this codebase
        # passed it, so the gate returned "only 1 buildable plan" on every certificate ever
        # written. batch is where the siblings exist — a length variant, a setup variant and
        # a chain for one API are three producers' answers to the same question, and when
        # they disagree about an input at least one of them is wrong about the target.
        groups: dict = {}
        for name, (ir, art, drive) in built.items():
            entry = next((o.api for o in ir.sequence
                          if o.id.startswith("o_consume")), ir.name)
            groups.setdefault(entry, []).append((ir, art, drive))
        compared = 0
        for entry, members in groups.items():
            usable = [(i, a, d) for i, a, d in members if a and a.replay_bin]
            if len(usable) < 2:
                continue
            shared = usable[0][2]
            r = d11_differential([i for i, _, _ in usable],
                                 [a for _, a, _ in usable], shared)
            compared += 1
            for i, _, _ in usable:
                measured[i.name] = [g for g in measured[i.name] if g.gate != "D11"] + [r]
        if compared:
            print(f"  D11 compared producers on {compared} entry point(s) with more than "
                  f"one buildable plan.")

    scored, shipped = [], 0
    for ir, gates in survivors:
        gates = measured.get(ir.name, gates)
        # "Measured" has to mean A BINARY EXISTED and gates ran against it. Two rounds of
        # this bug:
        #
        #   1. a plan handed to the measuring pass counted as measured even when its harness
        #      compiled to nothing, so it shipped and was named the winner off six static
        #      gates while every dynamic gate read "the binary was not built";
        #   2. the first fix accepted ANY non-NOT_RUN gate whose id starts with D — and D4
        #      is static reachability analysis that needs no binary at all. Three sqlite
        #      harnesses shipped on the strength of D4 alone, each one uncompilable.
        #   3. the second fix included D1, which inspects UNDEFINED SYMBOLS IN AN OBJECT
        #      FILE. That needs compilation but neither linking nor execution. Four sqlite
        #      plans for APIs behind -DSQLITE_ENABLE_RTREE and -DSQLITE_ENABLE_SNAPSHOT
        #      compiled fine, failed to LINK ("Undefined symbols for architecture"), and
        #      shipped on D1 alone with D2, D3, D5, D6 and D8 all NOT_RUN.
        #
        # So the check names the gates that EXECUTED THE HARNESS. Nothing else is evidence
        # that this thing runs. P3.HONESTY caught the same failure arriving by a fourth
        # road, emit refusing; absence of a dynamic verdict must never read as success,
        # whatever produced it.
        _RAN_THE_HARNESS = ("D2", "D3", "D5", "D6", "D8")
        was_measured = (ir.name in measured
                        and any(g.gate in _RAN_THE_HARNESS and g.verdict != NOT_RUN
                                for g in gates))
        s = ranking.score(ir.name, ir.producer, gates)
        s = replace(s, measured=was_measured)
        scored.append(s)

        # The depth gate applies only where depth was actually measured. Refusing to ship
        # on an edge count that D8 never produced rejects everything for a reason that does
        # not exist — which is what happened on a host with no libFuzzer runtime.
        depth_ok = (s.edges >= args.min_edges) if s.depth_known else True
        # A plan nobody measured is not shippable. Two different unknowns were being
        # conflated: "D8 could not run here" (fine, ship it and say depth is unmeasured) and
        # "this plan was never built at all" (not fine — we know nothing about it). The
        # second must not ride out on the first's exemption, or a run that measured 4 of 34
        # ships all 34.
        if s.shippable and (not deep or (s.measured and depth_ok)):
            d = out / ir.name
            d.mkdir(parents=True, exist_ok=True)
            try:
                em = emit(ir)
                _h, _d = _artifact_names(ir)
                (d / _h).write_text(em.source)
                (d / _d).write_text(em.driver)
                (d / "plan.hir.json").write_text(ir.dumps())
                (d / "build.sh").write_text(
                    "#!/bin/sh\nset -eu\nCC=\"${CC:-clang}\"\n\n"
                    f"{' '.join(em.build_command)}\n\n"
                    f"{' '.join(em.driver_build_command)}\n")
                (d / "build.sh").chmod(0o755)
                (d / "certificate.json").write_text(
                    build_certificate(ir, gates, em).dumps())
                mined = seeds.mine(ir.target.seed_dirs,
                                   max_bytes=ir.knobs.max_len or 65536) \
                    if ir.target.seed_dirs else None
                if mined and mined.files:
                    seeds.write(mined, d / "corpus")
                n = dictionary.write(ir.target.sources, d / "target.dict")
                if n:
                    (d / "README").write_text(
                        f"{ir.name}\n\n"
                        f"  sh build.sh\n"
                        f"  mkdir corpus\n"
                        f"  ./{ir.name}_fuzz corpus/ -dict=target.dict "
                        f"-max_len={ir.knobs.max_len}\n\n"
                        f"target.dict holds {n} tokens taken from the target's own string\n"
                        f"literals. A parser's vocabulary is written down inside the parser.\n"
                        f"Its effect is recorded in certificate.json under gate D8.\n")
                shipped += 1
            except EmitError:
                pass

    for ir, gates in rejected:
        scored.append(replace(ranking.score(ir.name, ir.producer, gates), measured=False))

    ranked = ranking.rank(scored)
    report = ranking.render(ranked)
    print(report)

    # WHERE each defect was caught, which is the axis this engine is actually different on.
    #
    # The published state of the art intercepts harness-induced crashes by RUNNING the
    # harness and attributing the crash afterwards. Every violation below with an `S` code
    # was found on the plan, before a compiler existed: no build, no campaign, no triage.
    # The rest needed a binary, and the split between the two is the interesting number.
    pre, post = Counter(), Counter()
    for sc in scored:
        for g in sc.gates:
            for v in g.violations:
                if v.severity != BLOCK:
                    continue
                (pre if g.gate.startswith("S") else post)[v.code] += 1
    if pre or post:
        print()
        print("WHERE THE DEFECTS WERE CAUGHT")
        print(f"  before any compiler ran : {sum(pre.values()):>4}")
        for code, n in pre.most_common():
            print(f"      {n:>3}  {code}")
        print(f"  needed a built binary   : {sum(post.values()):>4}")
        for code, n in post.most_common():
            print(f"      {n:>3}  {code}")
        total = sum(pre.values()) + sum(post.values())
        if total:
            print(f"  {sum(pre.values()) / total:.0%} of blocking defects cost zero "
                  f"compilation and zero campaign time.")

    (out / "REPORT.txt").write_text(
        f"harness suite for {tgt.name}\n"
        f"{len(plans)} proposed, {len(survivors)} passed static gates, "
        f"{shipped} shipped to {out}/\n"
        f"minimum edges to ship: {args.min_edges}\n" + report + "\n")
    _is_java = (tgt.language or "").lower() in ("java", "jvm", "kotlin")
    _files = ("Harness.java, Replay.java, build.sh and certificate.json" if _is_java
              else "harness.c, driver.c, build.sh and certificate.json")
    print(f"\n{shipped} harness(es) written to {out}/ — each with {_files}.")
    never = sum(1 for s in scored if s.shippable and not s.measured)
    if deep and never:
        print(f"{never} plan(s) passed the static gates but were never measured, so they "
              f"were NOT shipped. Raise --top to measure them; they are unknown, not bad.")
    unknown_depth = sum(1 for s in scored if s.measured and not s.depth_known)
    if deep and args.min_edges:
        print(f"Plans reaching fewer than {args.min_edges} edges were NOT shipped: a harness "
              f"that cannot get past the library's error path finds nothing.")
    if unknown_depth:
        # The reason is read from the gate, never assumed. This line used to assert "no
        # libFuzzer runtime here" whatever had happened — and on a host WITH libFuzzer it
        # said so anyway, while the real reason sat in D8's own evidence: the campaign
        # binary failed to LINK, because the plan called APIs compiled out of the target
        # (-DSQLITE_ENABLE_RTREE, -DSQLITE_ENABLE_SNAPSHOT). Blaming the host for a
        # target-configuration problem sends the reader to fix the wrong machine.
        reasons: dict = {}
        for _name, _gates in measured.items():
            d8 = next((g for g in _gates if g.gate == "D8"), None)
            if d8 is not None and d8.verdict == NOT_RUN and d8.reason:
                key = d8.reason.split(":")[0].strip()[:80]
                reasons[key] = reasons.get(key, 0) + 1
        why = ("; ".join(f"{n}x {k}" for k, n in sorted(reasons.items(), key=lambda x: -x[1]))
               or "see each certificate's D8 reason")
        print(f"{unknown_depth} shipped WITHOUT a depth measurement (D8 did not run: {why}). "
              f"Their edge counts read '?', not 0, and the depth gate was not applied to "
              f"them.")
    return 0 if shipped else 1


def cmd_audit(args) -> int:
    """Grade harnesses somebody else wrote.

    The half of the engine that is useful without finding a bug in any target: point it at a
    production harness and it reports the defects that harness carries into every campaign
    run against it. Coordinated-disclosure discipline applies to anything found here — a
    harness defect in someone's repository is a report to make politely, not a scoreboard.
    """
    paths: list = []
    for a in args.harness:
        p = Path(a)
        paths.extend(sorted(p.rglob("*.c")) + sorted(p.rglob("*.cc"))
                     if p.is_dir() else [p])

    rows, total_block, total_warn, unliftable, low_fidelity = [], 0, 0, [], []
    for p in paths:
        try:
            lifted = lift_c_harness(str(p), target_name=args.name or p.stem)
        except LiftError as e:
            # Its own words. A wrong reason sends the reader after a defect that is not there.
            unliftable.append((p, str(e)))
            continue
        except Exception as e:                                   # noqa: BLE001
            unliftable.append((p, f"{type(e).__name__}: {e}"))
            continue
        if lifted is None:
            unliftable.append((p, "the lift returned nothing and gave no reason"))
            continue
        gates = list(run_static_gates(lifted.ir))
        blocks = [v for g in gates for v in g.violations if v.severity == BLOCK]
        warns = [v for g in gates for v in g.violations if v.severity == WARN]
        confident = lifted.high_fidelity
        if confident:
            total_block += len(blocks)
            total_warn += len(warns)
        else:
            low_fidelity.append((p, lifted, blocks))
        rows.append((p, lifted, gates, blocks, warns))

        if (blocks and confident) or args.verbose:
            print(f"\n{p}")
            print(f"  {len(lifted.ir.sequence)} call(s), "
                  f"{len(lifted.ir.resources)} resource(s)"
                  + (f", {len(lifted.unread)} value(s) the lifter could not attribute"
                     if lifted.unread else ""))
            for v in blocks:
                print(f"  [BLOCK] {v.code}: {v.message}")
                if v.fix:
                    print(f"          fix: {v.fix}")
            for v in warns if args.verbose else []:
                print(f"  [warn ] {v.code}: {v.message[:120]}")

    print()
    print("=" * 74)
    print(f"AUDITED {len(rows)} harness(es) from {len(paths)} file(s)")
    print("=" * 74)
    print(f"  blocking defects : {total_block}   (high-fidelity lifts only)")
    print(f"  warnings         : {total_warn}")
    print(f"  low fidelity     : {len(low_fidelity)}   NOT counted as defects")
    print(f"  not liftable     : {len(unliftable)}")
    for p, lf, blocks in low_fidelity[:6]:
        print(f"      {p.name}: {lf.why_low_fidelity}")
        for v in blocks[:2]:
            print(f"          unverified: {v.code}")
    for p, why in unliftable[:8]:
        print(f"      {p.name}: {why}")
    if rows:
        print()
        print("Contract gates (S2) need the target's headers. Without them they report what")
        print("they could check and NOT RUN for the rest, rather than guessing — a harness")
        print("graded on a guess is worse than one not graded at all.")
    return 1 if total_block else 0


def cmd_targets(args) -> int:
    """Shortlist the dependencies of shipped programs that nobody appears to be fuzzing.

    Target choice is the cheapest improvement available to us and the one we had spent no
    effort on. CVE-2025-53367 was a 1-click RCE in a DjVu parser shipped by default with
    Evince on millions of systems, and it was never in OSS-Fuzz at all.
    """
    known = ossfuzz.load_known(args.oss_fuzz_list)
    surveys, failed = [], []
    for b in args.binary:
        p = Path(b)
        if not p.exists():
            from shutil import which
            w = which(b)
            if not w:
                failed.append((b, "not found"))
                continue
            p = Path(w)
        s = ossfuzz.survey(str(p), known)
        if s is None:
            from .toolchain import host as _host
            tool = {"macos": "otool -L", "windows": "llvm-readobj"}.get(_host().os, "ldd")
            failed.append((str(p), f"{tool} could not read it: a script, a static "
                                   f"binary, or a format this host cannot inspect"))
            continue
        surveys.append(s)

    if not surveys:
        print("nothing surveyed.")
        for b, why in failed:
            print(f"  {b}: {why}")
        return 1

    print(ossfuzz.render(surveys))

    if args.resolve:
        # A shortlist of NAMES is a list of things to go and look up by hand, which is where
        # the operator's afternoon goes. Resolving each candidate to its headers is what
        # turns "nobody is fuzzing djvulibre" into a command that can be run.
        stems, seen = [], set()
        for s_ in surveys:
            for d in s_.candidates:
                if d.stem not in seen:
                    seen.add(d.stem)
                    stems.append((d.stem, d.path))
        print()
        print("HEADERS")
        print("-" * 74)
        for st, lib_path in stems:
            h = ossfuzz.resolve_headers(st, lib_path)
            if h.found:
                print(f"  {st:<20} {h.method}")
                print(f"  {'':<20} {len(h.headers)} header(s), first: {h.headers[0]}")
                inc = " ".join(f"--include {d}" for d in h.include_dirs)
                # Siblings go on --also-header: a library routinely typedefs its handle in
                # one file and declares the API in another, and a header parsed alone yields
                # no plans while reporting no error.
                also = " ".join(f"--also-header {x}" for x in h.headers[1:6])
                more = (f"   (+{len(h.headers) - 6} more headers)"
                        if len(h.headers) > 6 else "")
                print(f"  {'':<20} hforge propose {h.headers[0]} {also} {inc}{more}")
                if h.why_not:
                    print(f"  {'':<20} CAUTION: {h.why_not}")
            else:
                print(f"  {st:<20} NO HEADERS — {h.why_not}")
        if not stems:
            print("  (no candidates to resolve)")

    if failed:
        print()
        for b, why in failed:
            print(f"  skipped {b}: {why}")
    return 0


def cmd_triage(args) -> int:
    """Judge crashes the way the engine judges harnesses.

    The discipline used to stop at the campaign: libFuzzer wrote `crash-<sha>` and from
    there nothing reproduced it, minimised it, attributed it, replayed it on another build,
    ruled out the instrumentation, or said what it did not establish. That is the worst
    possible place to stop being careful, because it is the moment before a maintainer is
    emailed.
    """
    crash_files: list = []
    for a in args.crash:
        p = Path(a)
        crash_files.extend(sorted(x for x in p.rglob("*") if x.is_file())
                           if p.is_dir() else [p])
    if not crash_files:
        print("no crash inputs found.")
        return 1

    report_text = Path(args.report).read_text(errors="replace") if args.report else ""
    crashes = [findings_gates.Crash(input_bytes=p.read_bytes(), origin=str(p),
                                    report=report_text)
               for p in crash_files]

    def _replay(path, label, sanitized=True):
        return findings_gates.Replay(binary=Path(path), label=label,
                                     sanitized=sanitized) if path else None

    ledger = None
    if args.ledger and Path(args.ledger).exists():
        ledger = json.loads(Path(args.ledger).read_text())

    prov = findings_report.Provenance(
        target=args.name or "", plan_name=Path(args.plan).stem if args.plan else "",
        ir_sha256=(hashlib.sha256(Path(args.plan).read_bytes()).hexdigest()
                   if args.plan and Path(args.plan).exists() else ""),
        source_commit=findings_report.git_commit(args.repo) if args.repo else "",
        compiler=find_cc() or "", platform=args.platform_id,
        sanitizers=["address"] if args.replay else [])

    inp = findings_pipeline.Inputs(
        crashes=crashes,
        instrumented=_replay(args.replay, "instrumented", True),
        baseline=_replay(args.baseline, "uninstrumented", False),
        variants=[_replay(v.split("=", 1)[1], v.split("=", 1)[0])
                  for v in (args.variant or []) if "=" in v] or None,
        ledger=ledger,
        independent_oracle=args.independent_oracle,
        provenance=prov,
        campaign_seconds=args.campaign_seconds,
        null_harness_faults=args.null_harness_faults,
        platform_id=args.platform_id)

    found, audit = findings_pipeline.triage(inp)
    for f in found:
        if f.reportable or args.verbose:
            print(findings_report.render(f))
    print(findings_pipeline.summarise(found, audit))

    if args.out:
        out = Path(args.out)
        for f in found:
            findings_report.write(f, out)
        print(f"\n{len(found)} finding artifact(s) written to {out}/")
    return 0 if any(f.reportable for f in found) else 1


def cmd_fprate(args) -> int:
    """Measure our own false-positive rate against constructed ground truth.

    QuartetFuzz reports 4.8%. We had never measured the equivalent, which made every
    comparison we drew an argument from architecture rather than a result.
    """
    from .findings import fprate

    target = Target(name=args.name or "target",
                    public_headers=[args.header] if args.header else [],
                    include_dirs=args.include or [],
                    sources=args.source or [],
                    link_libs=args.link or [])
    if not target.sources:
        print("a source build is required: ASan cannot see allocations inside an")
        print("uninstrumented library, so the crashes this measures would never occur.")
        return 1

    outcomes = fprate.run(target, seconds=args.seconds,
                          workdir=Path(args.out) if args.out else None)
    print(fprate.render(outcomes))
    if args.out:
        o = Path(args.out)
        o.mkdir(parents=True, exist_ok=True)
        (o / "fprate.json").write_text(json.dumps(
            [vars(x) for x in outcomes], indent=2, default=str))
        print(f"\nwritten to {o}/fprate.json")
    return 0


def cmd_gates(args) -> int:
    print("STATIC — run on the plan, before a compiler exists")
    for g, t in [("S1", "lifetime: created once, destroyed once, never used after"),
                 ("S2", "contract: NUL-termination, (ptr,len) pairs, ownership, non-null"),
                 ("S3", "ordering: create before use before destroy"),
                 ("S4", "boundary: public interface only"),
                 ("S5", "input flow: the fuzzer's bytes reach the target"),
                 ("S6", "error handling: failure returns checked before use")]:
        print(f"  {g}  {t}")
    print()
    print("DYNAMIC — run against a build")
    for g, t in [("D1", "liveness: the target call survived the optimiser"),
                 ("D2", "positive control: the harness finds a PLANTED defect"),
                 ("D3", "valid input must not crash"),
                 ("D4", "sink reachability, as a fraction"),
                 ("D5", "execution rate is plausible"),
                 ("D6", "determinism, reported as a rate"),
                 ("D7", "knobs recorded, and what they exclude computed"),
    ("D8", "campaign productivity: edges the fuzzer can actually see"),
                 ("D9", "misuse provenance: harness-allocated or library-allocated"),
                 ("D11", "differential consistency across producers")]:
        print(f"  {g:<3} {t}")
    print()
    print("A gate never returns a boolean. It returns a verdict plus the evidence, and")
    print("NOT RUN is a distinct outcome so an absent check never reads as a passed one.")
    return 0


def cmd_doctor(args) -> int:
    """What this machine can do, and what each absent tool costs you.

    The point is the second column. A missing tool is only worth reporting if you are told
    what it stops you proving, because otherwise the honest response to a warning is to
    ignore it.
    """
    inv = tc.inventory()
    h = inv.host
    print("=" * 78)
    print(f"HOST   {h.os}/{h.arch}   nearest modelled platform: {h.platform_id}")
    print("=" * 78)
    p = plat.PLATFORMS.get(h.platform_id)
    if p:
        print(f"  sanitizers   {','.join(p.sanitizers) or '-'}")
        print(f"  allocator    {p.allocator}")
        print(f"  ceiling      {p.trust_ceiling}")
    print()

    print(f"{'TOOL':<14} {'STATUS':<8} PATH / WHAT ITS ABSENCE COSTS")
    print("-" * 78)
    for t in inv.tools:
        if t.present:
            print(f"{t.name:<14} {'ok':<8} {t.path}")
        else:
            print(f"{t.name:<14} {'MISSING':<8} needed for {t.required_for}")
            print(f"{'':<23} cost: {t.cost_if_absent}")
    print()

    cap = dev.capability_report()
    print("DEVICES")
    print("-" * 78)
    found = cap["android_devices"] + cap["ios_simulators"]
    if not found:
        print("  none attached")
    for d in found:
        print(f"  {d['os']:<8} {d['kind']:<10} {d['serial'][:24]:<26} "
              f"{d['model']} {d['release']}")
        if d["platform_id"]:
            print(f"           -> platform {d['platform_id']}")
        for n in d["notes"]:
            print(f"           . {n}")
    if cap["blocked"]:
        print()
        print("BLOCKED")
        for b in cap["blocked"]:
            print(f"  - {b}")
    print()

    if inv.can_gate:
        print("VERDICT: this machine can certify. Static gates always run; dynamic gates have")
        print("a compiler. Anything a missing tool prevents will be reported as NOT RUN on the")
        print("certificate, never as a pass.")
        return 0
    print("VERDICT: no C compiler. Static gates still run and still catch contract defects,")
    print("but every dynamic gate will report NOT RUN.")
    return 1


def cmd_devices(args) -> int:
    found = dev.all_devices()
    if not found:
        cap = dev.capability_report()
        print("no devices attached.")
        for b in cap["blocked"]:
            print(f"  - {b}")
        return 1
    if args.json:
        print(json.dumps([d.to_json() for d in found], indent=2))
        return 0
    for d in found:
        print(f"{d.os}/{d.kind}  {d.serial}")
        print(f"  model      {d.model} {d.release}   abi={d.abi or '-'} api={d.api or '-'}")
        print(f"  platform   {d.platform_id or 'UNMODELLED — refuse to claim a ceiling'}")
        for n in d.notes:
            print(f"  . {n}")
        print()
    return 0


def _eviline(g) -> str:
    """One line of a gate's evidence. GateResult carries structured evidence rather than a
    prose field, deliberately: a gate reports what it measured, not a sentence about it."""
    if g.reason:
        return g.reason[:64]
    return ", ".join(f"{k}={v}" for k, v in list(g.evidence.items())[:3])[:64] or g.verdict


def cmd_selftest(args) -> int:
    """Prove the whole pipeline works on THIS machine, end to end, before you trust a result.

    Each stage is a claim with a check attached. A stage that cannot run on this host is
    SKIP with a reason, and SKIP is not PASS — the exit code distinguishes them.
    """
    import tempfile
    from .gates.dynamic_gates import d1_liveness, d3_valid_input, d2_positive_control
    from .gates.result import PASS

    root = Path(__file__).resolve().parent.parent
    ex = root / "examples"
    rows: list = []

    def stage(name, fn):
        try:
            ok, detail = fn()
        except Exception as e:                                # noqa: BLE001
            ok, detail = False, f"{type(e).__name__}: {e}"
        rows.append((name, ok, detail))
        tag = {True: " PASS ", False: " FAIL ", None: " SKIP "}[ok]
        print(f"[{tag}] {name:<34} {detail}")
        return ok

    print("=" * 78)
    print(f"SELFTEST   {tc.host().os}/{tc.host().arch}")
    print("=" * 78)

    good = ex / "hf_demo.good.hir.json"
    broken = ex / "hf_demo.broken.hir.json"

    def s_roundtrip():
        ir = HarnessIR.loads(good.read_text())
        again = HarnessIR.loads(ir.dumps())
        return again.dumps() == ir.dumps(), f"IR survives a JSON round trip ({ir.name})"

    def s_exitcodes():
        """The portability bug that mattered, pinned. Pure, so it is checked on every host
        for every host."""
        cases = [
            (-11, "linux", True, tc.FAULT), (139, "linux", True, tc.FAULT),
            (0, "linux", True, tc.OK), (2, "linux", True, tc.DRIVER_ERROR),
            (1, "linux", True, tc.FAULT), (1, "linux", False, tc.OK),
            (0xC0000005, "windows", True, tc.FAULT),
            (0xC0000374, "windows", True, tc.FAULT),
            (-1073741819, "windows", True, tc.FAULT),      # signed 0xC0000005
            (0, "windows", True, tc.OK),
            (139, "windows", True, tc.OK),                 # NOT a Windows crash
            (None, "linux", True, tc.TIMEOUT),
        ]
        bad = [(rc, o) for rc, o, san, want in cases
               if tc.classify_exit(rc, os_name=o, sanitized=san) != want]
        return not bad, (f"{len(cases)} exit codes classified correctly across linux/windows"
                         if not bad else f"misclassified {bad}")

    def s_static_rejects():
        gs = run_static_gates(HarnessIR.loads(broken.read_text()))
        blocking = [v for g in gs for v in g.violations if v.severity == BLOCK]
        s2 = [v for v in blocking if v.code.startswith("S2")]
        return bool(s2), (f"broken plan blocked by {len(blocking)} violation(s), "
                          f"incl. {s2[0].code if s2 else '-'} — no compiler ran")

    def s_static_accepts():
        gs = run_static_gates(HarnessIR.loads(good.read_text()))
        blocking = [v for g in gs for v in g.violations if v.severity == BLOCK]
        return not blocking, ("good plan passes all six static gates"
                              if not blocking else f"unexpected: {[v.code for v in blocking]}")

    def s_emit():
        em = emit(HarnessIR.loads(good.read_text()))
        ok = "LLVMFuzzerTestOneInput" in em.source and "malloc(" in em.driver
        return ok, "C emitted; replay driver uses an exactly-sized heap buffer"

    state: dict = {}

    def s_build():
        if not find_cc():
            return None, "no C compiler on this host"
        ir = HarnessIR.loads(good.read_text())
        em = emit(ir)
        wd = Path(tempfile.mkdtemp(prefix="hforge-selftest-"))
        art = build(ir, em, wd)
        state.update(ir=ir, em=em, art=art)
        return art.ok, (f"built with {Path(find_cc()).name} -> {wd}" if art.ok
                        else f"build failed: {art.log[-300:]}")

    def s_d1():
        if "art" not in state or not state["art"].ok:
            return None, "no build"
        g = d1_liveness(state["ir"], state["em"], state["art"])
        return g.verdict == PASS, f"{g.verdict}: {_eviline(g)}"

    def s_d3():
        if "art" not in state or not state["art"].ok:
            return None, "no build"
        ir = state["ir"]
        g = d3_valid_input(ir, state["art"], corpus.valid_only(ir).inputs)
        return g.verdict == PASS, f"{g.verdict}: valid input does not crash the harness"

    def s_d2():
        if "art" not in state or not state["art"].ok:
            return None, "no build"
        if args.quick:
            return None, "--quick: mutation testing skipped (it is the slowest gate)"
        ir = state["ir"]
        g = d2_positive_control(ir, state["em"], state["art"],
                                corpus.generate(ir).inputs[:24])
        return g.verdict == PASS, f"{g.verdict}: {_eviline(g)}"

    def s_certificate():
        ir = HarnessIR.loads(good.read_text())
        gs = list(run_static_gates(ir))
        cert = build_certificate(ir, gs, None)
        txt = render_text(cert)
        return ("unreachable" in cert.dumps() and cert.verdict in
                ("certified", "provisional", "rejected") and len(txt) > 200,
                f"verdict={cert.verdict}; declares what it CANNOT find")

    def s_producer():
        hdr = ex / "lib" / "hf_demo.h"
        plans = header_graph.propose([str(hdr)], Target(
            name="hf_demo", public_headers=["hf_demo.h"],
            include_dirs=[str(hdr.parent)], sources=[str(hdr.with_suffix(".c"))]),
            platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))
        return len(plans) >= 2, f"{len(plans)} plan(s) proposed from the header, no model used"

    def s_android_build():
        """Cross-compiling for Android proves the mobile path without needing a device. It
        is the half that can be checked anywhere the NDK is installed."""
        if not tc.find_ndk():
            return None, "no NDK: an Android harness cannot be built on this host"
        if "em" not in state:
            return None, "no build stage output to cross-compile"
        wd = Path(tempfile.mkdtemp(prefix="hforge-android-"))
        (wd / "harness.c").write_text(state["em"].source)
        (wd / "driver.c").write_text(state["em"].driver)
        srcs = [wd / "harness.c", wd / "driver.c", ex / "lib" / "hf_demo.c"]
        live = [d for d in dev.android_devices() if d.kind in ("device", "emulator")]
        serial = live[0].serial if live else None
        b = dev.build_android(srcs, wd, include_dirs=[str(ex / "lib")],
                              abi=args.abi, api=args.api, serial=serial)
        base = dev.build_android(srcs, wd, include_dirs=[str(ex / "lib")],
                                 abi=args.abi, api=args.api, detector="none",
                                 suffix="-baseline")
        state.update(android=b, android_base=base, android_serial=serial)
        if not b.ok:
            return False, f"{b.reason}: {b.log[-160:]}"
        note = (f" (downgraded from {b.requested_detector}: {b.downgrade_reason})"
                if b.downgraded else "")
        return True, f"{args.abi} api{args.api} with {b.detector}{note}"

    def s_android_run():
        """Runs the DIFFERENTIAL, not a single build. A lone instrumented run cannot tell a
        target defect from an instrumentation artifact, and the engine's first Android run
        was the artifact."""
        b, base = state.get("android"), state.get("android_base")
        serial = state.get("android_serial")
        if not b or not b.ok:
            return None, "nothing cross-compiled to run"
        if not serial:
            avds = dev.emulators_available()
            return None, (f"no device attached; {len(avds)} AVD(s) available to boot"
                          if avds else "no device attached and no AVD defined")
        if not (base and base.ok):
            return None, "no uninstrumented baseline to compare against"
        r = dev.run_differential(serial, b.binary, base.binary, b'{"a":1}')
        return r.verdict == tc.OK, f"{serial}: {r.verdict} — {r.detail[:80]}"

    def s_devices():
        cap = dev.capability_report()
        n = len(cap["android_devices"]) + len(cap["ios_simulators"])
        if n == 0:
            return None, "; ".join(cap["blocked"])[:70] or "no device attached"
        return True, f"{n} device(s) reachable and mapped to modelled platforms"

    stage("IR round-trip", s_roundtrip)
    stage("exit-code classification", s_exitcodes)
    stage("static gates REJECT bad plan", s_static_rejects)
    stage("static gates ACCEPT good plan", s_static_accepts)
    stage("C emission", s_emit)
    stage("build", s_build)
    stage("D1 liveness", s_d1)
    stage("D3 valid input", s_d3)
    stage("D2 positive control", s_d2)
    stage("certificate", s_certificate)
    stage("producer proposes", s_producer)
    stage("android cross-build", s_android_build)
    stage("android device run", s_android_run)
    stage("device reachability", s_devices)

    failed = [r for r in rows if r[1] is False]
    skipped = [r for r in rows if r[1] is None]
    print()
    print(f"{sum(1 for r in rows if r[1] is True)} passed, "
          f"{len(failed)} failed, {len(skipped)} skipped")
    if skipped:
        print("\nSKIPPED is not PASSED. Each of these is a check this machine could not run:")
        for n, _, d in skipped:
            print(f"  - {n}: {d}")
    if failed:
        print("\nFAILURES:")
        for n, _, d in failed:
            print(f"  - {n}: {d}")
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="hforge",
        description="Harness Forge — certify a fuzzing harness, do not just generate one.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("platforms", help="the OS x arch x variant matrix and its trust ceilings"
                   ).set_defaults(fn=cmd_platforms)
    sub.add_parser("gates", help="what every gate checks, and which phase it lands in"
                   ).set_defaults(fn=cmd_gates)
    sub.add_parser("doctor", help="what this machine can do, and what each missing tool costs"
                   ).set_defaults(fn=cmd_doctor)

    dv = sub.add_parser("devices", help="attached Android devices and iOS simulators")
    dv.add_argument("--json", action="store_true")
    dv.set_defaults(fn=cmd_devices)

    st = sub.add_parser("selftest", help="prove the whole pipeline works on THIS machine")
    st.add_argument("--quick", action="store_true", help="skip mutation testing")
    st.add_argument("--abi", default="arm64-v8a", help="Android ABI for the cross-build")
    st.add_argument("--api", type=int, default=29,
                    help="Android API level; HWASan needs arm64 and >=29")
    st.set_defaults(fn=cmd_selftest)

    v = sub.add_parser("validate", help="run the static gates on a plan (no compiler needed)")
    v.add_argument("ir")
    v.set_defaults(fn=cmd_validate)

    e = sub.add_parser("emit", help="emit C for the libFuzzer backend")
    e.add_argument("ir")
    e.add_argument("-o", "--out", default="build")
    e.set_defaults(fn=cmd_emit)

    c = sub.add_parser("certify", help="static gates, emit, build, dynamic gates, certificate")
    c.add_argument("ir")
    c.add_argument("-o", "--out", help="write the certificate JSON here")
    c.add_argument("--valid-corpus", help="directory of inputs the library should ACCEPT")
    c.add_argument("--work", help="build directory (default: a temp dir)")
    c.add_argument("--force", action="store_true",
                   help="build even when static gates blocked")
    c.add_argument("--seed", type=int, default=1337,
                   help="corpus seed; recorded on the certificate")
    c.add_argument("--no-positive-control", action="store_true",
                   help="skip D2 (mutation testing); it is the slowest gate")
    c.add_argument("--no-campaign", action="store_true",
                   help="skip D8, which builds the real fuzzer and runs it briefly")
    c.add_argument("--campaign-seconds", type=int, default=8,
                   help="how long D8 runs the campaign (default 8)")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(fn=cmd_certify)

    pr = sub.add_parser("propose",
                        help="synthesise candidate plans from a header and rank them by gate "
                             "evidence (no model involved)")
    pr.add_argument("header", nargs="?",
                    help="the library's public header. Omit when --classpath is given")
    pr.add_argument("--source", action="append",
                    help="target source file, .c or .java (repeatable)")
    pr.add_argument("--also-header", action="append",
                    help="additional header parsed for typedefs and declarations "
                         "(repeatable). Needed when a library typedefs its handle in one "
                         "file and declares its API in another, as libxml2 does.")
    pr.add_argument("--include", action="append",
                    help="extra -I directory (repeatable)")
    pr.add_argument("--seed-dir", action="append",
                    help="directory to mine for example inputs (repeatable). A project's "
                         "own test data is a valid corpus and is already in the tree.")
    pr.add_argument("--cflag", action="append",
                    help="compiler flag the target needs, e.g. --cflag=-DHAVE_CONFIG_H "
                         "(repeatable). Recorded on the IR so the plan stays reproducible.")
    pr.add_argument("--link", action="append",
                    help="linker argument such as -lmagic (repeatable). Use this when you "
                         "are gating against an INSTALLED library rather than its sources; "
                         "gates that need source will report NOT RUN.")
    pr.add_argument("--platform", action="append")
    pr.add_argument("--name", help="target name")
    pr.add_argument("-o", "--out", default="build/proposed")
    pr.add_argument("--max-len", type=int, default=4096)
    pr.add_argument("--seed", type=int, default=1337)
    pr.add_argument("--dynamic", action="store_true",
                    help="also build and run the dynamic gates on every candidate")
    pr.add_argument("--no-positive-control", action="store_true")
    pr.set_defaults(fn=cmd_propose)

    b = sub.add_parser("batch",
                       help="generate every plan for a target, gate them all, and ship only "
                            "the ones a real campaign shows reach into the code")
    b.add_argument("header", nargs="?",
                   help="the library's public header. Omit when --classpath is given")
    b.add_argument("--source", action="append")
    b.add_argument("--also-header", action="append")
    b.add_argument("--include", action="append")
    b.add_argument("--cflag", action="append")
    b.add_argument("--seed-dir", action="append",
                   help="directory to mine for example inputs (repeatable)")
    b.add_argument("--link", action="append")
    b.add_argument("--platform", action="append")
    b.add_argument("--name")
    b.add_argument("-o", "--out", default="build/suite")
    b.add_argument("--max-len", type=int, default=65536,
                   help="default 65536, ABOVE libFuzzer's silent 4096 default")
    b.add_argument("--seed", type=int, default=1337)
    b.add_argument("--top", type=int, default=32,
                   help="how many surviving plans get a real campaign (default 32). The "
                        "target archive and the mutant set are both cached across plans, so "
                        "the marginal cost of one more candidate is a link and a campaign, "
                        "not a rebuild of the target.")
    b.add_argument("--campaign-seconds", type=int, default=8)
    b.add_argument("--jobs", "-j", type=int, default=4,
                   help="how many plans to build and campaign concurrently (default 4)")
    b.add_argument("--min-edges", type=int, default=8,
                   help="do not ship a harness whose campaign reached fewer edges")
    b.add_argument("--no-positive-control", action="store_true")
    b.set_defaults(fn=cmd_batch)

    au = sub.add_parser("audit",
                        help="lift and grade harnesses somebody else wrote (files or dirs)")
    au.add_argument("harness", nargs="+")
    au.add_argument("--name", help="target name to record on the lifted plan")
    au.add_argument("-v", "--verbose", action="store_true")
    au.set_defaults(fn=cmd_audit)

    for _p in (pr, b):
        _p.add_argument("--classpath",
                        help="a jar or directory of .class files. Selects the Java producer "
                             "and the Jazzer backend; `header` is then unused")
        _p.add_argument("--java-class", action="append",
                        help="restrict to these fully-qualified classes (repeatable)")

    tg = sub.add_parser("targets",
                        help="shortlist unfuzzed input-parsing dependencies of shipped "
                             "programs")
    tg.add_argument("binary", nargs="+", help="a program name or path (ldd is used)")
    tg.add_argument("--oss-fuzz-list",
                    help="file of already-fuzzed project names, one per line; overrides the "
                         "bundled floor")
    tg.add_argument("--resolve", action="store_true",
                    help="locate each candidate's public headers and print the propose "
                         "command, so the shortlist is a work queue rather than a reading "
                         "list")
    tg.set_defaults(fn=cmd_targets)

    fpr = sub.add_parser("fprate",
                         help="measure our own false-positive rate against constructed "
                              "harness defects")
    fpr.add_argument("--header", help="the library's public header")
    fpr.add_argument("--source", action="append", help="library source (repeatable). "
                                                       "REQUIRED: an uninstrumented library "
                                                       "produces no observable faults")
    fpr.add_argument("--include", action="append")
    fpr.add_argument("--link", action="append")
    fpr.add_argument("--name")
    fpr.add_argument("--seconds", type=int, default=20)
    fpr.add_argument("--out")
    fpr.set_defaults(fn=cmd_fprate)

    tr = sub.add_parser("triage",
                        help="judge crash inputs: reproduce, minimise, attribute, replay "
                             "across builds, place on the ladder, state the exclusions")
    tr.add_argument("crash", nargs="+", help="crash input file(s) or a directory")
    tr.add_argument("--replay", help="the instrumented replay binary")
    tr.add_argument("--baseline", help="the SAME harness built without sanitizers")
    tr.add_argument("--variant", action="append",
                    help="label=path of another build, e.g. musl=/tmp/replay-musl "
                         "(repeatable)")
    tr.add_argument("--report", help="file holding the sanitizer output")
    tr.add_argument("--plan", help="the .hir.json this harness came from")
    tr.add_argument("--repo", help="target source tree, for the commit hash")
    tr.add_argument("--name", help="target name")
    tr.add_argument("--ledger", help="JSON of already-known findings")
    tr.add_argument("--independent-oracle", default="",
                    help="a tool that confirmed the fault and is NOT the one that found it; "
                         "naming the discovering sanitizer here is refused")
    tr.add_argument("--platform-id", default="linux-x86_64-glibc")
    tr.add_argument("--campaign-seconds", type=float, default=0.0)
    tr.add_argument("--null-harness-faults", type=int,
                    help="faults produced by a harness that calls nothing, on the same "
                         "corpus; the Auditor's baseline control needs it")
    tr.add_argument("-o", "--out", help="write finding artifacts here")
    tr.add_argument("-v", "--verbose", action="store_true")
    tr.set_defaults(fn=cmd_triage)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
