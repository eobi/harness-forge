"""Ranking — producers compete, gates rank, confidence decides nothing.

Every LLM-based generator in the literature selects its output by the model's own judgement:
regenerate until it compiles, then ship. That is the proposer certifying itself one level up
from where the doctrine forbids it, and it is why the field's harnesses carry defects into
production at the rates the audits report.

Here, selection is by **gate evidence only**. A producer may not attach a score, a confidence
or a preference. The ranking key is, in order:

  1. no blocking violations                 (a plan that cannot ship never wins)
  2. positive-control kill rate             (does it find planted defects at all)
  3. sink surface reached                   (how much of the target it touches)
  4. fewer NOT_RUN gates                    (more of it was actually checked)
  5. fewer warnings
  6. name, so ties are deterministic rather than dependent on dict order

Rule 6 is not decoration. An earlier ranking in this project's own research reported
P@50 = 1.00 because a stable sort preserved filesystem order inside a large tie group; the
number measured `os.listdir`, not the method.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..gates.result import BLOCK, WARN, NOT_RUN, GateResult


@dataclass
class Scored:
    plan_name: str
    gates: list
    blocking: int
    warnings: int
    not_run: int
    kill_rate: float
    sink_fraction: float
    producer: str
    edges: int = 0
    coverage_grew: bool = False
    measured: bool = True            # False when no dynamic gate was ever run on this plan
    depth_known: bool = False        # True only when D8 actually ran and produced a number
    reasons: list = field(default_factory=list)

    @property
    def shippable(self) -> bool:
        return self.blocking == 0

    @property
    def evidence(self) -> tuple:
        """Everything a GATE measured. Deliberately excludes the plan name.

        If two plans have the same evidence tuple, then nothing any gate observed tells them
        apart, and any order between them comes from the tie-break — not from measurement.
        """
        # Measured campaign depth leads, because reach is a PREREQUISITE for detection.
        # A harness that touches 36 edges and kills every planted defect in them still only
        # examines 36 edges' worth of the target; one that reaches 601 has 16x more of the
        # program in front of it. libmagic proved the point: the same entry point with and
        # without `magic_load` scores 601 edges against 36, and only the deep one grew
        # coverage at all.
        # `not measured` sits right after `blocking`, because a plan nobody measured must
        # not outrank one that was. Unmeasured plans carry NO dynamic gates at all, so their
        # `not_run` count is zero — which scored BETTER than a measured plan honestly
        # reporting the gates it could not run. On sqlite that put `autovacuum_pages`, never
        # built, above `sqlite3_exec`, which was. Absence reading as success, again.
        return (self.blocking, (not self.measured), -self.edges, -self.kill_rate,
                -self.sink_fraction, self.not_run, self.warnings)

    @property
    def key(self) -> tuple:
        # sort ascending, so negate everything that should be maximised. The plan name is
        # last and is a determinism tie-break ONLY: it is not evidence, and `render` refuses
        # to call the first row a winner when the name is the only thing that ordered it.
        return self.evidence + (self.plan_name,)


def _rate(text: str) -> float:
    try:
        a, b = text.split("/")
        return float(a) / float(b) if float(b) else 0.0
    except Exception:                                          # noqa: BLE001
        return 0.0


def score(plan_name: str, producer: str, gates: list) -> Scored:
    blocking = sum(1 for g in gates for v in g.violations if v.severity == BLOCK)
    warnings = sum(1 for g in gates for v in g.violations if v.severity == WARN)
    not_run = sum(1 for g in gates if g.verdict == NOT_RUN)

    kill, sink = 0.0, 0.0
    edges, grew, depth_known = 0, False, False
    reasons: list = []
    for g in gates:
        if g.gate == "D2":
            if g.verdict == NOT_RUN:
                reasons.append("positive control did not run: nothing shows this harness "
                               "can find anything")
            else:
                kill = _rate(g.evidence.get("kill_rate", "0/0"))
        if g.gate == "D4" and g.verdict != NOT_RUN:
            sink = float(g.evidence.get("fraction", 0.0))
        if g.gate == "D8" and g.verdict != NOT_RUN:
            edges = int(g.evidence.get("edges", 0))
            grew = bool(g.evidence.get("coverage_grew", False))
            depth_known = True
    for g in gates:
        for v in g.violations:
            if v.severity == BLOCK:
                reasons.append(f"{v.code}: {v.message[:110]}")
    return Scored(plan_name=plan_name, gates=gates, blocking=blocking, warnings=warnings,
                  not_run=not_run, kill_rate=kill, sink_fraction=sink, producer=producer,
                  edges=edges, coverage_grew=grew, depth_known=depth_known,
                  reasons=reasons)


def rank(scored: list) -> list:
    return sorted(scored, key=lambda s: s.key)


def discriminating(ranked: list) -> bool:
    """Whether gate evidence actually separates the shippable candidates.

    Ranking 74 libxml2 plans that every gate scored identically put `xmlBuildQName` first
    and printed "Selected by gate evidence" underneath it. Nothing had been selected: D2 and
    D4 could not run against an installed library, every candidate tied at zero, and the
    order was alphabetical. That is a silent wrong answer wearing the words of a real one.
    """
    shippable = [s for s in ranked if s.shippable]
    return len({s.evidence for s in shippable}) > 1


def _why_undiscriminating(ranked: list) -> list:
    """The specific reason no gate separated the candidates, and what to do about it."""
    out: list = []
    sample = next((s for s in ranked if s.shippable), None)
    if not sample:
        return out
    for g in sample.gates:
        if g.verdict == NOT_RUN and g.gate in ("D2", "D4", "D8"):
            out.append(f"{g.gate}: {g.reason}")
    return out


def render(ranked: list) -> str:
    L = ["", f"{'RANK':<5} {'PLAN':<34} {'BLOCK':>5} {'EDGES':>7} {'GREW':>5} "
             f"{'KILL':>6} {'SINKS':>6} {'N/RUN':>6} {'WARN':>5}", "-" * 92]
    for i, s in enumerate(ranked, 1):
        mark = " " if s.shippable else "x"
        # An unmeasured plan prints "?" rather than 0. Printing a zero it never measured
        # would be reporting an absent check as a failed one, which is the same error as
        # reporting it as a passed one.
        # "?" whenever the number was never produced — either the plan was never measured
        # at all, or D8 could not run (no libFuzzer runtime). Printing 0 for a depth nobody
        # measured is the same lie as printing PASS for a gate nobody ran.
        known = s.measured and s.depth_known
        edges = f"{s.edges:>7}" if known else f"{'?':>7}"
        grew = (("yes" if s.coverage_grew else "-") if known else "?")
        L.append(f"{mark}{i:<4} {s.plan_name[:33]:<34} {s.blocking:>5} {edges} "
                 f"{grew:>5} {s.kill_rate:>5.0%} "
                 f"{s.sink_fraction:>5.0%} {s.not_run:>6} {s.warnings:>5}")
    L.append("")
    if ranked and not ranked[0].shippable:
        L.append("No plan is shippable. Every candidate carries a blocking violation:")
        for r in ranked[0].reasons[:4]:
            L.append(f"  - {r}")
    elif ranked and discriminating(ranked):
        L.append(f"Winner: {ranked[0].plan_name} (producer: {ranked[0].producer}).")
        L.append("Selected by gate evidence. No producer supplied a score, a confidence or "
                 "a preference.")
    elif ranked:
        n = sum(1 for s in ranked if s.shippable)
        L.append(f"UNRANKED. {n} plan(s) are shippable and NO GATE DISTINGUISHES THEM.")
        L.append("The order above is alphabetical, which is a tie-break, not a measurement.")
        L.append("Naming a winner here would be inventing one.")
        why = _why_undiscriminating(ranked)
        if why:
            L.append("")
            L.append("The gates that would have separated them did not run:")
            for w in why:
                L.append(f"  - {w}")
            L.append("")
            L.append("Supply the target's sources (--source, plus --cflag as needed) and "
                     "re-run.")
            L.append("D2 measures whether each harness can find a planted defect and D4 "
                     "measures how")
            L.append("much of the sink surface it reaches; those are what rank a plan.")
    return "\n".join(L)
