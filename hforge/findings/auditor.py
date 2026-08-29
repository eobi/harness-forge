"""The Auditor — controls over a finding SET.

The corpus calls this *"the component nobody builds, because it makes your numbers worse."*
That is exactly the reason to build it. `plancheck` audits the repository against its plan;
nothing has ever audited a set of findings, and a set of findings is where the incentive to
self-deceive is strongest.

Every control here can only reduce a claim. None can promote one.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from ..gates.result import BLOCK, INFO, WARN, GateResult, Violation, decide, not_run


@dataclass
class AuditInput:
    findings: list                          # list[dict]: signature, rung, harness, input_sha
    null_harness_faults: Optional[int] = None   # faults from a harness that calls nothing
    campaign_seconds: float = 0.0
    corpus_size: int = 0
    independent_build_agrees: Optional[bool] = None


def a1_circularity(findings: list) -> GateResult:
    """Did the tool that discovered a fault also serve as its confirmation?"""
    title = "circularity: the discovering oracle is not the confirming oracle"
    bad = [f for f in findings
           if f.get("independent_oracle") and
           f["independent_oracle"] == f.get("discovering_oracle")]
    v = []
    if bad:
        v.append(Violation("A1.CIRCULAR", BLOCK,
                           f"{len(bad)} finding(s) are confirmed by the same tool that found "
                           f"them. ASan confirming ASan is one witness, not two."))
    return decide("A1", title, v, checked=len(findings), circular=len(bad))


def a2_trivial_baseline(inp: AuditInput) -> GateResult:
    """How many faults does a harness that calls NOTHING produce on the same corpus?

    If a null harness produces a comparable number, the suite is finding its own defects and
    the count says nothing about the target.
    """
    title = "trivial baseline: a null harness on the same corpus"
    if inp.null_harness_faults is None:
        return not_run("A2", title,
                       "no null-harness run was supplied; without it the finding count has "
                       "no floor to be measured against")
    n = len(inp.findings)
    v = []
    if inp.null_harness_faults >= max(1, n // 2):
        v.append(Violation("A2.BASELINE_COMPARABLE", BLOCK,
                           f"a harness calling nothing produced {inp.null_harness_faults} "
                           f"fault(s) against {n} from the real suite. The suite is largely "
                           f"finding itself."))
    return decide("A2", title, v, findings=n, null_faults=inp.null_harness_faults)


def a3_grouping(findings: list) -> GateResult:
    """Are N findings actually one defect reached N ways?

    The most common form of dishonesty in this field is an inflated count, and it is usually
    not deliberate — it is what happens when nobody groups by crash signature.
    """
    title = "grouping: distinct defects, not one defect counted many times"
    sigs = Counter(f.get("signature") or f.get("input_sha", "") for f in findings)
    distinct = len([s for s in sigs if s])
    v = []
    worst = sigs.most_common(1)[0] if sigs else ("", 0)
    if worst[1] > 1:
        v.append(Violation("A3.REGROUPED", INFO,
                           f"{len(findings)} crash(es) group into {distinct} distinct "
                           f"signature(s); the largest group holds {worst[1]}. Report the "
                           f"grouped number."))
    return decide("A3", title, v, crashes=len(findings), distinct=distinct)


def a4_capacity(inp: AuditInput) -> GateResult:
    """Could a campaign of this length distinguish this many findings?"""
    title = "capacity: the run was long enough to support the claim"
    n = len({f.get("signature") for f in inp.findings if f.get("signature")}) or \
        len(inp.findings)
    v = []
    if inp.campaign_seconds and n and inp.campaign_seconds / max(1, n) < 60:
        v.append(Violation("A4.THIN", WARN,
                           f"{n} distinct finding(s) from {inp.campaign_seconds:.0f}s of "
                           f"campaign — under a minute each. Short runs produce shallow "
                           f"crashes and over-reading them is how counts get inflated."))
    return decide("A4", title, v, distinct=n, seconds=inp.campaign_seconds)


def a5_transfer(inp: AuditInput) -> GateResult:
    """Does the set hold on an independently produced build?"""
    title = "transfer: the findings survive a different build of the same target"
    if inp.independent_build_agrees is None:
        return not_run("A5", title,
                       "no independent build was supplied, so toolchain-specific artifacts "
                       "cannot be ruled out")
    v = []
    if not inp.independent_build_agrees:
        v.append(Violation("A5.NO_TRANSFER", BLOCK,
                           "the findings do not reproduce on an independently produced "
                           "build, which usually means they belong to the toolchain rather "
                           "than to the target."))
    return decide("A5", title, v, agrees=inp.independent_build_agrees)


def run(inp: AuditInput) -> list:
    return [a1_circularity(inp.findings), a2_trivial_baseline(inp), a3_grouping(inp.findings),
            a4_capacity(inp), a5_transfer(inp)]


def render(results: list) -> str:
    L = ["", "THE AUDITOR — controls over the finding SET", "-" * 66]
    for g in results:
        mark = {"pass": " ok ", "fail": "FAIL", "not-run": " -- "}[g.verdict]
        L.append(f"[{mark}] {g.gate}  {g.title}")
        if g.reason:
            L.append(f"        {g.reason}")
        for v in g.violations:
            L.append(f"        [{v.severity}] {v.code}: {v.message}")
    L.append("")
    L.append("Every control here can only reduce a claim. That is the point of having them.")
    return "\n".join(L)
