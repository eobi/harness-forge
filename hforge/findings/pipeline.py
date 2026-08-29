"""Crash in, finding out — the whole F pipeline in one place.

The engine's discipline used to stop at the campaign. This is the rest of it: reproduce,
minimise, attribute, replay across variants, rule out the instrumentation, check the ledger,
place it on the ladder, and state what it does not establish. Then audit the SET.

The pipeline builds nothing. Every binary is supplied by the caller, because the thing that
judges a finding should not also be the thing that produced it — the same separation the
gates enforce between proposer and prover.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import platform as plat
from . import auditor, gates, ladder, report


@dataclass
class Inputs:
    """Everything the pipeline needs. Missing pieces produce NOT_RUN, never a guess."""
    crashes: list                              # list[gates.Crash]
    instrumented: Optional[gates.Replay] = None
    baseline: Optional[gates.Replay] = None    # same harness, no sanitizer
    variants: Optional[list] = None            # list[gates.Replay], other builds
    ledger: Optional[dict] = None
    independent_oracle: str = ""               # a tool that is NOT the discovering one
    provenance: Optional[report.Provenance] = None
    campaign_seconds: float = 0.0
    null_harness_faults: Optional[int] = None
    platform_id: str = "linux-x86_64-glibc"


def triage_one(crash: gates.Crash, inp: Inputs, index: int) -> report.Finding:
    ceiling = plat.get(inp.platform_id).ceiling_rung if inp.platform_id in plat.PLATFORMS \
        else 6

    g1 = gates.f1_reproduce(crash, inp.instrumented)
    g2, minimised = gates.f2_minimise(crash, inp.instrumented)
    g3 = gates.f3_attribute(crash)
    # The instrumented build is itself a variant, and the one every other build is being
    # compared against. Passing only the extra builds meant a single `--variant` produced
    # "fewer than two builds" and the oracle never ran.
    compare = ([inp.instrumented] if inp.instrumented else []) + list(inp.variants or [])
    g4 = gates.f4_variant(crash, compare if len(compare) > 1 else None)
    g5 = gates.f5_artifact(crash, inp.instrumented, inp.baseline)
    g6 = gates.f6_novelty(crash, minimised, inp.ledger)

    partial = [g1, g2, g3, g4, g5, g6]
    g7 = gates.f7_rung(crash, partial, independent_oracle=inp.independent_oracle,
                       ceiling=ceiling)
    rung = int(g7.evidence.get("rung", 0))
    g8 = gates.f8_exclusions(crash, partial + [g7], rung)

    return report.Finding(
        id=f"F-{index:04d}",
        input_sha256=hashlib.sha256(minimised).hexdigest(),
        input_bytes=minimised,
        rung=rung,
        rung_reason=str(g7.evidence.get("reason", "")),
        signature=str(g6.evidence.get("signature", "")) or gates._signature(crash.report),
        gates=partial + [g7, g8],
        provenance=inp.provenance or report.Provenance(),
        report_excerpt=(crash.report or "")[:4000])


def triage(inp: Inputs) -> tuple:
    """Every crash judged, then the set audited. Returns (findings, auditor results)."""
    findings = [triage_one(c, inp, i + 1) for i, c in enumerate(inp.crashes)]

    audit_rows = []
    for f in findings:
        f3 = next((g for g in f.gates if g.gate == "F3"), None)
        audit_rows.append({
            "signature": f.signature,
            "input_sha": f.input_sha256,
            "rung": f.rung,
            "discovering_oracle": (f3.evidence.get("discovering_oracle") if f3 else ""),
            "independent_oracle": inp.independent_oracle,
        })

    audit = auditor.run(auditor.AuditInput(
        findings=audit_rows,
        null_harness_faults=inp.null_harness_faults,
        campaign_seconds=inp.campaign_seconds,
        corpus_size=len(inp.crashes)))
    return findings, audit


def summarise(findings: list, audit: list) -> str:
    reportable = [f for f in findings if f.reportable]
    by_rung: dict = {}
    for f in findings:
        by_rung.setdefault(f.rung, []).append(f)
    distinct = len({f.signature for f in findings if f.signature}) or len(findings)

    L = ["", "=" * 74, "TRIAGE SUMMARY", "=" * 74,
         f"  crashes in           {len(findings)}",
         f"  distinct signatures  {distinct}",
         f"  REPORTABLE           {len(reportable)}",
         f"  ours, not theirs     {len(findings) - len(reportable)}", ""]
    for n in sorted(by_rung, reverse=True):
        L.append(f"  rung {n}  {len(by_rung[n]):>3}  {ladder.describe(n).claim}")
    if not reportable and findings:
        L += ["", "Nothing here is reportable. Every crash was refused by a gate that says it",
              "belongs to us — the harness's own memory, the instrumentation, or a defect",
              "already known. That is a correct outcome, not a failed run."]
    L.append(auditor.render(audit))
    return "\n".join(L)
