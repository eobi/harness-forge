"""The Harness Certificate — the artifact that actually ships.

A `.c` file with no provenance is what the field ships today. This ships the plan, the
gates that were run with their evidence, the fraction of the attack surface covered, the
trust ceiling of every platform it is claimed for, and — the line nobody else prints —
**what this harness cannot find**.

Two properties are deliberate and both are unusual:

  * it reports against itself. WARN-level findings and NOT_RUN gates appear on the face of
    the certificate, not in an appendix.
  * it states what was impossible. Without that line, "we found nothing" and "we could not
    have found anything" are indistinguishable, and only the harness author knows which.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from . import platform as plat
from .ir import HarnessIR
from .gates.result import GateResult, BLOCK, WARN, FAIL, NOT_RUN

CERT_VERSION = "1.0"


@dataclass
class Certificate:
    harness: str
    ir_sha256: str
    ir_schema: str
    producer: str
    target: dict
    platforms: list[dict]
    gates: list[dict]
    surface: dict
    unreachable: list[str]
    trust: dict
    reproduction: dict
    verdict: str                       # certified | rejected | provisional
    uncertified_regions: list[str] = field(default_factory=list)
    cert_version: str = CERT_VERSION

    def to_json(self) -> dict:
        d = {"cert_version": self.cert_version, "harness": self.harness,
             "ir_sha256": self.ir_sha256, "ir_schema": self.ir_schema,
             "producer": self.producer, "verdict": self.verdict,
             "target": self.target, "platforms": self.platforms,
             "trust": self.trust, "surface": self.surface,
             "unreachable": self.unreachable,
             "uncertified_regions": self.uncertified_regions,
             "gates": self.gates, "reproduction": self.reproduction}
        return d

    def dumps(self, indent: int = 2) -> str:
        return json.dumps(self.to_json(), indent=indent)


def _surface(ir: HarnessIR, gates: list[GateResult]) -> dict:
    """What fraction of the declared attack surface this one harness touches.

    Honest coverage beats 'unlimited'. A number a reader can audit is worth more than a
    claim they cannot.
    """
    called = sorted({op.api for op in ir.sequence})
    declared = sorted(ir.apis)
    d4 = next((g for g in gates if g.gate == "D4"), None)
    sinks = d4.evidence.get("sinks_reached") if d4 and d4.ok else None
    return {
        "apis_declared": declared,
        "apis_called": called,
        "entry_points_covered": f"{len(called)}/{len(declared)}",
        "apis_not_called": [a for a in declared if a not in called],
        "sinks_reached": sinks,
        "note": "surface coverage is per-harness. A target is covered by a SUITE; the "
                "suite-level figure lives on the engagement report, not here.",
    }


def _unreachable(ir: HarnessIR, gates: list[GateResult]) -> list[str]:
    out: list[str] = []
    d7 = next((g for g in gates if g.gate == "D7"), None)
    if d7 is not None:
        out.extend(d7.evidence.get("unreachable", []))
    ceiling, best = plat.ceiling(ir.platforms)
    if ceiling < 5:
        p = plat.get(best)
        out.append(f"no platform in this claim can certify above ladder rung {ceiling} "
                   f"(best is {best}, trust ceiling {p.trust_ceiling!r})")
    d8 = next((g for g in gates if g.gate == "D8"), None)
    if d8 is not None and d8.verdict != NOT_RUN:
        if not d8.evidence.get("target_instrumented"):
            out.append(
                f"nothing inside the target: it is linked prebuilt, so the campaign saw "
                f"{d8.evidence.get('edges', 0)} edge(s) and had no coverage feedback. "
                f"Memory errors inside the library are invisible to ASan here too.")
        elif not d8.evidence.get("coverage_grew"):
            out.append(
                f"anything past {d8.evidence.get('edges', 0)} edges: coverage did not grow "
                f"during a real campaign, so the harness is not reaching deeper code")
    for g in gates:
        if g.verdict == NOT_RUN:
            out.append(f"gate {g.gate} did not run: {g.reason}")
    return out


def _trust(ir: HarnessIR) -> dict:
    per = {}
    for pid in ir.platforms:
        p = plat.get(pid)
        per[pid] = {
            "trust_ceiling": p.trust_ceiling,
            "max_rung": p.ceiling_rung,
            "sanitizers": list(p.sanitizers),
            "allocator": p.allocator,
            "crash_artifact": p.crash_artifact,
            "coverage_backends": list(p.coverage),
            "notes": p.notes,
        }
    ceiling, best = plat.ceiling(ir.platforms)
    siblings = sorted({s for pid in ir.platforms for s in plat.reachability_siblings(pid)}
                      - set(ir.platforms))
    return {
        "per_platform": per,
        "max_certifiable_rung": ceiling,
        "best_platform": best,
        "reachability_hypotheses": siblings,
        "reachability_note":
            "these platforms likely share the target's source. A finding here is a "
            "REACHABILITY HYPOTHESIS there, never a certification. Prove it with a device "
            "or simulator run before claiming it.",
    }


def _reproduction(ir: HarnessIR, emitted) -> dict:
    return {
        "target": f"{ir.target.name} {ir.target.version} {ir.target.commit}".strip(),
        "build": " ".join(emitted.build_command) if emitted else "",
        "replay_build": " ".join(emitted.driver_build_command) if emitted else "",
        "env": "ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:allocator_may_return_null=1",
        "run": f"./{ir.name}_fuzz corpus/ -max_len={ir.knobs.max_len} "
               f"-timeout={ir.knobs.timeout_s} -rss_limit_mb={ir.knobs.rss_limit_mb}",
        "note": "the platform line is not decoration: a 32-bit integer bug does not exist "
                "in a 64-bit build, so 'does not reproduce' is uninterpretable without it.",
    }


def build_certificate(ir: HarnessIR, gates: list[GateResult],
                      emitted: Optional[Any] = None) -> Certificate:
    blocking = [v for g in gates for v in g.violations if v.severity == BLOCK]
    any_failed = any(g.verdict == FAIL for g in gates)
    not_run = [g.gate for g in gates if g.verdict == NOT_RUN]

    if blocking or any_failed:
        verdict = "rejected"
    elif not_run:
        verdict = "provisional"
    else:
        verdict = "certified"

    ir_bytes = ir.dumps().encode()
    return Certificate(
        harness=ir.name,
        ir_sha256=hashlib.sha256(ir_bytes).hexdigest(),
        ir_schema=ir.schema_version,
        producer=ir.producer,
        target=ir.target.to_json(),
        platforms=[{"id": p, **{k: v for k, v in plat.get(p).__dict__.items()
                                if k in ("os", "arch", "variant", "trust_ceiling")}}
                   for p in ir.platforms],
        gates=[g.to_json() for g in gates],
        surface=_surface(ir, gates),
        unreachable=_unreachable(ir, gates),
        trust=_trust(ir),
        reproduction=_reproduction(ir, emitted),
        verdict=verdict,
        uncertified_regions=[f"{b.id} ({b.where}): {b.reason or 'raw C block'}"
                             for b in ir.raw_blocks],
    )


def render_text(cert: Certificate) -> str:
    """A certificate a person can read in thirty seconds, which is the point."""
    L: list[str] = []
    mark = {"certified": "CERTIFIED", "provisional": "PROVISIONAL",
            "rejected": "REJECTED"}[cert.verdict]
    L.append("=" * 74)
    L.append(f"HARNESS CERTIFICATE   {cert.harness}   [{mark}]")
    L.append("=" * 74)
    L.append(f"target      {cert.target.get('name')} {cert.target.get('version','')}"
             f" {cert.target.get('commit','')}".rstrip())
    L.append(f"producer    {cert.producer}")
    L.append(f"ir sha256   {cert.ir_sha256[:32]}...")
    L.append(f"platforms   {', '.join(p['id'] for p in cert.platforms)}")
    L.append(f"max rung    {cert.trust['max_certifiable_rung']} "
             f"(best: {cert.trust['best_platform']})")
    L.append("")
    L.append("GATES")
    for g in cert.gates:
        v = {"pass": "PASS ", "fail": "FAIL ", "not-run": "  -  "}[g["verdict"]]
        L.append(f"  {v} {g['gate']:<4} {g['title']}")
        if g["verdict"] == "not-run":
            L.append(f"           reason: {g['reason']}")
        for viol in g["violations"]:
            tag = {"block": "BLOCK", "warn": "warn ", "info": "info "}[viol["severity"]]
            L.append(f"           [{tag}] {viol['code']}: {viol['message']}")
            if viol.get("fix"):
                L.append(f"                   fix: {viol['fix']}")
    L.append("")
    L.append("SURFACE")
    L.append(f"  entry points covered   {cert.surface['entry_points_covered']}")
    if cert.surface["apis_not_called"]:
        L.append(f"  declared, not called   {', '.join(cert.surface['apis_not_called'])}")
    L.append("")
    L.append("WHAT THIS HARNESS CANNOT FIND")
    for u in cert.unreachable:
        L.append(f"  - {u}")
    if cert.uncertified_regions:
        L.append("")
        L.append("UNCERTIFIED REGIONS (raw C outside the schema)")
        for r in cert.uncertified_regions:
            L.append(f"  - {r}")
    if cert.trust["reachability_hypotheses"]:
        L.append("")
        L.append("REACHABILITY HYPOTHESES (not certified, shared-source platforms)")
        L.append(f"  {', '.join(cert.trust['reachability_hypotheses'])}")
        L.append(f"  {cert.trust['reachability_note']}")
    L.append("")
    L.append("REPRODUCTION")
    for k, v in cert.reproduction.items():
        if v:
            L.append(f"  {k:<14} {v}")
    L.append("=" * 74)
    return "\n".join(L)
