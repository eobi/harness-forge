"""Gate results — the shared vocabulary of the certification layer.

A gate never returns a boolean. It returns a verdict plus the evidence that produced it,
because a certificate a reader cannot check is not a certificate.

Three verdicts, and the third one matters most:

  PASS        the gate ran and the harness satisfied it
  FAIL        the gate ran and the harness violated it
  NOT_RUN     the gate could not run here, and the reason is recorded

NOT_RUN exists so that an absent check never reads as a passed one. A campaign that found
nothing because a lens was missing is a different result from a campaign that found nothing
because there was nothing there, and the two must not look alike.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

PASS = "pass"
FAIL = "fail"
NOT_RUN = "not-run"

BLOCK = "block"      # the harness must not ship
WARN = "warn"        # ships, with the finding recorded on the certificate
INFO = "info"        # recorded for the reader, not a defect


@dataclass
class Violation:
    code: str                  # e.g. "S2.CSTRING"
    severity: str              # BLOCK | WARN | INFO
    message: str
    where: str = ""            # op id, slice id, resource id
    principle: str = ""        # P1..P4, mapped to the published correctness principles
    fix: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class GateResult:
    gate: str                  # "S1", "D3", ...
    title: str
    verdict: str               # PASS | FAIL | NOT_RUN
    violations: list[Violation] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""           # required when verdict is NOT_RUN

    @property
    def blocking(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == BLOCK]

    @property
    def ok(self) -> bool:
        return self.verdict == PASS

    def to_json(self) -> dict:
        return {"gate": self.gate, "title": self.title, "verdict": self.verdict,
                "reason": self.reason,
                "violations": [v.to_json() for v in self.violations],
                "evidence": self.evidence}


def passed(gate: str, title: str, **evidence) -> GateResult:
    return GateResult(gate=gate, title=title, verdict=PASS, evidence=evidence)


def failed(gate: str, title: str, violations: list[Violation], **evidence) -> GateResult:
    return GateResult(gate=gate, title=title, verdict=FAIL, violations=violations,
                      evidence=evidence)


def not_run(gate: str, title: str, reason: str) -> GateResult:
    return GateResult(gate=gate, title=title, verdict=NOT_RUN, reason=reason)


def decide(gate: str, title: str, violations: list[Violation], **evidence) -> GateResult:
    """PASS when nothing blocking was found; violations at WARN/INFO still ride along."""
    if any(v.severity == BLOCK for v in violations):
        return failed(gate, title, violations, **evidence)
    r = passed(gate, title, **evidence)
    r.violations = violations
    return r
