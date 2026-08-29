"""Provenance and the disclosure artifact.

A maintainer's first question is *"how do I reproduce this"* and the second is *"what exactly
did you run"*. A report that cannot answer both is asking to be ignored, and a system whose
whole argument is about proof cannot hand over a claim with no chain behind it.

Certificates already carry `ir_sha256`. Nothing else in the chain was identified, so a
finding could not be tied back to the plan and build that produced it:

    source commit -> plan (ir_sha256) -> build (compiler, flags, sanitizers)
                  -> corpus (seed + dictionary hashes) -> input (sha256)
                  -> finding (rung, gates, exclusions)

The disclosure artifact carries the whole chain, states the rung, and — the part nobody else
ships — states what the finding does **not** establish. Coordinated disclosure discipline is
the operator's; this module never contacts anyone.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import ladder

ARTIFACT_VERSION = "finding/1"


@dataclass
class Provenance:
    target: str = ""
    source_commit: str = ""
    plan_name: str = ""
    ir_sha256: str = ""
    compiler: str = ""
    build_flags: list = field(default_factory=list)
    sanitizers: list = field(default_factory=list)
    platform: str = ""
    dictionary_sha256: str = ""
    seed_shas: list = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


def git_commit(path: str) -> str:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:                                            # noqa: BLE001
        return ""


@dataclass
class Finding:
    id: str
    input_sha256: str
    input_bytes: bytes
    rung: int
    rung_reason: str
    signature: str
    gates: list = field(default_factory=list)
    provenance: Provenance = field(default_factory=Provenance)
    report_excerpt: str = ""

    @property
    def reportable(self) -> bool:
        """Whether this may be sent to a maintainer at all.

        A blocking F-gate means the finding is ours, not theirs — harness-owned memory, an
        instrumentation artifact, an already-known defect, or something that does not
        reproduce. Sending one of those costs a maintainer time and costs us standing.
        """
        return not any(v.severity == "block" for g in self.gates for v in g.violations)

    def to_json(self) -> dict:
        return {
            "artifact_version": ARTIFACT_VERSION,
            "id": self.id,
            "reportable": self.reportable,
            "rung": self.rung,
            "rung_claim": ladder.describe(self.rung).claim,
            "rung_oracle": ladder.describe(self.rung).oracle,
            "rung_reason": self.rung_reason,
            "signature": self.signature,
            "input_sha256": self.input_sha256,
            "input_size": len(self.input_bytes),
            "provenance": self.provenance.to_json(),
            "gates": [g.to_json() for g in self.gates],
            "unestablished": next((g.evidence.get("unestablished", [])
                                   for g in self.gates if g.gate == "F8"), []),
        }

    def dumps(self, indent: int = 2) -> str:
        return json.dumps(self.to_json(), indent=indent)


def render(f: Finding) -> str:
    r = ladder.describe(f.rung)
    L = [
        "=" * 74,
        f"FINDING {f.id}   [{'REPORTABLE' if f.reportable else 'NOT REPORTABLE'}]",
        "=" * 74,
        f"rung        {f.rung} — {r.claim}",
        f"oracle      {r.oracle}",
        f"why here    {f.rung_reason}",
        f"input       {f.input_sha256[:32]}...  ({len(f.input_bytes)} bytes)",
        f"signature   {f.signature or '-'}",
        "",
        "PROVENANCE",
    ]
    p = f.provenance
    for k, v in (("target", p.target), ("commit", p.source_commit),
                 ("plan", f"{p.plan_name} ({p.ir_sha256[:16]}...)" if p.ir_sha256
                  else p.plan_name),
                 ("compiler", p.compiler), ("sanitizers", ",".join(p.sanitizers)),
                 ("platform", p.platform),
                 ("dictionary", p.dictionary_sha256[:16] if p.dictionary_sha256 else ""),
                 ("seeds", f"{len(p.seed_shas)} mined")):
        if v:
            L.append(f"  {k:<12}{v}")

    L += ["", "GATES"]
    for g in f.gates:
        mark = {"pass": " ok ", "fail": "FAIL", "not-run": " -- "}[g.verdict]
        L.append(f"  [{mark}] {g.gate}  {g.title}")
        if g.reason:
            L.append(f"          {g.reason}")
        for v in g.violations:
            L.append(f"          [{v.severity}] {v.code}: {v.message}")
            if v.fix:
                L.append(f"                  fix: {v.fix}")

    unest = next((g.evidence.get("unestablished", []) for g in f.gates if g.gate == "F8"), [])
    if unest:
        L += ["", "WHAT THIS FINDING DOES NOT ESTABLISH"]
        L += [f"  - {u}" for u in unest]

    L += ["", "REPRODUCTION"]
    L.append(f"  the input is attached as {f.input_sha256[:16]}.bin")
    L.append(f"  build the plan named above and run: ./<harness>_replay {f.input_sha256[:16]}.bin")
    if not f.reportable:
        L += ["", "This finding is NOT reportable: a blocking gate above says it is ours, "
                  "not theirs.", "Sending it would cost a maintainer time and cost us "
                  "standing."]
    L.append("=" * 74)
    return "\n".join(L)


def write(f: Finding, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    d = out_dir / f.id
    d.mkdir(exist_ok=True)
    (d / "finding.json").write_text(f.dumps())
    (d / "finding.txt").write_text(render(f))
    (d / f"{f.input_sha256[:16]}.bin").write_bytes(f.input_bytes)
    if f.report_excerpt:
        (d / "sanitizer.txt").write_text(f.report_excerpt)
    return d
