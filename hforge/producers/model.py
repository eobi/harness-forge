"""A model producer — the boundary a model's proposals pass through.

`llm.propose(...) -> list[HarnessIR]`, slotting in beside `header_graph`. The doctrine is one
sentence and this module is where it becomes code:

    A model proposes IR. It never emits C, never scores itself, never decides anything.

Deliberately, this module does **not** call an API. It accepts IR from wherever a model
produced it — over MCP, from a file, from a fleet — and enforces the rules at the door. That
separation matters: the boundary must hold whoever the proposer is, and a boundary tangled up
with one vendor's client is a boundary that gets bypassed the day the vendor changes.

What is refused here, before any gate runs:

  * **a raw block.** Verbatim C that no static gate can see into. From a human author it is
    an escape hatch marked UNCERTIFIED; from a model it is a way to bypass the entire static
    layer, and it is refused outright.
  * **a score, confidence or preference.** `rank.render()` refuses to name a winner when no
    gate distinguishes the candidates. A producer expressing certainty is a way around that
    refusal, so the fields are stripped rather than ignored.
  * **a producer string that hides provenance.** It is rewritten to `llm:<model>@<version>`
    so a certificate says who proposed the plan. The ranking never sees it.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Optional

from ..ir import HarnessIR, Knobs, Target

# Keys a proposer might attach to argue for its own plan. Stripped, not honoured.
_PERSUASION = ("score", "confidence", "certainty", "priority", "rank", "preference",
               "recommended", "likelihood", "quality", "rating")


class Rejected(Exception):
    """A proposal the boundary will not pass into the gates."""


def _strip_persuasion(d: dict, where: str, notes: list) -> dict:
    out = {}
    for k, v in d.items():
        if k.lower() in _PERSUASION:
            notes.append(f"{where}: dropped {k!r} — a producer supplies no score, and the "
                         f"ranking refuses to name a winner when no gate distinguishes the "
                         f"candidates")
            continue
        out[k] = _strip_persuasion(v, f"{where}.{k}", notes) if isinstance(v, dict) else v
    return out


def accept(payload, *, model: str = "unknown", version: str = "",
           target: Optional[Target] = None, platforms: Optional[list] = None,
           knobs: Optional[Knobs] = None) -> tuple:
    """One model proposal in, one `HarnessIR` out — or `Rejected`.

    Returns `(ir, notes)`, where notes records everything the boundary changed. Silent
    normalisation would make the boundary invisible, and an invisible boundary is one nobody
    checks.
    """
    notes: list = []
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except Exception as e:                                   # noqa: BLE001
            raise Rejected(f"not valid JSON: {e}")
    if not isinstance(payload, dict):
        raise Rejected("a proposal must be a JSON object describing one Harness IR plan")

    payload = _strip_persuasion(payload, "plan", notes)

    if payload.get("raw_blocks"):
        raise Rejected(
            "the plan carries a raw_block. That is verbatim C which no static gate can see "
            "into — it is marked UNCERTIFIED precisely because the gates are blind to it, "
            "and a model that can emit one has bypassed the entire static layer. Express the "
            "construct in IR, or drop the entry point.")

    for op in payload.get("sequence", []) or []:
        if "code" in op or "c" in op:
            raise Rejected(f"op {op.get('id', '?')!r} carries inline C. A producer proposes "
                           f"IR; the emitter writes the C.")

    try:
        ir = HarnessIR.from_json(payload)
    except Exception as e:                                       # noqa: BLE001
        raise Rejected(f"not valid Harness IR: {type(e).__name__}: {e}")

    provenance = f"llm:{model}" + (f"@{version}" if version else "")
    if ir.producer != provenance:
        notes.append(f"producer rewritten to {provenance!r} so the certificate records who "
                     f"proposed this; the ranking never reads it")
    ir = replace(ir, producer=provenance)

    if target is not None:
        # The TARGET is the operator's, not the proposer's: sources, include dirs, cflags and
        # link libs decide what gets compiled and run, and a proposal that could set them
        # would be choosing what the machine executes.
        if payload.get("target") and payload["target"].get("sources"):
            notes.append("target.sources from the proposal were discarded; what gets "
                         "compiled is the operator's decision, not the proposer's")
        ir = replace(ir, target=target)
    if platforms:
        ir = replace(ir, platforms=list(platforms))
    if knobs is not None:
        ir = replace(ir, knobs=knobs)

    return ir, notes


def propose(payloads: Iterable, *, model: str = "unknown", version: str = "",
            target: Optional[Target] = None, platforms: Optional[list] = None,
            knobs: Optional[Knobs] = None) -> tuple:
    """The producer interface, same shape as `header_graph.propose`.

    Returns `(plans, rejections)`. A rejection is not an error to be swallowed: it is the
    boundary doing its job, and the count belongs in the session record beside
    *plans proposed versus plans that survived the gates*.
    """
    plans, rejected = [], []
    for i, p in enumerate(payloads):
        try:
            ir, notes = accept(p, model=model, version=version, target=target,
                               platforms=platforms, knobs=knobs)
            plans.append(ir)
            if notes:
                rejected.append({"index": i, "accepted": True, "adjustments": notes})
        except Rejected as e:
            rejected.append({"index": i, "accepted": False, "reason": str(e)})
    return plans, rejected


def load(path: str, **kw) -> tuple:
    """Proposals from a file: one JSON object, or a list of them."""
    data = json.loads(Path(path).read_text())
    return propose(data if isinstance(data, list) else [data], **kw)
