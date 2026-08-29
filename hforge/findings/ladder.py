"""The exploitability ladder — what a finding actually proves.

`platform.py` has cited rung numbers since Phase 1 — `TRUST_FULL` is annotated *"rung 5
reachable"*, `TRUST_SANITIZER_LIMITED` *"rung 4 ceiling"* — for a ladder that was never
implemented. Every certificate issued so far named a ceiling on a scale that did not exist.
This is that scale.

One oracle per rung. A finding sits at **the highest rung whose oracle passed**, never at the
one somebody hoped for, and the gap between those two is where this field does most of its
damage: a rung-2 observation written up as a rung-5 claim.

Rung 3 carries the thesis:

> *the proof may never come from the thing that proposed it*

ASan finding a fault and ASan confirming it is one witness, not two. Rung 3 requires an
oracle **independent of the one that discovered the crash** — a different sanitizer, a debug
allocator, valgrind. Without that, a finding stops at rung 2 no matter how convincing the
report reads.
"""
from __future__ import annotations

from dataclasses import dataclass

# Rung ids, low to high.
R0_PROCESSED = 0
R1_FAULT = 1
R2_REPRODUCIBLE = 2
R3_MEMORY_SAFETY = 3
R4_ATTACKER_INFLUENCED = 4
R5_LAYOUT_OR_CONTROL = 5
R6_EXPLOITABLE = 6


@dataclass(frozen=True)
class Rung:
    n: int
    claim: str
    oracle: str
    note: str = ""


LADDER = (
    Rung(R0_PROCESSED, "the input was processed and nothing faulted",
         "a clean run"),
    Rung(R1_FAULT, "a fault was observed",
         "a sanitizer report or a fatal signal",
         "one observation, possibly of the harness rather than the target"),
    Rung(R2_REPRODUCIBLE, "the fault is real and reducible",
         "F1 reproduction rate + F2 minimised reproducer",
         "most honest findings stop here or at rung 3, and saying so IS the product"),
    Rung(R3_MEMORY_SAFETY, "it is a memory-safety violation of the target",
         "an oracle INDEPENDENT of the one that discovered it, plus F3 attributing the "
         "access to the target rather than the harness",
         "ASan confirming ASan is one witness, not two"),
    Rung(R4_ATTACKER_INFLUENCED, "the attacker influences the offending access",
         "the offset or the content is demonstrably derived from the input"),
    Rung(R5_LAYOUT_OR_CONTROL, "the attacker influences allocation layout or control flow",
         "heap-layout or pointer influence demonstrated, not argued"),
    Rung(R6_EXPLOITABLE, "exploitable in the configuration the target actually ships",
         "an end-to-end demonstration in that configuration",
         "not reachable from a fuzzing campaign alone"),
)

BY_N = {r.n: r for r in LADDER}


def describe(n: int) -> Rung:
    return BY_N.get(n, LADDER[0])


def assign(*, faulted: bool, reproduce_rate: float, minimised: bool,
           attributed_to_target: bool, independent_oracle: bool,
           input_derived_access: bool = False, layout_or_control: bool = False,
           end_to_end: bool = False, ceiling: int = 6) -> tuple:
    """The highest rung whose oracle passed, and why it stopped there.

    Pure, so the rung a finding receives can be tested without producing a crash. `ceiling`
    is the platform's trust ceiling: a finding seen only under DBI cannot be promoted past
    what that platform can witness, however good the evidence looks.
    """
    if not faulted:
        return R0_PROCESSED, "no fault was observed"

    rung, why = R1_FAULT, "a fault was observed but it did not reproduce reliably"

    if reproduce_rate > 0.0 and minimised:
        rung, why = R2_REPRODUCIBLE, ("reproducible and minimised, but no oracle independent "
                                      "of the discovering sanitizer has confirmed it")
    elif reproduce_rate > 0.0:
        why = "reproduces, but no minimised reproducer exists"
    elif minimised:
        why = "a minimised input exists but the fault did not reproduce on replay"

    if rung >= R2_REPRODUCIBLE and attributed_to_target and independent_oracle:
        rung, why = R3_MEMORY_SAFETY, ("confirmed by an independent oracle and attributed to "
                                       "the target; no evidence the attacker controls the "
                                       "access")
    elif rung >= R2_REPRODUCIBLE and not attributed_to_target:
        why = ("reproducible, but the offending access is the HARNESS's memory, not the "
               "target's")
    elif rung >= R2_REPRODUCIBLE and not independent_oracle:
        why = ("reproducible and attributed to the target, but only the sanitizer that "
               "discovered it has confirmed it — one witness, not two")

    if rung >= R3_MEMORY_SAFETY and input_derived_access:
        rung, why = R4_ATTACKER_INFLUENCED, ("the offending access is input-derived; no "
                                             "layout or control-flow influence shown")
    if rung >= R4_ATTACKER_INFLUENCED and layout_or_control:
        rung, why = R5_LAYOUT_OR_CONTROL, ("layout or control-flow influence shown; not "
                                           "demonstrated end to end in a shipped "
                                           "configuration")
    if rung >= R5_LAYOUT_OR_CONTROL and end_to_end:
        rung, why = R6_EXPLOITABLE, "demonstrated end to end in a shipped configuration"

    if rung > ceiling:
        return ceiling, (f"evidence would support rung {rung}, but the platform's trust "
                         f"ceiling is {ceiling}: {describe(ceiling).claim}. Downgraded, "
                         f"not dropped.")
    return rung, why
