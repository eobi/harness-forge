"""The JVM ladder. Same shape, different claims — and it has to exist or nothing is reportable.

`findings/ladder.py` rung 3 is `R3_MEMORY_SAFETY`, *"it is a memory-safety violation of the
target"*, and its oracle is *"an oracle INDEPENDENT of the one that discovered it"* — a second
sanitizer, a debug allocator, valgrind. **There is no ASan for the JVM.** Ship the C ladder
against Java and rung 3 is unreachable by construction, so every Java finding caps at rung 2,
`Finding.reportable` is never true, and the engine is inert while every gate reads green. That
is the same failure as the sqlite chain that emitted flawless C and executed nothing, arriving
one layer up.

What carries over is the discipline, not the table:

  * a finding sits at **the highest rung whose oracle passed**, never the one hoped for
  * **rung 3 demands independence** — the thing that discovered a fault may not be the thing
    that confirms it
  * a platform **ceiling downgrades, it does not drop**

What changes is what each rung claims, and one rung inverts. In C, rung 5 (heap layout or
control-flow influence) is a hard argument built on top of memory corruption. On the JVM
there is no memory corruption to build on, but a Jazzer sanitizer firing — SQL injection, a
deserialization gadget, SSRF, path traversal — is *direct* evidence that attacker data
crossed a trust boundary, and it needs no layout argument at all. So rung 5 here is
**easier to reach and stronger when reached**, which is a real difference between the
languages rather than a translation of one.

Rung 3's independence problem has a good JVM answer and it is not a sanitizer: **`-Xint`
versus the JIT**. A fault that reproduces interpreted AND compiled is the library's. One that
appears only under C2 is a JIT artifact or an instrumentation effect — the same question
`devices.decide_differential` was written to answer on Android, asked of a different pair.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..findings.ladder import Rung

J0_PROCESSED = 0
J1_ESCAPED = 1
J2_REPRODUCIBLE = 2
J3_DEFECT = 3
J4_INPUT_DERIVED = 4
J5_TRUST_BOUNDARY = 5
J6_EXPLOITABLE = 6

LADDER = (
    Rung(J0_PROCESSED, "the input was processed and nothing escaped",
         "a clean run"),
    Rung(J1_ESCAPED, "an exception escaped the call",
         "a stack trace",
         "on the JVM this is NOT yet evidence of anything: a parser rejecting a random byte "
         "string throws, and that is the parser working"),
    Rung(J2_REPRODUCIBLE, "the escape is real and reducible",
         "F1 reproduction rate + F2 minimised reproducer",
         "unchanged from C, and most honest findings still stop here or at rung 3"),
    Rung(J3_DEFECT, "the exception is a DEFECT rather than the documented contract",
         "the classifier in java/exceptions.py: a JVM check fired in library frames, and the "
         "method does not declare it",
         "this replaces 'memory-safety violation'. Java's bounds check IS the always-on "
         "memory-safety oracle, so an ArrayIndexOutOfBoundsException in library code is the "
         "moral equivalent of a sanitizer report — the JVM caught what C would have let "
         "through"),
    Rung(J4_INPUT_DERIVED, "the attacker influences the offending value",
         "the index, length, class name or capacity is demonstrably derived from the input"),
    Rung(J5_TRUST_BOUNDARY, "attacker data crossed a trust boundary",
         "a Jazzer semantic sanitizer: injection, deserialization, SSRF, path traversal, "
         "reflective call",
         "STRONGER than its C counterpart, not weaker: no heap-layout argument is needed, "
         "because the sanitizer fired on the data reaching the sink"),
    Rung(J6_EXPLOITABLE, "exploitable in the configuration the target actually ships",
         "an end-to-end demonstration in that configuration",
         "not reachable from a fuzzing campaign alone"),
)

BY_N = {r.n: r for r in LADDER}


def describe(n: int) -> Rung:
    return BY_N.get(n, LADDER[0])


def assign(*, escaped: bool, reproduce_rate: float, minimised: bool,
           verdict: str = "", attributed_to_library: bool = False,
           independent_oracle: bool = False, input_derived: bool = False,
           sanitizer: str = "", end_to_end: bool = False, ceiling: int = 6) -> tuple:
    """The highest rung whose oracle passed, and why it stopped there.

    `verdict` is `java/exceptions.classify`'s output. It is load-bearing at rung 3: without
    it a `NumberFormatException` from a parser fed garbage would climb the same ladder as a
    genuine defect, and the engine would report a library's own error path.
    """
    from . import exceptions as jx

    if not escaped:
        return J0_PROCESSED, "no exception escaped"

    if verdict == jx.HARNESS:
        return J1_ESCAPED, ("the exception escaped from HARNESS frames. This crash is ours, "
                            "not the target's, and it cannot climb.")
    if verdict == jx.CONTRACT:
        return J1_ESCAPED, ("the exception is the library's DOCUMENTED way of rejecting "
                            "input, not a defect. A parser that throws on a random byte "
                            "string is a parser working.")
    if verdict == jx.EXHAUSTION:
        return J1_ESCAPED, ("resource exhaustion without an amplification ratio. A large "
                            "input consuming a lot of memory is arithmetic; supply the ratio "
                            "and this can be judged.")

    rung, why = J1_ESCAPED, "an exception escaped but it did not reproduce reliably"
    if reproduce_rate > 0.0 and minimised:
        rung, why = J2_REPRODUCIBLE, ("reproducible and minimised, but not yet shown to be a "
                                      "defect rather than the contract")
    elif reproduce_rate > 0.0:
        why = "reproduces, but no minimised reproducer exists"
    elif minimised:
        why = "a minimised input exists but the exception did not reproduce on replay"

    if rung >= J2_REPRODUCIBLE and verdict == jx.DEFECT and attributed_to_library:
        if independent_oracle:
            rung, why = J3_DEFECT, ("classified a defect, attributed to library frames, and "
                                    "confirmed by an independent execution mode; no evidence "
                                    "the attacker controls the value")
        else:
            why = ("classified a defect and attributed to the library, but only one "
                   "execution mode has seen it. Replay under -Xint as well: a fault that "
                   "appears only under the JIT is a JIT artifact, not a library bug.")
    elif rung >= J2_REPRODUCIBLE and verdict == jx.DEFECT and not attributed_to_library:
        why = ("reproducible, but no frame belongs to a declared library package, so the "
               "exception cannot be attributed to the target")
    elif rung >= J2_REPRODUCIBLE and verdict == jx.UNKNOWN:
        why = ("reproducible, but the exception is neither a JVM check, a documented "
               "rejection, nor the library's own type. Unclassified is not the same as safe.")

    if rung >= J3_DEFECT and input_derived:
        rung, why = J4_INPUT_DERIVED, ("the offending value is input-derived; no trust "
                                       "boundary shown")
    if sanitizer and rung >= J2_REPRODUCIBLE:
        # A sanitizer report is direct evidence and does not need rung 4 beneath it: the
        # tool fired BECAUSE attacker data reached the sink.
        rung, why = J5_TRUST_BOUNDARY, (f"a Jazzer sanitizer reported {sanitizer}: attacker "
                                        f"data reached a sink that crosses a trust boundary")
    if rung >= J5_TRUST_BOUNDARY and end_to_end:
        rung, why = J6_EXPLOITABLE, "demonstrated end to end in a shipped configuration"

    if rung > ceiling:
        return ceiling, (f"evidence would support rung {rung}, but the platform's trust "
                         f"ceiling is {ceiling}: {describe(ceiling).claim}. Downgraded, "
                         f"not dropped.")
    return rung, why


def for_language(language: str):
    """The ladder a plan's language is judged on.

    Selected rather than overloaded. A rung number means something different on each, and a
    certificate that prints 'rung 3' without saying which ladder is claiming more precision
    than it has.
    """
    from ..findings import ladder as c_ladder
    return (LADDER, assign, describe) if (language or "").lower() in ("java", "jvm", "kotlin") \
        else (c_ladder.LADDER, c_ladder.assign, c_ladder.describe)
