"""Is this exception a defect, or is it the library's documented contract?

This is Java's `S2` — the gate that pays for the whole module — and it is the reason the
build order in `plans/12-JAVA.md` puts it before the emitter.

`NumberFormatException` from a parser handed garbage **is the parser working**. A JVM fuzzer
without this classifier reports thousands of findings that are all documented behaviour, and
every gate downstream is then judging noise: F1 faithfully reproduces it, F2 minimises it,
the Auditor groups it, and a maintainer is emailed about their own error path. In C the
equivalent mistake is impossible — nothing declares `throws SIGSEGV`.

Three questions, in order, because the later ones only make sense once the earlier ones pass:

  1. **Did anything actually escape?**   A caught exception is not an event.
  2. **Whose frame threw it?**           An NPE inside the harness is ours. This is `F3`
                                         applied to a stack trace instead of an allocation
                                         stack, and it is the easier of the two.
  3. **Is this class of exception a defect for this method?**  A `throws` clause is the
                                         library telling us in advance that this is not a bug.

Resource exhaustion is deliberately NOT decided by class. `OutOfMemoryError` is a finding
when a 40-byte input consumes 2GB and arithmetic when a 2MB input does; the ratio is the
evidence and the verdict is refused without it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ── verdicts ─────────────────────────────────────────────────────────────────
CONTRACT = "contract"        # the library behaving as documented. Not a finding.
DEFECT = "defect"            # a genuine bug in the library
HARNESS = "harness"          # ours, not theirs
EXHAUSTION = "exhaustion"    # only a finding with an amplification ratio
UNKNOWN = "unknown"

# Java's bounds check is the always-on memory-safety oracle. One of these firing INSIDE the
# library is the moral equivalent of an ASan report: the JVM caught a memory error that C
# would have let through silently. They are never part of a sane API contract for a parser
# handed bytes.
_ALWAYS_DEFECT = {
    "java.lang.NullPointerException",
    "java.lang.ArrayIndexOutOfBoundsException",
    "java.lang.StringIndexOutOfBoundsException",
    "java.lang.IndexOutOfBoundsException",
    "java.lang.NegativeArraySizeException",
    "java.lang.ClassCastException",
    "java.lang.ArithmeticException",
    "java.lang.ArrayStoreException",
    "java.lang.AssertionError",              # an invariant the library itself asserted
    "java.lang.IllegalAccessError",
    "java.lang.NoSuchMethodError",
    "java.lang.VerifyError",
    "java.lang.ClassFormatError",
}

# Resource exhaustion: a finding only in proportion to the input that caused it.
_EXHAUSTION = {
    "java.lang.StackOverflowError",
    "java.lang.OutOfMemoryError",
}

# Exceptions that are how a Java API SAYS NO. Seeing one from a parser fed a random byte
# string is the parser rejecting a random byte string.
_TYPICALLY_CONTRACT = {
    "java.lang.IllegalArgumentException",
    "java.lang.NumberFormatException",         # extends IllegalArgumentException
    "java.lang.UnsupportedOperationException",
    "java.lang.IllegalStateException",
    "java.io.IOException",
    "java.io.EOFException",
    "java.io.UncheckedIOException",
    "java.nio.charset.MalformedInputException",
    "java.nio.BufferUnderflowException",
    "java.text.ParseException",
    "java.util.NoSuchElementException",
    "java.util.InputMismatchException",
}

# Jazzer's own signal that a SEMANTIC boundary was crossed — injection, deserialization,
# SSRF, path traversal. These are the high-value JVM findings and have no C analogue: no
# memory is corrupted and nothing crashes, which is precisely why a memory-shaped engine
# would score them zero.
_JAZZER_SANITIZER = re.compile(
    r"com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssue(\w+)")

# The head of a Java stack trace is `<FQCN>` or `<FQCN>: <message>` on the line before the
# first `\tat` frame. Requiring the name to END in Exception/Error/Throwable seemed safe and
# was not: a library's OWN exception type frequently does not — `Parser$BadRecord`,
# `ParseFailure`, `Problem` — and that is the single most common case, the one the CONTRACT
# verdict exists for. Anchoring on the trace's STRUCTURE rather than on a naming convention
# is the difference between classifying a library's error path and silently calling it
# unknown.
_THROWN = re.compile(
    r"^(?:Exception in thread \"[^\"]*\"\s*)?"
    r"(?P<cls>(?:[a-zA-Z_$][\w$]*\.)*[A-Z][\w$]*)"
    r"(?::[ \t]*(?P<msg>.*))?[ \t]*$", re.M)

# "\tat com.example.Parser.body(Parser.java:14)"
_FRAME = re.compile(
    r"^\s*at\s+(?P<decl>[\w$.]+)\.(?P<method>[\w$<>]+)\("
    r"(?:(?P<file>[\w$]+\.java):(?P<line>\d+)|[^)]*)\)", re.M)

_CAUSED_BY = re.compile(r"^Caused by:\s*", re.M)


@dataclass
class Frame:
    declaring: str
    method: str
    file: str = ""
    line: int = 0

    @property
    def package(self) -> str:
        return self.declaring.rsplit(".", 1)[0] if "." in self.declaring else ""


@dataclass
class Judgement:
    verdict: str
    exception: str = ""
    message: str = ""
    thrower: Optional[Frame] = None
    reason: str = ""
    sanitizer: str = ""              # a Jazzer semantic issue, if that is what this is
    frames: list = field(default_factory=list)
    amplification: Optional[float] = None    # bytes consumed per input byte, when known

    @property
    def is_finding(self) -> bool:
        """Whether a human should look at this at all. EXHAUSTION is deliberately excluded
        until a ratio is supplied — see `with_amplification`."""
        return self.verdict in (DEFECT,) or bool(self.sanitizer)


def parse_trace(text: str) -> tuple:
    """(exception_class, message, [Frame]) from a JVM stack trace.

    The LAST `Caused by:` block is the one that matters: a library that wraps a defect in its
    own `ParseException` would otherwise be judged on the wrapper, which is exactly the
    behaviour a maintainer would call a misreading.
    """
    if not text:
        return "", "", []
    blocks = _CAUSED_BY.split(text)
    block = blocks[-1] if len(blocks) > 1 else text

    # Only the head counts. Searching the whole block would match a class name inside a
    # frame line and report the wrong exception.
    head = block.split("\n\tat ")[0].split("\n    at ")[0]
    m = _THROWN.search(head)
    cls = m.group("cls") if m else ""
    msg = (m.group("msg") or "").strip() if m else ""

    frames = [Frame(declaring=f.group("decl"), method=f.group("method"),
                    file=f.group("file") or "", line=int(f.group("line") or 0))
              for f in _FRAME.finditer(block)]
    return cls, msg, frames


def _first_owned(frames: list, packages: set, harness: set) -> tuple:
    """The topmost frame belonging to the library or to us, and which it was.

    The topmost frame overall is usually a JDK internal — `java.base/java.util.Objects
    .requireNonNull` — and blaming the JDK for the library's null is the Java version of
    blaming the allocator for a heap overflow.
    """
    for f in frames:
        if f.declaring in harness or f.file in harness:
            return f, HARNESS
        if any(f.declaring.startswith(p) for p in packages):
            return f, DEFECT
    return (frames[0] if frames else None), UNKNOWN


def classify(trace: str, *, library_packages, harness_classes=(),
             declared_throws=()) -> Judgement:
    """Judge one escaped exception.

    `library_packages`  — package prefixes that ARE the target. Without them nothing can be
                          attributed and the honest verdict is UNKNOWN, not DEFECT.
    `harness_classes`   — class names or file names that are ours.
    `declared_throws`   — what the called method declares. The library telling us in advance
                          that this is not a bug, which beats every heuristic below.
    """
    packages = {p for p in library_packages if p}
    harness = set(harness_classes)
    declared = set(declared_throws)

    cls, msg, frames = parse_trace(trace)
    if not cls:
        return Judgement(UNKNOWN, reason="no exception class in the trace")

    j = Judgement(verdict=UNKNOWN, exception=cls, message=msg, frames=frames)

    san = _JAZZER_SANITIZER.search(trace)
    if san:
        # Jazzer names a crossed trust boundary directly. No attribution argument is needed:
        # the sanitizer fired because attacker-controlled data reached a sink.
        j.sanitizer = san.group(1)
        j.verdict = DEFECT
        j.reason = (f"a Jazzer sanitizer reported {san.group(1)}: attacker-controlled input "
                    f"reached a sink that crosses a trust boundary")
        return j

    thrower, owner = _first_owned(frames, packages, harness)
    j.thrower = thrower

    if owner == HARNESS:
        j.verdict = HARNESS
        j.reason = (f"the exception escaped from harness code at "
                    f"{thrower.file or thrower.declaring}:{thrower.line}. This crash is "
                    f"ours, not the target's.")
        return j

    if cls in _EXHAUSTION:
        j.verdict = EXHAUSTION
        j.reason = (f"{cls.rsplit('.', 1)[-1]} is a finding only in proportion to the input "
                    f"that caused it. Supply the amplification ratio; a large input "
                    f"consuming a lot of memory is arithmetic, not a bug.")
        return j

    short = cls.rsplit(".", 1)[-1]
    if cls in declared or short in declared:
        j.verdict = CONTRACT
        j.reason = (f"the method DECLARES throws {short}. The library is telling us this is "
                    f"its documented way of rejecting input, not a defect.")
        return j

    if cls in _ALWAYS_DEFECT:
        if owner != DEFECT:
            j.verdict = UNKNOWN
            j.reason = (f"{short} escaped, but no frame belongs to a declared library "
                        f"package, so it cannot be attributed to the target. Name the "
                        f"packages rather than accepting an unattributed finding.")
            return j
        j.verdict = DEFECT
        j.reason = (f"{short} raised in library code at "
                    f"{thrower.file or thrower.declaring}:{thrower.line}. The JVM's own "
                    f"checks are the always-on memory-safety oracle; this is the equivalent "
                    f"of a sanitizer report, and it is not a documented way to reject input.")
        return j

    if cls in _TYPICALLY_CONTRACT:
        j.verdict = CONTRACT
        j.reason = (f"{short} is how a Java API says no. It is not declared on this method, "
                    f"so it is worth a look — but a parser rejecting a random byte string is "
                    f"a parser working.")
        return j

    if any(cls.startswith(p) for p in packages):
        j.verdict = CONTRACT
        j.reason = (f"{short} belongs to the target's OWN exception hierarchy, which is a "
                    f"library defining how it reports bad input.")
        return j

    j.verdict = UNKNOWN
    j.reason = (f"{short} is neither a JVM check, a documented rejection, nor the library's "
                f"own exception type. Unclassified, which is not the same as safe.")
    return j


def with_amplification(j: Judgement, *, input_bytes: int,
                       consumed_bytes: int = 0, seconds: float = 0.0,
                       budget_seconds: float = 0.0) -> Judgement:
    """Turn an EXHAUSTION observation into a verdict, or refuse to.

    The threshold is a RATIO and never an absolute: a fixed "2GB is a bug" rule reports every
    large input and misses the 40-byte one, which is the finding that matters. This mirrors
    D5's discipline of measuring a rate rather than asserting a bound.
    """
    if j.verdict != EXHAUSTION:
        return j
    if input_bytes <= 0 or (consumed_bytes <= 0 and seconds <= 0.0):
        j.reason += " No ratio was supplied, so this stays UNMEASURED rather than becoming a claim."
        return j

    if consumed_bytes > 0:
        ratio = consumed_bytes / float(input_bytes)
        j.amplification = ratio
        if ratio >= 1000.0:
            j.verdict = DEFECT
            j.reason = (f"{input_bytes} input bytes caused {consumed_bytes} bytes of "
                        f"allocation — {ratio:.0f}x amplification. Unbounded allocation "
                        f"driven by input is a denial-of-service defect.")
        else:
            j.verdict = CONTRACT
            j.reason = (f"{ratio:.1f}x amplification: the memory is roughly proportional to "
                        f"the input. That is arithmetic, not a bug.")
        return j

    ratio = seconds / budget_seconds if budget_seconds > 0 else 0.0
    j.amplification = ratio
    if ratio >= 100.0:
        j.verdict = DEFECT
        j.reason = (f"{input_bytes} input bytes took {seconds:.2f}s against a {budget_seconds}s "
                    f"budget — {ratio:.0f}x. Input-driven superlinear time is the ReDoS "
                    f"shape and is a real denial-of-service finding on the JVM.")
    else:
        j.verdict = CONTRACT
        j.reason = f"{ratio:.1f}x the time budget: slow, not superlinear."
    return j
