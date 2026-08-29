"""Backends. One IR, many emitters: the same certified plan travels across OS and arch.

`Target.language` has existed since Phase 1 and exactly one module read it —
`cxx_libfuzzer`, which read it in order to REFUSE. Nothing dispatched on it: `cli.py`
imported `emit` from `c_libfuzzer` by name, so a second backend was reachable only from a
test that imported it directly. A language field that nothing routes on is documentation,
not a design.

This is the router. Adding a language means adding a row, and every call site keeps saying
`emit(ir)` without knowing what it will produce. `plancheck` C12 holds the rest of the
codebase to going through here.
"""
from __future__ import annotations

from typing import Callable

# Spellings a plan may legitimately carry. The IR is written by producers, by hand, and by a
# model behind `producers/model.py`, and they will not agree on punctuation.
_ALIASES = {
    "c": "c", "c99": "c", "c11": "c",
    "c++": "c++", "cpp": "c++", "cxx": "c++", "c++17": "c++",
    "java": "java", "jvm": "java", "kotlin": "java",
}


def normalise(language: str) -> str:
    return _ALIASES.get((language or "c").strip().lower(), "")


def backend_for(language: str) -> Callable:
    """The emitter for a language, or a refusal naming what IS supported.

    Imported lazily so that a broken or dependency-heavy backend cannot stop the others
    loading — the C path must not become unavailable because a Java module has a typo.
    """
    lang = normalise(language)
    if lang == "c":
        from .c_libfuzzer import emit as f
        return f
    if lang == "c++":
        from .cxx_libfuzzer import emit as f
        return f
    if lang == "java":
        from .java_jazzer import emit as f
        return f

    from .c_libfuzzer import EmitError
    raise EmitError(
        f"no backend for language {language!r}. Supported: "
        f"{', '.join(sorted(set(_ALIASES.values())))}. A plan naming a language nothing can "
        f"emit is refused here rather than silently emitted as C — which would compile, "
        f"pass the static gates, and certify a harness for a language it was not written in.")


def emit(ir):
    """Emit `ir` with the backend its language names."""
    return backend_for(ir.target.language)(ir)


def languages() -> list:
    return sorted(set(_ALIASES.values()))
