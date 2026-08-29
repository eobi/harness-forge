"""The boundary. Everything a model supplies passes through here first.

`certify` and `batch` compile and execute code. Exposed naively over a tool call, with the
caller supplying `--cflag`, `--link` and source paths, that is **arbitrary code execution on
the host wearing the costume of a tool call** — `-fplugin=evil.so` is enough on its own.

The correction that matters, from `08`: this begins at **Ring 1, not Ring 2**. `hf_propose`
runs the C preprocessor (that is how the producer stopped losing to macros in bzlib, libpng
and pcre2), `hf_targets` shells out to `ldd`, and `hf_doctor` compiles a probe. `-E` does not
make a compiler safe.

Two rules, both allow-list rather than deny-list, because a deny-list of compiler flags is a
list somebody will get around.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


class Refused(Exception):
    """A request the boundary will not pass. The message is shown to the caller verbatim."""


# Flags a target may legitimately need in order to compile. Anything not matching is refused
# BY NAME, so a new attack does not arrive as an unmatched pattern.
_ALLOWED_EXACT = {
    "-O0", "-O1", "-O2", "-Os", "-Og", "-g", "-g0", "-g1", "-g3",
    "-w", "-Wall", "-Wextra", "-Werror", "-Wno-error",
    "-std=c89", "-std=c99", "-std=c11", "-std=c17", "-std=gnu89", "-std=gnu99",
    "-std=gnu11", "-std=gnu17",
    "-fno-omit-frame-pointer", "-fomit-frame-pointer", "-fPIC", "-fpic", "-fPIE",
    "-fno-strict-aliasing", "-fwrapv", "-fno-builtin", "-pthread", "-m32", "-m64",
    "-funsigned-char", "-fsigned-char", "-fvisibility=default", "-fvisibility=hidden",
}
_ALLOWED_PREFIX = ("-D", "-U", "-I", "-W")          # -D/-U/-I are the ordinary target needs

# Never, whatever else is true. Each of these loads, links or redirects something.
#
# CASE IS LOAD-BEARING and this regex is deliberately case-SENSITIVE: `-o` is an output
# redirect and `-O1` is an optimisation level. An earlier version carried `re.I` and refused
# `-O1` as though it were `-o` — which would have made every legitimate build impossible
# while telling the caller it had tried to load a plugin.
_FORBIDDEN = re.compile(
    r"^-(?:fplugin"
    r"|fprofile[\w-]*"
    r"|fsanitize-(?:coverage-)?(?:allowlist|blacklist|ignorelist)"
    r"|-param"
    r"|specs"
    r"|B"                      # -B<dir>: an alternate compiler search path
    r"|Xclang|Xlinker|Xpreprocessor|Xassembler"
    r"|W[lap],"                # -Wl, -Wa, -Wp,: pass-through to linker/assembler/preproc
    r"|[Ll]"                   # -L<dir> and -l<name>: linking is not a compile flag
    r"|o"                      # -o: output redirect. lowercase only; -O1 is fine
    r"|include|imacros|isystem|idirafter"   # header injection by path
    r")")


def check_flag(flag: str) -> str:
    """One compiler flag, or `Refused`."""
    f = flag.strip()
    if not f:
        raise Refused("empty flag")
    if any(c in f for c in ";|&`$\n\r<>"):
        raise Refused(f"flag {f!r} contains shell metacharacters")
    if _FORBIDDEN.match(f):
        raise Refused(f"flag {f!r} is refused by name: it loads or redirects something "
                      f"(-fplugin, -B, -specs, -Xclang, -Wl, and friends are how a compiler "
                      f"becomes an execution primitive)")
    if f in _ALLOWED_EXACT:
        return f
    for p in _ALLOWED_PREFIX:
        if f.startswith(p) and len(f) > len(p):
            if "=" in f and f.split("=", 1)[1].startswith("-"):
                raise Refused(f"flag {f!r} smuggles another flag through its value")
            return f
    raise Refused(f"flag {f!r} is not on the allow-list. The list is deliberately short: "
                  f"-D, -U, -I, -W*, optimisation and debug levels, and a fixed set of "
                  f"code-generation flags. A deny-list is a list somebody gets around.")


def check_flags(flags: Optional[Iterable]) -> list:
    return [check_flag(f) for f in (flags or [])]


def check_link(arg: str) -> str:
    """A linker argument. Only `-l<name>` and a plain path inside the root are permitted, and
    the root check is applied by the caller — this only rejects the obvious escapes."""
    a = arg.strip()
    if any(c in a for c in ";|&`$\n\r<>"):
        raise Refused(f"link argument {a!r} contains shell metacharacters")
    if a.startswith("-l") and len(a) > 2 and re.fullmatch(r"-l[\w.+-]+", a):
        return a
    if a.startswith("-"):
        raise Refused(f"link argument {a!r} is refused: only -l<name> and file paths are "
                      f"permitted, not linker options")
    return a


@dataclass
class Root:
    """A declared target root. Every path argument must resolve inside it.

    Symlinks are resolved BEFORE the check, not after: a symlink inside the root pointing at
    `/etc` is the whole attack, and checking the unresolved path passes it.
    """
    path: Path

    @staticmethod
    def of(p) -> "Root":
        return Root(Path(p).expanduser().resolve())

    def check(self, candidate) -> Path:
        try:
            c = Path(candidate).expanduser().resolve()
        except (OSError, RuntimeError) as e:
            raise Refused(f"path {candidate!r} could not be resolved: {e}")
        if c == self.path or self.path in c.parents:
            return c
        raise Refused(f"path {candidate!r} resolves to {c}, which is outside the declared "
                      f"target root {self.path}. Symlinks are resolved before this check.")

    def check_all(self, candidates: Optional[Iterable]) -> list:
        return [str(self.check(c)) for c in (candidates or [])]
