"""Discover an application's entry points and the channel each takes its input through.

The producer half of B1. B1 gave the IR an AppEntry and the emitter a channel for each of the
shapes a CLI application exposes; this finds those shapes in a real codebase so the harness is
generated, not hand-written -- the same arc test-lift followed (IR + emitter first, producer
after).

Classification is by SIGNATURE, from the header's declarations, because that is what the
channel depends on:

    int main(int argc, char **argv)          -> argv     (bytes -> temp file -> argv slot)
    f(<byte*>, <size>)                        -> buffer   (bytes and length handed directly)
    f(const char *path-named)                 -> file_arg (bytes -> temp file, path passed)
    f(const char *content-named or unknown)   -> cstring  (NUL-terminated content in memory)

The lone-`const char *` case is the only ambiguous one -- a path or the content itself -- and
the parameter name decides it: `path`/`file`/`filename` means a path, anything else means
content. Getting it wrong yields a harness that runs and tests the wrong thing, so the choice
travels on the record and a caller can override it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..ir import (APP_ARGV, APP_BUFFER, APP_CSTRING, APP_FILE_ARG, AppEntry,
                  HarnessIR, Knobs, Target)
from .header_graph import parse_header

PRODUCER = "app_lift"

_BYTE_PTR = re.compile(r"\b(?:const\s+)?(?:unsigned\s+char|char|void|uint8_t|int8_t)\s*\*")
_SIZEISH = re.compile(r"\b(?:size_t|unsigned\s+long|unsigned\s+int|unsigned|int|long|"
                      r"ssize_t|uint\d+_t)\b")
_PATH_NAME = re.compile(r"(path|file|filename|fname|filepath|fpath)", re.I)
# A name that says "this is the content to parse", not a path.
_CONTENT_NAME = re.compile(r"(data|input|buf|buffer|str|string|text|src|json|xml|content|"
                           r"msg|payload|s)$", re.I)
# Entry points worth ranking to the top: they consume attacker input.
_PARSEISH = re.compile(r"(?:^|_)(main|parse|read|load|decode|scan|deserial|process|handle|"
                       r"from_|ingest|import)", re.I)


def _is_byte_ptr(ty: str) -> bool:
    return bool(_BYTE_PTR.search(ty)) and ty.count("*") == 1


def classify(decl) -> Optional[dict]:
    """Return a candidate {channel, symbol, argv?, param} for a declaration, or None."""
    params = list(getattr(decl, "params", []) or [])
    name = decl.name
    # main(int, char**)
    if len(params) == 2 and re.match(r"\bint\b", params[0][0].strip()) \
            and params[1][0].count("*") == 2 and "char" in params[1][0]:
        return {"channel": APP_ARGV, "symbol": name,
                "argv": [name.replace("_main", "") or "app", "@INPUT@"]}
    # f(byte*, size)
    if len(params) >= 2 and _is_byte_ptr(params[0][0]) \
            and "*" not in params[1][0] and _SIZEISH.search(params[1][0]):
        return {"channel": APP_BUFFER, "symbol": name, "param": params[0][1]}
    # f(const char *) -- lone char pointer: path or content
    if len(params) == 1 and _is_byte_ptr(params[0][0]) and "char" in params[0][0]:
        pn = params[0][1] or ""
        if _PATH_NAME.search(pn):
            return {"channel": APP_FILE_ARG, "symbol": name, "param": pn}
        return {"channel": APP_CSTRING, "symbol": name, "param": pn}
    return None


def _rank(c: dict) -> tuple:
    # Parse-like names first; among those main() last (argv is the heaviest channel), so a
    # direct parse function is preferred over driving the whole CLI when both exist.
    parseish = 0 if _PARSEISH.search(c["symbol"]) else 1
    is_main = 1 if c["channel"] == APP_ARGV else 0
    # buffer/cstring (no file I/O) are the most direct, then file_arg, then argv.
    directness = {APP_BUFFER: 0, APP_CSTRING: 0, APP_FILE_ARG: 1, APP_ARGV: 2}[c["channel"]]
    return (parseish, is_main, directness, c["symbol"])


def discover(headers: list, includes: tuple = ()) -> list:
    """Ranked AppEntry candidates from a library/application's headers."""
    seen, cands = set(), []
    for h in headers:
        if not Path(h).exists():
            continue
        try:
            decls = parse_header(h, tuple(includes), ())
        except Exception:                                          # noqa: BLE001
            continue
        for d in decls:
            if d.name in seen:
                continue
            c = classify(d)
            if c is None:
                continue
            seen.add(d.name)
            c["header"] = Path(h).name
            cands.append(c)
    cands.sort(key=_rank)
    return cands


def propose(headers: list, target: Target, includes: tuple = (),
            only: str = "") -> tuple:
    """(HarnessIR or None, record). `only` names one symbol to lift; else the top candidate."""
    cands = discover(headers, includes)
    rec = {"producer": PRODUCER, "candidates": [(c["symbol"], c["channel"]) for c in cands]}
    if only:
        cands = [c for c in cands if c["symbol"] == only]
    if not cands:
        rec["why_not"] = ("no application entry point found: no main(argc,argv), no "
                          "(buffer,size) function, no lone char* parser in the header(s)")
        return None, rec
    c = cands[0]
    ae = AppEntry(symbol=c["symbol"], channel=c["channel"], header=c.get("header", ""),
                  argv=c.get("argv", []))
    rec["chosen"] = {"symbol": c["symbol"], "channel": c["channel"],
                     "param": c.get("param")}
    plan = HarnessIR(name=f"{target.name}_{c['symbol']}"[:60], target=target,
                     app_entry=ae, knobs=Knobs(),
                     platforms=list(target.__dict__.get("platforms", []))
                     or ["linux-x86_64-glibc"],
                     producer=PRODUCER)
    return plan, rec
