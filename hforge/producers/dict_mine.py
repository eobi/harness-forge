"""Mine a libFuzzer dictionary from a target's own source.

The single largest lever on an application harness's depth is STRUCTURE. A raw byte fuzzer
rarely forms the magic a decoder gates on -- "IHDR", the JPEG marker 0xFFD8, "GIF89a" -- so it
never enters the format's body. A dictionary of those tokens fixes that: on stb_image the same
harness went from 146 to 915 edges once the fuzzer had the tokens to build valid headers.

The tokens are not hardcoded per format. They are MINED from the target's own source, so the
dictionary is correct for whatever the library actually parses: every string literal it
compares against, and every multi-byte magic it checks. A dictionary derived from the code is
a dictionary that cannot drift from it.
"""
from __future__ import annotations

import re
from pathlib import Path

# A string literal in C source: "..." with escapes. Kept when it is 2..32 bytes of the kind of
# content a parser BRANCHES on -- not a format string, not prose.
_STRLIT = re.compile(r'"((?:[^"\\\n]|\\.){2,64})"')
# A char-packed tag: 'I','H','D','R' or 'I','H','D'. Decoders spell format tags this way to
# avoid endianness (PNG chunk types, JPEG markers, RIFF fourccs) -- the single highest-value
# tokens, and invisible to string mining because they are never string literals.
_CHARTAG = re.compile(r"'([ -~])'\s*,\s*'([ -~])'\s*,\s*'([ -~])'(?:\s*,\s*'([ -~])')?")
# A byte-array magic: { 137,80,78,71,13,10,26,10 } -- a signature written as a decimal (or
# hex) initialiser. png_sig is exactly this shape.
_BYTEARR = re.compile(r"\{\s*((?:0[xX][0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*"
                      r"(?:0[xX][0-9a-fA-F]{1,2}|\d{1,3})){2,15})\s*,?\s*\}")


def _decode_c_escapes(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            simple = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "a": 7,
                      "b": 8, "f": 12, "v": 11}
            if n in simple:
                out.append(simple[n]); i += 2; continue
            if n == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:i + 4])
                if m:
                    out.append(int(m.group(0), 16)); i += 2 + len(m.group(0)); continue
            out.append(ord(n)); i += 2; continue
        out.append(ord(c) & 0xFF); i += 1
    return bytes(out)


def _is_useful(raw: bytes) -> bool:
    if not (2 <= len(raw) <= 32):
        return False
    if b"%" in raw:                      # printf/scanf format, not a magic
        return False
    printable = sum(1 for b in raw if 32 <= b < 127)
    # keep pure-magic (mostly non-printable, e.g. \x89PNG) OR mostly-printable tokens; drop
    # the middle (a stray escaped char in prose).
    if printable == len(raw):
        # all printable: must look like a token, not an English phrase with spaces
        return raw.count(b" ") <= 1 and any(32 <= b < 127 and chr(b).isalnum() for b in raw)
    return printable >= 1                 # has a magic byte and some structure


def _dict_escape(raw: bytes) -> str:
    out = []
    for b in raw:
        if b == 0x5C:
            out.append("\\\\")
        elif b == 0x22:
            out.append('\\"')
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def mine_tokens(sources: list) -> list:
    """Distinct dictionary tokens (as bytes) mined from the given C source files/paths."""
    seen: dict = {}
    for src in sources:
        p = Path(src)
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for m in _STRLIT.finditer(text):
            raw = _decode_c_escapes(m.group(1))
            if _is_useful(raw):
                seen.setdefault(raw, True)
        # char-packed tags -> the exact bytes, e.g. 'I','H','D','R' -> b"IHDR"
        for m in _CHARTAG.finditer(text):
            raw = bytes(ord(g) for g in m.groups() if g)
            if 2 <= len(raw) <= 8:
                seen.setdefault(raw, True)
        # byte-array signatures -> the exact bytes, e.g. {137,80,78,71,...} -> b"\x89PNG..."
        for m in _BYTEARR.finditer(text):
            try:
                vals = [int(x, 0) for x in re.split(r"\s*,\s*", m.group(1))]
            except ValueError:
                continue
            if all(0 <= v <= 255 for v in vals) and 3 <= len(vals) <= 16:
                seen.setdefault(bytes(vals), True)
    return list(seen.keys())


def to_libfuzzer_dict(tokens: list) -> str:
    """Render tokens as a libFuzzer dictionary file body."""
    lines = ["# mined by harness-forge from the target's own source"]
    for i, raw in enumerate(tokens):
        lines.append(f'k{i}="{_dict_escape(raw)}"')
    return "\n".join(lines) + "\n"


def mine_dict(sources: list) -> str:
    return to_libfuzzer_dict(mine_tokens(sources))
