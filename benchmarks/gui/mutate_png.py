"""A PNG-aware mutator, and the reason a GUI campaign needs one.

Random byte flips break the eight-byte signature or the IHDR before the decoder reaches
anything interesting, so every input is refused at the front door and the campaign measures
the parser's first check over and over. That is the same wall the library side hit: on an
X.509 parser, structurally valid seeds moved coverage from 12.22% to 32.10% at an identical
budget, because DER is length-prefixed and tag-typed and a mutator is rejected in the first
bytes of the outer structure.

A PNG is a signature, then chunks of (length, type, payload, CRC32). Keeping that skeleton
intact and mutating INSIDE it is what gets past the door. The CRC is the interesting knob:
recompute it and the chunk is well-formed but its contents are strange, which is the case
that exercises the decoder; leave it stale and libpng rejects the chunk immediately.
"""
from __future__ import annotations

import random
import struct
import zlib

SIG = b"\x89PNG\r\n\x1a\n"


def parse(data: bytes):
    """(type, payload) chunks, or None if this is not a PNG we can walk."""
    if not data.startswith(SIG):
        return None
    out, i = [], len(SIG)
    while i + 8 <= len(data):
        (ln,) = struct.unpack(">I", data[i:i + 4])
        typ = data[i + 4:i + 8]
        payload = data[i + 8:i + 8 + ln]
        if len(payload) != ln:
            return None
        out.append((typ, payload))
        i += 12 + ln
    return out or None


def build(chunks, *, fix_crc: bool = True) -> bytes:
    out = bytearray(SIG)
    for typ, payload in chunks:
        out += struct.pack(">I", len(payload)) + typ
        out += payload
        crc = zlib.crc32(typ + payload) & 0xFFFFFFFF if fix_crc else 0xDEADBEEF
        out += struct.pack(">I", crc)
    return bytes(out)


def mutate(data: bytes, rng: random.Random) -> tuple:
    """A structurally valid PNG with something odd inside it. Returns (bytes, what)."""
    chunks = parse(data)
    if chunks is None:
        b = bytearray(data)
        if b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        return bytes(b), "raw"

    ch = [(t, bytearray(p)) for t, p in chunks]
    what = rng.choice(["payload", "dims", "drop", "dup", "stale_crc", "trunc_idat"])

    if what == "payload":                       # noise inside a chunk's data
        idx = rng.randrange(len(ch))
        p = ch[idx][1]
        for _ in range(rng.randint(1, 6)):
            if p:
                p[rng.randrange(len(p))] = rng.randrange(256)
    elif what == "dims" and ch and ch[0][0] == b"IHDR" and len(ch[0][1]) >= 8:
        # width/height are the classic integer-overflow surface in image decoders
        w = rng.choice([0, 1, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF])
        h = rng.choice([0, 1, 0xFFFF, 0x40000000])
        ch[0][1][0:4] = struct.pack(">I", w)
        ch[0][1][4:8] = struct.pack(">I", h)
    elif what == "drop" and len(ch) > 2:
        del ch[rng.randrange(1, len(ch) - 1)]
    elif what == "dup" and len(ch) > 1:
        i = rng.randrange(len(ch))
        ch.insert(i, (ch[i][0], bytearray(ch[i][1])))
    elif what == "trunc_idat":
        for i, (t, p) in enumerate(ch):
            if t == b"IDAT" and len(p) > 4:
                ch[i] = (t, p[: rng.randrange(1, len(p))])
                break
    return build([(t, bytes(p)) for t, p in ch],
                 fix_crc=(what != "stale_crc")), what
