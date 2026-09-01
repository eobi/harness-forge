"""A PDF-aware mutator, and the confound that made it necessary.

The GUI track campaigned eog with the structure-aware PNG mutator and evince with plain
byte flips, then compared them: 29% of PNG mutations got past the front door against 97% of
PDF ones. That comparison varies the MUTATOR and the FORMAT together, so it cannot say
whether evince is more tolerant or the mutation was gentler. It is a confound in our own
result and this removes it.

The same argument as the PNG mutator, in a different grammar. A PDF is a header, a body of
numbered objects, a cross-reference table, and a trailer pointing at it. Random byte flips
usually land in an object's text and produce a file a tolerant reader still renders -- which
is why 97% were accepted and why that number says nothing about depth reached.

The interesting knobs are the ones a reader must act on:

  xref_offset   the trailer's `startxref` tells the reader where the table is. A wrong
                offset forces the recovery path, which is where readers reconstruct the
                document by scanning -- different code from the happy path.
  obj_len       `/Length` on a stream declares how many bytes follow. Lying about it is
                the classic surface: the reader either over-reads or truncates.
  filter        `/Filter /FlateDecode` promises the stream is deflate. Claiming a filter
                the payload does not satisfy sends the decoder into an error path.
  stream_bytes  noise INSIDE a stream, leaving the object structure intact, so the
                decompressor gets malformed input rather than the parser.

`raw` remains available and is returned unchanged when the input does not parse as a PDF,
so the mutator degrades to the old behaviour rather than failing.
"""
from __future__ import annotations

import random
import re
import zlib

HEADER = b"%PDF-"
_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_LENGTH = re.compile(rb"/Length\s+(\d+)")
_STARTXREF = re.compile(rb"startxref\s*\r?\n\s*(\d+)")


def looks_like_pdf(data: bytes) -> bool:
    return data.startswith(HEADER)


def _flip(b: bytearray, rng: random.Random, n: int = 4) -> None:
    for _ in range(rng.randint(1, n)):
        if b:
            b[rng.randrange(len(b))] = rng.randrange(256)


def mutate(data: bytes, rng: random.Random) -> tuple:
    """A structurally recognisable PDF with something a reader must react to.

    Returns (bytes, what) -- the same contract as mutate_png.mutate, so the campaign can
    choose a mutator by format without knowing anything else about it.
    """
    if not looks_like_pdf(data):
        b = bytearray(data)
        _flip(b, rng, 1)
        return bytes(b), "raw"

    b = bytearray(data)
    what = rng.choice(["xref_offset", "obj_len", "filter", "stream_bytes",
                       "header", "trailer_drop"])

    if what == "xref_offset":
        m = _STARTXREF.search(b)
        if not m:
            return bytes(b), "raw"
        # A plausible-looking but wrong offset: past the end, at zero, or mid-object.
        bad = rng.choice([0, len(b) + rng.randrange(1, 4096), rng.randrange(1, max(len(b), 2))])
        s, e = m.span(1)
        b[s:e] = str(bad).encode()

    elif what == "obj_len":
        m = rng.choice(list(_LENGTH.finditer(b))) if _LENGTH.search(b) else None
        if m is None:
            return bytes(b), "raw"
        real = int(m.group(1))
        bad = rng.choice([0, 1, real * 4 + 7, max(real - 3, 0), 0x7FFFFFFF])
        s, e = m.span(1)
        b[s:e] = str(bad).encode()

    elif what == "filter":
        if b.find(b"/Filter") < 0:
            # Claim a filter where none was promised: the payload is not deflate.
            i = b.find(b"stream")
            if i < 0:
                return bytes(b), "raw"
            b[i:i] = b"/Filter /FlateDecode\n"
        else:
            b = bytearray(b.replace(b"/FlateDecode",
                                    rng.choice([b"/LZWDecode", b"/ASCII85Decode",
                                                b"/RunLengthDecode"]), 1))

    elif what == "stream_bytes":
        i = b.find(b"stream")
        j = b.find(b"endstream", i + 1) if i >= 0 else -1
        if i < 0 or j < 0 or j - i < 16:
            return bytes(b), "raw"
        inner = bytearray(b[i + 6:j])
        _flip(inner, rng, 8)
        b[i + 6:j] = inner

    elif what == "header":
        # `%PDF-1.7` -> a version a reader may not accept, or a damaged marker. Readers
        # differ on whether they recover, which is the point.
        b[0:8] = rng.choice([b"%PDF-9.9", b"%PDF-0.0", b"%PDX-1.7", b"%PDF-1.\xff"])

    elif what == "trailer_drop":
        i = b.rfind(b"trailer")
        if i < 0:
            return bytes(b), "raw"
        b = b[:i]                                  # no trailer at all: recovery or refusal

    return bytes(b), what
