"""Input generation for the gates.

The gates need to exercise a harness, and they must do it the same way every run: a gate
whose verdict changes with the weather is not a gate. So this generator is seeded and
deterministic, and the seed is recorded on the certificate.

This is deliberately NOT a fuzzer. It produces a small, structured spread of inputs whose
only job is to reach code, so that D2 can ask "would this harness notice a defect" and D4
can ask "what does it touch". Coverage-guided search is the campaign's job, and the campaign
runs after certification, not during it.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .ir import HarnessIR, SLICE_CSTRING


@dataclass
class Corpus:
    inputs: list
    seed: int
    strategy: str

    def __len__(self) -> int:
        return len(self.inputs)


# Byte patterns that reach interesting code in real parsers far more often than random
# bytes do. Cheap, and the reason a tiny corpus is worth anything at all.
_INTERESTING = [
    b"", b"\x00", b"\xff", b"A", b"AAAA",
    b"{}", b"[]", b'{"a":1}', b"[[[[]]]]", b'{"a":[{"b":null}]}',
    b"0", b"-1", b"2147483648", b"4294967296", b"1e400",
    b'"\\u', b'"\\', b'"', b"\\", b"//", b"/*",
    b"\x89PNG\r\n\x1a\n", b"GIF89a", b"\xff\xd8\xff", b"%PDF-", b"PK\x03\x04",
    b"<?xml", b"<!DOCTYPE", b"\x1f\x8b",
]

_EDGE_INTS = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
              0x10000, 0x7fffffff, 0x80000000, 0xffffffff]


def _nesting(depth: int, opener: bytes = b"[", closer: bytes = b"]") -> bytes:
    return opener * depth + closer * depth


def generate(ir: HarnessIR, *, seed: int = 1337, count: int = 64) -> Corpus:
    """A deterministic spread sized to the harness's own knobs.

    Nothing here exceeds `max_len`, because generating inputs the harness would reject at
    the door tells the gates nothing. That constraint is also the point of gate D7: the
    knob decides the search space, and here it decides the corpus too.
    """
    rng = random.Random(seed)
    cap = ir.knobs.max_len or 4096
    lo = max(ir.knobs.min_len, 1)
    out: list = []

    for b in _INTERESTING:
        if lo <= len(b) <= cap:
            out.append(b)

    # depth ladder, bounded by what the knobs can express (this is what D7 reports on)
    for d in (1, 2, 4, 8, 16, 64, 256):
        s = _nesting(d)
        if len(s) <= cap:
            out.append(s)

    # little-endian edge integers, for harnesses whose first slice is a scalar
    for n in _EDGE_INTS:
        for width in (2, 4):
            b = n.to_bytes(8, "little")[:width] + b"{}"
            if lo <= len(b) <= cap:
                out.append(b)

    # a bounded random tail, seeded so the set is reproducible
    while len(out) < count:
        n = rng.randint(lo, min(cap, 128))
        out.append(bytes(rng.getrandbits(8) for _ in range(n)))

    # slices that must be NUL-terminated should also be exercised with an embedded NUL,
    # because that is where a length/terminator disagreement shows up
    if any(s.kind == SLICE_CSTRING for s in ir.slices):
        for b in (b"{\x00}", b"[\x001]", b"\x00"):
            if lo <= len(b) <= cap:
                out.append(b)

    seen, uniq = set(), []
    for b in out[:count]:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return Corpus(inputs=uniq, seed=seed, strategy="deterministic-spread")


def valid_only(ir: HarnessIR, *, seed: int = 1337) -> Corpus:
    """Inputs a well-behaved library should accept without faulting.

    Gate D3 needs these. If any of them crashes, the harness is broken and every finding it
    produces is its own.
    """
    cap = ir.knobs.max_len or 4096
    lo = max(ir.knobs.min_len, 1)
    good = [b"{}", b"[]", b'{"a":1}', b"[1,2,3]", b'{"a":[{"b":null}]}',
            b"[[[]]]", b'{"k":"v"}', b"0", b"true", b"x"]
    return Corpus(inputs=[b for b in good if lo <= len(b) <= cap],
                  seed=seed, strategy="hand-written-valid")
