#!/usr/bin/env python3
"""Mine API ordering conventions from a corpus, then find the harnesses that break them.

The gate bank checks what somebody wrote down: resource lifetimes, argument shapes, input
consumption. It cannot check a library's PROTOCOL -- that `X_init` must precede `X_parse`,
or that a context must be configured before it is used -- because nobody has written those
contracts down for the two thousand libraries in this corpus.

The corpus itself is the contract. If ninety harnesses across forty projects call
`yaml_parser_initialize` before `yaml_parser_set_input`, and one calls the second without
the first, the odd one out is worth reading. That is not proof of a defect: it is a
DEVIATION FROM A CONVENTION the corpus establishes, which is a different and weaker claim,
and the tool says so.

Two filters keep this from becoming a co-occurrence generator:

  SAME MODULE. `sprintf -> pcap_close` is seen 132 times in one order and is not a
  protocol; it is alphabetical accident. A pair must share a module prefix.

  ENOUGH WITNESSES, AND FEW ENOUGH EXCEPTIONS. A convention needs support, and a rule
  broken by half the corpus is not a rule. Both thresholds are arguments, printed with the
  result, because a mined rule whose support is hidden cannot be judged.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The vocabulary of "brings the object into existence". Same idea as the producer's
# new-ish set, kept local so the two can diverge if the evidence says they should.
_INIT_ISH = re.compile(r"(?:^|_)(init|new|create|open|alloc|setup|begin|start)",
                       re.I)

_PATTERNS = ("*/*fuzz*.c", "*/*fuzz*.cc", "*/*fuzz*.cpp",
             "*/*Fuzz*.c", "*/*Fuzz*.cc", "*/*Fuzz*.cpp")


def _module(sym: str) -> str:
    """`yaml_parser_initialize` -> `yaml`; `pixReadMem` -> `pix`. The library, roughly."""
    if "_" in sym:
        return sym.split("_", 1)[0].lower()
    m = re.match(r"^([a-z]+)[A-Z]", sym)
    return m.group(1).lower() if m else sym.lower()


def read_corpus(roots, *, trusted_only: bool = True) -> list:
    """One call-sequence per harness, from lifts the engine TRUSTS.

    Restricting to high-fidelity lifts is not fastidiousness, it is the difference between
    mining the corpus and mining our own blind spots. pjsip's wav harness calls `pj_init()`
    inside an `if` condition, which this lifter does not read; on the untrusted sequence it
    appeared to use pjlib without initialising it, and the miner reported it as a protocol
    violation. It is a defect in the lifter, and the lifter already says so -- the call is
    in `missed` and the lift is marked low fidelity. The miner simply was not listening.
    """
    from hforge.lift import c_harness
    seqs = []
    for root in roots:
        for pat in _PATTERNS:
            for f in sorted(Path(root).glob(pat)):
                try:
                    lifted = c_harness.lift(str(f))
                except Exception:
                    continue
                if trusted_only and not lifted.high_fidelity:
                    continue
                seqs.append((str(f), [op.api for op in lifted.ir.sequence]))
    return seqs


def mine(seqs, *, min_support: int = 10, max_violation_rate: float = 0.15) -> list:
    """Ordered pairs that look like a protocol, with the exceptions that break them."""
    before = collections.Counter()      # (a, b): a seen before b
    after = collections.Counter()       # (a, b): b seen before a  -- disqualifies
    has = collections.defaultdict(set)  # symbol -> harness indices
    for idx, (_path, seq) in enumerate(seqs):
        seen = set()
        for sym in seq:
            has[sym].add(idx)
            for earlier in seen:
                if earlier != sym:
                    before[(earlier, sym)] += 1
            seen.add(sym)
    for (a, b), n in list(before.items()):
        if before.get((b, a)):
            after[(a, b)] = before[(b, a)]

    rules = []
    for (a, b), support in before.items():
        if support < min_support or after.get((a, b)):
            continue
        if _module(a) != _module(b) or _module(a) == a.lower():
            continue
        # A MUST BE AN INITIALISER, or the rule finds alternatives rather than defects.
        #
        # `pixReadMemSpix -> pixDestroy` holds 276 times, and the three harnesses that
        # "break" it simply read their image with a different function. That is not a
        # protocol violation, it is a second way to do the same thing, and reporting it
        # would bury the real signal in benign variety.
        #
        # The shape worth flagging is USE OR TEARDOWN WITHOUT INITIALISATION, so A has to
        # look like the thing that brings the object into existence.
        if not _INIT_ISH.search(a):
            continue
        # ...and B must not be another initialiser: `x_new` before `x_create` is a choice
        # between constructors, not a sequence.
        if _INIT_ISH.search(b):
            continue
        callers_of_b = has[b]
        violators = sorted(callers_of_b - has[a])
        rate = len(violators) / max(len(callers_of_b), 1)
        if violators and rate <= max_violation_rate:
            rules.append({"before": a, "after": b, "support": support,
                          "callers_of_after": len(callers_of_b),
                          "violations": len(violators),
                          "violation_rate": round(rate, 3),
                          "violators": [seqs[i][0] for i in violators]})
    rules.sort(key=lambda r: (-r["support"], r["violation_rate"]))
    return rules


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--min-support", type=int, default=10)
    ap.add_argument("--max-violation-rate", type=float, default=0.15)
    ap.add_argument("--all-lifts", action="store_true",
                    help="include lifts the engine does not trust. Reports this engine's "
                         "blind spots as protocol violations; for diagnosis only.")
    ap.add_argument("-o", "--out")
    a = ap.parse_args(argv)

    seqs = read_corpus(a.roots, trusted_only=not a.all_lifts)
    rules = mine(seqs, min_support=a.min_support,
                 max_violation_rate=a.max_violation_rate)
    print(f"harnesses read (trusted)    {len(seqs)}")
    print(f"conventions with exceptions {len(rules)}")
    print(f"  support >= {a.min_support}, violation rate <= {a.max_violation_rate}")
    print()
    for r in rules[:25]:
        print(f"  {r['support']:4} harnesses call {r['before']} before {r['after']}")
        print(f"       {r['violations']} of {r['callers_of_after']} do not "
              f"({r['violation_rate']:.0%}):")
        for v in r["violators"][:3]:
            print(f"         {'/'.join(Path(v).parts[-2:])}")
    print()
    print("A deviation is NOT a defect. The corpus establishes a convention; a harness that")
    print("breaks it may be wrong, or may be the one that read the documentation. Read it.")
    if a.out:
        Path(a.out).write_text(json.dumps(
            {"harnesses": len(seqs), "min_support": a.min_support,
             "max_violation_rate": a.max_violation_rate, "rules": rules}, indent=1))
        print(f"\nwritten to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
