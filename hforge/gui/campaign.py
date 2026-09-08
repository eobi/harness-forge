"""The GUI-track search loop: a blind, mutation-based file-drop campaign over an
out-of-process target, judged by a platform observation layer.

This is deliberately BLIND -- no coverage feedback. The GUI track's contribution is the
oracle (rejection vs hang vs crash), not the search, and pretending otherwise would be the
same dishonesty the oracle exists to refuse. A coverage-guided loop (P6.TERM) is a separate,
later deliverable that needs instrumentation this driver does not have. What this gives
today is an honest campaign: mutate a seed, drop it on the target, let the observation layer
classify the outcome, and keep only what `is_finding()` accepts -- a crash or a genuine
hang, never a rejection the target was right to make.

The search is platform-agnostic: it takes a `driver` module (from `gui.driver_for_host()`)
and calls its `run_one`. The mutation, the deduplication key and the result aggregation are
pure, so the parts that encode judgement are testable without launching a single window.
"""
from __future__ import annotations

import os
import random
import shutil
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence


# ── mutation: pure, deterministic given the rng ──────────────────────────────

def mutate(data: bytes, rng: random.Random, corpus: Optional[Sequence[bytes]] = None) -> bytes:
    """One mutated child of `data`. Deterministic for a fixed rng, so a campaign replays.

    A small, format-agnostic operator set: bit/byte flips, truncation, repeated-byte
    insertion, chunk overwrite, and (when a corpus is given) a splice from another seed.
    Blind fuzzing lives and dies on the seeds, so splicing real structure between them is
    the one operator that matters most here.
    """
    b = bytearray(data)
    if not b:
        return bytes(rng.randbytes(rng.randint(1, 16)))
    strat = rng.random()
    if strat < 0.40:                                  # bit/byte flips
        for _ in range(rng.randint(1, 16)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif strat < 0.55:                                # truncate
        b = b[:rng.randint(1, len(b))]
    elif strat < 0.70:                                # insert repeated bytes
        i = rng.randrange(len(b))
        b[i:i] = bytes([rng.randrange(256)]) * rng.randint(1, 64)
    elif strat < 0.85:                                # overwrite a chunk
        i = rng.randrange(len(b)); n = rng.randint(1, 64)
        b[i:i + n] = bytes(rng.randrange(256) for _ in range(min(n, len(b) - i)))
    elif corpus:                                      # splice from another seed
        other = bytearray(rng.choice(corpus))
        if other:
            cut = rng.randrange(len(other))
            at = rng.randrange(len(b))
            b[at:at] = other[cut:]
    else:                                             # fallback: another flip
        b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


# ── deduplication: one key per distinct finding ──────────────────────────────

def finding_key(verdict) -> tuple:
    """A signature that collapses the same bug found many times into one entry.

    Keyed on the outcome and its evidence (for a crash, the exception/signal pair the .ips
    oracle recorded), so a thousand mutated inputs that all trigger one crash count once.
    """
    ev = tuple(str(e) for e in getattr(verdict, "evidence", ()) or ())
    return (verdict.outcome.value, ev)


# ── result aggregation: pure ─────────────────────────────────────────────────

@dataclass
class CampaignResult:
    executed: int = 0
    findings: list = field(default_factory=list)     # (input_path, verdict) kept, deduped
    elapsed_s: float = 0.0
    coverage: str = "blind (no instrumentation; GUI track is not coverage-guided)"

    def unique(self) -> int:
        return len({finding_key(v) for _, v in self.findings})

    def summary(self) -> str:
        lines = [f"executed {self.executed} inputs in {self.elapsed_s:.0f}s, "
                 f"{self.unique()} unique finding(s); coverage: {self.coverage}"]
        for path, v in self.findings:
            lines.append(f"  {v.outcome.value:12s} {finding_key(v)[1]}  {os.path.basename(path)}")
        return "\n".join(lines)


def aggregate(verdicts: Sequence) -> dict:
    """Count outcomes across a run, for a one-line campaign readout. Pure."""
    counts: dict = {}
    for v in verdicts:
        counts[v.outcome.value] = counts.get(v.outcome.value, 0) + 1
    return counts


# ── the loop: side-effecting, thin ───────────────────────────────────────────

def run_campaign(driver, *, app: str, seeds_dir: str, out_dir: str,
                 gui: bool = True, proc_name: Optional[str] = None,
                 argv_template: Optional[Sequence[str]] = None,
                 budget_s: int = 60, seed: int = 1337,
                 settle_s: float = 1.2, timeout_s: float = 20.0,
                 coverage_fn=None) -> CampaignResult:
    """Mutation campaign against one out-of-process target.

    `driver` is a platform observation module exposing `run_one` (macos_ax / linux_atspi).
    `coverage_fn(input_path) -> int`, if given, turns the search GREYBOX: an input that
    reaches more coverage than any before it is retained in the corpus, so the search grows
    toward new code instead of mutating blindly. Without it the search is blind and the
    corpus is fixed -- the honest default, since coverage needs instrumentation (litecov)
    the host may not have. Saves each unique crasher under `out_dir`.
    """
    os.makedirs(out_dir, exist_ok=True)
    corpus = [open(os.path.join(seeds_dir, f), "rb").read()
              for f in os.listdir(seeds_dir)
              if os.path.isfile(os.path.join(seeds_dir, f))]
    corpus = [c for c in corpus if c]
    if not corpus:
        corpus = [b"\x00"]
    rng = random.Random(seed)
    work = os.path.join(out_dir, "cur.input")
    res = CampaignResult()
    if coverage_fn is not None:
        res.coverage = "greybox (coverage-guided corpus growth)"
    seen: set = set()
    best_cov = -1
    start = time.time()
    while time.time() - start < budget_s:
        data = mutate(rng.choice(corpus), rng, corpus)
        with open(work, "wb") as f:
            f.write(data)
        v = driver.run_one(app=app, input_path=work, proc_name=proc_name, gui=gui,
                           argv_template=argv_template, settle_s=settle_s,
                           timeout_s=timeout_s)
        res.executed += 1
        if coverage_fn is not None:                       # greybox: keep new-coverage inputs
            cov = coverage_fn(work)
            if cov is not None and cov > best_cov:
                best_cov = cov
                corpus.append(data)
        if v.is_finding():
            k = finding_key(v)
            if k not in seen:
                seen.add(k)
                dst = os.path.join(out_dir, f"finding_{len(seen)}_{v.outcome.value}.input")
                shutil.copy(work, dst)
                with open(dst + ".txt", "w") as f:
                    f.write(v.note + "\n")
                res.findings.append((dst, v))
    res.elapsed_s = time.time() - start
    return res
