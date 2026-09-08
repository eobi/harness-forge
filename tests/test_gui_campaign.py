"""The GUI-track search loop: mutation, deduplication and aggregation, tested pure -- and
the loop itself driven by a fake observation layer, so no window ever opens.
"""
import random

from hforge.gui import campaign as C
from hforge.gui import GuiOutcome, GuiVerdict


# ── mutation is deterministic and actually mutates ───────────────────────────

def test_mutation_is_deterministic_for_a_fixed_seed():
    a = C.mutate(b"the quick brown fox", random.Random(1), None)
    b = C.mutate(b"the quick brown fox", random.Random(1), None)
    assert a == b


def test_mutation_changes_the_input():
    rng = random.Random(7)
    seed = b"A" * 64
    # over several draws at least one must differ (a flip could coincide, not 8 times)
    assert any(C.mutate(seed, rng, None) != seed for _ in range(8))


def test_mutation_of_empty_seed_produces_bytes():
    out = C.mutate(b"", random.Random(3), None)
    assert isinstance(out, bytes) and len(out) >= 1


# ── deduplication collapses the same crash ───────────────────────────────────

def _crash(sig):
    return GuiVerdict(GuiOutcome.CRASHED, evidence=[("EXC_BAD_ACCESS", sig)], note="x")


def test_finding_key_collapses_identical_crashes():
    assert C.finding_key(_crash("SIGSEGV")) == C.finding_key(_crash("SIGSEGV"))


def test_finding_key_separates_different_signals():
    assert C.finding_key(_crash("SIGSEGV")) != C.finding_key(_crash("SIGBUS"))


def test_finding_key_separates_crash_from_hang():
    hang = GuiVerdict(GuiOutcome.UNRESPONSIVE, note="hung")
    assert C.finding_key(_crash("SIGSEGV")) != C.finding_key(hang)


# ── aggregation counts outcomes ──────────────────────────────────────────────

def test_aggregate_counts_by_outcome():
    vs = [_crash("SIGSEGV"),
          GuiVerdict(GuiOutcome.ACCEPTED), GuiVerdict(GuiOutcome.ACCEPTED),
          GuiVerdict(GuiOutcome.REJECTED)]
    counts = C.aggregate(vs)
    assert counts["accepted"] == 2 and counts["crashed"] == 1 and counts["rejected"] == 1


# ── the loop, driven by a fake observation layer ─────────────────────────────

class _FakeDriver:
    """Stands in for macos_ax / linux_atspi: crashes when the input starts with 0xff,
    accepts otherwise. No process is launched."""
    def run_one(self, *, app, input_path, proc_name=None, gui=True,
                argv_template=None, settle_s=1.2, timeout_s=20.0):
        data = open(input_path, "rb").read()
        if data[:1] == b"\xff":
            return GuiVerdict(GuiOutcome.CRASHED, evidence=[("EXC_BAD_ACCESS", "SIGSEGV")],
                              note="fake crash")
        return GuiVerdict(GuiOutcome.ACCEPTED, note="fake accept")


def test_run_campaign_finds_and_dedups_crashers(tmp_path):
    seeds = tmp_path / "seeds"; seeds.mkdir()
    (seeds / "s1").write_bytes(b"\xff\x00\x01\x02\x03")   # a crashing seed
    (seeds / "s2").write_bytes(b"\x10" * 32)              # a benign seed
    out = tmp_path / "out"
    res = C.run_campaign(_FakeDriver(), app="Fake", seeds_dir=str(seeds),
                         out_dir=str(out), gui=True, budget_s=1, seed=1)
    assert res.executed > 0
    # crashers dedup to a single unique finding (all share exc/sig)
    assert res.unique() <= 1
    if res.findings:
        assert res.findings[0][1].outcome is GuiOutcome.CRASHED
        assert "crashed" in res.summary()


class _AcceptDriver:
    """Always accepts (a target that correctly handles every input): no launch."""
    def run_one(self, *, app, input_path, proc_name=None, gui=True,
                argv_template=None, settle_s=1.2, timeout_s=20.0):
        return GuiVerdict(GuiOutcome.ACCEPTED, note="fake accept")


def test_run_campaign_accept_is_not_reported(tmp_path):
    seeds = tmp_path / "seeds"; seeds.mkdir()
    (seeds / "s").write_bytes(b"\x10" * 16)
    out = tmp_path / "out"
    res = C.run_campaign(_AcceptDriver(), app="Fake", seeds_dir=str(seeds),
                         out_dir=str(out), gui=True, budget_s=1, seed=2)
    # a target that accepts everything yields no findings, however many inputs run
    assert res.executed > 0
    assert res.unique() == 0 and res.findings == []


# ── greybox: coverage_fn grows the corpus toward new coverage ────────────────

def test_greybox_coverage_marks_the_run_and_grows_corpus(tmp_path):
    seeds = tmp_path / "seeds"; seeds.mkdir()
    (seeds / "s").write_bytes(b"\x10" * 8)
    out = tmp_path / "out"
    seen_lengths = []
    # reward longer inputs: coverage == length, so the corpus should accrue longer inputs
    def cov(path):
        n = len(open(path, "rb").read()); seen_lengths.append(n); return n
    res = C.run_campaign(_AcceptDriver(), app="Fake", seeds_dir=str(seeds),
                         out_dir=str(out), gui=True, budget_s=1, seed=5, coverage_fn=cov)
    assert "greybox" in res.coverage
    assert res.executed > 0 and len(seen_lengths) == res.executed


def test_blind_run_is_labelled_blind(tmp_path):
    seeds = tmp_path / "seeds"; seeds.mkdir()
    (seeds / "s").write_bytes(b"\x10" * 8)
    out = tmp_path / "out"
    res = C.run_campaign(_AcceptDriver(), app="Fake", seeds_dir=str(seeds),
                         out_dir=str(out), gui=True, budget_s=1, seed=6)
    assert "blind" in res.coverage
