"""W0 the benchmark rig: the scoreboard math must be exact, not vibes."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from benchmark import _sign_test, scoreboard


def _rows(pairs):
    # pairs: {lib: (our_covs, dev_covs)}
    rows = []
    for lib, (ours, dev) in pairs.items():
        for c in ours:
            rows.append({"library": lib, "arm": "lifted:x", "cov": c})
        for c in dev:
            rows.append({"library": lib, "arm": "DEVELOPER:d", "cov": c})
    return rows


def test_ratio_and_parity_verdict():
    sb = scoreboard(_rows({"a": ([120], [100]), "b": ([90], [100])}), bar=1.14)
    per = {e["library"]: e for e in sb["per_library"]}
    assert per["a"]["ratio"] == 1.2 and per["a"]["beats_developer"]
    assert per["b"]["ratio"] == 0.9 and not per["b"]["beats_developer"]
    assert sb["beats_parity"]["wins"] == 1 and sb["beats_parity"]["losses"] == 1


def test_beats_bar_flag():
    sb = scoreboard(_rows({"a": ([120], [100])}), bar=1.14)
    assert sb["per_library"][0]["beats_bar"] is True   # 1.20 >= 1.14
    sb2 = scoreboard(_rows({"a": ([110], [100])}), bar=1.14)
    assert sb2["per_library"][0]["beats_bar"] is False  # 1.10 < 1.14


def test_no_developer_baseline_is_reported_not_scored():
    rows = [{"library": "a", "arm": "lifted:x", "cov": 50}]
    sb = scoreboard(rows, bar=1.14)
    assert sb["libraries_scored"] == 0
    assert sb["per_library"][0]["ratio"] is None


def test_underpowered_verdict_below_five_libraries():
    sb = scoreboard(_rows({"a": ([120], [100]), "b": ([130], [100])}), bar=1.14)
    assert "UNDERPOWERED" in sb["verdict"]


def test_sign_test_exact():
    assert _sign_test(0, 0) == 1.0
    assert round(_sign_test(5, 0), 4) == 0.0625   # all wins, n=5, two-sided
    assert _sign_test(1, 1) == 1.0


def test_median_uses_the_best_lifted_arm_per_library():
    rows = _rows({"a": ([80], [100])})
    rows += [{"library": "a", "arm": "lifted:better", "cov": 150}]
    sb = scoreboard(rows, bar=1.14)
    # best lifted (150) beats dev (100) -> ratio 1.5, not the weaker 0.8 arm
    assert sb["per_library"][0]["ratio"] == 1.5
