#!/usr/bin/env python3
"""The negative-capability survey: what a corpus of harnesses CANNOT find."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import bounds  # noqa: E402


def test_it_reads_a_disabled_detector(tmp_path):
    p = tmp_path / "someproj"
    p.mkdir()
    (p / "build.sh").write_text('echo "detect_leaks=0" >> $OUT/x.options\n')
    out = bounds.survey(tmp_path)
    assert "leaks_disabled" in out["someproj"]
    assert "build.sh" in out["someproj"]["leaks_disabled"]["seen_in"]


def test_a_project_that_disables_nothing_declares_no_bound(tmp_path):
    p = tmp_path / "clean"
    p.mkdir()
    (p / "build.sh").write_text("$CC $CFLAGS -c fuzz.c\n")
    assert bounds.survey(tmp_path) == {}


def test_an_input_cap_is_a_bound(tmp_path):
    """`max_len=1024` means no defect needing a longer input can ever be reached, however
    thoroughly the reachable part is covered."""
    p = tmp_path / "capped"
    p.mkdir()
    (p / "t.options").write_text("[libfuzzer]\nmax_len=1024\n")
    out = bounds.survey(tmp_path)
    assert "input_truncated" in out["capped"]
    assert "1024" in out["capped"]["input_truncated"]["why"]


def test_every_signal_says_what_cannot_be_FOUND(tmp_path):
    """A bound is a statement about findings, not about configuration. Each signal must
    describe the defect class that becomes invisible, because "detect_leaks=0" on its own
    tells a reader nothing about what the campaign's silence means."""
    for name, _pat, why in bounds.SIGNALS:
        assert len(why) > 20, name
        assert not why.startswith("detect"), name
