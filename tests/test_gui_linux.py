"""Linux GUI driver: the portable, host-agnostic parts (crash-signal classification, /proc
CPU parsing, quiescence) tested on any host; the AT-SPI walk degrades to empty off-Linux."""
from hforge.gui import linux_atspi as L
from hforge.gui import GuiOutcome


def test_stat_cpu_parses_utime_plus_stime_with_parens_in_comm():
    # comm "(my app)" contains a space and parens; utime=100 stime=25 -> 125
    fields = ["1", "(my app)", "S"] + [str(i) for i in range(3, 52)]
    fields[13] = "100"   # field 14 (utime), 0-indexed 13
    fields[14] = "25"    # field 15 (stime)
    assert L._parse_stat_cpu(" ".join(fields)) == 125.0


def test_stat_cpu_bad_line_is_none():
    assert L._parse_stat_cpu("no paren here") is None


def test_quiescence_rule_matches_darwin():
    assert L.quiescence_reached([1, 2, 3, 3, 3, 3], polls=4) is True
    assert L.quiescence_reached([1, 2, 3, 4], polls=4) is False


def test_segv_returncode_is_a_memory_safety_crash():
    v = L._crash_from_returncode(-11)
    assert v.outcome is GuiOutcome.CRASHED and v.is_finding()
    assert "memory-safety" in v.note and v.evidence == [("SIGSEGV",)]


def test_abort_returncode_is_a_crash_but_not_memory_safety():
    v = L._crash_from_returncode(-6)
    assert v.outcome is GuiOutcome.CRASHED and "abort/other" in v.note


def test_clean_exit_is_not_a_crash():
    assert L._crash_from_returncode(0) is None


def test_ax_tree_is_empty_without_atspi():
    # on a non-Linux host (or without pyatspi) the walk must degrade, not raise
    assert L.ax_tree("anything") == []
