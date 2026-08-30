"""GUI track: the classification rules, exercised without a display.

The judgement lives in `classify`, so it can be tested on this machine while the session
plumbing is exercised in a container. Every case below is one that was observed on a real
application, not an invented shape.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.gui.linux_atspi import GuiOutcome, classify, error_nodes        # noqa: E402


def test_a_refusal_is_not_a_finding():
    """THE case this track exists for. eog shows `info bar 'Error'` for a malformed PNG and
    keeps its window open. The first driver called that UNRESPONSIVE and reported five false
    hangs out of six inputs -- a harness defect wearing the costume of a finding."""
    v = classify(tree=[("frame", "eog"), ("info bar", "Error"), ("icon", "Error")],
                 exited=False, window_ms=380.0, serviced_action=True)
    assert v.outcome is GuiOutcome.REJECTED
    assert not v.is_finding(), "a target refusing bad input is working, not failing"


def test_a_refusal_outranks_liveness():
    """An application showing an error must not be called hung merely because it kept the
    window up. REJECTED is decided before the liveness check for exactly this reason."""
    v = classify(tree=[("frame", "eog"), ("alert", "dialog-error-symbolic")],
                 exited=False, window_ms=400.0, serviced_action=False)
    assert v.outcome is GuiOutcome.REJECTED


def test_a_hang_is_a_finding():
    v = classify(tree=[("frame", "eog"), ("drawing area", "")],
                 exited=False, window_ms=400.0, serviced_action=False)
    assert v.outcome is GuiOutcome.UNRESPONSIVE
    assert v.is_finding()


def test_a_dead_process_is_a_crash_whatever_the_tree_said():
    v = classify(tree=[("frame", "eog"), ("info bar", "Error")],
                 exited=True, window_ms=400.0, serviced_action=None)
    assert v.outcome is GuiOutcome.CRASHED and v.is_finding()


def test_no_window_is_not_a_pass():
    """Nothing mapped means nothing was tested. Reporting that as 'accepted' is the GUI
    version of a build failure reported as a clean run."""
    v = classify(tree=[], exited=False, window_ms=None, serviced_action=None)
    assert v.outcome is GuiOutcome.NO_WINDOW
    assert not v.is_finding()


def test_a_valid_file_is_accepted():
    v = classify(tree=[("frame", "eog"), ("drawing area", ""), ("status bar", "1024x768")],
                 exited=False, window_ms=410.0, serviced_action=True)
    assert v.outcome is GuiOutcome.ACCEPTED


def test_the_detector_matches_a_family_not_a_spelling():
    """eog says `info bar 'Error'`; evince says `alert 'dialog-error-symbolic'`. A detector
    keyed to one spelling works until the second toolkit."""
    assert error_nodes([("info bar", "Error")])
    assert error_nodes([("alert", "dialog-error-symbolic")])
    assert error_nodes([("label", "Could not load image: invalid header")])
    assert not error_nodes([("drawing area", ""), ("status bar", "2055 bytes")])


def test_a_warning_is_not_a_rejection():
    """evince raises `alert 'dialog-warning-symbolic'` for a malformed file it goes on to
    OPEN. Matching the role family alone called that a rejection — the mirror of the false
    hang, and just as wrong: an input that was processed, reported as one that was refused.
    Found by generalising to a second toolkit rather than by reasoning about it."""
    assert not error_nodes([("alert", "dialog-warning-symbolic")])
    v = classify(tree=[("frame", "evince"), ("alert", "dialog-warning-symbolic")],
                 exited=False, window_ms=520.0, serviced_action=True)
    assert v.outcome is GuiOutcome.ACCEPTED


def test_both_toolkit_spellings_of_a_real_error_are_caught():
    """eog: `info bar 'Error'`. evince: `alert 'dialog-error-symbolic'`, and it emits the
    eog spelling too. The family holds across both."""
    for node in (("info bar", "Error"), ("alert", "dialog-error-symbolic")):
        assert error_nodes([node]), node


def test_the_verdict_records_how_termination_was_decided():
    """A result reached by timeout means something different from one reached by
    quiescence, and a reader cannot tell them apart from the outcome alone."""
    from hforge.gui.linux_atspi import TerminationReason
    v = classify(tree=[("frame", "eog"), ("drawing area", "")], exited=False,
                 window_ms=330.0, serviced_action=True,
                 termination=TerminationReason.DEADLINE)
    assert v.outcome is GuiOutcome.ACCEPTED
    assert v.termination is TerminationReason.DEADLINE, (
        "an input that merely ran out of budget must not read as one that settled")
