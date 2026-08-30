"""Linux GUI driver: AT-SPI as the oracle, one isolated session per input.

WHAT WAS ACTUALLY BLOCKING THIS, recorded because it cost two wrong theories: GTK stalls
before mapping a window when XDG_RUNTIME_DIR is unset, and says NOTHING -- the process
stays alive, exits nothing, logs nothing. That reads as "GTK applications do not work
headlessly", which is false. Accessibility can stay on; it costs no window, and a harness
that cannot see dialogs cannot tell rejection from a hang.

THREE MEASURED FACTS this module is built on, reproduced in a container:

  * The window appears in about half a second (0.20-0.55 s across runs). POLL WITH A
    DEADLINE, never sleep a fixed time: a guess is both far too slow and unable to
    distinguish "not yet" from "never".

  * The tree keeps GROWING after the window maps. Stopping at the first showing node misses
    the error element entirely -- measured: an eog error bar appears only after the window
    is already up, so a driver that stops early reports every malformed file as accepted.

  * Error signalling is a FAMILY of roles, not one spelling. eog says `info bar 'Error'`,
    evince says `alert 'dialog-error-symbolic'`. Matching one spelling works until the
    second toolkit, which is the same shape as the byte-spelling list in the C producer.

Discrimination measured over a graded PNG corpus, one isolated session each:

    valid       122 nodes   accepted
    truncated   122 nodes   accepted     <- CORRECT: libpng renders the partial image
    hdr_only    133 nodes   rejected     info bar 'Error'
    badmagic    133 nodes   rejected
    badcrc      133 nodes   rejected
    garbage     133 nodes   rejected

`truncated` is accepted because the target is right to accept it, not because the oracle
missed it. An oracle judged only on the inputs it flags is not being judged.

GENERALISED TO A SECOND TOOLKIT BEFORE BEING BELIEVED, which is what caught the one defect
in the rule above. On evince with a ghostscript-produced PDF corpus:

    valid       132 nodes   accepted
    badhdr      132 nodes   accepted     <- poppler tolerates a corrupted header
    truncated   141 nodes   rejected     alert 'dialog-error-symbolic' + info bar 'Error'
    garbage     141 nodes   rejected     both spellings again

evince emits BOTH spellings, so the family holds. But it also raises `alert
'dialog-warning-symbolic'` for a malformed file it goes on to OPEN, and matching the role
alone called that a rejection -- the mirror of the false hang: an input that was processed,
reported as one that was refused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence

# The FAMILY, not a spelling. Grows once per toolkit rather than once per application.
ERROR_ROLES: tuple = ("info bar", "alert", "dialog", "notification", "alert dialog")

# Names that mark an error even when the role is generic. Kept small and case-folded.
ERROR_NAME_HINTS: tuple = ("error", "failed", "cannot", "unable", "invalid", "corrupt")

# A WARNING IS NOT A REJECTION, and matching the role family alone got this wrong.
#
# Measured on evince: a malformed-but-openable PDF produces `alert
# 'dialog-warning-symbolic'` while a genuinely unreadable one produces `alert
# 'dialog-error-symbolic'`. Both carry the `alert` role. Treating the role as sufficient
# classified a file the target had OPENED as refused -- the mirror of the false-hang this
# module exists to prevent, and just as wrong: it turns a processed input into a pass that
# was never processed.
#
# Checked before the error hints, because `dialog-warning-symbolic` contains neither an
# error word nor anything else to disqualify it; only the warning marker distinguishes it.
WARNING_NAME_HINTS: tuple = ("warning", "warn", "caution")


# ── P6.TERM: when is one GUI input finished? ─────────────────────────────────
#
# THE OBSERVER CHANGES THE OBSERVED, and this is measured rather than argued. Polling the
# accessibility tree makes the target service every request, so it never stops burning CPU:
#
#     CPU polled alone                   quiesces at 0.96 s,   26 ticks
#     CPU polled WHILE walking AT-SPI    NEVER quiesces,      201 ticks
#     CPU polled alone (repeat)          quiesces at 0.92 s,   18 ticks
#
# Eight times the CPU, and no quiescent point at all. A driver that walks the tree in a loop
# AND uses CPU quiescence to decide an input is finished therefore reports EVERY input as a
# hang -- a third way to manufacture a false hang, after the error-bar-as-hang and the
# warning-as-rejection already found here.
#
# So the two signals must not be used together, and the order matters:
#
#   1. WAIT FOR QUIESCENCE WITHOUT LOOKING. Cheap, non-invasive, and it is the signal that
#      actually means "the process has stopped working on this input".
#   2. THEN ENUMERATE ONCE for the verdict.
#
# Tree stability is kept as the fallback for targets whose CPU never settles -- an animated
# viewer, a spinner -- where quiescence is not available at any price.
QUIESCE_POLLS = 6            # consecutive unchanged CPU samples that count as settled
QUIESCE_INTERVAL_S = 0.05    # between samples; ~0.3 s of stillness at the default
WINDOW_DEADLINE_S = 15.0     # a window maps in 0.11-0.55 s measured; this is a ceiling


class TerminationReason(str, Enum):
    """Why the driver decided this input was finished. Recorded on the verdict, because a
    result reached by timeout means something different from one reached by quiescence."""

    QUIESCED = "quiesced"            # the process stopped consuming CPU
    TREE_STABLE = "tree_stable"      # fallback: the accessibility tree stopped changing
    DEADLINE = "deadline"            # neither settled; the budget ran out


class GuiOutcome(str, Enum):
    """What one input did to the application.

    REJECTED is the outcome the first driver did not have, and the one that matters: it is
    a PASS, not a finding. Without it a correctly-behaving target reports as five hangs out
    of six inputs.
    """

    ACCEPTED = "accepted"            # the file was opened and no error surfaced
    REJECTED = "rejected"            # the target refused it and said so — NOT a finding
    UNRESPONSIVE = "unresponsive"    # window up, but the process does not service actions
    NO_WINDOW = "no_window"          # nothing mapped inside the deadline
    CRASHED = "crashed"              # the process died


@dataclass
class GuiVerdict:
    outcome: GuiOutcome
    nodes: int = 0
    window_ms: Optional[float] = None
    action_ms: Optional[float] = None
    evidence: list = field(default_factory=list)
    note: str = ""
    termination: Optional[TerminationReason] = None

    def is_finding(self) -> bool:
        """Only a crash or a genuine hang is a candidate. A refusal is the target working."""
        return self.outcome in (GuiOutcome.CRASHED, GuiOutcome.UNRESPONSIVE)


def _is_error_node(role: str, name: Optional[str]) -> bool:
    low = (name or "").lower()
    # A warning wearing an error role is still a warning. evince raises `alert
    # 'dialog-warning-symbolic'` for a file it went on to open.
    if any(h in low for h in WARNING_NAME_HINTS) and not any(h in low for h in ERROR_NAME_HINTS):
        return False
    if role in ERROR_ROLES:
        return True
    return any(h in low for h in ERROR_NAME_HINTS)


def error_nodes(tree: Sequence) -> list:
    """Error elements in an accessibility tree given as (role, name) pairs.

    Accepts the tuples a walker produces rather than live AT-SPI objects, so the decision
    is testable without a display -- the part that encodes the judgement should not need
    an X server to exercise.
    """
    out = []
    for entry in tree:
        role = entry[0] if len(entry) > 0 else ""
        name = entry[1] if len(entry) > 1 else ""
        if _is_error_node(str(role), name):
            out.append((str(role), name))
    return out


def classify(*, tree: Sequence, exited: bool, window_ms: Optional[float],
             serviced_action: Optional[bool], action_ms: Optional[float] = None,
             termination: Optional[TerminationReason] = None) -> GuiVerdict:
    """One input's outcome, from what was observed. Pure, so the rules are testable.

    Order matters. A dead process is a crash whatever its last tree said; a target that
    never mapped a window was never tested; and REJECTED is checked BEFORE liveness because
    an application showing an error bar is behaving correctly and must not be reported as a
    hang just because it kept the window open.
    """
    errs = error_nodes(tree)
    if exited:
        return _v(termination, GuiOutcome.CRASHED, len(tree), window_ms, action_ms, errs,
                          "the process died while the input was open")
    if window_ms is None:
        return _v(termination, GuiOutcome.NO_WINDOW, len(tree), None, action_ms, errs,
                          "no window mapped inside the deadline; nothing was tested")
    if errs:
        return _v(termination, GuiOutcome.REJECTED, len(tree), window_ms, action_ms, errs,
                          "the target refused this input and said so — a pass, not a finding")
    if serviced_action is False:
        return _v(termination, GuiOutcome.UNRESPONSIVE, len(tree), window_ms, action_ms, errs,
                          "a window is up and the process does not service accessibility "
                          "actions: hung, and independent of what the window shows")
    return _v(termination, GuiOutcome.ACCEPTED, len(tree), window_ms, action_ms, errs,
                      "opened without an error element")


def _v(termination, outcome, nodes, window_ms, action_ms, evidence, note) -> GuiVerdict:
    return GuiVerdict(outcome, nodes, window_ms, action_ms, evidence, note, termination)
