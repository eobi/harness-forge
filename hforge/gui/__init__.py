"""The GUI track: driving a file into a windowed application and reading the result.

A GUI target needs a THIRD normal outcome beside processed and crashed, and getting that
wrong is not a detail. An application that opens a window, refuses a malformed file and
keeps the window up looks exactly like a hang from outside, and the first driver written
here called five of six inputs UNRESPONSIVE on that basis -- a harness defect wearing the
costume of a finding, which is the thing this engine exists to refuse.

The target was not hanging. It was correctly rejecting bad input and saying so, and only an
accessibility oracle can tell those apart from outside the process.

The taxonomy and the rejection-vs-hang rule (`GuiOutcome`, `classify`, `error_nodes`,
`is_finding`) are toolkit-independent and live in `linux_atspi`; each platform contributes
only its own observation layer. `macos_ax` is the Darwin sibling: it reads crashes from
DiagnosticReports (.ips) and rejections from the Accessibility (AX) tree, reusing the same
classifier. `driver_for_host()` picks the observation layer for the current host.
"""
from .linux_atspi import (                                        # noqa: F401
    GuiOutcome, GuiVerdict, TerminationReason, ERROR_ROLES, classify, error_nodes,
)


def driver_for_host():
    """Return the GUI observation module for the current host, or None if the track has no
    driver for it yet. Additive: an unknown host degrades to None, it does not raise."""
    try:
        from ..toolchain import host
        os_name = host().os
    except Exception:
        import platform
        os_name = {"Darwin": "macos", "Linux": "linux"}.get(platform.system(), "")
    if os_name == "macos":
        from . import macos_ax
        return macos_ax
    if os_name == "linux":
        from . import linux_atspi
        return linux_atspi
    return None
