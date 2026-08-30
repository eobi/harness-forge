"""The GUI track: driving a file into a windowed application and reading the result.

A GUI target needs a THIRD normal outcome beside processed and crashed, and getting that
wrong is not a detail. An application that opens a window, refuses a malformed file and
keeps the window up looks exactly like a hang from outside, and the first driver written
here called five of six inputs UNRESPONSIVE on that basis -- a harness defect wearing the
costume of a finding, which is the thing this engine exists to refuse.

The target was not hanging. It was correctly rejecting bad input and saying so, and only an
accessibility oracle can tell those apart from outside the process.
"""
from .linux_atspi import (                                        # noqa: F401
    GuiOutcome, GuiVerdict, ERROR_ROLES, classify,
)
