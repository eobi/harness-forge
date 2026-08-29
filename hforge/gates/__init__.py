"""The gate bank. Static gates run on the plan; dynamic gates run against a build."""
from .result import GateResult, Violation, PASS, FAIL, NOT_RUN, BLOCK, WARN, INFO  # noqa: F401
