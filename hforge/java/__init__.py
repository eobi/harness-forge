"""The JVM half. Everything here answers a question the C half never had to ask.

The two markers below are a PROTOCOL, not an implementation detail: the replay driver prints
one of them and the toolchain reads it. They live here rather than in the emitter because the
reader must not depend on the writer — plancheck C12 caught exactly that import on its first
real outing, which is the check working.

The reason they exist at all: a JVM process that dies of an uncaught exception exits 1, and
so does a missing input file, a bad classpath, and a JVM that would not start. There is no
exit code that means "this faulted", so the driver never asks anyone to infer one.
"""

FAULT_MARKER = "===HFORGE-FAULT==="
CLEAN_MARKER = "===HFORGE-CLEAN==="
