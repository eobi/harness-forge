#!/usr/bin/env python3
"""Phase 4 — lifting somebody else's C harness into the IR.

This is the domain the field is judged on: grading harnesses you did not write. Every test
here pins a FALSE POSITIVE the lifter produced against sqlite's real production harnesses,
because the first four audits were noise and every one would have been a wasted report to a
maintainer.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.gates.result import BLOCK                            # noqa: E402
from hforge.gates.static_gates import run_static_gates           # noqa: E402
from hforge.lift import c_harness                                # noqa: E402

_pass = _fail = 0


def check(name, fn):
    global _pass, _fail
    try:
        fn()
        print(f"  ok   {name}")
        _pass += 1
    except AssertionError as e:
        print(f"  FAIL {name}\n       {e}")
        _fail += 1
    except Exception as e:                                       # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


def _c(text: str) -> str:
    f = Path(tempfile.mkdtemp()) / "h.c"
    f.write_text(text)
    return str(f)


CLEAN = """
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    magic_t m = magic_open(0);
    magic_load(m, 0);
    magic_buffer(m, data, size);
    magic_close(m);
    return 0;
}
"""

USE_AFTER_FREE = CLEAN.replace("    return 0;",
                               "    magic_buffer(m, data, size);\n    return 0;")


def test_lifts_a_harness_into_ops_and_resources():
    L = c_harness.lift(_c(CLEAN))
    assert L is not None
    assert [o.api for o in L.ir.sequence] == [
        "magic_open", "magic_load", "magic_buffer", "magic_close"], \
        [o.api for o in L.ir.sequence]
    assert len(L.ir.resources) == 1


def test_detects_use_after_destroy_in_someone_elses_harness():
    """The P1 class QuartetFuzz reports finding in production harnesses."""
    L = c_harness.lift(_c(USE_AFTER_FREE))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S1.USE_AFTER_DESTROY" in codes, codes


def test_scalar_status_is_not_a_resource():
    """`int rc = sqlite3_open(...)` is the most common line in a C fuzz harness. Treating
    `rc` as a created object reported DOUBLE_CREATE and LEAK on every one of them — ordinary
    C, flagged as a defect. Four false positives against sqlite came from this alone."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int rc = 0;
    sqlite3 *db = 0;
    rc = sqlite3_open(":memory:", &db);
    rc = sqlite3_exec(db, "SELECT 1", 0, 0, 0);
    sqlite3_close(db);
    return 0;
}
"""))
    ids = {r.id for r in L.ir.resources}
    assert "r_rc" not in ids, f"a status code was modelled as a resource: {ids}"
    assert "r_db" in ids, ids


def test_out_parameter_creates_its_resource():
    """`rc = sqlite3_exec(db, sql, cb, 0, &zErrMsg)` — the return is a scalar status while
    the resource comes back through the address. Missing this made the later
    `sqlite3_free(zErrMsg)` read as a use-before-create."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *zErrMsg = 0;
    sqlite3 *db = 0;
    int rc = sqlite3_exec(db, "x", 0, 0, &zErrMsg);
    sqlite3_free(zErrMsg);
    return 0;
}
"""))
    creator = next((o for o in L.ir.sequence if o.binds == "r_zErrMsg"), None)
    assert creator is not None, [(o.api, o.binds) for o in L.ir.sequence]


def test_a_prototype_is_not_a_harness():
    """`ossshell.c` declares the entry point and calls it from main. Matching that prototype
    and taking the next `{` grabbed an unrelated function's body and graded it as a
    defective harness. It is not a harness at all."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    read_file(argv[1]);
    return 0;
}
"""))
    assert L is None, "a prototype was lifted as though it were a definition"


def test_input_survives_a_memcpy():
    """A harness that copies `data` into a buffer and parses the buffer was reported as
    never consuming its input at all."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    memcpy(buf, data, size);
    parse_it(buf, size);
    free(buf);
    return 0;
}
"""))
    consumed = any(a.source == "input" for o in L.ir.sequence for a in o.args)
    assert consumed, "the fuzzer's bytes were lost at the memcpy"


BRANCHING = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sqlite3 *db = 0;
    if (size < 4) return 0;
    if (sqlite3_open(":memory:", &db)) return 0;
    sqlite3_exec(db, "SELECT 1", 0, 0, 0);
    sqlite3_close(db);
    return 0;
}
"""


def test_call_in_a_condition_is_seen_and_runs_unconditionally():
    """`if (sqlite3_open(":memory:", &db)) return 0;` puts the call in the CONDITION, which
    always executes. A statement regex anchored on `;` never saw it, so `db` looked as
    though nothing created it and the later `sqlite3_close(db)` was reported as a
    use-before-create. That single miss produced most of the false positives against
    sqlite's real harnesses."""
    L = c_harness.lift(_c(BRANCHING))
    assert L is not None
    assert any(o.api == "sqlite3_open" for o in L.ir.sequence), \
        [o.api for o in L.ir.sequence]
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S1.USE_BEFORE_CREATE" not in codes, \
        f"a guarded-but-certain creation was still reported as missing: {codes}"


def test_a_branching_harness_can_now_be_graded_confidently():
    """Branches used to disqualify a lift outright. They are modelled now, so a harness
    whose values can be attributed is gradeable even with guards in it."""
    L = c_harness.lift(_c(BRANCHING))
    assert L.branches >= 2, L.branches
    assert L.high_fidelity, L.why_low_fidelity


def test_a_conditional_free_is_hedged_not_asserted():
    """A destroy on ONE branch, followed by a use, is a POSSIBLE use-after-free. Marking the
    resource dead would report every later use as certain, on a path that may never run —
    and the difference decides whether a maintainer gets emailed."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    magic_t m = magic_open(0);
    if (size > 4) { magic_close(m); }
    magic_buffer(m, data, size);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S1.USE_AFTER_DESTROY" not in codes, \
        "a conditional free was asserted as a certain use-after-free"
    assert L.hedged, "the conditional free was dropped instead of hedged"
    assert "POSSIBLE" in " ".join(L.hedged)


def test_low_attribution_still_disqualifies_a_lift():
    """What still disqualifies a lift is not being able to attribute the VALUES: if most
    arguments are opaque, the call graph reported is not the one that runs."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    do_thing(g_a, g_b, g_c, g_d);
    do_other(g_e, g_f, g_g, g_h);
    return 0;
}
"""))
    assert L is not None and not L.high_fidelity, L.why_low_fidelity


def test_a_straight_line_harness_is_high_fidelity():
    L = c_harness.lift(_c(CLEAN))
    assert L.high_fidelity, L.why_low_fidelity


def test_a_withheld_claim_is_withheld_whole():
    """An earlier hedge dropped `targets` while still declaring the API role `destroy`, and
    gate S3 then reported "destroy names no resource" — a false positive created by the
    hedge itself. If a claim is being withheld it must be withheld whole."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *zErr = 0;
    sqlite3 *db = 0;
    int rc = sqlite3_open(":memory:", &db);
    for (int i = 0; i < 2; i++) {
        rc = sqlite3_exec(db, "SELECT 1", 0, 0, &zErr);
        sqlite3_free(zErr);
    }
    sqlite3_close(db);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S3.DESTROY_NO_TARGET" not in codes, \
        f"the hedge produced its own false positive: {codes}"


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"lift — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
