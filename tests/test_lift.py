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
    src = _c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    read_file(argv[1]);
    return 0;
}
""")
    try:
        c_harness.lift(src)
    except c_harness.LiftError as e:
        # The REASON is pinned, not just the refusal. Three conditions used to return None
        # and the CLI reported all of them as "no entry point found", which sent a reader
        # after a defect that was not there.
        assert "definition" in str(e), str(e)
    else:
        raise AssertionError("a prototype was lifted as though it were a definition")


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


# ── fidelity must fail CLOSED ────────────────────────────────────────────────
#
# An audit of 372 production OSS-Fuzz harnesses put four in the reportable pile and all
# four were false positives. None was caused by a gate: the LIFTER built IR that did not
# match the harness, and the fidelity signal -- "values the lifter could not attribute" --
# cannot see a call or a flow that was never lifted at all. These pin the closed door.

def test_a_call_the_lifter_never_read_makes_the_lift_untrusted():
    """nettle calls `asn1_der_iterator_first(&iter, size, data)` inside an `if` condition.
    The lifter dropped it, reported zero unattributed values because every call it DID
    read was clean, and declared high fidelity. The gate then correctly said no op consumes
    input -- about a harness that consumes input fine."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct it iter;
    if (asn1_der_iterator_first(&iter, size, data) == 1) { use_it(&iter); }
    return 0;
}
"""))
    assert not L.high_fidelity
    assert any("asn1_der_iterator_first" in m for m in L.missed)


def test_input_reaching_the_target_by_a_path_we_cannot_follow_is_untrusted():
    """haproxy hands its parser a designated initialiser holding the input; lcms consumes
    it as data[0], data[1]. Every CALL is lifted in both, so a missed-call check stays
    silent -- but the flow was never followed and the harness looked inert."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct cfgfile f = { .content = (const char *)data, .size = size };
    parse_cfg(&f);
    return 0;
}
"""))
    assert not L.high_fidelity
    assert any("did not bind" in m for m in L.missed)


def test_a_size_guard_is_not_a_missed_flow():
    """`if (size < 4) return 0;` names the parameter without passing it anywhere, and
    nearly every harness has one. Counting guards as unfollowed flows made a correctly
    lifted branching harness untrusted -- a filter that rejects everything is not a
    filter."""
    L = c_harness.lift(_c(BRANCHING))
    assert L.high_fidelity, L.why_low_fidelity


def test_a_slot_the_harness_declares_needs_no_create_call():
    """`yajl_parser_config cfg = {...}; yajl_alloc(&callbacks, &cfg, NULL, &ctx);`

    The config is filled in BY THE CALLER and passed by address. Treating it as a resource
    awaiting a create reported S1.USE_BEFORE_CREATE against four correct production
    harnesses in the OSS-Fuzz fleet. Storage that the harness declares exists from its
    declaration; a pointer local is an out slot the library fills, and both are alive
    before the first call.
    """
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    yajl_parser_config cfg = { .allowComments = 1 };
    GError *err = NULL;
    yajl_handle parser = yajl_alloc(&cfg, &err);
    yajl_parse(parser, data, size);
    yajl_free(parser);
    return 0;
}
"""))
    kinds = {r.id: r.storage for r in L.ir.resources}
    assert kinds["r_cfg"] == "inline", kinds
    assert kinds["r_err"] == "out_param", kinds
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S1.USE_BEFORE_CREATE" not in codes, codes


def test_input_is_followed_through_a_fuzzed_data_provider():
    """`FuzzedDataProvider fdp(data, size); auto s = fdp.ConsumeRandomLengthString(64);`
    is how most modern harnesses shape their input. Every value it returns IS the fuzzer's
    bytes, so a library call receiving one consumes input -- without this the parameter
    looked used-once-and-dropped and the harness looked inert."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::string s = fdp.ConsumeRandomLengthString(64);
    parse_it(s);
    return 0;
}
"""))
    assert not any("Consume" in m for m in L.missed), L.missed


# ── branch arms: which path, not just how deep ───────────────────────────────

def test_sibling_blocks_are_mutually_exclusive_and_nested_ones_are_not():
    from hforge.lift import cflow
    b = cflow.parse("a(); if (x) { b(); } if (y) { c(); } d();")
    arms = {st.text.strip(): st.arm for st in b.stmts}
    assert arms["b();"] != arms["c();"]
    assert cflow.mutually_exclusive(arms["b();"], arms["c();"])
    assert not cflow.mutually_exclusive("1", "1.1")     # nested shares its parent's path
    assert not cflow.mutually_exclusive("", "1")        # top level excludes nothing


def test_each_switch_case_is_its_own_arm():
    """A switch body is a set of ALTERNATIVES, not one block. Treating it as one made
    every assignment in it a sibling of every other, so openvpn's `tmp` -- assigned in
    thirteen mutually exclusive cases and freed in each -- read as a resource created
    thirteen times with twelve leaked."""
    from hforge.lift import cflow
    # Multi-line, because the label split anchors at line starts -- a `case` in the middle
    # of a line is not how C is written and is not worth the ambiguity of matching there.
    b = cflow.parse("switch (k) {\ncase 1:\n  p();\n  break;\ncase 2:\n  q();\n  break;\n}")
    arms = {st.text.strip(): st.arm for st in b.stmts if st.text.strip() in ("p();", "q();")}
    assert len(set(arms.values())) == 2, arms
    assert cflow.mutually_exclusive(*arms.values())


def test_two_creates_on_exclusive_paths_are_not_a_double_create():
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *tmp;
    switch (size % 2) {
    case 0:
        tmp = get_string();
        use_it(tmp, data, size);
        free(tmp);
        break;
    case 1:
        tmp = get_string();
        other(tmp, data, size);
        free(tmp);
        break;
    }
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations
             if v.severity == BLOCK}
    assert "S1.DOUBLE_CREATE" not in codes, codes


def test_an_alias_carries_the_taint():
    """`const uint8_t *payload = data; size_t payload_len = size; parse(payload, len);`
    was the single most common shape this lifter could not follow. Both arguments bound as
    LITERALS and the harness was reported as consuming no input. It is not a C++ problem
    and not an exotic one -- it is an assignment."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *payload = data;
    size_t payload_len = size;
    parse_it(payload, payload_len);
    return 0;
}
"""))
    op = L.ir.sequence[0]
    got = {a.param: a.source for a in op.args}
    assert got == {"a0": "input", "a1": "length_of"}, got
    assert L.high_fidelity, L.why_low_fidelity


def test_an_untainted_name_cannot_invent_an_input_binding():
    """The alias rule is generous in ONE direction only. A local with no relationship to
    the fuzzer's bytes must not become an input, or the lifter would claim a harness
    consumes input that never touches it."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *fixed = "constant";
    parse_it(fixed, 7);
    consume(data, size);
    return 0;
}
"""))
    first = L.ir.sequence[0]
    assert all(a.source != "input" for a in first.args), [(a.param, a.source) for a in first.args]
