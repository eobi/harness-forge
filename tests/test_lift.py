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


def test_a_cxx_cast_is_unwrapped_before_the_argument_is_read():
    """`readJson(reinterpret_cast<const char*>(Data), Size)` is how a C++ harness hands
    bytes to a C API. The first version of this fix unwrapped the cast AFTER a strip that
    removes the trailing `)`, so the expression no longer ended in one, the pattern never
    matched, and the fix changed nothing while looking correct."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    readJson(reinterpret_cast<const char*>(Data), Size);
    return 0;
}
"""))
    got = {a.param: a.source for a in L.ir.sequence[0].args}
    assert got == {"a0": "input", "a1": "length_of"}, got


def test_a_skipped_accessor_is_not_also_reported_as_unread():
    """`strings.back().data()` -- `.data()` is excluded from the name-based check as std
    plumbing, and was re-added through the member-call path, which subtracted only the
    FuzzedDataProvider methods. Thirty-three harnesses were untrusted because two checks
    disagreed about the same set."""
    L = c_harness.lift(_c("""
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string s(reinterpret_cast<const char*>(data), size);
    parse_it(s.data(), s.size());
    return 0;
}
"""))
    assert "data" not in L.missed and "size" not in L.missed, L.missed


def test_cxx_value_local_is_not_a_leak():
    """`auto opts = set_options();` is destroyed at scope exit, not leaked.

    Regression for boost/boost_programoptions_fuzzer.cc, in which every object is a stack
    local and S1 reported each one as leaking. `is_ptr` says True for a class type because
    it asks about argument shape, which is the wrong question for ownership.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto opts = set_options();
    parse_config(data, size, opts);
    return 0;
}
"""))
    assert [r.storage for r in L.ir.resources if r.id == "r_opts"] == ["inline"]
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_auto_hiding_malloc_still_leaks():
    """The hole in the rule above, pinned: `auto` can hide a pointer, so a raw allocator
    keeps its handle no matter how the slot was declared.

    `strdup` rather than `malloc` deliberately -- malloc is excluded from callsites
    altogether, so a malloc version of this test asserts against a resource that does not
    exist and passes whatever the rule does.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto q = strdup("x");
    parse_config(data, size, q);
    return 0;
}
"""))
    assert [r.storage for r in L.ir.resources if r.id == "r_q"] == ["handle"]


def test_destroy_guarded_by_its_own_null_check_is_unconditional():
    """`if (msg != NULL) free_msg(msg);` is cleanup, not a conditional free.

    The arm where the free does not run is the arm where the resource was never created,
    so nothing survives the return either way. Regression for
    protobuf-c/unpack_fuzzer.c, which reported a leak it does not have.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Msg *msg = msg_unpack(data, size);
    if (msg != NULL) {
        msg_free_unpacked(msg, 0);
    }
    return 0;
}
"""))
    assert L.ir.apis["msg_free_unpacked"].role == "destroy"
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_a_negative_null_guard_still_reports():
    """`if (x == NULL) free(x);` guards the arm where the resource is ABSENT. Freeing
    there is a real defect and must keep reaching the gates."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Msg *msg = msg_unpack(data, size);
    if (msg == NULL) {
        msg_free_unpacked(msg, 0);
    }
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" in codes


def test_the_out_parameter_is_not_the_input_struct_beside_it():
    """`f(&hints, &res)` fills `res`; `hints` is a struct the harness owns and passes IN.

    Binding the first `&x` bound `hints` and left `res` created by nothing, so libevent's
    utils_fuzzer.cc reported a double destroy and two use-after-frees of a resource no op
    had ever created -- three blocking violations from one mis-chosen argument.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    lookup_common(data, size, &hints, &res);
    if (res != NULL) {
        freeaddrinfo(res);
    }
    return 0;
}
"""))
    assert [op.binds for op in L.ir.sequence if op.api == "lookup_common"] == ["r_res"]
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert not [c for c in codes if c.startswith("S1.")], codes


def test_a_slot_can_be_filled_twice():
    """Create, free, create again through the SAME out-parameter is two lifetimes.

    Once `res` was a known resource the second `&res` matched the plain-resource branch,
    so the second create bound nothing and its free read as a double destroy of the first.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct addrinfo *res = NULL;
    lookup(data, size, &res);
    if (res != NULL) { freeaddrinfo(res); }
    res = NULL;
    lookup(data, size, &res);
    if (res != NULL) { freeaddrinfo(res); }
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.DOUBLE_DESTROY" not in codes
    assert "S1.USE_AFTER_DESTROY" not in codes


def test_a_free_in_one_switch_arm_does_not_reach_a_use_in_another():
    """openvpn/fuzz_list.c is a state machine: a switch inside a for, freeing the hash in
    one case and iterating it in another. The cases never both run."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct hash *h = NULL;
    for (int i = 0; i < 4; i++) {
        switch (pick(data, size)) {
        case 0:
            h = hash_init(8);
            break;
        case 1:
            if (h) { hash_free(h); h = NULL; }
            break;
        case 2:
            if (h) { hash_iterator_init(h); }
            break;
        }
    }
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.USE_AFTER_DESTROY" not in codes
    assert "S1.DOUBLE_DESTROY" not in codes


def test_a_plain_free_is_a_destroy():
    """`free(p)` is the most common cleanup in C. It is excluded from callsites so that
    allocator noise does not become ops, and that exclusion made every resource released
    by a plain free read as leaked -- s2geometry mallocs through a local wrapper and frees
    the result two lines later."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *nt = null_terminated(data, size);
    if (nt == NULL) { return 0; }
    parse_it(nt);
    free(nt);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_auto_bound_to_a_new_ish_call_is_a_handle():
    """`auto d = exif_data_new_from_data(..)` is a handle somebody must release; `auto opts
    = set_options()` is a value. `auto` hides the difference, so the NAME decides."""
    handle = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto d = exif_data_new_from_data(data, size);
    dump(d);
    return 0;
}
"""))
    assert "S1.LEAK" in {v.code for g in run_static_gates(handle.ir) for v in g.violations}

    value = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto opts = set_options();
    parse_config(data, size, opts);
    return 0;
}
"""))
    assert "S1.LEAK" not in {v.code for g in run_static_gates(value.ir) for v in g.violations}


def test_a_smart_pointer_factory_is_not_a_handle():
    """`make_unique` matches the new-ish vocabulary but its whole point is that the
    destructor runs, so it must not be promoted to a handle.

    Written WITHOUT template arguments on purpose. `absl::make_unique<T>()` is not lifted
    as a call at all -- the angle brackets defeat the call pattern -- so in s2geometry's
    own harness `index` becomes a resource through the `&index` out-parameter on the line
    after, and a test using that form would pass without ever reaching this rule.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto index = make_unique(data, size);
    build_index(index);
    return 0;
}
"""))
    assert [r.storage for r in L.ir.resources if r.id == "r_index"] == ["inline"]
    assert "S1.LEAK" not in {v.code for g in run_static_gates(L.ir) for v in g.violations}


def test_a_balanced_ref_and_unref_is_not_a_destroy():
    """`ref(md); unref(md); count(md);` leaves md exactly as it was. Reading the unref as
    a destroy reported the count as a use-after-free. Regression for libexif's loader."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ExifData *d = exif_data_new_from_data(data, size);
    ExifMnoteData *md = exif_data_get_mnote_data(d);
    exif_mnote_data_ref(md);
    exif_mnote_data_unref(md);
    exif_mnote_data_count(md);
    exif_data_unref(d);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.USE_AFTER_DESTROY" not in codes
    assert "S1.DOUBLE_DESTROY" not in codes


def test_an_unmatched_unref_still_releases():
    """An unref with no ref before it is the release. libexif's from_data harness ends in
    `exif_data_unref(image)` and must not read as a leak."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ExifData *d = exif_data_new_from_data(data, size);
    if (d) {
        dump(d);
        exif_data_unref(d);
    }
    return 0;
}
"""))
    assert "S1.LEAK" not in {v.code for g in run_static_gates(L.ir) for v in g.violations}


def test_cleanup_on_an_early_return_path_is_not_a_double_free():
    """openvpn/fuzz_proxy.c frees everything and RETURNS on each validation failure, then
    frees again on the normal path. Control never reaches both -- but the early arm is a
    DESCENDANT of the top level, not a sibling, so mutual exclusion alone cannot see it."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *user = get_string(data, size);
    if (strlen(user) == 0) {
        free(user);
        return 0;
    }
    use_it(user);
    free(user);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.DOUBLE_DESTROY" not in codes
    assert "S1.USE_AFTER_DESTROY" not in codes


def test_a_braceless_branch_body_still_carries_its_guard():
    """`if (fa != NULL) fa_free(fa);` -- augeas frees six resources in exactly that shape.

    The braceless path passed neither arm nor guard, so these statements reached the gates
    with no branch context at all: the null-guard rule could not see the guard, and mutual
    exclusion could not see the arm.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct fa *fa1 = NULL;
    fa_compile(data, size, &fa1);
    if (fa1 != NULL)	fa_free(fa1);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_a_named_resource_beats_taint_so_ownership_stays_visible():
    """Taint spreads through handles: a context built over `data` taints every handle
    derived from it, and classifying those as INPUT hid ownership entirely -- so a borrowed
    pointer obtained from a dictionary read as an owned handle that leaks."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(0, (void *)data);
    cmsHANDLE hDict = cmsDictAlloc(context);
    const cmsDICTentry* entry = cmsDictGetEntryList(hDict);
    cmsDictNextEntry(entry);
    cmsDictFree(hDict);
    cmsDeleteContext(context);
    return 0;
}
"""))
    assert any(a.source == "resource" and a.ref == "r_hDict"
               for op in L.ir.sequence if op.api == "cmsDictGetEntryList"
               for a in op.args), "hDict must reach the gates as a resource, not as input"
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_a_cast_input_is_still_input():
    """`(void *)data` bound as a LITERAL: lstrip eats the cast's own opening paren, and the
    cast pattern then cannot match because it needs a leading `(`. The harness read as
    consuming nothing at all."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_it(0, (void *)data, size);
    return 0;
}
"""))
    assert any(a.source == "input" for op in L.ir.sequence for a in op.args), \
        "the cast argument is the only input this harness has"


def test_a_harness_local_collector_frees_in_bulk():
    """openvpn allocates through `gb_get_random_string()` and releases everything with
    `gb_cleanup()`; apache-httpd pairs `af_gb_*` with `af_gb_cleanup()`. The resource is
    never named at the free, so pairing by resource cannot see it -- and this is the shape
    that made S1.LEAK unreadable in the first place."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    gb_init();
    char *s = gb_get_random_string(data, size);
    use_it(s);
    gb_cleanup();
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes
    assert "S1.FREED_IN_BULK" in codes


def test_a_shared_prefix_alone_does_not_excuse_a_leak():
    """The narrowing that makes the rule above safe. `msg_unpack` and `msg_free_unpacked`
    share a prefix too, so keying on the prefix alone suppressed leaks across every
    well-named C library. A collector is distinguished by naming NO resource: it frees what
    the harness can no longer name. A free that takes its target is ordinary pairing."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Msg *msg = msg_unpack(data, size);
    Msg *other = msg_unpack(data, size);
    if (other != NULL) { msg_free_unpacked(other, 0); }
    use_it(msg);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" in codes, "msg is genuinely leaked and msg_free_unpacked names a target"


def test_a_resource_parked_in_a_struct_field_is_still_that_resource():
    """openvpn's proxy harness does `pi.proxy_authenticate = tmp;` and later
    `free(pi.proxy_authenticate)`. The free names the FIELD, the create named the variable,
    and nothing connected them.

    Two halves are needed and both are pinned here: the field assignment registers the
    alias, and the dotted expression resolves to the FIELD rather than the base -- reading
    left to right picked `pi`, itself a resource, and left the parked value marked live.
    """
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct proxy_info pi;
    setup(&pi, data, size);
    char *tmp_auth = get_random_string();
    pi.proxy_authenticate = tmp_auth;
    send_it(&pi);
    free(pi.proxy_authenticate);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.LEAK" not in codes


def test_a_free_verb_must_be_a_segment_not_a_substring():
    """"send" contains "end". A substring search made `nghttp2_session_mem_send2(session,
    &data)` a DESTROY of the session, and nghttp2's harness reported a double free and a
    use-after-free it does not have.

    Both directions matter: `freeaddrinfo` is a single segment and must still read as a
    free, so strong verbs match as a prefix while short ones must be the whole segment --
    otherwise "end" claims `endian` and "del" claims `delimiter`.
    """
    from hforge.lift.c_harness import _FREE_ISH
    for yes in ("freeaddrinfo", "evutil_freeaddrinfo", "g_obex_packet_free",
                "nghttp2_session_callbacks_del", "lldpd_port_cleanup", "exif_data_unref"):
        assert _FREE_ISH.search(yes), yes
    for no in ("nghttp2_session_mem_send2", "endian_swap", "delimiter_parse",
               "finish_parse", "xmlBufferAppend"):
        assert not _FREE_ISH.search(no), no


def test_a_slot_refilled_from_an_arena_leaks_nothing():
    """pjsip's auth harness parses twice into the same `msg`, both allocations taken from a
    pool that is released at the end. The first value is not leaked because nothing owned
    it individually -- ownership already knew this, and only the end-of-harness leak check
    was consulting it."""
    L = c_harness.lift(_c("""
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pj_pool_t *pool = create_pool(1000);
    pjsip_msg *msg = parse_sip_message(pool, data, size);
    handle(msg);
    msg = parse_sip_message(pool, data, size);
    handle(msg);
    release_pool(pool);
    return 0;
}
"""))
    codes = {v.code for g in run_static_gates(L.ir) for v in g.violations}
    assert "S1.DOUBLE_CREATE" not in codes
