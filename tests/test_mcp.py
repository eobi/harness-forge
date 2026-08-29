#!/usr/bin/env python3
"""M0-M4 — the tool surface, and the boundary a model cannot cross.

The engine's whole argument is that the arbiter was built before the model arrived. These
tests are what keeps that true once a model can call in.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.producers import model as model_producer                  # noqa: E402
from hforge_mcp import rings, safety                                   # noqa: E402
from hforge_mcp.server import Server                                   # noqa: E402

_pass = _fail = 0
ROOT = Path(__file__).resolve().parents[1]


def check(name, fn):
    global _pass, _fail
    try:
        fn()
        print(f"  ok   {name}")
        _pass += 1
    except AssertionError as e:
        print(f"  FAIL {name}\n       {e}")
        _fail += 1
    except Exception as e:                                             # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


# ── the flag allow-list ──────────────────────────────────────────────────────

def test_ordinary_build_flags_are_allowed():
    """An allow-list that refuses real builds gets removed, not obeyed. `-O1` in particular:
    an earlier version carried re.IGNORECASE and refused it as though it were `-o`."""
    for f in ("-DHAVE_CONFIG_H", "-I/src", "-O1", "-Os", "-g", "-Wall", "-std=c11",
              "-fno-omit-frame-pointer"):
        assert safety.check_flag(f) == f


def test_flags_that_make_a_compiler_an_execution_primitive_are_refused():
    for f in ("-fplugin=evil.so", "-Wl,--wrap=malloc", "-Xclang", "-specs=bad", "-B/tmp",
              "-o/tmp/x", "-lpthread", "-L/tmp", "-include/etc/passwd",
              "-fprofile-generate", "--param=x"):
        try:
            safety.check_flag(f)
            raise AssertionError(f"{f!r} passed the allow-list")
        except safety.Refused:
            pass


def test_shell_metacharacters_are_refused():
    for f in ("-DX=`id`", "-DX=$(id)", "-DX;id", "-DX|id"):
        try:
            safety.check_flag(f)
            raise AssertionError(f"{f!r} passed")
        except safety.Refused:
            pass


def test_a_symlink_out_of_the_root_is_refused():
    """Symlinks are resolved BEFORE the check. A link inside the root pointing at /etc is the
    whole attack, and checking the unresolved path passes it."""
    import tempfile, os
    root = Path(tempfile.mkdtemp())
    (root / "inside.txt").write_text("x")
    link = root / "escape"
    os.symlink("/etc", link)
    r = safety.Root.of(root)
    assert r.check(root / "inside.txt")
    try:
        r.check(link / "passwd")
        raise AssertionError("a symlink out of the root was accepted")
    except safety.Refused:
        pass


# ── the rings ────────────────────────────────────────────────────────────────

def test_ring_two_is_off_by_default():
    s = rings.Session(target_root=safety.Root.of(ROOT))
    try:
        rings._hf_certify(s, plan={"name": "x"})
        raise AssertionError("Ring 2 ran without an opt-in")
    except safety.Refused as e:
        assert "off by default" in str(e)


def test_a_tool_call_cannot_raise_its_own_ring():
    srv = Server(target_root=str(ROOT), max_ring=0)
    out = srv._call({"name": "hf_propose", "arguments": {"header": "x.h"}})
    body = json.loads(out["content"][0]["text"])
    assert out["isError"] and "ring" in body["error"]
    assert "cannot raise its own privilege" in body["how_to_enable"]


def test_ring_one_needs_a_declared_root():
    s = rings.Session()
    try:
        rings._hf_seed_mine(s, dirs=["/etc"])
        raise AssertionError("Ring 1 read the filesystem with no root declared")
    except safety.Refused:
        pass


def test_only_permitted_rings_are_advertised():
    srv = Server(target_root=str(ROOT), max_ring=0)
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {t.name for t in rings.RING0_TOOLS}, names
    assert "hf_certify" not in names


# ── the protocol ─────────────────────────────────────────────────────────────

def test_initialize_and_call_round_trip():
    srv = Server(target_root=str(ROOT))
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "hforge"
    out = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "hf_explain",
                                 "arguments": {"code": "S2.TYPE_CONFUSION"}}})
    body = json.loads(out["result"]["content"][0]["text"])
    assert body["known"] and "false findings" in body["explanation"]


def test_validate_returns_repairable_violations():
    """The inner loop only works because every violation carries `where` and `fix`. A
    verifier that returns 'invalid' produces a model that guesses."""
    srv = Server(target_root=str(ROOT))
    plan = json.loads((ROOT / "examples/hf_demo.broken.hir.json").read_text())
    out = srv._call({"name": "hf_validate", "arguments": {"plan": plan}})
    body = json.loads(out["content"][0]["text"])
    assert not body["shippable"] and body["blocking"]
    assert all(v.get("fix") for v in body["blocking"]), body["blocking"]


def test_the_session_record_counts_what_a_claim_would_rest_on():
    srv = Server(target_root=str(ROOT))
    plan = json.loads((ROOT / "examples/hf_demo.good.hir.json").read_text())
    srv._call({"name": "hf_validate", "arguments": {"plan": plan}})
    import tempfile
    p = srv.write_session(Path(tempfile.mkdtemp()) / "s.json")
    rec = json.loads(p.read_text())
    assert rec["proposed"] == 1 and rec["calls"][0]["tool"] == "hf_validate"


# ── the model producer boundary ──────────────────────────────────────────────

def _good() -> dict:
    return json.loads((ROOT / "examples/hf_demo.good.hir.json").read_text())


def test_a_raw_block_from_a_model_is_refused():
    """Verbatim C that no static gate can see into. From a human it is an escape hatch
    marked UNCERTIFIED; from a model it bypasses the entire static layer."""
    p = _good()
    p["raw_blocks"] = [{"id": "x", "where": "prologue", "code": "system(\"id\");",
                        "reason": "x"}]
    try:
        model_producer.accept(p, model="claude")
        raise AssertionError("a raw block was accepted from a model")
    except model_producer.Rejected as e:
        assert "bypassed the entire static layer" in str(e)


def test_a_self_supplied_score_is_stripped_not_honoured():
    p = _good()
    p["confidence"] = 0.99
    p["score"] = 10
    ir, notes = model_producer.accept(p, model="claude")
    assert not hasattr(ir, "confidence")
    assert any("supplies no score" in n for n in notes), notes


def test_provenance_is_stamped_so_a_certificate_can_say_who_proposed_it():
    ir, _ = model_producer.accept(_good(), model="claude", version="5")
    assert ir.producer == "llm:claude@5"


def test_the_proposer_does_not_choose_what_gets_compiled():
    """sources, include dirs and cflags decide what the machine executes. A proposal that
    could set them would be choosing that."""
    from hforge.ir import Target
    p = _good()
    p.setdefault("target", {})["sources"] = ["/etc/evil.c"]
    ir, notes = model_producer.accept(p, model="claude",
                                      target=Target(name="ours", sources=["ok.c"]))
    assert ir.target.sources == ["ok.c"], ir.target.sources
    assert any("operator's decision" in n for n in notes)


def test_inline_c_in_an_op_is_refused():
    p = _good()
    p["sequence"][0]["code"] = "system(\"id\");"
    try:
        model_producer.accept(p, model="claude")
        raise AssertionError("inline C was accepted")
    except model_producer.Rejected as e:
        assert "the emitter writes the C" in str(e)


def test_the_ranking_cannot_see_the_producer():
    """The day a model producer exists is the day someone is tempted to weight it."""
    from hforge.gates.result import passed
    from hforge.producers import rank
    g = [passed("D8", "campaign", edges=100, coverage_grew=True)]
    a = rank.score("same", "header_graph", g)
    b = rank.score("same", "llm:claude@5", g)
    assert a.key == b.key


# ── Ring 2 isolation ─────────────────────────────────────────────────────────

def test_ring_two_fails_closed_without_isolation():
    """The opt-in says the operator WANTS to build. It does not say the host can contain
    what gets built. A sandbox that silently turns itself off is worse than none, because
    the operator believes there is one."""
    from hforge_mcp import sandbox
    s = rings.Session(target_root=safety.Root.of(ROOT), ring2_enabled=True,
                      isolation=sandbox.Isolation(False, why_not="no engine in this test"))
    try:
        rings._hf_certify(s, plan={"name": "x"})
        raise AssertionError("Ring 2 built on the host with no isolation")
    except safety.Refused as e:
        assert "refused rather than" in str(e).lower()


def test_the_sandbox_states_what_it_guarantees():
    from hforge_mcp import sandbox
    d = sandbox.describe(sandbox.Isolation(True, engine="docker"))
    joined = " ".join(d["guarantees"])
    assert "no network" in joined and "read-only" in joined
    assert "fail closed" in d["policy"]


def test_sandbox_run_refuses_when_unavailable():
    from hforge_mcp import sandbox
    try:
        sandbox.run(["true"], iso=sandbox.Isolation(False, why_not="none"),
                    target_root=ROOT, scratch=ROOT / "build" / "x")
        raise AssertionError("ran with no isolation")
    except safety.Refused:
        pass


# ── the repair loop ──────────────────────────────────────────────────────────

def _validate_via_server(srv):
    def go(plan):
        return json.loads(
            srv._call({"name": "hf_validate", "arguments": {"plan": plan}})
            ["content"][0]["text"])
    return go


def test_the_repair_loop_converges_on_the_fix_strings_alone():
    """The control, not a stand-in for a model. A mechanical repairer that reads nothing but
    the returned `fix` text either converges — proving the messages are actionable — or it
    does not, in which case no model will do better on the same output and the GATE MESSAGES
    are the thing to fix."""
    from hforge_mcp import loop
    srv = Server(target_root=str(ROOT))
    broken = json.loads((ROOT / "examples/hf_demo.broken.hir.json").read_text())
    r = loop.repair_loop(broken, loop.FixStringRepairer(), _validate_via_server(srv))
    assert r.converged, r.summary
    assert len(r.rounds) <= 4, r.summary
    assert [s["kind"] for s in r.plan["slices"]] == ["cstring"]
    assert any(o.get("guarded_by") for o in r.plan["sequence"])


def test_the_loop_says_when_it_cannot_repair_rather_than_looping():
    from hforge_mcp import loop

    class Useless(loop.Repairer):
        name = "useless"

        def repair(self, plan, violations):
            return None

    srv = Server(target_root=str(ROOT))
    broken = json.loads((ROOT / "examples/hf_demo.broken.hir.json").read_text())
    r = loop.repair_loop(broken, Useless(), _validate_via_server(srv))
    assert not r.converged and "no repair available" in r.gave_up


def test_the_loop_is_bounded():
    from hforge_mcp import loop

    class Churn(loop.Repairer):
        name = "churn"

        def repair(self, plan, violations):
            p = dict(plan)
            p["notes"] = (p.get("notes") or "") + "."
            return p

    srv = Server(target_root=str(ROOT))
    broken = json.loads((ROOT / "examples/hf_demo.broken.hir.json").read_text())
    r = loop.repair_loop(broken, Churn(), _validate_via_server(srv), max_rounds=3)
    assert not r.converged and "after 3 rounds" in r.gave_up


# ── logging ──────────────────────────────────────────────────────────────────

def test_stdout_carries_protocol_and_nothing_else():
    """STDOUT IS THE PROTOCOL. One stray print corrupts the JSON-RPC stream and the client
    reports a parse error instead of the thing you were trying to say."""
    import subprocess, tempfile
    msgs = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "hf_explain", "arguments": {"code": "F7"}}}),
    ])
    log = Path(tempfile.mkdtemp()) / "s.jsonl"
    r = subprocess.run([sys.executable, "-m", "hforge_mcp",
                        "--target-root", str(ROOT), "--log", str(log)],
                       input=msgs, capture_output=True, text=True, cwd=str(ROOT),
                       timeout=120)
    for line in r.stdout.splitlines():
        if line.strip():
            json.loads(line)          # every stdout line must be valid JSON-RPC
    assert r.stderr.strip(), "nothing was logged to stderr"
    assert "server started" in r.stderr


def test_a_refusal_is_logged_as_a_warning():
    """A boundary that stops something and says nothing has no evidence it ever worked."""
    import subprocess, tempfile
    log = Path(tempfile.mkdtemp()) / "s.jsonl"
    msgs = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "hf_propose",
                                  "arguments": {"header": "/etc/passwd"}}})
    subprocess.run([sys.executable, "-m", "hforge_mcp", "--target-root",
                    str(ROOT / "examples"), "--log", str(log)],
                   input=msgs, capture_output=True, text=True, cwd=str(ROOT), timeout=120)
    events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    warn = [e for e in events if e["level"] == "warning"]
    assert warn, events
    assert "REFUSED" in warn[0]["msg"] and warn[0]["reason"]


def test_the_jsonl_log_survives_without_a_clean_exit():
    """`--session-out` only writes at exit, and long sessions usually end by being killed.
    The event log is appended and flushed per event."""
    import subprocess, tempfile
    log = Path(tempfile.mkdtemp()) / "s.jsonl"
    msgs = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    subprocess.run([sys.executable, "-m", "hforge_mcp", "--target-root", str(ROOT),
                    "--log", str(log)], input=msgs, capture_output=True, text=True,
                   cwd=str(ROOT), timeout=120)
    events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert events and events[0]["msg"] == "server started"
    assert all("t" in e and "level" in e for e in events)


def test_quiet_suppresses_stderr_but_not_the_file():
    import subprocess, tempfile
    log = Path(tempfile.mkdtemp()) / "s.jsonl"
    msgs = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    r = subprocess.run([sys.executable, "-m", "hforge_mcp", "--target-root", str(ROOT),
                        "--log", str(log), "--quiet"], input=msgs, capture_output=True,
                       text=True, cwd=str(ROOT), timeout=120)
    assert not r.stderr.strip()
    assert log.read_text().strip()


# ── the reachability walk ────────────────────────────────────────────────────

def test_the_call_graph_walk_visits_each_function_once():
    """It marked `seen` on POP, not on PUSH, so every caller of a shared helper re-enqueued
    it and the frontier grew far past the vertex set — O(V*E). A BFS over 4,368 functions
    took 5.6 SECONDS, which is what made ordering sqlite's candidates take half an hour."""
    from hforge.analysis.sinks import CodeMap, Function
    # A hub every node calls: the shape that made the old walk quadratic.
    fns = {"entry": Function(name="entry", file="f.c", start_line=1, end_line=2, body="",
                             calls={f"n{i}" for i in range(60)})}
    for i in range(60):
        fns[f"n{i}"] = Function(name=f"n{i}", file="f.c", start_line=1, end_line=2,
                                body="", calls={"hub"})
    fns["hub"] = Function(name="hub", file="f.c", start_line=1, end_line=2, body="",
                          calls=set())
    m = CodeMap(functions=fns, sinks=[], files=["f.c"])
    got = m.reachable_from(["entry"])
    assert "hub" in got and len(got) == 62, len(got)


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"mcp + model boundary — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
