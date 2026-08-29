"""A Model Context Protocol server over stdio.

JSON-RPC 2.0, line-delimited, no third-party dependency — the engine runs offline in a
container and a tool surface that needs a package index is a tool surface that is unavailable
when it matters.

Every response is the same structured JSON the CLI renders as prose. A model reading
`{"blocking": [{"code": "S2.TYPE_CONFUSION", "fix": "..."}]}` can converge; one reading a
formatted table has to parse English first.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Optional

from . import rings, safety

PROTOCOL_VERSION = "2024-11-05"
SERVER = {"name": "hforge", "version": "1.0.0"}

# STDOUT IS THE PROTOCOL. A single stray `print()` corrupts the JSON-RPC stream and the
# client sees a parse error rather than the thing you were trying to tell it. Every diagnostic
# goes to one of three places instead, because three different readers need different things:
#
#   stderr        a human tailing the server, and what an MCP client captures by default
#   <log>.jsonl   appended per event, so a KILLED session still has a record
#   the client    MCP `notifications/message`, for a model that should see its own warnings
LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


class Server:
    def __init__(self, target_root: Optional[str] = None, ring2: bool = False,
                 max_ring: int = 1, model: str = "", log_path: Optional[str] = None,
                 level: str = "info", quiet: bool = False) -> None:
        self.session = rings.Session(
            target_root=safety.Root.of(target_root) if target_root else None,
            ring2_enabled=ring2, model=model)
        # The operator decides how far the surface extends. Default is Ring 1: the whole
        # Tier-0 play (targets, seeds, dictionaries, proposal) with nothing built.
        self.max_ring = rings.RING2 if ring2 else max_ring
        self.level = LEVELS.get(level, 20)
        self.quiet = quiet
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._out = sys.stdout
        self.started = time.time()
        self.log("info", "server started", model=model, max_ring=self.max_ring,
                 target_root=target_root, pid=os.getpid())

    # ── logging ─────────────────────────────────────────────────────────────

    def log(self, level: str, message: str, **fields) -> None:
        """One event, to every reader that wants it. Never to stdout."""
        if LEVELS.get(level, 20) < self.level:
            return
        rec = {"t": round(time.time() - self.started, 3), "level": level,
               "msg": message, **fields}

        if not self.quiet:
            extra = " ".join(f"{k}={v}" for k, v in fields.items() if v not in (None, ""))
            sys.stderr.write(f"[{rec['t']:8.3f}] {level:<7} {message}"
                             + (f"  {extra}" if extra else "") + "\n")
            sys.stderr.flush()

        if self.log_path:
            # Appended per event and flushed. A session that is killed — which is how long
            # runs usually end — still leaves everything up to the kill.
            with self.log_path.open("a") as f:
                f.write(json.dumps(rec, default=str) + "\n")

        if level in ("warning", "error") and getattr(self, "_client_logging", False):
            self._notify("notifications/message",
                         {"level": level, "logger": "hforge", "data": rec})

    def _notify(self, method: str, params: dict) -> None:
        """A server-initiated notification: no id, no reply expected."""
        try:
            self._out.write(json.dumps({"jsonrpc": "2.0", "method": method,
                                        "params": params}) + "\n")
            self._out.flush()
        except Exception:                                        # noqa: BLE001
            pass

    # ── protocol ────────────────────────────────────────────────────────────

    def handle(self, msg: dict) -> Optional[dict]:
        mid, method = msg.get("id"), msg.get("method", "")
        try:
            if method == "initialize":
                caps = ((msg.get("params") or {}).get("capabilities") or {})
                self._client_logging = "logging" in caps
                self.log("info", "initialize",
                         client=((msg.get("params") or {}).get("clientInfo") or {})
                         .get("name", "?"))
                return self._ok(mid, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}, "logging": {}},
                    "serverInfo": SERVER,
                    "instructions": self._instructions()})
            if method in ("notifications/initialized", "initialized"):
                return None
            if method == "tools/list":
                return self._ok(mid, {"tools": [
                    {"name": t.name,
                     "description": f"[ring {t.ring}] {t.summary}",
                     "inputSchema": t.schema}
                    for t in rings.ALL_TOOLS if t.ring <= self.max_ring]})
            if method == "tools/call":
                return self._ok(mid, self._call(msg.get("params") or {}))
            if method == "ping":
                return self._ok(mid, {})
            return self._err(mid, -32601, f"unknown method {method!r}")
        except Exception as e:                                   # noqa: BLE001
            return self._err(mid, -32603, f"{type(e).__name__}: {e}",
                             traceback.format_exc(limit=3))

    def _call(self, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        tool = rings.BY_NAME.get(name)
        if tool is None:
            return self._text({"error": f"no such tool {name!r}"}, is_error=True)
        if tool.ring > self.max_ring:
            return self._text({
                "error": f"{name} is a ring-{tool.ring} tool and this session allows up to "
                         f"ring {self.max_ring}.",
                "how_to_enable": "the OPERATOR raises the ring when starting the server; a "
                                 "tool call cannot raise its own privilege."}, is_error=True)
        t0 = time.time()
        try:
            out = tool.fn(self.session, **args)
            self.session.record(name, args, ok=True)
            self.log("info", f"call {name}", ring=tool.ring,
                     ms=int((time.time() - t0) * 1000))
            return self._text(out)
        except safety.Refused as e:
            self.session.record(name, args, ok=False, note=str(e))
            # A refusal is the boundary working, and it is the single most important thing in
            # the log: it is the record that something was attempted and stopped.
            self.log("warning", f"REFUSED {name}", ring=tool.ring, reason=str(e)[:200])
            return self._text({"refused": str(e)}, is_error=True)
        except Exception as e:                                   # noqa: BLE001
            self.session.record(name, args, ok=False, note=f"{type(e).__name__}")
            self.log("error", f"failed {name}", error=f"{type(e).__name__}: {e}")
            return self._text({"error": f"{type(e).__name__}: {e}"}, is_error=True)

    @staticmethod
    def _text(payload: dict, is_error: bool = False) -> dict:
        return {"content": [{"type": "text",
                             "text": json.dumps(payload, indent=2, default=str)}],
                "isError": is_error}

    @staticmethod
    def _ok(mid, result) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _err(mid, code, message, data=None) -> dict:
        e = {"code": code, "message": message}
        if data:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": e}

    def _instructions(self) -> str:
        return (
            "Harness Forge. You propose fuzzing harnesses as IR; a gate bank you cannot "
            "read, influence or appear in decides whether they are any good.\n\n"
            "Start with hf_schema and hf_gates. Write a plan, call hf_validate, read the "
            "`fix` on every violation, repair, revalidate. That loop executes nothing and is "
            "cheap to run many times.\n\n"
            "Rules that will reject you outright: exactly one slice may take the remainder; "
            "fuzzer bytes may only be bound to a pointer-to-byte parameter; a resource is "
            "created once and destroyed once; a raw_block from a model producer is refused.\n\n"
            "You do not score plans. When no gate distinguishes two candidates the engine "
            "refuses to name a winner, and a confidence you supply cannot change that.")

    # ── session record ──────────────────────────────────────────────────────

    def write_session(self, path: Path) -> Path:
        """What a claim about this session would have to rest on.

        `plans proposed versus plans that survived the gates` is the number that makes a
        model-vs-deterministic comparison a result rather than an anecdote, and the plan
        hashes are what make it checkable by someone else.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "server": SERVER,
            "model": self.session.model,
            "max_ring": self.max_ring,
            "target_root": str(self.session.target_root.path)
            if self.session.target_root else None,
            "calls": self.session.calls,
            "plans_seen": self.session.plans_seen,
            "proposed": len(self.session.plans_seen),
        }, indent=2))
        return path


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="hforge-mcp",
                                 description="MCP server over the Harness Forge engine")
    ap.add_argument("--target-root", help="the only tree Ring 1 may read")
    ap.add_argument("--ring", type=int, default=1, choices=(0, 1, 2),
                    help="highest ring exposed (default 1: reads and proposes, builds "
                         "nothing)")
    ap.add_argument("--allow-build", action="store_true",
                    help="enable Ring 2, which COMPILES AND RUNS code. Off by default.")
    ap.add_argument("--session-out", help="write the session record here on exit")
    ap.add_argument("--model", default="", help="model identity, recorded in the session")
    ap.add_argument("--log", help="append one JSON object per event here; survives a kill, "
                                  "unlike --session-out which only writes on exit")
    ap.add_argument("--log-level", default="info",
                    choices=("debug", "info", "warning", "error"))
    ap.add_argument("--quiet", action="store_true",
                    help="no stderr output; use with --log when a client already captures "
                         "stderr for its own purposes")
    args = ap.parse_args(argv)

    srv = Server(target_root=args.target_root, ring2=args.allow_build,
                 max_ring=args.ring, model=args.model, log_path=args.log,
                 level=args.log_level, quiet=args.quiet)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = srv.handle(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        srv.log("info", "server stopped", calls=len(srv.session.calls),
                plans=len(srv.session.plans_seen))
        if args.session_out:
            srv.write_session(Path(args.session_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
