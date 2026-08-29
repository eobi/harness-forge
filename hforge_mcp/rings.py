"""The tools, grouped by blast radius.

Rings are not about whether a subprocess runs — Ring 1 runs the C preprocessor, `ldd` and a
compiler probe. They are about what a hostile caller could achieve:

| ring | executes | worst case |
|---|---|---|
| 0 | nothing | a malformed plan |
| 1 | compiler front end, `ldd` | code execution **unless flags are allow-listed** |
| 2 | full build + campaign | code execution, plus a fuzzer holding a socket |

Ring 0 is safe unconditionally and is where the repair loop lives. Rings 1 and 2 pass every
path and every flag through `safety` first, and Ring 2 additionally requires an explicit
per-session opt-in.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from hforge import corpus, platform as plat
from hforge.gates.result import BLOCK
from hforge.gates.static_gates import run_static_gates
from hforge.ir import HarnessIR
from hforge.findings import ladder

from . import safety, sandbox

RING0, RING1, RING2 = 0, 1, 2


@dataclass
class Tool:
    name: str
    ring: int
    summary: str
    schema: dict
    fn: Callable


@dataclass
class Session:
    """One agent session. Holds the opt-in state and the record."""
    target_root: Optional[safety.Root] = None
    ring2_enabled: bool = False
    isolation: Optional[object] = None      # sandbox.Isolation, checked at enable time
    model: str = ""
    calls: list = field(default_factory=list)
    plans_seen: list = field(default_factory=list)

    def record(self, tool: str, args: dict, ok: bool, note: str = "") -> None:
        self.calls.append({"tool": tool, "args": _redact(args), "ok": ok, "note": note})


def _redact(args: dict) -> dict:
    out = {}
    for k, v in (args or {}).items():
        if k == "plan" and isinstance(v, dict):
            out[k] = f"<plan {v.get('name', '?')}>"
        elif isinstance(v, str) and len(v) > 200:
            out[k] = v[:200] + "…"
        else:
            out[k] = v
    return out


# ── Ring 0 — pure, executes nothing ─────────────────────────────────────────

def _hf_schema(_s: Session, **_) -> dict:
    """The Harness IR, described well enough to write one without reading the source."""
    return {
        "version": "1",
        "top_level": ["name", "target", "apis", "slices", "resources", "sequence",
                      "knobs", "platforms", "producer", "raw_blocks", "notes"],
        "resource_storage": {
            "handle": "the library returns a pointer: magic_t m = magic_open(0)",
            "inline": "the CALLER allocates and passes its address: "
                      "yaml_parser_t p; yaml_parser_initialize(&p)",
            "out_param": "the library writes the pointer back through an argument: "
                         "sqlite3_open(path, &db)",
        },
        "arg_sources": {
            "input": "bytes from the fuzzer, via a declared slice",
            "length_of": "the length of a named slice",
            "resource": "a live resource from the graph",
            "literal": "a constant; use 0 for NULL",
            "out": "an out-parameter the library fills in",
        },
        "slice_kinds": ["bytes", "cstring", "u8", "u16le", "u32le", "u64le"],
        "rules_that_will_reject_you": [
            "exactly ONE slice may take the remainder; a second unbounded slice is "
            "inexpressible and the emitter refuses it",
            "fuzzer bytes may only be bound to a pointer-to-byte parameter — void*, char*, "
            "unsigned char*, uint8_t*. Binding them to a struct pointer or a function "
            "pointer is S2.TYPE_CONFUSION and is blocking",
            "a resource is created once, used only while live, destroyed once",
            "a raw_block is UNCERTIFIED and is refused outright from a model producer",
        ],
    }


def _hf_gates(_s: Session, **_) -> dict:
    """Every gate, what it checks, and when it runs."""
    return {
        "static": {
            "S1": "lifetime: created once, destroyed once, never used after",
            "S2": "contract: NUL-termination, (ptr,len) pairs, ownership, type confusion",
            "S3": "ordering: create before use before destroy",
            "S4": "boundary: public interface only",
            "S5": "input flow: the fuzzer's bytes reach the target",
            "S6": "error handling: failure returns checked before use",
        },
        "dynamic": {
            "D1": "liveness: the target call survived the optimiser",
            "D2": "positive control: the harness finds a PLANTED defect",
            "D3": "valid input must not crash",
            "D4": "sink reachability",
            "D5": "execution rate is plausible",
            "D6": "determinism, as a rate",
            "D7": "knobs recorded, and what they exclude computed",
            "D8": "campaign productivity: edges the fuzzer can actually see",
            "D9": "misuse provenance",
            "D11": "differential consistency across producers",
        },
        "findings": {f"F{i}": t for i, t in enumerate(
            ["", "reproduce (as a rate)", "minimise", "attribute to target vs harness",
             "cross-variant replay", "instrumentation artifact", "novelty",
             "ladder rung", "exclusions"]) if t},
        "note": "a gate never returns a boolean. NOT_RUN is a distinct verdict, so an "
                "absent check never reads as a passed one.",
    }


def _hf_explain(_s: Session, code: str = "", **_) -> dict:
    """The principle behind a violation code, so the rules are readable before they are hit."""
    book = {
        "S1": ("P1 lifetime", "A resource is created once, used only while it is live, and "
                              "destroyed once. Use-after-destroy in a harness produces "
                              "crashes that are the harness's own."),
        "S2": ("P2 protocol", "The API's stated requirements versus what the plan feeds it. "
                              "The cJSON exact-size-buffer defect produced eight false "
                              "reports against a library that was behaving correctly."),
        "S2.TYPE_CONFUSION": ("P2 protocol",
                              "Fuzzer bytes bound to a pointer the library will dereference. "
                              "It will read that as a real object, so EVERY crash is the "
                              "harness's own invalid pointer. The single largest source of "
                              "false findings in the literature, and decidable from the plan."),
        "S5": ("P4 input flow", "The fuzzer's bytes must reach the target. A harness that "
                                "runs a fixed program cannot find anything."),
        "D1": ("liveness", "If the target call is not an undefined symbol in the object, the "
                           "optimiser deleted it and the campaign searches an empty function."),
        "D2": ("positive control", "A harness that cannot detect a defect PLANTED in its own "
                                   "path will not detect a real one."),
        "D8": ("campaign productivity", "A correct harness linked against a prebuilt library "
                                        "sees only its own edges: random testing at speed."),
        "F3": ("attribution", "Whose memory was it. A fault in the harness's own buffer is "
                              "the harness's bug, and reporting it wastes a maintainer."),
        "F7": ("the ladder", "A finding sits at the highest rung whose oracle PASSED. Rung 3 "
                             "needs an oracle independent of the one that discovered it — "
                             "ASan confirming ASan is one witness, not two."),
    }
    key = code.strip()
    hit = book.get(key) or book.get(key.split(".")[0])
    if not hit:
        return {"code": key, "known": False,
                "hint": "try a gate id (S2, D8, F7) or a violation code (S2.TYPE_CONFUSION)"}
    return {"code": key, "known": True, "principle": hit[0], "explanation": hit[1]}


def _hf_platforms(_s: Session, **_) -> dict:
    return {"platforms": {p.id: {"sanitizers": list(p.sanitizers),
                                 "allocator": p.allocator,
                                 "trust_ceiling": p.trust_ceiling,
                                 "max_rung": p.ceiling_rung}
                          for p in plat.PLATFORMS.values()},
            "ladder": [{"rung": r.n, "claim": r.claim, "oracle": r.oracle}
                       for r in ladder.LADDER],
            "note": "the trust ceiling is the highest ladder rung a finding observed ONLY on "
                    "that platform may reach."}


def _hf_validate(s: Session, plan: Optional[dict] = None, **_) -> dict:
    """Run S1-S6 on a plan the caller supplies. No filesystem, no compiler, no subprocess.

    This is the inner repair loop: every violation carries `where` and `fix`, so a caller
    can converge instead of guessing.
    """
    if not plan:
        return {"error": "no plan supplied"}
    try:
        ir = HarnessIR.from_json(plan)
    except Exception as e:                                       # noqa: BLE001
        return {"error": f"the plan is not valid IR: {type(e).__name__}: {e}"}

    if ir.raw_blocks and str(ir.producer).startswith(("llm", "model")):
        return {"error": "a raw_block is verbatim C that no gate can see into, and it is "
                         "refused outright from a model producer. Express the construct in "
                         "IR or drop the entry point.",
                "refused": "RAW_BLOCK_FROM_MODEL"}

    results = list(run_static_gates(ir))
    s.plans_seen.append({"name": ir.name, "ir_sha256": ir.sha256()
                         if hasattr(ir, "sha256") else "", "producer": ir.producer})
    blocking = [v.to_json() for g in results for v in g.violations if v.severity == BLOCK]
    return {
        "plan": ir.name,
        "shippable": not blocking,
        "blocking": blocking,
        "gates": [g.to_json() for g in results],
        "next": ("emit and gate it dynamically" if not blocking else
                 "fix the blocking violations above; each carries `where` and `fix`"),
    }


RING0_TOOLS = [
    Tool("hf_schema", RING0, "the Harness IR schema and the rules that reject a plan",
         {"type": "object", "properties": {}}, _hf_schema),
    Tool("hf_gates", RING0, "every gate and what it checks",
         {"type": "object", "properties": {}}, _hf_gates),
    Tool("hf_explain", RING0, "the principle behind a gate or violation code",
         {"type": "object", "properties": {"code": {"type": "string"}},
          "required": ["code"]}, _hf_explain),
    Tool("hf_platforms", RING0, "the platform matrix, trust ceilings and the ladder",
         {"type": "object", "properties": {}}, _hf_platforms),
    Tool("hf_validate", RING0, "run the static gates on a plan; executes nothing",
         {"type": "object", "properties": {"plan": {"type": "object"}},
          "required": ["plan"]}, _hf_validate),
]


# ── Ring 1 — reads the target tree, and invokes tools ───────────────────────
#
# Every path is confined to the declared root and every flag passes the allow-list, because
# `hf_propose` runs the C preprocessor, `hf_targets` shells out to `ldd`, and `hf_doctor`
# compiles a probe. `-E` does not make a compiler safe.

def _need_root(s: Session) -> safety.Root:
    if s.target_root is None:
        raise safety.Refused("no target root declared for this session. Ring 1 reads the "
                             "filesystem, so the operator must name the tree it may read.")
    return s.target_root


def _hf_propose(s: Session, header: str = "", also_headers: Optional[list] = None,
                sources: Optional[list] = None, include_dirs: Optional[list] = None,
                cflags: Optional[list] = None, name: str = "",
                max_len: int = 4096, **_) -> dict:
    """Synthesise candidate plans from a header. Runs the preprocessor; nothing is built."""
    from hforge.ir import Knobs, Target
    from hforge.producers import header_graph

    root = _need_root(s)
    hdrs = [str(root.check(header))] + root.check_all(also_headers)
    tgt = Target(name=name or Path(header).stem,
                 public_headers=[Path(h).name for h in hdrs],
                 include_dirs=root.check_all(include_dirs) or
                 sorted({str(Path(h).parent) for h in hdrs}),
                 sources=root.check_all(sources),
                 cflags=safety.check_flags(cflags))
    plans = header_graph.propose(hdrs, tgt, platforms=["linux-x86_64-glibc"],
                                 knobs=Knobs(max_len=max_len))
    out = []
    for ir in plans:
        gates = list(run_static_gates(ir))
        blocking = [v.to_json() for g in gates for v in g.violations if v.severity == BLOCK]
        out.append({"name": ir.name, "shippable": not blocking,
                    "blocking": [b["code"] for b in blocking],
                    "entry": next((o.api for o in ir.sequence if o.id == "o_consume"), ""),
                    "max_len": ir.knobs.max_len, "plan": ir.to_json()})
    return {"proposed": len(out), "shippable": sum(1 for p in out if p["shippable"]),
            "plans": out}


def _hf_targets(s: Session, binaries: Optional[list] = None, **_) -> dict:
    """Shortlist unfuzzed input-parsing dependencies of shipped programs."""
    from hforge.targets import ossfuzz
    root = _need_root(s)
    known = ossfuzz.load_known()
    surveys = [ossfuzz.survey(str(root.check(b)), known) for b in (binaries or [])]
    surveys = [x for x in surveys if x]
    return {"surveyed": len(surveys),
            "candidates": [{"library": d.stem, "path": d.path, "reason": d.reason}
                           for sv in surveys for d in sv.candidates],
            "note": "the known-fuzzed list is a FLOOR, not the OSS-Fuzz registry. Verify each "
                    "candidate before spending days on it."}


def _hf_seed_mine(s: Session, dirs: Optional[list] = None, max_bytes: int = 65536,
                  **_) -> dict:
    from hforge.analysis import seeds
    root = _need_root(s)
    c = seeds.mine(root.check_all(dirs), max_bytes=max_bytes)
    return {"seeds": len(c.files), "bytes": c.total_bytes, "summary": c.summary()}


def _hf_dict(s: Session, sources: Optional[list] = None, limit: int = 512, **_) -> dict:
    from hforge.analysis import dictionary
    root = _need_root(s)
    toks = dictionary.extract(root.check_all(sources), limit=limit)
    return {"tokens": len(toks), "sample": toks[:40]}


def _hf_audit(s: Session, harnesses: Optional[list] = None, **_) -> dict:
    from hforge.lift.c_harness import lift
    root = _need_root(s)
    rows = []
    for h in (harnesses or []):
        p = root.check(h)
        lifted = lift(str(p))
        if lifted is None:
            rows.append({"file": str(p), "liftable": False,
                         "why": "no LLVMFuzzerTestOneInput definition"})
            continue
        gates = list(run_static_gates(lifted.ir))
        blocking = [v.to_json() for g in gates for v in g.violations
                    if v.severity == BLOCK]
        rows.append({"file": str(p), "liftable": True,
                     "high_fidelity": lifted.high_fidelity,
                     "why_low": lifted.why_low_fidelity,
                     "blocking": blocking if lifted.high_fidelity else [],
                     "unverified": [b["code"] for b in blocking]
                     if not lifted.high_fidelity else []})
    return {"audited": len(rows), "results": rows,
            "note": "findings from a LOW FIDELITY lift are shown as unverified and are not "
                    "counted; a wasted maintainer email costs more than a missed bug."}


def _hf_doctor(s: Session, **_) -> dict:
    from hforge import toolchain as tc
    inv = tc.inventory()
    iso = s.isolation or sandbox.detect()
    s.isolation = iso
    return {"host": {"os": inv.host.os, "arch": inv.host.arch,
                     "platform": inv.host.platform_id},
            "tools": [{"name": t.name, "present": t.present,
                       "cost_if_absent": t.cost_if_absent} for t in inv.tools],
            "can_gate": inv.can_gate,
            "ring2": sandbox.describe(iso)}


RING1_TOOLS = [
    Tool("hf_propose", RING1, "synthesise candidate plans from a header (runs the "
                              "preprocessor; builds nothing)",
         {"type": "object", "properties": {
             "header": {"type": "string"}, "also_headers": {"type": "array"},
             "sources": {"type": "array"}, "include_dirs": {"type": "array"},
             "cflags": {"type": "array"}, "name": {"type": "string"},
             "max_len": {"type": "integer"}}, "required": ["header"]}, _hf_propose),
    Tool("hf_targets", RING1, "shortlist unfuzzed input-parsing dependencies",
         {"type": "object", "properties": {"binaries": {"type": "array"}},
          "required": ["binaries"]}, _hf_targets),
    Tool("hf_seed_mine", RING1, "mine example inputs from a project's test data",
         {"type": "object", "properties": {"dirs": {"type": "array"},
                                           "max_bytes": {"type": "integer"}},
          "required": ["dirs"]}, _hf_seed_mine),
    Tool("hf_dict", RING1, "mine a fuzzing dictionary from the target's string literals",
         {"type": "object", "properties": {"sources": {"type": "array"},
                                           "limit": {"type": "integer"}},
          "required": ["sources"]}, _hf_dict),
    Tool("hf_audit", RING1, "lift and grade harnesses somebody else wrote",
         {"type": "object", "properties": {"harnesses": {"type": "array"}},
          "required": ["harnesses"]}, _hf_audit),
    Tool("hf_doctor", RING1, "what this machine can do (compiles a probe)",
         {"type": "object", "properties": {}}, _hf_doctor),
]


# ── Ring 2 — builds and executes ────────────────────────────────────────────

def _need_ring2(s: Session) -> None:
    if not s.ring2_enabled:
        raise safety.Refused(
            "Ring 2 builds and runs code and is off by default. The operator must enable it "
            "for this session. Everything in Rings 0 and 1 remains available.")
    iso = s.isolation or sandbox.detect()
    s.isolation = iso
    if not iso.available:
        # Fail closed. The opt-in says the operator WANTS to build; it does not say the host
        # can contain what gets built.
        raise safety.Refused(
            f"Ring 2 is enabled but cannot be isolated: {iso.why_not}. Refused rather than "
            f"run on the host — a fuzzer is a program running attacker-shaped input against "
            f"a parser, and it is the last process that should hold a socket.")


def _hf_certify(s: Session, plan: Optional[dict] = None, campaign_seconds: int = 8,
                positive_control: bool = False, **_) -> dict:
    from hforge.certificate import build_certificate
    from hforge.emit import emit
    from hforge.emit.c_libfuzzer import EmitError
    from hforge.gates.dynamic_gates import build, run_dynamic_gates

    _need_ring2(s)
    root = _need_root(s)
    if not plan:
        return {"error": "no plan supplied"}
    ir = HarnessIR.from_json(plan)
    safety.check_flags(ir.target.cflags)
    root.check_all(ir.target.sources)
    root.check_all(ir.target.include_dirs)
    for l in ir.target.link_libs:
        safety.check_link(l)

    gates = list(run_static_gates(ir))
    if any(v.severity == BLOCK for g in gates for v in g.violations):
        return {"verdict": "rejected", "reason": "static gates blocked; nothing was built",
                "gates": [g.to_json() for g in gates]}
    try:
        em = emit(ir)
    except EmitError as e:
        return {"verdict": "rejected", "reason": f"emit refused: {e}"}
    art = build(ir, em)
    gates += run_dynamic_gates(ir, em, art,
                               valid_corpus=corpus.valid_only(ir).inputs,
                               drive_corpus=corpus.generate(ir).inputs,
                               positive_control=positive_control,
                               campaign=True, campaign_seconds=campaign_seconds)
    cert = build_certificate(ir, gates, em)
    return {"verdict": cert.verdict, "certificate": cert.to_json()}


RING2_TOOLS = [
    Tool("hf_certify", RING2, "emit, build, run the dynamic gates and a short campaign",
         {"type": "object", "properties": {
             "plan": {"type": "object"}, "campaign_seconds": {"type": "integer"},
             "positive_control": {"type": "boolean"}}, "required": ["plan"]}, _hf_certify),
]


ALL_TOOLS = RING0_TOOLS + RING1_TOOLS + RING2_TOOLS
BY_NAME = {t.name: t for t in ALL_TOOLS}
