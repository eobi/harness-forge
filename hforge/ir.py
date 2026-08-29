"""The Harness IR — a harness is data, not code.

Every published harness generator emits C for one backend. A harness validated for
libFuzzer on Linux then tells you nothing about the same API under TinyInst on Windows,
and its defects are only discoverable by compiling and running it.

This module says a harness is a *plan*: a resource graph with lifetimes, an ordered call
sequence, a mapping from fuzzer bytes to arguments, and the API contracts the plan must
respect. Four things follow, and each is a capability the field does not have:

  1. ONE PLAN, MANY BACKENDS. The same IR emits a libFuzzer C harness, an AFL++ persistent
     loop, a TinyInst in-process driver, a GUI file-drop driver or an interpreter program.
     Certified semantics travel across OS and architecture.
  2. GATES BEFORE COMPILATION. Lifetime correctness, protocol compliance and ordering are
     properties of the plan. Checking them statically is strictly stronger than probing a
     compiled binary after the fact.
  3. THE IR IS THE CERTIFIABLE ARTIFACT. Versionable, diffable, publishable.
  4. THIRD-PARTY HARNESSES LIFT INTO IT, so somebody else's C can be graded.

An escape hatch exists (`RawBlock`) because a schema that cannot express real harnesses
would just be ignored. Anything inside a raw block is marked UNCERTIFIED and every gate
says so rather than silently passing it.

Pure dataclasses plus JSON round-trip. No I/O beyond `json`, no subprocess, no model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

# ── vocabulary ────────────────────────────────────────────────────────────────

# What an API call does to the resource graph. Ordering gates depend on these.
ROLE_CREATE = "create"      # returns a resource that must later be destroyed
ROLE_CONSUME = "consume"    # uses a resource and/or attacker input
ROLE_DESTROY = "destroy"    # releases a resource
ROLE_QUERY = "query"        # reads without transferring ownership
ROLE_RESET = "reset"        # returns a resource to its initial state
ROLES = (ROLE_CREATE, ROLE_CONSUME, ROLE_DESTROY, ROLE_QUERY, ROLE_RESET)

# Where an argument's value comes from.
SRC_INPUT = "input"         # a slice of the fuzzer's bytes
SRC_LITERAL = "literal"     # a constant the harness chooses
SRC_RESOURCE = "resource"   # a live resource from the graph
SRC_LENGTH_OF = "length_of" # the length of a named slice: the (ptr,len) partner
SRC_OUT = "out"             # an out-parameter the callee fills
SRC_SCRATCH = "scratch"     # a caller-allocated working buffer, passed as-is
SRC_SCRATCH_ADDR = "scratch_addr"   # the ADDRESS of a caller-allocated variable
SOURCES = (SRC_INPUT, SRC_LITERAL, SRC_RESOURCE, SRC_LENGTH_OF, SRC_OUT,
           SRC_SCRATCH, SRC_SCRATCH_ADDR)

# How a slice of fuzzer bytes is materialised before it reaches an argument.
# This distinction is not cosmetic: passing an exact-size buffer to a NUL-terminated API
# makes every input a false finding, which is exactly what happened to the cJSON harness
# in LAB-07 and produced eight reports against a library that was behaving correctly.
SLICE_BYTES = "bytes"              # raw (ptr, len); no terminator added
SLICE_CSTRING = "cstring"          # copied and NUL-terminated; the correct feed for char*
SLICE_U8 = "u8"
SLICE_U16LE = "u16le"
SLICE_U32LE = "u32le"
SLICE_U64LE = "u64le"
SLICE_KINDS = (SLICE_BYTES, SLICE_CSTRING, SLICE_U8, SLICE_U16LE, SLICE_U32LE, SLICE_U64LE)

_SCALAR_KINDS = {SLICE_U8: 1, SLICE_U16LE: 2, SLICE_U32LE: 4, SLICE_U64LE: 8}


# ── types and contracts ───────────────────────────────────────────────────────

@dataclass
class TypeRef:
    name: str                      # the C spelling, e.g. "cJSON *", "const char *"
    kind: str = "scalar"           # scalar | pointer | buffer | handle | callback | void
    const: bool = False
    # What a typedef in `name` bottoms out in, when the header says so. Empty when the
    # spelling IS the type.
    #
    # `const l_uint8 *` and `const unsigned char *` are the same type, and only leptonica's
    # environ.h says so. The producer resolves it; without somewhere to record it, S2 saw a
    # pointer to an unknown structured type, called binding fuzzer bytes to it type
    # confusion, and refused the only correct harness for pixReadMem.
    #
    # It goes on the IR rather than being imported into the gate, because a gate must not
    # depend on the thing it judges — and because the IR is the certifiable artifact, so a
    # resolution recorded here is printed, diffed and auditable rather than assumed.
    resolved: str = ""

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "TypeRef":
        return TypeRef(name=d["name"], kind=d.get("kind", "scalar"),
                       const=bool(d.get("const", False)),
                       resolved=d.get("resolved", ""))


@dataclass
class Contract:
    """What the library requires of a caller. Violating any of it produces a crash that
    belongs to the harness, not to the target."""
    # parameter names that must point at NUL-terminated memory
    nul_terminated: list[str] = field(default_factory=list)
    # (pointer_param, length_param) pairs that must agree
    length_delimited: list[list[str]] = field(default_factory=list)
    # parameters whose ownership passes to the callee (do not free them yourself)
    transfers_ownership: list[str] = field(default_factory=list)
    # parameters that must not be NULL
    requires_nonnull: list[str] = field(default_factory=list)
    # how failure is signalled: null | negative | zero | nonzero | none
    error_return: str = "none"
    reentrant: bool = True
    thread_affinity: str = "any"    # any | main | creating-thread
    # true when the symbol is not part of the library's public surface (gate S4)
    internal_only: bool = False
    # Exceptions the method DECLARES it may throw. This is a contract clause in the strictest
    # sense — the library stating in advance which failures are its documented way of
    # rejecting input — and without it a parser's own error path reads as a finding. C has no
    # equivalent (nothing declares `throws SIGSEGV`), so it is empty there; `javap` gives it
    # for free on the JVM. Additive with a default, so plans written before this still load.
    declared_exceptions: list[str] = field(default_factory=list)

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "Contract":
        return Contract(
            nul_terminated=list(d.get("nul_terminated", [])),
            length_delimited=[list(x) for x in d.get("length_delimited", [])],
            transfers_ownership=list(d.get("transfers_ownership", [])),
            requires_nonnull=list(d.get("requires_nonnull", [])),
            error_return=d.get("error_return", "none"),
            reentrant=bool(d.get("reentrant", True)),
            thread_affinity=d.get("thread_affinity", "any"),
            internal_only=bool(d.get("internal_only", False)),
            declared_exceptions=list(d.get("declared_exceptions", [])))


@dataclass
class ParamDecl:
    name: str
    type: TypeRef

    def to_json(self) -> dict:
        return {"name": self.name, "type": self.type.to_json()}

    @staticmethod
    def from_json(d: dict) -> "ParamDecl":
        return ParamDecl(name=d["name"], type=TypeRef.from_json(d["type"]))


@dataclass
class Api:
    """One library entry point, as declared by its header."""
    symbol: str
    header: str
    params: list[ParamDecl] = field(default_factory=list)
    returns: TypeRef = field(default_factory=lambda: TypeRef("void", "void"))
    role: str = ROLE_CONSUME
    contract: Contract = field(default_factory=Contract)

    def to_json(self) -> dict:
        return {"symbol": self.symbol, "header": self.header,
                "params": [p.to_json() for p in self.params],
                "returns": self.returns.to_json(), "role": self.role,
                "contract": self.contract.to_json()}

    @staticmethod
    def from_json(d: dict) -> "Api":
        return Api(symbol=d["symbol"], header=d["header"],
                   params=[ParamDecl.from_json(p) for p in d.get("params", [])],
                   returns=TypeRef.from_json(d.get("returns", {"name": "void", "kind": "void"})),
                   role=d.get("role", ROLE_CONSUME),
                   contract=Contract.from_json(d.get("contract", {})))


# ── the plan ──────────────────────────────────────────────────────────────────

@dataclass
class InputSlice:
    """A named piece of the fuzzer's bytes, and how it is materialised."""
    id: str
    kind: str = SLICE_BYTES
    # byte budget. `remainder` consumes everything left after fixed-width slices.
    remainder: bool = False
    min_len: int = 0
    max_len: int = 0                 # 0 = unbounded (subject to the harness max_len knob)

    @property
    def is_nul_terminated(self) -> bool:
        return self.kind == SLICE_CSTRING

    @property
    def fixed_width(self) -> int:
        return _SCALAR_KINDS.get(self.kind, 0)

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "InputSlice":
        return InputSlice(id=d["id"], kind=d.get("kind", SLICE_BYTES),
                          remainder=bool(d.get("remainder", False)),
                          min_len=int(d.get("min_len", 0)),
                          max_len=int(d.get("max_len", 0)))


@dataclass
class Arg:
    """One actual argument at a call site."""
    param: str                       # the declared parameter name it binds to
    source: str                      # one of SOURCES
    ref: str = ""                    # slice id, resource id, or slice id for length_of
    value: Any = None                # for SRC_LITERAL

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "Arg":
        return Arg(param=d["param"], source=d["source"], ref=d.get("ref", ""),
                   value=d.get("value"))


@dataclass
class Op:
    """One call in the sequence."""
    id: str
    api: str                         # Api.symbol
    args: list[Arg] = field(default_factory=list)
    binds: str = ""                  # resource id this op creates (create ops)
    targets: str = ""                # resource id this op destroys (destroy ops)
    # How many times to call this op, driving the library until it says stop. 0 = once.
    #
    # The single largest coverage gap measured against the gold OSS-Fuzz harnesses. Every
    # gold harness for a streaming or token API repeats the call: libyaml's scanner loops
    # tokens until the stream ends, brotli loops until the decoder reports success. Ours
    # called once and threw the parser away — 77 MILLION executions for 9.6% of libyaml
    # against gold's 70.6%, because each input produced exactly one token.
    #
    # BOUNDED, always. An unbounded loop driven by fuzzer input is a hang, and a hang is
    # indistinguishable from a finding until a human looks.
    repeat: int = 0
    guarded_by: list[str] = field(default_factory=list)  # resource ids checked non-null first

    def to_json(self) -> dict:
        return {"id": self.id, "api": self.api, "args": [a.to_json() for a in self.args],
                "binds": self.binds, "targets": self.targets, "repeat": self.repeat,
                "guarded_by": list(self.guarded_by)}

    @staticmethod
    def from_json(d: dict) -> "Op":
        return Op(id=d["id"], api=d["api"],
                  args=[Arg.from_json(a) for a in d.get("args", [])],
                  binds=d.get("binds", ""), targets=d.get("targets", ""),
                  repeat=int(d.get("repeat", 0)),
                  guarded_by=list(d.get("guarded_by", [])))


# Scratch kinds. A streaming API asks the caller to own the buffers and the cursors, and
# hands back how much it consumed.
SCRATCH_BYTES = "bytes"     # unsigned char buf[N]
SCRATCH_SIZE = "size"       # a size variable, initialised to a capacity or a slice length
SCRATCH_PTR = "ptr"         # a pointer variable, initialised to a slice or another scratch


@dataclass
class Scratch:
    """Storage the HARNESS owns because the library requires the caller to provide it.

    `uncompress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong *sourceLen)` needs
    an output buffer, its capacity BY ADDRESS (the library writes back how much it used),
    the input, and the input length by address. None of that is expressible as a literal, a
    slice or a resource — so before this existed the producer bound every one of them to 0
    and the call did nothing. Both zlib gold cases, both zopfli cases and brotli's streaming
    entry point are this shape.

    `init_from` names what the variable starts as: a slice id for SCRATCH_PTR/SCRATCH_SIZE,
    or another scratch id for an output cursor.
    """
    id: str
    kind: str = SCRATCH_BYTES
    capacity: int = 65536
    c_type: str = ""              # the declared type; empty means infer from kind
    init_from: str = ""
    # True when the LIBRARY allocates through this pointer and the caller must free it.
    # `ZopfliDeflate(..., unsigned char **out, ...)` documents "must be freed after use";
    # pointing it at our own array made the library realloc() storage it never malloc'd,
    # and the harness died on its second input.
    owns: bool = False

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "Scratch":
        return Scratch(id=d["id"], kind=d.get("kind", SCRATCH_BYTES),
                       capacity=int(d.get("capacity", 65536)),
                       c_type=d.get("c_type", ""), init_from=d.get("init_from", ""),
                       owns=bool(d.get("owns", False)))


@dataclass
class Resource:
    """A live object with a lifetime the plan must respect.

    `storage` says WHO owns the memory, which is a real distinction and not a detail:

      "handle"  the library allocates and returns a pointer, and the harness holds it
                    magic_t m = magic_open(0); ... magic_close(m);

      "inline"  the CALLER allocates the object and passes its address to an initialiser
                    yaml_parser_t p; yaml_parser_initialize(&p); ... yaml_parser_delete(&p);

      "out"     the caller allocates it and the CALLEE fills it. No library call creates
                it, so it is alive from its declaration.
                    json_error_t err; json_loadb(buf, n, 0, &err);
                It is not a lifetime the library manages and there is nothing to destroy;
                treating it as unborn made S1 refuse the only plan jansson's entry point
                has.

    The second form is everywhere — libyaml, zlib's z_stream, most C APIs with a context
    struct — and modelling only the first made those libraries unreachable. It is not a
    parser problem: the plan genuinely could not be expressed.

    The lifetime rules are identical in both cases, which is why this is a field on Resource
    rather than a different kind of thing: created once, used only while live, destroyed
    once. Only the C spelling differs.
    """
    id: str
    type: TypeRef
    storage: str = "handle"          # handle | inline | out_param

    @property
    def by_address(self) -> bool:
        """Whether the CREATE call receives the resource's address rather than returning it.
        True for a caller-allocated object and for an out-parameter constructor alike; the
        two differ only in who owns the memory."""
        return self.storage in ("inline", "out_param")

    @property
    def inline(self) -> bool:
        """The harness owns the storage and declares it.

        Both kinds are caller-allocated and differ only in WHO WRITES THEM: "inline" is
        filled by an initialiser the plan calls, "out" is filled by the callee. The emitter
        declares and zeroes them identically; only S1 needs to tell them apart, because an
        out slot has no creating call and is alive from its declaration.
        """
        return self.storage in ("inline", "out")

    def to_json(self) -> dict:
        return {"id": self.id, "type": self.type.to_json(), "storage": self.storage}

    @staticmethod
    def from_json(d: dict) -> "Resource":
        return Resource(id=d["id"], type=TypeRef.from_json(d["type"]),
                        storage=d.get("storage", "handle"))


@dataclass
class Knobs:
    """Every campaign parameter that decides what the harness CAN find.

    Recorded here so gate D7 can compute what they exclude. A campaign without its knobs
    is an anecdote, and 'we found nothing' is unreadable without them.
    """
    max_len: int = 4096              # libFuzzer's silent default; the classic bug filter
    min_len: int = 0
    timeout_s: int = 25
    rss_limit_mb: int = 2048
    malloc_limit_mb: int = 0
    sanitizers: list[str] = field(default_factory=lambda: ["address"])
    detect_leaks: bool = False
    optimisation: str = "-O1"

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "Knobs":
        k = Knobs()
        for f in ("max_len", "min_len", "timeout_s", "rss_limit_mb", "malloc_limit_mb"):
            if f in d:
                setattr(k, f, int(d[f]))
        k.sanitizers = list(d.get("sanitizers", k.sanitizers))
        k.detect_leaks = bool(d.get("detect_leaks", k.detect_leaks))
        k.optimisation = d.get("optimisation", k.optimisation)
        return k


@dataclass
class FormatModel:
    """Optional description of the input format, used by gate S6/D8 to state what shapes
    the harness can construct at all. This is what turns 'we found nothing' into
    'we could not have found a bug needing N nesting levels'."""
    name: str = ""
    max_nesting_expressible: int = 0     # 0 = not modelled
    requires_checksum: bool = False
    requires_compression: bool = False
    magic: str = ""

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "FormatModel":
        return FormatModel(name=d.get("name", ""),
                           max_nesting_expressible=int(d.get("max_nesting_expressible", 0)),
                           requires_checksum=bool(d.get("requires_checksum", False)),
                           requires_compression=bool(d.get("requires_compression", False)),
                           magic=d.get("magic", ""))


@dataclass
class RawBlock:
    """Escape hatch. Verbatim C the schema cannot express.

    Everything in here is UNCERTIFIED and every gate report says so, because a schema that
    refuses real harnesses gets bypassed rather than obeyed.
    """
    id: str
    where: str                       # "prologue" | "epilogue" | "before:<op-id>" | "after:<op-id>"
    code: str
    reason: str = ""

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "RawBlock":
        return RawBlock(id=d["id"], where=d["where"], code=d["code"],
                        reason=d.get("reason", ""))


@dataclass
class Target:
    name: str
    version: str = ""
    commit: str = ""
    public_headers: list[str] = field(default_factory=list)
    include_dirs: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    link_libs: list[str] = field(default_factory=list)
    # Flags the target needs in order to compile at all — `-DHAVE_CONFIG_H` and friends.
    # Real software is configured software: `file`, libxml2 and libyaml all read a generated
    # config.h, and without the define their sources do not build. Recorded on the IR rather
    # than passed at the command line so the plan stays reproducible by someone else.
    cflags: list[str] = field(default_factory=list)
    # Directories to mine for example inputs. A project that has tests has valid inputs, and
    # they are sitting in its repository — the same observation as the dictionary, applied
    # to whole documents instead of tokens.
    seed_dirs: list[str] = field(default_factory=list)
    language: str = "c"              # c | c++

    def to_json(self) -> dict: return asdict(self)

    @staticmethod
    def from_json(d: dict) -> "Target":
        t = Target(name=d["name"])
        for f in ("version", "commit", "language"):
            if f in d:
                setattr(t, f, d[f])
        for f in ("public_headers", "include_dirs", "sources", "link_libs"):
            setattr(t, f, list(d.get(f, [])))
        t.cflags = list(d.get("cflags", []))
        t.seed_dirs = list(d.get("seed_dirs", []))
        return t


@dataclass
class HarnessIR:
    """A complete harness plan."""
    name: str
    target: Target
    apis: dict[str, Api] = field(default_factory=dict)
    slices: list[InputSlice] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    scratch: list[Scratch] = field(default_factory=list)
    sequence: list[Op] = field(default_factory=list)
    knobs: Knobs = field(default_factory=Knobs)
    platforms: list[str] = field(default_factory=lambda: ["linux-x86_64-glibc"])
    format_model: Optional[FormatModel] = None
    raw_blocks: list[RawBlock] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    producer: str = "hand"           # which producer emitted this plan
    notes: str = ""

    # ── lookups ──
    def slice_by_id(self, sid: str) -> Optional[InputSlice]:
        return next((s for s in self.slices if s.id == sid), None)

    def resource_by_id(self, rid: str) -> Optional[Resource]:
        return next((r for r in self.resources if r.id == rid), None)

    def op_by_id(self, oid: str) -> Optional[Op]:
        return next((o for o in self.sequence if o.id == oid), None)

    def api_of(self, op: Op) -> Optional[Api]:
        return self.apis.get(op.api)

    def param_decl(self, api: Api, param: str) -> Optional[ParamDecl]:
        return next((p for p in api.params if p.name == param), None)

    @property
    def is_fully_certifiable(self) -> bool:
        """False when raw blocks are present: part of this plan is outside the schema."""
        return not self.raw_blocks

    # ── serialisation ──
    def to_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "producer": self.producer,
            "notes": self.notes,
            "target": self.target.to_json(),
            "platforms": list(self.platforms),
            "apis": {k: v.to_json() for k, v in self.apis.items()},
            "slices": [s.to_json() for s in self.slices],
            "resources": [r.to_json() for r in self.resources],
            "scratch": [x.to_json() for x in self.scratch],
            "sequence": [o.to_json() for o in self.sequence],
            "knobs": self.knobs.to_json(),
            "format_model": self.format_model.to_json() if self.format_model else None,
            "raw_blocks": [b.to_json() for b in self.raw_blocks],
        }

    def dumps(self, indent: int = 2) -> str:
        return json.dumps(self.to_json(), indent=indent)

    @staticmethod
    def from_json(d: dict) -> "HarnessIR":
        got = d.get("schema_version", SCHEMA_VERSION)
        if got.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise ValueError(f"IR schema major version mismatch: file {got}, "
                             f"engine {SCHEMA_VERSION}")
        fm = d.get("format_model")
        return HarnessIR(
            name=d["name"],
            target=Target.from_json(d["target"]),
            apis={k: Api.from_json(v) for k, v in d.get("apis", {}).items()},
            slices=[InputSlice.from_json(s) for s in d.get("slices", [])],
            resources=[Resource.from_json(r) for r in d.get("resources", [])],
            scratch=[Scratch.from_json(x) for x in d.get("scratch", [])],
            sequence=[Op.from_json(o) for o in d.get("sequence", [])],
            knobs=Knobs.from_json(d.get("knobs", {})),
            platforms=list(d.get("platforms", ["linux-x86_64-glibc"])),
            format_model=FormatModel.from_json(fm) if fm else None,
            raw_blocks=[RawBlock.from_json(b) for b in d.get("raw_blocks", [])],
            schema_version=got,
            producer=d.get("producer", "hand"),
            notes=d.get("notes", ""))

    @staticmethod
    def loads(text: str) -> "HarnessIR":
        return HarnessIR.from_json(json.loads(text))
