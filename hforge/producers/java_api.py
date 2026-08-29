"""Java API surface, read from bytecode, turned into plans.

Bytecode is a far better source than headers ever were. `javap` answers exactly, with no
preprocessor, no macros, no BSD-style definitions and no `extern "C" {` swallowing the file —
the four rewrites that C header parsing cost this project have no analogue here. It also
gives two things a C header cannot:

  * the **`throws` clause**, which is the library stating in advance which exceptions are its
    documented way of rejecting input. `java/exceptions.py` needs exactly that, and without
    it every parser's own error path reads as a finding.
  * **`AutoCloseable`**, which is a machine-readable lifetime. In C we infer a destructor
    from a name and get `sqlite3_finalize` wrong; in Java the interface declares it.

What is NOT available: parameter names, unless the target was compiled with `-parameters`.
Positional ids are used and the plan says so, because a plan that invents `text` for `p0`
looks more authoritative than it is.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..ir import (Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Resource,
                  Target, TypeRef, SLICE_BYTES, SLICE_CSTRING, SLICE_U32LE, SLICE_U64LE,
                  SLICE_U8, ROLE_CONSUME, ROLE_CREATE, ROLE_DESTROY)

PRODUCER = "java_api"

# ── how the fuzzer's bytes become a Java argument ────────────────────────────
#
# This table IS the mapping onto Jazzer's FuzzedDataProvider, and it is the cleanest part of
# the whole design: our InputSlice model and the provider are the same idea. Note what is
# absent — no (pointer, length) pair, because the provider carries its own length. The entire
# defect family that produced `sqlite3_prepare(db, sql, 0, ...)` cannot be expressed here.
DRIVABLE = {
    "java.lang.String":            (SLICE_CSTRING, "consumeRemainingAsString"),
    "java.lang.CharSequence":      (SLICE_CSTRING, "consumeRemainingAsString"),
    "byte[]":                      (SLICE_BYTES,   "consumeRemainingAsBytes"),
    "java.io.InputStream":         (SLICE_BYTES,   "consumeRemainingAsBytes"),
    "java.io.Reader":              (SLICE_CSTRING, "consumeRemainingAsString"),
    "java.nio.ByteBuffer":         (SLICE_BYTES,   "consumeRemainingAsBytes"),
    "int":                         (SLICE_U32LE,   "consumeInt"),
    "long":                        (SLICE_U64LE,   "consumeLong"),
    "short":                       (SLICE_U8,      "consumeShort"),
    "byte":                        (SLICE_U8,      "consumeByte"),
    "boolean":                     (SLICE_U8,      "consumeBoolean"),
    "char":                        (SLICE_U8,      "consumeChar"),
    "double":                      (SLICE_U64LE,   "consumeDouble"),
    "float":                       (SLICE_U32LE,   "consumeFloat"),
}
# Only ONE parameter may take the remainder. The rest are bounded, exactly as the C chain
# producer learned when sqlite3_open's filename ate the whole input.
_REMAINDER_KINDS = {SLICE_CSTRING, SLICE_BYTES}

_CLASS_DECL = re.compile(
    r"^(?P<mods>(?:public |final |abstract |static )*)"
    r"(?P<kind>class|interface|enum|record)\s+(?P<name>[\w$.]+)"
    r"(?:<[^>]*>)?"
    r"(?:\s+extends\s+(?P<ext>[\w$.<>, ]+?))?"
    r"(?:\s+implements\s+(?P<impl>[\w$.<>, ]+?))?\s*\{", re.M)

_MEMBER = re.compile(
    r"^\s{2}(?P<mods>(?:public|protected|private|static|final|abstract|synchronized|"
    r"native|default|strictfp|\s)*)"
    r"(?:<[^>]+>\s+)?"
    r"(?:(?P<ret>[\w$.\[\]<>, ?]+)\s+)?"
    r"(?P<name>[\w$.]+)"
    r"\((?P<params>[^)]*)\)"
    r"(?:\s+throws\s+(?P<throws>[\w$., ]+))?;", re.M)


@dataclass
class JClass:
    name: str                          # fully qualified
    is_public: bool = True
    is_abstract: bool = False
    is_interface: bool = False
    closeable: bool = False
    ctors: list = field(default_factory=list)     # list[JMethod]
    methods: list = field(default_factory=list)   # list[JMethod]
    skipped: list = field(default_factory=list)   # (member, why)

    @property
    def simple(self) -> str:
        return self.name.rsplit(".", 1)[-1]


@dataclass
class JMethod:
    owner: str
    name: str
    params: list = field(default_factory=list)    # list[str] java type names
    returns: str = "void"
    static: bool = False
    throws: list = field(default_factory=list)

    @property
    def symbol(self) -> str:
        return f"{self.owner}.{self.name}"

    @property
    def arity(self) -> int:
        return len(self.params)


def _run(cmd) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           errors="replace")
    except Exception:                                            # noqa: BLE001
        return None
    return r.stdout if r.returncode == 0 else None


def classes_in(classpath: str) -> list:
    """Every class name on a classpath entry — a jar or a directory of .class files."""
    p = Path(classpath)
    names: list = []
    if p.is_dir():
        for f in sorted(p.rglob("*.class")):
            rel = f.relative_to(p).with_suffix("")
            names.append(str(rel).replace("/", ".").replace("\\", "."))
    elif p.suffix == ".jar":
        out = _run(["jar", "tf", str(p)]) or ""
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.endswith(".class"):
                names.append(ln[:-len(".class")].replace("/", "."))
    # A nested class is reached through its outer one and is rarely the API surface; an
    # anonymous class never is.
    return [n for n in names if "$" not in n]


def parse_class(fqcn: str, classpath: str) -> Optional[JClass]:
    """One class, as `javap` describes it."""
    out = _run(["javap", "-p", "-classpath", classpath, fqcn])
    if not out:
        return None
    m = _CLASS_DECL.search(out)
    if not m:
        return None

    impl = (m.group("impl") or "") + " " + (m.group("ext") or "")
    c = JClass(name=m.group("name"),
               is_public="public" in (m.group("mods") or ""),
               is_abstract="abstract" in (m.group("mods") or ""),
               is_interface=m.group("kind") == "interface",
               closeable=("AutoCloseable" in impl or "Closeable" in impl))

    simple = c.simple
    for mm in _MEMBER.finditer(out):
        mods = mm.group("mods") or ""
        name = mm.group("name")
        ret = (mm.group("ret") or "").strip()
        raw = (mm.group("params") or "").strip()
        params = [x.strip() for x in raw.split(",") if x.strip()] if raw else []
        throws = [x.strip() for x in (mm.group("throws") or "").split(",") if x.strip()]

        if "private" in mods or "protected" in mods:
            continue                                  # not API
        if any("<" in x for x in params):
            c.skipped.append((name, "generic parameter: the erased type is not enough to "
                                    "construct a value, and guessing one is how a harness "
                                    "ends up testing itself"))
            continue

        meth = JMethod(owner=c.name, name=name, params=params, returns=ret or "void",
                       static="static" in mods, throws=throws)
        # javap prints a constructor as the fully-qualified class name with no return type.
        if not ret and (name == c.name or name.endswith("." + simple) or name == simple):
            meth.name = "<init>"
            c.ctors.append(meth)
        else:
            c.methods.append(meth)

    # `close()` is a declared lifetime, not one inferred from a name. In C we guess a
    # destructor from `_free`/`_close`/`_finalize` and got sqlite3_finalize wrong for weeks.
    if any(x.name == "close" and not x.params for x in c.methods):
        c.closeable = True
    return c


# ── plan synthesis ───────────────────────────────────────────────────────────

def _tref(java_type: str) -> TypeRef:
    """A Java type in the IR.

    Kind is deliberately NOT `pointer`. S2's type-confusion clause keys on a `*` in the type
    name and would not fire anyway, but the reason matters and belongs in the record: in
    Java you cannot bind raw bytes to an object reference — the verifier forbids it — so the
    single largest source of false findings in the C literature is impossible here by
    construction. That is a fact about the language, not a gate we passed.
    """
    prim = {"int", "long", "short", "byte", "boolean", "char", "double", "float", "void"}
    return TypeRef(name=java_type, kind="scalar" if java_type in prim else "object")


def _ctor_score(m: JMethod) -> tuple:
    """Prefer the constructor a harness can actually satisfy: fewest arguments, then most of
    them drivable."""
    drivable = sum(1 for p in m.params if p in DRIVABLE)
    return (len(m.params), -drivable)


def propose(classpath: str, target: Target, *, platforms=None,
            knobs: Optional[Knobs] = None, only: Optional[list] = None) -> list:
    """Every plan this classpath supports."""
    plats = platforms or ["jvm-openjdk-x86_64"]
    kn = knobs or Knobs()
    out: list = []

    names = only or classes_in(classpath)
    for fqcn in names:
        c = parse_class(fqcn, classpath)
        if c is None or c.is_interface or c.is_abstract or not c.is_public:
            continue
        out.extend(_plans_for(c, target, plats, kn))
    return out


def _plans_for(c: JClass, target: Target, platforms: list, knobs: Knobs) -> list:
    plans: list = []
    ctor = min(c.ctors, key=_ctor_score) if c.ctors else None
    closer = next((m for m in c.methods if m.name == "close" and not m.params), None)

    for meth in c.methods:
        if meth.name in ("close", "toString", "hashCode", "equals", "main"):
            continue
        if not any(p in DRIVABLE for p in meth.params):
            continue                    # nothing the fuzzer can steer: not a harness
        if not meth.static and ctor is None:
            continue                    # cannot obtain an instance

        apis: dict = {}
        seq: list = []
        slices: list = []
        resources: list = []
        used_remainder = False

        def bind(m: JMethod, op_id: str, on_resource: Optional[str]):
            nonlocal used_remainder
            args = []
            for i, ptype in enumerate(m.params):
                pname = f"p{i}"
                if ptype in DRIVABLE:
                    kind, _ = DRIVABLE[ptype]
                    remainder = kind in _REMAINDER_KINDS and not used_remainder
                    if remainder:
                        used_remainder = True
                    slices.append(InputSlice(f"{op_id}_{pname}", kind, remainder=remainder,
                                             min_len=1,
                                             max_len=0 if remainder else 256))
                    args.append(Arg(pname, "input", f"{op_id}_{pname}"))
                else:
                    # An object we cannot build. NULL is the honest binding and the API's
                    # own null check is then part of what is being tested.
                    args.append(Arg(pname, "literal", value=None))
            apis[m.symbol] = Api(
                m.symbol, c.name,
                [ParamDecl(f"p{i}", _tref(p)) for i, p in enumerate(m.params)],
                _tref(m.returns),
                ROLE_CREATE if m.name == "<init>" else
                (ROLE_DESTROY if m.name == "close" else ROLE_CONSUME),
                # The library telling us which exceptions are its contract, carried onto the
                # plan so triage reads it without re-running javap.
                Contract(error_return="exception", declared_exceptions=list(m.throws)))
            return args

        if not meth.static:
            cargs = bind(ctor, "o_create", None)
            resources.append(Resource("obj", _tref(c.name), storage="handle"))
            seq.append(Op("o_create", ctor.symbol, cargs, binds="obj"))

        margs = bind(meth, "o_consume", "obj" if not meth.static else None)
        seq.append(Op("o_consume", meth.symbol, margs,
                      guarded_by=["obj"] if not meth.static else []))

        if closer is not None and not meth.static:
            bind(closer, "o_close", "obj")
            seq.append(Op("o_close", closer.symbol, [], targets="obj",
                          guarded_by=["obj"]))

        if not slices:
            continue

        t = Target(name=target.name, version=target.version, commit=target.commit,
                   public_headers=list(target.public_headers),
                   include_dirs=list(target.include_dirs),
                   sources=list(target.sources), link_libs=list(target.link_libs),
                   cflags=list(target.cflags), seed_dirs=list(target.seed_dirs))
        t.language = "java"

        plans.append(HarnessIR(
            name=f"{target.name}_{c.simple}_{meth.name}"
                 f"{'' if meth.arity <= 1 else f'_a{meth.arity}'}",
            target=t, apis=apis, slices=slices, resources=resources, sequence=seq,
            knobs=knobs, platforms=platforms, producer=PRODUCER,
            notes=("parameter names are positional (p0, p1): javap does not expose them "
                   "unless the target was compiled with -parameters"
                   + ("; skipped: " + "; ".join(f"{n} ({w})" for n, w in c.skipped[:3])
                      if c.skipped else "")))) 
    return plans
