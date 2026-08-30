"""C++ header parsing — namespaces, classes, methods, overloads.

The IR was always language-neutral: resources with lifetimes, a call sequence, contracts,
slices. Only three modules assumed C — the emitter, the lifter and the header producer. This
is the second producer, and it exists because **most of the target surface is C++**: poppler,
ICU, protobuf, and most media and font libraries. Competing only on C caps the addressable
field at roughly half of it.

What C++ adds that C does not have, and how each is handled:

  * **namespaces** — a symbol is `ns::Class::method`, and the emitter must qualify it
  * **classes** — an object is a RESOURCE whose lifetime is a constructor and a destructor,
    which is the model the IR already has. `storage="object"` means stack-allocated with an
    implicit destructor; `storage="handle"` means `new`/`delete`
  * **overloads** — two methods share a name and differ by signature, so a plan must name the
    ARITY it meant or the emitter cannot pick
  * **references** — `const std::string&` is a pointer that cannot be null, which is a
    contract the C model already expresses as `requires_nonnull`
  * **std::string / std::vector<uint8_t>** — the two shapes almost every C++ harness uses to
    hand the fuzzer's bytes to a library

What is deliberately NOT handled, and reported rather than guessed: templates (a template is
not a symbol until it is instantiated), exceptions crossing the harness boundary, multiple
inheritance, and operator overloads.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..ir import (
    Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Resource, Target,
    TypeRef, ROLE_CONSUME, ROLE_CREATE, ROLE_DESTROY, ROLE_QUERY,
    SLICE_BYTES, SLICE_CSTRING,
)

# `class Foo {` / `struct Bar : public Base {`
# Shipping C++ libraries put an export macro between the keyword and the name --
# `class PUGIXML_CLASS xml_document`, `class LIBFOO_API Reader`, `__declspec(dllexport)`.
# Matching only `class <name>` finds ZERO classes in most real headers: pugixml parsed to
# nothing until this was fixed. The all-caps or attribute tokens before the name are
# consumed and the LAST identifier is the class; `final` is a suffix keyword, never a name.
_CLASS = re.compile(
    r"\b(class|struct)\s+"
    r"((?:(?:[A-Z_][A-Z0-9_]*|__declspec\s*\([^)]*\)|__attribute__\s*\(\([^)]*\)\)|"
    r"alignas\s*\([^)]*\))\s+)*)"
    r"([A-Za-z_]\w*)(?:\s+final)?\s*(?::\s*([^{]+))?\{")
_NAMESPACE = re.compile(r"\bnamespace\s+([A-Za-z_]\w*)\s*\{")
_ACCESS = re.compile(r"\b(public|private|protected)\s*:")

# A method or free function declaration inside a class body.
_METHOD = re.compile(
    r"^[ \t]*(?!(?:public|private|protected|using|typedef|friend|template|return)\b)"
    r"((?:virtual\s+|static\s+|inline\s+|explicit\s+|constexpr\s+)*)"      # 1 specifiers
    r"([^;{()]*?)"                                                        # 2 return type
    r"([A-Za-z_~]\w*)\s*"                                                 # 3 name
    r"\(([^;{)]*)\)\s*(const)?\s*(?:noexcept)?\s*(=\s*0)?\s*[;{]", re.M)

_STD_BYTES = re.compile(r"std::(?:vector\s*<\s*(?:uint8_t|unsigned\s+char|char)\s*>|"
                        r"string|string_view|span\s*<)", re.I)
_TEMPLATE = re.compile(r"\btemplate\s*<")


@dataclass
class Klass:
    """What is known about a class, for deciding whether a harness can BUILD one.

    `bases` is what makes an abstract interface usable: woff2's entry point takes a
    `WOFF2Out*`, which is pure virtual and cannot be constructed, and the library's own
    harness passes a `WOFF2StringOut` -- a concrete subclass sitting in the same header.
    Without inheritance the only honest answer is to refuse the plan.
    """
    name: str                          # qualified
    bases: list = field(default_factory=list)
    abstract: bool = False
    default_ctor: bool = False


@dataclass
class Method:
    cls: str
    ns: str
    name: str
    ret: str
    params: list                       # [(type, name)]
    is_ctor: bool = False
    is_dtor: bool = False
    is_static: bool = False
    is_const: bool = False
    is_pure: bool = False               # `= 0`: the class is abstract and cannot be built
    n_required: int = 0                 # leading params with no default argument

    @property
    def is_free(self) -> bool:
        """A function at namespace scope rather than a member of a class."""
        return not self.cls

    @property
    def qualified_class(self) -> str:
        return f"{self.ns}::{self.cls}" if self.ns else self.cls

    @property
    def symbol(self) -> str:
        if self.is_free:
            return f"{self.ns}::{self.name}" if self.ns else self.name
        return f"{self.qualified_class}::{self.name}"

    @property
    def arity(self) -> int:
        return len(self.params)


def _strip(src: str) -> str:
    """Comments and string bodies out, line structure preserved."""
    from ..analysis.sinks import strip_noise
    return strip_noise(src)


def _match_brace(s: str, i: int) -> int:
    depth = 0
    while i < len(s):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s) - 1


def _split_raw(s: str) -> list:
    """The parameter list split on top-level commas, each entry still verbatim."""
    s = s.strip()
    if not s or s == "void":
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur and "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def n_required(s: str) -> int:
    """How many leading parameters have no default argument.

    A C++ call may omit trailing defaulted parameters, so a harness that binds only these
    still compiles. pugixml's `load_buffer(contents, size, options = parse_default,
    encoding = encoding_auto)` is the common case: two required, two the caller may drop.
    """
    raw = _split_raw(s)
    n = 0
    for p in raw:
        if re.search(r"=\s*[^,]+$", p):
            break
        n += 1
    return n


def _split_params(s: str) -> list:
    out = _split_raw(s)
    parsed = []
    for i, p in enumerate(out):
        p = re.sub(r"=\s*[^,]+$", "", p).strip()        # drop a default argument
        m = re.match(r"^(.*?[\s&*])([A-Za-z_]\w*)$", p)
        if m:
            parsed.append((" ".join(m.group(1).split()), m.group(2)))
        else:
            parsed.append((" ".join(p.split()), f"arg{i}"))
    return parsed


def parse_header(path: str, include_dirs=(), cflags=()) -> tuple:
    """Methods and skips. `parse_classes` returns the inheritance graph beside them."""
    ms, sk, _ = parse_classes(path, include_dirs, cflags)
    return ms, sk


def parse_classes(path: str, include_dirs=(), cflags=()) -> tuple:
    """Classes and their public methods. Returns (methods, skipped) — what could not be read
    is returned, not dropped, because a producer that silently ignores half a header
    proposes plans for an API that is not there."""
    src = _strip(Path(path).read_text(errors="replace"))
    methods: list = []
    skipped: list = []
    classes: dict = {}

    # namespace stack by brace position
    ns_at: list = []
    class_spans: list = []
    classes: dict = {}
    for m in _NAMESPACE.finditer(src):
        ob = src.find("{", m.end() - 1)
        if ob >= 0:
            ns_at.append((ob, _match_brace(src, ob), m.group(1)))

    def ns_for(pos: int) -> str:
        names = [n for a, b, n in ns_at if a < pos < b]
        return "::".join(names)

    for cm in _CLASS.finditer(src):
        kind, cls = cm.group(1), cm.group(3)
        ob = src.find("{", cm.end() - 1)
        if ob < 0:
            continue
        cb = _match_brace(src, ob)
        body = src[ob + 1:cb]
        ns = ns_for(cm.start())

        if _TEMPLATE.search(src[max(0, cm.start() - 120):cm.start()]):
            skipped.append(f"{ns}::{cls}: a template is not a symbol until instantiated")
            continue

        # `struct` is public by default, `class` is private
        visible = (kind == "struct")
        pos = 0
        for am in _ACCESS.finditer(body):
            seg = body[pos:am.start()]
            if visible:
                methods += _methods_in(seg, cls, ns, skipped)
            visible = am.group(1) == "public"
            pos = am.end()
        if visible:
            methods += _methods_in(body[pos:], cls, ns, skipped)
        class_spans.append((ob, cb))

        qual = f"{ns}::{cls}" if ns else cls
        own = [m for m in methods if m.cls == cls and m.ns == ns]
        bases = []
        for b in (cm.group(4) or "").split(","):
            b = re.sub(r"\b(public|private|protected|virtual)\b", " ", b)
            b = re.sub(r"<[^>]*>", "", b).strip()
            if b:
                bases.append(b.split("::")[-1])
        classes[qual] = Klass(
            name=qual, bases=bases,
            abstract=any(m.is_pure for m in own),
            default_ctor=any(m.is_ctor and m.n_required == 0 for m in own))

    # FREE FUNCTIONS AT NAMESPACE SCOPE. `woff2::ConvertWOFF2ToTTF(const uint8_t*, size_t,
    # ...)` is the entry point of its library and is not a member of anything. Scanning
    # only class bodies dropped every such function WITHOUT recording it -- neither
    # proposed nor skipped, which is the silent omission this parser's own contract
    # forbids. Declarations inside a class body are already handled above and are excluded
    # here by position.
    for fm in _METHOD.finditer(src):
        if any(a < fm.start() < b for a, b in class_spans):
            continue
        name = fm.group(3)
        if name in ("if", "for", "while", "switch", "return", "operator"):
            continue
        ret = (fm.group(2) or "")
        if not ret.strip() or "operator" in ret or name.startswith("operator"):
            continue
        if _TEMPLATE.search(ret) or _TEMPLATE.search(src[max(0, fm.start() - 120):fm.start()]):
            skipped.append(f"{name}: a template is not a symbol until instantiated")
            continue
        ns = ns_for(fm.start())
        methods.append(Method(cls="", ns=ns, name=name, ret=" ".join(ret.split()),
                              params=_split_params(fm.group(4)),
                              is_static="static" in (fm.group(1) or ""),
                              is_const=bool(fm.group(5)), is_pure=bool(fm.group(6)),
                              n_required=n_required(fm.group(4))))

    return methods, skipped, classes


def _methods_in(seg: str, cls: str, ns: str, skipped: list) -> list:
    out = []
    for m in _METHOD.finditer(seg):
        spec, ret, name, params, is_const = (m.group(1) or ""), (m.group(2) or ""), \
            m.group(3), m.group(4), bool(m.group(5))
        is_pure = bool(m.group(6))
        if name in ("if", "for", "while", "switch", "return", "operator"):
            continue
        if "operator" in ret or name.startswith("operator"):
            skipped.append(f"{cls}::{name}: operator overload")
            continue
        if _TEMPLATE.search(ret):
            skipped.append(f"{cls}::{name}: template method")
            continue
        is_dtor = name.startswith("~")
        is_ctor = (name == cls)
        out.append(Method(cls=cls, ns=ns, name=name,
                          ret="void" if (is_ctor or is_dtor) else " ".join(ret.split()),
                          params=_split_params(params),
                          is_ctor=is_ctor, is_dtor=is_dtor,
                          is_static="static" in spec, is_const=is_const,
                          is_pure=is_pure, n_required=n_required(params)))
    return out


def takes_bytes(ty: str) -> bool:
    """Whether this parameter can carry the fuzzer's bytes.

    `std::string`, `std::string_view`, `std::vector<uint8_t>` and `std::span` are how almost
    every C++ harness hands input to a library, and they are the C++ equivalent of the
    `(ptr, len)` pair the C producer looks for.
    """
    return bool(_STD_BYTES.search(ty)) or bool(
        re.search(r"\b(?:const\s+)?(?:char|uint8_t|unsigned char|void)\s*\*", ty))


# ── plan synthesis ───────────────────────────────────────────────────────────
#
# The parser and the C++ emitter both existed and were tested, but nothing joined them:
# there was no way to get from a header to a plan, so C++ was unreachable from the command
# line. This is that join.

_INT_LEN = re.compile(r"\b(?:size_t|size_type|ssize_t|unsigned|int|long|"
                      r"u?int(?:8|16|32|64)_t)\b")


def _is_const_byte_ptr(ty: str) -> bool:
    return "*" in ty and "const" in ty and takes_bytes(ty)


def consume_binding(m: "Method"):
    """Which parameters carry the fuzzer's bytes: (bytes_index, length_index or None).

    Two shapes only, and the exclusions matter more than the inclusions:

    * a std:: byte-carrying type, which is self-describing; or
    * a **const** byte pointer immediately followed by an integer length.

    A NON-const byte pointer is refused. `load_buffer_inplace_own` takes ownership and
    frees the pointer with the library's allocator, so handing it a std::string's buffer
    is a guaranteed crash that says nothing about the library. Requiring the length also
    rejects `load_file(const char* path, ...)`, where the "byte pointer" is a FILENAME --
    a harness built on it would open attacker-named paths rather than parse anything.
    """
    req = m.params[:m.n_required]
    for i, (ty, _n) in enumerate(req):
        if _STD_BYTES.search(ty):
            return i, None
        if _is_const_byte_ptr(ty):
            nxt = req[i + 1][0] if i + 1 < len(req) else ""
            # A LENGTH IS A SCALAR. `_INT_LEN` matches `uint8_t`, which also appears in
            # `const uint8_t*` -- so wabt's `ReadBinaryIr(const char* filename,
            # const uint8_t* data, size_t size, ...)` would have bound the FILENAME as the
            # input and the data POINTER as its length.
            if nxt and "*" not in nxt and "&" not in nxt and _INT_LEN.search(nxt):
                return i, i + 1
    return None


_OWNED_SCRATCH = {"std::string": "std::string", "std::vector<uint8_t>": "std::vector<uint8_t>"}


def _base_name(ty: str) -> str:
    """The class a parameter refers to, with cv-qualifiers and indirection removed."""
    t = re.sub(r"\b(const|volatile|struct|class)\b", " ", ty)
    t = t.replace("*", " ").replace("&", " ").strip()
    return t.split("::")[-1].split()[-1] if t.split() else ""


def _concrete_for(ty: str, classes: dict) -> list:
    """Classes that could stand in for a parameter of this type, most direct first.

    An abstract interface is the normal shape for an output sink: woff2's entry point
    takes a `WOFF2Out*`, which has a pure virtual `Write`, and the only way to call it is
    with a concrete subclass. Both the type itself and its descendants are considered, so
    a concrete parameter type still works without a special case.
    """
    want = _base_name(ty)
    if not want:
        return []
    out = []
    for qual, k in sorted(classes.items()):
        if qual.split("::")[-1] == want and not k.abstract:
            out.append(qual)
    for qual, k in sorted(classes.items()):
        if k.abstract or qual in out:
            continue
        seen, stack = set(), list(k.bases)
        while stack:
            b = stack.pop()
            if b in seen:
                continue
            seen.add(b)
            for q2, k2 in classes.items():
                if q2.split("::")[-1] == b:
                    stack += k2.bases
        if want in seen:
            out.append(qual)
    return out


def constructible_argument(ty: str, classes: dict, methods: list):
    """How to BUILD an object for a parameter of this type, or None.

    Returns (qualified class, ctor Method, scratch type or ""). Two shapes are accepted
    and no others, because a guessed constructor argument is a silent behaviour change:

    * a default constructor, which needs nothing; or
    * a constructor taking ONE pointer to a standard container the harness can own --
      `WOFF2StringOut(std::string *buf)` is the shape, and the buffer becomes scratch.
    """
    for cls in _concrete_for(ty, classes):
        ctors = [m for m in methods if m.is_ctor and
                 (f"{m.ns}::{m.cls}" if m.ns else m.cls) == cls]
        for c in sorted(ctors, key=lambda m: m.n_required):
            if c.n_required == 0:
                return cls, c, ""
            if c.n_required == 1:
                pty = c.params[0][0]
                for spelled, decl in _OWNED_SCRATCH.items():
                    if spelled in pty.replace(" ", "") and "*" in pty:
                        return cls, c, decl
    return None


def resolve_extras(m: "Method", b, classes: dict, methods: list):
    """Every required parameter that is neither the bytes nor their length.

    Returns (bindings, "") or (None, reason). A binding is
    (index, class, ctor Method, scratch type) for a parameter the harness can CONSTRUCT,
    or (index, None, None, "") for a scalar, which is bound to literal 0.

    This is what separates a harness from a stub. woff2's entry point is
    `ConvertWOFF2ToTTF(data, len, WOFF2Out* out)`; refusing it costs the whole library,
    and binding the sink to nullptr crashes on the library's own contract. Building a
    `WOFF2StringOut` over a std::string is what the project's own harness does.
    """
    bi, li = b
    out = []
    for i, (ty, nm) in enumerate(m.params[:m.n_required]):
        if i in (bi, li):
            continue
        if "*" not in ty and "&" not in ty:
            out.append((i, None, None, ""))          # a scalar: literal 0 is a real value
            continue
        r = constructible_argument(ty, classes, methods)
        if r is None:
            return None, (f"{nm or ty}: a required pointer this producer cannot construct "
                          f"-- no concrete class with a default constructor, or one taking "
                          f"a single owned buffer, stands in for {ty}")
        out.append((i, r[0], r[1], r[2]))
    return out, ""


def _unbindable(m: "Method", b) -> str:
    """The first required parameter that is a pointer we have no value for, if any.

    Everything except the bytes and their length is bound to literal 0. For a scalar --
    an options flag, an enum -- that is a real value the library accepts. For a POINTER it
    is nullptr, and a library that documents an out-parameter as required will dereference
    it: `ConvertWOFF2ToTTF(data, len, WOFF2Out* out)` with a null sink crashes on its own
    contract. That crash is not a finding, and a harness that produces it wastes a
    campaign, so the plan is refused with the parameter named.
    """
    bi, li = b
    for i, (ty, nm) in enumerate(m.params[:m.n_required]):
        if i in (bi, li):
            continue
        if "*" in ty or "&" in ty:
            return nm or ty
    return ""


def _kind_of(ty: str) -> str:
    if "*" in ty or "&" in ty:
        return "pointer"
    if ty.strip() in ("void", ""):
        return "void"
    return "scalar"


def propose(headers, target, platforms=(), knobs=None, max_plans: int = 12,
            skipped=None) -> list:
    """Plans for a C++ class API: construct the object, feed it the fuzzer's bytes.

    A class is usable only when it is concrete and default-constructible. Both refusals
    are reported rather than silently dropped, because "no plan" and "this class is
    abstract" are different answers and only one of them is the user's fault.
    """
    from ..ir import HarnessIR

    hs = [headers] if isinstance(headers, (str, Path)) else list(headers)
    methods: list = []
    # WHY THERE IS NO PLAN IS THE ANSWER THE CALLER NEEDS. Every refusal below carries a
    # reason -- abstract class, no default constructor, a filename rather than a buffer,
    # a pointer we cannot construct -- and they were all appended to a local list and
    # thrown away, so `wabt::ReadBinaryIr` reported no plan and no cause at all. A caller
    # that passes a list gets them back; the parser has used this convention all along.
    skipped: list = skipped if skipped is not None else []
    classes: dict = {}
    for h in hs:
        ms, sk, cs = parse_classes(str(h))
        classes.update(cs)
        for m in ms:
            m.header = Path(h).name
        methods += ms
        skipped += sk

    by_class: dict = {}
    for m in methods:
        if not m.is_free:
            by_class.setdefault(m.qualified_class, []).append(m)

    cands = []
    # A free function needs no object: no constructor, no resource, just the call.
    for m in sorted([x for x in methods if x.is_free], key=lambda x: x.name):
        if m.is_pure:
            continue
        b = consume_binding(m)
        if b is None:
            continue
        ex, why = resolve_extras(m, b, classes, methods)
        if ex is None:
            skipped.append(f"{m.symbol}: {why}")
            continue
        extra = m.n_required - (1 if b[1] is None else 2)
        cands.append((extra, m.name, None, None, m, b, ex))

    for cls, ms in sorted(by_class.items()):
        if any(m.is_pure for m in ms):
            skipped.append(f"{cls}: abstract (a pure virtual method), cannot be constructed")
            continue
        ctor = next((m for m in ms if m.is_ctor and m.n_required == 0), None)
        if ctor is None:
            skipped.append(f"{cls}: no default constructor, so the harness cannot build one")
            continue
        for m in ms:
            if m.is_ctor or m.is_dtor or m.is_static:
                continue
            b = consume_binding(m)
            if b is None:
                continue
            ex, why = resolve_extras(m, b, classes, methods)
            if ex is None:
                skipped.append(f"{m.symbol}: {why}")
                continue
            # Fewer unbound required parameters first, then by name so the choice is
            # deterministic -- the same tie-break discipline the C producer uses.
            extra = m.n_required - (1 if b[1] is None else 2)
            cands.append((extra, m.name, cls, ctor, m, b, ex))

    plans = []
    for _e, _n, cls, ctor, m, (bi, li), extras in sorted(
            cands, key=lambda x: (x[0], x[1]))[:max_plans]:
        free = ctor is None
        # Objects the harness must BUILD to satisfy a parameter -- an output sink, most
        # often. Each becomes a resource, a constructor op that runs before the call, and,
        # when the constructor takes a buffer, scratch the harness owns.
        built, extra_res, extra_scratch, extra_ops, extra_apis = {}, [], [], [], []
        for idx, kcls, kctor, sctype in extras:
            if kcls is None:
                continue
            rid = "a%d" % idx
            built[idx] = rid
            extra_res.append({"id": rid, "type": {"name": kcls, "kind": "pointer"},
                              "storage": "inline"})
            cargs, cparams = [], []
            if sctype:
                sid = "b%d" % idx
                extra_scratch.append({"id": sid, "kind": "bytes", "c_type": sctype})
                pty, pnm = kctor.params[0]
                pnm = pnm or "buf"
                cparams.append({"name": pnm, "type": {"name": pty, "kind": "pointer"}})
                cargs.append({"param": pnm, "source": "scratch_addr", "ref": sid})
            extra_apis.append((kctor.symbol, {
                "symbol": kctor.symbol, "header": getattr(kctor, "header", ""),
                "role": "create", "params": cparams,
                "returns": {"name": "void", "kind": "void"}}))
            extra_ops.append({"id": "o_" + rid, "api": kctor.symbol, "args": cargs,
                              "binds": rid})

        params = ([] if free else
                  [{"name": "self", "type": {"name": f"{cls} *", "kind": "pointer"}}])
        args = ([] if free else
                [{"param": "self", "source": "resource", "ref": "o"}])
        for i, (ty, nm) in enumerate(m.params[:m.n_required]):
            pn = nm or f"arg{i}"
            params.append({"name": pn, "type": {"name": ty, "kind": _kind_of(ty)}})
            if i == bi:
                args.append({"param": pn, "source": "input", "ref": "d"})
            elif i == li:
                args.append({"param": pn, "source": "length_of", "ref": "d"})
            elif i in built:
                args.append({"param": pn, "source": "resource", "ref": built[i]})
            else:
                args.append({"param": pn, "source": "literal", "value": 0})

        tgt = dict(name=target.name, language="c++",
                   public_headers=list(target.public_headers),
                   include_dirs=list(target.include_dirs), sources=list(target.sources),
                   link_libs=list(target.link_libs), cflags=list(target.cflags),
                   seed_dirs=list(target.seed_dirs))
        plans.append(HarnessIR.from_json({
            "schema": "harness-ir/1",
            "name": (f"{target.name}_{m.name}" if free
                     else f"{target.name}_{m.cls}_{m.name}"),
            "producer": "cxx_header",
            "target": tgt,
            "apis": dict(
                ([] if free else
                 [(ctor.symbol,
                   {"symbol": ctor.symbol, "header": getattr(ctor, "header", ""),
                    "role": "create", "params": [],
                    "returns": {"name": "void", "kind": "void"}})])
                + [(m.symbol,
                    {"symbol": m.symbol, "header": getattr(m, "header", ""),
                     "role": "consume", "params": params,
                     "returns": {"name": m.ret or "void",
                                 "kind": _kind_of(m.ret or "void")}})]
                + extra_apis),
            "slices": [{"id": "d", "kind": "bytes", "remainder": True, "min_len": 1}],
            "resources": ([] if free else
                          [{"id": "o", "type": {"name": cls, "kind": "pointer"},
                            "storage": "inline"}]) + extra_res,
            "scratch": extra_scratch,
            "sequence": (([] if free else
                          [{"id": "o_new", "api": ctor.symbol, "args": [], "binds": "o"}])
                         + extra_ops
                         + [dict({"id": "o_consume", "api": m.symbol, "args": args},
                                 **({} if free else {"guarded_by": ["o"]}))]),
            "knobs": {"max_len": (knobs.max_len if knobs else 4096)},
            "platforms": list(platforms) or ["linux-x86_64-glibc"],
        }))
    return plans
