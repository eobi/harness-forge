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
_CLASS = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)\s*(?::\s*[^{]+)?\{")
_NAMESPACE = re.compile(r"\bnamespace\s+([A-Za-z_]\w*)\s*\{")
_ACCESS = re.compile(r"\b(public|private|protected)\s*:")

# A method or free function declaration inside a class body.
_METHOD = re.compile(
    r"^[ \t]*(?!(?:public|private|protected|using|typedef|friend|template|return)\b)"
    r"((?:virtual\s+|static\s+|inline\s+|explicit\s+|constexpr\s+)*)"      # 1 specifiers
    r"([^;{()]*?)"                                                        # 2 return type
    r"([A-Za-z_~]\w*)\s*"                                                 # 3 name
    r"\(([^;{)]*)\)\s*(const)?\s*(?:noexcept)?\s*(?:=\s*0)?\s*[;{]", re.M)

_STD_BYTES = re.compile(r"std::(?:vector\s*<\s*(?:uint8_t|unsigned\s+char|char)\s*>|"
                        r"string|string_view|span\s*<)", re.I)
_TEMPLATE = re.compile(r"\btemplate\s*<")


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

    @property
    def qualified_class(self) -> str:
        return f"{self.ns}::{self.cls}" if self.ns else self.cls

    @property
    def symbol(self) -> str:
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


def _split_params(s: str) -> list:
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
    """Classes and their public methods. Returns (methods, skipped) — what could not be read
    is returned, not dropped, because a producer that silently ignores half a header
    proposes plans for an API that is not there."""
    src = _strip(Path(path).read_text(errors="replace"))
    methods: list = []
    skipped: list = []

    # namespace stack by brace position
    ns_at: list = []
    for m in _NAMESPACE.finditer(src):
        ob = src.find("{", m.end() - 1)
        if ob >= 0:
            ns_at.append((ob, _match_brace(src, ob), m.group(1)))

    def ns_for(pos: int) -> str:
        names = [n for a, b, n in ns_at if a < pos < b]
        return "::".join(names)

    for cm in _CLASS.finditer(src):
        kind, cls = cm.group(1), cm.group(2)
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

    return methods, skipped


def _methods_in(seg: str, cls: str, ns: str, skipped: list) -> list:
    out = []
    for m in _METHOD.finditer(seg):
        spec, ret, name, params, is_const = (m.group(1) or ""), (m.group(2) or ""), \
            m.group(3), m.group(4), bool(m.group(5))
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
                          is_static="static" in spec, is_const=is_const))
    return out


def takes_bytes(ty: str) -> bool:
    """Whether this parameter can carry the fuzzer's bytes.

    `std::string`, `std::string_view`, `std::vector<uint8_t>` and `std::span` are how almost
    every C++ harness hands input to a library, and they are the C++ equivalent of the
    `(ptr, len)` pair the C producer looks for.
    """
    return bool(_STD_BYTES.search(ty)) or bool(
        re.search(r"\b(?:const\s+)?(?:char|uint8_t|unsigned char|void)\s*\*", ty))
