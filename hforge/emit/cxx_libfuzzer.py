"""C++ backend. Same IR, same gates, different language.

The IR needed no change to support this, which is the point of having had one: a resource
with a lifetime describes a C++ object as well as it describes a C handle. What differs is
only the spelling.

Three things C++ needs that C does not:

  * **an object is a resource with a scope.** `storage="object"` is a stack object whose
    destructor runs implicitly at the end of the harness; `storage="handle"` is `new`/`delete`.
    The distinction matters because a stack object cannot leak and a heap one can.
  * **the fuzzer's bytes must become a C++ type.** `std::string`, `std::string_view` and
    `std::vector<uint8_t>` are how nearly every C++ harness passes input, and each is
    constructed differently from a `(data, size)` pair.
  * **`extern "C"` on the entry point.** libFuzzer looks up an unmangled symbol; without it
    the harness compiles and the fuzzer cannot find it, which is a silent failure.

Overloads are resolved by ARITY, recorded on the op. Two methods sharing a name and differing
in signature are two different APIs, and a plan that does not say which one it meant is
refused rather than guessed at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..ir import (
    HarnessIR, SLICE_BYTES, SLICE_CSTRING, SRC_INPUT, SRC_LENGTH_OF, SRC_LITERAL,
    SRC_OUT, SRC_RESOURCE,
)
from .c_libfuzzer import EmitError, Emitted

P = "hf_"

_STRINGY = re.compile(r"std::(string_view|string)\b")
_VECTORY = re.compile(r"std::(?:vector|span)\s*<")


def _res(rid: str) -> str:
    return f"{P}o_{rid}"


def _slice(sid: str) -> str:
    return f"{P}s_{sid}"


def _cxx_input(type_name: str, sid: str) -> str:
    """The fuzzer's bytes, spelled as the parameter's C++ type."""
    if _STRINGY.search(type_name):
        return _slice(sid)
    if _VECTORY.search(type_name):
        return _slice(sid) + "_v"
    if "*" in type_name:
        return f"reinterpret_cast<{type_name.replace('&', '').strip()}>({_slice(sid)}.data())"
    raise EmitError(
        f"parameter type {type_name!r} is not a shape the fuzzer's bytes can take. C++ "
        f"harnesses pass input as std::string, std::string_view, std::vector<uint8_t>, "
        f"std::span or a byte pointer; anything else must be built by the plan.")


def emit(ir: HarnessIR, with_driver: bool = True) -> Emitted:
    if ir.target.language not in ("c++", "cpp", "cxx"):
        raise EmitError(f"this backend emits C++; target.language is {ir.target.language!r}")

    decls: list = []
    body: list = []
    frees: list = []

    # inputs
    for s in ir.slices:
        if s.remainder:
            decls.append(f"    std::string {_slice(s.id)}("
                         f"reinterpret_cast<const char *>({P}data), {P}size);")
        else:
            n = s.max_len or 64
            decls.append(f"    std::string {_slice(s.id)}("
                         f"reinterpret_cast<const char *>({P}data), "
                         f"std::min<size_t>({P}size, {n}));")
        decls.append(f"    std::vector<uint8_t> {_slice(s.id)}_v("
                     f"{_slice(s.id)}.begin(), {_slice(s.id)}.end());")

    # resources
    heap = {r.id for r in ir.resources if r.storage == "handle"}
    for r in ir.resources:
        base = r.type.name.replace("*", "").strip()
        if r.storage == "handle":
            decls.append(f"    {base} *{_res(r.id)} = nullptr;")
        else:
            # A stack object: its destructor runs at scope exit, so it cannot leak — which
            # is why `storage` is recorded rather than assumed.
            decls.append(f"    std::optional<{base}> {_res(r.id)};")

    sink_used = False
    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            raise EmitError(f"op {op.id} calls undeclared API {op.api!r}")

        args: list = []
        for pd in api.params:
            a = next((x for x in op.args if x.param == pd.name), None)
            if a is None:
                raise EmitError(f"op {op.id}: no argument for parameter {pd.name!r}")
            if a.source == SRC_LITERAL:
                args.append("nullptr" if a.value in (None, 0) and "*" in pd.type.name
                            else str(a.value if a.value is not None else 0))
            elif a.source == SRC_INPUT:
                args.append(_cxx_input(pd.type.name, a.ref))
            elif a.source == SRC_LENGTH_OF:
                args.append(f"{_slice(a.ref)}.size()")
            elif a.source == SRC_RESOURCE:
                args.append(_res(a.ref) if a.ref in heap else f"*{_res(a.ref)}")
            elif a.source == SRC_OUT:
                base = pd.type.name.replace("*", "").replace("&", "").strip()
                decls.append(f"    {base} {P}out_{op.id}_{pd.name}{{}};")
                args.append(f"&{P}out_{op.id}_{pd.name}")

        cls = api.header_class if hasattr(api, "header_class") else ""
        sym = api.symbol
        indent = "    "
        body.append(f"    /* {op.id}: {sym} [{api.role}] */")
        if op.guarded_by:
            cond = " && ".join(_res(g) for g in op.guarded_by)
            body.append(f"    if ({cond}) {{")
            indent = "        "

        if op.binds and op.binds in heap:
            base = sym.rsplit("::", 1)[0]
            body.append(f"{indent}{_res(op.binds)} = new {base}({', '.join(args)});")
        elif op.binds:
            base = sym.rsplit("::", 1)[0]
            body.append(f"{indent}{_res(op.binds)}.emplace({', '.join(args)});")
        elif "::" in sym and op.args and any(a.source == SRC_RESOURCE for a in op.args):
            recv = next(a.ref for a in op.args if a.source == SRC_RESOURCE)
            rest = [x for x, a in zip(args, api.params)
                    if not (next((y for y in op.args if y.param == a.name), None)
                            and next(y for y in op.args if y.param == a.name).source
                            == SRC_RESOURCE and next(y for y in op.args
                                                     if y.param == a.name).ref == recv)]
            arrow = "->" if recv in heap else "->"
            obj = _res(recv) if recv in heap else f"{_res(recv)}"
            meth = sym.rsplit("::", 1)[1]
            sink_used = True
            body.append(f"{indent}{P}sink += reinterpret_cast<intptr_t>("
                        f"(void *)&{obj});")
            body.append(f"{indent}{obj}{arrow}{meth}({', '.join(rest)});")
        else:
            # `(long)f(...)` does not compile when f returns void, and a free function at
            # namespace scope is the common case where it does -- the sink exists to stop
            # the optimiser discarding the call, so a void call simply gets no sink.
            if (api.returns.kind or "").lower() == "void":
                body.append(f"{indent}{sym}({', '.join(args)});")
            else:
                sink_used = True
                body.append(f"{indent}{P}sink += (long){sym}({', '.join(args)});")

        if op.targets and op.targets in heap:
            body.append(f"{indent}delete {_res(op.targets)};")
            body.append(f"{indent}{_res(op.targets)} = nullptr;")

        if op.guarded_by:
            body.append("    }")

    if sink_used:
        decls.insert(0, f"    volatile long {P}sink = 0;")
        body.append(f"    (void){P}sink;")

    headers = "\n".join(f'#include "{h}"' for h in ir.target.public_headers)
    source = f"""/* Generated by Harness Forge from a certified Harness IR plan.
 *
 *   harness  : {ir.name}
 *   target   : {ir.target.name}  (C++)
 *   producer : {ir.producer}
 *
 * `extern "C"` on the entry point is not decoration: libFuzzer looks up an UNMANGLED symbol,
 * and without it the harness compiles cleanly and the fuzzer never finds it.
 */
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <optional>
#include <string>
#include <vector>

{headers}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *{P}data, size_t {P}size) {{
{chr(10).join(decls)}

    if ({P}size > {ir.knobs.max_len}u) return 0;

{chr(10).join(body)}
{chr(10).join(frees)}
    return 0;
}}
"""

    incs = [f"-I{d}" for d in ir.target.include_dirs] + list(ir.target.cflags)
    san = ",".join(ir.knobs.sanitizers)
    common = ["$CXX", "-g", ir.knobs.optimisation, "-std=c++17",
              "-fno-omit-frame-pointer", *incs]
    build = [*common, f"-fsanitize=fuzzer{',' + san if san else ''}", "harness.cc",
             *ir.target.sources, *ir.target.link_libs, "-o", f"{ir.name}_fuzz"]
    dbuild = [*common] + ([f"-fsanitize={san}"] if san else []) + \
             ["harness.cc", "driver.cc", *ir.target.sources, *ir.target.link_libs,
              "-o", f"{ir.name}_replay"]

    driver = f"""/* Standalone replay for {ir.name}. Same exactly-sized heap buffer as the C
 * driver, for the same reason: libFuzzer hands the harness an exact allocation, so an
 * over-read by one byte hits a redzone. Out of a large static buffer it hits valid memory
 * and the bug is certified away.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

int main(int argc, char **argv) {{
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    std::vector<uint8_t> buf;
    uint8_t chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) buf.insert(buf.end(), chunk, chunk + n);
    fclose(f);
    uint8_t *exact = static_cast<uint8_t *>(malloc(buf.size() ? buf.size() : 1));
    if (!exact) return 2;
    if (!buf.empty()) memcpy(exact, buf.data(), buf.size());
    LLVMFuzzerTestOneInput(exact, buf.size());
    free(exact);
    return 0;
}}
""" if with_driver else ""

    return Emitted(source=source, driver=driver, build_command=build,
                   driver_build_command=dbuild,
                   entry_symbols=sorted({ir.api_of(o).symbol for o in ir.sequence
                                         if ir.api_of(o)}))
