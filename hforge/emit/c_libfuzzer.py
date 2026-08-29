"""C / libFuzzer emitter — one backend for the IR.

The plan is the certified artifact; this turns it into buildable C. Other backends
(AFL++ persistent, TinyInst in-process, GUI file-drop, interpreter) consume the same IR,
which is the point: certified semantics travel across OS and architecture.

Two outputs:

  * `LLVMFuzzerTestOneInput`, for the campaign
  * an optional standalone `main()` driver that reads one input from a file or stdin, so
    the *same* harness can be replayed with no fuzzer runtime present. The native-replay
    and determinism gates need this, and libFuzzer binaries ignore stdin.

The emitter declares every variable at the top of the function so a single `goto` cleanup
path is legal C. It also refuses rather than guesses: an IR it cannot express correctly
raises, instead of emitting C that compiles into something subtly different from the plan.
"""
from __future__ import annotations

from pathlib import Path

from dataclasses import dataclass

from ..ir import (
    HarnessIR, Op, Api, InputSlice,
    SRC_INPUT, SRC_LITERAL, SRC_RESOURCE, SRC_LENGTH_OF, SRC_OUT,
    SRC_SCRATCH, SRC_SCRATCH_ADDR,
    SCRATCH_BYTES, SCRATCH_PTR, SCRATCH_SIZE,
    SLICE_BYTES, SLICE_CSTRING, SLICE_U8, SLICE_U16LE, SLICE_U32LE, SLICE_U64LE,
)

P = "hf_"          # prefix for every emitter-owned identifier


class EmitError(Exception):
    """The plan cannot be expressed faithfully in this backend."""


@dataclass
class Emitted:
    source: str
    driver: str
    build_command: list[str]
    driver_build_command: list[str]
    entry_symbols: list[str]         # what gate D1 must find surviving in the object


_SCALAR_C = {SLICE_U8: "uint8_t", SLICE_U16LE: "uint16_t",
             SLICE_U32LE: "uint32_t", SLICE_U64LE: "uint64_t"}


def _is_pointer(type_name: str, kind: str = "") -> bool:
    """Whether a type is a pointer. `kind` is the IR's own declaration and wins when set.

    Libraries habitually hide the pointer behind a typedef — `magic_t`, `xmlDocPtr`,
    `sqlite3` — so a textual test for `*` refuses perfectly good plans. The IR already
    records `kind="pointer"` for exactly this reason; the emitter simply was not reading it.
    """
    return kind == "pointer" or "*" in type_name


def _slice_var(s: InputSlice) -> str:
    return f"{P}s_{s.id}"


def _len_var(s: InputSlice) -> str:
    return f"{P}len_{s.id}"


def _res_ok(rid: str) -> str:
    """The flag recording that a caller-allocated resource was successfully initialised.

    A handle resource IS its own liveness test: the pointer is NULL or it is not. An inline
    resource is a struct that always exists, so liveness has to be tracked separately or the
    plan would use an object whose initialiser failed.
    """
    return f"{P}ok_{rid}"


def _res_var(rid: str) -> str:
    return f"{P}r_{rid}"


def _lit(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, str):
        if value in ("NULL", "true", "false"):
            return value
        esc = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{esc}"'
    return str(value)


def _headers(ir: HarnessIR) -> list[str]:
    """What to `#include`, spelled so the compiler can find it.

    The include directive must be the path RELATIVE TO AN INCLUDE DIRECTORY, not the
    basename. brotli's public header is `c/include/brotli/decode.h` and the build passes
    `-Ic/include`, so `#include "decode.h"` does not resolve and the harness does not
    compile — which is how a brotli run reached `fatal error: 'decode.h' file not found`.
    It affects every library that namespaces its headers in a directory, which is most of
    them: brotli, cdio, openjpeg, ImageMagick, freetype.
    """
    seen, out = set(), []
    inc_dirs = [Path(d) for d in ir.target.include_dirs]
    for h in list(ir.target.public_headers) + [a.header for a in ir.apis.values()]:
        if not h or h in seen:
            continue
        seen.add(h)
        hp = Path(h)
        spelled = h
        if hp.is_absolute():
            # Shortest path that still resolves under one of the -I directories.
            rels = []
            for d in inc_dirs:
                try:
                    rels.append(hp.relative_to(d).as_posix())
                except ValueError:
                    continue
            spelled = min(rels, key=len) if rels else hp.name
        else:
            # A BARE NAME, which is what the producer records on each Api. If it does not
            # sit directly in an include directory, find where it does and spell the path
            # relative to that directory. brotli's header is `c/include/brotli/decode.h`
            # against `-Ic/include`, so `#include "decode.h"` does not resolve — and the
            # first version of this fix only handled absolute paths, so brotli failed to
            # build twice.
            found = []
            for d in inc_dirs:
                if (d / hp).exists():
                    found.append(hp.as_posix())
                    break
                for cand in list(d.glob(f"*/{hp.name}")) + list(d.glob(f"*/*/{hp.name}")):
                    found.append(cand.relative_to(d).as_posix())
            if found:
                spelled = min(found, key=len)
        out.append(spelled)
    return out


def _emit_slices(ir: HarnessIR) -> tuple[list[str], list[str], list[str]]:
    """Returns (declarations, body lines, free lines)."""
    decls: list[str] = []
    body: list[str] = []
    frees: list[str] = []

    fixed = [s for s in ir.slices if s.fixed_width]
    var = [s for s in ir.slices if not s.fixed_width]
    remainders = [s for s in var if s.remainder]
    if len(remainders) > 1:
        raise EmitError("more than one slice claims the remainder of the input")

    for s in fixed:
        ct = _SCALAR_C[s.kind]
        decls.append(f"    {ct} {_slice_var(s)} = 0;")
    for s in var:
        if s.kind == SLICE_CSTRING:
            decls.append(f"    char *{_slice_var(s)} = NULL;")
        else:
            decls.append(f"    const uint8_t *{_slice_var(s)} = NULL;")
        decls.append(f"    size_t {_len_var(s)} = 0;")

    body.append(f"    size_t {P}cursor = 0;")

    # fixed-width scalars are read first, from the front, little-endian
    for s in fixed:
        w = s.fixed_width
        body.append(f"    if ({P}cursor + {w} > {P}size) goto {P}cleanup;")
        if w == 1:
            body.append(f"    {_slice_var(s)} = {P}data[{P}cursor];")
        else:
            body.append(f"    memcpy(&{_slice_var(s)}, {P}data + {P}cursor, {w});")
        body.append(f"    {P}cursor += {w};")

    for s in var:
        if s.remainder:
            body.append(f"    {_len_var(s)} = {P}size - {P}cursor;")
        else:
            cap = s.max_len if s.max_len else 0
            if not cap:
                raise EmitError(
                    f"slice {s.id!r} is neither fixed-width nor remainder and has no max_len; "
                    f"the emitter will not guess how many bytes it takes")
            body.append(f"    {_len_var(s)} = ({P}size - {P}cursor) < {cap}u "
                        f"? ({P}size - {P}cursor) : {cap}u;")
        if s.min_len:
            body.append(f"    if ({_len_var(s)} < {s.min_len}u) goto {P}cleanup;")

        if s.kind == SLICE_CSTRING:
            v = _slice_var(s)
            body.append(f"    {v} = (char *)malloc({_len_var(s)} + 1);")
            body.append(f"    if (!{v}) goto {P}cleanup;")
            body.append(f"    memcpy({v}, {P}data + {P}cursor, {_len_var(s)});")
            body.append(f"    {v}[{_len_var(s)}] = '\\0';   /* contract: NUL-terminated */")
            frees.append(f"    free({_slice_var(s)});")
        else:
            body.append(f"    {_slice_var(s)} = {P}data + {P}cursor;")
        body.append(f"    {P}cursor += {_len_var(s)};")

    return decls, body, frees


def _scr_var(sid: str) -> str:
    return f"{P}sc_{sid}"


def _emit_scratch(ir: HarnessIR) -> tuple:
    """Declare the storage the LIBRARY requires the caller to own.

    A streaming decoder does not allocate for you: it takes your buffer, your cursor and
    your remaining-count, and writes back how far it got. Before this existed the producer
    had nothing to bind those to and used 0 — so `uncompress2(0, 0, input, 0)` and
    `BrotliDecoderDecompressStream(state, 0, 0, 0, 0, 0)` were emitted, and both died on
    the first input having done nothing.
    """
    # DECLARATIONS and INITIALISATION are returned separately, and the caller must place
    # the initialisation AFTER the slice body.
    #
    # Initialising a cursor where it is declared reads the slice pointer before the body has
    # assigned it: `const uint8_t *cur = hf_s_input;` ran while hf_s_input was still NULL and
    # available_in was still 0. libFuzzer read 44 valid brotli streams, the corpus collapsed
    # to `corp: 1/1b`, and coverage sat at 42 edges forever — every streaming harness was
    # decoding a null pointer of length zero, and no corpus on earth would have shown it.
    decls, init = [], []
    for sc in ir.scratch:
        v = _scr_var(sc.id)
        if sc.kind == SCRATCH_BYTES:
            decls.append(f"    static unsigned char {v}[{sc.capacity}];")
            init.append(f"    memset({v}, 0, sizeof {v});")
        elif sc.kind == SCRATCH_SIZE:
            t = sc.c_type or "size_t"
            if sc.init_from:
                sl = ir.slice_by_id(sc.init_from)
                src = _len_var(sl) if sl else f"sizeof {_scr_var(sc.init_from)}"
            else:
                src = str(sc.capacity)
            decls.append(f"    {t} {v} = 0;")
            init.append(f"    {v} = ({t})({src});")
        elif sc.kind == SCRATCH_PTR and sc.owns:
            t = sc.c_type or "unsigned char *"
            decls.append(f"    {t} {v} = NULL;")
        elif sc.kind == SCRATCH_PTR:
            t = sc.c_type or "const unsigned char *"
            decls.append(f"    {t} {v} = NULL;")
            if sc.init_from:
                sl = ir.slice_by_id(sc.init_from)
                src = (f"({t})" + (_slice_var(sl) if sl else _scr_var(sc.init_from)))
                init.append(f"    {v} = {src};")
    return decls, init


def _arg_expr(ir: HarnessIR, api: Api, op: Op, param: str) -> str:
    a = next((x for x in op.args if x.param == param), None)
    if a is None:
        raise EmitError(f"op {op.id}: no argument supplied for parameter {param!r}")
    if a.source == SRC_LITERAL:
        return _lit(a.value)
    if a.source == SRC_RESOURCE:
        r = next((x for x in ir.resources if x.id == a.ref), None)
        if r is not None and r.by_address and op.binds == a.ref:
            # Only the CREATE call takes the address; every later use passes the object or
            # pointer itself.
            return f"&{_res_var(a.ref)}"
        if r is not None and r.storage == "inline":
            return f"&{_res_var(a.ref)}"      # caller-allocated: always by address
        return _res_var(a.ref)
    if a.source == SRC_SCRATCH:
        sc = next((x for x in ir.scratch if x.id == a.ref), None)
        if sc is None:
            raise EmitError(f"op {op.id}: unknown scratch {a.ref!r}")
        pd = ir.param_decl(api, param)
        cast = f"({pd.type.name})" if pd else ""
        return f"{cast}{_scr_var(sc.id)}"
    if a.source == SRC_SCRATCH_ADDR:
        sc = next((x for x in ir.scratch if x.id == a.ref), None)
        if sc is None:
            raise EmitError(f"op {op.id}: unknown scratch {a.ref!r}")
        return f"&{_scr_var(sc.id)}"
    if a.source == SRC_OUT:
        return f"&{P}out_{op.id}_{param}"
    sl = ir.slice_by_id(a.ref)
    if sl is None:
        raise EmitError(f"op {op.id}: argument {param!r} references unknown slice {a.ref!r}")
    if a.source == SRC_LENGTH_OF:
        if sl.fixed_width:
            raise EmitError(f"op {op.id}: length_of a fixed-width slice {sl.id!r} is meaningless")
        return _len_var(sl)
    # SRC_INPUT
    pd = ir.param_decl(api, param)
    cast = ""
    if pd is not None and sl.kind == SLICE_BYTES and "uint8_t" not in pd.type.name:
        cast = f"({pd.type.name})"
    return f"{cast}{_slice_var(sl)}"


def _emit_ops(ir: HarnessIR) -> tuple[list[str], list[str]]:
    decls: list[str] = []
    body: list[str] = []
    sink_used = False

    inline_ids = {r.id for r in ir.resources if r.by_address}
    ptr_ids = {r.id for r in ir.resources if r.storage == "out_param"}
    for r in ir.resources:
        if r.storage == "out_param":
            # The library allocates and writes the pointer back through `&h`. The pointer
            # itself is the liveness test, exactly as for a returned handle.
            decls.append(f"    {r.type.name} {_res_var(r.id)} = NULL;")
            decls.append(f"    int {_res_ok(r.id)} = 0;")
            continue
        if r.inline:
            # The caller owns the storage. Zero-initialised so that a failed initialiser
            # leaves a defined object rather than a stack full of whatever was there.
            decls.append(f"    {r.type.name} {_res_var(r.id)};")
            decls.append(f"    int {_res_ok(r.id)} = 0;")
            body.append(f"    memset(&{_res_var(r.id)}, 0, sizeof {_res_var(r.id)});")
            continue
        if not _is_pointer(r.type.name, r.type.kind):
            raise EmitError(
                f"resource {r.id!r} has non-pointer type {r.type.name!r}. v1 models resources "
                f"as handles or pointers; express anything else in a raw block and accept it "
                f"as an uncertified region.")
        decls.append(f"    {r.type.name} {_res_var(r.id)} = NULL;")

    emitted_in_loop: set = set()
    for i, op in enumerate(ir.sequence):
        if op.id in emitted_in_loop:
            continue                     # already emitted inside a repeat loop
        api = ir.api_of(op)
        if api is None:
            raise EmitError(f"op {op.id} calls undeclared API {op.api!r}")

        for a in op.args:
            if a.source == SRC_OUT:
                pd = ir.param_decl(api, a.param)
                base = pd.type.name.rstrip(" *") if pd else "long"
                base_c = base.replace("const", "").strip()
                if base_c in ("void", ""):
                    # `void *z` is an opaque BUFFER, not a place to write one object:
                    # stripping the star yields `void hf_out_... = {0};`, which is not C.
                    # The emitter produced it, `emit` reported success, and the plan shipped
                    # and was ranked FIRST off six static gates while every dynamic gate read
                    # NOT_RUN "the binary was not built". Refusing here is what turns a
                    # compile error nobody reads into a verdict with a reason.
                    raise EmitError(
                        f"op {op.id}: parameter {a.param!r} is `{base}` and cannot be an "
                        f"out-parameter — there is no object to declare. Bind it to an "
                        f"input slice with its length, or to NULL.")
                # `= {0}` rather than `= 0`: an out-parameter is frequently a STRUCT
                # (`yaml_event_t`), and `yaml_event_t e = 0;` does not compile. A braced
                # initialiser is valid for scalars too, so one spelling covers both.
                decls.append(f"    {base} {P}out_{op.id}_{a.param} = {{0}};")

        args = ", ".join(_arg_expr(ir, api, op, pd.name) for pd in api.params)
        call = f"{api.symbol}({args})"
        indent = "    "
        body.append(f"    /* {op.id}: {api.symbol} [{api.role}] */")

        if op.repeat:
            # Drive the library until it says stop, BOUNDED. `yaml_parser_scan` returns one
            # token per call; calling it once was 77 million executions for 9.6% of libyaml
            # while the gold harness, which loops, reaches 70.6%.
            #
            # The bound is not optional: an unbounded loop steered by fuzzer input is a hang,
            # and a hang is indistinguishable from a finding until a human looks at it.
            body.append(f"    for (unsigned {P}it = 0; {P}it < {op.repeat}u; ++{P}it) {{")
            indent = "        "

        if op.guarded_by:
            cond = " && ".join(
                _res_var(g) if (g in ptr_ids or g not in inline_ids) else _res_ok(g)
                for g in op.guarded_by)
            body.append(f"    if ({cond}) {{")
            indent = "        "

        if op.binds and op.binds in inline_ids:
            # The initialiser returns a STATUS, not the object: the object is already the
            # harness's own storage. Binding the return value into the resource variable
            # would overwrite the struct with an int.
            if api.returns.kind == "void" or api.returns.name.strip() == "void":
                # ...unless it returns nothing. `ZopfliInitOptions(ZopfliOptions *)` is void,
                # and `(int)(void_call)` is not C — the harness failed to compile on the one
                # line that sets up its own configuration.
                body.append(f"{indent}{call};")
                body.append(f"{indent}{_res_ok(op.binds)} = 1;")
            else:
                body.append(f"{indent}{_res_ok(op.binds)} = (int)({call});")
        elif op.binds:
            body.append(f"{indent}{_res_var(op.binds)} = {call};")
        elif op.repeat and api.returns.kind != "void" and api.returns.name != "void":
            # The call's own result is the termination condition: stop when the library
            # stops making progress. Anything else needs library-specific knowledge the
            # producer does not have and must not invent.
            sink_used = True
            body.append(f"{indent}{P}sink += (long)({call});")
            body.append(f"{indent}if (!{P}sink) break;")
        elif api.returns.kind != "void" and api.returns.name != "void":
            sink_used = True
            body.append(f"{indent}{P}sink += (long){call};")
        else:
            body.append(f"{indent}{call};")

        if op.targets and op.targets in inline_ids:
            body.append(f"{indent}{_res_ok(op.targets)} = 0;")
        elif op.targets:
            body.append(f"{indent}{_res_var(op.targets)} = NULL;")

        if op.guarded_by:
            body.append(f"{'        ' if op.repeat else '    '}}}")

        if op.repeat and op.binds and op.binds in inline_ids:
            # Stop when the library stops making progress. For an op that fills a
            # caller-allocated struct the status lands in the resource's ok flag, so that is
            # the condition — `while (yaml_parser_scan(...))`, which is what the gold
            # harness does.
            body.append(f"        if (!{_res_ok(op.binds)}) break;")

        if op.repeat:
            # The cleanup for what THIS iteration produced belongs inside the loop. Left
            # outside, `yaml_parser_scan` would allocate a token per iteration and delete
            # exactly one — the harness leaking on its own, which LeakSanitizer reports as a
            # finding on every input.
            for later in ir.sequence[i + 1:]:
                if not (op.binds and later.targets == op.binds):
                    continue
                lapi = ir.api_of(later)
                if lapi is None:
                    continue
                largs = ", ".join(_arg_expr(ir, lapi, later, pd.name)
                                  for pd in lapi.params)
                body.append(f"        /* {later.id}: {lapi.symbol} (per iteration) */")
                body.append(f"        {lapi.symbol}({largs});")
                emitted_in_loop.add(later.id)
            body.append("    }")

    if sink_used:
        decls.insert(0, f"    volatile long {P}sink = 0;")
        body.append(f"    (void){P}sink;")
    return decls, body


HEADER_NOTE = """/* Generated by Harness Forge from a certified Harness IR plan.
 *
 *   harness : {name}
 *   target  : {target}{ver}
 *   producer: {producer}
 *   platforms: {plats}
 *
 * Do not edit this file. Edit the IR and re-emit, or the certificate stops describing
 * what you are actually running.
 */"""


def emit(ir: HarnessIR, *, with_driver: bool = True) -> Emitted:
    slice_decls, slice_body, slice_frees = _emit_slices(ir)
    op_decls, op_body = _emit_ops(ir)
    # Scratch is declared AFTER the slices, because a cursor is initialised from one.
    scratch_decls, scratch_init = _emit_scratch(ir)

    pre = [b.code for b in ir.raw_blocks if b.where == "prologue"]
    post = [b.code for b in ir.raw_blocks if b.where == "epilogue"]

    includes = "\n".join(f'#include "{h}"' for h in _headers(ir))
    ver = f" {ir.target.version}" if ir.target.version else ""

    lines = [
        HEADER_NOTE.format(name=ir.name, target=ir.target.name, ver=ver,
                           producer=ir.producer, plats=", ".join(ir.platforms)),
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        includes,
        "",
        f"int LLVMFuzzerTestOneInput(const uint8_t *{P}data, size_t {P}size) {{",
    ]
    lines += op_decls + slice_decls + scratch_decls
    lines.append("")
    if ir.knobs.min_len:
        lines.append(f"    if ({P}size < {ir.knobs.min_len}u) return 0;")
    if ir.knobs.max_len:
        lines.append(f"    if ({P}size > {ir.knobs.max_len}u) return 0;")
    lines.append("")
    for blk in pre:
        lines.append("    /* raw block: UNCERTIFIED */")
        lines.extend("    " + ln for ln in blk.splitlines())
    # Scratch is initialised HERE: after the slice body has assigned the input pointer and
    # its length, and before any op runs.
    lines += slice_body + scratch_init + [""] + op_body + [""]
    for blk in post:
        lines.append("    /* raw block: UNCERTIFIED */")
        lines.extend("    " + ln for ln in blk.splitlines())
    lines.append(f"{P}cleanup:")
    # Free what the LIBRARY allocated through an owned output pointer, or every input
    # leaks the compressed result and LeakSanitizer reports the harness's own bug.
    owned_frees = [f"    free((void *){_scr_var(sc.id)});"
                   for sc in ir.scratch if sc.kind == SCRATCH_PTR and sc.owns]
    lines += (slice_frees + owned_frees or [f"    ;"])
    lines.append("    return 0;")
    lines.append("}")
    source = "\n".join(lines) + "\n"

    driver = ""
    if with_driver:
        driver = f"""/* Standalone replay driver for {ir.name}.
 *
 * A libFuzzer binary ignores stdin, so the native-replay, valid-input and determinism
 * gates need the SAME harness built without the fuzzer runtime. This is that main().
 *
 * THE BUFFER MUST BE EXACTLY THE SIZE OF THE INPUT, and it must be on the heap.
 *
 * This is not a style choice, and getting it wrong silently disables the gate that matters
 * most. libFuzzer hands the harness a precisely-sized heap allocation, so a read one byte
 * past `size` lands in an ASan redzone and faults. Read the same byte out of a large static
 * buffer and it lands in valid memory, ASan says nothing, and a harness that over-reads
 * every input is certified clean.
 *
 * An earlier version of this driver used `static uint8_t buf[1 << 22]`. Gate D3 then passed
 * a plan that gate S2 had already rejected for feeding a non-terminated buffer to a
 * NUL-terminated API. The static gate was right and the dynamic gate was lying, because the
 * driver was not equivalent to the thing it claimed to model.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define HF_MAX_INPUT (1u << 22)

int main(int argc, char **argv) {{
    static uint8_t scratch[HF_MAX_INPUT];
    uint8_t *exact = NULL;
    size_t n = 0;

    if (argc > 1) {{
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 2;
        n = fread(scratch, 1, sizeof scratch, f);
        fclose(f);
    }} else {{
        n = fread(scratch, 1, sizeof scratch, stdin);
    }}

    /* Re-home the input into an exactly-sized heap allocation so the byte after it is a
     * redzone, exactly as it is under libFuzzer. malloc(0) may return NULL legitimately,
     * so ask for at least one byte and still pass n. */
    exact = (uint8_t *)malloc(n ? n : 1);
    if (!exact) return 2;
    if (n) memcpy(exact, scratch, n);

    LLVMFuzzerTestOneInput(exact, n);

    free(exact);
    return 0;
}}
"""

    san = ",".join(ir.knobs.sanitizers) if ir.knobs.sanitizers else ""
    incs = [f"-I{d}" for d in ir.target.include_dirs] + list(ir.target.cflags)
    common = ["-g", ir.knobs.optimisation, "-fno-omit-frame-pointer", *incs]
    fuzz_san = f"-fsanitize=fuzzer{',' + san if san else ''}"
    # Real filenames, not placeholders. `<harness.c>` in a shell script is a redirect from a
    # file literally named `<harness.c>`, so the emitted build.sh could not be run — the
    # operator had to hand-edit the one artifact whose whole job is to be runnable.
    build = ["$CC", *common, fuzz_san, "harness.c",
             *ir.target.sources, *ir.target.link_libs, "-o", f"{ir.name}_fuzz"]
    dbuild = ["$CC", *common] + ([f"-fsanitize={san}"] if san else []) + \
             ["harness.c", "driver.c", *ir.target.sources, *ir.target.link_libs,
              "-o", f"{ir.name}_replay"]

    return Emitted(source=source, driver=driver, build_command=build,
                   driver_build_command=dbuild,
                   entry_symbols=sorted({a.symbol for a in ir.apis.values()}))
