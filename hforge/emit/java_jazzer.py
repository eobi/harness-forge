"""Java backend: a Jazzer harness, plus a standalone replay driver.

We emit libFuzzer harnesses rather than building libFuzzer. Jazzer is the same decision on
the JVM: it is the de-facto Java fuzzer, libFuzzer-based, and what OSS-Fuzz runs for Java —
including the semantic sanitizers (injection, deserialization, SSRF, path traversal) that
have no C analogue and that carry the highest-value JVM findings. Building a JVM fuzzer here
would be re-doing the part of the problem that is already solved.

Two artifacts, mirroring the C backend exactly:

  * `Harness.java`   — `fuzzerTestOneInput(FuzzedDataProvider)`, what the campaign runs
  * `Replay.java`    — `main(String[] path)`, one input from a file, no fuzzer runtime.
                       Every gate that feeds a CHOSEN input (D3, D5, D6, F1, F2) needs this,
                       and on the JVM it is the only way to get a stack trace on stderr with
                       no Jazzer on the classpath.

The replay driver prints the trace and **exits 0 even when it caught something**, because on
the JVM an uncaught exception exits 1 and so does a missing file, a bad classpath and a
JVM that failed to start. `toolchain.classify_exit` cannot tell those apart, so the driver
does not ask it to: it prints a machine-readable marker and the fault is read from the
output, never from the status.
"""
from __future__ import annotations

from ..ir import (HarnessIR, SLICE_BYTES, SLICE_CSTRING, SLICE_U8, SLICE_U16LE, SLICE_U32LE,
                  SLICE_U64LE, SRC_INPUT, SRC_LITERAL, SRC_RESOURCE)
from .c_libfuzzer import EmitError, Emitted

HARNESS_CLASS = "Harness"
REPLAY_CLASS = "Replay"

# The markers the replay driver prints. Defined in `hforge.java` because they are a protocol
# between this writer and the reader in `java/toolchain.py`, and the reader must not import
# the emitter to learn them.
from ..java import CLEAN_MARKER, FAULT_MARKER          # noqa: E402

_CONSUME = {
    SLICE_CSTRING: ("String", "consumeRemainingAsString()", "consumeString({n})"),
    SLICE_BYTES:   ("byte[]", "consumeRemainingAsBytes()", "consumeBytes({n})"),
    SLICE_U8:      ("byte", "consumeByte()", "consumeByte()"),
    SLICE_U16LE:   ("short", "consumeShort()", "consumeShort()"),
    SLICE_U32LE:   ("int", "consumeInt()", "consumeInt()"),
    SLICE_U64LE:   ("long", "consumeLong()", "consumeLong()"),
}

# A parameter type the plan drives, and how the raw slice becomes it. `byte[]` reaches an
# InputStream through a wrapper rather than by a cast, because the JVM has no cast that would
# work — which is the same fact that makes S2's type confusion impossible here.
_ADAPT = {
    "java.io.InputStream":   "new java.io.ByteArrayInputStream({v})",
    "java.io.Reader":        "new java.io.StringReader({v})",
    "java.nio.ByteBuffer":   "java.nio.ByteBuffer.wrap({v})",
    "java.lang.CharSequence": "{v}",
}


def _var(slice_id: str) -> str:
    return "hf_" + slice_id.replace(".", "_").replace("-", "_")


def _lit(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        esc = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{esc}"'
    return str(value)


def _res_var(rid: str) -> str:
    return "hf_r_" + rid


def _simple(fq: str) -> str:
    return fq.rsplit(".", 1)[-1]


def _adapt(expr: str, declared: str, slice_kind: str) -> str:
    """Fit a consumed value to the declared parameter type, or refuse."""
    if declared in _ADAPT:
        return _ADAPT[declared].format(v=expr)
    return expr


def _arg_expr(ir: HarnessIR, api, op, index: int, pname: str) -> str:
    a = next((x for x in op.args if x.param == pname), None)
    if a is None:
        raise EmitError(f"op {op.id}: no argument supplied for parameter {pname!r}")
    if a.source == SRC_LITERAL:
        return _lit(a.value)
    if a.source == SRC_RESOURCE:
        return _res_var(a.ref)
    if a.source == SRC_INPUT:
        sl = ir.slice_by_id(a.ref)
        if sl is None:
            raise EmitError(f"op {op.id}: unknown slice {a.ref!r}")
        pd = ir.param_decl(api, pname)
        declared = pd.type.name if pd else ""
        return _adapt(_var(sl.id), declared, sl.kind)
    raise EmitError(f"op {op.id}: argument source {a.source!r} has no Java spelling. "
                    f"`length_of` and `out` are C shapes: FuzzedDataProvider carries its own "
                    f"length, and Java returns values rather than writing through pointers.")


# The declared PARAMETER type decides the local, not the slice kind. A `boolean` parameter
# whose slice is u8 would otherwise get `byte x = data.consumeByte();` passed where a boolean
# is wanted, and the harness would not compile — caught only because the real
# FuzzedDataProvider was read rather than assumed.
_BY_DECLARED = {
    "boolean": ("boolean", "consumeBoolean()"),
    "char":    ("char", "consumeChar()"),
    "byte":    ("byte", "consumeByte()"),
    "short":   ("short", "consumeShort()"),
    "int":     ("int", "consumeInt()"),
    "long":    ("long", "consumeLong()"),
    "float":   ("float", "consumeFloat()"),
    "double":  ("double", "consumeDouble()"),
}


def _declared_types(ir: HarnessIR) -> dict:
    """slice id -> the Java type the parameter it feeds is declared as."""
    out: dict = {}
    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue
        for a in op.args:
            if a.source != SRC_INPUT:
                continue
            pd = ir.param_decl(api, a.param)
            if pd is not None:
                out[a.ref] = pd.type.name
    return out


def _consume_lines(ir: HarnessIR, provider: str) -> list:
    """One local per slice, taken from the provider in plan order.

    Order matters and is the plan's: the provider is a cursor, so re-ordering these lines
    changes what every later slice receives. Bounded slices are consumed BEFORE the remainder
    for the same reason the C chain producer had to stop giving the first parameter
    everything.
    """
    out = []
    declared = _declared_types(ir)
    ordered = sorted(ir.slices, key=lambda s: (s.remainder, ir.slices.index(s)))
    for sl in ordered:
        want = declared.get(sl.id, "")
        if want in _BY_DECLARED:
            jtype, call = _BY_DECLARED[want]
            out.append(f"        {jtype} {_var(sl.id)} = {provider}.{call};")
            continue
        spec = _CONSUME.get(sl.kind)
        if spec is None:
            raise EmitError(f"slice {sl.id!r}: kind {sl.kind!r} has no FuzzedDataProvider "
                            f"equivalent")
        jtype, remainder_call, bounded_call = spec
        call = remainder_call if sl.remainder else bounded_call.format(
            n=sl.max_len or 256)
        out.append(f"        {jtype} {_var(sl.id)} = {provider}.{call};")
    return out


def emit(ir: HarnessIR) -> Emitted:
    lang = (ir.target.language or "").lower()
    if lang not in ("java", "jvm", "kotlin"):
        raise EmitError(f"this backend emits Java; target.language is {ir.target.language!r}")
    if ir.raw_blocks:
        raise EmitError("a Java plan may not carry raw blocks: verbatim source is exactly "
                        "what the static gates cannot see into")

    imports = ["import com.code_intelligence.jazzer.api.FuzzedDataProvider;"]
    body: list = []
    decls: list = []

    for r in ir.resources:
        decls.append(f"        {r.type.name} {_res_var(r.id)} = null;")

    live: set = set()
    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            raise EmitError(f"op {op.id} calls undeclared API {op.api!r}")
        args = ", ".join(_arg_expr(ir, api, op, i, pd.name)
                         for i, pd in enumerate(api.params))

        owner, member = api.symbol.rsplit(".", 1)
        indent = "        "
        guard = ""
        if op.guarded_by:
            guard = " && ".join(f"{_res_var(g)} != null" for g in op.guarded_by)

        if member == "<init>":
            call = f"new {owner}({args})"
        elif op.binds or not any(a.source == SRC_RESOURCE for a in op.args):
            # A static call, or an instance call on a resource this op targets.
            target_res = op.targets or (op.guarded_by[0] if op.guarded_by else None)
            call = (f"{_res_var(target_res)}.{member}({args})" if target_res
                    else f"{owner}.{member}({args})")
        else:
            call = f"{owner}.{member}({args})"

        body.append(f"{indent}/* {op.id}: {api.symbol} [{api.role}] */")
        if guard:
            body.append(f"{indent}if ({guard}) {{")
            indent += "    "

        if op.binds:
            body.append(f"{indent}{_res_var(op.binds)} = {call};")
            live.add(op.binds)
        elif api.returns.name not in ("void", ""):
            # Consume the result. javac does not eliminate dead calls, but the JIT can, and
            # a harness whose body C2 removed runs at enormous speed reporting nothing —
            # the same failure D1 exists to catch in C, arriving one layer later.
            body.append(f"{indent}hfSink += {_sink_cast(api.returns.name)};")
            body[-1] = body[-1].replace("hfSink += ;", "")
            body[-1] = f"{indent}hfSink += {_sink_of(api.returns.name, call)};"
        else:
            body.append(f"{indent}{call};")

        if op.targets:
            body.append(f"{indent}{_res_var(op.targets)} = null;")

        if guard:
            indent = indent[:-4]
            body.append(f"{indent}}}")

    consume = _consume_lines(ir, "data")
    declared = _declared_catches(ir)

    source = "\n".join([
        "// generated by harness-forge — do not edit",
        *imports,
        "",
        f"public final class {HARNESS_CLASS} {{",
        "    /** Read so the JIT cannot remove a call whose result is unused. */",
        "    public static volatile long hfSink = 0;",
        "",
        "    public static void fuzzerTestOneInput(FuzzedDataProvider data) {",
        *decls,
        *consume,
        "        try {",
        *[("    " + b) for b in body],
        *declared,
        "        } catch (RuntimeException | Error e) {",
        "            throw e;   // Jazzer classifies; the harness never swallows",
        "        } catch (Throwable t) {",
        "            // A checked exception nothing declared. Not rethrown: on the JVM,",
        "            // throwing is how an API says no.",
        "            return;",
        "        }",
        "    }",
        "}",
        "",
    ])

    driver = _driver(ir, consume, body, decls)

    cp = ":".join(ir.target.link_libs) if ir.target.link_libs else "."
    build = ["javac", "-cp", f"{cp}:$JAZZER_API", "-d", "classes",
             f"{HARNESS_CLASS}.java"]
    dbuild = ["javac", "-cp", cp, "-d", "classes", f"{REPLAY_CLASS}.java"]

    return Emitted(source=source, driver=driver, build_command=build,
                   driver_build_command=dbuild,
                   entry_symbols=sorted({op.api for op in ir.sequence}))


def _declared_catches(ir: HarnessIR) -> list:
    """Catch exactly the exceptions the called methods DECLARE, and nothing else.

    This is the plan doing something `jazzer --autofuzz` cannot, and it is measurable: run
    unmodified against a parser that declares `BadRecord` for empty input, Jazzer stops on
    the FIRST input and reports the library's own documented rejection as a crash. The
    campaign never starts. `javap` already told us which exceptions are the contract, so the
    harness catches precisely those.

    Only the EXACT declared types, never a supertype: catching `RuntimeException` because a
    method declares one subclass of it would swallow every real defect underneath, which is
    the opposite of the mistake being fixed.
    """
    seen: list = []
    for api in ir.apis.values():
        for exc in api.contract.declared_exceptions:
            # A binary name spells a nested class with `$`; Java source needs `.`.
            src_name = exc.replace("$", ".")
            if src_name and src_name not in seen:
                seen.append(src_name)
    out = []
    for i, exc in enumerate(seen):
        out.append(f"        }} catch ({exc} hfDeclared{i}) {{")
        out.append(f"            return;   // DECLARED by the target: its documented way of "
                   f"rejecting input, not a defect")
    return out


def _sink_of(ret: str, call: str) -> str:
    """Fold a return value into the sink so the call cannot be optimised away."""
    if ret in ("int", "short", "byte", "char", "long"):
        return f"(long)({call})"
    if ret in ("boolean",):
        return f"(({call}) ? 1L : 0L)"
    if ret in ("float", "double"):
        return f"(long)({call})"
    return f"java.util.Objects.hashCode({call})"


def _sink_cast(ret: str) -> str:
    return "0L"


def _catch_block() -> str:
    return ""


def _driver(ir: HarnessIR, consume: list, body: list, decls: list) -> str:
    """A standalone replay driver: one input, from a file, no Jazzer on the classpath.

    It reimplements the provider over a byte array rather than depending on Jazzer, because
    every gate that feeds a CHOSEN input has to run on a host where no fuzzer is installed —
    the same reason the C backend emits `driver.c` beside `harness.c`.
    """
    provider = _mini_provider()
    return "\n".join([
        "// generated by harness-forge — replay driver, no fuzzer runtime",
        f"public final class {REPLAY_CLASS} {{",
        "    public static volatile long hfSink = 0;",
        "",
        provider,
        "",
        "    public static void main(String[] argv) throws Exception {",
        "        if (argv.length < 1) { System.err.println(\"usage: Replay <input>\"); "
        "System.exit(2); }",
        "        byte[] raw;",
        "        try { raw = java.nio.file.Files.readAllBytes("
        "java.nio.file.Path.of(argv[0])); }",
        "        catch (java.io.IOException io) { System.err.println(\"cannot read input\"); "
        "System.exit(2); return; }",
        "        Data data = new Data(raw);",
        *decls,
        *consume,
        "        try {",
        *[("    " + b) for b in body],
        f"            System.out.println(\"{CLEAN_MARKER}\");",
        "        } catch (Throwable t) {",
        # The marker, not the exit status: on the JVM an uncaught exception exits 1 and so
        # does a missing file and a bad classpath. `classify_exit` cannot separate those, so
        # it is never asked to.
        f"            System.out.println(\"{FAULT_MARKER}\");",
        "            t.printStackTrace(System.out);",
        "        }",
        "        System.out.flush();",
        "        System.exit(0);",
        "    }",
        "}",
        "",
    ])


def _mini_provider() -> str:
    """Just enough of FuzzedDataProvider to replay one input deterministically.

    It must consume in the SAME ORDER and the same widths as Jazzer's, or a crashing input
    found by the campaign will not reproduce under the driver — and F1 would then report a
    0% reproduction rate for a real finding, which is the worst possible direction to be
    wrong in.

    It must also implement EVERY method the emitter can generate. It first shipped without
    `consumeChar`, so any plan with a `char` parameter produced a Replay.java that did not
    compile — and D2, D3, D6 and minimisation then reported NOT_RUN "the replay driver was
    not built", which reads as a toolchain problem rather than a hole in this class.
    """
    return "\n".join([
        "    static final class Data {",
        "        private final byte[] b; private int i = 0;",
        "        Data(byte[] b) { this.b = b; }",
        "        int remaining() { return b.length - i; }",
        "        byte consumeByte() { return i < b.length ? b[i++] : 0; }",
        "        boolean consumeBoolean() { return (consumeByte() & 1) != 0; }",
        "        short consumeShort() { return (short)((consumeByte() & 0xff) "
        "| ((consumeByte() & 0xff) << 8)); }",
        "        int consumeInt() { return (consumeShort() & 0xffff) "
        "| ((consumeShort() & 0xffff) << 16); }",
        "        long consumeLong() { return (consumeInt() & 0xffffffffL) "
        "| (((long)consumeInt()) << 32); }",
        "        char consumeChar() { return (char)consumeShort(); }",
        "        float consumeFloat() { return Float.intBitsToFloat(consumeInt()); }",
        "        double consumeDouble() { return Double.longBitsToDouble(consumeLong()); }",
        "        String consumeAsciiString(int n) { return new String(consumeBytes(n), "
        "java.nio.charset.StandardCharsets.US_ASCII); }",
        "        String consumeRemainingAsAsciiString() { return "
        "consumeAsciiString(remaining()); }",
        "        byte[] consumeBytes(int n) { int k = Math.min(n, remaining()); "
        "byte[] o = java.util.Arrays.copyOfRange(b, i, i + k); i += k; return o; }",
        "        byte[] consumeRemainingAsBytes() { return consumeBytes(remaining()); }",
        "        String consumeString(int n) { return new String(consumeBytes(n), "
        "java.nio.charset.StandardCharsets.UTF_8); }",
        "        String consumeRemainingAsString() { return consumeString(remaining()); }",
        "    }",
    ])
