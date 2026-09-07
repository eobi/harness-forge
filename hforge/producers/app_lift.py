"""Discover an application's entry points and the channel each takes its input through.

The producer half of B1. B1 gave the IR an AppEntry and the emitter a channel for each of the
shapes a CLI application exposes; this finds those shapes in a real codebase so the harness is
generated, not hand-written -- the same arc test-lift followed (IR + emitter first, producer
after).

Classification is by SIGNATURE, from the header's declarations, because that is what the
channel depends on:

    int main(int argc, char **argv)          -> argv     (bytes -> temp file -> argv slot)
    f(<byte*>, <size>)                        -> buffer   (bytes and length handed directly)
    f(const char *path-named)                 -> file_arg (bytes -> temp file, path passed)
    f(const char *content-named or unknown)   -> cstring  (NUL-terminated content in memory)

The lone-`const char *` case is the only ambiguous one -- a path or the content itself -- and
the parameter name decides it: `path`/`file`/`filename` means a path, anything else means
content. Getting it wrong yields a harness that runs and tests the wrong thing, so the choice
travels on the record and a caller can override it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..ir import (APP_ARGV, APP_BUFFER, APP_CSTRING, APP_FILE_ARG, AppEntry,
                  HarnessIR, Knobs, Target)
from .header_graph import parse_header

PRODUCER = "app_lift"

_BYTE_PTR = re.compile(r"\b(?:const\s+)?(?:unsigned\s+char|char|void|uint8_t|int8_t)\s*\*")
_SIZEISH = re.compile(r"\b(?:size_t|unsigned\s+long|unsigned\s+int|unsigned|int|long|"
                      r"ssize_t|uint\d+_t)\b")
_PATH_NAME = re.compile(r"(path|file|filename|fname|filepath|fpath)", re.I)
# A name that says "this is the content to parse", not a path.
_CONTENT_NAME = re.compile(r"(data|input|buf|buffer|str|string|text|src|json|xml|content|"
                           r"msg|payload|s)$", re.I)
# Entry points worth ranking to the top: they consume attacker input.
_PARSEISH = re.compile(r"(?:^|_)(main|parse|read|load|decode|decompress|uncompress|inflate|"
                       r"scan|deserial|process|handle|from_|ingest|import)", re.I)
# Config / dictionary / lifecycle helpers that also take a (buffer,len) -- ZSTD_CCtx_loadDictionary,
# LZ4_loadDict, *_setParameter. They consume attacker bytes but are not the format's DECODER; rank
# them below a real decode entry so the default harness drives the decompressor, not dict-loading.
_NOT_PRIMARY = re.compile(r"(dict|set_?param|_using|_reset|_create|_alloc|_free|_ctx)", re.I)
# A pointer whose pointee is an OPAQUE handle typedef (ZSTD_DCtx, XML_Parser, a *Stream/*Context):
# it has no complete definition in the header, so a local of that type will not compile and there
# is nothing valid to point it at. An entry that needs one is left to test-lift, not emitted.
_OPAQUE_HANDLE = re.compile(
    r"(Ctx|Context|Handle|Stream|Dict|State|Session|Parser|Reader|Writer|Decoder|Encoder)$")
# A shallow query: reads a header and answers a question, never entering the decode body.
_QUERY = re.compile(r"(?:^|_)(info|is_|is[A-Z]|get_?(?:size|width|height|len|info|count|"
                    r"dimensions|num)|test|check|valid|probe|detect|sniff|peek)", re.I)

# A by-value scalar that selects BEHAVIOUR -- a parse flag, decode mode, quality/level. Worth
# fuzzing from input bytes instead of defaulting to 0, because it gates real code (jansson's
# json_loads `flags`, a decoder's `mode`). Deliberately tight: NOT a size/count/index, which
# controls allocation or iteration and would hang or over-read if driven to a large value.
_FLAG_NAME = re.compile(r"(?:^|_)(flag|flags|mode|option|options|opt|quality|level|"
                        r"colou?rspace|policy|style|kind|variant)s?$", re.I)
_SIZE_NAME = re.compile(r"(?:^|_)(size|len|length|count|num|n|cap|capacity|width|height|"
                        r"stride|offset|index|idx|nmemb|bytes)s?$", re.I)


def _fuzz_scalar_arg(ty: str, j: int) -> str:
    """A behaviour scalar read from an input byte (0..255), safe on short inputs."""
    return f"({ty.strip()})(hf_size ? hf_data[{j} %% hf_size] : 0)".replace("%%", "%")


def _is_byte_ptr(ty: str) -> bool:
    return bool(_BYTE_PTR.search(ty)) and ty.count("*") == 1


# A by-value parameter we can safely default to 0: an integer/float/enum/bool scalar. NOT a
# struct or an opaque handle typedef (XML_Parser, yaml_parser_t used by value) -- defaulting
# one of those to 0 hands the target a NULL handle and the harness crashes on the first line
# for a reason that is the harness's fault, not the target's.
_SCALAR = re.compile(r"^\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
                     r"(?:void|int|char|short|long|float|double|size_t|ssize_t|"
                     r"unsigned|signed|_Bool|bool|enum\b.*|uint\d+_t|int\d+_t|off_t|"
                     r"ptrdiff_t|wchar_t)\s*$")


def _is_scalar(ty: str) -> bool:
    return ty.count("*") == 0 and bool(_SCALAR.match(ty.strip()))


def _looks_buffer(ty: str, nm: str) -> bool:
    """A single-level pointer that carries INPUT bytes: const-qualified, or content-named.

    Broader than _is_byte_ptr on purpose -- the real loaders take `stbi_uc const *`,
    `yaml_char_t *`, `png_bytep`, not the literal `const unsigned char *`. Any one-level
    pointer that is const (input, not an out-param) or named data/buf/input is a byte source;
    requiring const keeps an out-pointer+count pair (int *out, int n) from being read as input.
    """
    if ty.count("*") != 1:
        return False
    is_const = "const" in ty
    return is_const or bool(_CONTENT_NAME.search((nm or "").strip()))


# A parameter that carries a LENGTH even when its type is a library typedef the generator does
# not expand (zlib's uLong sourceLen, a codec's mySize_t n): recognised by a sizeish type OR a
# length-hinting name. Name-matching is looser than _SIZE_NAME (no _-boundary) on purpose --
# camelCase `sourceLen`/`destLen` carry no underscore -- but it is only ever consulted for the
# arg that immediately follows a byte pointer, so a stray "linено"-style name cannot trip it.
_LEN_HINT = re.compile(r"(?i)(len|size|count|bytes|nmemb|nbyte|amount|avail)")


def _looks_len(ty: str, nm: str) -> bool:
    return ty.count("*") == 0 and (bool(_SIZEISH.search(ty)) or bool(_LEN_HINT.search(nm or "")))


def _buffer_pair(params: list):
    """Index of the (buffer, len) pair: first const/content pointer with a length next arg."""
    for i in range(len(params) - 1):
        pty, pnm = params[i]
        nty, nnm = params[i + 1]
        if _looks_buffer(pty, pnm) and _looks_len(nty, nnm):
            return i
    return -1


def _out_scratch(params: list, buf_i: int, len_i: int) -> dict:
    """Map {out_buffer_index: length_index or None} for the DECOMPRESSOR idiom.

    f(out_buf, *out_len, const in_buf, in_len) -- zlib uncompress, and the same shape in zstd,
    lz4, brotli -- writes the decoded bytes into a caller-provided buffer. A single-level
    writable byte pointer (not the input, not const) is such an output; its capacity is the
    adjacent length argument (a *out_len the callee updates, or a scalar we set). Handing the
    callee a real scratch buffer + its true capacity fuzzes the DECODER instead of overflowing a
    one-byte local, which is why the entry would otherwise be refused as unsafe.
    """
    out: dict = {}
    for j, (ty, nm) in enumerate(params):
        if j in (buf_i, len_i):
            continue
        if ty.count("*") == 1 and "const" not in ty and \
                any(t in ty for t in ("char", "uint8", "int8", "Byte", "void")):
            li = None
            for k in (j + 1, j - 1):
                if 0 <= k < len(params) and k not in (buf_i, len_i) and k not in out:
                    kty, knm = params[k]
                    if kty.count("*") == 0 and _looks_len(kty, knm):
                        li = k
                        break                                 # scalar capacity
                    if kty.count("*") == 1 and (_SIZEISH.search(kty) or
                                                _LEN_HINT.search(knm or "")):
                        li = k
                        break                                 # *out_len the callee updates
            out[j] = li
    return out


def _pointee(ty: str) -> str:
    """Drop one level of pointer and any trailing const, for declaring an out-local."""
    t = ty.strip()
    star = t.rfind("*")
    if star < 0:
        return t
    base = (t[:star] + t[star + 1:]).replace("const", " ").strip()
    return re.sub(r"\s+", " ", base) or "int"


def _buffer_plan(params: list, buf_i: int, len_i: int):
    """(call_args, call_locals) filling every declared parameter of a deep buffer entry.

    The (buf,len) pair carries the fuzzer bytes; every other pointer becomes a zeroed local
    passed by address (an out-parameter the target writes), every scalar a 0. Returns
    (None, None) when a parameter cannot be filled safely -- a by-value struct/handle -- so
    the entry is left to test-lift rather than emitted wrong.
    """
    args: list = []
    locals_: list = []
    # Only an out-buffer whose CAPACITY we located is safe to back with a real scratch area;
    # a length-less output stays an ordinary (flagged-unsafe) out-param, never a sized buffer.
    scratch = {j for j, li in _out_scratch(params, buf_i, len_i).items() if li is not None}
    scratch_lens = {li for li in _out_scratch(params, buf_i, len_i).values() if li is not None}
    _CAP = 1 << 16                                    # 64 KiB scratch decode target
    for j, (ty, nm) in enumerate(params):
        if j == buf_i:
            args.append(f"({ty.strip()})hf_data")
        elif j == len_i:
            args.append(f"({ty.strip()})hf_size")
        elif j in scratch:
            # caller-provided output buffer: a real fixed scratch area, not a 1-byte local
            locals_.append(f"static unsigned char hf_out{j}[{_CAP}];")
            args.append(f"({ty.strip()})hf_out{j}")
        elif j in scratch_lens:
            # capacity of a scratch output buffer: the true size, in the callee's units
            if ty.count("*") >= 1:
                pt = _pointee(ty)
                locals_.append(f"{pt} hf_len{j} = {_CAP};")
                args.append(f"&hf_len{j}")
            else:
                args.append(f"({ty.strip()}){_CAP}")
        elif ty.count("*") >= 1:
            # out-parameter: a local of the pointed-to type, passed by address
            pt = _pointee(ty)
            if pt == "void":
                args.append("0")            # void* out: NULL, nothing to point at
                continue
            if _OPAQUE_HANDLE.search(pt):
                return None, None           # opaque handle: no complete type to declare
            ln = f"hf_a{j}"
            locals_.append(f"{pt} {ln} = {{0}};")
            args.append(f"&{ln}")
        elif _is_scalar(ty):
            if _FLAG_NAME.search(nm or "") and not _SIZE_NAME.search(nm or ""):
                args.append(_fuzz_scalar_arg(ty, j))   # a behaviour flag: fuzz it
            else:
                args.append("0")
        else:
            return None, None               # by-value struct/handle: cannot fill safely
    return args, locals_


# Win32 APIs a header forward-declares under _WIN32 to avoid pulling in windows.h. They
# survive preprocessing as decls "in" the header, and their (LPCSTR, int) pair reads as a
# (buffer,len) entry -- but they belong to the OS, not the target, so harnessing one fuzzes
# Windows, not the library. Discovered only when the generator runs ON Windows.
_OS_IMPORTS = frozenset({
    "MultiByteToWideChar", "WideCharToMultiByte", "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile", "GetTempFileNameA", "GetTempPathA", "DeleteFileA",
})


def _cstring_plan(params: list):
    """(call_args, call_locals) for a f(char *content, config...) parser, or (None, None).

    The content (param 0) is the NUL-terminated copy the emitter builds; every later argument
    is filled safely or the whole entry is refused."""
    args = ["(%s)hf_cstr" % params[0][0].strip()]
    locs: list = []
    for j in range(1, len(params)):
        ty, _nm = params[j]
        if ty.count("*") == 0 and _SCALAR.match(ty.strip()):
            if _FLAG_NAME.search(_nm or "") and not _SIZE_NAME.search(_nm or ""):
                args.append(_fuzz_scalar_arg(ty, j))
            else:
                args.append("0")
        elif "char" in ty and ty.count("*") == 1 and "const" in ty:
            args.append('""')                          # config string: empty, never NULL
        elif ty.count("*") >= 1 and "char" not in ty and "void" not in ty:
            pt = _pointee(ty)
            locs.append(f"{pt} hf_a{j} = {{0}};")
            args.append(f"&hf_a{j}")
        else:
            return None, None                          # writable char*/void* out: unsafe
    return args, locs


def classify(decl) -> Optional[dict]:
    """Return a candidate {channel, symbol, argv?, param, ...} for a declaration, or None."""
    params = list(getattr(decl, "params", []) or [])
    name = decl.name
    # A double-underscore anywhere is the near-universal C convention for a PRIVATE internal
    # (stbi__hdr_to_ldr, png__...): not a public entry point, and not what an application
    # drives. An OS import forward-declared under _WIN32 is not the target's either.
    if "__" in name or name in _OS_IMPORTS:
        return None
    # main(int, char**)
    if len(params) == 2 and re.match(r"\bint\b", params[0][0].strip()) \
            and params[1][0].count("*") == 2 and "char" in params[1][0]:
        return {"channel": APP_ARGV, "symbol": name,
                "argv": [name.replace("_main", "") or "app", "@INPUT@"]}
    # f(buffer, len, ...) -- a real loader: the (buf,len) pair anywhere, trailing out-locals.
    bi = _buffer_pair(params)
    if bi >= 0:
        call_args, call_locals = _buffer_plan(params, bi, bi + 1)
        if call_args is not None:
            # DEPTH: a full decoder writes several out-parameters and returns a buffer of
            # decoded data; a query (info/is_/get_size) reads a header and returns a flag.
            # Prefer the decoder so the DEFAULT entry drives the whole format body.
            returns_ptr = "*" in getattr(decl, "ret", "")
            is_query = bool(_QUERY.search(name))
            depth = len(call_locals) + (1 if returns_ptr else 0)
            # A WRITABLE BYTE-POINTER output (the *DecodeInto family: the caller passes the
            # pixel buffer) cannot be folded safely -- we would hand the decoder a 1-byte
            # local and it writes a whole image. Mark it so composition can exclude it.
            # Only a SINGLE-level writable byte pointer is a caller-provided output buffer
            # (WebPDecodeRGBAInto's `output_buffer`). A DOUBLE pointer (uint8_t** u in
            # WebPDecodeYUV) is an out-parameter the decoder ALLOCATES -- safe to fill with a
            # local pointer by address -- so it must not disqualify the entry.
            # A writable byte output we CAN size (a scratch buffer + its capacity) is handled by
            # _buffer_plan; only an UNHANDLED writable byte/void output (no length to bound it,
            # or a void* of unknown element size) is still unsafe to fold or drive.
            scratch = _out_scratch(params, bi, bi + 1)
            handled = {j for j, li in scratch.items() if li is not None}
            has_out_buffer = any(
                j not in (bi, bi + 1) and j not in handled and pty.count("*") == 1
                and "const" not in pty
                and any(t in pty for t in ("char", "uint8", "int8", "void"))
                for j, (pty, _pn) in enumerate(params))
            return {"channel": APP_BUFFER, "symbol": name, "param": params[bi][1],
                    "call_args": call_args, "call_locals": call_locals,
                    "arity": len(params), "depth": depth, "is_query": is_query,
                    "returns_ptr": returns_ptr, "has_out_buffer": has_out_buffer,
                    "out_scratch": bool(handled)}
    # f(const char *) -- lone char pointer: path or content
    if len(params) == 1 and _is_byte_ptr(params[0][0]) and "char" in params[0][0]:
        pn = params[0][1] or ""
        if _PATH_NAME.search(pn):
            return {"channel": APP_FILE_ARG, "symbol": name, "param": pn}
        return {"channel": APP_CSTRING, "symbol": name, "param": pn}
    # f(char *content, config...) -- a NUL-terminated parser with configuration arguments,
    # e.g. nsvgParse(char *input, const char *units, float dpi). The content is the first
    # parameter (a parser's primary input leads); the rest must be safely defaultable -- a
    # scalar to 0, a const char* config to "" (NOT NULL: the target may strcmp it), a non-char
    # out-pointer to a local. A writable char* or void* after the content is an output buffer
    # we cannot size, so the whole entry is refused rather than risk a harness-made overflow.
    if len(params) >= 2 and params[0][0].count("*") == 1 and "char" in params[0][0] \
            and (_CONTENT_NAME.search(params[0][1] or "") or "const" not in params[0][0]):
        args, locs = _cstring_plan(params)
        if args is not None:
            return {"channel": APP_CSTRING, "symbol": name, "param": params[0][1],
                    "call_args": args, "call_locals": locs, "arity": len(params),
                    "depth": len(locs), "is_query": bool(_QUERY.search(name))}
    return None


def _is_encoder(sym: str) -> bool:
    """An ENCODE/compress entry, which consumes raw bytes and emits a format -- the opposite of
    the attack surface. `uncompress`/`decompress`/`inflate`/`decode` are decoders despite sharing
    the substring, so they are excluded explicitly."""
    s = sym.lower()
    if any(d in s for d in ("uncompress", "decompress", "inflate", "decode", "unpack")):
        return False
    return bool(re.search(r"(compress|deflate|encode|(?:^|_)(?:write|save|dump|serial|mux))", s))


def _rank(c: dict) -> tuple:
    # An encoder (compress/deflate/encode) takes raw bytes and PRODUCES a format -- it is not the
    # attack surface a fuzzer wants; rank every decoder ahead of it so uncompress beats compress.
    is_encode = 1 if _is_encoder(c["symbol"]) else 0
    # A dictionary/config/lifecycle helper ranks below a real decode entry (see _NOT_PRIMARY).
    not_primary = 1 if _NOT_PRIMARY.search(c["symbol"]) else 0
    # Parse-like names first; among those main() last (argv is the heaviest channel), so a
    # direct parse function is preferred over driving the whole CLI when both exist.
    parseish = 0 if _PARSEISH.search(c["symbol"]) else 1
    # A query (stbi_info, stbi_is_hdr) reads the header and stops; a decoder runs the whole
    # format body. Rank queries after real decoders, and deeper decoders (more out-params, a
    # returned buffer) ahead of shallow ones, so the DEFAULT entry is the deepest available.
    is_query = 1 if c.get("is_query") else 0
    depth = -int(c.get("depth", 0))
    is_main = 1 if c["channel"] == APP_ARGV else 0
    # buffer/cstring (no file I/O) are the most direct, then file_arg, then argv.
    directness = {APP_BUFFER: 0, APP_CSTRING: 0, APP_FILE_ARG: 1, APP_ARGV: 2}[c["channel"]]
    return (is_encode, not_primary, parseish, is_query, is_main, directness, depth, c["symbol"])


def discover(headers: list, includes: tuple = ()) -> list:
    """Ranked AppEntry candidates from a library/application's headers."""
    seen, cands = set(), []
    for h in headers:
        if not Path(h).exists():
            continue
        try:
            decls = parse_header(h, tuple(includes), ())
        except Exception:                                          # noqa: BLE001
            continue
        for d in decls:
            if d.name in seen:
                continue
            c = classify(d)
            if c is None:
                continue
            seen.add(d.name)
            c["header"] = Path(h).name
            cands.append(c)
    cands.sort(key=_rank)
    return cands


def propose(headers: list, target: Target, includes: tuple = (),
            only: str = "") -> tuple:
    """(HarnessIR or None, record). `only` names one symbol to lift; else the top candidate."""
    cands = discover(headers, includes)
    rec = {"producer": PRODUCER, "candidates": [(c["symbol"], c["channel"]) for c in cands]}
    if only:
        cands = [c for c in cands if c["symbol"] == only]
    if not cands:
        rec["why_not"] = ("no application entry point found: no main(argc,argv), no "
                          "(buffer,size) function, no lone char* parser in the header(s)")
        return None, rec
    c = cands[0]
    ae = AppEntry(symbol=c["symbol"], channel=c["channel"], header=c.get("header", ""),
                  argv=c.get("argv", []),
                  call_args=c.get("call_args", []), call_locals=c.get("call_locals", []))
    rec["chosen"] = {"symbol": c["symbol"], "channel": c["channel"],
                     "param": c.get("param")}
    plan = HarnessIR(name=f"{target.name}_{c['symbol']}"[:60], target=target,
                     app_entry=ae, knobs=Knobs(),
                     platforms=list(target.__dict__.get("platforms", []))
                     or ["linux-x86_64-glibc"],
                     producer=PRODUCER)
    return plan, rec


# Encode/serialise names never belong in a DECODE fold -- they consume a decoded object, not
# the fuzzer's bytes, and would add nothing an attacker controls.
_ENCODE = re.compile(r"(encode|write|save|dump|serial|compress|mux)", re.I)
# A DIFFERENT codec subsystem than the format's own decode -- generic compression/entropy
# helpers (stb ships stbi_zlib_decode_*). Folding them adds a second decoder with different
# input semantics (and stb's guesssize variant hangs on a 0 size hint), so keep the fold to
# the FORMAT decode family.
_AUX_CODEC = re.compile(r"(zlib|inflate|deflate|lzw|huffman|base64|unzip|gunzip)", re.I)


def _find_free(decls: dict) -> str:
    """A one-argument deallocator for RETURNED BUFFERS. Prefer one taking void* (frees a
    malloc'd block, e.g. WebPFree) over a struct-specific destructor (WebPFreeDecBuffer)."""
    generic, other = "", ""
    for name, d in decls.items():
        params = list(getattr(d, "params", []) or [])
        if len(params) == 1 and params[0][0].count("*") >= 1 \
                and re.search(r"(?:^|_|[a-z])(free|delete|release|destroy)", name, re.I):
            if "void" in params[0][0] and params[0][0].count("*") == 1:
                if not generic or len(name) < len(generic):
                    generic = name
            elif not other:
                other = name
    return generic or other


def compose_app(headers: list, target, includes: tuple = (), max_fold: int = 16):
    """Fold a codec header's DECODE FAMILY -- every safe (buffer,size) decoder -- onto one
    input, the shape that reaches the union of their coverage. Returns (HarnessIR, record).

    A media decoder exposes RGBA / BGRA / YUV / info / advanced-with-options / incremental
    entries that all take the same bytes; a single developer fuzzer usually drives one.
    Excludes encoders and the *Into family (writable output buffers we cannot size).
    """
    from .header_graph import parse_header                          # noqa: PLC0415
    # Parse the given headers AND their siblings: a decoder's deallocator (WebPFree) and its
    # complete-struct definitions often live in a neighbouring header (webp/types.h).
    hdr_paths = list(headers)
    for h in headers:
        d = Path(h).parent
        if d.exists():
            hdr_paths += [str(p) for p in d.glob("*.h") if str(p) not in hdr_paths]
    decls: dict = {}
    complete: set = set()
    for h in hdr_paths:
        if Path(h).exists():
            for d in parse_header(h, tuple(includes), ()):
                decls.setdefault(d.name, d)
                complete |= set(getattr(d, "complete", ()) or ())

    def _local_ok(local: str) -> bool:
        # `TYPE hf_aN = {0};` -- safe when TYPE is a builtin/scalar, a pointer, or a struct
        # whose body we parsed (complete). An OPAQUE struct (WebPIDecoder) is not: a stack
        # local of an incomplete type does not compile, so its entry cannot be folded.
        ty = local.split("hf_a")[0].strip()
        if "*" in ty or _SCALAR.match(ty + " "):
            return True
        base = ty.replace("const", "").replace("struct", "").strip()
        return base in complete or base in ("", "int", "float", "double")

    cands = discover(headers, includes)
    fam, seen = [], set()
    for c in cands:
        if not (c["channel"] == APP_BUFFER and c.get("call_args")
                and not c.get("has_out_buffer") and not c.get("out_scratch")
                and not _ENCODE.search(c["symbol"])
                and c["symbol"] not in seen):
            continue
        if "Internal" in c["symbol"] or "__" in c["symbol"] or _AUX_CODEC.search(c["symbol"]):
            continue
        if not all(_local_ok(l) for l in c.get("call_locals", [])):
            continue                                     # opaque out-local: cannot stack-alloc
        seen.add(c["symbol"]); fam.append(c)
        if len(fam) >= max_fold:
            break
    rec = {"producer": PRODUCER, "family": [c["symbol"] for c in fam]}
    if len(fam) < 2:
        rec["why_not"] = "fewer than two safe (buffer,size) decoders to compose"
        return None, rec
    free = _find_free(decls)

    structs = _all_structs(hdr_paths)

    def mk(c) -> AppEntry:
        rp = c.get("returns_ptr", False)
        e = AppEntry(symbol=c["symbol"], channel=APP_BUFFER, header=c.get("header", ""),
                     call_args=c["call_args"], call_locals=c["call_locals"],
                     returns_ptr=rp, returns_int=not rp)
        # OPTION FUZZING: if this entry passes a config struct out-local that has an
        # initialiser and pointer-free scalar options, set those from input bytes so the
        # crop/scale/flip/dither code runs -- the coverage a developer's option-fuzzer reaches.
        for loc in c.get("call_locals", []):
            m = re.match(r"^([A-Za-z_][\w ]*?)\s+(hf_a\d+)\s*=", loc)
            if not m:
                continue
            sty = m.group(1).strip()
            fields, _safe = _struct_fuzz_fields(sty, structs)
            init = _find_init(sty, decls)
            if fields:
                e.config_local, e.config_init, e.config_fields = m.group(2), init, fields
                break
        return e

    primary = mk(fam[0])
    primary.header = ""   # emitter spells the include from target.public_headers below
    # The composed harness must #include the target header; ensure it is on the target so the
    # emitter spells it relative to the include dirs (stb_image.h, webp/decode.h), not omit it.
    try:
        have = set(getattr(target, "public_headers", []) or [])
        target.public_headers = list(getattr(target, "public_headers", []) or []) + \
            [h for h in headers if h not in have]
    except (AttributeError, TypeError):
        pass
    primary.free_symbol = free
    primary.fold = [mk(c) for c in fam[1:]]
    from ..ir import HarnessIR, Knobs                               # noqa: PLC0415
    plan = HarnessIR(name=f"{target.name}_codec_compose"[:60], target=target,
                     app_entry=primary, knobs=Knobs(),
                     platforms=list(getattr(target, "platforms", [])) or ["linux-x86_64-glibc"],
                     producer=PRODUCER)
    rec["chosen"] = {"primary": primary.symbol, "folded": len(primary.fold),
                     "free_symbol": free}
    return plan, rec


_STRUCT_SCALAR = re.compile(r"^(?:const\s+)?(?:unsigned\s+|signed\s+)?"
                            r"(?:int|char|short|long|float|double|size_t|uint\d+_t|int\d+_t|"
                            r"_Bool|bool)$")


def _all_structs(sources: list) -> dict:
    """{struct name -> [(ctype, field, is_ptr, is_array)]} parsed from header text.

    Handles both `typedef struct [tag] {..} NAME;` and `struct NAME {..};`, and comma-lists
    (`int crop_left, crop_top;`). Structs whose body contains a nested brace (union/anon) are
    skipped -- they cannot be fuzzed field-by-field safely and the regex would misparse them.
    """
    structs: dict = {}
    for src in sources:
        try:
            text = Path(src).read_text(errors="replace")
        except OSError:
            continue
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//.*", "", text)
        for pi, pat in ((0, r"typedef\s+struct\s*(?:\w+\s*)?\{([^{}]*?)\}\s*(\w+)\s*;"),
                        (1, r"struct\s+(\w+)\s*\{([^{}]*?)\}\s*;")):
            for m in re.finditer(pat, text, re.S):
                body, name = (m.group(1), m.group(2)) if pi == 0 else (m.group(2), m.group(1))
                fields = []
                for decl in body.split(";"):
                    decl = " ".join(decl.split())
                    mm = re.match(r"^((?:const |unsigned |signed |struct )*[A-Za-z_]\w*) (.+)$", decl)
                    if not mm:
                        continue
                    ctype = mm.group(1).replace("struct", "").strip()
                    for nm in mm.group(2).split(","):
                        clean = re.sub(r"[*\[\]0-9\s]", "", nm)
                        if clean:
                            fields.append((ctype, clean, "*" in nm, "[" in nm))
                structs.setdefault(name, fields)
    return structs


def _struct_fuzz_fields(typ: str, structs: dict, depth: int = 0):
    """(fields, safe): scalar fields as (dotted-path, ctype); safe=False if any pointer/union.

    Recurses into pointer-free sub-structs (config.options.flip) and skips any sub-struct that
    contains a pointer (config.output, which holds the pixel buffer), so setting the returned
    fields can never corrupt a buffer pointer."""
    if depth > 4 or typ not in structs:
        return ([], False)
    out, safe = [], True
    for ctype, fname, is_ptr, is_arr in structs[typ]:
        if is_ptr:
            safe = False                     # a pointer we might corrupt -> struct is unsafe
            continue
        if is_arr:
            continue                         # a padding/array field: skip it, still safe
        if ctype in structs:
            sub, sub_safe = _struct_fuzz_fields(ctype, structs, depth + 1)
            if sub_safe:
                out += [(fname + "." + p, t) for p, t in sub]
            else:
                safe = False
        elif _STRUCT_SCALAR.match(ctype):
            out.append((fname, ctype))
        else:
            safe = False
    return (out, safe)


def _find_init(struct_type: str, decls: dict) -> str:
    """An initialiser f(StructType*) named *Init*, required before a config is used."""
    for name, d in decls.items():
        if "Init" not in name:
            continue
        params = list(getattr(d, "params", []) or [])
        if len(params) == 1 and struct_type in params[0][0] and "*" in params[0][0]:
            return name
    return ""
