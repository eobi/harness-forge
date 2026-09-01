"""Producer: synthesise plans from a header and a call graph. No model involved.

This is the deterministic producer, and it exists to prove the architecture before any LLM
touches it: a producer proposes **IR**, never C, and the gates decide which proposal is
worth anything. If a header-parsing regex can produce certifiable plans, then the model's
job in Phase 3 is diversity and reach, not correctness — which is exactly where a model
should sit.

Three steps:

  1. parse function declarations out of the public headers
  2. infer each one's ROLE and CONTRACT from its signature
  3. traverse the resulting API graph and emit one candidate plan per consuming entry point

Step 2 is where the value is and where the honesty has to be. The inferences below are
heuristics with names, and every one of them is checked afterwards by a static gate: a
mis-inferred `nul_terminated` produces a plan that S2 either passes or blocks. The producer
is allowed to be wrong. It is not allowed to certify itself.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

from ..ir import (
    SCRATCH_BYTES, SCRATCH_PTR, SCRATCH_SIZE, Scratch,
    Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Resource, Target,
    TypeRef, ROLE_CREATE, ROLE_CONSUME, ROLE_DESTROY, ROLE_QUERY,
    SLICE_BYTES, SLICE_CSTRING, SLICE_U8,
)

# Real headers do not look like tutorial headers. Three shapes broke the first parser, and
# all three are the norm rather than the exception:
#
#   magic.h     const char *magic_buffer(magic_t, const void *, size_t);
#               ^ parameters with NO NAMES, and `magic_t` is `typedef struct magic_set *`,
#                 so a textual `"*" in ret` test does not see that it is a pointer
#   yaml.h      YAML_DECLARE(int)
#               yaml_parser_initialize(yaml_parser_t *parser);
#               ^ a MACRO-WRAPPED return type, on a different line from the name
#   libxml2     XMLPUBFUN xmlDocPtr XMLCALL
#                       xmlReadMemory (const char *buffer, int size, ...);
#               ^ export and calling-convention macros, and multi-line parameters
#
# A line-anchored regex sees none of them. So the scanner below normalises the header into
# statements first and then reads each statement whole, which is what a header actually is.
_QUALS = r"(?:(?:const|volatile|unsigned|signed|struct|enum|union|static|extern|inline)\s+)*"

# Bare macro tokens that decorate a declaration and carry no type information.
_TYPE_WORDS = {"const", "volatile", "unsigned", "signed", "struct", "enum", "union",
               "static", "extern", "inline", "void", "char", "short", "int", "long",
               "float", "double", "_Bool", "size_t", "ssize_t", "wchar_t", "FILE"}

_NOISE_MACRO = re.compile(
    r"\b(?:__extension__|__cdecl|__stdcall|__fastcall|__restrict\w*|__inline\w*|"
    r"_Noreturn|__nonnull|__THROW|__wur|__nothrow\w*)\b")


def _strip_balanced(src: str, opener: str) -> str:
    """Remove `opener(...)` including nested parentheses. Used for `__attribute__((...))`
    and `__declspec(...)`, which a non-nesting regex cannot delete correctly."""
    out, i = [], 0
    while True:
        j = src.find(opener, i)
        if j < 0:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i:j])
        k = src.find("(", j + len(opener))
        if k < 0:
            return "".join(out) + src[j:]
        depth, m = 0, k
        while m < len(src):
            if src[m] == "(":
                depth += 1
            elif src[m] == ")":
                depth -= 1
                if depth == 0:
                    break
            m += 1
        i = m + 1


def _statements(src: str) -> list:
    """The header as a list of declaration statements, whitespace collapsed.

    Splitting on `;` at paren/brace depth zero is what makes multi-line declarations work:
    a declaration is a statement, and a statement does not care where the newlines were.
    """
    # A preprocessor directive continues across newlines whenever the line ends in a
    # backslash. Stripping only the first line leaks the rest of a multi-line #define into
    # the statement stream, and the leaked text carries unbalanced parens and braces. In
    # yaml.h that pushed the depth counter permanently above zero, so no `;` ever split a
    # statement again and a 54KB header parsed to NOTHING while reporting no error.
    src = re.sub(r"^[ \t]*#(?:[^\n\\]|\\.|\\\r?\n)*", " ", src, flags=re.M)
    src = _strip_balanced(src, "__attribute__")
    src = _strip_balanced(src, "__declspec")
    src = _NOISE_MACRO.sub(" ", src)
    # `extern "C" {` wraps the whole public API of most C headers, and its brace must go or
    # every declaration sits at depth 1 and nothing ever splits on `;`. The quotes may
    # already have been blanked by strip_noise, which removes string literals — so the
    # string part is optional here. Matching only the literal `extern "C" {` form meant a
    # 5.9KB header parsed as ONE statement and a 54KB header as none at all.
    src = re.sub(r'\bextern\b\s*(?:"[^"]*")?\s*\{', " ", src)

    out, depth, cur = [], 0, []
    for ch in src:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)     # never let a stray closer strand the whole file
        if ch == ";" and depth == 0:
            out.append(" ".join("".join(cur).split()))
            cur = []
        else:
            cur.append(ch)
    return [s for s in out if s]


_TRAILING_ATTR = re.compile(
    r"^(?P<decl>.*\))\s*(?:__attribute__|__declspec|[A-Z][A-Z0-9_]{2,})\s*\(.*\)$",
    re.S)


def _strip_trailing_attribute(stmt: str) -> str:
    """Remove an attribute macro that follows the parameter list.

        json_t *json_loadb(const char *buf, size_t n, size_t flags, json_error_t *error)
            JANSSON_ATTRS((warn_unused_result));

    Scanning backwards for the parameter list finds JANSSON_ATTRS's parentheses instead,
    so the declaration parsed with name='JANSSON_ATTRS' and json_loadb was never seen —
    which is why jansson produced no plan for its own entry point. `__attribute__((...))`,
    `WARN_UNUSED_RESULT` and every project's own spelling have this shape.

    The guard is that the text BEFORE the suffix must itself end in `)`. That is what keeps
    `BZ_EXTERN int BZ_API(BZ2_bzCompressInit)(bz_stream *strm)` intact, where the macro
    wraps the NAME and the real parameter list is genuinely last.
    """
    for _ in range(4):                            # a declaration may carry several
        m = _TRAILING_ATTR.match(stmt.strip())
        if not m:
            break
        stmt = m.group("decl")
    return stmt


def _split_call(stmt: str):
    """Split `<return type> <name> ( <params> )` by finding the parameter list from the END.

    Scanning backwards matters: a parameter may itself be a function pointer, so the first
    `(` in the statement is often not the one that opens the parameter list.
    """
    stmt = _strip_trailing_attribute(stmt.strip())
    if not stmt.endswith(")"):
        return None
    depth, i = 0, len(stmt) - 1
    while i >= 0:
        if stmt[i] == ")":
            depth += 1
        elif stmt[i] == "(":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    if i <= 0:
        return None
    head, params = stmt[:i].strip(), stmt[i + 1:-1]
    m = re.search(r"([A-Za-z_]\w*)\s*$", head)
    if m:
        return head[:m.start(1)].strip(), m.group(1), params
    # The head ends in `)`, so there is no trailing identifier. Two different shapes look
    # like this and they must not be confused:
    #
    #   BZ_EXTERN int BZ_API(BZ2_bzCompressInit)(bz_stream *strm)
    #                        ^ a MACRO wrapping the name; discard it
    #   extern png_structp (png_create_read_struct)(png_const_charp ver)
    #          ^^^^^^^^^^^ the RETURN TYPE, with the name merely parenthesised; keep it
    #
    # Treating both as macros ate png's return type and left every declaration returning
    # `extern`, so no handle could be inferred from 245 parsed declarations.
    m = re.search(r"([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*$", head)
    if m:
        lead = m.group(1)
        is_macro = lead.isupper() and len(lead) > 2
        return head[:m.start(1) if is_macro else m.end(1)].strip(), m.group(2), params
    return None


def _clean_return(ret: str) -> str:
    """Reduce a decorated return type to the type itself.

    `YAML_DECLARE(int)` -> `int`      a macro that WRAPS the type
    `XMLPUBFUN xmlDocPtr XMLCALL` -> `xmlDocPtr`   macros that DECORATE it
    """
    m = re.match(r"^\s*[A-Z][A-Z0-9_]*\s*\(([^()]*)\)\s*(.*)$", ret)
    if m:
        ret = f"{m.group(1)} {m.group(2)}"
    # Storage-class and linkage specifiers are not part of the type. Leaving `extern` in
    # made the handle print as `extern gzFile` and would have emitted
    # `extern gzFile hf_r_h = NULL;` into the harness.
    ret = re.sub(r"\b(extern|static|inline|__inline|__inline__|register|auto|"
                 r"_Noreturn)\b", " ", ret)
    kept, dropped = [], []
    for tok in ret.split():
        bare = tok.replace("*", "")
        if bare and bare.isupper() and bare not in _TYPE_WORDS and len(bare) > 2:
            dropped.append(bare)
            if "*" in tok:                       # keep the stars a macro was glued to
                kept.append("*" * tok.count("*"))
            continue
        kept.append(tok)
    # AN ALL-CAPS TYPE IS NOT AN EXPORT MACRO, and case alone cannot tell them apart.
    #
    # `LEPT_DLL extern PIX * pixReadMem(...)` reduced to `*`: LEPT_DLL is a macro and PIX
    # is the RETURN TYPE, and both are uppercase. With no identifier left the declaration
    # was dropped, and so was every other pointer-returning function in leptonica — 1482
    # declarations parsed, no pixReadMem, and the handle mis-inferred as `l_uint8 *` from a
    # parameter. PIX, FPIX, DPIX, PIXCMAP, NUMA, SARRAY are all types spelled in caps.
    #
    # A decoration macro precedes the type, so the LAST uppercase token is the one that has
    # to be a type when nothing else survives. Put it back rather than return a bare star.
    if dropped and not any(c.isalpha() for c in "".join(kept)):
        kept.insert(0, dropped[-1])
    return " ".join(kept).strip()


def base_type(ty: str) -> str:
    """The type with qualifiers and pointer stars removed, so `const hd_ctx *` and
    `hd_ctx *` compare equal when deciding what the library's handle is.

    A scalar typedef is followed to what it aliases, so `l_uint8` answers as
    `unsigned char` and every byte check gets it without another entry in BYTE_BASES.
    """
    t = re.sub(r"\b(const|volatile|struct|enum|union|static|extern|inline)\b", " ", ty)
    bare = " ".join(t.replace("*", " ").split())
    return _resolve_alias(bare)


def hkey(ty: str, ptr_map: dict) -> str:
    """The identity of a type for handle matching: its pointee when it is a pointer typedef,
    otherwise its bare name. `png_structp`, `png_structrp` and `png_const_structp` all
    resolve to `png_struct`, which is what they actually are.

    EXCEPT when the pointee is `void`. A `typedef void *` is a NOMINAL type: the library
    distinguishes its handles by name and nothing else. Resolving them to `void` made
    lcms2's `cmsHPROFILE` and `cmsHANDLE` the same type, so a colour profile was paired
    with `cmsDictFree` — the destructor for a dictionary — which leaks the profile and frees
    a pointer of the wrong type. The handle for the whole library was inferred as
    `cmsContext` for the same reason. Keeping the typedef name is what the library means.
    """
    b = base_type(ty)
    resolved = ptr_map.get(b, b)
    return b if resolved == "void" and b != "void" else resolved


def _is_ptr(ty: str, ptr_types: frozenset = frozenset()) -> bool:
    """Whether a type is a pointer, INCLUDING one hidden behind a typedef.

    `magic_t`, `xmlDocPtr`, `sqlite3` — libraries habitually hide the handle's pointer-ness
    in a typedef. Missing that made the engine pick `const char *` as libmagic's handle,
    infer every role wrongly, and propose nothing.
    """
    return "*" in ty or base_type(ty) in ptr_types


# `int (*cb)(void *, int)` and `void (*)(void *)` — a parameter that is a function pointer.
# A CONTINUATION FLAG THE CALLEE WRITES, and only one whose polarity is unambiguous.
#
# `de265_error de265_decode(de265_decoder_context*, int* more)` sets `more` to 0 when the
# decoder has nothing left. Looping on it is the difference between one step of a
# multi-frame pipeline and the whole stream — and, for libde265, between a plan D3 refuses
# for leaking queued NAL units and one that does not.
#
# POSITIVE NAMES ONLY. `done` and `eof` mean the opposite, and a wrong polarity is either an
# instant exit or a loop that runs to its bound doing nothing. Inverting on a name is a
# guess; refusing to guess costs one loop and no correctness.
_CONTINUE_FLAG = re.compile(r"^(more|again|has_more|more_data|pending|continue|"
                            r"has_next|remaining)$", re.I)

_IS_FUNC_PTR = re.compile(r"\(\s*\*")

# The pointee recorded for a function-pointer typedef. It deliberately matches no handle.
FN_PTR = "__hf_function_pointer"


def is_callback(ty: str, ptr_map: dict) -> bool:
    """True for a callback written inline OR hidden behind a typedef.

    `void (*cb)(void *)` and `Jbig2ErrorCallback cb` are the same thing to a caller, and
    only the first has a star to find.
    """
    if _IS_FUNC_PTR.search(ty):
        return True
    return ptr_map.get(base_type(ty)) == FN_PTR

_STRINGISH = re.compile(r"(str|json|text|name|path|url|utf8|cstr|filename)", re.I)
# The optional short prefix is Hungarian notation, which older C APIs use
# constantly: `cmsOpenProfileFromMem(const void *MemPtr, cmsUInt32Number dwSize)`
# pairs MemPtr with dwSize, and a start-anchored pattern missed it — so the profile
# length was bound to 0, lcms2 was told the profile is zero bytes long, and 21
# million executions reached 1.95% of the library. The type `cmsUInt32Number` is
# unrecognisable across libraries; the NAME is not.
_LENISH = re.compile(r"^(?:[a-z]{1,3})?(n|len|length|size|count|sz|nbytes|num|bytes)\w*$", re.I)
# `cmsOpenProfileFromMem(const void *MemPtr, cmsUInt32Number dwSize)` pairs MemPtr
# with dwSize, and an anchored pattern missed it — so the profile length was bound to
# 0, lcms2 was told the profile is zero bytes, and 21 million executions reached 1.95%
# of the library. The type `cmsUInt32Number` is unrecognisable across libraries; the
# name is not.
_LENTYPE = re.compile(r"^(size_t|ssize_t|int|unsigned|unsigned int|long|"
                      r"unsigned long|uint32_t|uint64_t|int32_t|int64_t)$")
_BUFISH = re.compile(r"(buf|data|bytes|input|blob|src|payload)", re.I)
_OPAQUE_EXCLUDE = {"char", "void", "int", "unsigned char", "FILE", "size_t"}


@dataclass
class Decl:
    ret: str
    name: str
    params: list          # list[(type, name)]
    header: str
    ptr_types: frozenset = frozenset()
    ptr_map: dict = field(default_factory=dict)      # ptr typedef -> pointee base type
    # Integer object-like macros the header defines. A version or ABI parameter is usually
    # named after the macro that supplies its value, and passing 0 instead makes the call
    # fail a check the harness never sees.
    macros: dict = field(default_factory=dict)
    # Type names whose struct has a BODY in the parsed headers. A caller-allocated handle
    # requires one: `typedef struct sqlite3_stmt sqlite3_stmt;` declares an OPAQUE type
    # whose size is unknown, so `sqlite3_stmt x;` does not compile. The producer treated it
    # as an inline handle like `z_stream`, emitted exactly that declaration, and the plan
    # SHIPPED with a certificate — because emit succeeded, the static gates passed, and the
    # only gates that would have caught it need a binary that never built.
    complete: frozenset = frozenset()
    # Complete struct -> {field: macro} the library requires set before use. See
    # _required_init_fields: zeroing a caller-allocated struct is not initialising it.
    req_init: dict = field(default_factory=dict)

    @property
    def returns_pointer(self) -> bool:
        return _is_ptr(self.ret, self.ptr_types)

    @property
    def returns_void(self) -> bool:
        return self.ret.replace("*", "").strip() == "void"


def _split_params(s: str) -> list:
    s = s.strip()
    if not s or s == "void":
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())

    parsed = []
    for i, p in enumerate(out):
        if p == "...":
            continue
        m = re.match(r"^(.*?[\s\*])([A-Za-z_]\w*)\s*(\[\s*\d*\s*\])?$", p)
        if m and m.group(2) not in _TYPE_WORDS:
            ty, nm = m.group(1).strip(), m.group(2)
            if m.group(3):
                ty += " *"
        else:
            # An UNNAMED parameter, which is legal C and common in real headers. Give it a
            # positional name so the rest of the pipeline has something to bind to; type
            # based inference below does not depend on the name.
            ty, nm = p.strip(), f"arg{i}"
        parsed.append((" ".join(ty.split()), nm))
    return parsed


def _typedef_map(stmts: list) -> dict:
    """Pointer typedef name -> the type it points AT.

    Keeping the pointee matters because mature C libraries alias the same handle several
    ways. libpng declares all of

        typedef png_struct        * png_structp;
        typedef png_struct        * png_structrp;      /* restrict */
        typedef const png_struct  * png_const_structp;

    and `png_create_read_struct` returns `png_structp` while every consumer takes
    `png_structrp`. Comparing the typedef NAMES made those different types, so libpng had no
    handle, no roles and no plans — from 245 correctly parsed declarations.
    """
    out: dict = {}
    for st in stmts:
        if not st.startswith("typedef "):
            continue
        # A FUNCTION-POINTER TYPEDEF HIDES A CALLBACK BEHIND AN ORDINARY-LOOKING NAME.
        #
        # `typedef void (*Jbig2ErrorCallback)(void *data, const char *msg, ...);` — the
        # parameter then reads `Jbig2ErrorCallback error_callback`, with no star anywhere,
        # so the inline-callback check never fires. The producer could not map the type, and
        # an unmappable parameter refuses the whole plan: jbig2dec parsed perfectly, eight
        # declarations with the right handle, and proposed ZERO plans.
        #
        # Recorded here rather than in a new field so it travels through hkey() with
        # everything else. The sentinel pointee matches no handle, which is correct — a
        # callback is not a resource.
        m_fp = re.match(r"^typedef\s+.*\(\s*\*+\s*([A-Za-z_]\w*)\s*\)\s*\(", st)
        if m_fp:
            out[m_fp.group(1)] = FN_PTR
            continue
        if "(" in st:
            continue
        m = re.match(r"^typedef\s+(.*?)([A-Za-z_]\w*)$", st)
        if not m:
            continue
        pre, name = m.group(1), m.group(2)

        if "}" in pre:
            # A struct, union or enum DEFINITION rather than an alias. Its members are full
            # of pointers, and none of them belong to the typedef:
            #
            #     typedef struct yaml_emitter_s { unsigned char *buffer; ... } yaml_emitter_t;
            #
            # Treating that as a pointer typedef recorded the entire expanded struct body as
            # a type name. Only what follows the closing brace can carry the typedef's own
            # `*`. This surfaced only after preprocessing, which inlines these definitions.
            after = pre[pre.rfind("}") + 1:]
            if "*" not in after:
                continue
            tag = re.search(r"^\s*(?:struct|union|enum)\s+([A-Za-z_]\w*)", pre)
            if tag:
                out[name] = tag.group(1)
            else:
                # AN ANONYMOUS STRUCT STILL HAS A NAME -- the value typedef declared beside
                # the pointer one. libpng writes
                #     typedef struct { ... } png_image, *png_imagep;
                # so there is no tag after `struct` and png_imagep used to map to ITSELF.
                # hkey() then answered `png_imagep`, which is not in the complete-type set
                # (`png_image` is), the caller-allocated-struct branch declined, and the
                # parameter fell through to a literal 0.
                m2 = re.match(r"\s*([A-Za-z_]\w*)\s*,", after)
                out[name] = m2.group(1) if m2 else name
        elif "*" in pre:
            out[name] = base_type(pre)
    return out


def _typedefs(stmts: list) -> frozenset:
    """Typedef names that are really pointers: `typedef struct magic_set *magic_t`."""
    return frozenset(_typedef_map(stmts))


def header_byte_aliases(path: str, include_dirs=(), cflags=()) -> dict:
    """Scalar typedefs that bottom out in a byte type, from the WHOLE translation unit.

    The sibling of header_typedefs, and for the same reason: a type alias is a fact about
    the library, not about the file that happens to hold it.
    """
    from ..analysis.sinks import strip_noise
    if not Path(path).exists():
        return {}
    pp = _preprocess(path, include_dirs, cflags, whole_translation_unit=True)
    text = pp if pp is not None else Path(path).read_text(errors="replace")
    return _scalar_typedefs(_statements(strip_noise(text)))


# const-qualified byte-buffer pointer typedefs: name -> the byte base it points at.
#
# Populated per target by propose(), the same way _SCALAR_ALIASES is, because the typedef
# and its use routinely live in different files. Deliberately NOT derived from _typedef_map:
# that map stores the const-STRIPPED base, and const is the entire safety argument here.
# `typedef const void * png_const_voidp` is an input buffer; `typedef void * cmsHPROFILE`
# is an opaque handle, and treating the second as bytes is what paired a colour profile with
# a dictionary destructor. Only const-qualified byte pointees are ever recorded.
_CONST_BYTE_PTRS: dict = {}

_CONST_BYTE_PTR_RE = re.compile(
    r"^typedef\s+const\s+([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)\s*\*\s*([A-Za-z_]\w*)$")


def header_const_byte_ptrs(path: str, include_dirs=(), cflags=()) -> dict:
    """Pointer typedefs of the form `typedef const <byte type> * NAME`, from one header."""
    from ..analysis.sinks import strip_noise
    if not Path(path).exists():
        return {}
    pp = _preprocess(path, include_dirs, cflags)
    out: dict = {}
    for st in _statements(strip_noise(
            pp if pp is not None else Path(path).read_text(errors="replace"))):
        m = _CONST_BYTE_PTR_RE.match(" ".join(st.split()))
        if m and m.group(1).strip() in BYTE_BASES:
            out[m.group(2)] = m.group(1).strip()
    return out


def header_ptr_map(path: str, include_dirs=(), cflags=()) -> dict:
    """Pointer typedef -> pointee, for one header, whether or not it declares functions.

    The set-returning sibling below has been shared across a target's headers since libxml2
    needed it. The MAP was not, and that asymmetry cost libpng its entry point:
    `png_const_voidp` is typedef'd in pngconf.h and used in png.h, so the name was known to
    be a pointer while what it pointed AT was lost. png_image_begin_read_from_memory then
    had a parameter the byte check could not recognise, proposed no plan, and reported
    NO PLAN -- indistinguishable, from the outside, from a library with no fuzzable surface.
    Splitting types into a config header is the norm in C, not an oddity of libpng.
    """
    from ..analysis.sinks import strip_noise
    if not Path(path).exists():
        return {}
    pp = _preprocess(path, include_dirs, cflags)
    return _typedef_map(_statements(strip_noise(
        pp if pp is not None else Path(path).read_text(errors="replace"))))


def header_typedefs(path: str, include_dirs=(), cflags=()) -> frozenset:
    """Pointer typedefs declared in one header, independent of whether it declares any
    functions.

    A header that contains ONLY typedefs — `xmltypes.h`, `forward.h`, the pattern is
    everywhere — contributes no declarations, so collecting typedefs off the parsed
    declarations loses them completely. libxml2 happened to put both in tree.h and hid this.
    """
    from ..analysis.sinks import strip_noise
    if not Path(path).exists():
        return frozenset()
    pp = _preprocess(path, include_dirs, cflags)
    return _typedefs(_statements(strip_noise(
        pp if pp is not None else Path(path).read_text(errors="replace"))))


def _preprocess(path: str, include_dirs=(), cflags=(),
                whole_translation_unit: bool = False) -> Optional[str]:
    """Run the real C preprocessor and keep only what came from THIS header.

    Text parsing loses to macros, and the losses are silent. Four of eight real libraries
    yielded nothing at all:

        bzlib   BZ_EXTERN int BZ_API(BZ2_bzCompressInit)(bz_stream *strm, ...)
                ^ the NAME is inside a macro call
        png     PNG_EXPORT(24, void, png_set_sig_bytes, (png_structrp p, int n));
                ^ the whole DECLARATION is generated by a macro
        pcre2   names assembled by token concatenation through PCRE2_SUFFIX()
        lzma    an umbrella header that only #includes others

    A preprocessor solves all four at once, and it is already on the machine — the same
    clang the dynamic gates use. Failure is not fatal: the caller falls back to reading the
    text, which is what happens when a header needs flags we were not given.

    Only text attributed to the target header is kept. Preprocessed output otherwise carries
    every declaration in stdio.h, stdlib.h and everything else pulled in transitively, and
    the producer would propose harnesses for libc.
    """
    from .. import toolchain as tc
    cc = tc.find_cc()
    if not cc:
        return None
    cmd = [cc, "-E", "-x", "c", str(path)]
    cmd += [f"-I{d}" for d in include_dirs] + list(cflags)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except Exception:                                          # noqa: BLE001
        return None
    if r.returncode != 0 or not r.stdout:
        return None

    try:
        target = Path(path).resolve()
    except OSError:
        return None
    # TYPE FACTS COME FROM THE WHOLE TRANSLATION UNIT; API SURFACE DOES NOT.
    #
    # The per-header filter is right for declarations — without it the producer proposes
    # harnesses for stdio. It is wrong for TYPEDEFS: leptonica declares its API in
    # allheaders.h and spells a byte in environ.h, so filtering to the named header threw
    # away `typedef unsigned char l_uint8;` and `pixReadMem(const l_uint8 *, size_t)`
    # stopped looking like it takes bytes. What a type MEANS is not local to a file.
    if whole_translation_unit:
        return r.stdout or None

    out, keeping = [], False
    for line in r.stdout.splitlines():
        if line.startswith("# "):
            m = re.match(r'# \d+ "([^"]*)"', line)
            if m:
                # The target header, plus its own sibling directory for the umbrella
                # pattern: lzma.h is nothing but #includes of lzma/*.h, so keeping only the
                # named file yielded zero declarations from a real library.
                try:
                    f = Path(m.group(1)).resolve()
                    keeping = (f == target
                               or f.parent == target.parent / target.stem)
                except OSError:
                    keeping = False
            continue
        if keeping:
            out.append(line)
    text = "\n".join(out)
    return text if text.strip() else None


_INT_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+\(?\s*(-?\d+)\s*\)?[ \t]*$", re.M)


def _int_defines(path: str) -> dict:
    """Integer object-like macros a header defines, by name.

    Read from the RAW text, before preprocessing, because the preprocessor's whole job is
    to make these disappear.
    """
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return {}
    return {m.group(1): int(m.group(2)) for m in _INT_DEFINE.finditer(text)}


def parse_header(path: str, include_dirs=(), cflags=()) -> list:
    """Function declarations from one header.

    The C preprocessor is used when it is available, because macros defeat text parsing and
    do it silently. Comments and strings are removed either way, so a prototype inside a
    comment is never mistaken for API surface.
    """
    from ..analysis.sinks import strip_noise
    pp = _preprocess(path, include_dirs, cflags)
    src = strip_noise(pp if pp is not None
                      else Path(path).read_text(errors="replace"))
    stmts = _statements(src)
    macros = _int_defines(path)
    _SCALAR_ALIASES.update(_scalar_typedefs(stmts))
    ptr_map = _typedef_map(stmts)
    ptr_types = frozenset(ptr_map)
    complete = _complete_types(src)
    req_init = _required_init_fields(src, macros)

    out = []
    for st in stmts:
        if st.startswith("typedef "):
            continue
        # A DECLARATION AFTER A static inline BODY STILL CARRIES ITS CLOSING BRACE.
        #
        # jansson.h defines json_incref as a static inline, and the very next line is
        #   void json_delete(json_t *json);
        # Statements split on `;`, so this one arrives as `} void json_delete(json_t *json)`
        # and was discarded whole. jansson then had a handle it must free and NO destructor,
        # every plan using json_loadb was dropped for leaking, and the benchmark reported
        # "NO PLAN for the gold target" on a library whose entry point had parsed fine.
        #
        # Header-only helpers are everywhere, so this is not one library's quirk.
        # THE BRACE STRIP RUNS FIRST, because the statement carries BOTH braces:
        #   static JSON_INLINE json_t *json_incref(json_t *j) { ... } void json_delete(json_t *)
        # Checking for `{` before taking the tail discarded it again, which is the version
        # of this fix that did not work.
        if "}" in st:
            st = st.rsplit("}", 1)[1].strip()
        if not st or "{" in st:
            continue
        split = _split_call(st)
        if not split:
            continue
        head, name, params = split
        if name in ("if", "for", "while", "switch", "sizeof", "return", "defined"):
            continue
        ret = _clean_return(head)
        if not ret or not re.search(r"[A-Za-z_]", ret):
            continue
        if re.match(r"^(typedef|return|else)\b", ret):
            continue
        out.append(Decl(ret=" ".join(ret.split()), name=name,
                        params=_split_params(params), header=Path(path).name,
                        ptr_types=ptr_types, ptr_map=ptr_map, complete=complete,
                        req_init=req_init,
                        macros=macros))
    return out


# ── inference ─────────────────────────────────────────────────────────────────

_STRUCT_OPEN = re.compile(r"\b(?:typedef\s+)?(?:struct|union)\s+(?P<tag>[A-Za-z_]\w*)?\s*\{")
_ALIAS_AFTER = re.compile(r"^\s*\**\s*(?P<alias>[A-Za-z_]\w*)")


def _all_complete(decls: list) -> frozenset:
    """The UNION of complete types across every parsed header.

    Reading `decls[0].complete` used only the first header's types. `ZopfliDeflate` lives in
    deflate.h and `ZopfliOptions` is defined in zopfli.h, so the config struct was invisible
    and the entry point produced no plan at all — a multi-header target silently losing type
    information, which is the same shape as the typedef-sharing bug fixed for `ptr_map`.
    """
    out: set = set()
    for d in decls:
        out |= set(d.complete)
    return frozenset(out)


def _complete_types(src: str) -> frozenset:
    """Type names whose definition includes a body, and which can therefore be declared BY
    VALUE.

    The distinction the engine was missing entirely. `typedef struct yaml_parser_s { ... }
    yaml_parser_t;` gives a complete type a harness can allocate; `typedef struct
    sqlite3_stmt sqlite3_stmt;` gives an opaque one it can only point at. Both look
    identical to a rule that only asks "is there an init and a fini taking `T *`".

    Brace COUNTING, not a regular expression: `yaml_parser_s` nests anonymous unions three
    levels deep, and a pattern that handles one level of nesting reported it as incomplete —
    silently dropping the caller-allocated handle the whole inline-resource feature was
    built for, while still finding sqlite's flat one-line typedefs and so looking like it
    worked.

    Scanned over the RAW source, never over `_statements`: that splits on `;`, so a struct
    body full of member declarations never appears whole in any one statement.
    """
    out: set = set()
    text = src or ""
    for m in _STRUCT_OPEN.finditer(text):
        if m.group("tag"):
            out.add(m.group("tag"))
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(text):
            continue                       # unbalanced: say nothing rather than guess
        a = _ALIAS_AFTER.match(text[i + 1:i + 80])
        if a:
            out.add(a.group("alias"))
    return frozenset(out)


# Complete struct -> {field: macro}, for the target currently being proposed. Same idiom as
# _SCALAR_ALIASES and _CONST_BYTE_PTRS: a fact about the library's types that several
# unrelated points in the plan builder need, and that would otherwise be threaded through
# six signatures to reach the one place that binds a caller-allocated struct.
_REQ_INIT: dict = {}

_VERSION_MEMBER = re.compile(r"\b(?:png_)?(?:uint_32|uint32_t|unsigned\s+int|int|"
                             r"unsigned|size_t|png_uint_32)\s+(version|size)\s*;")


def _required_init_fields(src: str, macros: dict) -> dict:
    """Complete structs that carry a field the library checks, as type -> {field: macro}.

    THE IDIOM. A library that must stay ABI-compatible puts a `version` (sometimes `size`)
    field at the top of a caller-allocated struct and refuses any object whose value it does
    not recognise. libpng spells it `png_image.version` against `PNG_IMAGE_VERSION`. The
    caller is expected to set it; a memset leaves 0; the call is refused before any work
    happens.

    That cost libpng 220 million executions for 0.71% of the library, and no gate could see
    it: the harness was correct in every respect the plan could express.

    DERIVED, NOT LISTED. The field is found in the struct body and the macro is required to
    exist in the header with a matching name -- `png_image` -> `PNG_IMAGE_VERSION`. A
    per-library table would work today and grow once per library forever, which is the same
    mistake the byte-spelling list made before the header was read instead.
    """
    out: dict = {}
    text = src or ""
    for m in _STRUCT_OPEN.finditer(text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(text):
            continue
        body = text[m.end():i]
        fm = _VERSION_MEMBER.search(body)
        if not fm:
            continue
        names = [m.group("tag")] if m.group("tag") else []
        a = _ALIAS_AFTER.match(text[i + 1:i + 80])
        if a:
            names.append(a.group("alias"))
        for nm in names:
            if not nm:
                continue
            macro = f"{nm.upper()}_{fm.group(1).upper()}"
            if macro in (macros or {}):
                out[nm] = {fm.group(1): macro}
    return out


def _handle_type(decls: list) -> Optional[str]:
    """The type most plausibly acting as the library's opaque handle: the pointer type most
    often returned by one function and accepted as the first argument of many others.

    Two corrections learned from real headers. `char *` and `void *` are excluded outright —
    a library returns strings constantly and none of them are its handle, and letting
    `const char *` win is exactly how libmagic came out with every role inferred wrongly.
    And a candidate must be returned by at least one function that does NOT already take it,
    because that function is the constructor.
    """
    c = _returned_handles(decls)
    return c[0] if c else None


def _returned_handles(decls: list) -> list:
    """Every type that plausibly acts as a returned handle, most-used first."""
    pm = decls[0].ptr_map if decls else {}
    scores: dict = {}
    for d in decls:
        if not d.returns_pointer:
            continue
        b = hkey(d.ret, pm)
        if b in _OPAQUE_EXCLUDE or not b:
            continue
        if bool(d.params) and hkey(d.params[0][0], pm) == b:
            continue                                   # not a constructor
        n = sum(1 for o in decls if o.params and hkey(o.params[0][0], pm) == b)
        if n:
            scores[d.ret] = max(scores.get(d.ret, 0), n)
    return sorted(scores, key=lambda k: (-scores[k], k))


# A consumer that only RECORDS where the bytes are, without touching them.
_SETTER_ISH = re.compile(r"_(set_input|set_source|set_read|feed|push|write|attach)"
                         r"(_string|_buffer|_memory|_data)?$", re.I)
# The call that actually does the parsing work afterwards.
_DRIVER_ISH = re.compile(r"_(parse|scan|load|next|read|step|process|run|update|decode|"
                         r"inflate|advance|pull)$", re.I)

# Underscore-separated OR camelCase, and a trailing `_` is allowed because zlib's real
# entry points are `inflateInit_` and `deflateInit_` — the unsuffixed names are macros that
# do not survive preprocessing. Matching only `_init$` found neither, so zlib — the
# canonical caller-allocated library — produced no plans at all.
# Calls that must happen between construction and use. libmagic's `magic_buffer` reaches
# almost nothing until `magic_load` has read the magic database; libarchive needs its
# `archive_read_support_*` calls before it can recognise anything. Omitting them produced a
# harness that ran 13 million times and never left the error path.
_SETUP_ISH = re.compile(r"_(load|support|enable|use|add|select|configure|prepare|"
                        r"set_option|setopt|set_flags|declare|register)\w*$", re.I)

# Verbs that create a thing without saying "create": a parser prepares, compiles or builds.
_MAKE_ISH = re.compile(r"(?:_|(?<=[a-z]))(prepare|compile|build|make|acquire|obtain|"
                       r"construct|load|parse)(_?\w*)?$", re.I)

_INIT_ISH = re.compile(r"(?:_|(?<=[a-z]))(init|initialize|initialise|new|create|open|"
                       r"setup|alloc|start|begin|reset)_?$", re.I)
# `sqlite3_finalize` ends in "finalize", not "fini" — an anchor after the short form matched
# neither, so sqlite statements had a producer and no destroyer, and every chain leaked one.
_FINI_ISH = re.compile(r"(?:_|(?<=[a-z]))(delete|destroy|free|close|cleanup|clean|end|"
                       r"finalize|finalise|finish|fini|release|dispose|reset|discard|"
                       r"unref|put)_?$", re.I)

# A REUSE VERB IS NOT A DESTROY VERB, and `reset` sits in _FINI_ISH above.
#
# `de265_reset(ctx)` clears the decoder's state so the SAME context can decode another
# stream. The context is still alive and still has to be freed. But it returns void, takes
# only the handle, and ends in a verb _FINI_ISH matches — so it ranked as the best
# destructor and beat `de265_free_decoder`, which returns a `de265_error` status and
# therefore only matched the weaker any-position pattern.
#
# The result would have been a harness that never frees the decoder: every input leaks the
# whole context, and under LeakSanitizer every finding is the harness's own. That is the
# expat XML_DefaultCurrent mistake and the Brotli one, arriving a third time through a
# different door.
#
# _FINI_ISH is left ALONE — it is load-bearing in role inference in five other places, and
# narrowing it there would change targets that are currently correct. This demotes reuse
# verbs in the destroyer ranking only, and only below a real candidate: if a library offers
# nothing else, a reuse verb is still chosen, exactly as before.
_REUSE_ISH = re.compile(r"(?:_|(?<=[a-z]))(reset|clear|rewind|reinit|reinitialise|"
                        r"reinitialize)_?$", re.I)


def _outparam_handles(decls: list) -> list:
    """Constructors that hand the handle back through a POINTER-TO-POINTER parameter.

        int sqlite3_open(const char *filename, sqlite3 **ppDb);

    The third and last way a C library gives you a handle, after returning one and having
    the caller allocate it. sqlite3, and plenty besides, use only this form — so returned-
    handle inference found nothing, and the best `create` available was whatever else
    happened to return a `sqlite3 *`. The emitted plan called `sqlite3_context_db_handle(0)`
    as its constructor, which is not one.
    """
    pm = decls[0].ptr_map if decls else {}
    out: list = []
    for d in decls:
        # `_producer_of` was taught that a parser PREPARES or COMPILES a thing without
        # saying "create"; this must agree, or the type never enters the known-handle set
        # and no chain can reference it. Two places deciding "is this a constructor" by
        # different rules is how sqlite3_stmt stayed invisible.
        if d.returns_pointer or not d.params or not (
                _INIT_ISH.search(d.name) or _MAKE_ISH.search(d.name)):
            continue
        # The out-parameter is not always last. `sqlite3_prepare_v2(db, sql, n, &stmt,
        # &tail)` puts it fourth of five.
        cand = [t for t, _ in d.params if t.count("*") == 2]
        if not cand:
            continue
        last_ty = cand[0]
        base = hkey(last_ty.replace("*", "").strip(), pm)
        if not base or base in _OPAQUE_EXCLUDE:
            continue
        users = sum(1 for o in decls
                    if o.params and hkey(o.params[0][0], pm) == base)
        if users >= 2:
            fini = next((o for o in decls
                         if _FINI_ISH.search(o.name) and o.params
                         and hkey(o.params[0][0], pm) == base
                         and len(o.params) == 1), None)
            if fini:
                out.append((users, f"{base} *", base, d.name, fini.name))
    return [(h, b, i, f) for _, h, b, i, f in sorted(out, key=lambda x: (-x[0], x[1]))]


def _inline_handle(decls: list) -> Optional[tuple]:
    """A CALLER-ALLOCATED context object: `yaml_parser_t p; yaml_parser_initialize(&p);`.

    `_handle_type` only finds handles the library RETURNS. libyaml never returns one — the
    caller declares a `yaml_parser_t` and hands over its address — and so do zlib's
    `z_stream`, and a large share of C APIs built around a context struct. For those,
    handle inference returned None, every role came out `query`, and the library was
    unreachable. That was a gap in what the IR could express, not a parsing failure.

    Recognised by shape rather than by name alone: a type whose pointer is the first
    parameter of several functions, one of which reads as an initialiser and another as its
    matching destructor. Requiring the PAIR is what keeps this from firing on any struct
    that happens to be passed around.
    """
    first_param: dict = {}
    for d in decls:
        if d.params and "*" in d.params[0][0]:
            b = base_type(d.params[0][0])
            if b and b not in _OPAQUE_EXCLUDE:
                first_param.setdefault(b, []).append(d)

    found = _inline_handles(decls)
    return found[0] if found else None


def _inline_handles(decls: list) -> list:
    """EVERY caller-allocated context type, most-used first.

    A library routinely has more than one lifecycle. libyaml has both a `yaml_parser_t` and
    a `yaml_emitter_t`, and picking only the most-used one chose the emitter — so the
    PARSER, which is the only part of libyaml that consumes serialised bytes, was never
    proposed at all. The engine reported plans for a library whose actual attack surface it
    had not looked at.
    """
    pm = decls[0].ptr_map if decls else {}
    complete = _all_complete(decls)
    first_param: dict = {}
    for d in decls:
        if d.params and "*" in d.params[0][0]:
            b = hkey(d.params[0][0], pm)
            # A caller-allocated handle must be a COMPLETE type. Without this check
            # `sqlite3_stmt` — declared, never defined — was proposed as one, and the
            # emitter wrote `sqlite3_stmt hf_r_h;` which is not valid C.
            if b and b not in _OPAQUE_EXCLUDE and (not complete or b in complete):
                first_param.setdefault(b, []).append(d)

    out: list = []
    for b, users in first_param.items():
        if len(users) < 2:
            continue
        init = next((d for d in users
                     if _INIT_ISH.search(d.name) and not d.returns_pointer), None)
        fini = next((d for d in users
                     if _FINI_ISH.search(d.name) and len(d.params) == 1), None)
        if init and fini and init.name != fini.name:
            out.append((len(users), f"{b} *", b, init.name, fini.name))
    return [(h, base, i, f) for _, h, base, i, f in sorted(out, key=lambda x: (-x[0], x[1]))]


def infer_role(d: Decl, handle: Optional[str]) -> str:
    hb = hkey(handle, d.ptr_map) if handle else None
    takes_handle = bool(d.params) and hb and hkey(d.params[0][0], d.ptr_map) == hb
    if handle and d.returns_pointer and hkey(d.ret, d.ptr_map) == hb and not takes_handle:
        return ROLE_CREATE
    # A destructor need not return void. `sqlite3_close`, `archive_read_free` and
    # `BZ2_bzCompressEnd` all return a status, and requiring void meant sqlite3's destroy op
    # became `sqlite3_interrupt` — which leaves the database open.
    # A CONST handle cannot be destroyed through. `BrotliDecoderHasMoreOutput(const
    # BrotliDecoderState *)` returns a bool and was classified a destructor purely because
    # it takes one handle parameter — so it was emitted as the destroy op, the decoder state
    # was never freed, and LeakSanitizer stopped the campaign on the 4th input having
    # covered nothing. A library that marks the parameter const is telling us the call does
    # not own or release the object.
    _const_handle = bool(d.params) and "const" in d.params[0][0]
    if (takes_handle and len(d.params) == 1 and not _const_handle
            and (d.returns_void or _FINI_ISH.search(d.name)
                 or _DESTROY_ANYWHERE.search(d.name))):
        return ROLE_DESTROY
    if takes_handle and len(d.params) >= 2:
        return ROLE_CONSUME
    if takes_handle:
        return ROLE_QUERY
    if d.returns_pointer and len(d.params) >= 1:
        return ROLE_CONSUME
    # A CONST BYTE BUFFER IS ITSELF THE EVIDENCE, even with no handle in sight.
    #
    # Every rule above reaches "consumes input" through the library's own opaque handle or
    # through a returned pointer. libpng's simplified API has neither: the caller declares a
    # `png_image` on its own stack and passes `png_imagep` -- a caller-allocated struct, not
    # png_struct, which is what libpng's handle inference actually found. So
    # png_image_begin_read_from_memory(png_imagep, png_const_voidp, size_t) fell through to
    # `query` and no plan was ever built for the one entry point in that header that reads
    # attacker bytes.
    #
    # A parameter the fuzzer can fill, marked const so the library will not write through
    # it, is a stronger signal of an input-consuming entry point than the handle shape is.
    # Path-like names are excluded because those are filenames, and a harness must never
    # open a path built from fuzzer bytes.
    # NARROWLY: the buffer must be paired with a LENGTH. `(const void *, size_t)` is the
    # bytes-and-size idiom and it is unambiguous. Accepting a bare const buffer instead
    # reclassified setters, out-parameter fills and config-struct initialisers as consumers
    # and broke seven pinned tests -- those guards are load-bearing and the rule has to pass
    # them, not be widened until they yield.
    # NOT A SETTER. `yaml_parser_set_input_string(parser, const unsigned char *, size_t)`
    # matches buffer-and-length exactly, and it is not an entry point -- it hands the parser
    # its input and the work happens in the yaml_parser_load that follows. Calling it a
    # consumer cost libyaml its drive op and four pinned tests. A setter is a step in a
    # sequence; the rule below is only for functions that ARE the sequence.
    if _SETTER_ISH.search(d.name or ""):
        return ROLE_QUERY
    # NO DOUBLE POINTERS. `ZopfliDeflate(const ZopfliOptions *, int, int,
    # const unsigned char *in, size_t insize, unsigned char **out, size_t *outsize)`
    # matches buffer-and-length exactly, and calling it a direct entry point cost zopfli
    # its setup: the producer stopped chaining ZopfliInitOptions and emitted a bare call
    # that took NULL for the options and segfaulted on the first valid input. D3 refused
    # it, so the case reported a refusal instead of the 76.51% it had measured before.
    #
    # A `T **` parameter means the library allocates and hands something back, which is a
    # lifecycle this rule is not entitled to assume it understands. libpng's entry point
    # has no such parameter and is unaffected.
    if any(ty.count("*") >= 2 for ty, _ in d.params):
        return ROLE_QUERY
    _buf = any(not _path_like(nm) and "const" in ty and _byte_carrying_ty(ty)
               and base_type(ty) != "char"
               for ty, nm in d.params)
    _len = any(_SIZE_ISH.search(nm or "") or base_type(ty) in ("size_t", "ssize_t")
               for ty, nm in d.params)
    if _buf and _len:
        return ROLE_CONSUME
    return ROLE_QUERY


def infer_contract(d: Decl, role: str, handle: Optional[str]) -> Contract:
    c = Contract()
    hb = hkey(handle, d.ptr_map) if handle else None

    for i, (ty, nm) in enumerate(d.params):
        is_ptr = _is_ptr(ty, d.ptr_types)
        nxt = d.params[i + 1] if i + 1 < len(d.params) else None

        # (pointer, length) pairs: a buffer immediately followed by a size-shaped scalar.
        # Matched on TYPE as well as on name, because real headers often omit the names —
        # `magic_buffer(magic_t, const void *, size_t)` is a (ptr,len) pair with nothing to
        # read but the types.
        #
        # Type-based matching has to be narrower than name-based matching or it over-fires.
        # `magic_setparam(magic_t, int, const void *)` paired the HANDLE with the following
        # int, because a typedef'd handle is a pointer and `int` is size-shaped. The plan
        # then bound an argument to a slice that did not exist and emit refused. So a
        # type-matched pair additionally requires the pointer to look like a byte buffer,
        # and never the library's own handle.
        looks_like_buffer = (base_type(ty) in ("void", "char", "unsigned char", "uint8_t")
                             and (not hb or hkey(ty, d.ptr_map) != hb))
        pairs_by_name = bool(nxt and _LENISH.match(nxt[1]))
        pairs_by_type = bool(nxt and looks_like_buffer
                             and _LENTYPE.match(base_type(nxt[0])))
        if is_ptr and nxt and "*" not in nxt[0] and (pairs_by_name or pairs_by_type):
            c.length_delimited.append([nm, nxt[1]])
            continue
        if any(nm == p[0] for p in c.length_delimited):
            continue

        # char* that is not half of a pair is a C string, and the contract is termination.
        if is_ptr and re.search(r"\bchar\b", ty) and "unsigned" not in ty:
            c.nul_terminated.append(nm)
        elif is_ptr and hb and hkey(ty, d.ptr_map) == hb and role != ROLE_DESTROY:
            c.requires_nonnull.append(nm)
        elif is_ptr and _STRINGISH.search(nm) and "void" not in ty:
            c.nul_terminated.append(nm)

    if role == ROLE_CREATE and d.returns_pointer:
        c.error_return = "null"
    elif role == ROLE_CONSUME and re.match(r"^(int|long|ssize_t)$", d.ret):
        c.error_return = "negative"
    return c


def to_api(d: Decl, handle: Optional[str]) -> Api:
    role = infer_role(d, handle)
    _ = d.macros                      # carried on the Decl; the binder reads it via _MACROS
    def _tref(ty: str) -> TypeRef:
        # base_type already follows a byte alias; record it when it changed anything, so a
        # gate can judge the type rather than the spelling.
        bare = " ".join(re.sub(r"\b(const|volatile|struct|enum|union)\b", " ", ty)
                        .replace("*", " ").split())
        res = base_type(ty)
        resolved = "" if res == bare else res
        # A POINTER TYPEDEF HIDES THE STAR, AND WITH IT THE BUFFER.
        #
        # libpng declares `typedef const void * png_const_voidp;` and then
        # `png_image_begin_read_from_memory(png_imagep, png_const_voidp memory, size_t)`.
        # The parameter spelling carries no `*`, so the byte check -- which counts stars --
        # said no, no consume op was built, and the entry point got NO PLAN at all while the
        # from_file variant beside it proposed one. Two plans came out of the whole of png.h.
        #
        # ONLY THE const CASE IS EXPANDED, and that restraint is the whole safety argument.
        # `typedef void * cmsHPROFILE;` is the opaque-handle idiom, and hkey() already
        # refuses to resolve it because doing so made lcms2's cmsHPROFILE and cmsHANDLE the
        # same type and paired a colour profile with a dictionary destructor. A handle is
        # passed to functions that mutate it, so it is not const; an input buffer is. Const
        # is what separates `const void *` the buffer from `void *` the handle, and nothing
        # non-const is widened here.
        if not resolved and "*" not in ty and ty.strip() in _CONST_BYTE_PTRS:
            resolved = _CONST_BYTE_PTRS[ty.strip()]
        return TypeRef(ty, "pointer" if _is_ptr(ty, d.ptr_types) else "scalar",
                       const="const" in ty, resolved=resolved)

    return Api(symbol=d.name, header=d.header, role=role,
               params=[ParamDecl(nm, _tref(ty)) for ty, nm in d.params],
               returns=TypeRef(d.ret, "void" if d.returns_void
                               else ("pointer" if d.returns_pointer else "scalar")),
               contract=infer_contract(d, role, handle))


# ── plan synthesis ────────────────────────────────────────────────────────────

def propose(headers: list, target: Target, *, platforms: Optional[list] = None,
            knobs: Optional[Knobs] = None) -> list:
    """One candidate plan per consuming entry point: create -> consume -> destroy.

    Plans are PROPOSALS. Several will be wrong, and the gates are what say which. That is
    the design: producers compete, gates rank, confidence decides nothing.
    """
    # NORMALISE ONCE, HERE. An explicit platforms=None reaches the HarnessIR constructor as
    # a real None and OVERRIDES the dataclass default_factory, so the plan carries no
    # platform list at all and the C emitter dies on ", ".join(None). The chain plans passed
    # a default and the free-function plans passed the argument through, which is why only
    # SOME plans from the same header failed to emit -- jansson lost 4 of 34 that way, with
    # the failure reported as "emit refused" as though a gate had rejected them.
    platforms = platforms or ["linux-x86_64-glibc"]
    incs = tuple(target.include_dirs)
    cfl = tuple(target.cflags)
    decls: list = []
    for h in headers:
        if Path(h).exists():
            decls.extend(parse_header(h, incs, cfl))
    if not decls:
        return []

    # Typedefs are shared across a library's headers even though each file only sees its
    # own. libxml2 declares `xmlReadMemory` in parser.h but typedefs `xmlDocPtr` in tree.h,
    # so parsing parser.h alone cannot tell that its return type is a pointer — and the
    # handle comes out as None, every role as `query`, and no plan is proposed.
    #
    # Collected from the HEADERS, not from the parsed declarations: a header holding only
    # typedefs yields no declarations and would otherwise contribute nothing.
    shared = frozenset().union(frozenset(),
                              *(header_typedefs(h, incs, cfl) for h in headers))
    # The pointees, on the same argument. Earlier headers win on a clash so the primary
    # header's own spelling is never overridden by a secondary one.
    shared_map: dict = {}
    for h in reversed(list(headers)):
        shared_map.update(header_ptr_map(h, incs, cfl))
    # Byte spellings, from every header the target names. Same argument as `shared` above:
    # the alias may live in a file that declares no functions at all.
    for h in headers:
        _SCALAR_ALIASES.update(header_byte_aliases(h, incs, cfl))
        _CONST_BYTE_PTRS.update(header_const_byte_ptrs(h, incs, cfl))
    for d in decls:
        _REQ_INIT.update(getattr(d, "req_init", None) or {})
    for d in decls:
        d.ptr_types = shared
        # Keep whatever the declaring header already knew; add what the others knew.
        d.ptr_map = {**shared_map, **(d.ptr_map or {})}

    # Every lifecycle the library has, not just its most-used one. A single-handle
    # assumption chose libyaml's EMITTER and never proposed anything for its parser — the
    # only half of that library which consumes serialised bytes.
    # (handle, object_base, init, fini, acquisition mode). The three ways a C library hands
    # you a handle: it returns one, the caller allocates one, or it writes one back through
    # an out-parameter.
    candidates: list = [(h, None, None, None, "returned") for h in _returned_handles(decls)]
    candidates += [(h, b, i, f, "out_param") for h, b, i, f in _outparam_handles(decls)]
    candidates += [(h, b, i, f, "inline") for h, b, i, f in _inline_handles(decls)]
    if not candidates:
        candidates = [(None, None, None, None, "returned")]

    # Order the lifecycles by whether they actually LOOK like one.
    #
    # `sqlite3_context_db_handle()` returns a `sqlite3 *` and does not take one, so it is a
    # structurally valid constructor and it won — producing a harness that opened no
    # database. sqlite3's real constructor is `sqlite3_open`, which returns its handle
    # through an out-parameter, and the pair `sqlite3_open` / `sqlite3_close` is the thing
    # that identifies it. A candidate with both a constructor and a destructor NAMED as such
    # beats one that merely has the right shape.
    def _quality(c) -> tuple:
        handle, base, init, fini, mode = c
        if mode != "returned":
            named_init = bool(init and _INIT_ISH.search(init))
            named_fini = bool(fini and _FINI_ISH.search(fini))
        else:
            hb = hkey(handle, pm0) if handle else None
            named_init = any(d.returns_pointer and hkey(d.ret, pm0) == hb
                             and _INIT_ISH.search(d.name) for d in decls)
            named_fini = any(d.params and hkey(d.params[0][0], pm0) == hb
                             and _FINI_ISH.search(d.name) for d in decls)
        # On a tie, prefer the simplest acquisition form. libarchive has both
        # `archive_read_new()` (returns the handle) and `archive_read_open(a, ...)`, and both
        # read as a named constructor — but only the first actually creates anything. A
        # returned handle beats an out-parameter, which beats caller-allocated.
        rank = {"returned": 0, "out_param": 1, "inline": 2}[mode]
        return (-(int(named_init) + int(named_fini)), rank, str(handle))

    pm0 = decls[0].ptr_map if decls else {}
    candidates.sort(key=_quality)

    plans: list = []
    seen_consumers: set = set()
    for handle, inline_base, init_name, fini_name, mode in candidates:
        plans += _plans_for_handle(decls, target, handle, inline_base, init_name,
                                   fini_name, platforms, knobs, seen_consumers, mode)

    # A separate CHAIN pass, because role inference is relative to one handle.
    #
    # `sqlite3_step(sqlite3_stmt*)` consumes a STATEMENT, but a plan built around
    # `sqlite3 *` classifies it as a query and never proposes it. The library's real shape is
    # open -> prepare -> step -> finalize -> close, and no single-handle view can see it.
    plans += _chain_plans(decls, target, platforms, knobs, seen_consumers)
    plans += _free_function_plans(decls, target, platforms, knobs, seen_consumers)
    return plans


def _free_function_plans(decls, target, platforms, knobs, seen) -> list:
    """Entry points with NO handle: a function that takes bytes and returns a status.

    The producer was built entirely around lifecycles — create, consume, destroy — so a
    library whose real surface is free functions got nothing. For zlib we proposed only
    `gz*` plans, because `gzFile` is the only handle it has, while BOTH zlib gold cases
    (`compress2`, `uncompress2`) are free functions. Same for zopfli. Those cases scored
    "NO PLAN for the gold target" against QuartetFuzz at 51.74% and 80.06%.

    A lifecycle is not required to fuzz a parser. What is required is that the fuzzer's
    bytes reach it, and that whatever buffers it needs exist.
    """
    pm = decls[0].ptr_map if decls else {}
    apis = {d.name: to_api(d, None) for d in decls}
    known = {hkey(h, pm) for h in _returned_handles(decls)}
    known |= {b for _, b, _, _ in _inline_handles(decls)}
    known |= {b for _, b, _, _ in _outparam_handles(decls)}
    known.discard("")
    complete = _all_complete(decls)

    out: list = []
    for a in apis.values():
        if a.symbol in seen or not a.params:
            continue
        # No parameter may be a handle this library manages: that is the lifecycle path's
        # job, and duplicating it here would propose the shallow version again.
        if any(hkey(pd.type.name, pm) in known for pd in a.params):
            continue
        # `const` is read from the TYPE STRING: the parser does not always populate
        # TypeRef.const, and a missing flag silently means "no input parameter here".
        if not any(_byte_carrying(pd) and "const" in pd.type.name for pd in a.params):
            continue                     # nothing the fuzzer drives

        slices: list = []
        scratch: list = []
        resources: list = []
        setup: list = []
        teardown: list = []
        args = _stream_bind(a, None, pm, slices, scratch,
                            out_capacity=(knobs.max_len or 4096) * 16,
                            teardown=teardown,
                            complete=complete, apis=apis, resources=resources,
                            setup=setup)
        if args is None or not slices:
            continue

        used_apis = {a.symbol: a}
        for op in setup + teardown:
            # Teardown too. Registering only the setup ops left png_image_free out of the
            # plan's API table, and S2.UNKNOWN_API refused the plan — the gate catching a
            # half-finished change of mine, which is the second time in five minutes.
            if op.api in apis:
                used_apis[op.api] = apis[op.api]

        # A free function that RETURNS a handle still owns a lifetime.
        # `cmsOpenProfileFromMem(const void *, cmsUInt32Number) -> cmsHPROFILE` takes no
        # handle, so it arrives here rather than on the lifecycle path — and this path had
        # no destructor logic at all, so every input leaked a colour profile and
        # LeakSanitizer would report the harness's own bug as a finding.
        ret_key = hkey(a.returns.name, pm)
        drop_ops: list = []
        ret_res: list = []
        # AN OWNED RETURN IS NOT ALWAYS A "HANDLE".
        #
        # `uint8_t *WebPDecodeRGBA(const uint8_t *data, size_t size, int *w, int *h)`
        # returns a decoded image the caller must release with `WebPFree(void *)`. uint8_t
        # is not in `known` — nothing treats a byte pointer as a handle — so no destructor
        # was even looked for, and the harness cast the return to long, added it to the
        # sink, and LEAKED A DECODED IMAGE ON EVERY INPUT.
        #
        # Proposing the free is safe BECAUSE THE GATES CHECK IT. If the pointer is interior
        # rather than owned, freeing it aborts under ASan on the first valid input and D3
        # refuses the plan before any campaign runs. That is the trade this engine is built
        # to make: propose what the evidence suggests, and let a gate that runs decide.
        owned_return = (a.returns.kind == "pointer"
                        and a.returns.name.strip() not in ("void", "")
                        and (ret_key in known
                             or _destroyer_of(ret_key, apis, pm) is not None))
        if owned_return:
            d = _destroyer_of(ret_key, apis, pm)
            if d is not None:
                rid = f"ret_{ret_key}"
                ret_res.append(Resource(rid, TypeRef(a.returns.name, "pointer")))
                drop_ops.append(Op(f"o_drop_{rid}", d.symbol,
                                   [Arg(d.params[0].name, "resource", rid)],
                                   targets=rid, guarded_by=[rid]))
                used_apis[d.symbol] = apis[d.symbol]
        ir = HarnessIR(
            name=f"{target.name}_{a.symbol}", target=target, apis=used_apis,
            slices=slices, scratch=scratch, resources=resources + ret_res,
            sequence=setup + [Op("o_consume", a.symbol, args,
                                 binds=(ret_res[0].id if ret_res else ""))]
                     + teardown + drop_ops,
            knobs=knobs or Knobs(), platforms=platforms, producer="header_graph",
            notes="free function: no handle, caller-owned buffers")
        out.append(ir)
        seen.add(a.symbol)
    return out


def _chain_plans(decls, target, platforms, knobs, seen_consumers) -> list:
    """Plans whose consumer needs a resource that itself needs another resource."""
    if len(decls) < 3:
        return []
    pm = decls[0].ptr_map
    apis = {d.name: to_api(d, None) for d in decls}

    known = {hkey(h, pm) for h in _returned_handles(decls)}
    known |= {b for _, b, _, _ in _inline_handles(decls)}
    known |= {b for _, b, _, _ in _outparam_handles(decls)}
    known.discard("")
    if not known:
        return []

    # Anything that takes a known handle and is neither its constructor nor its destructor
    # is a candidate for "the work", whatever a single-handle role inference called it.
    makers = set()
    for b in known:
        got = _producer_of(b, apis, pm)
        if got:
            makers.add(got[0].symbol)
        d = _destroyer_of(b, apis, pm)
        if d:
            makers.add(d.symbol)

    out: list = []
    for a in apis.values():
        if a.symbol in makers or a.symbol in seen_consumers or not a.params:
            continue
        if hkey(a.params[0].type.name, pm) not in known:
            continue
        chain = _resource_chain(a, apis, pm, known)
        if not chain or len(chain["creates"]) < 2:
            continue

        slices: list = []
        seq: list = []
        resources: list = []
        used = {a.symbol}

        # Slice allocation is deferred to a second pass. Assigning the remainder to the
        # first byte-carrying parameter encountered gave sqlite3_open's FILENAME the whole
        # input and left sqlite3_prepare's SQL text as literal 0 — so prepare always
        # failed, the statement stayed NULL, and the guarded sqlite3_step never ran. The
        # plan compiled, passed the static gates, and executed nothing. That is the libcue
        # shape: 61M executions at cov:4, with every gate green.
        pending: list = []               # (arg_list, param_name) awaiting a slice
        pending_len: list = []           # (arg_list, len_param, buffer_param)

        for i, c in enumerate(chain["creates"]):
            api, mode, rid = c["api"], c["mode"], c["rid"]
            base = hkey_base_of(rid)
            lens = {ln: buf for buf, ln in api.contract.length_delimited}
            cargs = []
            for q in api.params:
                qb = hkey(q.type.name, pm)
                inner = chain["resolved"].get(qb)
                if q.type.name.count("*") == 2 and \
                        hkey(q.type.name.replace("*", "").strip(), pm) == base:
                    cargs.append(Arg(q.name, "resource", rid))
                elif inner and inner["rid"] != rid:
                    cargs.append(Arg(q.name, "resource", inner["rid"]))
                elif is_callback(q.type.name, pm) or q.type.name.count("*") >= 2:
                    cargs.append(Arg(q.name, "literal", value=0))
                elif q.name in lens:
                    cargs.append(Arg(q.name, "literal", value=0))   # may become length_of
                    pending_len.append((cargs, q.name, lens[q.name]))
                elif _byte_carrying(q) and not _path_like(q.name):
                    cargs.append(Arg(q.name, "literal", value=0))   # replaced below
                    pending.append((cargs, q.name))
                else:
                    cargs.append(Arg(q.name, "literal", value=0))
            resources.append(Resource(rid, TypeRef(f"{base} *", "pointer"),
                                      storage="out_param" if mode == "out_param"
                                      else "handle"))
            seq.append(Op(f"o_make{i}", api.symbol, cargs, binds=rid,
                          guarded_by=[chain["creates"][i - 1]["rid"]] if i else []))
            used.add(api.symbol)

        wargs = []
        clens = {ln: buf for buf, ln in a.contract.length_delimited}
        for q in a.params:
            inner = chain["resolved"].get(hkey(q.type.name, pm))
            if inner:
                wargs.append(Arg(q.name, "resource", inner["rid"]))
            elif q.name in clens:
                wargs.append(Arg(q.name, "literal", value=0))
                pending_len.append((wargs, q.name, clens[q.name]))
            elif _byte_carrying(q) and not _path_like(q.name):
                wargs.append(Arg(q.name, "literal", value=0))       # replaced below
                pending.append((wargs, q.name))
            else:
                wargs.append(Arg(q.name, "literal", value=0))

        if not pending:
            continue                     # nothing the fuzzer drives: not a harness

        # The DEEPEST candidate wins the remainder, because `pending` is built outermost
        # create first and the consumer last: the bytes should land as close to the call
        # under test as the API allows. Shallower ones still get input — a chain whose
        # intermediate constructor is starved produces no handle at all — but bounded, so
        # the byte budget is not spent on setup.
        sliced: set = set()
        for k, (arglist, pname) in enumerate(pending):
            deepest = (k == len(pending) - 1)
            slices.append(InputSlice(pname, SLICE_CSTRING, remainder=deepest, min_len=1,
                                     max_len=0 if deepest else 256))
            sliced.add(pname)
            for idx, ex in enumerate(arglist):
                if ex.param == pname:
                    arglist[idx] = Arg(pname, "input", pname)
                    break

        # A length parameter left at 0 is the same silent failure one level down.
        # `sqlite3_prepare(db, sql, 0, &stmt, 0)` says "read zero bytes of SQL": the call
        # returns OK, produces NO statement, and the guarded consumer never fires. The
        # harness was correct in structure and inert in fact.
        for arglist, lname, bufname in pending_len:
            if bufname not in sliced:
                continue
            for idx, ex in enumerate(arglist):
                if ex.param == lname:
                    arglist[idx] = Arg(lname, "length_of", bufname)
                    break

        last = chain["creates"][-1]["rid"]
        seq.append(Op("o_consume", a.symbol, wargs, guarded_by=[last]))

        for j, d in enumerate(chain["destroys"]):
            seq.append(Op(f"o_drop{j}", d["api"].symbol,
                          [Arg(d["api"].params[0].name, "resource", d["rid"])],
                          targets=d["rid"], guarded_by=[d["rid"]]))
            used.add(d["api"].symbol)

        out.append(_make_plan(target, a, "_chain", apis, used, slices, seq, resources,
                              knobs or Knobs(), platforms, None, None))
        seen_consumers.add(a.symbol)
    return out


# Every spelling of "a byte" a C API uses for a buffer. Restricting this to char/void/
# unsigned char silently excluded `const uint8_t *`, which is what the demo library and a
# great many real ones use — the plan then bound nothing and the entry point was dropped.
# ALIASES ARE READ FROM THE HEADER, NOT GUESSED FROM A LIST.
#
# BYTE_BASES below is a list of SPELLINGS, and it grew every time a library used its own:
# Bytef for zlib, guchar for glib, xmlChar for libxml2, png_byte for libpng. leptonica
# spells a byte `l_uint8`, and because that spelling was missing, `pixReadMem(const l_uint8
# *, size_t)` did not look like it takes bytes at all. The producer concluded the entry
# point had no input, went looking for a SETTER to feed the handle, and found
# `boxaPlotSides` — a plotting function. S1 and S2 refused the result, correctly, and the
# case reported "all plans refused by a static gate".
#
# The header already says `typedef unsigned char l_uint8;`. Reading that is not a guess,
# and it retires the list rather than extending it once per library.
_SCALAR_ALIASES: dict = {}


def _resolve_alias(name: str) -> str:
    """Follow a scalar typedef to the type it really is, with a depth cap for cycles."""
    seen = 0
    while name in _SCALAR_ALIASES and seen < 8:
        name = _SCALAR_ALIASES[name]
        seen += 1
    return name


BYTE_BASES = ("char", "void", "unsigned char", "signed char", "uint8_t", "int8_t",
              "u_char", "uchar", "byte", "BYTE", "guchar",
              # Library typedefs for "a byte". zlib spells it `Bytef`, and without this
              # `const Bytef *source` was not recognised as the input at all — so
              # uncompress2, the gold target, got no plan even after free functions were
              # supported.
              "Bytef", "Byte", "uch", "Bytefp", "u8", "U8", "UInt8", "uint8", "guint8",
              "gchar", "xmlChar", "JOCTET", "png_byte", "Uint8")


def _scalar_typedefs(stmts: list) -> dict:
    """`typedef unsigned char l_uint8;` -> {"l_uint8": "unsigned char"}.

    Pointer typedefs are _typedef_map's job and function pointers are is_callback's; this
    is only the plain aliases, which is where byte spellings live.
    """
    raw: dict = {}
    for st in stmts:
        if not st.startswith("typedef ") or "(" in st or "*" in st or "{" in st:
            continue
        m = re.match(r"^typedef\s+(.+?)\s+([A-Za-z_]\w*)$", st.strip())
        if not m:
            continue
        under = " ".join(m.group(1).split())
        if under and under != m.group(2):
            raw[m.group(2)] = under

    # ONLY BYTE ALIASES ARE KEPT, and the first attempt at this taught the reason.
    #
    # Resolving every scalar typedef put `typedef struct _Jbig2Ctx Jbig2Ctx;` in the table,
    # so base_type("Jbig2Ctx") answered "struct _Jbig2Ctx" — after the qualifier strip had
    # already run — and handles stopped comparing equal to themselves. Nine tests failed,
    # which is what those tests are for.
    #
    # The problem this solves is byte SPELLINGS, so nothing else needs to be in the table.
    out: dict = {}
    for alias, under in raw.items():
        seen, cur = 0, under
        while cur in raw and seen < 8:
            cur, seen = raw[cur], seen + 1
        # NEVER `void`, even though `void` is in BYTE_BASES for the sake of
        # `const void *data` buffers.
        #
        # `typedef void de265_decoder_context;` is the OPAQUE HANDLE idiom — libcurl spells
        # it `typedef void CURL;` — and resolving it stripped the handle's identity. The
        # returned-handle scan then found nothing, _free_function_plans stopped skipping
        # de265_push_data because its first parameter no longer looked like a handle, and
        # the stream binder bound a SCRATCH BUFFER cast to de265_decoder_context* as the
        # decoder. Every static gate passed and the emitted C compiled: a type-confused
        # harness with a clean certificate, which is the worst outcome this engine can
        # produce.
        #
        # This is P3.NOMINAL again — a void typedef is nominal, not structural — broken by
        # my own alias resolution hours after it was fixed.
        if cur in BYTE_BASES and cur != "void":
            out[alias] = cur
    return out


_SIZE_ISH = re.compile(r"(?:^|_)(size|len|length|nbytes|count|n)$", re.I)


def _byte_carrying_ty(ty: str) -> bool:
    """_byte_carrying, on a raw declaration spelling rather than a built TypeRef.

    infer_role runs before to_api, so it has (type, name) pairs and no TypeRef to consult.
    Kept beside its twin so the two cannot drift."""
    if "*" in ty:
        return ty.count("*") == 1 and base_type(ty) in BYTE_BASES
    return ty.strip() in _CONST_BYTE_PTRS


def _byte_carrying(q) -> bool:
    """A parameter the fuzzer can fill with bytes: a single pointer to a character or void
    type. Deliberately narrow — S2 blocks bytes bound to a struct pointer the library will
    dereference, and this must not propose what that gate exists to refuse."""
    if "*" in q.type.name:
        return q.type.name.count("*") == 1 and base_type(q.type.name) in BYTE_BASES
    # The star may be inside a typedef. to_api expands ONLY const byte pointees into
    # `resolved`, so reaching this line at all means the type is a const buffer alias and
    # not one of the void-pointer handles that must stay nominal.
    return bool(q.type.resolved) and base_type(q.type.resolved) in BYTE_BASES


def _path_like(name: str) -> bool:
    """A filename parameter must never receive fuzzer bytes.

    Two reasons, and the second is the serious one. It wastes the budget: a random filename
    fails to open and the rest of the lifecycle never runs. And a harness that opens a path
    built from attacker-controlled bytes CREATES OR READS ARBITRARY FILES in its working
    directory — our own engine emitting that would be a real defect, not a stylistic one.
    NULL is passed instead; libraries that accept it (sqlite3_open gives a private temporary
    database) proceed, and those that do not fail cleanly at the constructor where D3 sees
    it, rather than silently deep in the campaign."""
    return bool(_PATH_PARAM.search(name or ""))


_PATH_PARAM = re.compile(r"(?:^|_)(file|filename|fname|path|pathname|dir|dirname|uri|url)"
                         r"(?:$|_|name)", re.I)


def hkey_base_of(rid: str) -> str:
    """The type a resource id names. Ids are the bare type name now; the `r_` form is
    accepted so older plans on disk still load."""
    return rid[2:] if rid.startswith("r_") else rid


_FEED_ISH = re.compile(r"set_input|set_source|set_buffer|set_data|feed|push|"
                       r"input|source|supply|provide|append_input", re.I)


# Destroy verbs ANYWHERE in the name. `close` and `delete` were missing, so
# `cmsCloseProfile` was not recognised and every lcms2 profile leaked — LeakSanitizer then
# reports the harness's own bug on every input. The candidate must already take exactly the
# handle and not take it const, so a loose name match here is safe.
_DESTROY_ANYWHERE = re.compile(
    r"destroy|dispose|release|free|cleanup|teardown|close|delete|dealloc|unref", re.I)
# Parameter names that select a MODE rather than carry data. Deliberately narrow: driving
# an arbitrary integer from fuzzer input can violate an API's contract, and a contract
# violation is a crash the harness owns.
_MODEISH = re.compile(r"^(?:btype|type|mode|level|method|format|kind|variant|flags?|"
                      r"strategy|algo(?:rithm)?|encoding|final)$", re.I)
_CONFIG_INIT = re.compile(r"init|setup|default|reset|prepare", re.I)
_SIZEISH = re.compile(r"^(?:size_t|unsigned long|unsigned int|uLong|uLongf|size|"
                      r"u?int(?:8|16|32|64)_t|long|int)$")
# A library's OWN spelling of an integer. `cmsOpenProfileFromMem(const void *MemPtr,
# cmsUInt32Number dwSize)` — dwSize is the profile's length and was bound to 0, so lcms2 was
# told the profile is zero bytes and returned immediately, 21 million times for 1.95% of the
# library. The TYPE is unrecognisable across libraries; the NAME is not.
_SIZE_NAME = re.compile(r"^(?:\w*(?:size|len|length|count|bytes|num|n)\w*)$", re.I)


def _is_size_param(pd) -> bool:
    """A scalar that carries a length, by type or by name."""
    return bool(_SIZEISH.match(base_type(pd.type.name))
                or (_SIZE_NAME.match(pd.name or "")
                    and "*" not in pd.type.name))


def _stream_bind(api, handle, pm, slices, scratch, out_capacity=65536, teardown=None,
                 complete=frozenset(), apis=None, resources=None, setup=None):
    """Bind a CALLER-OWNS-THE-BUFFERS entry point, or return None.

    Three libraries in the QuartetFuzz benchmark are this shape and we scored nothing on all
    three, because every parameter that is not a plain buffer was bound to 0:

        uncompress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong *sourceLen)
        ZopfliDeflate(..., const unsigned char *in, size_t insize, ..., size_t *outsize)
        BrotliDecoderDecompressStream(state, size_t *available_in,
                                      const uint8_t **next_in, size_t *available_out,
                                      uint8_t **next_out, size_t *total_out)

    The rules, in order, and `const` is the load-bearing signal throughout:

      * `const BYTE *`            the input                      -> the fuzzer's slice
      * `const BYTE **`           a cursor INTO the input        -> a ptr scratch
      * `BYTE *`   (non-const)    an output buffer               -> a bytes scratch
      * `BYTE **`  (non-const)    an output cursor               -> a ptr scratch
      * `SIZE *` after a buffer   that buffer's size, by address -> a size scratch
      * `SIZE`     after a buffer that buffer's size, by value   -> length_of

    Returns a list of Arg, or None when the signature has a parameter this cannot explain —
    refusing rather than binding 0 and calling it a harness.
    """
    args, made = [], False
    last_buf = None                      # (kind, id) the next size parameter belongs to

    def _tail(nm):
        parts = re.split(r"[_\W]+|(?<=[a-z])(?=[A-Z])", nm or "")
        return parts[-1].lower() if parts else ""

    # A size parameter does not have to FOLLOW its buffer. brotli declares
    # `available_in` before `next_in` and `available_out` before `next_out`, so
    # left-to-right pairing gave the input length 0 and the decoder saw no bytes at all.
    # Names carry the association: the trailing token matches.
    pending: dict = {}        # size param -> the buffer param it names
    bound: dict = {}          # buffer param -> ("slice"|"scratch", id)
    size_types: dict = {}
    by_tail: dict = {}
    for q in api.params:
        stars_q = q.type.name.count("*")
        if base_type(q.type.name) in BYTE_BASES and stars_q >= 1:
            by_tail.setdefault(_tail(q.name), []).append(q.name)

    for pd in api.params:
        ty, nm = pd.type.name, pd.name
        stars = ty.count("*")
        base = base_type(ty)
        is_byte = base in BYTE_BASES
        const = "const" in ty

        if handle and hkey(ty, pm) == hkey(handle, pm):
            args.append(Arg(nm, "resource", "h")); last_buf = None; continue
        if is_callback(ty, pm):
            args.append(Arg(nm, "literal", value=0)); last_buf = None; continue

        if is_byte and stars == 1 and const:
            sid = nm
            slices.append(InputSlice(sid, SLICE_BYTES, remainder=True, min_len=1))
            args.append(Arg(nm, "input", sid)); last_buf = ("slice", sid); made = True
            bound[nm] = last_buf
        elif is_byte and stars == 2 and const:
            src = next((x.id for x in slices), None)
            if src is None:
                src = nm + "_in"
                slices.append(InputSlice(src, SLICE_BYTES, remainder=True, min_len=1))
                made = True
            sid = f"cur_{nm}"
            scratch.append(Scratch(sid, SCRATCH_PTR, c_type=ty.replace("*", "*", 1).rstrip("*").strip() + " *",
                                   init_from=src))
            args.append(Arg(nm, "scratch_addr", sid)); last_buf = ("slice", src)
            bound[nm] = last_buf
        elif is_byte and stars == 1:
            sid = f"outbuf_{nm}"
            scratch.append(Scratch(sid, SCRATCH_BYTES, capacity=out_capacity))
            args.append(Arg(nm, "scratch", sid)); last_buf = ("scratch", sid)
            bound[nm] = last_buf
        elif is_byte and stars == 2:
            # `T **` non-const is one of two things and the signature alone cannot say
            # which: a CURSOR into a buffer the caller supplies (brotli's `next_out`,
            # paired with `available_out`), or a pointer the LIBRARY allocates and the
            # caller frees (zopfli's `out`, documented "must be freed after use").
            #
            # The tell is whether the API also hands us a capacity. Guessing wrong in the
            # allocate direction is fatal — the library reallocs storage it never malloc'd —
            # so absent a capacity we assume the library allocates, which is the safe way to
            # be wrong.
            has_capacity = any(re.search(r"avail|capacit|remain|room", q.name, re.I)
                               for q in api.params)
            if has_capacity:
                buf = f"outbuf_{nm}"
                scratch.append(Scratch(buf, SCRATCH_BYTES, capacity=out_capacity))
                sid = f"cur_{nm}"
                scratch.append(Scratch(sid, SCRATCH_PTR,
                                       c_type=ty.rstrip("*").strip() + " *",
                                       init_from=buf))
                args.append(Arg(nm, "scratch_addr", sid)); last_buf = ("scratch", buf)
                bound[nm] = last_buf
            else:
                sid = f"own_{nm}"
                scratch.append(Scratch(sid, SCRATCH_PTR,
                                       c_type=ty.rstrip("*").strip() + " *", owns=True))
                args.append(Arg(nm, "scratch_addr", sid)); last_buf = None
        elif stars == 1 and _SIZEISH.match(base) and (size_types.__setitem__(nm, ty.rstrip("*").strip()) or True):
            # A size by address. Prefer the buffer whose NAME it shares a tail with; else
            # the buffer before it; else it is a pure OUT size the library writes (zopfli's
            # `outsize`) and starts at 0.
            kind, ref = last_buf if last_buf else (None, None)
            mate = by_tail.get(_tail(nm))
            if mate:
                mname = mate[0]
                pending[nm] = mname          # resolved once the buffer itself is bound
                args.append(Arg(nm, "scratch_addr", f"len_{nm}"))
                continue
            sid = f"len_{nm}"
            scratch.append(Scratch(sid, SCRATCH_SIZE,
                                   capacity=(out_capacity if kind == "scratch" else 0),
                                   c_type=ty.rstrip("*").strip(),
                                   init_from=(ref if kind == "slice" else "")))
            args.append(Arg(nm, "scratch_addr", sid))
        elif stars == 0 and _is_size_param(pd) and last_buf and last_buf[0] == "slice":
            args.append(Arg(nm, "length_of", last_buf[1])); last_buf = None
        elif stars == 0 and _MODEISH.search(nm or ""):
            # A MODE SELECTOR. `ZopfliDeflate(..., int btype, int final, ...)` picks between
            # stored, fixed-Huffman and dynamic-Huffman blocks — three entirely different
            # code paths. Pinned at 0 the harness only ever exercised stored blocks: 3.04%
            # of zopfli against a gold harness at 85.7%.
            #
            # A bounded byte, consumed before the remainder, so the fuzzer chooses the mode
            # and the input still drives the parse.
            sid = f"mode_{nm}"
            slices.insert(0, InputSlice(sid, SLICE_U8, remainder=False, max_len=1))
            args.append(Arg(nm, "input", sid)); last_buf = None
        elif stars == 0:
            args.append(Arg(nm, "literal", value=0)); last_buf = None
        elif (stars == 1 and hkey(ty, pm) in complete and apis is not None
              and resources is not None and setup is not None):
            # A CONFIGURATION STRUCT the caller owns and an initialiser fills.
            # `ZopfliDeflate(const ZopfliOptions *options, ...)` needs
            # `ZopfliInitOptions(&options)` first; the gold harness makes exactly that call.
            # Refusing the whole plan for it — which is what happened — loses the entry
            # point entirely, and passing 0 would have the library read a null config.
            base_t = hkey(ty, pm)
            # The verb can sit ANYWHERE in the name. Our init-ish patterns anchor it at the
            # end (`_init`, `initialize`), so `ZopfliInitOptions` — Zopfli + Init + Options —
            # matched nothing and the whole entry point was refused. A loose match is safe
            # here because the candidate must already take exactly one parameter, of exactly
            # this config type.
            init = next((x for x in apis.values()
                         if len(x.params) == 1
                         and hkey(x.params[0].type.name, pm) == base_t
                         and _CONFIG_INIT.search(x.symbol)), None)
            if init is None:
                # NO INITIALISER MEANS IT IS AN OUT-PARAMETER, NOT A CONFIG.
                #
                # `json_t *json_loadb(const char *buf, size_t n, size_t flags,
                #  json_error_t *error)` — the caller owns an error struct and the LIBRARY
                # fills it with why the parse failed. There is nothing to initialise, so
                # requiring an initialiser refused the whole plan and jansson's entry point
                # produced nothing at all.
                #
                # `const` is what separates the two. A `const T *` is an INPUT the library
                # reads, and handing it a zeroed struct is a guess about a contract we
                # cannot see — ZopfliDeflate needs ZopfliInitOptions first, and that case
                # must keep refusing. A non-const `T *` is a slot for the callee to write,
                # and declaring it and passing its address is exactly what a caller does.
                if "const" in ty:
                    return None
                rid = f"out_{nm}"
                resources.append(Resource(rid, TypeRef(base_t, "struct"), storage="out",
                                          init_fields=dict(_REQ_INIT.get(base_t) or {})))
                args.append(Arg(nm, "resource", rid))
                last_buf = None
                # AND FREE IT WHEN THE LIBRARY OFFERS A FREE.
                #
                # `png_image_begin_read_from_memory(png_imagep image, ...)` — the caller
                # declares a png_image and the library hangs an opaque control block off it
                # that `png_image_free(png_imagep)` releases. jansson's json_error_t has no
                # such call and needs none, so looking for one and finding nothing is the
                # correct outcome there; skipping the search entirely made libpng gate-pass,
                # compile, and leak on every input.
                #
                # Same rule as the error accessor: half the pair is worse than neither half.
                # TEARDOWN, not setup. Appending to `setup` put png_image_free BEFORE
                # png_image_begin_read_from_memory — S1.USE_AFTER_DESTROY caught it at once,
                # which is the gate doing precisely its job on my mistake.
                if teardown is not None:
                    d = _destroyer_of(base_t, apis, pm)
                    if d is not None and len(d.params) == 1:
                        teardown.append(Op(f"o_drop_{rid}", d.symbol,
                                           [Arg(d.params[0].name, "resource", rid)],
                                           targets=rid))
                continue
            rid = f"cfg_{nm}"
            resources.append(Resource(rid, TypeRef(base_t, "struct"), storage="inline",
                                      init_fields=dict(_REQ_INIT.get(base_t) or {})))
            setup.append(Op(f"o_cfg_{nm}", init.symbol,
                            [Arg(init.params[0].name, "resource", rid)], binds=rid))
            args.append(Arg(nm, "resource", rid)); last_buf = None
        else:
            return None                  # a pointer this cannot explain: refuse the plan
    # Resolve the sizes that named their buffer: an input buffer contributes its length,
    # an output buffer its capacity.
    for size_name, buf_name in pending.items():
        owner = bound.get(buf_name)
        if owner is None:
            scratch.append(Scratch(f"len_{size_name}", SCRATCH_SIZE, capacity=0,
                                   c_type=size_types.get(size_name, "size_t")))
            continue
        kind, ref = owner
        scratch.append(Scratch(f"len_{size_name}", SCRATCH_SIZE,
                               capacity=(out_capacity if kind == "scratch" else 0),
                               c_type=size_types.get(size_name, "size_t"),
                               init_from=(ref if kind == "slice" else "")))
    return args if made else None


def _feeder_for(handle, cons, apis: dict, pm: dict):
    """An API that DELIVERS bytes into the handle, for a target that takes none itself.

    The gap the QuartetFuzz benchmark exposed. `yaml_parser_load(parser, document)` carries
    no buffer: the bytes arrive earlier, through
    `yaml_parser_set_input_string(parser, input, size)`. Our producer had no way to express
    that, so the only plans it could make for the entry point either fed fuzzer bytes to the
    OUT parameter — S2 refused them, correctly — or called the setter and never called the
    parser at all. The gold OSS-Fuzz harness for this case reaches 77.7% of libyaml's lines;
    ours reached the entry point with no input at all.

    This is a whole class, not one library: libyaml, zlib's z_stream, OpenSSL BIOs, and any
    API where configuration and consumption are separate calls.

    Returns (api, buffer_param, length_param_or_None), or None.
    """
    if not handle:
        return None
    hk = hkey(handle, pm)
    best = None
    for a in apis.values():
        if a.symbol == cons.symbol or a.role in (ROLE_CREATE, ROLE_DESTROY):
            continue
        if not a.params or hkey(a.params[0].type.name, pm) != hk:
            continue
        buf = None
        for pd in a.params[1:]:
            if (pd.type.name.count("*") == 1
                    and base_type(pd.type.name) in BYTE_BASES):
                buf = pd.name
                break
        if buf is None:
            continue
        lens = {ln: b for b, ln in a.contract.length_delimited}
        ln = next((n for n, b in lens.items() if b == buf), None)
        # A named feeder beats an unnamed one; a (buffer, length) pair beats a bare pointer,
        # because the length is what lets the fuzzer control how much is read.
        score = (0 if _FEED_ISH.search(a.symbol) else 1, 0 if ln else 1, a.symbol)
        if best is None or score < best[0]:
            best = (score, a, buf, ln)
    return (best[1], best[2], best[3]) if best else None


_FINISH_ISH = re.compile(r"complete|finish|finalize|finalise|flush|end_|_end$|commit|"
                         r"done|close_input|eof", re.I)


def _finisher_for(handle, cons, apis: dict, pm: dict, used: set):
    """A call the library needs AFTER the target, to flush what the target buffered.

    The mirror of `_feeder_for`, and the same class of gap. `yajl_parse(hand, text, len)`
    lexes as much as it can and leaves the rest buffered; `yajl_complete_parse(hand)` is
    what forces end-of-input handling. Without it a yajl harness ran 91,977,013 executions
    for 36.98% of lines against a gold harness at 69.1%, and every one of the completion
    paths — the ones that decide whether a truncated document is an error — was unreachable.

    Deliberately narrow: it must take ONLY the handle, so it cannot need arguments we would
    have to invent, and it must not be the destructor.
    """
    if not handle:
        return None
    hk = hkey(handle, pm)
    best = None
    for a in apis.values():
        if a.symbol == cons.symbol or a.symbol in used or a.role == ROLE_DESTROY:
            continue
        if len(a.params) != 1 or hkey(a.params[0].type.name, pm) != hk:
            continue
        if not _FINISH_ISH.search(a.symbol) or _FINI_ISH.search(a.symbol):
            continue
        if best is None or a.symbol < best.symbol:
            best = a
    return best


_ERROR_ACCESSOR_ISH = re.compile(
    r"(?:_|(?<=[a-z]))(get_error|last_error|error_string|errorstring|geterror|"
    r"lasterror|strerror|error_message|errmsg)\w*$", re.I)
_ERROR_FREE_ISH = re.compile(
    r"(?:_|(?<=[a-z]))(free_error|error_free|free_errmsg|release_error)\w*$", re.I)


def _error_accessor_for(handle, cons, apis: dict, pm: dict, used: set, slice_id: str):
    """The accessor that renders WHY the last call failed, and the call that frees it.

    MEASURED, not guessed. yajl is the one case in run-009 behind gold — 65.12 against
    69.1 — and the deficit is almost entirely one file: yajl.c at 45.26% while the lexer
    sits at 77%. The uncovered functions are `yajl_render_error_string` (72 lines),
    `yajl_status_to_string`, `yajl_get_bytes_consumed` and `yajl_get_error` itself. Roughly
    a hundred lines that are reachable ONLY when the caller asks why a parse failed.

    A fuzzer drives the failure path constantly. The harness simply never asks.

    The emitted lifecycle — alloc, parse, complete, free — is CORRECT, and every gate passes
    on it. The coverage it misses is coverage no correct lifecycle reaches, which is why no
    amount of campaign time closed the gap.

    THE PAIRING IS NOT OPTIONAL. `yajl_get_error` returns owned memory and `yajl_free_error`
    releases it. Without the free, the harness leaks on every failing input, and under
    LeakSanitizer every finding would be the harness's own — exactly what S1 exists to
    block. So this returns BOTH calls or neither.

    NOT GATED ON FAILURE, deliberately. Running the accessor only when the target reports an
    error would need a new Op field and a rule for what counts as non-OK — and that
    convention is library-specific (`yajl_status_ok` is 0). Assuming "non-zero is failure"
    would be inventing a contract rather than reading one, which is the thing this engine
    refuses to do. Calling the accessor after a SUCCESSFUL parse is legal and still reaches
    the renderer, so the unconditional form costs nothing and assumes nothing.

    Returns (accessor, accessor_args, freer, freer_args) or None.
    """
    if not handle:
        return None
    hk = hkey(handle, pm)

    def _binds(a):
        """Every parameter but the handle must come from something the plan ALREADY has.

        No inventing values. The input slice and its length are already bound at the
        consuming call; a plain scalar gets 1, which for a `verbose` flag selects the
        longer message and therefore more of the renderer. A parameter that is neither is
        a parameter we would have to guess, and the candidate is dropped instead.
        """
        # The (ptr,len) pairing comes from the DECLARED contract, not from the type.
        # Binding by "is it an integer" put `int verbose` on the length of the input slice,
        # because a scalar next to a buffer looks like a length until you read which
        # parameter the contract actually pairs.
        lens = {ln: buf for buf, ln in a.contract.length_delimited}
        out, seen_handle = [], False
        for pd in a.params:
            if not seen_handle and hkey(pd.type.name, pm) == hk:
                out.append(Arg(pd.name, "resource", "h"))
                seen_handle = True
            elif slice_id and pd.name in lens:
                out.append(Arg(pd.name, "length_of", slice_id))
            elif slice_id and _byte_carrying(pd) and not _path_like(pd.name):
                out.append(Arg(pd.name, "input", slice_id))
            elif pd.type.kind != "pointer":
                # A plain scalar gets 0, the conservative value.
                #
                # It was 1, chosen so a `verbose` flag would select the longer message and
                # reach more of the renderer. MEASURED: that took yajl from 65.12% to
                # 0.00%. yajl_render_error_string's verbose branch writes up to about a
                # hundred bytes into `char text[72]`, guarded by an assert that fires after
                # the overflow, and the corrupted stack made the paired free segfault on
                # the third execution.
                #
                # The instinct — pick the argument that reaches more code — is the one this
                # engine exists to refuse. An argument is chosen because the contract allows
                # it, not because it looks productive. 0 is what a caller who has not
                # thought about it passes, and it is what we pass.
                out.append(Arg(pd.name, "literal", value=0))
            else:
                return None
        return out if seen_handle else None

    best = None
    for a in apis.values():
        if a.symbol == cons.symbol or a.symbol in used or a.role == ROLE_DESTROY:
            continue
        if not _ERROR_ACCESSOR_ISH.search(a.symbol):
            continue
        if a.returns.kind != "pointer" or a.returns.name.strip() in ("void", ""):
            continue
        args = _binds(a)
        if args is None:
            continue
        if best is None or a.symbol < best[0].symbol:
            best = (a, args)
    if best is None:
        return None
    acc, acc_args = best

    # The freer. It must take the handle and the accessor's return type, and it must be
    # named as a release of an error. Without it there is no plan: see the docstring.
    rk = hkey(acc.returns.name, pm)
    for f in apis.values():
        if f.symbol in (acc.symbol, cons.symbol) or f.symbol in used:
            continue
        if not _ERROR_FREE_ISH.search(f.symbol):
            continue
        if not any(hkey(q.type.name, pm) == rk for q in f.params):
            continue
        fargs, ok = [], False
        for pd in f.params:
            if hkey(pd.type.name, pm) == hk and not ok:
                fargs.append(Arg(pd.name, "resource", "h"))
            elif hkey(pd.type.name, pm) == rk and not ok:
                fargs.append(Arg(pd.name, "resource", "err"))
                ok = True
            else:
                fargs = None
                break
        if fargs and ok:
            return acc, acc_args, f, fargs
    return None


def _producer_of(base: str, apis: dict, pm: dict):
    """What creates a resource of this type, and how.

    Three shapes, matching the three C acquisition forms:
      * returns it            `sqlite3_stmt *f(...)`
      * writes it back        `int sqlite3_prepare_v2(db, sql, n, &stmt, &tail)`
      * initialises in place  `int yaml_parser_initialize(&p)`
    Returns (api, mode) or None.
    """
    # RANK candidates, do not require a name to match.
    #
    # `sqlite3_prepare_v2(db, sql, n, &stmt, &tail)` is what creates a statement, and it is
    # called neither "create" nor "open" — so an init-ish name requirement found no producer
    # and every statement-consuming plan was born broken. Meanwhile the returned-pointer
    # branch took the FIRST match and chose `sqlite3_context_db_handle`, an accessor, as the
    # connection's constructor.
    #
    # Both branches now score: a creation-shaped name first, then fewer parameters (a
    # constructor takes less than an accessor chain), then the name, for determinism.
    def _score(a) -> tuple:
        named = 0 if (_INIT_ISH.search(a.symbol) or _MAKE_ISH.search(a.symbol)) else 1
        return (named, len(a.params), a.symbol)

    rets = [a for a in apis.values()
            if a.returns.kind == "pointer" and hkey(a.returns.name, pm) == base
            and not any(hkey(q.type.name, pm) == base for q in a.params)]
    outs = [a for a in apis.values()
            if any(q.type.name.count("*") == 2
                   and hkey(q.type.name.replace("*", "").strip(), pm) == base
                   for q in a.params)]

    # An out-parameter constructor is preferred over a bare returned pointer when the
    # returned one does not look like a constructor: `sqlite3_open(path, &db)` beats
    # `sqlite3_context_db_handle(ctx)`.
    best_ret = min(rets, key=_score) if rets else None
    best_out = min(outs, key=_score) if outs else None
    if best_out is not None and (best_ret is None or _score(best_out)[0] < _score(best_ret)[0]):
        return best_out, "out_param"
    if best_ret is not None:
        return best_ret, "returned"
    if best_out is not None:
        return best_out, "out_param"
    return None


def _destroyer_of(base: str, apis: dict, pm: dict):
    return next((a for a in apis.values()
                 if a.role == ROLE_DESTROY and len(a.params) == 1
                 and hkey(a.params[0].type.name, pm) == base), None) or \
        next((a for a in apis.values()
              if _FINI_ISH.search(a.symbol) and len(a.params) == 1
              and hkey(a.params[0].type.name, pm) == base), None) or \
        next((a for a in apis.values()
              # A destroy verb MID-NAME. `cmsCloseProfile(cmsHPROFILE)` matched neither the
              # role nor the end-anchored pattern, so every lcms2 profile leaked.
              if _DESTROY_ANYWHERE.search(a.symbol) and len(a.params) == 1
              and "const" not in a.params[0].type.name
              and hkey(a.params[0].type.name, pm) == base), None) or \
        next((a for a in apis.values()
              # A GENERIC `free(void *)` FREES ANY POINTER THIS LIBRARY RETURNED.
              #
              # `void WebPFree(void *ptr)` releases what `uint8_t *WebPDecodeRGBA(...)`
              # returned, and matching by type finds nothing because `void` is not
              # `uint8_t`. The harness then cast the returned pointer to long, added it to
              # the sink, and LEAKED A DECODED IMAGE ON EVERY INPUT — under LeakSanitizer
              # every finding would be the harness's own, which is what S1 exists to stop.
              #
              # Deliberately last, so a typed destructor always wins: this only fires when
              # the library offers nothing more specific. It must also be NAMED as a free,
              # or `void *`-taking helpers like a callback registrar would qualify.
              #
              # _DESTROY_ANYWHERE, not _FINI_ISH: the end-anchored pattern needs the verb
              # after `_` or a lowercase letter, and `WebPFree` has an uppercase P before
              # it. Same shape as BrotliDecoderDestroyInstance.
              if _DESTROY_ANYWHERE.search(a.symbol) and len(a.params) == 1
              and a.params[0].type.name.count("*") == 1
              and base_type(a.params[0].type.name) == "void"
              and a.returns.name.strip() in ("void", "")), None)


def _resource_chain(cons, apis: dict, pm: dict, known: set, depth: int = 3) -> Optional[dict]:
    """Resolve every resource a consumer needs, and what produces each of THOSE.

    `sqlite3_step(sqlite3_stmt*)` needs a statement; a statement comes from
    `sqlite3_prepare_v2(db, sql, n, &stmt, &tail)`, which needs a connection; a connection
    comes from `sqlite3_open(path, &db)`. That is a three-link chain, and modelling only one
    handle is why 40 sqlite plans were born broken and failed D3 by crashing on valid input.

    Bounded at `depth`, and returns None rather than a partial chain: a lifecycle that is
    half-resolved produces a harness that passes the static gates and dereferences null.
    """
    needed = [hkey(q.type.name, pm) for q in cons.params
              if q.type.kind == "pointer" and hkey(q.type.name, pm) in known]
    if not needed:
        return None

    creates: list = []
    destroys: list = []
    resolved: dict = {}

    def resolve(base: str, level: int) -> bool:
        if base in resolved:
            return True
        if level > depth:
            return False
        got = _producer_of(base, apis, pm)
        if got is None:
            return False
        api, mode = got
        for q in api.params:
            b2 = hkey(q.type.name, pm)
            if b2 in known and b2 != base and not resolve(b2, level + 1):
                return False
        # `base` is already the bare type name; prefixing here and stripping it again in
        # hkey_base_of produced ids like `hf_r_r_sqlite3` in the emitted C. Cosmetic, but a
        # generated identifier that looks like a bug invites someone to go looking for one.
        rid = base
        resolved[base] = {"api": api, "mode": mode, "rid": rid}
        creates.append(resolved[base])
        d = _destroyer_of(base, apis, pm)
        if d is not None:
            destroys.append({"api": d, "rid": rid})
        return True

    for b in dict.fromkeys(needed):
        if not resolve(b, 1):
            return None
    # innermost resource is destroyed first
    return {"creates": creates, "destroys": list(reversed(destroys)),
            "resolved": resolved}


def _plans_for_handle(decls, target, handle, inline_base, init_name, fini_name,
                      platforms, knobs, seen_consumers, mode="inline") -> list:
    """Candidate plans for ONE lifecycle: create -> consume -> destroy."""
    pm = decls[0].ptr_map if decls else {}
    apis = {d.name: to_api(d, handle) for d in decls}
    if inline_base:
        # The initialiser takes the handle and returns a status, so signature-based role
        # inference reads it as a query. It is the constructor; say so explicitly.
        if init_name in apis:
            apis[init_name] = replace(apis[init_name], role=ROLE_CREATE)
        if fini_name in apis:
            apis[fini_name] = replace(apis[fini_name], role=ROLE_DESTROY)
    creators = [a for a in apis.values() if a.role == ROLE_CREATE]
    destroyers = [a for a in apis.values() if a.role == ROLE_DESTROY]
    consumers = [a for a in apis.values() if a.role == ROLE_CONSUME]
    if inline_base:
        creators = [a for a in creators if a.symbol == init_name]
        destroyers = [a for a in destroyers if a.symbol == fini_name]

    # Signature alone does not identify a destructor. `XML_DefaultCurrent(XML_Parser)`
    # returns void and takes exactly the handle, so it looked like one — and the emitted
    # expat harness called it INSTEAD of `XML_ParserFree`. Every iteration leaked a parser,
    # which under LeakSanitizer means a campaign that reports nothing but its own harness.
    #
    # So: among candidates with the right shape, prefer the one that is also NAMED like a
    # destructor. Signature-only candidates remain as a fallback, because a library with an
    # unconventionally-named destructor should still get a lifecycle rather than a leak.
    # A function that TAKES the handle cannot be what creates it. `sqlite3_blob_reopen(
    # sqlite3_blob *, sqlite3_int64)` points an existing blob at another row; it was chosen
    # as the blob's constructor because its name contains "open", and the emitted plan then
    # called it on NULL. The out-param and inline forms legitimately take the handle's
    # ADDRESS, which is a different shape and is preserved.
    # Only the INLINE form legitimately takes `handle *` — the address of a caller-allocated
    # struct. The out-param constructor takes `handle **`, so a single star is a mutator
    # there too, and excluding out_param from this filter left blob_reopen in place.
    if handle and mode != "inline":
        _real = [a for a in creators
                 if not any(hkey(pd.type.name, pm) == hkey(handle, pm)
                            and pd.type.name.count("*") == 1 for pd in a.params)]
        if _real:
            creators = _real
    def _creator_rank(a):
        """A constructor that CONSUMES INPUT beats one that does not.

        `cJSON_Parse(const char *) -> cJSON *` is the library's real entry point, and
        `cJSON_CreateArray()` is not: it takes nothing, so a harness built on it hands the
        fuzzer's bytes to no one and parses an empty array forever. Sorting init-ish names
        alphabetically chose CreateArray, and cJSON_Parse never appeared in ANY of the 444
        plans we proposed for cJSON.

        The shape is everywhere — `X_parse(const char *) -> X *` is how cJSON, json-c and
        libxml2 present themselves — and it is the difference between fuzzing a parser and
        fuzzing an allocator.
        """
        drives = any(_byte_carrying(q) for q in a.params)
        return (0 if drives else 1,
                0 if _INIT_ISH.search(a.symbol) or _MAKE_ISH.search(a.symbol) else 1,
                a.symbol)

    creators.sort(key=_creator_rank)

    def _destroyer_rank(a):
        """A destroy verb ANYWHERE in the name beats one nowhere.

        `BrotliDecoderDestroyInstance` matched no destructor pattern — they anchor the verb
        at the end — so `BrotliDecoderHasMoreOutput` was chosen as the destructor by
        alphabetical order. The decoder state was never freed, LeakSanitizer reported the
        harness's own leak on the 4th input, and the campaign stopped there.
        """
        return (3 if _REUSE_ISH.search(a.symbol) else
                0 if _FINI_ISH.search(a.symbol) else
                1 if _DESTROY_ANYWHERE.search(a.symbol) else 2, a.symbol)
    destroyers.sort(key=_destroyer_rank)

    # A VERSION PARAMETER IS NAMED AFTER THE MACRO THAT SUPPLIES ITS VALUE.
    #
    # jbig2dec's real constructor is a MACRO:
    #   #define jbig2_ctx_new(a, o, g, cb, d) \
    #           jbig2_ctx_new_imp((a),(o),(g),(cb),(d), JBIG2_VERSION_MAJOR, JBIG2_VERSION_MINOR)
    # A producer reading declarations sees only jbig2_ctx_new_imp and binds its two trailing
    # ints to 0 — and jbig2_ctx_new_imp RETURNS NULL when they do not match the library it
    # was compiled against. The handle is NULL, every guarded call is skipped, and the
    # campaign runs for ten minutes touching nothing.
    #
    # The parameter is named `jbig2_version_minor` and the header defines
    # JBIG2_VERSION_MINOR as 20. That is read from the header, not guessed: the name
    # uppercases to a macro the header actually defines as an integer.
    macros: dict = {}
    for _d in decls:
        macros.update(_d.macros)

    def _named_constant(pname: str):
        """The integer a parameter is named after, if the header defines one."""
        return macros.get(pname.upper())

    def _lifecycle_args(api, res_id: str = "h", claim_input: bool = False) -> list:
        """Bind EVERY parameter of a lifecycle op, not just the handle.

        The demo library's constructor was `hd_open(void)`, so an empty argument list
        happened to be correct and nothing noticed. Real constructors take arguments —
        `magic_open(int flags)` is the ordinary case — and a plan that omits one is
        incomplete. S2.MISSING_ARG caught this on all ten libmagic candidates, which is the
        gate working: the producer proposed something wrong and was refused before a
        compiler ever ran.

        A scalar defaults to 0, which for a flags argument means "no options" and is the
        conservative choice. If a constructor actually needs a non-zero argument, the
        dynamic gates find out — D3 will show valid input failing — and the knob belongs in
        the plan rather than in a guess made here.
        """
        out = []
        lens = {ln: b for b, ln in api.contract.length_delimited}
        for pd in api.params:
            if handle and hkey(pd.type.name, pm) == hkey(handle, pm):
                out.append(Arg(pd.name, "resource", res_id))
            elif (mode == "out_param" and pd.type.name.count("*") == 2
                  and handle and hkey(pd.type.name.replace("*", "").strip(),
                                      pm) == hkey(handle, pm)):
                out.append(Arg(pd.name, "resource", res_id))
            elif (claim_input and not slices and _byte_carrying(pd)
                  and not _path_like(pd.name)):
                # THE CONSTRUCTOR IS THE ENTRY POINT for a whole family of libraries.
                # `cJSON_Parse(const char *value) -> cJSON *` is how cJSON, json-c and
                # libxml2 present themselves, and binding `value` to 0 calls the parser with
                # NULL: it returns NULL, every later op is guarded off, and the campaign
                # runs forever touching nothing. MEASURED on cJSON before this fix —
                # 21,694,069 executions for 0.61% of lines.
                slices.append(InputSlice(pd.name, SLICE_CSTRING, remainder=True, min_len=1))
                out.append(Arg(pd.name, "input", pd.name))
            elif claim_input and pd.name in lens and lens[pd.name] in {sl.id for sl in slices}:
                out.append(Arg(pd.name, "length_of", lens[pd.name]))
            else:
                named = _named_constant(pd.name)
                out.append(Arg(pd.name, "literal",
                               value=0 if named is None else named))
        return out

    complete_types = _all_complete(decls)
    # Every type that behaves like a handle in this library, for chain resolution.
    known_handles = {hkey(h, pm) for h in _returned_handles(decls)}
    known_handles |= {b for _, b, _, _ in _inline_handles(decls)}
    known_handles |= {b for _, b, _, _ in _outparam_handles(decls)}
    known_handles.discard("")

    def _unsatisfied_handle(api) -> str:
        """A parameter of this constructor that is ITSELF a constructible handle, and that
        this path can only bind to NULL. Returns its type key, or "".

        `sqlite3_blob_open(sqlite3 *db, ...)` makes a blob out of a CONNECTION. Binding the
        connection to NULL produces a plan that opens nothing, hands NULL to the consumer,
        and crashes on valid input — 13 of 14 measured plans in a deep sqlite run were this
        shape, D3 refused every one, and the whole campaign budget went to them while the
        good sqlite3_exec plan sat unmeasured at rank 700.

        `_resource_chain` already refuses a partial lifecycle. This path had no such check,
        so it emitted the partial one and claimed the consumer, which stopped the chain
        producer from ever building the real thing.
        """
        # A HANDLE NOTHING CAN CONSTRUCT IS NOT AN UNSATISFIED ONE.
        #
        # `jbig2_ctx_new_imp(Jbig2Allocator *, Jbig2Options, Jbig2GlobalCtx *, ...)` was
        # refused because both pointer parameters count as "returned handles" — and they
        # count only because a DESTRUCTOR hands the allocator back: `Jbig2Allocator
        # *jbig2_ctx_free(Jbig2Ctx *)`. Nothing in the library constructs either type, so
        # refusing the constructor produced no plan at all for jbig2dec: eight declarations
        # parsed perfectly, the right handle inferred, and zero proposals.
        #
        # Refusing is right when the library CAN build the thing and we would be passing
        # NULL instead — that is sqlite3_blob_open, where a NULL connection crashes on every
        # valid input. It is wrong when NULL is the only call anyone could make. jbig2dec
        # documents exactly that: a NULL allocator selects the default malloc-based one.
        #
        # So the test is not "is this type a handle" but "can this library create one".
        creatable = {hkey(a.returns.name, pm) for a in apis.values()
                     if a.role == ROLE_CREATE and a.returns.kind == "pointer"}
        creatable |= {b for _, b, i, _ in _outparam_handles(decls) if i}
        creatable |= {b for _, b, i, _ in _inline_handles(decls) if i}
        for pd in api.params:
            k = hkey(pd.type.name, pm)
            if handle and k == hkey(handle, pm):
                continue                   # the handle this lifecycle is about
            if pd.type.name.count("*") == 1 and k in known_handles and k in creatable:
                return k
        return ""

    plans: list = []
    for cons in consumers:
        if cons.symbol in seen_consumers:
            continue                       # already planned under an earlier lifecycle
        used = {cons.symbol}
        create = creators[0] if creators else None
        destroy = destroyers[0] if destroyers else None
        if handle and create is None:
            # A lifecycle with a handle and NO constructor is a plan that hands the library
            # NULL. `sqlite3_blob` has no recognised creator — sqlite3_blob_open returns int
            # and writes through `sqlite3_blob **`, so role inference calls it a query — and
            # the emitted plan called sqlite3_blob_reopen(NULL). It passes every static gate,
            # crashes on the first valid input, and D3 refuses it after a full build.
            #
            # Refusing here costs nothing and frees the campaign slot. In a deep sqlite run
            # 13 of 14 measured plans were this shape: every one was refused by D3 after
            # being compiled and campaigned, while the good sqlite3_exec plan sat unmeasured.
            continue
        if create is not None and _unsatisfied_handle(create):
            # Leave this consumer for `_chain_plans`, which can build the full lifecycle.
            # Emitting the shallow version here AND claiming the consumer is what starved
            # the chain producer of the entry points it exists for.
            continue
        if create:
            used.add(create.symbol)
        if destroy:
            used.add(destroy.symbol)

        # A HANDLE-BASED entry point can still be the caller-owns-the-buffers shape.
        # `BrotliDecoderDecompressStream(state, size_t *available_in,
        # const uint8_t **next_in, ...)` takes a handle AND four caller-owned cursors; the
        # ordinary binder zeroed every one of them and the harness died on its second input.
        _stream_shape = any(
            (q.type.name.count("*") == 2 and base_type(q.type.name) in BYTE_BASES)
            or (q.type.name.count("*") == 1 and _SIZEISH.match(base_type(q.type.name)))
            for q in cons.params)
        if _stream_shape:
            _sl: list = []
            _sc: list = []
            _a = _stream_bind(cons, handle, pm, _sl, _sc,
                              out_capacity=(knobs.max_len if knobs else 4096) * 16 or 65536)
            if _a is not None and _sl:
                stream_args, stream_slices, stream_scratch = _a, _sl, _sc
            else:
                stream_args = None
        else:
            stream_args = None

        slices: list = []
        args: list = []
        nulled: set = set()          # pointer params bound to NULL rather than to input
        returns_handle = False       # a `T **` out-param for a handle this library makes
        extra_res: list = []         # caller-allocated OUT structs the target fills in
        extra_drop: list = []        # and the destructors that free them
        pair_lens = {p[1] for p in cons.contract.length_delimited}

        # WHICH PARAMETER GETS THE FUZZER'S BYTES, when more than one could take them.
        #
        # `ZSTD_decompress(void *dst, size_t dstCapacity, const void *src, size_t srcSize)`
        # has two void* parameters and the FIRST one is the output. Taking them in
        # declaration order bound the input to `dst` and passed `src` as NULL, so the
        # harness decompressed nothing while handing attacker bytes to a destination
        # pointer -- and all six static gates accepted it, which is the outcome this engine
        # exists to prevent. Coverage fell from 30.04% to 2.24% and the number still looked
        # like a measurement.
        #
        # A library marks its input `const`. That is the whole signal, and it is the same
        # one the const arm of _byte_carrying already trusts. When some parameter carries
        # it, no other parameter may take the input slice.
        _const_byte = next((q.name for q in cons.params
                            if "const" in q.type.name and _byte_carrying(q)
                            and not _path_like(q.name)), "")

        for pd in (() if stream_args is not None else cons.params):
            nm, ty = pd.name, pd.type.name
            if handle and hkey(ty, pm) == hkey(handle, pm):
                args.append(Arg(nm, "resource", "h"))
            elif nm in pair_lens:
                owner = next(p[0] for p in cons.contract.length_delimited if p[1] == nm)
                if owner in nulled:
                    # Its buffer was bound to NULL, so there is no slice to take a length
                    # from. `xmlReadMemory(buffer, size, URL, encoding, options)` pairs
                    # `encoding` with `options`; once `encoding` is NULL, a `length_of`
                    # pointing at it names a slice that does not exist and emit refuses.
                    args.append(Arg(nm, "literal", value=0))
                else:
                    args.append(Arg(nm, "length_of", owner))
            elif (ty.count("*") == 2
                  and hkey(ty.replace("*", "").strip(), pm) in known_handles):
                # A `T **` where T is a HANDLE this library knows how to make is not an
                # optional out-parameter: it is where the library returns a new object, and
                # most such APIs dereference it unconditionally.
                #
                # `sqlite3_prepare(db, sql, n, sqlite3_stmt **ppStmt, ...)` with ppStmt NULL
                # SEGVs on every input. The plan passed all six static gates, D3 refused it
                # after a full build, and the campaign recorded 0 edges — and in a deep
                # sqlite run this shape took 14 of 14 measurement slots and the run shipped
                # nothing.
                #
                # Refused here rather than bound, because binding it correctly means owning
                # the returned handle's lifetime — which is exactly what `_chain_plans`
                # does. Leaving the entry point to the chain producer gives a plan that
                # creates the statement, drives it, and finalises it.
                returns_handle = True
                args.append(Arg(nm, "literal", value=0))
            elif ty.count("*") >= 2:
                # A pointer to a pointer that is not the resource and not a known handle: an
                # OUT parameter the library fills in, such as `sqlite3_exec`'s
                # `char **errmsg`, which sqlite explicitly documents as optional. NULL is
                # the conventional call and the only safe binding — writing through an
                # address taken from fuzzer input is the harness corrupting itself.
                args.append(Arg(nm, "literal", value=0))
            elif is_callback(ty, pm):
                # A CALLBACK. `sqlite3_exec(db, sql, callback, arg, errmsg)` takes one, and
                # binding fuzzer bytes to it would have the library call an address made of
                # input — arbitrary control flow, and every crash the harness's own. NULL is
                # both safe and the conventional way to call these APIs.
                args.append(Arg(nm, "literal", value=0))
            elif nm in cons.contract.nul_terminated and not slices:
                slices.append(InputSlice(nm, SLICE_CSTRING, remainder=True, min_len=1))
                args.append(Arg(nm, "input", nm))
            elif (not slices and (not _const_byte or nm == _const_byte)
                  and (("*" in ty and base_type(ty) in BYTE_BASES)
                       or ty.strip() in _CONST_BYTE_PTRS)):
                # The second arm is the pointer-typedef spelling. Added rather than folded
                # into the first so `char **` keeps whatever it did before: this is the
                # branch that decides where the fuzzer's bytes go, and it is not the place
                # to tidy a condition. libpng's png_const_voidp reached here with no star to
                # match, took none of the branches below either, and the plan came out with
                # no input slice at all -- S5.NO_INPUT, a harness that calls the parser and
                # hands it nothing.
                slices.append(InputSlice(nm, SLICE_BYTES, remainder=True, min_len=1))
                args.append(Arg(nm, "input", nm))
            elif ((("*" in ty and ty.count("*") == 1) or ty.strip() in pm)
                  and hkey(ty, pm) in complete_types
                  and hkey(ty, pm) != (hkey(handle, pm) if handle else None)):
                # `or ty.strip() in pm` is the pointer-typedef spelling again, and this is
                # the branch where missing it did the most damage. libpng's png_imagep has
                # no star, so the caller-allocated struct was never declared and the
                # parameter fell through to a literal 0. The emitted harness read
                # `png_image_begin_read_from_memory(0, buf, len)`, and libpng returns
                # immediately on a NULL image -- a harness that compiles, passes every gate,
                # runs 29 million times and exercises 0.03% of the library. A plan that
                # reports a number while doing nothing is worse than one that reports
                # NO PLAN, because only the second is obviously wrong.
                # A pointer to a COMPLETE struct the target fills in: the caller allocates
                # it and passes its address. `yaml_parser_load(parser, yaml_document_t
                # *document)` ASSERTS document is non-NULL, so binding 0 aborts on every
                # input — and binding fuzzer bytes is the type confusion S2 refuses. The
                # only correct call is the one the gold harness makes: declare the object,
                # pass its address, and destroy it afterwards.
                #
                # Decidable only because `complete` records which structs have a body. An
                # opaque type cannot be declared by value at all.
                if extra_res:
                    # One caller-allocated out-struct per plan. `Op.binds` names a single
                    # resource, and the op that FILLS the struct is what creates it — a
                    # second one would have no creator and S1 would refuse the plan.
                    args.append(Arg(nm, "literal", value=0))
                else:
                    rid = f"out_{nm}"
                    base_t = hkey(ty, pm)
                    extra_res.append(Resource(rid, TypeRef(base_t, "struct"),
                                              storage="inline",
                                              init_fields=dict(_REQ_INIT.get(base_t) or {})))
                    args.append(Arg(nm, "resource", rid))
                    d = _destroyer_of(base_t, apis, pm)
                    if d is not None:
                        extra_drop.append((rid, d))
                        used.add(d.symbol)
            elif "*" in ty and not slices:
                # A pointer to a STRUCTURED type. Binding fuzzer bytes here is the type
                # confusion S2 refuses, and proposing it anyway wasted the entry point:
                # `yaml_parser_load(parser, yaml_document_t *document)` got bytes bound to
                # `document`, S2 blocked the plan, and libyaml's single most important entry
                # point produced nothing — while the gold OSS-Fuzz harness for it reaches
                # 77.7% of the library's lines.
                #
                # Refusing to bind it leaves `slices` empty, which is what lets the feeder
                # search above find `yaml_parser_set_input_string`. S2 stays exactly as it
                # is: it must still catch this from a producer that is not ours.
                nulled.add(nm)
                args.append(Arg(nm, "literal", value=0))
            elif "*" in ty:
                # EXACTLY ONE fuzzer-controlled buffer per plan, and it takes the remainder.
                #
                # An earlier version gave later buffers a bounded slice so they would be
                # expressible. The layout then read: remainder takes every byte, cursor
                # reaches the end, the bounded slice gets zero, its `min_len` check fails,
                # and the harness jumps to cleanup — ON EVERY INPUT. Not one library call
                # ever ran. clang proved it and deleted all of them, and D1 caught it as
                # three elided calls.
                #
                # NULL is also what these parameters want. `xmlReadMemory`'s URL and
                # encoding, and `sqlite3_exec`'s user-data pointer, are incidental; upstream
                # harnesses pass NULL for exactly this reason. D7 records the exclusion.
                args.append(Arg(nm, "literal", value=0))
                nulled.add(nm)
            else:
                args.append(Arg(nm, "literal", value=0))

        if stream_args is not None:
            args = stream_args
            slices = list(stream_slices)
            stream_scratch_out = list(stream_scratch)
        else:
            stream_scratch_out = []
        feeder = None
        # Claim order for the fuzzer's bytes, and it matters:
        #   1. a byte parameter on the TARGET itself   (already bound above)
        #   2. a byte parameter on the CONSTRUCTOR     — `cJSON_Parse(const char *)` IS the
        #      library's parser, so bytes belong there
        #   3. a SETTER that feeds the handle          — `yaml_parser_set_input_string`
        # Getting 2 and 3 the wrong way round gave cJSON a feeder-fed object built from
        # `cJSON_Parse(NULL)`: 36 million executions for 0.61% of lines.
        create_claims = (create is not None and not slices
                         and any(_byte_carrying(q) and not _path_like(q.name)
                                 for q in create.params))
        if not slices and not create_claims:
            # Before discarding: does the library take its input through a SETTER on this
            # handle? If so the fuzzer drives the target after all, one call earlier.
            got = _feeder_for(handle, cons, apis, pm)
            if got is None:
                continue                   # nothing the fuzzer controls: not a harness
            fapi, fbuf, flen = got
            slices.append(InputSlice(fbuf, SLICE_BYTES, remainder=True, min_len=1))
            fargs = []
            for pd in fapi.params:
                if hkey(pd.type.name, pm) == hkey(handle, pm):
                    fargs.append(Arg(pd.name, "resource", "h"))
                elif pd.name == fbuf:
                    fargs.append(Arg(pd.name, "input", fbuf))
                elif flen and pd.name == flen:
                    fargs.append(Arg(pd.name, "length_of", fbuf))
                else:
                    fargs.append(Arg(pd.name, "literal", value=0))
            feeder = (fapi, fargs)
            used.add(fapi.symbol)
        if returns_handle:
            # This entry point returns a new handle through a `T **` parameter and this
            # path can only bind it NULL. Leave it to `_chain_plans`, which creates the
            # object, drives it and destroys it.
            continue

        seq: list = []
        resources: list = []
        # A resource nothing in the plan uses is not a lifecycle, it is noise: it adds a
        # create and a destroy around a call that never touches it.
        needs_resource = any(a.source == "resource" for a in args)
        if create and handle and needs_resource:
            if inline_base and mode == "out_param":
                # The library allocates; the harness supplies where to put the pointer.
                resources.append(Resource("h", TypeRef(handle, "pointer"),
                                          storage="out_param"))
            elif inline_base:
                # The harness owns the storage: declare the OBJECT, pass its address.
                resources.append(Resource("h", TypeRef(inline_base, "struct"),
                                          storage="inline",
                                          init_fields=dict(_REQ_INIT.get(inline_base) or {})))
            else:
                resources.append(Resource("h", TypeRef(handle, "pointer")))
            seq.append(Op("o_create", create.symbol,
                          _lifecycle_args(create, claim_input=True), binds="h"))
        # Guard ONLY on a resource this op actually uses.
        #
        # It previously guarded on `h` whenever a create existed at all, even when the
        # consume takes no handle. libcue's `cue_parse_string(const char*)` is an
        # independent entry point, and wrapping it in `if (cd_get_track(0,0))` — which
        # returns NULL — meant it was never called. The campaign ran 61 MILLION executions
        # at cov:4 against a known-vulnerable build and found nothing, because the target
        # function was behind a condition that is always false.
        #
        # D2 caught it (0/6 planted defects killed) and was right to block the plan.
        resources.extend(extra_res)
        scratch_out = list(stream_scratch_out)
        if feeder is not None:
            # Ordering is the whole point: the bytes must be in the handle BEFORE the target
            # runs. The existing `_setup` variants insert calls too, but they bind every
            # non-handle parameter to 0 and can land AFTER the consumer — which for libyaml
            # produced `yaml_parser_load` first and `set_input_string` second.
            fapi, fargs = feeder
            seq.append(Op("o_feed", fapi.symbol, fargs,
                          guarded_by=["h"] if (create and handle) else []))
        uses_h = any(a.source == "resource" and a.ref == "h" for a in args)
        # The call that fills a caller-allocated out-struct IS its creation. Without saying
        # so, S1 sees a resource destroyed and used with nothing having created it and
        # refuses the plan — which is what happened to BOTH libyaml entry points:
        # `yaml_parser_load` and `yaml_parser_scan` were blocked by
        # S1.DESTROY_BEFORE_CREATE, and the 77.4% figure measured for the loader came from a
        # harness built directly, bypassing the gates. A number from a plan the engine
        # would refuse is not a number the engine can claim.
        # REPEAT when the target hands back one unit at a time.
        #
        # The signal: it fills a caller-allocated struct AND returns a status. That is the
        # shape of every token/event/record API — `yaml_parser_scan(parser, &token)`,
        # `yaml_parser_load(parser, &document)` — and calling it once yields exactly one
        # token per input. MEASURED: 77 million executions for 9.6% of libyaml against the
        # gold harness's 70.6%, which loops.
        #
        # Bounded at 64. Unbounded would be a hang steered by fuzzer input, and a hang looks
        # like a finding until someone checks.
        # Two shapes repeat, and both hand back one unit per call:
        #   * it fills a caller-allocated struct   — yaml_parser_scan(parser, &token)
        #   * it advances caller-owned CURSORS     — BrotliDecoderDecompressStream, which
        #     must be called until it stops asking for more output
        _streaming = any(sc.kind == SCRATCH_PTR for sc in stream_scratch_out)
        _repeats = ((bool(extra_res) or _streaming)
                    and cons.returns.name.strip() not in ("void", ""))
        seq.append(Op("o_consume", cons.symbol, args,
                      binds=(extra_res[0].id if extra_res else ""),
                      # Bounded by the INPUT LENGTH, not a constant. A token requires at
                      # least one byte, so max_len iterations is provably enough and still
                      # cannot hang. 64 was visibly too tight: the libyaml scanner reached
                      # 48.61% against gold's 70.6% because a YAML document has far more
                      # than 64 tokens and the loop stopped mid-stream.
                      repeat=((knobs.max_len if knobs and knobs.max_len else 4096)
                              if _repeats else 0),
                      guarded_by=["h"] if (create and handle and uses_h) else []))
        # A FINISHER WITHOUT A CREATE DESTROYS SOMETHING THAT WAS NEVER MADE.
        #
        # The op below binds resource "h" unconditionally while only its GUARD was
        # conditional on a create existing. For a consumer that neither takes nor returns
        # the library's handle -- ZSTD_decompress(void *dst, size_t, const void *src,
        # size_t) against a ZSTD_DCtx handle -- that emitted `o_finish` against a resource
        # nothing declared. S1 refused the plan as UNKNOWN_RESOURCE and zstd went from
        # 30.04% to no measurement at all. The gate was right; the plan should never have
        # been built.
        # `needs_resource` is the same term the o_create above is gated on: a resource is
        # only declared when the call's own arguments reference it. Without it here, the
        # finisher was emitted for a handle the plan never created.
        fin = (_finisher_for(handle, cons, apis, pm, used)
               if (create and handle and needs_resource) else None)
        if fin is not None:
            seq.append(Op("o_finish", fin.symbol,
                          [Arg(fin.params[0].name, "resource", "h")],
                          guarded_by=["h"] if (create and handle) else []))
            used.add(fin.symbol)

        # ASK THE LIBRARY WHY IT FAILED. See `_error_accessor_for`: for yajl this is about a
        # hundred lines that a correct lifecycle cannot otherwise reach, and the pairing
        # with the freer is mandatory or the harness leaks on every failing input.
        _in_slice = next((sl.id for sl in slices), "")
        err = _error_accessor_for(handle, cons, apis, pm, used, _in_slice)
        if err is not None:
            acc, acc_args, freer, freer_args = err
            # THE DECLARED RETURN TYPE, VERBATIM — not hkey(), which resolves a type to its
            # BASE and so turns `unsigned char *` into `unsigned char`. The emitter takes
            # the pointer from the type NAME, because a handle typedef like `yajl_handle`
            # already carries its own star; a raw pointer return does not. Getting this
            # wrong declared `unsigned char hf_r_err`, truncated the returned pointer to one
            # byte, and made the paired free segfault on the third execution — measured as
            # 0.00% where the case had been 65.12%.
            resources.append(Resource("err", TypeRef(acc.returns.name.strip(), "pointer"),
                                      storage="handle"))
            seq.append(Op("o_error", acc.symbol, acc_args, binds="err",
                          guarded_by=["h"] if (create and handle) else []))
            seq.append(Op("o_error_free", freer.symbol, freer_args, targets="err",
                          guarded_by=(["h", "err"] if (create and handle) else ["err"])))
            used.add(acc.symbol)
            used.add(freer.symbol)
        for rid, d in extra_drop:
            # Without this the target fills a structure every iteration and nothing frees
            # it: LeakSanitizer then reports a finding on EVERY input, which is the libcue
            # mistake — a harness whose own leak drowns the campaign.
            # Guarded on the call that filled it: `yaml_parser_load` returns 0 on a
            # rejected input, and deleting a document it never populated is the harness
            # acting on a failure value. S6 said exactly this, and named the fix — which is
            # what `Violation.fix` exists for. The gold harness makes the same check.
            seq.append(Op(f"o_drop_{rid}", d.symbol,
                          [Arg(d.params[0].name, "resource", rid)],
                          targets=rid, guarded_by=[rid]))
        # Variants: with and without the library's required setup calls.
        #
        # Which calls a target needs before it will parse anything is not decidable from a
        # signature, and guessing produces a harness that looks right and reaches nothing.
        # So the producer proposes BOTH shapes and gate D8 measures the edges each one
        # actually reaches. Depth becomes evidence rather than an assumption — which is the
        # same rule as everywhere else here: producers propose, gates rank.
        setups = [a for a in apis.values()
                  if a is not cons and _SETUP_ISH.search(a.symbol)
                  and a.params and handle
                  and hkey(a.params[0].type.name, pm) == hkey(handle, pm)
                  and all(("*" in q.type.name) or q.type.kind == "scalar"
                          for q in a.params[1:])
                  and (create is None or a.symbol != create.symbol)
                  and (destroy is None or a.symbol != destroy.symbol)]
        setups = sorted(setups, key=lambda a: a.symbol)[:4]

        # `yaml_parser_set_input_string` stores a pointer and returns. Nothing is parsed
        # until `yaml_parser_parse` is called, so a create -> set -> destroy plan compiles,
        # runs, and exercises essentially nothing. Where the library separates "here are the
        # bytes" from "now do the work", the plan needs both calls or it is a harness that
        # cannot find anything.
        #
        # The driver's non-handle pointer parameters are bound as OUT, never as input: the
        # library FILLS them. Binding them to fuzzer bytes would be the type confusion that
        # S2 blocks.
        if _SETTER_ISH.search(cons.symbol) and handle:
            driver = next(
                (a for a in apis.values()
                 if _DRIVER_ISH.search(a.symbol) and a.symbol != cons.symbol
                 and a.params and hkey(a.params[0].type.name, pm) == hkey(handle, pm)
                 and all(("*" in pd.type.name) or pd.type.kind == "scalar"
                         for pd in a.params[1:])), None)
            if driver is not None:
                dargs = []
                for pd in driver.params:
                    if hkey(pd.type.name, pm) == hkey(handle, pm):
                        dargs.append(Arg(pd.name, "resource", "h"))
                    elif "*" in pd.type.name and "const" not in pd.type.name:
                        dargs.append(Arg(pd.name, "out"))
                    else:
                        # A CONST pointer can never be an out-parameter: the library cannot
                        # write through it. `sqlite3_blob_write(blob, const void *z, int n,
                        # int iOffset)` takes a buffer the CALLER supplies, and calling it
                        # an out-parameter made the emitter declare `void hf_out_... = {0};`
                        # — not valid C. The plan shipped anyway and was named the winner
                        # off six static gates, with every dynamic gate reading NOT_RUN
                        # "the binary was not built".
                        dargs.append(Arg(pd.name, "literal", value=0))
                # PUMP THE DRIVER WHEN IT TELLS US THERE IS MORE.
                #
                # Bounded by max_len for the same reason every other loop here is: an
                # unbounded loop steered by fuzzer input is a hang, and a hang is
                # indistinguishable from a finding until a human looks. The flag only
                # shortens it.
                _flag = next((a.param for a in dargs
                              if a.source == "out" and _CONTINUE_FLAG.match(a.param or "")),
                             "")
                seq.append(Op("o_drive", driver.symbol, dargs, guarded_by=["h"],
                              repeat=((knobs.max_len if knobs and knobs.max_len else 4096)
                                      if _flag else 0),
                              repeat_while=_flag))
                used.add(driver.symbol)

        # A consumer that RETURNS an owned object must destroy it.
        #
        # `cue_parse_string(const char*)` returns a `Cd*` that `cd_delete` frees. Without
        # that op the harness leaks on every input, and under LeakSanitizer every input
        # becomes a finding — the precise false-positive class this project exists to
        # prevent. S1 warns about it; the producer was not acting on its own gate's warning.
        ret_owner = None
        if cons.returns.kind == "pointer" and not any(o.binds for o in seq):
            rk = hkey(cons.returns.name, pm)
            # Reuse the shared lookup rather than a private copy of it. This one knew only
            # the role and the END-ANCHORED name pattern, so `cmsCloseProfile` was invisible
            # and every lcms2 profile leaked — LeakSanitizer stopped the campaign after 20
            # inputs having covered nothing. `_destroyer_of` also accepts a destroy verb
            # mid-name, which is how libraries actually spell these.
            ret_owner = _destroyer_of(rk, apis, pm)
        if ret_owner is not None:
            resources.append(Resource("owned", TypeRef(cons.returns.name, "pointer")))
            for o in seq_tail_consume(seq):
                o.binds = "owned"
            seq.append(Op("o_free_owned", ret_owner.symbol,
                          [Arg(ret_owner.params[0].name, "resource", "owned")],
                          targets="owned", guarded_by=["owned"]))
            used.add(ret_owner.symbol)

        if destroy and handle and create and needs_resource:
            seq.append(Op("o_destroy", destroy.symbol, _lifecycle_args(destroy),
                          targets="h"))

        # A VARIANT SEARCH over the plan space, which is only possible because a harness
        # here is data rather than code. A generator that emits C cannot systematically
        # enumerate alternatives of its own output; it has one program and no way to ask
        # which shape of it reaches further.
        #
        # Each variant is a different hypothesis about what the library needs before it will
        # parse anything, and none of them is believed. D8 runs a real campaign against each
        # and the ranking keeps whichever measurably reaches furthest.
        # `max_len` is a knob whose wrong value makes defects INEXPRESSIBLE rather than
        # merely hard to find. libxml2's CVE-2022-40303 needs an input over 2GB; libFuzzer's
        # silent default is 4096. No single constant is right for every target, so propose
        # the plan at more than one size and let D8 report which reaches further — the same
        # rule as setup calls.
        base_len = (knobs or Knobs()).max_len or 4096
        size_variants = [(base_len, "")]
        if base_len < 1 << 20:
            size_variants.append((base_len * 16, f"_len{(base_len * 16) // 1024}k"))

        variants = [([], "")]
        if setups:
            variants.append((setups, "_setup"))
            if len(setups) > 1:
                # Individually too: one required call is the common case, and the full set
                # can be worse than a single one when a later call fails and leaves the
                # handle in an error state.
                for a in setups:
                    variants.append(([a], f"_with_{a.symbol}"))

        combos = [(ops_v, sfx + lsfx, mlen)
                  for ops_v, sfx in variants
                  for mlen, lsfx in size_variants]

        for setup_ops, suffix, mlen in combos:
            seq_v = list(seq)
            used_v = set(used)
            if setup_ops:
                insert_at = 1 if (create and handle) else 0
                # A setup call that RETURNS a handle through `T **` cannot be given NULL for
                # it. `sqlite3_prepare` was being used as a setup call for `sqlite3_exec`
                # with ppStmt = 0, which SEGVs before the entry point is ever reached — the
                # same misbinding as the consumer path, one level along, and it made every
                # `_setup` variant of a good plan crash on valid input.
                setup_ops = [a for a in setup_ops
                             if not any(q.type.name.count("*") == 2
                                        and hkey(q.type.name.replace("*", "").strip(), pm)
                                        in known_handles
                                        for q in a.params)]
            if setup_ops:
                # AFTER the feeder, never before it. Inserting at index 1 put
                # `yaml_parser_load` ahead of `yaml_parser_set_input_string`, so the setup
                # call consumed a stream that had no input yet and the scanner harness died
                # in 2 executions.
                base_at = 1 if (create and handle) else 0
                feed_at = next((i for i, o in enumerate(seq_v) if o.id == "o_feed"), None)
                insert_at = (feed_at + 1) if feed_at is not None else base_at
                for k, a in enumerate(setup_ops):
                    sargs = []
                    for q in a.params:
                        if hkey(q.type.name, pm) == hkey(handle, pm):
                            sargs.append(Arg(q.name, "resource", "h"))
                        else:
                            sargs.append(Arg(q.name, "literal", value=0))
                    seq_v.insert(insert_at + k,
                                 Op(f"o_setup{k}", a.symbol, sargs,
                                    guarded_by=["h"] if (create and handle) else []))
                    used_v.add(a.symbol)
            kv = replace(knobs or Knobs(), max_len=mlen)
            plans.append(_make_plan(target, cons, suffix, apis, used_v, slices, seq_v,
                                    resources, kv, platforms, handle, inline_base,
                                    scratch=scratch_out))
        seen_consumers.add(cons.symbol)
    return plans


def seq_tail_consume(seq: list) -> list:
    """The consume op, which is what produced the owned object."""
    return [o for o in seq if o.id == "o_consume"]


def _make_plan(target, cons, suffix, apis, used, slices, seq, resources, knobs, platforms,
               handle, inline_base, scratch=()):
        return HarnessIR(
            name=f"{target.name}_{cons.symbol}{suffix}",
            target=target,
            apis={s: apis[s] for s in sorted(used)},
            slices=slices, resources=resources, scratch=list(scratch), sequence=seq,
            knobs=knobs or Knobs(),
            platforms=platforms or ["linux-x86_64-glibc"],
            producer="header_graph",
            notes=f"proposed from {cons.header} by signature inference; "
                  f"handle type inferred as {handle!r}"
                  f"{' (caller-allocated)' if inline_base else ''}. Every inference here is "
                  f"checked by a static gate, and the producer certifies nothing.")
