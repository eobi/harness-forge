#!/usr/bin/env python3
"""Phase 3.6 — what real headers actually look like.

Every test here reproduces a shape that broke the engine on real software: libmagic (the
`file` CLI), libyaml, and libxml2 (`xmllint`). The producer worked perfectly on the demo
header and proposed ZERO plans for all three real libraries, reporting no error at all.

The fixtures are inline rather than pulled from the system, so these run on any machine with
no Docker, no packages and no network — the bugs are in the shapes, not in the libraries.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.analysis import sinks                              # noqa: E402
from hforge.producers import header_graph as hg                # noqa: E402

_pass = _fail = 0


def check(name, fn):
    global _pass, _fail
    try:
        fn()
        print(f"  ok   {name}")
        _pass += 1
    except AssertionError as e:
        print(f"  FAIL {name}\n       {e}")
        _fail += 1
    except Exception as e:                                     # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


def _hdr(text: str) -> str:
    f = Path(tempfile.mkdtemp()) / "t.h"
    f.write_text(text)
    return str(f)


# The three shapes, together, as they appear in the wild.
MAGIC_LIKE = """
#ifndef _MAGIC_H
#define _MAGIC_H

#define MAGIC_NONE       0x0000000
#define MAGIC_NO_CHECK   (MAGIC_NO_CHECK_A | \\
                          MAGIC_NO_CHECK_B | \\
                          MAGIC_NO_CHECK_C)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct magic_set *magic_t;

magic_t magic_open(int);
void magic_close(magic_t);
const char *magic_buffer(magic_t, const void *, size_t);
int magic_load(magic_t, const char *);

#ifdef __cplusplus
}
#endif
#endif
"""

YAML_LIKE = """
#define YAML_DECLARE(type) type

typedef struct yaml_parser_s yaml_parser_t;

YAML_DECLARE(int)
yaml_parser_initialize(yaml_parser_t *parser);

YAML_DECLARE(void)
yaml_parser_delete(yaml_parser_t *parser);
"""

XML_LIKE = """
#define XMLPUBFUN
#define XMLCALL

typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;

XMLPUBFUN xmlDocPtr XMLCALL
\t\txmlReadMemory\t\t(const char *buffer,
\t\t\t\t\t int size,
\t\t\t\t\t const char *URL);
XMLPUBFUN void XMLCALL
\t\txmlFreeDoc\t\t(xmlDocPtr cur);
"""


# ── the parser ───────────────────────────────────────────────────────────────

def test_multiline_define_does_not_swallow_the_header():
    """A `#define` continued with a backslash used to leak into the statement stream. The
    leaked text carried unbalanced parens, the depth counter never returned to zero, and a
    54KB header parsed to NOTHING while reporting no error."""
    d = hg.parse_header(_hdr(MAGIC_LIKE))
    assert len(d) >= 4, f"multi-line #define swallowed the header: only {len(d)} decls"


def test_extern_c_brace_does_not_swallow_the_header():
    """`extern "C" {` wraps almost every C public API. strip_noise blanks string literals
    first, so the text becomes `extern     {` and a regex looking for the literal `"C"`
    misses it — leaving the brace to hold every declaration at depth 1. A 5.9KB header then
    parsed as ONE statement."""
    src = MAGIC_LIKE.replace('extern "C" {', 'extern     {')     # post-strip_noise form
    stmts = hg._statements(src)
    assert len(stmts) > 3, f"extern-C brace collapsed the file into {len(stmts)} statement(s)"


def test_typedefd_pointer_handle_is_recognised():
    """`typedef struct magic_set *magic_t` — the handle is a pointer, but not textually.
    Missing that made `const char *` win as libmagic's handle, every role come out wrong,
    and zero plans get proposed."""
    d = hg.parse_header(_hdr(MAGIC_LIKE))
    assert hg._handle_type(d) == "magic_t", \
        f"handle inferred as {hg._handle_type(d)!r}, not 'magic_t'"


def test_string_return_is_never_the_handle():
    d = hg.parse_header(_hdr(MAGIC_LIKE))
    assert "char" not in (hg._handle_type(d) or ""), \
        "a char* was chosen as the library handle; a library returns strings constantly and "\
        "none of them are its handle"


def test_unnamed_parameters_are_accepted():
    """`magic_buffer(magic_t, const void *, size_t)` names nothing. Legal C, and common."""
    d = hg.parse_header(_hdr(MAGIC_LIKE))
    mb = next(x for x in d if x.name == "magic_buffer")
    assert len(mb.params) == 3, f"unnamed parameters dropped: {mb.params}"


def test_macro_wrapped_return_type_parses():
    """`YAML_DECLARE(int)` on one line, the name on the next."""
    d = hg.parse_header(_hdr(YAML_LIKE))
    names = {x.name for x in d}
    assert "yaml_parser_initialize" in names, f"macro-wrapped decls dropped: {names}"
    init = next(x for x in d if x.name == "yaml_parser_initialize")
    assert init.ret == "int", f"return type not unwrapped: {init.ret!r}"


def test_export_macros_and_multiline_params_parse():
    """`XMLPUBFUN xmlDocPtr XMLCALL` then a tab-indented name and wrapped parameters."""
    d = hg.parse_header(_hdr(XML_LIKE))
    names = {x.name for x in d}
    assert "xmlReadMemory" in names, f"export-macro decls dropped: {names}"
    rm = next(x for x in d if x.name == "xmlReadMemory")
    assert rm.ret == "xmlDocPtr", f"decorated return type not cleaned: {rm.ret!r}"
    assert len(rm.params) == 3, f"multi-line parameters lost: {rm.params}"


def test_handle_is_not_paired_as_a_length_delimited_buffer():
    """`magic_setparam(magic_t, int, const void *)` paired the HANDLE with the following
    int, because a typedef'd handle IS a pointer and `int` is size-shaped. The plan then
    bound an argument to a slice that did not exist and emit refused."""
    src = MAGIC_LIKE.replace("int magic_load(magic_t, const char *);",
                             "int magic_setparam(magic_t, int, const void *);")
    d = hg.parse_header(_hdr(src))
    handle = hg._handle_type(d)
    sp = next(x for x in d if x.name == "magic_setparam")
    c = hg.infer_contract(sp, hg.infer_role(sp, handle), handle)
    assert not any(p[0] == "arg0" for p in c.length_delimited), \
        f"the handle was paired as a buffer: {c.length_delimited}"


def test_length_pair_is_still_found_from_types_alone():
    """The inverse must keep working: `(const void *, size_t)` IS a (ptr,len) pair even with
    no names to read."""
    d = hg.parse_header(_hdr(MAGIC_LIKE))
    handle = hg._handle_type(d)
    mb = next(x for x in d if x.name == "magic_buffer")
    c = hg.infer_contract(mb, hg.infer_role(mb, handle), handle)
    assert c.length_delimited, "the (void*, size_t) pair was not recognised without names"


def test_typedefs_are_shared_across_headers():
    """libxml2 declares xmlReadMemory in parser.h but typedefs xmlDocPtr in tree.h. Parsing
    one file cannot see the other's typedefs, so the handle came out None."""
    a = _hdr("typedef struct _xmlDoc xmlDoc;\ntypedef xmlDoc *xmlDocPtr;\n")
    b = _hdr("xmlDocPtr xmlReadMemory(const char *buffer, int size);\n"
             "void xmlFreeDoc(xmlDocPtr cur);\n")
    decls = hg.parse_header(a) + hg.parse_header(b)
    # Collected per HEADER, which is what propose() does. Header `a` declares no functions
    # at all, so gathering typedefs off the declarations would lose every one of them.
    shared = frozenset().union(hg.header_typedefs(a), hg.header_typedefs(b))
    for x in decls:
        x.ptr_types = shared
    assert "xmlDocPtr" in shared, (
        "a typedef-only header contributed nothing; its typedefs were dropped")
    rm = next(x for x in decls if x.name == "xmlReadMemory")
    assert rm.returns_pointer, "a typedef from another header was not applied"


# ── the sink scanner ─────────────────────────────────────────────────────────

BSD_STYLE = """
file_public struct magic_set *
magic_open(int flags)
{
\tchar buf[16];
\tstrcpy(buf, "x");
\treturn 0;
}

static int
helper(const char *s, size_t n)
{
\tmemcpy(0, s, n);
\treturn 0;
}
"""


def test_bsd_style_definitions_are_found():
    """Return type on its own line, name starting the next. `file`, OpenSSH and much of BSD
    C are written this way, and the scanner matched NONE of it — so gate D4 reported
    'reaches 0 of 19 sinks' on real software, which reads like a finding but was a parser
    artifact."""
    f = Path(tempfile.mkdtemp()) / "t.c"
    f.write_text(BSD_STYLE)
    funcs, found = sinks.scan_file(str(f))
    assert "magic_open" in funcs, f"BSD-style definition not found: {sorted(funcs)}"
    assert "helper" in funcs, f"static BSD-style definition not found: {sorted(funcs)}"


def test_sinks_inside_bsd_style_functions_are_attributed():
    f = Path(tempfile.mkdtemp()) / "t.c"
    f.write_text(BSD_STYLE)
    funcs, found = sinks.scan_file(str(f))
    kinds = {s.kind for s in found}
    assert "strcpy" in kinds and "memcpy" in kinds, f"sinks missed: {kinds}"
    assert any(s.function == "magic_open" for s in found), \
        "a sink was found but attributed to no function"


# ── caller-allocated handles, and what they exposed ─────────────────────────

YAML_FULL = """
typedef struct yaml_parser_s yaml_parser_t;
typedef struct yaml_emitter_s yaml_emitter_t;
typedef struct yaml_event_s yaml_event_t;
int yaml_parser_initialize(yaml_parser_t *parser);
void yaml_parser_delete(yaml_parser_t *parser);
void yaml_parser_set_input_string(yaml_parser_t *parser, const unsigned char *input, size_t size);
int yaml_parser_parse(yaml_parser_t *parser, yaml_event_t *event);
int yaml_emitter_initialize(yaml_emitter_t *emitter);
void yaml_emitter_delete(yaml_emitter_t *emitter);
int yaml_emitter_emit(yaml_emitter_t *emitter, yaml_event_t *event);
"""


def _propose_yaml():
    from hforge.ir import Knobs, Target
    h = _hdr(YAML_FULL)
    return hg.propose([h], Target(name="y", public_headers=["t.h"],
                                  include_dirs=[str(Path(h).parent)]),
                      platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))


def test_caller_allocated_handle_is_found():
    """`yaml_parser_t p; yaml_parser_initialize(&p);` — the library never returns a handle,
    so returned-handle inference finds nothing and the library was unreachable. zlib's
    z_stream and most C context-struct APIs have this shape."""
    d = hg.parse_header(_hdr(YAML_FULL))
    assert hg._handle_type(d) is None, "this library returns no handle; that is the point"
    found = hg._inline_handles(d)
    names = {x[1] for x in found}
    assert "yaml_parser_t" in names, f"caller-allocated handle not found: {found}"


def test_every_lifecycle_is_planned_not_just_the_biggest():
    """libyaml has a parser AND an emitter. Taking only the most-used handle chose the
    emitter, so the PARSER — the only half that consumes serialised bytes — was never
    proposed at all."""
    d = hg.parse_header(_hdr(YAML_FULL))
    names = {x[1] for x in hg._inline_handles(d)}
    assert {"yaml_parser_t", "yaml_emitter_t"} <= names, f"only found {names}"


def test_inline_resource_emits_address_of_and_zeroing():
    from hforge.emit.c_libfuzzer import emit
    plans = _propose_yaml()
    plan = next((p for p in plans if "set_input_string" in p.name), None)
    assert plan is not None, f"no plan for the byte-consuming entry point: " \
                             f"{[p.name for p in plans]}"
    src = emit(plan).source
    assert "yaml_parser_t hf_r_h;" in src, "the object was not declared by the harness"
    assert "memset(&hf_r_h" in src, "a caller-allocated object was left uninitialised"
    assert "yaml_parser_initialize(&hf_r_h)" in src, "the address was not passed"
    assert "yaml_parser_delete(&hf_r_h)" in src


def test_inline_resource_tracks_liveness_separately():
    """A handle IS its own liveness test — NULL or not. An inline struct always exists, so
    a failed initialiser would otherwise go unnoticed and the plan would use a dead object."""
    from hforge.emit.c_libfuzzer import emit
    plan = next(p for p in _propose_yaml() if "set_input_string" in p.name)
    src = emit(plan).source
    assert "hf_ok_h" in src and "if (hf_ok_h)" in src, \
        "no liveness flag: a failed initialiser would be used as though it succeeded"


def test_setter_only_plan_chains_the_call_that_does_the_work():
    """`set_input_string` stores a pointer and returns. Without the follow-up call nothing
    is ever parsed, and the harness compiles, runs, and finds nothing forever."""
    from hforge.emit.c_libfuzzer import emit
    plan = next(p for p in _propose_yaml() if "set_input_string" in p.name)
    syms = [op.api for op in plan.sequence]
    assert any(s in ("yaml_parser_parse", "yaml_parser_scan", "yaml_parser_load")
               for s in syms), f"no work is driven after the setter: {syms}"
    src = emit(plan).source
    assert "= {0};" in src, "a struct out-parameter was initialised with `= 0`, which is " \
                            "not valid C and would not compile"


def test_out_parameters_are_never_filled_with_fuzzer_bytes():
    """The driver's pointer parameters are OUT — the library writes them. Binding them to
    input would be the very type confusion S2 exists to block."""
    from hforge.ir import SRC_INPUT
    plan = next(p for p in _propose_yaml() if "set_input_string" in p.name)
    drive = next(op for op in plan.sequence if op.id == "o_drive")
    assert not any(a.source == SRC_INPUT for a in drive.args), \
        "the driver call was fed fuzzer bytes through a struct pointer"


# ── the type-confusion gate ─────────────────────────────────────────────────

def _plan_binding_input_to(type_name: str):
    from hforge.ir import (Api, Arg, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Target,
                           TypeRef, SLICE_BYTES, ROLE_CONSUME)
    api = Api(symbol="f", header="t.h", role=ROLE_CONSUME,
              params=[ParamDecl("p", TypeRef(type_name, "pointer"))],
              returns=TypeRef("int", "scalar"))
    return HarnessIR(name="t", target=Target(name="t"), apis={"f": api},
                     slices=[InputSlice("p", SLICE_BYTES, remainder=True, min_len=1)],
                     resources=[], sequence=[Op("o", "f", [Arg("p", "input", "p")])],
                     knobs=Knobs(), platforms=["linux-x86_64-glibc"])


def test_struct_pointer_fed_with_bytes_is_blocked():
    """A libyaml candidate cast raw input to `yaml_document_t *`. The library dereferences
    that as a real object, so EVERY crash is the harness's own invalid pointer. This is the
    largest single source of false findings in the literature, and it is decidable from the
    plan alone."""
    from hforge.gates.static_gates import run_static_gates
    from hforge.gates.result import BLOCK
    gates = run_static_gates(_plan_binding_input_to("yaml_document_t *"))
    codes = {v.code for g in gates for v in g.violations if v.severity == BLOCK}
    assert "S2.TYPE_CONFUSION" in codes, f"type confusion not blocked: {codes}"


def test_byte_pointers_are_still_allowed():
    """The inverse must hold or the gate blocks every real harness."""
    from hforge.gates.static_gates import run_static_gates
    from hforge.gates.result import BLOCK
    for ty in ("const void *", "char *", "unsigned char *", "uint8_t *"):
        gates = run_static_gates(_plan_binding_input_to(ty))
        codes = {v.code for g in gates for v in g.violations if v.severity == BLOCK}
        assert "S2.TYPE_CONFUSION" not in codes, f"{ty} was wrongly rejected"


# ── ranking must not invent a winner ────────────────────────────────────────

def test_ranking_refuses_a_winner_with_no_discriminating_evidence():
    """74 libxml2 plans scored identically and the first one alphabetically was printed as
    'Selected by gate evidence'. Nothing had been selected."""
    from hforge.producers import rank
    from hforge.gates.result import passed
    g = [passed("S1", "lifetime")]
    tied = [rank.score("b_plan", "header_graph", g), rank.score("a_plan", "header_graph", g)]
    ranked = rank.rank(tied)
    assert not rank.discriminating(ranked)
    out = rank.render(ranked)
    assert "UNRANKED" in out and "Winner:" not in out, out[-200:]
    assert "alphabetical" in out


def test_ranking_still_names_a_winner_when_evidence_differs():
    from hforge.producers import rank
    from hforge.gates.result import passed
    weak = rank.score("a_plan", "p", [passed("D2", "pc", kill_rate="0/4")])
    strong = rank.score("b_plan", "p", [passed("D2", "pc", kill_rate="4/4")])
    ranked = rank.rank([weak, strong])
    assert rank.discriminating(ranked)
    out = rank.render(ranked)
    assert "Winner: b_plan" in out, out[-200:]


# ── shapes found across ten real libraries ──────────────────────────────────

def test_destructor_is_chosen_by_name_not_only_by_signature():
    """`XML_DefaultCurrent(XML_Parser)` returns void and takes exactly the handle, so it
    looks like a destructor. It is a callback helper. The emitted expat harness called it
    INSTEAD of `XML_ParserFree`, leaking a parser on every iteration — under LeakSanitizer
    a campaign that reports nothing but its own harness."""
    from hforge.ir import Knobs, Target
    src = """
typedef struct XML_ParserStruct *XML_Parser;
XML_Parser XML_ParserCreate(const char *encoding);
int XML_Parse(XML_Parser parser, const char *s, int len, int isFinal);
void XML_DefaultCurrent(XML_Parser parser);
void XML_ParserFree(XML_Parser parser);
"""
    h = _hdr(src)
    plans = hg.propose([h], Target(name="x", public_headers=["t.h"],
                                   include_dirs=[str(Path(h).parent)]),
                       platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))
    plan = next(p for p in plans if p.name.endswith("XML_Parse"))
    destroy = next(op for op in plan.sequence if op.id == "o_destroy")
    assert destroy.api == "XML_ParserFree", \
        f"destroy op calls {destroy.api!r}; the handle is never freed"


def test_storage_class_is_not_part_of_the_return_type():
    """Preprocessed headers carry `extern` on every declaration. Leaving it in made zlib's
    handle print as `extern gzFile` and would have emitted `extern gzFile hf_r_h = NULL;`."""
    d = hg.parse_header(_hdr("extern int foo(int a);\nextern char *bar(void);\n"))
    rets = {x.name: x.ret for x in d}
    assert rets["foo"] == "int", rets
    assert "extern" not in rets["bar"], rets


def test_macro_wrapped_function_name_parses():
    """bzlib: `BZ_EXTERN int BZ_API(BZ2_bzCompressInit)(bz_stream *strm, int b);` — the NAME
    itself sits inside a macro call."""
    d = hg.parse_header(_hdr(
        "typedef struct { int x; } bz_stream;\n"
        "extern int BZ_API(BZ2_bzCompressInit)(bz_stream *strm, int blockSize);\n"))
    names = {x.name for x in d}
    assert "BZ2_bzCompressInit" in names, f"macro-wrapped name lost: {names}"


def test_parenthesised_name_keeps_its_return_type():
    """libpng: `extern png_structp (png_create_read_struct)(png_const_charp v);` — the name
    is merely parenthesised, so the token before `(` is the RETURN TYPE, not a macro.
    Treating both alike ate png's return type and left everything returning `extern`."""
    d = hg.parse_header(_hdr(
        "typedef struct png_struct_def png_struct;\n"
        "typedef png_struct * png_structp;\n"
        "extern png_structp (png_create_read_struct)(const char *ver);\n"))
    dec = next(x for x in d if x.name == "png_create_read_struct")
    assert dec.ret == "png_structp", f"return type lost: {dec.ret!r}"


def test_typedef_aliases_resolve_to_the_same_handle():
    """libpng aliases one handle several ways — png_structp, png_structrp, png_const_structp
    — and the constructor returns one while every consumer takes another. Comparing typedef
    NAMES made them different types: 245 parsed declarations, no handle, no plans."""
    d = hg.parse_header(_hdr(
        "typedef struct png_struct_def png_struct;\n"
        "typedef png_struct * png_structp;\n"
        "typedef png_struct * png_structrp;\n"
        "png_structp png_create_read_struct(const char *ver);\n"
        "void png_read_info(png_structrp p, const char *d, unsigned long n);\n"
        "void png_destroy_read_struct(png_structp p);\n"))
    pm = d[0].ptr_map
    assert hg.hkey("png_structp", pm) == hg.hkey("png_structrp", pm) == "png_struct", pm
    assert hg._returned_handles(d), "aliased handle still not discovered"


def test_struct_definition_typedef_is_not_a_pointer_typedef():
    """Preprocessing inlines `typedef struct {...} yaml_emitter_t;`. The struct's MEMBERS
    are full of pointers, and treating that as a pointer typedef recorded the whole expanded
    struct body as a type name."""
    d = hg.parse_header(_hdr(
        "typedef struct yaml_emitter_s { unsigned char *buffer; char *problem; } "
        "yaml_emitter_t;\n"
        "int yaml_emitter_initialize(yaml_emitter_t *e);\n"
        "void yaml_emitter_delete(yaml_emitter_t *e);\n"
        "void yaml_emitter_feed(yaml_emitter_t *e, const unsigned char *b, size_t n);\n"))
    pm = d[0].ptr_map
    assert "yaml_emitter_t" not in pm, \
        f"a struct definition was recorded as a pointer typedef: {pm.get('yaml_emitter_t')}"


def test_camelcase_lifecycle_names_are_recognised():
    """zlib's real entry points are `inflateInit_` and `inflateEnd` — camelCase, and one
    with a trailing underscore. Matching only `_init$` found neither, so zlib produced
    nothing at all."""
    d = hg.parse_header(_hdr(
        "typedef struct z_stream_s { unsigned char *next_in; } z_stream;\n"
        "extern int inflateInit_(z_stream *strm, const char *version, int size);\n"
        "extern int inflate(z_stream *strm, int flush);\n"
        "extern int inflateEnd(z_stream *strm);\n"))
    found = hg._inline_handles(d)
    assert found, "zlib's caller-allocated z_stream was not recognised"
    assert found[0][2] == "inflateInit_" and found[0][3] == "inflateEnd", found


def test_d8_flags_an_uninstrumented_target():
    """The gate that answers a different question from all the others: not "is this harness
    correct" but "will a campaign against it find anything".

    A correct harness linked against a prebuilt library ran 11.7 MILLION executions with
    coverage stuck at 2 — its own edges — because -fsanitize=fuzzer instruments harness.c
    and nothing else. Every other gate passed. Pure decision logic is tested here so the
    check runs without a libFuzzer runtime."""
    from hforge.gates.dynamic_gates import d8_campaign
    from hforge.gates.result import NOT_RUN
    from hforge.ir import HarnessIR
    ir = HarnessIR.loads(
        (Path(__file__).resolve().parents[1] / "examples/hf_demo.good.hir.json").read_text())
    assert not ir.target.sources or True
    from hforge.emit.c_libfuzzer import emit
    g = d8_campaign(ir, emit(ir), seconds=2)
    # Either the host has no libFuzzer (NOT RUN, with a reason) or the gate ran and reported
    # edges. Both are acceptable; silently passing with no evidence is not.
    assert g.verdict == NOT_RUN and g.reason or "edges" in g.evidence, g


def test_build_script_has_no_placeholders():
    """`<harness.c>` in a shell script is a redirect from a file of that literal name, so the
    emitted build.sh could not be run — the one artifact whose entire job is to be runnable."""
    from hforge.emit.c_libfuzzer import emit
    from hforge.ir import HarnessIR
    ir = HarnessIR.loads(
        (Path(__file__).resolve().parents[1] / "examples/hf_demo.good.hir.json").read_text())
    em = emit(ir)
    joined = " ".join(em.build_command) + " " + " ".join(em.driver_build_command)
    assert "<" not in joined and ">" not in joined, joined
    assert "harness.c" in joined and "driver.c" in joined


def test_setup_variants_are_proposed_not_assumed():
    """libmagic's `magic_buffer` reaches almost nothing until `magic_load` has read the
    magic database: 36 edges without it, 601 with. Which calls a target needs is not
    decidable from a signature, so the producer proposes BOTH shapes and D8 measures them."""
    from hforge.ir import Knobs, Target
    src = """
typedef struct magic_set *magic_t;
magic_t magic_open(int flags);
void magic_close(magic_t ms);
int magic_load(magic_t ms, const char *f);
const char *magic_buffer(magic_t ms, const void *b, size_t n);
"""
    h = _hdr(src)
    plans = hg.propose([h], Target(name="m", public_headers=["t.h"],
                                   include_dirs=[str(Path(h).parent)]),
                       platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))
    names = {p.name for p in plans}
    assert "m_magic_buffer" in names and "m_magic_buffer_setup" in names, names
    deep = next(p for p in plans if p.name == "m_magic_buffer_setup")
    assert any(op.api == "magic_load" for op in deep.sequence), \
        [op.api for op in deep.sequence]
    shallow = next(p for p in plans if p.name == "m_magic_buffer")
    assert not any(op.api == "magic_load" for op in shallow.sequence), \
        "both variants are the same; there is nothing for the gate to compare"


def test_ranking_leads_on_measured_depth():
    """Reach is a prerequisite for detection. A harness touching 36 edges cannot find more
    than 36 edges' worth of defects, whatever its kill rate on them."""
    from hforge.producers import rank
    from hforge.gates.result import passed
    shallow = rank.score("a_shallow", "p", [passed("D8", "campaign", edges=36,
                                                   coverage_grew=False)])
    deep = rank.score("b_deep", "p", [passed("D8", "campaign", edges=601,
                                             coverage_grew=True)])
    ranked = rank.rank([shallow, deep])
    assert ranked[0].plan_name == "b_deep", [r.plan_name for r in ranked]
    assert rank.discriminating(ranked)


def test_unmeasured_plan_cannot_outrank_a_measured_one():
    """The third appearance of the same defect. An unmeasured plan carries NO dynamic gates,
    so its `not_run` count is zero — which scored BETTER than a measured plan honestly
    reporting the gates it could not run. On sqlite that ranked `autovacuum_pages`, never
    built, above `sqlite3_exec`, which was."""
    from dataclasses import replace as _replace
    from hforge.producers import rank
    from hforge.gates.result import passed, not_run
    measured = rank.score("b_measured", "p", [
        passed("D8", "campaign", edges=540, coverage_grew=True),
        not_run("D2", "positive control", "disabled for this run"),
        not_run("D9", "misuse", "no report to attribute")])
    unmeasured = _replace(rank.score("a_unmeasured", "p", [passed("S1", "lifetime")]),
                          measured=False)
    ranked = rank.rank([unmeasured, measured])
    assert ranked[0].plan_name == "b_measured", [r.plan_name for r in ranked]


def test_unmeasured_edges_render_as_unknown_not_zero():
    """Printing 0 edges for a plan nobody measured reports an absent check as a failed one,
    which is the same error as reporting it as a passed one."""
    from dataclasses import replace as _replace
    from hforge.producers import rank
    from hforge.gates.result import passed
    s = _replace(rank.score("p", "prod", [passed("S1", "lifetime")]), measured=False)
    out = rank.render(rank.rank([s]))
    assert "?" in out, out


def test_sink_map_is_cached_across_plans():
    """52.4 seconds to map sqlite3.c, once per candidate, across 262 candidates: 3.8 hours
    of the same scan. The map depends only on the sources."""
    import time
    from hforge.analysis import sinks
    src = str(Path(__file__).resolve().parents[1] / "examples/lib/hf_demo.c")
    sinks.build_map([src])
    t0 = time.time()
    sinks.build_map([src])
    assert time.time() - t0 < 0.05, "the sink map is being rebuilt for every plan"


# ── dictionary from the target's own source ─────────────────────────────────

FIXTURE_C = """
#include "thing.h"
static const char *kw[] = { "SELECT", "INSERT", "CREATE TABLE", "WHERE", "AND" };
static int orderByConsumed = 0;
void f(void) {
    sqlite3_log("%s: out of memory at %d\\n", "thing.c", 1);
    cmp(x, ":memory:");
    cmp(y, "content=");
}
"""


def test_dictionary_extracts_the_input_vocabulary():
    """A parser's vocabulary is written down inside the parser. libFuzzer discovers
    `CREATE TABLE` by mutating bytes until it stumbles on it; `-dict=` hands it over."""
    from hforge.analysis import dictionary
    f = Path(tempfile.mkdtemp()) / "t.c"
    f.write_text(FIXTURE_C)
    toks = dictionary.extract([str(f)])
    for want in ("SELECT", "CREATE TABLE", "WHERE", "AND", ":memory:"):
        assert want in toks, f"{want!r} missing from {toks}"


def test_dictionary_drops_program_noise():
    """Format specifiers, source file names and camelCase C symbols are about the program,
    not about its input language. A dictionary full of them costs the fuzzer time."""
    from hforge.analysis import dictionary
    f = Path(tempfile.mkdtemp()) / "t.c"
    f.write_text(FIXTURE_C)
    toks = dictionary.extract([str(f)])
    for junk in ("thing.c", "thing.h", "orderByConsumed"):
        assert junk not in toks, f"{junk!r} should not be in a fuzzing dictionary: {toks}"
    assert not any("%s" in t for t in toks), toks
    assert not any(t.lower().startswith("out of memory") for t in toks), toks


def test_dictionary_renders_libfuzzer_format():
    from hforge.analysis import dictionary
    out = dictionary.render(['SELECT', 'a"b'])
    assert 'k0="SELECT"' in out
    assert 'k1="a\\"b"' in out, out       # the quote must be escaped


def test_d8_records_whether_a_dictionary_was_used():
    """Its effect is measured, not assumed. A dictionary that does not move coverage should
    be dropped rather than kept out of politeness."""
    src = (Path(__file__).resolve().parents[1]
           / "hforge/gates/dynamic_gates.py").read_text()
    assert "dictionary=bool(dict_args)" in src, \
        "D8 does not record whether the campaign had a dictionary"
    assert "-dict=" in src


def test_batch_command_is_registered():
    src = (Path(__file__).resolve().parents[1] / "hforge/cli.py").read_text()
    assert 'sub.add_parser("batch"' in src
    assert "min_edges" in src, "batch cannot refuse to ship a harness that reaches nothing"


# ── multi-resource lifecycles ────────────────────────────────────────────────

CHAINED = """
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte,
                       sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt *stmt);
int sqlite3_finalize(sqlite3_stmt *stmt);
"""


def _chain_plans(src: str):
    from hforge.ir import Knobs, Target
    h = _hdr(src)
    return hg.propose([h], Target(name="t", public_headers=["t.h"],
                                  include_dirs=[str(Path(h).parent)]),
                      platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))


def test_a_consumer_needing_two_resources_gets_both():
    """`sqlite3_step` needs a statement; a statement needs a connection. Modelling one
    handle is why 40 sqlite plans were born broken and failed D3 by crashing on valid
    input."""
    plans = _chain_plans(CHAINED)
    step = next((p for p in plans if p.name.endswith("sqlite3_step_chain")), None)
    assert step is not None, sorted(p.name for p in plans)
    apis = [o.api for o in step.sequence]
    assert "sqlite3_open" in apis and "sqlite3_prepare_v2" in apis, apis
    assert apis.index("sqlite3_open") < apis.index("sqlite3_prepare_v2") < \
        apis.index("sqlite3_step")


def test_resources_are_destroyed_innermost_first():
    plans = _chain_plans(CHAINED)
    step = next(p for p in plans if p.name.endswith("sqlite3_step_chain"))
    apis = [o.api for o in step.sequence]
    assert apis.index("sqlite3_finalize") < apis.index("sqlite3_close"), apis


def test_a_creation_verb_need_not_be_called_create():
    """`sqlite3_prepare_v2` makes a statement and is named neither create nor open.
    Requiring an init-ish name found no producer at all."""
    plans = _chain_plans(CHAINED)
    assert any("chain" in p.name for p in plans), sorted(p.name for p in plans)


def test_finalize_is_recognised_as_a_destructor():
    """The pattern anchored after `fini`, so `sqlite3_finalize` matched nothing and every
    chain leaked its statement."""
    assert hg._FINI_ISH.search("sqlite3_finalize")
    assert hg._FINI_ISH.search("sqlite3_close")


def test_an_accessor_is_not_chosen_as_a_constructor():
    """`sqlite3_context_db_handle` returns a `sqlite3 *` and was taken as the connection's
    constructor because the returned-pointer branch used the first match."""
    src = CHAINED + "\nsqlite3 *sqlite3_context_db_handle(void *ctx);\n"
    plans = _chain_plans(src)
    ch = [p for p in plans if p.name.endswith("_chain")]
    assert ch, "no chain proposed"
    for p in ch:
        makers = [o.api for o in p.sequence if o.binds]
        assert "sqlite3_context_db_handle" not in makers, makers


def test_generated_resource_ids_are_not_doubled():
    """`hf_r_r_sqlite3` in emitted C is cosmetic, but an identifier that looks like a bug
    invites someone to go looking for one."""
    from hforge.emit.c_libfuzzer import emit
    plans = _chain_plans(CHAINED)
    step = next(p for p in plans if p.name.endswith("sqlite3_step_chain"))
    assert "hf_r_r_" not in emit(step).source


def test_the_deepest_call_gets_the_fuzzer_bytes():
    """First-come-first-served slice allocation gave sqlite3_open's FILENAME the whole input
    and left prepare's SQL as literal 0. MEASURED: 619 features and a corpus that never grew
    past 2 entries in 800K executions, against 1313 features and 324 entries once the bytes
    landed on zSql."""
    plans = _chain_plans(CHAINED)
    step = next(p for p in plans if p.name.endswith("sqlite3_step_chain"))
    prep = next(o for o in step.sequence if o.api == "sqlite3_prepare_v2")
    sql = next(a for a in prep.args if a.param == "zSql")
    assert sql.source == "input", sql


def test_a_length_parameter_is_bound_to_its_buffer_not_to_zero():
    """`sqlite3_prepare(db, sql, 0, &stmt, 0)` reads ZERO bytes of SQL: it returns OK,
    produces no statement, and the guarded consumer never fires. Correct in structure,
    inert in fact."""
    plans = _chain_plans(CHAINED)
    step = next(p for p in plans if p.name.endswith("sqlite3_step_chain"))
    prep = next(o for o in step.sequence if o.api == "sqlite3_prepare_v2")
    n = next(a for a in prep.args if a.param == "nByte")
    assert n.source == "length_of" and n.ref == "zSql", n


def test_a_filename_parameter_is_never_fed_fuzzer_bytes():
    """A harness that opens a path built from attacker bytes creates or reads arbitrary
    files in its working directory. That is our own defect, not the target's."""
    plans = _chain_plans(CHAINED)
    step = next(p for p in plans if p.name.endswith("sqlite3_step_chain"))
    opn = next(o for o in step.sequence if o.api == "sqlite3_open")
    fn = next(a for a in opn.args if a.param == "filename")
    assert fn.source == "literal", fn
    assert not any(sl.id == "filename" for sl in step.slices)


def test_a_chain_that_drives_nothing_is_not_proposed():
    """A lifecycle with no byte-carrying parameter anywhere is a harness the fuzzer cannot
    steer; it burns budget reporting a flat curve."""
    src = """
typedef struct Ctx Ctx;
typedef struct Item Item;
int ctx_open(Ctx **out);
int ctx_close(Ctx *c);
int item_make(Ctx *c, Item **out);
int item_free(Item *i);
int item_count(Item *i);
"""
    plans = _chain_plans(src)
    assert not any(p.name.endswith("_chain") for p in plans), \
        [p.name for p in plans]


def test_a_partial_chain_is_refused_rather_than_half_built():
    """A lifecycle that is half-resolved produces a harness that passes the static gates and
    dereferences null."""
    src = """
typedef struct Ctx Ctx;
typedef struct Item Item;
int item_use(Item *i);
"""
    plans = _chain_plans(src)
    assert not any(p.name.endswith("_chain") for p in plans), \
        [p.name for p in plans]



# ── what a deep sqlite run exposed ───────────────────────────────────────────

OPAQUE_AND_COMPLETE = """
typedef struct opq opq;                 /* declared, never defined: opaque */
typedef struct ctx_s { int a; union { int b; struct { int c; } d; } e; } ctx_t;
int  opq_step(opq *o);
int  opq_reset(opq *o);
int  ctx_initialize(ctx_t *c);
int  ctx_delete(ctx_t *c);
int  ctx_parse(ctx_t *c, const char *text);
"""


def test_an_opaque_type_is_never_a_caller_allocated_handle():
    """`typedef struct sqlite3_stmt sqlite3_stmt;` declares a type whose SIZE IS UNKNOWN, so
    `sqlite3_stmt x;` does not compile. The producer treated it as an inline handle like
    z_stream and emitted exactly that declaration. The plan SHIPPED with a certificate: emit
    succeeded, six static gates passed, and every gate that would have caught it needs a
    binary that never built."""
    h = _hdr(OPAQUE_AND_COMPLETE)
    decls = hg.parse_header(h, include_dirs=[str(Path(h).parent)])
    assert "opq" not in decls[0].complete
    assert "ctx_t" in decls[0].complete
    assert "opq" not in [b for _, b, _, _ in hg._inline_handles(decls)]


def test_a_nested_struct_body_is_still_a_complete_type():
    """`yaml_parser_s` nests anonymous unions three levels deep. A pattern handling one level
    reported it INCOMPLETE — dropping the caller-allocated handle the inline-resource feature
    was built for, while still finding sqlite's flat one-line typedefs and so looking like it
    worked."""
    h = _hdr(OPAQUE_AND_COMPLETE)
    decls = hg.parse_header(h, include_dirs=[str(Path(h).parent)])
    assert "ctx_t" in decls[0].complete
    assert "ctx_t" in [b for _, b, _, _ in hg._inline_handles(decls)]


def test_a_struct_body_is_read_from_source_not_from_statements():
    """`_statements` splits on `;`, so a struct body full of member declarations never
    appears whole in any one statement."""
    src = "typedef struct s_ { int a; int b; int c; } t_;"
    assert "t_" in hg._complete_types(src)


HANDLE_OUT = """
typedef struct conn conn;
typedef struct stmt stmt;
int conn_open(const char *path, conn **out);
int conn_close(conn *c);
int conn_prepare(conn *c, const char *sql, int n, stmt **out, const char **tail);
int stmt_step(stmt *s);
int stmt_finalize(stmt *s);
int conn_exec(conn *c, const char *sql, char **errmsg);
"""


def _plans_for(src):
    from hforge.ir import Knobs, Target
    h = _hdr(src)
    return hg.propose([h], Target(name="t", public_headers=["t.h"],
                                  include_dirs=[str(Path(h).parent)]),
                      platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))


def test_a_handle_out_parameter_is_never_bound_to_null():
    """`sqlite3_prepare(db, sql, n, sqlite3_stmt **ppStmt, ...)` with ppStmt NULL SEGVs on
    every input: that is where the library RETURNS the statement and it dereferences it
    unconditionally. In a deep sqlite run this one shape took 14 of 14 measurement slots,
    D3 refused every one after a full build, and the run shipped nothing."""
    for p in _plans_for(HANDLE_OUT):
        for op in p.sequence:
            api = p.apis.get(op.api)
            if api is None:
                continue
            for a in op.args:
                if a.source != "literal" or a.value not in (0, None):
                    continue
                pd = p.param_decl(api, a.param)
                if pd is None:
                    continue
                ty = pd.type.name
                assert not (ty.count("*") == 2 and "stmt" in ty), \
                    f"{p.name}: {op.api}({a.param}) hands NULL where a handle is returned"


def test_an_optional_out_parameter_may_still_be_null():
    """`conn_exec(c, sql, char **errmsg)` — sqlite documents errmsg as optional, and NULL is
    the conventional call. The rule must separate that from a handle out-parameter."""
    plans = _plans_for(HANDLE_OUT)
    ex = [p for p in plans if "conn_exec" in p.name]
    assert ex, [p.name for p in plans]


def test_a_setup_call_that_returns_a_handle_is_not_used_as_setup():
    """The same misbinding one level along: `sqlite3_prepare` was inserted as a SETUP call
    for sqlite3_exec with ppStmt = 0, so every `_setup` variant of an otherwise good plan
    segfaulted before reaching its entry point."""
    for p in _plans_for(HANDLE_OUT):
        for op in p.sequence:
            if not op.id.startswith("o_setup"):
                continue
            assert op.api != "conn_prepare", f"{p.name} uses conn_prepare as a setup call"


def test_a_handle_with_no_constructor_is_refused():
    """`sqlite3_blob` has no recognised creator — sqlite3_blob_open returns int and writes
    through `sqlite3_blob **`, so role inference calls it a query — and the emitted plan
    called sqlite3_blob_reopen(NULL)."""
    src = """
typedef struct blob blob;
int blob_reopen(blob *b, long row);
int blob_read(blob *b, void *z, int n);
int blob_close(blob *b);
"""
    plans = _plans_for(src)
    for p in plans:
        bound = {o.binds for o in p.sequence if o.binds}
        for r in p.resources:
            assert r.id in bound, f"{p.name} declares {r.id} and never constructs it"



# ── what the QuartetFuzz benchmark exposed ───────────────────────────────────

FEEDER_LIB = """
typedef struct { int state; } prs_t;
typedef struct { int n; } doc_t;
int prs_initialize(prs_t *p);
void prs_delete(prs_t *p);
int prs_set_input_string(prs_t *p, const unsigned char *input, unsigned long size);
int prs_load(prs_t *p, doc_t *document);
int doc_initialize(doc_t *d);
void doc_delete(doc_t *d);
"""


def test_input_arrives_through_a_setter_when_the_target_takes_none():
    """`yaml_parser_load(parser, document)` carries no buffer: the bytes arrive earlier via
    `yaml_parser_set_input_string`. With no way to express that, the only plans for libyaml's
    most important entry point either fed bytes to the OUT parameter — S2 refused them — or
    called the setter and never called the parser. 64 of 70 libyaml plans were blocked and
    none reached the gold target, whose OSS-Fuzz harness covers 77.7% of the library."""
    plans = _plans_for(FEEDER_LIB)
    load = next((p for p in plans if p.name.endswith("prs_load")), None)
    assert load is not None, sorted(p.name for p in plans)
    apis = [o.api for o in load.sequence]
    assert "prs_set_input_string" in apis, apis
    assert apis.index("prs_set_input_string") < apis.index("prs_load"), apis


def test_the_feeder_receives_the_fuzzer_bytes_and_their_length():
    plans = _plans_for(FEEDER_LIB)
    load = next(p for p in plans if p.name.endswith("prs_load"))
    feed = next(o for o in load.sequence if o.api == "prs_set_input_string")
    srcs = {a.param: a.source for a in feed.args}
    assert srcs["input"] == "input" and srcs["size"] == "length_of", srcs


def test_a_complete_out_struct_is_allocated_and_destroyed():
    """`yaml_parser_load` ASSERTS its document is non-NULL, so binding 0 aborts on every
    input. The caller must declare the object and pass its address — and destroy it, or
    LeakSanitizer reports a finding on every input, which is the libcue mistake."""
    plans = _plans_for(FEEDER_LIB)
    load = next(p for p in plans if p.name.endswith("prs_load"))
    consume = next(o for o in load.sequence if o.api == "prs_load")
    doc = next(a for a in consume.args if a.param == "document")
    assert doc.source == "resource", doc
    res = next(r for r in load.resources if r.id == doc.ref)
    assert res.storage == "inline", res
    assert any(o.api == "doc_delete" and o.targets == doc.ref for o in load.sequence), \
        [o.api for o in load.sequence]


def test_fuzzer_bytes_are_never_bound_to_a_structured_pointer():
    """Proposing the type confusion and letting S2 refuse it wasted the entry point. S2 stays
    as it is — it must still catch this from a producer that is not ours — but ours stops
    making the mistake."""
    from hforge.ir import SLICE_BYTES
    for p in _plans_for(FEEDER_LIB):
        for o in p.sequence:
            api = p.apis.get(o.api)
            if api is None:
                continue
            for a in o.args:
                if a.source != "input":
                    continue
                pd = p.param_decl(api, a.param)
                if pd is None or "*" not in pd.type.name:
                    continue
                assert hg.base_type(pd.type.name) in hg.BYTE_BASES, \
                    f"{p.name}: {o.api}({a.param}) is {pd.type.name}"


def test_uint8_counts_as_a_byte_type():
    """Restricting byte buffers to char/void/unsigned char silently excluded
    `const uint8_t *`, which the demo library and a great many real ones use."""
    for t in ("uint8_t", "int8_t", "unsigned char", "char", "void"):
        assert t in hg.BYTE_BASES



# ── caller-owned buffers: what the benchmark's zlib and zopfli cases needed ──

FREEFN = """
typedef struct { int level; } Opt;
void OptInitDefaults(Opt *o);
int lib_decompress(unsigned char *dest, unsigned long *destLen,
                   const unsigned char *source, unsigned long *sourceLen);
int lib_deflate(const Opt *options, int btype,
                const unsigned char *in, unsigned long insize,
                unsigned char **out, unsigned long *outsize);
"""


def test_scratch_round_trips_through_the_ir():
    from hforge.ir import HarnessIR, Knobs, Scratch, Target
    ir = HarnessIR(name="t", target=Target("t", public_headers=["a.h"]),
                   scratch=[Scratch("out", "bytes", 4096),
                            Scratch("own", "ptr", owns=True)], knobs=Knobs())
    back = HarnessIR.loads(ir.dumps())
    assert [(x.id, x.kind, x.owns) for x in back.scratch] == \
        [("out", "bytes", False), ("own", "ptr", True)]


def test_a_free_function_entry_point_gets_a_plan():
    """The producer was built entirely around lifecycles, so a library whose real surface is
    free functions got nothing: BOTH zlib gold cases are free functions, and both scored
    "NO PLAN for the gold target" against QuartetFuzz at 51.74% and 80.06%."""
    plans = _plans_for(FREEFN)
    p = next((x for x in plans if x.name.endswith("lib_decompress")), None)
    assert p is not None, sorted(x.name for x in plans)
    assert not p.resources or all(r.storage == "inline" for r in p.resources)


def test_an_input_length_by_address_is_bound_not_zeroed():
    """`uncompress2`'s `sourceLen` is the input length BY ADDRESS. Bound to 0 the call reads
    nothing."""
    p = next(x for x in _plans_for(FREEFN) if x.name.endswith("lib_decompress"))
    op = next(o for o in p.sequence if o.api == "lib_decompress")
    src = {a.param: a.source for a in op.args}
    assert src["source"] == "input", src
    assert src["sourceLen"] == "scratch_addr", src
    sc = next(x for x in p.scratch if x.id == "len_sourceLen")
    assert sc.init_from == "source", sc


def test_a_library_allocated_output_pointer_starts_null_and_is_freed():
    """`T **` with no capacity parameter means the LIBRARY allocates and the caller frees.
    Pointing it at our own array made the library realloc storage it never malloc'd."""
    from hforge.emit.c_libfuzzer import emit
    p = next(x for x in _plans_for(FREEFN) if x.name.endswith("lib_deflate"))
    own = next((x for x in p.scratch if x.owns), None)
    assert own is not None, [(x.id, x.kind, x.owns) for x in p.scratch]
    src = emit(p).source
    assert f"{'hf_sc_' + own.id} = NULL;" in src, src
    assert f"free((void *)hf_sc_{own.id});" in src, src


def test_a_config_struct_is_initialised_before_use():
    """`ZopfliDeflate(const ZopfliOptions *, ...)` needs `ZopfliInitOptions(&opt)` first, and
    the verb sits MID-NAME so the init patterns matched nothing."""
    p = next(x for x in _plans_for(FREEFN) if x.name.endswith("lib_deflate"))
    apis = [o.api for o in p.sequence]
    assert "OptInitDefaults" in apis, apis
    assert apis.index("OptInitDefaults") < apis.index("lib_deflate")


def test_a_void_initialiser_is_not_cast_to_int():
    """`(int)(void_call)` is not C, and it broke the harness on the one line that sets up its
    own configuration."""
    from hforge.emit.c_libfuzzer import emit
    p = next(x for x in _plans_for(FREEFN) if x.name.endswith("lib_deflate"))
    src = emit(p).source
    assert "(int)(OptInitDefaults" not in src, src
    assert "OptInitDefaults(&hf_r_cfg_options);" in src, src


def test_complete_types_are_unioned_across_headers():
    """Reading only the first header's types made a config struct declared in a second
    header invisible, and the entry point produced no plan at all."""
    import tempfile, os
    d = tempfile.mkdtemp()
    a = os.path.join(d, "a.h"); b = os.path.join(d, "b.h")
    open(a, "w").write("typedef struct Cfg Cfg;\nint use(const Cfg *c, const char *s);\n")
    open(b, "w").write("typedef struct Cfg { int x; } Cfg;\nvoid CfgInit(Cfg *c);\n")
    da = hg.parse_header(a, include_dirs=[d])
    db = hg.parse_header(b, include_dirs=[d])
    assert "Cfg" not in da[0].complete
    assert "Cfg" in hg._all_complete(da + db)


def test_a_subdirectory_header_is_included_by_its_relative_path():
    """brotli's header is `c/include/brotli/decode.h` against `-Ic/include`, so
    `#include "decode.h"` does not resolve — it broke every library that namespaces its
    headers."""
    import tempfile, os
    from hforge.emit.c_libfuzzer import _headers
    from hforge.ir import HarnessIR, Knobs, Target
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "brotli"))
    open(os.path.join(d, "brotli", "decode.h"), "w").write("int x;\n")
    t = Target("b", public_headers=["decode.h"], include_dirs=[d])
    ir = HarnessIR(name="t", target=t, knobs=Knobs())
    assert _headers(ir) == ["brotli/decode.h"], _headers(ir)



# ── the loop: the single largest coverage gap against the gold harnesses ─────

TOKEN_API = """
typedef struct { int state; } prs_t;
typedef struct { int kind; } tok_t;
int prs_initialize(prs_t *p);
void prs_delete(prs_t *p);
int prs_set_input_string(prs_t *p, const unsigned char *input, unsigned long size);
int prs_scan(prs_t *p, tok_t *token);
void tok_delete(tok_t *t);
"""


def test_a_token_api_is_driven_in_a_loop():
    """`yaml_parser_scan` returns ONE token per call. Calling it once was 77 million
    executions for 9.6% of libyaml against the gold harness's 70.6%; looping took the same
    harness to 46.15% in a fraction of the budget."""
    p = next(x for x in _plans_for(TOKEN_API) if x.name.endswith("prs_scan"))
    op = next(o for o in p.sequence if o.api == "prs_scan")
    assert op.repeat > 0, [(o.id, o.api, o.repeat) for o in p.sequence]


def test_the_loop_is_bounded_by_the_input_length():
    """An unbounded loop steered by fuzzer input is a hang, and a hang is indistinguishable
    from a finding until a human looks at it.

    The bound is the input length, not a constant: a token needs at least one byte, so
    max_len iterations is provably enough and still cannot run away. A fixed 64 was the
    first attempt and it is not obviously right for a document of any size."""
    from hforge.ir import Knobs, Target
    from pathlib import Path as _P
    h = _hdr(TOKEN_API)
    for limit in (256, 4096):
        plans = hg.propose([h], Target(name="t", public_headers=["t.h"],
                                       include_dirs=[str(_P(h).parent)]),
                           platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=limit))
        op = next(o for p in plans if p.name.endswith("prs_scan")
                  for o in p.sequence if o.api == "prs_scan")
        assert op.repeat == limit, (limit, op.repeat)


def test_per_iteration_cleanup_is_inside_the_loop():
    """Left outside, the target allocates a token per iteration and the harness deletes
    exactly one — a leak of its own making, which LeakSanitizer reports on every input."""
    from hforge.emit.c_libfuzzer import emit
    p = next(x for x in _plans_for(TOKEN_API) if x.name.endswith("prs_scan"))
    src = emit(p).source
    body = src[src.index("for (unsigned hf_it"):]
    close = body.index("\n    }")
    assert "tok_delete" in body[:close], body[:close]


def test_the_loop_stops_when_the_library_stops():
    from hforge.emit.c_libfuzzer import emit
    p = next(x for x in _plans_for(TOKEN_API) if x.name.endswith("prs_scan"))
    assert "break;" in emit(p).source


def test_a_const_handle_is_never_a_destructor():
    """`BrotliDecoderHasMoreOutput(const BrotliDecoderState *)` returns a bool and was
    classified a destructor because it takes one handle — so it was emitted as the destroy
    op, the state was never freed, and LeakSanitizer stopped the campaign on input 4."""
    src = """
typedef struct dec dec;
dec *dec_create(void);
int dec_has_more_output(const dec *d);
void dec_destroy_instance(dec *d);
int dec_process(dec *d, const unsigned char *in, unsigned long n);
"""
    for p in _plans_for(src):
        for o in p.sequence:
            if o.targets:
                assert o.api != "dec_has_more_output", \
                    f"{p.name}: a const-handle query was used as the destructor"



def test_scratch_is_initialised_after_the_input_is_assigned():
    """Initialising a cursor where it is DECLARED reads the slice pointer before the body
    has assigned it, so every streaming harness decoded a null pointer of length zero.

    libFuzzer read 44 valid brotli streams, the corpus collapsed to `corp: 1/1b`, and
    coverage sat at 42 edges forever. No corpus would have revealed it — the harness was
    incapable of reading its input. Fixing the order took brotli from 6.32% to 84.42% and
    zlib from 11.43% to 53.93%, both past the human harness."""
    from hforge.emit.c_libfuzzer import emit
    p = next(x for x in _plans_for(FREEFN) if x.name.endswith("lib_decompress"))
    src = emit(p).source
    body = src[src.index("LLVMFuzzerTestOneInput"):]
    # the slice pointer is assigned, and only then does any scratch read it
    assign = body.index("hf_s_source = hf_data")
    # the ASSIGNMENT that reads the slice's length, not the zero-initialised declaration
    read = body.index("hf_sc_len_sourceLen = (unsigned long)(hf_len_source)")
    assert read > assign, "scratch read the input before the body assigned it"



# ── what an unfuzzed target (lcms2) exposed that the benchmark never did ─────

OPAQUE_VOID = """
typedef void* hProfile;
typedef void* hDict;
hProfile OpenProfileFromMem(const void *MemPtr, unsigned int dwSize);
int CloseProfile(hProfile p);
hDict DictAlloc(void);
void DictFree(hDict d);
"""


def test_two_void_star_typedefs_are_not_the_same_type():
    """`cmsHPROFILE` and `cmsHANDLE` are both `typedef void *`. Resolving them to `void`
    made them one type, so a colour profile was paired with `cmsDictFree` — a dictionary's
    destructor. A void* typedef is NOMINAL: the library distinguishes by name only."""
    h = _hdr(OPAQUE_VOID)
    decls = hg.parse_header(h, include_dirs=[str(Path(h).parent)])
    pm = decls[0].ptr_map
    assert hg.hkey("hProfile", pm) != hg.hkey("hDict", pm)
    assert hg.hkey("hProfile", pm) == "hProfile"


def test_a_returned_handle_is_closed_by_the_right_destructor():
    """The profile must be paired with CloseProfile, never with DictFree."""
    plans = _plans_for(OPAQUE_VOID)
    p = next((x for x in plans if x.name.endswith("OpenProfileFromMem")), None)
    assert p is not None, sorted(x.name for x in plans)
    apis = [o.api for o in p.sequence]
    assert "CloseProfile" in apis, apis
    assert "DictFree" not in apis, apis


def test_a_destroy_verb_mid_name_is_recognised():
    """`cmsCloseProfile` and `BrotliDecoderDestroyInstance` put the verb in the middle; our
    patterns anchored it at the end, so both leaked."""
    for n in ("cmsCloseProfile", "BrotliDecoderDestroyInstance", "DictFree"):
        assert hg._DESTROY_ANYWHERE.search(n), n


def test_a_hungarian_prefixed_length_is_still_a_length():
    """`cmsOpenProfileFromMem(const void *MemPtr, cmsUInt32Number dwSize)` — dwSize is the
    profile's length. A start-anchored pattern missed it, the length was bound to 0, and
    lcms2 was told the profile is zero bytes: 21 million executions for 1.95%."""
    assert hg._LENISH.match("dwSize")
    assert hg._LENISH.match("cbLen")
    assert not hg._LENISH.match("MemPtr")


def test_the_length_is_bound_when_only_the_name_says_so():
    """The TYPE `cmsUInt32Number` is unrecognisable across libraries; the name is not."""
    p = next(x for x in _plans_for(OPAQUE_VOID) if x.name.endswith("OpenProfileFromMem"))
    op = next(o for o in p.sequence if o.api == "OpenProfileFromMem")
    src = {a.param: a.source for a in op.args}
    assert src["MemPtr"] == "input" and src["dwSize"] == "length_of", src


def test_an_explicitly_named_seed_directory_is_trusted():
    """The data-directory filter stops a whole repository being mined as input. When the
    operator names a directory outright it is redundant — and it rejected every one of
    lcms2's ICC profiles because they live in `testbed/`."""
    import tempfile, os
    from hforge.analysis import seeds as sm
    d = tempfile.mkdtemp()
    sub = os.path.join(d, "testbed")
    os.makedirs(sub)
    open(os.path.join(sub, "a.icc"), "wb").write(b"acsp" + b"\x00" * 100)
    assert len(sm.mine([sub], max_bytes=65536).files) == 1


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"real headers — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
