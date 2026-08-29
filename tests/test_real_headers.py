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


def test_a_reuse_verb_does_not_win_the_destructor_slot():
    """`reset` clears a resource for reuse; it does not release it.

    libde265 declares both:

        void       de265_reset(de265_decoder_context*);
        de265_error de265_free_decoder(de265_decoder_context*);

    `de265_reset` returns void, takes only the handle, and ends in a verb `_FINI_ISH`
    matches — so it ranked as the best destructor and beat the real one, which returns a
    status and therefore only matched the weaker any-position pattern.

    The harness would then never free the decoder: every input leaks the whole context,
    and under LeakSanitizer every finding is the harness's own. Same shape as expat's
    XML_DefaultCurrent and Brotli's HasMoreOutput, a third time.
    """
    plans = _plans_for("""
        typedef struct de265_decoder_context de265_decoder_context;
        typedef int de265_error;
        de265_decoder_context* de265_new_decoder(void);
        de265_error de265_push_data(de265_decoder_context*, const void* data, int length);
        void de265_reset(de265_decoder_context*);
        de265_error de265_free_decoder(de265_decoder_context*);
    """)
    consuming = [p for p in plans if any(o.api == "de265_push_data" for o in p.sequence)]
    assert consuming, "no plan drives de265_push_data"

    for p in consuming:
        destroy = [o for o in p.sequence if o.targets]
        assert destroy, f"{p.name}: nothing destroys the decoder"
        assert destroy[0].api == "de265_free_decoder", (
            f"{p.name}: destroyed with {destroy[0].api!r}. A reuse verb is not a "
            f"destructor, and the decoder is left leaked on every input.")


def test_a_reuse_verb_is_still_used_when_a_library_offers_nothing_else():
    """The demotion is a RANKING change, not an exclusion.

    A library whose only teardown call is `_reset` should still get it. Demoting reuse
    verbs below real candidates must not turn 'the weaker choice' into 'no choice', which
    would refuse plans that are as good as that library allows.
    """
    plans = _plans_for("""
        typedef struct ctx ctx;
        ctx* ctx_new(void);
        int ctx_parse(ctx*, const char* data, int n);
        void ctx_reset(ctx*);
    """)
    consuming = [p for p in plans if any(o.api == "ctx_parse" for o in p.sequence)]
    assert consuming, "no plan drives ctx_parse"
    assert any(o.api == "ctx_reset" and o.targets
               for p in consuming for o in p.sequence), (
        "with no alternative, the reuse verb should still be chosen")


YAJL_ERR = """
typedef struct yajl_handle_t * yajl_handle;
typedef struct { int dummy; } yajl_callbacks;
typedef int yajl_status;
yajl_handle yajl_alloc(const yajl_callbacks *callbacks, void *afs, void *ctx);
yajl_status yajl_parse(yajl_handle hand, const unsigned char *jsonText, size_t jsonTextLen);
yajl_status yajl_complete_parse(yajl_handle hand);
unsigned char * yajl_get_error(yajl_handle hand, int verbose, const unsigned char *jsonText, size_t jsonTextLen);
void yajl_free_error(yajl_handle hand, unsigned char * str);
void yajl_free(yajl_handle handle);
"""


def _yajl_plan(src=YAJL_ERR, api="yajl_parse"):
    return next((p for p in _plans_for(src)
                 if any(o.api == api for o in p.sequence)), None)


def test_the_harness_asks_the_library_why_it_failed():
    """Roughly a hundred lines of yajl are reachable only through this call.

    MEASURED in run-009: yajl is the one case behind gold, 65.12 against 69.1, and the
    deficit is almost entirely yajl.c at 45.26% while the lexer sits at 77%. The uncovered
    functions are yajl_render_error_string (72 lines), yajl_status_to_string,
    yajl_get_bytes_consumed and yajl_get_error itself — all of them behind "the caller
    asked what went wrong". A fuzzer drives the failure path constantly and the harness
    never asked.
    """
    p = _yajl_plan()
    assert p is not None, "no plan drives yajl_parse"
    acc = [o for o in p.sequence if o.api == "yajl_get_error"]
    assert acc, f"error accessor never called: {[o.api for o in p.sequence]}"
    assert acc[0].binds, "the returned string is owned and must bind a resource"


def test_the_error_string_is_freed_by_its_own_pair():
    """yajl_get_error returns OWNED memory. Without yajl_free_error the harness leaks on
    every failing input, and under LeakSanitizer every finding is the harness's own —
    which is exactly what S1 exists to block."""
    p = _yajl_plan()
    acc = next(o for o in p.sequence if o.api == "yajl_get_error")
    freed = [o for o in p.sequence if o.targets == acc.binds]
    assert freed, f"{acc.binds!r} is bound and never released"
    assert freed[0].api == "yajl_free_error", f"released by {freed[0].api!r}"
    assert p.sequence.index(freed[0]) > p.sequence.index(acc), "freed before it is acquired"


def test_an_error_accessor_with_no_freer_is_not_called_at_all():
    """Half the pair is worse than neither half.

    Calling an owned-return accessor without its release is a leak on every input. When a
    library offers no matching freer the accessor must be left out, not called anyway.
    """
    src = YAJL_ERR.replace("void yajl_free_error(yajl_handle hand, unsigned char * str);", "")
    p = _yajl_plan(src)
    assert p is not None
    assert not [o for o in p.sequence if o.api == "yajl_get_error"], (
        "accessor called with nothing to free its result: every input leaks")


def test_a_verbose_flag_is_not_bound_to_the_input_length():
    """A scalar beside a buffer looks like a length until you read the contract.

    Binding by 'is this an integer' put `int verbose` on length_of(jsonText). It is a
    flag, and the pairing that matters is the one the DECLARED contract records.
    """
    p = _yajl_plan()
    acc = next(o for o in p.sequence if o.api == "yajl_get_error")
    by = {a.param: a for a in acc.args}
    assert by["verbose"].source == "literal", (
        f"verbose bound as {by['verbose'].source!r}, not a literal")
    # 0, not 1. Choosing 1 to "reach more of the renderer" walked into a stack overflow in
    # yajl_render_error_string and took the case from 65.12% to 0.00%.
    assert by["verbose"].value == 0, (
        f"verbose is {by['verbose'].value}; a scalar we did not have to choose gets 0")
    assert by["jsonTextLen"].source == "length_of", "the real length lost its binding"


def test_an_owned_return_keeps_its_pointer_type():
    """`unsigned char *` must not be declared as `unsigned char`.

    hkey() resolves a type to its BASE, which is right for matching handles across typedef
    aliases and wrong for declaring a variable. It turned `unsigned char *` into
    `unsigned char`, the emitter declared a one-byte variable, the returned pointer was
    truncated into it, and the paired free segfaulted on the third execution. Measured as
    0.00% on a case that had been 65.12%.

    The handle escaped only because `yajl_handle` is a typedef that carries its own star.
    """
    p = _yajl_plan()
    err = next(o for o in p.sequence if o.api == "yajl_get_error")
    res = next(r for r in p.resources if r.id == err.binds)
    assert "*" in res.type.name, (
        f"resource {res.id!r} declared as {res.type.name!r}: the pointer is gone, and the "
        f"emitter takes the star from the type name")

    from hforge.emit import emit
    decl = [l.strip() for l in emit(p).source.splitlines()
            if "hf_r_err" in l and "=" in l and "NULL" in l][0]
    assert "*" in decl, f"emitted a non-pointer declaration: {decl}"


def test_an_all_caps_type_is_not_mistaken_for_an_export_macro():
    """`LEPT_DLL extern PIX * pixReadMem(...)` — LEPT_DLL is a macro, PIX is the type.

    Case alone cannot tell them apart, and stripping both left the return type as a bare
    `*`, which has no identifier, so the declaration was dropped. With it went every
    pointer-returning function in leptonica: 1482 declarations parsed, no pixReadMem, and
    the handle mis-inferred as `l_uint8 *` from a parameter. PIX, FPIX, DPIX, PIXCMAP,
    NUMA and SARRAY are all types spelled in capitals.
    """
    assert hg._clean_return("LEPT_DLL extern PIX *") == "PIX *"
    assert hg._clean_return("LEPT_DLL extern l_ok") == "l_ok"
    # a macro that really is only decoration still goes
    assert hg._clean_return("XMLPUBFUN xmlDocPtr XMLCALL") == "xmlDocPtr"


def test_an_attribute_macro_after_the_parameter_list_is_not_the_declaration():
    """jansson declares its entry point with a trailing attribute macro.

        json_t *json_loadb(const char *buf, size_t n, size_t flags, json_error_t *error)
            JANSSON_ATTRS((warn_unused_result));

    Scanning backwards for the parameter list finds JANSSON_ATTRS's parentheses, so the
    declaration parsed as name='JANSSON_ATTRS' and json_loadb was never seen at all.
    """
    head, name, params = hg._split_call(
        "json_t *json_loadb(const char *buffer, size_t buflen, size_t flags, "
        "json_error_t *error) JANSSON_ATTRS((warn_unused_result))")
    assert name == "json_loadb", f"parsed the attribute macro as the function: {name!r}"
    assert hg._clean_return(head) == "json_t *"
    assert "buflen" in params


def test_a_macro_wrapping_the_name_is_still_stripped():
    """The guard that makes the fix above safe.

    `BZ_API(BZ2_bzCompressInit)(bz_stream *strm)` also ends in `)...)`, but the text
    before the macro does NOT end in `)`, so it is a wrapped NAME and not a trailing
    attribute. Treating the two alike would break bzip2 and png.
    """
    _, name, _ = hg._split_call("BZ_EXTERN int BZ_API(BZ2_bzCompressInit)(bz_stream *strm)")
    assert name == "BZ2_bzCompressInit"
    head, name, _ = hg._split_call(
        "extern png_structp (png_create_read_struct)(png_const_charp ver)")
    assert name == "png_create_read_struct"
    assert hg._clean_return(head) == "png_structp"


JBIG2 = """
typedef struct _Jbig2Ctx Jbig2Ctx;
typedef struct _Jbig2Allocator Jbig2Allocator;
typedef struct _Jbig2GlobalCtx Jbig2GlobalCtx;
typedef struct _Jbig2Image Jbig2Image;
typedef int Jbig2Options;
typedef void (*Jbig2ErrorCallback)(void *data, const char *msg, int severity, int seg);
#define JBIG2_VERSION_MAJOR (0)
#define JBIG2_VERSION_MINOR (20)
Jbig2Ctx *jbig2_ctx_new_imp(Jbig2Allocator *allocator, Jbig2Options options,
                            Jbig2GlobalCtx *global_ctx, Jbig2ErrorCallback error_callback,
                            void *error_callback_data,
                            int jbig2_version_major, int jbig2_version_minor);
Jbig2Allocator *jbig2_ctx_free(Jbig2Ctx *ctx);
int jbig2_data_in(Jbig2Ctx *ctx, const unsigned char *data, size_t size);
int jbig2_complete_page(Jbig2Ctx *ctx);
"""


def _jbig2_plan():
    return next((p for p in _plans_for(JBIG2)
                 if any(o.api == "jbig2_data_in" for o in p.sequence)), None)


def test_a_handle_nothing_can_construct_does_not_refuse_the_constructor():
    """jbig2dec parsed perfectly and proposed ZERO plans.

    `jbig2_ctx_new_imp(Jbig2Allocator *, ..., Jbig2GlobalCtx *, ...)` was refused because
    both pointer parameters count as returned handles — and they count only because a
    DESTRUCTOR hands the allocator back: `Jbig2Allocator *jbig2_ctx_free(Jbig2Ctx *)`.
    Nothing in the library constructs either type, so NULL is the only call anyone could
    make, and refusing produced no harness at all.

    Refusing is right when the library CAN build the thing — sqlite3_blob_open with a NULL
    connection crashes on every valid input. The test is not "is this a handle" but "can
    this library create one".
    """
    assert _jbig2_plan() is not None, "no plan for an API whose every role is correct"


def test_a_typedef_hides_a_callback_and_it_still_binds_null():
    """`typedef void (*Jbig2ErrorCallback)(...)` has no star at the use site.

    The inline-callback check looks for `(*`, so a callback behind a typedef reads as an
    ordinary unmappable type. Binding fuzzer bytes to it would have the library call an
    address made of input.
    """
    p = _jbig2_plan()
    create = next(o for o in p.sequence if o.api == "jbig2_ctx_new_imp")
    cb = next(a for a in create.args if a.param == "error_callback")
    assert cb.source == "literal" and not cb.value, f"callback bound as {cb.source}:{cb.value}"


def test_a_version_parameter_takes_the_constant_it_is_named_after():
    """jbig2_ctx_new_imp returns NULL when the version arguments do not match.

    The real constructor is a macro passing JBIG2_VERSION_MAJOR/MINOR. A producer reading
    declarations sees only the _imp function and binds 0, so the handle is NULL, every
    guarded call is skipped, and the campaign runs for ten minutes touching nothing.

    `jbig2_version_minor` uppercases to JBIG2_VERSION_MINOR, which the header defines as
    20. Read from the header, not guessed.
    """
    p = _jbig2_plan()
    create = next(o for o in p.sequence if o.api == "jbig2_ctx_new_imp")
    by = {a.param: a.value for a in create.args}
    assert by["jbig2_version_minor"] == 20, (
        f"version minor bound to {by['jbig2_version_minor']}; the header says 20 and the "
        f"library returns NULL for anything else")
    assert by["jbig2_version_major"] == 0


def test_a_librarys_own_byte_spelling_is_read_not_guessed():
    """BYTE_BASES was a list of SPELLINGS and it grew once per library.

    Bytef for zlib, guchar for glib, xmlChar for libxml2, png_byte for libpng. leptonica
    spells a byte `l_uint8`, and without that spelling `pixReadMem(const l_uint8 *,
    size_t)` does not look like it takes bytes: the producer concludes the entry point has
    no input and goes looking for a setter to feed the handle.

    The header says `typedef unsigned char l_uint8;`. Reading it retires the list instead
    of extending it.
    """
    plans = _plans_for("""
        typedef unsigned char l_uint8;
        typedef struct Pix PIX;
        PIX * pixReadMem(const l_uint8 *data, size_t size);
        void pixDestroy(PIX **ppix);
    """)
    assert hg.base_type("const l_uint8 *") == "unsigned char", (
        "the alias was not followed; every byte check still depends on the spelling")
    consuming = [p for p in plans if any(o.api == "pixReadMem" for o in p.sequence)]
    assert consuming, "no plan drives an entry point that plainly takes (bytes, len)"
    for p in consuming:
        op = next(o for o in p.sequence if o.api == "pixReadMem")
        assert any(a.source == "input" for a in op.args), (
            f"{p.name}: fuzzer bytes never reach the call")


def test_an_opaque_struct_typedef_is_not_followed():
    """The guard on the fix above, and it is not hypothetical.

    Resolving EVERY scalar typedef put `typedef struct _Jbig2Ctx Jbig2Ctx;` in the table,
    so base_type("Jbig2Ctx") answered "struct _Jbig2Ctx" after the qualifier strip had
    already run, and handles stopped comparing equal to themselves. Nine tests failed.
    Only aliases that bottom out in a byte type belong in that table.
    """
    _plans_for("""
        typedef struct _Jbig2Ctx Jbig2Ctx;
        typedef unsigned char jb_byte;
        Jbig2Ctx *jb_new(void);
        int jb_data_in(Jbig2Ctx *ctx, const jb_byte *data, size_t size);
        void jb_free(Jbig2Ctx *ctx);
    """)
    assert hg.base_type("Jbig2Ctx") == "Jbig2Ctx", "an opaque handle typedef was followed"
    assert hg.base_type("const jb_byte *") == "unsigned char", "the byte alias was not"


def test_a_declaration_after_an_inline_body_is_not_discarded():
    """Header-only helpers are everywhere, and jansson showed what they cost.

        static JSON_INLINE json_t *json_incref(json_t *j) { ... }
        void json_delete(json_t *json);

    Statements split on `;`, so the second arrives carrying the first's closing brace, and
    a check for `{` threw the whole thing away. jansson then had a handle it must free and
    NO destructor, so every plan using its entry point was dropped for leaking and the
    benchmark reported "NO PLAN for the gold target" on a library that parsed fine.

    The brace strip has to run BEFORE the definition check, because the statement carries
    both braces. The version that ran it after did not work.
    """
    decls = hg.parse_header(_hdr("""
        typedef struct json_t json_t;
        static inline json_t *json_incref(json_t *j) { return j; }
        void json_delete(json_t *json);
        json_t *json_loadb(const char *buffer, size_t buflen);
    """))
    names = {d.name for d in decls}
    assert "json_delete" in names, (
        f"the declaration after the inline body was discarded: {sorted(names)}")
    assert "json_incref" not in names, "an inline DEFINITION is not a declaration"


def test_the_ir_records_what_a_typedef_resolves_to():
    """A gate must not depend on the producer, and it still has to know what a type is.

    `const l_uint8 *` and `const unsigned char *` are the same type, and only leptonica's
    environ.h says so. Without a place to record it, S2 saw a pointer to an unknown
    structured type, called binding fuzzer bytes to it type confusion, and refused the only
    correct harness for pixReadMem.

    Recorded on the IR, so the gate judges a fact printed in the certificate rather than a
    claim passed to it.
    """
    plans = _plans_for("""
        typedef unsigned char l_uint8;
        typedef struct Pix PIX;
        PIX * pixReadMem(const l_uint8 *data, size_t size);
        void pixDestroy(PIX **ppix);
    """)
    p = next(x for x in plans if any(o.api == "pixReadMem" for o in x.sequence))
    api = p.apis["pixReadMem"]
    data = next(q for q in api.params if q.name == "data")
    assert data.type.resolved == "unsigned char", (
        f"resolution not recorded: name={data.type.name!r} resolved={data.type.resolved!r}")

    from hforge.gates.static_gates import run_static_gates
    from hforge.gates.result import BLOCK
    blocks = {v.code for r in run_static_gates(p) for v in r.violations if v.severity == BLOCK}
    assert "S2.TYPE_CONFUSION" not in blocks, (
        "the gate still refuses a byte buffer it cannot spell")


def test_a_destructor_taking_the_address_of_the_handle_gets_it():
    """`void pixDestroy(PIX **ppix)` takes the ADDRESS so it can NULL the caller's variable.

    `by_address` only fired on the CREATE call, so the destroy passed `PIX *` where `PIX **`
    was declared. Every static gate passed — the plan is right — and the generated C did not
    compile. run-016 caught it only because the emitter-defect gate exists; before that it
    was a warning and a garbage number.
    """
    from hforge.emit import emit
    plans = _plans_for("""
        typedef unsigned char l_uint8;
        typedef struct Pix PIX;
        PIX * pixReadMem(const l_uint8 *data, size_t size);
        void pixDestroy(PIX **ppix);
    """)
    p = next(x for x in plans if any(o.api == "pixReadMem" for o in x.sequence))
    line = next(l for l in emit(p).source.splitlines() if "pixDestroy" in l and "(" in l)
    assert "&" in line, f"destructor did not get the address: {line.strip()}"


def test_a_callee_filled_struct_is_declared_not_refused():
    """`json_loadb(buf, n, flags, json_error_t *error)` — the library fills the error.

    A complete struct pointer was only understood as a CONFIG needing an initialiser, so a
    parameter with no initialiser refused the whole plan and jansson's entry point produced
    nothing. `const` separates the two: `const T *` is an input the library reads and still
    needs its initialiser, a bare `T *` is a slot for the callee to write.
    """
    from hforge.emit import emit
    plans = _plans_for("""
        typedef struct json_t json_t;
        typedef struct { int line; int column; char text[160]; } json_error_t;
        json_t *json_loadb(const char *buffer, size_t buflen, size_t flags, json_error_t *error);
        void json_delete(json_t *json);
    """)
    hit = [p for p in plans if any(o.api == "json_loadb" for o in p.sequence)]
    assert hit, "the entry point was refused for a slot the callee fills"
    p = hit[0]
    res = next(r for r in p.resources if r.id.startswith("out_"))
    assert res.storage == "out", f"storage is {res.storage!r}, so S1 will call it unborn"
    src = emit(p).source
    assert "memset(&" in src, "the slot is not zeroed before the library writes to it"
    call = next(l for l in src.splitlines() if "json_loadb(" in l and "=" in l)
    assert "&" in call, f"the slot was not passed by address: {call.strip()}"


def test_a_const_config_struct_still_needs_its_initialiser():
    """The guard on the fix above.

    `ZopfliDeflate(const ZopfliOptions *options, ...)` reads that struct. Handing it a
    zeroed one is a guess about a contract we cannot see, so a const struct pointer with no
    initialiser must still refuse.
    """
    plans = _plans_for("""
        typedef struct { int numiterations; int blocksplitting; } ZopfliOptions;
        void ZopfliDeflate(const ZopfliOptions *options, int btype, int final,
                           const unsigned char *in, size_t insize,
                           unsigned char **out, size_t *outsize);
    """)
    for p in plans:
        for o in p.sequence:
            if o.api != "ZopfliDeflate":
                continue
            arg = next((a for a in o.args if a.param == "options"), None)
            if arg is not None and arg.source == "resource":
                res = next(r for r in p.resources if r.id == arg.ref)
                assert res.storage != "out", (
                    "a const config was treated as a callee-filled slot and passed zeroed")


def test_a_generic_void_free_releases_an_owned_return():
    """`uint8_t *WebPDecodeRGBA(...)` is released by `void WebPFree(void *)`.

    Matching by type finds nothing, because void is not uint8_t, so the harness cast the
    returned pointer to long, added it to the sink, and leaked a decoded image on every
    input. A generic named free is a LAST-RESORT destructor: a typed one always wins, and
    it must be named as a free or a void*-taking callback registrar would qualify.

    Proposing it is safe because the gates check it — freeing an interior pointer aborts
    under ASan on the first valid input and D3 refuses the plan before any campaign.
    """
    from hforge.emit import emit
    plans = _plans_for("""
        typedef unsigned char uint8_t;
        uint8_t *WebPDecodeRGBA(const uint8_t *data, size_t data_size, int *width, int *height);
        void WebPFree(void *ptr);
    """)
    p = next((x for x in plans if any(o.api == "WebPDecodeRGBA" for o in x.sequence)), None)
    assert p is not None, "no plan for an entry point that plainly takes (bytes, len)"
    assert any(o.api == "WebPFree" for o in p.sequence), (
        f"the decoded image is never released: {[o.api for o in p.sequence]}")
    src = emit(p).source
    assert "WebPFree(" in src and "(long)WebPDecodeRGBA" not in src, (
        "the return was discarded into the sink instead of being held and freed")


def test_a_callee_filled_struct_is_freed_when_the_library_offers_a_free():
    """`png_image_begin_read_from_memory(png_imagep image, ...)` hangs an opaque control
    block off the caller's struct, and `png_image_free` releases it.

    The out-slot path declared the struct and looked for no destructor — right for
    jansson's json_error_t, where none exists, and wrong here, so libpng gate-passed,
    compiled and leaked on every input. Same rule as the error accessor: half the pair is
    worse than neither half.

    Three things had to be right and the gates caught each: the free goes in TEARDOWN, not
    setup, or S1 reports USE_AFTER_DESTROY; its API must be registered, or S2 reports
    UNKNOWN_API; and a caller-allocated struct is marked dead rather than assigned NULL,
    which does not compile.
    """
    from hforge.emit import emit
    plans = _plans_for("""
        typedef struct { int version; int width; int height; void *opaque; } png_image;
        int png_image_begin_read_from_memory(png_image *image, const void *memory, size_t size);
        void png_image_free(png_image *image);
    """)
    p = next((x for x in plans
              if any(o.api == "png_image_begin_read_from_memory" for o in x.sequence)), None)
    assert p is not None, "no plan for an entry point that takes (bytes, len)"
    apis = [o.api for o in p.sequence]
    assert "png_image_free" in apis, f"the control block is never released: {apis}"
    assert apis.index("png_image_free") > apis.index("png_image_begin_read_from_memory"), (
        f"freed before it is filled: {apis}")
    src = emit(p).source
    assert "png_image_free(&" in src, "the struct was not passed by address"
    assert "hf_r_out_image = NULL" not in src, (
        "a caller-allocated struct was assigned NULL, which does not compile")


def test_a_typedef_to_void_is_an_opaque_handle_not_a_byte_buffer():
    """`typedef void de265_decoder_context;` is the opaque handle idiom.

    libcurl spells it `typedef void CURL;`. Byte-alias resolution keeps aliases that bottom
    out in BYTE_BASES, and `void` is in that list for the sake of `const void *data`
    buffers — so the handle resolved to void, lost its identity, stopped being found as a
    returned handle, and the stream binder bound a SCRATCH BUFFER cast to
    `de265_decoder_context *` as the decoder.

    Every static gate passed and the emitted C compiled: a type-confused harness with a
    clean certificate, which is the worst outcome this engine can produce. Same principle
    as P3.NOMINAL, broken by the alias resolution added hours after it.
    """
    src = """
        typedef void de265_decoder_context;
        typedef int de265_error;
        de265_decoder_context* de265_new_decoder(void);
        de265_error de265_push_data(de265_decoder_context*, const void* data, int length);
        de265_error de265_decode(de265_decoder_context*, int* more);
        de265_error de265_free_decoder(de265_decoder_context*);
    """
    plans = _plans_for(src)
    assert hg.base_type("de265_decoder_context *") == "de265_decoder_context", (
        "an opaque void typedef was resolved away and the handle lost its identity")
    hit = [p for p in plans if any(o.api == "de265_push_data" for o in p.sequence)]
    assert hit, "no plan drives the entry point"
    seq = [o.api for o in hit[0].sequence]
    assert "de265_new_decoder" in seq and "de265_free_decoder" in seq, (
        f"the lifecycle collapsed to a free function: {seq}")


def test_a_driver_loops_on_the_flag_the_library_writes():
    """`de265_decode(ctx, int *more)` sets `more` to 0 when the decoder is finished.

    Calling it once left NAL units queued that de265_free_decoder does not release, so D3
    refused the plan for leaking on valid input — the missing pump did not merely cost
    coverage, it caused the leak.

    The loop cannot use the call's own result: the existing rule stops when the result is
    falsy, and DE265_OK is 0, so it would exit after the first SUCCESSFUL call. Only a
    POSITIVELY named flag is honoured — `done` and `eof` mean the opposite and inverting on
    a name is a guess.
    """
    plans = _plans_for("""
        typedef void de265_decoder_context;
        typedef int de265_error;
        de265_decoder_context* de265_new_decoder(void);
        de265_error de265_push_data(de265_decoder_context*, const void* data, int length);
        de265_error de265_decode(de265_decoder_context*, int* more);
        de265_error de265_free_decoder(de265_decoder_context*);
    """)
    p = next(x for x in plans if any(o.api == "de265_decode" for o in x.sequence))
    drive = next(o for o in p.sequence if o.api == "de265_decode")
    assert drive.repeat > 0, "the driver is called once and the queue is never drained"
    assert drive.repeat_while == "more", (
        f"loop exit is {drive.repeat_while!r}; the call's own result cannot be used because "
        f"DE265_OK is 0")
