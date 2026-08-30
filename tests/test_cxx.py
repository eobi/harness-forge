#!/usr/bin/env python3
"""C++ — the second language, on the same IR and the same gates.

Most of the target surface is C++: poppler, ICU, protobuf, and most media and font
libraries. Competing only on C caps the addressable field at roughly half of it.

The IR needed no change, which is the point of having had one — a resource with a lifetime
describes a C++ object as well as a C handle. Only the spelling differs.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.emit import cxx_libfuzzer                              # noqa: E402
from hforge.emit.c_libfuzzer import EmitError                      # noqa: E402
from hforge.ir import HarnessIR                                    # noqa: E402
from hforge.producers import cxx_header as cx                      # noqa: E402

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
    except Exception as e:                                          # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


HDR = """
#include <string>
#include <vector>
namespace fmt {
class Parser {
public:
    Parser();
    explicit Parser(int flags);
    ~Parser();
    bool parse(const std::string& data);
    bool parse(const std::vector<uint8_t>& data, size_t limit);
    int errorCode() const;
private:
    void internalReset();
    char buf_[16];
};
template <typename T> class Generic { public: void go(T); };
}
"""


def _hdr(text: str) -> str:
    f = Path(tempfile.mkdtemp()) / "p.hpp"
    f.write_text(text)
    return str(f)


def test_namespaces_qualify_the_symbol():
    ms, _ = cx.parse_header(_hdr(HDR))
    assert any(m.symbol == "fmt::Parser::parse" for m in ms), [m.symbol for m in ms]


def test_overloads_are_separated_by_arity():
    """Two methods sharing a name and differing in signature are two APIs. A plan that does
    not say which it meant cannot be emitted."""
    ms, _ = cx.parse_header(_hdr(HDR))
    parses = [m for m in ms if m.name == "parse"]
    assert {m.arity for m in parses} == {1, 2}, [(m.name, m.arity) for m in parses]


def test_private_members_are_not_api():
    ms, _ = cx.parse_header(_hdr(HDR))
    assert not any(m.name == "internalReset" for m in ms), \
        "a private method was proposed as public API"


def test_constructors_and_destructors_are_identified():
    ms, _ = cx.parse_header(_hdr(HDR))
    assert any(m.is_ctor for m in ms) and any(m.is_dtor for m in ms)


def test_a_template_is_skipped_with_a_reason():
    """A template is not a symbol until it is instantiated. Reported, not silently dropped."""
    ms, skipped = cx.parse_header(_hdr(HDR))
    assert any("Generic" in s for s in skipped), skipped
    assert not any(m.cls == "Generic" for m in ms)


def test_struct_is_public_by_default():
    ms, _ = cx.parse_header(_hdr("struct Open { void go(int x); };"))
    assert any(m.name == "go" for m in ms), [m.symbol for m in ms]


def test_byte_carrying_types_are_recognised():
    for t in ("const std::string&", "std::string_view", "const std::vector<uint8_t>&",
              "const char *", "uint8_t *"):
        assert cx.takes_bytes(t), t
    assert not cx.takes_bytes("int")


# ── the emitter ──────────────────────────────────────────────────────────────

def _plan(**over) -> dict:
    p = {"schema": "harness-ir/1", "name": "t", "producer": "cxx_header",
         "target": {"name": "t", "language": "c++", "public_headers": ["p.hpp"]},
         "apis": {"fmt::Parser::Parser": {
             "symbol": "fmt::Parser::Parser", "header": "p.hpp", "role": "create",
             "params": [], "returns": {"name": "void", "kind": "void"}},
             "fmt::Parser::parse": {
                 "symbol": "fmt::Parser::parse", "header": "p.hpp", "role": "consume",
                 "params": [{"name": "self",
                             "type": {"name": "fmt::Parser *", "kind": "pointer"}},
                            {"name": "data",
                             "type": {"name": "const std::string&", "kind": "pointer"}}],
                 "returns": {"name": "bool", "kind": "scalar"}}},
         "slices": [{"id": "d", "kind": "bytes", "remainder": True, "min_len": 1}],
         "resources": [{"id": "p", "type": {"name": "fmt::Parser", "kind": "pointer"},
                        "storage": "handle"}],
         "sequence": [{"id": "o_new", "api": "fmt::Parser::Parser", "args": [],
                       "binds": "p"},
                      {"id": "o_parse", "api": "fmt::Parser::parse",
                       "args": [{"param": "self", "source": "resource", "ref": "p"},
                                {"param": "data", "source": "input", "ref": "d"}],
                       "guarded_by": ["p"]}],
         "knobs": {"max_len": 4096}, "platforms": ["linux-x86_64-glibc"]}
    p.update(over)
    return p


def test_the_entry_point_is_extern_c():
    """libFuzzer looks up an UNMANGLED symbol. Without extern "C" the harness compiles
    cleanly and the fuzzer never finds it — a silent failure."""
    src = cxx_libfuzzer.emit(HarnessIR.from_json(_plan())).source
    assert 'extern "C" int LLVMFuzzerTestOneInput' in src


def test_fuzzer_bytes_become_a_cxx_type():
    src = cxx_libfuzzer.emit(HarnessIR.from_json(_plan())).source
    assert "std::string hf_s_d(reinterpret_cast<const char *>(hf_data)" in src
    assert "std::vector<uint8_t> hf_s_d_v(" in src


def test_a_heap_object_is_new_and_the_method_is_called_through_it():
    src = cxx_libfuzzer.emit(HarnessIR.from_json(_plan())).source
    assert "new fmt::Parser(" in src
    assert "hf_o_p->parse(" in src


def test_the_c_backend_refuses_a_cxx_plan_and_vice_versa():
    """Emitting C++ through the C backend would produce something that compiles and means
    something else."""
    p = _plan()
    p["target"]["language"] = "c"
    try:
        cxx_libfuzzer.emit(HarnessIR.from_json(p))
        raise AssertionError("the C++ backend emitted a C plan")
    except EmitError as e:
        assert "language" in str(e)


def test_an_unmappable_parameter_type_is_refused_not_guessed():
    """If the fuzzer's bytes cannot take the parameter's shape, say so. Guessing produces a
    harness that compiles and tests something other than what was intended."""
    p = _plan()
    p["apis"]["fmt::Parser::parse"]["params"][1]["type"]["name"] = "const MyCustomThing&"
    try:
        cxx_libfuzzer.emit(HarnessIR.from_json(p))
        raise AssertionError("an unmappable type was silently accepted")
    except EmitError as e:
        assert "not a shape the fuzzer's bytes can take" in str(e)


def test_the_replay_driver_uses_an_exactly_sized_buffer():
    """The same reason as the C driver: libFuzzer hands an exact allocation, so an over-read
    by one byte hits a redzone. From a large static buffer it hits valid memory and the bug
    is certified away."""
    em = cxx_libfuzzer.emit(HarnessIR.from_json(_plan()))
    assert "malloc(buf.size()" in em.driver


def test_the_build_command_is_cxx17():
    em = cxx_libfuzzer.emit(HarnessIR.from_json(_plan()))
    joined = " ".join(em.build_command)
    assert "-std=c++17" in joined and "$CXX" in joined


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"c++ — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)


def test_a_c_harness_still_exports_an_unmangled_entry_point_under_cxx():
    """A C plan compiled by a C++ compiler must still be found by libFuzzer.

    This is the shape that makes it matter: a library written in C++ behind an
    `extern "C"` API — libde265, and most codecs — is read by the C producer and emitted
    as C, but it has to link against C++ objects, so the build uses clang++.

    Without the guard the symbol is mangled, libFuzzer looks up an unmangled
    `LLVMFuzzerTestOneInput`, does not find it, and the campaign runs DOING NOTHING. It
    compiles, it links, it reports executions, and it never calls the harness. A silent
    zero that reads as "the engine cannot do C++".
    """
    import json as _json
    from hforge.emit.c_libfuzzer import emit as emit_c

    root = Path(__file__).resolve().parent.parent
    ir = HarnessIR.from_json(_json.loads(
        (root / "examples" / "hf_demo.good.hir.json").read_text()))
    out = emit_c(ir)

    for text, what in ((out.source, "harness"), (out.driver, "replay driver")):
        i = text.index("LLVMFuzzerTestOneInput")
        before = text[:i]
        assert "#ifdef __cplusplus" in before, f"{what}: entry point is not guarded"
        assert 'extern "C"' in before, f"{what}: no extern \"C\" for a C++ build"


def test_a_pointer_squeezed_into_a_byte_is_refused_before_the_campaign():
    """The compiler already knew, in milliseconds, what two campaigns spent 20 minutes on.

    `unsigned char hf_r_err = NULL;` for a function returning `unsigned char *` is an
    incompatible pointer-to-integer conversion. clang warned, the build succeeded, the
    harness segfaulted on its third execution, and the case measured 0.00% where it had
    been 65.12%.

    That is S2.TYPE_CONFUSION occurring at the C level AFTER emission, which was the one
    place no gate looked.
    """
    import shutil
    import tempfile
    from hforge.toolchain import check_emitted_c

    cc = shutil.which("clang") or shutil.which("cc")
    if cc is None:
        return  # no compiler here; the gate reports NOT RUN rather than passing

    d = Path(tempfile.mkdtemp())
    decl = ("#include <stddef.h>\n"
            "unsigned char *get_error(void);\nvoid free_error(unsigned char *);\n"
            "int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) {\n"
            "    unsigned char %s e = 0;\n"
            "    e = get_error();\n    if (e) free_error(e);\n"
            "    (void)d; (void)n; return 0;\n}\n")

    bad = d / "bad.c"
    bad.write_text(decl % "")
    assert check_emitted_c(cc, bad), "the shipped defect compiled clean; the gate is inert"

    good = d / "good.c"
    good.write_text(decl % "*")
    assert not check_emitted_c(cc, good), "a correct harness must not be refused"


# ── the join: header -> plan ─────────────────────────────────────────────────
#
# parse_header and the emitter both existed and were green, and C++ still did not work
# end to end: nothing synthesised a plan, nothing routed to it, and the emitted build.sh
# referenced an undefined $CXX so every C++ build aborted. These pin all three.

_REAL = '''
namespace pugi {
    class PUGIXML_CLASS xml_writer {
    public:
        virtual void write(const void* data, size_t size) = 0;
    };
    class PUGIXML_CLASS xml_document: public xml_node {
    public:
        xml_document();
        ~xml_document();
        xml_parse_result load_file(const char* path, unsigned int options = 4);
        xml_parse_result load_buffer(const void* contents, size_t size,
                                     unsigned int options = 4, xml_encoding e = enc_auto);
        xml_parse_result load_buffer_inplace_own(void* contents, size_t size);
    };
}
'''


def _parse_real(tmp_path):
    h = tmp_path / "p.hpp"
    h.write_text(_REAL)
    return cx.parse_header(str(h))


def test_an_export_macro_does_not_hide_the_class(tmp_path):
    """`class PUGIXML_CLASS xml_document` is how real headers are written. Matching only
    `class <name>` found ZERO classes in pugixml -- 241 methods were invisible."""
    ms, _ = _parse_real(tmp_path)
    assert {m.cls for m in ms} == {"xml_writer", "xml_document"}


def test_trailing_defaulted_parameters_are_not_required(tmp_path):
    ms, _ = _parse_real(tmp_path)
    lb = next(m for m in ms if m.name == "load_buffer")
    assert (lb.n_required, len(lb.params)) == (2, 4)


def test_a_pure_virtual_marks_the_class_abstract(tmp_path):
    ms, _ = _parse_real(tmp_path)
    assert next(m for m in ms if m.name == "write").is_pure


def _plans(tmp_path):
    from hforge.ir import Target
    _parse_real(tmp_path)
    t = Target(name="pugixml", public_headers=["p.hpp"], include_dirs=[str(tmp_path)],
               sources=[], link_libs=[], cflags=[], seed_dirs=[])
    return cx.propose([str(tmp_path / "p.hpp")], t)


def test_only_the_safe_consumer_is_proposed(tmp_path):
    """Three of the four byte-taking methods are traps:

    * `write` is pure virtual, so the class cannot be constructed at all;
    * `load_file` takes a FILENAME, and a harness built on it opens attacker-named paths;
    * `load_buffer_inplace_own` FREES the pointer with the library's allocator, so handing
      it a std::string's buffer crashes by construction and proves nothing.
    """
    names = {p.name for p in _plans(tmp_path)}
    assert names == {"pugixml_xml_document_load_buffer"}


def test_the_plan_binds_bytes_and_length_to_the_right_parameters(tmp_path):
    ir = _plans(tmp_path)[0]
    op = next(o for o in ir.sequence if o.id == "o_consume")
    got = {a.param: a.source for a in op.args}
    assert got["contents"] == "input" and got["size"] == "length_of"
    assert got["self"] == "resource"
    # the two defaulted parameters are dropped, not bound to a guessed value
    assert "options" not in got and "e" not in got


def test_a_cxx_plan_emits_a_runnable_build(tmp_path):
    """The C++ build command says `$CXX`. A preamble setting only `CC` made every emitted
    C++ build.sh abort on `CXX: unbound variable` under `set -eu`."""
    from hforge.cli import _cc_preamble, _artifact_names
    ir = _plans(tmp_path)[0]
    assert 'CXX="${CXX:-clang++}"' in _cc_preamble(ir)
    assert _artifact_names(ir) == ("harness.cc", "driver.cc")


def test_a_cxx_header_routes_to_the_cxx_producer(tmp_path):
    from hforge.cli import looks_like_cxx
    h = tmp_path / "p.hpp"
    h.write_text(_REAL)
    assert looks_like_cxx(str(h))
    c = tmp_path / "plain.h"
    c.write_text("int foo(const unsigned char *b, size_t n);\n")
    assert not looks_like_cxx(str(c))


# ── free functions at namespace scope ────────────────────────────────────────

_FREE = '''
namespace woff2 {
  bool ConvertWOFF2ToTTF(const uint8_t* data, size_t length, WOFF2Out* out);
  size_t ComputeWOFF2FinalSize(const uint8_t* data, size_t length);
  void Consume(const uint8_t* data, size_t length);
}
'''


def _free(tmp_path):
    from hforge.ir import Target
    h = tmp_path / "w.hpp"
    h.write_text(_FREE)
    t = Target(name="woff2", public_headers=["w.hpp"], include_dirs=[str(tmp_path)],
               sources=[], link_libs=[], cflags=[], seed_dirs=[])
    return cx.propose([str(h)], t)


def test_a_free_function_is_not_dropped_silently(tmp_path):
    """`woff2::ConvertWOFF2ToTTF` is its library's entry point and belongs to no class.
    Scanning only class bodies dropped every such function without recording it."""
    h = tmp_path / "w.hpp"
    h.write_text(_FREE)
    ms, _ = cx.parse_header(str(h))
    assert "woff2::ComputeWOFF2FinalSize" in {m.symbol for m in ms}


def test_a_required_pointer_we_cannot_build_is_refused(tmp_path):
    """`ConvertWOFF2ToTTF(data, len, WOFF2Out* out)` with a null sink crashes on the
    library's own contract. That crash is not a finding."""
    assert "woff2_ConvertWOFF2ToTTF" not in {p.name for p in _free(tmp_path)}
    assert "woff2_ComputeWOFF2FinalSize" in {p.name for p in _free(tmp_path)}


def test_a_free_function_plan_needs_no_object(tmp_path):
    ir = next(p for p in _free(tmp_path) if p.name == "woff2_ComputeWOFF2FinalSize")
    assert ir.resources == []
    assert [o.id for o in ir.sequence] == ["o_consume"]


def test_a_void_call_is_not_cast_to_long(tmp_path):
    """`hf_sink += (long)f(...)` does not compile when f returns void."""
    ir = next(p for p in _free(tmp_path) if p.name == "woff2_Consume")
    src = cxx_libfuzzer.emit(ir).source
    assert "(long)woff2::Consume" not in src
    assert "    woff2::Consume(" in src


# ── constructing an object to satisfy a parameter ────────────────────────────
#
# The shape that separates a harness from a stub. woff2's entry point is
# `ConvertWOFF2ToTTF(data, len, WOFF2Out* out)`: refusing it costs the library, and
# binding the sink to nullptr crashes on the library's contract rather than on a bug.

_SINK = '''
namespace woff2 {
  class WOFF2Out {
   public:
    virtual ~WOFF2Out(void) {}
    virtual bool Write(const void *buf, size_t n) = 0;
  };
  class WOFF2StringOut : public WOFF2Out {
   public:
    explicit WOFF2StringOut(std::string *buf);
    bool Write(const void *buf, size_t n);
  };
  bool ConvertWOFF2ToTTF(const uint8_t *data, size_t length, WOFF2Out* out);
}
'''


def _sink_plans(tmp_path):
    from hforge.ir import Target
    h = tmp_path / "s.hpp"
    h.write_text(_SINK)
    t = Target(name="woff2", public_headers=["s.hpp"], include_dirs=[str(tmp_path)],
               sources=[], link_libs=[], cflags=[], seed_dirs=[])
    return cx.propose([str(h)], t)


def test_an_abstract_parameter_is_satisfied_by_a_concrete_subclass(tmp_path):
    """`WOFF2Out` is pure virtual. The only way to call the entry point is to find a
    concrete descendant, which is what the library's own harness does."""
    ir = next(p for p in _sink_plans(tmp_path) if "ConvertWOFF2ToTTF" in p.name)
    assert [r.type.name for r in ir.resources] == ["woff2::WOFF2StringOut"]


def test_a_constructor_taking_a_buffer_gets_scratch_the_harness_owns(tmp_path):
    ir = next(p for p in _sink_plans(tmp_path) if "ConvertWOFF2ToTTF" in p.name)
    assert [(s.id, s.c_type) for s in ir.scratch] == [("b2", "std::string")]


def test_the_object_is_constructed_before_the_call_that_uses_it(tmp_path):
    ir = next(p for p in _sink_plans(tmp_path) if "ConvertWOFF2ToTTF" in p.name)
    ids = [o.id for o in ir.sequence]
    assert ids.index("o_a2") < ids.index("o_consume")


def test_a_namespaced_free_function_is_not_called_as_a_method(tmp_path):
    """`woff2::ConvertWOFF2ToTTF` is qualified AND has a resource argument once the sink
    exists. Treating "qualified plus a resource" as a method call invoked the function ON
    the sink and dropped the sink from the argument list."""
    ir = next(p for p in _sink_plans(tmp_path) if "ConvertWOFF2ToTTF" in p.name)
    src = cxx_libfuzzer.emit(ir).source
    assert "->ConvertWOFF2ToTTF(" not in src
    assert "woff2::ConvertWOFF2ToTTF(" in src


def test_the_sink_is_passed_by_address_to_a_pointer_parameter(tmp_path):
    """An object held inline lives in a std::optional: a `T*` parameter needs `&*opt`."""
    ir = next(p for p in _sink_plans(tmp_path) if "ConvertWOFF2ToTTF" in p.name)
    src = cxx_libfuzzer.emit(ir).source
    assert "&*hf_o_a2" in src
    assert "hf_o_a2.emplace(&hf_x_b2)" in src


# ── a defaulted flag, exercised across its family ────────────────────────────

_FLAGS = '''
namespace pugi {
  const unsigned int parse_minimal = 0x0000;
  const unsigned int parse_pi = 0x0001;
  const unsigned int parse_comments = 0x0002;
  const unsigned int parse_cdata = 0x0004;
  const unsigned int parse_default = parse_cdata | parse_pi;
  const unsigned int parse_full = parse_default | parse_pi | parse_comments;
  class PUGIXML_CLASS xml_document {
   public:
    xml_document();
    ~xml_document();
    int load_buffer(const void* contents, size_t size,
                    unsigned int options = parse_default);
  };
}
'''


def test_the_flag_family_is_read_out_of_the_header(tmp_path):
    """The three values pugixml's own harness passes, derived rather than listed: the
    least (a bare zero), the default the signature names, and the most inclusive (the
    one referencing the most other members)."""
    h = tmp_path / "f.hpp"
    h.write_text(_FLAGS)
    consts = cx.parse_constants(str(h))
    assert cx.flag_family("parse_default", consts) == [
        "pugi::parse_minimal", "pugi::parse_default", "pugi::parse_full"]


def _flag_plan(tmp_path):
    from hforge.ir import Target
    h = tmp_path / "f.hpp"
    h.write_text(_FLAGS)
    t = Target(name="pugixml", public_headers=["f.hpp"], include_dirs=[str(tmp_path)],
               sources=[], link_libs=[], cflags=[], seed_dirs=[])
    return next(p for p in cx.propose([str(h)], t) if "load_buffer" in p.name)


def test_the_call_is_repeated_once_per_flag_value(tmp_path):
    ir = _flag_plan(tmp_path)
    assert [o.id for o in ir.sequence] == ["o_new", "o_consume_0", "o_consume_1",
                                           "o_consume_2"]


def test_each_repeat_passes_a_named_constant_not_a_guessed_number(tmp_path):
    """A guessed flag value is a silent behaviour change; a named constant is the
    library's own vocabulary and is auditable in the emitted source."""
    src = cxx_libfuzzer.emit(_flag_plan(tmp_path)).source
    for v in ("pugi::parse_minimal", "pugi::parse_default", "pugi::parse_full"):
        assert f"hf_s_d.size(), {v})" in src


def test_a_defaulted_parameter_with_no_family_is_still_dropped(tmp_path):
    """The family must be READ, not invented: when the default is not a named constant in
    a family of at least three, the parameter is omitted as before."""
    h = tmp_path / "g.hpp"
    h.write_text('''
namespace lib {
  class Reader {
   public:
    Reader();
    int read(const void* d, size_t n, int mode = 3);
  };
}
''')
    from hforge.ir import Target
    t = Target(name="lib", public_headers=["g.hpp"], include_dirs=[str(tmp_path)],
               sources=[], link_libs=[], cflags=[], seed_dirs=[])
    ir = next(p for p in cx.propose([str(h)], t) if "read" in p.name)
    assert [o.id for o in ir.sequence] == ["o_new", "o_consume"]
