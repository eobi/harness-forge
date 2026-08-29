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
