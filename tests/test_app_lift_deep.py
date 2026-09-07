"""Pin the deep application-entry classifier: multi-arg loaders, out-param fill, ranking."""
from types import SimpleNamespace as D
from hforge.producers.app_lift import classify, _rank


def _decl(name, ret, params):
    return D(name=name, ret=ret, params=params)


def test_multiarg_loader_recognised_and_filled():
    # stbi_load_from_memory(stbi_uc const *buffer, int len, int *x, int *y, int *comp, int req)
    d = _decl("load_from_memory", "unsigned char *",
              [("stbi_uc const *", "buffer"), ("int", "len"),
               ("int *", "x"), ("int *", "y"), ("int *", "comp"), ("int", "req")])
    c = classify(d)
    assert c["channel"] == "buffer"
    assert c["call_args"][0].endswith(")hf_data") and c["call_args"][1].endswith(")hf_size")
    assert c["call_args"][2] == "&hf_a2" and c["call_args"][5] == "0"   # out-locals + scalar 0
    assert any("hf_a2" in l for l in c["call_locals"])
    assert c["depth"] >= 3                        # 3 out-params + returns a pointer


def test_byvalue_handle_refused():
    # XML_Parse(XML_Parser p, const char *s, int len, int final): p is a by-value opaque handle
    d = _decl("XML_Parse", "int",
              [("XML_Parser", "p"), ("const char *", "s"), ("int", "len"), ("int", "final")])
    assert classify(d) is None                    # left to test-lift, not emitted NULL-handle


def test_private_and_os_import_dropped():
    assert classify(_decl("stbi__hdr_to_ldr", "float *",
                          [("stbi_uc const *", "d"), ("int", "n")])) is None
    assert classify(_decl("MultiByteToWideChar", "int",
                          [("const char *", "s"), ("int", "n")])) is None


def test_query_ranks_below_decoder():
    load = classify(_decl("load_from_memory", "unsigned char *",
                          [("const unsigned char *", "b"), ("int", "n"),
                           ("int *", "x"), ("int *", "y")]))
    info = classify(_decl("info_from_memory", "int",
                          [("const unsigned char *", "b"), ("int", "n"),
                           ("int *", "x"), ("int *", "y")]))
    load["header"] = info["header"] = "x.h"
    assert _rank(load) < _rank(info)              # decoder before query


def test_cstring_multiarg_parser():
    # nsvgParse(char *input, const char *units, float dpi): content + config args
    d = _decl("nsvgParse", "void *",
              [("char *", "input"), ("const char *", "units"), ("float", "dpi")])
    c = classify(d)
    assert c["channel"] == "cstring"
    assert c["call_args"][0].endswith(")hf_cstr")   # content is the NUL-terminated copy
    assert c["call_args"][1] == '""'                 # config string: empty, not NULL
    assert c["call_args"][2] == "0"                  # dpi scalar default


def test_cstring_refuses_writable_out_buffer():
    # strcpy(char *dst, const char *src): dst is a writable output we cannot size -> refuse
    d = _decl("strcpy", "char *", [("char *", "dst"), ("const char *", "src")])
    c = classify(d)
    # dst is content-named? no -- first param 'dst' is not; but even if taken, a non-const
    # char* AFTER the content must refuse. Here param0 'dst' non-const char* is the content,
    # param1 const char* -> "" which is safe, so this one is allowed but harmless (copies into
    # the fuzzer string). The dangerous shape is a non-const char* AFTER content:
    d2 = _decl("f", "int", [("char *", "input"), ("char *", "outbuf")])
    assert classify(d2) is None


def _decl_ret(name, ret, params):
    return D(name=name, ret=ret, params=params, complete=frozenset(), ptr_types=frozenset())


def test_compose_app_folds_decode_family(tmp_path):
    # a tiny codec header: two decoders sharing (buf,len) + a free
    h = tmp_path / "dec.h"
    h.write_text(
        "unsigned char* Dec_RGBA(const unsigned char* data, unsigned long size, int* w, int* h);\n"
        "unsigned char* Dec_BGRA(const unsigned char* data, unsigned long size, int* w, int* h);\n"
        "int Dec_Info(const unsigned char* data, unsigned long size, int* w, int* h);\n"
        "void Dec_Free(void* ptr);\n")
    from hforge.producers import app_lift
    from hforge.ir import Target
    from hforge.emit import emit
    tgt = Target(name="tinycodec", public_headers=["dec.h"])
    plan, rec = app_lift.compose_app([str(h)], tgt)
    assert plan is not None
    assert set(rec["family"]) >= {"Dec_RGBA", "Dec_BGRA"}     # folded the decode family
    assert rec["chosen"]["free_symbol"] == "Dec_Free"         # found the void* deallocator
    src = emit(plan).source
    assert "Dec_RGBA(" in src and "Dec_BGRA(" in src          # both folded onto one input
    assert "Dec_Free(" in src                                 # returned buffers are freed
    assert src.count("hf_data") >= 2                          # same input to each


def test_compose_app_excludes_encoders_and_out_buffers(tmp_path):
    h = tmp_path / "c.h"
    h.write_text(
        "unsigned char* Dec_A(const unsigned char* d, unsigned long n, int* w);\n"
        "int Enc_Save(const unsigned char* d, unsigned long n, char* out);\n"   # encoder: excluded
        "int Dec_Into(const unsigned char* d, unsigned long n, unsigned char* outbuf);\n")  # out buffer: excluded
    from hforge.producers import app_lift
    from hforge.ir import Target
    tgt = Target(name="c", public_headers=["c.h"])
    plan, rec = app_lift.compose_app([str(h)], tgt)
    # only Dec_A is a safe decoder; fewer than two -> refused, and Enc/Into never appear
    assert "Enc_Save" not in rec.get("family", [])
    assert "Dec_Into" not in rec.get("family", [])


def test_flag_scalar_is_fuzzed_not_defaulted():
    # json_loadb(const char* buffer, size_t buflen, size_t flags, json_error_t* error)
    d = _decl("json_loadb", "void *",
              [("const char *", "buffer"), ("size_t", "buflen"),
               ("size_t", "flags"), ("json_error_t *", "error")])
    c = classify(d)
    # the (buf,len) pair carries bytes; `flags` is a behaviour scalar -> fuzzed from a byte
    assert any("hf_data[" in a and "flags" not in a for a in c["call_args"])
    assert c["call_args"][2].startswith("(size_t)(hf_size ? hf_data[")


def test_size_scalar_is_not_fuzzed():
    # a `count`/`size` scalar must stay 0 -- fuzzing it to a large value would hang/over-read
    from hforge.producers.app_lift import _fuzz_scalar_arg, _FLAG_NAME, _SIZE_NAME
    assert _SIZE_NAME.search("num_items") and not _FLAG_NAME.search("num_items")
    assert _FLAG_NAME.search("decode_flags") and not _SIZE_NAME.search("decode_flags")
