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
