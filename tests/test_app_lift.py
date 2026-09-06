"""B1 producer: discover application entry points and classify each by channel."""
from types import SimpleNamespace

from hforge.ir import APP_ARGV, APP_BUFFER, APP_CSTRING, APP_FILE_ARG
from hforge.producers.app_lift import classify


def _d(name, params, ret="int"):
    return SimpleNamespace(name=name, params=params, ret=ret)


def test_main_argc_argv_is_the_argv_channel():
    c = classify(_d("main", [("int", "argc"), ("char **", "argv")]))
    assert c["channel"] == APP_ARGV and "@INPUT@" in c["argv"]


def test_buffer_and_size_is_the_buffer_channel():
    c = classify(_d("parse", [("const char *", "data"), ("size_t", "n")]))
    assert c["channel"] == APP_BUFFER
    c2 = classify(_d("decode", [("const uint8_t *", "buf"), ("unsigned long", "len")]))
    assert c2["channel"] == APP_BUFFER


def test_lone_path_named_pointer_is_the_file_channel():
    assert classify(_d("parse_file", [("const char *", "path")]))["channel"] == APP_FILE_ARG
    assert classify(_d("load", [("const char *", "filename")]))["channel"] == APP_FILE_ARG


def test_lone_content_named_pointer_is_the_cstring_channel():
    assert classify(_d("parse_json", [("const char *", "text")]))["channel"] == APP_CSTRING
    assert classify(_d("parse", [("const char *", "input")]))["channel"] == APP_CSTRING


def test_a_function_with_no_input_shaped_signature_is_not_a_candidate():
    assert classify(_d("get_version", [])) is None
    assert classify(_d("set_flag", [("int", "on")])) is None


def test_discover_ranks_a_direct_parser_above_main():
    # From the bug-shaped app: parse_buffer/parse_file/main all present; the direct buffer
    # parser ranks first, main (heaviest channel) last.
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        h = pathlib.Path(td) / "app.h"
        h.write_text("int parse_buffer(const char *data, unsigned long n);\n"
                     "int parse_file(const char *path);\n"
                     "int app_main(int argc, char **argv);\n")
        from hforge.producers.app_lift import discover
        got = [(c["symbol"], c["channel"]) for c in discover([str(h)], ())]
    assert got[0] == ("parse_buffer", APP_BUFFER)
    assert got[-1][1] == APP_ARGV
