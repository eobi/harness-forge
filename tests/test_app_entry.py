"""B1: application entry points. Input reaches an APPLICATION through a channel, not an API.

Pinned because this is the abstraction CLI apps, GUI apps and mobile apps all share -- the
one the IR lacked, and the reason P5/P6/P7 were blocked on the same missing concept.
"""
from hforge.emit import emit
from hforge.ir import (APP_ARGV, APP_BUFFER, APP_FILE_ARG, AppEntry, HarnessIR, Target)


def _emit(channel, **kw):
    ae = AppEntry(symbol="parse_it", channel=channel, header="app.h", **kw)
    h = HarnessIR(name="app", target=Target(name="app", sources=["app.c"]), app_entry=ae)
    return emit(h).source


def test_buffer_channel_hands_bytes_and_length_directly():
    src = _emit(APP_BUFFER)
    assert "parse_it((const char *)hf_data, hf_size)" in src
    assert "mkstemp" not in src, "the buffer channel needs no temp file"


def test_file_arg_channel_materialises_a_temp_file_and_unlinks_it():
    src = _emit(APP_FILE_ARG)
    assert "mkstemp(hf_path)" in src
    assert "parse_it(hf_path)" in src
    # per-invocation and always removed, including the early returns
    assert src.count("unlink(hf_path)") >= 2


def test_argv_channel_puts_the_temp_path_in_the_marked_slot():
    src = _emit(APP_ARGV, argv=["app", "--parse", "@INPUT@"])
    assert '"--parse"' in src and "hf_path" in src
    assert "@INPUT@" not in src, "the placeholder must be replaced, not emitted"
    assert "parse_it((int)(sizeof(hf_argv)" in src


def test_app_entry_round_trips_through_json():
    ae = AppEntry(symbol="m", channel=APP_ARGV, argv=["a", "@INPUT@"], header="h.h")
    h = HarnessIR(name="t", target=Target(name="t"), app_entry=ae)
    r = HarnessIR.from_json(h.to_json())
    assert r.app_entry.channel == APP_ARGV
    assert r.app_entry.argv == ["a", "@INPUT@"]
    assert r.app_entry.symbol == "m"


def test_a_library_harness_is_unaffected():
    # No app_entry -> the ordinary library path, still producing the libFuzzer entry.
    h = HarnessIR(name="lib", target=Target(name="lib"))
    assert "LLVMFuzzerTestOneInput" in emit(h).source
