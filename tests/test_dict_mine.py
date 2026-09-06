"""Pin the dictionary miner: real magic out of real source, no prose."""
from hforge.producers.dict_mine import mine_tokens, mine_dict, _is_useful, _decode_c_escapes


def test_char_tag_magic(tmp_path):
    src = tmp_path / "dec.c"
    src.write_text('if (t == PNG_TYPE(\'I\',\'H\',\'D\',\'R\')) {}\n'
                   'static const unsigned char sig[8] = {137,80,78,71,13,10,26,10};\n')
    toks = mine_tokens([str(src)])
    assert b"IHDR" in toks                      # char-packed tag mined
    assert bytes([137, 80, 78, 71, 13, 10, 26, 10]) in toks   # byte-array signature mined


def test_string_literals_kept_prose_dropped(tmp_path):
    src = tmp_path / "s.c"
    src.write_text('memcmp(p, "JFIF", 4); const char *m = "this is a long error message";\n'
                   'printf("value=%d here", x);\n')
    toks = mine_tokens([str(src)])
    assert b"JFIF" in toks                       # a token
    assert not any(b"%" in t for t in toks)      # format strings dropped


def test_hexbyte_arrays(tmp_path):
    src = tmp_path / "h.c"
    src.write_text("unsigned char magic[] = { 0xff, 0xd8, 0xff, 0xe0 };\n")
    toks = mine_tokens([str(src)])
    assert bytes([0xff, 0xd8, 0xff, 0xe0]) in toks


def test_dict_format_escapes():
    body = mine_dict([])
    assert body.startswith("#")                  # header comment, empty body otherwise
    # escaping: a non-printable byte renders as \xHH in the dict line
    from hforge.producers.dict_mine import _dict_escape
    assert _dict_escape(bytes([0x89, 0x50])) == "\\x89P"


def test_escape_decoder():
    assert _decode_c_escapes("\\x89PNG") == b"\x89PNG"
    assert _decode_c_escapes("\\r\\n") == b"\r\n"


def test_useful_filter():
    assert _is_useful(b"IHDR")
    assert _is_useful(b"\x89PNG\r\n\x1a\n")
    assert not _is_useful(b"a")                   # too short
    assert not _is_useful(b"value=%d")            # format string
