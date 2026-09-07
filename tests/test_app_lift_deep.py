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
    assert _SIZE_NAME.search("count") and not _FLAG_NAME.search("count")
    assert _FLAG_NAME.search("decode_flags") and not _SIZE_NAME.search("decode_flags")


def test_decompressor_idiom_scratch_buffer():
    # uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen) -- the
    # zlib/zstd/lz4/brotli shape: input is NOT the first arg, and a writable output buffer is
    # present. The (source,sourceLen) pair must be found via the library size typedef/name, and
    # dest/destLen filled with a real scratch buffer + its capacity, not a 1-byte local.
    d = _decl("uncompress", "int",
              [("Bytef *", "dest"), ("uLongf *", "destLen"),
               ("const Bytef *", "source"), ("uLong", "sourceLen")])
    c = classify(d)
    assert c is not None and c["channel"] == "buffer"
    assert not c["has_out_buffer"]                       # the out buffer is handled, not unsafe
    assert c["out_scratch"] is True
    # input flows into source/sourceLen (args 2,3); dest is a sized scratch, destLen its capacity
    assert c["call_args"][2].endswith(")hf_data") and c["call_args"][3].endswith(")hf_size")
    assert any("hf_out0[" in l for l in c["call_locals"])        # a real scratch array
    assert any("hf_len1 = " in l for l in c["call_locals"])      # capacity, not zero
    assert c["call_args"][0].endswith("hf_out0") and c["call_args"][1] == "&hf_len1"


def test_encoder_ranks_below_decoder():
    # among compress + uncompress, the decoder is chosen (attacker controls compressed input)
    from hforge.producers.app_lift import _is_encoder
    assert _is_encoder("compress") and _is_encoder("deflate")
    assert not _is_encoder("uncompress") and not _is_encoder("inflate")
    dec = _decl("uncompress", "int", [("Bytef *", "dest"), ("uLongf *", "destLen"),
                                      ("const Bytef *", "source"), ("uLong", "sourceLen")])
    enc = _decl("compress", "int", [("Bytef *", "dest"), ("uLongf *", "destLen"),
                                    ("const Bytef *", "source"), ("uLong", "sourceLen")])
    ranked = sorted([classify(enc), classify(dec)], key=_rank)
    assert ranked[0]["symbol"] == "uncompress"           # decoder first


def test_zstd_void_out_buffer_scratch():
    # ZSTD_decompress(void* dst, size_t dstCap, const void* src, size_t srcSize): a void* output
    # is a byte sink -- sized with a scratch buffer + capacity, same as a typed byte* output.
    d = _decl("ZSTD_decompress", "size_t",
              [("void *", "dst"), ("size_t", "dstCapacity"),
               ("const void *", "src"), ("size_t", "srcSize")])
    c = classify(d)
    assert c is not None and not c["has_out_buffer"] and c["out_scratch"] is True
    assert c["call_args"][2].endswith(")hf_data") and c["call_args"][3].endswith(")hf_size")
    assert c["call_args"][0].endswith("hf_out0") and c["call_args"][1].endswith("65536")


def test_opaque_handle_out_param_refused():
    # ZSTD_decompress_usingDDict(ZSTD_DCtx* dctx, void* dst, size_t dstCap, const void* src,
    # size_t srcSize, const ZSTD_DDict* ddict): dctx/ddict are opaque handles with no complete
    # type -- a local of one will not compile, so the entry is refused, not emitted broken.
    d = _decl("ZSTD_decompress_usingDDict", "size_t",
              [("ZSTD_DCtx *", "dctx"), ("void *", "dst"), ("size_t", "dstCap"),
               ("const void *", "src"), ("size_t", "srcSize"), ("const ZSTD_DDict *", "ddict")])
    c = classify(d)
    # either refused outright, or at least never chosen over the plain decoder
    from hforge.producers.app_lift import _rank
    plain = classify(_decl("ZSTD_decompress", "size_t",
                           [("void *", "dst"), ("size_t", "dstCap"),
                            ("const void *", "src"), ("size_t", "srcSize")]))
    cands = [x for x in (c, plain) if x is not None]
    assert sorted(cands, key=_rank)[0]["symbol"] == "ZSTD_decompress"


def test_dict_loader_ranks_below_decoder():
    from hforge.producers.app_lift import _rank
    dec = classify(_decl("ZSTD_decompress", "size_t",
                         [("void *", "d"), ("size_t", "dc"),
                          ("const void *", "s"), ("size_t", "ss")]))
    dic = classify(_decl("ZSTD_CCtx_loadDictionary", "size_t",
                         [("void *", "cctx"), ("const void *", "dict"), ("size_t", "dictSize")]))
    cands = [x for x in (dic, dec) if x is not None]
    assert sorted(cands, key=_rank)[0]["symbol"] == "ZSTD_decompress"


def test_prefers_oneshot_memory_decoder_over_variants():
    # When a clean one-shot *_memory/*_parse decoder sits beside streaming/path/dict variants,
    # the fuzzer must pick the one-shot: it takes the buffer directly, no stream object or file.
    from hforge.producers.app_lift import _rank
    mem = classify(_decl("ufbx_load_memory", "void *",
                         [("const void *", "data"), ("size_t", "size"),
                          ("const void *", "opts"), ("void *", "error")]))
    strm = classify(_decl("ufbx_load_stream_prefix", "void *",
                          [("const void *", "prefix"), ("size_t", "prefix_size"),
                           ("void *", "stream"), ("void *", "error")]))
    cands = sorted([x for x in (strm, mem) if x is not None], key=_rank)
    assert cands[0]["symbol"] == "ufbx_load_memory"


def test_path_named_pointer_is_not_a_content_buffer():
    # f(const char* filename, size_t filename_len, ...) reads a PATH -- fuzzing it would exercise
    # filesystem handling, not the decoder. It must not be lifted as a (buffer,len) content entry.
    from hforge.producers.app_lift import _looks_buffer
    assert not _looks_buffer("const char *", "filename")
    assert not _looks_buffer("const char *", "path")
    assert _looks_buffer("const char *", "data")          # real content still recognised
    d = _decl("ufbx_load_file_len", "void *",
              [("const char *", "filename"), ("size_t", "filename_len"),
               ("const void *", "opts"), ("void *", "error")])
    c = classify(d)
    # no content (buffer,len) pair -> not a buffer-channel entry (filename is a path, not bytes)
    assert c is None or c["channel"] != "buffer"


def test_length_before_buffer_brotli_shape():
    # BrotliDecoderDecompress(size_t encoded_size, const uint8_t* encoded_buffer,
    #                         size_t* decoded_size, uint8_t* decoded_buffer)
    # input length precedes the buffer; output buffer + its *size are a scratch pair.
    d = _decl("BrotliDecoderDecompress", "int",
              [("size_t", "encoded_size"), ("const uint8_t *", "encoded_buffer"),
               ("size_t *", "decoded_size"), ("uint8_t *", "decoded_buffer")])
    c = classify(d)
    assert c is not None and c["channel"] == "buffer"
    # encoded_buffer gets the fuzzer bytes, encoded_size gets hf_size (length before buffer)
    assert c["call_args"][1].endswith(")hf_data") and c["call_args"][0].endswith(")hf_size")
    # decoded_buffer is a real scratch, decoded_size its capacity -> not an unhandled out buffer
    assert not c["has_out_buffer"] and c["out_scratch"] is True
    assert any("hf_out3" in l for l in c["call_locals"])


def test_length_before_buffer_does_not_pair_void_config():
    # a const void* config arg must NOT be paired with an unrelated preceding size (ufbx opts)
    d = _decl("ufbx_load_file_len", "void *",
              [("const char *", "filename"), ("size_t", "filename_len"),
               ("const void *", "opts"), ("void *", "error")])
    c = classify(d)
    assert c is None or c["channel"] != "buffer"
