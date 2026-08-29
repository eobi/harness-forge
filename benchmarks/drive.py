"""One benchmark case: propose -> pick the plan for the gold target -> build -> fuzz -> cover."""
import glob, json, os, pathlib, shutil, subprocess, sys
sys.path.insert(0, "/hf")
from hforge.producers import header_graph as hg
from hforge.emit import emit
from hforge.emit.c_libfuzzer import EmitError
from hforge.gates.static_gates import run_static_gates
from hforge.gates.result import BLOCK
from hforge.ir import Knobs, Target
from hforge.toolchain import check_emitted_c

CASES = {
 "libyaml/libyaml_loader_fuzzer": dict(
    hdr="/b/inc/yaml.h", inc=["/b/inc","/b/libyaml/include","/b/libyaml/src"],
    src=sorted(glob.glob("/b/libyaml/src/*.c")), fn="yaml_parser_load",
    cflags=['-DYAML_VERSION_STRING="0.2.5"','-DYAML_VERSION_MAJOR=0','-DYAML_VERSION_MINOR=2','-DYAML_VERSION_PATCH=5'],
    seeds=["/b/libyaml/tests","/b/libyaml/regression-inputs"],
    cover=["/b/libyaml/src/api.c","/b/libyaml/src/loader.c","/b/libyaml/src/parser.c","/b/libyaml/src/reader.c","/b/libyaml/src/scanner.c"]),
 "libyaml/libyaml_scanner_fuzzer": dict(
    hdr="/b/inc/yaml.h", inc=["/b/inc","/b/libyaml/include","/b/libyaml/src"],
    src=sorted(glob.glob("/b/libyaml/src/*.c")), fn="yaml_parser_scan",
    cflags=['-DYAML_VERSION_STRING="0.2.5"','-DYAML_VERSION_MAJOR=0','-DYAML_VERSION_MINOR=2','-DYAML_VERSION_PATCH=5'],
    # SCANNER SIDE ONLY. parser.c and loader.c are the layers ABOVE yaml_parser_scan
    # (scan -> parse -> load), 1,128 of 3,658 lines that no scanner harness can reach. A
    # whole-file denominator caps any scan harness at 69.2% and gold reports 70.6%, which
    # proves gold excludes them. Measured over the right set the scanner reads 70.47%,
    # not 48.74% — I hand-listed this wrong three times before checking.
    cover=["/b/libyaml/src/api.c","/b/libyaml/src/reader.c","/b/libyaml/src/scanner.c"]),
 "brotli/decode_fuzzer": dict(
    hdr="/b/brotli/c/include/brotli/decode.h", inc=["/b/brotli/c/include"],
    src=sorted(glob.glob("/b/brotli/c/common/*.c"))+sorted(glob.glob("/b/brotli/c/dec/*.c")),
    fn="BrotliDecoderDecompressStream", cflags=[],
    seeds=["/b/brotli/tests/testdata"],
    cover=sorted(glob.glob("/b/brotli/c/dec/*.c"))),
 "zopfli/zopfli_deflate_fuzzer": dict(
    hdr="/b/zopfli/src/zopfli/deflate.h",
    also=["/b/zopfli/src/zopfli/zopfli.h"], inc=["/b/zopfli/src/zopfli"],
    # zopfli_bin.c carries the CLI's own main(), which collides with libFuzzer's.
    src=[f for f in sorted(glob.glob("/b/zopfli/src/zopfli/*.c")) if "_bin" not in f],
    fn="ZopfliDeflate", cflags=[],
    cover=[f for f in sorted(glob.glob("/b/zopfli/src/zopfli/*.c")) if "_bin" not in f]),
 "zlib/zlib_uncompress2_fuzzer": dict(
    hdr="/b/zlib/zlib.h", inc=["/b/zlib"], src=sorted(glob.glob("/b/zlib/*.c")),
    fn="uncompress2", cflags=["-DHAVE_UNISTD_H"],
    cover=["/b/zlib/inflate.c","/b/zlib/inftrees.c","/b/zlib/inffast.c","/b/zlib/uncompr.c","/b/zlib/adler32.c","/b/zlib/crc32.c","/b/zlib/zutil.c"]),
 "yajl-ruby/json_fuzzer": dict(
    hdr="/b/yajl/inc/yajl/yajl_parse.h", inc=["/b/yajl/inc","/b/yajl/src","/b/yajl/src/api"],
    src=sorted(glob.glob("/b/yajl/src/*.c")), fn="yajl_parse", cflags=[],
    seeds=["/b/yajl/test/parsing/cases"],
    # PARSE SIDE ONLY. yajl_gen.c writes JSON, yajl_tree.c is a separate entry point, and
    # yajl_encode.c serves the writer — 647 of 1,636 lines that `yajl_parse` cannot reach.
    # A whole-library denominator caps ANY parse harness at 60.5%, and gold reports 69.1%,
    # which is only possible if gold excludes them too. Same argument as libyaml's emitter.
    cover=["/b/yajl/src/yajl.c","/b/yajl/src/yajl_alloc.c","/b/yajl/src/yajl_buf.c",
           "/b/yajl/src/yajl_lex.c","/b/yajl/src/yajl_parser.c"]),
 # ── Tier B from the native attack-surface map ─────────────────────────────
 # Real blast radius, a fraction of the scrutiny, and NO public OSS-Fuzz harness — which
 # is the case an LLM cannot have memorised. There is no gold or QuartetFuzz figure to
 # compare against here, and that is the point: this is where a harness generator has to
 # actually reason rather than recall.
 "lcms2/cmsOpenProfileFromMem": dict(
    hdr="/b/lcms2/include/lcms2.h", inc=["/b/lcms2/include","/b/lcms2/src"],
    src=sorted(glob.glob("/b/lcms2/src/*.c")), fn="cmsOpenProfileFromMem", cflags=[],
    seeds=["/b/lcms2/testbed"], max_len=65536,
    # PROFILE I/O ONLY. cmsOpenProfileFromMem reads an ICC profile; colour transforms,
    # gamma, CGATS and the PostScript writer are separate entry points it cannot reach.
    cover=["/b/lcms2/src/cmsio0.c","/b/lcms2/src/cmsio1.c","/b/lcms2/src/cmstypes.c",
           "/b/lcms2/src/cmsplugin.c","/b/lcms2/src/cmserr.c","/b/lcms2/src/cmsmd5.c",
           "/b/lcms2/src/cmsnamed.c","/b/lcms2/src/cmslut.c"]),
 "iperf/cjson_fuzzer": dict(
    hdr="/b/cjson/cJSON.h", inc=["/b/cjson"], src=["/b/cjson/cJSON.c"],
    fn="cJSON_Parse", cflags=[], cover=["/b/cjson/cJSON.c"]),
 # ── Tier B and unfuzzed parsers, from the native attack-surface map ───────
 # The map's own advice: the big names are the blast-radius answer, not the find-a-bug
 # answer. Tier B is "real blast radius, a fraction of the scrutiny", and it is where
 # lcms2 and libde265 came from — eight engine defects between them. None of these have a
 # gold or QuartetFuzz figure, which is the point: they are cases a model cannot recall.
 #
 # Each was chosen for a SHAPE the suite has not tested, not for the name.
 "jbig2dec/jbig2_data_in": dict(
    # Tier B. The constructor is a MACRO wrapping jbig2_ctx_new_imp with two version
    # arguments — a producer that only reads function declarations cannot see it.
    hdr="/b/jbig2dec/jbig2.h", inc=["/b/jbig2dec"],
    # DECODE PATH ONLY. jbig2dec.c and pbm2png.c are command-line tools, getopt*.c is
    # their argument parsing, and the png/pbm writers are OUTPUT — jbig2_image_png.c needs
    # libpng, which this case does not build and a decoder does not need.
    #
    # `-Dbool=int`: jbig2_image.h uses `bool`, and the definition lives in jbig2_priv.h as
    # an UNCONDITIONAL `#define bool int` that jbig2_image.h does not include. Forcing
    # <stdbool.h> instead makes `bool` mean `_Bool` and collides with their macro; defining
    # it identically on the command line is the same token sequence, so it is not a
    # redefinition at all.
    src=[f for f in sorted(glob.glob("/b/jbig2dec/*.c"))
         if not f.endswith(("/jbig2dec.c", "/pbm2png.c", "/getopt.c", "/getopt1.c",
                            "/sha1.c", "/jbig2_image_png.c", "/jbig2_image_pbm.c"))],
    fn="jbig2_data_in",
    cflags=["-DHAVE_STDINT_H", "-Dbool=int"], max_len=65536,
    cover=[f for f in sorted(glob.glob("/b/jbig2dec/*.c"))
           if not f.endswith(("/jbig2dec.c", "/pbm2png.c", "/getopt.c", "/getopt1.c",
                              "/sha1.c", "/jbig2_image_png.c", "/jbig2_image_pbm.c"))]),
 "leptonica/pixReadMem": dict(
    # Tier B, in tesseract and every OCR stack. The destructor takes a POINTER TO THE
    # HANDLE — `void pixDestroy(PIX **ppix)` — which is the shape that broke sqlite's
    # constructor inference from the other direction.
    # Run benchmarks/targets/leptonica.sh first: allheaders.h includes alltypes.h which
    # includes endianness.h, a file leptonica's configure GENERATES. Without it the C
    # preprocessor fails, the parse falls back to raw text, environ.h's
    # `typedef unsigned char l_uint8` is never seen, and pixReadMem stops looking like it
    # takes bytes — five steps to a gate verdict about something else entirely.
    hdr="/b/leptonica/src/allheaders.h", inc=["/b/leptonica/src"],
    src=(sorted(glob.glob("/b/leptonica/src/*.c"))
         + [f for f in sorted(glob.glob("/b/libpng/*.c"))
            if not f.endswith(("/example.c", "/pngtest.c"))]
         + sorted(glob.glob("/b/zlib/*.c"))),
    fn="pixReadMem",
    # The image I/O modules compile against libjpeg, libpng, libtiff, libwebp and giflib,
    # none of which this image carries. leptonica guards each behind a HAVE_LIB macro that
    # its configure sets; without configure they default on and the build fails on
    # jpeglib.h. Turned off explicitly, which narrows pixReadMem to the formats leptonica
    # decodes itself — BMP, PNM, SPIX — and that is stated rather than silently accepted:
    # the denominator below is the files those formats can reach.
    # PNG AND ZLIB ARE COMPILED IN, because both are already in this tree and leptonica
    # guards each decoder behind a HAVE_LIB macro. Turning everything off to make the build
    # work also cut the surface to BMP, PNM and SPIX — the formats leptonica implements
    # itself — which is a large part of why it read 17.24%. jpeg, tiff, webp and gif stay
    # off: their libraries are not here.
    cflags=["-DHAVE_LIBJPEG=0", "-DHAVE_LIBPNG=1", "-DHAVE_LIBTIFF=0",
            "-DHAVE_LIBWEBP=0", "-DHAVE_LIBGIF=0", "-DHAVE_LIBZ=1",
            "-DHAVE_LIBJP2K=0", "-DHAVE_LIBWEBP_ANIM=0",
            "-I/b/libpng", "-I/b/zlib"],
    # prog/ for its own test images, AND pngsuite now that PNG decoding is compiled IN.
    # 51 canonical PNGs are worth more than leptonica's handful of BMPs: measured on this
    # very build, its own images read 8.32% of lines against 0.84% for random bytes of the
    # same sizes, so the corpus is the lever and PNG is the format with the corpus.
    seeds=["/b/leptonica/prog", "/b/libpng/contrib/pngsuite"],
    max_len=65536,
    # ONLY THE FORMATS THIS BUILD CAN DECODE. png, jpeg, tiff, webp and gif are compiled
    # out above, so counting their readers would cap any harness far below what it can
    # reach and make the figure meaningless.
    # LEPTONICA'S OWN READERS ONLY. libpng and zlib are linked so that pngio.c has
    # something to call, but they are their own cases with their own rows and counting them
    # here would measure a dependency rather than this entry point.
    cover=["/b/leptonica/src/readfile.c", "/b/leptonica/src/bmpio.c",
           "/b/leptonica/src/pnmio.c", "/b/leptonica/src/spixio.c",
           "/b/leptonica/src/pngio.c", "/b/leptonica/src/pix1.c",
           "/b/leptonica/src/pix2.c", "/b/leptonica/src/colormap.c"]),
 "jansson/json_loadb": dict(
    # The destructor is a STATIC INLINE in the header — `json_decref` calls json_delete —
    # so a producer reading declarations sees no destroyer for a handle it must free.
    # There is also an out-parameter that is NOT a handle: `json_error_t *error`.
    hdr="/b/jansson/src/jansson.h", inc=["/b/jansson/src", "/b/jansson"],
    src=sorted(glob.glob("/b/jansson/src/*.c")),
    fn="json_loadb",
    # 115 valid documents from jansson's own conformance suite, plus the invalid ones —
    # both are useful, and the invalid set is arguably more so for a parser: they are
    # hand-written near-misses, which is exactly the neighbourhood a mutator explores badly
    # from scratch.
    seeds=["/b/jansson/test/suites"],
    # `-include stdint.h` on the command line, not in jansson_config.h. utf.c uses int32_t
    # and does not include the config header, so putting the include there fixed
    # hashtable.c and left utf.c failing with `unknown type name 'int32_t'` — and the
    # cascading parse errors after it pointed at a phantom identifier rather than the real
    # cause. configure normally settles this per translation unit.
    cflags=["-include", "stdint.h"], max_len=65536,
    cover=sorted(glob.glob("/b/jansson/src/*.c"))),
 "libpng/png_image_begin_read_from_memory": dict(
    # Android platform library, and in every browser and toolkit. Run
    # benchmarks/targets/libpng.sh first for pnglibconf.h.
    #
    # The SHAPE this adds: a caller-allocated struct the library INITIALISES and FREES.
    # `int png_image_begin_read_from_memory(png_imagep image, png_const_voidp memory,
    # size_t size)` where the caller declares a png_image, and png_image_free releases what
    # the library hung off it. Neither an opaque handle nor a plain out-parameter.
    hdr="/b/libpng/png.h", also=["/b/libpng/pngconf.h"],
    inc=["/b/libpng", "/b/zlib"],
    # pngtest.c and example.c each carry their own main(), which collides with
    # libFuzzer's — the same shape as zopfli's zopfli_bin.c. Excluded from the link and
    # from the denominator: a test program is not the library's attack surface.
    src=[f for f in sorted(glob.glob("/b/libpng/*.c"))
         if not f.endswith(("/example.c", "/pngtest.c"))]
        + sorted(glob.glob("/b/zlib/*.c")),
    fn="png_image_begin_read_from_memory", cflags=[], max_len=65536,
    # THE CANONICAL PNG TEST SUITE, 51 files, in the tree. A PNG has a magic number, a
    # chunk structure and a CRC per chunk; libFuzzer will not synthesise one from an empty
    # corpus inside 600 seconds, so without seeds the campaign spends its whole budget
    # being rejected at the signature check. brotli is the control: it mines 50 seeds from
    # its own testdata and reaches 85%.
    seeds=["/b/libpng/contrib/pngsuite"],
    # png's own sources only: zlib is a dependency this build links, not the surface under
    # test, and it already has two cases of its own.
    cover=[f for f in sorted(glob.glob("/b/libpng/*.c"))
           if not f.endswith(("/example.c", "/pngtest.c"))]),
 "libwebp/WebPDecodeRGBA": dict(
    # THE MAP'S CANONICAL EXAMPLE: one heap overflow in libwebp reached Chrome, Firefox,
    # Safari, Electron, Signal, Slack, Android and iOS at the same time. It is also in
    # Android's platform image stack, so it belongs to the mobile surface as much as the
    # desktop one.
    #
    # The SHAPE this adds: a free function with an owned return AND two scalar
    # out-parameters. `uint8_t *WebPDecodeRGBA(const uint8_t *data, size_t data_size,
    # int *width, int *height)` freed by `WebPFree(void *)`. Nothing else in the suite
    # combines a caller-freed return with out-params the callee writes.
    hdr="/b/libwebp/src/webp/decode.h",
    # types.h, because `void WebPFree(void *)` is declared THERE and decode.h only includes
    # it. The per-header filter in _preprocess keeps declarations from the named file only —
    # rightly, or the producer proposes harnesses for stdio — so without this the destructor
    # is invisible, no cleanup is planned, and a decoded image leaks on every input.
    also=["/b/libwebp/src/webp/types.h"],
    inc=["/b/libwebp", "/b/libwebp/src"],
    src=(sorted(glob.glob("/b/libwebp/src/dec/*.c"))
         + sorted(glob.glob("/b/libwebp/src/dsp/*.c"))
         + sorted(glob.glob("/b/libwebp/src/utils/*.c"))),
    fn="WebPDecodeRGBA", cflags=[], max_len=65536,
    # SEEDS SYNTHESISED BY THE LIBRARY'S OWN ENCODER. Run benchmarks/targets/libwebp.sh
    # first; it builds WebPEncodeRGBA and emits 24 valid RIFF/WEBP files across lossy,
    # lossless and a quality sweep, at sizes that cross the block boundaries a codec cares
    # about.
    #
    # libwebp keeps its corpus outside the repository, so this case ran at seeds=0 and
    # spent its budget failing the container check. An encoder IS a seed generator, and
    # this is the round-trip idea at its simplest.
    #
    # Prioritised by FORMAT on measured grounds: leptonica went 10.73 -> 20.67 on real BMP
    # headers while jansson moved 0.16 on real JSON, because a mutator reaches "{}" in two
    # bytes and never reaches a RIFF container.
    seeds=["/b/libwebp/hf-seeds"],
    # DECODE PATH ONLY. enc/, mux/ and demux/ are separate libraries a decode entry point
    # cannot reach; dsp/ carries both, but its encode kernels are unreachable from here and
    # excluding the directory wholesale would drop the decode kernels with them.
    cover=(sorted(glob.glob("/b/libwebp/src/dec/*.c"))
           + sorted(glob.glob("/b/libwebp/src/utils/*.c")))),
 # ── the internet's plumbing ───────────────────────────────────────────────
 # Libraries that sit in the path of untrusted input on a very large fraction of the
 # deployed internet. Two of them are heavily fuzzed already, which makes them CALIBRATION
 # rather than discovery: if this engine cannot reach a decent fraction of expat, the
 # number says something about the engine, not the library.
 "expat/XML_Parse": dict(
    # XML for Python's ElementTree, Perl, PHP, Firefox, and most C software that reads XML.
    # A textbook lifecycle — XML_ParserCreate / XML_Parse / XML_ParserFree — which is the
    # shape this producer was built around, so a low score here would be damning.
    # Run benchmarks/targets/expat.sh first for the cmake-generated expat_config.h.
    hdr="/b/expat/expat/lib/expat.h",
    inc=["/b/expat/expat", "/b/expat/expat/lib"],
    # A LIBRARY'S .c FILES ARE NOT ALL MEANT TO BE COMPILED, and expat is the third target
    # in this suite to prove it — after jbig2dec's CLI tools and libpng's pngtest.c. Three
    # distinct reasons here:
    #   xmltok_impl.c, xmltok_ns.c, xcsinc.c   #included INTO another file, not compiled
    #   random_*.c                             one PLATFORM ALTERNATE per entropy source,
    #                                          and cmake picks exactly one. Compiling all
    #                                          six pulls in rand_s (Windows) and
    #                                          arc4random (BSD), neither of which links.
    # random_getrandom.c is kept because expat_config.h declares HAVE_GETRANDOM, so the
    # header and the source list have to agree — that is what a build system is for, and
    # writing it out is the price of not having one.
    src=[f for f in sorted(glob.glob("/b/expat/expat/lib/*.c"))
         if not f.endswith(("/xmltok_impl.c", "/xmltok_ns.c", "/xcsinc.c"))
         and not (f.rsplit("/", 1)[-1].startswith("random_")
                  and not f.endswith("/random_getrandom.c"))],
    fn="XML_Parse", cflags=["-DHAVE_EXPAT_CONFIG_H", "-DXML_GE=1"], max_len=65536,
    seeds=["/b/expat/expat/tests"],
    cover=[f for f in sorted(glob.glob("/b/expat/expat/lib/*.c"))
           if not f.endswith(("/xmltok_impl.c", "/xmltok_ns.c", "/xcsinc.c"))
           and not (f.rsplit("/", 1)[-1].startswith("random_")
                    and not f.endswith("/random_getrandom.c"))]),
 "mbedtls/mbedtls_x509_crt_parse": dict(
    # X.509 CERTIFICATE PARSING — where untrusted bytes enter every TLS handshake, before
    # any authentication has happened. mbedTLS is in routers, IoT firmware, embedded Linux
    # and anything that needs TLS without OpenSSL's footprint.
    #
    # 3.6 LTS deliberately: mbedTLS 4.x moved its crypto into the tf_psa_crypto submodule,
    # so a shallow clone of main cannot build at all, and 3.6 is what deployments run.
    #
    # A textbook lifecycle on a (bytes, len) entry point:
    #   mbedtls_x509_crt_init -> mbedtls_x509_crt_parse(chain, buf, buflen)
    #                         -> mbedtls_x509_crt_free
    hdr="/b/mbedtls/include/mbedtls/x509_crt.h",
    inc=["/b/mbedtls/include", "/b/mbedtls/library"],
    src=sorted(glob.glob("/b/mbedtls/library/*.c")),
    fn="mbedtls_x509_crt_parse", cflags=[], max_len=65536,
    # mbedTLS ships DER and PEM certificates for its own test suite: real ASN.1, which a
    # mutator does not reach by accident. Same argument as pngsuite for libpng.
    seeds=["/b/mbedtls/tests/data_files"],
    # THE X.509 SURFACE ONLY. The TLS state machine, the ciphersuites and the crypto
    # primitives are linked because the parser calls into them, but a certificate-parsing
    # entry point does not reach ssl_tls13_server.c, and counting it would cap the figure
    # far below anything achievable.
    cover=["/b/mbedtls/library/x509.c", "/b/mbedtls/library/x509_crt.c",
           "/b/mbedtls/library/x509_crl.c", "/b/mbedtls/library/x509_csr.c",
           "/b/mbedtls/library/asn1parse.c", "/b/mbedtls/library/oid.c",
           "/b/mbedtls/library/pem.c", "/b/mbedtls/library/base64.c"]),
 "zstd/ZSTD_decompress": dict(
    # zstd is in the Linux kernel, btrfs, most package managers, and every large web stack
    # that compresses anything. `size_t ZSTD_decompress(void *dst, size_t dstCapacity,
    # const void *src, size_t compressedSize)` is the caller-owns-the-output-buffer shape:
    # a scratch buffer sized by a knob, which the stream binder already models.
    hdr="/b/zstd/lib/zstd.h", inc=["/b/zstd/lib", "/b/zstd/lib/common"],
    src=[f for f in sorted(glob.glob("/b/zstd/lib/common/*.c")
                           + glob.glob("/b/zstd/lib/decompress/*.c")
                           + glob.glob("/b/zstd/lib/compress/*.c"))],
    fn="ZSTD_decompress", cflags=["-DZSTD_DISABLE_ASM=1"], max_len=65536,
    # DECOMPRESSION ONLY. compress/ is linked because the decoder references shared
    # entropy code, but a decode entry point cannot reach the encoder and counting it
    # would cap the figure for no reason.
    cover=sorted(glob.glob("/b/zstd/lib/decompress/*.c")
                 + glob.glob("/b/zstd/lib/common/*.c"))),
 # ── C++ targets ───────────────────────────────────────────────────────────
 # First C++ case in the suite. libde265 is C++ behind an `extern "C"` API, which is the
 # common shape for codecs and the one that matters most: the header producer can read the
 # C declarations, and only the build has to change to clang++.
 #
 # It is here for a second reason. libde265 ships its OWN hand-written fuzz harness at
 # fuzzing/stream_fuzzer.cc, so the gold column for this case is MEASURED on this machine
 # at this budget rather than cited from somebody's paper. Same compiler, same corpus
 # policy, same 600 seconds, same denominator. Run `benchmarks/targets/libde265.sh` first;
 # the build needs two headers cmake would otherwise generate.
 "libde265/stream_decode": dict(
    cxx=True, std="c++11",
    hdr="/b/libde265/libde265/de265.h",
    inc=["/b/libde265", "/b/libde265/libde265"],
    # en265.cc is the ENCODER's public API and it sits in the same directory as the
    # decoder. It pulls encoder_context and config_parameters out of encoder/, which is a
    # separate library this case does not build, so linking it fails on a dozen undefined
    # references that have nothing to do with decoding. Excluding it is the same argument
    # as the coverage denominator below, applied to the link line.
    src=[f for f in sorted(glob.glob("/b/libde265/libde265/*.cc"))
         if not f.endswith("/en265.cc")],
    fn="de265_push_data", cflags=["-DHAVE_CONFIG_H"], max_len=65536,
    # The library's own harness, built and measured exactly as ours is. This is a gold
    # figure this repository PRODUCES, not one it quotes.
    gold_harness="/b/libde265/fuzzing/stream_fuzzer.cc",
    # DECODE PATH ONLY. encoder/ is a separate library, the x86 and arm32 SIMD directories
    # are not compiled on aarch64, and sherlock265/dec265 are applications.
    cover=[f for f in sorted(glob.glob("/b/libde265/libde265/*.cc"))
           if not f.endswith("/en265.cc")]),
}

def main():
    case = sys.argv[1]; seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 600
    c = CASES[case]
    # Some libraries declare the entry point in one header and its configuration helper in
    # another: ZopfliDeflate is in deflate.h, ZopfliInitOptions in zopfli.h. Give the
    # producer both, exactly as an operator would with --also-header.
    t = Target(name=case.split("/")[0],
               public_headers=[c["hdr"]] + list(c.get("also", [])),
               include_dirs=c["inc"],
               sources=c["src"], cflags=c["cflags"])
    # max_len is PER CASE. An ICC profile runs to 654 KB and a 4096-byte harness discards
    # every one of them at the door — `if (hf_size > 4096u) return 0;` — so the seeds are
    # mined, handed to libFuzzer, and thrown away by the harness itself.
    mlen = c.get("max_len", 4096)
    plans = hg.propose(t.public_headers, t, platforms=["linux-aarch64-glibc"],
                       knobs=Knobs(max_len=mlen))
    # Any plan that CALLS the gold target function, in whatever role. `cJSON_Parse(const
    # char *)` returns a handle, so our producer uses it as the CONSTRUCTOR — which is
    # exactly what the gold harness does (parse then delete). Insisting the target be the
    # `o_consume` op would score that a miss when the harness is right.
    cands = [p for p in plans if any(o.api == c["fn"] for o in p.sequence)]
    # Prefer plans where the fuzzer's bytes actually reach that call.
    def _driven(pl):
        op = next((o for o in pl.sequence if o.api == c["fn"]), None)
        return 1 if op and any(a.source == "input" for a in op.args) else 0

    def _is_entry(pl):
        """The gold target must be the ENTRY POINT, not an incidental setup call.

        Relaxing this to "any plan that calls the function" picked, for libyaml's scanner
        case, a plan whose consumer was `yaml_parser_set_input` — which takes a read-handler
        CALLBACK, bound to NULL — with `yaml_parser_scan` demoted to a setup op. The harness
        aborted after 2 executions and scored 0.00%.
        """
        return 1 if any(o.id.startswith("o_consume") and o.api == c["fn"]
                        for o in pl.sequence) else 0

    def _plain(pl):
        """Prefer the plan WITHOUT extra setup calls.

        A `_setup` variant inserts other library calls around the target, and for libyaml
        that meant `yaml_parser_load` beside `yaml_parser_scan` — which libyaml forbids on
        one parser and asserts on. Ranking by deepest sequence chose it every time.
        """
        return 0 if ("_setup" not in pl.name and "_with_" not in pl.name) else 1

    cands.sort(key=lambda x: (-_is_entry(x), -_driven(x), _plain(x),
                              -len(x.sequence), len(x.name)))
    out = {"case": case, "engine": os.environ.get("HF_ENGINE_SHA", "unknown"),
           "target": c["fn"], "proposed": len(plans),
           "plans_for_target": len(cands)}
    if not cands:
        out["result"] = "NO PLAN for the gold target"
        print(json.dumps(out)); return
    ok = []
    for p in cands:
        rs = run_static_gates(p)
        b = sorted({v.code for r in rs for v in r.violations if v.severity == BLOCK})
        if not b:
            ok.append(p)
    out["passed_static"] = len(ok)
    if not ok:
        out["result"] = "all plans for the gold target were refused by a static gate"
        print(json.dumps(out)); return
    # prefer the plan with the most ops (deepest lifecycle), then the shortest name
    p = sorted(ok, key=lambda x: (-_is_entry(x), -_driven(x), _plain(x),
                                  -len(x.sequence), len(x.name)))[0]
    out["target_is_input_driven"] = bool(_driven(p))
    out["target_is_entry_point"] = bool(_is_entry(p))
    out["plan"] = p.name
    out["sequence"] = [o.api for o in p.sequence]
    try:
        e = emit(p)
    except EmitError as ex:
        out["result"] = f"emit refused: {ex}"; print(json.dumps(out)); return
    wd = pathlib.Path(f"/b/runs/{case.replace('/','__')}"); wd.mkdir(parents=True, exist_ok=True)
    (wd/"harness.c").write_text(e.source)

    # KEEP EVERY RUN'S EVIDENCE ON DISK.
    #
    # A benchmark row is a summary, and a summary cannot be audited. Three of this
    # project's four wrong diagnoses were caught by re-reading a raw libFuzzer log
    # after the number had already been written down: `corp: 1/1b` with coverage
    # frozen at 42 is what exposed the scratch-initialisation bug, and no JSON
    # field would have shown it. So the log outlives the run.
    logs = pathlib.Path(os.environ.get("HF_LOGDIR", "/b/logs")) / case.replace("/", "__")
    logs.mkdir(parents=True, exist_ok=True)
    (logs/"harness.c").write_text(e.source)
    (logs/"plan.hir.json").write_text(json.dumps(p.to_json() if hasattr(p, "to_json")
                                                 else {"name": p.name,
                                                       "sequence": [o.api for o in p.sequence]},
                                                 indent=2, default=str))
    out["logs"] = str(logs)
    # C++ targets build with clang++ and an explicit standard. Everything else about the
    # build is identical, on purpose: a gold harness and ours must differ in the harness
    # and in nothing else, or the comparison measures the build.
    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]

    # ── the emitted C is ours; a warning about it is evidence about the producer ──
    #
    # This case cost two 600-second campaigns and three wrong diagnoses. The emitter
    # declared `unsigned char hf_r_err` for a function returning `unsigned char *`, clang
    # warned, the build succeeded, and the harness segfaulted on its third execution for a
    # measured 0.00% where the case had been 65.12%. The compiler knew in milliseconds.
    diag = check_emitted_c(cc[0], wd/"harness.c", c["inc"], c["cflags"],
                           is_cxx=bool(c.get("cxx")))
    if diag:
        (logs/"emitter-defect.log").write_text("\n".join(diag) + "\n")
        out["result"] = "REFUSED: the emitted harness has an emitter defect"
        out["emitter_defect"] = diag[:3]
        print(json.dumps(out))
        return

    binp = wd/"fuzz"
    cmd = cc + ["-g","-O1","-fno-omit-frame-pointer",
           "-fprofile-instr-generate","-fcoverage-mapping"]
    cmd += [f"-I{i}" for i in c["inc"]] + c["cflags"]
    cmd += ["-fsanitize=fuzzer,address", str(wd/"harness.c")] + c["src"] + ["-o", str(binp)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    (logs/"build.cmd").write_text(" ".join(cmd) + "\n")
    # A build.log left over from an EARLIER failed attempt sits next to a successful build
    # and reads as if this run failed. run-010's first attempt failed to link en265.cc; the
    # retry succeeded into the same directory and the stale log stayed. Evidence that
    # describes a different run is worse than no evidence.
    (logs/"build.log").unlink(missing_ok=True)
    if r.returncode != 0:
        # The truncated field in the JSON row is for reading; the file is for fixing.
        (logs/"build.log").write_text(r.stdout + r.stderr)
        out["result"] = "build failed"; out["error"] = r.stderr[-400:]
        print(json.dumps(out)); return
    # A FRESH CORPUS EVERY RUN, unless the operator asks otherwise.
    #
    # This directory persisted across runs 009-021, so every campaign started from whatever
    # its predecessors had found. For the seven saturated cases that changed nothing —
    # run-016 reproduced run-009 to the hundredth with a corpus that had grown for four runs
    # — but it CONFOUNDS ANY BEFORE-AND-AFTER on the same case, which is exactly what the
    # seed comparison was: leptonica's 10.73 -> 20.67 cannot be attributed to seeds rather
    # than to carry-over from the previous run's corpus.
    #
    # measure_gold already wipes its own corpus for this reason, with a comment saying that
    # handing gold OUR grown corpus would measure our corpus and not their harness. The same
    # argument applies to comparing our own runs to each other; I applied it to the
    # comparison I was suspicious of and not to the one I was making.
    #
    # HF_KEEP_CORPUS=1 restores the old behaviour for anyone who wants a long-running
    # accumulating campaign, which is a legitimate thing to want and a different experiment.
    corp = wd/"corpus"
    if corp.exists() and not os.environ.get("HF_KEEP_CORPUS"):
        shutil.rmtree(corp)
    corp.mkdir(exist_ok=True)
    out["corpus_policy"] = ("kept" if os.environ.get("HF_KEEP_CORPUS") else "fresh")

    # THE ENGINE ALREADY MINES BOTH OF THESE AND THE BENCHMARK WAS USING NEITHER.
    # Measured on sqlite, the dictionary alone took one harness from 867 to 5,441 edges
    # (6.3x) on the same budget. Running the benchmark with an empty corpus and no
    # dictionary measured the producer with two of the engine's own instruments switched
    # off — a fault in the benchmark, not in the engine.
    from hforge.analysis import dictionary, seeds as seedmod
    dict_args = []
    dpath = wd/"target.dict"
    if dictionary.write(c["src"], dpath):
        dict_args = [f"-dict={dpath}"]
    n_seeds = 0
    if c.get("seeds"):
        # Seeds are capped at the harness's own max_len, not an arbitrary 4096: lcms2's ICC
        # profiles run to 654 KB and every one was silently rejected, and 8 of brotli's 44
        # streams too.
        mined = seedmod.mine(c["seeds"], max_bytes=65536)
        n_seeds = seedmod.write(mined, corp)
    out["dictionary"] = bool(dict_args)
    out["seeds"] = n_seeds
    # ── D1 and D3, before the campaign ────────────────────────────────────────────
    #
    # drive.py ran the STATIC gates and nothing else, so every case was campaigned on a
    # plan D1-D11 had never seen. The cost was two 600-second runs proving a harness that
    # segfaulted on its third execution — which is precisely what D3 exists to catch.
    #
    # Not the full gate bank: those build their own binary and this one is already built.
    # These are the two that are nearly free once it exists.
    #
    # D1, LIVENESS: the target call must survive the optimiser. A call clang proved dead
    # and deleted leaves a harness that runs and reaches nothing, and coverage cannot tell
    # that apart from a hard target.
    nm = subprocess.run(["nm", "-C", str(binp)], capture_output=True, text=True,
                        errors="replace")
    if nm.returncode == 0 and c["fn"] not in nm.stdout:
        out["result"] = f"REFUSED by D1: {c['fn']} is not in the built binary"
        print(json.dumps(out)); return
    out["d1_liveness"] = "pass"

    # D3, VALID INPUT MUST NOT CRASH: a short run over the mined seeds. A harness that
    # faults on input the library ACCEPTS is reporting its own defect, and every finding
    # from it would be the harness's own.
    #
    # NOTE FOR ANYONE READING A ROW AGAINST A LOG: this gate GROWS THE CORPUS. libFuzzer
    # writes newly-interesting inputs back into a writable corpus directory, so libwebp's
    # 24 mined seeds became 79 files by the time the campaign started. `seeds` on the row is
    # what the miner supplied; the log's "seed corpus: files: N" is what existed after this
    # check. Both are true and they measure different moments.
    smoke = subprocess.run([str(binp), str(corp), "-runs=400", f"-max_len={mlen}"],
                           capture_output=True, text=True, errors="replace",
                           timeout=300)
    if smoke.returncode != 0:
        log = smoke.stdout + smoke.stderr
        (logs/"d3-refused.log").write_text(log)
        first = next((l for l in log.splitlines()
                      if "ERROR:" in l or "SUMMARY:" in l), "").strip()
        out["result"] = "REFUSED by D3: valid input crashes the harness"
        out["d3_evidence"] = first[:220]
        print(json.dumps(out)); return
    out["d3_valid_input"] = "pass"

    prof = wd/"run.profraw"
    env = dict(os.environ, LLVM_PROFILE_FILE=str(prof))
    # THE CAMPAIGN'S OUTPUT GOES TO A FILE, NOT INTO MEMORY.
    #
    # jbig2dec prints an error to stderr for every rejected input, through the default
    # handler a NULL error_callback selects. 25,353,303 executions produced 2.5 GB of
    # "jbig2 decoder FATAL ERROR: page has no image". capture_output=True held all of it
    # in this process, the campaign did not survive to flush its coverage profile,
    # run.profraw came out 0 bytes, and llvm-cov reported 0.00% for a harness that had
    # just run 25 million times and passed D1 and D3.
    #
    # A talkative library is not a defect. Reading its output into memory is.
    logf = logs/"fuzz.log"
    with open(logf, "w", errors="replace") as fh:
        fr = subprocess.run([str(binp), str(corp), *dict_args, f"-max_total_time={seconds}",
                             "-print_final_stats=1", f"-max_len={mlen}"],
                            stdout=fh, stderr=subprocess.STDOUT,
                            env=env, timeout=seconds+300)
    size = logf.stat().st_size
    out["campaign_log_bytes"] = size
    CAP = 8 << 20
    if size > CAP:
        # Keep both ends: the header carries the seed and the dictionary, the tail carries
        # the final stats. Everything between is the same line several million times.
        with open(logf, "rb") as fh:
            head = fh.read(CAP // 2)
            fh.seek(-(CAP // 2), 2)
            tail = fh.read()
        logf.write_bytes(head + b"\n\n[... " + str(size - CAP).encode() +
                         b" bytes elided: the target writes to stderr on every input ...]\n\n"
                         + tail)
        out["campaign_log_truncated"] = True
    log = logf.read_text(errors="replace")
    (logs/"fuzz.cmd").write_text(
        " ".join([str(binp), str(corp), *dict_args, f"-max_total_time={seconds}",
                  "-print_final_stats=1", f"-max_len={mlen}"]) + "\n")
    if dict_args and dpath.exists():
        (logs/"target.dict").write_text(dpath.read_text(errors="replace"))
    out["executions"] = int(next((x for x in __import__("re").findall(
        r"stat::number_of_executed_units:\s*(\d+)", log)), 0) or 0)
    # AN EMPTY PROFILE IS A FAILED MEASUREMENT, NOT A ZERO.
    #
    # `llvm-profdata merge` SUCCEEDS on an empty .profraw and produces a valid, empty
    # profile; llvm-cov then reports 0.00% for every file. That is indistinguishable from a
    # harness that genuinely covered nothing — and jbig2dec published exactly that row while
    # its own d1_liveness and d3_valid_input both said pass. Two facts in one row
    # contradicting each other, and nothing noticed.
    # COVERAGE IS MEASURED BY REPLAYING THE CORPUS, NOT BY THE CAMPAIGN.
    #
    # libFuzzer writes its profile at clean exit, so any campaign that DIES takes its
    # measurement with it — jbig2dec at 1,761 MB and leptonica once real BMP seeds got it
    # past the header check and into allocation. Both produced a corpus full of interesting
    # inputs and no number.
    #
    # Replaying that corpus in a separate process with -runs=0 exits cleanly and profiles
    # exactly the inputs the campaign found. It also separates two things that were tangled:
    # how the campaign ENDED is a fact about the target's resource behaviour, and how much
    # it REACHED is a fact about the harness. A campaign that dies still earns a number.
    replay = wd/"replay.profraw"
    rp = subprocess.run([str(binp), str(corp), "-runs=0", f"-max_len={mlen}"],
                        capture_output=True, text=True, errors="replace",
                        env=dict(os.environ, LLVM_PROFILE_FILE=str(replay)),
                        timeout=600)
    if replay.exists() and replay.stat().st_size > 0:
        out["coverage_from"] = "corpus replay"
        out["replay_exit"] = rp.returncode
        prof = replay
    elif prof.exists() and prof.stat().st_size > 0:
        out["coverage_from"] = "campaign"

    if not prof.exists() or prof.stat().st_size == 0:
        # SAY WHAT KILLED IT, not merely that the profile is missing.
        #
        # jbig2dec reached 1,761 MB of RSS on a ~200-byte input and libFuzzer killed the
        # process at its limit, so nothing flushed. Reporting that as "no profile" describes
        # the symptom and hides the cause. An OOM or a crash that ends the campaign is a
        # RESOURCE-POLICY outcome — the certificate already states that allocations beyond
        # the limit are the campaign's policy and not a target defect — and it is a
        # candidate for triage, which is a human act, not a finding this driver may declare.
        why, artifact = "the campaign wrote no coverage profile", ""
        for line in log.splitlines():
            if line.startswith("SUMMARY: libFuzzer:"):
                why = line.split("SUMMARY: libFuzzer:", 1)[1].strip()
            elif "Test unit written to" in line:
                artifact = line.rsplit(" ", 1)[-1].strip()
        out["result"] = (f"NOT MEASURED: campaign ended on {why}, so no coverage was "
                         f"flushed; 0.00% would be a failed measurement reported as a real "
                         f"one")
        out["campaign_end"] = why
        if artifact:
            out["reproducer"] = artifact
            out["triage_note"] = ("A reproducer was written. Whether this is a target defect "
                                  "or this harness's resource policy needs triage; the "
                                  "engine does not decide that.")
        out["profraw_bytes"] = prof.stat().st_size if prof.exists() else -1
        print(json.dumps(out)); return
    mg = subprocess.run(["llvm-profdata-14","merge","-sparse",str(prof),
                         "-o",str(wd/"run.profdata")], capture_output=True, text=True)
    if mg.returncode != 0:
        (logs/"profdata.log").write_text(mg.stdout + mg.stderr)
        out["result"] = f"NOT MEASURED: llvm-profdata merge failed: {mg.stderr[-200:]}"
        print(json.dumps(out)); return
    # THE DENOMINATOR IS DERIVED, NOT HAND-LISTED.
    #
    # I hand-listed cover files three times and was wrong three times: libyaml's loader
    # included the emitter side, yajl included the generator and tree, and the scanner
    # included parser.c and loader.c — the layers ABOVE yaml_parser_scan. Each time the
    # engine looked far worse than it was; the scanner reads 48.74% over the wrong file set
    # and 70.47% over the right one, against a gold harness at 70.6%.
    #
    # So ask the engine. D4's call-graph walk already computes what an entry point reaches;
    # a file with no reachable function in it cannot be part of the denominator, and gold's
    # own numbers prove it excludes them too (they exceed the ceiling otherwise).
    # The automatic derivation is left OFF: `reachable_from` is a name-based closure that
    # over-approximates (its own docstring says so), and for libyaml it pulled parser.c and
    # loader.c back in because yaml_parser_scan appears in their call graphs as a callee.
    # Each cover list below carries the ceiling argument that justifies it.
    # The coverage denominator is HAND-LISTED per case, with the ceiling argument that
    # justifies it recorded beside each list. Automatic derivation was tried and removed:
    # `reachable_from` is a name-based closure that over-approximates — for libyaml it pulled
    # parser.c and loader.c back in because yaml_parser_scan appears in their call graphs as
    # a callee, which is exactly the file set that made the scanner read 48.74% instead of
    # 70.47%.
    cover = c["cover"]
    out["cover_files"] = [f.rsplit("/", 1)[-1] for f in cover]
    cr = subprocess.run(["llvm-cov-14","report",str(binp),
                         f"-instr-profile={wd}/run.profdata"] + cover,
                        capture_output=True, text=True)
    # The TOTAL row is the only thing the JSON carries, but the per-file breakdown is
    # what makes a denominator argument checkable by someone who does not trust ours.
    (logs/"coverage.txt").write_text(cr.stdout + cr.stderr)
    tot = [l for l in cr.stdout.splitlines() if l.startswith("TOTAL")]
    if tot:
        f = tot[0].split()
        out["regions_pct"] = f[3].rstrip('%'); out["functions_pct"] = f[6].rstrip('%')
        out["lines_pct"] = f[9].rstrip('%'); out["branches_pct"] = f[12].rstrip('%')
    out["result"] = "measured"

    # ── the gold harness, when the project ships one ──────────────────────────────
    #
    # Every other gold figure in this suite is CITED from somebody else's paper, which
    # means it was produced on another machine, with another compiler, at another budget,
    # over a denominator we cannot inspect. When a project ships its own hand-written fuzz
    # harness in tree, none of that is necessary: build it here, run it here, measure it
    # over the same file list, and the comparison differs in the harness and in nothing
    # else. That is a stronger claim than any citation, and it can go against us.
    if c.get("gold_harness"):
        g = measure_gold(c, wd, logs, corp, dict_args, seconds, mlen, cover)
        out["gold_measured_here"] = g

    print(json.dumps(out))


def measure_gold(c, wd, logs, corp, dict_args, seconds, mlen, cover):
    """Build and run the project's own harness under exactly our build and budget."""
    gsrc = c["gold_harness"]
    gwd = wd/"gold"; gwd.mkdir(exist_ok=True)
    glogs = logs/"gold"; glogs.mkdir(exist_ok=True)
    gbin = gwd/"fuzz"
    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]
    cmd = cc + ["-g", "-O1", "-fno-omit-frame-pointer",
                "-fprofile-instr-generate", "-fcoverage-mapping"]
    cmd += [f"-I{i}" for i in c["inc"]] + c["cflags"]
    cmd += ["-fsanitize=fuzzer,address", gsrc] + c["src"] + ["-o", str(gbin)]
    (glogs/"build.cmd").write_text(" ".join(cmd) + "\n")
    (glogs/"build.log").unlink(missing_ok=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        (glogs/"build.log").write_text(r.stdout + r.stderr)
        return {"result": "build failed", "error": r.stderr[-400:]}

    # A FRESH corpus. Handing the gold harness the corpus OUR run just grew would measure
    # our corpus, not their harness, and it would flatter us: those inputs were selected
    # by a fuzzer driving our entry point. Same seeds and same dictionary, same start.
    gcorp = gwd/"corpus"
    if gcorp.exists():
        shutil.rmtree(gcorp)
    gcorp.mkdir()
    if c.get("seeds"):
        from hforge.analysis import seeds as seedmod
        seedmod.write(seedmod.mine(c["seeds"], max_bytes=65536), gcorp)
    prof = gwd/"run.profraw"
    fr = subprocess.run([str(gbin), str(gcorp), *dict_args, f"-max_total_time={seconds}",
                         "-print_final_stats=1", f"-max_len={mlen}"],
                        capture_output=True, text=True, errors="replace",
                        env=dict(os.environ, LLVM_PROFILE_FILE=str(prof)),
                        timeout=seconds + 300)
    (glogs/"fuzz.log").write_text(fr.stdout + fr.stderr)
    subprocess.run(["llvm-profdata-14", "merge", "-sparse", str(prof),
                    "-o", str(gwd/"run.profdata")], capture_output=True)
    cr = subprocess.run(["llvm-cov-14", "report", str(gbin),
                         f"-instr-profile={gwd}/run.profdata"] + cover,
                        capture_output=True, text=True)
    (glogs/"coverage.txt").write_text(cr.stdout + cr.stderr)
    g = {"result": "measured", "source": gsrc}
    tot = [l for l in cr.stdout.splitlines() if l.startswith("TOTAL")]
    if tot:
        f = tot[0].split()
        g["regions_pct"], g["lines_pct"] = f[3].rstrip("%"), f[9].rstrip("%")
    g["executions"] = int(next((x for x in __import__("re").findall(
        r"stat::number_of_executed_units:\s*(\d+)", fr.stdout + fr.stderr)), 0) or 0)
    return g

main()
