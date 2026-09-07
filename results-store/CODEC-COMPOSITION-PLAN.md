# Focused block: the codec-composition test (scheduled 2026-09-07)

The ONE open question that could flip the coverage axis above parity: on a MEDIA CODEC, does
our multi-entry/composed harness beat the developer harness, because a codec exposes several
decode subsystems (RGBA / YUV / incremental / features / demux) that a single dev fuzzer does
not combine?

Target: libwebp (decode is self-contained -- src/dec + src/dsp + src/utils + src/webp -- no
zlib). Dev harness: tests/fuzzer/dec_fuzzer.cc (single WebPDecode). Ours: a COMPOSED harness
folding WebPGetInfo + WebPDecodeRGBA + WebPDecodeYUVA + incremental WebPIDecode on the same
bytes -- exactly the shape harness-forge's composition lever produces.

Measure budget-matched, paired, with valid WebP seeds. If ours >= dev, composition crosses
parity on the codec archetype and the OGHarn claim becomes defensible on that class; if not,
it confirms below-parity with data.
