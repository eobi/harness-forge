# #1+#2: auto-composed codec harness, generalized (2026-09-07)

harness-forge now AUTO-GENERATES the composed codec harness (`hforge app-lift --compose`) that
was hand-written for the 1.29x result. It discovers a header's decode FAMILY and folds every
safe (buffer,size) decoder onto one input, freeing returned buffers via a discovered void*
deallocator. Safety filters exclude encoders, the *Into caller-buffer family, opaque-handle
consumers, private/Internal symbols, and auxiliary codecs (zlib/inflate) that are a different
subsystem than the format's own decode.

## Measured, auto-generated (median cov, budget-matched)
| codec | single-entry | composed (auto) | gain | vs dev |
|-------|-------------:|----------------:|-----:|-------|
| libwebp | 1545 | 1694 | +10% | 0.92x the simple dev harness (1.29x with options -- see #3) |
| stb_image | 871 | 931 | +7% | (no standalone dev harness; lever confirmed) |

Composition is a positive coverage lever on BOTH codecs; the magnitude tracks how DISTINCT the
decode subsystems are (webp's RGBA/YUV/options are more distinct than stb's overlapping load
variants). The AUTO-generated harness matches the hand-written composition -- the engine
produces the win now, not a person.
