# Codec-composition test — RESULT (libwebp v1.2.4, 2026-09-07)

The hypothesis: on a media codec, does folding decode subsystems (the composition lever) let
an AUTO-generated harness beat the developer harness? Measured, 3x60s each, median edge
coverage, same valid WebP seed corpus, ASan+libFuzzer, all built against libwebp v1.2.4.

| harness | what it does | median cov | ratio to simple |
|---------|--------------|-----------:|----------------:|
| dev simple_api_fuzzer | maintainer, hash picks ONE decode path/input | 1837 | 1.00x |
| ours: single | WebPDecodeRGBA only | 1545 | 0.84x |
| ours: composed | + BGRA + ARGB + YUV + incremental | 1775 | 0.97x |
| ours: composed+options | + advanced decode with crop/scale/flip/colorspace | **2366** | **1.29x** |
| dev advanced_api_fuzzer | maintainer, fuzzes decode options thoroughly | 2599 | 1.41x |

## Findings (honest, both directions)
1. **Composition is a real, powerful coverage lever on codecs.** Folding decode subsystems
   moved an auto-generated harness 0.84x -> 0.97x -> 1.29x of the SIMPLE developer harness.
2. **It crosses parity AND OGHarn's 1.14x bar against a typical (simple) developer harness**
   -- 1.29x. This is the FIRST measured result of our approach EXCEEDING a developer harness.
3. **But it does NOT beat the maintainer's MOST-comprehensive harness.** libwebp's
   advanced_api_fuzzer, which fuzzes the same decode options more thoroughly, reaches 2599;
   our best composed harness is 2366 = 0.91x of it. A maximally-tuned developer harness still
   leads.

## Honest one-line
On the codec archetype, composition lets an auto-generated harness EXCEED a typical developer
decode fuzzer (1.29x, past OGHarn's bar) by folding the option/incremental subsystems that
harness omits -- but a maximally-tuned developer harness that already fuzzes those options
still leads (we reach 0.91x of it). Composition closes the coverage gap from ~0.87x (JSON,
below parity) to parity-and-beyond vs a simple harness on codecs; superiority over the best
hand-tuned harness is not claimed.
