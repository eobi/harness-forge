# #3: auto option-fuzzing — RESULT (2026-09-07)

harness-forge now enumerates a codec config struct's POINTER-FREE scalar fields (a
self-contained struct parser in app_lift) and sets them from input bytes before the advanced
decode call -- automatically fuzzing crop/scale/flip/dither, the options a developer's
option-fuzzer reaches. Pointer-bearing sub-structs (WebPDecBuffer output) are skipped, so
setting fields can never corrupt a buffer pointer; padding arrays are skipped, not treated as
unsafe.

## Measured (libwebp v1.2.4, 3x60s median, same seeds)
| harness | median cov | vs simple dev |
|---------|-----------:|--------------:|
| ours single | 1545 | 0.84x |
| ours composed (no options) | 1694 | 0.92x |
| **ours composed + AUTO options** | **1905** | **1.04x** |
| dev simple_api | 1837 | 1.00x |
| hand-written composed + options | 2366 | 1.29x |
| dev advanced_api | 2599 | 1.41x |

## Findings (honest)
1. Auto option-fuzzing takes the AUTO-generated harness from 0.92x to **1.04x -- it now BEATS
   the simple developer harness**, generated end to end with no human.
2. It does NOT reach the hand-written 1.29x or OGHarn's 1.14x bar. The gap is option-VALUE
   quality: the hand harness set crop/scale dimensions proportional to the image (w/2, h/2),
   which are valid and exercise the resize code; the general generator sets each field from
   one input byte (0..255) -- small values are more often valid than a full 32-bit word (which
   the decoder rejects up front, measured WORSE), but they are not image-aware.
3. Making the option values image-dimension-aware would need target knowledge the generator
   does not have; 1.04x is the honest fully-general result. The lever is real and now
   automatic: single 0.84x -> composed 0.92x -> +auto-options 1.04x.
