# Deep Windows generation + NemesisForge fuzz — 2026-09-06

Generator ran natively on Windows 11 ARM64 (VM 192.168.1.236, CPython 3.12.10).
Build + ASan fuzz ran on macOS arm64 (clang libFuzzer; ASan does not work under x64
emulation on ARM64 Windows, so the campaign is Mac-native — the harness is identical).

## 1. Generator limitations fixed (hforge)

Three real defects, all found by trying to harness real GUI file-loaders:

1. `classify` missed typedef / trailing-const byte pointers (`stbi_uc const *buffer`,
   `yaml_char_t *`). Only literal `const unsigned char *` matched, so the actual image/
   font/audio loaders were invisible; only shallow 2-arg helpers were found. Fixed:
   `_looks_buffer` accepts any single-level const/content-named pointer with an adjacent
   size, and `_buffer_pair` finds the (buf,len) pair anywhere in the signature.
2. The emitter passed only `(data,size)` and ignored every other declared argument, so any
   real loader `f(buf,len,*x,*y,*comp,req)` emitted a call that WOULD NOT COMPILE. The
   "passing" helpers only passed static gates; they were never built. Fixed: `_buffer_plan`
   fills every argument — (buf,len) pair carries the bytes, out-pointers become zeroed
   locals passed by address, scalars default to 0 — via new `AppEntry.call_args/call_locals`.
3. On Windows the preprocessor defines `_WIN32`, exposing OS APIs forward-declared in the
   header (`MultiByteToWideChar`) and private internals (`stbi__hdr_to_ldr`). Fixed: reject
   `__`-containing names (C reserves them for the implementation) and a Win32 import denylist.

484 tests pass; 115 app/lift/emit/ir tests pass; backward compatible (empty call_args =
legacy 2-arg call, byte-for-byte).

## 2. Live Windows generation (deep, after fix)

| path | before fix | after fix |
|------|-----------|-----------|
| CLI application-entry (lib headers) | 17 | 33 |
| GUI file-loaders (stb image/font/audio) | 16 | 73 |

stb_image discovery 7 -> 13 (Mac) / 14 (Windows: +stbi_convert_wchar_to_utf8, a genuine
Windows-only target path). Windows no longer over-counts OS/internal symbols.

## 3. Build+smoke yield (gate-passing is not valid-fuzzable)

Generation is broad; BUILD + SMOKE is the filter that keeps the runnable set:

- stb_image: 13 harnesses -> 11 CLEAN, 2 HANG/OOM (zlib helpers), 0 build-fail.
  All 7 real image loaders (`stbi_*_from_memory`) CLEAN.
- stb_vorbis: 8 harnesses -> 3 CLEAN (the memory decoders a player uses), 5 build-fail
  (handle-consumers correctly rejected — they need an opened stb_vorbis*).

The pipeline self-corrects: emit broadly, the compiler + smoke drop what cannot run,
leaving the deep file-decode entry points.

## 4. NemesisForge deep fuzz (build + ASan campaign)

Both fed to `forge lab` (builds the harness with library sources, ASan libFuzzer, triage):

| target | kind | edges (naive) | edges (seeds+dict) | execs | crashes |
|--------|------|---------------|--------------------|-------|---------|
| stb_image `stbi_load_from_memory` | GUI file-loader (image decode) | 146 | **915** | 35k | 0 |
| jansson `json_loads`+copy+equal | CLI parser (JSON) | 432 | **523** (saturated) | 42.5M | 0 |

0 findings on both: stb_image and jansson are OSS-Fuzz-hardened, so a clean deep ASan run is
the correct, expected result. Coverage climbs 6.3x on the GUI target once valid seeds + a
format dictionary give the fuzzer structure — the harness reaches the decoders, it was the
seeding that was shallow, not the harness.

## 5. Honest competitive position

- LEAD (no named competitor matches the combination): fully-autonomous DEEP harness
  generation for BOTH CLI parsers and GUI file-loaders, cross-platform (Mac + Windows
  native), with build+smoke self-filtering. WinAFL/Jackalope are closed-binary; OGHarn/
  QuartetFuzz are library-API harness gen; GUIFUZZ++ drives widgets. None auto-generate
  deep, building GUI-loader + CLI harnesses from headers on Windows.
- NOT ahead: raw coverage. jansson 523 edges < developer 663 < OGHarn's +14% bar. We are at
  parity-to-below on coverage against a tuned developer harness. Stated plainly.
- We do NOT do GUIFUZZ++'s widget-event axis; we hit the file-decode seam a GUI app loads
  through. Different axis — we cannot claim "more GUI bugs".
- 0 bugs here because targets are hardened. NemesisForge's findings edge is on UNFUZZED
  targets (cf. the CWPack heap-OOB it found). To beat competitors on FINDINGS, point this
  pipeline at obscure/unfuzzed GUI-loader and CLI libraries, not stb_image/jansson.
