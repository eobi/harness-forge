# Live Windows harness generation — 2026-09-06

Host: Windows 11 ARM64 (VM 192.168.1.236), native CPython 3.12.10.
Generator: harness-forge, zero runtime deps (pure stdlib) — ran unmodified on Windows.
Phase measured: PROPOSE -> LIFT -> SEAM -> GATE -> EMIT. Static gates only.
NOT build/fuzz-verified here: this VM was reverted since the last session (no cl.exe /
VS Build Tools). The Windows build path itself (cl /GS + _WIN32 temp-file shim) was
verified in the prior session; these specific harnesses were not compiled on this VM.

## Counts (gate-passing, emitted to disk)

| path | what it is | generated | distinct on disk |
|------|-----------|-----------|------------------|
| library test-lift | lift a lib's own unit tests into harnesses | 119 | 107 |
| application-entry (lib headers) | app-lift on jansson/cjson public headers | 17 | 17 |
| GUI file-loader (stb) | app-lift on stb_image/truetype/vorbis decoders | 16 | 16 |
| **total** | | **152** | **140** |

library test-lift by lib: jansson 52, cjson 50, expat 15, libyaml 2.
application-entry by lib: jansson 10, cjson 7 (expat/libyaml 0 — their parse
signatures don't match the 2-arg buffer / lone-char* classifier heuristic).
GUI by loader: stb_image 7, stb_truetype 5, stb_vorbis 3, stb_image_write 1.

## Honest framing

- The engine has NO separate GUI channel by design. A GUI app's untrusted input enters
  through File->Open / drag-drop, which calls a decode/parse function — the SAME
  file/buffer entry a CLI tool uses. Our "GUI" number is the decode-entry harnesses for
  the libraries GUI apps load (stb_image = image viewers, stb_truetype = any GUI text,
  stb_vorbis = media players).
- We do NOT synthesize widget/menu events. That is GUIFUZZ++'s axis; we do not claim it.
- Some app-entry / GUI candidates are shallow helpers (stbi_zlib_decode_*,
  stbtt_CompareUTF8toUTF16) rather than the ideal deep-parse seam — the (buffer,size)
  classifier is permissive. The 119 library test-lift harnesses are the higher-quality,
  deep-subsystem-ranked set.
- Emitted harnesses are portable libFuzzer harnesses carrying #ifdef _WIN32 / windows.h.

## Next to make these build+fuzz-verified on Windows
Install VS Build Tools (VC.Tools.x86.x64) on the VM, build with cl /fsanitize or /GS,
run each harness for a short budget, and report build-rate + any crashes. Generation is
proven live; build/fuzz validation is the separate step gated on the toolchain.
