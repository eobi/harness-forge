# Deeper: native-Windows coverage-guided fuzzing + automatic structure — 2026-09-06

Two depth axes added and committed, then a genuinely Windows-native campaign run.

## Automatic structure (the largest depth lever, now generator-side)

The 6.2x coverage gap on stb_image (146 -> 915 edges) was STRUCTURE, not the harness.
Both halves are now automatic:

- **dict_mine** (hforge/producers/dict_mine.py): mines a libFuzzer dictionary from the
  target's OWN source -- string literals, char-packed tags ('I','H','D','R' -> IHDR), and
  byte-array signatures ({137,80,78,71,...} -> the PNG magic). `app-lift --out` writes
  <out>.dict beside the harness. Auto-mined dict + seeds reaches 911 edges, matching a
  hand-written one (915).
- **deepest-entry ranking** (app_lift): a full decoder (several out-params, returns a
  decoded buffer) now ranks ahead of a shallow query (stbi_info/stbi_is_hdr). The DEFAULT
  entry is stbi_load_*, not stbi_info.

Dict-only with an EMPTY corpus reaches 194 edges -- valid seeds are still the larger half,
because a valid PNG needs correct CRC/length/zlib the fuzzer will not assemble from tokens
alone. Deep = auto-dict + seeds (mined from the library's test corpus where it ships one).

## Native Windows fuzzing (no libFuzzer runtime required)

Windows-on-ARM ships clang 22 but NO clang_rt.fuzzer.lib, so a libFuzzer harness cannot link
there -- the reason a Windows-native campaign did not exist. `-fsanitize-coverage=trace-pc`
still instruments, so hforge/emit/resources/hf_winfuzz.c supplies the missing engine: edge
feedback (return address hashed into a bitmap -- no guard sections, which Windows COFF gives
no __start_/__stop_ boundary symbols for), byte + dictionary mutation, corpus-keeps-new-edge,
and SEH to catch the access violation. Same LLVMFuzzerTestOneInput; one harness, every host.

### Live, native on Windows 11 ARM64 (clang 22.1.8, our own engine)

| target | kind | edges primed | edges final | execs | exec/s | crashes |
|--------|------|--------------|-------------|-------|--------|---------|
| stb_image `stbi_load_from_memory` | GUI file-loader | 468 | **743** (600s) | 16.3k | ~130 (slow img units) | 0 |
| jansson parse+copy+equal | CLI parser | 259 | **411** (saturated) | 4.4M | **1.28M** | 0 |

Edge counts use return-address hashing (trace-pc), so they undercount vs libFuzzer's
guard-based counts and are NOT comparable to the Mac numbers (stb 915 / jansson 523) --
different metric, same harness. 0 crashes on both: hardened targets, expected.

Caveat stated plainly: no ASan on Windows ARM64 (its runtime is absent too), so this catches
access-violation-class crashes via SEH, not silent heap-OOB. ASan-rich fuzzing stays on the
Mac path; Windows gets native coverage-guided AV-class fuzzing.

## Competitive read

- Windows-native, source-based, coverage-guided fuzzing of BOTH a GUI file-loader and a CLI
  parser, from an auto-generated harness, is WinAFL/Jackalope's platform without their
  closed-binary constraint -- and neither generates the harness. This is a real, defensible
  Windows capability now, measured live.
- Still not ahead on raw ASan coverage vs a tuned developer harness (Mac path). Honest.
- Bugs need unfuzzed targets; stb_image/jansson are hardened.
