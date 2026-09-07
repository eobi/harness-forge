# Popular Windows apps → generator → readings → NemesisForge (live)

Date: 2026-09-07. All numbers live-measured, not asserted.

## Scope note (honest)
The Harness Forge generator reads SOURCE/HEADERS. A closed Windows app (.exe with no source)
has nothing for app-lift to parse. The path that fulfils "popular app → generator → readings →
NemesisForge" is: the OPEN-SOURCE parsing engine that actually runs inside a popular app. Fully
closed apps need binary-level instrumentation (WinAFL/TinyInst) — the closed-binary track, not
the generator.

## Anchor app installed
- 7-Zip (winget 7zip.7zip) — installed on the Win11 ARM64 VM. Hundreds of millions of installs.
  The Deflate decoder inside it (and inside Windows Explorer ZIP folders, Git for Windows, every
  browser, every PNG) is zlib `inflate`.

## Generator generalization shipped (the reason zlib/zstd now work)
app-lift previously REFUSED zlib: uncompress(dest,*destLen,const src,srcLen) has input as args
3–4 (not leading) plus a writable output buffer. Fixes (commits 732a25b, ca1e686):
  - _looks_len: length recognised by name (camelCase sourceLen) or library size typedef (uLong),
    not only size_t/int.
  - _out_scratch: the decompressor idiom f(out,*outlen,const in,inlen) — zlib/zstd/lz4/brotli —
    gets a real 64 KiB scratch buffer + true capacity, so the DECODER runs (no 1-byte overflow).
  - void* outputs handled (ZSTD_decompress), opaque handles (ZSTD_DCtx*) refused, decoder ranked
    above compress/loadDictionary/setParameter.
  - +5 regression tests; 521 pass.

## Live readings

### Windows native (hf_winfuzz, trace-pc + trace-cmp, no libFuzzer runtime)
| harness (auto-generated) | edges | exec/s | crashes |
|---|---|---|---|
| zlib `uncompress` (Deflate — the 7-Zip/Explorer/Git/browser decoder) | 1,444 | 225K | 0 |
| stb_image composed GUI (7 decoders folded) | 1,850 | — | 0 |
| cjson CLI (flag-fuzzing) | 1,318 | 178K | 0 |

GUI baseline was 743 edges → composition + auto-seeds + auto-dict = 2.49× deeper.

### NemesisForge (macOS, libFuzzer + 8 oracles) — discovery pass on the SAME generated harnesses
| target | sources built | corpus grown | status | findings |
|---|---|---|---|---|
| zlib `uncompress` | 10 | 36 → 336 | done | 0 (clean — decade of OSS-Fuzz) |
| zstd `ZSTD_decompress` | 12 | 10 → 760 | done | 0 (clean — OSS-Fuzz-hardened) |

0 findings on these two is the HONEST result: both are among the most-fuzzed C code on earth.
Corpus growth proves the campaigns really ran (coverage feedback), and NemesisForge distinguishes
"0 findings / ran" from "no campaign / build failed" — both here built and ran.

## Known next gap (honest)
lz4's decoders use a fully-scattered layout LZ4_decompress_safe(src, dst, srcSize, dstCapacity):
neither the (buffer,len) input pair nor the (out,capacity) pair is adjacent, so app-lift does not
yet recognise it. Needs name-stem pairing (src→srcSize, dst→dstCapacity). Deferred; noted.
