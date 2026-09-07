# Under-fuzzed parser hunt (option b) — 2026-09-07

Goal: a plausible finding in a less-hardened parser that ships inside popular software, via the
generator → NemesisForge loop. All results live-measured.

## Targets hunted (generator produced the harness; NemesisForge/libFuzzer drove it, ASan)
| lib | ships in | chosen entry | budget | corpus grown | result |
|---|---|---|---|---|---|
| qoi | image tools | qoi_decode | 240s | 10 | clean |
| dr_wav | audio apps/games | drwav_open_memory_..._f32 | 240s | (ran) | clean |
| dr_flac | audio apps | drflac_..._f32 | 240s | 150 | clean |
| dr_mp3 | audio apps | drmp3_..._f32 | 240s | — | clean |
| ufbx | Blender/Unity/Unreal pipelines | ufbx_load_memory | 300s | 1510 | clean |
| stb_vorbis | countless games | stb_vorbis_decode_memory | 300s | 86 | clean |
| cgltf | 3D engines/tools | cgltf_parse | 240s | 3102 | clean |
| toml (tomlc99) | config-driven apps | toml_parse | 240s | — | clean |
| tinyexr | VFX/graphics tooling | LoadEXRFromMemory | 300s+seeded | 460 (cov 538→890 seeded) | clean |

tinyexr showed two libFuzzer OOMs — both cumulative RSS (the 2.4 MB seed + large mutations); the
written artifacts were a 0-byte and a 1075-byte unit that DO NOT reproduce a single-input OOM in
a fresh process (run in 1 ms, exit 0). Not a bug. Verified with -malloc_limit_mb.

## Honest conclusion
The popular open-source single-header parsers are now well swept by OSS-Fuzz; cold/short campaigns
find nothing, and corpus growth on the complex ones (cgltf 3102, ufbx 1510) confirms the campaigns
were real, not stalled. The generator→NemesisForge loop built and drove every target.

## What the hunt PERMANENTLY improved in the generator (commit 15d6255)
  * a path/filename pointer is no longer mistaken for a content buffer (ufbx_load_file_len would
    have fuzzed a filesystem path, not the decoder).
  * streaming/incremental/dict variants (pushdata/stream/prefix/base64/from_file) are de-ranked,
    so the clean one-shot *_memory / *_parse decoder is chosen automatically.
  Result: ufbx/cgltf/stb_vorbis now auto-select the right entry with no --only override.

## Higher-EV next options for an actual finding
  1. Genuinely OSS-Fuzz-ABSENT niche libraries (embedded/IoT parsers, vendor SDKs), where the
     low-hanging fruit has not been swept.
  2. Hours-long SEEDED campaigns on the complex targets (real .fbx/.ogg/.exr corpora), which is
     how bugs in these are actually found today.
  3. The closed-binary Windows track (WinAFL/TinyInst) on a real installed .exe.
