# Auto seed provisioning — the generator ships a ready-to-fuzz corpus (2026-09-07)

A harness is only as deep as the corpus it starts from: an unseeded campaign spends its budget
being rejected at the first signature check. The generator already emitted the harness, the
build and an auto-mined dictionary; it now also emits SEEDS (hforge/seeds.py), two ways:

  * MINE the target's own repository for data files (test inputs, fixtures, sample docs),
    preferring the harness's format and excluding source.
  * SYNTHESISE a minimal valid file per recognised format (hardcoded bytes -- stdlib only, no
    image library), so a target with no corpus still starts INSIDE the decoder. Format is
    detected from the target name, header names and API symbols (stb -> png/jpeg/gif/bmp,
    WebPDecode -> webp, cJSON_Parse -> json).

`hforge app-lift [--compose] --out h.c` now writes h.c + h.driver.c + h.dict + h.seeds/.

## Measured (stb_image single-entry, INITED coverage before any fuzzing)
| starting corpus | edges at INITED |
|-----------------|----------------:|
| one garbage seed | 38 |
| **auto-provisioned (20 mined + 4 synth)** | **542** |

**14x more coverage the instant the campaign starts**, generated with no human. This is the
largest coverage lever (structure) made automatic and applied to EVERY generated harness, not
just codecs -- the artifact NemesisForge receives is now complete and deep.
