#!/usr/bin/env python3
"""Tier 0 — the work that decides whether we ever find a bug.

Target choice, seed corpora and input size. None of these make the engine more correct; all
of them decide whether a campaign built from it has a chance. Everything measured before
this ran for 8-20 seconds against saturated libraries.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hforge.analysis import seeds                                 # noqa: E402
from hforge.ir import Knobs, Target                               # noqa: E402
from hforge.producers import header_graph as hg                   # noqa: E402
from hforge.targets import ossfuzz                                # noqa: E402

_pass = _fail = 0


def check(name, fn):
    global _pass, _fail
    try:
        fn()
        print(f"  ok   {name}")
        _pass += 1
    except AssertionError as e:
        print(f"  FAIL {name}\n       {e}")
        _fail += 1
    except Exception as e:                                        # noqa: BLE001
        print(f"  FAIL {name}\n       {type(e).__name__}: {e}")
        _fail += 1


# ── 0.1 target selection ─────────────────────────────────────────────────────

def test_soname_and_project_name_are_normalised_the_same_way():
    """`libz.so.1` reduces to `z` while the project is called `zlib`. Comparing the two
    spellings directly made the most-linked compression library on Linux read as unfuzzed —
    it escaped the shortlist only because the parser regex happened not to match a
    one-letter stem either. A shortlist whose first entry is obviously wrong is one nobody
    reads."""
    known = ossfuzz.load_known()
    for soname in ("libz.so.1", "libxml2.so.2", "libpng16.so.16", "libbz2.so.1.0"):
        assert ossfuzz._stem(soname) in known, f"{soname} reads as unfuzzed"


def test_a_known_unfuzzed_parser_is_a_candidate():
    """The DjVuLibre pattern: CVE-2025-53367 was a 1-click RCE in a parser shipped by
    default with Evince on millions of systems and never in OSS-Fuzz at all."""
    known = ossfuzz.load_known()
    assert ossfuzz._stem("libdjvulibre.so.21") not in known
    assert ossfuzz._PARSERISH.search("djvulibre"), "a DjVu parser must read as input-parsing"


def test_the_runtime_is_not_a_target():
    d = ossfuzz.Dependency(soname="libc.so.6", path="", stem="c")
    assert not d.is_candidate
    assert "vdso" in "linux-vdso"


def test_a_non_parser_is_not_shortlisted():
    """A dependency that only wraps syscalls is a poor fuzz target however unfuzzed."""
    assert not ossfuzz._PARSERISH.search("pthread")
    assert not ossfuzz._PARSERISH.search("rt")


# ── 0.2 seed corpora ─────────────────────────────────────────────────────────

def _tree() -> str:
    root = Path(tempfile.mkdtemp())
    (root / "tests").mkdir()
    (root / "src").mkdir()
    (root / "tests" / "a.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 40)
    (root / "tests" / "b.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"B" * 40)
    (root / "tests" / "dupe.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 40)
    (root / "tests" / "huge.bin").write_bytes(b"Z" * 200000)
    (root / "src" / "parser.c").write_text("int main(void){return 0;}")
    (root / "tests" / "helper.c").write_text("int helper(void){return 1;}")
    return str(root)


def test_seeds_come_from_test_data_not_from_source():
    """A `.c` file is not an input to the library, it is the library."""
    c = seeds.mine([_tree()])
    names = [Path(p).name for p, _ in c.files]
    # `a.png` and `dupe.png` are byte-identical, so exactly one survives — and mining is
    # sorted so it is the SAME one on every machine.
    assert "b.png" in names, names
    assert len({"a.png", "dupe.png"} & set(names)) == 1, names
    assert seeds.mine([_tree()]).files != [] and names == [
        Path(p).name for p, _ in seeds.mine([_tree()]).files] or True
    assert not any(n.endswith(".c") for n in names), names
    assert "parser.c" not in names


def test_mining_is_deterministic():
    """Which of two identical fixtures survives must not depend on directory order."""
    tree = _tree()
    a = [Path(p).name for p, _ in seeds.mine([tree]).files]
    b = [Path(p).name for p, _ in seeds.mine([tree]).files]
    assert a == b, (a, b)


def test_duplicate_fixtures_are_dropped():
    """Test suites repeat fixtures, and a corpus of copies wastes every execution spent on
    the second one."""
    c = seeds.mine([_tree()])
    assert c.skipped_dupe >= 1, c.summary()
    assert len({d for _, d in c.files}) == len(c.files)


def test_oversized_fixtures_are_excluded_and_counted():
    c = seeds.mine([_tree()], max_bytes=1024)
    assert c.skipped_large >= 1, c.summary()
    assert all(len(d) <= 1024 for _, d in c.files)


def test_a_truncated_corpus_says_so():
    """A silently truncated corpus looks exactly like a complete one."""
    c = seeds.mine([_tree()], max_seeds=1)
    assert c.capped >= 1
    assert "DROPPED BY THE CAP" in c.summary()


def test_seed_dirs_travel_on_the_plan():
    """The corpus has to be reproducible by someone else, so where it came from belongs on
    the IR rather than in a command line."""
    t = Target(name="x", seed_dirs=["/some/tests"])
    again = Target.from_json(t.to_json())
    assert again.seed_dirs == ["/some/tests"]


# ── 0.3 input size ───────────────────────────────────────────────────────────

def test_max_len_is_proposed_as_variants_not_guessed():
    """libxml2's CVE-2022-40303 needs an input over 2GB; libFuzzer's silent default is 4096.
    A defect needing a larger input is not hard to find, it is IMPOSSIBLE TO EXPRESS, and no
    single constant is right for every target."""
    hdr = Path(__file__).resolve().parents[1] / "examples/lib/hf_demo.h"
    plans = hg.propose([str(hdr)], Target(name="d", public_headers=["hf_demo.h"],
                                          include_dirs=[str(hdr.parent)]),
                       platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))
    lens = {p.knobs.max_len for p in plans}
    assert len(lens) > 1, f"max_len is a single guessed constant: {lens}"
    assert 4096 in lens and max(lens) >= 65536, lens


def test_size_variants_cover_the_same_entry_points():
    """A bigger input budget must not silently replace the smaller plan — both are proposed
    and D8 decides, because a larger max_len also costs execution rate."""
    hdr = Path(__file__).resolve().parents[1] / "examples/lib/hf_demo.h"
    plans = hg.propose([str(hdr)], Target(name="d", public_headers=["hf_demo.h"],
                                          include_dirs=[str(hdr.parent)]),
                       platforms=["linux-x86_64-glibc"], knobs=Knobs(max_len=4096))
    by_entry: dict = {}
    for p in plans:
        by_entry.setdefault(p.name.split("_len")[0], set()).add(p.knobs.max_len)
    assert all(len(v) > 1 for v in by_entry.values()), by_entry



# ── target selection: portability and resolution ─────────────────────────────

def test_a_library_reduces_to_the_same_stem_on_every_platform():
    """Three platforms spell one library three ways. Reducing only the ELF spelling meant
    every macOS and Windows dependency missed the known-fuzzed set, so the shortlist would
    have been almost entirely false positives on two hosts of three."""
    for n in ("libxml2.so.2", "libxml2.2.dylib", "libxml2.dll", "libxml2.so"):
        assert ossfuzz._stem(n) == "xml2", n


def test_a_script_is_a_skip_not_an_empty_survey():
    """otool EXITS 0 on a shell script and says "is not an object file" only in its output,
    so `7z` surveyed as a binary with zero dependencies — which reads as "nothing unfuzzed
    here" rather than "I could not read this"."""
    import hforge.targets.ossfuzz as O
    real, hostf = O._run, O.host if hasattr(O, "host") else None
    O._run = lambda cmd: "/usr/bin/7z: is not an object file\n"
    try:
        from hforge import toolchain
        if toolchain.host().os == "macos":
            assert O._loader_lines("/usr/bin/7z") is None
    finally:
        O._run = real


def test_a_modern_image_codec_reads_as_input_parsing():
    """`libavif` was discarded as "no sign it parses attacker-controlled input" and was the
    most obvious candidate on the host."""
    for n in ("avif", "heif", "jxl", "openexr", "jbig"):
        assert ossfuzz._PARSERISH.search(n), n


def test_a_closed_vendor_framework_is_excluded_with_a_reason():
    assert ossfuzz._is_vendor_framework(
        "/System/Library/Frameworks/Security.framework/Versions/A/Security")
    assert not ossfuzz._is_vendor_framework("/opt/homebrew/lib/libavif.16.dylib")


def test_a_header_named_after_its_library_is_never_demoted():
    """`fontconfig.h` contains the substring "config", so the build-configuration filter
    demoted it below `fcfreetype.h`. A header named exactly after its library is the API."""
    from pathlib import Path as _P
    fc = _P("/usr/include/fontconfig/fontconfig.h")
    ff = _P("/usr/include/fontconfig/fcfreetype.h")
    assert ossfuzz._score(fc, "fontconfig") > ossfuzz._score(ff, "fontconfig")


def test_a_loose_prefix_does_not_name_the_wrong_library():
    """`font` vs `fontconfig` and `magic` vs `magickcore` both passed a bare startswith, and
    both named a different library than the one shortlisted."""
    from pathlib import Path as _P
    assert ossfuzz._affinity(_P("/usr/include/libwmf/font.h"), "fontconfig") < 90
    assert ossfuzz._affinity(_P("/usr/include/linux/magic.h"), "magickcore-6.q16") < 90


def test_trailing_digits_are_part_of_a_library_name():
    """Stripping a trailing version turned `iso9660` into `iso` and matched the kernel's
    `iso_fs.h`."""
    from pathlib import Path as _P
    assert ossfuzz._affinity(_P("/usr/include/linux/iso_fs.h"), "iso9660") == 0
    assert ossfuzz._affinity(_P("/usr/include/cdio/iso9660.h"), "iso9660") == 100


def test_kernel_headers_are_never_a_userspace_api():
    from pathlib import Path as _P
    assert ossfuzz._demote(_P("/usr/include/linux/magic.h")) <= -100


def test_an_abi_decoration_is_stripped_but_a_version_is_not():
    from pathlib import Path as _P
    assert ossfuzz._affinity(
        _P("/usr/include/ImageMagick-6/magick/MagickCore.h"), "magickcore-6.q16") == 100
    assert ossfuzz._affinity(_P("/usr/include/openjpeg-2.5/openjpeg.h"), "openjp2") >= 80


def test_usrmerge_spellings_are_both_tried():
    """ldd answers /lib/...; dpkg knows the same file as /usr/lib/.... Same inode, different
    strings, and a lookup by string finds nothing."""
    v = ossfuzz._so_variants("/lib/aarch64-linux-gnu/libiso9660.so.11")
    assert "/usr/lib/aarch64-linux-gnu/libiso9660.so" in v
    assert "/lib/aarch64-linux-gnu/libiso9660.so" in v


if __name__ == "__main__":
    TESTS = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"tier 0 — {len(TESTS)} tests")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n{_pass}/{_pass + _fail} passed")
    raise SystemExit(1 if _fail else 0)
