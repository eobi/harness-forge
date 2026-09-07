"""Seeds for a generated harness — so the artifact NemesisForge receives is READY TO FUZZ.

A harness's real-world coverage is dominated by the corpus it starts from: an unseeded
campaign spends its budget being rejected at the first signature check (stb_image reaches ~146
edges cold and ~915 with valid seeds + a dictionary). The generator already emits the harness,
the build and an auto-mined dictionary; this emits the missing half -- SEEDS -- two ways:

  * MINE the target's own repository for data files (test inputs, fixtures, sample documents),
    which are the best possible seeds when they exist.
  * SYNTHESISE a minimal valid file for a recognised format, so a target with no corpus still
    starts INSIDE the decoder rather than at the header check.

Stdlib only, like the rest of the engine: the synthesised seeds are hardcoded byte sequences,
not generated with an image library that would be one more thing to install.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

_SEED_DIRS = ("testdata", "test-data", "test_data", "data_files", "fuzz", "corpus",
              "seeds", "fixtures", "regression", "samples", "sample", "cases",
              "pngsuite", "tests", "test", "examples", "example", "data")

_NOT_DATA = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc", ".s", ".asm",
    ".py", ".sh", ".bash", ".pl", ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".m", ".mm", ".cs", ".js", ".ts", ".lua", ".php",
    ".am", ".ac", ".m4", ".cmake", ".mk", ".make", ".ninja", ".gradle", ".bazel",
    ".md", ".rst", ".adoc", ".1", ".3", ".man", ".po", ".pot",
    ".o", ".a", ".so", ".dylib", ".dll", ".lib", ".exe", ".pyc", ".class",
    ".gitignore", ".gitattributes", ".gitmodules", ".yml", ".yaml", ".toml", ".cfg",
    ".in", ".sym", ".def", ".map", ".pc", ".spec", ".txt",
}
_NOT_DATA_NAMES = {"LICENSE", "COPYING", "AUTHORS", "NEWS", "ChangeLog", "Makefile",
                   "CMakeLists.txt", "configure", "config.guess", "config.sub", "README"}


def _rank(p: Path, root: Path) -> int:
    parts = [x.lower() for x in p.relative_to(root).parts[:-1]]
    for i, name in enumerate(_SEED_DIRS):
        if any(name in part for part in parts):
            return i
    return len(_SEED_DIRS)


def mine(roots, *, formats: tuple = (), max_files: int = 48,
         max_bytes: int = 1 << 20, min_bytes: int = 1) -> list:
    """Data files from the target's repositories, best first. `formats` are preferred exts."""
    seen: set = set()
    cands: list = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.is_symlink() or ".git" in p.parts:
                continue
            if p.suffix.lower() in _NOT_DATA or p.name in _NOT_DATA_NAMES:
                continue
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            if sz < min_bytes or sz > max_bytes:
                continue
            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
            if h in seen:
                continue
            seen.add(h)
            fmt = 0 if (formats and p.suffix.lower() in formats) else 1
            cands.append((fmt, _rank(p, root), sz, p))
    cands.sort(key=lambda t: (t[0], t[1], t[2]))
    return [c[3] for c in cands[:max_files]]


# Minimal VALID files (hardcoded bytes). Where a fully-valid minimal file is impractical to
# hardcode (jpeg, webp), a signature prefix still starts the fuzzer past the magic check.
_PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6200010000050001"
    "0d0a2db40000000049454e44ae426082")
_GIF_1x1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
            b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")
_BMP_2x2 = bytes.fromhex(
    "424d460000000000000036000000280000000200000002000000010018000000"
    "0000100000000000000000000000000000000000ff000000ff0000ff000000ff00")

SYNTH: dict = {
    "png":  {"a.png": _PNG_1x1},
    "gif":  {"a.gif": _GIF_1x1},
    "bmp":  {"a.bmp": _BMP_2x2},
    "jpeg": {"a.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01"
                      b"\x00\x01\x00\x00\xff\xd9"},
    "webp": {"a.webp": b"RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00"
                       b"\x00\x00\x00\x88\x88\x08"},
    "tiff": {"a.tiff": b"II\x2a\x00\x08\x00\x00\x00"},
    "qoi":  {"a.qoi": b"qoif\x00\x00\x00\x01\x00\x00\x00\x01\x04\x00"
                      b"\xff\x00\x00\x00\xff" + b"\x00" * 7 + b"\x01"},
    "json": {"a.json": b'{"a":[1,2,{"b":null,"c":true}],"d":"x","e":1.5e3}',
             "b.json": b"[[[[1]]]]"},
    "xml":  {"a.xml": b'<?xml version="1.0"?><r a="1"><b>t</b><c/></r>'},
    "yaml": {"a.yaml": b"a: 1\nb:\n  - x\n  - y\nc: {k: v}\n"},
    "svg":  {"a.svg": b'<svg width="4" height="4"><rect x="1" y="1" width="2" '
                      b'height="2" fill="red"/></svg>'},
    "toml": {"a.toml": b'[a]\nb = 1\nc = "x"\nd = [1, 2, 3]\n'},
}

# Keyword -> format(s). Matched against the target name, header names, and API symbols.
_FMT_HINTS = {
    "png": ("png",), "jpeg": ("jpeg", "jpg"), "jpg": ("jpeg",), "gif": ("gif",),
    "webp": ("webp",), "bmp": ("bmp",), "tiff": ("tiff", "tif"), "qoi": ("qoi",),
    "json": ("json",), "yaml": ("yaml", "yml"), "xml": ("xml", "expat"),
    "svg": ("svg",), "toml": ("toml",),
    "stbi": ("png", "jpeg", "gif", "bmp"), "image": ("png", "jpeg", "gif", "bmp"),
    "cjson": ("json",), "jansson": ("json",),
}


def detect_formats(name: str = "", headers=(), symbols=()) -> list:
    """Formats a harness likely consumes, from its name, header names and API symbols."""
    hay = " ".join([name] + [Path(h).name for h in headers] + list(symbols)).lower()
    fmts: list = []
    for key, out in _FMT_HINTS.items():
        if key in hay:
            for f in out:
                if f not in fmts:
                    fmts.append(f)
    return fmts


def provision(dest, roots=(), *, name: str = "", headers=(), symbols=(),
              max_mined: int = 32) -> dict:
    """Write a ready-to-fuzz seed corpus for a harness: mined data files + synthesised seeds."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    fmts = detect_formats(name, headers, symbols)
    exts = tuple("." + f for f in fmts)
    n_mined = 0
    for p in mine(roots, formats=exts, max_files=max_mined):
        try:
            shutil.copyfile(p, dest / f"mined_{n_mined:03d}{p.suffix.lower()[:8]}")
            n_mined += 1
        except OSError:
            continue
    n_synth = 0
    for f in (fmts or ["json", "xml", "png"]):        # a small generic fallback if unknown
        for fname, data in SYNTH.get(f, {}).items():
            try:
                (dest / f"synth_{fname}").write_bytes(data)
                n_synth += 1
            except OSError:
                continue
    return {"dir": str(dest), "mined": n_mined, "synthesised": n_synth,
            "formats": fmts, "total": n_mined + n_synth}
