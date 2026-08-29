"""Which of a program's dependencies is nobody fuzzing?

The DjVuLibre pattern, from GitHub Security Lab's analysis of bugs that outlive continuous
fuzzing: **CVE-2025-53367 was a 1-click RCE in a DjVu parser shipped by default with Evince
on millions of systems, and DjVuLibre was never in OSS-Fuzz at all.** Poppler's own harnesses
likewise never instrumented freetype, cairo or libpng.

The gap is structural rather than accidental. A project gets enrolled; its dependencies
process the same attacker-controlled bytes and do not. Finding them is mechanical: list what
a shipped binary loads, subtract what is already being fuzzed, and keep whatever parses
input.

This module is deliberately a *shortlist generator*, not an oracle. It says where to look.
Whether a library is genuinely unfuzzed is checked by a human against the OSS-Fuzz project
list, because being wrong here wastes days rather than minutes.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Projects with an OSS-Fuzz presence, as library/soname stems. Deliberately conservative: a
# name here means "do not bother", so a missing entry costs a wasted look while a wrong entry
# costs a missed target. Refresh with --oss-fuzz-list; this bundled set is a floor, not the
# full ~1200-project registry.
KNOWN_FUZZED = {
    "libxml2", "libxslt", "expat", "sqlite3", "zlib", "bzip2", "libbz2", "lzma", "liblzma",
    "zstd", "libzstd", "brotli", "libpng", "libjpeg", "libjpeg-turbo", "jpeg", "freetype",
    "harfbuzz", "cairo", "pixman", "openssl", "crypto", "ssl", "libssh", "libssh2", "curl",
    "nghttp2", "c-ares", "libarchive", "libtiff", "tiff", "giflib", "gif", "libwebp", "webp",
    "openjpeg", "libpcap", "pcre", "pcre2", "libyaml", "yaml", "json-c", "jansson", "libcbor",
    "protobuf", "re2", "icu", "icuuc", "icui18n", "libsndfile", "flac", "opus", "vorbis",
    "ogg", "ffmpeg", "avcodec", "avformat", "libvpx", "dav1d", "aom", "sqlite", "gnutls",
    "nettle", "gmp", "krb5", "systemd", "dbus", "glib", "gio", "gobject", "pcsclite",
    "libidn2", "unistring", "psl", "nss", "nspr", "elfutils", "elf", "capstone", "binutils",
    "libgcrypt", "gpg-error", "libassuan", "ncurses", "readline", "libevent", "libuv",
    "openldap", "ldap", "lber", "sasl2", "libmagic", "magic", "file", "libtasn1", "p11-kit",
    "libseccomp", "libcap", "attr", "acl", "selinux", "libmount", "blkid", "uuid",
    # SONAME spellings, which are not the project spellings. `libz.so.1` reduces to `z`
    # while the project is called `zlib`, so the most-linked compression library on Linux
    # read as unfuzzed. It escaped the shortlist only because the parser regex happened not
    # to match a one-letter stem either — a near miss, not a safeguard.
    "z", "bz2", "lz4", "lzo2", "z3", "crypt", "gcrypt", "tasn1", "unistring", "idn2",
    "jpeg", "png16", "tiffxx", "xml2", "xslt", "exslt", "yaml-0", "pcre2-8", "pcre2-16",
    "icutu", "icuio", "avutil", "swscale", "swresample", "sndfile", "FLAC", "vorbisfile",
    # Image and document formats added after `libavif` came top of a shortlist on a Homebrew
    # host: it parses attacker bytes, and it has been an OSS-Fuzz project for years. The
    # classifier was right and the floor was short.
    "avif", "libavif", "heif", "libheif", "jxl", "libjxl", "openexr", "imath", "lcms2",
    "lcms", "raw", "libraw", "jbig2dec", "exiv2", "poppler", "mupdf", "tesseract",
    "leptonica", "rsvg", "rsvg-2", "gdk_pixbuf", "gdk_pixbuf-2.0", "spng", "wolfssl",
    "mbedtls", "mbedcrypto", "mbedx509", "unbound", "wireshark", "wiretap", "wsutil",
    "plist", "plist-2.0", "yajl", "cjson", "msgpackc", "flatbuffers", "snappy", "lz4",
}

# Libraries that parse attacker-controllable input. A dependency that only wraps syscalls is
# a poor fuzz target however unfuzzed it is.
_PARSERISH = re.compile(
    r"(xml|json|yaml|toml|ini|cfg|conf|parse|lex|font|ttf|otf|image|img|png|jpe?g|gif|tiff|"
    r"webp|bmp|avif|heif|heic|jxl|jp2|jbig|exr|dng|psd|xcf|ico|icns|tga|pcx|ppm|wmf|emf|"
    r"djvu|pdf|ps|eps|svg|zip|tar|gz|bz2|xz|zstd|lz|ar$|cab|rar|7z|codec|decode|"
    r"encode|audio|video|media|sound|wav|flac|mp3|ogg|opus|vorbis|proto|asn1|ber|der|cert|"
    r"crypt|hash|archive|compress|regex|pcre|markup|html|css|doc|sheet|cue|iso|cdio|magic|"
    r"charset|iconv|unicode|utf|locale|sql|db$|record|packet|net|http|url|uri|mime|mail)",
    re.I)


@dataclass
class Dependency:
    soname: str
    path: str
    stem: str                        # libfoo.so.1.2 -> foo
    fuzzed: bool = False
    parserish: bool = False
    reason: str = ""

    @property
    def is_candidate(self) -> bool:
        return (not self.fuzzed) and self.parserish


@dataclass
class Survey:
    binary: str
    deps: list = field(default_factory=list)

    @property
    def candidates(self) -> list:
        return [d for d in self.deps if d.is_candidate]


def _stem(soname: str) -> str:
    """`libxml2.so.2`, `libxml2.2.dylib` and `libxml2.dll` must all reduce to `xml2`.

    Three platforms spell the same library three ways. Reducing only the ELF spelling meant
    every macOS and Windows dependency compared against the known-fuzzed set as a miss, so
    the shortlist would have been almost entirely false positives on two of three hosts."""
    n = Path(soname).name
    n = re.sub(r"\.so(\.\d+)*$", "", n)          # libfoo.so.1.2
    n = re.sub(r"\.dylib$", "", n)                # libfoo.2.dylib -> libfoo.2
    n = re.sub(r"\.(dll|DLL)$", "", n)
    n = re.sub(r"(\.\d+)+$", "", n)               # trailing version, whichever spelling
    n = re.sub(r"^lib", "", n)
    return n.lower()


def _normalise(names) -> set:
    """Both sides of the comparison go through the same stem rule.

    `libxml2.so.2` reduces to `xml2`, but the bundled list spelled it `libxml2` — so the most
    heavily fuzzed library in the world would have been reported as an unfuzzed candidate.
    A shortlist whose first entry is obviously wrong is a shortlist nobody reads.
    """
    return {_stem(n) for n in names}


def load_known(path: Optional[str] = None) -> set:
    """The set of already-fuzzed project names. A caller-supplied list beats the bundled one,
    which is a floor rather than the full registry."""
    if not path:
        return _normalise(KNOWN_FUZZED)
    text = Path(path).read_text(errors="replace")
    return _normalise(line.strip() for line in text.splitlines()
                      if line.strip() and not line.startswith("#"))


# Names that are the platform runtime rather than a target: no attacker input reaches them
# through this program, and every binary loads them.
_RUNTIME = {
    "c", "m", "dl", "pthread", "rt", "gcc_s", "stdc++", "atomic", "quadmath",
    "system.b", "objc.a", "c++", "c++abi", "c++.1", "objc",           # macOS
    "kernel32", "msvcrt", "ucrtbase", "ntdll", "advapi32", "user32",  # Windows
    "vcruntime140", "api-ms-win-crt-runtime-l1-1-0",
}


def _is_vendor_framework(path: str) -> bool:
    return ("/System/Library/Frameworks/" in path
            or "/System/Library/PrivateFrameworks/" in path
            or path.lower().startswith("c:\\windows\\"))


def _is_runtime(stem: str) -> bool:
    return (stem in _RUNTIME or stem.startswith("ld-linux") or "vdso" in stem
            or stem.startswith("api-ms-win-"))


def _loader_lines(binary: str) -> Optional[list]:
    """What this program loads, on whichever host we are standing on.

    `ldd` exists on Linux and nowhere else. Surveying only through it meant this module —
    the one whose whole job is choosing a target worth fuzzing — silently returned None on
    macOS and Windows and reported "ldd failed", which reads as a broken binary rather than
    an unsupported host.

    Returns a list of (soname, path) or None if no loader tool could answer.
    """
    from ..toolchain import host
    h = host()

    if h.os == "macos":
        # otool -L: one dependency per indented line, absolute path first.
        r = _run(["otool", "-L", binary])
        if r is None:
            return None
        if "is not an object file" in r:
            # otool EXITS 0 on a shell script and says so only in its output. `7z` and
            # `bdftogd` are scripts; they surveyed as binaries with zero dependencies, which
            # the operator reads as "nothing unfuzzed here" rather than "I could not read
            # this". Returning None makes it a reported skip.
            return None
        out = []
        for line in r.splitlines()[1:]:
            m = re.match(r"\s+(\S+)\s+\(compatibility", line)
            if m:
                out.append((Path(m.group(1)).name, m.group(1)))
        return out

    if h.os == "windows":
        # The PE import table. llvm-readobj ships with LLVM, which we already require for
        # the sanitizers; dumpbin is the Visual Studio spelling of the same thing.
        r = _run(["llvm-readobj", "--coff-imports", binary])
        if r is not None:
            return [(m.group(1), "") for m in
                    re.finditer(r"^\s*Name:\s*(\S+\.dll)\s*$", r, re.I | re.M)]
        r = _run(["dumpbin", "/dependents", binary])
        if r is None:
            return None
        return [(m.group(1), "") for m in re.finditer(r"^\s+(\S+\.dll)\s*$", r, re.I | re.M)]

    r = _run(["ldd", binary])
    if r is None:
        return None
    out = []
    for line in r.splitlines():
        m = re.search(r"(\S+\.so[\.\d]*)\s*(?:=>\s*(\S+))?", line)
        if not m:
            continue
        path = m.group(2) or ""
        if path == "not" and "not found" in line:
            path = ""
        out.append((m.group(1), path))
    return out


def _run(cmd) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception:                                            # noqa: BLE001
        return None
    return r.stdout if r.returncode == 0 else None


def survey(binary: str, known: Optional[set] = None) -> Optional[Survey]:
    """Every shared library a program loads, marked for whether anyone is fuzzing it."""
    known = _normalise(known if known is not None else KNOWN_FUZZED)
    lines = _loader_lines(binary)
    if lines is None:
        return None

    out = Survey(binary=binary)
    for soname, path in lines:
        stem = _stem(soname)
        if _is_runtime(stem):
            continue                                             # the runtime, not a target
        d = Dependency(soname=soname, path=path, stem=stem,
                       fuzzed=stem in known,
                       parserish=bool(_PARSERISH.search(stem)))
        if _is_vendor_framework(path):
            # Apple's Security.framework came top of the shortlist on this host. It is
            # closed vendor code with no headers to propose against and a vendor already
            # fuzzing it — the opposite of the DjVuLibre case, which is an OPEN library
            # nobody had enrolled. Recorded with a reason rather than dropped, because a
            # shortlist that silently omits things is the thing this module warns about.
            d.fuzzed = True
            d.reason = "closed vendor framework: no source to harness"
            out.deps.append(d)
            continue
        if d.fuzzed:
            d.reason = "already has an OSS-Fuzz presence"
        elif not d.parserish:
            d.reason = "no sign it parses attacker-controlled input"
        else:
            d.reason = "PARSES INPUT AND NOT KNOWN TO BE FUZZED"
        out.deps.append(d)
    return out


def render(surveys: list) -> str:
    """One shortlist across several binaries, most-shared libraries first — a parser loaded
    by many tools is worth more than one loaded by a single utility."""
    seen: dict = {}
    for s in surveys:
        for d in s.deps:
            e = seen.setdefault(d.stem, {"dep": d, "users": set()})
            e["users"].add(Path(s.binary).name)

    cands = sorted((e for e in seen.values() if e["dep"].is_candidate),
                   key=lambda e: (-len(e["users"]), e["dep"].stem))
    L = ["", f"{'LIBRARY':<22} {'USED BY':<7} PATH", "-" * 74]
    for e in cands:
        d = e["dep"]
        L.append(f"{d.stem:<22} {len(e['users']):<7} {d.path or d.soname}")
        L.append(f"{'':<22} {'':<7} loaded by: {', '.join(sorted(e['users'])[:6])}")
    L.append("")
    L.append(f"{len(cands)} candidate(s): they parse input and are not in the known-fuzzed")
    L.append("set. That set is a FLOOR, not the full OSS-Fuzz registry — check each against")
    L.append("the project list before spending days on it. A wrong exclusion costs a missed")
    L.append("target; a wrong inclusion costs a wasted afternoon.")
    return "\n".join(L)


# ── from a name to something `propose` can consume ───────────────────────────

@dataclass
class Headers:
    """Where a candidate's public headers are, and HOW that was decided.

    The method is recorded because the two routes are not equally trustworthy. pkg-config is
    the library telling us about itself; a filesystem search is us guessing from a name, and
    a guess that lands on the wrong package produces a harness against a library the program
    never loads.
    """
    stem: str
    headers: list = field(default_factory=list)
    include_dirs: list = field(default_factory=list)
    method: str = ""                 # pkg-config:<name> | search:<dir> | ""
    why_not: str = ""

    @property
    def found(self) -> bool:
        return bool(self.headers)


_INCLUDE_ROOTS = ("/usr/include", "/usr/local/include", "/opt/homebrew/include",
                  "/opt/local/include")


def _pkgconfig_names() -> list:
    out = _run(["pkg-config", "--list-all"])
    return [ln.split()[0] for ln in out.splitlines() if ln.strip()] if out else []


def _prefix_ratio(a: str, b: str) -> float:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n / max(len(a), len(b)) if a and b else 0.0


def _affinity(header: Path, stem: str) -> int:
    """How strongly a header's NAME says it belongs to this library.

    Needed because pkg-config answers a different question than the one asked.
    `pkg-config --cflags-only-I fontconfig` returns FreeType's and libpng's include dirs —
    fontconfig's own header sits in the implicit /usr/include — so trusting it produced a
    command that said "fuzz fontconfig" and handed over a different library's API. A wrong
    target is worse than no target: the campaign runs, the certificate is valid, and it
    certifies the wrong thing.
    """
    base = header.stem.lower()
    # Trailing digits are usually PART of the name — iso9660, openjp2, pcre2, png16 — so
    # only an ABI decoration is stripped. Removing digits wholesale turned `iso9660` into
    # `iso` and matched the kernel's `iso_fs.h`.
    core = re.sub(r"-\d+\.q\d+$", "", stem)          # magickcore-6.q16 -> magickcore
    core = re.sub(r"-\d+(\.\d+)*$", "", core)         # yaml-0.1 -> yaml
    names = {stem, core, core.replace("-", ""), core.replace("_", "")}
    names = {n for n in names if len(n) >= 3}

    for n in names:
        if base == n or base == f"lib{n}":
            return 100
    for n in names:
        # A SHARED PREFIX covering most of both names, rather than one being a prefix of the
        # other. `libopenjp2` ships `openjpeg.h`: neither name contains the other, but they
        # agree on six characters of seven and eight. A bare startswith missed that and, in
        # the other direction, accepted `font` for `fontconfig` and `magic` for
        # `magickcore` — both naming a different library than the one shortlisted.
        if len(base) >= 4 and _prefix_ratio(base, n) >= 0.75:
            return 90
    parent = re.sub(r"^lib", "", header.parent.name.lower())
    for n in names:
        if len(parent) >= 4 and (parent.startswith(n) or n.startswith(parent)):
            return 80
    return 0


def _score(header: Path, stem: str) -> int:
    """Affinity, less any demotion — but an EXACT name match is never demoted.

    `fontconfig.h` is the fontconfig API and it contains the substring "config", so the
    build-configuration filter demoted it below `fcfreetype.h`. A header named exactly after
    its library is the API by definition."""
    a = _affinity(header, stem)
    return a if a >= 100 else a + _demote(header)


def _demote(header: Path) -> int:
    """A build-configuration header is not an API. ImageMagick resolved to
    `magick-baseconfig.h` purely because it sorts first."""
    if "/include/linux/" in str(header) or "/include/asm" in str(header):
        return -100          # kernel UAPI is never a userspace library's API
    b = header.name.lower()
    if any(k in b for k in ("config", "version", "export", "visibility", "internal",
                            "private", "deprecated", "compat", "port", "macros")):
        return -30
    return 0


def _so_variants(path: str) -> list:
    """Every spelling of the unversioned library the packaging system might know.

    `ldd` answers `/lib/aarch64-linux-gnu/libiso9660.so.11`; dpkg knows the same file as
    `/usr/lib/aarch64-linux-gnu/libiso9660.so.11`. usrmerge means the two are the same
    inode and different strings, and a lookup by string finds nothing.
    """
    if not path:
        return []
    p = Path(path)
    base = re.sub(r"\.so(\.\d+)*$", ".so", p.name)
    out, dirs = [], {str(p.parent)}
    d = str(p.parent)
    if d.startswith("/usr/lib"):
        dirs.add(d.replace("/usr/lib", "/lib", 1))
    elif d.startswith("/lib"):
        dirs.add("/usr" + d)
    for dd in dirs:
        out.append(f"{dd}/{base}")       # the -dev symlink: what a dev package owns
        out.append(f"{dd}/{p.name}")     # the runtime object
    return out


def _owner_headers(path: str) -> Optional[tuple]:
    """Ask the packaging system which package owns this library, and what headers it ships.

    Scoring header names against a library name produced confident wrong answers:
    `magickwand-6.q16` resolved to the Linux kernel's `/usr/include/linux/magic.h`, and
    `iso9660` to the kernel's `iso_fs.h`, because stripping a trailing version turned
    `iso9660` into `iso` and a prefix rule did the rest. The package manager KNOWS the
    answer; a name heuristic only ever approximates it.

    Returns (headers, package) or None.
    """
    for cand in _so_variants(path):
        owner = _run(["dpkg", "-S", cand])
        if not owner:
            continue
        pkg = owner.split(":")[0].strip()
        if not pkg:
            continue
        pkgs = [pkg]
        if not pkg.endswith("-dev"):
            # The runtime package was matched; its headers live in the -dev sibling.
            pkgs += [re.sub(r"\d+$", "", pkg) + "-dev", pkg + "-dev"]
        for q in pkgs:
            listing = _run(["dpkg", "-L", q])
            if not listing:
                continue
            hs = sorted(ln.strip() for ln in listing.splitlines()
                        if ln.strip().endswith(".h") and Path(ln.strip()).is_file())
            if hs:
                return hs, q

    for cand in _so_variants(path):
        owner = _run(["rpm", "-qf", cand])
        if not owner:
            continue
        pkg = owner.strip().splitlines()[0]
        for q in (pkg, re.sub(r"-\d.*$", "", pkg) + "-devel"):
            listing = _run(["rpm", "-ql", q])
            if not listing:
                continue
            hs = sorted(ln.strip() for ln in listing.splitlines()
                        if ln.strip().endswith(".h") and Path(ln.strip()).is_file())
            if hs:
                return hs, q
    return None


def resolve_headers(stem: str, path: str = "") -> Headers:
    """The public headers for a shortlisted library, or a stated reason there are none.

    A shortlist of NAMES is a list of things to go and look up by hand; `targets` produced one
    and stopped there, which is where the operator's afternoon went. This closes the gap
    between "nobody is fuzzing djvulibre" and a `propose` invocation.

    Candidates are gathered from every route and then SCORED, rather than taken from the
    first route that answers. Ranking is what stops pkg-config's answer for one library
    being served as another's.
    """
    h = Headers(stem=stem)

    # 1. Authoritative: the packaging system owns the mapping from library to headers.
    owned = _owner_headers(path)
    if owned:
        hs, pkg = owned
        best = sorted(hs, key=lambda f: (-_score(Path(f), stem), len(f), f))[0]
        h.headers = [best] + [x for x in hs if x != best][:59]
        h.include_dirs = list(dict.fromkeys(
            [str(Path(f).parent) for f in hs[:20]] +
            [str(Path(best).parent.parent)]))
        h.method = f"package:{pkg}"
        return h

    cands: list = []                 # (header_path, include_dirs, method)

    for pc in _pkgconfig_for(stem):
        cflags = _run(["pkg-config", "--cflags-only-I", pc])
        if cflags is None:
            continue
        dirs = [d for d in (t[2:] for t in cflags.split() if t.startswith("-I"))
                if Path(d).is_dir()]
        for d in dirs:
            for f in Path(d).rglob("*.h"):
                cands.append((f, dirs, f"pkg-config:{pc}"))

    roots = list(_INCLUDE_ROOTS)
    # Homebrew keeps KEG-ONLY formulas out of /opt/homebrew/include and off the default
    # pkg-config path — sqlite3 among them, so the header this engine has been parsing all
    # week resolved to "not installed".
    for opt in (Path("/opt/homebrew/opt"), Path("/usr/local/opt")):
        if opt.is_dir():
            for name in (stem, f"lib{stem}", stem.rstrip("0123456789")):
                inc = opt / name / "include"
                if inc.is_dir():
                    roots.insert(0, str(inc))

    for root in roots:
        rp = Path(root)
        if not rp.is_dir():
            continue
        for f in rp.glob("*.h"):
            cands.append((f, [root], f"search:{root}"))
        # One level down, because a library's headers usually live in a directory named
        # after the PROJECT rather than the soname: `libdjvulibre.so.21` ships
        # `/usr/include/libdjvu/ddjvuapi.h`, and `libiso9660.so.11` ships
        # `/usr/include/cdio/iso9660.h`. Searching only `<root>/<stem>/` missed both — the
        # first being the exact library this module was written about.
        for sub in rp.iterdir():
            if not sub.is_dir():
                continue
            for f in sub.glob("*.h"):
                cands.append((f, [root], f"search:{sub}"))

    scored = [(_score(f, stem), f, dirs, m) for f, dirs, m in cands]
    scored = [t for t in scored if t[0] > 0]
    if not scored:
        h.why_not = ("no header whose name relates to this library: the development package "
                     "is not installed, or its headers are named nothing like its soname")
        return h

    scored.sort(key=lambda t: (-t[0], len(str(t[1])), str(t[1])))
    best_score, best, best_dirs, method = scored[0]
    # Ship every same-directory sibling: an API is rarely one file, and propose reads them
    # all to resolve typedefs across headers.
    sibs = sorted({str(f) for sc, f, _, _ in scored
                   if f.parent == best.parent and sc > 0})
    h.headers = [str(best)] + [x for x in sibs if x != str(best)]
    h.headers = h.headers[:60]
    h.include_dirs = list(dict.fromkeys(best_dirs + [str(best.parent), str(best.parent.parent)]))
    h.method = method
    if best_score < 90:
        h.why_not = (f"matched on directory name only (score {best_score}) — confirm this is "
                     f"the right library before spending a campaign on it")
    return h


def _pkgconfig_for(stem: str) -> list:
    """pkg-config names rarely equal the soname stem: `libdjvulibre.so.21` ships
    `ddjvuapi.pc`. Exact first, then substring."""
    names = _pkgconfig_names()
    exact = [n for n in names if _stem(n) == stem or n == stem]
    fuzzy = [n for n in names if stem in n.lower() or n.lower() in stem]
    return exact + [n for n in fuzzy if n not in exact]
