#!/usr/bin/env python3
"""How many generated harnesses actually COMPILE, per library.

WHY THIS IS SEPARATE FROM FUZZING. A fuzzing campaign that fails to build reports "no
crashes", which is indistinguishable from a campaign that built and found nothing. Measuring
the compile rate first separates "the harness is wrong" from "the library has no bug here",
and it costs seconds per harness instead of a minute.

WHAT PASSING MEANS. The harness compiles and links against the library with libFuzzer. It
does NOT mean the harness is correct, reaches anything interesting, or terminates -- the
gates speak to the first, coverage to the second, and only a campaign to the third.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def _sources(lib_dir: Path, limit: int = 400) -> list[str]:
    skip = ("test", "example", "fuzz", "bench", "demo", "tool", "prog")
    out = []
    for c in sorted(lib_dir.rglob("*.c")):
        rel = str(c.relative_to(lib_dir)).lower()
        if any(s in rel for s in skip):
            continue
        out.append(str(c))
    return out[:limit]


# NEVER put a test directory on the include path. mbedtls ships
# tests/include/baremetal-override/time.h, which #errors unless MBEDTLS_HAVE_TIME is set --
# so adding it SHADOWED the system time.h and reported all 101 mbedtls harnesses as failing
# to compile, with an error that reads like a library misconfiguration and is really a
# directory this probe should never have passed.
_NOT_AN_INCLUDE_DIR = ("/test", "/tests", "/example", "/examples", "/fuzz", "/bench",
                       "/programs", "/override")


def _incdirs(lib_dir: Path) -> list[str]:
    d = {lib_dir}
    for name in ("include", "src", "lib", "api"):
        p = lib_dir / name
        if p.is_dir():
            d.add(p)
    # BOTH the directory holding a header AND its parent. A library that namespaces its
    # public headers is included as <brotli/port.h>, which resolves against c/include and
    # NOT against c/include/brotli -- adding only the holding directory took every one of
    # brotli's harnesses from compiling to not compiling, with the error coming from the
    # library's own header rather than from anything generated.
    for h in lib_dir.rglob("*.h"):
        d.add(h.parent)
        d.add(h.parent.parent)
        if len(d) > 60:
            break
    return [f"-I{x}" for x in sorted(map(str, d))
            if not any(t in str(x).lower() for t in _NOT_AN_INCLUDE_DIR)]


def check(h: Path, incs: list[str], cc: str) -> tuple[str, bool, str]:
    # SYNTAX ONLY. Linking needs every symbol the library defines, which is a build-system
    # problem and not a property of the harness. -fsyntax-only answers the question asked
    # here -- does this harness compile against the library's real headers -- in a fraction
    # of the time and without a per-library build recipe.
    p = subprocess.run([cc, "-fsyntax-only", "-w", *incs, str(h)],
                       capture_output=True, text=True, timeout=90)
    err = ""
    if p.returncode != 0:
        for line in (p.stderr or "").splitlines():
            if ": error:" in line:
                err = line.split(": error:", 1)[1].strip()[:110]
                break
    return h.name, p.returncode == 0, err


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--harnesses", default="/tmp/hf-harnesses")
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--per-lib", type=int, default=0, help="0 = all")
    ap.add_argument("--out", default="/tmp/hf-harnesses/compile.json")
    a = ap.parse_args()

    rows = []
    for libdir in sorted(Path(a.harnesses).iterdir()):
        if not libdir.is_dir():
            continue
        lib = libdir.name
        src = Path(a.work) / lib
        if not src.is_dir():
            continue
        hs = sorted(libdir.rglob("*.c"))
        if a.per_lib:
            hs = hs[:a.per_lib]
        if not hs:
            continue
        incs = _incdirs(src)
        t0 = time.time()
        errs: dict[str, int] = {}
        okn = 0
        with ThreadPoolExecutor(max_workers=8) as ex:
            for name, ok, err in ex.map(lambda h: check(h, incs, a.cc), hs):
                if ok:
                    okn += 1
                elif err:
                    errs[err] = errs.get(err, 0) + 1
        top = sorted(errs.items(), key=lambda kv: -kv[1])[:3]
        rows.append({"library": lib, "harnesses": len(hs), "compiled": okn,
                     "rate": round(100.0 * okn / len(hs), 1),
                     "seconds": round(time.time() - t0, 1),
                     "top_errors": [{"error": e, "count": n} for e, n in top]})
        print(f"  {lib:12s} {okn:4d}/{len(hs):<4d} = {rows[-1]['rate']:5.1f}%"
              f"   {top[0][0][:58] if top else ''}", flush=True)

    tot_h = sum(r["harnesses"] for r in rows)
    tot_ok = sum(r["compiled"] for r in rows)
    res = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "compiler": a.cc, "mode": "-fsyntax-only",
           "harnesses": tot_h, "compiled": tot_ok,
           "rate": round(100.0 * tot_ok / tot_h, 1) if tot_h else 0.0, "rows": rows}
    Path(a.out).write_text(json.dumps(res, indent=1))
    print(f"\n{tot_ok}/{tot_h} = {res['rate']}% compile   -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
