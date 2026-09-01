#!/usr/bin/env python3
"""Generate gate-passing harnesses across every library checkout, and record the count.

WHY A SWEEP. Every harness produced so far came from a library chosen by hand, which makes
the yield look like whatever the chosen library happened to give. A sweep over the whole
corpus reports the yield of the METHOD instead: how many candidates a public header
produces, how many survive the static gates, and -- the number that actually matters -- how
many are left to hand a fuzzer.

WHAT IS RECORDED. Per library: candidates proposed, candidates after synthesis, candidates
the gates ACCEPT, and the reason the rest were rejected. A library that yields nothing is
recorded as yielding nothing; that is a result about the method, not a run to leave out.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The public header a consumer of the library would include. Picked by hand ONCE, because
# "the header with the most declarations" chooses internal headers that no consumer sees,
# and harnesses built from those measure the wrong surface.
HEADERS = {
    "brotli":    "c/include/brotli/decode.h",
    "cjson":     "cJSON.h",
    "expat":     "expat/lib/expat.h",
    "jansson":   "src/jansson.h",
    "jbig2dec":  "jbig2.h",
    "lcms2":     "include/lcms2.h",
    "leptonica": "src/allheaders.h",
    "libde265":  "libde265/de265.h",
    "libpng":    "png.h",
    "libwebp":   "src/webp/decode.h",
    "libyaml":   "include/yaml.h",
    "mbedtls":   "include/mbedtls/x509_crt.h",
    "wabt":      "include/wabt/binary-reader.h",
    "woff2":     "include/woff2/decode.h",
    "yajl":      "src/api/yajl_parse.h",
    "zlib":      "zlib.h",
    "zopfli":    "src/zopfli/zopfli.h",
    "zstd":      "lib/zstd.h",
}


def sweep(work: Path, out: Path, timeout: int) -> dict:
    rows = []
    for name, rel in sorted(HEADERS.items()):
        hdr = work / name / rel
        if not hdr.exists():
            rows.append({"library": name, "status": "no-header", "header": str(rel)})
            print(f"  {name:12s} SKIP  header not present", flush=True)
            continue
        dest = out / name
        dest.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            p = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "forge_bridge.py"), str(hdr),
                 "--include", str(work / name), "--name", name,
                 "--out", str(dest), "--emit-only", "--max", "200"],
                capture_output=True, text=True, timeout=timeout, cwd=ROOT)
            txt = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            rows.append({"library": name, "status": "timeout", "seconds": timeout})
            print(f"  {name:12s} TIMEOUT after {timeout}s", flush=True)
            continue
        # rglob, not glob: the bridge writes into --out/<name>/, so a flat glob finds
        # nothing and reports a working library as yielding zero harnesses.
        emitted = sorted(dest.rglob("*.c"))
        row = {"library": name, "status": "ok" if p.returncode == 0 else "error",
               "returncode": p.returncode, "harnesses_emitted": len(emitted),
               "seconds": round(time.time() - t0, 1),
               "tail": txt.strip().splitlines()[-3:] if txt.strip() else []}
        rows.append(row)
        print(f"  {name:12s} {len(emitted):4d} harnesses  {row['seconds']:6.1f}s"
              f"{'' if p.returncode == 0 else '  (rc=%d)' % p.returncode}", flush=True)
    return {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "libraries": len(HEADERS), "rows": rows,
            "total_harnesses": sum(r.get("harnesses_emitted", 0) for r in rows)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", default="/tmp/hf-bench")
    ap.add_argument("--out", default="/tmp/hf-harnesses")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    print(f"sweeping {len(HEADERS)} libraries -> {out}", flush=True)
    res = sweep(Path(a.work), out, a.timeout)
    (out / "sweep.json").write_text(json.dumps(res, indent=1))
    ok = [r for r in res["rows"] if r.get("harnesses_emitted")]
    print(f"\n{res['total_harnesses']} harnesses from {len(ok)}/{len(HEADERS)} libraries")
    print(f"recorded: {out / 'sweep.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
