#!/usr/bin/env python3
"""Harvest third-party harnesses AND the headers needed to grade them.

WHY THE HEADERS. The existing corpus kept only harnesses, so every audit ran with the
contract gates dark: S2 fires off a DECLARATION, and a harness is call sites. 1,401 harnesses
were graded that way and S2 reported NOT RUN on all of them. NOT RUN is not PASS, so the
corpus has to carry the headers or the number it produces is not the number it looks like.

DISK STAYS FLAT. Each repository is shallow-cloned, the harnesses and candidate public
headers are copied out, and the clone is deleted before the next one starts. 479 repositories
do not fit on this machine and do not need to.

RESUMABLE. A project already harvested is skipped, so this can be run in batches and extended
without redoing work or double-counting.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_HARNESS = ("*fuzz*.c", "*fuzz*.cc", "*fuzz*.cpp", "*Fuzz*.c", "*Fuzz*.cc", "*Fuzz*.cpp")
# Where a C library puts the header a consumer includes. Ordered: earlier is more likely to
# be the public surface rather than an internal detail.
_HDR_DIRS = ("include", "src", "lib", "api", "public", ".")


def _main_repo(proj: Path) -> str:
    y = proj / "project.yaml"
    if not y.exists():
        return ""
    for line in y.read_text(errors="ignore").splitlines():
        if line.strip().startswith("main_repo:"):
            url = line.split(":", 1)[1].strip().strip('"').strip("'")
            return url if url.startswith("https://github.com/") else ""
    return ""


def harvest(name: str, url: str, out: Path, max_headers: int, timeout: int,
            oss_dir: Path | None = None) -> dict:
    dest = out / name
    if (dest / "manifest.json").exists():
        return json.loads((dest / "manifest.json").read_text())
    rec = {"project": name, "repo": url, "harnesses": 0, "headers": 0, "status": "ok"}
    with tempfile.TemporaryDirectory(prefix="hv-") as td:
        clone = Path(td) / "r"
        p = subprocess.run(["git", "clone", "--depth", "1", "--quiet",
                            "--filter=blob:none", url, str(clone)],
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            rec["status"] = "clone-failed"
            rec["error"] = (p.stderr or "")[-120:]
            return rec
        hs: list = []
        for pat in _HARNESS:
            hs.extend(q for q in clone.rglob(pat) if q.is_file())
        hs = sorted({q.resolve() for q in hs})[:60]
        # MOST PROJECTS KEEP THEIR HARNESS IN THE OSS-FUZZ TREE, NOT UPSTREAM.
        #
        # Six of the first eight clones carried no harness at all, and harvesting only
        # upstream would have thrown away the majority of the corpus while reporting a clean
        # "no-harness". The harness and the header simply live in different repositories, and
        # the audit needs both: the tree has 419 harnesses, the clone has the declarations.
        if not hs and oss_dir is not None and oss_dir.is_dir():
            for pat in _HARNESS:
                hs.extend(q for q in oss_dir.rglob(pat) if q.is_file())
            hs = sorted({q.resolve() for q in hs})[:60]
            if hs:
                rec["harness_source"] = "oss-fuzz-tree"
        if not hs:
            rec["status"] = "no-harness"
            return rec
        rec.setdefault("harness_source", "upstream")
        (dest / "harness").mkdir(parents=True, exist_ok=True)
        for i, q in enumerate(hs):
            try:
                shutil.copyfile(q, dest / "harness" / f"{i:03d}_{q.name}")
            except OSError:
                continue
        rec["harnesses"] = len(list((dest / "harness").glob("*")))

        # HEADERS, ranked by how public the directory looks. Capped, because a large project
        # ships thousands and the contract gate only needs the declarations the harness calls.
        seen: set = set()
        picked: list = []
        for d in _HDR_DIRS:
            base = clone / d if d != "." else clone
            if not base.is_dir():
                continue
            for q in sorted(base.rglob("*.h")):
                if any(x in str(q).lower() for x in ("/test", "/example", "/third_party",
                                                     "/vendor", "/build")):
                    continue
                if q.name in seen:
                    continue
                seen.add(q.name)
                picked.append(q)
                if len(picked) >= max_headers:
                    break
            if len(picked) >= max_headers:
                break
        (dest / "include").mkdir(parents=True, exist_ok=True)
        for q in picked:
            try:
                shutil.copyfile(q, dest / "include" / q.name)
            except OSError:
                continue
        rec["headers"] = len(list((dest / "include").glob("*.h")))
    (dest / "manifest.json").write_text(json.dumps(rec, indent=1))
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--oss-fuzz", default=str(Path.home() / "Documents" /
                                              "Autogon Research Institute" / "oss-fuzz"))
    ap.add_argument("--out", default="/tmp/hf-corpus")
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--max-headers", type=int, default=120)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--jobs", type=int, default=6)
    a = ap.parse_args()

    projects = sorted((Path(a.oss_fuzz) / "projects").iterdir())
    todo: list = []
    for proj in projects:
        if not proj.is_dir():
            continue
        url = _main_repo(proj)
        if url:
            todo.append((proj.name, url))
    todo = todo[a.skip:a.skip + a.limit]
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    print(f"harvesting {len(todo)} project(s) -> {out}", flush=True)

    recs: list = []
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = {ex.submit(harvest, n, u, out, a.max_headers, a.timeout,
                          Path(a.oss_fuzz) / "projects" / n): n
                for n, u in todo}
        for f in futs:
            try:
                r = f.result()
            except Exception as ex2:                                # noqa: BLE001
                r = {"project": futs[f], "status": "error", "error": str(ex2)[:120],
                     "harnesses": 0, "headers": 0}
            recs.append(r)
            if r.get("harnesses"):
                print(f"  {r['project'][:26]:28s} {r['harnesses']:3d} harness(es), "
                      f"{r['headers']:3d} header(s)", flush=True)

    ok = [r for r in recs if r.get("harnesses")]
    summary = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "attempted": len(recs), "with_harnesses": len(ok),
               "harnesses": sum(r.get("harnesses", 0) for r in ok),
               "headers": sum(r.get("headers", 0) for r in ok),
               "by_status": {}, "rows": recs}
    for r in recs:
        s = r.get("status", "?")
        summary["by_status"][s] = summary["by_status"].get(s, 0) + 1
    (out / "harvest.json").write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['harnesses']} harness(es) and {summary['headers']} header(s) "
          f"from {len(ok)}/{len(recs)} project(s)")
    print(f"  status: {summary['by_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
