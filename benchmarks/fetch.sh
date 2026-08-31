#!/bin/sh
# Fetch every benchmark target at a PINNED revision, and record what was fetched.
#
#   benchmarks/fetch.sh            # fetch anything missing or at the wrong revision
#   benchmarks/fetch.sh libpng     # just one
#
# WHY THIS FILE EXISTS. Runs 016 through 023 measured sources that were cloned by hand,
# at whatever revision upstream's default branch happened to be that afternoon. The work
# directory then got cleared, and with it the only record of which libpng those numbers
# describe. A coverage percentage against an unknown revision is not a measurement anyone
# can check, including us. Every row this suite emits from here on names the source it
# measured, and this script is what makes that name true.
#
# The clone happens on the HOST because the benchmark image ships no git. The per-target
# prep runs INSIDE the image because it needs that image's clang and its headers, not the
# host's. Splitting the two is deliberate; doing either on the wrong side fails in ways
# that look like an engine defect.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="${HF_BENCH_WORK:-/tmp/hf-bench}"
IMAGE="${HF_BENCH_IMAGE:-hforge-linuxbench}"
mkdir -p "$WORK"

# dir | repo | tag. Tags resolved against upstream on 2026-08-29; the sha each one pointed
# at that day is recorded in versions.json at fetch time, so a retag upstream shows up as a
# changed sha in the lock rather than as a silently different measurement.
TARGETS=$(cat <<'LIST'
libyaml   https://github.com/yaml/libyaml             0.2.5
brotli    https://github.com/google/brotli            v1.1.0
yajl      https://github.com/lloyd/yajl               2.1.0
cjson     https://github.com/DaveGamble/cJSON         v1.7.18
zopfli    https://github.com/google/zopfli            zopfli-1.0.3
zlib      https://github.com/madler/zlib              v1.3.1
jansson   https://github.com/akheron/jansson          v2.14
jbig2dec  https://github.com/ArtifexSoftware/jbig2dec 0.20
lcms2     https://github.com/mm2/Little-CMS           lcms2.16
leptonica https://github.com/DanBloomberg/leptonica   1.85.0
libde265  https://github.com/strukturag/libde265      v1.0.15
pugixml   https://github.com/zeux/pugixml             v1.15
woff2     https://github.com/google/woff2             main
wabt      https://github.com/WebAssembly/wabt         1.0.41
libpng    https://github.com/pnggroup/libpng          v1.6.44
libwebp   https://github.com/webmproject/libwebp      v1.4.0
expat     https://github.com/libexpat/libexpat        R_2_6_4
zstd      https://github.com/facebook/zstd            v1.5.6
mbedtls   https://github.com/Mbed-TLS/mbedtls         mbedtls-3.6.2
LIST
)

WANT="$*"
echo "$TARGETS" | while read -r dir url tag; do
  [ -n "${dir:-}" ] || continue
  if [ -n "$WANT" ]; then
    case " $WANT " in *" $dir "*) ;; *) continue ;; esac
  fi
  dest="$WORK/$dir"
  if [ -d "$dest/.git" ]; then
    have=$(git -C "$dest" rev-parse HEAD 2>/dev/null || echo none)
    want=$(git -C "$dest" rev-parse "refs/tags/$tag^{commit}" 2>/dev/null || echo unknown)
    if [ "$have" = "$want" ]; then
      echo "$dir: already at $tag"
      continue
    fi
  fi
  echo "$dir: cloning $tag"
  rm -rf "$dest"
  # --depth 1 against the tag: the suite needs the tree, never the history.
  git clone --quiet --depth 1 --branch "$tag" "$url" "$dest"
done

# libyaml's yaml.h is reached through /b/inc as well as its own include/. Both paths are
# in the case's include list, so both have to exist.
if [ -f "$WORK/libyaml/include/yaml.h" ]; then
  mkdir -p "$WORK/inc" && cp "$WORK/libyaml/include/yaml.h" "$WORK/inc/yaml.h"
fi

# THE LOCK. One line per target: the revision this tree actually holds, read back from the
# clone rather than from the table above, so a failed or partial fetch cannot be recorded
# as a success.
python3 - "$WORK" <<'PY'
import json, subprocess, sys, pathlib
work = pathlib.Path(sys.argv[1])
out = {}
for d in sorted(p for p in work.iterdir() if (p / ".git").is_dir()):
    def git(*a):
        try:
            return subprocess.run(["git", "-C", str(d), *a], capture_output=True,
                                  text=True, check=True).stdout.strip()
        except Exception:
            return None
    out[d.name] = {"sha": git("rev-parse", "HEAD"),
                   "described": git("describe", "--tags", "--always"),
                   "origin": git("config", "--get", "remote.origin.url")}
(work / "versions.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print(f"versions.json: {len(out)} target(s) locked")
PY

# Per-target prep — generated headers, and libwebp's round-trip seed corpus. These need the
# image's toolchain, so they run in it.
PREP=""
for s in "$REPO"/benchmarks/targets/*.sh; do
  [ -e "$s" ] || continue
  n=$(basename "$s" .sh)
  if [ -n "$WANT" ]; then
    case " $WANT " in *" $n "*) ;; *) continue ;; esac
  fi
  [ -d "$WORK/$n" ] || continue
  PREP="$PREP $n"
done
if [ -n "$PREP" ]; then
  # rm first: `cp -r src dst` nests into dst/src when dst exists, which leaves the
  # container running a STALE copy of the prep scripts and makes an edit look like it had
  # no effect.
  rm -rf "$WORK/targets"
  cp -r "$REPO/benchmarks/targets" "$WORK/targets"
  docker run --rm -v "$WORK:/b" "$IMAGE" sh -c '
    for n in '"$PREP"'; do
      echo "prep: $n"
      sh "/b/targets/$n.sh" "/b/$n" || echo "prep: $n FAILED" >&2
    done'
fi
echo "fetch: done"
