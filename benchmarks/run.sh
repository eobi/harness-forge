#!/bin/sh
# Run a benchmark against the Linux image, reproducibly.
#
#   benchmarks/run.sh run-010 600 libyaml/libyaml_loader_fuzzer brotli/decode_fuzzer ...
#   benchmarks/run.sh run-010 600            # every case drive.py defines
#
# WHY A SCRIPT AND NOT A COMMAND YOU TYPE. Two runs of this suite have to differ in the
# engine and in nothing else. Typing the docker invocation by hand means the mount layout,
# the budget or the case list can drift between runs without anyone noticing, and then a
# coverage difference has two possible causes instead of one.
#
# THE MOUNT LAYOUT MATTERS, AND ONE HALF OF IT IS READ-ONLY ON PURPOSE:
#   /hf  the repository, READ-ONLY. Each case is a separate `python3 drive.py` process, so
#        every case imports hforge fresh from this mount. Editing the engine while a run is
#        in progress therefore changes what the REMAINING cases measure. Read-only stops
#        the container writing here; it does not stop you, so do not edit hforge/ mid-run.
#   /b   the work directory, writable: fetched target sources, corpora, binaries, results
#        and logs.
set -eu

RUN_ID="${1:?usage: run.sh <run-id> <seconds> [case ...]}"
SECONDS_PER_CASE="${2:?usage: run.sh <run-id> <seconds> [case ...]}"
shift 2

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="${HF_BENCH_WORK:-/tmp/hf-bench}"
IMAGE="${HF_BENCH_IMAGE:-hforge-linuxbench}"
mkdir -p "$WORK"

# The driver is COPIED into the work directory rather than run from /hf. A run must not
# change under its own feet: with the copy in place, editing benchmarks/drive.py during a
# run is safe, and the run keeps measuring what it started with.
cp "$REPO/benchmarks/drive.py" "$WORK/drive.py"
cp -r "$REPO/benchmarks/targets" "$WORK/targets" 2>/dev/null || true

CASES="$*"
if [ -z "$CASES" ]; then
  CASES=$(cd "$REPO" && python3 -c "
import re, pathlib
src = pathlib.Path('benchmarks/drive.py').read_text()
ns = {'glob': __import__('glob')}
exec(re.search(r'^CASES = \{.*?^\}', src, re.S | re.M).group(0), ns)
print(' '.join(ns['CASES']))
")
fi

# WHICH ENGINE PRODUCED THIS ROW.
#
# A results file without it is not reproducible: run-009's eight harnesses were emitted
# against one revision, and three producer fixes landed within twenty minutes of the last
# one finishing. Six months on, nobody can tell which tree a number came from unless the
# number says. The host has git; the image does not need it.
ENGINE_SHA=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
if ! git -C "$REPO" diff --quiet HEAD 2>/dev/null; then
  # An uncommitted tree is a tree nobody else can check out. Say so in the row rather than
  # recording a sha that does not describe what actually ran.
  ENGINE_SHA="$ENGINE_SHA-dirty"
fi
echo "engine: $ENGINE_SHA"

RESULTS="$WORK/results-$RUN_ID.jsonl"
: > "$RESULTS"
echo "run $RUN_ID: ${SECONDS_PER_CASE}s per case"
echo "cases: $CASES"

docker run --rm --name "hf-$RUN_ID" \
  -v "$REPO:/hf:ro" -v "$WORK:/b" \
  -e HF_LOGDIR="/b/logs/$RUN_ID" -e HF_ENGINE_SHA="$ENGINE_SHA" \
  "$IMAGE" sh -c "
    mkdir -p /b/logs/$RUN_ID
    for c in $CASES; do
      echo \"### \$c\" >&2
      python3 /b/drive.py \"\$c\" $SECONDS_PER_CASE >> /b/results-$RUN_ID.jsonl \
        2>> /b/logs/$RUN_ID/driver.log || echo \"{\\\"case\\\":\\\"\$c\\\",\\\"result\\\":\\\"driver crashed\\\"}\" >> /b/results-$RUN_ID.jsonl
    done
  "

cp "$RESULTS" "$REPO/benchmarks/results/$RUN_ID.jsonl"
mkdir -p "$REPO/benchmarks/results/logs"
cp -r "$WORK/logs/$RUN_ID" "$REPO/benchmarks/results/logs/" 2>/dev/null || true
python3 "$REPO/benchmarks/rank.py" "$REPO/benchmarks/results/$RUN_ID.jsonl" --write
echo "run $RUN_ID: results and logs collected, tables regenerated"
