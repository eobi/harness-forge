#!/bin/sh
# Does coverage guidance beat blind mutation on a GUI target?
#
# BOTH ARMS ARE INSTRUMENTED IDENTICALLY. Only the SELECTION differs: the guided arm breeds
# from inputs that reached a region nothing else did, the blind arm always mutates the
# original seed. Turning instrumentation off in the blind arm would compare two different
# programs and attribute the difference to guidance.
#
# PAIRED BY RNG SEED. Repeat k of each arm starts from the same mutation stream, so the two
# arms see the same first input and diverge only when the guided one starts breeding. An
# unpaired comparison at these sample sizes measures the RNG.
set -eu
N="${N:-20}"
REPEATS="${REPEATS:-4}"
SEED_FILE="${SEED_FILE:-/usr/share/icons/Adwaita/256x256/legacy/ac-adapter.png}"
REC="${REC:-/tmp/guided_vs_blind.jsonl}"
: > "$REC"
k=1
while [ "$k" -le "$REPEATS" ]; do
  for guide in 1 0; do
    rm -rf /tmp/gvb_cov
    HF_GUI_COVERAGE=1 HF_GUI_GUIDE="$guide" HF_GUI_COV_DIR=/tmp/gvb_cov \
    HF_GUI_COV_BIN=/tmp/pngcov/lib/libpng16.so.16.37.0 \
    HF_GUI_APP_BIN=/home/ubuntu/covbuild/eog-42.0/build/src/eog \
    LD_LIBRARY_PATH=/tmp/pngcov/lib \
    python3 benchmarks/gui/campaign.py --app eog --n "$N" --rng "$((1337 + k))" \
      --seed-file "$SEED_FILE" --record "$REC" 2>&1 | tail -2
  done
  k=$((k + 1))
done
echo "recorded: $REC"
