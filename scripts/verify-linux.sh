#!/bin/sh
# Verify the engine on real Linux, across the variants that actually differ.
#
# Three platforms, not one, because the platform model claims they are distinct and an
# unexercised claim is a guess:
#
#   linux-aarch64-glibc   ptmalloc, the common server case
#   linux-aarch64-musl    mallocng — a different allocator, so a different heap-bug surface
#   linux-x86_64-glibc    a different word size and codegen, under emulation
#
# The last step is the one worth having: the same plan is certified on all three and the gate
# verdicts are compared. Agreement is the expected result. DISAGREEMENT IS NOT A FAILURE OF
# THIS SCRIPT — it is the variant-disagreement oracle firing, and it means the harness's
# behaviour depends on the allocator or the word size. Read it, do not suppress it.
set -eu
cd "$(dirname "$0")/.."
OUT="${TMPDIR:-/tmp}/hforge-linux-verify"
mkdir -p "$OUT"

docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 2; }

run() {  # name image platform_flag
    echo "=============================================================="
    echo "  $1"
    echo "=============================================================="
    docker run --rm $3 -v "$PWD:/hf" -w /hf "$2" sh -c '
        python3 -m hforge doctor 2>&1 | sed -n "2,7p"
        for t in tests/test_phase1.py tests/test_phase2.py tests/test_phase3.py \
                 tests/test_portability.py; do
            printf "%-30s " "$t"; python3 "$t" 2>&1 | tail -1
        done
        python3 -m hforge selftest 2>&1 | tail -8
        python3 -m hforge certify examples/hf_demo.good.hir.json \
            --no-positive-control -o /hf/'"$1"'.cert.json >/dev/null 2>&1 || true
    '
    if [ -f "$1.cert.json" ]; then mv "$1.cert.json" "$OUT/"; fi
    echo
}

docker build -q -f scripts/docker/Dockerfile.glibc -t hforge-glibc scripts/docker >/dev/null
docker build -q -f scripts/docker/Dockerfile.musl  -t hforge-musl  scripts/docker >/dev/null
docker build -q --platform linux/amd64 -f scripts/docker/Dockerfile.glibc \
       -t hforge-glibc-amd64 scripts/docker >/dev/null

run linux-aarch64-glibc hforge-glibc       ""
run linux-aarch64-musl  hforge-musl        ""
run linux-x86_64-glibc  hforge-glibc-amd64 "--platform linux/amd64"

echo "=============================================================="
echo "  CROSS-VARIANT AGREEMENT"
echo "=============================================================="
python3 scripts/compare_certs.py "$OUT"/*.cert.json
