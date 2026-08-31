# The reference environment for every number in benchmarks/results/.
#
# THIS FILE WAS MISSING UNTIL 2026-08-30, and the omission mattered more than it looks.
# The image existed only on the author's machine, so the toolchain that fixes the compiler,
# the sanitizers and the coverage tooling -- the whole reason two runs differ in the engine
# and not in the environment -- could not be rebuilt by anyone else. Every replication
# instruction in REPLICATION.md was unrunnable, and the gap was found by checking whether
# the command in that file worked before publishing it. It did not.
#
# Recovered from the running image's own layer history rather than rewritten from memory,
# so it produces the environment the recorded results were actually measured in.
#
#   docker build -t hforge-linuxbench benchmarks/
#
# clang/LLVM 14 is PINNED deliberately. Coverage percentages are not comparable across
# LLVM versions -- the instrumentation, the region counting and the summary arithmetic all
# move -- so a replication on clang 17 is a different experiment, not a disagreement.
FROM debian:bookworm-slim

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      python3 clang-14 llvm-14 libclang-rt-14-dev libc++-14-dev libc++abi-14-dev \
      binutils file ca-certificates \
    && ln -sf /usr/bin/clang-14 /usr/local/bin/clang \
    && ln -sf /usr/bin/clang++-14 /usr/local/bin/clang++ \
    && ln -sf /usr/bin/llvm-nm-14 /usr/local/bin/llvm-nm \
    && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/local/bin/clang
WORKDIR /work
