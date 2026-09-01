#!/bin/sh
# Audit each library's own in-tree harnesses WITH its public header, so S2 runs.
set -u
run() {
  lib="$1"; hdr="$2"; inc="$3"
  files=$(find "/tmp/hf-bench/$lib" \( -name "*fuzz*.c" -o -name "*fuzz*.cc" \) 2>/dev/null | grep -v "/build/" | head -50)
  [ -z "$files" ] && return
  [ -f "$hdr" ] || { echo "$lib: header missing $hdr"; return; }
  out=$(python3.13 -m hforge audit $files --header "$hdr" --include "$inc" --name "$lib" 2>&1)
  n=$(echo "$out" | grep -c "\[BLOCK\]")
  s2=$(echo "$out" | grep -c "S2\.")
  aud=$(echo "$out" | grep "AUDITED" | head -1)
  printf "  %-11s %-34s BLOCK=%-3s S2=%s\n" "$lib" "$aud" "$n" "$s2"
  echo "$out" | grep "\[BLOCK\]" | sed 's/^/      /' | head -4
}
run cjson     /tmp/hf-bench/cjson/cJSON.h                /tmp/hf-bench/cjson
run jansson   /tmp/hf-bench/jansson/src/jansson.h        /tmp/hf-bench/jansson/src
run expat     /tmp/hf-bench/expat/expat/lib/expat.h      /tmp/hf-bench/expat/expat/lib
run libpng    /tmp/hf-bench/libpng/png.h                 /tmp/hf-bench/libpng
run libwebp   /tmp/hf-bench/libwebp/src/webp/decode.h    /tmp/hf-bench/libwebp/src
run brotli    /tmp/hf-bench/brotli/c/include/brotli/decode.h /tmp/hf-bench/brotli/c/include
run zstd      /tmp/hf-bench/zstd/lib/zstd.h              /tmp/hf-bench/zstd/lib
run leptonica /tmp/hf-bench/leptonica/src/allheaders.h   /tmp/hf-bench/leptonica/src
run mbedtls   /tmp/hf-bench/mbedtls/include/mbedtls/x509_crt.h /tmp/hf-bench/mbedtls/include
