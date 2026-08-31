#!/bin/sh
# Open the bluez fuzz_gobex GError-leak PR against google/oss-fuzz.
#
# Run this yourself: forking and pushing are outward-facing actions and were blocked by
# the agent's permission classifier, which is the correct default for them.
set -eu

WORK="${WORK:-/tmp/ossfuzz-pr}"
gh repo fork google/oss-fuzz --clone=false || true
rm -rf "$WORK"
git clone --depth 1 "https://github.com/eobi/oss-fuzz.git" "$WORK"
cd "$WORK"
git checkout -b bluez-fuzz-gobex-free-gerror

python3 - <<'PY'
from pathlib import Path
p = Path("projects/bluez/fuzz_gobex.c")
s = p.read_text()
old = """    g_obex_packet_free(pkt);
  }
"""
new = """    g_obex_packet_free(pkt);
  }
  if (err != NULL) {
    g_error_free(err);
  }
"""
assert old in s, "anchor not found -- the harness changed upstream; re-read before filing"
assert "g_error_free" not in s, "already fixed upstream"
p.write_text(s.replace(old, new, 1))
print("patched projects/bluez/fuzz_gobex.c")
PY

git diff --stat
git commit -aqm "bluez: free the GError in fuzz_gobex

g_obex_packet_decode() allocates a GError through g_set_error() on four failure
paths and returns NULL from each; the harness frees pkt but never the error. The
'len < 3 + header_offset' path is taken by any input under three bytes, so under
fuzzing this leaks on most inputs rather than in an edge case."

git push -u origin bluez-fuzz-gobex-free-gerror
gh pr create --repo google/oss-fuzz \
  --title "bluez: free the GError leaked by fuzz_gobex on every failed decode" \
  --body-file "$(dirname "$0")/0001-pr-body.md"
