# Finding 0001 — bluez `fuzz_gobex.c` leaks a `GError` on every failed decode

**Status:** confirmed by reading the library source. NOT yet reported upstream.
**Found by:** `S1.LEAK`, on a high-fidelity lift, during the OSS-Fuzz fleet audit.
**Severity:** the harness cannot detect memory leaks in gobex at all (see below).
**Fix:** one line.

## The harness

`oss-fuzz/projects/bluez/fuzz_gobex.c`:

```c
GObexPacket *pkt;
GError *err = NULL;
pkt = g_obex_packet_decode(data, size, 0, G_OBEX_DATA_REF, &err);
if (pkt != NULL) {
  g_obex_packet_encode(pkt, buf, sizeof(buf));
  g_obex_packet_free(pkt);
}
return 0;
```

`pkt` is freed. `err` is not, and there is no `g_error_free` or `g_clear_error` anywhere in
the file.

## Why it leaks

`g_obex_packet_decode` (bluez `gobex/gobex-packet.c`) allocates a `GError` through
`g_set_error` on **four** distinct failure paths and returns NULL:

- `data_policy == G_OBEX_DATA_INHERIT` — "Invalid data policy"
- `len < 3 + header_offset` — "Not enough data to decode packet"
- `packet_len != len` — "Incorrect packet length"
- `parse_headers(..., err)` failing, which reaches `goto failed`

The second is trivially reachable: any input shorter than three bytes takes it. A fuzzer
spends most of its inputs on exactly these paths, so the leak is not an edge case, it is
the common case.

## What makes this worth reporting rather than noting

`projects/bluez/build.sh` line 51:

```sh
echo "detect_leaks=0" >> $OUT/fuzz_gobex.options
```

**`fuzz_gobex` is the only bluez target with leak detection disabled**, and it is the only
bluez harness that touches a `GError`. The workaround and the defect line up exactly.

The consequence is the part that matters: with `detect_leaks=0`, this target can no longer
report a leak *in gobex itself*. A harness defect has silently removed a whole bug class
from the library's fuzzing coverage. That is the negative-capability argument this project
exists to make, found in the wild rather than argued from a bench.

## Fix

```c
   if (pkt != NULL) {
     g_obex_packet_encode(pkt, buf, sizeof(buf));
     g_obex_packet_free(pkt);
   }
+  if (err != NULL) {
+    g_error_free(err);
+  }
```

With that applied, `S1.LEAK` clears on the same lift — verified, before and after:

```
BEFORE | high_fidelity True | ['S1.LEAK']
AFTER  | high_fidelity True | []
```

The follow-up worth proposing in the same report is removing `detect_leaks=0`, which is
the actual value of the fix: it restores leak detection for gobex.

## Provenance

- Corpus: `github.com/google/oss-fuzz`, shallow clone, `projects/*/*fuzz*.{c,cc}`
- Library source: `github.com/bluez/bluez`, shallow clone, `gobex/gobex-packet.c`
- Gate: `S1.LEAK`, resource `r_err`, storage `out_param`
- Lift: high fidelity, 0 missed calls
