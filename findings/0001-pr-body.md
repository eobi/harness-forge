### Summary

`fuzz_gobex.c` passes `&err` to `g_obex_packet_decode()` but never releases it. On every
failed decode the `GError` is leaked.

### Why it leaks

`g_obex_packet_decode()` (bluez `gobex/gobex-packet.c`) allocates a `GError` via
`g_set_error()` on four failure paths and returns `NULL` from each:

- `data_policy == G_OBEX_DATA_INHERIT` — "Invalid data policy"
- `len < 3 + header_offset` — "Not enough data to decode packet"
- `packet_len != len` — "Incorrect packet length"
- `parse_headers(..., err)` failing, reaching `goto failed`

The second is taken by any input shorter than three bytes, so under fuzzing this is the
common path rather than an edge case. The harness frees `pkt` but contains no
`g_error_free()` or `g_clear_error()`.

### Fix

```c
   if (pkt != NULL) {
     g_obex_packet_encode(pkt, buf, sizeof(buf));
     g_obex_packet_free(pkt);
   }
+  if (err != NULL) {
+    g_error_free(err);
+  }
```

### Possible follow-up (not included here)

`projects/bluez/build.sh` sets `detect_leaks=0` for `fuzz_gobex`, and it is the only bluez
target that does — as well as the only bluez harness that touches a `GError`. With this
leak fixed it may be possible to drop that line and restore leak detection for gobex,
which is the real value of the change.

I have deliberately left that out of this PR: I have not built and run the target under
LeakSanitizer, so I cannot claim no other leaks remain. Happy to follow up if maintainers
would like it tested.

### How this was found

Static harness analysis — a resource-lifetime check over the lifted harness, flagging an
out-parameter that is still live when the entry point returns. Confirmed by reading
`gobex-packet.c` before filing.
