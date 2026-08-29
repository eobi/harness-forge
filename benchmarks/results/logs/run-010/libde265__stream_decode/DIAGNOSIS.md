# libde265: 14.55 against a gold harness we measured at 14.80

`ours/gold` **0.98x**. The first case in this suite where the gold column is a number this
repository produced rather than one it cites: libde265 ships its own fuzz harness at
`fuzzing/stream_fuzzer.cc`, so it was built with the same compiler, run for the same 600 s,
over the same file list, from a fresh corpus with the same seeds. The comparison differs in
the harness and in nothing else.

## The prediction was wrong, and that is the finding

Before the run I predicted we would land "meaningfully below gold", because our plan calls
`de265_decode` once where gold pumps it:

```c
/* gold */                                  /* ours */
de265_push_data(ctx, data, size, 0, 0);     de265_push_data(h, data, len, 0, 0);
de265_flush_data(ctx);                      de265_flush_data(h);
int more = 1;                               de265_decode(h, &more);
while (more) {                              de265_free_decoder(h);
  de265_decode(ctx, &more);
  while (de265_get_next_picture(ctx)) {}
}
de265_free_decoder(ctx);
```

The pump cost **0.25 points**. Here is why:

| file | ours | gold |
|---|---|---|
| `de265.cc` | 11.74% | **18.66%** |
| `decctx.cc` | 14.66% | 14.91% |
| every other file | identical | identical |
| `cabac.cc` | **0.00%** | **0.00%** |
| `deblock.cc` | **0.00%** | **0.00%** |
| `intrapred.cc` | **0.00%** | **0.00%** |
| `motion.cc` | **0.00%** | **0.00%** |
| `transform.cc` | **0.00%** | **0.00%** |

**The entire H.265 decode core is unreachable for the hand-written harness too.** The
arithmetic decoder, the deblocking filter, intra prediction, motion compensation, the
transform — nothing runs, for either of us, across 1.8 million executions each.

libFuzzer cannot synthesise a valid HEVC bitstream from an empty corpus in ten minutes.
Both harnesses spend the whole budget in NAL parsing and never present the decoder with a
picture to decode. **The harness structure is not the bottleneck on this target. The input
is.**

The real 6.9-point gap in `de265.cc` is the API surface: gold calls three
`de265_set_parameter_*` functions and drains pictures with `de265_get_next_picture`, and we
call neither. That is `P3.OPTION_SETTER` — already recorded from yajl — and the drain half
of `P3.DRIVE_LOOP`. Both are real and both are worth fixing. Neither is what I expected to
be looking at.

## What this changes

`P3.DRIVE_LOOP` is **not** urgent for this target, and the measurement says so plainly:
adding the pump without seeds would buy a fraction of a point. What would move this number
is the round-trip seed synthesis on the roadmap — feed the decoder streams the project's own
encoder produced — and that is now the highest-value item for any codec target rather than
an item on a list.

A cited gold figure could not have established this. The absolute 14.80% would have looked
like a broken measurement or a bad denominator. Measuring it here made it a fact about the
target: **at 600 s from an empty corpus, this is simply where a HEVC decoder harness gets
to**, however carefully it is written.
