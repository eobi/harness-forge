# yajl: 65.12 against gold 69.1 — where the 4 points are

This is the one run-009 case where the engine sits **behind** both gold (0.94x) and the
cited QuartetFuzz figure (79.87). Written down here rather than in a commit message
because the fix has to wait for the run to finish — the container reads `hforge/` live,
so editing the producer mid-run would change what the remaining cases measure.

## What was measured

```
yajl.c          45.26%     <- the deficit is almost entirely here
yajl_alloc.c   100.00%
yajl_buf.c      91.84%
yajl_lex.c      77.20%
yajl_parser.c   52.46%
TOTAL           65.12%
```

104,816,902 executions in 600 s — an order of magnitude more than any other case in this
run. That is not throughput to be proud of. It means nearly every input is rejected
immediately and the harness never gets far into the library.

## The uncovered functions, by line count

| function | lines | covered | reached only by |
|---|---|---|---|
| `yajl_render_error_string` | 72 | 0.00% | `yajl_get_error` on the failure branch |
| `yajl_parse_integer` | 24 | 0.00% | an integer literal wide enough to need it |
| `yajl_config` | 19 | 0.00% | an explicit option-setting call |
| `yajl_status_to_string` | 15 | 0.00% | error reporting |
| `yajl_get_bytes_consumed` | 4 | 0.00% | error reporting |
| `yajl_get_error` / `yajl_free_error` | 6 | 0.00% | the failure branch |

The harness we emitted is correct and complete as a *lifecycle*:

```c
hf_r_h = yajl_alloc(0, 0, 0);
yajl_parse(hf_r_h, data, size);
yajl_complete_parse(hf_r_h);
yajl_free(hf_r_h);
```

Create, consume, finish, destroy — every gate passes, and nothing here is wrong. The
coverage it does not get is coverage that **no correct lifecycle reaches**.

## Two shapes the producer does not model, neither of them yajl-specific

### 1. Error accessors are finishers on the failure branch

```c
YAJL_API unsigned char * yajl_get_error(yajl_handle hand, int verbose,
                                        const unsigned char *jsonText, size_t jsonTextLen);
YAJL_API void yajl_free_error(yajl_handle hand, unsigned char *str);
```

Roughly a hundred lines of yajl — the error renderer, the status stringifier, the
byte-offset accessor — are reachable **only** after a parse fails and the caller asks why.
A fuzzer drives the failure path constantly; the harness simply never asks.

`_finisher_for` already models finishers, but it selects query functions that run on the
success path. This is a different shape: an accessor **gated on the consuming call
returning non-OK**, usually paired with a matching free.

```c
yajl_status st = yajl_parse(h, data, size);
if (st != yajl_status_ok) {
    unsigned char *e = yajl_get_error(h, 1, data, size);
    yajl_free_error(h, e);          /* the pairing is not optional: it leaks otherwise */
}
```

The pairing matters twice over. Without `yajl_free_error` the harness leaks on every
failing input, and under LeakSanitizer every finding would be the harness's own — which is
exactly the class of defect gate S1 exists to block. So this cannot be bolted on as "call
more functions"; the free has to come with it or the plan must be refused.

Generalisation: a function whose name matches `*_get_error` / `*_last_error` /
`*_error_string` / `*_strerror`, taking the handle and returning a string or struct, is an
error accessor. If a same-family `*_free_error` / `*_error_free` exists it is its
destructor, and S1's create-once-destroy-once obligation applies to the returned pointer.

### 2. Varargs option setters between create and consume

```c
YAJL_API int yajl_config(yajl_handle h, yajl_option opt, ...);
```

`yajl_allow_comments`, `yajl_allow_trailing_garbage`, `yajl_allow_multiple_values`,
`yajl_allow_partial_values`, `yajl_dont_validate_strings` — each unlocks lexer and parser
paths that are dead with the defaults. The engine has `_CONFIG_INIT` handling, but it
models a **config struct** filled before construction, not an `(handle, enum, value)`
setter called after it.

This one needs care rather than enthusiasm. The options are not free-floating knobs: a
harness that flips `yajl_dont_validate_strings` is testing a different contract, and a
certificate has to say which configuration it certified. The honest form is one plan per
configuration, each certified separately and each recording its options in the IR, not one
harness that sets everything.

## Why this is the argument for the repair loop

Both shapes were found by reading a coverage report next to a harness and asking which
functions no correct lifecycle can reach. That is a mechanical question, and roadmap item 3
— the measurement-driven repair loop — is exactly the machine that asks it: take the
uncovered function list, ask what call sequence would reach each one, propose a plan
extension, and re-measure.

The engine found this deficit in its own output. It just needed a human to read the report.
