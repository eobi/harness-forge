# B1 — the IR application entry point

**The one abstraction the IR lacked.** Every role it knew -- create, consume, destroy,
query, reset -- is a C-function lifecycle, so CLI applications, GUI applications and mobile
applications were all unreachable for the SAME reason: input does not arrive through an API
call, it arrives through a channel. B1 adds that concept.

## What it is

`hforge/ir.py`: `AppEntry(symbol, channel, header, argv, returns_int)`, carried on a
`HarnessIR` INSTEAD OF an op sequence. An application harness makes no lifecycle claims, so
the create/consume/destroy gates are vacuous on it by design and the certificate says so
rather than pretending.

Three channels, the three shapes a CLI application exposes:

| channel | the target | how bytes arrive |
|---|---|---|
| `buffer` | `f(const char *data, size_t n)` | handed directly |
| `file_arg` | `f(const char *path)` | written to a per-invocation temp file, path passed |
| `argv` | `int main(int argc, char **argv)` | temp file, path in the `@INPUT@` argv slot |

The two path channels write the input to a private `mkstemp` file and `unlink` it on every
exit including the early returns -- a fixed path would leak one input into the next iteration.
This is the exact shape a GUI file-drop and a mobile share-sheet specialise on top of.

## Verified end to end

An emitted `file_arg` harness (`example-file-channel-harness.c`) against a bug-shaped mini CLI
parser: compiled with clang+libFuzzer, ran 153,779 executions through the file channel, and
AddressSanitizer caught a stack-buffer-overflow at the parser's copy site when the input
reached it. The channel genuinely delivers the fuzzer's bytes to the application's parse path;
the harness is not empty.

## What this unblocks

| phase | was blocked on | now |
|---|---|---|
| P5 Windows applications | no app entry point | the concept exists; needs the Windows channel + a VM run |
| P6 GUI | no app entry point | the concept exists; GUI is a file-drop/dialog channel on top |
| P7 mobile applications | no app entry point | the concept exists; intents/share-sheet are channels on top |

## What is next (this is v1: IR + emitter, hand-built AppEntry)

Same stage P3.LIFT started at -- IR and emitter first, producer next.
  1. a PRODUCER that discovers app entries from a codebase (a main(), a parse-file function);
  2. the `stdin` channel (freopen/pipe);
  3. Windows as a channel variant (B2), then GUI (B3) and mobile (B5) channels.
