# GUI ranking

Every figure here was produced by this repository, in the container defined by
`benchmarks/gui/Dockerfile`, on one machine. There is **no cited column**: no published
desktop-GUI fuzzing work reports the quantity this table reports, because the nearest
comparable system uses a different bug definition (see below).

Regenerate:

```
python3 benchmarks/gui/rank_gui.py benchmarks/gui/results/*.jsonl --write
```

## What the columns mean

| column | meaning |
|---|---|
| **control** | the unmodified seed. If it does not open cleanly the campaign refuses to run, because a null result from a broken campaign is indistinguishable from a clean one |
| **past the parser** | inputs the target ACCEPTED — it opened the file rather than refusing it. This is a measure of the mutator, not of the target |
| **rejected** | the target refused the input and said so. **A pass, not a finding** |
| **findings** | crashes and genuine hangs only |

`rejected` is the column most likely to be misread. An application that opens a window,
refuses a malformed file and keeps the window up is indistinguishable from a hang unless
something reads the screen; an earlier driver called five of six such inputs UNRESPONSIVE.
A refusal is the target working correctly.

## Why there is no comparison column

The nearest published system, GUIFUZZ++ (ASE 2025), fuzzes **GUI interactions** — clicks,
scrolls, key presses — and defines a bug by process signal or AddressSanitizer report. This
track fuzzes **the file a GUI application opens** and defines outcomes by the accessibility
tree. The two measure different things on different surfaces, and putting them in one table
would imply a comparison that does not exist.

What GUIFUZZ++ has and this does not: **coverage feedback**. They are grey-box through
AFL++; this campaign mutates blind. That is a real gap and it is not hidden by the absence
of a column.

<!-- GUIBENCH:BEGIN -->

| app | format | mutator | n | control | past the parser | rejected | findings |
|---|---|---|---:|---|---:|---:|---:|
| eog | png | byte-flip | 12 | accepted (117 nodes) | **0.0%** | 12 | 0 |
| eog | png | structure-aware | 12 | accepted (117 nodes) | **25.0%** | 9 | 0 |
| evince | pdf | raw-fallback | 12 | accepted (132 nodes) | **100.0%** | 0 | 0 |

Sources: gui-001. **findings** counts only crashes and genuine hangs — a target refusing an input is the target working, and is never counted here.

<!-- GUIBENCH:END -->

## Reading the current rows

**eog, 0% against 25%** is the mutator, not the target: byte flips break the PNG signature
so nothing reaches the decoder, while keeping the chunk skeleton and recomputing the CRC
gets a quarter of inputs past it.

**evince at 100% is a real property of poppler, and the negative control is why we can say
so.** Random byte flips in a PDF mostly land in content streams and metadata, and poppler
reconstructs the xref and tolerates broken objects, so almost anything still opens. On its
own, "12 of 12 accepted" is indistinguishable from an oracle that never fires — which is
exactly why every campaign now runs deliberate garbage through the target first and records
whether the oracle flagged it. Both applications flagged it, so the acceptances are real.

**`raw-fallback` is not `structure-aware`.** The PNG-aware mutator cannot parse a PDF and
falls back to byte flips, and the row records what was actually done rather than what was
asked for. A PDF-aware mutator does not exist yet, so the evince row measures poppler's
tolerance and not the mutator's quality.

**Zero findings everywhere.** Both targets are mature and heavily fuzzed; this is the
expected result and it is an earned one — the positive control proves a file can be opened,
the negative control proves a refusal can be seen, and a quarter of the eog inputs reached
the decoder.

## Protocol

| | |
|---|---|
| session | private display, private session bus, `XDG_RUNTIME_DIR` set |
| isolation | **one directory per input** — measured; the filesystem around the input is part of the input |
| termination | wait for CPU quiescence **without polling**, then enumerate once |
| oracle | accessibility-tree error roles as a family, with warnings excluded |
| budget | seconds per input, stated per row |
