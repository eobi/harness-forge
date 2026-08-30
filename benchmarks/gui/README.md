# The GUI lab

A reproducible Ubuntu image and two probes that establish, on a real GTK application, the
three things the Linux GUI driver is built on. Everything here runs in a container, so the
findings do not depend on a particular desktop.

```bash
docker build -t hforge-gui benchmarks/gui
docker run --rm -v "$PWD/benchmarks/gui:/lab" hforge-gui bash /lab/discriminate.sh
docker run --rm -v "$PWD/benchmarks/gui:/lab" hforge-gui bash /lab/liveness.sh
```

## What they measure

`discriminate.sh` opens a graded PNG corpus in `eog`, one isolated session each, and reads
the accessibility tree:

| input | nodes | verdict |
|---|---:|---|
| valid | 122 | accepted |
| truncated (400 of 2055 bytes) | 122 | accepted |
| header only | 133 | rejected — `info bar 'Error'` |
| bad magic | 133 | rejected |
| bad CRC | 133 | rejected |
| garbage | 133 | rejected |

`truncated` is accepted because **the target is right to accept it** — libpng renders the
partial image it has. An oracle judged only on the inputs it flags is not being judged.

`liveness.sh` performs a real accessibility action and re-enumerates. Both a valid and a
rejected input return in about 29 ms with the tree intact, which is what distinguishes
"refused this input" from "hung" **from outside the process** — an oracle independent of the
window behaviour that produced the false reading this track began with.

## A second toolkit, which is what caught the defect

`toolkits.sh` repeats the exercise with `evince` on a ghostscript-produced PDF corpus:

| input | nodes | verdict |
|---|---:|---|
| valid | 132 | accepted |
| bad header | 132 | accepted — poppler tolerates it |
| truncated | 141 | rejected — `alert 'dialog-error-symbolic'` **and** `info bar 'Error'` |
| garbage | 141 | rejected — both spellings |

evince emits **both** spellings, so the role family holds. But it also raises `alert
'dialog-warning-symbolic'` for a malformed file it goes on to **open**, and matching the
role alone classified that as a rejection — an input that was processed, reported as one
that was refused. That is the mirror of the false hang this track began with, and only a
second toolkit exposed it.

## P6.TERM: the observer changes the observed

`observer-effect.sh` answers "when is one GUI input finished?" and finds that the two
obvious signals cannot be used together.

| condition | CPU quiesces | total ticks |
|---|---|---:|
| CPU polled alone | 0.96 s | 26 |
| CPU polled **while walking AT-SPI** | **never** | **201** |
| CPU polled alone (repeat) | 0.92 s | 18 |

Walking the accessibility tree makes the target service every request, so it burns eight
times the CPU and never settles. A driver that polls the tree in a loop **and** uses CPU
quiescence to decide an input is finished therefore reports **every input as a hang** — a
third way to manufacture a false hang, after the error-bar-as-hang and the
warning-as-rejection this lab already found.

The rule that follows: **wait for quiescence without looking, then enumerate once.** Tree
stability stays as the fallback for targets whose CPU never settles — an animated viewer, a
spinner — where quiescence is not available at any price. Whichever fired is recorded on the
verdict, because a result reached by deadline means something different from one that
settled.

## The isolation boundary is the DIRECTORY

`campaign.py` runs a seeded campaign: a positive control first, then mutated inputs, one
verdict each. Building it surfaced the least obvious result in this lab.

Node counts climbed by exactly one per input — 117, 118, 119, 120 — and the cause was not
stale processes, a shared session bus, or a shared `HOME`. All three were eliminated and the
drift survived every one. eog **loads the containing folder as an image collection**, so
with all inputs written to one directory, every run could see every input before it.

| | inputs 0–3 |
|---|---|
| same directory | 117, 118, 119, 120 |
| one directory per input | 117, 117, 117, 117 |

The drifting count was the symptom; the disease was that **the inputs were not independent**.
A crash attributed to input 40 could have been caused by input 3 still sitting in the folder.

For a library harness the process is the isolation boundary. **For a GUI target the
filesystem around the input is part of the input**, and nothing about process, session or
home isolation implies it.

## The campaign refuses to start without a positive control

If the unmodified seed does not open cleanly, the run stops. A campaign that reports nothing
is worth nothing unless something establishes that it would have reported something — the
failure mode this programme has now found four times in its own tools.

## Two things that cost time, recorded so they do not again

**`XDG_RUNTIME_DIR` is not optional.** Without it GTK stalls before mapping and says
nothing: the process stays alive, exits nothing, logs nothing. It reads as "GTK does not
work headlessly", which is false.

**Poll for the window; never sleep.** It maps in 0.20–0.55 s, and the tree keeps growing
afterwards — the error element arrives *after* the window. A driver that stops at the first
showing node reports every malformed file as accepted, which is how a broken oracle looks
like a clean result.
