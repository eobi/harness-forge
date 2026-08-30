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

## Two things that cost time, recorded so they do not again

**`XDG_RUNTIME_DIR` is not optional.** Without it GTK stalls before mapping and says
nothing: the process stays alive, exits nothing, logs nothing. It reads as "GTK does not
work headlessly", which is false.

**Poll for the window; never sleep.** It maps in 0.20–0.55 s, and the tree keeps growing
afterwards — the error element arrives *after* the window. A driver that stops at the first
showing node reports every malformed file as accepted, which is how a broken oracle looks
like a clean result.
