"""One GUI campaign: mutate a seed, open it, record what the target did, repeat.

Run inside the lab image, with the repository mounted at /hf:

    docker run --rm -v "$PWD:/hf:ro" -v "$PWD/benchmarks/gui:/lab" hforge-gui \\
        bash -lc 'source /lab/session.sh && python3 /lab/campaign.py --app eog --n 12'

THE ORDER HERE IS THE RESULT OF P6.TERM, not a preference. Walking the accessibility tree
makes the target service every request -- measured at eight times the CPU, and it then never
goes quiet -- so a driver that polls the tree while waiting for quiescence calls every input
a hang. Wait without looking, then look once.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/hf")
from hforge.gui.linux_atspi import (                              # noqa: E402
    QUIESCE_INTERVAL_S, QUIESCE_POLLS, WINDOW_DEADLINE_S,
    GuiOutcome, TerminationReason, classify,
)

import gi                                                          # noqa: E402
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi                                    # noqa: E402


def walk(node, out=None):
    out = out if out is not None else []
    try:
        out.append((node.get_role_name(), node.get_name()))
        for i in range(node.get_child_count()):
            walk(node.get_child_at_index(i), out)
    except Exception:                                              # noqa: BLE001
        pass
    return out


def apps(match: str):
    found = []
    for i in range(Atspi.get_desktop_count()):
        desk = Atspi.get_desktop(i)
        for j in range(desk.get_child_count()):
            a = desk.get_child_at_index(j)
            try:
                if a and a.get_name() and match in a.get_name().lower():
                    found.append(a)
            except Exception:                                      # noqa: BLE001
                pass
    return found


def ticks(pid: int) -> int:
    try:
        st = open(f"/proc/{pid}/stat").read().split()
        return int(st[13]) + int(st[14])
    except Exception:                                              # noqa: BLE001
        return -1


def first_button(node):
    try:
        if node.get_role_name() == "push button":
            return node
        for i in range(node.get_child_count()):
            b = first_button(node.get_child_at_index(i))
            if b is not None:
                return b
    except Exception:                                              # noqa: BLE001
        pass
    return None


COVERAGE = bool(os.environ.get("HF_GUI_COVERAGE"))
COV_DIR = Path(os.environ.get("HF_GUI_COV_DIR", "/tmp/cov"))
COV_BIN = os.environ.get("HF_GUI_COV_BIN", "")
LLVM = os.environ.get("HF_LLVM_BIN", "/usr/lib/llvm-14/bin")


def _regions_covered() -> int:
    """Regions this input reached, or -1 if coverage is unavailable.

    Counting REGIONS rather than lines: a line can be covered by any path through it, while
    a region distinguishes the branches, which is what a guided campaign is choosing
    between. Returns a count, not a percentage -- the denominator is fixed across a run and
    a ratio only adds a division.
    """
    raws = sorted(COV_DIR.glob("*.profraw"))
    if not raws or not COV_BIN:
        return -1
    merged = COV_DIR / "merged.profdata"
    try:
        r = subprocess.run([f"{LLVM}/llvm-profdata", "merge", "-sparse",
                            *[str(x) for x in raws], "-o", str(merged)],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            return -1
        out = subprocess.run([f"{LLVM}/llvm-cov", "export", "-summary-only", COV_BIN,
                              f"-instr-profile={merged}"],
                             capture_output=True, text=True, timeout=120)
        if out.returncode != 0:
            return -1
        data = json.loads(out.stdout)
        return int(data["data"][0]["totals"]["regions"]["covered"])
    except Exception:                                              # noqa: BLE001
        return -1


def _close_window(pid: int) -> None:
    """Ask the target's window to close, the way a user would.

    `xdotool search --pid` finds the window without a window manager, which matters because
    the campaign runs on a bare Xvfb display. ctrl+w is the close accelerator in every GTK
    viewer here; a target that ignores it is still terminated by the caller.
    """
    try:
        out = subprocess.run(["xdotool", "search", "--pid", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout.split()
        if not out:
            return
        # ctrl+q BEFORE ctrl+w, and to EVERY window this process owns.
        #
        # A refused input leaves an error dialog on top. ctrl+w closes that dialog and the
        # application keeps running, so it never reaches exit() and never writes its
        # profile -- which made coverage unreadable for exactly the inputs a campaign most
        # wants to measure. ctrl+q quits the application whatever is focused.
        for win in reversed(out):
            for key in ("ctrl+q", "ctrl+w"):
                subprocess.run(["xdotool", "key", "--window", win, key],
                               capture_output=True, timeout=5)
    except Exception:                                              # noqa: BLE001
        pass


def run_one(app: str, path: str, budget: float):
    """Open one file and decide what happened. One process, one verdict."""
    argv = [app, "--new-instance", path] if app == "eog" else [app, path]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()

    # 1. WINDOW: poll with a deadline. It maps in 0.11-0.55 s measured; a fixed sleep is
    #    both far too slow and unable to tell "not yet" from "never".
    window_ms = None
    while time.time() - t0 < min(WINDOW_DEADLINE_S, budget):
        if p.poll() is not None:
            break
        if apps(app):
            window_ms = (time.time() - t0) * 1000.0
            break
        time.sleep(0.05)

    # 2. QUIESCENCE, WITHOUT LOOKING. This is the step the tree walk destroys.
    term = TerminationReason.DEADLINE
    prev, stable = -1, 0
    while time.time() - t0 < budget:
        if p.poll() is not None:
            break
        c = ticks(p.pid)
        if c == prev and c > 0:
            stable += 1
            if stable >= QUIESCE_POLLS:
                term = TerminationReason.QUIESCED
                break
        else:
            stable = 0
        prev = c
        time.sleep(QUIESCE_INTERVAL_S)

    # 3. NOW look, once.
    exited = p.poll() is not None
    tree = [n for a in apps(app) for n in walk(a)]

    # 4. Liveness only if it can change the answer: an error element already explains the
    #    window, and acting on the target costs it CPU we have just finished waiting out.
    serviced, action_ms = None, None
    if not exited and tree:
        from hforge.gui.linux_atspi import error_nodes
        if not error_nodes(tree):
            t1 = time.time()
            for a in apps(app):
                b = first_button(a)
                if b is not None:
                    try:
                        b.do_action(0)
                        serviced = True
                    except Exception:                              # noqa: BLE001
                        serviced = False
                    break
            action_ms = (time.time() - t1) * 1000.0
            if serviced:
                serviced = bool([n for a in apps(app) for n in walk(a)])

    v = classify(tree=tree, exited=exited, window_ms=window_ms,
                 serviced_action=serviced, action_ms=action_ms, termination=term)

    # A CLEAN EXIT, SO AN INSTRUMENTED BUILD CAN WRITE ITS PROFILE.
    #
    # clang emits coverage in an atexit handler. `terminate()` sends SIGTERM, which skips
    # it, so the .profraw is created at startup and stays ZERO BYTES -- and a zero-byte
    # profile looks exactly like "this input covered nothing". Closing the window instead
    # lets GTK return from main and the counters are written.
    #
    # Costs nothing when the target is not instrumented: it is one xdotool call, and the
    # terminate() below still runs if the window refuses to close.
    if COVERAGE:
        _close_window(p.pid)
        try:
            p.wait(timeout=6)
        except Exception:                                          # noqa: BLE001
            pass
        # WAIT FOR THE PROFILE, DO NOT ASSUME IT.
        #
        # The counters are written as the process leaves, which happens slightly after
        # wait() returns. Reading immediately found no file, reported -1, and the next
        # input deleted the profile before anyone looked again -- so coverage was always
        # unavailable while the mechanism itself worked perfectly when called by hand.
        for _ in range(40):
            if any(f.stat().st_size > 0 for f in COV_DIR.glob("*.profraw")):
                break
            time.sleep(0.05)
    p.terminate()
    try:
        p.wait(timeout=5)
    except Exception:                                              # noqa: BLE001
        p.kill()
    for _ in range(80):                       # let it leave the tree before the next input
        if not apps(app):
            break
        time.sleep(0.05)
    return v


def mutate_naive(seed: bytes, rng: random.Random) -> tuple:
    """Byte flips. Almost always breaks the signature or the header, so the campaign
    measures the parser's first check over and over."""
    b = bytearray(seed)
    for _ in range(rng.randint(1, 8)):
        if not b:
            break
        b[rng.randrange(len(b))] = rng.randrange(256)
    if rng.random() < 0.25 and len(b) > 32:
        b = b[: rng.randrange(16, len(b))]
    return bytes(b), "flip"


def mutate(seed: bytes, rng: random.Random, aware: bool = True) -> tuple:
    """Pick the mutator by what the seed IS, not by what the campaign hopes it is.

    Dispatching on the format removes a confound in this track's own numbers. eog was
    campaigned with the PNG mutator and evince with plain byte flips, and the two were then
    compared: 29% of PNG mutations got past the front door against 97% of PDF ones. That
    varies the MUTATOR and the FORMAT together, so it cannot say whether evince is more
    tolerant or the mutation was gentler.

    Falls back to byte flips for any format without a grammar here, and says so in the
    label, so a run is never silently less structured than it appears.
    """
    if not aware:
        return mutate_naive(seed, rng)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from mutate_pdf import looks_like_pdf, mutate as pdf_mutate
        if looks_like_pdf(seed):
            return pdf_mutate(seed, rng)
    except Exception:                                              # noqa: BLE001
        pass
    try:
        from mutate_png import mutate as png_mutate
        return png_mutate(seed, rng)
    except Exception:                                              # noqa: BLE001
        return mutate_naive(seed, rng)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="eog")
    ap.add_argument("--seed-file", default="")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--budget", type=float, default=8.0)
    ap.add_argument("--rng", type=int, default=1337)
    ap.add_argument("--results", default="",
                    help="append a JSON row here so the GUI table can be regenerated")
    ap.add_argument("--naive", action="store_true",
                    help="byte flips instead of the structure-aware mutator, for comparison")
    a = ap.parse_args()

    seed_path = a.seed_file
    if not seed_path:
        cands = sorted(Path("/usr/share/icons").rglob("*.png"))
        seed_path = str(next(p for p in cands if p.stat().st_size > 2000))
    seed = Path(seed_path).read_bytes()
    rng = random.Random(a.rng)
    work = Path("/tmp/gui-campaign")
    work.mkdir(exist_ok=True)
    ext = Path(seed_path).suffix or ".bin"

    # ONE DIRECTORY PER INPUT, and this is the isolation boundary that actually matters.
    #
    # eog loads the CONTAINING FOLDER as an image collection, so with every input written
    # to one directory each run could see every input before it: node counts climbed by
    # exactly one per input, and a crash on input 40 might have been caused by input 3
    # still sitting in the folder. Measured:
    #
    #     same directory        117, 118, 119, 120
    #     directory per input   117, 117, 117, 117
    #
    # A fresh process, a fresh session bus and a fresh HOME all failed to fix this. Only
    # the directory did. For a library harness the process is the boundary; for a GUI
    # target the filesystem around the input is part of the input.
    def slot(i: int) -> Path:
        d = work / f"in{i:04d}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # A POSITIVE CONTROL FIRST. Without it a campaign that reports nothing cannot be
    # distinguished from a campaign that never ran -- the failure this programme keeps
    # finding in its own tools.
    ctl = slot(-1) / f"control{ext}" if False else (work / "control" / f"control{ext}")
    ctl.parent.mkdir(parents=True, exist_ok=True)
    ctl.write_bytes(seed)
    cv = run_one(a.app, str(ctl), a.budget)
    print(f"  control        {cv.outcome.value:12} nodes={cv.nodes:3} "
          f"term={cv.termination.value if cv.termination else '-'}")
    if cv.outcome is not GuiOutcome.ACCEPTED:
        print("  REFUSING TO RUN: the unmodified seed did not open cleanly, so a null "
              "result from this campaign would mean nothing.", file=sys.stderr)
        return 1

    # AND A NEGATIVE CONTROL, which the positive one does not replace.
    #
    # The positive control proves the pipeline can open a file. It says nothing about
    # whether the oracle can SEE a refusal, and without that "12 of 12 accepted" is
    # indistinguishable from an oracle that never fires. evince accepted every mutated PDF
    # on its first run here, which is plausible -- poppler is famously tolerant -- and
    # would look identical to a broken detector.
    neg = work / "negative" / f"garbage{ext}"
    neg.parent.mkdir(parents=True, exist_ok=True)
    neg.write_bytes(b"this is not a valid file of any kind, by construction")
    nv = run_one(a.app, str(neg), a.budget)
    print(f"  neg control    {nv.outcome.value:12} nodes={nv.nodes:3} "
          f"term={nv.termination.value if nv.termination else '-'}")
    oracle_live = nv.outcome is GuiOutcome.REJECTED
    if not oracle_live:
        print("  WARNING: the oracle did not flag deliberate garbage. Every 'accepted' "
              "below is therefore unproven -- it may be the detector, not the target.",
              file=sys.stderr)

    tally: dict = {}
    kinds: dict = {}
    corpus: list = []          # inputs that reached a region nothing else did
    best_regions = -1          # -1 until coverage is read; never negative after
    for i in range(a.n):
        f = slot(i) / f"input{ext}"
        # COVERAGE-GUIDED, WHEN COVERAGE IS AVAILABLE. Mutate the best input seen so far
        # rather than always the original seed, which is the difference between a random
        # walk and a search. Without instrumentation `corpus` never grows past the seed and
        # the loop behaves exactly as before.
        parent = corpus[rng.randrange(len(corpus))] if corpus else seed
        data, what = mutate(parent, rng, aware=not a.naive)
        kinds[what] = kinds.get(what, 0) + 1
        f.write_bytes(data)
        if COVERAGE:
            for old_raw in COV_DIR.glob("*.profraw"):
                old_raw.unlink(missing_ok=True)
        v = run_one(a.app, str(f), a.budget)
        tally[v.outcome.value] = tally.get(v.outcome.value, 0) + 1

        gained = ""
        if COVERAGE:
            n = _regions_covered()
            if n > best_regions:
                # KEEP IT. A mutation that reached a region nothing else did is the only
                # kind worth breeding from; the rest are noise however they were labelled.
                corpus.append(data)
                gained = f"  +{n - best_regions} regions" if best_regions >= 0 else ""
                best_regions = n
        mark = "  <-- FINDING" if v.is_finding() else ""
        print(f"  input {i:03d}  {what:11} {v.outcome.value:12} nodes={v.nodes:3} "
              f"term={v.termination.value if v.termination else '-':10} "
              f"{f.stat().st_size:>6}B{gained}{mark}")
    acc = tally.get("accepted", 0)
    if COVERAGE:
        print(f"\n  coverage-guided: corpus grew to {len(corpus)} input(s), "
              f"{best_regions} regions covered")
    print(f"\n  {a.n} inputs ({'byte flips' if a.naive else 'structure-aware'}): "
          + ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    print(f"  past the front door: {acc}/{a.n} = {100.0*acc/max(1,a.n):.0f}% accepted")
    findings = tally.get("crashed", 0) + tally.get("unresponsive", 0)
    print(f"  findings: {findings}   (a refusal is the target working, not a finding)")

    # A ROW, so the table can be regenerated rather than hand-maintained. Same discipline as
    # the C track: a table nobody can regenerate is a table nobody can check.
    if a.results:
        import json
        row = {
            "app": a.app,
            "format": ext.lstrip("."),
            # WHAT WAS ACTUALLY DONE, not what was asked for. The PNG-aware mutator falls
            # back to raw byte flips on any format it cannot parse, so a row that reported
            # the requested mode would claim structure-awareness a PDF run never had.
            "mutator": ("byte-flip" if a.naive
                        else ("raw-fallback" if set(kinds) <= {"raw", "flip"}
                              else "structure-aware")),
            "mutations": kinds,
            "inputs": a.n,
            "budget_s": a.budget,
            "rng": a.rng,
            "control": cv.outcome.value,
            "control_nodes": cv.nodes,
            "neg_control": nv.outcome.value,
            "oracle_live": oracle_live,
            "accepted": tally.get("accepted", 0),
            "rejected": tally.get("rejected", 0),
            "unresponsive": tally.get("unresponsive", 0),
            "crashed": tally.get("crashed", 0),
            "no_window": tally.get("no_window", 0),
            "past_front_door_pct": round(100.0 * acc / max(1, a.n), 1),
            "findings": findings,
        }
        with open(a.results, "a") as fh:
            fh.write(json.dumps(row) + "\n")
        print(f"  row appended to {a.results}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
