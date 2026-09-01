# Coverage feedback for the GUI track

Established 2026-09-01. The track's stated gap since it began: GUIFUZZ++ is grey-box and we
were blind, so a campaign could not tell a productive mutation from a wasted one and
`P6.TERM` — coverage-guided termination — had no input to work from.

It now works. **25.64% region coverage from a single image open**, read back from a running
desktop application.

## The chain

```
clang-instrumented eog          CC=clang CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
  ↓  open a mutated file        LLVM_PROFILE_FILE=/tmp/cov/eog-%p.profraw
  ↓  wait for quiescence        the existing accessibility oracle, unchanged
  ↓  xdotool key ctrl+w         a CLEAN EXIT, which is the whole trick
  ↓  .profraw written           552 KB per run
llvm-profdata merge → llvm-cov report
```

## Why the obvious approaches fail, and what to do instead

**A killed process writes nothing.** clang emits the profile in an `atexit` handler. The
campaign's normal shutdown is `SIGTERM`, which skips it, so the `.profraw` is created at
startup and stays **zero bytes**. That zero looks exactly like "this input covered nothing".

**Continuous mode is not available.** `LLVM_PROFILE_FILE=...%c` writes counters live and
would be the clean answer. It needs clang 17; jammy ships 14.

**An `LD_PRELOAD` flush shim cannot work either, and the reason is worth recording.** A
constructor that installs a `SIGUSR1` handler calling `__llvm_profile_write_file()` looks
right and fails twice over: linking the symbol gives `undefined symbol` at load, and
resolving it with `dlsym(RTLD_DEFAULT, ...)` silently returns NULL. Checking with `nm`
explains both —

```
nm /tmp/tiny | grep llvm_profile_write_file
0000000000002 3f4 t __llvm_profile_write_file      ← lowercase t: LOCAL
```

compiler-rt marks the profile writer **local**, so `-Wl,--export-dynamic` does not export it
and nothing outside the binary can ever call it. Rebuilding eog with `--export-dynamic` was
wasted effort, and the `nm` check is what should have come first.

**So: make the application exit.** `xdotool key --window <id> ctrl+w` closes eog's window,
GTK returns from `main`, and the profile writes normally. The window id comes from
`xdotool search --pid`, which works without a window manager.

## What this enables and what it does not

**Enables:** coverage-guided GUI campaigns. A mutation that raises coverage is worth keeping;
one that does not is not. That is the input `P6.TERM` needs.

**Does not:** answer whether the campaign finds bugs. 7,000 blind inputs across eog and
evince found none, and coverage feedback changes the search, not the oracle.

**A caution on the number.** 25.64% is coverage of **eog's own sources**, not of the image
decoder. Most of what an image viewer does on a corrupt PNG happens inside gdk-pixbuf and
libpng, which are not instrumented here. Coverage of the application is a proxy for depth
reached, and a loose one.
