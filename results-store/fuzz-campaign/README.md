# Fuzzing the generated harnesses with NemesisForge

**651,343,964 executions across 83 built harnesses**, 30s budget each,
generated 2026-09-01T14:14:23Z. Raw: `campaign-2026-09-01.json`, `campaign-2026-09-01.jsonl`.

harness-forge PROPOSES and CERTIFIES; NemesisForge HUNTS. This is the join run at corpus
scale: every generated harness that builds gets a real libFuzzer campaign, and what each one
actually did is written down.

| library | campaigns that ran | executions | peak coverage |
|---|---|---|---|
| brotli | 10/10 | 54,605,596 | 808 |
| cjson | 10/10 | 70,907,928 | 226 |
| expat | 0/10 | 0 | 0 |
| jansson | 10/10 | 193,792,270 | 49 |
| jbig2dec | 8/8 | 76,908,815 | 41 |
| lcms2 | 4/10 | 0 | 0 |
| libwebp | 10/10 | 44,097,300 | 472 |
| libyaml | 10/10 | 8 | 0 |
| yajl | 10/10 | 85,893,832 | 53 |
| zlib | 10/10 | 125,134,914 | 387 |
| zopfli | 1/1 | 3,301 | 511 |

## Crashes: 4. Findings promoted: 0.

Every crash was refused by the oracle. That is the separation working rather than a
disappointing result: a crash is a CANDIDATE, and a generated harness that violates an API
contract is not a library bug. Earlier today four such crashes WERE certified as findings,
which is the failure this engine exists to prevent; both halves of that are now fixed
(a producer rule here, a deterministic artifact filter in NemesisForge).

## What this run says about the HARNESSES, which is the point

Three numbers are worth more than the execution total:

**libyaml ran 10 campaigns and executed 8 times in total.** Every harness crashes after 2
executions at zero coverage. These are bad harnesses -- the same contract-violation shape as
the `yajl_free_error` family, which means the deallocator rule added today is too narrow.
An open defect in this engine, recorded as such.

**jansson executed 193,792,270 times and peaked at coverage 49.** It compiles, runs, and
touches almost nothing. "Executes" and "reaches something" are different claims, and only
measuring both tells them apart.

**16 of 99 campaigns did not build** (expat 10, lcms2 6). Not a target problem.

## The field that makes this readable: `fuzz_ran`

Without it, a campaign where the fuzz step was never reached is indistinguishable from one
that ran and executed nothing -- both leave the counters absent and both report "built".
An earlier run of this same sweep reported build failures as successful builds for exactly
that reason, and it was invisible until this field existed.

## Caveat

30 seconds per harness is a smoke test, not a campaign. Nothing here is evidence that these
harnesses do or do not find bugs; it is evidence that they build, run, and reach what the
coverage column says they reach.
