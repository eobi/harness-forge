# B1 validated on real applications, not a toy

`hforge app-lift` was pointed at two real programs from the durable corpus. Both were
discovered, classified, emitted, compiled, and run -- the mechanism works on real code.

## libyaml `run-parser-test-suite` (argv channel, the full YAML scanner+parser)

    hforge app-lift --header <decl> --name run_parser   -> run_parser_main [argv]
    compiled: harness + run-parser-test-suite.c (-Dmain=run_parser_main) + libyaml/src/*.c
    fuzzed 20s: ~37,000 executions

The fuzzer's bytes reached DEEP into the real parser -- the run printed libyaml's own
diagnostics ("did not find expected key", "mapping values are not allowed in this context",
"control characters are not allowed"), which only the genuine scanner/parser emits. This is a
generated harness driving a real, complex parser through the application's own argv entry.

Then libFuzzer reported a deadly signal. TRIAGED, NOT REPORTED: run-parser-test-suite.c calls
`abort()` at line 139 (on YAML_ANY_SCALAR_STYLE) and line 147 (on any event type its printer
does not handle). libyaml produced those events correctly; the TEST PROGRAM aborts because it
chooses not to print them. The crash is the harness's own abort(), not a libyaml defect, and
it is not a finding. This is the same artifact discipline the library track applies -- a crash
in the harness's own code is not a bug in the target.

## jansson `json_process` (argv channel) -- a channel-contract mismatch, surfaced honestly

app-lift discovered json_process_main [argv], emitted, compiled against the full jansson
parser, and ran 174,063 executions -- but coverage stayed at 8 and the run printed "Could not
open <tmp>/input". json_process is jansson's test runner: it treats its argv as a DIRECTORY
containing an `input` file, not a plain file to parse. The file channel handed it a file, so
it never reached the parser, and coverage=8 said so plainly rather than the engine pretending
to fuzz it.

## What this establishes

  - app-lift works on real, complex applications, not just the bug-shaped demo.
  - a generated harness reaches deep into a real parser through the app's own entry point.
  - the honesty holds at the application layer: a harness-side abort() is triaged as an
    artifact, and a channel that does not match the app's input contract shows up as flat
    coverage rather than a false success.

## What it reveals to build next

  - a STDIN channel: many real CLIs read stdin, and some (json_process) take a directory or
    structured path rather than a plain file. The channel set covers argv/file/buffer/cstring
    today; stdin and directory-shaped inputs are the next real-app channels.
  - app-entry artifact triage: an abort()/exit() in the application's own code on valid input
    is an app artifact, the app-layer analogue of the library S1 checks.
