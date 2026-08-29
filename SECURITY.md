# Security and disclosure

This project builds fuzzing harnesses. Used as intended it finds memory-safety defects in
other people's software, so how those defects are handled is part of the tool, not an
afterthought.

## Reporting a vulnerability in Harness Forge itself

Open a GitHub security advisory on this repository. Do not open a public issue for a
vulnerability. You will get an acknowledgement within 5 working days.

## Fuzzing targets: what this tool expects of you

**Fuzz only software you are authorised to fuzz.** Your own code, code you have permission
to test, or open-source software under a coordinated-disclosure process. This is not legal
advice and it is not a disclaimer we hide behind — it is the condition under which the tool
is useful rather than harmful.

**Findings go to the maintainer first.** The convention this project follows is a **90-day
window** from the first substantive report to public disclosure, extendable by agreement
when a fix is genuinely in progress, and shortened only when the defect is already being
exploited. If a maintainer is unreachable after documented attempts, say so publicly when
you disclose rather than implying they ignored you.

## The engine will never call something a zero-day

By deliberate design, no output of this tool prints the words "zero-day", and no gate
returns a verdict that asserts one.

A crash is a hypothesis. A finding is a hypothesis with a proof attached. Whether a proven
finding is a previously unknown vulnerability is a question about the *world* — about
existing CVEs, upstream commits, embargoed reports and duplicate submissions — and no
program with only the target's source in front of it can answer it. That call is a human
act, made after triage, and the engine is built so it cannot be mistaken for having made it.

The exploitability ladder is the honest form of the same discipline. Rung 3 and above
require an oracle **independent of the one that discovered the crash**, and the certificate
names which rung a finding reached and what the machine could not establish.

## What a certificate does not certify

Every generated certificate carries a `WHAT THIS HARNESS CANNOT FIND` block, computed from
the sanitizers and knobs actually in force. When a campaign reports nothing, that block is
the scope of the silence.

`NOT_RUN` is a distinct verdict from `PASS` throughout. A gate that could not run is never
counted as one that passed, in the tool's output or in this project's own claims about
itself.
