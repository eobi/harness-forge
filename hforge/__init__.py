"""Harness Forge — a certification authority for fuzzing harnesses.

The field builds generators. The field's own numbers say the generator is not the
bottleneck: harness defects produce false-positive crash rates as high as 94%, and an audit
of 586 production harnesses found 53 violations. The bottleneck is that nobody can tell you
whether a harness is any good until after it has wasted a campaign or produced a false
finding.

So this is not a generator. It is an IR, a gate bank and an evidence record, with generators
as replaceable plug-ins. The model proposes a plan; the gates certify it; confidence decides
nothing.
"""
__version__ = "0.1.0"
